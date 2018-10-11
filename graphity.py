#!/usr/bin/env python

import r2pipe
import sys
import os
import json
import re
import networkx as nx
from time import time
from datetime import datetime
from argparse import ArgumentParser
from base64 import b64decode
from collections import Counter
from graphityOut import toNeo, fromNeo, printGraph, printGraphInfo, dumpGraphInfoCsv, toPickle, fromPickle
from graphityViz import graphvizPlot, dumpJsonForJit, dumpGml, dumpGmlSubgraph, dumpJsonForD3
from graphityUtils import gimmeDatApiName, sha1hash, getAllAttributes, is_ascii, Hvalue, check_pe_header
from graphityOps import patternScan
import graphityFunc


# Works, takes its time, sometimes assigns wrong names to functions
# DEPRECATED
def loadFlirts():

	try:
		# load FLIRT signatures from local flirt directory
		flirtDir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'flirt')
		sigFiles = [f for f in os.listdir(flirtDir) if os.path.isfile(os.path.join(flirtDir, f))]

		for sigFile in sigFiles:
			r2cmd = "zfs %s" % os.path.join(flirtDir, sigFile)
			R2PY.cmd(r2cmd)

	except Exception as e:
		print(str(e) + " FAIL loading FLIRT sig file")


# Too slow for now, waiting for fix
def loadZigs():

	try:
		# load directory of zigs
		print('Loading msvcrt.sdb {:%Y-%m-%d %H:%M:%S}'.format(datetime.now()))

		zigpath = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'signatures')
		zigfile = os.path.join(zigpath, 'msvcrt.sdb')
		r2cmd = "zo %s" % zigfile
		# TODO load all signatures
		R2PY.cmd(r2cmd)

		print('msvcrt.sdb loaded {:%Y-%m-%d %H:%M:%S}'.format(datetime.now()))

		R2PY.cmd("e search.in = io.sections.exec")
		# e search.in = raw --- ?
		
		#toScan = getCodeSections()
		#for section in toScan:
			
		r2cmd = "z/" #%d %d" % (section[0], section[1])
		R2PY.cmd(r2cmd)

		print('msvcrt.zig scan on code section(s) finished {:%Y-%m-%d %H:%M:%S}'.format(datetime.now()))

	except Exception as e:
		print(str(e))


def flagLibraryCode(graphity):
	
	signList = R2PY.cmd("fs sign; fj")
	#print (signList)
	if signList:
		signListJ = json.loads(signList)
		for item in signListJ:
			libfunction = hex(item['offset'])
			if libfunction in graphity:
				print (graphity.node[libfunction])

# Checks whether an address is located in an executable section
def isValidCode(callAddress, sectionsList):

	# sectionsList contains executable sections as 2-element lists, containing start and end of each section
	for execSection in sectionsList:
		if int(callAddress, 16) >= execSection[0] and int(callAddress, 16) < execSection[1]:
			return True
	return False


# Returns a list of executable sections
def getCodeSections():

	returnSections = []

	# regular expression to pick out the executable section(s)
	execSection = re.compile("perm=....x")

	# will return the section table from radare2
	sections = R2PY.cmd("iS")

	sectionData = {}

	for line in sections.splitlines():
		if re.search(execSection, line):
			for element in line.split():
				items = element.split('=')
				sectionData[items[0]] = items[1]

			start = int(sectionData['vaddr'], 16)
			end = start + int(sectionData['vsz'])
			psize = int(sectionData['sz'])
			returnSections.append([start, end, psize])

	return returnSections


# Returns an executables imports as a list
def getIat():

	iatlist = []
	cmd = "iij"
	iatjson = json.loads(R2PY.cmd(cmd))
	for item in iatjson:
		iatlist.append(hex(item['plt']))
	return iatlist


# Returns a dictionary of xrefs to symbols
def crossRefScan():

	cmd = "axtj @@ sym.*"
	finalCalls = {}

	# fixing the JSON... issue reported to radare2, keep in mind to remove workaround
	temp = R2PY.cmd(cmd).replace('\n', ',')
	temp = temp.replace(",,", ",")
	temp = "[" + temp + "]"
	# print(temp)
	xrefj = json.loads(temp)
	# TODO check!!

	for xrefitem in xrefj:
		for xreflevel2 in xrefitem:

			# not data xref means its code or call
			if xreflevel2['type'] != 'd':
				finalCalls[hex(xreflevel2['from'])] = xreflevel2['opcode']
				pass

			# data potentially means API referenced by register; please note these are rather uncommon in the long list of symbol refs
			# thus, bottelneck in parsing speed lies in number of refs
			if xreflevel2['type'] == 'd' and ( xreflevel2['opcode'].startswith('mov') or xreflevel2['opcode'].startswith('lea') ):

				# 'grepping' out the register from mov/lea operation
				register = xreflevel2['opcode'].split()[1].replace(',','')

				# disassemble downwards; mmmaybe smarter to disassemble until end of function, but possible that there is no function at all
				# TODO find end of function, just in case
				cmd = "pd 300 @ " + hex(xreflevel2['from'])
				moreDisasm = R2PY.cmd(cmd)

				# possible branches towards target
				realCall = "call %s" % register
				aJmp = "jmp %s" % register

				for disasmLine in moreDisasm.splitlines()[1:]:
					if realCall in disasmLine or aJmp in disasmLine:
						#found a call!!
						temp = disasmLine + ";" + xreflevel2['opcode'].split(',')[1].rstrip()
						tempSplit = temp.split()
						finalCalls[hex(int(tempSplit[0], 16))] = ' '.join(tempSplit[1:])

					elif register in disasmLine:
						# TODO if mov dword abc, reg is found -> follow abc?
						# TODO could be parsed in more detail, e.g. mov dword, reg won't change the reg
						#print disasmLine

						break
						#pass
	return finalCalls


# Parses the binary for strings and their references to nodes
def stringScan(debugDict):

	# Workflow is: get string, get xrefs to string if any, get functions of xrefs if any; fit node in graph with the string
	allMyStrings = []
	return allMyStrings

	# izzj parses entire binary
	stringCmd = "izzj"
	strings = R2PY.cmd(stringCmd)
	
	parsedStrings = json.loads(strings)
	
	debugDict['stringsDangling'] = []
	debugDict['stringsNoRef'] = []

	i = 0
	j = 1
	while i < len(parsedStrings["strings"]):
		stringItem = parsedStrings["strings"][i]

		# Strings when retrieved through izzj command are BASE64 encoded
		thatOneString = b64decode(stringItem['string']).replace(b'\\', b' \\\\ ')
		thatOneString.replace(b'\'', b'')
		
		try:
		
			thatOneString = thatOneString.decode()
		
			xrefCmd = "axtj @ " + hex(stringItem['vaddr'])
			stringXrefsJ = R2PY.cmd(xrefCmd)
			# RN
			stringXrefsJ = stringXrefsJ.replace("\"\"", "\"")
			# print(stringXrefsJ)
			# TODO this should be a list, but is returned as a string now?
			#if stringXrefsJ != []:
			if len(stringXrefsJ) > 2:
				stringXrefs = json.loads(stringXrefsJ)

				# check whether string item is root of list of strings
				j = 1
				lastItem = stringItem
				while (i + j) < len(parsedStrings["strings"]):
					nextStringItem = parsedStrings["strings"][i + j]
					lastAddr = lastItem['vaddr']
					lastSize = lastItem['size']

					# string offsets are 4 byte aligned, TODO check whether this is always the case
					padding = 4 - (lastSize % 4)
					if padding == 4:
						padding = 0
					nextAddr = lastAddr + lastSize + padding

					if nextAddr != nextStringItem['vaddr'] or hasXref(hex(nextStringItem['vaddr'])):
						# end.. exit here
						break
					else:
						thatOneString = thatOneString + "|" + b64decode(nextStringItem['string']).decode()
						j = j + 1
						lastItem = nextStringItem

				# iterate refs on string, if any
				for ref in stringXrefs:
					
					# sort out strings with code ref, i.e. non-strings
					if ref['type'] != 'c' and ref['type'] != 'C':
						stringAddr = hex(ref['from'])
						stringFuncRef = gimmeRespectiveFunction(stringAddr)
						if stringFuncRef != '0x0':
							allMyStrings.append([stringAddr, stringFuncRef, thatOneString])
						else:
							# TODO this is merely still useful strings, see how to fit them in the graphs and db
							# RN print("DANGLING STRING NO FUNCREF %s %s" % (stringAddr, thatOneString))
							debugDict['stringsDangling'].append(thatOneString)
					
			else:
				debugDict['stringsNoRef'].append(thatOneString)
						

		except UnicodeDecodeError:
			pass
		if j > 1:
			i = i + j
		else:
			i = i + 1

	debugDict['stringsDanglingTotal'] = len(debugDict['stringsDangling'])
	debugDict['stringsNoRefTotal'] = len(debugDict['stringsNoRef'])
	return allMyStrings


# Text whether xrefs exist for given address
def hasXref(vaddr):

	refs = R2PY.cmd("axtj @ " + vaddr)
	if refs:
		return True
	else:
		return False


# Creating the NetworkX graph, nodes are functions, edges are calls or callbacks
def createRawGraph():

	graphity = nx.DiGraph()
	debugDict = {}

	functions = R2PY.cmd("aflj")
	if functions:
		functionList=json.loads(functions)
		#print json.dumps(functionList, indent=4, sort_keys=True)
	else:
		functionList = []

	# figuring out code section size total
	sectionsList = getCodeSections()
	xlen = 0
	for execSec in sectionsList:
		xlen = xlen + execSec[2]
	debugDict['xsectionsize'] = xlen

	# CREATING THE GRAPH

	refsGlobalVar = 0
	refsUnrecognized = 0
	refsFunc = 0
	debugDict['functions'] = len(functionList)

	### NetworkX Graph Structure ###

	# FUNCTION as node, attributes: function address, size, calltype, list of calls, list of strings, count of calls; functiontype[Callback, Export], alias (e.g. export name), mnemonic distribution
	# FUNCTIoN REFERENCE as edge (function address -> target address), attributes: ref offset (at)
	# INDIRECT REFERENCE as edge (currently for threads and Windows hooks, also indirect code and indirect data references)
	# API CALLS (list attribute of function node): address, API name
	# STRINGS (list attribute of function node): address, string, evaluation

	####

	# TODO add count of refs from A to B as weights to edges
	# TODO count calls to global vars, to indirect targets
	
	for item in functionList:

		#print hex(item['offset'])
		graphity.add_node(hex(item['offset']), size=item['realsz'], calltype=item['calltype'], calls=[], apicallcount=0, strings=[], stringcount=0, functiontype='')

	for item in functionList:

		# TODO look into new values provided by aflj
		# print(item)
		if 'callrefs' in item:
			for xref in item['callrefs']:

				if xref['type'] == 'C':

					# If an edge is added, that includes a non-existent node, the node will be added, but w/o the necessary attributes
					# Thasss why we iterate twice, can theoretically be speeded up but needs testing
					if hex(xref['addr']) in graphity:
						if item['offset'] != xref['addr']:
							graphity.add_edge(hex(item['offset']), hex(xref['addr']), pos=hex(xref['at']))
							refsFunc = refsFunc + 1

					elif hex(xref['addr']) in getIat():
						pass

					elif not isValidCode(hex(xref['addr']), sectionsList):
						# TODO do something
						print("DANGLING call to address outside code section, glob var, dynamic API loading %s -> %s" % (hex(item['offset']), hex(xref['addr'])))
						refsGlobalVar = refsGlobalVar + 1

					else:
						print("FAIL: Call to code thats not a function, an import/symbol or otherwise recognized. Missed function perhaps. %s -> %s" % (hex(item['offset']), hex(xref['addr'])))
						refsUnrecognized = refsUnrecognized + 1

	print('* %s Graph created with NetworkX ' % str(datetime.now()))
	debugDict['refsFunctions'] = refsFunc
	debugDict['refsGlobalVar'] = refsGlobalVar
	debugDict['refsUnrecognized'] = refsUnrecognized

	apiRefs = crossRefScan()

	callNum = len(apiRefs)
	missesNum = 0

	# FITTING GRAPH WITH API REFS

	for call in apiRefs:

		# get the address of the function, that contains the call to a given symbol
		funcAddress = gimmeRespectiveFunction(call)

		# TODO check if funcAddress is the real function address
		if funcAddress in graphity:

			# node(funcAddress) has attribute calls, which contains a list of API calls
			api = gimmeDatApiName(apiRefs[call])

			graphity.node[funcAddress]['calls'].append([call, api])
			
		# detected API call reference does not resolve to a function offset, insert handling for this here
		else:
			print("DANGLING API CALL %s %s" % (call, apiRefs[call]))
			missesNum = missesNum+1

	# debug: print total API refs and functionless API refs, maybe indicator for obfuscated code
	print('* %s Graph extended with API calls, %d calls in total, %d dangling w/o function reference ' % (str(datetime.now()), callNum, missesNum))
	debugDict['apiTotal'] = callNum
	debugDict['apiMisses'] = missesNum


	# FITTING GRAPH WITH STRING REFS

	allTheStrings = stringScan(debugDict)
	stringrefs = 0

	for aString in allTheStrings:

		stringAddr = aString[0]
		stringFunc = aString[1]
		stringData = aString[2]

		# add string to respective function node in graph
		if stringFunc in graphity:
			graphity.node[stringFunc]['strings'].append([stringAddr, stringData])
			stringrefs = stringrefs + 1

		else:
			print("\n*** BIG FAIL *** String's function not in graph %s %s" % (stringFunc, stringData))

	print('* %s Graph extended with string references ' % (str(datetime.now())))
	debugDict['stringsReferencedTotal'] = stringrefs

	return graphity, debugDict


# Tag exports of DLLs
# TODO : check whether exports are coming back after bugfix (?)
def analyzeExports(graphity):

	exportsj = json.loads(R2PY.cmd("iEj"))
	for item in exportsj:

		exportAddress = hex(item['vaddr'])
		exportName = item['name']

		exportFunction = gimmeRespectiveFunction(exportAddress)

		if exportFunction in graphity:
			graphity.node[exportFunction]['functiontype'] = 'Export'
			graphity.node[exportFunction]['alias'] = exportName


# Removing thunks as they make my graphs fat, replace by API calls
def thunkPruning(graphity):

	for aNode in graphity.nodes(data=True):

		# most obvious thunks, other thunks exist too, len seen was 11, 13
		# TODO !!!!!!!! check for 64bit
		# TODO check with radare for thunk detection?
		# funclets that contain nothing but a jump to an import, and do not call other functions
		if len(aNode[1]['calls']) == 1 and aNode[1]['size'] == 6 and not graphity.successors(aNode[0]):

			thunk = aNode[0]
			thunkApi = aNode[1]['calls'][0]

			# need to go on with radare from here, cause graphity doesn't know all the addressed of the xrefs to thunks from within a function
			# getting all xrefs on thunk, then getting function its located in to get to node of graph
			temp = R2PY.cmd("axtj " + thunk)

			thunkRefs = []
			if temp:
				thunkRefs = json.loads(temp)

			for aRef in thunkRefs:

				thunkCallAddr = hex(aRef['from'])
				thunkFuncRef = gimmeRespectiveFunction(thunkCallAddr)

				# if thunk's xrefs include a detected function then add thunk as a regular API call to calls list of respective node
				if thunkFuncRef != '0x0':
					graphity.node[thunkFuncRef]['calls'].append([thunkCallAddr, thunkApi[1]])

			# after xref to thunk has been added to all calling functions, remove thunk node from graph
			graphity.remove_node(thunk)


# Adding edges to indirectly referenced functions, thread handlers and hook functions for now only
def tagCallbacks(graphity):

	for aNode in graphity.nodes(data=True):
		for call in aNode[1]['calls']:

			xrefTarget = ''
			# TODO consider this bad practise, do something smarter, not sure yet what,  consider _beginthread API etc. etc.
			# also, maybe this is fixed in radare later, so consider this code redundant by then
			if 'CreateThread' in call[1]:
				xrefTarget = getCallback(call[0], 3)
				
			if 'SetWindowsHookEx' in call[1]:
				xrefTarget = getCallback(call[0], 2)
			
			if xrefTarget:
				print (xrefTarget, aNode[0])
				addIndirectEdge(graphity, aNode[0], xrefTarget, "apicallback", "Callback")
				
		# implicitly filters out callbacks fixed already - gets all nodes with zero in-degre
		# TODO see if feasible for all functions, even with such already having in edges
	for aNode in graphity.nodes(data=True):
		if graphity.in_degree(aNode[0]) == 0:
			jay = R2PY.cmd("axtj @ " + aNode[0])
			
			if jay:
				xrefs = json.loads(jay)
				for xref in xrefs:
				
					# if xref is code its almost certainly an edge to add
					if xref['type'] == 'c':
						
						# TODO circle back on jumptable-as-a-function bug from r2
						# really ugly workaround, really really ugly..
						if not 'dword [' in xref['opcode']:
							addIndirectEdge(graphity, hex(xref['from']), aNode[0], "coderef", "IndirectCode")
								
					# if xref is data
					if xref['type'] == 'd':
					
						opcd = xref['opcode']
						# TODO run more tests on this list not sure these are all possible cases
						# TODO make datarefs optional!
						if opcd.startswith('push') or opcd.startswith('lea') or opcd.startswith('mov'):
							print (hex(xref['from']), opcd)
							addIndirectEdge(graphity, hex(xref['from']), aNode[0], "dataref", "IndirectData")
						else:
							# TODO look into add reg, ThreadRoutine -> as xref
							print ("up for discussion: " + hex(xref['from']), xref['type'], xref['opcode'])
						

def addIndirectEdge(graphity, fromAddr, toAddr, calltype, functiontype):
	
	fromNode = gimmeRespectiveFunction(fromAddr)
	toNode = gimmeRespectiveFunction(toAddr)
	if fromNode in graphity and toNode in graphity:
		graphity.node[toNode]['functiontype'] = functiontype
		graphity.add_edge(fromNode, toNode, calltype=calltype)
		print ("added callback edge", fromNode, toNode, calltype, "\n")
	else:
		print ("Something went wrong with indirect edge ", fromAddr, toAddr, calltype)
	

# Parsing the handler offset out of the function arguments
def getCallback(call, argcount):

	# simplistic: walk up the code until xref to code is found, works as long as API only receives one code ref, works well with Windows APIs
	disasmMore = "pd -30 @" + call
	upwards = R2PY.cmd(disasmMore)

	for otherLine in reversed(upwards.splitlines()):
		if 'push' in otherLine:
			argcount = argcount - 1

		# TODO better done with a regex, bug prone
		if not argcount:
			address = otherLine.split("push",1)[1].split()[0]
			if 'fcn.' in address:
				return hex(int(address.split('.')[1], 16))
			if '0x' in address:
				return hex(int(address.split('0x')[1], 16))
			else:
				return ''


# WORKAROUND until function detection - bug? feature? in radare is fixed and export vaddr equal actual offsets again
def gimmeRespectiveFunction(address):
	if address:
		return R2PY.cmd("?v $FB @ " + address)
	return ''

def mnemonicism(offset):

	mnems = []
	fsize = 0
	weight = 0
	
	funcdump = R2PY.cmd("pdfj @ " + offset)
	if funcdump:
		dumpj = json.loads(funcdump)
		for item in dumpj["ops"]:
			#print(item)
			if "type" in item:
				mnems.append(item["type"])
			#print (item["type"], item["opcode"])
		fsize = dumpj["size"]
	
	#print ("\n" + offset + " " + str(fsize))
	mnemdict = Counter(mnems)
	#for mnem in sorted(mnemdict):
	#	print (mnem, mnemdict[mnem])
		
	for mnem in mnemdict:
		if mnem in ['shl', 'shr', 'mul', 'div', 'rol', 'ror', 'sar', 'load', 'store']:
			weight += mnemdict[mnem]
	return (weight * 10) / fsize

	# TODO count how many above certain threshold, see how close they are together in the graph?
	
	
# super graph creation function, radare-analyses the sample, puts together all of the graph and debug info
def graphMagix(filepath, allAtts, deactivatecache):

	global R2PY

	if (os.path.isfile("cache/" + allAtts['sha1'] + ".txt") and os.path.isfile("cache/" + allAtts['sha1'] + ".dbg") and deactivatecache == False):
		print('* %s Loading graph from cache under ./cache/[sha1].txt or .dbg' % str(datetime.now()))
		graphity, debug = fromPickle(allAtts['sha1'])

	else:
		print('* %s R2 started analysis ' % str(datetime.now()))

		BENCH['r2_start'] = time()
		print("filepath:" + filepath)

		R2PY = r2pipe.open(filepath)

		R2PY.cmd("e asm.lines = false")
		R2PY.cmd("e asm.fcnlines = false")
		R2PY.cmd("e anal.autoname= false")
		R2PY.cmd("e anal.jmptbl = true")
		R2PY.cmd("e anal.hasnext = true")
		R2PY.cmd("e anal.bb.maxsize = 1M")
		#R2PY.cmd("e src.null = true")
		R2PY.cmd("aaa")
		#R2PY.cmd("afr")
		#R2PY.cmd("afr @@ sym*")
		
		#loadZigs()
		#loadFlirts()

		BENCH['r2_end'] = time()
		print('* %s R2 finished analysis' % str(datetime.now()))

		# GRAPH CREATION
		graphity, debug = createRawGraph()

		# TODO testing lib code detected
		#flagLibraryCode(graphity)
			
		# DLL PROCESSING
		if 'DLL' in allAtts['filetype']:
			analyzeExports(graphity)

		# Thunk pruning, thunks are unnecessary information in the graph
		thunkPruning(graphity)

		# handler tagging
		tagCallbacks(graphity)
		
		# update api and string count attributes
		for aNode in graphity.nodes(data=True):
			aNode[1]['apicallcount'] = len(aNode[1]['calls'])
			aNode[1]['stringcount'] = len(aNode[1]['strings'])

		# calc mnemonic dist
		for aNode in graphity.nodes():
			graphity.node[aNode]['mnemonicism'] = mnemonicism(aNode)
			
		BENCH['graph_end'] = time()

		# graph and debug info caching to save parsing time, potentially
		if (deactivatecache == False):
			toPickle(graphity, debug, allAtts['sha1'])

	return graphity, debug

'''
	#global R2PY

		for entry in behaviours:
			info = behaviours[entry]
			for api_info in info:
				for api in api_info:
					print(api, api_info[api])
					addr = "s." + str(api_info[api])
					R2PY.cmd(addr)
					print(R2PY.cmd("pdf"))

'''


def get_behaviors(filepath, dst_file):
	global BENCH
	BENCH = {}

	behaviours = {}
	if check_pe_header(filepath):
		print('* %s Parsing %s ' % (str(datetime.now()), filepath))
		allAtts = getAllAttributes(filepath)
		graphity, debug = graphMagix(filepath, allAtts, True)  # args.deactivatecache)

		# BEHAVIOR
		print('* %s Scanning for API patterns ' % str(datetime.now()))
		BENCH['behavior_start'] = time()
		allThePatterns = graphityFunc.funcDict

		for patty in allThePatterns:
			# print(patty)
			findings = patternScan(graphity, allThePatterns[patty])

			for hit in findings:
				if not False in hit['patterns'].values():
					print("For %s found %s" % (patty, str(hit['patterns'])))
					if patty in behaviours:
						list_hit = behaviours[patty]
						list_hit.append(hit['patterns'])
						behaviours[patty] = list_hit
					else:
						behaviours[patty] = [hit['patterns']]
		BENCH['behavior_end'] = time()

	ret_info = {}
	if behaviours:
		function_list = {}
		for behav in behaviours:
			info = behaviours[behav]
			for entry in info:
				for name in entry:
					if not str(entry[name]) in function_list:
						function_list[str(entry[name])] = behav
						print(entry)

		base_file = dst_file.replace(".behav.json", "")
		for funct in function_list:
			R2PY.cmd("s." + funct)
			pseudo_code = R2PY.cmd("pdc")
			code_file = base_file + "." + function_list[funct] + "_" + funct + ".c"
			with open(code_file, "w") as out:
				for line in pseudo_code.split("\n"):
					line = line.rstrip()
					if line:
						out.write(line + "\n")

		ret_info["Suspicious Behaviors"] = behaviours
		with open(dst_file, "w") as out:
			out.write(json.dumps(ret_info, sort_keys=True, indent=4))

	return ret_info


if __name__ == '__main__':

	#global R2PY
	global BENCH
	BENCH = {}

	parser = ArgumentParser()
	parser.add_argument("input", help="Tool requires an input file or directory; directory, i.e. batch processing, only possible and feasible for csvdump option")
	parser.add_argument("-d", "--deactivatecache", action="store_true", help="Deactivate caching of graphs, for debugging of graph generation")
	
	# Text output options
	parser.add_argument("-p", "--printing", action="store_true", help="Print the graph as text, as in, nodes with respective content")
	parser.add_argument("-i", "--info", action="store_true", help="Print info and stats of the graph")
	parser.add_argument("-b", "--behavior", action="store_true", help="Scan for behaviors listed in graphityFunc.py")
	
	# Visualization & viz data options
	parser.add_argument("-l", "--plotting", action="store_true", help="Plotting the graph via pyplot")	
	parser.add_argument("-g", "--gml", action="store_true", help="Spit out GML data for Gephi and what not")
	parser.add_argument("-s", "--gmlsub", help="Define an offset in the form e.g. 0x401000 to dump the subgraph starting there")
	parser.add_argument("-j", "--jit", action="store_true", help="Spits out JSON data, ready to be visualized within JS InfoVis as force directed graph")
	
	# Batch processing options
	parser.add_argument("-n", "--neodump", action="store_true", help="Dump graph to Neo4j (configured to flush previous data from Neo, might wanna change that) - BATCH PROCESSING ONLY")
	parser.add_argument("-c", "--csvdump", help="Dump info data to a given csv file, appends a line per sample, for testing now also dumps strings per binary in dedicated csv file - BATCH PROCESSING ONLY")

	args = parser.parse_args()
	# TODO check the path pythonically

	# Batch processing options: csvdump, neodump, TBC
	if args.input and os.path.isdir(args.input):
		for (dirpath, dirnames, filenames) in os.walk(args.input):
			for filename in filenames:
				filepath = os.path.join(dirpath, filename)

				if check_pe_header(filepath):
					print('* %s Parsing %s ' % (str(datetime.now()), filename))
					allAtts = getAllAttributes(filepath)
					graphity, debug = graphMagix(filepath, allAtts, args.deactivatecache)

					if args.csvdump:
						# CSVDUMP
						dumpGraphInfoCsv(graphity, debug, allAtts, args.csvdump)
						print('* %s Dumping graph info to indicated csv file ' % str(datetime.now()))

					if args.neodump:
						# TO NEO STUFF
						toNeo(graphity, allAtts)
						print('* %s Dumped to Neo4J ' % str(datetime.now()))

	elif args.input and check_pe_header(args.input):

		# ATTRIBUTES: md5, sha1, filename, filetype, ssdeep, filesize, imphash, compilationts, addressep, sectionep,
		# sectioncount, sectioninfo, tlssections, originalfilename

		allAtts = getAllAttributes(args.input)
		graphity, debug = graphMagix(args.input, allAtts, args.deactivatecache)
		
		# TODO decide what to do with dangling strings/APIs (string filtering with frequency analysis?)

		if args.printing:
			# PRINT GRAPH TO CMDLINE
			print("* %s Printing the graph - nodes and node attributes" % str(datetime.now()))
			BENCH['printing_start'] = time()
			printGraph(graphity)
			BENCH['printing_end'] = time()

		if args.info:
			# PRINT GRAPH INFO
			BENCH['info_start'] = time()
			printGraphInfo(graphity, debug)
			BENCH['info_end'] = time()

			# TODO look into certificate info: iC

		if args.plotting:
			# GRAPH PLOTTING STUFF
			#try:
			print('* %s Plotting routine starting ' % str(datetime.now()))
			BENCH['plotting_start'] = time()
			graphvizPlot(graphity, allAtts)
			BENCH['plotting_end'] = time()
			print('* %s Plotting routine finished ' % str(datetime.now()))
			#except:
			#	   print '* %s Cant plot this with pydot, too big ' % str(datetime.now())

		if args.neodump:
			# TO NEO STUFF
			BENCH['neo_start'] = time()
			toNeo(graphity, allAtts)
			BENCH['neo_end'] = time()
			print('* %s Dumped to Neo4J ' % str(datetime.now()))

		if args.behavior:
			# BEHAVIOR
			# TODO enable switching of behavior dictionaries
			print('* %s Scanning for API patterns ' % str(datetime.now()))
			BENCH['behavior_start'] = time()
			allThePatterns = graphityFunc.funcDict

			behaviours = {}
			for patty in allThePatterns:
				# print(patty)
				findings = patternScan(graphity, allThePatterns[patty])

				for hit in findings:
					if not False in hit['patterns'].values():
						print("For %s found %s" % (patty, str(hit['patterns'])))
						if patty in behaviours:
							list_hit = behaviours[patty]
							list_hit.append(hit['patterns'])
							behaviours[patty] = list_hit
						else:
							behaviours[patty] = [hit['patterns']]

			out_file = args.input + ".behavior.json"
			save_behaviors(out_file, behaviours)

			BENCH['behavior_end'] = time()

		if args.gml:
			# GML and stuff
			BENCH['gml_start'] = time()
			dumpGml(graphity, allAtts)
			BENCH['gml_end'] = time()
			
		if args.gmlsub:
			# TODO add bench
			dumpGmlSubgraph(graphity, gmlsub)
			
		if args.jit:
			#dumpJsonForJit(graphity, indent=2)
			BENCH['d3_start'] = time()
			dumpJsonForD3(graphity)
			BENCH['d3_end'] = time()
			
			
			# TODO calculate dispersion for 2-n anchor addresses
			# TODO handling of LoadLib/GetPAddr. for "hiding something" question, follow GetProc return value


		print('* %s Stuffs all finished ' % str(datetime.now()))

		# TIME
		print("\n__..--*** I WANNA BE A BENCHMARK WHEN I GROW UP ***--..__")

		if 'r2_start' in BENCH:
			print("__ %5f R2 Analysis" % (BENCH['r2_end'] - BENCH['r2_start']))
		if 'graph_end' in BENCH:
			print("__ %5f Graph construction" % (BENCH['graph_end'] - BENCH['r2_end']))

		if 'printing_start' in BENCH:
			print("__ %5f Printing" % (BENCH['printing_end'] - BENCH['printing_start']))
		if 'info_start' in BENCH:
			print("__ %5f Info" % (BENCH['info_end'] - BENCH['info_start']))
		if 'plotting_start' in BENCH:
			print("__ %5f Plotting" % (BENCH['plotting_end'] - BENCH['plotting_start']))
		if 'behavior_start' in BENCH:
			print("__ %5f Behavior" % (BENCH['behavior_end'] - BENCH['behavior_start']))
		if 'neo_start' in BENCH:
			print("__ %5f Neo4j" % (BENCH['neo_end'] - BENCH['neo_start']))
		if 'csv_start' in BENCH:
			print("__ %5f CSV dump" % (BENCH['csv_end'] - BENCH['csv_start']))
		if 'gml_start' in BENCH:
			print("__ %5f GML dump" % (BENCH['gml_end'] - BENCH['gml_start']))
		if 'd3_start' in BENCH:
			print("__ %5f D3 dump" % (BENCH['d3_end'] - BENCH['d3_start']))

	else:
		print("Potentially not a PE file %s" % args.input)


