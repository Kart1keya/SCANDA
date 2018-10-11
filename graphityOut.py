#!/usr/bin/env python

import sys
import os
import py2neo
import networkx as nx
import numpy as np
import pickle
import re
import json
from graphityUtils import gimmeDatApiName, getAllAttributes
from graphityOps import fetchExtendedGraph, stringData


def toNeo(graphity, allAtts):

	# GRAPH DB STUFF - NEO4J
	# receives the NetworkX graph and accompanying sample data
	# pushes the graph to Neo4J

	### NetworkX Graph Structure ###

	# FUNCTION as node, attributes: function address, size, calltype, list of calls, list of strings, count of calls; functiontype[Standard, Callback, Export], alias (e.g. export name)
	# FUNCTIoN REFERENCE as edge (function address -> target address), attributes: ref offset (at)
	# CALLBACK REFERENCE as edge (currently for threads and Windows hooks)
	# API CALLS (list attribute of function node): address, API name
	# STRINGS (list attribute of function node): address, string

	####

	py2neo.authenticate("localhost:7474", "neo4j", "neo4j")
	neoGraph = py2neo.Graph("http://localhost:7474/")
	neoSelector = py2neo.NodeSelector(neoGraph)

	# flush of the DB, for test purposes
	neoGraph.delete_all()

	mySha1 = allAtts['sha1']

	if neoSelector.select("SAMPLE", sha1=mySha1).first():
		print("Graph for sample %s already exists in Neo4j instance!" % mySha1)

	else:

		# create master node for binary information
		sampleNode = py2neo.Node("SAMPLE", sha1=mySha1, fileSize=allAtts['filesize'], binType=allAtts['filetype'], imphash=allAtts['imphash'], compilation=allAtts['compilationts'], addressEp=allAtts['addressep'], sectionEp=allAtts['sectionep'], sectionCount=allAtts['sectioncount'], originalFilename=allAtts['originalfilename'])
		neoGraph.create(sampleNode)

		# get nodes with 0 indegree, prepare relations from master node 
		indegrees = graphity.in_degree()
		rootlist = []
		for val in indegrees:
			if indegrees[val] == 0:
				rootlist.append(val)

		# parsing of the NetworkX graph - functions, APIs and strings are all Neo4j nodes
		for nxNode in graphity.nodes(data=True):

			funcAddress = nxNode[0]
			funcCalltype = nxNode[1]['calltype']
			funcSize = nxNode[1]['size']
			funcAlias = ''
			funcType = ''
			if nxNode[1].get('functiontype') : funcType = nxNode[1]['functiontype']
			if nxNode[1].get('alias') : funcAlias = nxNode[1]['alias']

			# sha1 serves as link to master node, but also as node identifier in combination with the function address
			# TODO for saving memory, explore possibility of replacing sha1 with an index, as sha info is held in master node anyway
			functionNode = py2neo.Node("FUNCTION", sample=mySha1, address=funcAddress, callType=funcCalltype, funcSize=funcSize, funcType=funcType, alias=funcAlias)
			neoGraph.create(functionNode)
			
			if funcAddress in rootlist:
				rootrel = py2neo.Relationship(sampleNode, "virtual_relationship", functionNode)
				neoGraph.create(rootrel)

			stringList = nxNode[1]['strings']

			for stringData in stringList:
				strRefAddress = stringData[0]
				theString = stringData[1]

				# TODO think about string attributes to store, e.g. entropy, len
				try:

					# create string node or merge if string already exists, add relationship
					stringNode = py2neo.Node("STRING", string=theString)
					# TODO try this using Subgraph class, less interaction with DB server
					neoGraph.merge(stringNode)

					stringRel = py2neo.Relationship(functionNode, "references_string", stringNode, address=strRefAddress)
					neoGraph.create(stringRel)

				except:
					print("ERROR with this string %s" % theString)

			callsList = nxNode[1]['calls']

			for callData in callsList:
				callRefAddress = callData[0]
				callApiName = callData[1]

				# create API node or merge if API already exists, add relationship
				apiNode = py2neo.Node("API", apiname=callApiName)
				neoGraph.merge(apiNode)

				apiRel = py2neo.Relationship(functionNode, "calls_api", apiNode, address=callRefAddress)
				neoGraph.create(apiRel)

		for from_node, to_node, properties in graphity.edges(data=True):

			realFromNode = neoSelector.select("FUNCTION", sample=mySha1, address=from_node).first()
			realToNode = neoSelector.select("FUNCTION", sample=mySha1, address=to_node).first()

			funcCallsFunc =  py2neo.Relationship(realFromNode, "calls_sub", realToNode)
			neoGraph.create(funcCallsFunc)


# EXPERIMENTAL fetching queries from Neo
def fromNeo():
	
	py2neo.authenticate("localhost:7474", "neo4j", "neo4j")
	neoGraph = py2neo.Graph("http://localhost:7474/")
	neoSelector = py2neo.NodeSelector(neoGraph)
	
	query = neoGraph.run("MATCH (f:FUNCTION)-->(s:STRING) WHERE s.string CONTAINS 'OpenSSL' RETURN DISTINCT f.sample")
	print (query.dump())
	
	query = neoGraph.run("MATCH (s:SAMPLE {sha1: '04301b59c6eb71db2f701086b617a98c6e026872'})-[rels*]->(c) RETURN *")
	print (query.dump())

	
# dump entire NetworkX graph + debug info to text files, graph caching to save parsing time for already parsed binaries
def toPickle(graphity, debug, sha1):

	dumpfile = "cache/" + sha1 + ".txt"
	debugfile = "cache/" + sha1 + ".dbg"
	pickle.dump(graphity, open(dumpfile, 'wb'))
	pickle.dump(debug, open(debugfile, 'wb'))


# load graph and its debug info from cache, identified by SHA1
def fromPickle(sha1):

	dumpfile = "cache/" + sha1 + ".txt"
	debugfile = "cache/" + sha1 + ".dbg"
	graphity = pickle.load(open(dumpfile, 'rb'))
	debug = pickle.load(open(debugfile, 'rb'))
	return graphity, debug


# print functions, their APIs and strings to the commandline, enhancements needed
def printGraph(graphity):

	# TODO add more info to print, alias and stuff, sample info
	# print dangling APIs
	# print dangling strings

	# urgent TODO sort nodes before printing by address
	
	for item in graphity.nodes(data=True):
		print(item[0], item[1]['apicallcount'], item[1]['stringcount'])
		if 'alias' in item[1]:
			print("Node alias: " + item[1]['alias'])
			
		for callItem in item[1]['calls']:
			callItem.append('C')
		for stringItem in item[1]['strings']:
			stringItem.append('S')

		# mix up API calls and strings and sort by offset
		callStringMerge = item[1]['calls'] + item[1]['strings']
		callStringMerge.sort(key=lambda x: x[0])

		for cx in callStringMerge:
			print(cx)


# Printing all the meta info to cmdline
def printGraphInfo(graphity, debug):

	# GENERAL INFO

	print(".\nGeneral graph info:")
	allAtts = getAllAttributes(sys.argv[1])
	print("SAMPLE " + allAtts['filename'])
	print("Type: " + allAtts['filetype'])
	print("Size: " + str(allAtts['filesize']))
	print("MD5: " + allAtts['md5'])
	print("SHA1: " + allAtts['sha1'])
	print(nx.info(graphity))

	# GRAPH PARSING INFO

	print(".\nGraph measurement data:")
	print("%6d Total functions detected with 'aflj'" % debug['functions'])
	print("%6d Count of references to local functions" % debug['refsFunctions'])
	print("%6d Count of references to data section, global variables" % debug['refsGlobalVar'])
	print("%6d Count of references to unrecognized locations" % debug['refsUnrecognized'])
	print("%6d Total API refs found via symbol xref check" % debug['apiTotal'])
	print("%6d Count APIs w/o function xref" % debug['apiMisses'])
	print("%6d Total referenced Strings" % debug['stringsReferencedTotal'])
	print("%6d Count of dangling strings (w/o function reference)" % debug['stringsDanglingTotal'])
	print("%6d Count of strings w/o any reference" % debug['stringsNoRefTotal'])

	# PE DETAILS

	print(".\nPE details:")
	print("Imphash:\t\t" + allAtts['imphash'])
	print("Compilation time:\t" + allAtts['compilationts'])
	print("Entrypoint address:\t" + hex(allAtts['addressep']))
	print("Entrypoint section:\t" + allAtts['sectionep'])
	print("TLS section count:\t" + str(allAtts['tlssections']))
	print("Original filename:\t" + allAtts['originalfilename'])
	print("Section count:\t\t" + str(allAtts['sectioncount']))
	print("Section details:")

	i=0
	while i < allAtts['sectioncount'] and i < 12:
		print("%8s %8d %s" % (allAtts['sectioninfo'][i], allAtts['sectioninfo'][i+12], allAtts['sectioninfo'][i+24]))
		i = i + 1


	# TODO resources list


	try:
		degrees = nx.out_degree_centrality(graphity)
	except:
		degrees = 0

	indegrees = graphity.in_degree()

	# SPAGHETTI CODE METRICS

	print(".\nFat node detection with out-degree centrality, count calls, count strings:")
	if degrees:
		sortit = sorted(degrees, key=degrees.get, reverse=True)
		for val in sortit[:20]:
			# TODO check the numbers
			print("%s %.6f %d %d" % (val, degrees[val], len(graphity.node[val]['calls']), len(graphity.node[val]['strings'])))

	print('.')

	# OUT DEGREE CENTRALITY HISTOGRAM

	print("Histogram of out degree centrality:")
	nummy = np.array(list(degrees.values()))
	bins = [0, 0.0005, 0.001, 0.0015, 0.002, 0.004, 0.006, 0.008, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.1, 0.2, 0.3, 0.4, 0.5]
	hist, bin_edges = np.histogram(nummy, bins=bins)
	for be in bin_edges:
		end = ' '
		print be, end
	print("")
	for hi in hist:
		print hi, end
	print("\n.")

	# LOOSE NODE COUNT

	numInZero = 0
	for val in indegrees:
		if indegrees[val] == 0:
			numInZero = numInZero + 1
	nodeNum = graphity.number_of_nodes()
	if not nodeNum:
		nodeNum = 1

	print("Loose nodes %d of total %d, thats %f%%" % (numInZero, nodeNum, 100.0 * (float(numInZero) / float(nodeNum))))

	# RATIO OF API CALLS AND STRINGS WITHING CODE SECTION

	print(".\nExecSize FunctionCount ApiCount StringCount")
	print("%d %d %d %d" % (debug['xsectionsize'], debug['functions'], debug['apiTotal'], debug['stringsReferencedTotal'])) # code section size, function count, total api, total string

	kilobytes = (float(debug['xsectionsize']) / 1000.0)
	if kilobytes > 0:
		print("Per-Kilobyte ratio")
		print(float(debug['functions']) / kilobytes, float(debug['apiTotal']) / kilobytes, float(debug['stringsReferencedTotal']) / kilobytes)

	# AVERAGE DEGREE CONNECTIVITY

	print(".\nAverage degree connectivity per degree k:") #average nearest neighbor degree of nodes with degree k
	avConn = nx.average_degree_connectivity(graphity)
	for connectivity in avConn:
		print("%3d %.6f" % (connectivity, avConn[connectivity]))

	print(".")

	# GETPROCADDRESS DETECTION, not a suuuuper useful metric, but interesting to look at, different from beh. detection, cause count is total

	allCalls = nx.get_node_attributes(graphity, 'calls')
	gpaCount = 0

	for function in allCalls:
		for call in allCalls[function]:
			if 'GetProcAddress' in call[1]:
				gpaCount = gpaCount + 1

	print("Found %d calls to GetProcAddress\n." % gpaCount)

	# TODO number of nodes w strings/apis vs. nodes w/o


def dumpGraphInfoCsv(graphity, debug, allAtts, csvfile):

	# filename, filetype, filesize, codesectionsize, md5, compilationtime, addressep, sectionep, tlssections, originalfilename, sectioncount, sectiondata, functionstotal, refslocal, refsglobalvar,
	# refsunknown, apitotal, apimisses, stringsreferenced, stringsdangling, stringsnoref, ratiofunc, ratioapi, ratiostring, getproc, createthreat, memalloc

	final = []
	if os.path.isfile(csvfile):
		dumpfile = open(csvfile, 'a')
	else:
		try:
			dumpfile = open(csvfile, 'w')
			dumpfile.write("filename,filetype,filesize,codesecsize,md5,imphash,compilationtime,addressep,sectionep,tlssections,originalfilename,sectioncount,secname1,secname2,secname3,secname4,secname5,secname6,secsize1,secsize2,secsize3,secsize4,secsize5,secsize6,secent1,secent2,secent3,secent4,secent5,secent6,functionstotal,refslocal,refsglobalvar,refsunknown,apitotal,apimisses,stringsreferenced,stringsdangling,stringsnoref,ratiofunc,ratioapi,ratiostring,getprocaddress,memallocation,createthread,ctshortestpath,callbackcount,cbaveragesize,cblargestsize,stringsrefhisto")
			dumpfile.write("\n")
		except:
			print("ERROR couldn't create the csv dump file")
			return


	final.append(allAtts['filename'])
	final.append(allAtts['filetype'].replace(',',''))
	final.append(str(allAtts['filesize']))
	final.append(str(debug['xsectionsize']))
	final.append(allAtts['md5'])
	final.append(allAtts['imphash'])
	final.append(allAtts['compilationts'])
	final.append(hex(allAtts['addressep']))
	final.append(allAtts['sectionep'])
	final.append(str(allAtts['tlssections']))
	final.append(allAtts['originalfilename'])
	final.append(str(allAtts['sectioncount']))

	secStuff = allAtts['sectioninfo'][:6] + allAtts['sectioninfo'][12:18] + allAtts['sectioninfo'][24:30]
	final = final + secStuff

	final.append(debug['functions'])
	final.append(debug['refsFunctions'])
	final.append(debug['refsGlobalVar'])
	final.append(debug['refsUnrecognized'])
	final.append(debug['apiTotal'])
	final.append(debug['apiMisses'])
	final.append(debug['stringsReferencedTotal'])
	final.append(debug['stringsDanglingTotal'])
	final.append(debug['stringsNoRefTotal'])

	# Ratios: functions, APIs, strings per kilobyte of code section
	kilobytes = (float(debug['xsectionsize']) / 1000.0)
	if kilobytes > 0:
		final.append(str(float(debug['functions']) / kilobytes))
		final.append(str(float(debug['apiTotal']) / kilobytes))
		final.append(str(float(debug['stringsReferencedTotal']) / kilobytes))
	else:
		final.append('')
		final.append('')
		final.append('')

	# Counting total calls to APIs of interest
	allCalls = nx.get_node_attributes(graphity, 'calls')
	gpaCount = 0
	createThCount = 0
	memAllocs = 0

	# TODO replace this with exGraph 
	for function in allCalls:
		for call in allCalls[function]:
			if 'GetProcAddress' in call[1]:
				gpaCount = gpaCount + 1
			if 'CreateThread' in call[1]:
				createThCount = createThCount + 1
			if 'alloc' in call[1].lower():
				memAllocs = memAllocs + 1

	final.append(str(gpaCount))
	final.append(str(memAllocs))
	final.append(str(createThCount))

	# Extended version of graphity, where strings/apis are nodes by themselves + graph has a supernode
	exGraph = fetchExtendedGraph(graphity, allAtts)

	shortestPathLen = 0
	if createThCount > 0:
		#shortestPath = nx.shortest_path(exGraph, allAtts['sha1'], 'CreateThread')[1:]
		#allShortestPaths = nx.all_shortest_paths(exGraph, allAtts['sha1'], 'CreateThread')
		try:
			shortestPathLen = nx.shortest_path_length(exGraph, allAtts['sha1'], 'CreateThread')
			
		except:
			#print (exGraph.node['CreateThread'], exGraph.node[allAtts['sha1']])
			pass
	# add shortest path length as metric
	final.append(str(shortestPathLen))
		
	# Callback sizes
	callbackCount = 0
	callbackSizes = []
	callbacks = (n for n in exGraph if 'functiontype' in exGraph.node[n] and exGraph.node[n]['functiontype'] == 'Callback')
	for cback in callbacks:
		callbackCount += 1
		callbackSizes.append(exGraph.node[cback]['size'])
		
	final.append(str(callbackCount))
	avSize = 0
	maxSize = 0
	if callbackCount > 0:
		avSize = int(np.mean(callbackSizes))
		maxSize = max(callbackSizes)
	final.append(avSize)
	final.append(maxSize)
	
	
	# TODO convert stringdata to dictionary
	stringStuff = stringData(graphity, debug)
	refHistoList = []
	# slice data to get eval column
	for line in stringStuff:
		if line[1] == 'ref':
			refHistoList.append(line[3])
	
	nummy = np.array(refHistoList)
	bins = [0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.1]
	histo, bin_edges = np.histogram(nummy, bins=bins)
	histolist = []
	for hi in histo:
		histolist.append(str(hi))
	final.append(','.join(histolist))

	
	
	theline = ",".join(map(str, final)) + "\n"

	dumpfile.write(theline)
	dumpfile.close()
	
	# Dumping dedicated CSV for string eval data, per binary
	stringCsv = "output/" + csvfile + "_" + allAtts['sha1'] + ".csv"
	stringFile = open(stringCsv, 'w')
	
	for list in stringStuff:
		list[0] = list[0].replace(',', '.') 
		list[0] = list[0].replace(';', '.') 
		
	for item in stringStuff:
		content = ','.join(map(str, item)) + "\n"
		stringFile.write(content)
	stringFile.close()


