from pydotplus.graphviz import Node
import networkx as nx
from networkx.readwrite import json_graph
import json
import os

from graphityOps import fetchExtendedGraph, fetchExtendedSubgraph, fetchBehaviorgadgetGraph, fetchSpecialGraph, fetchD3Graph
import graphityFunc


def dumpGml(graphity, allAtts):

	gmlData = graphity.copy()
	
	# gotta fix the lists of lists to list for gml, otherwise incompatible
	for node in gmlData.node:
		for attr in gmlData.node[node]:
			if type(gmlData.node[node][attr]) == list:
				listOfLists = gmlData.node[node][attr]
				seList = map(' '.join, listOfLists)
				gmlData.node[node][attr] = ' | '.join(seList)
				
	nx.write_gml(gmlData, "output/callgraph.gml")

	
	# generates GML for graph containing behavior gadgets, no strings/apis
	behaviorGraph = fetchBehaviorgadgetGraph(graphity)
	nx.write_gml(behaviorGraph, "output/behaviorgaddgets.gml")
	
	# generates GML for special gadgets, handed over as list, searched for within API calls
	allocGraph = fetchSpecialGraph(graphity, ['alloc', 'mem'])
	nx.write_gml(allocGraph, "output/allocgadgets.gml")
	
	# generates GML for extended Graph, where APIs and strings are dedicated nodes
	extendedGraph = fetchExtendedGraph(graphity, allAtts)
	nx.write_gml(extendedGraph, "output/extendedgraph.gml")


# dumps the gml data for a subgraph starting at [address] with APIs/strings as dedicated nodes
def dumpGmlSubgraph(graphity, address):
	if address in graphity:
		subgraph = fetchExtendedSubgraph(graphity, address)
		gmlfile = "output/subgraph_" + address + ".gml"
		nx.write_gml(subgraph, gmlfile)		

	
# Graph plotting with pydotplus from within NetworkX, format is dot
def graphvizPlot(graphity, allAtts):

	pydotMe = nx.drawing.nx_pydot.to_pydot(graphity)
	for node in pydotMe.get_nodes():

		# get node address to be able to fetch node directly from graphity to preserve data types of attributes
		nodeaddr = node.to_string().split()[0].replace('\"', '')
		finalString = ''

		if node.get('calls') != '[]' or node.get('strings') != '[]':
		
			finalList = []
			
			# fetching string and call lists directly from graphity
			callList = graphity.node[nodeaddr]['calls']
			stringList = graphity.node[nodeaddr]['strings']
			
			for item in callList:
				finalList.append(str(item[0]) + ": [C] " + str(item[1]))
			for otem in stringList:
				finalList.append(str(otem[0]) + ": [S] " + str(otem[1]))
			
			finalList.sort()
			finalString = '\n'.join(finalList)
			
		if node.get('functiontype') == 'Export':
			label = "Export " + nodeaddr + node.get('alias')
			label = label + "\n" + finalString
			node.set_fillcolor('skyblue')
			node.set_style('filled,setlinewidth(3.0)')
			node.set_label(label)

		elif node.get('functiontype') == 'Callback':
			label = "Callback " + nodeaddr + "\n" + finalString
			node.set_fillcolor('darkolivegreen1')
			node.set_style('filled,setlinewidth(3.0)')
			node.set_label(label)
		
		elif node.get('functiontype').startswith('Indirect'):
			label = "IndirectRef " + nodeaddr + "\n" + finalString
			node.set_fillcolor('lemonchiffon1')
			node.set_style('filled,setlinewidth(3.0)')
			node.set_label(label)

		elif finalString != '':
			finalString = nodeaddr + "\n" + finalString
			node.set_fillcolor('lightpink1')
			node.set_style('filled,setlinewidth(3.0)')
			node.set_label(finalString)

	print(finalString)
	graphinfo = "SAMPLE " + allAtts['filename'] + "\nType: " + allAtts['filetype'] + "\nSize: " + str(allAtts['filesize']) + "\nMD5: " + allAtts['md5'] + "\nImphash:\t\t" + allAtts['imphash'] + "\nCompilation time:\t" + allAtts['compilationts'] + "\nEntrypoint section:\t" + allAtts['sectionep']
	print(graphinfo)
	titleNode = Node()
	titleNode.set_label(graphinfo)
	titleNode.set_shape('rectangle')
	titleNode.set_fillcolor('grey')
	titleNode.set_style('filled')
	pydotMe.add_node(titleNode)

	graphname = allAtts['filename'] + ".png"
	print(graphname)
	try:
		# TODO pydotplus throws an error sometimes (Error: /tmp/tmp6XgKth: syntax error in line 92 near '[') look into pdp code to see why
		out_filename = os.path.join(os.path.abspath(os.path.dirname(__file__)), graphname)
		print(out_filename)
		pydotMe.write_png(out_filename)
	except Exception as e:
		print("ERROR drawing graph")
		print(str(e))


# Experimental Javascript InfoVis Tk data generation
def dumpJsonForJit(graphity, indent=None):

	json_graph = []
	for node in graphity.nodes():
		json_node = {
			'id': node,
			'name': node
		}
		# node data
		json_node['data'] = graphity.node[node]
		
		# Style
		if graphity.node[node].get('calls') != []:
			json_node['data']['$color'] = '#FFFF00' # yellow
			
		if graphity.node[node].get('functiontype') == 'Callback':
			json_node['data']['$dim'] = 8
			json_node['data']['$type'] = 'square'
			json_node['data']['$color'] = '#FF0080' # pink
			json_node['name'] = node + " Callback"
		
		if graphity.node[node].get('functiontype') == 'Export':
			json_node['data']['$dim'] = 8
			json_node['data']['$type'] = 'square'
			json_node['data']['$color'] = '#3ADF00' # green
			json_node['name'] = node + " Export"

		
		# adjacencies
		if graphity[node]:
			json_node['adjacencies'] = []
			
			for neighbour in graphity[node]:
				adjacency = {'nodeTo': neighbour}
				# adjacency data
				adjacency['data'] = graphity.edge[node][neighbour]
				json_node['adjacencies'].append(adjacency)
		#print (json_node)
		json_graph.append(json_node)

	#print(json.dumps(json_graph, indent=indent))
	return json.dumps(json_graph, indent=indent)


def dumpJsonForD3(graphity):

	# TODO transform graph to visualization needs
	
	d3graph = fetchD3Graph(graphity)

	data = json.dumps(json_graph.node_link_data(d3graph), indent=2)
	d3file = "d3js/d3.json"
	d3handle = open(d3file, 'w')
	d3handle.write(data)
	d3handle.close()