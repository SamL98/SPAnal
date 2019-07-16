from graphviz import Digraph
import sys
from os.path import isfile
import json

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('Please provide a class name')
		exit()

	classname = sys.argv[1]
	call_graph_fname = 'call_graphs/%s.json' % classname
	if not isfile(call_graph_fname):
		print('Call graph does not exist')
		exit()

	with open(call_graph_fname) as f:
		calls = json.loads(f.read())

	dot = Digraph(comment=classname, engine='fdp')
	methods = []

	for methname, methcalls in calls.items():
		if not methname in methods:
			methods.append(methname)
			dot.node(methname)

		for called_methname in methcalls:
			if not called_methname in methods:
				methods.append(called_methname)
				dot.node(called_methname)

			dot.edge(methname, called_methname)

	dot.render('call_graphs/%s.gv' % classname, view=True)
