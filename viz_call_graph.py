from graphviz import Digraph
import sys
import os
from os.path import isfile
import json

if __name__ == '__main__':
	if len(sys.argv) < 2:
		classnames = [f[:f.index('.json')] for f in os.listdir('call_graphs') if f.endswith('.json')]
	else:
		classnames = sys.argv[1:]

	title = '_'.join(classnames[:min(3, len(classnames))])
	dot = Digraph(comment=title, engine='fdp')
	methods = []

	for classname in classnames:
		call_graph_fname = 'call_graphs/%s.json' % classname
		if not isfile(call_graph_fname):
			print('Call graph does not exist')
			exit()

		with open(call_graph_fname) as f:
			calls = json.loads(f.read())

		for methname, methcalls in calls.items():
			methname = methname.strip(':').replace(':', '-')

			if not methname in methods:
				methods.append(methname)
				dot.node(methname)

			for called_methname in methcalls:
				called_methname = called_methname.strip(':').replace(':', '-')
				if not called_methname in methods:
					methods.append(called_methname)
					dot.node(called_methname)

				dot.edge(methname, called_methname)

	dot.render('call_graphs/%s.gv' % title, view=True)
