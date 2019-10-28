import json
import os
from os.path import join
import sys


def resolve_call_stack(call_graph, callee_methname, call_stack):
	for caller_methname, func_calls in call_graph.items():
		if callee_methname in func_calls:
			tmp_call_stack = call_stack.copy()
			tmp_call_stack.append(caller_methname)
			resolve_call_stack(call_graph, caller_methname, tmp_call_stack)

	print('\n'.join(call_stack) + '\n')


if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('Please provide a method to resolve the call stack')
		exit()

	call_graph = {}
	for fname in os.listdir('call_graphs'):
		if not fname.endswith('.json'): continue

		with open(join('call_graphs', fname)) as f:
			func_calls = json.loads(f.read())

		call_graph.update(func_calls)

	full_methname = sys.argv[1]
	resolve_call_stack(call_graph, full_methname, [])
