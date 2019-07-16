import r2pipe
import json
import sys
from get_classlist import get_classlist
from process_method import process_method


def get_calls(r, classname, func_disasm):
	curr_instances = { 'self': classname }
	calls = []

	for inst in func_disasm[1:]:
		inst_disasm = inst['disasm']
		if not 'blx fcn.objc_msgSend' in inst_disasm and not 'blx sym.imp.objc_msgSend' in inst_disasm:
			continue

		r.cmd('s %d' % inst['offset'])
		sel_cmt = r.cmd('CC.').strip('\n')
		if not '(' in sel_cmt:
			continue

		terms = sel_cmt.split(' ')
		receiver, sel = tuple(terms[0].split('.'))
		if not receiver in list(curr_instances.keys()):
			continue

		rettype = terms[1].strip('()')
		curr_instances[sel.strip(':')] = rettype

		calls.append('.'.join([curr_instances[receiver], sel]))

	return calls


if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('Please provide a classname')
		exit()

	r = r2pipe.open('http://localhost:9090')
	classes = get_classlist(r)
	classname = sys.argv[1]

	calls = {}

	for sel, impptr in classes[classname]['methods'].items():
		if impptr % 2 != 0: 
			impptr -= 1

		func_name = '.'.join(['method', classname, sel])
		func = r.cmdj('pdfj @ %d' % impptr)

		if func is None:
			continue

		func_calls = get_calls(r, classname, func['ops'])
		calls['.'.join([classname, sel])] = func_calls

	with open('call_graphs/%s.json' % classname, 'w') as f:
		f.write(json.dumps(calls))
