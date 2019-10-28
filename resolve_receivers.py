import base64 as b64
from resolve_selectors import resolve_selectors_in_func
import sys
import r2pipe
import json

def resolve_receivers_in_func(r, func, classes, classname=None):
	if func is None:
		return

	func_disasm = func['ops']
	
	if classname is None:
		full_methname = func['name']
		classname = full_methname.split('.')[1]

	curr_instances = { classname: 'self' }
	sel2class = { sel: classname for sel in classes[classname]['methods'].keys() }

	for inst in func_disasm[1:]:
		inst_disasm = inst['disasm']

		if not 'blx fcn.objc_' in inst_disasm and not 'blx sym.imp.objc_' in inst_disasm and not 'blx objc_' in inst_disasm:
			continue

		if 'release' in inst_disasm:
			# handle release
			continue

		if not 'msgSend' in inst_disasm:
			continue

		if not 'comment' in inst:
			continue

		sel = str(b64.b64decode(inst['comment']))[2:-1]

		if not sel in sel2class:
			continue

		receiver = sel2class[sel]
		instance = receiver

		if receiver in curr_instances:
			instance = curr_instances[receiver]

		rettype = None

		if sel in classes[receiver]['ivars']:
			rettype = classes[receiver]['ivars'][sel]

			if len(rettype) > 2 and rettype[0] == '<' and rettype[-1] == '>' or not rettype in classes:
				rettype = rettype[1:-1] + 'Impl'

			if not rettype in classes:
				rettype += 'ementation'

			if rettype in classes:
				curr_instances[rettype] = sel

				for rsel in classes[rettype]['methods'].keys():
					sel2class[rsel] = rettype

		r.cmd('s %d' % inst['offset'])
		r.cmd('CC-')

		cmt = instance + '.' + sel

		if not rettype is None:
			cmt = '%s (%s)' % (cmt, rettype)

		r.cmd('CC %s' % cmt)


if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('Please provide a function name')
		exit()

	classname = None
	if len(sys.argv) > 2:
		classname = sys.argv[2]

	with open('classes.json') as f:
		classes = json.loads(f.read())

	r = r2pipe.open('http://localhost:9090')
	func = r.cmdj('pdfj @ %s' % sys.argv[1])
	resolve_receivers_in_func(r, func, classes, classname=classname)

