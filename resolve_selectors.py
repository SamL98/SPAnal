'''
To resolve selector, find all instances of: blx objc_msgSend
and make the following assumptions:

1) The selector is set up within the previous 100 bytes
2) The selector is set up like so:

		movw r0, word
		movt r0, word
		add r0, pc
		lrl r1, [r0]

   where the ordering of the movw and mot instructions are interchangeable.
'''
import re
import sys
import r2pipe
import argparse

def resolve_selectors_in_func(r, func):
	if func is None:
		return

	func_disasm = func['ops']
	reg2sel = {}
	reg2off = {}

	bw_mov_re = re.compile('movw ([a-z])([a-z0-9]), 0x[a-f0-9]{1,4}')
	tw_mov_re = re.compile('movt ([a-z])([a-z0-9]), 0x[a-f0-9]{1,4}')
	pc_add_re = re.compile('add ([a-z])([a-z0-9]), pc')
	reg_load_re = re.compile('ldr(.w)? ([a-z])([a-z0-9]), \[([a-z])([a-z0-9])\]')
	r1_mov_re = re.compile('mov r1, ([a-z])([a-z0-9])')

	for inst in func_disasm:
		try:
			disasm = inst['disasm']
			op = inst['opcode']
		except KeyError:
			continue

		# go forward until msgSend, building up mapping of registers to selrefs
		if 'blx' in disasm and 'objc_msgSend' in disasm and 'r1' in reg2sel:
			r.cmd('s %d' % inst['offset'])
			r.cmd('CC-')
			r.cmd('CC %s' % reg2sel['r1'])
			continue

		bw_match = bw_mov_re.match(op)
		tw_match = tw_mov_re.match(op)

		if bw_match or tw_match:
			parts = op.split(' ')
			reg = parts[1].strip(',')

			if not reg in reg2off: reg2off[reg] = {}
			if 'offset' in reg2off[reg]: del reg2off[reg]['offset']

			k = 'bw'
			if tw_match: k = 'tw'
			reg2off[reg][k] = int(parts[-1], 16)

		elif pc_add_re.match(op):
			parts = op.split(' ')
			reg = parts[1].strip(',')
			off = inst['offset'] + 4

			if reg in reg2off and 'tw' in reg2off[reg] and 'bw' in reg2off[reg]:
				roff = reg2off[reg]
				reg2off[reg]['offset'] = ((roff['tw'] << 16) | roff['bw']) + off

		elif reg_load_re.match(op):
			parts = op.split(' ')
			dst = parts[1].strip(',')
			src = parts[-1][1:-1]

			if src in reg2off and 'offset' in reg2off[src]:
				sel_offset = r.cmdj('pxwj 4 @ %s' % reg2off[src]['offset'])[0]
				sel = r.cmd('ps @ %d' % sel_offset).strip('\n')
				reg2sel[dst] = sel

		elif r1_mov_re.match(op):
			reg = op.split(', ')[-1]
			
			if reg in reg2sel:
				reg2sel['r1'] = reg2sel[reg]

		elif not op.startswith('str'):
			try: reg = op.split(' ')[1].strip(',')
			except IndexError: continue
			if len(reg) == 2 and reg in reg2off: del reg2off[reg]


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('--impptr', dest='impptr', type=int, default=None)
	parser.add_argument('--func_name', dest='func_name', type=str, default=None)
	args = parser.parse_args()

	impptr = None
	func_name = None

	if args.impptr:
		impptr = args.impptr
		if impptr % 2 != 0: impptr -= 1
		func_name = 'func.%08x' % impptr
		impptr = hex(impptr)
	elif args.func_name:
		func_name = args.func_name
		impptr = func_name
	else:
		print('Please provide an imp pointer or func name')
		exit()

	r = r2pipe.open('http://localhost:9090')
	r.cmd('afr %s @ %s' % (func_name, impptr))

	func = r.cmdj('pdfj @ %s' % impptr)
	resolve_selectors_in_func(r, func)

