import r2pipe
import json
import sys
from get_classlist import get_classlist
from resolve_selectors import resolve_selectors_in_func
from resolve_receivers import resolve_receivers_in_func

def process_method(r, classname, sel, impptr, classes):
	func_name = '.'.join(['method', classname, sel])
	r.cmd('afr %s @ %d' % (func_name, impptr))

	func = r.cmdj('pdfj @ %d' % impptr)
	resolve_selectors_in_func(r, func)

	func = r.cmdj('pdfj @ %d' % impptr)
	resolve_receivers_in_func(r, func, classes)


if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('Please provide a method name')
		exit()

	r = r2pipe.open('http://localhost:9090')
	classes = get_classlist(r)

	full_methname = sys.argv[1]
	parts = full_methname.split('.')
	classname, sel = parts[0], parts[1]

	impptr = classes[classname]['methods'][sel]
	if impptr % 2 != 0:
		impptr -= 1

	process_method(r, classname, sel, impptr, classes)
