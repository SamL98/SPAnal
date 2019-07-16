import r2pipe
import json
from os.path import isfile

def get_class_info(r, class_ptr):
	data_ptr = r.cmdj('pxwj 4 @ %d' % (class_ptr+0x10))[0]

	if data_ptr % 2 != 0:
		data_ptr -= 1

	name_ptr = r.cmdj('pxwj 4 @ %d' % (data_ptr+0x10))[0]
	classname = r.cmd('ps @ %d' % name_ptr)
	if classname: classname = classname.strip('\n')

	methodlist_ptr = r.cmdj('pxwj 4 @ %d' % (data_ptr+0x14))[0]
	nmethods = r.cmdj('pxwj 4 @ %d' % (methodlist_ptr+4))[0]

	ivars_ptr = r.cmdj('pxwj 4 @ %d' % (data_ptr+0x1c))[0]
	nivars = r.cmdj('pxwj 4 @ %d' % (ivars_ptr+4))[0]

	return classname, methodlist_ptr+8, nmethods, ivars_ptr+8, nivars


def get_classlist(r):
	fname = 'classes.json'

	if isfile(fname):
		with open(fname) as f:
			classes = json.loads(f.read())

		return classes

	classlist_start = 0x2b445f0
	classlist_end = 0x2b4aa38
	nclasses = (classlist_end - classlist_start)//4

	class_ptrs = r.cmdj('pxwj %d @ %d' % (nclasses*4, classlist_start))
	classes = {}

	for class_ptr in class_ptrs:
		classname, methodlist_ptr, nmethods, ivars_ptr, nivars = get_class_info(r, class_ptr)
		
		classes[classname] = {}
		classes[classname]['methods'] = {}
		classes[classname]['ivars'] = {}

		methods = r.cmdj('pxwj %d @ %d' % (nmethods*12, methodlist_ptr))

		for i in range(0, len(methods), 3):
			selname = r.cmd('ps @ %d' % methods[i])
			if selname is None:
				continue

			selname = selname.strip('\n')
			impptr = methods[i+2]
			classes[classname]['methods'][selname] = impptr

		ivars = r.cmdj('pxwj %d @ %d' % (nivars*20, ivars_ptr))

		for i in range(0, len(ivars), 5):
			ivarname = r.cmd('ps @ %d' % ivars[i+1])
			if ivarname is None:
				continue

			ivarname = ivarname.strip('_\n')
			ivartype = r.cmd('ps @ %d' % ivars[i+2])
			if ivartype is None:
				continue

			ivartype = ivartype.strip('@"<>\n')
			classes[classname]['ivars'][ivarname] = ivartype

	with open(fname, 'w') as f:
		f.write(json.dumps(classes))

	return classes


if __name__ == '__main__':
	r = r2pipe.open('http://localhost:9090')
	get_classlist(r)
