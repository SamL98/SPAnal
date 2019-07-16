'''
Walk through the class list and then then the method list
for each class, seek to the implementation and rename the method
'''

import r2pipe
import atexit
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

	return classname, methodlist_ptr+8, nmethods

def get_methodname(r, method_ptr):
	methodname_ptr = r.cmdj('pxwj 4 @ %d' % method_ptr)[0]
	methodname = r.cmd('ps @ %d' % methodname_ptr)
	if methodname: methodname = methodname.strip('\n')
	return methodname

def get_methodimp(method_ptr):
	methodimp_ptr = r.cmdj('pxwj 4 @ %d' % (method_ptr+8))[0]
	return methodimp_ptr-1


method_ind = 0
method_ind_fname = '.method_ind'

def save_method_ind():
	global method_ind
	with open(method_ind_fname, 'w') as f:
		f.write(str(method_ind))

if __name__ == '__main__':
	r = r2pipe.open('http://localhost:9090')

	classlist_start = 0x2b445f0
	classlist_end = 0x2b4aa38
	nclasses = (classlist_end - classlist_start)//4

	atexit.register(save_method_ind)
	
	if isfile(method_ind_fname):
		with open(method_ind_fname) as f:
			method_ind = int(f.read())

	class_ptrs = r.cmdj('pxwj %d @ %d' % (nclasses*4, classlist_start))

	for class_ptr in class_ptrs:
		classname, methodlist_ptr, nmethods = get_class_info(class_ptr)
		if '\\x' in classname or methodlist_ptr == 0:
			continue

		while method_ind < nmethods:
			method_ptr = methodlist_ptr + i*12
			methodname = get_methodname(method_ptr)
			methodimp = get_methodimp(method_ptr)

			if methodname is None or methodimp is None or '\\x' in methodname:
				continue

			r.cmd('s %d' % methodimp)
			r.cmd('af method.%s.%s' % (classname, methodname))

			method_ind += 1
