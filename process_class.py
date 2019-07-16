import r2pipe
import json
import sys
from get_classlist import get_classlist
from process_method import process_method

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('Please provide a classname')
		exit()

	r = r2pipe.open('http://localhost:9090')
	classes = get_classlist(r)
	classname = sys.argv[1]

	for sel, impptr in classes[classname]['methods'].items():
		if impptr % 2 != 0: impptr -= 1

		print(sel)
		process_method(r, classname, sel, impptr, classes)
