#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#:name: fgpwd.py
#:auth: John Lehr; slo.sleuth@gmail.com
#:lic : GPL3

#:hist: 1.2 added help and filename path handling
#:hist: 1.1 changed to uppercase output 

version = 1.2

import sys, hashlib
import argparse, os.path

def get_md5(fname):
	'''(str) -> str
	
	Return md5 hash embedded in Furious Gold archive filename
	
	>>> get_hash('MEMORY_DUMP_OT-5020N_f4bf515a0dfffdf3cbca165d7c72b25e.osp')
	f4bf515a0dfffdf3cbca165d7c72b25e
	'''
	
	fname = os.path.basename(fname)
	fname = fname.rstrip('.osp')
	fname = fname.split('_')
	md5 = fname[3]
	
	if len(md5) != 32:
	    print('This Does not appear to be Furious Gold dump file')
	    sys.exit(1)
	return md5

def main():
	parser = argparse.ArgumentParser(description='Extract password from \
		Furious Gold archive.')
	parser.add_argument('FILE', help='Furious Gold archive file')
	parser.add_argument('--version', action='version',
        version='%(prog)s v.' + str(version))
	
	args = parser.parse_args()

	# extract md5 from filename
	md5 = get_md5(args.FILE)
	
	# calculate sha1 of md5 digest
	md5 = bytes(md5, 'utf-8')
	sha1 = hashlib.sha1(md5).hexdigest()
	
	# print sha1 digest to stdout
	print('Password:', sha1.upper())

if __name__ == '__main__':
    main()
