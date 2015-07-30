#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#: Title    : AndroidUnlocker.py
#: Date     : 2015-06-06
#: Author   : "John Lehr" <slo.sleuth@gmail.com>
#: Version  : 2.0
#: License  : GPLv2 <http://www.gnu.org/licenses/gpl-2.0.html>
#: Desc     : scan Android binary NAND dump for gesture/password keys
#: Depends  : none

#: Copyright: 2015 "John Lehr" <slo.sleuth@gmail.com>

import argparse
import sys
import array
import itertools
import hashlib
import re
from binascii import hexlify
from datetime import datetime
from struct import pack

version = '2.0'
pwd_regex = re.compile(b'([0-9A-F]{40})([0-9A-F]{32})?')
salt_regex = re.compile(b'lockscreen.password_salt(\-?[0-9]+)')

class NandPage:
    '''Class to search NAND pages from Android devices for hashes and salt
    values related to the pattern, pin, and password screen locks.'''

    def __init__(self, data, offset=0):
        self.data = data
        self.offset = offset
        self.pattern = None
        self.sha1 = None
        self.md5  = None
        self.salt = None
        self.salthex = None
        self.isgesture = None
        self.ispassword = None
        self.issalt = None
        self.istruncatedsalt = None

    def __str__(self):
        '''Return string representation of NandPage object.'''
        if self.isgesture:
            text = 'gesture.key   at offset {}: {}'.format(self.offset, 
                    self.sha1)
        if self.ispassword:
            text = 'password.key  at offset {}: {}'.format(self.offset,
                    self.sha1 + self.md5)
        if self.issalt:
            text = 'password_salt at offset {}: {}'.format(self.offset, 
                    self.salt)
        if self.istruncatedsalt:
            text = 'truncated salt at offset {}: {}'.format(self.offset,
                    self.salt)
        return text

    def get_gesture(self, patterns):
        '''Set sha1, pattern, and isgesture attributes if page contains a
        gesture.key hash.  Hash is validated by patterns dictionary.'''
        # check for 20 byte hash followed by nulls
        if self.data[:20] != b'\x00' * 20 and self.data[20:40] == b'\x00' * 20:
            # if present, possible gesture.key sha1 hash.  Validate with
            # patterns dictionary
            sha1 = hexlify(self.data[:20]).decode()
            pattern = patterns.get(sha1, None)
            # if valid, update attributes
            if pattern:
                self.sha1 = sha1
                self.pattern = pattern
                self.isgesture = True
        return

    def get_password(self):
        '''Set sha1, md5 and ispassword if page contains a password.key hash.
        '''
        # check for sequence of 56 nulls starting at offset 72
        if self.data[:72] != b'\x00' * 72 and self.data[72:80] == b'\x00' * 8:
            # if present, possible password.key sha1|md5 in first 72 bytes
            match = pwd_regex.match(self.data[:72])
            # if ascii hexadecimal values are detected, update attributes
            if match:
                self.sha1 = match.group(1).decode()
                self.md5  = match.group(2)
                self.ispassword = True
                # Don't update self.md5 for Samsung complex hash (no MD5
                # present in passwork.key)
                if self.md5:
                    self.md5 = self.md5.decode()
                else:
                    self.md5 = ''
        return

    def get_salt(self):
        '''Set salt, salthex, and issalt attributes if page contains a password
        salt.  Offset is updated from page start to salt insteger start.'''
        # salt is contained in SQLite database.  The value is preceded by
        # name 'lockscreen.password_salt'
        match = salt_regex.search(self.data)
        # If salt validated detected, update attributes
        if match:
            salt = match.group(1)
            salt_len = self.data[match.start(0)-1]
            salt_len = (salt_len - 13) // 2
            if len(salt) == salt_len:
                self.salt = int(salt)
                self.offset = match.start(1) + self.offset
                self.salthex = hexlify(pack('>q', self.salt)).decode().\
                               lstrip('0')
                self.issalt = True
            else:
                self.istruncatedsalt = True
                self.salt = int(salt)
        return

def build_pattern_dict():
    '''Return a dictionary of hash:pattern items for decoding gesture.key
    sha1 hash values.'''

    # Pattern is made of points 0-8
    points = [i for i in range(0,9)]

    # create a dictionary of pattern hashes
    patterns = dict()
    for length in range(4, 10):
        for pattern in itertools.permutations(points, length):
            pattern_bytes = array.array('B', pattern).tobytes()
            sha1 = hashlib.sha1()
            sha1.update(pattern_bytes)
            patterns[sha1.hexdigest()] = pattern

    return patterns

def calculate_spare(page_size):
    '''Return int representing proper NAND spare area for page_size.'''
    page_size = validate_page_size(page_size)
    return page_size // 512 * 16

def get_time():
    '''Return the current date and time in YYYY-MM-DD hh:mm:ss format.'''
    return str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

def validate_page_size(size):
    '''Return size if divisible by 512 or exit.'''
    if size % 512 == 0:
        return size
    else:
        print('ERROR: {} not a valid page size'.format(size))
        sys.exit(1)

def add_value(dictionary, key, value):
    '''Add new key:[value] to dictionary if not already present.  Append value
    to existing list is key is present.'''
    if key in dictionary.keys():
        dictionary[key].append(value)
    else:
        dictionary[key] = [value]

def main():
    parser = argparse.ArgumentParser(
        description='Find and Android lockscreen hashes and password salt.',
        epilog='This application searches for SHA1 and MD5 hash values in raw \
        NAND dumps and, if appropriate returns matching gestures.  Incorrect \
        page size can lead to truncated salt results.')

    parser.add_argument('BIN', help='Raw data from Android NAND Flash')
    parser.add_argument('-g', '--gesture', dest='gesture', action='store_true',
        help='Search for gesture.key and print pattern')
    parser.add_argument('-p', '--password', dest='password',
        action='store_true', help='Search for password.key hash and salt')
    parser.add_argument('-n', '--no_progress', dest='progress',
        action='store_false', default=True, help='Show progress of search')
    parser.add_argument('-s', '--size', dest='size', metavar='N', default=2048,
        type=int, help='NAND flash page size, default=2048')
    parser.add_argument('-S', '--spare', dest='spare', action='store_true',
        help='Add spare area to page size based on page size')
    parser.add_argument('--version', action='version',
        version='%(prog)s v.' + version)

    args = parser.parse_args()
    if not args.gesture and not args.password:
        print('error: search type not specified')
        sys.exit(1)

    #open file and cal
    nand = open(args.BIN, 'rb')
    nand.size = nand.seek(0,2)
    nand.seek(0)

    # ensure user entered a proper page size, else exit
    #validate_page_size(args.size)

    args.size = validate_page_size(args.size)
    nand.pagecount = nand.size//args.size

    # print search information
    print('\nSearching file:\t', nand.name)
    print('Page size:\t', args.size)

    # add spare area if user selected
    if args.spare:
        spare = calculate_spare(args.size)
        args.size = args.size + spare
        print('Spare area:\t', spare, 'bytes added to page')
    if args.password:
        print('Search type:\t password.key')
    if args.gesture:
        print('Search type:\t gesture.key')
        print('\nBuilding gesture dictionary: ', end='')
        patterns = build_pattern_dict()
        print(len(patterns), 'patterns')


    print('\nSearch started:', get_time(), '\n')

    # loop through NAND pages
    count = 1
    results = dict()
    while count <= nand.pagecount:
        pageoffset = nand.tell()
        page = NandPage(nand.read(args.size), pageoffset)

        # show progress
        if args.progress:
            text = '\rProcessing page {:,} of {:,} '.format(count,
                    nand.pagecount)
            sys.stdout.write(text)
        #sys.stdout.flush()

        if args.gesture:
            page.get_gesture(patterns)
            if page.isgesture:
                add_value(results, page.sha1, (page, page.offset))
                text = '\r  {}\n'.format(str(page).split(':')[0])
                sys.stdout.write(text)
                continue
        if args.password:
            page.get_password()
            if page.ispassword:
                add_value(results, page.sha1, (page, page.offset))
                text = '\r  {}\n'.format(str(page).split(':')[0])
                sys.stdout.write(text)
                continue
            page.get_salt()
            if page.issalt:
                add_value(results, page.salt, (page, page.offset))
                text = '\r  {}\n'.format(str(page).split(':')[0])
                sys.stdout.write(text)
            if page.istruncatedsalt:
                text = '\r  {}\n'.format(str(page).split(':')[0])
                sys.stdout.write(text)
        count += 1

    print('\r', ' '* 72)
    print('Search stopped:', get_time())
    print()

    # print results

    print('RESULTS:\n')
    if not results:
        print('No lockscreen data found.\n')
        sys.exit(0)
    for result in results.values():
        offsets = []
        for page, offset in result:
            offsets.append(offset)
        if page.isgesture:
            print('gesture.key')
            print('SHA1 Hash:\t', page.sha1)
            print('Pattern:  \t', ', '.join(str(p) for p in page.pattern))
        if page.ispassword:
            print('password.key')
            print('SHA1 Hash:\t', page.sha1)
            print('MD5 Hash: \t', page.md5)
        if page.issalt:
            print('lockscreen.password_salt')
            print('Salt:    \t', page.salt)
            print('Salt Hex:\t', page.salthex)
        print('Offset(s):\t', ', '.join(str(offset) for offset in offsets))

        if page.ispassword and page.md5:
            print('=== [HINT] ===\t Standard password.key, use MD5 with \
hashcat mode -m10')
        if page.ispassword and not page.md5:
            print('=== [HINT] ===\t Samsung complex hash, use SHA1 with \
hashcat mode -m5800')
        print()

if __name__ == '__main__':
    main()
