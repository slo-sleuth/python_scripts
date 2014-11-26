#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#: Title    : AndroidUnlocker.py
#: Date     : 2014-11-04
#: Author   : "John Lehr" <slo.sleuth@gmail.com>
#: Version  : 1.4
#: License  : GPLv2 <http://www.gnu.org/licenses/gpl-2.0.html>
#: Desc     : scan Android binary dump for gesture/password keys
#: Depends  : python3-tk

#: Copyright: 2014 "John Lehr" <slo.sleuth@gmail.com>

# 2014-11-04    v1.4  General code cleanup, truncated salt detection
# 2014-03-24    v1.3  Bugfix for salt detection, added field length reading
# 2013-12-18    v1.2  Bugfix in password dictionary
# 2013-12-02    v1.1  Added hashcat hints
# 2013-12-02    v1.0  Added file selection dialogs
# 2013-11-27    v1.0  Initial release

version = "1.4"

import argparse, sys, re, mmap, sqlite3, itertools
from binascii import hexlify
from datetime import datetime
from struct import pack
from os import path
from tkinter import filedialog

def calculate_spare(page_size):
    '''(int) -> int

    Calculate spare are size based in NAND flash page size.

    >>> calculate_spare(512)
    16
    >>> calculate_spare(2048)
    64
    '''
    page_size = validate_page_size(page_size)
    return page_size // 512 * 16

def find_gesture_hash(data):
    '''(bytes) -> str

    Regex search of data for 20b SHA1 value at the beginning of the data
    block followed by a series of \x00.  Return the SHA1 hash value.

    >>> find_gesture_hash(data_block)
    '30c70ca3ed4b3c56c326937024a5fea4f8c41360'
    '''

    gesture_regex = re.compile(b'([\x01-\xFF]{20})\x00{108}')
    match = gesture_regex.match(data)
    if match:
        return hexlify(match.group(1)).decode()

def find_password_hash(data):
    '''(bytes) -> tuple
    Return a tuple of SHA1, MD5 hash from data where the hashes occur at
    the beginning of the data and are followed by nulls.  MD5 may be
    missing the event of a SAMSUNG complex hash.

    Precondition: data is at least the first 128 bytes of a NAND flash
    memory page.

    >>> find_password_hash(data_block)
    ('F07450568EEDCA7A4DC4B8700A96C2FBB3FA6E9C', '7A27D7E1EE84F99DF6F10C511B5B26B6')
    >>> find_password_hash(data_block)
    ('F07450568EEDCA7A4DC4B8700A96C2FBB3FA6E9C', NONE)
    '''

    passwd_regex = re.compile(b'([0-9A-F]{40})([0-9A-F]{32})?\x00{56}')
    match = passwd_regex.match(data)
    if match:
        sha1 = match.group(1).decode()
        md5  = match.group(2)
        if md5:
            md5 = md5.decode()
        return sha1, md5
    return

def find_salt(data, offset):
    '''(bytes) -> int, int

    Search bytes for salt values from sqlite memory pages and return page offset
    and salt value.

    >>> find_salt(binary_data)
    (594, -4561001319859322107)
    '''

    salt = re.compile(b'(lockscreen\.password_salt)(\-?[0-9]+)')
    match = salt.search(data)

    if match:
        salt = match.group(2)
        offset = match.start(2) + offset

        # validate salt from record header length value
        salt_len = data[match.start(1)-1]
        salt_len = (salt_len - 13) // 2

        if salt_len != len(salt):
            print('\tTruncated salt found at offset {}'.format(offset))
            return

        return int(salt), offset

def gesture_lookup(sha1, db):
    '''(str, file obj) -> list of int

    Lookup sha1 in db and return pattern in a list.

    Precondition: db is a sqlite database created with the
    GenerateAndroidGesturePatternTable.py script.

    >>> gesture_lookup('30c70ca3ed4b3c56c326937024a5fea4f8c41360', db)
    [3, 0, 1, 6]
    '''

    conn = sqlite3.connect(db)
    cursor = conn.cursor()

    cursor.execute('SELECT pattern FROM RainbowTable WHERE hash = "{}"'.
        format(sha1))
    pattern = cursor.fetchone()
    if pattern:
        return pattern[0]

def get_time():
    return str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

def validate_page_size(size):
    '''(int) -> int

    Check that size is a multiple of 512

    >>> validate_page_size(1024)
    1024
    >>> validate_page_size(1025)
    ERROR: 1025 not a valid page size'''

    if size % 512 == 0:
        return size
    else:
        print('ERROR: {} not a valid page size'.format(size))
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='Find and Android lockscreen hashes and password salt.',
        epilog='This application searches for SHA1 and MD5 hash values in raw \
        NAND dumps and, if appropriate, queries a SQLite rainbow table for \
        matching gestures.  A rainbow table such as \
        "AndroidGesturePatternTable.sqlite" rainbow table is required for \
        gesture pattern lookup.  Incorrect page size can lead to truncated \
        salt results.')

    parser.add_argument('BIN', help='Raw data from Android NAND Flash')
    parser.add_argument('-g', '--gesture', dest='gesture', action='store_true',
        help='Search for gesture.key and lookup pattern in DB')
    parser.add_argument('-p', '--password', dest='password', action='store_true',
        help='Search for password.key hash and salt')
    parser.add_argument('-s', '--size', dest='size', metavar='N', default=2048,
        type=int, help='NAND flash page size, default=2048')
    parser.add_argument('-S', '--spare', dest='spare', action='store_true',
        help='Add spare area to page size based on page size')
    parser.add_argument('--version', action='version',
        version='%(prog)s v.' + version)

    args = parser.parse_args()

    # check user arguments
    page_size = validate_page_size(args.size)
    block_sz = args.size + args.spare

    if not args.gesture and not args.password:
        print('\nerror: Search type not specified.  Select -g gesture or \
-p password.')
        sys.exit(1)

    # prompt for BIN file if not provided by user
    if not path.isfile(args.BIN):
        args.BIN = filedialog.askopenfilename(title='Select BIN file')

    # locate rainbow table for gesture lookup
    if args.gesture:
        # first check in current path of script
        db = path.split(sys.argv[0])[0] + '/AndroidGesturePatternTable.sqlite'

        # if not in script path, raise a file selection box
        if not path.isfile(db):
            db = filedialog.askopenfilename(title='Select Database')
            if not db:
                print('ERROR: No database file selected')
                sys.exit(1)

    print('\nSearch started at {}'.format(get_time()))
    print('\nProcessing:')

    # open file and process on page at a time
    with open(args.BIN, 'r+b') as f:
        #mm = mmap.mmap(f.fileno(), 0)
        mm = f.read()

    gesture_dict  = {}
    password_dict = {}
    salt_dict     = {}

    for offset in range(0, len(mm), block_sz) :
        block = mm[offset: offset + block_sz]

        if args.password:
            password = find_password_hash(block[:128])
            if password:
                if password in password_dict.keys():
                    password_dict[password].append(offset)
                else:
                    password_dict[password] = [offset]
                    print('\tUnique password.key found at offset {}'.
                        format(offset))
            salt = find_salt(block, offset)
            if salt:
                salt, offset = salt
                if salt in salt_dict.keys():
                    salt_dict[salt].append(offset)
                else:
                    salt_dict[salt] = [offset]
                    print('\tUnique salt found at offset {}'.format(offset))

        if args.gesture:
            gesture = find_gesture_hash(block[:128])
            if gesture:
                if gesture in gesture_dict.keys():
                    gesture_dict[gesture].append(offset)
                else:
                    gesture_dict[gesture] = [offset]
                    print('\tPossible gesture.key found at offset {}'.
                        format(offset))

    print('\nSearch completed at {}'.format(get_time()))

    # print search results
    print('\nSearch Results:')
    for password in password_dict.keys():
        print()
        sha1 = password[0]
        md5 = password[1]
        print('SHA1:\t\t{}'.format(sha1))
        if not md5 == '\x00' * 32:
            print('MD5:\t\t{}'.format(md5))
        offsets = ', '.join(str(x) for x in password_dict[password])
        print('Offset(s):\t{}'.format(offsets))

        # print hashcat hint
        if md5:
            print('=== [HINT] === \tStandard password.key, use MD5 with hashcat mode -m10')
        else:
            print('=== [HINT] === \tSamsung complex hash, use SHA1 with hashcat mode -m5800')

    for salt in salt_dict.keys():
        print()
        salt_hex = hexlify(pack('>q', salt)).decode()
        print('SALT: \t\t{}\nSALT Hex:\t{}'.format(salt, salt_hex))
        offsets = ', '.join(str(x) for x in salt_dict[salt])
        print('Offset(s):\t{}'.format(offsets))

    message = 0
    for gesture in gesture_dict.keys():
        pattern = gesture_lookup(gesture, db)
        if pattern:
            print()
            print('gesture.key: \t{}\nPattern: \t{}'.format(gesture, pattern))
            offsets = ', '.join(str(x) for x in gesture_dict[gesture])
            print('Offset(s):\t{}'.format(offsets))
            message = 1
        elif not message == 1:
            message = 2

    # print message if no password.key hash found
    if args.password and not password_dict:
        print()
        print('No password.key located in ' + args.BIN)

    # print message if no valid gesture.key hash found
    if message == 2:
        print()
        print('No valid gesture.key found in ' + args.BIN)

    return 0
if __name__ == '__main__':
    main()
