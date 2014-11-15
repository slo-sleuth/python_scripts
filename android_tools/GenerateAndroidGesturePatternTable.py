#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#: Title    : GenerateAndroidGesturePatternTable.py
#: Date     : 2014-11-04
#: Author   : "John Lehr" <slo.sleuth@gmail.com>
#: Version  : 1.0
#: License  : GPLv2 <http://www.gnu.org/licenses/gpl-2.0.html>
#: Desc     : scan Android binary dump for gesture/password keys
#: Depends  : python3-tk

#: Copyright: 2014 "John Lehr" <slo.sleuth@gmail.com>

#: to do    : add user option to change pattern length in db

import sqlite3, hashlib, itertools, datetime
import array
from datetime import datetime
import os.path as path

__version__ = "1.0"
__description__ = "Builds the rainbow table for breaking the Android Gesture Lock Pattern."
__contact__ = "slo.sleuth@gmail.com"

# Constants
pattern_length = 9
db = "AndroidGesturePatternTable.sqlite"

def generate_pattern_list(pattern_length):
    points = []
    for i in range(0, pattern_length):
        points.append(i)
    return points


def get_time():
    return str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


def main():
    if path.exists(db):
        print("The database file \'{}\' already exists, exiting...".
            format(db))
        exit()

    # Setup Database
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE RainbowTable (hash primary key, pattern text);")

    points = generate_pattern_list(pattern_length)

    with conn:
        for length in range(4, 10):
            print('{}: Building for {} length patterns'.
                format(get_time(), str(length)))
            for pattern in itertools.permutations(points, length):
                pattern_bytes = array.array("B", pattern).tobytes()
                sha1 = hashlib.sha1()
                sha1.update(pattern_bytes)
                conn.execute("INSERT INTO RainbowTable VALUES (?, ?);",
                    (sha1.hexdigest(), str(pattern)))
    conn.execute("VACUUM;")
    conn.close()

    print('{}: Completed processing.'.format(get_time()))


if __name__ == "__main__":
    main()
