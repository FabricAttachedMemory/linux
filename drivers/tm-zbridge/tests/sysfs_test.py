#!/bin/python3

#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.

# it's been a decade people get over it.
# This testing program assumes it's the only one that
# is accessing the sysfs interface at the same time.
# It also doesn't really do anything fancy with colors
# A signle failure may cause all other tests to fail
# it's not really meant to be robust so that's not a big deal

TOP_LEVEL = '/sys/kernel/desc/'
BOOK_TABLE = 'book_table'
BOOKLET_TABLE = 'booklet_table'
BOOK_CURSOR = 'book_table_cursor'
BOOKLET_CURSOR = 'booklet_table_cursor'


def test_cursor(file_name):

    ret = True

    cursor_file = open(file_name, 'r+')
    cursor_file.write('5')
    cursor_file.flush()


    cursor_file.seek(0)
    if not cursor_file.read() == '5\n':
        print("readdded " + t)
        print("Cursor for " + file_name + " incorrect")
        ret = False

    cursor_file.write('100000000')
    cursor_file.flush()
    cursor_file.seek(0)
    if not cursor_file.read() == '5\n':
        print("Cursor for " + file_name + " allowed out of bounds, High")
        ret = False

    cursor_file.write('-1')
    cursor_file.flush()
    cursor_file.seek(0)
    if not cursor_file.read() == '5\n':
        print("Crusor for " + file_name + " aollowed out of bounds, Low")
        ret = False

    cursor_file.close()

    return ret

def test_table(file_name):
    ret = True

    table_file = open(file_name, 'r+')
    # account for strangeness might screw up testing validity but I'm
    # not overly worried in the futrue force load and zero for testing
    table_file.write('put 5 0')

    table_file.seek(0)
    if not table_file.read() == '5, 0x0\n':
        print("table file " + file_name + " incorrect read")

    table_file.write('put 6 0')
    table_file.flush()
    table_file.seek(0)
    table_file.write('set 6')
    table_file.flush()
    table_file.seek(0)
    if not table_file.read() == '6, 0x0\n':
        print("table file " + file_name + " incorrect cursor")
        ret = False

    table_file.write('put 6 0x1')
    table_file.flush()
    table_file.seek(0)
    if not table_file.read() == '6, 0x1\n':
        print("table file " + file_name + " incorrect read after write")
        ret = False

    table_file.write('put 7, 0x0')
    table_file.flush()
    table_file.seek(0)
    if table_file.read() == '7, 0x0\n':
        print("table file " + file_name + " put modified cursor")
        ret = False

    table_file.write('set 100000000')
    table_file.flush()
    table_file.seek(0)
    if not table_file.read() == '6, 0x1\n':
        print("table file " + file_name + " cursor allow out of bounds High")
        ret = False

    table_file.write('set -1')
    table_file.flush()
    table_file.seek(0)
    if not table_file.read() == '6, 0x1\n':
        print ("table file " + file_name + " cursor allow out of bounds Low")
        ret = False

    table_file.close()

    return ret

def clean():
    f = open(TOP_LEVEL + BOOK_CURSOR)
    f.write()




def main():
    test_cursor(TOP_LEVEL + BOOK_CURSOR)
    test_table(TOP_LEVEL + BOOK_TABLE)
    test_cursor(TOP_LEVEL + BOOKLET_CURSOR)
    test_table(TOP_LEVEL + BOOKLET_TABLE)

if __name__ == "__main__":
    main()
