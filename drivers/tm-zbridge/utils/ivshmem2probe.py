#!/usr/bin/python3 -tt

# IVSHMEM areas are preserved in QEMU invocation stanzas, and I "assign"
# their function abbreviations in alphabetic order.  Recover those regions
# via lspci of the Red Hat PCI pseudo devices for IVSMEM, assign abbrevs,
# and issue a modprobe line.

from itertools import groupby
from pdb import set_trace
try:
    from StringIO import StringIO
except Exception:
    from io import StringIO

from piper import piper

# Abbreviations were from chipset ERS as of June 2015
abbrevs = ('nvm_bk', 'zbcsr', 'desbk', 'desbl', 'frwl', 'inlv', 'commit')

# Get one big line and separate it into groups based on a key line.
# groupby returns iterators, run through them to get group iterators, walk
# them, then parse the line.  List of list comprehensions are too Perly.

ret, stdout, stderr = piper('lspci -v -d1af4:1110') # RedHat IVSHMEM
if isinstance(stdout, bytes):
    stdout = stdout.decode()
groups = groupby(StringIO(stdout), lambda line: 'RAM memory: Red Hat' in line)
tmp = [ list(lines) for is_sep, lines in groups if not is_sep ]
assert len(tmp) == len(abbrevs), 'I didn''t see that coming'

baseaddrs = [ ]
for lines in tmp:
    memline = [ l for l in lines if '64-bit, prefetch' in l ][0]
    assert memline, 'Oops'
    elems = memline.split()
    # baseaddrs.append('0x%s %s' % (elems[2], elems[-1]))
    baseaddrs.append('0x%s' % elems[2])

areas = dict(zip(abbrevs, baseaddrs))
for k in sorted(areas.keys()):
    print('%8s: %s' % (k, areas[k]))
NVM = areas['nvm_bk']

modprobe = 'modprobe zbridge '
for k in sorted(areas.keys()):
    modprobe += '%s=%s ' % (k, areas[k])
modprobe += 'bk_size=8'
print(modprobe)
