"""Every good project needs a utils, time to start one."""

import errno
import os
import shlex
import shutil
import subprocess
import sys

###########################################################################
# Sub-process caller that returns ret, stdout, stderr

def piper(cmdstr, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
    """Pipe a command, maybe retrieve stdout/stderr, hides ugly output"""
    try:
        cmd = shlex.split(cmdstr)
        p = subprocess.Popen(cmd, stdout=stdout, stderr=stderr)
        stdout, stderr = p.communicate()        # implicit wait()
        ret = p.returncode
        if ret is None:
            ret = 0
        return ret, stdout, stderr
    except Exception as e:
        raise RuntimeError('Bad piper: %s' % str(e))
