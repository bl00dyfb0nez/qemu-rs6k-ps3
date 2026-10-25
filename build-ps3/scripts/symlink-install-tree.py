#!/usr/bin/env python3

from pathlib import PurePath
import errno
import json
import os
import shlex
import shutil
import subprocess
import sys

def destdir_join(d1: str, d2: str) -> str:
    if not d1:
        return d2
    # c:\destdir + c:\prefix must produce c:\destdir\prefix
    return str(PurePath(d1, *PurePath(d2).parts[1:]))

introspect = os.environ.get('MESONINTROSPECT')
out = subprocess.run([*shlex.split(introspect), '--installed'],
                     stdout=subprocess.PIPE, check=True).stdout
for source, dest in json.loads(out).items():
    bundle_dest = destdir_join('qemu-bundle', dest)
    path = os.path.dirname(bundle_dest)
    try:
        os.makedirs(path, exist_ok=True)
    except BaseException as e:
        print(f'error making directory {path}', file=sys.stderr)
        raise e
    try:
        os.symlink(source, bundle_dest)
    except OSError as e:
        # Windows refuses symlinks without Developer Mode; a copy is
        # equivalent for a local build tree.
        if getattr(e, 'winerror', 0) == 1314 or e.errno in (errno.EPERM, errno.EACCES):
            # A local build tree does not need the install bundle; skip
            # entries whose target has not been built yet.
            if not os.path.exists(source):
                continue
            shutil.copy2(source, bundle_dest)
            continue
        raise
    except BaseException as e:
        if not isinstance(e, OSError) or e.errno != errno.EEXIST:
            if os.name == 'nt':
                print('Please enable Developer Mode to support soft link '
                      'without Administrator permission')
            print(f'error making symbolic link {dest}', file=sys.stderr)
            raise e
