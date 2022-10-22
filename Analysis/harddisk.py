import os, glob, hashlib
import Data.enums as enums

def take_disk_snapshot(path):
    sys_map = {}
    for filename in glob.iglob(path + "**", recursive=True):
        if os.path.isfile(filename):
            sys_map.update({filename: [sha256sum(filename), os.path.getsize(filename)]})
    return sys_map


def sha256sum(filename):
    if os.path.isdir(filename):
        return;
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    try:
        with open(filename, 'rb', buffering=0) as f:
            while n := f.readinto(mv):
                h.update(mv[:n])
    except:
        return enums.results.GENERAL_FAILURE.value
    return h.hexdigest()
