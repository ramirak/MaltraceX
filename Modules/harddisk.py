import os, glob, hashlib
import Data.enums as enums
import Data.files as files

def collect_files():
    conf = files.retrieve_from_file(enums.files.CONFIG.value)
    if not conf:
        return False
    path = conf["snapshot_path"] + "\\"
    sys_map = {}
    for filename in glob.iglob(path + "**", recursive=True):
        if os.path.isfile(filename):
            sys_map.update({filename: [sha256sum(filename), os.path.getsize(filename)]})
    return sys_map


def sha256sum(filename):
    if os.path.isdir(filename) or not os.path.exists(filename):
        return False

    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    try:
        with open(filename, 'rb', buffering=0) as f:
            while n := f.readinto(mv):
                h.update(mv[:n])
    except:
        return False
    return h.hexdigest()
