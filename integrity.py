import glob
import hashlib
import os
import data
import time

def take_snapshot(path):
    sys_map = {}
    for filename in glob.iglob(path + "**", recursive=True):
        print(filename)
        if os.path.isfile(filename):
            sys_map.update({filename: sha256sum(filename)})
    print("\nDone.\n")
    return sys_map


def check_integrity(sys_map_before, path):
    f = open("traces.mt", "w")
    f.write("----------------------------------------------------------------------------------\n")
    f.write("--------------------------------Maltrace Log File---------------------------------\n")
    f.write("----------------------------------------------------------------------------------\n")
    if not bool(sys_map_before):
        print("\nNo snapshot found\n")
        return
    for filename in glob.iglob(path + '**', recursive=True):
        if os.path.isfile(filename):
            if(filename not in sys_map_before):
                f.write("\nFound new trace: " + filename + " was created on: " + str(time.ctime(os.path.getmtime(filename)) + "\n"))
                f.write("\n----------------------------------------------------------------------------------\n")
            if(filename in sys_map_before):
                hash_before = sys_map_before[filename]
                hash_after = sha256sum(filename)
                if(hash_before != hash_after):
                    f.write("\nFile - " + filename + " has changed on: " + str(time.ctime(os.path.getmtime(filename)) + "\n"))
                    f.write("Original hash : " + hash_before + "\n")
                    f.write("Changed hash : " + hash_after + "\n")
                    f.write("\n----------------------------------------------------------------------------------\n")
    f.close()
    data.show_traces()

                    
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
        return -1
    return h.hexdigest()
