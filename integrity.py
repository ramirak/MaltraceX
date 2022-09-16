import glob
import hashlib
import os
import re
import data
import time
import detect
from reg_scan import get_reg_dict

def take_snapshot(path):
    sys_map = {}
    for filename in glob.iglob(path + "**", recursive=True):
        print(filename)
        if os.path.isfile(filename):
            sys_map.update({filename: [sha256sum(filename), os.path.getsize(filename)]})
    print("\nDone.\n")
    return sys_map, get_reg_dict()


def check_integrity(sys_map_before, reg_map, path, scan):
    f = open("traces.mt", "w")
    f.write("----------------------------------------------------------------------------------\n")
    f.write("--------------------------------MaltraceX Log File---------------------------------\n")
    f.write("----------------------------------------------------------------------------------\n")
    if not bool(sys_map_before):
        print("\nNo snapshot found\n")
        return

    ## First check system files
    for filename in glob.iglob(path + '**', recursive=True):
        if os.path.isfile(filename):
            if(filename not in sys_map_before):
                f.write("\nFound new trace: " + filename + " was created on: " + str(time.ctime(os.path.getmtime(filename)) + "\n"))
                new_hash = sha256sum(filename)
                f.write("File Hash : " + new_hash)
                if scan:
                    f.write(detect.get_report(new_hash))
                f.write("\n----------------------------------------------------------------------------------\n")
            else:
                hash_before = sys_map_before[filename][0]
                hash_after = sha256sum(filename)
                size_before = sys_map_before[filename][1]
                size_after = os.path.getsize(filename)

                if(hash_before != hash_after):
                    f.write("\nFile - " + filename + " was changed on: " + str(time.ctime(os.path.getmtime(filename)) + "\n"))
                    f.write("Original hash : " + hash_before + ", Size: " + str(size_before) + "B\n")
                    f.write("New hash : " + hash_after + ", Size: " + str(size_after) + "B\n")
                    if scan:
                        f.write(detect.get_report(hash_after))
                    f.write("\n----------------------------------------------------------------------------------\n")

    ## Now check common registry locations
    new_reg_map = get_reg_dict()
    for folder in new_reg_map:
        for key in new_reg_map[folder]:
            new_val = new_reg_map[folder][key]
            if folder not in reg_map:
                continue
            elif key not in reg_map[folder]:
                f.write("Found new registry key: " + key + "\n" + "Value: " + new_val)
                f.write("\n----------------------------------------------------------------------------------\n")
            elif new_val != reg_map[folder][key]:
                f.write("Found new value: " + key + "\n" + "Old Value: " + reg_map[folder][key]  + "\nNew Value: " + new_val)
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
