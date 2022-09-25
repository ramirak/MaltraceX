import glob, os, hashlib, time
from Analysis.memory import get_procs
import Data.files as files
import Api.vt as vt
from .registry import get_reg_dict
from Utils.string_utils import *


def take_snapshot(path):
    sys_map = {}
    for filename in glob.iglob(path + "**", recursive=True):
        print(filename)
        if os.path.isfile(filename):
            sys_map.update({filename: [sha256sum(filename), os.path.getsize(filename)]})
    print("\nDone.\n")
    return sys_map, get_reg_dict(), get_procs()


def check_integrity(sys_map, reg_map, proc_map, path, scan):
    paths = files.retrieve_from_file("Conf/paths.conf")
    f = open(paths["traces"], "w")
    f.write(print_header("MaltraceX Log File"))
    
    ## User should first create a system snapshot
    if not bool(sys_map):
        print("\nNo snapshot found\n")
        return
    ## First check system files
    inspect_files(path, sys_map, scan, f)
    ## Check changes to chosen registry locations
    inspect_registry(reg_map, f)
    ## Check memory for new running processes
    inspect_procs(proc_map, f)
    f.close()
    files.show_file_content(paths["traces"])


def inspect_files(path, sys_map, scan, f):
    f.write(print_header("Explorer lookup:"))
    for filename in glob.iglob(path + '**', recursive=True):
        if os.path.isfile(filename):
            if(filename not in sys_map):
                f.write("\nFound new trace: " + filename + " was created on: " + str(time.ctime(os.path.getmtime(filename)) + "\n"))
                new_hash = sha256sum(filename)
                f.write("File Hash : " + new_hash)
                ## Virus total scan depends on user configuration
                if scan: 
                    f.write(vt.get_report(new_hash, True))
                f.write(print_divider())
            else:
                hash_before = sys_map[filename][0]
                hash_after = sha256sum(filename)
                size_before = sys_map[filename][1]
                size_after = os.path.getsize(filename)

                if(hash_before != hash_after):
                    f.write("\nFile - " + filename + " was changed on: " + str(time.ctime(os.path.getmtime(filename)) + "\n"))
                    f.write("Original hash : " + hash_before + ", Size: " + str(size_before) + "B\n")
                    f.write("New hash : " + hash_after + ", Size: " + str(size_after) + "B\n")
                    ## Virus total scan depends on user configuration
                    if scan:
                        f.write(vt.get_report(hash_after, True))
                    f.write(print_divider())
    f.write(print_header("End explorer lookup:"))


def inspect_registry(reg_map, f):
        ## Windows only
    if os.name == 'nt':
        ## Now check common registry locations    
        f.write(print_header("Registry lookup:"))
        new_reg_map = get_reg_dict()
        for folder in new_reg_map:
            for key in new_reg_map[folder][1]:
                new_val = new_reg_map[folder][1][key]
                if folder not in reg_map:
                    continue
                elif key not in reg_map[folder][1]:
                    f.write("Found new registry key:\nIn: " + new_reg_map[folder][0] + "\\" + folder + "\nKey: " + key + ", Value: " + new_val)
                    f.write(print_divider())
                elif new_val != reg_map[folder][1][key]:
                    f.write("Found new value for: " + key + "\nIn: " + new_reg_map[folder][0] + "\\" + folder +  "\nOld Value: " + reg_map[folder][1][key]  + "\nNew Value: " + new_val)
                    f.write(print_divider())
        f.write(print_header("End registry lookup:"))


def inspect_procs(proc_map, f):
    new_proc_map = get_procs()
    f.write(print_header("Memory Lookup:"))
    f.write("\n* New processes:\n\n")
    f.write(get_proc_header())
    for proc in new_proc_map:
        if proc not in proc_map:
            f.write(format_proc(proc, new_proc_map[proc]))
    f.write("\n* Killed processes:\n\n")
    f.write(get_proc_header())
    for proc in proc_map:
        if proc not in new_proc_map:
            f.write(format_proc(proc, proc_map[proc]))
    f.write(print_header("End memory Lookup:"))


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

