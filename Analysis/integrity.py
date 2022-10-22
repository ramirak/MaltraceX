import glob, os, time
from Analysis.memory import take_processes_snapshot
import Data.files as files
import Data.enums as enums
import Api.vt as vt
from Analysis.registry import take_registry_snapshot
from Utils.string_utils import *
from .harddisk import *
from threading import Lock

critical_function_lock = Lock()

def take_snapshot(path):
    if critical_function_lock.locked():
        return enums.results.ALREADY_RUNNING.value
    with critical_function_lock:
        try:    
            disk_map = take_disk_snapshot(path)
            reg_map = take_registry_snapshot()
            proc_map = take_processes_snapshot()
           
            files.dump_to_file(disk_map, enums.files.HASHES.value)
            files.dump_to_file(reg_map, enums.files.REGISTRY.value)
            files.dump_to_file(proc_map, enums.files.PROCESSES.value)
            return enums.results.SUCCESS.value
        except:
            return enums.results.GENERAL_FAILURE.value


def check_integrity(path, scan):
    if critical_function_lock.locked():
        return enums.results.ALREADY_RUNNING.value
    with critical_function_lock:
        try:    
            sys_map, reg_map, proc_map = {} , {}, {}

            if os.path.exists(enums.files.HASHES.value):
                sys_map = files.retrieve_from_file(enums.files.HASHES.value)
            if os.path.exists(enums.files.REGISTRY.value):
                reg_map = files.retrieve_from_file(enums.files.REGISTRY.value)    
            if os.path.exists(enums.files.PROCESSES.value):
                proc_map = files.retrieve_from_file(enums.files.PROCESSES.value)    

            ## User should first create a system snapshot
            if not len(sys_map) or not len(reg_map) or not len(proc_map):
                return enums.results.SNAPSHOT_NOT_FOUND.value

            f = open(enums.files.TRACES.value, "w")
            f.write(print_header("MaltraceX Log File"))
            
            ## First check system files
            r1 = inspect_files(path, sys_map, scan, f)
            ## Check changes to chosen registry locations
            r2 = inspect_registry(reg_map, f)
            ## Check memory for new running processes
            r3 = inspect_procs(proc_map, f)
            f.close()
            files.show_file_content(enums.files.TRACES.value)

            err = enums.results.GENERAL_FAILURE.value
            if r1 == err or r2 == err or r3 == err:
                return enums.results.FINISHED_WITH_ERRORS.value
            return enums.results.SUCCESS.value
        except Exception as e:
            return enums.results.GENERAL_FAILURE.value


def inspect_files(path, sys_map, scan, f):
    f.write(print_header("Explorer lookup:"))
    for filename in glob.iglob(path + '**', recursive=True):
        if os.path.isfile(filename):
            if(filename not in sys_map):
                f.write("\nFound new trace: " + filename + " was created on: " + str(time.ctime(os.path.getmtime(filename)) + "\n"))
                new_hash = sha256sum(filename)
                if new_hash == enums.results.GENERAL_FAILURE.value:
                    continue
                f.write("File Hash : " + new_hash)
                ## Virus total scan depends on user configuration
                if scan: 
                    f.write(vt.get_report(new_hash))
                f.write(print_divider())
            else:
                hash_before = sys_map[filename][0]
                hash_after = sha256sum(filename)
                if hash_after == enums.results.GENERAL_FAILURE.value:
                    continue
                size_before = sys_map[filename][1]
                size_after = os.path.getsize(filename)

                if(hash_before != hash_after):
                    f.write("\nFile - " + filename + " was changed on: " + str(time.ctime(os.path.getmtime(filename)) + "\n"))
                    f.write("Original hash : " + hash_before + ", Size: " + str(size_before) + "B\n")
                    f.write("New hash : " + hash_after + ", Size: " + str(size_after) + "B\n")
                    ## Virus total scan depends on user configuration
                    if scan:
                        f.write(vt.get_report(hash_after))
                    f.write(print_divider())
    f.write(print_header("End explorer lookup:"))
    return enums.results.SUCCESS.value


def inspect_registry(reg_map, f):
    ## Windows only
    if os.name == 'nt':
        ## Now check common registry locations    
        f.write(print_header("Registry lookup:"))
        new_reg_map = take_registry_snapshot()
        if len(new_reg_map) == 0:
            return enums.results.GENERAL_FAILURE.value
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
    return enums.results.SUCCESS.value
    

def inspect_procs(proc_map, f):
    new_proc_map = take_processes_snapshot()
    if len(new_proc_map) == 0:
        return enums.results.GENERAL_FAILURE.value
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
    return enums.results.SUCCESS.value

