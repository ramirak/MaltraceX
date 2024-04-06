
import Data.files as files
from Data.report import do_print
import Data.enums as enums
from Modules.virus_total import get_report
from Modules.registry import *
from Modules.harddisk import *
from Modules.networking import *
from Modules.memory import *
from Analysis.snapshot import *
import os, glob, time, subprocess, ipaddress


def check_integrity(log_mode, scan, full_check):
    conf = files.retrieve_from_file(enums.files.CONFIG.value)
    if not conf:
        return False

    path = conf["snapshot_path"] + "\\"

    sys_map = files.retrieve_from_file(enums.files.HASHES.value)
    if not sys_map:
        return False

    do_print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~", log_mode) 
    do_print("~~ MaltraceX integrity test ~~", log_mode) 
    do_print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~", log_mode) 

    ## Check system files
    do_print("Files lookup:", log_mode) 
    res = inspect_files(sys_map, scan, log_mode)
    if not res:
        print("Failed to inspect file changes.")
        return False
    do_print("Done.\n", log_mode) 

    if full_check:
        ## Check changes registry
        reg_map = files.retrieve_from_file(enums.files.REGISTRY.value)     
        if not reg_map:
            return False
        do_print("Registry lookup:", log_mode)         
        res = inspect_registry(reg_map, log_mode)
        if not res:
            print("Failed to inspect registry changes.")
            return False
        do_print("Done.\n", log_mode) 
    return True


def inspect_files(sys_map, scan, log_mode):
    try:
        new_sys_map = collect_files()

        for filename in new_sys_map:
                if filename in sys_map:
                    hash_before = sys_map[filename][0]
                    size_before = sys_map[filename][1]
                if filename in new_sys_map:
                    hash_after = new_sys_map[filename][0]
                    size_after = new_sys_map[filename][1]
                scan_now = False

                if(filename not in sys_map):
                    do_print("Found new trace: " + filename + " was created on: " + str(time.ctime(os.path.getmtime(filename))), log_mode)                    
                    do_print("      File Hash: " + hash_after + "\n", log_mode)
                    scan_now = True
                elif(hash_before != hash_after):
                    do_print("File - " + filename + " was changed on: " + str(time.ctime(os.path.getmtime(filename))), log_mode)
                    do_print("      Original hash : " + str(hash_before) + ", Size: " + str(size_before) + "B", log_mode)
                    do_print("      New hash : " + str(hash_after) + ", Size: " + str(size_after) + "B\n", log_mode)
                    scan_now = True
                
                if scan and scan_now:
                    vt_report = get_report(filename, hash_after)
                    if not vt_report:
                        continue
                    do_print(vt_report, log_mode)

        for filename in sys_map:
            if (filename not in new_sys_map):
                do_print("Deleted - " + filename + "\n", log_mode)
        return True
    except Exception as e:
        print(e)
        return False


def inspect_registry(reg_map, log_mode):
    try:
        ## Windows only
        if os.name == 'nt':
            ## Now check common registry locations    
            new_reg_map = collect_registry()
            if not new_reg_map:
                return False        
            for key in new_reg_map:
                if key not in reg_map:
                    do_print("Found new registry key:\n" + key + "\n" + new_reg_map[key], log_mode)
                elif new_reg_map[key] != reg_map[key]:
                    do_print("Found altered registry:\n" + key + "\nOld: " + reg_map[key]  + "\nNew: " + new_reg_map[key], log_mode)
        else:
            do_print("Windows only, skipping..", log_mode)
        return True
    except Exception as e:
        print(e)
        return False    


def inspect_procs(duration, log_mode):
    try:
        if os.name == 'nt':
            proc_whitelist = files.retrieve_from_file(enums.files.PROCESSES.value)
            if not proc_whitelist:
                return False
            processes = collect_processes(duration)
            if not processes:
                return False

            do_print("\nProcesses that were not found in the whitelist file: ", log_mode)
            for key in processes:
                if key not in proc_whitelist:
                    do_print("Process " + processes[key] + " was spawned.", log_mode)
        else:
            do_print("Windows only, skipping..", log_mode)
        return True
    except:
        return False


def inspect_network(duration, flt, log_mode, do_whois):
    try:
        conns_whitelist = files.retrieve_from_file(enums.files.CAPTURE.value)
        if not conns_whitelist:
            return False
        conns = catpure_packets(duration, flt)
        if not conns:
            return False
        
        do_print("\nConnections that were not found in the whitelist file: ", log_mode)
        for key in conns:
            if key not in conns_whitelist:
                do_print("New conn to - " + key + ":" + conns[key], log_mode)
                if do_whois and not ipaddress.ip_address(key).is_private:
                    inspect_address(key, log_mode)
        return True
    except:
        return False