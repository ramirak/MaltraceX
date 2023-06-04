import glob, os, time, subprocess
from Analysis.memory import take_processes_snapshot
import Data.files as files
from Data.report import write_report, get_proc_header, format_proc
import Data.enums as enums
from Api.vt import get_report
from Analysis.registry import take_registry_snapshot
from Utils.string_utils import *
from .harddisk import *
from Analysis.networking import *
from Utils.validations import parse_res

def live_mode_inspect(exec_path, duration):
    sucess = enums.results.SUCCESS.value

    if not os.path.exists(exec_path):
        return enums.results.FILE_NOT_FOUND.value

    print("Taking snapshot, please wait..")
    res = take_snapshot()
    if res != enums.results.SUCCESS.value:
        return res

    res1 = ""
    # Not supported for windows
    if os.name != 'nt':
        print("Starting packet capture..")    
        res1 = catpure_packets(duration)

    print("Starting file execution..")
    subprocess.Popen(exec_path.split(), stdout=subprocess.PIPE)

    # wait for requested duration before checking for changes.
    print("Sleeping for " + str(duration) + "..")
    time.sleep(int(duration))

    print("Checking integrity..")
    res2 = check_integrity()

    # Timeout, check found connections if any
    if res1 == sucess and res2 == sucess:
        report = inspect_addresses(enums.files.TDUMP.value)
        write_report(enums.files.TRACES.value, "Connections lookup", report , True, "a+") 

    return sucess

def take_snapshot():
    try:    
        disk_map = take_disk_snapshot()
        if disk_map == enums.results.FILE_NOT_FOUND.value:
            return disk_map 
        files.dump_to_file(disk_map, enums.files.HASHES.value)
        files.dump_to_file(take_registry_snapshot(), enums.files.REGISTRY.value) 
        files.dump_to_file(take_processes_snapshot(), enums.files.PROCESSES.value) 
        return enums.results.SUCCESS.value
    except:
        return enums.results.GENERAL_FAILURE.value


def check_integrity():
    try:
        conf = files.retrieve_from_file(enums.files.CONFIG.value)
        if conf == enums.results.FILE_NOT_FOUND.value:
            return conf

        path = conf["snapshot_path"]
        scan = bool(conf["virus_total_scan"])

        fnf = enums.results.FILE_NOT_FOUND.value
        sys_map = files.retrieve_from_file(enums.files.HASHES.value)
        reg_map = files.retrieve_from_file(enums.files.REGISTRY.value)    
        proc_map = files.retrieve_from_file(enums.files.PROCESSES.value)    

        ## User should first create a system snapshot
        if sys_map == fnf or reg_map == fnf or proc_map == fnf:
            return enums.results.SNAPSHOT_NOT_FOUND.value
 
        write_report(enums.files.TRACES.value, "MaltraceX Log File", "" , False , "w") 

        ## First check system files
        r = inspect_files(path, sys_map, scan)
        write_report(enums.files.TRACES.value, "Files lookup", r, True ,"a+")

        ## Check changes to chosen registry locations
        r = inspect_registry(reg_map)
        write_report(enums.files.TRACES.value, "Registry lookup (Win only)", r, True , "a+")

        ## Check memory for new running processes
        r = inspect_procs(proc_map)
        write_report(enums.files.TRACES.value, "Memory lookup", r, True ,"a+") 
        
        files.show_file_content(enums.files.TRACES.value)
        return enums.results.SUCCESS.value
    except Exception as e:
        print(e)
        return enums.results.GENERAL_FAILURE.value


def inspect_files(path, sys_map, scan):
    report = ""
    for filename in glob.iglob(path + '**', recursive=True):
        if os.path.isfile(filename):
            if(filename not in sys_map):
                report += "\nFound new trace: " + filename + " was created on: " + str(time.ctime(os.path.getmtime(filename)) + "\n")
                new_hash = sha256sum(filename)
                if new_hash == enums.results.GENERAL_FAILURE.value or new_hash == enums.results.FILE_NOT_FOUND.value:
                    continue
                report += "File Hash : " + new_hash
                ## Virus total scan depends on user configuration
                if scan:
                    vt_report = get_report(filename, new_hash)
                    if parse_res(vt_report) != -1:
                        report += vt_report
            else:
                hash_before = sys_map[filename][0]
                hash_after = sha256sum(filename)
                if hash_after == enums.results.GENERAL_FAILURE.value or hash_after == enums.results.FILE_NOT_FOUND.value:
                    continue
                size_before = sys_map[filename][1]
                size_after = os.path.getsize(filename)

                if(hash_before != hash_after):
                    report += "\nFile - " + filename + " was changed on: " + str(time.ctime(os.path.getmtime(filename)) + "\n")
                    report += "Original hash : " + str(hash_before) + ", Size: " + str(size_before) + "B\n"
                    report += "New hash : " + str(hash_after) + ", Size: " + str(size_after) + "B\n"
                    ## Virus total scan depends on user configuration
                    if scan:
                        vt_report = get_report(filename, hash_after)
                        if parse_res(vt_report) != -1:
                            report += vt_report

    for filename in sys_map:
        if not os.path.isfile(filename):
            report += "Deleted - " + filename + "\n"

    return report


def inspect_registry(reg_map):
    report = ""
    ## Windows only
    if os.name == 'nt':
        ## Now check common registry locations    
        new_reg_map = take_registry_snapshot()
        
        for folder in new_reg_map:
            for key in new_reg_map[folder][1]:
                new_val = new_reg_map[folder][1][key]
                if folder not in reg_map:
                    continue
                elif key not in reg_map[folder][1]:
                    report += "Found new registry key:\nIn: " + new_reg_map[folder][0] + "\\" + folder + "\nKey: " + key + ", Value: " + new_val
                elif new_val != reg_map[folder][1][key]:
                    report += "Found new value for: " + key + "\nIn: " + new_reg_map[folder][0] + "\\" + folder +  "\nOld Value: " + reg_map[folder][1][key]  + "\nNew Value: " + new_val
    return report
    

def inspect_procs(proc_map):
    report = ""
    new_proc_map = take_processes_snapshot()
    report += "\n* New processes:\n\n"
    report += get_proc_header()
    for proc in new_proc_map:
        if proc not in proc_map:
            report += format_proc(proc, new_proc_map[proc])
    report += "\n* Killed processes:\n\n"
    report += get_proc_header()
    for proc in proc_map:
        if proc not in new_proc_map:
            report += format_proc(proc, proc_map[proc])
    return report



