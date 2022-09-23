import os, glob
from Analysis.pestruct import get_dlls, get_dos_headers, pe_load
import Data.files as files
import Analysis.integrity as integrity
from Api.vt import get_report
from datetime import datetime

conf_file = "Conf/maltrace.conf"
paths_file = "Conf/paths.conf"

VT_SCAN, PE_ANALYZE, *_ = range(5)

def init():
    if not os.path.exists("Logs"):
        os.makedirs("Logs")
    if os.path.isfile('Imgs/logo.txt'):
        with open('Imgs/logo.txt', 'r') as f:
            print(f.read())
    while(True):
        main_menu()
   

def main_menu():
    sys_map, reg_map = {} , {}
    conf, paths = files.retrieve_from_file(conf_file), files.retrieve_from_file(paths_file)
    scan_path, hashes_path, registry_path, reglog_path = conf["path"], paths["hashes"], paths["registry"], paths["reglog"]
    scan, api_k = bool(conf["scan"]), conf["vt_key"]

    if os.path.exists(hashes_path):
        sys_map = files.retrieve_from_file(hashes_path)
    if os.path.exists(registry_path):
        reg_map = files.retrieve_from_file(registry_path)    

    choice = -1
    while(choice == -1):
        print("(1) Take system Snapshot")
        print("(2) Test system integrity")
        print("(3) Scan a file")
        print("(4) Analyze")
        print("(5) Exit")

        choice = assert_choice(input("\n> "))
        if(choice == 1):
            sys_map, reg_map = integrity.take_snapshot(scan_path)
            files.dump_to_file(sys_map, hashes_path)
            files.dump_to_file(reg_map, reglog_path)
        elif(choice == 2):
            integrity.check_integrity(sys_map, reg_map, scan_path, scan)
        elif(choice == 3):
            if api_k == "":
                print("\nPlease set your Virus Total api key first\n")
                continue
            path = input("\nEnter containing folder path > \n")
            if os.path.isdir(path):
                files_menu(path, VT_SCAN)
        elif(choice == 4):
            path = input("\nEnter containing folder path > \n")
            if os.path.isdir(path):
                files_menu(path, PE_ANALYZE)
        elif(choice == 5):
            exit(0)
        else:
            choice = -1


def files_menu(path, action_type):
    count, choice = 1, 0
    files_lst = []
    paths = files.retrieve_from_file("Conf/paths.conf")

    for filename in glob.iglob(path + '/**', recursive=False):
        if os.path.isfile(filename):
            print("(" + str(count) + ")" + filename)
            files_lst.append(filename)
            count+=1
    while choice != -1:
        choice = assert_choice(input("\nFile ID to scan > "))
        if choice == -1:
            return
        if choice <= 0 or choice > len(files_lst):
            print("Invalid file ID")
            continue
        chosen_file = files_lst[choice-1]
        if action_type == VT_SCAN:
            file_hash = integrity.sha256sum(chosen_file)
            log_file = paths["report"]
            with open(log_file, "a+") as logfile:
                    now = datetime.now()
                    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
                    logfile.write("\n-------------------- " + chosen_file + " - " + file_hash + ": " + dt_string + " --------------------\n")
                    logfile.write(get_report(file_hash, False) + "\n")
        elif action_type == PE_ANALYZE:
            pe = pe_load(chosen_file)
            if pe != None:
                dlls, funcs = get_dlls(pe, True)
                log_file = paths["pefile"]
                with open(log_file, "a+") as logfile:
                    now = datetime.now()
                    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
                    logfile.write("\n-------------------- " + chosen_file + ": " + dt_string + " --------------------\n")
                files.dump_list_to_file(get_dos_headers(pe), "\n----------- DOS Headers: -----------\n", log_file)
                files.dump_list_to_file(dlls, "\n----------- Dll imports: -----------\n", log_file)
                files.dump_list_to_file(funcs, "\n----------- Functions: -----------\n", log_file)
                files.dump_list_to_file(pe.sections, "\n----------- Sections: -----------\n", log_file)
                print("Done, Log file can be found in: " + log_file)
            else:
                print("Non PE file")


def assert_choice(choice):
    try:
        choice = int(choice)
    except:
        return -1;
    return choice


init()