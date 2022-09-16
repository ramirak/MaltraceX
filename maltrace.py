import os
import data
import integrity
from detect import get_report
import glob

hashes_file = "hashes.mt"
reg_file = "reg_map.mt"
conf_file = "maltrace.conf"

def init():
    if os.path.isfile('logo.txt'):
        with open('logo.txt', 'r') as f:
            print(f.read())
    while(True):
        main_menu()
   

def main_menu():
    sys_map = {}
    reg_map = {}
    conf = data.retrieve_from_file(conf_file)
    path = conf["path"]
    scan = bool(conf["scan"])
    api_k = conf["vt_key"]

    if os.path.exists(hashes_file):
        sys_map = data.retrieve_from_file(hashes_file)
    if os.path.exists(reg_file):
        reg_map = data.retrieve_from_file(reg_file)    

    choice = -1
    while(choice == -1):
        print("(1) Take system Snapshot")
        print("(2) Test system integrity")
        print("(3) Scan a file")
        print("(4) Exit")

        choice = assert_choice(input("\n> "))
        if(choice == 1):
            sys_map, reg_map = integrity.take_snapshot(path)
            data.dump_to_file(sys_map, hashes_file)
            data.dump_to_file(reg_map, reg_file)
        elif(choice == 2):
            integrity.check_integrity(sys_map, reg_map, path, scan)
        elif(choice == 3):
            if api_k == "":
                print("\nPlease set your Virus Total api key first\n")
                continue
            path = input("\nEnter containing folder path > \n")
            if os.path.isdir(path):
                files_menu(path)
        elif(choice == 4):
            exit(0)
        else:
            choice = -1


def files_menu(path):
    count = 1
    choice = 0
    files = []
    for filename in glob.iglob(path + '/**', recursive=False):
        if os.path.isfile(filename):
            print("(" + str(count) + ")" + filename)
            files.append(filename)
            count+=1
    while choice != -1:
        choice = assert_choice(input("\nFile ID to scan > "))
        if choice == -1:
            return
        if choice <= 0 or choice > len(files):
            print("Invalid file ID")
            continue
        file_hash = integrity.sha256sum(files[choice-1])
        print(file_hash)
        print(get_report(file_hash))

def assert_choice(choice):
    try:
        choice = int(choice)
    except:
        return -1;
    return choice


init()