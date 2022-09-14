import os
import data
from integrity import sha256sum
from detect import get_report
import glob

hashes_file = "hashes.mt"
conf_file = "maltrace.conf"

def init():
    with open('logo.txt', 'r') as f:
        print(f.read())
    while(True):
        main_menu()
   

def main_menu():
    sys_map = {}
    conf = data.retrieve_from_file(conf_file)
    path = conf["path"]
    scan = bool(conf["scan"])
    api_k = conf["vt_key"]

    if os.path.exists(hashes_file):
        sys_map = data.retrieve_from_file(hashes_file)
    choice = -1
    while(choice == -1):
        print("(1) Take system Snapshot")
        print("(2) Test system integrity")
        print("(3) Scan a file")
        print("(4) Exit")
        choice = assert_choice(input("\n> "))
        if(choice == 1):
            sys_map = integrity.take_snapshot(path)
            data.dump_to_file(sys_map, hashes_file)
        elif(choice == 2):
            integrity.check_integrity(sys_map, path, scan)
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
        file_hash = sha256sum(files[choice-1])
        print(file_hash)
        print(get_report(file_hash))

def assert_choice(choice):
    try:
        choice = int(choice)
    except:
        return -1;
    return choice


init()