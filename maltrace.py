import os
import data, integrity

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
    if os.path.exists(hashes_file):
        sys_map = data.retrieve_from_file(hashes_file)
    choice = -1
    while(choice == -1):
        print("(1) Take system Snapshot")
        print("(2) Test system integrity")
        print("(3) Exit")
        choice = assert_choice(input("\n> "))
        if(choice == 1):
            sys_map = integrity.take_snapshot(path)
            data.dump_to_file(sys_map, hashes_file)
        elif(choice == 2):
            integrity.check_integrity(sys_map, path,bool(conf["scan"]))
        elif(choice == 3):
            exit(0)
        else:
            choice = -1


def assert_choice(choice):
    try:
        choice = int(choice)
    except:
        return -1;
    return choice


init()