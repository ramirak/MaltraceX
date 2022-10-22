import os, glob
from Analysis.memory import get_connections, get_processes
from Analysis.pestruct import write_pe_report
import Data.files as files
import Analysis.integrity as integrity
from Api.vt import write_vt_report
import Data.enums as enums
import whois

logo = ("               .__   __                      \n"
"  _____ _____  |  |_/  |_____________    ____  ____  \n"
" /      \__  \ |  |\   __\_  __ \__  \ _/ ___\/ __ \ \n"
"|  Y Y  \/ __ \|  |_|  |  |  | \// __  \  \__\  ___/ \n"
"|__|_|  (____  /____/__|  |__|  (____  /\___  >___  >\n"
"      \/     \/                      \/     \/    \/ \n")


def init():
    if not os.path.exists("Logs"):
        os.makedirs("Logs")
    print(logo)
    while(True):
        main_menu()
   

def main_menu():
    conf = files.retrieve_from_file(enums.files.CONFIG.value)
    virus_total_scan, virus_total_key = bool(conf["virus_total_scan"]), conf["virus_total_key"]
    snapshot_path = conf["snapshot_path"]

    choice = -1
    while(choice == -1):
        print("(1) Take system Snapshot")
        print("(2) Test system integrity")
        print("(3) Scan a file")
        print("(4) Analyze PE")
        print("(5) Whois lookup")
        print("(6) Show processes")
        print("(7) Show connections")
        print("(8) Exit")

        choice = assert_choice(input("\n> "))
        if(choice == 1):
            integrity.take_snapshot(snapshot_path)
        elif(choice == 2):
            integrity.check_integrity(snapshot_path, virus_total_scan)
        elif(choice == 3):
            if virus_total_key == "":
                print("\nPlease set your Virus Total api key first\n")
                continue
            path = input("\nEnter containing folder path > \n")
            if os.path.isdir(path):
                files_menu(path, enums.operations.VIRUS_TOTAL_SCAN.value)
        elif(choice == 4):
            path = input("\nEnter containing folder path > \n")
            if os.path.isdir(path):
                files_menu(path, enums.operations.PE_ANALYZE.value)
        elif(choice == 5):
            print(whois.whois(input("Please enter a valid domain: ")))
        elif(choice == 6):
            print(get_processes())
        elif(choice == 7):
            print(get_connections())
        elif(choice == 8):
            exit(0)
        else:
            choice = -1


def files_menu(path, action_type):
    count, choice = 1, 0
    files_lst = []

    for filename in glob.iglob(path + '/**', recursive=False):
        if os.path.isfile(filename):
            print("(" + str(count) + ") " + filename)
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
        if action_type == enums.operations.VIRUS_TOTAL_SCAN.value:
            write_vt_report(chosen_file)
        elif action_type == enums.operations.PE_ANALYZE.value:
            write_pe_report(chosen_file)


def assert_choice(choice):
    try:
        choice = int(choice)
    except:
        return -1;
    return choice


init()