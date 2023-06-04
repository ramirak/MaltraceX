import os, ctypes
from Analysis.pestruct import write_pe_report
from Api.vt import get_report
from Analysis.harddisk import sha256sum
from Utils.validations import parse_res
import Analysis.integrity as integrity
import argparse

logo = ("               .__   __                      \n"
"  _____ _____  |  |_/  |_____________    ____  ____  \n"
" /      \__  \ |  |\   __\_  __ \__  \ _/ ___\/ __ \ \n"
"|  Y Y  \/ __ \|  |_|  |  |  | \// __  \  \__\  ___/ \n"
"|__|_|  (____  /____/__|  |__|  (____  /\___  >___  >\n"
"      \/     \/                      \/     \/    \/ \n")

parser = argparse.ArgumentParser(description="Maltrace - scan your system integrity and find traces of malwares.")
parser.add_argument("-s", "--scan", help = "full path to file", required = False, default = "")
parser.add_argument("-a", "--analyze", help = "full path to file", required = False, default = "")
parser.add_argument("-t", "--take-snapshot", help = "Take snapshot of a defined folder", required = False, action='store_true')
parser.add_argument("-c", "--check-integrity", help = "Check the integrity after a snapshot was created", required = False, action='store_true')
parser.add_argument("-l", "--live-mode", help = "Path to an executable", required = False, default= "")
parser.add_argument("-d", "--duration", help = "Duration in seconds", required = False, default= "300")

argument = parser.parse_args()
   
def init():
    if not os.path.exists("Logs"):
        os.makedirs("Logs")
    print(logo)
    
    if argument.take_snapshot:
        print("Taking snapshot. Please wait ..")
        parse_res(integrity.take_snapshot())
    elif argument.check_integrity:
        print("Checking system integrity. Please wait ..")
        parse_res(integrity.check_integrity())
    elif argument.scan != "":
        print("Trying to scan the chosen file, please wait for the report to complete ..")
        filename = argument.scan
        if parse_res(sha256sum(filename)) != -1:
            parse_res(get_report(filename, hash_value))
    elif argument.analyze != "":
        print("Analyzing file, please wait for the report to complete ..")
        parse_res(write_pe_report(argument.analyze))
    elif argument.live_mode != "":
        if not check_priv():
            print("This mode requires admin rights.")
            return
        print("Starting live mode.")
        parse_res(integrity.live_mode_inspect(argument.live_mode, argument.duration))


def check_priv():
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

init()
