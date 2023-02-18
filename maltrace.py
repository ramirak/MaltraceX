import os
from Analysis.pestruct import write_pe_report
import Analysis.integrity as integrity
from Api.vt import write_vt_report
import Data.enums as enums
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
        parse_res(write_vt_report(argument.scan))
    elif argument.analyze != "":
        print("Analyzing file, please wait for the report to complete ..")
        parse_res(write_pe_report(argument.analyze))


def parse_res(res):
    if res == enums.results.GENERAL_FAILURE.value:
        print("General Failure.")
    elif res == enums.results.API_KEY_NOT_FOUND.value:
        print("Please set your API key.")
    elif res == enums.results.SNAPSHOT_NOT_FOUND.value:
        print("No snapshot found.")
    elif res == enums.results.NO_MATCH_FOUND.value:
        print("No match was found.")
    elif res == enums.results.NON_PE_FILE.value:
        print("Non PE file.")
    elif res == enums.results.FINISHED_WITH_ERRORS.value:
        print("Finished with errors.")
    elif res == enums.results.FILE_NOT_FOUND.value:
        print("File not found.")
    elif res == enums.results.SUCCESS.value:
        print("Done.")


init()