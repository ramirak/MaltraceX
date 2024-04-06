import os, ctypes
from Modules.virus_total import get_report
from Modules.harddisk import sha256sum
from Modules.pestruct import write_pe_report
from Analysis.integrity import *
from Analysis.snapshot import *
import argparse


logo = ("               .__   __                      \n"
"  _____ _____  |  |_/  |_____________    ____  ____  \n"
" /      \\__  \\ |  |\\   __\\_  __ \\__  \\ _/ ___\\/ __ \\ \n"
"|  Y Y  \\/ __ \\|  |_|  |  |  | \\// __  \\  \\__\\  ___/ \n"
"|__|_|  (____  /____/__|  |__|  (____  /\\___  >___  >\n"
"      \\/     \\/                      \\/     \\/    \\/ \n")

print(logo)

usage = "[ -t -f / -c -o -s -f / -vt <path> / -a <path> / -sn -w -d -i -e -o / -p -w -d -o ]"

parser = argparse.ArgumentParser(description="Maltrace - scan your system integrity and find traces of malwares.", usage="%(prog)s " + usage,formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=60))
# Main operations
parser.add_argument("-t", "--take-snapshot", help = "Take snapshot for defined folder and registy keys.", required = False, action='store_true')
parser.add_argument("-c", "--check-integrity", help = "Check the integrity of the system.", required = False, action='store_true')
parser.add_argument("-p", "--process-listener", help = "Monitor spawned processes.", required = False, action='store_true')
parser.add_argument("-v", "--virus-total", metavar="<path>",  help = "Scan a file with virus total.", required = False, default = "")
parser.add_argument("-a", "--analyze", metavar="<path>", help = "Inspect executable properties.", required = False, default = "")
parser.add_argument("-sn", "--sniff", help = "Sniff network traffic.", required = False, action='store_true')
# Additional flags
parser.add_argument("-o", "--output", help = "Output to file.", required = False, action='store_true')
parser.add_argument("-f", "--full", help = "Perform full system check.", required = False, action='store_true')
parser.add_argument("-s", "--scan-findings", help = "scan found files.", required = False, action='store_true')
parser.add_argument("-w", "--whitelist", help = "Create whitelist.", required = False, action='store_true')
parser.add_argument("-i", "--info", help = "Get more information.", required = False, action='store_true')
parser.add_argument("-d", "--duration", metavar="<seconds>", help = "Duration in seconds.", required = False, default= "300")
parser.add_argument("-e", "--filter", metavar="<npcap filter>", help = "Filter packet capture.", required = False, default= "")


argument = parser.parse_args()
   
def init():
    try:
        if not os.path.exists("Logs"):
            os.makedirs("Logs")
    except:
        print("Failed to create Logs dir")
        return
    
    if argument.take_snapshot:
        print("Taking snapshot. Please wait ..")
        take_system_snapshot(argument.full)
    elif argument.check_integrity:
        print("Checking system integrity. Please wait ..")
        check_integrity(argument.output, argument.scan_findings, argument.full)
    elif argument.virus_total != "":
        print("Trying to scan the chosen file, please wait for the report to complete ..")
        file = argument.virus_total
        hash_val = sha256sum(file)
        if not hash_val:
            get_report(file, hash_val)
    elif argument.process_listener:
        print("Starting process listener for " + str(argument.duration) + " seconds.")
        if argument.whitelist:
            take_memory_snapshot(int(argument.duration))
        else:
            inspect_procs(int(argument.duration), argument.output)
    elif argument.sniff:
        print("Starting network sniffer for " + str(argument.duration) + " seconds.")
        if argument.whitelist:
            take_connections_snapshot(int(argument.duration), "")
        else:
            inspect_network(int(argument.duration), str(argument.filter), argument.output, argument.info)
    elif argument.analyze != "":
        print("Analyzing file, please wait for the report to complete ..")
        write_pe_report(argument.analyze)
    

def check_priv():
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0


if check_priv():
    try:
        init()
    except KeyboardInterrupt:
        sys.exit(0)
else:
    print("Admin privileges required.")