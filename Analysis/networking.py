import subprocess, whois
from Data.files import retrieve_lines_from_file
import Data.enums as enums 
from Utils.string_utils import find_between

def catpure_packets(duration):
    output = enums.files.TDUMP.value
    try:
        # Capture any traffic not destined to local network and not related to basic http/s traffic
        cmd = "sudo timeout " + duration + " tcpdump -nni any not port 443 and not port 80 and not dst net 192.168.0.0/16 and not dst net 10.0.0.0/16 and not dst net 172.16.0.0/16 &> " + output + "&"
         
        subprocess.call(cmd, shell=True)
        return enums.results.SUCCESS.value
    except Exception as e:
        print(e)
        return enums.results.GENERAL_FAILURE.value


def inspect_addresses(pcap_filename):
    packets = retrieve_lines_from_file(pcap_filename)
    strings = []
    new_connections = set()
    report = ""

    for packet in packets:
        strings.append(find_between(packet, "> ", ":"))
  
    for string in strings:
        new_connections.add(string.rsplit('.', 1)[0]) 

    for address in new_connections:
        if len(address) <= 1:
            continue
        ip_info = str(whois.whois(address))
        report += "New connection: " + address + " : \n"
        report += ip_info + "\n"

    return report
        
