import subprocess
from scapy.all import *
from Data.files import retrieve_lines_from_file
import Data.enums as enums 
from Data.report import do_print
import whois

def catpure_packets(duration, flt):
    output_file = enums.files.CAPTURE.value
    conns = {}
    try:
        def collect_packets(conns):
            def packet_callback(packet):
                sport = 0
                dport = 0            
                if UDP in packet:
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                if TCP in packet:
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                if IP in packet:
                    ip_src=packet[IP].src
                    ip_dst=packet[IP].dst
                    
                    do_print("%s:%s -> %s:%s" % (ip_src, sport, ip_dst, dport), 0)

                    if get_if_addr(conf.iface) != ip_dst:
                        conns.update({ str(ip_dst) : str(dport)})
            return packet_callback            
        sniff(filter=flt, prn=collect_packets(conns), timeout=duration)
        return conns
    except Exception as e:
        print(e)
        return False


def inspect_address(conn, log_mode):
    try:
        ip_info = whois.whois(conn)
        do_print("Initiating Whois for - " + conn + " :\n", log_mode)
        do_print(str(ip_info) + "\n", log_mode)
        return True
    except Exception as e:
        print(e)
        return False        
