import glob, os, time, subprocess, wmi
from scapy.all import *


conns = {}

def collect_packets(conns):
    def packet_callback(packet):
        if IP in packet:
            ip_src=packet[IP].src
            ip_dst=packet[IP].dst
        #print("%s -> %s" % (ip_src, ip_dst))
            conns.update({ str(ip_src) : str(ip_dst)})
    return packet_callback

sniff(filter="port 443", prn=collect_packets(conns), timeout=20)


print(conns)

'''
def list_registry_keys(root_key, registry_path, registry_dict):
    try:
        key = winreg.OpenKey(root_key, registry_path)
        for i in range(winreg.QueryInfoKey(key)[0]):
            subkey_name = winreg.EnumKey(key, i)
            full_path = registry_path + str("\\") + subkey_name
            if registry_path == '':
                full_path = subkey_name
            try:
                hkey = winreg.OpenKey(root_key, full_path, 0, winreg.KEY_READ)
                for j in range(winreg.QueryInfoKey(hkey)[1]):
                    value = winreg.EnumValue(hkey, j)
                    registry_dict.update({full_path + "\\" + value[0] : [value]})
            except Exception as e:
                pass
            list_registry_keys(root_key, full_path, registry_dict)
    except Exception as e:
        pass



registry_dict = {}
list_registry_keys(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\ActivationBroker', registry_dict)

print(str(registry_dict))

'''
