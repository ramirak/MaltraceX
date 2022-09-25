from logging import exception
import psutil
from datetime import datetime

def get_procs():
    pids = psutil.pids()
    proc_list = {}
    for pid in pids: 
        try:
            p = psutil.Process(pid)
            proc_name = p.name()
            proc_mem = p.memory_percent()            
            proc_cpu = p.cpu_percent()
            proc_location = p.cwd()
            proc_cons = ""
            cons = p.connections()
            if len(cons) != 0:
                proc_cons = "Connection: " + str(cons[0][3][0]) + ":" + str(cons[0][3][1]) + " -> " + str(cons[0][4][0]) + ": " + str(cons[0][4][1]) + "\n"
            c_date = datetime.fromtimestamp(p.create_time()).strftime('%Y-%m-%d %H:%M:%S')
            if proc_name not in proc_list:
                proc_list.update({proc_name: [proc_mem, proc_cpu, c_date, proc_location, proc_cons]})
        except:
            continue
    return proc_list


def get_connections():
    conn_str = ""
    for conn in psutil.net_connections():
        conn_str += "%-45s | %-40s | State: %-15s | PID: %-20s \n" % (str(conn[3])[8:-1], str(conn[4])[8:-1], conn[5] ,conn[6])
    return conn_str

