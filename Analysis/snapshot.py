

import Data.files as files
import Data.enums as enums
from Modules.registry import *
from Modules.harddisk import *
from Modules.networking import *
from Modules.memory import *


def take_system_snapshot(full_check):
    try:    
        disk_map = collect_files()
        if not disk_map:
            return False
        files.dump_to_file(disk_map, enums.files.HASHES.value)
        if full_check:
            reg_map = collect_registry()
            if not reg_map:
                return False
            files.dump_to_file(reg_map, enums.files.REGISTRY.value)
        return True
    except Exception as e:
        print(e)
        return False


def take_memory_snapshot(duration):
    try:
        processes = collect_processes(duration)
        if not processes:
            return False
        files.dump_to_file(processes, enums.files.PROCESSES.value)
        return True 
    except Exception as e:
        print(e)
        return False


def take_connections_snapshot(duration, flt):
    try:
        connections = catpure_packets(duration, flt)
        if not connections:
            return False
        files.dump_to_file(connections, enums.files.CAPTURE.value)
        return True 
    except Exception as e:
        print(e)
        return False
