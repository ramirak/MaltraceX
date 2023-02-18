from enum import Enum

p = "Logs/"

class files(Enum):
    CONFIG = "maltrace.conf"
    TRACES = p + "traces.mt"
    HASHES = p + "hashes.mt"
    PESCAN = p + "pescan.mt"
    REPORT = p + "reports.mt"
    REGISTRY = p + "registry.mt"
    PROCESSES = p + "processes.mt"


class operations(Enum):
    VIRUS_TOTAL_SCAN = 0
    PE_ANALYZE = 1 


class results(Enum):
    GENERAL_FAILURE = -1
    API_KEY_NOT_FOUND = 0
    SNAPSHOT_NOT_FOUND = 1
    NO_MATCH_FOUND = 2
    NON_PE_FILE = 3
    FINISHED_WITH_ERRORS = 4
    FILE_NOT_FOUND = 5
    SUCCESS = 6