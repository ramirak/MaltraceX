from enum import Enum

p = "Logs/"

class files(Enum):
    CONFIG = "maltrace.conf"
    HASHES = p + "hashes.mt"
    PESCAN = p + "pescan.mt"
    CAPTURE  = p + "capture.mt"
    REPORT = p + "report.mt"
    REGISTRY = p + "registry.mt"
    PROCESSES = p + "processes.mt"