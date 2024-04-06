from datetime import datetime
import Data.enums as enums


def write_report(filename, data, mode):
    with open(filename, mode) as report_file:
        dt_string = datetime.now()
        report_file.write(str(dt_string) + ": " + data + "\n")


def do_print(string, write_to_file):
    if write_to_file:
        write_report(enums.files.REPORT.value, string, "a+")
    elif write_to_file == 0:
        print(string)
    else:
        # No print
        pass