from datetime import datetime

def format_proc(proc, values):
    return ('%-30s %-10f %-10f %-20s %-10s\n%s\n' % (proc , values[0], values[1], values[2], values[3], values[4]))
  

def get_proc_header():
    return ('%-30s %-10s %-10s %-20s %-10s\n' % ("Name" , "Memory", "CPU", "Date", "Path"))


def print_divider():
    return "\n-------------------------------------------\n";


def get_n_chars(length, ch):
    new_str = ""
    for i in range(length):
        new_str += ch
    return new_str


def print_header(header_str):
    header = "\n"
    length = 100
    side = (length - len(header_str)) / 2
    header += get_n_chars(int(side), "-")
    header += " " + header_str + " "
    header += get_n_chars(int(side), "-")
    return header + "\n"


def write_report(filename, header, data, end , mode):
    with open(filename, mode) as report_file:
        report_file.write(print_header(header))
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        report_file.write(dt_string + "\n")
        report_file.write(data + "\n")
        if end:
            report_file.write(print_header("End " + header))
