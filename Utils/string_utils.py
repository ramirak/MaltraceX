
def format_proc(proc, values):
    return ('%-30s %-10f %-10f %-20s %-10s\n%s\n' % (proc , values[0], values[1], values[2], values[3], values[4]))
  

def get_proc_header():
    return ('%-30s %-10s %-10s %-20s %-10s\n' % ("Name" , "Memory", "CPU", "Date", "Path"))


def print_divider():
    return "\n----------------------------------------------------------------------------------\n";


def print_header(header_str):
    header = ""
    length = 100
    side = (length - len(header_str)) / 2
    header += get_n_chars(int(side), "-")
    header += " " + header_str + " "
    header += get_n_chars(int(side), "-")
    return header + "\n"


def get_n_chars(length, ch):
    new_str = ""
    for i in range(length):
        new_str += ch
    return new_str