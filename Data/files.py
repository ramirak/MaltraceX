import json, os
import Data.enums as enums


def dump_to_file(data,filename):
    with open(filename, 'w+') as convert_file:
        convert_file.write(json.dumps(data))


def dump_list_to_file(lst, msg, log_file):
    if log_file:
        with open(log_file, 'a+') as f:
            f.write(msg)
            for val in lst:
                if type(val) is list:
                    for i in val:
                        f.write("- " + str(i) + "\n")
                else: 
                    f.write("- " + str(val) + "\n")


def retrieve_from_file(filename):
    if os.path.isfile:
        with open(filename, 'r') as f:
            return json.load(f)
    return enums.results.FILE_NOT_FOUND.value


def retrieve_lines_from_file(filename):
    lines = []
    with open(filename) as file:
        for line in file:
            lines.append(line)
    return lines


def show_file_content(filename):
    if os.path.isfile(filename):
        with open(filename, 'r') as f:
            content = f.read()
            return content
    return ""
