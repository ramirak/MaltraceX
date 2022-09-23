import json, os

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
    if(os.path.isfile):
        with open(filename, 'r') as f:
            return json.load(f)
    print("File " + filename + " does not exists")
    exit(-1)


def show_file_content(filename):
    with open(filename, 'r') as f:
        print(f.read())