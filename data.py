import json

def dump_to_file(data,filename):
    with open(filename, 'w') as convert_file:
        convert_file.write(json.dumps(data))


def retrieve_from_file(filename):
    with open(filename, 'r') as f:
        return json.load(f)


def show_traces():
    with open('traces.mt', 'r') as f:
        print(f.read())