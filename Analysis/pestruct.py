from datetime import datetime
import pefile
import Data.enums as enums
import Data.files as files

def pe_load(filename):
    try:
        return pefile.PE(filename)
    except:
        return


def get_dlls(pe, additional_info):
    dll_list = []
    pe_imports = []
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:    
            if entry.dll != None:
                dll_list.append(entry.dll.decode())
                if additional_info:
                    pe_imports.append(get_imported_functions(entry))
        if additional_info:
            return dll_list, pe_imports
    except:
        return None
    return dll_list


def get_imported_functions(entry):
    pe_imports = []
    for func in entry.imports:
        if func.name != None:
            pe_imports.append(func.name.decode('utf-8'))
    return pe_imports


def get_dos_headers(pe):
    return pe.DOS_HEADER.dump()


def write_pe_report(chosen_file):
    pe = pe_load(chosen_file)
    if pe != None:
        dlls, funcs = get_dlls(pe, True)
        log_file = enums.files.PESCAN.value
        with open(log_file, "a+") as logfile:
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            logfile.write("\n-------------------- " + chosen_file + ": " + dt_string + " --------------------\n")
        files.dump_list_to_file(get_dos_headers(pe), "\n----------- DOS Headers: -----------\n", log_file)
        files.dump_list_to_file(dlls, "\n----------- Dll imports: -----------\n", log_file)
        files.dump_list_to_file(funcs, "\n----------- Functions: -----------\n", log_file)
        files.dump_list_to_file(pe.sections, "\n----------- Sections: -----------\n", log_file)
        return enums.results.SUCCESS.value
    else:
        return enums.results.NON_PE_FILE.value