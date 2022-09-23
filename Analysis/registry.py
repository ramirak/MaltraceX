from Data.files import retrieve_from_file
import os

## Windows only
if os.name == 'nt':
    from winreg import *

    def get_value(key):
        i = 0
        values = {}
        while True:
            try:
                keyname = EnumValue(key, i)
                values.update({keyname[0]: keyname[1]})
            except WindowsError:
                return values
            i+=1

    def str_to_regkey(str):
        if str == "HKLM":
            return HKEY_LOCAL_MACHINE
        if str == "HKCU":
            return HKEY_CURRENT_USER
        if str == "HKCR":
            return HKEY_CLASSES_ROOT
        if str == "HKU":
            return HKEY_USERS
        if str == "HKCC":
            return HKEY_CURRENT_CONFIG


    def get_reg_dict():
        paths = retrieve_from_file("Conf/paths.conf")
        data = retrieve_from_file(paths["registry"])
        x = 0
        registry_dict = {}
        for reg in data["commonReg"]:
            try:
                key_s = reg["key"]
                path = reg["path"]
                key = OpenKey(str_to_regkey(key_s), path, 0, KEY_READ)
                value = get_value(key)
                registry_dict.update({path : [key_s,value]})
                x+=1
            except WindowsError:
                continue
        return registry_dict

else:
    def get_reg_dict():
        return {}