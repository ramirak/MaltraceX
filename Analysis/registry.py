from Data.files import retrieve_from_file
import Data.enums as enums
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


    def take_registry_snapshot():
        config = retrieve_from_file(enums.files.CONFIG.value)
        x = 0
        registry_dict = {}
        for reg in config["monitored_registry"]:
            try:
                key_str = reg["key"]
                path = reg["path"]
                key = OpenKey(str_to_regkey(key_str), path, 0, KEY_READ)
                value = get_value(key)
                registry_dict.update({path : [key_str,value]})
                x+=1
            except WindowsError:
                break
        return registry_dict

else:
    def take_registry_snapshot():
        return {}