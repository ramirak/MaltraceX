from Data.files import retrieve_from_file
import Data.enums as enums
import os

## Windows only
if os.name == 'nt':
    import winreg

    def str_to_regkey(str):
        if str == "HKLM":
            return winreg.HKEY_LOCAL_MACHINE
        if str == "HKCU":
            return winreg.HKEY_CURRENT_USER
        if str == "HKCR":
            return winreg.HKEY_CLASSES_ROOT
        if str == "HKU":
            return winreg.HKEY_USERS
        if str == "HKCC":
            return winreg.HKEY_CURRENT_CONFIG


    def list_registry_keys(root_key, registry_path, registry_dict):
        try:
            key = winreg.OpenKey(root_key, registry_path)
            for i in range(winreg.QueryInfoKey(key)[0]):
                subkey_name = winreg.EnumKey(key, i)
                full_path = registry_path + str("\\") + subkey_name
                if registry_path == "":
                    full_path = subkey_name
                try:
                    hkey = winreg.OpenKey(root_key, full_path, 0, winreg.KEY_READ)
                    for j in range(winreg.QueryInfoKey(hkey)[1]):
                        value = winreg.EnumValue(hkey, j)
                        registry_dict.update({full_path + "\\" + value[0] : str(value)})
                except Exception as e:
                    pass
                list_registry_keys(root_key, full_path, registry_dict)
        except Exception as e:
            pass


    def collect_registry():
        try:
            config = retrieve_from_file(enums.files.CONFIG.value)
            if not config:
                return False
            registry_dict = {}
            for reg in config["monitored_registry"]:    
                key = reg["key"]
                path = reg["path"]
                list_registry_keys(str_to_regkey(key), path, registry_dict)
            return registry_dict
        except Exception as e:
            print(e)
            return False

else:
    def collect_registry():
        return {}
