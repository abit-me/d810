import os
import json
import idaapi
from ida_kernwin import is_idaq

MANAGER_INFO_FILENAME = "manager_info.json"
def reload_all_modules():
    manager_info_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), MANAGER_INFO_FILENAME)

    with open(manager_info_path, "r") as f:
        manager_info = json.load(f)

    for module_name in manager_info["module_list"]:
        if module_name == "d810.ida_ui" and not is_idaq():
            continue
        # print("require module_name: " + module_name)
        idaapi.require(module_name)