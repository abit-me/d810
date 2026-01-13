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


def get_all_subclasses(python_class: type) -> list[type]:
    """Return all subclasses of a class, recursively.

    Traverses the entire class hierarchy to find all concrete subclasses,
    returning them sorted by class name.
    """
    python_class.__subclasses__()

    subclasses = set()
    check_these = [python_class]

    while check_these:
        parent = check_these.pop()
        for child in parent.__subclasses__():
            if child not in subclasses:
                subclasses.add(child)
                check_these.append(child)

    return sorted(subclasses, key=lambda x: x.__name__)