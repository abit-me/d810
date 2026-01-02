import ida_idaapi
from pathlib import Path

def run_script(script_path: str) -> bool:
    """
    Execute a Python script in IDA's context.

    Args:
        script_path: Path to the Python script file

    Returns:
        True if script executed successfully, False otherwise
    """
    script_file = Path(script_path)

    if not script_file.is_file():
        print(f"✗ Error: Script file not found: {script_path}")
        return False

    if script_file.suffix != '.py':
        print(f"✗ Error: Not a Python file: {script_path}")
        return False

    try:
        print(f"✓ Executing script: {script_file.name}")
        ida_idaapi.IDAPython_ExecScript(str(script_file), globals())
        print(f"✓ Script completed successfully")
        return True
    except Exception as e:
        print(f"✗ Script execution failed: {e}")
        import traceback
        traceback.print_exc()
        return False