#!/usr/bin/env python3
"""
IDA Pro Batch Analysis Tool
============================

A command-line tool for automated binary analysis using IDA Pro's idalib.

Features:
- Automatic analysis with auto-wait
- Segment enumeration
- Python script execution
- Signature file application
- Undo/redo support
- JSON output for signature matches

Usage:
    python idacli.py -f binary.exe -l
    python idacli.py -f binary.dll -s analysis.py
    python idacli.py -f binary.so -g signatures.sig -o results.json

Author: IDA Pro User
Date: 2025-12-31
"""

import os
import sys
from pathlib import Path

import idapro
import ida_segment
import ida_idaapi
import ida_funcs
import ida_undo
import ida_hexrays

from d850.argument import create_argument_parser, validate_arguments
from d810.state_manager import StateManager
from d850.decompile import decompile
from d850.signature import apply_signature_file

D850_VERSION = "0.1"

def list_segments() -> None:
    """
    List all segments in the loaded binary.

    Prints detailed information about each segment including:
    - Name, start/end addresses
    - Segment class (code/data)
    - Bitness and permissions
    """
    segment_count = ida_segment.get_segm_qty()

    if segment_count == 0:
        print("No segments found")
        return

    print(f"\n{'='*70}")
    print(f"Segments ({segment_count} total)")
    print(f"{'='*70}\n")

    for i in range(segment_count):
        seg = ida_segment.getnseg(i)
        if not seg:
            continue

        seg_name = ida_segment.get_segm_name(seg)
        seg_class = ida_segment.get_segm_class(seg)
        is_data = seg_class == ida_segment.SEG_DATA
        is_code = seg_class == ida_segment.SEG_CODE

        print(f"[{i + 1}] {seg_name}")
        print(f"    Address:     {hex(seg.start_ea)} - {hex(seg.end_ea)}")
        print(f"    Size:        {seg.end_ea - seg.start_ea:,} bytes")
        print(f"    Type:        {'Data' if is_data else 'Code' if is_code else 'Other'}")
        print(f"    Bitness:     {seg.bitness * 8}-bit")
        print(f"    Permissions: {seg.perm:#x}")
        print()


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


# def cleanup():
#     """清理所有 hooks"""
#     global test_hook, state_manager
#
#     try:
#         if 'test_hook' in globals() and test_hook:
#             test_hook.unhook()
#             print("✓ Test hook cleaned up")
#     except:
#         pass
#
#     try:
#         if 'state_manager' in globals() and state_manager:
#             state_manager.stop()  # StateManager 应该有 stop() 方法
#             print("✓ State manager cleaned up")
#     except:
#         pass


########################################################################################################################
    # ✅ 创建 StateManager
    # state_manager = StateManager()
    # state_manager.start()
    # print("D-810 ready to deobfuscate...")

def start():

    result = ida_hexrays.init_hexrays_plugin()
    # print(f"ida_hexrays.init_hexrays_plugin(): {result}")
    # test_hook()
    # state_manager = StateManager()
    # state_manager.start()
    # decompile_all_func()

    #test_hook.hook()

    state_manager = StateManager()
    state_manager.start()

    decompile(0xADCC, True)
    ida_hexrays.term_hexrays_plugin()

########################################################################################################################

def main() -> int:
    """
    Main entry point.

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    # Parse arguments
    parser = create_argument_parser()
    args = parser.parse_args()

    # Validate arguments
    error_msg = validate_arguments(args)
    if error_msg:
        print(f"✗ Error: {error_msg}\n", file=sys.stderr)
        parser.print_help()
        return 1

    # Print configuration
    print(f"\n{'='*70}")
    print(f"IDA Pro Batch Analysis")
    print(f"{'='*70}")
    print(f"Working directory: {os.getcwd()}")
    print(f"Binary file:       {args.file}")
    if args.script:
        print(f"Script:            {args.script}")
    if args.signature:
        print(f"Signature:         {args.signature}")
        print(f"Output:            {args.output}")
    print(f"Persist changes:   {args.persist}")
    print(f"{'='*70}\n")

    try:
        # Open database
        print(f"Opening database...")
        idapro.open_database(args.file, True)
        print(f"✓ Database opened")

        # D810 start
        start()

        # Create undo point
        if ida_undo.create_undo_point(b"Initial state"):
            print(f"✓ Undo point created")
        else:
            print(f"⚠ Warning: Failed to create undo point")

        # List segments
        if args.list_segments:
            list_segments()

        # Run script
        if args.script:
            if not run_script(args.script):
                print(f"⚠ Warning: Script execution failed")

        # Apply signature
        if args.signature:
            if not apply_signature_file(args.file, args.signature, args.output):
                print(f"⚠ Warning: Signature application failed")

        # Revert changes if needed
        if not args.persist:
            print(f"\nReverting changes...")
            if ida_undo.perform_undo():
                print(f"✓ Changes reverted")
            else:
                print(f"✗ Failed to revert changes")

        return 0

    except KeyboardInterrupt:
        print(f"\n✗ Interrupted by user")
        return 130

    except Exception as e:
        print(f"\n✗ Fatal error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    finally:
        # Always close database
        print(f"\nClosing database...")

        try:
            idapro.close_database(True)
            print(f"✓ Database closed")
        except Exception as e:
            print(f"✗ Error closing database: {e}", file=sys.stderr)

        print(f"\nDone. Thanks for using IDA Pro!\n")


if __name__ == '__main__':
    sys.exit(main())