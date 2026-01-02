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
from d850.decompile import decompile_func, decompile_all_func
from d850.script import run_script
from d850.segment import list_segments
from d850.signature import apply_signature_file

D850_VERSION = "0.1"


########################################################################################################################

def start(addr: ida_idaapi.ea_t = 0, force_recompile: bool = True):

    ida_hexrays.init_hexrays_plugin()
    state_manager = StateManager()
    state_manager.start()
    if addr == 0:
        decompile_all_func()
    else:
        decompile_func(addr, force_recompile)

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
    if args.target:
        print(f"Function:          {args.target}")

    print(f"Persist changes:   {args.persist}")
    print(f"{'='*70}\n")

    try:
        # Open database
        print(f"Opening database...")
        idapro.open_database(args.file, True)
        print(f"✓ Database opened")

        # D810 start
        # start(0xADCC)
        start(args.target, True)

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