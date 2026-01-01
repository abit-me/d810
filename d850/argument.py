import argparse
from pathlib import Path
from typing import Optional

from commandline.str_util import str_to_bool


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure argument parser.

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        description="IDA Pro batch analysis tool using idalib",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List segments
  %(prog)s -f binary.exe -l

  # Run analysis script
  %(prog)s -f binary.dll -s analysis.py

  # Apply signature and save results
  %(prog)s -f binary.so -g sigs.sig -o results.json

  # Multiple operations without saving
  %(prog)s -f binary.exe -l -s script.py -p false
        """
    )

    parser.add_argument(
        '-f', '--file',
        required=True,
        type=str,
        metavar='PATH',
        help='Binary file to analyze'
    )

    parser.add_argument(
        '-l', '--list-segments',
        type=str_to_bool,
        nargs='?',
        const=True,
        default=False,
        metavar='BOOL',
        help='List all segments (default: false)'
    )

    parser.add_argument(
        '-s', '--script',
        type=str,
        metavar='PATH',
        help='Python script to execute'
    )

    parser.add_argument(
        '-g', '--signature',
        type=str,
        metavar='PATH',
        help='Signature file (.sig) to apply'
    )

    parser.add_argument(
        '-o', '--output',
        type=str,
        metavar='PATH',
        help='Output file for signature results (JSON)'
    )

    parser.add_argument(
        '-p', '--persist',
        type=str_to_bool,
        nargs='?',
        const=True,
        default=True,
        metavar='BOOL',
        help='Save database changes (default: true)'
    )

    return parser


def validate_arguments(args: argparse.Namespace) -> Optional[str]:
    """
    Validate command-line arguments.

    Args:
        args: Parsed arguments

    Returns:
        Error message if validation fails, None otherwise
    """
    # Check signature and output are used together
    if (args.signature is not None) != (args.output is not None):
        return "Arguments -g/--signature and -o/--output must be used together"

    # Check binary file exists
    if not Path(args.file).is_file():
        return f"Binary file not found: {args.file}"

    # Check script exists if specified
    if args.script and not Path(args.script).is_file():
        return f"Script file not found: {args.script}"

    # Check signature exists if specified
    if args.signature and not Path(args.signature).is_file():
        return f"Signature file not found: {args.signature}"

    return None