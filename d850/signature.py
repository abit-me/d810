import json
from pathlib import Path
from typing import Set

import idapro
import ida_auto
import ida_funcs
import ida_idp


class SignatureHooks(ida_idp.IDB_Hooks):
    """
    IDB hooks for tracking signature matching results.

    Attributes:
        matched_funcs: Set of function start addresses that matched signatures
    """

    def __init__(self):
        super().__init__()
        self.matched_funcs: Set[int] = set()

    def func_added(self, pfn: ida_funcs.func_t) -> int:
        """Called when a function is added to the database."""
        self.matched_funcs.add(pfn.start_ea)
        return 0

    def func_deleted(self, func_ea: int) -> int:
        """Called when a function is deleted from the database."""
        self.matched_funcs.discard(func_ea)
        return 0

    def func_updated(self, pfn: ida_funcs.func_t) -> int:
        """Called when a function is updated."""
        self.matched_funcs.add(pfn.start_ea)
        return 0

    def idasgn_loaded(self, sig_name: str) -> int:
        """Called when a signature file is loaded."""
        print(f"✓ Signature loaded: {sig_name}")
        return 0

    def dump_matches(self) -> None:
        """Print all matched functions."""
        if not self.matched_funcs:
            print("No functions matched")
            return

        print(f"\nMatched Functions ({len(self.matched_funcs)}):")
        for func_ea in sorted(self.matched_funcs):
            func_name = ida_funcs.get_func_name(func_ea)
            print(f"  {func_name or '<unnamed>'} @ {hex(func_ea)}")


def apply_signature_file(
        database_path: str,
        signature_path: str,
        output_path: str
) -> bool:
    """
    Apply a signature file and save matching results.

    Args:
        database_path: Path to the IDA database
        signature_path: Path to the .sig file
        output_path: Path to save JSON results

    Returns:
        True if signature applied successfully, False otherwise
    """
    sig_file = Path(signature_path)

    # Validate signature file
    if not sig_file.is_file():
        print(f"✗ Error: Signature file not found: {signature_path}")
        return False

    if sig_file.suffix != '.sig':
        print(f"✗ Error: Not a .sig file: {signature_path}")
        return False

    print(f"✓ Applying signature: {sig_file.name}")

    # Install hooks to track matches
    sig_hook = SignatureHooks()
    sig_hook.hook()

    try:
        # Apply signature and wait for completion
        ida_funcs.plan_to_apply_idasgn(str(sig_file))
        print("  Waiting for signature analysis...")
        ida_auto.auto_wait()

        # Get match statistics
        total_matches = 0
        sig_count = ida_funcs.get_idasgn_qty()

        for index in range(sig_count):
            sig_name, _, match_count = ida_funcs.get_idasgn_desc_with_matches(index)
            if sig_file.name in sig_name:
                total_matches = match_count
                break

        # Build results
        results = {
            "signature_file": str(sig_file),
            "database_file": database_path,
            "total_matches": total_matches,
            "matched_functions": []
        }

        for func_ea in sorted(sig_hook.matched_funcs):
            func_name = ida_funcs.get_func_name(func_ea)
            results['matched_functions'].append({
                "name": func_name or "<unnamed>",
                "address": hex(func_ea)
            })

        # Save results
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"✓ Signature applied: {total_matches} matches")
        print(f"✓ Results saved to: {output_path}")

        return True

    except Exception as e:
        print(f"✗ Signature application failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        sig_hook.unhook()