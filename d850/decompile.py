import ida_funcs
import ida_hexrays
import ida_idaapi


def decompile_all_func():
    """反编译所有函数"""
    import ida_funcs
    import ida_hexrays

    nb_funcs = ida_funcs.get_func_qty()

    for i in range(nb_funcs):
        pfn = ida_funcs.getn_func(i)
        if pfn:
            hf = ida_hexrays.hexrays_failure_t()
            cfunc = ida_hexrays.decompile(pfn, hf, ida_hexrays.DECOMP_NO_WAIT)
            print(f'decompile {cfunc}')
            if cfunc:
                # 如果需要访问 mba 并优化（会 crash）
                # mba = cfunc.mba
                # if mba:
                #     mba.optimize_local(0)
                pass

def decompile_func(func_ea: ida_idaapi.ea_t, force_recompile: bool = False):
    """反编译函数，可选强制重新反编译"""
    import ida_funcs
    import ida_hexrays

    pfn = ida_funcs.get_func(func_ea)
    if not pfn:
        print(f"✗ No function at {hex(func_ea)}")
        return None

    print(f"\nDecompiling {ida_funcs.get_func_name(pfn.start_ea)} @ {hex(pfn.start_ea)}")

    # ✅ 如果需要强制重新反编译
    if force_recompile:
        # 清除该函数的反编译缓存
        ida_hexrays.mark_cfunc_dirty(func_ea)
        print("  ✓ Cleared decompilation cache")

    hf = ida_hexrays.hexrays_failure_t()

    # ✅ 不使用 DECOMP_NO_WAIT，强制完整反编译
    cfunc = ida_hexrays.decompile(pfn, hf, 0)

    if cfunc:
        print(f"✓ Success")
        return cfunc
    else:
        print(f"✗ Failed: {hf.str()}")
        return None