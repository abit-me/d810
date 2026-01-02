import ida_segment

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