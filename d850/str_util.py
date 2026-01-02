def str_to_bool(value: str) -> bool:
    """
    Convert string to boolean.

    Args:
        value: String value to convert

    Returns:
        Boolean value

    Raises:
        ValueError: If value is not a valid boolean string
    """
    if isinstance(value, bool):
        return value

    value_lower = value.lower()

    if value_lower in {'false', 'f', '0', 'no', 'n'}:
        return False
    elif value_lower in {'true', 't', '1', 'yes', 'y'}:
        return True

    raise ValueError(f"'{value}' is not a valid boolean value")


def str_to_int(s: str) -> int:
    """
    将字符串转换为整数，自动识别十六进制（0x前缀）和十进制

    Args:
        s: 输入字符串，如 "0xadcc", "44492"

    Returns:
        int: 转换后的整数

    Raises:
        ValueError: 如果字符串格式无效
    """
    # int() 的第二个参数为 0 时会自动检测进制
    # 支持 0x, 0o, 0b 前缀
    return int(s, 0)