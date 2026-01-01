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