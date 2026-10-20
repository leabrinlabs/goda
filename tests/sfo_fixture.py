"""Synthetic PSF metadata for host-only tests; no game assets."""
import struct
PSF_MAGIC=b"\0PSF"
PSF_TEXT=0x0204
PSF_INTEGER=0x0404
PSF_BINARY=0x0004

def make_sfo(values: dict[str, str | int | bytes]) -> bytes:
    """Create a deterministic minimal PSF fixture for host-side tests."""
    keys = bytearray()
    value_table = bytearray()
    entries: list[tuple[int, int, int, int, int]] = []
    for key in sorted(values):
        key_rel = len(keys)
        keys.extend(key.encode("utf-8") + b"\0")
        while len(value_table) % 4:
            value_table.append(0)
        value_rel = len(value_table)
        value = values[key]
        if isinstance(value, str):
            encoded = value.encode("utf-8") + b"\0"
            fmt = PSF_TEXT
        elif isinstance(value, int):
            encoded = struct.pack("<i", value)
            fmt = PSF_INTEGER
        else:
            encoded = bytes(value)
            fmt = PSF_BINARY
        value_table.extend(encoded)
        entries.append((key_rel, fmt, len(encoded), len(encoded), value_rel))

    key_offset = 20 + len(entries) * 16
    data_offset = key_offset + len(keys)
    header = struct.pack("<4sIIII", PSF_MAGIC, 0x00000101, key_offset, data_offset, len(entries))
    index = bytearray()
    for key_rel, fmt, length, max_length, value_rel in entries:
        index.extend(struct.pack("<HHIII", key_rel, fmt, length, max_length, value_rel))
    return bytes(header + index + keys + value_table)
