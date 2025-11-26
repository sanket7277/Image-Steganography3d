import base64
import hashlib
from typing import Dict
from PIL import Image

# MAGIC header for validation
MAGIC = b'STG1'


# ============================================================
# KEY DERIVATION (SHA256 -> Fernet key)
# ============================================================
def _derive_fernet_key(password: str) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


# ============================================================
# PAYLOAD CREATOR
# Supports:
# - text
# - file (any type: image / video / 3d / etc.)
# ============================================================
def prepare_payload(
    kind: str,
    text: str = "",
    blob: bytes = b"",
    file_ext: str = "bin",
    password: str = ""
) -> bytes:

    flags = 0
    encrypted = False

    # ------------------------------------------------------------
    # TEXT PAYLOAD
    # ------------------------------------------------------------
    if kind == "text":
        data = text.encode("utf-8")
        flags |= (1 << 0)  # mark as text

    # ------------------------------------------------------------
    # GENERIC FILE PAYLOAD (image, video, 3D, etc.)
    # ------------------------------------------------------------
    elif kind == "file":
        ext_bytes = file_ext.lower().encode("utf-8")
        data = bytes([len(ext_bytes)]) + ext_bytes + blob
        flags |= (1 << 1)  # mark as file

    else:
        raise ValueError("Invalid kind provided to prepare_payload")

    # ------------------------------------------------------------
    # ENCRYPT IF PASSWORD PROVIDED
    # ------------------------------------------------------------
    if password:
        from cryptography.fernet import Fernet

        f = Fernet(_derive_fernet_key(password))
        data = f.encrypt(data)
        flags |= (1 << 2)  # encrypted flag
        encrypted = True

    # ------------------------------------------------------------
    # FORMAT:
    # MAGIC | FLAGS | LENGTH(4 bytes) | DATA
    # ------------------------------------------------------------
    length = len(data).to_bytes(4, "big")
    return MAGIC + bytes([flags]) + length + data


# ============================================================
# PAYLOAD PARSER
# Detects:
# - text
# - file
# - encrypted or not
# ============================================================
def parse_payload(payload: bytes, password: str = "") -> Dict:

    if len(payload) < 9 or payload[:4] != MAGIC:
        raise ValueError("Invalid or corrupted payload")

    flags = payload[4]

    is_text = bool(flags & (1 << 0))
    is_file = bool(flags & (1 << 1))
    encrypted = bool(flags & (1 << 2))

    length = int.from_bytes(payload[5:9], "big")
    data = payload[9:9 + length]

    # ------------------------------------------------------------
    # DECRYPT IF NEEDED
    # ------------------------------------------------------------
    if encrypted:
        if not password:
            raise ValueError("Password required to decrypt payload")

        from cryptography.fernet import Fernet
        f = Fernet(_derive_fernet_key(password))
        data = f.decrypt(data)

    # ------------------------------------------------------------
    # TEXT PAYLOAD
    # ------------------------------------------------------------
    if is_text:
        return {
            "kind": "text",
            "text": data.decode("utf-8", errors="replace")
        }

    # ------------------------------------------------------------
    # FILE PAYLOAD
    # FORMAT:
    # [ext_len:1] [ext:ext_len bytes] [blob:remaining bytes]
    # ------------------------------------------------------------
    if is_file:
        ext_len = data[0]
        ext = data[1:1 + ext_len].decode("utf-8")
        blob = data[1 + ext_len:]

        return {
            "kind": "file",
            "file_ext": ext,
            "blob": blob
        }

    raise ValueError("Unknown payload type")


# ============================================================
# BIT HELPERS
# ============================================================
def _bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def _bits_to_bytes(bits):
    out = bytearray()
    cur = 0
    count = 0

    for b in bits:
        cur = (cur << 1) | (b & 1)
        count += 1

        if count == 8:
            out.append(cur)
            cur = 0
            count = 0

    return bytes(out)


# ============================================================
# LSB ENCODE
# ============================================================
def encode_lsb(cover_path: str, payload: bytes, out_path: str):

    img = Image.open(cover_path).convert("RGB")
    pixels = list(img.getdata())

    flat = [c for pixel in pixels for c in pixel]

    if len(payload) * 8 > len(flat):
        raise ValueError("Cover image too small for payload!")

    bit_stream = _bytes_to_bits(payload)
    flat_mod = []

    for i, val in enumerate(flat):
        try:
            bit = next(bit_stream)
            flat_mod.append((val & 0xFE) | bit)
        except StopIteration:
            flat_mod.extend(flat[i:])
            break

    new_pixels = [
        tuple(flat_mod[i:i + 3])
        for i in range(0, len(flat_mod), 3)
    ]

    out = Image.new("RGB", img.size)
    out.putdata(new_pixels)
    out.save(out_path, format="PNG")


# ============================================================
# LSB DECODE
# ============================================================
def decode_lsb(stego_path: str) -> bytes:

    img = Image.open(stego_path).convert("RGB")
    flat = [c for pixel in img.getdata() for c in pixel]

    bits = [(val & 1) for val in flat]
    data = _bits_to_bytes(bits)

    if len(data) < 9 or data[:4] != MAGIC:
        raise ValueError("Invalid stego or no hidden data found")

    length = int.from_bytes(data[5:9], "big")
    return data[:9 + length]
