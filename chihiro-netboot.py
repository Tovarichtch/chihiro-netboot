#!/usr/bin/env python3
# chihiro-netboot: convert MAME Chihiro files into playable netboot images.
#
# Usage:
#     chihiro-netboot                          (auto-detect all games in current dir)
#     chihiro-netboot /path/to/games           (auto-detect all games in a folder)
#     chihiro-netboot game.chd game.zip        (convert one game)
#     chihiro-netboot game.cue game.zip        (same, from a Redump cue/bin set)
#     chihiro-netboot --list game.chd game.zip
#
# What you need (from a standard MAME set):
#     1. The game's disc: a .chd (e.g. hotd3/gdx-0001.chd), or the .cue of a
#        Redump cue/bin set with its .bin tracks beside it
#     2. The game's .zip file   (e.g. hotd3.zip)
#
# What you get:
#     output/<game>.bin, a FATX netboot image.
#
# Based on JayFoxRox's Chihiro-Tools. MIT license.

import sys
import os
import struct
import subprocess
import tempfile
import zipfile
import argparse
import array
import shutil
import time
import threading
import ctypes
import ctypes.util
from ctypes import (POINTER, byref, c_char_p, c_int, c_size_t, c_ulong,
                    c_void_p, c_wchar_p, create_string_buffer)


# ---------------------------------------------------------------------------
# DES-ECB through the OS crypto library (CNG / CommonCrypto / OpenSSL),
# so there is nothing to install. pycryptodome is the last-resort fallback.
# ---------------------------------------------------------------------------

DES_TEST_KEY = bytes.fromhex("133457799BBCDFF1")
DES_TEST_CIPHER = bytes.fromhex("85E813540F0AB405")
DES_TEST_PLAIN = bytes.fromhex("0123456789ABCDEF")


def _des_backend_windows():
    # DES-ECB decrypt via Windows CNG (bcrypt.dll, built into Windows).
    b = ctypes.WinDLL("bcrypt")
    for name, args in [
        ("BCryptOpenAlgorithmProvider", [POINTER(c_void_p), c_wchar_p, c_wchar_p, c_ulong]),
        ("BCryptSetProperty", [c_void_p, c_wchar_p, c_char_p, c_ulong, c_ulong]),
        ("BCryptGenerateSymmetricKey", [c_void_p, POINTER(c_void_p), c_char_p, c_ulong, c_char_p, c_ulong, c_ulong]),
        ("BCryptDecrypt", [c_void_p, c_char_p, c_ulong, c_void_p, c_char_p, c_ulong, c_char_p, c_ulong, POINTER(c_ulong), c_ulong]),
    ]:
        f = getattr(b, name)
        f.restype = ctypes.c_long   # NTSTATUS
        f.argtypes = args

    alg = c_void_p()
    if b.BCryptOpenAlgorithmProvider(byref(alg), "DES", None, 0) != 0:
        return None
    mode = "ChainingModeECB".encode("utf-16-le") + b"\x00\x00"
    if b.BCryptSetProperty(alg, "ChainingMode", mode, len(mode), 0) != 0:
        return None

    def decrypt(data, key):
        hkey = c_void_p()
        if b.BCryptGenerateSymmetricKey(alg, byref(hkey), None, 0, key, 8, 0) != 0:
            raise RuntimeError("BCryptGenerateSymmetricKey failed")
        out = create_string_buffer(len(data))
        done = c_ulong(0)
        status = b.BCryptDecrypt(hkey, data, len(data), None, None, 0,
                                 out, len(out), byref(done), 0)
        if status != 0:
            raise RuntimeError(f"BCryptDecrypt failed (0x{status & 0xFFFFFFFF:08X})")
        return out.raw[:done.value]

    return decrypt


def _des_backend_macos():
    # DES-ECB decrypt via CommonCrypto (built into macOS).
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    lib.CCCrypt.restype = c_int
    lib.CCCrypt.argtypes = [c_ulong, c_ulong, c_ulong, c_char_p, c_size_t,
                            c_char_p, c_char_p, c_size_t, c_char_p, c_size_t,
                            POINTER(c_size_t)]
    kCCDecrypt, kCCAlgorithmDES, kCCOptionECBMode = 1, 1, 2

    def decrypt(data, key):
        out = create_string_buffer(len(data))
        moved = c_size_t(0)
        status = lib.CCCrypt(kCCDecrypt, kCCAlgorithmDES, kCCOptionECBMode,
                             key, 8, None, data, len(data),
                             out, len(out), byref(moved))
        if status != 0:
            raise RuntimeError(f"CCCrypt failed ({status})")
        return out.raw[:moved.value]

    return decrypt


def _des_backend_openssl():
    # DES-ECB decrypt via the system OpenSSL (Linux).
    libname = ctypes.util.find_library("crypto")
    if not libname:
        return None
    c = ctypes.CDLL(libname)
    for name, res, args in [
        ("EVP_CIPHER_CTX_new", c_void_p, []),
        ("EVP_CIPHER_CTX_free", None, [c_void_p]),
        ("EVP_DecryptInit_ex", c_int, [c_void_p, c_void_p, c_void_p, c_char_p, c_char_p]),
        ("EVP_CIPHER_CTX_set_padding", c_int, [c_void_p, c_int]),
        ("EVP_DecryptUpdate", c_int, [c_void_p, c_char_p, POINTER(c_int), c_char_p, c_int]),
    ]:
        try:
            f = getattr(c, name)
        except AttributeError:
            return None
        f.restype = res
        f.argtypes = args

    # OpenSSL 3 moved DES into the "legacy" provider; on OpenSSL 1.1 these
    # symbols simply do not exist and EVP_des_ecb() alone is enough.
    try:
        c.OSSL_PROVIDER_load.restype = c_void_p
        c.OSSL_PROVIDER_load.argtypes = [c_void_p, c_char_p]
        c.OSSL_PROVIDER_load(None, b"legacy")
        c.OSSL_PROVIDER_load(None, b"default")
    except AttributeError:
        pass
    try:
        c.EVP_des_ecb.restype = c_void_p
        cipher = c.EVP_des_ecb()
    except AttributeError:
        return None
    if not cipher:
        return None

    def decrypt(data, key):
        ctx = c.EVP_CIPHER_CTX_new()
        try:
            if c.EVP_DecryptInit_ex(ctx, cipher, None, key, None) != 1:
                raise RuntimeError("EVP_DecryptInit_ex failed")
            c.EVP_CIPHER_CTX_set_padding(ctx, 0)
            out = create_string_buffer(len(data))
            outl = c_int(0)
            if c.EVP_DecryptUpdate(ctx, out, byref(outl), data, len(data)) != 1:
                raise RuntimeError("EVP_DecryptUpdate failed")
            return out.raw[:outl.value]
        finally:
            c.EVP_CIPHER_CTX_free(ctx)

    return decrypt


def _des_backend_pycryptodome():
    # Fallback: pycryptodome, if the user has it installed.
    try:
        from Crypto.Cipher import DES
    except ImportError:
        return None

    def decrypt(data, key):
        return DES.new(key, DES.MODE_ECB).decrypt(data)

    return decrypt


def get_des_backend():
    # Pick the first working DES backend for this platform.
    #
    # Returns (name, decrypt_function). Exits with a clear message if none work.
    #
    if sys.platform == "win32":
        order = [("Windows CNG", _des_backend_windows)]
    elif sys.platform == "darwin":
        order = [("CommonCrypto", _des_backend_macos)]
    else:
        order = [("OpenSSL", _des_backend_openssl)]
    order.append(("pycryptodome", _des_backend_pycryptodome))

    for name, factory in order:
        try:
            decrypt = factory()
        except OSError:
            decrypt = None
        if decrypt is None:
            continue
        try:
            if decrypt(DES_TEST_CIPHER, DES_TEST_KEY) == DES_TEST_PLAIN:
                return name, decrypt
        except Exception:
            continue

    print()
    print("  No usable DES implementation found on this system.")
    print("  Install the fallback with:")
    print()
    print("    pip install pycryptodome")
    print()
    sys.exit(1)


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------

def progress(current, total, label=""):
    width = 30
    pct = current / total if total else 1
    filled = int(width * pct)
    bar = "#" * filled + "." * (width - filled)
    mb_done = current / 1024 / 1024
    mb_total = total / 1024 / 1024
    print(f"\r  [{bar}] {pct*100:3.0f}%  {mb_done:.0f}/{mb_total:.0f} MB {label}",
          end="", flush=True)
    if current >= total:
        print()


# ---------------------------------------------------------------------------
# Security IC: extract the DES key and loader filename
# ---------------------------------------------------------------------------

def read_data_file(data):
    # Parse a 80-byte .data dump (10 challenge-response pairs, 8 bytes each).
    #
    # The file layout matches the securityIcDump_t struct in parse-securityic.c:
    #     [0:8]   binaryChallenge    [8:16]  challenge8 (version)
    #     [16:24] challenge7 (test)  [24:32] challenge6
    #     [32:40] challenge5         [40:48] challenge4
    #     [48:56] challenge3         [56:64] challenge2
    #     [64:72] challenge1         [72:80] challenge0
    #
    # Key  = challenge3[1:8] + challenge4[1]  (8 bytes)
    # Loader = challenge5[1:8]                (ASCII filename)
    #
    if len(data) != 80:
        return None, None

    key = data[49:56] + data[41:42]
    loader_raw = data[33:40]
    loader = loader_raw.split(b"\x00")[0].decode("ascii", errors="replace")

    # Basic sanity: key should not be all zeros, loader should be printable
    if key == b"\x00" * 8:
        return None, None
    if not loader or not loader.isprintable():
        return None, None

    return key, loader


def read_pic_file(data):
    # Extract key from a PIC firmware dump (.pic file).
    #
    # The PIC stores challenge responses interleaved in its data section.
    # Each response byte is at stride 2 (every other byte of a 16-byte region).
    # Offsets from extract-securityic.c struct layout.
    #
    # Some dumps are 16400 bytes (16-byte header before the 16384-byte firmware).
    #
    if len(data) == 0x4000 + 16:
        data = data[:0x4000]
    if len(data) != 0x4000:
        return None, None

    # Offsets into PIC firmware for each response field.
    # Derived from the securityIc_t packed struct in extract-securityic.c:
    #   code[0x600] at 0x000, then union starting at 0x600.
    pic_offsets = [
        0x6E0,  # response9 = binaryChallenge  -> .data[0:8]
        0x6BC,  # response8 = version           -> .data[8:16]
        0x6AA,  # response7 = test              -> .data[16:24]
        0x7DE,  # response6 = D1strdf1          -> .data[24:32]
        0x7BE,  # response5 = loader filename   -> .data[32:40]
        0x79E,  # response4 = last key byte     -> .data[40:48]
        0x77E,  # response3 = first 7 key bytes -> .data[48:56]
        0x698,  # response2 = DIMMID2           -> .data[56:64]
        0x686,  # response1 = DIMMID1           -> .data[64:72]
        0x674,  # response0 = DIMMID0           -> .data[72:80]
    ]

    buf = bytearray(80)
    for i, offset in enumerate(pic_offsets):
        for j in range(8):
            buf[i * 8 + j] = data[offset + j * 2]

    return read_data_file(bytes(buf))


CHIHIRO_BIOS_PICS = {
    "317-0352-exp.pic",
    "317-0422-jpn.pic",
    "317-unknown.pic",
}


def load_keys_from_zip(zip_path):
    # Load all candidate DES keys from a MAME .zip.
    #
    # Every Chihiro MAME ZIP contains 3 shared BIOS PICs (317-0352, 317-0422,
    # 317-unknown) plus the game's own key as a .data (80 bytes) or .pic (16 KB).
    #
    # Returns a list of (key, loader, source_description) ordered by preference:
    # game-specific keys first, then BIOS PICs as fallback.
    #
    if not os.path.exists(zip_path):
        raise FileNotFoundError(f"File not found: {zip_path}")

    try:
        zf = zipfile.ZipFile(zip_path, "r")
    except zipfile.BadZipFile:
        raise ValueError(f"{os.path.basename(zip_path)} is not a valid ZIP file.")

    candidates = []
    bios_fallbacks = []
    zipname = os.path.basename(zip_path)

    with zf:
        for name in zf.namelist():
            if name.endswith(".data"):
                try:
                    key, loader = read_data_file(zf.read(name))
                except Exception:
                    continue
                if key:
                    candidates.append((key, loader, f"{zipname} -> {name}"))

            elif name.endswith(".pic"):
                try:
                    key, loader = read_pic_file(zf.read(name))
                except Exception:
                    continue
                if key:
                    if name in CHIHIRO_BIOS_PICS:
                        bios_fallbacks.append((key, loader, f"{zipname} -> {name}"))
                    else:
                        candidates.append((key, loader, f"{zipname} -> {name}"))

    if not candidates and not bios_fallbacks:
        raise ValueError(f"No valid key found in {zipname}.")

    return candidates + bios_fallbacks


# ---------------------------------------------------------------------------
# GD-ROM: extract Track 3 raw data
# ---------------------------------------------------------------------------

def tool_dir():
    # Directory containing this tool (script or frozen executable).
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def find_chdman():
    # Locate chdman: in temp, next to this tool, in the current dir, then in PATH.
    temp_chdman = os.path.join(tempfile.gettempdir(), "chdman.exe" if os.name == "nt" else "chdman")
    if os.path.isfile(temp_chdman):
        return temp_chdman

    exe = "chdman.exe" if os.name == "nt" else "chdman"
    for candidate in (os.path.join(tool_dir(), exe), os.path.join(".", exe)):
        if os.path.isfile(candidate):
            if os.name == "nt" and not candidate.lower().startswith("c:"):
                try:
                    shutil.copyfile(candidate, temp_chdman)
                    return temp_chdman
                except Exception:
                    pass
            return candidate
    return shutil.which("chdman")


def extract_chd(chd_path):
    # Extract tracks from a .chd using chdman. Returns (track3_path, offset, tmp_dir).

    # Use system temp first (fast local disk), fall back to current dir
    try:
        tmp_dir = tempfile.mkdtemp(prefix="chihiro_")
        # Check there's enough space (~1.5 GB needed)
        stat = shutil.disk_usage(tmp_dir)
        if stat.free < 2_000_000_000:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            tmp_dir = tempfile.mkdtemp(prefix="chihiro_", dir=".")
    except OSError:
        tmp_dir = tempfile.mkdtemp(prefix="chihiro_", dir=".")
    cue_path = os.path.join(tmp_dir, "disc.cue")
    bin_pattern = os.path.join(tmp_dir, "track%t.bin")

    print("  Running chdman... ", end="", flush=True)

    chdman = find_chdman()
    if chdman is None:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print()
        print("  'chdman' was not found.")
        print("  chdman ships with MAME. Either install it:")
        print("    macOS:   brew install rom-tools")
        print("    Linux:   sudo apt install mame-tools   (or pacman -S mame-tools)")
        print("    Windows: download MAME from mamedev.org (chdman.exe is included)")
        print("  ...or place chdman (chdman.exe on Windows) next to this tool.")
        sys.exit(1)

    proc = subprocess.Popen(
        [chdman, "extractcd", "-i", chd_path,
         "-o", cue_path, "-ob", bin_pattern],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    output_chunks = []
    def drain_output():
        while True:
            chunk = proc.stdout.read(512)
            if not chunk:
                break
            output_chunks.append(chunk)

    drain_thread = threading.Thread(target=drain_output, daemon=True)
    drain_thread.start()

    spinner = "|/-\\"
    tick = 0
    while proc.poll() is None:
        print(f"\r  Running chdman... {spinner[tick % 4]}", end="", flush=True)
        tick += 1
        time.sleep(0.15)

    drain_thread.join()
    print("\r  Running chdman... done" + " " * 10)

    if proc.returncode != 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        stderr_msg = "".join(output_chunks).strip()
        raise RuntimeError(f"chdman failed: {stderr_msg}")

    # Detect sector format from CUE
    sector_size = 2352
    if not os.path.exists(cue_path):
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError("chdman ran but produced no cue sheet.")
    with open(cue_path) as f:
        for line in f:
            if "MODE1/2048" in line:
                sector_size = 2048
            elif "MODE1/2352" in line:
                sector_size = 2352

    # chdman with -ob "track%t.bin" creates track01.bin, track02.bin, track03.bin
    # Track 3 is the high-density data track (the big one)
    track3 = os.path.join(tmp_dir, "track03.bin")
    if os.path.exists(track3):
        return track3, tmp_dir, sector_size

    # Fallback: largest .bin in the temp dir
    bins = sorted(
        [os.path.join(tmp_dir, f) for f in os.listdir(tmp_dir) if f.endswith(".bin")],
        key=os.path.getsize, reverse=True,
    )
    if bins:
        return bins[0], tmp_dir, sector_size

    shutil.rmtree(tmp_dir, ignore_errors=True)
    raise RuntimeError("chdman ran but no track files were created.")


def read_cue(cue_path):
    # Read a Redump-style .cue and return its data track, without chdman.
    #
    # A Redump GD-ROM dump is a .cue next to one .bin per track. The cue
    # names each file and the mode of the track inside it:
    #
    #     FILE "... (Track 3).bin" BINARY
    #       TRACK 03 MODE1/2352
    #
    # Returns (track_path, None, sector_size); None because there is no
    # temporary directory to clean up afterwards.
    #
    base = os.path.dirname(os.path.abspath(cue_path))
    tracks = []
    current = None

    with open(cue_path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.upper().startswith("FILE "):
                name = line[5:].rsplit(" ", 1)[0].strip().strip('"')
                current = os.path.join(base, name)
            elif line.upper().startswith("TRACK ") and current:
                parts = line.split()
                if len(parts) >= 3 and parts[1].isdigit():
                    tracks.append((int(parts[1]), current, parts[2].upper()))
                current = None

    data = [t for t in tracks if t[2].startswith("MODE") and os.path.exists(t[1])]
    if not data:
        raise RuntimeError(f"No data track found next to {os.path.basename(cue_path)}. "
                           "The .bin files must sit beside the .cue.")

    # Take the biggest data track rather than track 3 by name: on a GD-ROM the
    # high-density track is the game and dwarfs the rest, and going by size
    # also covers a plain CD-ROM and any disc that orders its tracks
    # differently. It is the same choice extract_chd falls back to.
    chosen = max(data, key=lambda t: os.path.getsize(t[1]))

    return chosen[1], None, 2048 if chosen[2].endswith("/2048") else 2352


MODE1_SYNC = bytes([0x00] + [0xFF] * 10 + [0x00])


def load_track_data(chd_path):
    # Extract the data track from a .chd and return raw ISO 9660 data.
    #
    # Handles two disc formats:
    #   - GD-ROM (MODE1/2352): strips CD sector overhead, LBA starts at 45000
    #   - CD-ROM (MODE1/2048): data is already raw ISO, LBA starts at 0
    #
    # Returns (iso_data_bytes, tmp_dir, lba_offset).
    #
    lower = chd_path.lower()
    if lower.endswith(".cue"):
        track_path, tmp_dir, sector_size = read_cue(chd_path)
    elif lower.endswith(".chd"):
        track_path, tmp_dir, sector_size = extract_chd(chd_path)
    else:
        raise ValueError(f"Expected a .chd or .cue file, got: {os.path.basename(chd_path)}")

    file_size = os.path.getsize(track_path)

    if sector_size == 2048:
        print(f"  Track: {os.path.basename(track_path)} ({file_size / 1024 / 1024:.0f} MB, CD-ROM)")
        print(f"  Reading {file_size // 2048:,d} sectors...")
        with open(track_path, "rb") as f:
            data = f.read()
        progress(file_size, file_size)

        # Detect whether the 2048-byte track was mastered with GD-ROM (45000) or CD/DVD (0) LBA
        detected_offset = 0
        if len(data) >= 17 * 2048:
            pvd = data[16 * 2048:17 * 2048]
            if len(pvd) == 2048 and pvd[0] == 0x01 and pvd[1:6] == b"CD001":
                root_lba = struct.unpack_from("<I", pvd, 156 + 2)[0]
                if root_lba >= GD_LBA_OFFSET:
                    detected_offset = GD_LBA_OFFSET

        return data, tmp_dir, detected_offset

    sector_count = file_size // 2352
    total_out = sector_count * 2048

    print(f"  Track 3: {os.path.basename(track_path)} ({file_size / 1024 / 1024:.0f} MB, GD-ROM)")
    print(f"  Reading and stripping {sector_count:,d} sectors...")

    with open(track_path, "rb") as f:
        header = f.read(16)
        if header[:12] != MODE1_SYNC:
            print("  WARNING: Data does not look like MODE1/2352 sectors.")
        f.seek(0)

        out = bytearray(total_out)
        for i in range(sector_count):
            sector = f.read(2352)
            if len(sector) < 2352:
                break
            out[i * 2048:(i + 1) * 2048] = sector[16:2064]

            if i % 10000 == 0 or i == sector_count - 1:
                progress((i + 1) * 2048, total_out)

    return bytes(out), tmp_dir, GD_LBA_OFFSET


# ---------------------------------------------------------------------------
# ISO 9660 filesystem
# ---------------------------------------------------------------------------

GD_LBA_OFFSET = 45000


def iso_offset(lba, lba_offset):
    # Convert an absolute LBA to a byte offset in the ISO data.
    return (lba - lba_offset) * 2048


def validate_iso(iso_data, lba_offset):
    # Check that the ISO data has a valid Primary Volume Descriptor.
    pvd_start = iso_offset(lba_offset + 16, lba_offset)
    pvd = iso_data[pvd_start:pvd_start + 2048]
    return len(pvd) == 2048 and pvd[0] == 0x01 and pvd[1:6] == b"CD001"


def get_root_dir(iso_data, lba_offset):
    # Read the root directory location from the PVD.
    pvd_start = iso_offset(lba_offset + 16, lba_offset)
    pvd = iso_data[pvd_start:pvd_start + 2048]
    root_lba = struct.unpack_from("<I", pvd, 156 + 2)[0]
    root_size = struct.unpack_from("<I", pvd, 156 + 10)[0]
    return root_lba, root_size


def parse_directory(iso_data, dir_lba, dir_size, lba_offset):
    # Parse an ISO 9660 directory. Yields (name, lba, size, is_dir).
    base = iso_offset(dir_lba, lba_offset)
    pos = 0

    while pos < dir_size:
        if base + pos >= len(iso_data) or base + pos < 0:
            break
        rec_len = iso_data[base + pos]
        if rec_len == 0:
            next_sector = ((pos // 2048) + 1) * 2048
            if next_sector >= dir_size:
                break
            pos = next_sector
            continue

        file_lba = struct.unpack_from("<I", iso_data, base + pos + 2)[0]
        file_size = struct.unpack_from("<I", iso_data, base + pos + 10)[0]
        flags = iso_data[base + pos + 25]
        name_len = iso_data[base + pos + 32]
        name_raw = iso_data[base + pos + 33:base + pos + 33 + name_len]

        pos += rec_len

        if name_len == 1 and name_raw[0] in (0x00, 0x01):
            continue

        name = name_raw.decode("ascii", errors="replace")
        if ";" in name:
            name = name[:name.index(";")]

        yield name, file_lba, file_size, bool(flags & 0x02)


def find_file(iso_data, target_name, lba_offset, dir_lba=None, dir_size=None):
    # Find a file by name anywhere in the ISO filesystem.
    if dir_lba is None:
        dir_lba, dir_size = get_root_dir(iso_data, lba_offset)

    for name, lba, size, is_dir in parse_directory(iso_data, dir_lba, dir_size, lba_offset):
        if not is_dir and name.upper() == target_name.upper():
            return lba, size
        if is_dir:
            result = find_file(iso_data, target_name, lba_offset, lba, size)
            if result:
                return result
    return None


def find_largest_file(iso_data, lba_offset, dir_lba=None, dir_size=None):
    # Find the largest file on the disc. Returns (name, lba, size) or None.
    if dir_lba is None:
        dir_lba, dir_size = get_root_dir(iso_data, lba_offset)

    best = None
    for name, lba, size, is_dir in parse_directory(iso_data, dir_lba, dir_size, lba_offset):
        if is_dir:
            sub = find_largest_file(iso_data, lba_offset, lba, size)
            if sub and (best is None or sub[2] > best[2]):
                best = sub
        elif best is None or size > best[2]:
            best = (name, lba, size)
    return best


def list_all_files(iso_data, lba_offset, dir_lba=None, dir_size=None, prefix="/"):
    # List every file on the disc.
    if dir_lba is None:
        dir_lba, dir_size = get_root_dir(iso_data, lba_offset)

    files = []
    for name, lba, size, is_dir in parse_directory(iso_data, dir_lba, dir_size, lba_offset):
        if is_dir:
            files.extend(list_all_files(iso_data, lba_offset, lba, size, prefix + name + "/"))
        else:
            files.append((prefix + name, lba, size))
    return files


def extract_file_data(iso_data, lba, size, lba_offset):
    # Read file bytes from the ISO image.
    start = iso_offset(lba, lba_offset)
    return iso_data[start:start + size]


# ---------------------------------------------------------------------------
# DES decryption with byte-swap
# ---------------------------------------------------------------------------

def byteswap_blocks(data):
    # Reverse each 8-byte block. Uses array.array for C-speed processing.
    #
    # This is the "byte-swap" step from decrypt.c: swap(0,7), swap(1,6), etc.
    # Treating the data as 64-bit integers and calling byteswap() does the same thing.
    #
    arr = array.array("Q", data)
    arr.byteswap()
    return arr.tobytes()


_des_backend = None


def decrypt_fatx(data, key):
    # Decrypt a FATX blob using DES-ECB with the Chihiro byte-swap scheme.
    #
    # The DIMM board encryption is: byteswap -> DES-ECB -> byteswap.
    # So decryption is the same: byteswap -> DES-ECB-decrypt -> byteswap.
    #
    # The key from the .data file is big-endian; DES needs it reversed
    # (see decrypt.c line 52: key[7-i]).
    #
    global _des_backend
    if len(data) % 8 != 0:
        raise ValueError(f"Encrypted data size ({len(data):,d}) is not a multiple of 8 bytes")

    if _des_backend is None:
        _des_backend = get_des_backend()
    backend_name, des_decrypt = _des_backend

    reversed_key = key[::-1]
    size_mb = len(data) / 1024 / 1024

    print(f"  Byte-swap ({size_mb:.0f} MB)... ", end="", flush=True)
    data = byteswap_blocks(data)
    print("done")

    print(f"  DES-ECB decrypt ({backend_name})... ", end="", flush=True)

    # Decrypt in chunks to show progress (ECB has no state between blocks)
    chunk_size = 32 * 1024 * 1024  # 32 MB
    out = bytearray(len(data))
    for i in range(0, len(data), chunk_size):
        end = min(i + chunk_size, len(data))
        out[i:end] = des_decrypt(data[i:end], reversed_key)
        progress(end, len(data))

    print(f"\r  DES-ECB decrypt ({backend_name})... done" + " " * 40)

    print(f"  Byte-swap... ", end="", flush=True)
    result = byteswap_blocks(bytes(out))
    print("done")

    return result


# ---------------------------------------------------------------------------
# Auto-detection: find game pairs (MAME ZIP + GD-ROM)
# ---------------------------------------------------------------------------

def find_games(directory="."):
    # Find all (game_name, zip_path, gdrom_path) pairs in a directory.
    #
    # A ZIP is a Chihiro ROM set if it contains .data or .pic key files.
    # Returns (pairs, orphans).
    #
    zips = {}
    for entry in os.listdir(directory):
        path = os.path.join(directory, entry)
        if not os.path.isfile(path) or not entry.lower().endswith(".zip"):
            continue
        try:
            with zipfile.ZipFile(path, "r") as zf:
                if any(n.endswith(".data") or n.endswith(".pic")
                       for n in zf.namelist()):
                    zips[os.path.splitext(entry)[0]] = path
        except (zipfile.BadZipFile, PermissionError):
            pass

    pairs = []
    orphans = []
    for game_name, zip_path in sorted(zips.items()):
        gdrom = None

        # MAME layout: gamename/something.chd, or a Redump gamename/*.cue
        subdir = os.path.join(directory, game_name)
        if os.path.isdir(subdir):
            candidates = [
                os.path.join(subdir, f) for f in os.listdir(subdir)
                if f.lower().endswith((".chd", ".cue"))
            ]
            if candidates:
                # Pick largest disc image (avoids auxiliary patch/key discs like cdp-*)
                gdrom = max(candidates, key=os.path.getsize)

        # Flat layout: gamename.chd or gamename.cue
        if not gdrom:
            for ext in (".chd", ".cue"):
                candidate = os.path.join(directory, game_name + ext)
                if os.path.exists(candidate):
                    gdrom = candidate
                    break

        if gdrom:
            pairs.append((game_name, zip_path, gdrom))
        else:
            orphans.append(game_name)

    return pairs, orphans


# ---------------------------------------------------------------------------
# Pipeline: convert one game
# ---------------------------------------------------------------------------

def convert_game(game_name, zip_path, gdrom_path, output_dir="output",
                  list_mode=False):
    # Run the full conversion pipeline for one game.
    #
    # Returns output_path on success, None on failure.
    #
    print()
    print(f"  === {game_name} ===")

    # --- Step 1: Key ---

    print()
    print("[1/4] Reading security key...")
    try:
        key_candidates = load_keys_from_zip(zip_path)
    except (ValueError, FileNotFoundError) as e:
        print(f"  ERROR: {e}")
        return None

    print(f"  Found {len(key_candidates)} key candidate(s)")

    # --- Step 2: Read disc ---

    print()
    print(f"[2/4] Extracting disc: {os.path.basename(gdrom_path)}")

    if not os.path.exists(gdrom_path):
        print(f"  ERROR: File not found: {gdrom_path}")
        return None

    try:
        iso_data, tmp_dir, lba_offset = load_track_data(gdrom_path)
    except (ValueError, FileNotFoundError, RuntimeError) as e:
        print(f"  ERROR: {e}")
        return None

    try:
        if not validate_iso(iso_data, lba_offset):
            print("  ERROR: No valid ISO 9660 filesystem found.")
            return None
        print(f"  ISO 9660: OK")

        if list_mode:
            print()
            print("  Files on disc:")
            for path, lba, size in list_all_files(iso_data, lba_offset):
                print(f"    {path:40s} {size:>12,d} bytes")
            return None

        # --- Step 3: Find the FATX blob ---

        print()
        print("[3/4] Finding game data on disc...")

        des_key = None
        fatx_lba = None
        fatx_size = None

        for key, loader_name, key_source in key_candidates:
            result = find_file(iso_data, loader_name, lba_offset)
            if not result:
                continue

            loader_lba, loader_size = result
            loader_data = extract_file_data(iso_data, loader_lba, loader_size, lba_offset)
            if len(loader_data) < 0xE0:
                continue

            fatx_name = loader_data[0xC0:0xE0].split(b"\x00")[0].decode("ascii", errors="replace")
            result = find_file(iso_data, fatx_name, lba_offset)
            if not result:
                continue

            des_key = key
            fatx_lba, fatx_size = result
            print(f"  Source:  {key_source}")
            print(f"  Key:     {des_key.hex().upper()}")
            print(f"  Loader:  {loader_name} -> FATX blob: {fatx_name}")
            break

        if des_key is None:
            if not key_candidates:
                print(f"  ERROR: No key candidates found.")
                return None

            # Probe candidate files by test-decrypting the first block for FATX magic header.
            # Exclude media container files (.afs, .adx, .sfd, video/audio formats).
            media_exts = (".afs", ".adx", ".sfd", ".mpg", ".mpeg", ".avi", ".wmv", ".wav")
            all_files = list_all_files(iso_data, lba_offset)
            candidates = sorted(
                [f for f in all_files if not f[0].lower().endswith(media_exts) and f[2] >= 1024 * 1024 and f[2] % 8 == 0],
                key=lambda x: (x[0].lower().endswith((".img", ".bin")), x[2]),
                reverse=True,
            )

            backend_name, des_decrypt_fn = get_des_backend()

            for path, f_lba, f_size in candidates:
                sample_len = min(512, f_size)
                if sample_len % 8 != 0:
                    continue
                sample = extract_file_data(iso_data, f_lba, sample_len, lba_offset)
                for k, _, src in key_candidates:
                    if k:
                        rev_k = k[::-1]
                        swapped = byteswap_blocks(sample)
                        dec = des_decrypt_fn(swapped, rev_k)
                        if byteswap_blocks(dec)[:4] == b"FATX":
                            des_key = k
                            key_source = src
                            fatx_name = os.path.basename(path)
                            fatx_lba = f_lba
                            fatx_size = f_size
                            print(f"  Source:  {key_source}")
                            print(f"  Key:     {des_key.hex().upper()}")
                            print(f"  FATX blob: {path} (verified FATX magic)")
                            break
                if des_key:
                    break

            # If no candidate matched FATX magic, fallback to the largest candidate file
            if des_key is None:
                fallback_cand = candidates[0] if candidates else find_largest_file(iso_data, lba_offset)
                if not fallback_cand:
                    print(f"  ERROR: No matching key/loader found on disc.")
                    return None
                if isinstance(fallback_cand[0], str) and fallback_cand[0].startswith("/"):
                    fatx_name = os.path.basename(fallback_cand[0])
                    fatx_lba = fallback_cand[1]
                    fatx_size = fallback_cand[2]
                else:
                    fatx_name, fatx_lba, fatx_size = fallback_cand
                des_key = key_candidates[0][0]
                print(f"  Source:  {key_candidates[0][2]}")
                print(f"  Key:     {des_key.hex().upper()}")
                print(f"  FATX blob: {fatx_name} (largest candidate file)")

        print(f"  Size:      {fatx_size / 1024 / 1024:.0f} MB")

        fatx_encrypted = extract_file_data(iso_data, fatx_lba, fatx_size, lba_offset)
        del iso_data

        # --- Step 4: Decrypt ---

        print()
        print("[4/4] Decrypting...")
        try:
            fatx_decrypted = decrypt_fatx(fatx_encrypted, des_key)
        except ValueError as e:
            print(f"  ERROR: {e}")
            return None
        del fatx_encrypted

        if fatx_decrypted[:4] == b"FATX":
            print(f"  FATX magic: OK")
        else:
            print(f"  WARNING: No FATX magic; output may be corrupt.")

        # --- Write ---

        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{game_name}.bin")

        print(f"  Writing {output_path}... ", end="", flush=True)
        with open(output_path, "wb") as f:
            f.write(fatx_decrypted)
        print("done")

        size_mb = len(fatx_decrypted) / 1024 / 1024
        print()
        print(f"  -> {output_path}  ({size_mb:.0f} MB)")

        return output_path
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Convert Sega Chihiro GD-ROM dumps into playable netboot images.",
        epilog=(
            "examples:\n"
            "  %(prog)s                              auto-detect and convert all games\n"
            "  %(prog)s /path/to/games                auto-detect games in a folder\n"
            "  %(prog)s hotd3.chd hotd3.zip           convert one game (explicit files)\n"
            "  %(prog)s hotd3.cue hotd3.zip           same, from a Redump cue/bin set\n"
            "  %(prog)s --list game.chd game.zip      list files on disc\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("chd", nargs="?",
                        help="the game's disc: a MAME .chd or a Redump .cue, "
                             "or a folder to scan")
    parser.add_argument("zip", nargs="?", help="MAME ROM .zip for the game")
    parser.add_argument("-o", "--output", help="output directory (default: output/)")
    parser.add_argument("-l", "--list", action="store_true", help="list disc contents and exit")
    parser.add_argument("--selftest", action="store_true",
                        help="verify the DES backend and exit")
    args = parser.parse_args()

    if args.selftest:
        name, _ = get_des_backend()
        print(f"DES backend: {name}: OK")
        return

    print()
    print("  chihiro-netboot")
    print("  GD-ROM (.chd or Redump .cue) to FATX netboot image converter")
    print("  " + "-" * 42)

    output_dir = args.output or "output"

    # --- Explicit mode: both arguments provided ---

    if args.chd and args.zip:
        if args.chd.lower().endswith(".zip") and args.zip.lower().endswith((".chd", ".cue")):
            args.chd, args.zip = args.zip, args.chd
        game_name = os.path.splitext(os.path.basename(args.zip))[0]
        result = convert_game(game_name, args.zip, args.chd, output_dir, args.list)
        if result:
            print()
            print("  " + "=" * 42)
            print(f"  Done! {result} is ready.")
            print()
        return

    # --- Auto-detect mode ---

    # A single argument that is a folder means "scan this folder". With no
    # argument, scan the current directory; if that finds nothing and we are
    # a double-clicked executable, scan the folder the executable lives in.
    scan_dir = "."
    if args.chd:
        if not os.path.isdir(args.chd):
            parser.error(f"'{args.chd}' is not a folder; to convert one game, "
                         "pass both the disc (.chd or .cue) and the .zip.")
        scan_dir = args.chd
        if not args.output:
            output_dir = os.path.join(scan_dir, "output")

    print()
    print(f"  Scanning {os.path.abspath(scan_dir)}...")
    pairs, orphans = find_games(scan_dir)

    if not pairs and scan_dir == "." and tool_dir() != os.path.abspath("."):
        print(f"  Nothing here; scanning {tool_dir()}...")
        pairs, orphans = find_games(tool_dir())
        if pairs and not args.output:
            output_dir = os.path.join(tool_dir(), "output")

    if orphans:
        for name in orphans:
            print(f"  {name}.zip found but no .chd; expected {name}/{name}*.chd")

    if not pairs:
        print()
        print("  No complete games found. The script needs:")
        print("    1. A MAME ROM .zip  (e.g. hotd3.zip)")
        print("    2. Its .chd file    (e.g. hotd3/gdx-0001.chd)")
        print()
        print("  Standard MAME layout:")
        print("    hotd3.zip")
        print("    hotd3/gdx-0001.chd")
        print()
        print("  Or specify files explicitly:")
        print("    chihiro-netboot hotd3/gdx-0001.chd hotd3.zip")
        sys.exit(1)

    print()
    for name, zp, gd in pairs:
        print(f"  {name:20s}  {os.path.basename(zp)} + {os.path.basename(gd)}")

    # Convert all
    results = []
    for game_name, zip_path, gdrom_path in pairs:
        result = convert_game(game_name, zip_path, gdrom_path, output_dir, args.list)
        results.append((game_name, result))

    # Summary
    if not args.list and len(results) > 0:
        succeeded = [(n, p) for n, p in results if p]
        failed = [n for n, p in results if not p]

        print()
        print("  " + "=" * 42)
        if succeeded:
            print(f"  Converted {len(succeeded)} game(s):")
            for name, path in succeeded:
                print(f"    {path}")
        if failed:
            print(f"  Failed: {', '.join(failed)}")
        if succeeded:
            print()
            print("  These netboot images are ready. Have fun!")
        print()


if __name__ == "__main__":
    try:
        main()
    finally:
        # Double-clicked executable on Windows: keep the console open so the
        # result (or the error) can actually be read.
        double_clicked = len(sys.argv) == 1 or (
            len(sys.argv) == 2 and os.path.isdir(sys.argv[1]))
        if getattr(sys, "frozen", False) and os.name == "nt" and double_clicked:
            input("\n  Press Enter to close...")
