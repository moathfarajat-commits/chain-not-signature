#!/usr/bin/env python3
"""E4: archive key wrapping, classical against post-quantum.

Long-lived archives (medical imaging, evidence, surveillance) use envelope
encryption: each object is encrypted under its own AES-256 data key, and that
key is stored wrapped under a public key, today usually RSA-OAEP. Harvest now,
decrypt later applies directly, so migration means unwrapping every data key
under the legacy key and wrapping it again under a KEM.

Two parts.

Part 1 times one wrap and one unwrap per scheme, 1,000 calls each. The KEM
side uses the construction RFC 9629 specifies for CMS KEMRecipientInfo: the
KEM gives a shared secret, HKDF-SHA256 turns it into a key-encryption key, and
AES-256 key wrap (RFC 3394) wraps the 32-byte data key into 40 bytes. So the
stored bytes are the KEM ciphertext plus 40, and the timed wrap covers all
three steps, as the timed RSA wrap covers all of OAEP.

Part 2 re-wraps a small archive on disk, RSA-2048 to ML-KEM-768, and times
each object's unwrap, wrap and I/O separately. Where the wrapped key lives
decides what the I/O is, so three layouts are measured:

  sidecar    the wrapped key is in its own small file next to the object;
             re-wrapping replaces that file and never touches the object
  embedded   the wrapped key is in the object's header; the header grows by
             about 870 bytes, a file cannot grow at the front in place, so
             the whole object is rewritten
  reserved   the header was written with room for the larger key, so the
             new key is written over the old one in place

Writes are made durable with fsync before the next object starts. Reads come
from a warm page cache, because the archive was written moments earlier; the
I/O figures are therefore write-and-sync cost, not cold-read cost.

Two switches remove both caveats (they are what run_extra.sh sets):

  LINEA_E4_COLD=1       empty the page cache after the archive is written and
                        before it is re-wrapped (macOS: purge; Linux:
                        drop_caches), so every read comes from the drive
  LINEA_E4_FULLSYNC=1   on macOS make every write durable with F_FULLFSYNC,
                        which flushes the drive's own cache; fsync does not

With LINEA_E4_ARCHIVE_ONLY=1 part 1 is skipped and the results go to
e4_keywrap_cold.json, so the warm run stays as it was.
"""

import fcntl
import glob
import os
import subprocess
import shutil
import statistics
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import time_it, write_json  # noqa: E402

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import (aes_key_unwrap,
                                                    aes_key_wrap)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGES = sorted(glob.glob(os.path.join(ROOT, "images", "*.jpg")))

DATA_KEY_BYTES = 32          # AES-256
KW_BYTES = DATA_KEY_BYTES + 8  # RFC 3394 adds one 64-bit block
KDF_INFO = b"line-a e4 KEMRecipientInfo KEK"

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None)

ARCHIVE_OBJECTS = int(os.environ.get("LINEA_E4_OBJECTS", "2000"))
LARGE_OBJECTS = int(os.environ.get("LINEA_E4_LARGE_OBJECTS", "200"))
LARGE_BYTES = 4 * 1024 * 1024


def kek_from(shared_secret):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=KDF_INFO).derive(shared_secret)


# --- the two wrapping schemes, each as wrap(dk) -> bytes, unwrap(bytes) -> dk

class RsaScheme:
    def __init__(self, bits):
        self.name = f"RSA-{bits}-OAEP"
        self.library = "OpenSSL"
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        self.pub = self.key.public_key()

    def wrap(self, dk):
        return self.pub.encrypt(dk, OAEP)

    def unwrap(self, blob):
        return self.key.decrypt(blob, OAEP)


class OpenSslKem:
    def __init__(self, name, cls):
        self.name = name
        self.library = "OpenSSL"
        self.key = cls.generate()
        self.pub = self.key.public_key()

    def encap(self):
        ss, ct = self.pub.encapsulate()
        return ct, ss

    def decap(self, ct):
        return self.key.decapsulate(ct)


class OqsKem:
    def __init__(self, name, oqs):
        self.name = name
        self.library = "liboqs"
        self.kem = oqs.KeyEncapsulation(name)
        self.pk = self.kem.generate_keypair()

    def encap(self):
        return self.kem.encap_secret(self.pk)

    def decap(self, ct):
        return self.kem.decap_secret(ct)


class KemScheme:
    """KEM, then HKDF-SHA256, then AES-256 key wrap: RFC 9629's shape."""

    def __init__(self, kem):
        self.kem = kem
        self.name = kem.name
        self.library = kem.library
        ct, _ = kem.encap()
        self.ct_len = len(ct)

    def wrap(self, dk):
        ct, ss = self.kem.encap()
        return ct + aes_key_wrap(kek_from(ss), dk)

    def unwrap(self, blob):
        ct, wrapped = blob[:self.ct_len], blob[self.ct_len:]
        return aes_key_unwrap(kek_from(self.kem.decap(ct)), wrapped)


# --- Part 1: one wrap, one unwrap

def primitive_row(scheme, family):
    dk = os.urandom(DATA_KEY_BYTES)
    blob = scheme.wrap(dk)
    assert scheme.unwrap(blob) == dk
    row = {
        "scheme": scheme.name,
        "library": scheme.library,
        "family": family,
        "wrapped_bytes": len(blob),
        "wrap": time_it(lambda: scheme.wrap(dk)),
        "unwrap": time_it(lambda: scheme.unwrap(blob)),
    }
    if isinstance(scheme, KemScheme):
        # The symmetric tail on its own, so a reader can see it is small
        # rather than take that on trust.
        ss = os.urandom(32)
        wrapped = aes_key_wrap(kek_from(ss), dk)
        row["kem_ciphertext_bytes"] = scheme.ct_len
        row["kdf_and_keywrap"] = time_it(lambda: aes_key_wrap(kek_from(ss), dk))
        row["kdf_and_keyunwrap"] = time_it(
            lambda: aes_key_unwrap(kek_from(ss), wrapped))
    return row


# --- Part 2: re-wrap an archive on disk

# Object header: magic, key-slot length, wrapped-key length, then the slot.
# The slot is the wrapped key padded to the slot length; 'reserved' objects are
# written with a slot big enough for the post-quantum key from the start.
MAGIC = b"LAE4"
HDR = struct.Struct(">4sHH")


COLD = os.environ.get("LINEA_E4_COLD") == "1"
FULLSYNC = os.environ.get("LINEA_E4_FULLSYNC") == "1" and hasattr(fcntl, "F_FULLFSYNC")
ARCHIVE_ONLY = os.environ.get("LINEA_E4_ARCHIVE_ONLY") == "1"


def durable(f):
    """Make f's writes durable: F_FULLFSYNC when asked for and available."""
    f.flush()
    if FULLSYNC:
        fcntl.fcntl(f.fileno(), fcntl.F_FULLFSYNC)
    else:
        os.fsync(f.fileno())


def drop_page_cache():
    """Empty the OS page cache. Returns how, or None if it could not."""
    os.sync()
    if sys.platform == "darwin":
        r = subprocess.run(["sudo", "-n", "purge"], capture_output=True)
        return "purge" if r.returncode == 0 else None
    r = subprocess.run(["sudo", "-n", "sh", "-c", "sync; echo 3 > /proc/sys/vm/drop_caches"],
                       capture_output=True)
    return "drop_caches" if r.returncode == 0 else None


def sync_write(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        durable(f)
    os.replace(tmp, path)


def build_archive(where, layout, legacy, n, payloads, slot):
    aes_nonce = b"\0" * 12   # a fresh key per object makes a fixed nonce safe
    for i in range(n):
        dk = os.urandom(DATA_KEY_BYTES)
        body = AESGCM(dk).encrypt(aes_nonce, payloads[i % len(payloads)], None)
        wk = legacy.wrap(dk)
        obj = os.path.join(where, f"{i:06d}.obj")
        if layout == "sidecar":
            with open(obj, "wb") as f:
                f.write(body)
            with open(obj + ".key", "wb") as f:
                f.write(wk)
        else:
            s = slot if layout == "reserved" else len(wk)
            hdr = HDR.pack(MAGIC, s, len(wk)) + wk.ljust(s, b"\0")
            with open(obj, "wb") as f:
                f.write(hdr + body)
    os.sync() if hasattr(os, "sync") else None


def rewrap_one(obj, layout, legacy, new):
    t0 = time.perf_counter()
    if layout == "sidecar":
        with open(obj + ".key", "rb") as f:
            wk = f.read()
        rest = None
    else:
        with open(obj, "rb") as f:
            magic, s, n = HDR.unpack(f.read(HDR.size))
            assert magic == MAGIC
            wk = f.read(s)[:n]
            rest = f.read() if layout == "embedded" else None
    t1 = time.perf_counter()
    dk = legacy.unwrap(wk)
    t2 = time.perf_counter()
    nk = new.wrap(dk)
    t3 = time.perf_counter()
    if layout == "sidecar":
        sync_write(obj + ".key", nk)
    elif layout == "embedded":
        sync_write(obj, HDR.pack(MAGIC, len(nk), len(nk)) + nk + rest)
    else:
        if len(nk) > s:
            raise ValueError("reserved slot too small")
        with open(obj, "r+b") as f:
            f.write(HDR.pack(MAGIC, s, len(nk)) + nk.ljust(s, b"\0"))
            durable(f)
    t4 = time.perf_counter()
    return {"read": t1 - t0, "unwrap": t2 - t1, "wrap": t3 - t2,
            "write": t4 - t3}


def check_one(obj, layout, new, payload):
    if layout == "sidecar":
        with open(obj + ".key", "rb") as f:
            wk = f.read()
        with open(obj, "rb") as f:
            body = f.read()
    else:
        with open(obj, "rb") as f:
            _, s, n = HDR.unpack(f.read(HDR.size))
            wk = f.read(s)[:n]
            body = f.read()
    dk = new.unwrap(wk)
    return AESGCM(dk).decrypt(b"\0" * 12, body, None) == payload


def summarise(samples):
    ms = sorted(x * 1000 for x in samples)
    return {"median_ms": round(statistics.median(ms), 4),
            "mean_ms": round(statistics.fmean(ms), 4),
            "p95_ms": round(ms[min(int(0.95 * len(ms)), len(ms) - 1)], 4),
            "total_s": round(sum(ms) / 1000, 3)}


def archive_run(label, payloads, n, legacy, new, base):
    slot = new.ct_len + KW_BYTES
    rows = []
    for layout in ("sidecar", "embedded", "reserved"):
        where = tempfile.mkdtemp(prefix=f"e4-{layout}-", dir=base)
        try:
            build_archive(where, layout, legacy, n, payloads, slot)
            objs = sorted(glob.glob(os.path.join(where, "*.obj")))
            # Size before the re-wrap, so the three layouts report the same
            # object rather than whatever the re-wrap left behind.
            obj_bytes = [os.path.getsize(o) for o in objs]
            parts = {"read": [], "unwrap": [], "wrap": [], "write": []}
            cache = drop_page_cache() if COLD else "warm"
            if COLD and cache is None:
                raise RuntimeError("could not empty the page cache; run sudo -v first")
            w0 = time.perf_counter()
            for obj in objs:
                for k, v in rewrap_one(obj, layout, legacy, new).items():
                    parts[k].append(v)
            wall = time.perf_counter() - w0
            # Every object must still decrypt under the new key.
            ok = all(check_one(o, layout, new, payloads[i % len(payloads)])
                     for i, o in enumerate(objs))
            if not ok:
                raise RuntimeError(f"{layout}: object failed to decrypt")
            per = [sum(p) for p in zip(*parts.values())]
            rows.append({
                "corpus": label,
                "layout": layout,
                "objects": n,
                "median_object_bytes": int(statistics.median(obj_bytes)),
                "legacy": legacy.name,
                "new": f"{new.name} ({new.library})",
                "wall_s": round(wall, 3),
                "objects_per_s": round(n / wall, 1),
                "per_object": summarise(per),
                "read": summarise(parts["read"]),
                "unwrap": summarise(parts["unwrap"]),
                "wrap": summarise(parts["wrap"]),
                "write": summarise(parts["write"]),
                "verified": ok,
                "page_cache": cache,
                "sync": "F_FULLFSYNC" if FULLSYNC else "fsync",
            })
            print(f"    {label:6s} {layout:9s} {n / wall:8.1f} objects/s")
        finally:
            shutil.rmtree(where, ignore_errors=True)
    return rows


def main():
    try:
        import oqs
    except Exception:
        oqs = None

    prim = []
    if ARCHIVE_ONLY:
        return archive_main()
    print("  part 1: wrap and unwrap, 1,000 calls each")
    for bits in (2048, 3072):
        print(f"    RSA-{bits}")
        prim.append(primitive_row(RsaScheme(bits), "classical"))
    for label, cls in [("ML-KEM-768", mlkem.MLKEM768PrivateKey),
                       ("ML-KEM-1024", mlkem.MLKEM1024PrivateKey)]:
        print(f"    {label} (OpenSSL)")
        prim.append(primitive_row(KemScheme(OpenSslKem(label, cls)),
                                  "post-quantum"))
        if oqs is not None:
            try:
                k = KemScheme(OqsKem(label, oqs))
            except Exception:
                k = None
            if k is not None:
                print(f"    {label} (liboqs)")
                prim.append(primitive_row(k, "post-quantum"))
    base = next(r for r in prim if r["scheme"] == "RSA-2048-OAEP")
    for r in prim:
        r["wrapped_bytes_vs_rsa2048"] = round(
            r["wrapped_bytes"] / base["wrapped_bytes"], 2)
        r["part"] = "primitive"

    print("  part 2: archive re-wrap, RSA-2048 to ML-KEM-768 (OpenSSL)")
    legacy = RsaScheme(2048)
    new = KemScheme(OpenSslKem("ML-KEM-768", mlkem.MLKEM768PrivateKey))
    base_dir = os.environ.get("LINEA_E4_DIR") or None
    photos = [open(p, "rb").read() for p in IMAGES]
    large = [os.urandom(LARGE_BYTES)]
    arch = archive_run("kodak", photos, ARCHIVE_OBJECTS, legacy, new, base_dir)
    arch += archive_run("4MiB", large, LARGE_OBJECTS, legacy, new, base_dir)
    for r in arch:
        r["part"] = "archive"

    write_json("e4_keywrap.json", prim + arch, notes=[
        "KEM rows use RFC 9629's construction: KEM, HKDF-SHA256 to a KEK, "
        "AES-256 key wrap (RFC 3394) of the 32-byte data key",
        "wrapped_bytes for a KEM is the KEM ciphertext plus the 40-byte "
        "key-wrap output; for RSA-OAEP it is the modulus size",
        "timed wrap and unwrap cover every step of each construction",
        "archive rows: reads are from a warm page cache; every write is "
        "followed by fsync (not F_FULLFSYNC on macOS)",
        "archive rows: each object is verified to decrypt under the new key "
        "after the run",
        "HQC is not measured here; see README",
    ])


def archive_main():
    print(f"  archive re-wrap only: cache {'cold' if COLD else 'warm'}, "
          f"{'F_FULLFSYNC' if FULLSYNC else 'fsync'}")
    legacy = RsaScheme(2048)
    new = KemScheme(OpenSslKem("ML-KEM-768", mlkem.MLKEM768PrivateKey))
    base_dir = os.environ.get("LINEA_E4_DIR") or None
    photos = [open(p, "rb").read() for p in IMAGES]
    large = [os.urandom(LARGE_BYTES)]
    arch = archive_run("kodak", photos, ARCHIVE_OBJECTS, legacy, new, base_dir)
    arch += archive_run("4MiB", large, LARGE_OBJECTS, legacy, new, base_dir)
    for r in arch:
        r["part"] = "archive"
    write_json("e4_keywrap_cold.json", arch, notes=[
        "archive re-wrap only, RSA-2048 to ML-KEM-768 (RFC 9629 construction)",
        "page_cache: how the cache was emptied after the archive was written "
        "and before the re-wrap (purge on macOS), or warm",
        "sync: F_FULLFSYNC flushes the drive's cache on macOS; fsync does not",
        "each object is verified to decrypt under the new key after the run",
    ])


if __name__ == "__main__":
    main()
