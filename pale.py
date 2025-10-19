#!/usr/bin/env python3
"""
PALE
Just a cli project dedicated to my pale.
Created by: Om Joshi 
Github: https://github.com/iamomjoshi
repo: https://github.com/iamomjoshi/pale

This script combines a small UI (banner + colored helpers) with a
secure file encrypt/decrypt tool using AES-GCM (streaming) and PBKDF2.
"""

from pathlib import Path
import argparse
import sys
import getpass
import secrets
import time

# cryptography imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import constant_time

# ---------------------------
# UI / Colors / Banner
# ---------------------------
class Colors:
    # Basic colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Bright colors
    BRIGHT_RED = '\033[1;91m'
    BRIGHT_GREEN = '\033[1;92m'
    BRIGHT_YELLOW = '\033[1;93m'
    BRIGHT_BLUE = '\033[1;94m'
    BRIGHT_MAGENTA = '\033[1;95m'
    BRIGHT_CYAN = '\033[1;96m'
    BRIGHT_WHITE = '\033[1;97m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    
    # Reset
    RESET = '\033[0m'
    END = '\033[0m'

def print_banner():
    """Print the application banner with creator info."""
    banner = f"""
{Colors.BRIGHT_CYAN}██████╗  █████╗ ██╗     ███████╗{Colors.END}
{Colors.BRIGHT_CYAN}██╔══██╗██╔══██╗██║     ██╔════╝{Colors.END}
{Colors.BRIGHT_BLUE}██████╔╝███████║██║     █████╗  {Colors.END}
{Colors.BLUE}██╔═══╝ ██╔══██║██║     ██╔══╝  {Colors.END}
{Colors.BRIGHT_MAGENTA}██║     ██║  ██║███████╗███████╗{Colors.END}
{Colors.MAGENTA}╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝{Colors.END}

{Colors.BRIGHT_GREEN} {Colors.BRIGHT_CYAN}PALE{Colors.END} {Colors.BRIGHT_GREEN}– Advanced CLI Security Utility{Colors.END}
{Colors.BRIGHT_YELLOW} Created by: {Colors.BRIGHT_CYAN}Om Joshi{Colors.END} {Colors.BRIGHT_YELLOW}| Modern Security Framework{Colors.END}
{Colors.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}
"""
    print(banner)

def print_success(message: str):
    """Print success message with styling."""
    print(f"{Colors.BRIGHT_GREEN}{message}{Colors.END}")

def print_error(message: str):
    """Print error message with styling."""
    print(f"{Colors.BRIGHT_RED}{message}{Colors.END}", file=sys.stderr)

def print_warning(message: str):
    """Print warning message with styling."""
    print(f"{Colors.BRIGHT_YELLOW}{message}{Colors.END}")

def print_info(message: str):
    """Print info message with styling."""
    print(f"{Colors.BRIGHT_CYAN}{message}{Colors.END}")

# ---------------------------
# Encryption implementation
# ---------------------------
# Constants and format
MAGIC = b'PALEENC!'         # 8 bytes
VERSION = b'\x01'           # 1 byte
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
HEADER_SIZE = len(MAGIC) + len(VERSION) + SALT_SIZE + NONCE_SIZE
KDF_ITERATIONS_DEFAULT = 200_000
KEY_LEN = 32                # AES-256
CHUNK_SIZE = 64 * 1024      # 64 KiB streaming chunk

def derive_key(password: bytes, salt: bytes, iterations: int = KDF_ITERATIONS_DEFAULT) -> bytes:
    """Derive a symmetric key from password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_file(inpath: Path, outpath: Path, password: bytes, iterations: int = KDF_ITERATIONS_DEFAULT):
    """Encrypt input file to output file using AES-GCM (streaming)."""
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt, iterations)

    with inpath.open('rb') as fin, outpath.open('wb') as fout:
        # header
        fout.write(MAGIC)
        fout.write(VERSION)
        fout.write(salt)
        fout.write(nonce)

        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()

        total_in = 0
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            total_in += len(chunk)
            ct = encryptor.update(chunk)
            if ct:
                fout.write(ct)

        encryptor.finalize()
        tag = encryptor.tag  # 16 bytes
        fout.write(tag)

    # best-effort memory cleanup
    try:
        del key
    except Exception:
        pass

    print_success(f'Encrypted: {inpath} -> {outpath}  ({total_in} bytes)')

def decrypt_file(inpath: Path, outpath: Path, password: bytes, iterations: int = KDF_ITERATIONS_DEFAULT):
    """Decrypt input file to output file using AES-GCM (streaming)."""
    filesize = inpath.stat().st_size
    if filesize < HEADER_SIZE + TAG_SIZE:
        raise ValueError('Input file too small or not in expected format.')

    with inpath.open('rb') as fin:
        magic = fin.read(len(MAGIC))
        if not constant_time.bytes_eq(magic, MAGIC):
            raise ValueError('Input file not in expected pale-encrypted format (magic mismatch).')

        version = fin.read(1)
        if version != VERSION:
            raise ValueError('Unsupported version.')

        salt = fin.read(SALT_SIZE)
        nonce = fin.read(NONCE_SIZE)

        current_offset = fin.tell()
        ciphertext_len = filesize - current_offset - TAG_SIZE
        if ciphertext_len < 0:
            raise ValueError('Malformed input file.')

        fin.seek(filesize - TAG_SIZE)
        tag = fin.read(TAG_SIZE)

        key = derive_key(password, salt, iterations)
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        ).decryptor()

        fin.seek(current_offset)
        bytes_remaining = ciphertext_len

        with outpath.open('wb') as fout:
            while bytes_remaining > 0:
                read_size = min(CHUNK_SIZE, bytes_remaining)
                chunk = fin.read(read_size)
                if not chunk:
                    break
                bytes_remaining -= len(chunk)
                pt = decryptor.update(chunk)
                if pt:
                    fout.write(pt)

            try:
                decryptor.finalize()
            except InvalidTag as e:
                # delete incomplete output file
                try:
                    fout.close()
                except Exception:
                    pass
                try:
                    outpath.unlink(missing_ok=True)
                except Exception:
                    pass
                raise InvalidTag('Decryption failed: authentication tag mismatch. Wrong password or/or corrupted file.') from e

    try:
        del key
    except Exception:
        pass

    print_success(f'Decrypted: {inpath} -> {outpath}')

# ---------------------------
# CLI
# ---------------------------
def parse_args():
    p = argparse.ArgumentParser(prog='pale', description='PALE — CLI security utilities (file encrypt/decrypt).')
    p.add_argument('--no-banner', action='store_true', help='Do not print banner on startup.')

    sub = p.add_subparsers(dest='cmd', required=True)

    enc = sub.add_parser('encrypt', help='Encrypt a file')
    enc.add_argument('-i', '--input', required=True, help='Input file path')
    enc.add_argument('-o', '--output', help='Output file path (defaults to input + .enc)')
    enc.add_argument('-p', '--password', help='Password (insecure to pass on CLI). If omitted, will prompt.')
    enc.add_argument('--iterations', type=int, default=KDF_ITERATIONS_DEFAULT, help=f'PBKDF2 iterations (default {KDF_ITERATIONS_DEFAULT})')

    dec = sub.add_parser('decrypt', help='Decrypt a file')
    dec.add_argument('-i', '--input', required=True, help='Input encrypted file path')
    dec.add_argument('-o', '--output', help='Output file path (defaults to input without .enc if exists)')
    dec.add_argument('-p', '--password', help='Password (insecure to pass on CLI). If omitted, will prompt.')
    dec.add_argument('--iterations', type=int, default=KDF_ITERATIONS_DEFAULT, help=f'PBKDF2 iterations (default {KDF_ITERATIONS_DEFAULT})')

    return p.parse_args()

def main():
    args = parse_args()

    if not args.no_banner:
        try:
            print_banner()
        except Exception:
            pass

    if args.cmd == 'encrypt':
        inp = Path(args.input)
        if not inp.exists():
            print_error(f'Input file does not exist: {inp}')
            sys.exit(2)

        out = Path(args.output) if args.output else inp.with_name(inp.name + '.enc')
        if out.exists():
            resp = input(f'Output {out} exists — overwrite? [y/N]: ')
            if resp.lower() != 'y':
                print_warning('Aborted.')
                sys.exit(3)

        if args.password:
            pwd = args.password.encode('utf-8')
        else:
            p1 = getpass.getpass('Password: ')
            p2 = getpass.getpass('Confirm password: ')
            if p1 != p2:
                print_error('Passwords do not match.')
                sys.exit(4)
            pwd = p1.encode('utf-8')

        try:
            encrypt_file(inp, out, pwd, iterations=args.iterations)
        except Exception as e:
            print_error(f'Encryption error: {e}')
            sys.exit(5)

    elif args.cmd == 'decrypt':
        inp = Path(args.input)
        if not inp.exists():
            print_error(f'Input file does not exist: {inp}')
            sys.exit(2)

        out = Path(args.output) if args.output else (inp.with_name(inp.name[:-4]) if inp.name.endswith('.enc') else inp.with_name(inp.name + '.dec'))
        if out.exists():
            resp = input(f'Output {out} exists — overwrite? [y/N]: ')
            if resp.lower() != 'y':
                print_warning('Aborted.')
                sys.exit(3)

        if args.password:
            pwd = args.password.encode('utf-8')
        else:
            p1 = getpass.getpass('Password: ')
            pwd = p1.encode('utf-8')

        try:
            decrypt_file(inp, out, pwd, iterations=args.iterations)
        except InvalidTag as e:
            print_error(str(e))
            sys.exit(6)
        except Exception as e:
            print_error(f'Decryption error: {e}')
            sys.exit(7)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_info('\nGoodbye! Stay secure!')
