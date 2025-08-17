# Misc

{{#include ../banners/hacktricks-training.md}}

- Quick TTL OS-guess from ping replies (heuristic only):
  - ~128 => Windows hosts (common default initial TTL 128)
  - ~255 => Network gear/routers (e.g., Cisco, many routers default 255)
  - ~64  => Linux/Unix/macOS
  Notes: Routers decrement TTL by 1 per hop, so one-hop-away hosts may appear as 127/254/63. Treat this only as a hint, never a fingerprint by itself.

- Common /etc/shadow hash identifiers:
  - `$1$`  = MD5
  - `$2a$`/`$2b$`/`$2y$` = bcrypt (Blowfish variants)
  - `$5$`  = SHA-256 (sha256crypt)
  - `$6$`  = SHA-512 (sha512crypt)
  - `$y$`  = yescrypt (increasingly the default in modern distros like Fedora 35+, Debian 12+, Ubuntu 22.04+ when libxcrypt is used)
  - `$argon2id$` = Argon2id (used by some PAM/libxcrypt builds and apps)

- If you don’t know what speaks on a TCP port, try simple banner grabbing first:
  - TCP cleartext: `printf 'GET / HTTP/1.0\r\n\r\n' | nc -nv <IP> <PORT>`
  - TLS: `openssl s_client -connect <IP>:<PORT> -servername <HOST> -showcerts`
  - STARTTLS (SMTP as example): `openssl s_client -starttls smtp -connect <IP>:25`
  - Nmap quick fingerprint: `nmap -sV --version-all -p <PORTS> <IP>`

**UDP scans (quick checks)**

- Netcat one-liner: `nc -vnzu -w1 <IP> 1-1024`
- Nmap (more reliable): `sudo nmap -sU -Pn --top-ports 200 --defeat-rst-ratelimit <IP>`
- nping single probe: `nping --udp -p 53 <IP>`

Remember: empty UDP payloads to closed ports usually trigger ICMP Port Unreachable, but ICMP rate limiting and firewalls cause drops (false "open"), so confirm with service-specific probes (e.g., DNS query to 53, NTP query to 123).

# CTF - Tricks

In Windows use WinZip/Explorer search to find files with patterns quickly.
Alternate Data Streams: `dir /r | find ":$DATA"` (PowerShell: `Get-Item -Path .\file -Stream *`)

```
binwalk --dd=".*" <file>                 # Extract everything by magic
binwalk -M -e -d=10000 suspicious.pdf     # Recursive extraction up to depth 10000
```

Steganography in whitespace (Snow):
- Conceal: `stegsnow -C -p 'pass' -m 'secret' infile.txt outfile.txt`
- Extract: `stegsnow -C -p 'pass' outfile.txt`
- Capacity estimate: `stegsnow -S -l 72 infile.txt`

Quick QR decode: `zbarimg -q image.png`

## Crypto

featherduster

Base encodings quick identifiers:
- Base64 (6→8): 0–9, a–z, A–Z, +, /, = padding
- Base32 (5→8): A–Z, 2–7, = padding
- Base85/Ascii85 (7→8): 0–9, a–z, A–Z, ., -, :, +, =, ^, !, /, *, ?, &, <, >, (, ), [, ], {, }, @, %, $
- uuencode → starts with `begin <mode> <filename>` and binary-looking alphabet
- xxencode → starts with `begin <mode> <filename>` and base64-like alphabet

Vigenère (freq analysis) → https://www.guballa.de/vigenere-solver
Scytale (transposition) → https://www.dcode.fr/scytale-cipher

25x25 = QR (version 2). Use zbarimg/qrencode for quick checks.

factordb.com
rsatool

Snow → hide messages using spaces/tabs at EOL (use stegsnow above)

# Characters

- U+202E (Right-To-Left Override, RLO) ⇒ renders text right-to-left; can hide payloads “backwards”.
- Related bidi and zero-width controls worth hunting for in source/files:
  - Bidi: U+202A..U+202E (LRE/RLE/LRO/RLO/PDF), U+2066..U+2069 (LRI/RLI/FSI/PDI)
  - Zero‑width: U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (BOM)

Detection tips:
- Show code points: `hexdump -C file` or `od -An -tx1 -v file`
- Grep suspicious Unicode: `grep -nP "[\x{200B}\x{200C}\x{200D}\x{FEFF}\x{202A}-\x{202E}\x{2066}-\x{2069}]" file`
- Visualize with escapes: `cat -v file` or `sed -n 'l' file`

Notes: "Trojan Source" attacks embed bidi controls inside comments/strings to make code display differently from compiler parsing. Many compilers/editors now warn, but you should scan repos and block these by CI.



## References

- Trojan Source: Invisible Vulnerabilities (Boucher & Anderson, updated Mar 8, 2023). https://arxiv.org/abs/2111.00169
- Fedora: yescrypt as default hashing method for shadow passwords (Change accepted for Fedora 35+). https://fedoraproject.org/wiki/Changes/yescrypt_as_default_hashing_method_for_shadow
{{#include ../banners/hacktricks-training.md}}
