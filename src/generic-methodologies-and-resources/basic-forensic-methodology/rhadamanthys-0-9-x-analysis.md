# Rhadamanthys 0.9.x – Analysis and TTPs

{{#include ../../banners/hacktricks-training.md}}

This page documents the forensic triage and reverse-engineering highlights for Rhadamanthys stealer version 0.9.x (notably 0.9.2): format changes in its custom “XS” modules, configuration deobfuscation pipeline, in-memory re-obfuscation of the Stage 2 package, anti-analysis and sandbox checks, injection strategy, and network delivery changes.

Key takeaways for defenders
- Update XS parsers for XS1_B/XS2_B header shifts and import changes
- Implement the new config decoding pipeline (custom Base64 → ChaCha20 → CBC XOR shuffle → LZO)
- Account for per-unpack LFSR XOR re-obfuscation of package payloads
- Hunt for mutex patterns MSCTF.Asm.{GUID}, duplicated mutex handles, and stable Bot ID artifacts
- Monitor WebSocket C2 and PNG-based Stage 3 delivery

## Execution chain overview (0.9.x)
- Stage 1 loader: native PE, heavy control-flow obfuscation (disconnected basic blocks and indirect jumps). When re-run unpacked directly, shows an anti-unpacked prompt via MessageBoxW: “Do you want to run a malware? (Crypt build to disable this message)”. Suggested triage tools: PE-sieve/[HollowsHunter](https://github.com/hasherezade/hollows_hunter), TinyTracer.
- Stage 2 core + package: decrypts/decompresses an embedded package, immediately re-obfuscates it in memory with an LFSR XOR keyed per-unpack. Modules are addressed by checksum rather than by name and fetched on demand.
- Stage 3 stealer: delivered over C2 as a PNG-carried payload; strings protected with RC4, numerous Lua plugins for credential and wallet theft, plus browser/system fingerprinting content.

## Custom XS formats: XS1_B / XS2_B changes
Rhadamanthys modules are custom “XS” executables, not PEs. Version 0.9.x modifies headers and import records to break older tooling while preserving semantics.

XS1_B header (ver=4) changes
- Removed WORD imp_key at its old position
- Added 1-byte imp_key later in the header
- Changed DLL-name decoding to a bit-by-bit reassembly with ASCII validation

```c
#pragma pack(push, 1)
typedef struct {
  WORD magic;
  WORD nt_magic;
  WORD sections_count;
  /* WORD imp_key; <- removed */
  WORD hdr_size;
  BYTE ver;
  BYTE imp_key; /* <- added here (1 byte) */
  DWORD module_size;
  DWORD entry_point;
  t_XS_data_dir data_dir[XS_DATA_DIR_COUNT];
  t_XS_section sections;
} t_XS_format_B;
#pragma pack(pop)
```

New DLL-name decoder (decode_name_B)
<details>
<summary>Click to expand</summary>

```c
bool decode_name_B(BYTE* dll_name, size_t name_len){
  if(!name_len) return false; BYTE out_name[128]={0}; size_t indx=0,pos=0,flag=0;
  for(size_t i=0;i<name_len;++i){ BYTE outC=0; for(WORD round=7; round>0; round--){
      BYTE val=dll_name[indx]; if(pos){ flag=(val>>(7-pos))&1; if(pos==7){pos=0; ++indx;} else ++pos; }
      else { flag=val>>7; pos=1; } outC |= (flag!=0) << (round-1); }
    if(!is_valid_dll_char(outC)) return false; out_name[i]=outC; }
  out_name[name_len]=0; ::memcpy(dll_name,out_name,name_len); return true; }
```

</details>

XS2_B import record widening
- obf_dll_len widened from WORD to DWORD
- Some builds may store DLL names unobfuscated

```c
#pragma pack(push, 1)
typedef struct {
  DWORD dll_name_rva;
  DWORD first_thunk;
  DWORD original_first_thunk;
  DWORD obf_dll_len; /* was WORD */
} t_XS_import_B;
#pragma pack(pop)
```

Imports still use an imp_key, now 1 byte, folded into function checksum resolution.

Conversion tooling
- Use the updated XS→PE converter that understands XS1_B / XS2_B changes: https://github.com/hasherezade/hidden_bee_tools/releases

## Configuration decoding pipeline (0.9.x)
Embedded config (marker changed to 0xBEEF) is multi-layered:
1) Base64 with a custom alphabet
2) ChaCha20 decrypt (key/IV stored at blob start)
3) CBC XOR shuffle
4) LZO decompress

Custom Base64 alphabet
```
4NOPQRSTUVWXY567DdeEqrstuvwxyz-ABC1fghop23Fijkbc|lmnGHIJKLMZ089a
```

Decompressed layout (supports multiple C2 URLs):
```c
struct config_new{
  DWORD flags; DWORD unk0; BYTE aes_iv[16];
  BYTE mutex_seed[16]; BYTE unk1[18]; WORD padding; BYTE urls[256];
};
```
Observed flags
- 0x2  = config initialized (W)
- 0x10 = delete initial file (R/W)
- 0x20 = close mutex handle like 0x40; enable staging (stage.x86, early.x86/early.x64) (R/W)
- 0x40 = do not pass mutex handle to injected processes (R)

Stable Bot ID
- Bot ID = SHA1(HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid + volume serial from GetVolumeInformationW), hex-encoded. Implemented in both Stage 2 netclient and Stage 3 core.

## Stage 2 package: per-unpack in-memory re‑obfuscation and checksum‑addressed modules
Immediately after decompression, the package content is re-obfuscated in memory using an LFSR-style XOR (tap 0xB400) with a per-unpack key. Files are addressed by checksum and fetched via a chunked directory; chunks are decoded on the fly with the same XOR.

XOR encoder/decoder
```c
void xor_based_enc_dec(const uint8_t* src,size_t size,uint8_t* dst,uint16_t key){
  for(size_t i=0;i<size;++i){ dst[i]=src[i]^uint8_t(key); uint16_t lsb=key&1u; key>>=1; if(lsb) key^=0xB400u; }
}
```

Directory/record layout and fetch logic
<details>
<summary>Click to expand</summary>

```c
typedef struct DATA_DIR{ struct{ uint32_t header_rel_off; uint32_t checksum; }; } _DATA_DIR;
typedef struct DATA_RECORD{ struct{ uint32_t size; uint8_t offset[1]; }; } _DATA_RECORD;
typedef struct PACKAGE{
  uint32_t total_size; uint16_t reserved; uint16_t xor_key; uint32_t dir_offset;
  uint16_t data_offset; uint8_t file_count; uint8_t blk_shift; _DATA_DIR dir[1];
} _PACKAGE;

BYTE* fetch_from_package(PACKAGE* pkg,uint32_t wanted,size_t& out_size){
  BYTE* base=(BYTE*)&pkg->dir_offset+pkg->data_offset; size_t chunk=2<<pkg->blk_shift;
  for(size_t i=0;i<pkg->file_count;i++) if(wanted==pkg->dir[i].checksum){
    DATA_RECORD* rec=(DATA_RECORD*)((ULONG_PTR)&pkg->dir_offset+pkg->dir[i].header_rel_off);
    size_t cnt=rec->size/chunk + ((rec->size%chunk)?1:0); BYTE* buf=(BYTE*)calloc(rec->size,1);
    size_t done=0; for(size_t j=0;j<cnt;j++){ uint8_t off=rec->offset[j]; size_t src_ofs=chunk*off;
      size_t cur=chunk; size_t rem=rec->size-done; if(cur>rem) cur=rem;
      xor_based_enc_dec(&base[src_ofs],cur,buf+done,pkg->xor_key); done+=cur; }
    out_size=done; return buf; }
  return nullptr; }
```

</details>

Reference decoder/unpacker: https://gist.github.com/hasherezade/371b517a24fd546dd5a89ed386ec0f5d

## Mutex derivation and propagation
Given a 16-byte mutex_seed in config, Stage 2 hashes it with magic “XRHY” and derives GUID-like names used to coordinate across processes:
```
Global\MSCTF.Asm.{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}
Session\%u\MSCTF.Asm.{...}   // fallback, %u in [1..8]
MSCTF.Asm.{...}
```
Unless disabled by flags 0x20 or 0x40, the mutex handle is duplicated into injected processes. This is useful for hunting the execution tree.

## Anti-analysis and sandbox gating (Strategy module)
Strategy receives a pointer to fetch_from_package plus the package itself, allowing it to pull multiple config records on demand (beyond just processes.x). Checks include:
- Forbidden process list (processes.x)
- Triage wallpaper hash (SHA1): 5b94362ac6a23c5aba706e8bfd11a5d8bab6097d
- Sandbox fodder files: foobar.jpg/.mp3/.txt/.wri, waller.dat
- Sandbox usernames: JohnDeo, HAL9TH, JOHN, JOHN-PC, MUELLER-PC, george, DESKTOP-B0T
- Dummy “secrets” files (keys.txt, passwords.txt) detected by equal-content hashing
- Stealthy MAC harvesting via UuidCreateSequential (UUIDv1) and comparing the node (MAC) against virtual NIC OUI blocklists
  - Blocklist reference: https://gist.github.com/hasherezade/af11786a670c76b60ecd29de00d6d9b8#file-macs-txt
- HWID blocklist via WMI: SELECT UUID FROM Win32_ComputerSystemProduct and compare against known list
  - Blocklist reference: https://gist.github.com/hasherezade/af11786a670c76b60ecd29de00d6d9b8#file-uuids-txt

## Stage 3 delivery via PNG container
Netclient registers a single image/png parser. Payload bytes are embedded directly in pixel data behind this header; decryption requires the session’s shared secret (cannot decode offline from captures):

```c
typedef struct png_data{
  BYTE key_n[0x20]; BYTE key_e[0x20]; DWORD size; BYTE hash[0x14]; BYTE data[1];
} _png_data;
```

Images appear as random noise; older JPEG/WAV stego parsers are removed in 0.9.2.

## Injection targets (configurable)
Targets are supplied by the package, filtered for local availability, and one is chosen randomly. Subset observed:
```
%Systemroot%\system32\bthudtask.exe
%Systemroot%\system32\dllhost.exe
%Systemroot%\SysWOW64\dllhost.exe
%Systemroot%\system32\taskhostw.exe
%Systemroot%\SysWOW64\TsWpfWrp.exe
%Systemroot%\system32\spoolsv.exe
%Systemroot%\system32\wuaulct.exe
%Systemroot%\system32\AtBroker.exe
%Systemroot%\SysWOW64\AtBroker.exe
%Systemroot%\system32\fontdrvhost.exe
%Systemroot%\SysWOW64\xwizard.exe
%Systemroot%\SysWOW64\msinfo32.exe
%Systemroot%\SysWOW64\msra.exe
```
Fallbacks: credwiz.exe, OOBE-Maintenance.exe, dllhost.exe, openwith.exe, rundll32.exe.

## Stage 3 string protection → RC4 (XS2_B)
String protection moved from custom XOR to RC4, with multiple decoder variants (ANSI/Unicode, argument ordering differences), e.g., dec_cstringA/B, dec_wstringA/B. Helper thunks further complicate bulk ID. Use updated IDA scripts and naming conventions:
- IDA RC4 string deobfuscator: https://gist.github.com/hasherezade/914ee14ca05e1f7c984b86ee4a0f74f2
- Example decrypted strings: https://gist.github.com/hasherezade/7f6008708dd4eecbebcb3c810c46f6e8

## Network behavior
NTP pre-checks (random order) before contacting C2:
```
time.google.com
time.cloudflare.com
time.facebook.com
time.windows.com
time.apple.com
time-a-g.nist.gov
ntp.time.in.ua
ts1.aco.net
ntp1.net.berkeley.edu
ntp.nict.jp
x.ns.gin.ntt.net
gbg1.ntp.se
ntp1.hetzner.de
ntp.time.nl
pool.ntp.org
```

Cosmetic domain churn (no DGA)
- Per-run random hostname replaces the configured host in certain strings/logs; real connections still use the configured C2 over WebSocket.

```c
void generate_domain_str(char* buf,size_t max){
  srand(time(0)); rand();
  for(size_t i=0;i<max;i++){
    int r=rand(); BYTE c=r-0x1A*((((0x4EC4EC4FLL*r>>32)&0x80000000)!=0)+((int)(0x4EC4EC4FLL*r>>32)>>3))+0x61; buf[i]=c; }
}
```

Transport: WebSocket remains in use.

## Stealers and web fingerprinting modules
- Lua runner powers many plugins (FTP, mail, messengers, notes, VPN, games, 2FA/PM, wallets)
- New (0x23) plugin: Ledger Live – enumerates %AppData%/Ledger Live and %LOCALAPPDATA%/Ledger Live, adds files, sets commit tag “!CP:LedgerLive”
- Browser fingerprinting: fingerprint.js collects system/browser/WebGL/Canvas/Network/Screen/Hardware/Language/Fonts/WebRTC/Audio and POSTs JSON to /p/result; index.html is a minimal carrier

## Detection and hunting ideas
Update parsers/detectors
- XS1_B/XS2_B: process 1-byte imp_key, widened import fields, new DLL decoder; convert XS→PE before static work
- Package: implement LFSR XOR re-obfuscation and checksum-addressed fetch to recover modules from memory dumps

Hunt / Telemetry
- WebSocket beacons; monitor PNG responses with “noisy” visuals and embedded payload patterns
- Mutex names: MSCTF.Asm.{GUID}, “Global\” and “Session\n\” variants; duplicated mutex handles across processes
- Stable Bot ID: SHA1(MachineGuid+VolumeSerial) usage across Stage 2/3
- Anti-sandbox gates: UUIDv1 MAC harvesting via UuidCreateSequential and WMI Win32_ComputerSystemProduct.UUID blocklists; look for Triage wallpaper hash and sandbox fodder files/usernames
- Randomized, config-supplied injection targets; correlate with Stage 3 load timing/events

Practical reversing tips
- Stage 1 loader is LLVM-like obfuscated; use PE-sieve/HollowsHunter to catch unpacked/injected modules; pair with TinyTracer to follow indirect control flow
- For string recovery in Stage 3, enumerate all RC4 decoder variants before bulk deobfuscation

## Analyst tooling
- XS converter/format docs (XS1_B/XS2_B): https://github.com/hasherezade/hidden_bee_tools/releases
- Stage 2 package decoder (reference): https://gist.github.com/hasherezade/371b517a24fd546dd5a89ed386ec0f5d
- XS2_B RC4 string deobfuscator (IDA): https://gist.github.com/hasherezade/914ee14ca05e1f7c984b86ee4a0f74f2
- Strategy MAC/HWID blocklists: https://gist.github.com/hasherezade/af11786a670c76b60ecd29de00d6d9b8

## References

- [Rhadamanthys 0.9.x – Walk through the updates (Check Point Research)](https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/)
- [hidden_bee_tools – XS converter releases](https://github.com/hasherezade/hidden_bee_tools/releases)
- [Stage 2 package decoder gist](https://gist.github.com/hasherezade/371b517a24fd546dd5a89ed386ec0f5d)
- [XS2_B RC4 string deobfuscator (IDA) gist](https://gist.github.com/hasherezade/914ee14ca05e1f7c984b86ee4a0f74f2)
- [Strategy blocklists (MAC/HWID) gists](https://gist.github.com/hasherezade/af11786a670c76b60ecd29de00d6d9b8)
- [HollowsHunter](https://github.com/hasherezade/hollows_hunter)

{{#include ../../banners/hacktricks-training.md}}