# AdaptixC2 Витяг конфігурації та TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 — модульний, open‑source post‑exploitation/C2 framework з Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) та підтримкою BOF. Ця сторінка документує:
- Як його RC4‑упакована конфігурація вбудована і як витягти її з beacons
- Мережеві та профільні індикатори для HTTP/SMB/TCP listeners
- Поширені loader та persistence TTPs, зафіксовані в реальних кампаніях, з посиланнями на відповідні сторінки технік Windows

## Beacon профілі та поля

AdaptixC2 підтримує три основні типи beacon:
- BEACON_HTTP: web C2 з налаштовуваними servers/ports/SSL, method, URI, headers, user‑agent та власною назвою параметра
- BEACON_SMB: named‑pipe peer‑to‑peer C2 (intranet)
- BEACON_TCP: direct sockets, опційно з prepended marker для обфускації початку протоколу

Типові поля профілю, спостережувані в HTTP конфігураціях beacon (після дешифрування):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – used to parse response sizes
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Example default HTTP profile (from a beacon build):
```json
{
"agent_type": 3192652105,
"use_ssl": true,
"servers_count": 1,
"servers": ["172.16.196.1"],
"ports": [4443],
"http_method": "POST",
"uri": "/uri.php",
"parameter": "X-Beacon-Id",
"user_agent": "Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0",
"http_headers": "\r\n",
"ans_pre_size": 26,
"ans_size": 47,
"kill_date": 0,
"working_time": 0,
"sleep_delay": 2,
"jitter_delay": 0,
"listener_type": 0,
"download_chunk_size": 102400
}
```
Спостережено зловмисний HTTP-профіль (реальна атака):
```json
{
"agent_type": 3192652105,
"use_ssl": true,
"servers_count": 1,
"servers": ["tech-system[.]online"],
"ports": [443],
"http_method": "POST",
"uri": "/endpoint/api",
"parameter": "X-App-Id",
"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
"http_headers": "\r\n",
"ans_pre_size": 26,
"ans_size": 47,
"kill_date": 0,
"working_time": 0,
"sleep_delay": 4,
"jitter_delay": 0,
"listener_type": 0,
"download_chunk_size": 102400
}
```
## Упакування зашифрованої конфігурації та шлях завантаження

Коли оператор натискає Create у builder, AdaptixC2 вбудовує зашифрований профіль як tail blob у beacon. Формат такий:
- 4 bytes: configuration size (uint32, little‑endian)
- N bytes: RC4‑encrypted configuration data
- 16 bytes: RC4 key

Завантажувач beacon копіює 16‑byte ключ із кінця та RC4‑розшифровує N‑byte блок на місці:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Practical implications:
- The entire structure often lives inside the PE .rdata section.
- Extraction is deterministic: read size, read ciphertext of that size, read the 16‑byte key placed immediately after, then RC4‑decrypt.

## Configuration extraction workflow (захисники)

Напишіть extractor, який імітує логіку beacon:
1) Знайдіть blob всередині PE (зазвичай .rdata). Практичний підхід — просканувати .rdata на наявність правдоподібного макету [size|ciphertext|16‑byte key] і спробувати RC4.
2) Прочитайте перші 4 байти → size (uint32 LE).
3) Прочитайте наступні N=size байтів → ciphertext.
4) Прочитайте фінальні 16 байтів → RC4 key.
5) RC4‑decrypt ciphertext. Потім розпарсіть plain profile як:
- u32/boolean scalars як зазначено вище
- length‑prefixed strings (u32 length followed by bytes; trailing NUL can be present)
- масиви: servers_count followed by that many [string, u32 port] pairs

Мінімальний Python proof‑of‑concept (standalone, no external deps), який працює з попередньо витягнутим blob:
```python
import struct
from typing import List, Tuple

def rc4(key: bytes, data: bytes) -> bytes:
S = list(range(256))
j = 0
for i in range(256):
j = (j + S[i] + key[i % len(key)]) & 0xFF
S[i], S[j] = S[j], S[i]
i = j = 0
out = bytearray()
for b in data:
i = (i + 1) & 0xFF
j = (j + S[i]) & 0xFF
S[i], S[j] = S[j], S[i]
K = S[(S[i] + S[j]) & 0xFF]
out.append(b ^ K)
return bytes(out)

class P:
def __init__(self, buf: bytes):
self.b = buf; self.o = 0
def u32(self) -> int:
v = struct.unpack_from('<I', self.b, self.o)[0]; self.o += 4; return v
def u8(self) -> int:
v = self.b[self.o]; self.o += 1; return v
def s(self) -> str:
L = self.u32(); s = self.b[self.o:self.o+L]; self.o += L
return s[:-1].decode('utf-8','replace') if L and s[-1] == 0 else s.decode('utf-8','replace')

def parse_http_cfg(plain: bytes) -> dict:
p = P(plain)
cfg = {}
cfg['agent_type']    = p.u32()
cfg['use_ssl']       = bool(p.u8())
n                    = p.u32()
cfg['servers']       = []
cfg['ports']         = []
for _ in range(n):
cfg['servers'].append(p.s())
cfg['ports'].append(p.u32())
cfg['http_method']   = p.s()
cfg['uri']           = p.s()
cfg['parameter']     = p.s()
cfg['user_agent']    = p.s()
cfg['http_headers']  = p.s()
cfg['ans_pre_size']  = p.u32()
cfg['ans_size']      = p.u32() + cfg['ans_pre_size']
cfg['kill_date']     = p.u32()
cfg['working_time']  = p.u32()
cfg['sleep_delay']   = p.u32()
cfg['jitter_delay']  = p.u32()
cfg['listener_type'] = 0
cfg['download_chunk_size'] = 0x19000
return cfg

# Usage (when you have [size|ciphertext|key] bytes):
# blob = open('blob.bin','rb').read()
# size = struct.unpack_from('<I', blob, 0)[0]
# ct   = blob[4:4+size]
# key  = blob[4+size:4+size+16]
# pt   = rc4(key, ct)
# cfg  = parse_http_cfg(pt)
```
Поради:
- When automating, use a PE parser to read .rdata then apply a sliding window: for each offset o, try size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4‑decrypt and check that string fields decode as UTF‑8 and lengths are sane.
- Parse SMB/TCP profiles by following the same length‑prefixed conventions.

## Network fingerprinting and hunting

HTTP
- Поширене: POST to operator‑selected URIs (e.g., /uri.php, /endpoint/api)
- Користувацький заголовок, що використовується для beacon ID (e.g., X‑Beacon‑Id, X‑App‑Id)
- User‑agents, що імітують Firefox 20 або contemporary Chrome builds
- Частота опитування видно через sleep_delay/jitter_delay

SMB/TCP
- SMB named‑pipe listeners для intranet C2 в середовищах, де web egress обмежений
- TCP beacons можуть додавати кілька байтів перед трафіком, щоб заобфускувати початок протоколу

## Loader and persistence TTPs seen in incidents

In‑memory PowerShell loaders
- Download Base64/XOR payloads (Invoke‑RestMethod / WebClient)
- Виділяють unmanaged memory, копіюють shellcode, змінюють захист на 0x40 (PAGE_EXECUTE_READWRITE) через VirtualProtect
- Виконують через .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Check these pages for in‑memory execution and AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Виявлені механізми персистенції
- Ярлик у Startup folder (.lnk) для повторного запуску loader при вході користувача
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), часто з benign‑sounding іменами на кшталт "Updater" для запуску loader.ps1
- DLL search‑order hijack шляхом розміщення msimg32.dll у %APPDATA%\Microsoft\Windows\Templates для вразливих процесів

Technique deep‑dives and checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ідеї для hunting
- PowerShell, що створює переходи RW→RX: VirtualProtect до PAGE_EXECUTE_READWRITE всередині powershell.exe
- Патерни dynamic invocation (GetDelegateForFunctionPointer)
- Startup .lnk у папках user або common Startup
- Підозрілі Run keys (e.g., "Updater") і імена loader типу update.ps1/loader.ps1
- Шляхи до DLL, доступні для запису користувачем, під %APPDATA%\Microsoft\Windows\Templates, що містять msimg32.dll

## Notes on OpSec fields

- KillDate: timestamp після якого агент self‑expires
- WorkingTime: години, коли агент має бути активним, щоб злитися з бізнес‑активністю

Ці поля можна використовувати для кластеризації і пояснення спостережуваних періодів тиші.

## YARA and static leads

Unit 42 published basic YARA for beacons (C/C++ and Go) and loader API‑hashing constants. Consider complementing with rules that look for the [size|ciphertext|16‑byte‑key] layout near PE .rdata end and the default HTTP profile strings.

## References

- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
