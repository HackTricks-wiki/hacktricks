# Витягування конфігурації та TTPs AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 — це модульний open-source post-exploitation/C2 framework із beacon для Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) і підтримкою BOF. На цій сторінці описано:
- Як його RC4-packed конфігурація вбудовується в beacon і як витягнути її з beacon
- Мережеві/profile indicators для HTTP/SMB/TCP listeners
- Поширені loader і persistence TTPs, що спостерігаються у wild, із посиланнями на відповідні сторінки Windows techniques

Останні upstream releases також постачають DNS/DoH beacon listeners і окреме сімейство Gopher agent/listener, тому сучасна Adaptix infrastructure може піддаватися більшій кількості indicators, ніж оригінальні HTTP/SMB/TCP surfaces, навіть якщо конкретний sample усе ще використовує classic beacon agent.

## Beacon profiles і fields

AdaptixC2 підтримує три основні типи beacon:
- BEACON_HTTP: web C2 із конфігурованими servers/ports/SSL, method, URI, headers, user-agent і custom parameter name
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: direct sockets, опційно з prepended marker для obfuscate початку протоколу

Це layouts beacon, публічно задокументовані в ранніх Adaptix analyses, і вони досі є найпоширенішою starting point для extraction на стороні sample. Однак поточні upstream builds також постачають `BeaconDNS` і Gopher extenders на server side, тому не слід припускати, що кожне live Adaptix deployment exposes лише HTTP/SMB/TCP infrastructure.

Typical profile fields, що спостерігаються в HTTP beacon configs (після decryption):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – використовуються для parse розмірів response
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Сучасні BeaconHTTP builds також підтримують operator-selected rotation між кількома URI, user-agents, Host headers і servers, із sequential або random selection. З погляду hunting це означає, що один infected host може fan out через кілька callback paths і header combinations, не залишаючи classic RC4-packed beacon family.

Приклад default HTTP profile (із beacon build):
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
Зафіксований шкідливий HTTP-профіль (реальна атака):
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
## Пакування зашифрованої конфігурації та шлях завантаження

Коли operator натискає Create у builder, AdaptixC2 вбудовує зашифрований профіль у beacon як кінцевий blob. Формат:
- 4 байти: розмір конфігурації (uint32, little-endian)
- N байт: конфігураційні дані, зашифровані RC4
- 16 байт: ключ RC4

Завантажувач beacon копіює 16-байтовий ключ із кінця та виконує RC4-дешифрування блоку розміром N байт на місці:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Практичні наслідки:
- Уся структура часто міститься всередині секції PE .rdata.
- Витягування є детермінованим: прочитати розмір, прочитати ciphertext такого розміру, прочитати 16-байтовий ключ, розміщений безпосередньо після нього, а потім виконати RC4-decrypt.

## Процес витягування конфігурації (для defenders)

Напишіть extractor, який імітує логіку beacon:
1) Знайдіть blob усередині PE (зазвичай у .rdata). Практичний підхід — просканувати .rdata на наявність правдоподібної структури [size|ciphertext|16-byte key] і спробувати виконати RC4.
2) Прочитайте перші 4 байти → size (uint32 LE).
3) Прочитайте наступні N=size байтів → ciphertext.
4) Прочитайте останні 16 байтів → RC4 key.
5) Виконайте RC4-decrypt ciphertext. Потім розберіть plain profile як:
- u32/boolean scalars, зазначені вище
- strings із префіксом довжини (u32 length, після якого йдуть bytes; trailing NUL може бути присутнім)
- arrays: servers_count, після якого йде відповідна кількість пар [string, u32 port]

Мінімальний Python proof-of-concept (standalone, без external deps), який працює з попередньо витягнутим blob:
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
- Під час автоматизації використовуйте PE parser для читання .rdata, а потім застосуйте sliding window: для кожного offset o спробуйте size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = наступні 16 bytes; виконайте RC4-decrypt і перевірте, що string fields декодуються як UTF-8, а lengths є коректними.
- Парсинг SMB/TCP profiles виконуйте за такими самими length-prefixed conventions.

## Custom listener profiles: не hard-code лише classic HTTP schema

Зовнішній формат пакування (`u32 size | RC4 ciphertext | 16-byte key`) можна повторно використовувати, тому actor-customized listeners можуть зберігати той самий extraction workflow, змінюючи при цьому decrypted field layout повністю.

Хорошим нещодавнім прикладом є кампанія Tropic Trooper у квітні 2026 року, під час якої extracted Adaptix beacon не містив standard HTTP/TCP profile. Натомість decrypted blob зберігав GitHub transport parameters, зокрема:
- `repo_owner`
- `repo_name`
- `api_host` (наприклад, `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Практична стратегія parser:
- Спочатку виявляйте outer RC4 blob точно як зазвичай.
- Після decryption використовуйте branching на основі sentinel strings і field sanity, а не відразу застосовуйте HTTP parser.
- Хорошими sentinels є `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, named-pipe-style strings або очевидно коректні server/port arrays.
- Якщо HTTP parser завершується помилкою, але plaintext містить узгоджені length-prefixed UTF-8 strings, збережіть sample і спробуйте alternative schemas замість того, щоб відкидати його як false positive.

У цій кампанії custom listener використовував GitHub issues як C2 transport, а beacon звертався до `ipinfo.io`, щоб дізнатися свою зовнішню IP-адресу, оскільки GitHub API не розкриває operator безпосередньо source address victim.

## Network fingerprinting і hunting

HTTP
- Типово: POST до URI, вибраних operator (наприклад, /uri.php, /endpoint/api)
- Custom header parameter, який використовується для beacon ID (наприклад, X‑Beacon‑Id, X‑App‑Id)
- User-agents, що імітують Firefox 20 або актуальні Chrome builds
- Polling cadence, видимий через sleep_delay/jitter_delay
- Новіші builds можуть rotate URIs, user-agents, Host headers і servers між callbacks, тому кластеризуйте за uncommon header names, response-size patterns, TLS reuse і timing, а не припускайте наявність однієї пари path/UA

SMB/TCP
- SMB named-pipe listeners для intranet C2, де web egress обмежений
- TCP beacons можуть додавати кілька bytes перед traffic, щоб obfuscate protocol start

Поточні upstream teamserver defaults
- `profile.yaml` наразі містить teamserver `0.0.0.0:4321`, endpoint `/endpoint`, filenames сертифіката/ключа `server.rsa.crt` і `server.rsa.key`, а також extenders для HTTP, SMB, TCP, DNS, Beacon agent і Gopher
- Для unmatched routes default error handler повертає `Server: AdaptixC2` і `Adaptix-Version: v1.2`
- Стандартне тіло 404 містить `AdaptixC2 404` і `You need to enter the correct connection details.`
- Internet-wide scans у 2026 році виявили багато exposed teamservers на `4321` і багато beacon listeners на `43211`, тому обидва порти корисні як seed pivots, але їх не слід вважати exhaustive

DNS/DoH listener fingerprints
- Поточний BeaconDNS extender відповідає авторитетно (`AA=true`)
- На queries, що не відповідають beacon protocol shape — зокрема на names із менш ніж 5 labels перед configured domain — зазвичай повертається `TXT "OK"`
- Якщо configured base TTL залишено нульовим, listener використовує 10-секундне base value і додає до 59 секунд jitter
- Це робить short-label active probes корисними, коли HTTP listener не exposed

## Loader і persistence TTPs, помічені в incidents

In-memory PowerShell loaders
- Завантажують Base64/XOR payloads (Invoke‑RestMethod / WebClient)
- Виділяють unmanaged memory, копіюють shellcode, перемикають protection на 0x40 (PAGE_EXECUTE_READWRITE) через VirtualProtect
- Виконують через .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Trojanized signed software / staged shellcode loaders
- У 2026 році ланцюжок Tropic Trooper використовував trojanized SumatraPDF executable (TOSHIS loader), який перенаправляв `_security_init_cookie` до malicious code замість patching PE entry point
- Loader resolved APIs за допомогою Adler-32 hashing, завантажував decoy PDF, отримував second-stage shellcode, decrypt-ив його за допомогою AES-128-CBC через WinCrypt (`CryptDeriveKey` з hardcoded seed) і reflectively виконував Adaptix beacon у memory
- Пізніше persistence було перенесено до scheduled tasks із benign-looking names, таких як `\MSDNSvc` або `\MicrosoftUDN`, налаштованих на повторний запуск agent приблизно кожні дві години

Перегляньте ці сторінки щодо in-memory execution і AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Спостережувані persistence mechanisms
- Startup folder shortcut (.lnk) для повторного запуску loader під час logon
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), часто з benign-sounding names на кшталт "Updater" для запуску loader.ps1
- DLL search-order hijack через розміщення msimg32.dll у %APPDATA%\Microsoft\Windows\Templates для susceptible processes

Technique deep-dives і checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ідеї для hunting
- PowerShell, що породжує RW→RX transitions: VirtualProtect до PAGE_EXECUTE_READWRITE всередині powershell.exe
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- Unmatched HTTPS 404s із `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` або `You need to enter the correct connection details.`
- DNS responses із `AA=true` і `TXT "OK"` для short queries у suspect domains
- GitHub API traffic до `/repos/<owner>/<repo>/issues`, після якого з того самого loader/beacon chain виконуються lookups до `ipinfo.io`
- Startup .lnk у user або common Startup folders
- Suspicious Run keys (наприклад, "Updater") і loader names на кшталт update.ps1/loader.ps1
- Trojanized PE samples, які redirect `_security_init_cookie` до downloader code перед показом decoy document
- User-writable DLL paths під %APPDATA%\Microsoft\Windows\Templates, що містять msimg32.dll

## Примітки щодо OpSec fields

- KillDate: timestamp, після якого agent self-expires
- WorkingTime: години, протягом яких agent має бути active, щоб blend in із business activity

Ці fields можна використовувати для clustering і пояснення observed quiet periods.

## YARA і static leads

Unit 42 опублікувала базові YARA для beacons (C/C++ і Go) та loader API-hashing constants. Розгляньте можливість доповнити їх rules, які шукають layout [size|ciphertext|16-byte-key] поблизу кінця PE .rdata, default HTTP profile strings і новіші server/listener markers, такі як `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` і `ipinfo.io`.

## References

- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [AdaptixC2: Fingerprinting an Open-Source C2 Framework at Scale (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [Tropic Trooper Pivots to AdaptixC2 and Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
