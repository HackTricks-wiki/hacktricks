# Витягування конфігурації AdaptixC2 і TTPs

AdaptixC2 — це модульний open-source post-exploitation/C2 framework із Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) і підтримкою BOF.<sup>[[1]](#references)</sup> На цій сторінці описано:
- як його RC4-packed configuration вбудовується в beacons і як витягнути її з них;
- мережеві/profile indicators для HTTP/SMB/TCP listeners;
- поширені loader і persistence TTPs, що спостерігаються in the wild, із посиланнями на відповідні сторінки з Windows techniques.

Останні upstream releases також містять DNS/DoH beacon listeners і окреме сімейство Gopher agent/listener, тому сучасна інфраструктура Adaptix може відкривати більше поверхонь, ніж початкові HTTP/SMB/TCP, навіть якщо конкретний sample все ще використовує classic beacon agent.<sup>[[2]](#references)</sup>

## Beacon profiles і fields

AdaptixC2 підтримує три основні типи beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 із налаштовуваними servers/ports/SSL, method, URI, headers, user-agent і custom parameter name;
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet);
- BEACON_TCP: direct sockets, опційно з prepended marker для obfuscate початку протоколу.

Ці beacon layouts описані в ранніх публічних аналізах Adaptix і досі є найпоширенішою starting point для extraction на стороні sample.<sup>[[1]](#references)</sup> Однак поточні upstream builds також містять `BeaconDNS` і Gopher extenders на стороні server, тому не слід вважати, що кожне live Adaptix deployment відкриває лише HTTP/SMB/TCP infrastructure.<sup>[[2]](#references)</sup>

Типові profile fields, що спостерігаються в HTTP beacon configs (після decryption):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – використовуються для parse розмірів response;
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Сучасні BeaconHTTP builds також підтримують operator-selected rotation між кількома URIs, user-agents, Host headers і servers із sequential або random selection.<sup>[[2]](#references)</sup> З погляду hunting це означає, що один infected host може розподіляти callbacks між кількома шляхами та комбінаціями headers, не виходячи за межі classic RC4-packed beacon family.

Приклад default HTTP profile (із beacon build):<sup>[[1]](#references)</sup>
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
Виявлений шкідливий HTTP-профіль (реальна атака):<sup>[[1]](#references)</sup>
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

Коли оператор натискає Create у builder, AdaptixC2 вбудовує зашифрований profile у beacon як tail blob. Формат:<sup>[[1]](#references)</sup>
- 4 байти: розмір конфігурації (uint32, little-endian)
- N байт: зашифровані за допомогою RC4 дані конфігурації
- 16 байт: ключ RC4

Loader beacon копіює 16-байтовий ключ із кінця та розшифровує блок розміром N байт за допомогою RC4 безпосередньо в пам’яті:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Практичні наслідки:<sup>[[1]](#references)</sup>
- Уся структура часто міститься всередині секції PE .rdata.
- Extraction є детермінованим: прочитайте size, прочитайте ciphertext такого розміру, прочитайте 16-байтовий key, розміщений одразу після нього, а потім виконайте RC4-decrypt.

## Workflow extraction конфігурації (defenders)

Напишіть extractor, який імітує логіку beacon:<sup>[[1]](#references)</sup>
1) Locate blob усередині PE (зазвичай у .rdata). Практичний підхід — просканувати .rdata на наявність правдоподібної структури [size|ciphertext|16-byte key] і спробувати RC4.
2) Прочитайте перші 4 bytes → size (uint32 LE).
3) Прочитайте наступні N=size bytes → ciphertext.
4) Прочитайте останні 16 bytes → RC4 key.
5) Виконайте RC4-decrypt ciphertext. Потім розберіть plain profile як:
- u32/boolean scalars, як зазначено вище
- strings із префіксом довжини (u32 length, за яким ідуть bytes; trailing NUL може бути присутнім)
- arrays: servers_count, за яким іде відповідна кількість пар [string, u32 port]

Мінімальний Python proof-of-concept (standalone, без external deps), який працює з попередньо extracted blob:
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
- Під час автоматизації використовуйте PE parser для читання .rdata, а потім застосуйте sliding window: для кожного offset o спробуйте size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = наступні 16 bytes; виконайте RC4-decrypt і перевірте, чи string fields декодуються як UTF-8, а їхні довжини є коректними.
- Парсіть SMB/TCP profiles, дотримуючись тих самих length-prefixed conventions.

## Custom listener profiles: не обмежуйтеся hard-code лише класичною HTTP schema

Зовнішній packing format (`u32 size | RC4 ciphertext | 16-byte key`) можна повторно використовувати, тому actor-customized listeners можуть зберігати той самий extraction workflow, повністю змінюючи layout розшифрованих полів.

Хорошим нещодавнім прикладом є кампанія Tropic Trooper у березні 2026 року, де extracted Adaptix beacon не містив стандартного HTTP/TCP profile. Натомість decrypted blob зберігав GitHub transport parameters, такі як:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (наприклад, `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Практична parser strategy:
- Спочатку виявляйте outer RC4 blob точно як зазвичай.
- Після decryption використовуйте sentinel strings і перевірку коректності полів, а не одразу застосовуйте HTTP parser.
- До хороших sentinels належать `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, named-pipe-style strings або явно коректні server/port arrays.
- Якщо HTTP parser завершується помилкою, але plaintext містить узгоджені length-prefixed UTF-8 strings, збережіть sample і спробуйте alternative schemas замість того, щоб відкидати його як false positive.

У цій кампанії custom listener використовував GitHub issues як C2 transport, а beacon звертався до `ipinfo.io`, щоб дізнатися свою зовнішню IP-адресу, оскільки GitHub API безпосередньо не розкриває оператору source address жертви.<sup>[[5]](#references)</sup>

## Network fingerprinting і hunting

HTTP:<sup>[[1]](#references)</sup>
- Типово: POST до URI, вибраних оператором (наприклад, /uri.php, /endpoint/api)
- Custom header parameter, що використовується для beacon ID (наприклад, X‑Beacon‑Id, X‑App‑Id)
- User-agents, що імітують Firefox 20 або актуальні Chrome builds
- Polling cadence, видимий через sleep_delay/jitter_delay
- Новіші builds можуть змінювати URI, user-agents, Host headers і servers під час різних callbacks, тому кластеризацію слід виконувати за uncommon header names, response-size patterns, TLS reuse і timing, а не припускати наявність єдиної пари path/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB named-pipe listeners для intranet C2, коли web egress обмежений
- TCP beacons можуть додавати кілька bytes перед traffic, щоб приховати початок протоколу

Поточні upstream teamserver defaults
- `profile.yaml` наразі постачається з teamserver `0.0.0.0:4321`, endpoint `/endpoint`, іменами certificate/key files `server.rsa.crt` і `server.rsa.key`, а також extenders для HTTP, SMB, TCP, DNS, Beacon agent і Gopher.<sup>[[2]](#references)</sup>
- Для unmatched routes default error handler повертає `Server: AdaptixC2` і `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Стандартне тіло 404 містить `AdaptixC2 404` і `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Internet-wide scans у 2026 році виявили багато exposed teamservers на `4321` і багато beacon listeners на `43211`, тому обидва ports корисні як seed pivots, але їх не слід вважати вичерпними.<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints:<sup>[[4]](#references)</sup>
- Поточний BeaconDNS extender відповідає authoritatively (`AA=true`)
- На queries, що не відповідають beacon protocol shape — зокрема на names із менш ніж 5 labels перед configured domain — зазвичай повертається `TXT "OK"`
- Якщо configured base TTL залишено рівним нулю, listener використовує 10-second base і додає до 59 секунд jitter
- Це робить short-label active probes корисними, коли HTTP listener не exposed

## Loader і persistence TTPs, помічені в incidents

In-memory PowerShell loaders:<sup>[[1]](#references)</sup>
- Завантажують Base64/XOR payloads (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Виділяють unmanaged memory, копіюють shellcode, змінюють protection на 0x40 (PAGE_EXECUTE_READWRITE) через VirtualProtect.<sup>[[7]](#references)</sup>
- Виконуються через .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders:<sup>[[5]](#references)</sup>
- У ланцюжку Tropic Trooper 2026 року використовувався trojanized SumatraPDF executable (TOSHIS loader), який перенаправляв `_security_init_cookie` до malicious code замість patching PE entry point
- Loader розв’язував APIs через Adler-32 hashing, завантажував decoy PDF, отримував second-stage shellcode, розшифровував його за допомогою AES-128-CBC через WinCrypt (`CryptDeriveKey` із hardcoded seed), а потім reflectively виконував Adaptix beacon у memory
- Згодом persistence було перенесено до scheduled tasks із benign-looking names, такими як `\MSDNSvc` або `\MicrosoftUDN`, налаштованих на повторний запуск agent приблизно кожні дві години

Перегляньте ці сторінки щодо in-memory execution і AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms observed:<sup>[[1]](#references)</sup>
- Shortcut (.lnk) у Startup folder для повторного запуску loader під час logon
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), часто з benign-sounding names на кшталт "Updater" для запуску loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijack через розміщення msimg32.dll у %APPDATA%\Microsoft\Windows\Templates для susceptible processes

Technique deep-dives і checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ідеї для hunting
- PowerShell, що створює RW→RX transitions: VirtualProtect до PAGE_EXECUTE_READWRITE всередині powershell.exe.<sup>[[8]](#references)</sup>
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- Unmatched HTTPS 404s із `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` або `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS responses із `AA=true` і `TXT "OK"` для short queries підозрілих domains.<sup>[[4]](#references)</sup>
- GitHub API traffic до `/repos/<owner>/<repo>/issues`, після якого відбуваються lookups до `ipinfo.io` з того самого loader/beacon chain.<sup>[[5]](#references)</sup>
- Startup .lnk у user або common Startup folders.<sup>[[1]](#references)</sup>
- Suspicious Run keys (наприклад, "Updater") і loader names на кшталт update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanized PE samples, які перенаправляють `_security_init_cookie` до downloader code перед показом decoy document.<sup>[[5]](#references)</sup>
- User-writable DLL paths у %APPDATA%\Microsoft\Windows\Templates, що містять msimg32.dll.<sup>[[1]](#references)</sup>

## Примітки щодо OpSec fields

- KillDate: timestamp, після якого agent self-expires.<sup>[[1]](#references)</sup>
- WorkingTime: години, коли agent має бути активним, щоб імітувати business activity.<sup>[[1]](#references)</sup>

Ці fields можна використовувати для clustering і пояснення спостережуваних періодів тиші.

## YARA і static leads

Unit 42 опублікувала базові YARA для beacons (C/C++ і Go) та loader API-hashing constants.<sup>[[1]](#references)</sup> Розгляньте можливість доповнити їх rules, які шукають layout [size|ciphertext|16-byte-key] поблизу кінця PE .rdata, default HTTP profile strings і новіші server/listener markers, такі як `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` і `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Новий Open-Source Framework, використаний у реальних атаках (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 на GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Документація Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Масштабне fingerprinting Open-Source C2 Framework (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper переходить на AdaptixC2 і Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Константи захисту memory – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
