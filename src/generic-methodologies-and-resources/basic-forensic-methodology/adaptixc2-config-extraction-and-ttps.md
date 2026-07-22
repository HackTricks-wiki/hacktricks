# Ekstrakcja konfiguracji AdaptixC2 i TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 to modularny, open-source’owy framework post-exploitation/C2 z beaconami Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) oraz obsługą BOF. Ta strona opisuje:
- sposób osadzania konfiguracji spakowanej za pomocą RC4 oraz jej ekstrakcję z beaconów
- wskaźniki sieciowe/profile dla listenerów HTTP/SMB/TCP
- typowe TTPs loaderów i persistence obserwowane w środowisku, wraz z linkami do odpowiednich stron dotyczących technik Windows

Nowsze upstream releases zawierają również listenery beaconów DNS/DoH oraz oddzielną rodzinę agentów/listenerów Gopher, dlatego współczesna infrastruktura Adaptix może ujawniać więcej niż oryginalne powierzchnie HTTP/SMB/TCP, nawet gdy konkretny sample nadal używa klasycznego beacona.

## Profile beaconów i pola

AdaptixC2 obsługuje trzy podstawowe typy beaconów:
- BEACON_HTTP: web C2 z konfigurowalnymi serwerami/portami/SSL, metodą, URI, nagłówkami, user-agentem oraz niestandardową nazwą parametru
- BEACON_SMB: C2 peer-to-peer oparte na named pipe (intranet)
- BEACON_TCP: bezpośrednie sockety, opcjonalnie z poprzedzającym markerem służącym do zaciemnienia początku protokołu

Są to layouty beaconów udokumentowane publicznie we wczesnych analizach Adaptix i nadal stanowią najczęstszy punkt wyjścia do ekstrakcji po stronie sample. Jednak obecne upstream builds zawierają również extendery `BeaconDNS` i Gopher po stronie serwera, dlatego nie należy zakładać, że każde aktywne wdrożenie Adaptix udostępnia wyłącznie infrastrukturę HTTP/SMB/TCP.

Typowe pola profilu obserwowane w konfiguracjach beaconów HTTP (po odszyfrowaniu):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – używane do parsowania rozmiarów odpowiedzi
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Nowsze buildy BeaconHTTP obsługują również wybierane przez operatora rotowanie między wieloma URI, user-agentami, nagłówkami Host i serwerami, z wyborem sekwencyjnym lub losowym. Z perspektywy huntingu oznacza to, że jeden zainfekowany host może komunikować się z wieloma ścieżkami callback oraz kombinacjami nagłówków, nie opuszczając klasycznej rodziny beaconów spakowanych za pomocą RC4.

Przykładowy domyślny profil HTTP (z builda beacona):
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
Zaobserwowany złośliwy profil HTTP (rzeczywisty atak):
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
## Szyfrowane pakowanie konfiguracji i ścieżka ładowania

Gdy operator klika Create w builderze, AdaptixC2 osadza zaszyfrowany profil jako końcowy blob w beaconie. Format:
- 4 bajty: rozmiar konfiguracji (uint32, little-endian)
- N bajtów: konfiguracja zaszyfrowana RC4
- 16 bajtów: klucz RC4

Loader beacona kopiuje 16-bajtowy klucz z końca i odszyfrowuje blok N bajtów za pomocą RC4 w miejscu:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Praktyczne konsekwencje:
- Cała struktura często znajduje się w sekcji PE .rdata.
- Ekstrakcja jest deterministyczna: odczytaj rozmiar, odczytaj ciphertext o tym rozmiarze, odczytaj 16-bajtowy klucz umieszczony bezpośrednio za nim, a następnie wykonaj deszyfrowanie RC4.

## Workflow ekstrakcji konfiguracji (obrońcy)

Napisz extractor, który imituje logikę beacon:
1) Zlokalizuj blob wewnątrz PE (zwykle w sekcji .rdata). Praktyczne podejście polega na przeskanowaniu .rdata w poszukiwaniu prawdopodobnego układu [size|ciphertext|16-byte key] i podjęciu próby użycia RC4.
2) Odczytaj pierwsze 4 bajty → size (uint32 LE).
3) Odczytaj kolejne N=size bajtów → ciphertext.
4) Odczytaj ostatnie 16 bajtów → klucz RC4.
5) Wykonaj deszyfrowanie RC4 ciphertextu. Następnie sparsuj profil w postaci plaintextu jako:
- skalary u32/boolean, jak opisano powyżej
- stringi z prefiksem długości (długość u32, a następnie bajty; końcowy NUL może występować)
- tablice: servers_count, a następnie odpowiednią liczbę par [string, port u32]

Minimalny proof-of-concept w Pythonie (standalone, bez zewnętrznych zależności), działający z wcześniej wyodrębnionym blobem:
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
Wskazówki:
- Podczas automatyzacji użyj parsera PE do odczytu `.rdata`, a następnie zastosuj sliding window: dla każdego offsetu o spróbuj size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; wykonaj deszyfrowanie RC4 i sprawdź, czy pola stringów dekodują się jako UTF-8, a ich długości są poprawne.
- Parsuj profile SMB/TCP, stosując te same konwencje length-prefixed.

## Custom listener profiles: nie hard-code’uj wyłącznie klasycznego schematu HTTP

Zewnętrzny format pakowania (`u32 size | RC4 ciphertext | 16-byte key`) jest wielokrotnego użytku, dlatego listenery dostosowane przez aktora mogą zachować ten sam workflow ekstrakcji, zmieniając całkowicie układ odszyfrowanych pól.

Dobrym niedawnym przykładem jest kampania Tropic Trooper z kwietnia 2026 roku, w której wyekstrahowany Adaptix beacon nie zawierał standardowego profilu HTTP/TCP. Zamiast tego odszyfrowany blob przechowywał parametry transportu GitHub, takie jak:
- `repo_owner`
- `repo_name`
- `api_host` (na przykład `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktyczna strategia parsera:
- Najpierw wykryj zewnętrzny blob RC4 dokładnie jak zwykle.
- Po deszyfrowaniu rozgałęź parser na podstawie sentinel strings i poprawności pól, zamiast od razu wymuszać parser HTTP.
- Dobrymi sentinelami są `api.github.com`, `/issues?state=open`, metody/URI HTTP, stringi w stylu named pipe lub oczywiście poprawne tablice server/port.
- Jeśli parser HTTP zawiedzie, ale plaintext zawiera spójne stringi UTF-8 z length-prefixed, zachowaj próbkę i spróbuj alternatywnych schematów zamiast odrzucać ją jako false positive.

W tej kampanii custom listener używał GitHub issues jako transportu C2, a beacon odpytywał `ipinfo.io`, aby poznać swój zewnętrzny adres IP, ponieważ GitHub API nie ujawnia operatorowi bezpośrednio źródłowego adresu ofiary.

## Network fingerprinting i hunting

HTTP
- Typowe: POST do URI wybranych przez operatora (np. `/uri.php`, `/endpoint/api`)
- Custom header parameter używany jako beacon ID (np. `X‑Beacon‑Id`, `X‑App‑Id`)
- User-agenty naśladujące Firefox 20 lub współczesne buildy Chrome
- Częstotliwość pollingu widoczna przez `sleep_delay`/`jitter_delay`
- Nowsze buildy mogą rotować URI, user-agenty, nagłówki Host i serwery między callbackami, dlatego grupuj na podstawie nietypowych nazw nagłówków, wzorców rozmiaru odpowiedzi, ponownego użycia TLS i timingów, zamiast zakładać pojedynczą parę ścieżka/UA

SMB/TCP
- Listenery SMB named pipe dla intranetowego C2, gdy web egress jest ograniczony
- Beacony TCP mogą dodawać kilka bajtów przed traffic, aby zaciemnić początek protokołu

Current upstream teamserver defaults
- `profile.yaml` obecnie dostarczany jest z teamserverem `0.0.0.0:4321`, endpointem `/endpoint`, nazwami plików certificate/key `server.rsa.crt` i `server.rsa.key` oraz extenderami dla HTTP, SMB, TCP, DNS, Beacon agent i Gopher
- Dla niepasujących routes domyślny error handler zwraca `Server: AdaptixC2` i `Adaptix-Version: v1.2`
- Standardowy body odpowiedzi 404 zawiera `AdaptixC2 404` oraz `You need to enter the correct connection details.`
- Scany obejmujące cały Internet w 2026 roku wykazały wiele exposed teamservers na `4321` oraz wiele beacon listenerów na `43211`, dlatego oba porty są użytecznymi seed pivots, ale nie należy traktować ich jako wyczerpujących

Fingerprinty listenera DNS/DoH
- Obecny extender BeaconDNS odpowiada autorytatywnie (`AA=true`)
- Zapytania, które nie pasują do kształtu protokołu beacon — w szczególności nazwy zawierające mniej niż 5 labels przed skonfigurowaną domeną — są zwykle obsługiwane odpowiedzią `TXT "OK"`
- Jeśli skonfigurowany base TTL pozostanie równy zero, listener używa wartości bazowej 10 sekund i dodaje do 59 sekund jitteru
- Dzięki temu short-label active probes są przydatne, gdy HTTP listener nie jest wystawiony

## Loader i persistence TTPs obserwowane w incydentach

Loadery PowerShell działające in-memory
- Pobierają payloady Base64/XOR (`Invoke‑RestMethod` / WebClient)
- Alokują unmanaged memory, kopiują shellcode i zmieniają ochronę na `0x40` (`PAGE_EXECUTE_READWRITE`) za pomocą `VirtualProtect`
- Wykonują kod przez .NET dynamic invocation: `Marshal.GetDelegateForFunctionPointer` + `delegate.Invoke()`

Trojanized signed software / staged shellcode loaders
- W łańcuchu Tropic Trooper z 2026 roku użyto trojanized executable SumatraPDF (loadera TOSHIS), który przekierowywał `_security_init_cookie` do malicious code zamiast modyfikować PE entry point
- Loader rozwiązywał API za pomocą hashowania Adler-32, pobierał decoy PDF, pobierał second-stage shellcode, deszyfrował go przy użyciu AES-128-CBC przez WinCrypt (`CryptDeriveKey` z hardcoded seed), a następnie wykonywał reflectively Adaptix beacon w pamięci
- Persistence została później przeniesiona do scheduled tasks z pozornie benignowymi nazwami, takimi jak `\MSDNSvc` lub `\MicrosoftUDN`, skonfigurowanymi do ponownego uruchamiania agenta mniej więcej co dwie godziny

Sprawdź te strony pod kątem in-memory execution oraz kwestii AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Zaobserwowane mechanizmy persistence
- Skrót (.lnk) w Startup folder uruchamiający ponownie loader przy logowaniu
- Registry Run keys (`HKCU/HKLM ...\CurrentVersion\Run`), często z benign-sounding names, takimi jak `"Updater"`, uruchamiającymi `loader.ps1`
- DLL search-order hijack przez umieszczenie `msimg32.dll` w `%APPDATA%\Microsoft\Windows\Templates` dla podatnych procesów

Szczegółowe omówienia technik i testy:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Pomysły na hunting
- PowerShell uruchamiający przejścia RW→RX: `VirtualProtect` do `PAGE_EXECUTE_READWRITE` wewnątrz `powershell.exe`
- Wzorce dynamic invocation (`GetDelegateForFunctionPointer`)
- Niedopasowane HTTPS 404 z `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` lub `You need to enter the correct connection details.`
- Odpowiedzi DNS z `AA=true` i `TXT "OK"` dla short queries w podejrzanych domenach
- Traffic GitHub API do `/repos/<owner>/<repo>/issues`, po którym z tego samego łańcucha loader/beacon następują odwołania do `ipinfo.io`
- Startup `.lnk` w folderach użytkownika lub wspólnych folderach Startup
- Podejrzane Run keys (np. `"Updater"`), a także nazwy loaderów, takie jak `update.ps1`/`loader.ps1`
- Trojanized samples PE przekierowujące `_security_init_cookie` do kodu downloadera przed wyświetleniem decoy document
- Ścieżki DLL zapisywalne przez użytkownika w `%APPDATA%\Microsoft\Windows\Templates`, zawierające `msimg32.dll`

## Uwagi dotyczące pól OpSec

- KillDate: timestamp, po którym agent sam wygasa
- WorkingTime: godziny, w których agent powinien być aktywny, aby upodobnić się do aktywności biznesowej

Pola te mogą być używane do klastrowania oraz wyjaśniania zaobserwowanych okresów ciszy.

## YARA i wskazówki statyczne

Unit 42 opublikowało podstawowe reguły YARA dla beaconów (C/C++ i Go) oraz stałych używanych do hashowania API w loaderach. Rozważ uzupełnienie ich o reguły wyszukujące układ [size|ciphertext|16-byte-key] w pobliżu końca PE `.rdata`, domyślne stringi profilu HTTP oraz nowsze markery server/listener, takie jak `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` i `ipinfo.io`.

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
