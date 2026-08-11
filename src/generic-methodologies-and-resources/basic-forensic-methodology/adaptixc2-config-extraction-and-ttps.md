# Ekstrakcja konfiguracji i TTPs AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 to modularny, open‑source’owy framework post‑exploitation/C2 z beaconami Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) oraz obsługą BOF.<sup>[[1]](#references)</sup> Ta strona opisuje:
- sposób osadzania konfiguracji spakowanej za pomocą RC4 oraz jej ekstrakcji z beaconów
- wskaźniki sieciowe/profile dla listenerów HTTP/SMB/TCP
- typowe loaderowe i persistence TTPs obserwowane w praktyce, wraz z linkami do odpowiednich stron dotyczących technik Windows

Nowsze wydania upstream zawierają również listenery beaconów DNS/DoH oraz oddzielną rodzinę agentów/listenerów Gopher, dlatego współczesna infrastruktura Adaptix może ujawniać więcej niż pierwotne powierzchnie HTTP/SMB/TCP, nawet gdy konkretny sample nadal używa klasycznego beacona.<sup>[[2]](#references)</sup>

## Profile beaconów i pola

AdaptixC2 obsługuje trzy podstawowe typy beaconów:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 z konfigurowalnymi serwerami/portami/SSL, metodą, URI, nagłówkami, user-agentem i niestandardową nazwą parametru
- BEACON_SMB: komunikacja C2 peer-to-peer oparta na named pipe (intranet)
- BEACON_TCP: bezpośrednie sockety, opcjonalnie z poprzedzającym markerem do zaciemniania początku protokołu

Są to układy beaconów publicznie opisane we wczesnych analizach Adaptix i nadal stanowią najczęstszy punkt wyjścia do ekstrakcji po stronie sample’a.<sup>[[1]](#references)</sup> Jednak obecne buildy upstream zawierają również rozszerzenia `BeaconDNS` i Gopher po stronie serwera, dlatego nie należy zakładać, że każda działająca infrastruktura Adaptix udostępnia wyłącznie infrastrukturę HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Typowe pola profilu obserwowane w konfiguracjach beaconów HTTP (po deszyfracji):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – używane do parsowania rozmiarów odpowiedzi
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Nowsze buildy BeaconHTTP obsługują również wybieraną przez operatora rotację pomiędzy wieloma URI, user-agentami, nagłówkami Host i serwerami, z wyborem sekwencyjnym lub losowym.<sup>[[2]](#references)</sup> Z perspektywy threat hunting oznacza to, że pojedynczy zainfekowany host może komunikować się z kilkoma ścieżkami callback oraz kombinacjami nagłówków, nie opuszczając klasycznej rodziny beaconów spakowanych za pomocą RC4.

Przykładowy domyślny profil HTTP (z builda beacona):<sup>[[1]](#references)</sup>
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
Zaobserwowany złośliwy profil HTTP (rzeczywisty atak):<sup>[[1]](#references)</sup>
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
## Szyfrowanie konfiguracji, pakowanie i ścieżka ładowania

Gdy operator klika Create w builderze, AdaptixC2 osadza zaszyfrowany profil jako końcowy blob w beaconie. Format to:<sup>[[1]](#references)</sup>
- 4 bajty: rozmiar konfiguracji (uint32, little-endian)
- N bajtów: dane konfiguracji zaszyfrowane RC4
- 16 bajtów: klucz RC4

Loader beacona kopiuje 16-bajtowy klucz z końca i odszyfrowuje blok N bajtów za pomocą RC4 w miejscu:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Praktyczne implikacje:<sup>[[1]](#references)</sup>
- Cała struktura często znajduje się wewnątrz sekcji PE .rdata.
- Ekstrakcja jest deterministyczna: odczytaj rozmiar, odczytaj ciphertext o tym rozmiarze, odczytaj 16‑bajtowy klucz umieszczony bezpośrednio za nim, a następnie wykonaj RC4‑decrypt.

## Workflow ekstrakcji konfiguracji (obrońcy)

Napisz extractor, który naśladuje logikę beaconu:<sup>[[1]](#references)</sup>
1) Zlokalizuj blob wewnątrz PE (zwykle w .rdata). Praktyczne podejście polega na przeskanowaniu .rdata w poszukiwaniu wiarygodnego układu [size|ciphertext|16‑byte key] i podjęciu próby użycia RC4.
2) Odczytaj pierwsze 4 bajty → size (uint32 LE).
3) Odczytaj następne N=size bajtów → ciphertext.
4) Odczytaj ostatnie 16 bajtów → klucz RC4.
5) Wykonaj RC4‑decrypt ciphertextu. Następnie sparsuj plain profile jako:
- skalary u32/boolean, jak opisano powyżej
- stringi z prefiksem długości (długość u32, po której następują bajty; końcowy NUL może występować)
- tablice: servers_count, po którym następuje określona liczba par [string, u32 port]

Minimalny Python proof‑of‑concept (standalone, bez zewnętrznych zależności), działający z wcześniej wyekstrahowanym blobem:
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
- Podczas automatyzacji użyj parsera PE do odczytu sekcji .rdata, a następnie zastosuj przesuwane okno: dla każdego przesunięcia o spróbuj size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; odszyfruj za pomocą RC4 i sprawdź, czy pola łańcuchów znaków dekodują się jako UTF-8, a długości są prawidłowe.
- Parsuj profile SMB/TCP, korzystając z tych samych konwencji pól poprzedzonych długością.

## Custom listener profiles: don't hard-code only the classic HTTP schema

Zewnętrzny format pakowania (`u32 size | RC4 ciphertext | 16-byte key`) można ponownie wykorzystać, dlatego listenery dostosowane przez aktora mogą zachować ten sam proces ekstrakcji, zmieniając jednocześnie całkowicie układ odszyfrowanych pól.

Dobrym, niedawnym przykładem jest kampania Tropic Trooper z marca 2026 roku, w której wyekstrahowany Adaptix beacon nie zawierał standardowego profilu HTTP/TCP. Zamiast tego odszyfrowany blob przechowywał parametry transportu GitHub, takie jak:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (na przykład `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktyczna strategia parsera:
- Najpierw wykryj zewnętrzny blob RC4 dokładnie jak zwykle.
- Po odszyfrowaniu rozgałęź parser na podstawie łańcuchów sygnaturowych i poprawności pól, zamiast od razu wymuszać parser HTTP.
- Dobrymi sygnaturami są `api.github.com`, `/issues?state=open`, czasowniki/URI HTTP, łańcuchy w stylu named pipe lub wyraźnie poprawne tablice serwerów/portów.
- Jeśli parser HTTP zawiedzie, ale plaintext zawiera spójne łańcuchy UTF-8 poprzedzone długością, zachowaj próbkę i spróbuj alternatywnych schematów zamiast odrzucać ją jako false positive.

W tej kampanii custom listener wykorzystywał GitHub issues jako transport C2, a beacon odpytywał `ipinfo.io`, aby poznać swój zewnętrzny adres IP, ponieważ GitHub API nie ujawnia operatorowi bezpośrednio adresu źródłowego ofiary.<sup>[[5]](#references)</sup>

## Network fingerprinting and hunting

HTTP:<sup>[[1]](#references)</sup>
- Typowe: żądania POST do URI wybranych przez operatora (np. /uri.php, /endpoint/api)
- Custom header parameter używany jako beacon ID (np. X‑Beacon‑Id, X‑App‑Id)
- User-agenty naśladujące Firefox 20 lub współczesne wersje Chrome
- Częstotliwość odpytywania widoczna za pośrednictwem sleep_delay/jitter_delay
- Nowsze buildy mogą rotować URI, user-agenty, nagłówki Host i serwery między callbackami, dlatego należy grupować zdarzenia na podstawie rzadko spotykanych nazw nagłówków, wzorców rozmiaru odpowiedzi, ponownego użycia TLS i czasu, zamiast zakładać pojedynczą parę ścieżka/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listenery named pipe SMB do intranetowego C2, gdy web egress jest ograniczony
- TCP beacons mogą poprzedzać ruch kilkoma bajtami w celu zaciemnienia początku protokołu

Bieżące domyślne wartości upstream teamserver
- `profile.yaml` obecnie zawiera teamserver `0.0.0.0:4321`, endpoint `/endpoint`, nazwy plików certyfikatu/klucza `server.rsa.crt` i `server.rsa.key` oraz extenders dla HTTP, SMB, TCP, DNS, Beacon agent i Gopher.<sup>[[2]](#references)</sup>
- W przypadku niedopasowanych tras domyślny error handler zwraca `Server: AdaptixC2` oraz `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Standardowe body odpowiedzi 404 zawiera `AdaptixC2 404` oraz `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Skany obejmujące cały Internet przeprowadzone w 2026 roku wykazały wiele exposed teamservers na porcie `4321` oraz wiele beacon listenerów na `43211`, dlatego oba porty są użytecznymi punktami początkowymi, ale nie należy traktować ich jako wyczerpującego zestawu.<sup>[[4]](#references)</sup>

Sygnatury listenerów DNS/DoH:<sup>[[4]](#references)</sup>
- Bieżący extender BeaconDNS odpowiada autorytatywnie (`AA=true`)
- Zapytania, które nie pasują do kształtu protokołu beacon — w szczególności nazwy zawierające mniej niż 5 labeli przed skonfigurowaną domeną — często otrzymują odpowiedź `TXT "OK"`
- Jeśli skonfigurowany bazowy TTL pozostawiono na zero, listener używa wartości bazowej 10 sekund i dodaje jitter do 59 sekund
- Dzięki temu krótkie aktywne sondy są przydatne, gdy nie jest wystawiony żaden listener HTTP

## Loader and persistence TTPs seen in incidents

Loadery PowerShell działające in-memory:<sup>[[1]](#references)</sup>
- Pobierają payloady Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Przydzielają unmanaged memory, kopiują shellcode i zmieniają ochronę na 0x40 (PAGE_EXECUTE_READWRITE) za pomocą VirtualProtect.<sup>[[7]](#references)</sup>
- Wykonują kod przez dynamic invocation .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders:<sup>[[5]](#references)</sup>
- W 2026 roku jeden z łańcuchów Tropic Trooper wykorzystywał trojanized executable SumatraPDF (TOSHIS loader), który przekierowywał `_security_init_cookie` do złośliwego kodu zamiast modyfikować punkt wejścia PE
- Loader rozwiązywał API za pomocą haszowania Adler-32, pobierał decoy PDF, pobierał second-stage shellcode, odszyfrowywał go za pomocą AES-128-CBC przez WinCrypt (`CryptDeriveKey` z hardcoded seed), a następnie wykonywał reflectively Adaptix beacon w pamięci
- Persistence została później przeniesiona do scheduled tasks o pozornie nieszkodliwych nazwach, takich jak `\MSDNSvc` lub `\MicrosoftUDN`, skonfigurowanych do ponownego uruchamiania agenta mniej więcej co dwie godziny

Sprawdź te strony pod kątem wykonywania in-memory oraz zagadnień AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Zaobserwowane mechanizmy persistence:<sup>[[1]](#references)</sup>
- Skrót (.lnk) w Startup folder, uruchamiający loader ponownie podczas logowania
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), często z pozornie nieszkodliwymi nazwami, takimi jak "Updater", aby uruchamiać loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijack przez umieszczenie msimg32.dll w %APPDATA%\Microsoft\Windows\Templates dla podatnych procesów

Szczegółowe analizy technik i kontrole:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Pomysły na hunting
- PowerShell generujący przejścia RW→RX: VirtualProtect do PAGE_EXECUTE_READWRITE wewnątrz powershell.exe.<sup>[[8]](#references)</sup>
- Wzorce dynamic invocation (GetDelegateForFunctionPointer)
- Niedopasowane odpowiedzi HTTPS 404 zawierające `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` lub `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Odpowiedzi DNS z `AA=true` i `TXT "OK"` dla krótkich zapytań w podejrzanych domenach.<sup>[[4]](#references)</sup>
- Ruch GitHub API do `/repos/<owner>/<repo>/issues`, po którym następują odwołania do `ipinfo.io` z tego samego łańcucha loader/beacon.<sup>[[5]](#references)</sup>
- Plik Startup .lnk w folderach Startup użytkownika lub wspólnych folderach Startup.<sup>[[1]](#references)</sup>
- Podejrzane Run keys (np. "Updater") oraz nazwy loaderów, takie jak update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanized próbki PE, które przekierowują `_security_init_cookie` do kodu downloadera przed wyświetleniem decoy document.<sup>[[5]](#references)</sup>
- Ścieżki DLL zapisywalne przez użytkownika w %APPDATA%\Microsoft\Windows\Templates, zawierające msimg32.dll.<sup>[[1]](#references)</sup>

## Notes on OpSec fields

- KillDate: timestamp, po którym agent sam wygasa.<sup>[[1]](#references)</sup>
- WorkingTime: godziny, w których agent powinien być aktywny, aby upodobnić się do aktywności biznesowej.<sup>[[1]](#references)</sup>

Pola te mogą służyć do grupowania zdarzeń i wyjaśniania zaobserwowanych okresów ciszy.

## YARA and static leads

Unit 42 opublikowało podstawowe reguły YARA dla beaconów (C/C++ i Go) oraz stałych używanych do haszowania API przez loadery.<sup>[[1]](#references)</sup> Rozważ uzupełnienie ich o reguły wyszukujące układ [size|ciphertext|16‑byte‑key] w pobliżu końca sekcji PE .rdata, domyślne łańcuchy profilu HTTP oraz nowsze znaczniki serwera/listenera, takie jak `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` i `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Nowy open-source framework wykorzystywany w atakach w świecie rzeczywistym (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Dokumentacja Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting open-source frameworka C2 na dużą skalę (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper przechodzi na AdaptixC2 i custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Stałe ochrony pamięci – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
