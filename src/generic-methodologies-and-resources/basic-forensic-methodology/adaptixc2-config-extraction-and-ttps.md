# Wyodrębnianie konfiguracji AdaptixC2 i TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 to modułowy framework post-exploitation/C2 o otwartym kodzie źródłowym, obsługujący beacony Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) oraz BOF.<sup>[[1]](#references)</sup> Ta strona opisuje:
- Sposób osadzenia konfiguracji spakowanej za pomocą RC4 oraz jej wyodrębniania z beaconów
- Wskaźniki sieciowe i profilowe listenerów HTTP/SMB/TCP
- Typowe TTPs loaderów i mechanizmów persistence zaobserwowane w terenie, wraz z odnośnikami do odpowiednich stron o technikach Windows

Najnowsze wersje upstream zawierają również listenery beaconów DNS/DoH oraz oddzielną rodzinę agentów/listenerów Gopher. Dlatego współczesna infrastruktura Adaptix może udostępniać więcej niż pierwotne interfejsy HTTP/SMB/TCP, nawet jeśli konkretny sample nadal używa klasycznego agenta beacon.<sup>[[2]](#references)</sup>

## Profile beaconów i pola

AdaptixC2 obsługuje trzy główne typy beaconów:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 z konfigurowalnymi serwerami/portami/SSL, metodą, URI, nagłówkami, user-agentem i własną nazwą parametru
- BEACON_SMB: komunikacja peer-to-peer przez nazwane pipe’y (intranet)
- BEACON_TCP: bezpośrednie gniazda, opcjonalnie z poprzedzającym znacznikiem maskującym początek protokołu

Są to układy beaconów udokumentowane publicznie we wczesnych analizach Adaptix i nadal stanowią najczęstszy punkt wyjścia do wyodrębniania konfiguracji z sample’a.<sup>[[1]](#references)</sup> Jednak obecne buildy upstream zawierają również po stronie serwera rozszerzenia `BeaconDNS` i Gopher. Nie zakładaj więc, że każda aktywna instalacja Adaptix udostępnia wyłącznie infrastrukturę HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Typowe pola profilu wykrywane w konfiguracjach beaconów HTTP (po odszyfrowaniu):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (tablica stringów), ports (tablica u32)
- http_method, uri, parameter, user_agent, http_headers (stringi z prefiksem długości)
- ans_pre_size (u32), ans_size (u32) – używane do parsowania rozmiarów odpowiedzi
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Najnowsze buildy BeaconHTTP obsługują również rotację między wieloma URI, user-agentami, nagłówkami Host i serwerami, wybraną przez operatora, z wyborem sekwencyjnym lub losowym.<sup>[[2]](#references)</sup> Z perspektywy threat huntingu oznacza to, że pojedynczy zainfekowany host może korzystać z wielu ścieżek callbacków i kombinacji nagłówków, nie opuszczając przy tym klasycznej rodziny beaconów spakowanych za pomocą RC4.

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

## Pakowanie zaszyfrowanej konfiguracji i ścieżka ładowania

Gdy operator kliknie Create w builderze, AdaptixC2 osadza zaszyfrowany profil jako końcowy blob w beaconie. Format:<sup>[[1]](#references)</sup>
- 4 bajty: rozmiar konfiguracji (uint32, little-endian)
- N bajtów: konfiguracja zaszyfrowana RC4
- 16 bajtów: klucz RC4

Loader beacona kopiuje 16-bajtowy klucz z końca i odszyfrowuje blok N bajtów algorytmem RC4 w miejscu:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Praktyczne implikacje:<sup>[[1]](#references)</sup>
- Cała struktura często znajduje się w sekcji PE .rdata.
- Ekstrakcja jest deterministyczna: odczytaj rozmiar, odczytaj szyfrogram o tym rozmiarze, odczytaj 16-bajtowy klucz umieszczony bezpośrednio za nim, a następnie odszyfruj RC4.

## Przepływ ekstrakcji konfiguracji (obrońcy)

Napisz narzędzie ekstrakcyjne naśladujące logikę beacona:<sup>[[1]](#references)</sup>
1) Znajdź blob w pliku PE (zwykle w sekcji .rdata). Praktyczne podejście polega na skanowaniu .rdata w poszukiwaniu wiarygodnego układu [rozmiar|szyfrogram|16-bajtowy klucz] i próbie odszyfrowania RC4.
2) Odczytaj pierwsze 4 bajty → rozmiar (uint32 LE).
3) Odczytaj kolejne N=size bajtów → szyfrogram.
4) Odczytaj ostatnie 16 bajtów → klucz RC4.
5) Odszyfruj szyfrogram za pomocą RC4. Następnie parsuj profil w postaci jawnej:
   - skalarów u32/boolean zgodnie z opisem powyżej
   - ciągów znaków z prefiksem długości (długość u32, po której następują bajty; na końcu może występować NUL)
   - tablic: servers_count, po którym następuje podana liczba par [ciąg znaków, port u32]

Minimalny proof-of-concept w Pythonie (samodzielny, bez zewnętrznych zależności), działający z wcześniej wyodrębnionym blobem:

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
- Przy automatyzacji użyj parsera PE, aby odczytać .rdata, a następnie zastosuj przesuwane okno: dla każdego offsetu o spróbuj size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = następne 16 bajtów; odszyfruj RC4 i sprawdź, czy pola tekstowe dają się zdekodować jako UTF-8, a długości są sensowne.
- Parsuj profile SMB/TCP, stosując te same konwencje pól z prefiksem długości.

## Profile custom listenerów: nie zakładaj na sztywno wyłącznie klasycznego schematu HTTP

Zewnętrzny format pakowania (`u32 size | RC4 ciphertext | 16-byte key`) można wykorzystać ponownie, więc listenery dostosowane przez aktora mogą używać tego samego workflow ekstrakcji, zmieniając przy tym całkowicie układ odszyfrowanych pól.

Dobrym, niedawnym przykładem jest kampania Tropic Trooper z marca 2026 roku, w której wyodrębniony Adaptix beacon nie zawierał standardowego profilu HTTP/TCP. Zamiast tego odszyfrowany blob przechowywał parametry transportu GitHub, takie jak:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (na przykład `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktyczna strategia parsowania:
- Najpierw wykryj zewnętrzny blob RC4 tak jak zwykle.
- Po odszyfrowaniu rozgałęź parser na podstawie ciągów znacznikowych i poprawności pól, zamiast od razu wymuszać użycie parsera HTTP.
- Dobrymi znacznikami są `api.github.com`, `/issues?state=open`, czasowniki HTTP/URI, ciągi przypominające nazwy potoków, lub oczywiście poprawne tablice serwerów/portów.
- Jeśli parser HTTP zawiedzie, ale tekst jawny zawiera spójne ciągi UTF-8 z prefiksem długości, zachowaj próbkę i spróbuj alternatywnych schematów, zamiast odrzucać ją jako fałszywie pozytywny wynik.

W tej kampanii custom listener używał GitHub issues jako transportu C2, a beacon odpytwał `ipinfo.io`, aby poznać swój zewnętrzny adres IP, ponieważ GitHub API nie ujawnia operatorowi bezpośrednio adresu źródłowego ofiary.<sup>[[5]](#references)</sup>

## Fingerprinting sieci i hunting

HTTP:<sup>[[1]](#references)</sup>
- Typowe: POST do URI wybranych przez operatora (np. /uri.php, /endpoint/api)
- Niestandardowy parametr nagłówka używany jako beacon ID (np. X‑Beacon‑Id, X‑App‑Id)
- User-agents podszywające się pod Firefox 20 lub współczesne wersje Chrome
- Częstotliwość odpytywania widoczna w sleep_delay/jitter_delay
- Nowsze wersje mogą rotować URI, user-agents, nagłówki Host i serwery między callbackami, więc grupuj ruch na podstawie nietypowych nazw nagłówków, wzorców rozmiarów odpowiedzi, ponownego użycia TLS i czasu, zamiast zakładać pojedynczą parę ścieżka/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listenery SMB używające nazwanych potoków dla intranetowego C2, gdy ruch wychodzący przez sieć WWW jest ograniczony
- Beacony TCP mogą dodawać kilka bajtów przed ruchem, aby zaciemnić początek protokołu

Domyślne ustawienia bieżącego upstream teamserver
- `profile.yaml` zawiera obecnie teamserver `0.0.0.0:4321`, endpoint `/endpoint`, nazwy plików certyfikatu/klucza `server.rsa.crt` i `server.rsa.key` oraz rozszerzenia dla HTTP, SMB, TCP, DNS, agenta Beacon i Gopher.<sup>[[2]](#references)</sup>
- W przypadku niepasujących tras domyślny handler błędów zwraca `Server: AdaptixC2` i `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Domyślne ciało odpowiedzi 404 zawiera `AdaptixC2 404` i `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Skanowanie całego Internetu w 2026 roku wykazało wiele ujawnionych teamserverów na porcie `4321` i wiele beacon listenerów na porcie `43211`, dlatego oba porty są przydatnymi punktami wyjścia do dalszych poszukiwań, ale nie należy traktować ich jako wyczerpującej listy.<sup>[[4]](#references)</sup>

Odciski listenerów DNS/DoH:<sup>[[4]](#references)</sup>
- Bieżące rozszerzenie BeaconDNS odpowiada autorytatywnie (`AA=true`)
- Zapytania niepasujące do kształtu protokołu beacon — w szczególności nazwy zawierające mniej niż 5 etykiet przed skonfigurowaną domeną — często otrzymują odpowiedź `TXT "OK"`
- Jeśli skonfigurowana bazowa wartość TTL pozostaje równa zero, listener używa wartości bazowej 10 sekund i dodaje do 59 sekund jittera
- Dzięki temu aktywne sondy z krótkimi etykietami są przydatne, gdy nie jest wystawiony listener HTTP

## TTP loaderów i persistence zaobserwowane podczas incydentów

Loadery PowerShell działające w pamięci:<sup>[[1]](#references)</sup>
- Pobierają payloady Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Przydzielają pamięć niezarządzaną, kopiują shellcode i zmieniają ochronę na 0x40 (PAGE_EXECUTE_READWRITE) za pomocą VirtualProtect.<sup>[[7]](#references)</sup>
- Wykonują kod przez dynamiczne wywołanie .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Podpisane, podmienione oprogramowanie / etapowe loadery shellcode:<sup>[[5]](#references)</sup>
- W łańcuchu ataku Tropic Trooper z 2026 roku użyto podmienionego pliku wykonywalnego SumatraPDF (loader TOSHIS), który przekierowywał `_security_init_cookie` do złośliwego kodu, zamiast modyfikować punkt wejścia PE
- Loader rozwiązywał API za pomocą hashowania Adler-32, pobierał przynętę w postaci PDF, pobierał shellcode drugiego etapu, odszyfrowywał go algorytmem AES-128-CBC przez WinCrypt (`CryptDeriveKey` z użyciem zakodowanego na stałe ziarna) i refleksyjnie wykonywał Adaptix beacon w pamięci
- Persistence przeniesiono później do zaplanowanych zadań o nazwach wyglądających na nieszkodliwe, takich jak `\MSDNSvc` lub `\MicrosoftUDN`, skonfigurowanych tak, aby ponownie uruchamiały agenta mniej więcej co dwie godziny

Zapoznaj się z tymi stronami, aby dowiedzieć się więcej o wykonywaniu kodu w pamięci oraz kwestiach związanych z AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Zaobserwowane mechanizmy persistence:<sup>[[1]](#references)</sup>
- Skrót (.lnk) w folderze Autostart uruchamiający ponownie loadera podczas logowania
- Klucze rejestru Run (HKCU/HKLM ...\CurrentVersion\Run), często z nazwami brzmiącymi nieszkodliwie, takimi jak "Updater", uruchamiające loader.ps1.<sup>[[10]](#references)</sup>
- Przejęcie kolejności wyszukiwania DLL przez umieszczenie msimg32.dll w %APPDATA%\Microsoft\Windows\Templates dla podatnych procesów

Szczegółowe omówienia technik i kontrole:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Pomysły na hunting
- Procesy PowerShell tworzące przejścia RW→RX: VirtualProtect ustawiający PAGE_EXECUTE_READWRITE wewnątrz powershell.exe.<sup>[[8]](#references)</sup>
- Wzorce dynamicznego wywoływania (GetDelegateForFunctionPointer)
- Niepasujące odpowiedzi HTTPS 404 z `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` lub `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Odpowiedzi DNS z `AA=true` i `TXT "OK"` na krótkie zapytania w podejrzanych domenach.<sup>[[4]](#references)</sup>
- Ruch do GitHub API pod adresem `/repos/<owner>/<repo>/issues`, po którym następują zapytania do `ipinfo.io` w ramach tego samego łańcucha loader/beacon.<sup>[[5]](#references)</sup>
- Pliki .lnk w folderach Autostart użytkownika lub wspólnych folderach Autostart.<sup>[[1]](#references)</sup>
- Podejrzane klucze Run (np. "Updater") i nazwy loaderów, takie jak update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Podmienione próbki PE przekierowujące `_security_init_cookie` do kodu pobierającego payload, zanim wyświetlony zostanie dokument-przynęta.<sup>[[5]](#references)</sup>
- Zapisywalne przez użytkownika ścieżki DLL w %APPDATA%\Microsoft\Windows\Templates zawierające msimg32.dll.<sup>[[1]](#references)</sup>

## Uwagi dotyczące pól OpSec

- KillDate: znacznik czasu, po którym agent sam się dezaktywuje.<sup>[[1]](#references)</sup>
- WorkingTime: godziny, w których agent powinien być aktywny, aby wtopić się w zwykłą aktywność biznesową.<sup>[[1]](#references)</sup>

Pola te można wykorzystać do grupowania i wyjaśniania zaobserwowanych okresów ciszy.

## YARA i wskazówki do analizy statycznej

Unit 42 opublikował podstawowe reguły YARA dla beaconów (C/C++ i Go) oraz stałych używanych do hashowania API przez loadery.<sup>[[1]](#references)</sup> Warto uzupełnić je regułami wyszukującymi układ [size|ciphertext|16-byte-key] w pobliżu końca sekcji PE .rdata, domyślne ciągi profilu HTTP oraz nowsze znaczniki serwera/listenera, takie jak `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` i `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: nowy framework open source wykorzystywany w rzeczywistych atakach (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Dokumentacja Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: fingerprinting frameworka C2 open source na dużą skalę (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper przechodzi na AdaptixC2 i custom Beacon listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – dokumentacja Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – dokumentacja Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Stałe ochrony pamięci – dokumentacja Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – klucze Run rejestru/folder Autostart](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
