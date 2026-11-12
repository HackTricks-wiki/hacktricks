# Wyodrębnianie konfiguracji AdaptixC2 i TTP

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 to modularny framework post-exploitation/C2 o otwartym kodzie źródłowym, obsługujący beacony Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) oraz BOF.<sup>[[1]](#references)</sup> Ta strona opisuje:
- Sposób osadzania konfiguracji spakowanej za pomocą RC4 oraz jej wyodrębniania z beaconów
- Wskaźniki sieciowe i profilowe listenerów HTTP/SMB/TCP
- Typowe TTP loaderów i persistence obserwowane w terenie, z linkami do odpowiednich stron poświęconych technikom Windows

Najnowsze wydania upstream zawierają również listenery beaconów DNS/DoH oraz odrębną rodzinę agentów/listenerów Gopher, dlatego nowoczesna infrastruktura Adaptix może udostępniać więcej niż pierwotne interfejsy HTTP/SMB/TCP, nawet jeśli konkretny sample nadal korzysta z klasycznego agenta beacon.<sup>[[2]](#references)</sup>

## Profile beaconów i pola

AdaptixC2 obsługuje trzy główne typy beaconów:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 z konfigurowalnymi serwerami/portami/SSL, metodą, URI, nagłówkami, user-agentem i niestandardową nazwą parametru
- BEACON_SMB: komunikacja peer-to-peer przez named pipe (intranet)
- BEACON_TCP: bezpośrednie gniazda, opcjonalnie ze znacznikiem dodanym na początku w celu utrudnienia rozpoznania początku protokołu

Są to układy beaconów opisane publicznie we wczesnych analizach Adaptix i nadal stanowią najczęstszy punkt wyjścia do wyodrębniania danych z sample.<sup>[[1]](#references)</sup> Jednak bieżące wersje upstream zawierają również rozszerzenia `BeaconDNS` i Gopher po stronie serwera, dlatego nie należy zakładać, że każda aktywna instalacja Adaptix udostępnia wyłącznie infrastrukturę HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Poniższe podsumowanie pól i przykłady JSON opisują format HTTP analizowany w 2025 roku; nie stanowią specyfikacji parsera dla nowszych wersji upstream. Typowe pola w tych przykładach (po odszyfrowaniu):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (tablica ciągów znaków), ports (tablica u32)
- http_method, uri, parameter, user_agent, http_headers (ciągi znaków poprzedzone długością)
- ans_pre_size (u32), ans_size (u32) – używane do parsowania rozmiarów odpowiedzi
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Najnowsze wersje BeaconHTTP obsługują również rotację wybraną przez operatora między wieloma URI, user-agentami, nagłówkami Host i serwerami, z wyborem sekwencyjnym lub losowym.<sup>[[2]](#references)</sup> Z punktu widzenia threat huntingu oznacza to, że pojedynczy zainfekowany host może korzystać z wielu ścieżek callbacków i kombinacji nagłówków, nie opuszczając przy tym klasycznej rodziny beaconów spakowanych za pomocą RC4.

Przykładowy domyślny profil HTTP (z kompilacji beacon):<sup>[[1]](#references)</sup>

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

Gdy operator klika Create w builderze, AdaptixC2 kompiluje zaszyfrowany profil do beacona. Nie zakładaj, że znajduje się on na końcu pliku PE lub shellcode: zlokalizuj bajty profilu, skanując sekcje lub podążając za `getProfile()` w próbce. Spakowany format wygląda następująco:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 bajty: rozmiar konfiguracji (uint32, little-endian)
- N bajtów: zaszyfrowane RC4 dane konfiguracji
- 16 bajtów: klucz RC4

Loader beacona kopiuje 16-bajtowy klucz z końca i odszyfrowuje blok N bajtów algorytmem RC4 w miejscu:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Praktyczne konsekwencje:<sup>[[1]](#references)</sup>
- Cała struktura często znajduje się w sekcji PE .rdata.
- Ekstrakcja jest deterministyczna: odczytaj rozmiar, odczytaj ciphertext o tym rozmiarze, odczytaj 16-bajtowy klucz umieszczony bezpośrednio za nim, a następnie odszyfruj RC4.

## Workflow ekstrakcji konfiguracji (obrońcy)

Ogólne informacje o triage próbki przed wyodrębnieniem beacona znajdziesz w sekcji [Malware Analysis](malware-analysis.md).

Napisz extractor naśladujący logikę beacona:<sup>[[1]](#references)</sup>
1) Zlokalizuj blob w pliku PE (zwykle w sekcji .rdata). Praktyczne podejście: przeskanuj .rdata w poszukiwaniu prawdopodobnego układu [size|ciphertext|16-byte key] i spróbuj użyć RC4.
2) Odczytaj pierwsze 4 bajty → rozmiar (uint32 LE).
3) Odczytaj następne N=size bajtów → ciphertext.
4) Odczytaj ostatnie 16 bajtów → klucz RC4.
5) Odszyfruj ciphertext za pomocą RC4. Następnie sparsuj profil w postaci jawnej:
   - skalary u32/boolean, jak opisano powyżej
   - ciągi z prefiksem długości (długość u32, po której następują bajty; może występować końcowy NUL)
   - tablice: servers_count, a następnie wskazana liczba par [string, u32 port]

Legacy HTTP proof-of-concept w Pythonie (samodzielny, bez zewnętrznych zależności) dla wcześniej wyodrębnionego bloba w kolejności pól używanej w terenie w 2025 r. W przypadku nowszych standardowych buildów użyj parsera aktualnego schematu poniżej:<sup>[[1]](#references)[[11]](#references)</sup>

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

### Parsowanie bieżących standardowych profili HTTP i DNS

Bieżąca wersja upstream najpierw zapisuje sześć wartości `u32` w formacie little-endian: watermark/type agenta, datę wyłączenia, czas działania, opóźnienie, jitter oraz watermark/type listenera. Dane specyficzne dla HTTP zaczynają się następnie od jednobajtowej flagi SSL. W przeciwieństwie do przykładu ze starszej wersji, zawierają listy URI, user-agentów i nagłówków Host z licznikami, a po nich tryb rotacji i ustawienia proxy. Dlatego starszy parser zaczyna odczytywać flagę SSL z pola daty wyłączenia i zwraca nieprawidłowe wyniki w tych wersjach. Długości ciągów i wartości liczbowe w tym profilu są zapisane w formacie little-endian; spakowane ciągi znaków mają końcowy bajt NUL, jeśli nie są puste.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

Użyj poniższego parsera z helperami `P` i `rc4` do odszyfrowanego plaintextu standardowego profilu **HTTP**. Nie umieszczaj klucza RC4 w publicznych raportach: profil HTTP może zawierać nazwę użytkownika i hasło proxy.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Parsowanie bieżącego plaintextu standardowego profilu HTTP</summary>

```python
def parse_current_http_cfg(plain: bytes) -> dict:
    p = P(plain)
    keys = ('agent_type', 'kill_date', 'working_time',
            'sleep_delay', 'jitter_delay', 'listener_type')
    cfg = {key: p.u32() for key in keys}
    cfg['use_ssl'] = bool(p.u8())
    count = p.u32()
    if not 0 < count <= 128:
        raise ValueError('implausible server count')
    cfg['servers'] = []
    cfg['ports'] = []
    for _ in range(count):
        cfg['servers'].append(p.s())
        cfg['ports'].append(p.u32())
    cfg['http_method'] = p.s()
    def strings():
        n = p.u32()
        if n > 128:
            raise ValueError('implausible string count')
        return [p.s() for _ in range(n)]
    cfg['uris'] = strings()
    cfg['parameter'] = p.s()
    cfg['user_agents'] = strings()
    cfg['http_headers'] = p.s()
    cfg['ans_pre_size'] = p.u32()
    cfg['ans_size'] = p.u32() + cfg['ans_pre_size']
    cfg['host_headers'] = strings()
    cfg['rotation_mode'] = p.u32()  # 0=sequential, 1=random
    cfg['proxy_type'] = p.u32()     # 0=none, 1=HTTP, 2=HTTPS
    cfg['proxy_host'] = p.s()
    cfg['proxy_port'] = p.u32()
    cfg['proxy_username'] = p.s()
    cfg['proxy_password'] = p.s()
    if p.o != len(plain):
        raise ValueError('unexpected trailing bytes or wrong schema')
    return cfg
```

</details>

W przypadku standardowego DNS beacon odczytaj te same sześć typowych pól `u32`, a następnie ciągi `domain`, `resolvers`, `doh_resolvers` i `qtype`, poprzedzone długością. Odczytaj `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` i `dns_mode` jako `u32`, a następnie ciąg user-agent DoH poprzedzony długością. `dns_mode` rozróżnia UDP, DoH i oba kierunki fallbacku. To osobny układ — nie przepuszczaj tekstu jawnego DNS przez parser HTTP.<sup>[[12]](#references)[[13]](#references)</sup>

Wskazówki:
- Podczas automatyzacji użyj parsera PE do odczytania .rdata, a następnie zastosuj przesuwne okno: dla każdego offsetu o spróbuj size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = następne 16 bajtów; odszyfruj RC4 i sprawdź, czy pola tekstowe dają się zdekodować jako UTF-8, a długości są sensowne.
- Parsuj profile SMB/TCP, stosując te same konwencje pól poprzedzonych długością.

## Profile niestandardowych listenerów: nie ograniczaj się na sztywno do klasycznego schematu HTTP

Zewnętrzny format pakowania (`u32 size | RC4 ciphertext | 16-byte key`) można wykorzystać ponownie, więc listenery dostosowane przez aktora mogą zachować ten sam proces ekstrakcji, zmieniając całkowicie układ odszyfrowanych pól.

Dobrym, niedawnym przykładem jest kampania Tropic Trooper z marca 2026 r., w której wyodrębniony Adaptix beacon nie zawierał standardowego profilu HTTP/TCP. Zamiast tego odszyfrowany blob przechowywał parametry transportu GitHub, takie jak:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (na przykład `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktyczna strategia parsowania:
- Najpierw wykryj zewnętrzny blob RC4 dokładnie tak jak zwykle.
- Po odszyfrowaniu wybierz odpowiednią gałąź na podstawie ciągów identyfikujących i poprawności pól, zamiast od razu wymuszać użycie parsera HTTP.
- Dobrymi ciągami identyfikującymi są `api.github.com`, `/issues?state=open`, czasowniki HTTP/URI, ciągi przypominające nazwane potoki lub oczywiście prawidłowe tablice serwerów/portów.
- Jeśli parser HTTP zawiedzie, ale tekst jawny zawiera spójne ciągi UTF-8 poprzedzone długością, zachowaj próbkę i spróbuj zastosować alternatywne schematy zamiast odrzucać ją jako fałszywy alarm.

W tej kampanii niestandardowy listener wykorzystywał GitHub issues jako transport C2, a beacon odpytywał `ipinfo.io`, aby poznać zewnętrzny adres IP, ponieważ GitHub API nie ujawnia operatorowi bezpośrednio adresu źródłowego ofiary.<sup>[[5]](#references)</sup> Informacje o osobnym uzgadnianiu połączenia z użyciem issue i pliku repozytorium znajdziesz w [GitHub Issues and Repository Files as a C2 Channel](../github-issues-and-repository-files-c2.md).

## Rozpoznawanie i wyszukiwanie śladów w sieci

HTTP:<sup>[[1]](#references)</sup>
- Typowe: POST do URI wybranych przez operatora (np. /uri.php, /endpoint/api)
- Niestandardowy parametr nagłówka używany jako identyfikator beacon (np. X‑Beacon‑Id, X‑App‑Id)
- User-agenty podszywające się pod Firefox 20 lub współczesne wersje Chrome
- Częstotliwość odpytywania widoczna w wartościach sleep_delay/jitter_delay
- Nowsze wersje mogą rotować URI, user-agenty, nagłówki Host i serwery między callbackami, dlatego grupuj na podstawie nietypowych nazw nagłówków, wzorców rozmiarów odpowiedzi, ponownego użycia TLS i czasu, zamiast zakładać stałą parę ścieżka/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listenery SMB z nazwanymi potokami do intranetowego C2, gdy ruch wychodzący przez sieć WWW jest ograniczony
- Beacony TCP mogą dodawać kilka bajtów przed ruchem, aby zaciemnić początek protokołu

Bieżące domyślne ustawienia teamserver upstream
- Plik `profile.yaml` zawiera obecnie teamserver `0.0.0.0:4321`, endpoint `/endpoint`, nazwy plików certyfikatu/klucza `server.rsa.crt` i `server.rsa.key` oraz extendery dla HTTP, SMB, TCP, DNS, agenta Beacon i Gopher.<sup>[[2]](#references)</sup>
- W przypadku niedopasowanych tras domyślny handler błędów zwraca `Server: AdaptixC2` i `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Domyślna treść odpowiedzi 404 zawiera `AdaptixC2 404` i `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Skanowanie całego Internetu w 2026 r. wykazało wiele wystawionych teamserverów na porcie `4321` i wiele listenerów beacon na porcie `43211`, dlatego oba porty są przydatnymi punktami wyjścia do dalszego wyszukiwania, ale nie należy uznawać ich za wyczerpujące.<sup>[[4]](#references)</sup>

Ślady listenerów DNS/DoH:<sup>[[4]](#references)</sup>
- Bieżący extender BeaconDNS odpowiada autorytatywnie (`AA=true`)
- Zapytania niepasujące do formatu protokołu beacon — zwłaszcza nazwy zawierające mniej niż 5 etykiet przed skonfigurowaną domeną — zwykle otrzymują odpowiedź `TXT "OK"`
- Jeśli podstawowy TTL pozostawiono na zero, listener używa wartości bazowej 10 sekund i dodaje do 59 sekund jittera
- Dzięki temu aktywne sondy z krótkimi etykietami są przydatne, gdy nie jest wystawiony listener HTTP

## TTP loaderów i mechanizmy utrwalania zaobserwowane w incydentach

Loadery PowerShell działające w pamięci:<sup>[[1]](#references)</sup>
- Pobierają payloady Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Przydzielają pamięć niezarządzaną, kopiują shellcode i zmieniają jej ochronę na 0x40 (PAGE_EXECUTE_READWRITE) za pomocą VirtualProtect.<sup>[[7]](#references)</sup>
- Wykonują kod przez dynamiczne wywołanie .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Podpisane, zmodyfikowane trojaniem oprogramowanie / wieloetapowe loadery shellcode:<sup>[[5]](#references)</sup>
- W łańcuchu ataku Tropic Trooper z 2026 r. użyto zmodyfikowanego trojanem pliku wykonywalnego SumatraPDF (loadera TOSHIS), który przekierowywał `_security_init_cookie` do złośliwego kodu zamiast modyfikować punkt wejścia PE
- Loader rozwiązywał API za pomocą haszowania Adler-32, pobierał plik PDF-wabik, pobierał shellcode drugiego etapu, odszyfrowywał go za pomocą AES-128-CBC przez WinCrypt (`CryptDeriveKey` z użyciem zakodowanego na stałe ziarna) i refleksyjnie wykonywał Adaptix beacon w pamięci
- Później mechanizm utrwalania przeniesiono do zaplanowanych zadań o pozornie nieszkodliwych nazwach, takich jak `\MSDNSvc` lub `\MicrosoftUDN`, skonfigurowanych tak, by ponownie uruchamiać agenta mniej więcej co dwie godziny

Informacje o wykonywaniu kodu w pamięci oraz zagadnieniach związanych z AMSI/ETW znajdziesz na tych stronach:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Zaobserwowane mechanizmy utrwalania:<sup>[[1]](#references)</sup>
- Skrót (.lnk) w folderze Autostart uruchamiający loader ponownie przy logowaniu
- Klucze Run rejestru (HKCU/HKLM ...\CurrentVersion\Run), często z pozornie nieszkodliwymi nazwami, takimi jak "Updater", uruchamiające loader.ps1.<sup>[[10]](#references)</sup>
- Przejęcie kolejności wyszukiwania DLL przez umieszczenie pliku msimg32.dll w %APPDATA%\Microsoft\Windows\Templates dla podatnych procesów

Szczegółowe omówienia technik i kontrole:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Pomysły na wyszukiwanie śladów
- Przejścia PowerShell z RW→RX: VirtualProtect ustawiający PAGE_EXECUTE_READWRITE w procesie powershell.exe.<sup>[[8]](#references)</sup>
- Wzorce dynamicznego wywoływania (GetDelegateForFunctionPointer)
- Niedopasowane odpowiedzi HTTPS 404 zawierające `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` lub `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Odpowiedzi DNS z `AA=true` i `TXT "OK"` na krótkie zapytania w podejrzanych domenach.<sup>[[4]](#references)</sup>
- Ruch do GitHub API pod adresem `/repos/<owner>/<repo>/issues`, po którym następują zapytania do `ipinfo.io` z tego samego łańcucha loadera/beacon.<sup>[[5]](#references)</sup>
- Skróty .lnk w folderach Autostart użytkownika lub wspólnych folderach Autostart.<sup>[[1]](#references)</sup>
- Podejrzane klucze Run (np. "Updater") oraz nazwy loaderów, takie jak update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Próbki PE zmodyfikowane trojanem, które przekierowują `_security_init_cookie` do kodu pobierającego przed wyświetleniem dokumentu-wabika.<sup>[[5]](#references)</sup>
- Zapisywalne przez użytkownika ścieżki DLL w %APPDATA%\Microsoft\Windows\Templates zawierające msimg32.dll.<sup>[[1]](#references)</sup>

## Uwagi dotyczące pól OpSec

- KillDate: znacznik czasu, po którym agent sam się dezaktywuje.<sup>[[1]](#references)</sup>
- WorkingTime: godziny, w których agent powinien być aktywny, aby upodobnić się do aktywności biznesowej.<sup>[[1]](#references)</sup>

Tych pól można używać do grupowania oraz wyjaśniania zaobserwowanych okresów ciszy.

## YARA i wskazówki do analizy statycznej

Unit 42 opublikował podstawowe reguły YARA dla beaconów (C/C++ i Go) oraz stałych używanych do haszowania API w loaderach.<sup>[[1]](#references)</sup> Warto uzupełnić je o reguły wyszukujące układ [size|ciphertext|16-byte-key] w pobliżu końca PE .rdata, domyślne ciągi profilu HTTP oraz nowsze znaczniki serwera/listenera, takie jak `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` i `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: Nowy framework open source wykorzystywany w rzeczywistych atakach (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Dokumentacja Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Masowe rozpoznawanie open source'owego frameworka C2 (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper przechodzi na AdaptixC2 i niestandardowy listener Beacon (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – dokumentacja Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – dokumentacja Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Stałe ochrony pamięci – dokumentacja Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Klucze Run rejestru/Folder Autostart](https://attack.mitre.org/techniques/T1547/001/)
- [11] [Generowanie profilu AdaptixC2 (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [Parser profilu beacon AdaptixC2 (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [Generowanie profilu DNS AdaptixC2 (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [Pakowanie profilu AdaptixC2 (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
