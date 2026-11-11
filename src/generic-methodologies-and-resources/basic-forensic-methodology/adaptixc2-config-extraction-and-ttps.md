# AdaptixC2 Configuration Extraction and TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 to modułowy, open-source’owy framework post-exploitation/C2 z beaconami Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) i obsługą BOF.<sup>[[1]](#references)</sup> Ta strona opisuje:
- Sposób osadzania konfiguracji spakowanej za pomocą RC4 oraz jej ekstrakcji z beaconów
- Wskaźniki sieciowe/profile dla listenerów HTTP/SMB/TCP
- Typowe TTPs loaderów i mechanizmów persistence zaobserwowane w środowisku rzeczywistym, z linkami do odpowiednich stron o technikach Windows

Najnowsze wydania upstream zawierają również listenery beaconów DNS/DoH oraz osobną rodzinę agentów/listenerów Gopher, dlatego nowoczesna infrastruktura Adaptix może udostępniać więcej niż tylko pierwotne powierzchnie HTTP/SMB/TCP, nawet gdy konkretny sample nadal używa klasycznego agenta beacon.<sup>[[2]](#references)</sup>

## Profile beaconów i pola

AdaptixC2 obsługuje trzy podstawowe typy beaconów:<sup>[[1]](#references)</sup>
- BEACON_HTTP: webowe C2 z konfigurowalnymi serwerami/portami/SSL, metodą, URI, nagłówkami, user-agentem i własną nazwą parametru
- BEACON_SMB: komunikacja peer-to-peer przez nazwane potoki (intranet)
- BEACON_TCP: bezpośrednie połączenia socket, opcjonalnie z poprzedzającym znacznikiem, który zaciemnia początek protokołu

Są to układy beaconów udokumentowane publicznie we wczesnych analizach Adaptix i nadal stanowią najczęstszy punkt wyjścia do ekstrakcji po stronie sample.<sup>[[1]](#references)</sup> Jednak obecne buildy upstream zawierają również rozszerzenia `BeaconDNS` i Gopher po stronie serwera, więc nie należy zakładać, że każda działająca infrastruktura Adaptix udostępnia wyłącznie HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Poniższe podsumowanie pól i przykłady JSON opisują format HTTP analizowany w 2025 roku; nie stanowią specyfikacji parsera dla nowszych buildów upstream. Typowe pola w tych samplach (po odszyfrowaniu):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – używane do parsowania rozmiarów odpowiedzi
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Najnowsze buildy BeaconHTTP obsługują również wybraną przez operatora rotację wielu URI, user-agentów, nagłówków Host i serwerów, z wyborem sekwencyjnym lub losowym.<sup>[[2]](#references)</sup> Z perspektywy threat huntingu oznacza to, że pojedynczy zainfekowany host może korzystać z wielu ścieżek callback i kombinacji nagłówków, nie opuszczając klasycznej rodziny beaconów spakowanych za pomocą RC4.

Przykładowy domyślny profil HTTP (z buildu beacon):<sup>[[1]](#references)</sup>

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

Gdy operator klika Create w builderze, AdaptixC2 kompiluje zaszyfrowany profil do beacona. Nie zakładaj, że znajduje się on na końcu PE lub shellcode: znajdź bajty profilu, skanując sekcje lub śledząc `getProfile()` w próbce. Spakowany format wygląda następująco:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 bajty: rozmiar konfiguracji (uint32, little‑endian)
- N bajtów: dane konfiguracji zaszyfrowane RC4
- 16 bajtów: klucz RC4

Loader beacona kopiuje 16-bajtowy klucz z końca i odszyfrowuje blok N bajtów za pomocą RC4, bezpośrednio w miejscu jego przechowywania:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Praktyczne implikacje:<sup>[[1]](#references)</sup>
- Cała struktura często znajduje się w sekcji PE .rdata.
- Ekstrakcja jest deterministyczna: odczytaj rozmiar, odczytaj szyfrogram o tym rozmiarze, odczytaj 16-bajtowy klucz umieszczony bezpośrednio za nim, a następnie odszyfruj RC4.

## Przepływ pracy ekstrakcji konfiguracji (obrońcy)

Ogólne informacje o triage próbki przed wyodrębnieniem beacona znajdziesz w sekcji [Analiza malware](malware-analysis.md).

Napisz extractor naśladujący logikę beacona:<sup>[[1]](#references)</sup>
1) Zlokalizuj blob w pliku PE (zwykle w .rdata). Praktyczne podejście to skanowanie .rdata w poszukiwaniu prawdopodobnego układu [rozmiar|szyfrogram|16-bajtowy klucz] i próba odszyfrowania RC4.
2) Odczytaj pierwsze 4 bajty → rozmiar (uint32 LE).
3) Odczytaj kolejne N=size bajtów → szyfrogram.
4) Odczytaj ostatnie 16 bajtów → klucz RC4.
5) Odszyfruj szyfrogram RC4. Następnie sparsuj profil w postaci jawnej:
   - wartości skalarne u32/boolean, jak opisano powyżej
   - ciągi znaków z prefiksem długości (długość u32, a po niej bajty; może występować końcowy NUL)
   - tablice: servers_count, a po nim odpowiednia liczba par [ciąg znaków, port u32]

Legacy HTTP Python proof-of-concept (samodzielny, bez zewnętrznych zależności) dla wcześniej wyodrębnionego bloba w kolejności pól z 2025 r. W przypadku nowszych stock buildów użyj poniższego parsera current-schema:<sup>[[1]](#references)[[11]](#references)</sup>

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

### Parsowanie aktualnych domyślnych profili HTTP i DNS

Bieżąca wersja upstream najpierw zapisuje sześć wartości `u32` w porządku little-endian: znacznik/typ agenta, datę wyłączenia, czas działania, interwał uśpienia, jitter i znacznik/typ listenera. Dane specyficzne dla HTTP zaczynają się następnie od jednobajtowej flagi SSL. W przeciwieństwie do przykładu legacy zawierają listy URI, user-agentów i nagłówków Host z liczbą elementów, a po nich tryb rotacji i ustawienia proxy. Dlatego parser legacy zaczyna odczytywać flagę SSL od pola daty wyłączenia i zwraca nieprawidłowe wyniki dla tych wersji. Długości ciągów i wartości całkowite w tym profilu są zakodowane w porządku little-endian; spakowane ciągi mają końcowy bajt NUL, jeśli nie są puste.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

Korzystając z opisanych wyżej helperów `P` i `rc4`, użyj tego parsera na odszyfrowanym plaintextcie **domyślnego profilu HTTP**. Nie ujawniaj klucza RC4 w publicznych raportach: profil HTTP może zawierać nazwę użytkownika i hasło proxy.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Parsowanie plaintextu aktualnego domyślnego profilu HTTP</summary>

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

W przypadku standardowego DNS beacon odczytaj te same sześć wspólnych pól `u32`, a następnie ciągi `domain`, `resolvers`, `doh_resolvers` i `qtype` poprzedzone długością. Odczytaj `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` i `dns_mode` jako `u32`, a potem ciąg user-agent DoH poprzedzony długością. `dns_mode` rozróżnia UDP, DoH i dwa kierunki fallbacku. To osobny układ — nie przepuszczaj plaintextu DNS przez parser HTTP.<sup>[[12]](#references)[[13]](#references)</sup>

Wskazówki:
- Przy automatyzacji użyj parsera PE, aby odczytać .rdata, a następnie zastosuj przesuwane okno: dla każdego offsetu o spróbuj size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = kolejne 16 bajtów; odszyfruj RC4 i sprawdź, czy pola tekstowe dekodują się jako UTF-8, a długości są prawidłowe.
- Parsuj profile SMB/TCP, stosując te same konwencje pól poprzedzonych długością.

## Niestandardowe profile listenerów: nie ograniczaj się na sztywno do klasycznego schematu HTTP

Zewnętrzny format pakowania (`u32 size | RC4 ciphertext | 16-byte key`) można ponownie wykorzystać, więc listenery dostosowane przez aktora mogą zachować ten sam przepływ ekstrakcji, a jednocześnie całkowicie zmienić układ odszyfrowanych pól.

Dobrym, niedawnym przykładem jest kampania Tropic Trooper z marca 2026 r., w której wyodrębniony Adaptix beacon nie zawierał standardowego profilu HTTP/TCP. Zamiast tego odszyfrowany blob przechowywał parametry transportu GitHub, takie jak:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (na przykład `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktyczna strategia parsowania:
- Najpierw wykryj zewnętrzny blob RC4 w zwykły sposób.
- Po odszyfrowaniu wybierz schemat na podstawie ciągów znacznikowych i poprawności pól, zamiast od razu wymuszać użycie parsera HTTP.
- Dobrymi ciągami znacznikowymi są `api.github.com`, `/issues?state=open`, czasowniki HTTP/URI, ciągi w stylu nazwanych potoków lub wyraźnie poprawne tablice serwerów/portów.
- Jeśli parser HTTP zawiedzie, ale plaintext zawiera spójne ciągi UTF-8 poprzedzone długością, zachowaj próbkę i sprawdź alternatywne schematy, zamiast odrzucać ją jako fałszywy wynik.

W tej kampanii niestandardowy listener używał GitHub issues jako transportu C2, a beacon odpytował `ipinfo.io`, aby poznać zewnętrzny adres IP, ponieważ GitHub API nie ujawnia operatorowi bezpośrednio źródłowego adresu ofiary.<sup>[[5]](#references)</sup>

## Rozpoznawanie odcisków sieciowych i hunting

HTTP:<sup>[[1]](#references)</sup>
- Typowe: POST do URI wybranych przez operatora (np. /uri.php, /endpoint/api)
- Niestandardowy parametr nagłówka używany jako beacon ID (np. X‑Beacon‑Id, X‑App‑Id)
- User-agenty podszywające się pod Firefox 20 lub współczesne wersje Chrome
- Częstotliwość odpytywania widoczna przez sleep_delay/jitter_delay
- Nowsze kompilacje mogą rotować URI, user-agenty, nagłówki Host i serwery między callbackami, dlatego grupuj je na podstawie nietypowych nazw nagłówków, wzorców rozmiaru odpowiedzi, ponownego użycia TLS i czasu, zamiast zakładać pojedynczą parę ścieżka/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listenery SMB z nazwanymi potokami na potrzeby intranetowego C2, gdy ruch wychodzący przez web jest ograniczony
- Beacony TCP mogą dodawać kilka bajtów przed ruchem, aby zaciemnić początek protokołu

### Bieżące domyślne ustawienia upstream teamservera
- `profile.yaml` zawiera obecnie teamserver `0.0.0.0:4321`, endpoint `/endpoint`, nazwy plików certyfikatu/klucza `server.rsa.crt` i `server.rsa.key` oraz rozszerzenia dla HTTP, SMB, TCP, DNS, agenta Beacon i Gopher.<sup>[[2]](#references)</sup>
- W przypadku niedopasowanych tras domyślny handler błędów zwraca `Server: AdaptixC2` i `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Domyślne ciało odpowiedzi 404 zawiera `AdaptixC2 404` i `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Skanowanie całego Internetu w 2026 r. wykryło wiele dostępnych z zewnątrz teamserverów na porcie `4321` i wiele beacon listenerów na porcie `43211`, dlatego oba porty są przydatnymi punktami wyjścia do dalszego wyszukiwania, ale nie należy traktować ich jako wyczerpującej listy.<sup>[[4]](#references)</sup>

Odciski listenerów DNS/DoH:<sup>[[4]](#references)</sup>
- Bieżące rozszerzenie BeaconDNS odpowiada autorytatywnie (`AA=true`)
- Zapytania, które nie pasują do formatu protokołu beacon — w szczególności nazwy z mniej niż 5 etykietami przed skonfigurowaną domeną — często otrzymują odpowiedź `TXT "OK"`
- Jeśli podstawowy TTL pozostawiono na poziomie zero, listener używa wartości bazowej 10 sekund i dodaje jitter do 59 sekund
- Dzięki temu aktywne sondy z krótkimi etykietami są przydatne, gdy nie jest wystawiony listener HTTP

## TTP loaderów i utrzymywania dostępu zaobserwowane w incydentach

Loadery PowerShell działające w pamięci:<sup>[[1]](#references)</sup>
- Pobierają payloady Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Alokują pamięć niezarządzaną, kopiują shellcode i zmieniają jej ochronę na 0x40 (PAGE_EXECUTE_READWRITE) za pomocą VirtualProtect.<sup>[[7]](#references)</sup>
- Wykonują kod przez dynamiczne wywołanie .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanyzowane podpisane oprogramowanie / etapowane loadery shellcode:<sup>[[5]](#references)</sup>
- W 2026 r. łańcuch Tropic Trooper używał trojanyzowanego pliku wykonywalnego SumatraPDF (loader TOSHIS), który przekierowywał `_security_init_cookie` do złośliwego kodu zamiast modyfikować punkt wejścia PE
- Loader rozwiązywał API za pomocą haszowania Adler-32, pobierał przynętę w postaci pliku PDF, pobierał shellcode drugiego etapu, odszyfrowywał go algorytmem AES-128-CBC przez WinCrypt (`CryptDeriveKey` na podstawie zakodowanego na stałe ziarna), a następnie refleksyjnie wykonywał w pamięci Adaptix beacon
- Później utrzymywanie dostępu przeniesiono do zaplanowanych zadań o niewinnie wyglądających nazwach, takich jak `\MSDNSvc` lub `\MicrosoftUDN`, skonfigurowanych tak, aby ponownie uruchamiały agenta mniej więcej co dwie godziny

Sprawdź te strony, aby zapoznać się z wykonywaniem w pamięci oraz kwestiami AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Zaobserwowane mechanizmy utrzymywania dostępu:<sup>[[1]](#references)</sup>
- Skrót (.lnk) w folderze Autostart, ponownie uruchamiający loader przy logowaniu
- Klucze Run w rejestrze (HKCU/HKLM ...\CurrentVersion\Run), często o niewinnie brzmiących nazwach, takich jak "Updater", uruchamiające loader.ps1.<sup>[[10]](#references)</sup>
- Hijacking kolejności wyszukiwania DLL przez umieszczenie msimg32.dll w %APPDATA%\Microsoft\Windows\Templates dla podatnych procesów

Szczegółowe omówienia technik i kontrole:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Pomysły na hunting
- Procesy PowerShell wykonujące przejścia RW→RX: VirtualProtect zmieniający ochronę pamięci na PAGE_EXECUTE_READWRITE wewnątrz powershell.exe.<sup>[[8]](#references)</sup>
- Wzorce dynamicznego wywoływania (GetDelegateForFunctionPointer)
- Niedopasowane odpowiedzi HTTPS 404 zawierające `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` lub `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Odpowiedzi DNS z `AA=true` i `TXT "OK"` na krótkie zapytania w podejrzanych domenach.<sup>[[4]](#references)</sup>
- Ruch GitHub API do `/repos/<owner>/<repo>/issues`, po którym następują zapytania do `ipinfo.io` z tego samego łańcucha loadera/beacon.<sup>[[5]](#references)</sup>
- Plik .lnk w folderze Autostart użytkownika lub wspólnym folderze Autostart.<sup>[[1]](#references)</sup>
- Podejrzane klucze Run (np. "Updater") oraz nazwy loaderów, takie jak update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanyzowane próbki PE przekierowujące `_security_init_cookie` do kodu pobierającego przed wyświetleniem dokumentu-przynęty.<sup>[[5]](#references)</sup>
- Zapisywalne przez użytkownika ścieżki DLL w %APPDATA%\Microsoft\Windows\Templates zawierające msimg32.dll.<sup>[[1]](#references)</sup>

## Uwagi dotyczące pól OpSec

- KillDate: znacznik czasu, po którym agent sam się dezaktywuje.<sup>[[1]](#references)</sup>
- WorkingTime: godziny, w których agent powinien być aktywny, aby wtapiać się w typową aktywność biznesową.<sup>[[1]](#references)</sup>

Pola te można wykorzystać do grupowania i wyjaśniania zaobserwowanych okresów ciszy.

## YARA i wskazówki do analizy statycznej

Unit 42 opublikował podstawowe reguły YARA dla beaconów (C/C++ i Go) oraz stałych haszowania API używanych przez loadery.<sup>[[1]](#references)</sup> Warto uzupełnić je o reguły wyszukujące układ [size|ciphertext|16-byte-key] w pobliżu końca PE .rdata, domyślne ciągi profilu HTTP oraz nowsze znaczniki serwera/listenera, takie jak `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` i `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: Nowy framework open source wykorzystywany w rzeczywistych atakach (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Dokumentacja Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Rozpoznawanie odcisków frameworka C2 open source na dużą skalę (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper przechodzi na AdaptixC2 i niestandardowy Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – dokumentacja Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – dokumentacja Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Stałe ochrony pamięci – dokumentacja Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – klucze Run w rejestrze/folder Autostart](https://attack.mitre.org/techniques/T1547/001/)
- [11] [Generowanie profilu AdaptixC2 (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [Parser profilu AdaptixC2 beacon (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [Generowanie profilu DNS AdaptixC2 (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [Pakowanie profilu AdaptixC2 (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
{{#include ../../banners/hacktricks-training.md}}
