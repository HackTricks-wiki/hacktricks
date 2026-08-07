# Bezpieczeństwo macOS i eskalacja uprawnień

{{#include ../../banners/hacktricks-training.md}}

## Podstawy MacOS

Jeśli nie znasz macOS, zacznij od nauki podstaw macOS:

- Specjalne **pliki i uprawnienia** macOS:


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- Typowi **użytkownicy** macOS


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- **Architektura** jądra


{{#ref}}
mac-os-architecture/
{{#endref}}

- Typowe **usługi i protokoły sieciowe** macOS


{{#ref}}
macos-protocols.md
{{#endref}}

- macOS **Opensource**: [https://opensource.apple.com/](https://opensource.apple.com/)
- Aby pobrać `tar.gz`, zmień URL, taki jak [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/), na [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

W firmach systemy **macOS** będą najprawdopodobniej **zarządzane za pomocą MDM**. Dlatego z perspektywy atakującego warto wiedzieć, **jak to działa**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS — inspekcja, debugowanie i fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Mechanizmy ochrony macOS


{{#ref}}
macos-security-protections/
{{#endref}}

## Powierzchnia ataku

### Uprawnienia plików

Jeśli **proces działający jako root zapisuje** plik, nad którym użytkownik ma kontrolę, użytkownik może wykorzystać to do **eskalacji uprawnień**.\
Może się to zdarzyć w następujących sytuacjach:

- Używany plik został już utworzony przez użytkownika (jest własnością użytkownika)
- Użytkownik może zapisywać w używanym pliku za pośrednictwem grupy
- Używany plik znajduje się w katalogu należącym do użytkownika (użytkownik może utworzyć plik)
- Używany plik znajduje się w katalogu należącym do root, ale użytkownik ma do niego dostęp zapisu za pośrednictwem grupy (użytkownik może utworzyć plik)

Możliwość **utworzenia pliku**, który będzie **używany przez root**, pozwala użytkownikowi **wykorzystać jego zawartość**, a nawet utworzyć **symlinki/hardlinki**, aby wskazywały inne miejsce.

W przypadku tego rodzaju podatności nie zapomnij **sprawdzić podatnych instalatorów `.pkg`**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Handlery rozszerzeń plików i schematów URL

Dziwne aplikacje zarejestrowane dla rozszerzeń plików mogą zostać wykorzystane, a różne aplikacje mogą być rejestrowane do otwierania określonych protokołów


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## Eskalacja uprawnień macOS TCC / SIP

W macOS **aplikacje i pliki binarne mogą mieć uprawnienia** do uzyskiwania dostępu do folderów lub ustawień, dzięki czemu są bardziej uprzywilejowane niż inne.

Dlatego atakujący, który chce skutecznie przejąć maszynę macOS, będzie musiał **eskalować swoje uprawnienia TCC** (lub nawet **ominąć SIP**, zależnie od swoich potrzeb).

Uprawnienia te są zwykle przyznawane w postaci **entitlements**, z którymi aplikacja jest podpisana, lub aplikacja może zażądać określonych dostępów, a po ich **zatwierdzeniu przez użytkownika** można je znaleźć w **bazach danych TCC**. Innym sposobem uzyskania tych uprawnień przez proces jest bycie **procesem potomnym procesu** posiadającego te **uprawnienia**, ponieważ są one zwykle **dziedziczone**.<sup>[[5]](#references)</sup>

Skorzystaj z poniższych odnośników, aby poznać różne sposoby [**eskalacji uprawnień w TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), [**ominięcia TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) oraz dowiedzieć się, jak w przeszłości [**omijano SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Tradycyjna eskalacja uprawnień w macOS

Oczywiście z perspektywy red teams interesująca będzie również eskalacja do root. W poniższym artykule znajdziesz kilka wskazówek:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## Zgodność macOS

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Materiały referencyjne

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
