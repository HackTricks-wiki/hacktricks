# Bezpieczeństwo macOS i eskalacja uprawnień

{{#include ../../banners/hacktricks-training.md}}

## Podstawy MacOS

Jeśli nie znasz macOS, powinieneś zacząć od nauki podstaw macOS:

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

- **Architektura** j**ądra**


{{#ref}}
mac-os-architecture/
{{#endref}}

- Typowe **usługi sieciowe i protokoły** macOS


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Aby pobrać `tar.gz`, zmień URL, taki jak [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) na [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

W firmach systemy **macOS** będą najprawdopodobniej **zarządzane za pomocą MDM**. Dlatego z perspektywy atakującego warto wiedzieć, **jak to działa**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspekcja, debugowanie i fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Mechanizmy ochrony macOS


{{#ref}}
macos-security-protections/
{{#endref}}

## Powierzchnia ataku

### Uprawnienia plików

Jeśli **proces działający jako root zapisuje** plik, który może być kontrolowany przez użytkownika, użytkownik może wykorzystać to do **eskalacji uprawnień**.\
Może to wystąpić w następujących sytuacjach:

- Używany plik został już utworzony przez użytkownika (jest własnością użytkownika)
- Używany plik jest zapisywalny przez użytkownika za pośrednictwem grupy
- Używany plik znajduje się wewnątrz katalogu należącego do użytkownika (użytkownik może utworzyć plik)
- Używany plik znajduje się wewnątrz katalogu należącego do root, ale użytkownik ma do niego dostęp z prawem zapisu za pośrednictwem grupy (użytkownik może utworzyć plik)

Możliwość **utworzenia pliku**, który będzie **używany przez root**, pozwala użytkownikowi **wykorzystać jego zawartość** lub nawet utworzyć **symlinki/hardlinki**, aby wskazywały inne miejsce.

W przypadku tego rodzaju podatności nie zapomnij **sprawdzić podatnych installerów `.pkg`**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Handlery rozszerzeń plików i schematów URL

Nietypowe aplikacje zarejestrowane dla rozszerzeń plików mogą być wykorzystywane, a różne aplikacje mogą być rejestrowane do otwierania określonych protokołów


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / eskalacja uprawnień SIP

W macOS **aplikacje i pliki binarne mogą mieć uprawnienia** do uzyskiwania dostępu do folderów lub ustawień, które czynią je bardziej uprzywilejowanymi od innych.

Dlatego atakujący, który chce skutecznie skompromitować maszynę z macOS, będzie musiał **eskalować swoje uprawnienia TCC** (lub nawet **ominąć SIP**, zależnie od potrzeb).

Uprawnienia te są zwykle nadawane w postaci **entitlements**, z którymi podpisana jest aplikacja, albo aplikacja może zażądać określonych dostępów, które po **zatwierdzeniu przez użytkownika** można znaleźć w **bazach danych TCC**. Innym sposobem uzyskania tych uprawnień przez proces jest bycie **procesem potomnym procesu** posiadającego te **uprawnienia**, ponieważ są one zwykle **dziedziczone**.

Skorzystaj z tych odnośników, aby znaleźć różne sposoby na [**eskalację uprawnień w TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), [**ominięcie TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) oraz informacje o tym, jak w przeszłości [**omijano SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Tradycyjna eskalacja uprawnień w macOS

Oczywiście z perspektywy red teams powinieneś również interesować się eskalacją do root. Sprawdź poniższy wpis, aby znaleźć wskazówki:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## Zgodność macOS

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Odnośniki

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
