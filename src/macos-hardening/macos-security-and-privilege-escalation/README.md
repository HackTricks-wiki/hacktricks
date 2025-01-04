# macOS Security & Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic MacOS

Jeśli nie znasz macOS, powinieneś zacząć od nauki podstaw macOS:

- Specjalne **pliki i uprawnienia** macOS:

{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- Powszechni **użytkownicy** macOS

{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**

{{#ref}}
macos-applefs.md
{{#endref}}

- **architektura** jądra

{{#ref}}
mac-os-architecture/
{{#endref}}

- Powszechne **usługi i protokoły sieciowe** macOS

{{#ref}}
macos-protocols.md
{{#endref}}

- **Oprogramowanie open source** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Aby pobrać `tar.gz`, zmień adres URL, na przykład [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) na [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

W firmach systemy **macOS** będą prawdopodobnie **zarządzane przez MDM**. Dlatego z perspektywy atakującego interesujące jest, **jak to działa**:

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspekcja, Debugowanie i Fuzzing

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS Security Protections

{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### Uprawnienia plików

Jeśli **proces działający jako root zapisuje** plik, który może być kontrolowany przez użytkownika, użytkownik może to wykorzystać do **eskalacji uprawnień**.\
Może to wystąpić w następujących sytuacjach:

- Plik użyty został już utworzony przez użytkownika (należy do użytkownika)
- Plik użyty jest zapisywalny przez użytkownika z powodu grupy
- Plik użyty znajduje się w katalogu należącym do użytkownika (użytkownik mógłby utworzyć plik)
- Plik użyty znajduje się w katalogu należącym do roota, ale użytkownik ma do niego dostęp do zapisu z powodu grupy (użytkownik mógłby utworzyć plik)

Możliwość **utworzenia pliku**, który będzie **używany przez roota**, pozwala użytkownikowi **wykorzystać jego zawartość** lub nawet utworzyć **symlinki/twarde linki**, aby wskazać go w inne miejsce.

W przypadku tego rodzaju luk nie zapomnij **sprawdzić podatnych instalatorów `.pkg`**:

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Obsługa rozszerzeń plików i schematów URL

Dziwne aplikacje zarejestrowane przez rozszerzenia plików mogą być wykorzystywane, a różne aplikacje mogą być zarejestrowane do otwierania określonych protokołów

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

W macOS **aplikacje i pliki binarne mogą mieć uprawnienia** do dostępu do folderów lub ustawień, które czynią je bardziej uprzywilejowanymi niż inne.

Dlatego atakujący, który chce skutecznie skompromitować maszynę macOS, będzie musiał **eskalować swoje uprawnienia TCC** (lub nawet **obejść SIP**, w zależności od jego potrzeb).

Te uprawnienia są zazwyczaj nadawane w formie **uprawnień**, z którymi aplikacja jest podpisana, lub aplikacja może poprosić o pewne dostępy, a po **zatwierdzeniu ich przez użytkownika** mogą być one znalezione w **bazach danych TCC**. Innym sposobem, w jaki proces może uzyskać te uprawnienia, jest bycie **dzieckiem procesu** z tymi **uprawnieniami**, ponieważ są one zazwyczaj **dziedziczone**.

Śledź te linki, aby znaleźć różne sposoby [**eskalacji uprawnień w TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), aby [**obejść TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) i jak w przeszłości [**SIP został obejrzany**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Traditional Privilege Escalation

Oczywiście z perspektywy zespołu red team również powinieneś być zainteresowany eskalacją do roota. Sprawdź następujący post, aby uzyskać kilka wskazówek:

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS Compliance

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## References

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
