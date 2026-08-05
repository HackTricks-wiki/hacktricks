# Bypasses Sandbox macOS Office

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

Aplikacja używa **custom Sandbox** z wykorzystaniem entitlementu **`com.apple.security.temporary-exception.sbpl`**, a ten custom sandbox pozwala zapisywać pliki w dowolnym miejscu, o ile nazwa pliku zaczyna się od `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Dlatego obejście zabezpieczeń było tak proste, jak **zapisanie pliku `plist`** LaunchAgent w `~/Library/LaunchAgents/~$escape.plist`.

Sprawdź [**oryginalny raport tutaj**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass via Login Items and zip

Pamiętaj, że po pierwszym obejściu Word może zapisywać dowolne pliki, których nazwa zaczyna się od `~$`, chociaż po załataniu poprzedniej luki nie można było zapisywać w `/Library/Application Scripts` ani w `/Library/LaunchAgents`.

Odkryto, że z poziomu sandbox można utworzyć **Login Item** (aplikacje, które są uruchamiane po zalogowaniu użytkownika). Jednak te aplikacje **nie zostaną uruchomione, chyba że** będą **notarized**, a także **nie można dodawać argumentów** (więc nie można po prostu uruchomić reverse shell za pomocą **`bash`**).

W ramach poprzedniego Sandbox bypass Microsoft wyłączył możliwość zapisywania plików w `~/Library/LaunchAgents`. Odkryto jednak, że jeśli umieścisz **plik zip jako Login Item**, `Archive Utility` po prostu go **rozpakowuje** w jego bieżącej lokalizacji. Ponieważ domyślnie folder `LaunchAgents` w `~/Library` nie jest utworzony, możliwe było **spakowanie pliku plist do `LaunchAgents/~$escape.plist`** i **umieszczenie** pliku zip w **`~/Library`**, aby po rozpakowaniu trafił do miejsca persistence.

Sprawdź [**oryginalny raport tutaj**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass via Login Items and .zshenv

(Pamiętaj, że po pierwszym obejściu Word może zapisywać dowolne pliki, których nazwa zaczyna się od `~$`).

Poprzednia technika miała jednak ograniczenie: jeśli folder **`~/Library/LaunchAgents`** istniał, ponieważ utworzyło go inne oprogramowanie, technika kończyła się niepowodzeniem. Dlatego odkryto dla tego przypadku inny łańcuch Login Items.

Atakujący mógł utworzyć pliki **`.bash_profile`** i **`.zshenv`** z payloadem do wykonania, a następnie spakować je i **zapisać plik zip w folderze użytkownika ofiary**: **`~/~$escape.zip`**.

Następnie należało dodać plik zip do **Login Items**, a potem aplikację **`Terminal`**. Gdy użytkownik zaloguje się ponownie, plik zip zostanie rozpakowany w folderze użytkownika, nadpisując **`.bash_profile`** i **`.zshenv`**, dzięki czemu terminal wykona jeden z tych plików (zależnie od tego, czy używany jest bash, czy zsh).

Sprawdź [**oryginalny raport tutaj**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open and env variables

Z procesów działających w sandbox nadal można wywoływać inne procesy za pomocą utility **`open`**. Ponadto procesy te będą działać **we własnym sandbox**.

Odkryto, że utility open ma opcję **`--env`**, która uruchamia aplikację z **określonymi** zmiennymi środowiskowymi. Możliwe było więc utworzenie pliku **`.zshenv`** wewnątrz folderu znajdującego się **w** **sandbox**, a następnie użycie `open` z `--env` i ustawieniem zmiennej **`HOME`** na ten folder podczas otwierania aplikacji `Terminal`, która wykona plik `.zshenv` (z jakiegoś powodu konieczne było również ustawienie zmiennej `__OSINSTALL_ENVIROMENT`).

Sprawdź [**oryginalny raport tutaj**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open and stdin

Utility **`open`** obsługiwało również parametr **`--stdin`** (po poprzednim bypass nie można już było używać `--env`).

Chodzi o to, że nawet jeśli **`python`** był podpisany przez Apple, **nie wykona** skryptu z atrybutem **`quarantine`**. Możliwe było jednak przekazanie mu skryptu przez stdin, dzięki czemu nie sprawdzał, czy plik był poddany kwarantannie:

1. Upuść plik **`~$exploit.py`** zawierający dowolne polecenia Python.
2. Uruchom _open_ **`–stdin='~$exploit.py' -a Python`**, co uruchamia aplikację Python, używając upuszczonego pliku jako standardowego wejścia. Python bez problemu wykona nasz kod, a ponieważ jest procesem potomnym _launchd_, nie podlega regułom sandbox Worda.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
