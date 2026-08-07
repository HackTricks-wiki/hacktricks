# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Ominięcie Sandbox Worda przez Launch Agents

Aplikacja używa **custom Sandbox** za pomocą entitlementu **`com.apple.security.temporary-exception.sbpl`**, a ten custom sandbox pozwala zapisywać pliki w dowolnym miejscu, o ile nazwa pliku zaczyna się od `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Dlatego escape był tak prosty, jak **zapisanie `plist`** LaunchAgent w `~/Library/LaunchAgents/~$escape.plist`.

Sprawdź [**oryginalny raport tutaj**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Ominięcie Sandbox Worda przez Login Items i zip

Pamiętaj, że po pierwszym escape Word może zapisywać dowolne pliki, których nazwa zaczyna się od `~$`, chociaż po załataniu poprzedniej podatności nie można było już zapisywać w `/Library/Application Scripts` ani w `/Library/LaunchAgents`.

Odkryto, że z poziomu sandboxa można utworzyć **Login Item** (aplikacje, które zostaną uruchomione po zalogowaniu użytkownika). Jednak te aplikacje **nie uruchomią się, jeśli** nie będą **notarized**, a także **nie można dodawać argumentów** (nie można więc po prostu uruchomić reverse shell za pomocą **`bash`**).

W ramach poprzedniego Sandbox bypassu Microsoft wyłączył możliwość zapisywania plików w `~/Library/LaunchAgents`. Odkryto jednak, że jeśli umieści się **plik zip jako Login Item**, `Archive Utility` po prostu go **rozpakowuje** w bieżącej lokalizacji. Ponieważ domyślnie folder `LaunchAgents` w `~/Library` nie jest utworzony, można było **spakować plist do `LaunchAgents/~$escape.plist`** i **umieścić** plik zip w **`~/Library`**, aby podczas rozpakowywania trafił do lokalizacji persistence.

Sprawdź [**oryginalny raport tutaj**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Ominięcie Sandbox Worda przez Login Items i .zshenv

(Pamiętaj, że po pierwszym escape Word może zapisywać dowolne pliki, których nazwa zaczyna się od `~$`).

Poprzednia technika miała jednak ograniczenie: jeśli folder **`~/Library/LaunchAgents`** istniał, ponieważ utworzyło go inne oprogramowanie, technika kończyła się niepowodzeniem. W związku z tym odkryto dla tego przypadku inny łańcuch Login Items.

Atakujący mógł utworzyć pliki **`.bash_profile`** i **`.zshenv`** z payloadem do wykonania, a następnie je spakować i **zapisać plik zip w folderze użytkownika ofiary**: **`~/~$escape.zip`**.

Następnie można dodać plik zip do **Login Items**, a potem aplikację **`Terminal`**. Gdy użytkownik zaloguje się ponownie, plik zip zostanie rozpakowany w folderze użytkownika, nadpisując **`.bash_profile`** i **`.zshenv`**, przez co terminal wykona jeden z tych plików (zależnie od tego, czy używany jest bash, czy zsh).

Sprawdź [**oryginalny raport tutaj**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Ominięcie Sandbox Worda za pomocą Open i zmiennych env

Z procesów działających w sandboxie nadal można wywoływać inne procesy za pomocą narzędzia **`open`**. Co więcej, procesy te będą działać **we własnym sandboxie**.

Odkryto, że narzędzie open ma opcję **`--env`**, umożliwiającą uruchomienie aplikacji z **określonymi zmiennymi env**. Można więc było utworzyć plik **`.zshenv`** w folderze **wewnątrz** **sandboxa**, a następnie użyć `open` z opcją `--env`, ustawiając zmienną **`HOME`** na ten folder i otwierając aplikację `Terminal`, która wykona plik `.zshenv` (z jakiegoś powodu konieczne było również ustawienie zmiennej `__OSINSTALL_ENVIROMENT`).

Sprawdź [**oryginalny raport tutaj**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Ominięcie Sandbox Worda za pomocą Open i stdin

Narzędzie **`open`** obsługiwało również parametr **`--stdin`** (po poprzednim bypassie nie można już było używać `--env`).

Chodzi o to, że nawet jeśli **`python`** był podpisany przez Apple, **nie wykona** skryptu z atrybutem **`quarantine`**. Można było jednak przekazać mu skrypt przez stdin, dzięki czemu nie sprawdzał, czy plik był objęty kwarantanną:

1. Upuść plik **`~$exploit.py`** zawierający dowolne polecenia Python.
2. Uruchom _open_ **`–stdin='~$exploit.py' -a Python`**, co uruchamia aplikację Python, używając naszego upuszczonego pliku jako standardowego wejścia. Python bez problemu wykona nasz kod, a ponieważ jest procesem potomnym _launchd_, nie podlega regułom sandboxa Worda.<sup>[[5]](#references)</sup>

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Uncovering a macOS App Sandbox escape vulnerability: A deep dive into CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)

{{#include ../../../../../banners/hacktricks-training.md}}
