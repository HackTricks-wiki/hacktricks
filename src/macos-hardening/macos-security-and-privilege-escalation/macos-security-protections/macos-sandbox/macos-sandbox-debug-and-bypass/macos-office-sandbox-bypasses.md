# Obejścia Sandbox w aplikacjach Office dla macOS

{{#include ../../../../../banners/hacktricks-training.md}}

### Obejście Sandbox w Wordzie za pomocą Launch Agents

Aplikacja używa **custom Sandbox** z wykorzystaniem entitlementu **`com.apple.security.temporary-exception.sbpl`**, a ten custom sandbox pozwala zapisywać pliki w dowolnym miejscu, o ile nazwa pliku zaczyna się od `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Dlatego ucieczka sprowadzała się do **zapisania pliku `plist`** LaunchAgent w `~/Library/LaunchAgents/~$escape.plist`.

Sprawdź [**oryginalny raport tutaj**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[1]</sup>

### Obejście Sandbox w Wordzie za pomocą Login Items i zip

Pamiętaj, że po pierwszej ucieczce Word może zapisywać dowolne pliki, których nazwa zaczyna się od `~$`, jednak po załataniu poprzedniej podatności nie można było zapisywać w `/Library/Application Scripts` ani w `/Library/LaunchAgents`.

Odkryto, że z poziomu sandboxa można utworzyć **Login Item** (aplikacje, które zostaną uruchomione po zalogowaniu użytkownika). Jednak takie aplikacje **nie zostaną uruchomione, chyba że** będą **notarized**, a także **nie można dodać argumentów** (nie można więc po prostu uruchomić reverse shell za pomocą **`bash`**).

W ramach poprzedniego obejścia Sandbox firma Microsoft wyłączyła możliwość zapisywania plików w `~/Library/LaunchAgents`. Odkryto jednak, że jeśli umieścisz **plik zip jako Login Item**, `Archive Utility` po prostu go **rozpakowuje** w bieżącej lokalizacji. Ponieważ domyślnie folder `LaunchAgents` w `~/Library` nie jest tworzony, możliwe było **spakowanie pliku plist do `LaunchAgents/~$escape.plist`** i **umieszczenie** pliku zip w `~/Library`, aby po rozpakowaniu trafił on do miejsca persistence.

Sprawdź [**oryginalny raport tutaj**](https://objective-see.org/blog/blog_0x4B.html).<sup>[2]</sup>

### Obejście Sandbox w Wordzie za pomocą Login Items i .zshenv

(Pamiętaj, że po pierwszej ucieczce Word może zapisywać dowolne pliki, których nazwa zaczyna się od `~$`).

Poprzednia technika miała jednak ograniczenie: jeśli folder **`~/Library/LaunchAgents`** istniał, ponieważ utworzyło go inne oprogramowanie, technika kończyła się niepowodzeniem. Dlatego odkryto inny łańcuch Login Items.

Atakujący mógł utworzyć pliki **`.bash_profile`** i **`.zshenv`** z payloadem do wykonania, a następnie spakować je i **zapisać plik zip w folderze użytkownika ofiary**: **`~/~$escape.zip`**.

Następnie należało dodać plik zip do **Login Items**, a potem aplikację **`Terminal`**. Gdy użytkownik zalogowałby się ponownie, plik zip zostałby rozpakowany w folderze użytkownika, nadpisując **`.bash_profile`** i **`.zshenv`**, a tym samym terminal wykonałby jeden z tych plików (zależnie od tego, czy używany jest bash, czy zsh).

Sprawdź [**oryginalny raport tutaj**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[3]</sup>

### Obejście Sandbox w Wordzie za pomocą open i zmiennych env

Z procesów działających w sandboxie nadal można wywoływać inne procesy za pomocą narzędzia **`open`**. Co więcej, procesy te będą działać **we własnym sandboxie**.

Odkryto, że narzędzie open ma opcję **`--env`**, która umożliwia uruchomienie aplikacji z **określonymi zmiennymi env**. Możliwe było zatem utworzenie pliku **`.zshenv`** w folderze **wewnątrz** **sandboxa**, a następnie użycie `open` z opcją `--env` i ustawienie zmiennej **`HOME`** na ten folder podczas otwierania aplikacji `Terminal`, która wykona plik `.zshenv` (z jakiegoś powodu konieczne było również ustawienie zmiennej `__OSINSTALL_ENVIROMENT`).

Sprawdź [**oryginalny raport tutaj**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[4]</sup>

### Obejście Sandbox w Wordzie za pomocą Open i stdin

Narzędzie **`open`** obsługiwało również parametr **`--stdin`** (po poprzednim obejściu nie można już było używać `--env`).

Problem polegał na tym, że nawet jeśli **`python`** był podpisany przez Apple, **nie wykona** skryptu z atrybutem **`quarantine`**. Możliwe było jednak przekazanie mu skryptu przez stdin, dzięki czemu nie sprawdzał, czy plik był poddany kwarantannie:

1. Upuść plik **`~$exploit.py`** zawierający dowolne polecenia Python.
2. Uruchom _open_ **`–stdin='~$exploit.py' -a Python`**, co uruchamia aplikację Python, używając upuszczonego pliku jako jej standardowego wejścia. Python bez problemu wykona nasz kod, a ponieważ jest procesem potomnym _launchd_, nie podlega regułom sandboxa Worda.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
