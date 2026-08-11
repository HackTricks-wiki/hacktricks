# Bypasses sandboxa Office w macOS

{{#include ../../../../../banners/hacktricks-training.md}}

Poniżej opisano **historyczne ucieczki z sandboxa Microsoft Office for Mac**. Dokumentują one możliwe do ponownego wykorzystania błędy w granicach zaufania, ale nie należy zakładać podatności załatanych kombinacji Office/macOS bez odtworzenia dokładnej wersji i polityki.

### Word sandbox bypass przez LaunchAgents

Podatna aplikacja używała niestandardowej reguły sandboxa za pośrednictwem `com.apple.security.temporary-exception.sbpl`. Zezwalała ona na pliki zwykłe, których basename zaczynał się od `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

Dlatego ucieczka sprowadzała się do **zapisania `plist`** LaunchAgent w `~/Library/LaunchAgents/~$escape.plist`.

Sprawdź [**oryginalny raport tutaj**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass przez Login Items i zip

Pamiętaj, że od czasu pierwszej ucieczki Word może zapisywać dowolne pliki, których nazwa zaczyna się od `~$`, chociaż po załataniu poprzedniej luki nie można było zapisywać w `/Library/Application Scripts` ani w `/Library/LaunchAgents`.

Podatny sandbox zezwalał na utworzenie **Login Item**, który uruchamia się po zalogowaniu użytkownika. Zademonstrowana ścieżka wymagała akceptowalnej, podpisanej/zanotaryzowanej aplikacji i nie zezwalała na dowolne argumenty, dlatego dodanie `bash` z argumentem reverse-shell było niewystarczające.<sup>[[2]](#references)</sup>

W ramach poprzedniego Sandbox bypass firma Microsoft wyłączyła możliwość zapisywania plików w `~/Library/LaunchAgents`. Odkryto jednak, że jeśli umieścisz **plik zip jako Login Item**, `Archive Utility` po prostu go **rozpakuje** w bieżącej lokalizacji. Ponieważ domyślnie folder `LaunchAgents` z `~/Library` nie jest tworzony, możliwe było **spakowanie pliku plist do `LaunchAgents/~$escape.plist`** i **umieszczenie** pliku zip w **`~/Library`**, aby po rozpakowaniu trafił do lokalizacji persistence.

Sprawdź [**oryginalny raport tutaj**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass przez Login Items i .zshenv

(Pamiętaj, że od czasu pierwszej ucieczki Word może zapisywać dowolne pliki, których nazwa zaczyna się od `~$`).

Poprzednia technika miała jednak ograniczenie: jeśli folder **`~/Library/LaunchAgents`** istniał, ponieważ został utworzony przez inne oprogramowanie, kończyła się niepowodzeniem. Dlatego odkryto inną chain Login Items.

Attacker mógł utworzyć **`.bash_profile`** i **`.zshenv`** zawierające payload, zarchiwizować je i zapisać ZIP w katalogu domowym **victim's** jako **`~/~$escape.zip`**.

Następnie należało dodać ZIP oraz **Terminal** jako Login Items. Przy kolejnym logowaniu Archive Utility rozpakowuje dotfiles do katalogu domowego użytkownika, a shell Terminala ewaluje odpowiedni startup file (`.bash_profile` dla zademonstrowanej ścieżki Bash lub `.zshenv` dla Zsh).<sup>[[3]](#references)</sup>

Sprawdź [**oryginalny raport tutaj**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass z Open i zmiennymi env

Procesy działające w sandboxie nadal mogły żądać uruchomienia aplikacji za pośrednictwem **`open`**. Uruchomiona aplikacja działała we własnym kontekście bezpieczeństwa, zamiast dziedziczyć dokładny profil sandboxa Word.<sup>[[4]](#references)</sup>

Podatne narzędzie `open` miało opcję **`--env`** służącą do przekazywania zmiennych środowiskowych. Exploit tworzył `.zshenv` wewnątrz sandboxa, ustawiał `HOME` na ten katalog i uruchamiał Terminal, aby Zsh go zewaluował. Opisana chain ustawia również błędnie zapisaną prywatną zmienną `__OSINSTALL_ENVIROMENT`; podczas odtwarzania historycznego PoC zachowaj tę dokładną pisownię.<sup>[[4]](#references)</sup>

Sprawdź [**oryginalny raport tutaj**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass z Open i stdin

Narzędzie **`open`** obsługiwało również parametr **`--stdin`** (a po poprzednim bypassie nie można już było używać `--env`).

Chociaż aplikacja Python firmy Apple odrzucała skrypt objęty kwarantanną, podatny workflow mógł przekazać ten sam skrypt przez standardowe wejście, omijając opartą na pliku kontrolę kwarantanny:<sup>[[5]](#references)</sup>

1. Upuść plik **`~$exploit.py`** zawierający dowolne polecenia Python.
2. Uruchom `open --stdin='~$exploit.py' -a Python`. Uruchomiona aplikacja Python otrzymuje przekazany kod na standardowym wejściu i w podatnych wersjach wykonuje go poza sandboxem Word, ponieważ LaunchServices tworzy ją za pośrednictwem `launchd`.<sup>[[5]](#references)</sup>

## References

- [1] [Ucieczka z sandboxa – Microsoft Office na macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama na macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Ucieczka z sandboxa Office365 na MacOS](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Analiza techniczna CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Odkrywanie podatności umożliwiającej ucieczkę z App Sandbox w macOS: szczegółowa analiza CVE-2022-26706 – Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
