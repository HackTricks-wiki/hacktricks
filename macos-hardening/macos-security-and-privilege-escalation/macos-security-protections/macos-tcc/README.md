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

**TCC** is handled by the **daemon** located in `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` and configured in `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registering the mach service `com.apple.tccd.system`).

There is a **user-mode tccd** running per logged in user defined in `/System/Library/LaunchAgents/com.apple.tccd.plist` registering the mach services `com.apple.tccd` and `com.apple.usernotifications.delegate.com.apple.tccd`.

Here you can see the tccd running as system and as user:

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

Permissions are **inherited from the parent** application and the **permissions** are **tracked** based on the **Bundle ID** and the **Developer ID**.

### TCC DatabaseS

The selections is then stored in the TCC system-wide database in **`/Library/Application Support/com.apple.TCC/TCC.db`** or in **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** for per-user preferences. The databases are **protected from editing with SIP**(System Integrity Protection), but you can read them.

{% hint style="danger" %}
The TCC database in **iOS** is in **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

There is a **third** TCC database in **`/var/db/locationd/clients.plist`** to indicate clients allowed to **access location services**.

Moreover, a process with **full disk access** can **edit the user-mode** database. Now an app also needs **FDA** to **read** the database.

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

**Full Disk Access** is name is **`kTCCServiceSystemPolicyAllFiles`** and **`kTCCServiceAppleEvents`** allows the app to send events to other applications that are commonly used for **automating tasks**. Moreover, **`kTCCServiceSystemPolicySysAdminFiles`** allows to **change** the **`NFSHomeDirectory`** attribute of a user that changes his home folder and therefore allows to **bypass TCC**.
{% endhint %}

You could also check **already given permissions** to apps in `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

{% hint style="success" %}
Nota that even if one of the databases are inside the users home, **users cannot directly modify these databases because of SIP** (even if you are root). The only way a new rule can be configured or modified is via System Preferences pane or prompts where the app asks the user.

However, remember that users _can_ **delete or query rules** using **`tccutil`** .&#x20;
{% endhint %}

#### Reset

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

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

{% hint style="warning" %}
Therefore, other applications using the same name and bundle ID won't be able to access granted permissions given to other apps.
{% endhint %}

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

{% hint style="success" %}
Apart from some official documentation about entitlements it's also possible to find unofficial **interesting information about entitlements in** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)
{% endhint %}

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
It's curious that the **`com.apple.macl`** attribute is managed by the **Sandbox**, not tccd.

Also note that if you move a file that allows the UUID of an app in your computer to a different compiter, because the same app will have different UIDs, it won't grant access to that app.
{% endhint %}

The extended attribute `com.apple.macl` **can’t be cleared** like other extended attributes because it’s **protected by SIP**. However, as [**explained in this post**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), it's possible to disable it **zipping** the file, **deleting** it and **unzipping** it.

### TCC Bypasses

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## References

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
*   [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
