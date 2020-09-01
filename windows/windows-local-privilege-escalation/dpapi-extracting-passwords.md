# DPAPI - Extracting Passwords

## What is DPAPI

Its primary use in the Windows operating system is to **perform symmetric encryption of asymmetric private keys**, using a user or system secret as a significant contribution of entropy.  
**DPAPI allows developers to encrypt keys using a symmetric key derived from the user's logon secrets**, or in the case of system encryption, using the system's domain authentication secrets.

This makes very easy to developer to **save encrypted data** in the computer **without** needing to **worry** how to **protect** the **encryption** **key**.

## What does DPAPI protect?

DPAPI is utilized to protect the following personal data:

* Passwords and form auto-completion data in Internet Explorer, Google \*Chrome
* E-mail account passwords in Outlook, Windows Mail, Windows Mail, etc.
* Internal FTP manager account passwords
* Shared folders and resources access passwords
* Wireless network account keys and passwords
* Encryption key in Windows CardSpace and Windows Vault
* Remote desktop connection passwords, .NET Passport
* Private keys for Encrypting File System \(EFS\), encrypting mail S-MIME, other user's certificates, SSL/TLS in Internet Information Services
* EAP/TLS and 802.1x \(VPN and WiFi authentication\)
* Network passwords in Credential Manager
* Personal data in any application programmatically protected with the API function CryptProtectData. For example, in Skype, Windows Rights Management Services, Windows Media, MSN messenger, Google Talk etc.

An example of a successful and clever way to protect data using DPAPI is the implementation of the auto-completion password encryption algorithm in Internet Explorer. To encrypt the login and password for a certain web page, it calls the CryptProtectData function, where in the optional entropy parameter it specifies the address of the web page. Thus, unless one knows the original URL where the password was entered, nobody, not even Internet Explorer itself, can decrypt that data back.

 The DPAPI keys used for encrypting the user's RSA keys are stored under `%APPDATA%\Microsoft\Protect\{SID}` directory, where {SID} is the [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) of that user. **The DPAPI key is stored in the same file as the master key that protects the users private keys**. It usually is 64 bytes of random data. \(Notice that this directory is protected so you cannot list it using`dir` from the cmd, but you can list it from PS\).

```text
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

You can use **mimikatz module** `dpapi::masterkey` with the appropriate arguments \(`/pvk` or `/rpc`\) to decrypt it.

The **credentials files protected by the master password** are usually located in:

```text
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.  
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module \(if you are root\).

