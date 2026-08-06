# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

Path `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` में आपको database `appdb.dat` (Windows anniversary से पहले) या `wpndatabase.db` (Windows Anniversary के बाद) मिल सकता है।

इस SQLite database के अंदर, आप `Notification` table पा सकते हैं, जिसमें सभी notifications (XML format में) होती हैं और इनमें interesting data हो सकता है।

### Timeline

Timeline एक Windows characteristic है, जो visit किए गए web pages, edited documents और executed applications का **chronological history** प्रदान करती है।

Database path `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` में स्थित होता है। इस database को SQLite tool से या tool [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) से खोला जा सकता है, **जो 2 files generate करता है जिन्हें tool** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **से खोला जा सकता है**।

### ADS (Alternate Data Streams)

Downloaded files में **ADS Zone.Identifier** हो सकता है, जो यह बताता है कि उसे intranet, internet आदि से **कैसे** **downloaded** किया गया था। कुछ software (जैसे browsers) आमतौर पर **और भी अधिक** **information** डालते हैं, जैसे वह **URL** जहाँ से file downloaded की गई थी।

## **File Backups**

### Recycle Bin

Vista/Win7/Win8/Win10 में **Recycle Bin** drive के root (`C:\$Recycle.bin`) में मौजूद folder **`$Recycle.bin`** में पाया जा सकता है।\
जब इस folder में कोई file delete की जाती है, तो 2 specific files बनाई जाती हैं:

- `$I{id}`: File information (इसे delete किए जाने की date}
- `$R{id}`: File का content

![File Backups - Recycle Bin: $R{id}: File का content](<../../../images/image (1029).png>)

इन files के होने पर आप tool [**Rifiuti**](https://github.com/abelcheung/rifiuti2) का उपयोग deleted files का original address और उसे delete किए जाने की date प्राप्त करने के लिए कर सकते हैं (Vista – Win10 के लिए `rifiuti-vista.exe` का उपयोग करें)।
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy Microsoft Windows में शामिल एक technology है, जो computer files या volumes की **backup copies** या snapshots बना सकती है, भले ही उनका उपयोग किया जा रहा हो।

ये backups आमतौर पर file system के root से `\System Volume Information` में स्थित होते हैं और इनका नाम निम्न image में दिखाए गए **UIDs** से बना होता है:

![Recycle Bin - Volume Shadow Copies: ये backups आमतौर पर file system के root से System Volume Information में स्थित होते हैं और इनका नाम image में दिखाए गए UIDs से बना होता है](<../../../images/image (94).png>)

**ArsenalImageMounter** से forensics image को mount करने पर, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) tool का उपयोग shadow copy का निरीक्षण करने और shadow copy backups से **files extract** करने के लिए किया जा सकता है।

![Recycle Bin - Volume Shadow Copies: ArsenalImageMounter से forensics image को mount करने पर ShadowCopyView tool का उपयोग shadow copy का निरीक्षण करने और shadow copy backups से files extract करने के लिए किया जा सकता है](<../../../images/image (576).png>)

Registry entry `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` में वे files और keys होती हैं जिन्हें **backup नहीं करना है**:

![Recycle Bin - Volume Shadow Copies: registry entry HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore में वे files और keys होती हैं जिन्हें backup नहीं करना है](<../../../images/image (254).png>)

Registry `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` में `Volume Shadow Copies` से संबंधित configuration information भी होती है।

### Office AutoSaved Files

Office autosaved files यहां मिल सकती हैं: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Shell item एक ऐसा item है जिसमें किसी अन्य file तक access करने के तरीके की information होती है।

### Recent Documents (LNK)

Windows user द्वारा **file open, use या create करने** पर इन **shortcuts** को **automatically** **create** करता है:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

जब कोई folder create किया जाता है, तो उस folder, parent folder और grandparent folder का link भी create किया जाता है।

ये automatically created link files **origin के बारे में information रखती हैं**, जैसे कि वह **file** है या **folder**, उस file के **MAC** **times**, उस **volume** की information जहां file stored है, और **target file का folder**। यह information उन files को recover करने में उपयोगी हो सकती है, यदि वे remove कर दी गई हों।

इसके अलावा, link file की **date created**, original file के पहली बार **used** होने का पहला **time** होती है और link file की **date modified**, origin file के उपयोग किए जाने का अंतिम **time** होती है।

इन files का निरीक्षण करने के लिए आप [**LinkParser**](http://4discovery.com/our-tools/) का उपयोग कर सकते हैं।

इस tool में आपको timestamps के **2 sets** मिलेंगे:

- **First Set:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Second Set:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

timestamps का पहला set **file के स्वयं के timestamps** को reference करता है। दूसरा set **linked file के timestamps** को reference करता है।

आप Windows CLI tool [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) चलाकर भी यही information प्राप्त कर सकते हैं।
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
इस मामले में, जानकारी को एक CSV file के अंदर save किया जाएगा।

### Jumplists

ये प्रत्येक application द्वारा indicated recent files होती हैं। यह **किसी application द्वारा उपयोग की गई recent files की list** होती है, जिसे आप प्रत्येक application पर access कर सकते हैं। इन्हें **automatically या custom** बनाया जा सकता है।

**Automatically** बनाई गई **jumplists** `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` में store होती हैं। Jumplists का नाम `{id}.autmaticDestinations-ms` format का होता है, जिसमें initial ID application की ID होती है।

Custom jumplists `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` में store होती हैं और इन्हें application आमतौर पर तब create करती है जब file के साथ कुछ **important** हुआ हो (शायद उसे favorite के रूप में mark किया गया हो)।

किसी भी jumplist का **created time** **file को access किए जाने का पहला समय** दर्शाता है और **modified time अंतिम समय** दर्शाता है।

आप [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) का उपयोग करके jumplists को inspect कर सकते हैं।

![Recent Documents (LNK) - Jumplists: आप JumplistExplorer का उपयोग करके jumplists को inspect कर सकते हैं](<../../../images/image (168).png>)

(_ध्यान दें कि JumplistExplorer द्वारा दिए गए timestamps स्वयं jumplist file से संबंधित होते हैं_)

### Shellbags

[**shellbags क्या होते हैं, यह जानने के लिए इस link को follow करें।**](interesting-windows-registry-keys.md#shellbags)

## Windows USBs का उपयोग

USB device के उपयोग की पहचान निम्नलिखित के creation के आधार पर की जा सकती है:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

ध्यान दें कि कुछ LNK files original path की ओर point करने के बजाय WPDNSE folder की ओर point करती हैं:

![Shellbags - Use of Windows USBs: ध्यान दें कि कुछ LNK files original path की ओर point करने के बजाय WPDNSE folder की ओर point करती हैं](<../../../images/image (218).png>)

WPDNSE folder में मौजूद files original files की copy होती हैं, इसलिए ये PC के restart होने के बाद survive नहीं करेंगी और GUID shellbag से लिया जाता है।

### Registry Information

USB से connected devices के बारे में interesting information रखने वाली registry keys जानने के लिए [इस page को check करें](interesting-windows-registry-keys.md#usb-information)।

### setupapi

USB connection कब बनाई गई थी, इसके timestamps प्राप्त करने के लिए file `C:\Windows\inf\setupapi.dev.log` को check करें (`Section start` search करें)।

![Registry Information - setupapi: USB connection कब बनाई गई थी, इसके timestamps प्राप्त करने के लिए file C: Windows inf setupapi.dev.log को check करें (Section start search करें)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) का उपयोग किसी image से connected रहे USB devices के बारे में information प्राप्त करने के लिए किया जा सकता है।

![setupapi - USB Detective: USBDetective का उपयोग किसी image से connected रहे USB devices के बारे में information प्राप्त करने के लिए किया जा सकता है](<../../../images/image (452).png>)

### Plug and Play Cleanup

'Plug and Play Cleanup' नामक scheduled task मुख्य रूप से outdated driver versions को remove करने के लिए design किया गया है। इसके specified purpose में latest driver package version को retain करना शामिल है, लेकिन online sources के अनुसार यह उन drivers को भी target करता है जो 30 दिनों से inactive हैं। इसलिए, पिछले 30 दिनों में connected न किए गए removable devices के drivers delete किए जा सकते हैं।<sup>[[1]](#references)</sup>

यह task निम्नलिखित path पर स्थित है: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Task के content को दर्शाने वाला screenshot: ![USB Detective - Plug and Play Cleanup: यह task निम्नलिखित path पर स्थित है: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Task के मुख्य Components और Settings:**

- **pnpclean.dll**: यह DLL वास्तविक cleanup process के लिए responsible है।
- **UseUnifiedSchedulingEngine**: `TRUE` पर set है, जो generic task scheduling engine के उपयोग को दर्शाता है।
- **MaintenanceSettings**:
- **Period ('P1M')**: Task Scheduler को regular Automatic maintenance के दौरान monthly cleanup task initiate करने का निर्देश देता है।
- **Deadline ('P2M')**: यदि task लगातार दो महीनों तक fail हो, तो Task Scheduler को emergency Automatic maintenance के दौरान task execute करने का निर्देश देता है।

यह configuration drivers की regular maintenance और cleanup सुनिश्चित करती है तथा लगातार failures की स्थिति में task को दोबारा attempt करने का provision देती है।

**अधिक information के लिए check करें:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)<sup>[[1]](#references)</sup>

## Emails

Emails में **2 interesting parts होते हैं: headers और email का content**। **Headers** में आपको निम्नलिखित information मिल सकती है:

- Emails किसने भेजे (email address, IP, email को redirect करने वाले mail servers)
- Email कब भेजा गया

इसके अलावा, `References` और `In-Reply-To` headers में messages की ID मिल सकती है:

![Plug and Play Cleanup - Emails: Email कब भेजा गया](<../../../images/image (593).png>)

### Windows Mail App

यह application emails को HTML या text में save करती है। Emails `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` के अंदर मौजूद subfolders में मिल सकती हैं। Emails `.dat` extension के साथ save होती हैं।

Emails का **metadata** और **contacts** **EDB database** के अंदर मिल सकते हैं: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

File की **extension को `.vol` से `.edb` में change करें** और इसे खोलने के लिए [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) tool का उपयोग करें। `Message` table के अंदर आप emails देख सकते हैं।

### Microsoft Outlook

जब Exchange servers या Outlook clients का उपयोग किया जाता है, तो कुछ MAPI headers मौजूद होंगे:

- `Mapi-Client-Submit-Time`: Email भेजे जाने के समय system का समय
- `Mapi-Conversation-Index`: Thread के child messages की संख्या और thread के प्रत्येक message का timestamp
- `Mapi-Entry-ID`: Message identifier।
- `Mappi-Message-Flags` और `Pr_last_Verb-Executed`: MAPI client के बारे में information (message read? no read? responded? redirected? out of the office?)

Microsoft Outlook client में सभी sent/received messages, contacts data और calendar data एक PST file में store होते हैं:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Registry path `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` यह दर्शाता है कि कौन-सी file उपयोग की जा रही है।

आप [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) tool का उपयोग करके PST file खोल सकते हैं।

![Windows Mail App - Microsoft Outlook: आप Kernel PST Viewer tool का उपयोग करके PST file खोल सकते हैं](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Microsoft Outlook को **IMAP** या किसी **Exchange** server के साथ configure किए जाने पर एक **OST file** generate होती है, जिसमें PST file के समान information store होती है। यह file server के साथ synchronize होती है और **पिछले 12 महीनों** का data, अधिकतम **50GB size** तक, retain करती है। यह PST file वाली directory में ही स्थित होती है। OST file देखने के लिए [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) का उपयोग किया जा सकता है।

### Retrieving Attachments

Lost attachments निम्नलिखित स्थानों से recover की जा सकती हैं:

- **IE10** के लिए: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11 और उसके बाद के versions** के लिए: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird** data store करने के लिए **MBOX files** का उपयोग करता है, जो `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles` में स्थित होती हैं।

### Image Thumbnails

- **Windows XP और 8-8.1**: Thumbnails वाले folder को access करने पर image previews store करने वाली `thumbs.db` file generate होती है, deletion के बाद भी।
- **Windows 7/10**: UNC path के माध्यम से network पर access किए जाने पर `thumbs.db` create होती है।
- **Windows Vista और इसके बाद के versions**: Thumbnail previews `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` में centralized होती हैं और files का नाम **thumbcache_xxx.db** होता है। इन files को देखने के लिए [**Thumbsviewer**](https://thumbsviewer.github.io) और [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) tools हैं।

### Windows Registry Information

Windows Registry, जिसमें extensive system और user activity data store होता है, निम्नलिखित files में contained होती है:

- विभिन्न `HKEY_LOCAL_MACHINE` subkeys के लिए `%windir%\System32\Config`।
- `HKEY_CURRENT_USER` के लिए `%UserProfile%{User}\NTUSER.DAT`।
- Windows Vista और इसके बाद के versions `%Windir%\System32\Config\RegBack\` में `HKEY_LOCAL_MACHINE` registry files का backup रखते हैं।
- इसके अतिरिक्त, Windows Vista और Windows 2008 Server onwards से program execution information `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` में store होती है।

### Tools

Registry files को analyze करने के लिए कुछ tools उपयोगी हैं:

- **Registry Editor**: यह Windows में installed होता है। यह current session की Windows registry में navigate करने के लिए एक GUI है।
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): यह आपको registry file load करके GUI के माध्यम से उसमें navigate करने देता है। इसमें ऐसे Bookmarks भी होते हैं जो interesting information वाली keys को highlight करते हैं।
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): इसमें भी एक GUI है, जिससे loaded registry में navigate किया जा सकता है। इसमें ऐसे plugins भी होते हैं जो loaded registry के अंदर interesting information को highlight करते हैं।
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): यह एक अन्य GUI application है, जो loaded registry से important information extract कर सकती है।

### Recovering Deleted Element

जब कोई key delete की जाती है, तो उसे deleted के रूप में mark किया जाता है, लेकिन जब तक उसके द्वारा occupied space की आवश्यकता न हो, तब तक उसे remove नहीं किया जाता। इसलिए, **Registry Explorer** जैसे tools का उपयोग करके इन deleted keys को recover करना संभव है।

### Last Write Time

प्रत्येक Key-Value में एक **timestamp** होता है, जो उसके last modified होने का समय दर्शाता है।

### SAM

File/hive **SAM** में system के **users, groups और users के passwords** के hashes होते हैं।

`SAM\Domains\Account\Users` में आप username, RID, last login, last failed logon, login counter, password policy और account creation time प्राप्त कर सकते हैं। **Hashes** प्राप्त करने के लिए आपको file/hive **SYSTEM** की भी **need** होती है।

### Interesting entries in the Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

[इस post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) में आप suspicious behaviours detect करने के लिए common Windows processes के बारे में जान सकते हैं।<sup>[[2]](#references)</sup>

### Windows Recent APPs

Registry `NTUSER.DAT` के अंदर path `Software\Microsoft\Current Version\Search\RecentApps` में आपको **executed application**, उसके **last execution time** और उसे launch किए जाने की **number of times** से संबंधित information वाली subkeys मिल सकती हैं।

### BAM (Background Activity Moderator)

आप registry editor से `SYSTEM` file खोल सकते हैं। इसके बाद path `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` के अंदर **प्रत्येक user द्वारा execute की गई applications** और उन्हें execute किए जाने का **समय** मिल सकता है (समय registry की Data value के अंदर होता है)।

### Windows Prefetch

Prefetching एक ऐसी technique है, जो computer को silently **content display करने के लिए आवश्यक resources fetch** करने देती है, जिन्हें user **निकट भविष्य में access कर सकता है**, ताकि resources को अधिक तेज़ी से access किया जा सके।

Windows prefetch में **executed programs के caches** create किए जाते हैं, जिससे उन्हें faster load किया जा सके। ये caches `.pf` files के रूप में `C:\Windows\Prefetch` path के अंदर create होते हैं। XP/VISTA/WIN7 में 128 files और Win8/Win10 में 1024 files की limit होती है।

File name `{program_name}-{hash}.pf` के रूप में create होता है (hash executable के path और arguments पर आधारित होता है)। W10 में ये files compressed होती हैं। ध्यान दें कि file की केवल presence यह indicate करती है कि **program को किसी समय execute किया गया था**।

File `C:\Windows\Prefetch\Layout.ini` में उन prefetched files के **folders के names** होते हैं। इस file में **executions की संख्या**, execution की **dates** और program द्वारा **open की गई files** के बारे में **information** होती है।

इन files को inspect करने के लिए आप [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) tool का उपयोग कर सकते हैं:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** का लक्ष्य भी prefetch जैसा ही है, यानी **लोड होने वाले अगले programs का अनुमान लगाकर उन्हें तेज़ी से load करना**। हालांकि, यह prefetch service का विकल्प नहीं है।\
यह service `C:\Windows\Prefetch\Ag*.db` में database files generate करती है।

इन databases में आप **program** का **नाम**, **executions की संख्या**, **खोली गई files**, **access किए गए volumes**, **पूरा path**, **timeframes** और **timestamps** पा सकते हैं।

आप इस information को [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) tool का उपयोग करके access कर सकते हैं।

### SRUM

**System Resource Usage Monitor** (SRUM) **किसी process द्वारा consume किए गए resources को monitor करता है**। यह W8 में आया और data को `C:\Windows\System32\sru\SRUDB.dat` में स्थित ESE database में store करता है।

यह निम्नलिखित information देता है:

- AppID और Path
- Process execute करने वाला user
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

यह information हर 60 mins में update होती है।

आप [**srum_dump**](https://github.com/MarkBaggett/srum-dump) tool का उपयोग करके इस file से data प्राप्त कर सकते हैं।
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**, जिसे **ShimCache** के नाम से भी जाना जाता है, **Microsoft** द्वारा application compatibility समस्याओं से निपटने के लिए विकसित **Application Compatibility Database** का एक भाग है। यह system component file metadata के विभिन्न विवरण रिकॉर्ड करता है, जिनमें शामिल हैं:

- File का पूरा path
- File का आकार
- **$Standard_Information** (SI) के अंतर्गत Last Modified time
- ShimCache का Last Updated time
- Process Execution Flag

ऐसा data operating system के version के आधार पर registry में निर्धारित locations पर store किया जाता है:

- XP के लिए, data `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` के अंतर्गत store किया जाता है, जिसमें 96 entries की capacity होती है।
- Server 2003, साथ ही Windows versions 2008, 2012, 2016, 7, 8 और 10 के लिए, storage path `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache` है, जिसमें क्रमशः 512 और 1024 entries store की जा सकती हैं।

Stored information को parse करने के लिए [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) का उपयोग recommended है।

![SRUM - AppCompatCache (ShimCache): Stored information को parse करने के लिए AppCompatCacheParser tool का उपयोग recommended है](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** file मूल रूप से एक registry hive है, जो system पर execute किए गए applications के बारे में details log करती है। यह आमतौर पर `C:\Windows\AppCompat\Programas\Amcache.hve` पर मिलती है।

यह file recently executed processes के records store करने के लिए महत्वपूर्ण है, जिनमें executable files के paths और उनके SHA1 hashes शामिल होते हैं। यह information system पर applications की activity track करने के लिए अत्यंत उपयोगी है।

**Amcache.hve** से data extract और analyze करने के लिए [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool का उपयोग किया जा सकता है। निम्न command **Amcache.hve** file के contents को parse करने और results को CSV format में output करने के लिए AmcacheParser का उपयोग करने का एक example है:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
उत्पन्न CSV files में, `Amcache_Unassociated file entries` विशेष रूप से उल्लेखनीय है क्योंकि यह unassociated file entries के बारे में समृद्ध जानकारी प्रदान करता है।

उत्पन्न की गई सबसे interesting CVS file `Amcache_Unassociated file entries` है।

### RecentFileCache

यह artifact केवल W7 में `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` पर पाया जा सकता है और इसमें कुछ binaries के recent execution के बारे में जानकारी होती है।

आप file को parse करने के लिए tool [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) का उपयोग कर सकते हैं।

### Scheduled tasks

आप इन्हें `C:\Windows\Tasks` या `C:\Windows\System32\Tasks` से extract कर सकते हैं और XML के रूप में पढ़ सकते हैं।

### Services

आप इन्हें registry में `SYSTEM\ControlSet001\Services` के अंतर्गत पा सकते हैं। आप देख सकते हैं कि क्या execute होने वाला है और कब।

### **Windows Store**

installed applications `\ProgramData\Microsoft\Windows\AppRepository\`\
में पाए जा सकते हैं।  
इस repository में database **`StateRepository-Machine.srd`** के अंदर system में **प्रत्येक installed application** का **log** होता है।

इस database की Application table के अंदर, "Application ID", "PackageNumber", और "Display Name" columns पाए जा सकते हैं। इन columns में pre-installed और installed applications की जानकारी होती है और यह पता लगाया जा सकता है कि कुछ applications uninstall की गई थीं या नहीं, क्योंकि installed applications की IDs sequential होनी चाहिए।

registry path `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
के अंदर **installed application** को भी **find** किया जा सकता है।  
और **uninstalled** **applications** यहां पाई जा सकती हैं: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

Windows events के अंदर दिखाई देने वाली information हैं:

- क्या हुआ
- Timestamp (UTC + 0)
- शामिल Users
- शामिल Hosts (hostname, IP)
- Access किए गए Assets (files, folder, printer, services)

Logs Windows Vista से पहले `C:\Windows\System32\config` में और Windows Vista के बाद `C:\Windows\System32\winevt\Logs` में स्थित होते हैं। Windows Vista से पहले event logs binary format में थे और उसके बाद वे **XML format** में होते हैं तथा **.evtx** extension का उपयोग करते हैं।

Event files का location SYSTEM registry में **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** पर पाया जा सकता है।

उन्हें Windows Event Viewer (**`eventvwr.msc`**) से या [**Event Log Explorer**](https://eventlogxp.com) **या** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** जैसे अन्य tools से visualize किया जा सकता है।**

## Understanding Windows Security Event Logging

Access events `C:\Windows\System32\winevt\Security.evtx` पर स्थित security configuration file में record किए जाते हैं। इस file का size adjustable होता है और जब इसकी capacity पूरी हो जाती है, तो पुराने events overwrite कर दिए जाते हैं। Recorded events में user logins और logoffs, user actions और security settings में changes के साथ-साथ file, folder और shared asset access शामिल होते हैं।

### Key Event IDs for User Authentication:

- **EventID 4624**: बताता है कि user ने successfully authenticate किया।
- **EventID 4625**: authentication failure को दर्शाता है।
- **EventIDs 4634/4647**: user logoff events को दर्शाते हैं।
- **EventID 4672**: administrative privileges के साथ login को दर्शाता है।

#### Sub-types within EventID 4634/4647:

- **Interactive (2)**: Direct user login।
- **Network (3)**: Shared folders तक access।
- **Batch (4)**: Batch processes का execution।
- **Service (5)**: Service launches।
- **Proxy (6)**: Proxy authentication।
- **Unlock (7)**: Password से screen unlock की गई।
- **Network Cleartext (8)**: Clear text password transmission, अक्सर IIS से।
- **New Credentials (9)**: Access के लिए different credentials का usage।
- **Remote Interactive (10)**: Remote desktop या terminal services login।
- **Cache Interactive (11)**: Domain controller से contact किए बिना cached credentials के साथ login।
- **Cache Remote Interactive (12)**: Cached credentials के साथ remote login।
- **Cached Unlock (13)**: Cached credentials के साथ unlocking।

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: User name मौजूद नहीं है - Username enumeration attack का संकेत हो सकता है।
- **0xC000006A**: Correct user name लेकिन wrong password - Possible password guessing या brute-force attempt।
- **0xC0000234**: User account locked out - Multiple failed logins वाले brute-force attack के बाद हो सकता है।
- **0xC0000072**: Account disabled - Disabled accounts तक access करने के unauthorized attempts।
- **0xC000006F**: Allowed time के बाहर logon - Set login hours के बाहर access करने के attempts को दर्शाता है, जो unauthorized access का possible संकेत हो सकता है।
- **0xC0000070**: Workstation restrictions का violation - Unauthorized location से login करने का attempt हो सकता है।
- **0xC0000193**: Account expiration - Expired user accounts के साथ access attempts।
- **0xC0000071**: Expired password - Outdated passwords के साथ login attempts।
- **0xC0000133**: Time sync issues - Client और server के बीच बड़े time discrepancies अधिक sophisticated attacks, जैसे pass-the-ticket, का संकेत हो सकते हैं।
- **0xC0000224**: Mandatory password change required - Frequent mandatory changes account security को destabilize करने के attempt का संकेत दे सकते हैं।
- **0xC0000225**: Security issue के बजाय system bug को दर्शाता है।
- **0xC000015b**: Denied logon type - Unauthorized logon type के साथ access attempt, जैसे किसी user द्वारा service logon execute करने का प्रयास।

#### EventID 4616:

- **Time Change**: System time में modification, जो events की timeline को obscure कर सकता है।

#### EventID 6005 and 6006:

- **System Startup and Shutdown**: EventID 6005 system के starting up को दर्शाता है, जबकि EventID 6006 इसके shutting down को दर्शाता है।

#### EventID 1102:

- **Log Deletion**: Security logs का clear किया जाना, जो अक्सर illicit activities को cover up करने का red flag होता है।

#### EventIDs for USB Device Tracking:

- **20001 / 20003 / 10000**: USB device का first connection।
- **10100**: USB driver update।
- **EventID 112**: USB device insertion का time।

इन login types और credential dumping opportunities को simulate करने के practical examples के लिए [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them) देखें।

Event details, जिनमें status और sub-status codes शामिल हैं, event causes के बारे में further insights प्रदान करते हैं, विशेष रूप से Event ID 4625 में।

### Recovering Windows Events

Deleted Windows Events को recover करने की chances बढ़ाने के लिए suspect computer को सीधे unplug करके power down करने की सलाह दी जाती है। `.evtx` extension specify करने वाले recovery tool **Bulk_extractor** को ऐसे events recover करने के प्रयास के लिए recommend किया जाता है।

### Identifying Common Attacks via Windows Events

Common cyber attacks की पहचान करने के लिए Windows Event IDs का उपयोग करने की comprehensive guide के लिए [Red Team Recipe](https://redteamrecipe.com/event-codes/) पर जाएं।

#### Brute Force Attacks

Multiple EventID 4625 records से पहचाने जा सकते हैं, जिनके बाद attack सफल होने पर EventID 4624 आता है।

#### Time Change

EventID 4616 द्वारा record किया जाता है; system time में changes forensic analysis को complicated बना सकते हैं।

#### USB Device Tracking

USB device tracking के लिए useful System EventIDs में initial use के लिए 20001/20003/10000, driver updates के लिए 10100 और insertion timestamps के लिए DeviceSetupManager का EventID 112 शामिल हैं।

#### System Power Events

EventID 6005 system startup को दर्शाता है, जबकि EventID 6006 shutdown को दर्शाता है।

#### Log Deletion

Security EventID 1102 logs के deletion का signal देता है, जो forensic analysis के लिए एक critical event है।

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)

{{#include ../../../banners/hacktricks-training.md}}
