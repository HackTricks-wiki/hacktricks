# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

प्रति-user notification database `%LOCALAPPDATA%\Microsoft\Windows\Notifications` के अंतर्गत होता है (उदाहरण के लिए, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`)। Windows 10 के शुरुआती releases में `appdb.dat` का उपयोग किया जाता था; Anniversary Update (1607) ने `wpndatabase.db` पेश किया। SQLite database में notification payloads और timing fields वाली `Notification` table शामिल होती है, हालांकि retention और उपलब्ध data release तथा cleanup policy के अनुसार अलग-अलग हो सकते हैं।<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline एक activity-history feature है, जिसमें supported applications, documents और अन्य user activity के records हो सकते हैं; इसका coverage application और Windows version पर निर्भर करता है।<sup>[[4]](#references)</sup>

Database `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` पर स्थित होता है। इसे SQLite से खोला जा सकता है या [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) से parse किया जा सकता है, जिसके output की समीक्षा [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md) से की जा सकती है।<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Local trust boundary के बाहर से download की गई files में **`Zone.Identifier` alternate data stream** हो सकती है, जो zone information record करती है और इसमें URL जैसे origin metadata शामिल हो सकते हैं। इसकी presence और fields producer तथा system policy पर निर्भर करते हैं।<sup>[[6]](#references)</sup>

## **File Backups**

### Recycle Bin

Vista और उसके बाद के versions में, **Recycle Bin** drive के root में मौजूद **`$Recycle.bin`** folder में पाया जा सकता है (उदाहरण के लिए, `C:\$Recycle.bin`)।\
जब इस folder में कोई file delete की जाती है, तो 2 specific files बनाई जाती हैं:

- `$I{id}`: File information, जिसमें deletion time और original path शामिल होते हैं
- `$R{id}`: File का content

![File Backups - Recycle Bin: $R{id}: Content of the file](<../../../images/image (1029).png>)

इन files के होने पर, original path और deletion time extract करने के लिए [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) का उपयोग किया जा सकता है (target Windows release के लिए उपयुक्त version का उपयोग करें)।<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) उपयोग में होने वाली files के volumes की point-in-time shadow copies बना सकता है; shadow copy forensic image का विकल्प नहीं है।<sup>[[8]](#references)</sup>

Copy metadata सामान्यतः volume root पर `\System Volume Information` से संबद्ध होता है, और इसके identifiers system के अनुसार अलग-अलग होते हैं:

![Recycle Bin - Volume Shadow Copies: ये backups आमतौर पर file system के root से System Volume Information में स्थित होते हैं और इनका नाम चित्र में दिखाए गए UIDs से बना होता है...](<../../../images/image (94).png>)

किसी उपयुक्त forensic mounter से image mount करने के बाद, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) उपलब्ध VSS snapshots को enumerate कर सकता है और उनमें से files को browse या copy कर सकता है।<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: ArsenalImageMounter से forensics image mount करने पर ShadowCopyView tool का उपयोग shadow copy का निरीक्षण करने और files को extract करने के लिए किया जा सकता है...](<../../../images/image (576).png>)

VSS registry writer configuration में `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` शामिल है, जहाँ backup से exclude की गई files और keys निर्दिष्ट की जा सकती हैं:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: registry entry HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore में backup न की जाने वाली files और keys होती हैं](<../../../images/image (254).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` key में भी VSS service configuration होती है।<sup>[[8]](#references)</sup>

### Office AutoSaved Files

AutoRecover locations Office application, version और configuration के अनुसार अलग-अलग होती हैं। Word के लिए Microsoft `%APPDATA%\Microsoft\Word` को default location के रूप में document करता है; सक्रिय path के लिए application settings देखें।<sup>[[12]](#references)</sup>

## Shell Items

Shell item ऐसा item होता है जिसमें किसी अन्य file तक पहुँचने के तरीके की जानकारी होती है।

### Recent Documents (LNK)

Windows सामान्यतः तब recent-item shortcuts बनाता है जब कोई user किसी item को खोलता है या अन्यथा access करता है:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Folder access से उस folder और संबंधित parent folders के लिए भी links बन सकते हैं।

इन link files में target type, target MAC times, volume information और target path शामिल हो सकते हैं। यह metadata किसी removed target की पहचान करने में सहायता कर सकता है, लेकिन artifact अपने-आप में यह प्रमाण नहीं है कि target किसी विशेष user ने खोला था।<sup>[[13]](#references)[[14]](#references)</sup>

LNK के अपने filesystem timestamps और उसमें embedded target timestamps अलग-अलग होते हैं। Corroborating artifacts के बिना link creation को first use या link modification को last use न मानें; format target timestamps को link file के timestamps से अलग store करता है।<sup>[[13]](#references)[[14]](#references)</sup>

मौजूदा [**LinkParser**](http://4discovery.com/our-tools/) link को historical option के रूप में रखा गया है, लेकिन review के दौरान इसका documentation उपलब्ध नहीं था। Documented command-line parser के लिए [**LECmd**](https://github.com/EricZimmerman/LECmd) का उपयोग करें।<sup>[[15]](#references)</sup>

ये tools सामान्यतः timestamps के दो sets दिखाते हैं:

- **Target timestamps:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Link-file timestamps:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

पहला set target को संदर्भित करता है; दूसरा set स्वयं LNK file को संदर्भित करता है। दोनों की व्याख्या parser के documentation और filesystem context के आधार पर करें।<sup>[[14]](#references)[[15]](#references)</sup>

आप Windows CLI tool [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) चलाकर भी यही जानकारी प्राप्त कर सकते हैं।<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
इस मामले में, जानकारी एक CSV फ़ाइल के अंदर सहेजी जाएगी।

### Jumplists

Jump Lists प्रति-application हाल की या task-specific items की सूचियाँ होती हैं और automatic या custom हो सकती हैं।<sup>[[13]](#references)</sup>

Automatic Jump Lists `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` में संग्रहीत होती हैं और `{id}.automaticDestinations-ms` जैसे नामों का उपयोग करती हैं, जहाँ ID application की पहचान करती है।

Custom Jump Lists `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\` में संग्रहीत होती हैं; application यह नियंत्रित करती है कि वह कौन-सी task या item entries बनाए।

Filesystem द्वारा बनाए और संशोधित किए गए समय Jump List फ़ाइल का वर्णन करते हैं, न कि स्वचालित रूप से सूचीबद्ध प्रत्येक target के पहले और अंतिम access का। Parsed entries को फ़ाइल के timestamps और अन्य artifacts के साथ correlate करें।<sup>[[13]](#references)</sup>

आप [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) का उपयोग करके Jump Lists का निरीक्षण कर सकते हैं।<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: आप JumplistExplorer का उपयोग करके jumplists का निरीक्षण कर सकते हैं](<../../../images/image (168).png>)

(_ध्यान दें कि JumplistExplorer द्वारा दिए गए timestamps स्वयं jumplist फ़ाइल से संबंधित हैं_)

### Shellbags

[**shellbags क्या हैं, यह जानने के लिए इस link का अनुसरण करें।**](interesting-windows-registry-keys.md#shellbags)

## Windows USBs का उपयोग

USB के उपयोग की कभी-कभी removable media से files access किए जाने पर बनाए गए artifacts के माध्यम से पुष्टि की जा सकती है, जिनमें शामिल हैं:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

[**USBDetective**](https://usbdetective.com) जैसे tools इन artifacts को USB device records के साथ correlate करते हैं, लेकिन artifact की उपलब्धता Windows version और application पर निर्भर करती है।<sup>[[18]](#references)</sup>

Windows XP और Windows 7 MTP workflows के लिए documented testing में, कुछ LNKs original path के बजाय `WPDNSE` folder की ओर संकेत कर रहे थे।<sup>[[16]](#references)</sup>

![Shellbags - Windows USBs का उपयोग: ध्यान दें कि कुछ LNK files original path की ओर संकेत करने के बजाय WPDNSE folder की ओर संकेत करती हैं](<../../../images/image (218).png>)

उस study में `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` के अंदर copies देखी गईं; उसके tests में temporary contents restart के बाद सुरक्षित नहीं रहे, और GUID को shellbag data के साथ correlate किया जा सका। इसे universal rule के बजाय OS-, device- और application-dependent behavior मानें।<sup>[[16]](#references)</sup>

### Registry Information

[यह जानने के लिए इस page को देखें](interesting-windows-registry-keys.md#usb-information) कि कौन-सी registry keys USB से connected devices के बारे में महत्वपूर्ण information रखती हैं।

### setupapi

Vista और उसके बाद के versions में device-installation activity के लिए `C:\Windows\inf\setupapi.dev.log` का निरीक्षण करें। Section headers में `Section start` timestamps शामिल होते हैं; ये setup processing को document करते हैं और इन्हें exact physical insertion time मानने के बजाय अन्य connection evidence के साथ correlate किया जाना चाहिए।<sup>[[17]](#references)</sup>

![Registry Information - setupapi: USB connection कब बनाया गया, इसके timestamps प्राप्त करने के लिए C: Windows inf setupapi.dev.log फ़ाइल देखें (Section start खोजें)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) का उपयोग image से connected रह चुके USB devices के बारे में information प्राप्त करने के लिए किया जा सकता है।<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective का उपयोग image से connected रह चुके USB devices के बारे में information प्राप्त करने के लिए किया जा सकता है](<../../../images/image (452).png>)

### Plug and Play Cleanup

`Plug and Play Cleanup` नामक scheduled task पुराने driver versions को हटा देता है। Adam Harrison द्वारा documented Windows 10 task definition उन drivers को भी target करती है जो 30 दिनों से inactive हैं, इसलिए removable-device driver evidence साफ़ किया जा सकता है; इस behavior को generalize करने से पहले local task definition और Windows build की पुष्टि करें।<sup>[[1]](#references)</sup>

यह task निम्नलिखित path पर स्थित है: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

**Task के मुख्य Components और Settings:**

- **pnpclean.dll**: यह DLL वास्तविक cleanup process के लिए ज़िम्मेदार है।
- **UseUnifiedSchedulingEngine**: `TRUE` पर set है, जो generic task scheduling engine के उपयोग को दर्शाता है।
- **MaintenanceSettings**:
- **Period ('P1M')**: Task Scheduler को नियमित Automatic maintenance के दौरान cleanup task monthly शुरू करने का निर्देश देता है।
- **Deadline ('P2M')**: यदि task लगातार दो months तक fail हो, तो Task Scheduler को emergency Automatic maintenance के दौरान task execute करने का निर्देश देता है।

यह configuration नियमित maintenance schedule करती है और लगातार failures के बाद retry करती है; exact XML और behavior version-dependent हैं।<sup>[[1]](#references)</sup>

**अधिक information के लिए देखें:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)।<sup>[[1]](#references)</sup>

## Emails

Emails में email के **2 महत्वपूर्ण parts: headers और content** होते हैं। **headers** में आपको निम्न जैसी information मिल सकती है:

- Emails किसने भेजे (email address, IP, वे mail servers जिन्होंने email redirect किया)
- Email कब भेजा गया

इसके अलावा, `References` और `In-Reply-To` headers conversation के साथ replies को associate करने के लिए उपयोग किए जाने वाले message IDs रख सकते हैं।<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emails: Email कब भेजा गया](<../../../images/image (593).png>)

### Windows Mail App

यह application email content को `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` जैसे paths के अंतर्गत auxiliary text या HTML files में save करती है; exact numbered folder और file layout artifact के अनुसार अलग हो सकते हैं।<sup>[[75]](#references)</sup>

Emails का **metadata** और **contacts**, **ESE database** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` के अंदर पाए जा सकते हैं।<sup>[[75]](#references)</sup>

`store.vol` Extensible Storage Engine (ESE) format का उपयोग करता है। एक copy पर काम करें और [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) जैसे ESE parser का उपयोग करें; यदि किसी tool को `.edb` suffix की आवश्यकता हो, तो केवल copy का नाम बदलें और `Message` table पर निर्भर रहने से पहले table schema verify करें।<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Outlook MAPI properties का निरीक्षण करते समय, canonical properties में शामिल हैं:

- `PidTagClientSubmitTime`: वह UTC time जब client ने message submit किया।
- `PidTagConversationIndex`: conversation thread में message की relative position।
- `PidTagEntryId`: message object के लिए identifier।
- `PidTagMessageFlags`: submitted, read, unread या attachments होने जैसे status flags।
- `PidTagLastVerbExecuted`: message के लिए record किया गया अंतिम operation, जैसे open, reply या forward।<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlook data-file locations version और account type के अनुसार अलग होते हैं। Microsoft PST/OST files के लिए ये common locations document करता है:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Registry path `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` Outlook profile और संबंधित data-file configuration की पहचान कर सकता है।

PST files में messages, contacts, calendar data और अन्य Outlook items हो सकते हैं। आप [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) से एक copy का निरीक्षण कर सकते हैं।<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: आप Kernel PST Viewer tool का उपयोग करके PST file खोल सकते हैं](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST file** Exchange या Microsoft 365 accounts के लिए एक local cache होती है; Cached Exchange Mode POP या IMAP accounts पर लागू नहीं होता। Offline period configurable होता है और अक्सर default रूप से 12 months होता है, जबकि PST/OST size limits अलग configurable settings होती हैं। OST file देखने के लिए [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) का उपयोग किया जा सकता है।<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Retrieving Attachments

Lost attachments निम्न locations से recover किए जा सकते हैं:

- Legacy Outlook/IE configurations के लिए: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Newer Outlook/IE11 configurations के लिए: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`।<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** profile data को `%APPDATA%\Thunderbird\Profiles` के अंतर्गत store करता है; mail folders आमतौर पर account-specific `Mail` या `ImapMail` directories के अंतर्गत बिना extension वाली mbox files का उपयोग करते हैं।<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: Thumbnail previews आमतौर पर प्रति-folder `thumbs.db` files में store किए जाते थे।
- **Network folders**: संबंधित thumbnail behavior enabled होने पर UNC folder के लिए `thumbs.db` file अभी भी बनाई जा सकती है; यह assume न करें कि प्रत्येक Windows version या policy इसे create करती है।
- **Windows Vista और newer**: System thumbnail cache `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` के अंतर्गत centralized होता है और इसमें **thumbcache_xxx.db** जैसी files होती हैं। [**Thumbsviewer**](https://thumbsviewer.github.io) legacy `Thumbs.db` को parse कर सकता है, जबकि [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) modern thumbnail-cache databases को parse कर सकता है।<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Information

Windows Registry, जिसमें system और user configuration data store होता है, निम्न locations में hive files के अंदर होती है:

- `%WINDIR%\System32\Config` विभिन्न `HKEY_LOCAL_MACHINE` subkeys को support करने वाले machine hives के लिए।
- `%USERPROFILE%\NTUSER.DAT` user की `HKEY_CURRENT_USER` hive के लिए।
- कुछ पुराने Windows installations में `%WINDIR%\System32\Config\RegBack\` के अंदर copies होती हैं; Windows 10 version 1803 और बाद के versions इस directory को automatically populate नहीं करते, जब तक periodic backup enabled न हो।<sup>[[34]](#references)[[35]](#references)</sup>
- Per-user shell और class-registration data modern Windows में आमतौर पर `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` में भी store होता है।<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

कुछ tools registry hives का analysis करने के लिए उपयोगी हैं; किसी output पर निर्भर करने से पहले प्रत्येक tool के supported hive formats और version की पुष्टि करें:

- **Registry Editor**: यह Windows में installed होता है। यह current session की Windows registry में navigate करने के लिए GUI है।
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): यह आपको registry file load करने और GUI के माध्यम से उसमें navigate करने देता है। इसमें interesting information वाली keys को highlight करने वाले Bookmarks भी होते हैं।
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): इसमें भी एक GUI है, जो loaded registry में navigate करने देती है और इसमें loaded registry के अंदर interesting information को highlight करने वाले plugins भी होते हैं।
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): loaded registry hive से information extract करने में सक्षम एक अन्य GUI application।<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Recovering Deleted Element

Deleted hive cells तब तक मौजूद रह सकती हैं जब तक उनका space reuse न हो जाए, लेकिन recovery hive state और parser पर निर्भर करती है; recovered deleted keys को guaranteed records के बजाय validation आवश्यक evidence मानें।

### Last Write Time

Registry keys में last-write timestamp होता है; Windows इसे key या उसकी किसी value entry के लिए expose करता है, इसलिए किसी value का अपना independent modification timestamp आवश्यक नहीं होता।<sup>[[69]](#references)</sup>

### SAM

**SAM** hive में local user और group account data होता है, जिसमें system की boot-key material द्वारा protected password hashes भी शामिल हैं।<sup>[[38]](#references)[[39]](#references)</sup>

`SAM\Domains\Account\Users` में आप account identifiers और कुछ logon तथा policy fields प्राप्त कर सकते हैं। Offline hash extraction के लिए संबंधित boot-key material recover करने हेतु `SYSTEM` hive की भी आवश्यकता होती है।<sup>[[38]](#references)[[39]](#references)</sup>

### Windows Registry में Interesting entries


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

[common Windows processes पर मौजूदा post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) अतिरिक्त reading के रूप में रखा गया है; किसी भी process-behavior claims को current Windows documentation और local evidence के साथ corroborate करें।<sup>[[2]](#references)</sup>

### Windows Recent APPs

Windows 10 के उन versions पर जहाँ यह उपलब्ध है, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` में प्रति-application subkeys होती हैं, जिनमें last-used time और launch count जैसे fields होते हैं; यह artifact बाद के releases से हटा दिया गया था, इसलिए target build को validate करें।<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

जिन systems पर Background Activity Moderator उपलब्ध है, वहाँ `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` या नया `...\bam\State\UserSettings\{SID}` path inspect करें। Values user SID के अनुसार keyed होती हैं और इनमें tracked executable paths तथा FILETIME-like execution data हो सकता है; यह artifact version-dependent है और इसे अन्य evidence के साथ corroborate किया जाना चाहिए।<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetching resources और launch metadata को cache करती है, ताकि programs अधिक तेज़ी से start हो सकें।

Prefetch files `C:\Windows\Prefetch` में `.pf` files के रूप में store होती हैं; format, retention और file-count limits Windows version के अनुसार अलग होती हैं। Microsoft Windows 8 और बाद के versions में last eight execution times और अधिकतम 1024 files की retention document करता है, इसलिए पुराने fixed-limit summaries को generalize नहीं किया जाना चाहिए।<sup>[[13]](#references)</sup>

Filename आमतौर पर `{program_name}-{hash}.pf` format का उपयोग करता है, जिसमें hash path और arguments जैसे execution context से derived होता है; Windows 10 और बाद के versions file को compress कर सकते हैं। Presence उपयोगी execution evidence है, लेकिन यह अपने-आप में user execution का proof नहीं है और इसे अन्य artifacts के साथ correlate किया जाना चाहिए।<sup>[[13]](#references)</sup>

इन files का निरीक्षण करने के लिए आप [**PECmd.exe**](https://github.com/EricZimmerman/PECmd) का उपयोग कर सकते हैं, जो applicable Windows 10 Prefetch files के लिए directory parsing, CSV/HTML output और decompression support document करता है।<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain**, लोडिंग को बेहतर बनाने के लिए ऐतिहासिक उपयोग पैटर्न का इस्तेमाल करके Prefetch का पूरक बनता है। इन्हें बनाने वाले सिस्टम में, इसकी database files आमतौर पर `C:\Windows\Prefetch\Ag*.db` में मिलती हैं; इनका format और उपलब्धता version पर निर्भर करता है।<sup>[[41]](#references)</sup>

इन databases में application names, usage counts, accessed files या volumes, paths और time ranges शामिल हो सकते हैं, लेकिन इन्हें exact execution log नहीं माना जाना चाहिए।<sup>[[41]](#references)</sup>

मौजूदा [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) link को संभावित parser के रूप में रखा गया है; इस्तेमाल से पहले tool के documentation के अनुसार इसकी वर्तमान उपलब्धता और supported output की पुष्टि करें।

### SRUM

**System Resource Usage Monitor** (SRUM), applications और users द्वारा resource use को record करता है। इसे Windows 8 में पेश किया गया था और यह data को ESE database `C:\Windows\System32\sru\SRUDB.dat` में store करता है।<sup>[[13]](#references)</sup>

यह निम्नलिखित जानकारी देता है:

- AppID और Path
- Record से संबंधित User/SID
- भेजे गए Bytes
- प्राप्त किए गए Bytes
- Network Interface
- Connection duration
- Process duration

Collection cadence और retention implementation पर निर्भर करते हैं; यह न मानें कि प्रत्येक record exact 60-minute execution interval को दर्शाता है।<sup>[[13]](#references)</sup>

आप वर्तमान tool version में documented options का उपयोग करके [**srum_dump**](https://github.com/MarkBaggett/srum-dump) से data extract और review कर सकते हैं।<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

**AppCompatCache**, जिसे **ShimCache** के नाम से भी जाना जाता है, Windows application-compatibility infrastructure का हिस्सा है और compatibility decisions के लिए file metadata रिकॉर्ड करता है। hive path, record format, retained capacity और fields Windows release के अनुसार अलग-अलग होते हैं; modern Windows पर केवल ShimCache यह साबित नहीं कर सकता कि किसी user ने file execute की थी। संबंधित `SYSTEM` hive को [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) से parse करें और इसके output की पुष्टि execution artifacts से करें।<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): संग्रहीत जानकारी को parse करने के लिए AppCompatCacheParser tool का उपयोग करने की अनुशंसा की जाती है](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** file एक registry hive है, जो Windows द्वारा देखे गए applications और files की inventory रखती है। यह आमतौर पर `C:\Windows\AppCompat\Programs\Amcache.hve` पर मिलती है।

इसमें associated और unassociated file entries, paths और SHA1 values शामिल हो सकते हैं, लेकिन इसकी उपस्थिति inventory evidence है और अपने-आप यह साबित नहीं करती कि किसी process को execute किया गया था।<sup>[[13]](#references)[[44]](#references)</sup>

**Amcache.hve** को extract और analyze करने के लिए [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool का उपयोग करें। यह command hive को parse करती है और CSV output लिखती है।<sup>[[44]](#references)</sup>

उदाहरण के लिए:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
दिए गए CSV files में, `Amcache_Unassociated file entries` उन files की जांच करते समय उपयोगी हो सकती हैं जो किसी पहचाने गए program से associated नहीं हैं।<sup>[[44]](#references)</sup>

### RecentFileCache

Windows 7 systems पर, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` में हाल ही में देखे गए binaries की जानकारी हो सकती है; इसकी availability और semantics version पर निर्भर करती हैं।

आप file को parse करने के लिए [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) का उपयोग कर सकते हैं।<sup>[[45]](#references)</sup>

### Scheduled tasks

Scheduled-task evidence आधुनिक tasks के लिए `C:\Windows\System32\Tasks` में और legacy tasks के लिए `.job` files के साथ `C:\Windows\Tasks` में मिल सकता है; OS के लिए उपयुक्त task definition format की जांच करें।<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Service Control Manager database `SYSTEM\CurrentControlSet\Services` के अंतर्गत होता है (offline SYSTEM hive के लिए, संबंधित control-set key की जांच करें); इसमें executable paths और start types जैसे service और driver configuration शामिल होते हैं।<sup>[[72]](#references)</sup>

### **Windows Store**

Installed Windows Store applications `\ProgramData\Microsoft\Windows\AppRepository\` के अंतर्गत दिखाई दे सकती हैं, जिसमें database **`StateRepository-Machine.srd`** भी शामिल है। Schema और paths Windows release के अनुसार अलग-अलग होते हैं।<sup>[[71]](#references)</sup>

Database में application identifiers, package numbers और display names हो सकते हैं। Identifiers में gaps अकेले इस बात का प्रमाण नहीं हैं कि कोई application uninstalled थी; package और registry state से corroborate करें।

Package registrations `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` के अंतर्गत भी दिखाई दे सकती हैं। Microsoft removed provisioned apps के लिए version-specific `Deprovisioned` subkey document करता है; यह न मानें कि हर build पर `Deleted` subkey मौजूद होती है।<sup>[[70]](#references)</sup>

## Windows Events

Provider के आधार पर, Windows events में निम्न जानकारी हो सकती है:

- क्या हुआ
- एक `TimeCreated` timestamp, जिसकी व्याख्या event schema और host time context के साथ करनी आवश्यक है
- शामिल users
- शामिल hosts (hostname, IP)
- Access की गई assets (files, folders, printers या services)।<sup>[[49]](#references)</sup>

Windows Vista से पहले, event logs सामान्यतः `C:\Windows\System32\config` के अंतर्गत legacy binary format का उपयोग करते थे; Vista और बाद के versions Windows Event Log format का उपयोग करते हैं, जो सामान्यतः `C:\Windows\System32\winevt\Logs` के अंतर्गत होता है और जिसमें `.evtx` files XML-rendered event data रखती हैं।<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM registry channel configuration को **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** के अंतर्गत store करता है, जिसमें configured file path और retention settings शामिल हैं।<sup>[[47]](#references)</sup>

इन्हें Windows Event Viewer (**`eventvwr.msc`**) या [**Event Log Explorer**](https://eventlogxp.com) और [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md) जैसे tools से देखा जा सकता है।<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

Vista और बाद के versions पर, Security channel सामान्यतः `C:\Windows\System32\winevt\Logs\Security.evtx` में store होता है। इसका maximum size और retention policy configurable होता है; circular logging के साथ, file अपनी limit तक पहुंचने पर पुराने records overwrite हो सकते हैं। Relevant auditing enabled होने पर channel authentication, logoff, privilege, audit-policy और object-access events record कर सकता है।<sup>[[46]](#references)[[47]](#references)</sup>

### Key Event IDs for User Authentication:

- **Event ID 4624**: Account logon सफल हुआ।<sup>[[50]](#references)</sup>
- **Event ID 4625**: Account logon विफल हुआ।<sup>[[51]](#references)</sup>
- **Event ID 4634**: Logon session समाप्त किया गया।<sup>[[52]](#references)</sup>
- **Event ID 4647**: User ने logoff शुरू किया।<sup>[[53]](#references)</sup>
- **Event ID 4672**: New logon को special privileges assign किए गए; यह system और administrator accounts के लिए सामान्य है, इसलिए यह अकेले malicious activity का प्रमाण नहीं है।<sup>[[54]](#references)</sup>

#### Logon types commonly recorded in 4624, 4625, 4634, and 4647:

- **Interactive (2)**: Interactive local logon।
- **Network (3)**: Shared resource तक access।
- **Batch (4)**: Batch-process logon।
- **Service (5)**: Service logon।
- **Unlock (7)**: Workstation unlock।
- **NetworkCleartext (8)**: ऐसा network logon जो authentication package को credentials cleartext में supply करता है।
- **NewCredentials (9)**: Outbound connections के लिए supplied alternate credentials का उपयोग करने वाला logon।
- **RemoteInteractive (10)**: Remote Desktop या Terminal Services logon।
- **CachedInteractive (11)**: Cached domain credentials का उपयोग करने वाला interactive logon।
- **CachedRemoteInteractive (12)**: Cached remote-interactive logon।
- **CachedUnlock (13)**: Cached credentials का उपयोग करके unlock।<sup>[[50]](#references)[[51]](#references)</sup>

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: ऐसा कोई user नहीं है।
- **0xC000006A**: User name सही है, लेकिन password गलत है।
- **0xC0000234**: Account locked out है।
- **0xC0000072**: Account disabled है।
- **0xC000006F**: Allowed hours के बाहर logon।
- **0xC0000070**: Workstation restriction violation।
- **0xC0000193**: Account expired है।
- **0xC0000071**: Password expired है।
- **0xC0000133**: Client और server के समय में अंतर बहुत अधिक है।
- **0xC0000224**: Account को अपना password बदलना आवश्यक है।
- **0xC0000225**: `STATUS_NOT_FOUND`; code अकेले किसी system bug या attack की पहचान नहीं करता।
- **0xC000015B**: Requested logon type account को granted नहीं है।<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: System time बदला गया। कई events routine time-service correction को दर्शाते हैं, इसलिए इसे tampering मानने से पहले actor और time source से correlate करें।<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008, and 6009:

- **Power and service context**: Event 12 OS start record करता है, 13 OS shutdown record करता है, 1074 planned shutdown या restart record करता है, 6008 unexpected shutdown दर्शाता है और 6009 boot के समय Windows version record करता है। Events 6005 और 6006 क्रमशः Event Log service के start और stop होने का संकेत देते हैं; ये स्वयं OS startup और shutdown का प्रमाण नहीं हैं।<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Event 1102 record करता है कि Security audit log clear किया गया; इस event से अकेले intent assume करने के बजाय actor और आसपास के events की जांच करें।<sup>[[62]](#references)</sup>

#### EventIDs for USB Device Tracking:

- **20001 / 20003**: `UserPnp` device-installation events, जो first-use या installation activity स्थापित करने में सहायता कर सकते हैं।
- **10000 / 10100**: `DriverFrameworks-UserMode` events, जो device activity के साथ दिखाई दे सकते हैं।
- **Event ID 112**: `DeviceSetupManager/Admin` activity, जो insertion-related timestamps प्रदान कर सकती है।
- Provider, channel और event semantics Windows version के अनुसार अलग-अलग होते हैं; meaning assign करने से पहले provider name और event payload की जांच करें।<sup>[[59]](#references)</sup>

Logon types और उनसे associated credential material के practical examples के लिए [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them) देखें।<sup>[[60]](#references)</sup>

Event details, जिनमें logon type, status, substatus, source address और process fields शामिल हैं, Event ID 4625 के लिए context प्रदान करते हैं; status code या repeated failure pattern investigative lead है, conclusion नहीं।<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

क्योंकि event logs सामान्यतः circular होते हैं, logger द्वारा overwrite किए गए records recover करना संभव नहीं हो सकता। Live system के साथ interaction करने से पहले forensic image या working copy preserve करें; **Bulk_extractor** जैसे validated parser या carver का उपयोग केवल यह confirm करने के बाद करें कि tool version target `.evtx` data को support करता है, और केवल events recover करने का प्रयास करने के लिए running system को unplug न करें।<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

Practical event-ID reference के लिए मौजूदा [Red Team Recipe](https://redteamrecipe.com/event-codes/) link देखें और इसके examples को ऊपर दिए गए provider documentation के विरुद्ध validate करें।

#### Brute Force Attacks

Repeated Event ID 4625 failures को बाद की 4624 success, logon type, status, source और account context के साथ correlate करें; sequence investigation का indicator है, attack का proof नहीं।<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616 system-time changes record करता है, जो timeline analysis को जटिल बना सकते हैं; इसकी तुलना time-service और host evidence से करें।<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB event IDs provider-specific होते हैं; `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 और `DeviceSetupManager/Admin` 112 को SetupAPI और registry artifacts के साथ correlate करें।<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

OS start, shutdown, restart और unexpected-power context के लिए 12/13/1074/6008/6009 का उपयोग करें; 6005/6006 Event Log service के start/stop को mark करते हैं।<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102 record करता है कि Security audit log clear किया गया और इसे responsible account और process के साथ correlate किया जाना चाहिए।<sup>[[62]](#references)</sup>

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Common Windows Processes की जांच](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Windows 10 Notifications का Digital Forensic View](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman forensic tools](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier और Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [VSS के अंतर्गत Registry backup और restore operations](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Backup और restore के लिए Registry keys](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [AutoRecover location पर Word performance issue](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Incident Response Guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: Data Exfiltration Artifacts की पहचान](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI device installation log entries](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID और Related Types](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Outlook data files को ढूंढना और transfer करना](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Cached Exchange Mode को turn on करना](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [केवल items का एक subset synchronized है](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Outlook data files के लिए size limits configure करना](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Thunderbird user data को कहां store करता है](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird account settings और mbox directories](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registry का RegBack में backup नहीं लिया जाता](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Registry को remotely edit करना](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Passwords technical overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch evidence](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Event Log File Format](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog registry key](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated event property](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [System event logs का उपयोग करके unexpected reboots का troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Shutdown in process का troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Windows 10 के लिए USB Storage Device Forensics](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Background activity moderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Windows Desktop के Outlook में Quick Print द्वारा PDF attachments की printing रुकना](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Registry files](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Update के दौरान removed apps को वापस आने से रोकना](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTK और Registry Viewer Test Results](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Database of Installed Services](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Scheduled Tasks Error Task Scheduler Service Is Not Available के साथ fail होती हैं](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Windows Mail database को navigate करना](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
