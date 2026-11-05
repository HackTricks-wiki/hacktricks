# Windows आर्टिफैक्ट्स

{{#include ../../../banners/hacktricks-training.md}}

## सामान्य Windows आर्टिफैक्ट्स

### Windows 10 सूचनाएँ

प्रति-उपयोगकर्ता सूचना डेटाबेस `%LOCALAPPDATA%\Microsoft\Windows\Notifications` के अंतर्गत होता है (उदाहरण के लिए, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`)। Windows 10 के शुरुआती रिलीज़ में `appdb.dat` का इस्तेमाल होता था; Anniversary Update (1607) में `wpndatabase.db` आया। SQLite डेटाबेस में notification payloads और समय-संबंधी फ़ील्ड वाला `Notification` टेबल शामिल होता है, हालाँकि डेटा का प्रतिधारण और उपलब्धता रिलीज़ तथा cleanup policy के अनुसार अलग-अलग होती है।<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline एक activity-history सुविधा है, जिसमें समर्थित applications, documents और उपयोगकर्ता की अन्य गतिविधियों के रिकॉर्ड हो सकते हैं; इसका दायरा application और Windows version पर निर्भर करता है।<sup>[[4]](#references)</sup>

यह डेटाबेस `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` पर मौजूद होता है। इसे SQLite से खोला जा सकता है या [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) से parse किया जा सकता है; इसके output की समीक्षा [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md) से की जा सकती है।<sup>[[4]](#references)[[5]](#references)</sup>

### Windows Recall snapshots (Copilot+ PCs)

समर्थित Windows 11 Copilot+ PCs पर Recall वैकल्पिक है। मौजूदा builds में snapshots और उनका index, Windows Hello तथा VBS enclave से जुड़ी keys से encrypt किए जाते हैं। Store की offline copy को plaintext SQLite database न मानें; 2024 preview और जारी किए गए design में access की विशेषताएँ अलग-अलग हैं।<sup>[[77]](#references)</sup>

**सक्रिय, enabled Recall session** में, उसी उपयोगकर्ता की `AIXHost.exe` rendering process एक अलग access surface है। TotalRecall Reloaded proof of concept उस process में DLL inject करता है और उसके Recall COM interfaces को call करता है। पूरी history निकालने के लिए उपयोगकर्ता को अब भी Windows Hello से authenticate करना पड़ता है; यह offline decryption या Hello bypass नहीं है। शोधकर्ता ने Windows 11 ARM64 पर इस tool का दस्तावेज़ीकरण किया है, इसलिए इस पर निर्भर होने से पहले target build के साथ इसकी compatibility जाँच लें।<sup>[[78]](#references)[[77]](#references)</sup>

```powershell
totalrecall.exe --preauth  # Most recent capture and settings; no Hello prompt
totalrecall.exe --wait     # Wait for the user to open Recall and authenticate
```

`--preauth` का उपयोग `GetRecentCaptureThumbnail` के ज़रिए Hello के बिना नवीनतम capture का बड़ा rendition अनुरोध करने के लिए होता है। Authorization के बाद, `--wait` screenshots, OCR text और प्रति-capture metadata निकाल सकता है, जिसमें application और window context शामिल हैं। आउटपुट timestamp वाले `extraction_*` directory में लिखा जाता है। ये proof of concept से प्राप्त build-dependent निष्कर्ष हैं; इनसे यह गारंटी नहीं मिलती कि Recall enabled है या हर screen capture की गई थी।<sup>[[78]](#references)</sup>

### ADS (Alternate Data Streams)

स्थानीय trust boundary के बाहर से download की गई files में **`Zone.Identifier` alternate data stream** हो सकती है, जो zone की जानकारी दर्ज करती है और इसमें URL जैसे origin metadata शामिल हो सकते हैं। इसकी मौजूदगी और fields, producer और system policy पर निर्भर करते हैं।<sup>[[6]](#references)</sup>

## **File Backups**

### Recycle Bin

Vista और उसके बाद के versions में, **Recycle Bin** drive के root में मौजूद **`$Recycle.bin`** folder में पाया जा सकता है (उदाहरण के लिए, `C:\$Recycle.bin`)।\
इस folder में कोई file delete करने पर 2 specific files बनाई जाती हैं:

- `$I{id}`: File की जानकारी, जिसमें deletion time और original path शामिल हैं
- `$R{id}`: File का content

![File Backups - Recycle Bin: $R{id}: File का content](<../../../images/image (1029).png>)

इन files से, original path और deletion time निकालने के लिए [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) का उपयोग किया जा सकता है (target Windows release के अनुसार उपयुक्त version इस्तेमाल करें)।<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![फ़ाइल बैकअप - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### वॉल्यूम शैडो कॉपीज़

Volume Shadow Copy Service (VSS), फ़ाइलों के उपयोग में होने के दौरान वॉल्यूम की किसी निश्चित समय की शैडो कॉपी बना सकती है; शैडो कॉपी फॉरेंसिक इमेज का विकल्प नहीं है।<sup>[[8]](#references)</sup>

कॉपी का मेटाडेटा आम तौर पर वॉल्यूम के रूट पर मौजूद `\System Volume Information` से जुड़ा होता है; इसके आइडेंटिफ़ायर सिस्टम के अनुसार अलग-अलग होते हैं:

![Recycle Bin - वॉल्यूम शैडो कॉपीज़: ये बैकअप आम तौर पर फ़ाइल सिस्टम के रूट में मौजूद System Volume Information में होते हैं और इनके नाम UID से बने होते हैं, जो...](<../../../images/image (94).png>)

उपयुक्त फॉरेंसिक माउंटर से इमेज माउंट करने के बाद, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) उपलब्ध VSS स्नैपशॉट की सूची दिखा सकता है और उनमें फ़ाइलें ब्राउज़ या कॉपी कर सकता है।<sup>[[9]](#references)</sup>

![Recycle Bin - वॉल्यूम शैडो कॉपीज़: फॉरेंसिक इमेज को ArsenalImageMounter से माउंट करने पर, ShadowCopyView टूल का उपयोग शैडो कॉपी की जाँच करने और उसमें से फ़ाइलें निकालने के लिए भी किया जा सकता है...](<../../../images/image (576).png>)

VSS registry writer configuration में `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` शामिल है, जो उन फ़ाइलों और keys को निर्दिष्ट कर सकता है जिन्हें बैकअप से बाहर रखा गया है:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - वॉल्यूम शैडो कॉपीज़: registry entry HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore में वे फ़ाइलें और keys होती हैं जिनका बैकअप नहीं लेना है](<../../../images/image (254).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` key में भी VSS service configuration होती है।<sup>[[8]](#references)</sup>

### Office की AutoSaved फ़ाइलें

AutoRecover के स्थान Office application, version और configuration के अनुसार अलग-अलग होते हैं। Word के लिए, Microsoft `%APPDATA%\Microsoft\Word` को डिफ़ॉल्ट स्थान बताता है; सक्रिय path जानने के लिए application settings देखें।<sup>[[12]](#references)</sup>

## Shell Items

Shell item में किसी अन्य फ़ाइल तक पहुँचने के बारे में जानकारी होती है।

### हाल के दस्तावेज़ (LNK)

Windows में, उपयोगकर्ता द्वारा किसी item को खोलने या किसी अन्य तरीके से उस तक पहुँचने पर, आम तौर पर हाल ही के items के shortcuts बनाए जाते हैं:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

फ़ोल्डर तक पहुँचने पर उस फ़ोल्डर और उससे जुड़े parent folders के links भी बन सकते हैं।

इन link फ़ाइलों में target का type, target के MAC times, volume की जानकारी और target path शामिल हो सकते हैं। यह मेटाडेटा हटाए गए target की पहचान करने में मदद कर सकता है, लेकिन यह artifact अपने आप में इस बात का प्रमाण नहीं है कि किसी खास उपयोगकर्ता ने target खोला था।<sup>[[13]](#references)[[14]](#references)</sup>

LNK के अपने filesystem timestamps और उसमें मौजूद target timestamps अलग-अलग होते हैं। जब तक अन्य artifacts से पुष्टि न हो, link बनने को पहली बार उपयोग किए जाने के रूप में या link में बदलाव को आखिरी बार उपयोग किए जाने के रूप में न समझें; format, target timestamps को link फ़ाइल के timestamps से अलग संग्रहीत करता है।<sup>[[13]](#references)[[14]](#references)</sup>

मौजूदा [**LinkParser**](http://4discovery.com/our-tools/) link को ऐतिहासिक विकल्प के रूप में बरकरार रखा गया है, लेकिन समीक्षा के दौरान इसका documentation उपलब्ध नहीं था। दस्तावेज़ीकृत command-line parser के लिए, [**LECmd**](https://github.com/EricZimmerman/LECmd) का उपयोग करें।<sup>[[15]](#references)</sup>

ये टूल आम तौर पर timestamps के दो सेट दिखाते हैं:

- **Target timestamps:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **Link-file timestamps:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

पहला सेट target से संबंधित है; दूसरा सेट स्वयं LNK फ़ाइल से संबंधित है। दोनों की व्याख्या parser के documentation और filesystem के संदर्भ में करें।<sup>[[14]](#references)[[15]](#references)</sup>

आप Windows CLI tool [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) चलाकर भी वही जानकारी प्राप्त कर सकते हैं।<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

इस मामले में, जानकारी को CSV फ़ाइल में सहेजा जाएगा।

### Jumplists

Jump Lists प्रति-एप्लिकेशन हाल ही में उपयोग किए गए या कार्य-विशिष्ट आइटम की सूचियाँ होती हैं। ये स्वचालित या कस्टम हो सकती हैं।<sup>[[13]](#references)</sup>

स्वचालित Jump Lists `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` में संग्रहीत होती हैं और इनके नाम `{id}.automaticDestinations-ms` जैसे होते हैं, जहाँ ID एप्लिकेशन की पहचान करती है।

कस्टम Jump Lists `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\` में संग्रहीत होती हैं; एप्लिकेशन नियंत्रित करता है कि वह कौन-सी कार्य या आइटम प्रविष्टियाँ बनाता है।

फ़ाइल सिस्टम के निर्माण और संशोधन समय Jump List फ़ाइल के बारे में बताते हैं, न कि सूची में शामिल हर लक्ष्य तक पहली और आखिरी पहुँच के बारे में। पार्स की गई प्रविष्टियों का फ़ाइल के टाइमस्टैम्प और अन्य आर्टिफ़ैक्ट से मिलान करें।<sup>[[13]](#references)</sup>

आप [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) का उपयोग करके Jump Lists का निरीक्षण कर सकते हैं।<sup>[[5]](#references)</sup>

![हाल के दस्तावेज़ (LNK) - Jumplists: आप JumplistExplorer का उपयोग करके jumplists का निरीक्षण कर सकते हैं](<../../../images/image (168).png>)

(_ध्यान दें कि JumplistExplorer द्वारा दिए गए टाइमस्टैम्प स्वयं jumplist फ़ाइल से संबंधित हैं_)

### Shellbags

[**Shellbags क्या हैं, यह जानने के लिए इस लिंक पर जाएँ।**](interesting-windows-registry-keys.md#shellbags)

## Windows USBs का उपयोग

कभी-कभी removable media से फ़ाइलों तक पहुँचने पर बने आर्टिफ़ैक्ट से USB के उपयोग की पुष्टि की जा सकती है। इनमें शामिल हैं:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

[**USBDetective**](https://usbdetective.com) जैसे टूल इन आर्टिफ़ैक्ट का USB डिवाइस रिकॉर्ड से मिलान करते हैं, लेकिन आर्टिफ़ैक्ट की उपलब्धता Windows संस्करण और एप्लिकेशन पर निर्भर करती है।<sup>[[18]](#references)</sup>

Windows XP और Windows 7 MTP workflows के लिए किए गए परीक्षणों में, कुछ LNK मूल पथ के बजाय `WPDNSE` फ़ोल्डर की ओर संकेत करते थे।<sup>[[16]](#references)</sup>

![Shellbags - Windows USBs का उपयोग: ध्यान दें कि कुछ LNK फ़ाइलें मूल पथ के बजाय WPDNSE फ़ोल्डर की ओर संकेत करती हैं](<../../../images/image (218).png>)

उस अध्ययन में `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` के अंतर्गत प्रतियाँ मिलीं; उसके परीक्षणों में अस्थायी सामग्री restart के बाद मौजूद नहीं रही, और GUID का मिलान shellbag डेटा से किया जा सका। इसे OS, डिवाइस और एप्लिकेशन पर निर्भर व्यवहार मानें, न कि सार्वभौमिक नियम।<sup>[[16]](#references)</sup>

### Registry Information

[यह जानने के लिए यह पृष्ठ देखें](interesting-windows-registry-keys.md#usb-information) कि USB से जुड़े डिवाइसों के बारे में कौन-सी registry keys में उपयोगी जानकारी होती है।

### setupapi

Vista और उसके बाद के संस्करणों में, डिवाइस-इंस्टॉलेशन गतिविधि के लिए `C:\Windows\inf\setupapi.dev.log` देखें। सेक्शन हेडर में `Section start` टाइमस्टैम्प शामिल होते हैं; ये setup processing का रिकॉर्ड रखते हैं। इन्हें अन्य कनेक्शन-साक्ष्यों के साथ मिलाकर देखें, न कि डिवाइस को भौतिक रूप से लगाने के सटीक समय के रूप में।<sup>[[17]](#references)</sup>

![Registry Information - setupapi: USB कनेक्शन कब हुआ, इसके टाइमस्टैम्प पाने के लिए C: Windows inf setupapi.dev.log फ़ाइल देखें (Section start खोजें)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

किसी image से जुड़े USB डिवाइसों के बारे में जानकारी पाने के लिए [**USBDetective**](https://usbdetective.com) का उपयोग किया जा सकता है।<sup>[[18]](#references)</sup>

![setupapi - USB Detective: किसी image से जुड़े USB डिवाइसों के बारे में जानकारी पाने के लिए USBDetective का उपयोग किया जा सकता है](<../../../images/image (452).png>)

### Plug and Play Cleanup

`Plug and Play Cleanup` नाम का scheduled task पुराने driver versions को हटाता है। Adam Harrison द्वारा प्रलेखित Windows 10 task definition उन drivers को भी लक्षित करती है जो 30 दिनों से निष्क्रिय हों। इसलिए removable-device driver के साक्ष्य साफ़ हो सकते हैं; इस व्यवहार को सामान्य मानने से पहले स्थानीय task definition और Windows build की पुष्टि करें।<sup>[[1]](#references)</sup>

यह task इस पथ पर मौजूद है: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`।

![Windows Plug and Play Cleanup scheduled task की XML definition](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Task के प्रमुख घटक और सेटिंग्स:**

- **pnpclean.dll**: यह DLL वास्तविक cleanup प्रक्रिया के लिए ज़िम्मेदार है।
- **UseUnifiedSchedulingEngine**: इसे `TRUE` पर सेट किया गया है, जो generic task scheduling engine के उपयोग को दर्शाता है।
- **MaintenanceSettings**:
  - **Period ('P1M')**: Task Scheduler को नियमित Automatic maintenance के दौरान हर महीने cleanup task शुरू करने का निर्देश देता है।
  - **Deadline ('P2M')**: यदि task लगातार दो महीनों तक विफल रहता है, तो Task Scheduler को emergency Automatic maintenance के दौरान task चलाने का निर्देश देता है।

यह कॉन्फ़िगरेशन नियमित maintenance और लगातार विफलताओं के बाद पुनः प्रयास निर्धारित करती है; सटीक XML और व्यवहार संस्करण पर निर्भर करते हैं।<sup>[[1]](#references)</sup>

**अधिक जानकारी के लिए देखें:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Emails

Emails में **2 उपयोगी हिस्से होते हैं: headers और email की सामग्री**। **headers** में आपको ऐसी जानकारी मिल सकती है:

- Emails **किसने** भेजे (email address, IP, वे mail servers जिन्होंने email को redirect किया)
- Email **कब** भेजा गया

इसके अलावा, `References` और `In-Reply-To` headers में ऐसे message IDs हो सकते हैं जिनका उपयोग replies को किसी conversation से जोड़ने के लिए किया जाता है।<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emails: Email कब भेजा गया](<../../../images/image (593).png>)

### Windows Mail App

यह एप्लिकेशन email की सामग्री को सहायक text या HTML फ़ाइलों में, `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` जैसे पथों के अंतर्गत सहेजता है; सटीक numbered folder और file layout आर्टिफ़ैक्ट के अनुसार अलग हो सकता है।<sup>[[75]](#references)</sup>

Emails का **metadata** और **contacts**, **ESE database** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` में मिल सकते हैं।<sup>[[75]](#references)</sup>

`store.vol` में Extensible Storage Engine (ESE) format का उपयोग होता है। इसकी एक copy पर काम करें और [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) जैसे ESE parser का उपयोग करें; यदि किसी टूल को `.edb` suffix की आवश्यकता हो, तो केवल copy का नाम बदलें। `Message` table पर भरोसा करने से पहले table schema की पुष्टि करें।<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Outlook MAPI properties का निरीक्षण करते समय, canonical properties में ये शामिल हैं:

- `PidTagClientSubmitTime`: वह UTC समय जब client ने message जमा किया।
- `PidTagConversationIndex`: conversation thread में message की सापेक्ष स्थिति।
- `PidTagEntryId`: message object का identifier।
- `PidTagMessageFlags`: status flags, जैसे submitted, read, unread या attachments की मौजूदगी।
- `PidTagLastVerbExecuted`: message के लिए रिकॉर्ड किया गया आखिरी operation, जैसे open, reply या forward।<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlook data-file के स्थान संस्करण और account type के अनुसार अलग होते हैं। Microsoft PST/OST फ़ाइलों के लिए ये सामान्य स्थान बताता है:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Registry path `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` से Outlook profile और संबंधित data-file configuration की पहचान हो सकती है।

PST फ़ाइलों में messages, contacts, calendar data और अन्य Outlook items हो सकते हैं। आप इसकी copy का निरीक्षण [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) से कर सकते हैं।<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: आप Kernel PST Viewer टूल का उपयोग करके PST फ़ाइल खोल सकते हैं](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST फ़ाइल**, Exchange या Microsoft 365 accounts के लिए एक local cache होती है; Cached Exchange Mode POP या IMAP accounts पर लागू नहीं होता। Offline period को कॉन्फ़िगर किया जा सकता है और यह अक्सर डिफ़ॉल्ट रूप से 12 महीने होता है, जबकि PST/OST size limits अलग से कॉन्फ़िगर की जाती हैं। OST फ़ाइल देखने के लिए [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) का उपयोग किया जा सकता है।<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Attachments पुनः प्राप्त करना

खोए हुए attachments शायद इन स्थानों से वापस प्राप्त किए जा सकते हैं:

- पुराने Outlook/IE configurations के लिए: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- नए Outlook/IE11 configurations के लिए: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`।<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** profile data को `%APPDATA%\Thunderbird\Profiles` के अंतर्गत सहेजता है; mail folders में आम तौर पर account-specific `Mail` या `ImapMail` directories के भीतर बिना extension वाली mbox फ़ाइलें होती हैं।<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: Thumbnail previews आम तौर पर हर फ़ोल्डर की `thumbs.db` फ़ाइलों में सहेजे जाते थे।
- **Network folders**: संबंधित thumbnail behavior सक्षम होने पर UNC folder के लिए भी `thumbs.db` फ़ाइल बनाई जा सकती है; यह न मानें कि हर Windows version या policy इसे बनाती है।
- **Windows Vista और नए संस्करण**: System thumbnail cache, `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` में केंद्रीकृत होती है और इसमें **thumbcache_xxx.db** जैसी फ़ाइलें होती हैं। [**Thumbsviewer**](https://thumbsviewer.github.io) पुरानी `Thumbs.db` फ़ाइलों को पार्स कर सकता है, जबकि [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) आधुनिक thumbnail-cache databases को पार्स कर सकता है।<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Information

Windows Registry, जिसमें system और user configuration data होता है, इन hive files में मौजूद होती है:

- `%WINDIR%\System32\Config` में वे machine hives होते हैं जो विभिन्न `HKEY_LOCAL_MACHINE` subkeys को आधार देते हैं।
- `%USERPROFILE%\NTUSER.DAT` में user की `HKEY_CURRENT_USER` hive होती है।
- कुछ पुराने Windows installations में `%WINDIR%\System32\Config\RegBack\` के अंतर्गत copies होती हैं; Windows 10 version 1803 और उसके बाद के संस्करण इस directory को अपने-आप नहीं भरते, जब तक periodic backup सक्षम न हो।<sup>[[34]](#references)[[35]](#references)</sup>
- आधुनिक Windows में प्रति-user shell और class-registration data आम तौर पर `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` में भी सहेजा जाता है।<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

Registry hives का विश्लेषण करने के लिए कुछ टूल उपयोगी हैं; किसी output पर भरोसा करने से पहले जाँचें कि हर टूल किन hive formats और versions का समर्थन करता है:

- **Registry Editor**: यह Windows में पहले से इंस्टॉल होता है। यह मौजूदा session की Windows registry में नेविगेट करने के लिए GUI है।
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): यह आपको registry file लोड करने और GUI के ज़रिए उसमें नेविगेट करने देता है। इसमें ऐसे Bookmarks भी हैं जो उपयोगी जानकारी वाली keys को दिखाते हैं।
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): इसमें भी GUI है, जो लोड की गई registry में नेविगेट करने देता है; साथ ही इसमें ऐसे plugins हैं जो लोड की गई registry की उपयोगी जानकारी दिखाते हैं।
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): एक अन्य GUI एप्लिकेशन, जो लोड की गई registry hive से जानकारी निकाल सकता है।<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### हटाए गए Element को पुनः प्राप्त करना

हटाए गए hive cells तब तक मौजूद रह सकते हैं, जब तक उनकी जगह का दोबारा उपयोग न हो; लेकिन पुनर्प्राप्ति hive की स्थिति और parser पर निर्भर करती है। पुनर्प्राप्त हटाई गई keys को ऐसे साक्ष्य मानें जिनकी पुष्टि आवश्यक है, न कि पक्के रिकॉर्ड।

### Last Write Time

Registry keys में last-write timestamp होता है; Windows इसे key या उसकी किसी भी value entry के लिए दिखाता है। इसलिए किसी value का अपना स्वतंत्र संशोधन timestamp होना ज़रूरी नहीं है।<sup>[[69]](#references)</sup>

### SAM

**SAM** hive में local user और group account data होता है, जिसमें system के boot-key material से सुरक्षित password hashes भी शामिल हैं।<sup>[[38]](#references)[[39]](#references)</sup>

`SAM\Domains\Account\Users` में account identifiers और कुछ logon तथा policy fields प्राप्त किए जा सकते हैं। Offline hash extraction के लिए संबंधित boot-key material पुनः प्राप्त करने हेतु `SYSTEM` hive भी आवश्यक है।<sup>[[38]](#references)[[39]](#references)</sup>

### Windows Registry में उपयोगी प्रविष्टियाँ


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## चलाए गए Programs

### Basic Windows Processes

सामान्य Windows processes पर एक मौजूदा [पोस्ट](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) अतिरिक्त पढ़ने के लिए उपलब्ध है; process behavior से जुड़े किसी भी दावे की पुष्टि वर्तमान Windows documentation और स्थानीय साक्ष्य से करें।<sup>[[2]](#references)</sup>

### Windows Recent APPs

Windows 10 के उन versions में जहाँ यह उपलब्ध है, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` में प्रति-application subkeys होती हैं, जिनमें last-used time और launch count जैसे fields शामिल होते हैं; बाद के releases से यह आर्टिफ़ैक्ट हटा दिया गया था, इसलिए लक्षित build की पुष्टि करें।<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

जिन systems में Background Activity Moderator उपलब्ध है, उनमें `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` या नया `...\bam\State\UserSettings\{SID}` path देखें। Values को user SID के अनुसार व्यवस्थित किया जाता है और उनमें ट्रैक किए गए executable paths तथा FILETIME-जैसा execution data हो सकता है; यह आर्टिफ़ैक्ट संस्करण पर निर्भर है और अन्य साक्ष्यों से इसकी पुष्टि की जानी चाहिए।<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetching resources और launch metadata को cache करता है, ताकि programs जल्दी शुरू हो सकें।

Prefetch फ़ाइलें `C:\Windows\Prefetch` में `.pf` फ़ाइलों के रूप में सहेजी जाती हैं; format, retention और फ़ाइलों की संख्या की limits Windows version के अनुसार अलग होती हैं। Microsoft के अनुसार Windows 8 और उसके बाद के संस्करण आखिरी आठ execution times और अधिकतम 1024 फ़ाइलें रखते हैं, इसलिए पुराने निश्चित-limit वाले सारांशों को सामान्य नियम न मानें।<sup>[[13]](#references)</sup>

फ़ाइल का नाम आम तौर पर `{program_name}-{hash}.pf` होता है। Hash, path और arguments जैसे execution context से निकाला जाता है; Windows 10 और उसके बाद के संस्करण फ़ाइल को compress कर सकते हैं। फ़ाइल की मौजूदगी execution का उपयोगी साक्ष्य है, लेकिन अपने-आप में यह साबित नहीं करती कि किसी user ने उसे चलाया था। इसकी पुष्टि अन्य आर्टिफ़ैक्ट से करें।<sup>[[13]](#references)</sup>

इन फ़ाइलों का निरीक्षण करने के लिए [**PECmd.exe**](https://github.com/EricZimmerman/PECmd) का उपयोग कर सकते हैं। इसके documentation में लागू Windows 10 Prefetch फ़ाइलों के लिए directory parsing, CSV/HTML output और decompression support शामिल हैं।<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain**, loading को बेहतर बनाने के लिए ऐतिहासिक उपयोग पैटर्न का उपयोग करके Prefetch को पूरक बनाता है। जिन सिस्टम में ये फ़ाइलें बनती हैं, वहाँ इसकी database फ़ाइलें आम तौर पर `C:\Windows\Prefetch\Ag*.db` में मिलती हैं; format और उपलब्धता Windows version पर निर्भर करती है।<sup>[[41]](#references)</sup>

इन databases में application names, usage counts, access की गई files या volumes, paths और time ranges हो सकते हैं, लेकिन इन्हें execution का सटीक log नहीं मानना चाहिए।<sup>[[41]](#references)</sup>

मौजूदा [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) link को संभावित parser के रूप में रखा गया है; उपयोग से पहले tool के documentation में इसकी मौजूदा उपलब्धता और समर्थित output की पुष्टि करें।

### SRUM

**System Resource Usage Monitor** (SRUM), applications और users द्वारा किए गए resource use को रिकॉर्ड करता है। इसे Windows 8 में पेश किया गया था और यह डेटा ESE database `C:\Windows\System32\sru\SRUDB.dat` में store करता है।<sup>[[13]](#references)</sup>

इसमें निम्नलिखित जानकारी मिलती है:

- AppID और Path
- रिकॉर्ड से जुड़ा User/SID
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

डेटा संग्रह का अंतराल और retention, implementation पर निर्भर करते हैं; यह न मानें कि हर रिकॉर्ड ठीक 60 मिनट के execution interval को दर्शाता है।<sup>[[13]](#references)</sup>

आप [**srum_dump**](https://github.com/MarkBaggett/srum-dump) से डेटा extract और review कर सकते हैं। इसके लिए मौजूदा tool version में documented options का उपयोग करें।<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

**AppCompatCache**, जिसे **ShimCache** के नाम से भी जाना जाता है, Windows के application-compatibility infrastructure का हिस्सा है और compatibility संबंधी निर्णयों के लिए file metadata रिकॉर्ड करता है। Hive path, record format, retained capacity और fields, Windows के release के अनुसार अलग-अलग होते हैं; आधुनिक Windows पर, केवल ShimCache से यह साबित नहीं होता कि किसी user ने कोई file execute की थी। संबंधित `SYSTEM` hive को [**AppCompatCacheParser** tool](https://github.com/EricZimmerman/AppCompatCacheParser) से parse करें और इसके output की पुष्टि execution artifacts से करें।<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): संग्रहित जानकारी parse करने के लिए, AppCompatCacheParser tool का उपयोग करने की सलाह दी जाती है](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** file एक registry hive है, जो Windows द्वारा देखे गए applications और files की सूची रखती है। यह आमतौर पर `C:\Windows\AppCompat\Programs\Amcache.hve` पर मिलती है।

इसमें संबंधित और असंबंधित file entries, paths और SHA1 values हो सकती हैं, लेकिन इसकी मौजूदगी केवल inventory का साक्ष्य है और इससे अपने आप यह साबित नहीं होता कि कोई process execute हुआ था।<sup>[[13]](#references)[[44]](#references)</sup>

**Amcache.hve** से data निकालने और उसका विश्लेषण करने के लिए [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool का उपयोग करें। यह command hive को parse करके CSV output लिखती है।<sup>[[44]](#references)</sup>

उदाहरण के लिए:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

जनरेट की गई CSV फ़ाइलों में, `Amcache_Unassociated file entries` उन फ़ाइलों की जाँच करते समय उपयोगी हो सकती है जो किसी पहचाने गए प्रोग्राम से संबद्ध नहीं हैं।<sup>[[44]](#references)</sup>

### RecentFileCache

Windows 7 सिस्टम पर, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` में हाल ही में देखे गए binaries के बारे में जानकारी हो सकती है; इसकी उपलब्धता और अर्थ version पर निर्भर करते हैं।

फ़ाइल को parse करने के लिए [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) का उपयोग किया जा सकता है।<sup>[[45]](#references)</sup>

### Scheduled tasks

आधुनिक tasks के प्रमाण `C:\Windows\System32\Tasks` में और legacy tasks के `.job` फ़ाइलों के साथ `C:\Windows\Tasks` में मिल सकते हैं; OS के अनुसार उपयुक्त task definition format की जाँच करें।<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Service Control Manager का database `SYSTEM\CurrentControlSet\Services` के अंतर्गत होता है (offline SYSTEM hive के लिए, संबंधित control-set key की जाँच करें); इसमें executable paths और start types जैसी service और driver configuration होती है।<sup>[[72]](#references)</sup>

### **Windows Store**

इंस्टॉल किए गए Windows Store applications, `\ProgramData\Microsoft\Windows\AppRepository\` के अंतर्गत दर्ज हो सकते हैं; इसमें database **`StateRepository-Machine.srd`** भी शामिल है। Schema और paths, Windows release के अनुसार बदलते हैं।<sup>[[71]](#references)</sup>

Database में application identifiers, package numbers और display names हो सकते हैं। Identifiers में gaps अपने-आप में इस बात का प्रमाण नहीं हैं कि कोई application uninstall किया गया था; package और registry state से इसकी पुष्टि करें।

Package registrations, `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` के अंतर्गत भी मिल सकते हैं। Microsoft, हटाए गए provisioned apps के लिए version-specific `Deprovisioned` subkey का दस्तावेज़ देता है; यह न मानें कि हर build में `Deleted` subkey मौजूद होती है।<sup>[[70]](#references)</sup>

## Windows Events

Provider के आधार पर, Windows events में ये जानकारी हो सकती है:

- क्या हुआ
- `TimeCreated` timestamp, जिसकी व्याख्या event schema और host के समय-संदर्भ के अनुसार करनी चाहिए
- शामिल users
- शामिल hosts (hostname, IP)
- एक्सेस किए गए assets (files, folders, printers या services)।<sup>[[49]](#references)</sup>

Windows Vista से पहले, event logs आम तौर पर `C:\Windows\System32\config` के अंतर्गत legacy binary format का उपयोग करते थे; Vista और उसके बाद के versions में Windows Event Log format का उपयोग होता है, जो सामान्यतः `C:\Windows\System32\winevt\Logs` के अंतर्गत होता है। इसमें `.evtx` फ़ाइलें होती हैं, जिनमें event data को XML के रूप में render किया जाता है।<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM registry, channel configuration को **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** के अंतर्गत रखता है; इसमें configured file path और retention settings शामिल हैं।<sup>[[47]](#references)</sup>

इन्हें Windows Event Viewer (**`eventvwr.msc`**) या [**Event Log Explorer**](https://eventlogxp.com) और [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md) जैसे tools से देखा जा सकता है।<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Windows Security Event Logging को समझना

Vista और उसके बाद के versions में, Security channel आम तौर पर `C:\Windows\System32\winevt\Logs\Security.evtx` में संग्रहीत होता है। इसका अधिकतम आकार और retention policy configurable हैं; circular logging में, फ़ाइल अपनी सीमा तक पहुँचने पर पुराने records overwrite हो सकते हैं। प्रासंगिक auditing सक्षम होने पर यह channel authentication, logoff, privilege, audit-policy और object-access events रिकॉर्ड कर सकता है।<sup>[[46]](#references)[[47]](#references)</sup>

### User Authentication के लिए प्रमुख Event IDs:

- **Event ID 4624**: Account logon सफल रहा।<sup>[[50]](#references)</sup>
- **Event ID 4625**: Account logon विफल रहा।<sup>[[51]](#references)</sup>
- **Event ID 4634**: Logon session समाप्त हुआ।<sup>[[52]](#references)</sup>
- **Event ID 4647**: User ने logoff शुरू किया।<sup>[[53]](#references)</sup>
- **Event ID 4672**: नए logon को special privileges दिए गए; यह system और administrator accounts के लिए सामान्य है, इसलिए अपने-आप में malicious activity का प्रमाण नहीं है।<sup>[[54]](#references)</sup>

#### 4624, 4625, 4634 और 4647 में आम तौर पर दर्ज किए जाने वाले Logon types:

- **Interactive (2)**: स्थानीय interactive logon।
- **Network (3)**: साझा resource तक पहुँच।
- **Batch (4)**: Batch-process logon।
- **Service (5)**: Service logon।
- **Unlock (7)**: Workstation unlock।
- **NetworkCleartext (8)**: ऐसा network logon जिसमें authentication package को credentials cleartext में दिए जाते हैं।
- **NewCredentials (9)**: Outbound connections के लिए दिए गए वैकल्पिक credentials का उपयोग करने वाला logon।
- **RemoteInteractive (10)**: Remote Desktop या Terminal Services logon।
- **CachedInteractive (11)**: Cached domain credentials का उपयोग करने वाला interactive logon।
- **CachedRemoteInteractive (12)**: Cached remote-interactive logon।
- **CachedUnlock (13)**: Cached credentials का उपयोग करके unlock।<sup>[[50]](#references)[[51]](#references)</sup>

#### EventID 4625 के Status और Sub Status Codes:

- **0xC0000064**: ऐसा कोई user नहीं है।
- **0xC000006A**: User name सही है, लेकिन password गलत है।
- **0xC0000234**: Account lock हो गया है।
- **0xC0000072**: Account disabled है।
- **0xC000006F**: अनुमत समय के बाहर logon।
- **0xC0000070**: Workstation restriction का उल्लंघन।
- **0xC0000193**: Account की अवधि समाप्त हो गई है।
- **0xC0000071**: Password की अवधि समाप्त हो गई है।
- **0xC0000133**: Client और server के समय का अंतर बहुत अधिक है।
- **0xC0000224**: Account को अपना password बदलना होगा।
- **0xC0000225**: `STATUS_NOT_FOUND`; केवल इस code से किसी system bug या attack की पहचान नहीं होती।
- **0xC000015B**: Account को अनुरोधित logon type की अनुमति नहीं है।<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **समय में बदलाव**: System का समय बदला गया। कई events में सामान्य time-service correction दिखाई देती है, इसलिए इसे छेड़छाड़ मानने से पहले actor और time source की पुष्टि करें।<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008 और 6009:

- **Power और service संदर्भ**: Event 12 OS start रिकॉर्ड करता है, 13 OS shutdown, 1074 नियोजित shutdown या restart, 6008 अप्रत्याशित shutdown और 6009 boot के समय Windows version रिकॉर्ड करता है। Events 6005 और 6006 क्रमशः Event Log service के शुरू और बंद होने का संकेत देते हैं; ये अपने-आप में OS startup और shutdown का प्रमाण नहीं हैं।<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Event 1102 रिकॉर्ड करता है कि Security audit log साफ़ किया गया; केवल इस event से मंशा मानने के बजाय actor और आसपास के events की जाँच करें।<sup>[[62]](#references)</sup>

#### USB Device Tracking के EventIDs:

- **20001 / 20003**: `UserPnp` device-installation events, जो पहली बार उपयोग या installation activity स्थापित करने में मदद कर सकते हैं।
- **10000 / 10100**: `DriverFrameworks-UserMode` events, जो device activity के साथ दिखाई दे सकते हैं।
- **Event ID 112**: `DeviceSetupManager/Admin` activity, जिससे insertion से संबंधित timestamps मिल सकते हैं।
- Provider, channel और event के अर्थ Windows version के अनुसार बदलते हैं; कोई अर्थ निर्धारित करने से पहले provider name और event payload की जाँच करें।<sup>[[59]](#references)</sup>

Logon types और उनसे संबंधित credential material के व्यावहारिक उदाहरणों के लिए, [Altered Security की विस्तृत मार्गदर्शिका](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them) देखें।<sup>[[60]](#references)</sup>

Event details—जैसे logon type, status, substatus, source address और process fields—Event ID 4625 का संदर्भ देते हैं; status code या बार-बार विफल होने का pattern जाँच का सुराग है, निष्कर्ष नहीं।<sup>[[51]](#references)[[55]](#references)</sup>

### Windows Events पुनर्प्राप्त करना

चूँकि event logs आम तौर पर circular होते हैं, logger द्वारा overwrite किए गए records शायद पुनर्प्राप्त न किए जा सकें। किसी live system से संपर्क करने से पहले forensic image या working copy सुरक्षित रखें; **Bulk_extractor** जैसे validated parser या carver का उपयोग तभी करें जब यह पुष्टि कर लें कि tool का version लक्षित `.evtx` data को support करता है, और केवल events पुनर्प्राप्त करने की कोशिश में चालू system का power unplug न करें।<sup>[[46]](#references)</sup>

### Windows Events से सामान्य Attacks की पहचान करना

व्यावहारिक event-ID संदर्भ के लिए, मौजूदा [Red Team Recipe](https://redteamrecipe.com/event-codes/) link देखें और उसके उदाहरणों की ऊपर दिए गए provider documentation से पुष्टि करें।

#### Brute Force Attacks

बार-बार होने वाली Event ID 4625 विफलताओं को बाद की 4624 सफलता, logon type, status, source और account संदर्भ से correlate करें; यह क्रम जाँच का संकेत है, attack का प्रमाण नहीं।<sup>[[50]](#references)[[51]](#references)</sup>

#### समय में बदलाव

Event ID 4616 system-time में बदलाव रिकॉर्ड करता है, जिससे timeline analysis जटिल हो सकता है; इसकी तुलना time-service और host के प्रमाणों से करें।<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB event IDs provider-specific होते हैं; `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 और `DeviceSetupManager/Admin` 112 को SetupAPI और registry artifacts से correlate करें।<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

OS start, shutdown, restart और अप्रत्याशित power की स्थिति के लिए 12/13/1074/6008/6009 का उपयोग करें; 6005/6006, Event Log service के शुरू/बंद होने को दर्शाते हैं।<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102 रिकॉर्ड करता है कि Security audit log साफ़ किया गया; इसे ज़िम्मेदार account और process से correlate करना चाहिए।<sup>[[62]](#references)</sup>



## References

- [1] [Windows Plug and Play की सफ़ाई](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - सामान्य Windows Processes की जाँच](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Windows 10 Notifications का Digital Forensic दृष्टिकोण](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman के forensic tools](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier और Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [VSS के अंतर्गत Registry backup और restore operations](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Backup और restore के लिए Registry keys](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [AutoRecover location पर Word की performance समस्या](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Incident Response Guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: Data Exfiltration Artifacts की पहचान](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI device installation log entries](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID और संबंधित Types](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Outlook data files ढूँढ़ना और transfer करना](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Cached Exchange Mode चालू करना](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [केवल कुछ items ही synchronized होते हैं](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Outlook data files के size limits configure करना](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Thunderbird user data कहाँ संग्रहीत करता है](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird account settings और mbox directories](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registry का RegBack में backup नहीं लिया जाता](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Registry को remotely edit करना](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Passwords का तकनीकी अवलोकन](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch के प्रमाण](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
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
- [57] [System event logs का उपयोग करके अप्रत्याशित reboots की समस्या का निवारण](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [प्रक्रिया में shutdown की समस्या का निवारण](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Windows 10 के लिए USB Storage Device Forensics](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Windows Logon Types की विस्तृत जानकारी](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Background activity moderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Outlook Desktop में Quick Print से PDF attachments की printing बंद हो जाती है](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Registry files](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Update के दौरान हटाए गए apps को फिर से आने से रोकना](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTK और Registry Viewer के परीक्षण परिणाम](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [इंस्टॉल की गई Services का Database](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Task Scheduler Service उपलब्ध नहीं होने की त्रुटि से Scheduled Tasks विफल होते हैं](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Windows Mail database को खंगालना](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
- [77] [Windows clients के लिए Recall प्रबंधित करना](https://learn.microsoft.com/en-us/windows/client-management/manage-recall)
- [78] [TotalRecall Reloaded](https://github.com/xaitax/TotalRecall)
{{#include ../../../banners/hacktricks-training.md}}
