# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

पथ `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` में आप डेटाबेस `appdb.dat` (Windows anniversary से पहले) या `wpndatabase.db` (Windows Anniversary के बाद) पा सकते हैं।

इस SQLite डेटाबेस के अंदर, आप `Notification` तालिका पा सकते हैं जिसमें सभी सूचनाएँ (XML प्रारूप में) होती हैं जो दिलचस्प डेटा हो सकता है।

### Timeline

Timeline एक Windows विशेषता है जो **कालानुक्रमिक इतिहास** प्रदान करती है जिसमें देखी गई वेब पृष्ठ, संपादित दस्तावेज़, और निष्पादित अनुप्रयोग शामिल होते हैं।

डेटाबेस पथ `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` में स्थित है। इस डेटाबेस को SQLite टूल या टूल [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) के साथ खोला जा सकता है **जो 2 फ़ाइलें उत्पन्न करता है जिन्हें टूल** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **के साथ खोला जा सकता है।**

### ADS (Alternate Data Streams)

डाउनलोड की गई फ़ाइलों में **ADS Zone.Identifier** हो सकता है जो **यह बताता है कि** इसे **कैसे** **डाउनलोड** किया गया था, जैसे कि इंट्रानेट, इंटरनेट, आदि। कुछ सॉफ़्टवेयर (जैसे ब्राउज़र) आमतौर पर फ़ाइल डाउनलोड करने के लिए **URL** जैसी **अधिक** **जानकारी** भी डालते हैं।

## **File Backups**

### Recycle Bin

Vista/Win7/Win8/Win10 में **Recycle Bin** को ड्राइव के रूट में **`$Recycle.bin`** फ़ोल्डर में पाया जा सकता है (`C:\$Recycle.bin`).\
जब इस फ़ोल्डर में एक फ़ाइल हटाई जाती है, तो 2 विशिष्ट फ़ाइलें बनाई जाती हैं:

- `$I{id}`: फ़ाइल जानकारी (जब इसे हटाया गया था)
- `$R{id}`: फ़ाइल की सामग्री

![](<../../../images/image (1029).png>)

इन फ़ाइलों के साथ, आप टूल [**Rifiuti**](https://github.com/abelcheung/rifiuti2) का उपयोग करके हटाई गई फ़ाइलों का मूल पता और इसे हटाए जाने की तारीख प्राप्त कर सकते हैं (Vista – Win10 के लिए `rifiuti-vista.exe` का उपयोग करें)।
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../images/image (495) (1) (1) (1).png>)

### वॉल्यूम शैडो कॉपियाँ

शैडो कॉपी एक तकनीक है जो Microsoft Windows में शामिल है, जो कंप्यूटर फ़ाइलों या वॉल्यूम की **बैकअप कॉपियाँ** या स्नैपशॉट बनाने की अनुमति देती है, भले ही वे उपयोग में हों।

ये बैकअप आमतौर पर फ़ाइल सिस्टम की जड़ से `\System Volume Information` में स्थित होते हैं और नाम **UIDs** से बना होता है, जो निम्नलिखित छवि में दिखाए गए हैं:

![](<../../../images/image (94).png>)

**ArsenalImageMounter** के साथ फॉरेंसिक इमेज को माउंट करते समय, टूल [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) का उपयोग शैडो कॉपी का निरीक्षण करने और यहां तक कि शैडो कॉपी बैकअप से **फाइलें निकालने** के लिए किया जा सकता है।

![](<../../../images/image (576).png>)

रजिस्ट्री प्रविष्टि `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` उन फ़ाइलों और कुंजियों को **बैकअप न करने** के लिए शामिल करती है:

![](<../../../images/image (254).png>)

रजिस्ट्री `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` में `वॉल्यूम शैडो कॉपियाँ` के बारे में कॉन्फ़िगरेशन जानकारी भी होती है।

### ऑफिस ऑटोसेव्ड फ़ाइलें

आप ऑफिस ऑटोसेव्ड फ़ाइलें निम्नलिखित पते पर पा सकते हैं: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## शेल आइटम

एक शेल आइटम एक ऐसा आइटम है जिसमें किसी अन्य फ़ाइल तक पहुँचने के बारे में जानकारी होती है।

### हाल के दस्तावेज़ (LNK)

Windows **स्वचालित रूप से** इन **शॉर्टकट्स** को तब **बनाता है** जब उपयोगकर्ता **एक फ़ाइल खोलता है, उपयोग करता है या बनाता है**:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- ऑफिस: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

जब एक फ़ोल्डर बनाया जाता है, तो फ़ोल्डर, पैरेंट फ़ोल्डर और दादा फ़ोल्डर के लिए एक लिंक भी बनाया जाता है।

ये स्वचालित रूप से बनाए गए लिंक फ़ाइलें **उद्गम के बारे में जानकारी** **रखती हैं** जैसे कि यह **फ़ाइल** **है** **या** **फ़ोल्डर**, उस फ़ाइल के **MAC** **समय**, फ़ाइल कहाँ संग्रहीत है उसका **वॉल्यूम जानकारी** और **लक्षित फ़ाइल का फ़ोल्डर**। यह जानकारी उन फ़ाइलों को पुनर्प्राप्त करने में सहायक हो सकती है यदि वे हटा दी गई हों।

इसके अलावा, लिंक फ़ाइल की **तारीख बनाई गई** मूल फ़ाइल के **पहले** **उपयोग** की पहली **बार** है और लिंक फ़ाइल की **तारीख संशोधित** मूल फ़ाइल के उपयोग की **अंतिम** **बार** है।

इन फ़ाइलों का निरीक्षण करने के लिए आप [**LinkParser**](http://4discovery.com/our-tools/) का उपयोग कर सकते हैं।

इस टूल में आपको **2 सेट** टाइमस्टैम्प मिलेंगे:

- **पहला सेट:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **दूसरा सेट:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate।

पहले सेट का टाइमस्टैम्प **फ़ाइल के स्वयं के टाइमस्टैम्प** को संदर्भित करता है। दूसरा सेट **लिंक की गई फ़ाइल के टाइमस्टैम्प** को संदर्भित करता है।

आप Windows CLI टूल चलाकर समान जानकारी प्राप्त कर सकते हैं: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In this case, the information is going to be saved inside a CSV file.

### Jumplists

ये हाल के फ़ाइलें हैं जो प्रत्येक एप्लिकेशन के लिए निर्दिष्ट की गई हैं। यह **एक एप्लिकेशन द्वारा उपयोग की गई हाल की फ़ाइलों की सूची** है जिसे आप प्रत्येक एप्लिकेशन पर एक्सेस कर सकते हैं। इन्हें **स्वचालित रूप से या कस्टम** बनाया जा सकता है।

स्वचालित रूप से बनाए गए **jumplists** `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` में संग्रहीत होते हैं। jumplists का नाम `{id}.autmaticDestinations-ms` प्रारूप का पालन करते हैं जहाँ प्रारंभिक ID एप्लिकेशन का ID है।

कस्टम jumplists `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` में संग्रहीत होते हैं और इन्हें आमतौर पर एप्लिकेशन द्वारा बनाया जाता है क्योंकि फ़ाइल के साथ कुछ **महत्वपूर्ण** हुआ है (शायद पसंदीदा के रूप में चिह्नित किया गया है)

किसी भी jumplist का **निर्माण समय** **पहली बार फ़ाइल को एक्सेस किए जाने का समय** और **संशोधित समय अंतिम बार** को दर्शाता है।

आप [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) का उपयोग करके jumplists की जांच कर सकते हैं।

![](<../../../images/image (168).png>)

(_ध्यान दें कि JumplistExplorer द्वारा प्रदान किए गए टाइमस्टैम्प jumplist फ़ाइल से संबंधित हैं_)

### Shellbags

[**Follow this link to learn what are the shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Use of Windows USBs

यह पहचानना संभव है कि एक USB डिवाइस का उपयोग किया गया था धन्यवाद निम्नलिखित के निर्माण के लिए:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

ध्यान दें कि कुछ LNK फ़ाइल मूल पथ की ओर इशारा करने के बजाय WPDNSE फ़ोल्डर की ओर इशारा करती है:

![](<../../../images/image (218).png>)

WPDNSE फ़ोल्डर में फ़ाइलें मूल फ़ाइलों की एक प्रति हैं, इसलिए ये PC के पुनरारंभ के दौरान जीवित नहीं रहेंगी और GUID एक shellbag से लिया गया है।

### Registry Information

[Check this page to learn](interesting-windows-registry-keys.md#usb-information) कौन से रजिस्ट्री कुंजी USB जुड़े उपकरणों के बारे में दिलचस्प जानकारी रखती हैं।

### setupapi

USB कनेक्शन कब उत्पन्न हुआ, इसके बारे में टाइमस्टैम्प प्राप्त करने के लिए फ़ाइल `C:\Windows\inf\setupapi.dev.log` की जांच करें ( `Section start` के लिए खोजें)।

![](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) का उपयोग उन USB उपकरणों के बारे में जानकारी प्राप्त करने के लिए किया जा सकता है जो एक छवि से जुड़े हुए हैं।

![](<../../../images/image (452).png>)

### Plug and Play Cleanup

'Plug and Play Cleanup' के रूप में ज्ञात अनुसूचित कार्य मुख्य रूप से पुराने ड्राइवर संस्करणों को हटाने के लिए डिज़ाइन किया गया है। इसके निर्दिष्ट उद्देश्य के विपरीत, जो नवीनतम ड्राइवर पैकेज संस्करण को बनाए रखने के लिए है, ऑनलाइन स्रोतों का सुझाव है कि यह 30 दिनों से निष्क्रिय ड्राइवरों को भी लक्षित करता है। परिणामस्वरूप, पिछले 30 दिनों में जुड़े नहीं गए हटाने योग्य उपकरणों के ड्राइवरों को हटाने के अधीन किया जा सकता है।

यह कार्य निम्नलिखित पथ पर स्थित है: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

कार्य की सामग्री को दर्शाने वाली एक स्क्रीनशॉट प्रदान की गई है: ![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**कार्य के प्रमुख घटक और सेटिंग्स:**

- **pnpclean.dll**: यह DLL वास्तविक सफाई प्रक्रिया के लिए जिम्मेदार है।
- **UseUnifiedSchedulingEngine**: `TRUE` पर सेट, सामान्य कार्य अनुसूची इंजन के उपयोग को इंगित करता है।
- **MaintenanceSettings**:
- **Period ('P1M')**: कार्य शेड्यूलर को नियमित स्वचालित रखरखाव के दौरान मासिक सफाई कार्य शुरू करने के लिए निर्देशित करता है।
- **Deadline ('P2M')**: कार्य शेड्यूलर को निर्देशित करता है, यदि कार्य दो लगातार महीनों के लिए विफल रहता है, तो आपातकालीन स्वचालित रखरखाव के दौरान कार्य को निष्पादित करें।

यह कॉन्फ़िगरेशन नियमित रखरखाव और ड्राइवरों की सफाई सुनिश्चित करता है, लगातार विफलताओं के मामले में कार्य को फिर से प्रयास करने के लिए प्रावधानों के साथ।

**For more information check:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Emails

ईमेल में **2 दिलचस्प भाग होते हैं: ईमेल के हेडर और सामग्री**। **हेडर** में आप जानकारी पा सकते हैं जैसे:

- **किसने** ईमेल भेजा (ईमेल पता, IP, मेल सर्वर जिन्होंने ईमेल को पुनर्निर्देशित किया)
- **कब** ईमेल भेजा गया था

इसके अलावा, `References` और `In-Reply-To` हेडर के अंदर आप संदेशों की ID पा सकते हैं:

![](<../../../images/image (593).png>)

### Windows Mail App

यह एप्लिकेशन ईमेल को HTML या टेक्स्ट में सहेजता है। आप ईमेल को `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` के अंदर उपफोल्डरों में पा सकते हैं। ईमेल को `.dat` एक्सटेंशन के साथ सहेजा जाता है।

ईमेल का **मेटाडेटा** और **संपर्क** **EDB डेटाबेस** के अंदर पाया जा सकता है: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**फाइल का एक्सटेंशन** `.vol` से `.edb` में बदलें और आप इसे खोलने के लिए [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) टूल का उपयोग कर सकते हैं। `Message` तालिका के अंदर आप ईमेल देख सकते हैं।

### Microsoft Outlook

जब एक्सचेंज सर्वर या आउटलुक क्लाइंट का उपयोग किया जाता है, तो कुछ MAPI हेडर होंगे:

- `Mapi-Client-Submit-Time`: सिस्टम का समय जब ईमेल भेजा गया था
- `Mapi-Conversation-Index`: थ्रेड के बच्चों के संदेशों की संख्या और थ्रेड के प्रत्येक संदेश का टाइमस्टैम्प
- `Mapi-Entry-ID`: संदेश पहचानकर्ता।
- `Mappi-Message-Flags` और `Pr_last_Verb-Executed`: MAPI क्लाइंट के बारे में जानकारी (संदेश पढ़ा? नहीं पढ़ा? उत्तर दिया? पुनर्निर्देशित? कार्यालय से बाहर?)

Microsoft Outlook क्लाइंट में, सभी भेजे गए/प्राप्त संदेश, संपर्क डेटा, और कैलेंडर डेटा PST फ़ाइल में संग्रहीत होते हैं:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

रजिस्ट्री पथ `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` उस फ़ाइल को इंगित करता है जिसका उपयोग किया जा रहा है।

आप PST फ़ाइल को [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) टूल का उपयोग करके खोल सकते हैं।

![](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

एक **OST फ़ाइल** Microsoft Outlook द्वारा उत्पन्न होती है जब इसे **IMAP** या **Exchange** सर्वर के साथ कॉन्फ़िगर किया जाता है, जो PST फ़ाइल के समान जानकारी संग्रहीत करती है। यह फ़ाइल सर्वर के साथ समन्वयित होती है, **अंतिम 12 महीनों** के लिए डेटा बनाए रखती है, अधिकतम आकार **50GB** तक, और PST फ़ाइल के समान निर्देशिका में स्थित होती है। OST फ़ाइल देखने के लिए, [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) का उपयोग किया जा सकता है।

### Retrieving Attachments

खोई हुई अटैचमेंट्स को पुनर्प्राप्त किया जा सकता है:

- **IE10** के लिए: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11 और ऊपर** के लिए: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird** **MBOX फ़ाइलों** का उपयोग डेटा संग्रहीत करने के लिए करता है, जो `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles` में स्थित होती हैं।

### Image Thumbnails

- **Windows XP और 8-8.1**: थंबनेल के साथ एक फ़ोल्डर को एक्सेस करने से एक `thumbs.db` फ़ाइल उत्पन्न होती है जो छवि पूर्वावलोकन संग्रहीत करती है, यहां तक कि हटाने के बाद भी।
- **Windows 7/10**: `thumbs.db` तब बनाई जाती है जब UNC पथ के माध्यम से नेटवर्क पर एक्सेस किया जाता है।
- **Windows Vista और नए**: थंबनेल पूर्वावलोकन `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` में केंद्रीकृत होते हैं जिनकी फ़ाइलें **thumbcache_xxx.db** नाम की होती हैं। [**Thumbsviewer**](https://thumbsviewer.github.io) और [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) इन फ़ाइलों को देखने के लिए उपकरण हैं।

### Windows Registry Information

Windows Registry, जो व्यापक प्रणाली और उपयोगकर्ता गतिविधि डेटा संग्रहीत करता है, निम्नलिखित फ़ाइलों में निहित है:

- विभिन्न `HKEY_LOCAL_MACHINE` उपकुंजी के लिए `%windir%\System32\Config`।
- `HKEY_CURRENT_USER` के लिए `%UserProfile%{User}\NTUSER.DAT`।
- Windows Vista और बाद के संस्करण `HKEY_LOCAL_MACHINE` रजिस्ट्री फ़ाइलों का बैकअप `%Windir%\System32\Config\RegBack\` में करते हैं।
- इसके अतिरिक्त, प्रोग्राम निष्पादन की जानकारी `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` में संग्रहीत होती है जो Windows Vista और Windows 2008 Server के बाद से है।

### Tools

कुछ उपकरण रजिस्ट्री फ़ाइलों का विश्लेषण करने के लिए उपयोगी हैं:

- **Registry Editor**: यह Windows में स्थापित है। यह वर्तमान सत्र की Windows रजिस्ट्री के माध्यम से नेविगेट करने के लिए एक GUI है।
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): यह आपको रजिस्ट्री फ़ाइल को लोड करने और GUI के साथ उनके माध्यम से नेविगेट करने की अनुमति देता है। इसमें दिलचस्प जानकारी वाले कुंजी को उजागर करने वाले बुकमार्क भी होते हैं।
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): फिर से, इसमें एक GUI है जो लोड की गई रजिस्ट्री के माध्यम से नेविगेट करने की अनुमति देता है और इसमें प्लगइन्स होते हैं जो लोड की गई रजिस्ट्री के अंदर दिलचस्प जानकारी को उजागर करते हैं।
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): एक और GUI एप्लिकेशन जो लोड की गई रजिस्ट्री से महत्वपूर्ण जानकारी निकालने में सक्षम है।

### Recovering Deleted Element

जब एक कुंजी को हटाया जाता है, तो इसे इस तरह से चिह्नित किया जाता है, लेकिन जब तक यह स्थान आवश्यक नहीं होता, तब तक इसे हटाया नहीं जाएगा। इसलिए, **Registry Explorer** जैसे उपकरणों का उपयोग करके इन हटाई गई कुंजियों को पुनर्प्राप्त करना संभव है।

### Last Write Time

प्रत्येक Key-Value में एक **टाइमस्टैम्प** होता है जो यह दर्शाता है कि इसे अंतिम बार कब संशोधित किया गया था।

### SAM

फ़ाइल/हाइव **SAM** में **उपयोगकर्ताओं, समूहों और उपयोगकर्ताओं के पासवर्ड** हैश होते हैं।

`SAM\Domains\Account\Users` में आप उपयोगकर्ता नाम, RID, अंतिम लॉगिन, अंतिम विफल लॉगिन, लॉगिन काउंटर, पासवर्ड नीति और जब खाता बनाया गया था, प्राप्त कर सकते हैं। **हैश** प्राप्त करने के लिए आपको फ़ाइल/हाइव **SYSTEM** की भी **आवश्यकता** है।

### Interesting entries in the Windows Registry

{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

In [this post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) you can learn about the common Windows processes to detect suspicious behaviours.

### Windows Recent APPs

Registry `NTUSER.DAT` में पथ `Software\Microsoft\Current Version\Search\RecentApps` के अंदर आप **कार्यक्रम निष्पादित**, **अंतिम बार** इसे निष्पादित किया गया था, और **कितनी बार** इसे लॉन्च किया गया था, के बारे में जानकारी के साथ उपकुंजी पा सकते हैं।

### BAM (Background Activity Moderator)

आप रजिस्ट्री संपादक के साथ `SYSTEM` फ़ाइल खोल सकते हैं और पथ `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` के अंदर आप **प्रत्येक उपयोगकर्ता द्वारा निष्पादित कार्यक्रमों** के बारे में जानकारी पा सकते हैं (पथ में `{SID}` नोट करें) और **कब** उन्हें निष्पादित किया गया था (समय रजिस्ट्री के डेटा मान के अंदर है)।

### Windows Prefetch

Prefetching एक तकनीक है जो एक कंप्यूटर को चुपचाप **संसाधनों को लाने** की अनुमति देती है जो एक उपयोगकर्ता **निकट भविष्य में एक्सेस कर सकता है** ताकि संसाधनों को तेजी से एक्सेस किया जा सके।

Windows prefetch में **निष्पादित कार्यक्रमों के कैश** बनाने की प्रक्रिया होती है ताकि उन्हें तेजी से लोड किया जा सके। ये कैश `.pf` फ़ाइलों के रूप में निम्नलिखित पथ में बनाए जाते हैं: `C:\Windows\Prefetch`। XP/VISTA/WIN7 में फ़ाइलों की सीमा 128 है और Win8/Win10 में 1024 फ़ाइलें हैं।

फ़ाइल का नाम `{program_name}-{hash}.pf` के रूप में बनाया जाता है (हैश पथ और निष्पादन योग्य के तर्कों पर आधारित होता है)। W10 में ये फ़ाइलें संकुचित होती हैं। ध्यान दें कि फ़ाइल की केवल उपस्थिति यह संकेत देती है कि **कार्यक्रम को किसी बिंदु पर निष्पादित किया गया था**।

फ़ाइल `C:\Windows\Prefetch\Layout.ini` में **उन फ़ाइलों के फ़ोल्डरों के नाम होते हैं जो पूर्व-लाए गए हैं**। इस फ़ाइल में **निष्पादन की संख्या**, **निष्पादन की तिथियाँ** और **फ़ाइलें** **खुली** होती हैं जो कार्यक्रम द्वारा खोली गई हैं।

इन फ़ाइलों की जांच करने के लिए आप टूल [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) का उपयोग कर सकते हैं:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** का वही लक्ष्य है जो prefetch का है, **कार्यक्रमों को तेजी से लोड करना** यह अनुमान लगाकर कि अगला क्या लोड होने वाला है। हालाँकि, यह prefetch सेवा का स्थान नहीं लेता।\
यह सेवा `C:\Windows\Prefetch\Ag*.db` में डेटाबेस फ़ाइलें उत्पन्न करेगी।

इन डेटाबेस में आप **कार्यक्रम का नाम**, **कार्यवाहियों की संख्या**, **खुले फ़ाइलें**, **एक्सेस किया गया वॉल्यूम**, **पूर्ण पथ**, **समय सीमा** और **टाइमस्टैम्प** पा सकते हैं।

आप इस जानकारी को [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) उपकरण का उपयोग करके एक्सेस कर सकते हैं।

### SRUM

**System Resource Usage Monitor** (SRUM) **एक प्रक्रिया द्वारा उपभोग किए गए संसाधनों** की **निगरानी** करता है। यह W8 में प्रकट हुआ और यह डेटा को `C:\Windows\System32\sru\SRUDB.dat` में ESE डेटाबेस में संग्रहीत करता है।

यह निम्नलिखित जानकारी प्रदान करता है:

- AppID और पथ
- उपयोगकर्ता जिसने प्रक्रिया को निष्पादित किया
- भेजे गए बाइट्स
- प्राप्त बाइट्स
- नेटवर्क इंटरफ़ेस
- कनेक्शन की अवधि
- प्रक्रिया की अवधि

यह जानकारी हर 60 मिनट में अपडेट होती है।

आप इस फ़ाइल से दिनांक प्राप्त करने के लिए [**srum_dump**](https://github.com/MarkBaggett/srum-dump) उपकरण का उपयोग कर सकते हैं।
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

The **AppCompatCache**, जिसे **ShimCache** के नाम से भी जाना जाता है, **Microsoft** द्वारा विकसित **Application Compatibility Database** का एक हिस्सा है, जो एप्लिकेशन संगतता समस्याओं को हल करने के लिए है। यह सिस्टम घटक विभिन्न फ़ाइल मेटाडेटा के टुकड़ों को रिकॉर्ड करता है, जिसमें शामिल हैं:

- फ़ाइल का पूरा पथ
- फ़ाइल का आकार
- **$Standard_Information** (SI) के तहत अंतिम संशोधित समय
- ShimCache का अंतिम अपडेट समय
- प्रक्रिया निष्पादन ध्वज

इस तरह का डेटा रजिस्ट्री में विशिष्ट स्थानों पर संग्रहीत होता है, जो ऑपरेटिंग सिस्टम के संस्करण के आधार पर होता है:

- XP के लिए, डेटा `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` के तहत संग्रहीत होता है, जिसमें 96 प्रविष्टियों की क्षमता होती है।
- सर्वर 2003 के लिए, साथ ही Windows के संस्करण 2008, 2012, 2016, 7, 8, और 10 के लिए, संग्रहण पथ `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache` है, जो क्रमशः 512 और 1024 प्रविष्टियों को समायोजित करता है।

संग्रहीत जानकारी को पार्स करने के लिए, [**AppCompatCacheParser** tool](https://github.com/EricZimmerman/AppCompatCacheParser) का उपयोग करने की सिफारिश की जाती है।

![](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** फ़ाइल मूल रूप से एक रजिस्ट्री हाइव है जो सिस्टम पर निष्पादित अनुप्रयोगों के बारे में विवरण लॉग करती है। यह आमतौर पर `C:\Windows\AppCompat\Programas\Amcache.hve` पर पाई जाती है।

यह फ़ाइल हाल ही में निष्पादित प्रक्रियाओं के रिकॉर्ड को संग्रहीत करने के लिए उल्लेखनीय है, जिसमें निष्पादन योग्य फ़ाइलों के पथ और उनके SHA1 हैश शामिल हैं। यह जानकारी सिस्टम पर अनुप्रयोगों की गतिविधि को ट्रैक करने के लिए अमूल्य है।

**Amcache.hve** से डेटा निकालने और विश्लेषण करने के लिए, [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool का उपयोग किया जा सकता है। निम्नलिखित कमांड **Amcache.hve** फ़ाइल की सामग्री को पार्स करने और परिणामों को CSV प्रारूप में आउटपुट करने के लिए AmcacheParser का उपयोग करने का एक उदाहरण है:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Among the generated CSV files, the `Amcache_Unassociated file entries` is particularly noteworthy due to the rich information it provides about unassociated file entries.

The most interesting CVS file generated is the `Amcache_Unassociated file entries`.

### RecentFileCache

यह आर्टिफैक्ट केवल W7 में `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` में पाया जा सकता है और इसमें कुछ बाइनरी के हालिया निष्पादन के बारे में जानकारी होती है।

You can use the tool [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) to parse the file.

### Scheduled tasks

आप इन्हें `C:\Windows\Tasks` या `C:\Windows\System32\Tasks` से निकाल सकते हैं और XML के रूप में पढ़ सकते हैं।

### Services

आप इन्हें रजिस्ट्री में `SYSTEM\ControlSet001\Services` के तहत पा सकते हैं। आप देख सकते हैं कि क्या निष्पादित होने वाला है और कब।

### **Windows Store**

स्थापित एप्लिकेशन `\ProgramData\Microsoft\Windows\AppRepository\` में पाए जा सकते हैं।\
इस रिपॉजिटरी में **लॉग** है जिसमें **प्रत्येक एप्लिकेशन जो सिस्टम में स्थापित है** **`StateRepository-Machine.srd`** डेटाबेस के अंदर है।

इस डेटाबेस के एप्लिकेशन तालिका के अंदर, "Application ID", "PackageNumber", और "Display Name" जैसे कॉलम पाए जा सकते हैं। ये कॉलम पूर्व-स्थापित और स्थापित एप्लिकेशनों के बारे में जानकारी रखते हैं और यह पता लगाया जा सकता है कि क्या कुछ एप्लिकेशन अनइंस्टॉल किए गए थे क्योंकि स्थापित एप्लिकेशनों के IDs अनुक्रमिक होने चाहिए।

यह भी संभव है कि रजिस्ट्री पथ में स्थापित एप्लिकेशन को **पाया जा सके**: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
और **अनइंस्टॉल** **एप्लिकेशन** में: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

Windows इवेंट्स के अंदर जो जानकारी दिखाई देती है वह है:

- क्या हुआ
- टाइमस्टैम्प (UTC + 0)
- शामिल उपयोगकर्ता
- शामिल होस्ट (hostname, IP)
- एक्सेस किए गए एसेट्स (फाइलें, फ़ोल्डर, प्रिंटर, सेवाएँ)

लॉग `C:\Windows\System32\config` में Windows Vista से पहले और `C:\Windows\System32\winevt\Logs` में Windows Vista के बाद स्थित हैं। Windows Vista से पहले, इवेंट लॉग बाइनरी प्रारूप में थे और इसके बाद, वे **XML प्रारूप** में हैं और **.evtx** एक्सटेंशन का उपयोग करते हैं।

इवेंट फ़ाइलों का स्थान SYSTEM रजिस्ट्री में **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** में पाया जा सकता है।

आप इन्हें Windows Event Viewer (**`eventvwr.msc`**) से या अन्य उपकरणों जैसे [**Event Log Explorer**](https://eventlogxp.com) **या** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** से देख सकते हैं।**

## Understanding Windows Security Event Logging

Access events को सुरक्षा कॉन्फ़िगरेशन फ़ाइल में दर्ज किया जाता है जो `C:\Windows\System32\winevt\Security.evtx` पर स्थित है। इस फ़ाइल का आकार समायोज्य है, और जब इसकी क्षमता पूरी हो जाती है, तो पुराने इवेंट्स को ओवरराइट किया जाता है। दर्ज किए गए इवेंट्स में उपयोगकर्ता लॉगिन और लॉगऑफ, उपयोगकर्ता क्रियाएँ, और सुरक्षा सेटिंग्स में परिवर्तन, साथ ही फ़ाइल, फ़ोल्डर, और साझा एसेट्स का एक्सेस शामिल है।

### Key Event IDs for User Authentication:

- **EventID 4624**: Indicates a user successfully authenticated.
- **EventID 4625**: Signals an authentication failure.
- **EventIDs 4634/4647**: Represent user logoff events.
- **EventID 4672**: Denotes login with administrative privileges.

#### Sub-types within EventID 4634/4647:

- **Interactive (2)**: Direct user login.
- **Network (3)**: Access to shared folders.
- **Batch (4)**: Execution of batch processes.
- **Service (5)**: Service launches.
- **Proxy (6)**: Proxy authentication.
- **Unlock (7)**: Screen unlocked with a password.
- **Network Cleartext (8)**: Clear text password transmission, often from IIS.
- **New Credentials (9)**: Usage of different credentials for access.
- **Remote Interactive (10)**: Remote desktop or terminal services login.
- **Cache Interactive (11)**: Login with cached credentials without domain controller contact.
- **Cache Remote Interactive (12)**: Remote login with cached credentials.
- **Cached Unlock (13)**: Unlocking with cached credentials.

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: User name does not exist - Could indicate a username enumeration attack.
- **0xC000006A**: Correct user name but wrong password - Possible password guessing or brute-force attempt.
- **0xC0000234**: User account locked out - May follow a brute-force attack resulting in multiple failed logins.
- **0xC0000072**: Account disabled - Unauthorized attempts to access disabled accounts.
- **0xC000006F**: Logon outside allowed time - Indicates attempts to access outside of set login hours, a possible sign of unauthorized access.
- **0xC0000070**: Violation of workstation restrictions - Could be an attempt to login from an unauthorized location.
- **0xC0000193**: Account expiration - Access attempts with expired user accounts.
- **0xC0000071**: Expired password - Login attempts with outdated passwords.
- **0xC0000133**: Time sync issues - Large time discrepancies between client and server may be indicative of more sophisticated attacks like pass-the-ticket.
- **0xC0000224**: Mandatory password change required - Frequent mandatory changes might suggest an attempt to destabilize account security.
- **0xC0000225**: Indicates a system bug rather than a security issue.
- **0xC000015b**: Denied logon type - Access attempt with unauthorized logon type, such as a user trying to execute a service logon.

#### EventID 4616:

- **Time Change**: Modification of the system time, could obscure the timeline of events.

#### EventID 6005 and 6006:

- **System Startup and Shutdown**: EventID 6005 indicates the system starting up, while EventID 6006 marks it shutting down.

#### EventID 1102:

- **Log Deletion**: Security logs being cleared, which is often a red flag for covering up illicit activities.

#### EventIDs for USB Device Tracking:

- **20001 / 20003 / 10000**: USB device first connection.
- **10100**: USB driver update.
- **EventID 112**: Time of USB device insertion.

For practical examples on simulating these login types and credential dumping opportunities, refer to [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Event details, including status and sub-status codes, provide further insights into event causes, particularly notable in Event ID 4625.

### Recovering Windows Events

To enhance the chances of recovering deleted Windows Events, it's advisable to power down the suspect computer by directly unplugging it. **Bulk_extractor**, a recovery tool specifying the `.evtx` extension, is recommended for attempting to recover such events.

### Identifying Common Attacks via Windows Events

For a comprehensive guide on utilizing Windows Event IDs in identifying common cyber attacks, visit [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force Attacks

Identifiable by multiple EventID 4625 records, followed by an EventID 4624 if the attack succeeds.

#### Time Change

Recorded by EventID 4616, changes to system time can complicate forensic analysis.

#### USB Device Tracking

Useful System EventIDs for USB device tracking include 20001/20003/10000 for initial use, 10100 for driver updates, and EventID 112 from DeviceSetupManager for insertion timestamps.

#### System Power Events

EventID 6005 indicates system startup, while EventID 6006 marks shutdown.

#### Log Deletion

Security EventID 1102 signals the deletion of logs, a critical event for forensic analysis.

{{#include ../../../banners/hacktricks-training.md}}
