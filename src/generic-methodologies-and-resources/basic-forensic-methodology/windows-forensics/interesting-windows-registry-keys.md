# Interesting Windows Registry Keys

{{#include ../../../banners/hacktricks-training.md}}

### **Windows Version and Owner Info**

- **`Software\Microsoft\Windows NT\CurrentVersion`** पर स्थित, आप Windows संस्करण, Service Pack, स्थापना समय, और पंजीकृत मालिक का नाम सीधे तरीके से पाएंगे।

### **Computer Name**

- होस्टनाम **`System\ControlSet001\Control\ComputerName\ComputerName`** के तहत पाया जाता है।

### **Time Zone Setting**

- सिस्टम का समय क्षेत्र **`System\ControlSet001\Control\TimeZoneInformation`** में संग्रहीत होता है।

### **Access Time Tracking**

- डिफ़ॉल्ट रूप से, अंतिम पहुँच समय ट्रैकिंग बंद होती है (**`NtfsDisableLastAccessUpdate=1`**)। इसे सक्षम करने के लिए, उपयोग करें:
`fsutil behavior set disablelastaccess 0`

### Windows Versions and Service Packs

- **Windows संस्करण** संस्करण (जैसे, Home, Pro) और इसके रिलीज़ (जैसे, Windows 10, Windows 11) को दर्शाता है, जबकि **Service Packs** अपडेट होते हैं जो सुधार और कभी-कभी नए फीचर्स शामिल करते हैं।

### Enabling Last Access Time

- अंतिम पहुँच समय ट्रैकिंग को सक्षम करने से आप देख सकते हैं कि फ़ाइलें कब अंतिम बार खोली गई थीं, जो फोरेंसिक विश्लेषण या सिस्टम निगरानी के लिए महत्वपूर्ण हो सकता है।

### Network Information Details

- रजिस्ट्री नेटवर्क कॉन्फ़िगरेशन पर विस्तृत डेटा रखती है, जिसमें **नेटवर्क के प्रकार (वायरलेस, केबल, 3G)** और **नेटवर्क श्रेणियाँ (Public, Private/Home, Domain/Work)** शामिल हैं, जो नेटवर्क सुरक्षा सेटिंग्स और अनुमतियों को समझने के लिए महत्वपूर्ण हैं।

### Client Side Caching (CSC)

- **CSC** ऑफ़लाइन फ़ाइल पहुँच को साझा फ़ाइलों की प्रतियों को कैश करके बढ़ाता है। विभिन्न **CSCFlags** सेटिंग्स यह नियंत्रित करती हैं कि कौन सी फ़ाइलें कैश की जाती हैं, प्रदर्शन और उपयोगकर्ता अनुभव को प्रभावित करती हैं, विशेष रूप से उन वातावरणों में जहां कनेक्टिविटी अस्थायी होती है।

### AutoStart Programs

- विभिन्न `Run` और `RunOnce` रजिस्ट्री कुंजियों में सूचीबद्ध कार्यक्रम स्वचालित रूप से स्टार्टअप पर लॉन्च होते हैं, जो सिस्टम बूट समय को प्रभावित करते हैं और संभावित रूप से मैलवेयर या अवांछित सॉफ़्टवेयर की पहचान के लिए रुचि के बिंदु हो सकते हैं।

### Shellbags

- **Shellbags** न केवल फ़ोल्डर दृश्य के लिए प्राथमिकताएँ संग्रहीत करते हैं बल्कि फ़ोल्डर पहुँच के फोरेंसिक सबूत भी प्रदान करते हैं, भले ही फ़ोल्डर अब मौजूद न हो। ये जांचों के लिए अमूल्य हैं, उपयोगकर्ता गतिविधि को प्रकट करते हैं जो अन्य तरीकों से स्पष्ट नहीं होती।

### USB Information and Forensics

- रजिस्ट्री में USB उपकरणों के बारे में संग्रहीत विवरण यह पता लगाने में मदद कर सकते हैं कि कौन से उपकरण एक कंप्यूटर से जुड़े थे, संभावित रूप से संवेदनशील फ़ाइल ट्रांसफर या अनधिकृत पहुँच घटनाओं से एक उपकरण को जोड़ते हैं।

### Volume Serial Number

- **Volume Serial Number** फ़ाइल सिस्टम के विशिष्ट उदाहरण को ट्रैक करने के लिए महत्वपूर्ण हो सकता है, फोरेंसिक परिदृश्यों में जहां फ़ाइल की उत्पत्ति को विभिन्न उपकरणों के बीच स्थापित करने की आवश्यकता होती है।

### **Shutdown Details**

- शटडाउन समय और गिनती (यह केवल XP के लिए) **`System\ControlSet001\Control\Windows`** और **`System\ControlSet001\Control\Watchdog\Display`** में रखी जाती है।

### **Network Configuration**

- विस्तृत नेटवर्क इंटरफ़ेस जानकारी के लिए, **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`** पर जाएँ।
- पहले और अंतिम नेटवर्क कनेक्शन समय, जिसमें VPN कनेक्शन शामिल हैं, विभिन्न पथों के तहत **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`** में लॉग किए जाते हैं।

### **Shared Folders**

- साझा फ़ोल्डर और सेटिंग्स **`System\ControlSet001\Services\lanmanserver\Shares`** के तहत हैं। क्लाइंट साइड कैशिंग (CSC) सेटिंग्स ऑफ़लाइन फ़ाइल उपलब्धता को निर्धारित करती हैं।

### **Programs that Start Automatically**

- पथ जैसे **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** और `Software\Microsoft\Windows\CurrentVersion` के तहत समान प्रविष्टियाँ उन कार्यक्रमों का विवरण देती हैं जो स्टार्टअप पर चलने के लिए सेट हैं।

### **Searches and Typed Paths**

- एक्सप्लोरर खोजें और टाइप किए गए पथ रजिस्ट्री में **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** के तहत ट्रैक किए जाते हैं, क्रमशः WordwheelQuery और TypedPaths के लिए।

### **Recent Documents and Office Files**

- हाल के दस्तावेज़ और Office फ़ाइलें जो एक्सेस की गई हैं, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` और विशिष्ट Office संस्करण पथों में नोट की गई हैं।

### **Most Recently Used (MRU) Items**

- MRU सूचियाँ, जो हाल के फ़ाइल पथ और कमांड को इंगित करती हैं, विभिन्न `ComDlg32` और `Explorer` उपकुंजियों में `NTUSER.DAT` के तहत संग्रहीत होती हैं।

### **User Activity Tracking**

- User Assist फ़ीचर विस्तृत एप्लिकेशन उपयोग आँकड़े लॉग करता है, जिसमें रन गिनती और अंतिम रन समय शामिल है, **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`** पर।

### **Shellbags Analysis**

- Shellbags, जो फ़ोल्डर पहुँच विवरण प्रकट करते हैं, `USRCLASS.DAT` और `NTUSER.DAT` में `Software\Microsoft\Windows\Shell` के तहत संग्रहीत होते हैं। विश्लेषण के लिए **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** का उपयोग करें।

### **USB Device History**

- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** और **`HKLM\SYSTEM\ControlSet001\Enum\USB`** में जुड़े USB उपकरणों के बारे में समृद्ध विवरण होते हैं, जिसमें निर्माता, उत्पाद नाम, और कनेक्शन टाइमस्टैम्प शामिल हैं।
- एक विशिष्ट USB उपकरण से जुड़े उपयोगकर्ता को उस उपकरण के **{GUID}** के लिए `NTUSER.DAT` हाइव में खोजकर पहचाना जा सकता है।
- अंतिम माउंटेड उपकरण और इसका वॉल्यूम सीरियल नंबर `System\MountedDevices` और `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt` के माध्यम से ट्रेस किया जा सकता है।

यह गाइड Windows सिस्टम पर विस्तृत सिस्टम, नेटवर्क, और उपयोगकर्ता गतिविधि जानकारी तक पहुँचने के लिए महत्वपूर्ण पथों और विधियों को संक्षेप में प्रस्तुत करता है, स्पष्टता और उपयोगिता के लिए लक्ष्य बनाते हुए।

{{#include ../../../banners/hacktricks-training.md}}
