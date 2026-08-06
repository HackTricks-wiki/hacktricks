# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

[https://www.exemsi.com/documentation/getting-started/](https://www.exemsi.com/download/) से free version app download करें, इसे execute करें और इसमें "malicious" binary को wrap करें।\
ध्यान दें कि यदि आप केवल **command lines execute** करना चाहते हैं, तो आप "**.bat**" को wrap कर सकते हैं (**cmd.exe** चुनने के बजाय .bat file चुनें)।

![MSI Wrapper: ध्यान दें कि यदि आप केवल command lines execute करना चाहते हैं, तो आप " .bat " को wrap कर सकते हैं (cmd.exe चुनने के बजाय .bat file चुनें)](<../../images/image (417).png>)

और configuration का यह सबसे महत्वपूर्ण भाग है:

![MSI Wrapper: और यह configuration का सबसे महत्वपूर्ण भाग है](<../../images/image (312).png>)

![MSI Wrapper: और यह configuration का सबसे महत्वपूर्ण भाग है](<../../images/image (346).png>)

![MSI Wrapper: और यह configuration का सबसे महत्वपूर्ण भाग है](<../../images/image (1072).png>)

(कृपया ध्यान दें कि यदि आप अपनी स्वयं की binary को pack करने का प्रयास करते हैं, तो आप इन values को modify कर पाएंगे।)

अब केवल **next buttons** पर click करें और अंत में **build button** पर click करें; आपका installer/wrapper generate हो जाएगा।

{{#include ../../banners/hacktricks-training.md}}
