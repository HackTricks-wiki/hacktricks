# Integrity Levels

{{#include ../../banners/hacktricks-training.md}}

## Integrity Levels

Windows Vista और इसके बाद के संस्करणों में, सभी संरक्षित वस्तुओं के साथ एक **integrity level** टैग होता है। यह सेटअप ज्यादातर फ़ाइलों और रजिस्ट्री कुंजियों को "मध्यम" integrity level असाइन करता है, कुछ फ़ोल्डरों और फ़ाइलों को छोड़कर जिनमें Internet Explorer 7 कम integrity level पर लिख सकता है। डिफ़ॉल्ट व्यवहार यह है कि मानक उपयोगकर्ताओं द्वारा शुरू की गई प्रक्रियाओं का मध्यम integrity level होता है, जबकि सेवाएँ आमतौर पर सिस्टम integrity level पर कार्य करती हैं। एक उच्च-integrity लेबल रूट निर्देशिका की सुरक्षा करता है।

एक मुख्य नियम यह है कि वस्तुओं को उन प्रक्रियाओं द्वारा संशोधित नहीं किया जा सकता है जिनका integrity level वस्तु के स्तर से कम है। integrity levels हैं:

- **Untrusted**: यह स्तर उन प्रक्रियाओं के लिए है जिनमें गुमनाम लॉगिन होते हैं। %%%Example: Chrome%%%
- **Low**: मुख्य रूप से इंटरनेट इंटरैक्शन के लिए, विशेष रूप से Internet Explorer के Protected Mode में, संबंधित फ़ाइलों और प्रक्रियाओं को प्रभावित करता है, और कुछ फ़ोल्डर जैसे **Temporary Internet Folder**। Low integrity प्रक्रियाओं को महत्वपूर्ण प्रतिबंधों का सामना करना पड़ता है, जिसमें रजिस्ट्री लिखने की अनुमति नहीं और सीमित उपयोगकर्ता प्रोफ़ाइल लिखने की अनुमति शामिल है।
- **Medium**: अधिकांश गतिविधियों के लिए डिफ़ॉल्ट स्तर, मानक उपयोगकर्ताओं और बिना विशिष्ट integrity levels वाली वस्तुओं को असाइन किया गया। यहां तक कि Administrators समूह के सदस्य भी डिफ़ॉल्ट रूप से इस स्तर पर कार्य करते हैं।
- **High**: प्रशासकों के लिए आरक्षित, उन्हें निम्न integrity levels पर वस्तुओं को संशोधित करने की अनुमति देता है, जिसमें उच्च स्तर पर स्वयं वस्तुएं भी शामिल हैं।
- **System**: Windows कर्नेल और कोर सेवाओं के लिए सबसे उच्चतम संचालन स्तर, जो प्रशासकों के लिए भी पहुंच से बाहर है, महत्वपूर्ण सिस्टम कार्यों की सुरक्षा सुनिश्चित करता है।
- **Installer**: एक अद्वितीय स्तर जो सभी अन्य स्तरों से ऊपर है, इस स्तर पर वस्तुओं को किसी अन्य वस्तु को अनइंस्टॉल करने की अनुमति देता है।

आप **Process Explorer** का उपयोग करके एक प्रक्रिया का integrity level प्राप्त कर सकते हैं **Sysinternals** से, प्रक्रिया की **properties** तक पहुँचकर और "**Security**" टैब को देख कर:

![](<../../images/image (824).png>)

आप `whoami /groups` का उपयोग करके अपना **current integrity level** भी प्राप्त कर सकते हैं

![](<../../images/image (325).png>)

### Integrity Levels in File-system

फ़ाइल-सिस्टम के अंदर एक वस्तु को **न्यूनतम integrity level आवश्यकता** की आवश्यकता हो सकती है और यदि एक प्रक्रिया के पास यह integrity level नहीं है तो वह इसके साथ इंटरैक्ट नहीं कर सकेगी।\
उदाहरण के लिए, चलिए **एक नियमित उपयोगकर्ता कंसोल फ़ाइल से एक नियमित फ़ाइल बनाते हैं और अनुमतियों की जांच करते हैं**:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
अब, फ़ाइल को **उच्च** इंटीग्रिटी स्तर सौंपते हैं। यह **एक कंसोल से किया जाना चाहिए** जो **व्यवस्थापक** के रूप में चल रहा हो क्योंकि **सामान्य कंसोल** मध्यम इंटीग्रिटी स्तर पर चल रहा होगा और **उच्च इंटीग्रिटी स्तर** को किसी ऑब्जेक्ट को सौंपने की अनुमति **नहीं होगी**:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
यहाँ चीजें दिलचस्प हो जाती हैं। आप देख सकते हैं कि उपयोगकर्ता `DESKTOP-IDJHTKP\user` के पास फ़ाइल पर **पूर्ण विशेषाधिकार** हैं (वास्तव में, यही वह उपयोगकर्ता है जिसने फ़ाइल बनाई थी), हालाँकि, लागू किए गए न्यूनतम इंटीग्रिटी स्तर के कारण वह फ़ाइल को और संशोधित नहीं कर पाएगा जब तक कि वह उच्च इंटीग्रिटी स्तर के भीतर नहीं चल रहा है (ध्यान दें कि वह इसे पढ़ सकेगा):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!NOTE]
> **इसलिए, जब एक फ़ाइल का न्यूनतम इंटीग्रिटी स्तर होता है, तो इसे संशोधित करने के लिए आपको कम से कम उस इंटीग्रिटी स्तर पर चलाना होगा।**

### बाइनरी में इंटीग्रिटी स्तर

मैंने `cmd.exe` की एक प्रति `C:\Windows\System32\cmd-low.exe` में बनाई और इसे **एक व्यवस्थापक कंसोल से निम्न इंटीग्रिटी स्तर पर सेट किया:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
अब, जब मैं `cmd-low.exe` चलाता हूँ, यह **कम-इंटीग्रिटी लेवल** के तहत चलेगा बजाय मध्यम के:

![](<../../images/image (313).png>)

जिज्ञासु लोगों के लिए, यदि आप एक बाइनरी को उच्च इंटीग्रिटी लेवल असाइन करते हैं (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), तो यह स्वचालित रूप से उच्च इंटीग्रिटी लेवल के साथ नहीं चलेगा (यदि आप इसे मध्यम इंटीग्रिटी लेवल से बुलाते हैं --डिफ़ॉल्ट रूप से-- यह मध्यम इंटीग्रिटी लेवल के तहत चलेगा)।

### प्रक्रियाओं में इंटीग्रिटी लेवल

सभी फ़ाइलों और फ़ोल्डरों का एक न्यूनतम इंटीग्रिटी लेवल नहीं होता, **लेकिन सभी प्रक्रियाएँ एक इंटीग्रिटी लेवल के तहत चल रही हैं**। और फ़ाइल-सिस्टम के साथ जो हुआ, उसके समान, **यदि एक प्रक्रिया किसी अन्य प्रक्रिया के अंदर लिखना चाहती है, तो उसके पास कम से कम वही इंटीग्रिटी लेवल होना चाहिए**। इसका मतलब है कि कम इंटीग्रिटी लेवल वाली प्रक्रिया मध्यम इंटीग्रिटी लेवल वाली प्रक्रिया के लिए पूर्ण पहुँच के साथ हैंडल नहीं खोल सकती।

इस और पिछले अनुभाग में टिप्पणी की गई प्रतिबंधों के कारण, सुरक्षा के दृष्टिकोण से, हमेशा **कम से कम इंटीग्रिटी लेवल पर प्रक्रिया चलाने की सिफारिश की जाती है**।

{{#include ../../banners/hacktricks-training.md}}
