# macOS नेटवर्क सेवाएँ और प्रोटोकॉल

{{#include ../../banners/hacktricks-training.md}}

## रिमोट एक्सेस सेवाएँ

ये सामान्य macOS सेवाएँ हैं जिन्हें आप दूरस्थ रूप से एक्सेस कर सकते हैं।\
आप इन सेवाओं को `System Settings` --> `Sharing` में सक्षम/अक्षम कर सकते हैं।

- **VNC**, जिसे “Screen Sharing” के रूप में जाना जाता है (tcp:5900)
- **SSH**, जिसे “Remote Login” कहा जाता है (tcp:22)
- **Apple Remote Desktop** (ARD), या “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, जिसे “Remote Apple Event” के रूप में जाना जाता है (tcp:3031)

जांचें कि क्या इनमें से कोई सक्षम है:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) एक उन्नत संस्करण है [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) का, जो macOS के लिए अनुकूलित है, जो अतिरिक्त सुविधाएँ प्रदान करता है। ARD में एक उल्लेखनीय सुरक्षा कमी इसका नियंत्रण स्क्रीन पासवर्ड के लिए प्रमाणीकरण विधि है, जो केवल पासवर्ड के पहले 8 अक्षरों का उपयोग करती है, जिससे यह [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) के प्रति संवेदनशील हो जाती है, जैसे कि Hydra या [GoRedShell](https://github.com/ahhh/GoRedShell/) के साथ, क्योंकि कोई डिफ़ॉल्ट दर सीमा नहीं है।

संवेदनशील उदाहरणों की पहचान **nmap** के `vnc-info` स्क्रिप्ट का उपयोग करके की जा सकती है। सेवाएँ जो `VNC Authentication (2)` का समर्थन करती हैं, विशेष रूप से 8-अक्षर पासवर्ड कटौती के कारण brute force हमलों के प्रति संवेदनशील होती हैं।

प्रिविलेज वृद्धि, GUI एक्सेस, या उपयोगकर्ता निगरानी जैसे विभिन्न प्रशासनिक कार्यों के लिए ARD को सक्षम करने के लिए, निम्नलिखित कमांड का उपयोग करें:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD विभिन्न नियंत्रण स्तर प्रदान करता है, जिसमें अवलोकन, साझा नियंत्रण और पूर्ण नियंत्रण शामिल हैं, और सत्र उपयोगकर्ता पासवर्ड परिवर्तन के बाद भी बने रहते हैं। यह सीधे Unix कमांड भेजने की अनुमति देता है, जिन्हें प्रशासनिक उपयोगकर्ताओं के लिए रूट के रूप में निष्पादित किया जाता है। कार्य अनुसूची और रिमोट स्पॉटलाइट खोज उल्लेखनीय विशेषताएँ हैं, जो कई मशीनों में संवेदनशील फ़ाइलों के लिए दूरस्थ, कम-प्रभाव वाली खोजों को सुविधाजनक बनाती हैं।

## Bonjour प्रोटोकॉल

Bonjour, एक Apple द्वारा डिज़ाइन की गई तकनीक, **एक ही नेटवर्क पर उपकरणों को एक-दूसरे की पेश की गई सेवाओं का पता लगाने** की अनुमति देती है। इसे Rendezvous, **Zero Configuration**, या Zeroconf के रूप में भी जाना जाता है, यह एक उपकरण को TCP/IP नेटवर्क में शामिल होने, **स्वचालित रूप से एक IP पता चुनने**, और अन्य नेटवर्क उपकरणों को अपनी सेवाएँ प्रसारित करने में सक्षम बनाता है।

Zero Configuration Networking, जो Bonjour द्वारा प्रदान किया जाता है, सुनिश्चित करता है कि उपकरण:

- **DHCP सर्वर की अनुपस्थिति में भी स्वचालित रूप से एक IP पता प्राप्त करें।**
- **DNS सर्वर की आवश्यकता के बिना नाम-से-पता अनुवाद** कर सकें।
- नेटवर्क पर उपलब्ध **सेवाओं का पता लगाएँ।**

Bonjour का उपयोग करने वाले उपकरण **169.254/16 रेंज** से एक **IP पता असाइन** करेंगे और नेटवर्क पर इसकी विशिष्टता की पुष्टि करेंगे। Macs इस उपनेट के लिए एक रूटिंग टेबल प्रविष्टि बनाए रखते हैं, जिसे `netstat -rn | grep 169` के माध्यम से सत्यापित किया जा सकता है।

DNS के लिए, Bonjour **Multicast DNS (mDNS) प्रोटोकॉल** का उपयोग करता है। mDNS **port 5353/UDP** पर कार्य करता है, **मानक DNS प्रश्नों** का उपयोग करते हुए लेकिन **multicast address 224.0.0.251** को लक्षित करता है। यह दृष्टिकोण सुनिश्चित करता है कि नेटवर्क पर सभी सुनने वाले उपकरण प्रश्नों को प्राप्त और उत्तर दे सकें, जिससे उनके रिकॉर्ड को अपडेट करना सुविधाजनक हो जाता है।

नेटवर्क में शामिल होने पर, प्रत्येक उपकरण एक नाम का स्व-चयन करता है, जो आमतौर पर **.local** में समाप्त होता है, जो होस्टनाम से व्युत्पन्न हो सकता है या यादृच्छिक रूप से उत्पन्न हो सकता है।

नेटवर्क के भीतर सेवा खोज को **DNS सेवा खोज (DNS-SD)** द्वारा सुविधाजनक बनाया जाता है। DNS SRV रिकॉर्ड के प्रारूप का लाभ उठाते हुए, DNS-SD **DNS PTR रिकॉर्ड** का उपयोग करके कई सेवाओं की सूची बनाने में सक्षम बनाता है। एक ग्राहक एक विशिष्ट सेवा की तलाश में `<Service>.<Domain>` के लिए एक PTR रिकॉर्ड का अनुरोध करेगा, यदि सेवा कई होस्टों से उपलब्ध है तो उसे `<Instance>.<Service>.<Domain>` के रूप में प्रारूपित PTR रिकॉर्ड की एक सूची प्राप्त होगी।

`dns-sd` उपयोगिता का उपयोग **नेटवर्क सेवाओं की खोज और विज्ञापन** के लिए किया जा सकता है। इसके उपयोग के कुछ उदाहरण इस प्रकार हैं:

### SSH सेवाओं की खोज

नेटवर्क पर SSH सेवाओं की खोज के लिए, निम्नलिखित कमांड का उपयोग किया जाता है:
```bash
dns-sd -B _ssh._tcp
```
यह कमांड \_ssh.\_tcp सेवाओं के लिए ब्राउज़िंग शुरू करता है और टाइमस्टैम्प, फ्लैग, इंटरफेस, डोमेन, सेवा प्रकार, और इंस्टेंस नाम जैसी जानकारी आउटपुट करता है।

### HTTP सेवा का विज्ञापन करना

HTTP सेवा का विज्ञापन करने के लिए, आप उपयोग कर सकते हैं:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
यह कमांड पोर्ट 80 पर `/index.html` के पथ के साथ "Index" नामक एक HTTP सेवा को पंजीकृत करता है।

फिर नेटवर्क पर HTTP सेवाओं की खोज करने के लिए:
```bash
dns-sd -B _http._tcp
```
जब एक सेवा शुरू होती है, तो यह अपने अस्तित्व की घोषणा सभी उपकरणों को सबनेट पर मल्टीकास्ट करके करती है। इन सेवाओं में रुचि रखने वाले उपकरणों को अनुरोध भेजने की आवश्यकता नहीं होती है, बल्कि वे बस इन घोषणाओं को सुनते हैं।

एक अधिक उपयोगकर्ता-अनुकूल इंटरफ़ेस के लिए, **Discovery - DNS-SD Browser** ऐप जो Apple App Store पर उपलब्ध है, आपके स्थानीय नेटवर्क पर उपलब्ध सेवाओं को दृश्य रूप में प्रदर्शित कर सकता है।

वैकल्पिक रूप से, सेवाओं को ब्राउज़ और खोजने के लिए कस्टम स्क्रिप्ट लिखी जा सकती हैं जो `python-zeroconf` लाइब्रेरी का उपयोग करती हैं। [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) स्क्रिप्ट `_http._tcp.local.` सेवाओं के लिए एक सेवा ब्राउज़र बनाने का प्रदर्शन करती है, जो जोड़ी गई या हटी हुई सेवाओं को प्रिंट करती है:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Bonjour को बंद करना

यदि सुरक्षा के बारे में चिंताएँ हैं या Bonjour को बंद करने के अन्य कारण हैं, तो इसे निम्नलिखित कमांड का उपयोग करके बंद किया जा सकता है:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## संदर्भ

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

{{#include ../../banners/hacktricks-training.md}}
