# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` एक kernel hardening फीचर है जो किसी process को `execve()` के दौरान अतिरिक्त privileges प्राप्त करने से रोकता है। व्यवहार में, एक बार यह flag सेट हो जाने पर, किसी setuid बाइनरी, setgid बाइनरी, या Linux file capabilities वाले फ़ाइल को execute करने से process को उसके मौजूदा privileges से अधिक अधिकार नहीं मिलते। कंटेनर-आधारित वातावरण में यह महत्वपूर्ण है क्योंकि कई privilege-escalation chains इमेज के अंदर ऐसे executable पर निर्भर करते हैं जो लॉन्च होने पर privileges बदल देते हैं।

रक्षा के दृष्टिकोण से, `no_new_privs` namespaces, seccomp, या capability dropping का विकल्प नहीं है। यह एक reinforcement layer है। यह कोड execution प्राप्त हो जाने के बाद होने वाले विशिष्ट प्रकार के follow-up escalation को रोकता है। इसलिए यह उन परिवेशों में विशेष रूप से उपयोगी है जहाँ images में helper binaries, package-manager artifacts, या legacy tools मौजूद होते हैं, जो आंशिक compromise के साथ मिलकर खतरनाक हो सकते हैं।

## ऑपरेशन

इस व्यवहार के पीछे kernel flag `PR_SET_NO_NEW_PRIVS` है। एक बार जब यह किसी process के लिए सेट हो जाता है, तो बाद की `execve()` कॉल्स privileges बढ़ा नहीं सकतीं। महत्वपूर्ण बात यह है कि process अभी भी बाइनरी चला सकता है; बस वह उन बाइनरियों का उपयोग किसी ऐसे privilege सीमा को पार करने के लिए नहीं कर सकता जिसे kernel सामान्यतः मानता।

Kubernetes-उन्मुख वातावरण में, `allowPrivilegeEscalation: false` कंटेनर प्रक्रिया के लिए इस व्यवहार से मेल खाता है। Docker और Podman जैसे runtimes में, समान सेटिंग आमतौर पर एक security option के माध्यम से स्पष्ट रूप से सक्षम की जाती है।

## लैब

वर्तमान process स्थिति का निरीक्षण करें:
```bash
grep NoNewPrivs /proc/self/status
```
उसकी तुलना ऐसे कंटेनर से करें जहाँ runtime फ्लैग सक्षम है:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
कठोर सुरक्षा वाले वर्कलोड पर, परिणाम में `NoNewPrivs: 1` दिखना चाहिए।

## सुरक्षा प्रभाव

यदि `no_new_privs` मौजूद नहीं है, तो container के अंदर पाया गया foothold अभी भी setuid helpers या file capabilities वाले बायनरी के माध्यम से उन्नत (upgrade) किया जा सकता है। यदि यह मौजूद है, तो exec के बाद होने वाले उन privilege परिवर्तनों को रोका जाता है। यह प्रभाव विशेषकर उन broad base images में प्रासंगिक है जो कई ऐसे utilities शिप करते हैं जिनकी application को मूल रूप से कभी जरूरत ही नहीं थी।

## गलत कॉन्फ़िगरेशन

सबसे आम समस्या यह है कि उस नियंत्रण को उन वातावरणों में सक्षम नहीं करना जहां यह अनुकूल होगा। Kubernetes में, अक्सर `allowPrivilegeEscalation` को enabled छोड़ देना सामान्य ऑपरेशनल गलती होती है। Docker और Podman में, संबंधित security option को छोड़ देने से वही असर होता है। एक और बार-बार होने वाला विफलता मोड यह मानना है कि चूँकि एक container "not privileged" है, exec-time privilege transitions स्वाभाविक रूप से अप्रासंगिक हैं।

## दुरुपयोग

यदि `no_new_privs` सेट नहीं है, तो पहला सवाल यह है कि क्या image में ऐसे बायनरी मौजूद हैं जो अभी भी privilege बढ़ा सकते हैं:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
दिलचस्प परिणामों में शामिल हैं:

- `NoNewPrivs: 0`
- setuid helpers जैसे `su`, `mount`, `passwd`, या distribution-specific प्रशासनिक उपकरण
- ऐसी बाइनरीज़ जिनमें file capabilities हैं जो नेटवर्क या फ़ाइलसिस्टम अनुमतियाँ प्रदान करती हैं

वास्तविक आकलन में, ये निष्कर्ष अपने आप में किसी कामकाजी escalation को साबित नहीं करते, लेकिन ये ठीक-ठीक उन बाइनरीज़ की पहचान करते हैं जिन्हें अगले परीक्षण के लिए आज़माना चाहिए।

### पूर्ण उदाहरण: In-Container Privilege Escalation Through setuid

यह नियंत्रण आमतौर पर **in-container privilege escalation** को रोकता है, न कि सीधे host escape को। यदि `NoNewPrivs` `0` है और एक setuid helper मौजूद है, तो इसे स्पष्ट रूप से टेस्ट करें:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
यदि कोई ज्ञात setuid binary मौजूद और कार्यरत है, तो इसे इस तरह लॉन्च करने की कोशिश करें कि privilege transition संरक्षित रहे:
```bash
/bin/su -c id 2>/dev/null
```
यह अपने आप container से बाहर नहीं निकलता, लेकिन यह container के अंदर एक low-privilege foothold को container-root में बदल सकता है, जो अक्सर बाद में mounts, runtime sockets, या kernel-facing interfaces के जरिए host escape के लिए आवश्यक शर्त बन जाता है।

## Checks

इन checks का लक्ष्य यह स्थापित करना है कि क्या exec-time privilege gain ब्लॉक किया गया है और क्या image में अभी भी ऐसे helpers मौजूद हैं जो यदि ब्लॉक न किया गया हो तो मायने रखेंगे।
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
यहाँ दिलचस्प बातें:

- `NoNewPrivs: 1` आमतौर पर सुरक्षित परिणाम होता है।
- `NoNewPrivs: 0` का मतलब है कि setuid और file-cap आधारित उन्नयन पथ प्रासंगिक बने रहते हैं।
- एक minimal image जिसमें कम या कोई setuid/file-cap बाइनरी न हों, हमलावर के लिए कम post-exploitation विकल्प देता है, भले ही `no_new_privs` अनुपस्थित हो।

## रनटाइम डिफ़ॉल्ट

| Runtime / प्लेटफ़ॉर्म | डिफ़ॉल्ट स्थिति | डिफ़ॉल्ट व्यवहार | आम मैन्युअल कमजोरियाँ |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से सक्षम नहीं | स्पष्ट रूप से `--security-opt no-new-privileges=true` के साथ सक्षम किया जाता है | फ्लैग छोड़ना, `--privileged` |
| Podman | डिफ़ॉल्ट रूप से सक्षम नहीं | स्पष्ट रूप से `--security-opt no-new-privileges` या समकक्ष सुरक्षा कॉन्फ़िगरेशन के साथ सक्षम | विकल्प छोड़ना, `--privileged` |
| Kubernetes | वर्कलोड नीति द्वारा नियंत्रित | `allowPrivilegeEscalation: false` प्रभाव को सक्षम करता है; कई वर्कलोड अभी भी इसे सक्षम छोड़ देते हैं | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes वर्कलोड सेटिंग्स का पालन करता है | आम तौर पर Pod सुरक्षा संदर्भ से विरासत में मिलता है | Kubernetes पंक्ति के समान |

यह सुरक्षा अक्सर इसलिए अनुपस्थित रहती है क्योंकि किसी ने इसे चालू नहीं किया, न कि इसलिए कि runtime इसका समर्थन नहीं करता।
{{#include ../../../../banners/hacktricks-training.md}}
