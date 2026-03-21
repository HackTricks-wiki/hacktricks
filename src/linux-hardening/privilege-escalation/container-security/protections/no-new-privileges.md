# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` एक कर्नेल हार्डनिंग फीचर है जो किसी process को `execve()` के जरिए अधिक प्रिविलेज हासिल करने से रोकता है। व्यवहारिक रूप में, एक बार यह flag सेट हो जाने पर, setuid बाइनरी, setgid बाइनरी, या Linux file capabilities वाले फ़ाइल को execute करने पर भी प्रोसेस को मौजूद प्रिविलेज के अलावा अतिरिक्त प्रिविलेज नहीं मिलते। containerized परिवेशों में यह महत्वपूर्ण है क्योंकि कई privilege-escalation चेन उस तरह के executable पर निर्भर होते हैं जो image के अंदर मिलता है और लॉन्च होने पर प्रिविलेज बदल देता है।

रक्षा की दृष्टि से, `no_new_privs` namespaces, seccomp, या capability dropping का विकल्प नहीं है। यह एक reinforcement layer है। यह कोड execution प्राप्त हो जाने के बाद होने वाली एक विशेष प्रकार की follow-up escalation को रोकता है। इसलिए यह उन परिवेशों में विशेष रूप से उपयोगी है जहाँ images में helper binaries, package-manager artifacts, या legacy tools होते हैं जो partial compromise के साथ मिलकर खतरनाक हो सकते हैं।

## ऑपरेशन

इस व्यवहार के पीछे कर्नेल flag `PR_SET_NO_NEW_PRIVS` है। एक बार यह किसी process के लिए सेट हो जाने पर बाद के `execve()` कॉल प्रिविलेज बढ़ा नहीं सकते। महत्वपूर्ण बात यह है कि प्रोसेस अभी भी बाइनरी चला सकता है; बस वह उन बाइनरियों का उपयोग उस प्रिविलेज सीमा को पार करने के लिए नहीं कर सकता जिसे कर्नेल सामान्यत: मान्यता देता।

Kubernetes-संगत परिवेशों में, `allowPrivilegeEscalation: false` container process के लिए इस व्यवहार के अनुरूप होता है। Docker और Podman शैली के runtimes में, समान व्यवहार आमतौर पर एक security option के जरिए स्पष्ट रूप से सक्षम किया जाता है।

## लैब

वर्तमान process स्थिति की जाँच करें:
```bash
grep NoNewPrivs /proc/self/status
```
इसे उस container से तुलना करें जहाँ runtime flag सक्षम है:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
On a hardened workload, the result should show `NoNewPrivs: 1`.

## सुरक्षा प्रभाव

यदि `no_new_privs` अनुपस्थित है, तो कंटेनर के अंदर प्राप्त foothold को अभी भी setuid helpers या binaries with file capabilities के माध्यम से बढ़ाया जा सकता है। यदि यह मौजूद है, तो ये post-exec privilege परिवर्तन अवरुद्ध हो जाते हैं। यह प्रभाव विशेष रूप से उन व्यापक बेस इमेजेज़ में महत्वपूर्ण है जो कई ऐसे utilities भेजती हैं जिनकी application को मूल रूप से आवश्यकता ही नहीं थी।

## मिसकंफिगरेशन

सबसे सामान्य समस्या बस उस नियंत्रण को सक्षम न करना है जहाँ यह compatible होगा। In Kubernetes, leaving `allowPrivilegeEscalation` enabled is often the default operational mistake. In Docker and Podman, omitting the relevant security option has the same effect. एक और बार-बार होने वाला विफलता मोड यह मानना है कि क्योंकि एक कंटेनर 'not privileged' है, exec-time privilege transitions स्वचालित रूप से अप्रासंगिक हैं।

## दुरुपयोग

यदि `no_new_privs` सेट नहीं है, तो पहला सवाल यह है कि क्या इमेज में ऐसे binaries मौजूद हैं जो अभी भी privilege बढ़ा सकते हैं:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
दिलचस्प परिणामों में शामिल हैं:

- `NoNewPrivs: 0`
- setuid helpers जैसे कि `su`, `mount`, `passwd`, या distribution-specific admin tools
- ऐसे binaries जिनमें file capabilities हों जो network या filesystem privileges प्रदान करते हों

### पूर्ण उदाहरण: In-Container Privilege Escalation Through setuid

यह नियंत्रण आम तौर पर host escape को सीधे रोकने के बजाय **in-container privilege escalation** को रोकता है। यदि `NoNewPrivs` `0` है और कोई setuid helper मौजूद है, तो इसका स्पष्ट रूप से परीक्षण करें:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
यदि कोई ज्ञात setuid binary मौजूद और functional है, तो इसे ऐसे लॉन्च करने का प्रयास करें जो privilege transition को संरक्षित करे:
```bash
/bin/su -c id 2>/dev/null
```
यह खुद से container को escape नहीं करता, लेकिन यह container के अंदर एक low-privilege foothold को container-root में बदल सकता है, जो अक्सर बाद में host escape के लिए mounts, runtime sockets, या kernel-facing interfaces के माध्यम से आवश्यक पूर्व-शर्त बन जाता है।

## जांचें

इन जांचों का उद्देश्य यह निर्धारित करना है कि exec-time privilege gain अवरुद्ध है या नहीं, और यदि अवरुद्ध नहीं है तो image में अभी भी ऐसे helpers मौजूद हैं या नहीं जो मायने रखेंगे।
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
What is interesting here:

- `NoNewPrivs: 1` आम तौर पर सुरक्षित परिणाम होता है।
- `NoNewPrivs: 0` का अर्थ है कि setuid और file-cap आधारित escalation paths प्रासंगिक बनी रहती हैं।
- एक minimal image जिसमें कुछ या कोई setuid/file-cap binaries नहीं होते, वह हमलावर को कम post-exploitation विकल्प देता है भले ही `no_new_privs` गायब हो।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से सक्षम नहीं | Enabled explicitly with `--security-opt no-new-privileges=true` | फ्लैग छोड़ना, `--privileged` |
| Podman | डिफ़ॉल्ट रूप से सक्षम नहीं | Enabled explicitly with `--security-opt no-new-privileges` or equivalent security configuration | विकल्प छोड़ना, `--privileged` |
| Kubernetes | वर्कलोड नीति द्वारा नियंत्रित | `allowPrivilegeEscalation: false` enables the effect; कई वर्कलोड इसे अभी भी सक्षम छोड़ देते हैं | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes वर्कलोड सेटिंग्स का पालन करता है | आमतौर पर Pod security context से विरासत में मिलता है | Kubernetes पंक्ति के समान |

यह सुरक्षा अक्सर इसलिए अनुपस्थित रहती है क्योंकि किसी ने इसे चालू नहीं किया होता, न कि इसलिए कि runtime में इसका समर्थन नहीं है।
