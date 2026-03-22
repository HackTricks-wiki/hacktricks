# मूल्यांकन और हार्डनिंग

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

एक अच्छा container assessment दो समानांतर प्रश्नों का उत्तर देना चाहिए। पहला, वर्तमान workload से एक attacker क्या कर सकता है? दूसरा, किन operator विकल्पों ने उसे यह करने में सक्षम बनाया? Enumeration tools पहले प्रश्न में मदद करते हैं, और hardening guidance दूसरे में। दोनों को एक ही पृष्ठ पर रखना इस सेक्शन को केवल escape tricks के कैटलॉग से अधिक उपयोगी बनाता है—यह एक फील्ड रेफरेंस के रूप में काम करता है।

## Enumeration Tools

कई tools container environment को जल्दी से characterize करने में उपयोगी रहते हैं:

- `linpeas` कई container indicators, mounted sockets, capability sets, dangerous filesystems, और breakout hints पहचान सकता है।
- `CDK` विशेष रूप से container environments पर केंद्रित है और इसमें enumeration के साथ कुछ automated escape checks भी शामिल हैं।
- `amicontained` हल्का है और container restrictions, capabilities, namespace exposure, और संभावित breakout classes पहचानने में उपयोगी है।
- `deepce` एक और container-focused enumerator है जिसमें breakout-oriented checks हैं।
- `grype` तब उपयोगी होता है जब assessment में केवल runtime escape analysis के बजाय image-package vulnerability review भी शामिल हो।

इन tools का मूल्य गति और कवरेज है, निश्चितता नहीं। ये जल्दी से मोटा-पोस्टर बताते हैं, लेकिन रोचक findings का अभी भी वास्तविक runtime, namespace, capability, और mount मॉडल के खिलाफ मैन्युअल अर्थ लगाना ज़रूरी होता है।

## Hardening Priorities

सबसे महत्वपूर्ण hardening सिद्धांत अवधारणात्मक रूप से सरल हैं हालांकि उनका implementation प्लेटफ़ॉर्म के अनुसार बदलता है। privileged containers से बचें। mounted runtime sockets से बचें। containers को writable host paths तब तक न दें जब तक बहुत स्पष्ट कारण न हो। जहाँ संभव हो user namespaces या rootless execution का उपयोग करें। सभी capabilities गिरा दें और केवल वे ही वापस जोड़ें जिनकी workload को वास्तव में आवश्यकता है। application compatibility समस्याओं को ठीक करने के लिए seccomp, AppArmor, और SELinux को disable करने के बजाय इन्हें enabled रखें। resources सीमित रखें ताकि एक compromised container आसानी से host को service deny न कर सके।

Image और build hygiene runtime posture जितना ही मायने रखती हैं। minimal images का उपयोग करें, अक्सर rebuild करें, उन्हें scan करें, जहाँ व्यावहारिक हो provenance की मांग करें, और layers में secrets न रखें। एक container जो non-root के रूप में चल रहा है, छोटा image है, और उसका syscall तथा capability surface संकीर्ण है, उसे डिफेंड करना बहुत आसान है बनाम एक बड़े convenience image के जो host-equivalent root के रूप में चल रहा हो और उसमें debugging tools पहले से इंस्टॉल हों।

## Resource-Exhaustion Examples

Resource controls ग्लैमरस नहीं होते, लेकिन वे container security का हिस्सा हैं क्योंकि ये compromise के blast radius को सीमित करते हैं। memory, CPU, या PID limits के बिना, एक साधारण shell भी host या पड़ोसी workloads को degrade करने के लिए काफी हो सकता है।

Example host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
ये उदाहरण उपयोगी हैं क्योंकि वे दिखाते हैं कि हर खतरनाक container परिणाम एक साफ़ "escape" नहीं होता। कमजोर cgroup limits फिर भी code execution को वास्तविक operational impact में बदल सकते हैं।

## Hardening Tooling

For Docker-centric environments, `docker-bench-security` remains a useful host-side audit baseline because it checks common configuration issues against widely recognized benchmark guidance:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
यह टूल threat modeling का विकल्प नहीं है, लेकिन यह समय के साथ जमा होने वाले लापरवाही से कॉन्फ़िगर किए गए daemon, mount, network, और runtime defaults को खोजने में फिर भी उपयोगी है।

## Checks

इनका उपयोग आकलन के दौरान त्वरित प्रारंभिक कमांड्स के रूप में करें:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
What is interesting here:

- एक root process जिसके पास व्यापक capabilities हों और `Seccomp: 0` हो, तुरंत ध्यान देने योग्य है।
- संदिग्ध mounts और runtime sockets अक्सर किसी भी kernel exploit की तुलना में प्रभाव तक पहुँचने का तेज़ मार्ग प्रदान करते हैं।
- कमजोर runtime posture और कमजोर resource limits का संयोजन आम तौर पर एकल अलग हुई गलती के बजाय सामान्यतः permissive container environment की ओर संकेत करता है।
{{#include ../../../banners/hacktricks-training.md}}
