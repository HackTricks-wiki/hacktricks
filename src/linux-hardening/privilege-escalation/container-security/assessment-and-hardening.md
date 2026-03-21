# आकलन और हार्डनिंग

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

एक अच्छा container आकलन दो समानांतर प्रश्नों का उत्तर देना चाहिए। पहला: मौजूदा workload से एक attacker क्या कर सकता है? दूसरा: किन operator विकल्पों ने इसे संभव बनाया? Enumeration tools पहले प्रश्न में मदद करते हैं, और hardening guidance दूसरे में। दोनों को एक ही पृष्ठ पर रखना इस अनुभाग को केवल escape tricks की सूची के बजाय फील्ड संदर्भ के रूप में अधिक उपयोगी बनाता है।

## Enumeration टूल्स

कई tools container पर्यावरण का जल्दी से वर्णन करने में उपयोगी रहते हैं:

- `linpeas` कई container संकेतकों, mounted sockets, capability sets, खतरनाक filesystems, और breakout hints की पहचान कर सकता है।
- `CDK` विशेष रूप से container environments पर केंद्रित है और enumeration के साथ कुछ automated escape checks शामिल करता है।
- `amicontained` lightweight है और container restrictions, capabilities, namespace exposure, और संभावित breakout classes की पहचान करने में उपयोगी है।
- `deepce` एक और container-focused enumerator है जिसमें breakout-oriented checks शामिल हैं।
- `grype` तब उपयोगी है जब आकलन में केवल runtime escape analysis के बजाय image-package vulnerability review शामिल हो।

इन tools का मूल्य गति और कवरेज है, न कि निश्चितता। ये जल्दी से मोटा posture प्रकट करने में मदद करते हैं, लेकिन रोचक findings को अभी भी वास्तविक runtime, namespace, capability, और mount model के खिलाफ मैन्युअल व्याख्या की आवश्यकता होती है।

## Hardening प्राथमिकताएँ

सबसे महत्वपूर्ण hardening सिद्धांत अवधारणात्मक रूप से सरल हैं, हालांकि उनका कार्यान्वयन प्लेटफ़ॉर्म के अनुसार बदलता है। Privileged containers से बचें। Mounted runtime sockets से बचें। जब तक बहुत विशिष्ट कारण न हो, containers को writable host paths न दें। जहाँ संभव हो user namespaces या rootless execution का उपयोग करें। सभी capabilities हटाएँ और केवल वही वापस जोड़ें जो workload को वास्तव में चाहिए। application compatibility समस्याओं को ठीक करने के लिए उन्हें disable करने के बजाय seccomp, AppArmor, और SELinux को enabled रखें। संसाधनों को सीमित रखें ताकि एक compromised container आसानी से host को service deny न कर सके।

Image और build hygiene runtime posture जितनी ही मायने रखती हैं। Minimal images का उपयोग करें, अक्सर rebuild करें, उन्हें scan करें, जहाँ संभव हो provenance की आवश्यकता रखें, और layers में secrets न रखें। Non-root के रूप में चल रहा एक container जिसका image छोटा है और जिसकी syscall और capability surface संकीर्ण है, उसे defend करना बहुत आसान है बनिस्बत एक बड़े convenience image के जो host-equivalent root के रूप में चल रहा हो और जिसमें debugging tools preinstalled हों।

## Resource-Exhaustion उदाहरण

Resource controls भले ही भड़कीले न हों, लेकिन वे container security का हिस्सा हैं क्योंकि वे compromise के blast radius को सीमित करते हैं। अगर memory, CPU, या PID limits नहीं हैं, तो एक साधारण shell भी host या पड़ोसी workloads को degrade करने के लिए पर्याप्त हो सकता है।

Example host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
ये उदाहरण उपयोगी हैं क्योंकि वे दिखाते हैं कि हर खतरनाक container परिणाम एक साफ़ "escape" नहीं होता। कमजोर cgroup limits होने पर code execution भी वास्तविक ऑपरेशनल प्रभाव में बदल सकती है।

## हार्डनिंग टूलिंग

Docker-centric परिवेशों में, `docker-bench-security` एक उपयोगी host-side audit baseline बना रहता है क्योंकि यह व्यापक रूप से मान्यता प्राप्त benchmark guidance के विरुद्ध सामान्य configuration मुद्दों की जांच करता है:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
यह टूल threat modeling का विकल्प नहीं है, लेकिन यह समय के साथ जमा होने वाले लापरवाह daemon, mount, network, और runtime defaults को खोजने में फिर भी मूल्यवान है।

## जांच

मूल्यांकन के दौरान त्वरित प्रथम-पास कमांड के रूप में इनका उपयोग करें:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
यहाँ क्या रोचक है:

- विस्तृत capabilities वाले root process और `Seccomp: 0` तुरंत ध्यान के पात्र हैं।
- संदिग्ध mounts और runtime sockets अक्सर किसी भी kernel exploit की तुलना में प्रभाव पहुँचाने का तेज़ मार्ग प्रदान करते हैं।
- कमजोर runtime posture और कमजोर resource limits का संयोजन आमतौर पर एक अलग-थलग गलती की बजाय सामान्यतः permissive container environment की ओर संकेत करता है।
