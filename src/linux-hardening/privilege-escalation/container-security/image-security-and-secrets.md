# इमेज सुरक्षा, साइनिंग और सीक्रेट्स

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

कंटेनर सुरक्षा वर्कलोड लॉन्च होने से पहले ही शुरू होती है। इमेज तय करती है कि कौन से बाइनरीज़, इंटरप्रेटर, लाइब्रेरीज़, स्टार्टअप स्क्रिप्ट्स और एम्बेडेड कॉन्फ़िगरेशन प्रोडक्शन तक पहुँचेंगे। अगर इमेज backdoored, stale, या इसमें सीक्रेट्स बेक किए गए हों, तो बाद में किया गया runtime hardening पहले से ही एक समझौता किए गए आर्टिफैक्ट पर लागू हो रहा होता है।

इसीलिए इमेज की provenance, vulnerability scanning, signature verification, और secret handling को namespaces और seccomp जैसी चीज़ों के साथ ही चर्चा में रखा जाना चाहिए। ये लाइफसाइकल के एक अलग चरण की रक्षा करते हैं, लेकिन यहाँ की असफलताएँ अक्सर उस attack surface को परिभाषित कर देती हैं जिसे बाद में runtime को नियंत्रित करना पड़ता है।

## इमेज रजिस्ट्रीज़ और ट्रस्ट

इमेज सार्वजनिक रजिस्ट्रीज़ जैसे Docker Hub से आ सकती हैं या किसी organization द्वारा ऑपरेट की गई निजी रजिस्ट्रीज़ से। सुरक्षा का सवाल सिर्फ यह नहीं है कि इमेज कहाँ रहती है, बल्कि क्या टीम उसकी provenance और integrity स्थापित कर सकती है। सार्वजनिक स्रोतों से unsigned या कमजोर तरीके से ट्रैक की गई इमेज खींचने से प्रोडक्शन में malicious या tampered कंटेंट पहुँचने का जोखिम बढ़ जाता है। यहाँ तक कि internally hosted रजिस्ट्रीज़ को भी स्पष्ट ownership, review, और trust policy की आवश्यकता होती है।

Docker Content Trust historically used Notary and TUF concepts to require signed images. The exact ecosystem has evolved, but the enduring lesson remains useful: image identity and integrity should be verifiable rather than assumed.

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
उदाहरण का मकसद यह नहीं है कि हर टीम को अभी भी वही tooling इस्तेमाल करना चाहिए, बल्कि यह बताना है कि signing और key management कोई सैद्धान्तिक बात नहीं बल्कि ऑपरेशनल कार्य हैं।

## Vulnerability Scanning

Image scanning दो अलग-अलग सवालों के जवाब देने में मदद करता है। पहला, क्या image में ज्ञात vulnerable packages या libraries मौजूद हैं? दूसरा, क्या image अनावश्यक software लेकर चल रहा है जो attack surface को बढ़ाता है? debugging tools, shells, interpreters, और stale packages से भरा image न सिर्फ़ exploit करने में आसान होता है बल्कि समझने में भी कठिन होता है।

अक्सर उपयोग किए जाने वाले scanners के उदाहरण:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
इन टूल्स के परिणामों की व्याख्या सावधानी से करनी चाहिए। किसी अप्रयुक्त पैकेज में मौजूद एक vulnerability का जोखिम एक exposed RCE path के बराबर नहीं होता, लेकिन दोनों ही hardening निर्णयों के लिए प्रासंगिक हैं।

## बिल्ड-टाइम सीक्रेट्स

container build पाइपलाइनों में सबसे पुरानी गलतियों में से एक है secrets को सीधे image में एम्बेड करना या उन्हें environment variables के माध्यम से पास करना, जो बाद में `docker inspect`, build logs, या recovered layers के जरिए दिखाई देने लगते हैं। बिल्ड-टाइम सीक्रेट्स को image फ़ाइलसिस्टम में कॉपी करने की बजाय build के दौरान अस्थायी रूप से माउंट किया जाना चाहिए।

BuildKit ने इस मॉडल को बेहतर बनाया है, जिससे dedicated build-time secret handling संभव हुई। किसी लेयर में secret लिखने की बजाय build step उसे अस्थायी रूप से उपयोग कर सकता है:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
यह इसलिए महत्वपूर्ण है क्योंकि image layers स्थायी artifacts होते हैं। एक बार कोई secret किसी committed layer में आ गया, तो बाद में किसी अन्य layer में फ़ाइल को हटाने से मूल खुलासा image history से वास्तव में हटा नहीं जाता।

## Runtime Secrets

एक चल रहे workload के लिए आवश्यक secrets को जहाँ भी संभव हो ad hoc पैटर्न जैसे plain environment variables से बचाना चाहिए। Volumes, dedicated secret-management integrations, Docker secrets, और Kubernetes Secrets सामान्य mechanisms हैं। इनमें से कोई भी सभी जोखिम नहीं हटाता, खासकर अगर attacker के पास पहले से ही workload में code execution है, लेकिन ये credentials को image में स्थायी रूप से स्टोर करने या उन्हें inspection tooling के माध्यम से casually एक्सपोज़ करने की तुलना में फिर भी बेहतर हैं।

A simple Docker Compose style secret declaration looks like:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
Kubernetes में, Secret objects, projected volumes, service-account tokens, और cloud workload identities एक व्यापक और अधिक शक्तिशाली मॉडल बनाते हैं, लेकिन वे host mounts, broad RBAC, या कमजोर Pod design के माध्यम से अनजाने में खुलासे के अधिक अवसर भी पैदा करते हैं।

## दुरुपयोग

जब किसी लक्ष्य की समीक्षा की जा रही हो, उद्देश्य यह पता लगाना है कि क्या secrets image में baked किए गए थे, layers में leaked हुए थे, या predictable runtime locations में mounted किए गए थे:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
ये कमांड तीन अलग समस्याओं के बीच अंतर करने में मदद करते हैं: एप्लिकेशन कॉन्फ़िगरेशन leaks, image-layer leaks, और runtime-injected secret फ़ाइलें। यदि कोई secret `/run/secrets`, किसी projected volume, या किसी cloud identity token path के अंतर्गत दिखाई देता है, तो अगला कदम यह समझना है कि यह केवल वर्तमान workload तक पहुँच देता है या कहीं अधिक बड़े control plane तक।

### पूरा उदाहरण: इमेज फ़ाइलसिस्टम में एम्बेडेड Secret

यदि किसी build pipeline ने `.env` फ़ाइलें या credentials को final image में कॉपी किया है, तो post-exploitation सरल हो जाता है:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
प्रभाव एप्लिकेशन पर निर्भर करता है, लेकिन embedded signing keys, JWT secrets, या cloud credentials आसानी से container compromise को API compromise, lateral movement, या trusted application tokens की forgery में बदल सकते हैं।

### Full Example: Build-Time Secret Leakage Check

यदि चिंता यह है कि image history ने किसी secret-bearing layer को capture कर लिया है:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
यह प्रकार की समीक्षा उपयोगी होती है क्योंकि एक secret अंतिम filesystem दृश्य से हटाया गया हो सकता है जबकि वह अभी भी किसी पुराने layer या build metadata में मौजूद रह सकता है।

## जाँच

इन जाँचों का उद्देश्य यह निर्धारित करना है कि क्या image और secret-handling pipeline ने runtime से पहले attack surface को बढ़ा दिया है या नहीं।
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
What is interesting here:

- संदिग्ध build इतिहास से कॉपी किए गए क्रेडेंशियल्स, SSH सामग्री, या असुरक्षित build कदम उजागर हो सकते हैं।
- projected volume paths के अंतर्गत मौजूद secrets सिर्फ़ लोकल एप्लिकेशन एक्सेस तक ही सीमित नहीं रहते; वे क्लस्टर या क्लाउड एक्सेस भी दे सकते हैं।
- स्पष्ट टेक्स्ट में क्रेडेंशियल्स वाले बहुत सारी configuration फाइलें आमतौर पर इंगित करती हैं कि image या deployment मॉडल ज़रूरत से ज़्यादा ट्रस्ट मटेरियल साथ ले जा रहा है।

## Runtime Defaults

| Runtime / platform | डिफॉल्ट स्थिति | डिफॉल्ट व्यवहार | सामान्य मैनुअल कमजोरियाँ |
| --- | --- | --- | --- |
| Docker / BuildKit | सुरक्षित build-time secret mounts को सपोर्ट करता है, पर यह स्वतः नहीं होता | Secrets को अस्थायी रूप से `build` के दौरान mount किया जा सकता है; image signing and scanning के लिए स्पष्ट workflow विकल्प आवश्यक हैं | secrets को image में कॉपी करना, secrets को `ARG` या `ENV` से पास करना, provenance checks को disable करना |
| Podman / Buildah | OCI-native builds और secret-aware workflows को सपोर्ट करता है | मजबूत build workflows उपलब्ध हैं, लेकिन operators को उन्हें जानबूझकर चुनना होगा | Containerfiles में secrets embed करना, व्यापक build contexts, permissive bind mounts during builds |
| Kubernetes | Native Secret objects और projected volumes | Runtime secret delivery first-class है, पर exposure RBAC, pod design, और host mounts पर निर्भर करती है | overbroad Secret mounts, service-account token का दुरुपयोग, `hostPath` के जरिये kubelet-managed volumes तक पहुंच |
| Registries | Integrity वैकल्पिक है जब तक लागू न किया गया हो | Public और private registries नीति, signing, और admission निर्णयों पर निर्भर करते हैं | unsigned images को freely pull करना, कमजोर admission control, खराब key management |
{{#include ../../../banners/hacktricks-training.md}}
