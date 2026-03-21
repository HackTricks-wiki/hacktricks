# इमेज सुरक्षा, साइनिंग, और सीक्रेट्स

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

Container सुरक्षा workload लॉन्च होने से पहले शुरू होती है। इमेज तय करती है कि कौन‑से बाइनरीज़, इंटरप्रेटर, लाइब्रेरीज़, स्टार्टअप स्क्रिप्ट्स और एम्बेडेड कॉन्फ़िगरेशन प्रोडक्शन तक पहुँचेंगे। अगर इमेज backdoored है, पुरानी है, या उसमें सीक्रेट्स बेक किए गए हैं, तो बाद में की जाने वाली runtime hardening पहले से ही एक compromised artifact पर काम कर रही होती है।

इसी लिए image provenance, vulnerability scanning, signature verification, और secret handling को namespaces और seccomp जैसी चीज़ों के साथ एक ही बातचीत में रखना चाहिए। ये लाइफसाइकल के एक अलग चरण की सुरक्षा करते हैं, पर यहाँ हुई विफलताएँ अक्सर उस attack surface को परिभाषित कर देती हैं जिसे रनटाइम बाद में नियंत्रित करना पड़ता है।

## इमेज रजिस्ट्री और ट्रस्ट

इमेज सार्वजनिक रजिस्ट्रीज़ जैसे Docker Hub से आ सकती हैं या किसी organization द्वारा ऑपरेट की गई प्राइवेट रजिस्ट्रीज़ से। सुरक्षा का सवाल सिर्फ यह नहीं है कि इमेज कहाँ रहती है, बल्कि यह है कि टीम इमेज की provenance और integrity स्थापित कर सकती है या नहीं। पब्लिक सोर्सेज से बिना सिग्नेचर वाली या खराब तरीके से ट्रैक की गई इमेजेस खींचने से दुर्भावनापूर्ण या छेड़छाड़ किया गया कंटेंट प्रोडक्शन में पहुँचने का जोखिम बढ़ जाता है। यहां तक कि internally hosted registries को भी स्पष्ट ownership, review, और trust policy की आवश्यकता होती है।

Docker Content Trust ऐतिहासिक रूप से signed images की ज़रूरत के लिए Notary और TUF concepts का उपयोग करता था। पूरा ecosystem बदल चुका है, पर स्थायी सबक उपयोगी बना रहता है: image identity और integrity को assumed करने की बजाय verifiable होना चाहिए।

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
उदाहरण का उद्देश्य यह नहीं है कि हर टीम को अभी भी एक ही उपकरणों का उपयोग करना चाहिए, बल्कि यह कि साइनिंग और कुंजी प्रबंधन संचालन संबंधी कार्य हैं, न कि केवल सैद्धान्तिक अवधारणाएँ।

## भेद्यता स्कैनिंग

इमेज स्कैनिंग दो अलग-अलग प्रश्नों के उत्तर देने में मदद करता है। पहला, क्या इमेज में ज्ञात कमजोर पैकेज या लाइब्रेरी मौजूद हैं? दूसरा, क्या इमेज में अनावश्यक सॉफ़्टवेयर है जो attack surface को बढ़ाता है? डिबगिंग टूल्स, शेल्स, इंटरप्रेटर्स और पुराने पैकेजों से भरी हुई इमेज का शोषण करना आसान और समझना कठिन दोनों होता है।

आम तौर पर उपयोग किए जाने वाले स्कैनरों के उदाहरण निम्नलिखित हैं:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
इन टूल्स के परिणामों की व्याख्या सावधानीपूर्वक की जानी चाहिए। अप्रयुक्त पैकेज में मौजूद किसी कमज़ोरी का जोखिम खुले हुए RCE path जितना गंभीर नहीं होता, फिर भी दोनों ही सुरक्षा को मजबूत करने से जुड़े निर्णयों के लिए प्रासंगिक हैं।

## बिल्ड-टाइम सीक्रेट्स

कंटेनर बिल्ड पाइपलाइनों में सबसे पुरानी गलतियों में से एक है सीक्रेट्स को सीधे इमेज में एम्बेड करना या उन्हें environment variables के माध्यम से पास करना जो बाद में `docker inspect`, build logs, या recovered layers के जरिए दिखाई दे जाते हैं। बिल्ड-टाइम सीक्रेट्स को इमेज फाइलसिस्टम में कॉपी करने के बजाय बिल्ड के दौरान अस्थायी रूप से mount करना चाहिए।

BuildKit ने इस मॉडल में सुधार किया है और dedicated build-time secret handling को सक्षम किया। किसी secret को layer में लिखने के बजाय, build step इसे अस्थायी रूप से उपयोग कर सकता है:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
यह इसलिए महत्वपूर्ण है क्योंकि इमेज लेयर्स स्थायी आर्टिफैक्ट होते हैं। एक बार जब कोई secret किसी committed लेयर में चला जाता है, तो बाद में किसी दूसरी लेयर में फ़ाइल हटाने से इमेज हिस्ट्री से मूल खुलासा वास्तव में हटता नहीं है।

## Runtime Secrets

रनिंग वर्कलोड के लिए आवश्यक Secrets को भी जहाँ संभव हो ad hoc पैटर्न — जैसे साधारण environment variables — से बचना चाहिए। Volumes, dedicated secret-management integrations, Docker secrets, और Kubernetes Secrets सामान्य तंत्र हैं। इनमें से किसी से भी सभी जोखिम समाप्त नहीं होते, खासकर यदि attacker पहले से ही workload में code execution कर चुका हो, फिर भी ये credentials को स्थायी रूप से इमेज में स्टोर करने या उन्हें inspection tooling के माध्यम से सहजता से उजागर करने की तुलना में बेहतर होते हैं।

एक साधारण Docker Compose शैली का secret declaration इस प्रकार दिखता है:
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
Kubernetes में, Secret objects, projected volumes, service-account tokens, और cloud workload identities एक व्यापक और अधिक शक्तिशाली मॉडल बनाते हैं, लेकिन वे host mounts, broad RBAC, या कमजोर Pod design के माध्यम से अनजाने में उजागर होने के और अधिक मौके भी पैदा करते हैं।

## Abuse

जब किसी target की समीक्षा की जा रही हो, तो उद्देश्य यह पता लगाना होता है कि क्या secrets image में baked किए गए थे, layers में leaked हो गए थे, या predictable runtime locations में mounted किए गए थे:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
ये commands तीन अलग समस्याओं के बीच अंतर करने में मदद करते हैं: application configuration leaks, image-layer leaks, और runtime-injected secret files। यदि कोई secret `/run/secrets`, किसी projected volume, या किसी cloud identity token path में दिखाई देता है, तो अगला कदम यह समझना होता है कि क्या वह केवल वर्तमान workload को ही एक्सेस देता है या किसी बहुत बड़े control plane को।

### पूर्ण उदाहरण: इमेज फ़ाइल सिस्टम में एम्बेडेड secret

यदि किसी build pipeline ने `.env` फ़ाइलें या credentials को final image में कॉपी कर दिया है, तो post-exploitation सरल हो जाता है:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
प्रभाव एप्लिकेशन पर निर्भर करता है, लेकिन embedded signing keys, JWT secrets, या cloud credentials आसानी से container compromise को API compromise, lateral movement, या trusted application tokens की forgery में बदल सकते हैं।

### पूर्ण उदाहरण: Build-Time Secret Leakage Check

यदि चिंता यह है कि image history ने किसी secret-bearing layer को capture कर लिया है:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
यह प्रकार की समीक्षा उपयोगी है क्योंकि कोई secret अंतिम filesystem view से हटाया गया हो सकता है जबकि वह किसी पूर्व लेयर या build metadata में अभी भी मौजूद रह सकता है।

## Checks

इन जांचों का उद्देश्य यह स्थापित करना है कि क्या image और secret-handling pipeline ने runtime से पहले attack surface बढ़ा दिया होने की संभावना है।
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
What is interesting here:

- संदिग्ध build history से कॉपी किए गए credentials, SSH सामग्री, या असुरक्षित build steps सामने आ सकते हैं।
- projected volume paths के तहत मौजूद Secrets केवल स्थानीय application एक्सेस तक सीमित नहीं रहते — वे cluster या cloud access भी दे सकते हैं।
- कई configuration files जिनमें plaintext credentials होते हैं, अक्सर संकेत देते हैं कि image या deployment model अनावश्यक रूप से अधिक trust material ले जा रहा है।

## रनटाइम डिफ़ॉल्ट

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Supports secure build-time secret mounts, but not automatically | Secrets can be mounted ephemerally during `build`; image signing and scanning require explicit workflow choices | copying secrets into the image, passing secrets by `ARG` or `ENV`, disabling provenance checks |
| Podman / Buildah | Supports OCI-native builds and secret-aware workflows | Strong build workflows are available, but operators must still choose them intentionally | embedding secrets in Containerfiles, broad build contexts, permissive bind mounts during builds |
| Kubernetes | Native Secret objects and projected volumes | Runtime secret delivery is first-class, but exposure depends on RBAC, pod design, and host mounts | overbroad Secret mounts, service-account token misuse, `hostPath` access to kubelet-managed volumes |
| Registries | Integrity is optional unless enforced | Public and private registries both depend on policy, signing, and admission decisions | pulling unsigned images freely, weak admission control, poor key management |
