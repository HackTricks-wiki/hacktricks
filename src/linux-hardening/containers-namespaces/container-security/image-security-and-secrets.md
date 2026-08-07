# Image Security, Signing, और Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Container security workload launch होने से पहले ही शुरू हो जाती है। Image यह निर्धारित करती है कि कौन से binaries, interpreters, libraries, startup scripts और embedded configuration production तक पहुंचेंगे। यदि image backdoored, stale है, या उसमें secrets baked-in हैं, तो इसके बाद होने वाली runtime hardening पहले से ही एक compromised artifact पर काम कर रही होती है।

इसीलिए image provenance, vulnerability scanning, signature verification और secret handling को namespaces और seccomp के साथ एक ही चर्चा में शामिल किया जाना चाहिए। ये lifecycle के अलग phase की सुरक्षा करते हैं, लेकिन यहां होने वाली failures अक्सर उस attack surface को निर्धारित करती हैं जिसे runtime को बाद में contain करना पड़ता है।

## Image Registries And Trust

Images public registries जैसे Docker Hub से या किसी organization द्वारा संचालित private registries से आ सकती हैं। Security का सवाल केवल यह नहीं है कि image कहां रहती है, बल्कि यह है कि क्या team उसकी provenance और integrity स्थापित कर सकती है। Public sources से unsigned या poorly tracked images pull करने से malicious या tampered content के production में पहुंचने का risk बढ़ जाता है। Internally hosted registries को भी स्पष्ट ownership, review और trust policy की आवश्यकता होती है।

Docker Content Trust ने ऐतिहासिक रूप से signed images अनिवार्य करने के लिए Notary और TUF concepts का उपयोग किया। Exact ecosystem विकसित हो चुका है, लेकिन स्थायी lesson अभी भी उपयोगी है: image identity और integrity को assumed होने के बजाय verifiable होना चाहिए।

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
इस example का उद्देश्य यह नहीं है कि हर team को अब भी वही tooling इस्तेमाल करनी चाहिए, बल्कि यह है कि signing और key management operational tasks हैं, abstract theory नहीं।

## Vulnerability Scanning

Image scanning दो अलग-अलग questions का उत्तर देने में मदद करती है। पहला, क्या image में known vulnerable packages या libraries हैं? दूसरा, क्या image में unnecessary software मौजूद है, जो attack surface को बढ़ाता है? Debugging tools, shells, interpreters और stale packages से भरी image को exploit करना आसान होता है और उसके बारे में सही निष्कर्ष निकालना कठिन होता है।

आम तौर पर इस्तेमाल किए जाने वाले scanners के examples में शामिल हैं:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
इन tools से प्राप्त results की सावधानीपूर्वक व्याख्या की जानी चाहिए। किसी unused package में मौजूद vulnerability का risk किसी exposed RCE path के risk के समान नहीं होता, लेकिन hardening से जुड़े decisions के लिए दोनों अभी भी relevant हैं।

## Build-Time Secrets

Container build pipelines की सबसे पुरानी गलतियों में से एक है secrets को सीधे image में embed करना या उन्हें ऐसे environment variables के माध्यम से pass करना, जो बाद में `docker inspect`, build logs या recovered layers के जरिए दिखाई दे सकते हैं। Build-time secrets को image filesystem में copy करने के बजाय build के दौरान ephemeral रूप से mount किया जाना चाहिए।

BuildKit ने dedicated build-time secret handling की अनुमति देकर इस model को बेहतर बनाया। किसी secret को layer में लिखने के बजाय, build step उसे transient रूप से consume कर सकता है:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
यह महत्वपूर्ण है क्योंकि image layers durable artifacts होते हैं। एक बार कोई secret committed layer में शामिल हो जाए, तो बाद की किसी अन्य layer में file को delete करने से image history से original disclosure वास्तव में remove नहीं होता।

## Runtime Secrets

चल रहे workload के लिए आवश्यक secrets को भी, जब संभव हो, plain environment variables जैसे ad hoc patterns से बचाना चाहिए। Volumes, dedicated secret-management integrations, Docker secrets और Kubernetes Secrets सामान्य mechanisms हैं। इनमें से कोई भी सभी risks को समाप्त नहीं करता, खासकर तब जब attacker के पास workload में पहले से code execution हो, लेकिन फिर भी ये credentials को image में स्थायी रूप से store करने या inspection tooling के माध्यम से उन्हें लापरवाही से expose करने से बेहतर हैं।

एक simple Docker Compose style secret declaration इस प्रकार दिखती है:
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
Kubernetes में Secret objects, projected volumes, service-account tokens और cloud workload identities एक अधिक व्यापक और शक्तिशाली मॉडल बनाते हैं, लेकिन ये host mounts, व्यापक RBAC या कमजोर Pod design के माध्यम से accidental exposure के अधिक अवसर भी पैदा करते हैं।

## दुरुपयोग

किसी target की समीक्षा करते समय, उद्देश्य यह पता लगाना है कि क्या secrets image में bake किए गए थे, layers में leak हुए थे, या predictable runtime locations में mount किए गए थे:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
ये commands तीन अलग-अलग समस्याओं के बीच अंतर करने में मदद करती हैं: application configuration leaks, image-layer leaks और runtime-injected secret files। यदि कोई secret `/run/secrets`, projected volume या cloud identity token path के अंतर्गत दिखाई देता है, तो अगला कदम यह समझना है कि क्या वह केवल वर्तमान workload तक access देता है या इससे कहीं बड़े control plane तक।

### Full Example: Embedded Secret In Image Filesystem

यदि किसी build pipeline ने `.env` files या credentials को final image में copy कर दिया है, तो post-exploitation सरल हो जाता है:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
प्रभाव application पर निर्भर करता है, लेकिन embedded signing keys, JWT secrets या cloud credentials आसानी से container compromise को API compromise, lateral movement या trusted application tokens की forgery में बदल सकते हैं।

### पूर्ण उदाहरण: Build-Time Secret Leakage Check

यदि चिंता यह है कि image history ने secret-bearing layer को capture कर लिया है:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
इस तरह की समीक्षा उपयोगी है क्योंकि कोई secret final filesystem view से delete किया जा सकता है, लेकिन फिर भी वह किसी earlier layer या build metadata में मौजूद रह सकता है।

## Checks

इन checks का उद्देश्य यह निर्धारित करना है कि runtime से पहले image और secret-handling pipeline ने attack surface को बढ़ाने की संभावना पैदा की है या नहीं।
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
यहाँ क्या interesting है:

- एक suspicious build history से copied credentials, SSH material या unsafe build steps का पता चल सकता है।
- projected volume paths के अंतर्गत Secrets केवल local application access ही नहीं, बल्कि cluster या cloud access तक ले जा सकते हैं।
- plaintext credentials वाली configuration files की बड़ी संख्या आमतौर पर संकेत देती है कि image या deployment model आवश्यकता से अधिक trust material ले जा रहा है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Secure build-time secret mounts को support करता है, लेकिन automatically नहीं | `build` के दौरान Secrets को ephemerally mount किया जा सकता है; image signing और scanning के लिए explicit workflow choices आवश्यक हैं | Secrets को image में copy करना, `ARG` या `ENV` के माध्यम से Secrets पास करना, provenance checks को disable करना |
| Podman / Buildah | OCI-native builds और secret-aware workflows को support करता है | Strong build workflows उपलब्ध हैं, लेकिन operators को अभी भी उन्हें जानबूझकर चुनना पड़ता है | Containerfiles में Secrets embed करना, broad build contexts, builds के दौरान permissive bind mounts |
| Kubernetes | Native Secret objects और projected volumes | Runtime secret delivery first-class है, लेकिन exposure RBAC, pod design और host mounts पर निर्भर करता है | overbroad Secret mounts, service-account token misuse, kubelet-managed volumes तक `hostPath` access |
| Registries | जब तक enforce न किया जाए, integrity optional होती है | Public और private registries दोनों policy, signing और admission decisions पर निर्भर करते हैं | unsigned images को freely pull करना, weak admission control, poor key management |

{{#include ../../../banners/hacktricks-training.md}}
