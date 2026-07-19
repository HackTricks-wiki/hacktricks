# Image Security, Signing, और Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Container security workload launch होने से पहले ही शुरू हो जाती है। Image यह निर्धारित करती है कि कौन-से binaries, interpreters, libraries, startup scripts और embedded configuration production तक पहुँचेंगे। यदि image backdoored, stale हो, या उसमें secrets पहले से baked हों, तो उसके बाद की runtime hardening पहले से ही compromised artifact पर काम कर रही होती है।

इसीलिए image provenance, vulnerability scanning, signature verification और secret handling की चर्चा namespaces और seccomp के साथ की जानी चाहिए। ये lifecycle के अलग phase की सुरक्षा करते हैं, लेकिन यहाँ होने वाली failures अक्सर उस attack surface को निर्धारित करती हैं जिसे runtime को बाद में contain करना पड़ता है।

## Image Registries और Trust

Images Docker Hub जैसे public registries से या किसी organization द्वारा संचालित private registries से आ सकती हैं। Security question केवल यह नहीं है कि image कहाँ मौजूद है, बल्कि यह है कि क्या team उसकी provenance और integrity स्थापित कर सकती है। Public sources से unsigned या poorly tracked images pull करने से malicious या tampered content के production में पहुँचने का risk बढ़ जाता है। Internally hosted registries को भी स्पष्ट ownership, review और trust policy की आवश्यकता होती है।

Docker Content Trust ने ऐतिहासिक रूप से signed images की आवश्यकता के लिए Notary और TUF concepts का उपयोग किया। Exact ecosystem विकसित हो चुका है, लेकिन स्थायी lesson अभी भी उपयोगी है: image identity और integrity को assumed होने के बजाय verifiable होना चाहिए।

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
इस example का point यह नहीं है कि हर team को अभी भी वही tooling इस्तेमाल करनी चाहिए, बल्कि यह है कि signing और key management operational tasks हैं, abstract theory नहीं।

## Vulnerability Scanning

Image scanning दो अलग-अलग सवालों का जवाब देने में मदद करता है। पहला, क्या image में known vulnerable packages या libraries हैं? दूसरा, क्या image में अनावश्यक software मौजूद है, जो attack surface को बढ़ाता है? Debugging tools, shells, interpreters और stale packages से भरी image को exploit करना आसान और उसके बारे में तर्क करना कठिन होता है।

आम तौर पर इस्तेमाल किए जाने वाले scanners के examples में शामिल हैं:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
इन tools से प्राप्त results की सावधानीपूर्वक व्याख्या की जानी चाहिए। किसी unused package में मौजूद vulnerability का risk, exposed RCE path के risk के समान नहीं होता, लेकिन hardening decisions के लिए दोनों अभी भी relevant हैं।

## Build-Time Secrets

Container build pipelines में सबसे पुरानी गलतियों में से एक है secrets को सीधे image में embed करना या उन्हें ऐसे environment variables के माध्यम से pass करना, जो बाद में `docker inspect`, build logs या recovered layers के माध्यम से दिखाई दे सकते हैं। Build-time secrets को image filesystem में copy करने के बजाय build के दौरान ephemerally mount किया जाना चाहिए।

BuildKit ने dedicated build-time secret handling की सुविधा देकर इस model को बेहतर बनाया। किसी secret को layer में लिखने के बजाय, build step उसे transiently consume कर सकता है:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
यह महत्वपूर्ण है क्योंकि image layers durable artifacts होते हैं। एक बार कोई secret किसी committed layer में शामिल हो जाए, तो बाद में किसी अन्य layer में उस file को delete करने से image history से original disclosure वास्तव में हटता नहीं है।

## Runtime Secrets

किसी running workload के लिए आवश्यक secrets को भी, जब संभव हो, plain environment variables जैसे ad hoc patterns से बचाना चाहिए। Volumes, dedicated secret-management integrations, Docker secrets और Kubernetes Secrets सामान्य mechanisms हैं। इनमें से कोई भी सभी risks को समाप्त नहीं करता, खासकर यदि attacker के पास workload में पहले से code execution हो, लेकिन फिर भी ये credentials को image में स्थायी रूप से store करने या inspection tooling के माध्यम से उन्हें लापरवाही से expose करने की तुलना में बेहतर हैं।

एक simple Docker Compose style secret declaration इस प्रकार दिखता है:
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
In Kubernetes में, Secret objects, projected volumes, service-account tokens, और cloud workload identities एक अधिक व्यापक और शक्तिशाली model बनाते हैं, लेकिन host mounts, broad RBAC, या कमजोर Pod design के माध्यम से accidental exposure के अधिक अवसर भी पैदा करते हैं।

## Abuse

किसी target की समीक्षा करते समय, उद्देश्य यह पता लगाना है कि secrets image में baked किए गए थे, layers में leak हुए थे, या predictable runtime locations में mounted थे:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
ये commands तीन अलग-अलग समस्याओं के बीच अंतर करने में मदद करते हैं: application configuration leaks, image-layer leaks और runtime-injected secret files। यदि कोई secret `/run/secrets`, projected volume या cloud identity token path के अंतर्गत दिखाई देता है, तो अगला कदम यह समझना है कि क्या वह केवल current workload को access देता है या इससे कहीं बड़े control plane तक access मिलता है।

### Image Filesystem में Embedded Secret का पूरा उदाहरण

यदि किसी build pipeline ने `.env` files या credentials को final image में copy कर दिया है, तो post-exploitation सरल हो जाता है:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
प्रभाव application पर निर्भर करता है, लेकिन embedded signing keys, JWT secrets या cloud credentials container compromise को आसानी से API compromise, lateral movement या trusted application tokens की forgery में बदल सकते हैं।

### Full Example: Build-Time Secret Leakage Check

यदि चिंता यह है कि image history ने secret-bearing layer को capture कर लिया है:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
इस तरह की समीक्षा उपयोगी है क्योंकि किसी secret को अंतिम filesystem view से delete कर दिया गया हो सकता है, जबकि वह अभी भी किसी पुराने layer या build metadata में मौजूद रह सकता है।

## Checks

इन checks का उद्देश्य यह निर्धारित करना है कि क्या image और secret-handling pipeline ने runtime से पहले attack surface को बढ़ाया है।
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
यहाँ क्या महत्वपूर्ण है:

- एक संदिग्ध build history से copied credentials, SSH material या unsafe build steps का पता चल सकता है।
- projected volume paths के अंतर्गत secrets केवल local application access ही नहीं, बल्कि cluster या cloud access भी दे सकते हैं।
- plaintext credentials वाली configuration files की बड़ी संख्या आमतौर पर संकेत देती है कि image या deployment model आवश्यकता से अधिक trust material रख रहा है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | सुरक्षित build-time secret mounts का समर्थन करता है, लेकिन यह स्वतः सक्षम नहीं होता | `build` के दौरान secrets को अस्थायी रूप से mount किया जा सकता है; image signing और scanning के लिए स्पष्ट workflow विकल्प आवश्यक होते हैं | secrets को image में copy करना, secrets को `ARG` या `ENV` के माध्यम से भेजना, provenance checks को disable करना |
| Podman / Buildah | OCI-native builds और secret-aware workflows का समर्थन करता है | मजबूत build workflows उपलब्ध हैं, लेकिन operators को उन्हें जानबूझकर चुनना पड़ता है | Containerfiles में secrets embed करना, broad build contexts, builds के दौरान permissive bind mounts |
| Kubernetes | Native Secret objects और projected volumes | Runtime secret delivery first-class है, लेकिन exposure RBAC, pod design और host mounts पर निर्भर करता है | बहुत व्यापक Secret mounts, service-account token का दुरुपयोग, kubelet-managed volumes तक `hostPath` access |
| Registries | Integrity तब तक optional है जब तक इसे enforce न किया जाए | Public और private registries दोनों policy, signing और admission decisions पर निर्भर करते हैं | unsigned images को बिना रोक-टोक pull करना, कमजोर admission control, खराब key management |
{{#include ../../../banners/hacktricks-training.md}}
