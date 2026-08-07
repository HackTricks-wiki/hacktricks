# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Container security में confusion के सबसे बड़े स्रोतों में से एक यह है कि कई पूरी तरह अलग components को अक्सर एक ही शब्द में समेट दिया जाता है। "Docker" किसी image format, CLI, daemon, build system, runtime stack या केवल containers की सामान्य अवधारणा का संदर्भ दे सकता है। Security work के लिए यह अस्पष्टता समस्या है, क्योंकि अलग-अलग protections अलग layers की जिम्मेदारी होती हैं। खराब bind mount से होने वाला breakout, low-level runtime bug से होने वाले breakout जैसा नहीं होता, और न ही यह Kubernetes में cluster policy की गलती जैसा होता है।

यह page ecosystem को उसकी भूमिका के अनुसार अलग करता है, ताकि section के बाकी हिस्से में सटीक रूप से बताया जा सके कि कोई protection या weakness वास्तव में कहाँ मौजूद है।

## OCI As The Common Language

Modern Linux container stacks अक्सर इसलिए interoperable होते हैं क्योंकि वे OCI specifications के एक set का उपयोग करते हैं। **OCI Image Specification** बताता है कि images और layers को कैसे represent किया जाता है। **OCI Runtime Specification** बताता है कि runtime को process कैसे launch करना चाहिए, जिसमें namespaces, mounts, cgroups और security settings शामिल हैं। **OCI Distribution Specification** यह standardize करता है कि registries content को कैसे expose करती हैं।

यह महत्वपूर्ण है क्योंकि इससे पता चलता है कि एक tool से बनाई गई container image को अक्सर दूसरे tool से क्यों चलाया जा सकता है, और कई engines एक ही low-level runtime को share क्यों कर सकते हैं। इससे यह भी स्पष्ट होता है कि अलग-अलग products में security behavior एक जैसा क्यों दिख सकता है: उनमें से कई समान OCI runtime configuration तैयार करके उसे runtimes के उसी छोटे set को सौंपते हैं।

## Low-Level OCI Runtimes

Low-level runtime वह component है जो kernel boundary के सबसे करीब होता है। यही वह हिस्सा है जो वास्तव में namespaces बनाता है, cgroup settings लिखता है, capabilities और seccomp filters लागू करता है, और अंत में container process को `execve()` करता है। जब लोग mechanical level पर "container isolation" की चर्चा करते हैं, तो आमतौर पर वे इसी layer की बात कर रहे होते हैं, भले ही वे इसे स्पष्ट रूप से न कहें।

### `runc`

`runc` reference OCI runtime है और अब भी सबसे प्रसिद्ध implementation है। इसका उपयोग Docker, containerd और कई Kubernetes deployments में बड़े पैमाने पर किया जाता है। बहुत-सा public research और exploitation material `runc`-style environments को target करता है, क्योंकि वे आम हैं और क्योंकि `runc` वह baseline निर्धारित करता है जिसे कई लोग Linux container की कल्पना करते समय ध्यान में रखते हैं। इसलिए `runc` को समझना classic container isolation के लिए एक मजबूत mental model देता है।

### `crun`

`crun` एक अन्य OCI runtime है, जिसे C में लिखा गया है और modern Podman environments में व्यापक रूप से उपयोग किया जाता है। इसे अक्सर अच्छे cgroup v2 support, मजबूत rootless ergonomics और कम overhead के लिए सराहा जाता है। Security perspective से महत्वपूर्ण बात यह नहीं है कि इसे किसी अलग language में लिखा गया है, बल्कि यह है कि इसकी भूमिका वही रहती है: यह वह component है जो OCI configuration को kernel के अंतर्गत चल रहे process tree में बदलता है। Rootless Podman workflow अक्सर अधिक सुरक्षित महसूस होता है, ऐसा इसलिए नहीं कि `crun` जादुई रूप से सब कुछ ठीक कर देता है, बल्कि इसलिए कि इसके आसपास का पूरा stack user namespaces और least privilege पर अधिक निर्भर करता है।

### `runsc` From gVisor

`runsc` gVisor द्वारा उपयोग किया जाने वाला runtime है। यहाँ boundary का अर्थ महत्वपूर्ण रूप से बदल जाता है। सामान्य तरीके से अधिकांश syscalls को सीधे host kernel तक भेजने के बजाय, gVisor एक userspace kernel layer जोड़ता है, जो Linux interface के बड़े हिस्सों को emulate या mediate करती है। परिणाम कुछ अतिरिक्त flags वाला सामान्य `runc` container नहीं है; यह एक अलग sandbox design है, जिसका उद्देश्य host-kernel attack surface को कम करना है। Compatibility और performance tradeoffs इस design का हिस्सा हैं, इसलिए `runsc` का उपयोग करने वाले environments को सामान्य OCI runtime environments से अलग तरीके से document किया जाना चाहिए।

### `kata-runtime`

Kata Containers workload को एक lightweight virtual machine के अंदर launch करके boundary को और आगे बढ़ाते हैं। Administratively, यह अब भी container deployment जैसा दिख सकता है और orchestration layers इसे उसी तरह treat कर सकती हैं, लेकिन underlying isolation boundary classic host-kernel-shared container की तुलना में virtualization के अधिक करीब होती है। इससे Kata तब उपयोगी होता है जब container-centric workflows छोड़े बिना मजबूत tenant isolation चाहिए।

## Engines And Container Managers

यदि low-level runtime वह component है जो सीधे kernel से बात करता है, तो engine या manager वह component है जिसके साथ users और operators आमतौर पर interact करते हैं। यह image pulls, metadata, logs, networks, volumes, lifecycle operations और API exposure को संभालता है। यह layer अत्यंत महत्वपूर्ण है क्योंकि कई real-world compromises यहीं होते हैं: runtime socket या daemon API तक access host compromise के बराबर हो सकता है, भले ही low-level runtime स्वयं पूरी तरह सुरक्षित हो।

### Docker Engine

Docker Engine developers के लिए सबसे पहचाना जाने वाला container platform है और container vocabulary के Docker-केंद्रित बनने के कारणों में से एक है। सामान्य path `docker` CLI से `dockerd` तक जाता है, जो आगे `containerd` और OCI runtime जैसे lower-level components को coordinate करता है। ऐतिहासिक रूप से Docker deployments अक्सर **rootful** रहे हैं, इसलिए Docker socket तक access एक अत्यंत शक्तिशाली primitive रहा है। इसी कारण बहुत-सा practical privilege-escalation material `docker.sock` पर केंद्रित होता है: यदि कोई process `dockerd` से privileged container बनाने, host paths mount करने या host namespaces join करने के लिए कह सकता है, तो उसे kernel exploit की आवश्यकता शायद न हो।

### Podman

Podman को अधिक daemonless model के आधार पर design किया गया था। Operationally, इससे यह विचार मजबूत होता है कि containers standard Linux mechanisms के माध्यम से managed किए जाने वाले processes हैं, न कि किसी एक लंबे समय तक चलने वाले privileged daemon के माध्यम से। Classic Docker deployments की तुलना में Podman की **rootless** story भी काफी मजबूत है, जिन्हें बहुत से लोगों ने पहले सीखा था। इससे Podman automatically safe नहीं बनता, लेकिन यह default risk profile को काफी बदल देता है, विशेषकर user namespaces, SELinux और `crun` के साथ।

### containerd

containerd कई modern stacks में core runtime management component है। इसका उपयोग Docker के अंतर्गत होता है और यह प्रमुख Kubernetes runtime backends में से एक है। यह powerful APIs expose करता है, images और snapshots manage करता है और अंतिम process creation को low-level runtime को सौंपता है। containerd से संबंधित security discussions में यह स्पष्ट होना चाहिए कि containerd socket या `ctr`/`nerdctl` functionality तक access Docker API तक access जितना ही खतरनाक हो सकता है, भले ही interface और workflow कम "developer friendly" लगें।

### CRI-O

CRI-O, Docker Engine की तुलना में अधिक focused है। General-purpose developer platform होने के बजाय इसे Kubernetes Container Runtime Interface को साफ तरीके से implement करने के लिए बनाया गया है। इससे यह Kubernetes distributions और OpenShift जैसे SELinux-heavy ecosystems में विशेष रूप से आम है। Security perspective से इसका narrow scope उपयोगी है क्योंकि यह conceptual clutter कम करता है: CRI-O मुख्य रूप से "Kubernetes के लिए containers चलाने" वाली layer का हिस्सा है, न कि एक everything-platform।

### Incus, LXD, And LXC

Incus/LXD/LXC systems को Docker-style application containers से अलग समझना चाहिए, क्योंकि इनका उपयोग अक्सर **system containers** के रूप में होता है। आमतौर पर system container से lightweight machine जैसा व्यवहार अपेक्षित होता है, जिसमें अधिक पूर्ण userspace, long-running services, अधिक device exposure और host integration शामिल होती है। Isolation mechanisms अब भी kernel primitives होते हैं, लेकिन operational expectations अलग होती हैं। परिणामस्वरूप, यहाँ misconfigurations अक्सर "bad app-container defaults" जैसी नहीं दिखतीं, बल्कि lightweight virtualization या host delegation की गलतियों जैसी दिखती हैं।

### systemd-nspawn

systemd-nspawn एक रोचक स्थान रखता है क्योंकि यह systemd-native है और testing, debugging तथा OS-जैसे environments चलाने के लिए बहुत उपयोगी है। यह dominant cloud-native production runtime नहीं है, लेकिन labs और distro-oriented environments में पर्याप्त रूप से दिखाई देता है, इसलिए इसका उल्लेख आवश्यक है। Security analysis के लिए यह एक और याद दिलाता है कि "container" की अवधारणा कई ecosystems और operational styles में फैली हुई है।

### Apptainer / Singularity

Apptainer (पूर्व में Singularity) research और HPC environments में आम है। इसके trust assumptions, user workflow और execution model Docker/Kubernetes-केंद्रित stacks से महत्वपूर्ण रूप से अलग हैं। विशेष रूप से, ये environments अक्सर users को packaged workloads चलाने की सुविधा देना चाहते हैं, बिना उन्हें व्यापक privileged container-management powers दिए। यदि reviewer यह मान ले कि हर container environment मूल रूप से "server पर Docker" है, तो वह इन deployments को गंभीर रूप से गलत समझेगा।

## Build-Time Tooling

कई security discussions केवल run time की बात करती हैं, लेकिन build-time tooling भी महत्वपूर्ण है क्योंकि यह image contents, build secrets exposure और final artifact में embed होने वाले trusted context की मात्रा निर्धारित करता है।

**BuildKit** और `docker buildx` modern build backends हैं, जो caching, secret mounting, SSH forwarding और multi-platform builds जैसी सुविधाएँ support करते हैं। ये उपयोगी features हैं, लेकिन security perspective से ये ऐसी जगहें भी बनाते हैं जहाँ secrets image layers में leak हो सकते हैं या अत्यधिक व्यापक build context उन files को expose कर सकता है जिन्हें कभी शामिल नहीं किया जाना चाहिए था। **Buildah** OCI-native ecosystems में, विशेषकर Podman के आसपास, इसी तरह की भूमिका निभाता है, जबकि **Kaniko** का उपयोग अक्सर उन CI environments में किया जाता है जो build pipeline को privileged Docker daemon देना नहीं चाहते।

मुख्य lesson यह है कि image creation और image execution अलग phases हैं, लेकिन कमजोर build pipeline container launch होने से बहुत पहले ही कमजोर runtime posture बना सकती है।

## Orchestration Is Another Layer, Not The Runtime

Kubernetes को runtime के साथ mentally equate नहीं करना चाहिए। Kubernetes orchestrator है। यह Pods को schedule करता है, desired state store करता है और workload configuration के माध्यम से security policy व्यक्त करता है। इसके बाद kubelet containerd या CRI-O जैसे CRI implementation से बात करता है, जो आगे `runc`, `crun`, `runsc` या `kata-runtime` जैसे low-level runtime को invoke करता है।

यह separation महत्वपूर्ण है क्योंकि कई लोग किसी protection का श्रेय गलत रूप से "Kubernetes" को देते हैं, जबकि वह वास्तव में node runtime द्वारा enforce की जाती है, या वे "containerd defaults" को ऐसे behavior के लिए दोष देते हैं जो Pod spec से आया था। व्यवहार में final security posture एक composition होती है: orchestrator किसी चीज़ का अनुरोध करता है, runtime stack उसका translation करता है और अंततः kernel उसे enforce करता है।

## Why Runtime Identification Matters During Assessment

यदि आप engine और runtime की पहचान शुरुआत में कर लेते हैं, तो बाद के कई observations को समझना आसान हो जाता है। Rootless Podman container से संकेत मिलता है कि user namespaces संभवतः इस setup का हिस्सा हैं। किसी workload में mounted Docker socket यह संकेत देता है कि API-driven privilege escalation एक realistic path है। CRI-O/OpenShift node को देखते ही आपको SELinux labels और restricted workload policy के बारे में सोचना चाहिए। gVisor या Kata environment में आपको यह मानने से अधिक सावधान रहना चाहिए कि classic `runc` breakout PoC उसी तरह behave करेगा।

इसीलिए container assessment के शुरुआती steps में हमेशा दो सरल प्रश्नों के उत्तर खोजने चाहिए: **container को कौन-सा component manage कर रहा है** और **किस runtime ने वास्तव में process launch किया**। एक बार ये उत्तर स्पष्ट हो जाएँ, तो बाकी environment को reason करना आमतौर पर काफी आसान हो जाता है।

## Runtime Vulnerabilities

हर container escape operator misconfiguration से नहीं होता। कभी-कभी runtime स्वयं vulnerable component होता है। यह महत्वपूर्ण है क्योंकि workload ऐसी configuration के साथ चल रहा हो सकता है जो सावधानीपूर्वक बनाई हुई दिखती है, फिर भी low-level runtime flaw के कारण exposed हो सकता है।

इसका classic example `runc` में **CVE-2019-5736** है, जिसमें malicious container host के `runc` binary को overwrite कर सकता था और फिर बाद के `docker exec` या समान runtime invocation का इंतजार कर सकता था, ताकि attacker-controlled code trigger हो सके। यह exploit path साधारण bind-mount या capability mistake से बहुत अलग है, क्योंकि इसमें exec handling के दौरान runtime द्वारा container process space में दोबारा प्रवेश करने के तरीके का दुरुपयोग किया जाता है।<sup>[[1]](#references)</sup>

Red-team perspective से एक minimal reproduction workflow है:
```bash
go build main.go
./main
```
फिर, host से:
```bash
docker exec -it <container-name> /bin/sh
```
मुख्य सीख exact historical exploit implementation नहीं, बल्कि assessment implication है: यदि runtime version vulnerable है, तो साधारण in-container code execution ही host को compromise करने के लिए पर्याप्त हो सकता है, भले ही दिखाई देने वाला container configuration स्पष्ट रूप से कमजोर न लगे।

`runc` में `CVE-2024-21626`, BuildKit mount races और containerd parsing bugs जैसे हाल के runtime CVEs इसी बात को दोहराते हैं। Runtime version और patch level security boundary का हिस्सा हैं, केवल maintenance से जुड़ी मामूली बातें नहीं।

## संदर्भ

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

{{#include ../../../banners/hacktricks-training.md}}
