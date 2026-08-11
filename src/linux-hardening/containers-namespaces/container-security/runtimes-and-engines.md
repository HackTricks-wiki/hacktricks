# Container Runtimes, Engines, Builders, और Sandboxes

Container security में भ्रम के सबसे बड़े स्रोतों में से एक यह है कि कई पूरी तरह अलग components को अक्सर एक ही शब्द में समेट दिया जाता है। "Docker" किसी image format, CLI, daemon, build system, runtime stack या सामान्य रूप से containers की अवधारणा का संदर्भ हो सकता है। Security work के लिए यह अस्पष्टता समस्या है, क्योंकि अलग-अलग layers अलग-अलग protections के लिए जिम्मेदार होती हैं। खराब bind mount से हुआ breakout, low-level runtime bug से हुए breakout जैसा नहीं होता, और न ही यह Kubernetes में cluster policy की गलती के समान होता है।

यह page ecosystem को उसकी भूमिका के अनुसार अलग करता है, ताकि section के बाकी हिस्से में सटीक रूप से बताया जा सके कि कोई protection या weakness वास्तव में किस स्थान पर मौजूद है।

## Common Language के रूप में OCI

Modern Linux container stacks अक्सर इसलिए interoperable होते हैं क्योंकि वे OCI specifications के एक set को समझते हैं। **OCI Image Specification** बताता है कि images और layers को कैसे represent किया जाता है। **OCI Runtime Specification** बताता है कि runtime को process कैसे launch करना चाहिए, जिसमें namespaces, mounts, cgroups और security settings शामिल हैं। **OCI Distribution Specification** यह standardize करता है कि registries content को कैसे expose करती हैं।

यह महत्वपूर्ण है क्योंकि इससे समझ आता है कि एक tool से बनाई गई container image को अक्सर दूसरे tool से क्यों चलाया जा सकता है, और कई engines एक ही low-level runtime को क्यों share कर सकते हैं। इससे यह भी स्पष्ट होता है कि अलग-अलग products में security behavior समान क्यों दिखाई दे सकता है: उनमें से कई एक ही OCI runtime configuration तैयार करके उसे runtimes के उसी छोटे set को सौंपते हैं।

## Low-Level OCI Runtimes

Low-level runtime वह component है जो kernel boundary के सबसे निकट होता है। यही वह भाग है जो वास्तव में namespaces बनाता है, cgroup settings लिखता है, capabilities और seccomp filters लागू करता है, और अंत में container process पर `execve()` चलाता है। जब लोग mechanical level पर "container isolation" की चर्चा करते हैं, तो आमतौर पर वे इसी layer की बात कर रहे होते हैं, भले ही वे इसे स्पष्ट रूप से न कहें।

### `runc`

`runc` reference OCI runtime है और अब भी सबसे प्रसिद्ध implementation है। इसका व्यापक उपयोग Docker, containerd और कई Kubernetes deployments में होता है। Public research और exploitation material का बड़ा हिस्सा `runc`-style environments को target करता है, केवल इसलिए कि वे common हैं और क्योंकि `runc` वह baseline निर्धारित करता है जिसे कई लोग Linux container की कल्पना करते समय ध्यान में रखते हैं। इसलिए `runc` को समझना reader को classic container isolation का मजबूत mental model देता है।

### `crun`

`crun` एक अन्य OCI runtime है, जो C में लिखा गया है और modern Podman environments में व्यापक रूप से उपयोग होता है। इसकी अच्छी cgroup v2 support, मजबूत rootless ergonomics और कम overhead के लिए अक्सर प्रशंसा की जाती है। Security के दृष्टिकोण से महत्वपूर्ण बात यह नहीं है कि यह किसी अलग language में लिखा गया है, बल्कि यह है कि इसकी भूमिका वही रहती है: यह वह component है जो OCI configuration को kernel के अंतर्गत चल रहे process tree में बदलता है। Rootless Podman workflow अक्सर इसलिए अधिक सुरक्षित महसूस होता है क्योंकि `crun` जादुई रूप से सब कुछ ठीक कर देता है ऐसा नहीं, बल्कि इसके आसपास का पूरा stack user namespaces और least privilege पर अधिक निर्भर करता है।

### gVisor का `runsc`

`runsc` gVisor द्वारा उपयोग किया जाने वाला runtime है। यहां boundary का अर्थ महत्वपूर्ण रूप से बदल जाता है। सामान्य तरीके से अधिकांश syscalls को सीधे host kernel तक पहुंचाने के बजाय, gVisor userspace kernel layer जोड़ता है, जो Linux interface के बड़े हिस्सों को emulate या mediate करती है। इसका परिणाम कुछ extra flags वाला सामान्य `runc` container नहीं है; यह एक अलग sandbox design है, जिसका उद्देश्य host-kernel attack surface को कम करना है। Compatibility और performance tradeoffs इस design का हिस्सा हैं, इसलिए `runsc` का उपयोग करने वाले environments को सामान्य OCI runtime environments से अलग तरीके से document किया जाना चाहिए।

### `kata-runtime`

Kata Containers workload को lightweight virtual machine के भीतर launch करके boundary को और आगे बढ़ाते हैं। Administratively, यह अब भी container deployment जैसा दिख सकता है और orchestration layers इसे उसी रूप में treat कर सकती हैं, लेकिन underlying isolation boundary classic host-kernel-shared container की अपेक्षा virtualization के अधिक निकट होती है। इससे Kata उपयोगी होता है जब container-centric workflows छोड़े बिना stronger tenant isolation चाहिए।

## Engines और Container Managers

यदि low-level runtime वह component है जो सीधे kernel से बात करता है, तो engine या manager वह component है जिसके साथ users और operators आमतौर पर interact करते हैं। यह image pulls, metadata, logs, networks, volumes, lifecycle operations और API exposure संभालता है। यह layer अत्यंत महत्वपूर्ण है क्योंकि कई real-world compromises यहीं होते हैं: runtime socket या daemon API तक access host compromise के बराबर हो सकता है, भले ही low-level runtime स्वयं पूरी तरह स्वस्थ हो।

### Docker Engine

Docker Engine developers के लिए सबसे पहचाना जाने वाला container platform है और container vocabulary के इतने Docker-केंद्रित बनने का एक कारण भी है। सामान्य path `docker` CLI से `dockerd` तक जाता है, जो आगे `containerd` और OCI runtime जैसे lower-level components को coordinate करता है। ऐतिहासिक रूप से Docker deployments अक्सर **rootful** रहे हैं, इसलिए Docker socket तक access एक अत्यंत शक्तिशाली primitive रहा है। इसी कारण practical privilege-escalation material का बड़ा हिस्सा `docker.sock` पर केंद्रित होता है: यदि कोई process `dockerd` से privileged container बनाने, host paths mount करने या host namespaces join करने के लिए कह सकता है, तो उसे kernel exploit की आवश्यकता ही नहीं हो सकती।

### Podman

Podman को अधिक daemonless model के आधार पर design किया गया था। Operationally, यह इस विचार को मजबूत करता है कि containers standard Linux mechanisms के माध्यम से managed processes मात्र हैं, न कि किसी एक लंबे समय तक चलने वाले privileged daemon द्वारा managed entities। Classic Docker deployments की तुलना में, जिन्हें बहुत से लोगों ने सबसे पहले सीखा था, Podman की **rootless** story भी काफी मजबूत है। इससे Podman automatically safe नहीं बनता, लेकिन यह default risk profile को काफी बदल देता है, खासकर user namespaces, SELinux और `crun` के साथ।

### containerd

containerd कई modern stacks में core runtime management component है। इसका उपयोग Docker के अंतर्गत होता है और यह प्रमुख Kubernetes runtime backends में से एक है। यह powerful APIs expose करता है, images और snapshots manage करता है, और अंतिम process creation low-level runtime को सौंपता है। containerd के संबंध में security discussions में यह स्पष्ट होना चाहिए कि containerd socket या `ctr`/`nerdctl` functionality तक access Docker API तक access जितना ही खतरनाक हो सकता है, भले ही interface और workflow कम "developer friendly" महसूस हों।

### CRI-O

CRI-O का scope Docker Engine से अधिक focused है। General-purpose developer platform होने के बजाय, इसे Kubernetes Container Runtime Interface को cleanly implement करने के लिए बनाया गया है। इसलिए यह Kubernetes distributions और OpenShift जैसे SELinux-heavy ecosystems में विशेष रूप से common है। Security के दृष्टिकोण से इसका narrow scope उपयोगी है क्योंकि यह conceptual clutter कम करता है: CRI-O मुख्य रूप से "Kubernetes के लिए containers चलाने" वाली layer का हिस्सा है, न कि एक everything-platform।

### Incus, LXD और LXC

Incus/LXD/LXC systems को Docker-style application containers से अलग रखना उपयोगी है क्योंकि इनका उपयोग अक्सर **system containers** के रूप में किया जाता है। System container से आमतौर पर lightweight machine जैसा व्यवहार अपेक्षित होता है, जिसमें अधिक पूर्ण userspace, long-running services, अधिक device exposure और host integration शामिल होते हैं। Isolation mechanisms अब भी kernel primitives होते हैं, लेकिन operational expectations अलग होती हैं। परिणामस्वरूप, यहां misconfigurations अक्सर "bad app-container defaults" जैसी नहीं दिखतीं, बल्कि lightweight virtualization या host delegation की गलतियों जैसी होती हैं।

### systemd-nspawn

systemd-nspawn एक रोचक स्थान रखता है क्योंकि यह systemd-native है और testing, debugging तथा OS-जैसे environments चलाने के लिए बहुत उपयोगी है। यह dominant cloud-native production runtime नहीं है, लेकिन labs और distro-oriented environments में पर्याप्त रूप से दिखाई देता है कि इसका उल्लेख आवश्यक है। Security analysis के लिए यह एक और याद दिलाता है कि "container" की अवधारणा कई ecosystems और operational styles में फैली हुई है।

### Apptainer / Singularity

Apptainer (पूर्व नाम Singularity) research और HPC environments में common है। इसकी trust assumptions, user workflow और execution model Docker/Kubernetes-केंद्रित stacks से महत्वपूर्ण रूप से अलग हैं। विशेष रूप से, इन environments में users को packaged workloads चलाने की सुविधा देना महत्वपूर्ण होता है, बिना उन्हें broad privileged container-management powers दिए। यदि कोई reviewer यह मान ले कि हर container environment मूल रूप से "server पर Docker" है, तो वह इन deployments को गंभीर रूप से गलत समझेगा।

## Build-Time Tooling

कई security discussions केवल run time की बात करती हैं, लेकिन build-time tooling भी महत्वपूर्ण है क्योंकि यह image contents, build secrets exposure और final artifact में embedded trusted context की मात्रा निर्धारित करता है।

**BuildKit** और `docker buildx` modern build backends हैं, जो caching, secret mounting, SSH forwarding और multi-platform builds जैसी सुविधाएं support करते हैं। ये उपयोगी features हैं, लेकिन security के दृष्टिकोण से ये ऐसे स्थान भी बनाते हैं जहां secrets image layers में leak हो सकते हैं या अत्यधिक व्यापक build context ऐसी files expose कर सकता है जिन्हें कभी शामिल नहीं किया जाना चाहिए था। **Buildah** OCI-native ecosystems में, विशेष रूप से Podman के आसपास, समान भूमिका निभाता है, जबकि **Kaniko** का उपयोग अक्सर उन CI environments में किया जाता है जो build pipeline को privileged Docker daemon देना नहीं चाहते।

मुख्य सीख यह है कि image creation और image execution अलग phases हैं, लेकिन कमजोर build pipeline container launch होने से काफी पहले ही कमजोर runtime posture बना सकती है।

## Orchestration Runtime से अलग एक और Layer है

Kubernetes को runtime के साथ मानसिक रूप से समान नहीं मानना चाहिए। Kubernetes orchestrator है। यह Pods schedule करता है, desired state store करता है और workload configuration के माध्यम से security policy व्यक्त करता है। इसके बाद kubelet containerd या CRI-O जैसे CRI implementation से बात करता है, जो आगे `runc`, `crun`, `runsc` या `kata-runtime` जैसे low-level runtime को invoke करता है।

यह separation महत्वपूर्ण है क्योंकि कई लोग किसी protection का श्रेय गलत तरीके से "Kubernetes" को देते हैं, जबकि वह वास्तव में node runtime द्वारा enforce की जाती है, या वे "containerd defaults" को उस behavior के लिए दोष देते हैं जो Pod spec से आया था। व्यवहार में final security posture एक composition होता है: orchestrator किसी चीज के लिए request करता है, runtime stack उसका translation करता है और अंततः kernel उसे enforce करता है।

## Assessment के दौरान Runtime Identification क्यों महत्वपूर्ण है

यदि आप engine और runtime की पहचान जल्दी कर लेते हैं, तो बाद के कई observations को समझना आसान हो जाता है। Rootless Podman container संकेत देता है कि user namespaces कहानी का हिस्सा होने की संभावना है। Workload में mounted Docker socket बताता है कि API-driven privilege escalation एक realistic path है। CRI-O/OpenShift node पर आपको तुरंत SELinux labels और restricted workload policy के बारे में सोचना चाहिए। gVisor या Kata environment में आपको यह मानने से अधिक सावधान रहना चाहिए कि classic `runc` breakout PoC उसी तरह behave करेगा।

इसीलिए container assessment के पहले steps में हमेशा दो सरल प्रश्नों का उत्तर शामिल होना चाहिए: **container को कौन-सा component manage कर रहा है** और **process को वास्तव में किस runtime ने launch किया**। इन उत्तरों के स्पष्ट हो जाने के बाद बाकी environment को reason करना आमतौर पर काफी आसान हो जाता है।

## Runtime Vulnerabilities

हर container escape operator misconfiguration के कारण नहीं होता। कभी-कभी runtime स्वयं vulnerable component होता है। यह महत्वपूर्ण है क्योंकि कोई workload सावधानीपूर्वक configuration के साथ चल रहा दिखाई दे सकता है और फिर भी low-level runtime flaw के माध्यम से exposed हो सकता है।

Classic example `runc` में मौजूद **CVE-2019-5736** है, जिसमें malicious container host `runc` binary को overwrite कर सकता था और बाद में होने वाले `docker exec` या समान runtime invocation की प्रतीक्षा कर सकता था, ताकि attacker-controlled code trigger हो जाए। यह exploit path साधारण bind-mount या capability mistake से बहुत अलग है क्योंकि यह exec handling के दौरान runtime द्वारा container process space में दोबारा प्रवेश करने के तरीके का दुरुपयोग करता है।<sup>[[1]](#references)</sup>

Red-team perspective से एक minimal reproduction workflow है:
```bash
go build main.go
./main
```
फिर, host से:
```bash
docker exec -it <container-name> /bin/sh
```
मुख्य सीख exact historical exploit implementation नहीं है, बल्कि assessment implication है: यदि runtime version vulnerable है, तो साधारण in-container code execution host को compromise करने के लिए पर्याप्त हो सकता है, भले ही दिखाई देने वाली container configuration स्पष्ट रूप से कमजोर न लगे।

`runc` में `CVE-2024-21626`, BuildKit mount races और containerd parsing bugs जैसे हालिया runtime CVEs इसी बात को और मजबूत करते हैं। Runtime version और patch level security boundary का हिस्सा हैं, केवल maintenance से जुड़ी मामूली बातें नहीं।

## References

- [1] [runC के माध्यम से Docker से बाहर निकलना – CVE-2019-5736 की व्याख्या](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
