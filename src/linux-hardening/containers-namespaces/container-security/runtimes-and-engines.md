# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Container security में भ्रम के सबसे बड़े कारणों में से एक यह है कि कई बिल्कुल अलग-अलग components को अक्सर एक ही शब्द में समेट दिया जाता है। "Docker" का मतलब image format, CLI, daemon, build system, runtime stack या सामान्य रूप से containers का विचार हो सकता है। Security work में यह अस्पष्टता समस्या है, क्योंकि अलग-अलग layers अलग-अलग protections के लिए ज़िम्मेदार होती हैं। खराब bind mount से होने वाला breakout, low-level runtime bug से होने वाले breakout जैसा नहीं है; और इनमें से कोई भी Kubernetes में cluster policy की गलती जैसा नहीं है।

यह पेज ecosystem को उसकी भूमिकाओं के अनुसार अलग करता है, ताकि section के बाकी हिस्से इस बारे में सटीक रूप से बात कर सकें कि कोई protection या weakness वास्तव में किस layer में मौजूद है।

## OCI As The Common Language

आधुनिक Linux container stacks अक्सर इसलिए interoperable होते हैं, क्योंकि वे OCI specifications के एक समूह का उपयोग करते हैं। **OCI Image Specification** बताता है कि images और layers को किस तरह दर्शाया जाता है। **OCI Runtime Specification** बताता है कि runtime को process कैसे launch करना चाहिए, जिसमें namespaces, mounts, cgroups और security settings शामिल हैं। **OCI Distribution Specification** registries द्वारा content उपलब्ध कराने के तरीके को standardize करता है।

यह इसलिए महत्वपूर्ण है, क्योंकि इससे समझ आता है कि एक tool से बनाई गई container image को अक्सर किसी दूसरे tool से क्यों चलाया जा सकता है, और कई engines एक ही low-level runtime का उपयोग क्यों कर सकते हैं। इससे यह भी समझ आता है कि अलग-अलग products में security behavior एक जैसा क्यों दिख सकता है: उनमें से कई एक ही OCI runtime configuration तैयार करके runtimes के उसी छोटे समूह को सौंपते हैं।

## Low-Level OCI Runtimes

Low-level runtime वह component है जो kernel boundary के सबसे करीब होता है। यही वह हिस्सा है जो वास्तव में namespaces बनाता है, cgroup settings लिखता है, capabilities और seccomp filters लागू करता है, और अंत में container process पर `execve()` चलाता है। जब लोग mechanical स्तर पर "container isolation" की चर्चा करते हैं, तो आम तौर पर वे इसी layer की बात कर रहे होते हैं, भले ही वे इसे स्पष्ट रूप से न कहें।

### `runc`

`runc` reference OCI runtime है और अब भी सबसे जाना-पहचाना implementation है। इसका Docker, containerd और कई Kubernetes deployments में बड़े पैमाने पर उपयोग होता है। Public research और exploitation सामग्री का बड़ा हिस्सा `runc`-जैसे environments को target करता है, क्योंकि वे आम हैं और `runc` वह baseline तय करता है जिसकी कल्पना कई लोग Linux container के बारे में सोचते समय करते हैं। इसलिए `runc` को समझने से classic container isolation का एक मज़बूत mental model मिलता है।

### `crun`

`crun` एक और OCI runtime है, जिसे C में लिखा गया है और आधुनिक Podman environments में इसका व्यापक उपयोग होता है। इसे अक्सर cgroup v2 के अच्छे support, मज़बूत rootless ergonomics और कम overhead के लिए सराहा जाता है। Security के नज़रिये से महत्वपूर्ण बात यह नहीं है कि इसे किसी दूसरी language में लिखा गया है, बल्कि यह है कि इसकी भूमिका वही रहती है: यह OCI configuration को kernel के अंतर्गत चल रहे process tree में बदलता है। Rootless Podman workflow अक्सर इसलिए अधिक सुरक्षित महसूस होता है क्योंकि `crun` जादुई ढंग से सब कुछ ठीक कर देता है, ऐसा नहीं; बल्कि उसके आसपास का पूरा stack user namespaces और least privilege पर अधिक ज़ोर देता है।

### `runsc` From gVisor

`runsc`, gVisor द्वारा इस्तेमाल किया जाने वाला runtime है। यहाँ boundary का अर्थ महत्वपूर्ण रूप से बदल जाता है। अधिकतर syscalls को सामान्य तरीके से सीधे host kernel तक पहुँचाने के बजाय, gVisor एक userspace kernel layer जोड़ता है, जो Linux interface के बड़े हिस्से को emulate या mediate करती है। इसका परिणाम कुछ अतिरिक्त flags वाला सामान्य `runc` container नहीं है; यह एक अलग sandbox design है, जिसका उद्देश्य host-kernel attack surface को कम करना है। Compatibility और performance के tradeoffs इस design का हिस्सा हैं, इसलिए `runsc` इस्तेमाल करने वाले environments का दस्तावेज़ीकरण सामान्य OCI runtime environments से अलग होना चाहिए।

### `kata-runtime`

Kata Containers workload को lightweight virtual machine के भीतर launch करके boundary को और आगे ले जाते हैं। प्रशासनिक रूप से यह अब भी container deployment जैसा दिख सकता है और orchestration layers इसे उसी तरह मान सकती हैं, लेकिन इसकी underlying isolation boundary classic host-kernel-shared container के बजाय virtualization के अधिक करीब होती है। इससे Kata उन स्थितियों में उपयोगी होता है जहाँ container-केंद्रित workflows छोड़े बिना tenants के बीच अधिक मज़बूत isolation चाहिए।

## Engines And Container Managers

अगर low-level runtime वह component है जो सीधे kernel से बात करता है, तो engine या manager वह component है जिससे आम तौर पर users और operators interact करते हैं। यह image pulls, metadata, logs, networks, volumes, lifecycle operations और API exposure संभालता है। यह layer बेहद महत्वपूर्ण है, क्योंकि वास्तविक दुनिया के कई compromises यहीं होते हैं: runtime socket या daemon API तक पहुँच host compromise के बराबर हो सकती है, भले ही low-level runtime पूरी तरह सुरक्षित हो।

### Docker Engine

Docker Engine developers के लिए सबसे पहचाना जाने वाला container platform है और container vocabulary के Docker-जैसा बनने का एक कारण भी है। सामान्य क्रम `docker` CLI से `dockerd` तक जाता है, जो आगे `containerd` और OCI runtime जैसे low-level components के साथ तालमेल करता है। ऐतिहासिक रूप से, Docker deployments अक्सर **rootful** रहे हैं, इसलिए Docker socket तक पहुँच बहुत शक्तिशाली primitive रही है। इसी कारण privilege-escalation की इतनी सारी व्यावहारिक सामग्री `docker.sock` पर केंद्रित है: अगर कोई process `dockerd` से privileged container बनाने, host paths mount करने या host namespaces join करने के लिए कह सकता है, तो उसे kernel exploit की ज़रूरत शायद न पड़े।

Release numbers की तुलना major, minor और patch components के आधार पर करें, dots हटाकर नहीं: `18.09.1`, अपने zero-padded minor component के बावजूद, `18.09.2` और `18.09.4` दोनों से पुराना है। Docker के [18.09 release notes](https://docs.docker.com/engine/release-notes/18.09/) में दर्ज है कि CVE-2019-5736 के लिए bundled `runc` fix 18.09.2 में और CVE-2019-13139 के लिए build-reference fix 18.09.4 में शामिल था। ये version से जुड़े संकेत हैं, किसी reachable exploit का प्रमाण नहीं। इन्हीं release notes में चेतावनी दी गई है कि daemon, client और runtime अलग-अलग package किए जाते हैं; इसलिए daemon version के साथ installed runtime और vendor backports भी जाँचें। Build-reference issue के लिए प्रभावित build workflow तक पहुँच और attacker-controlled input भी आवश्यक है।

### Podman

Podman को daemonless model के इर्द-गिर्द बनाया गया था। संचालन के स्तर पर यह इस विचार को मज़बूत करता है कि containers बस standard Linux mechanisms से manage होने वाले processes हैं, न कि किसी लंबे समय तक चलने वाले privileged daemon के ज़रिए। Podman की **rootless** support भी उन classic Docker deployments से कहीं बेहतर है जिन्हें कई लोगों ने पहले सीखा था। इससे Podman अपने-आप सुरक्षित नहीं हो जाता, लेकिन इससे default risk profile में बड़ा बदलाव आता है, खासकर जब इसे user namespaces, SELinux और `crun` के साथ इस्तेमाल किया जाए।

### containerd

containerd कई आधुनिक stacks का core runtime management component है। इसका उपयोग Docker के अंतर्गत और Kubernetes के प्रमुख runtime backends में से एक के रूप में भी होता है। यह शक्तिशाली APIs उपलब्ध कराता है, images और snapshots manage करता है, और process को अंततः बनाने का काम low-level runtime को सौंपता है। containerd से जुड़ी security चर्चाओं में इस बात पर ज़ोर देना चाहिए कि containerd socket या `ctr`/`nerdctl` functionality तक पहुँच, Docker API तक पहुँच जितनी ही ख़तरनाक हो सकती है, भले ही इसका interface और workflow कम "developer friendly" लगे।

### CRI-O

CRI-O, Docker Engine से अधिक सीमित दायरे वाला है। सामान्य-purpose developer platform होने के बजाय, इसे Kubernetes Container Runtime Interface को साफ़-सुथरे ढंग से लागू करने के लिए बनाया गया है। इसलिए Kubernetes distributions और OpenShift जैसे SELinux-heavy ecosystems में इसका उपयोग खास तौर पर आम है। Security के नज़रिये से, इसका सीमित दायरा उपयोगी है, क्योंकि इससे वैचारिक उलझन कम होती है: CRI-O मुख्यतः "Kubernetes के लिए containers चलाने" वाली layer का हिस्सा है, न कि हर काम करने वाला platform।

जब Kubernetes node CRI-O इस्तेमाल करता हो, तो **node की active CRI-O release** के साथ यह भी जाँचें कि मौजूदा identity ऐसे namespace में Pods बना सकती है या नहीं, जहाँ scheduling होती है। [CVE-2022-0811](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) के कारण प्रभावित releases में crafted Pod sysctl values host kernel parameter बदल सकती थीं और host-root execution तक पहुँच सकती थीं। Upstream advisory में patched releases और workarounds दिए गए हैं। Local `crio --version` से Minikube या किसी दूसरे node container के भीतर मौजूद runtime का पता नहीं चल सकता; पढ़ने योग्य Minikube startup log से version का संकेत मिल सकता है, लेकिन यह ऐतिहासिक साक्ष्य है, live runtime या उसके patch state का प्रमाण नहीं। इसे reachable escalation मानने से पहले वास्तविक node runtime, Pod-create authorization, admission rules और संबंधित seccomp तथा user-namespace boundaries की पुष्टि करें।

एक सीधा local `pinns` review path भी है: [discoverers ने बताया कि flawed helper को invoke करने के लिए Kubernetes की आवश्यकता नहीं है](https://www.crowdstrike.com/en-us/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/). जाँचें कि क्या मौजूदा account root-owned setuid `pinns` चला सकता है, क्या NoNewPrivs या `nosuid` mount उस transition को रोकता है, और क्या installed **helper build** में fix मौजूद नहीं है। [Upstream advisory](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) में patched release versions दिए गए हैं, लेकिन daemon द्वारा दिखाया गया version अकेले यह साबित नहीं करता कि कौन-सी helper binary installed है; distributor backports भी exposure बदल सकते हैं। Setuid file सिर्फ़ एक संभावित candidate है; routine enumeration के दौरान उसे चलाए बिना helper provenance, configuration और host sysctl behavior को validate करें।

### Incus, LXD, And LXC

Incus/LXD/LXC systems को Docker-शैली के application containers से अलग रखना उपयोगी है, क्योंकि इनका इस्तेमाल अक्सर **system containers** के रूप में होता है। आम तौर पर system container से उम्मीद की जाती है कि वह अधिक पूर्ण userspace, लंबे समय तक चलने वाली services, अधिक device exposure और व्यापक host integration वाली lightweight machine जैसा दिखे। Isolation के तरीके अब भी kernel primitives ही हैं, लेकिन परिचालन संबंधी अपेक्षाएँ अलग होती हैं। इसलिए यहाँ की misconfigurations अक्सर "खराब app-container defaults" के बजाय lightweight virtualization या host delegation की गलतियों जैसी दिखती हैं।

### systemd-nspawn

systemd-nspawn एक दिलचस्प स्थान रखता है, क्योंकि यह systemd-native है और testing, debugging तथा OS-जैसे environments चलाने के लिए बहुत उपयोगी है। यह cloud-native production का प्रमुख runtime नहीं है, लेकिन labs और distro-केंद्रित environments में इतना आम है कि इसका उल्लेख ज़रूरी है। Security analysis के लिए यह एक और याद दिलाता है कि "container" की अवधारणा कई ecosystems और operational styles में फैली हुई है।

### Apptainer / Singularity

Apptainer (जिसे पहले Singularity कहा जाता था) research और HPC environments में आम है। इसकी trust assumptions, user workflow और execution model, Docker/Kubernetes-केंद्रित stacks से महत्वपूर्ण रूप से अलग हैं। खास तौर पर, ये environments अक्सर इस बात को लेकर बहुत सावधान रहते हैं कि users को व्यापक privileged container-management powers दिए बिना packaged workloads चलाने दिया जाए। अगर reviewer यह मान ले कि हर container environment मूल रूप से "server पर Docker" जैसा है, तो वह इन deployments को गंभीर रूप से गलत समझेगा।

## Build-Time Tooling

कई security चर्चाएँ सिर्फ़ run time की बात करती हैं, लेकिन build-time tooling भी महत्वपूर्ण है, क्योंकि यही image contents, build secrets के exposure और final artifact में शामिल होने वाले trusted context की मात्रा तय करता है।

**BuildKit** और `docker buildx` आधुनिक build backends हैं, जो caching, secret mounting, SSH forwarding और multi-platform builds जैसी सुविधाएँ support करते हैं। ये उपयोगी सुविधाएँ हैं, लेकिन security के नज़रिये से ये ऐसी जगहें भी बनाती हैं जहाँ secrets image layers में leak हो सकते हैं या बहुत व्यापक build context उन files को उजागर कर सकता है जिन्हें कभी शामिल नहीं किया जाना चाहिए था। **Buildah** OCI-native ecosystems में, खासकर Podman के साथ, ऐसी ही भूमिका निभाता है; वहीं **Kaniko** का उपयोग अक्सर उन CI environments में होता है जो build pipeline को privileged Docker daemon की अनुमति नहीं देना चाहते।

मुख्य सीख यह है कि image बनाना और image चलाना अलग-अलग phases हैं, लेकिन कमज़ोर build pipeline container launch होने से बहुत पहले ही कमज़ोर runtime posture बना सकती है।

## Orchestration Is Another Layer, Not The Runtime

Kubernetes को मानसिक रूप से runtime के बराबर नहीं मानना चाहिए। Kubernetes orchestrator है। यह Pods schedule करता है, desired state store करता है और workload configuration के ज़रिए security policy व्यक्त करता है। फिर kubelet containerd या CRI-O जैसे CRI implementation से बात करता है, जो आगे `runc`, `crun`, `runsc` या `kata-runtime` जैसे low-level runtime को invoke करता है।

यह अलगाव इसलिए महत्वपूर्ण है, क्योंकि कई लोग गलती से किसी protection का श्रेय "Kubernetes" को देते हैं, जबकि उसे वास्तव में node runtime लागू करता है; या वे "containerd defaults" को ऐसे behavior के लिए दोष देते हैं जो Pod spec से आया था। व्यवहार में, अंतिम security posture कई चीज़ों का मेल होता है: orchestrator किसी चीज़ की माँग करता है, runtime stack उसे translate करता है और अंततः kernel उसे लागू करता है।

## Why Runtime Identification Matters During Assessment

अगर आप engine और runtime की पहचान शुरू में कर लेते हैं, तो बाद के कई observations को समझना आसान हो जाता है। Rootless Podman container से संकेत मिलता है कि user namespaces संभवतः इस स्थिति का हिस्सा हैं। किसी workload में mount किया गया Docker socket API-आधारित privilege escalation को एक वास्तविक रास्ता बना सकता है। CRI-O/OpenShift node देखते ही आपको SELinux labels और restricted workload policy के बारे में सोचना चाहिए। gVisor या Kata environment में यह मानने से बचना चाहिए कि classic `runc` breakout PoC उसी तरह काम करेगा।

इसीलिए container assessment के शुरुआती कदमों में हमेशा दो सरल सवालों के जवाब देने चाहिए: **कौन-सा component container को manage कर रहा है** और **किस runtime ने वास्तव में process launch किया**। इन सवालों के जवाब स्पष्ट हो जाने पर, बाकी environment को समझना आम तौर पर बहुत आसान हो जाता है।

## Runtime Vulnerabilities

हर container escape operator misconfiguration के कारण नहीं होता। कभी-कभी runtime खुद vulnerable component होता है। यह इसलिए महत्वपूर्ण है, क्योंकि workload सावधानीपूर्वक configured दिखने के बावजूद low-level runtime flaw के ज़रिए exposed हो सकता है।

इसका classic उदाहरण `runc` में **CVE-2019-5736** है, जिसमें एक malicious container host के `runc` binary को overwrite कर सकता था और फिर बाद में होने वाले `docker exec` या इसी तरह के runtime invocation का इंतज़ार कर सकता था, ताकि attacker-controlled code trigger हो जाए। यह exploit path साधारण bind-mount या capability की गलती से बहुत अलग है, क्योंकि यह exec handling के दौरान runtime द्वारा container process space में दोबारा प्रवेश करने के तरीके का दुरुपयोग करता है।<sup>[[1]](#references)</sup>

Red-team के नज़रिये से एक न्यूनतम reproduction workflow यह है:

```bash
go build main.go
./main
```

फिर, host से:

```bash
docker exec -it <container-name> /bin/sh
```

मुख्य सीख किसी सटीक ऐतिहासिक exploit implementation के बारे में नहीं, बल्कि assessment पर उसके प्रभाव के बारे में है: यदि runtime version vulnerable है, तो सामान्य in-container code execution ही host को compromise करने के लिए पर्याप्त हो सकता है, भले ही दिखाई देने वाली container configuration स्पष्ट रूप से कमजोर न लगे।

`runc` में `CVE-2024-21626`, BuildKit mount races और containerd parsing bugs जैसे हालिया runtime CVEs इसी बात को पुष्ट करते हैं। Runtime version और patch level सुरक्षा सीमा का हिस्सा हैं, महज़ रखरखाव से जुड़ी छोटी-मोटी बातें नहीं।

## References

- [1] [runC के ज़रिए Docker से बाहर निकलना – CVE-2019-5736 की व्याख्या](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
