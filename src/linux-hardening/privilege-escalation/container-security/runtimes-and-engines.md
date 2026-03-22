# कंटेनर रनटाइम्स, इंजन, बिल्डर, और सैंडबॉक्स

{{#include ../../../banners/hacktricks-training.md}}

कंटेनर सुरक्षा में सबसे बड़ी उलझनों में से एक यह है कि कई बिल्कुल अलग घटकों को अक्सर एक ही शब्द में समेट दिया जाता है। "Docker" किसी image format, CLI, daemon, build system, runtime stack, या सामान्य रूप से कंटेनरों के विचार का संदर्भ दे सकता है। सुरक्षा के काम के लिए यह ambiguity समस्या पैदा करती है, क्योंकि अलग‑अलग लेयर अलग‑अलग सुरक्षा के ज़िम्मेदार होती हैं। एक खराब bind mount से होने वाला breakout उसी चीज़ की तरह नहीं है जो किसी low-level runtime bug से होता है, और न ही ये वही है जो Kubernetes में किसी क्लस्टर नीति की गलती से होता है।

यह पृष्ठ भूमिका के अनुसार इकोसिस्टम को अलग करता है ताकि सेक्शन का बाकी हिस्सा सटीक रूप से बता सके कि किस सुरक्षा या कमजोरी का असली स्थान कहाँ है।

## OCI को सामान्य भाषा के रूप में

आधुनिक Linux container stacks अक्सर इसलिए इंटरऑपरेट करते हैं क्योंकि वे एक सेट OCI specifications बोलते हैं। **OCI Image Specification** यह बताती है कि images और layers कैसे प्रस्तुत किए जाते हैं। **OCI Runtime Specification** यह वर्णन करता है कि runtime को process कैसे लॉन्च करना चाहिए, जिसमें namespaces, mounts, cgroups, और security settings शामिल हैं। **OCI Distribution Specification** यह मानकीकृत करती है कि registries सामग्री कैसे expose करते हैं।

यह महत्वपूर्ण है क्योंकि यह समझाता है कि एक उपकरण से बनाया गया container image अक्सर दूसरे उपकरण से चलाया जा सकता है, और कई engines एक ही low-level runtime साझा क्यों कर सकते हैं। यह यह भी स्पष्ट करता है कि सुरक्षा व्यवहार विभिन्न उत्पादों में समान क्यों दिख सकता है: उनमें से कई वही OCI runtime configuration बना रहे होते हैं और इसे एक ही छोटे सेट runtimes को दे रहे होते हैं।

## Low-Level OCI Runtimes

low-level runtime वह घटक है जो kernel boundary के सबसे निकट होता है। यह वह हिस्सा है जो वास्तव में namespaces बनाता है, cgroup settings लिखता है, capabilities और seccomp filters लागू करता है, और अंत में `execve()` से container process को चलाता है। जब लोग यांत्रिक स्तर पर "container isolation" पर चर्चा करते हैं, तो वे आमतौर पर उसी लेयर की बात कर रहे होते हैं, भले ही वे इसे स्पष्ट रूप से न कहें।

### `runc`

`runc` reference OCI runtime है और सबसे प्रसिद्ध implementation में से एक बना हुआ है। यह Docker, containerd, और कई Kubernetes deployments के तहत भारी रूप से उपयोग किया जाता है। बहुत सारा सार्वजनिक शोध और exploitation सामग्री `runc`-style environments को टार्गेट करती है सिर्फ इसलिए कि वे आम हैं और क्योंकि `runc` उस baseline को परिभाषित करता है जिसे कई लोग एक Linux container की छवि में सोचते हैं। इसलिए `runc` को समझना पाठक को क्लासिक container isolation का एक मजबूत मानसिक मॉडल देता है।

### `crun`

`crun` एक और OCI runtime है, जो C में लिखा गया है और आधुनिक Podman वातावरणों में व्यापक रूप से उपयोग होता है। इसे अक्सर बेहतर cgroup v2 support, मजबूत rootless ergonomics, और कम overhead के लिए सराहा जाता है। सुरक्षा के दृष्टिकोण से महत्वपूर्ण बात यह नहीं कि यह अलग भाषा में लिखा है, बल्कि यह है कि यह अभी भी वही भूमिका निभाता है: यह वह घटक है जो OCI configuration को kernel के तहत चलती process tree में बदलता है। एक rootless Podman workflow अक्सर इसलिए अधिक सुरक्षित महसूस करता है क्योंकि आसपास का पूरा stack user namespaces और least privilege की ओर अधिक झुकता है, न कि इसलिए कि `crun` जादुई रूप से सब कुछ ठीक कर देता है।

### `runsc` From gVisor

`runsc` gVisor द्वारा उपयोग किया जाने वाला runtime है। यहाँ boundary का अर्थ महत्वपूर्ण रूप से बदल जाता है। अधिकांश syscalls को सधे हुए तरीके से host kernel को सीधे पास करने के बजाय, gVisor एक userspace kernel layer डालता है जो Linux interface के बड़े हिस्सों का अनुकरण या मध्यस्थता करता है। परिणाम एक सामान्य `runc` container नहीं है जिसमें कुछ अतिरिक्त flags हों; यह एक अलग sandbox डिजाइन है जिसका उद्देश्य host‑kernel attack surface को कम करना है। संगतता और प्रदर्शन के tradeoffs उस डिजाइन का हिस्सा हैं, इसलिए `runsc` का उपयोग करने वाले वातावरणों को सामान्य OCI runtime वातावरणों से अलग तरीके से दस्तावेज़ किया जाना चाहिए।

### `kata-runtime`

Kata Containers सीमा को और आगे बढ़ाते हैं by launching the workload inside a lightweight virtual machine। प्रशासनिक रूप से, यह अभी भी एक कंटेनर deployment जैसा दिख सकता है, और orchestration लेयर इसे वैसे ही treat कर सकती हैं, लेकिन अंतर्निहित isolation boundary क्लासिक host‑kernel‑shared container की तुलना में virtualization के करीब होता है। यह उन परिस्थितियों में उपयोगी बनाता है जहाँ मजबूत tenant isolation की आवश्यकता हो बिना container‑centric workflows को बंद किए।

## Engines और Container Managers

यदि low-level runtime वह घटक है जो सीधे kernel से बात करता है, तो engine या manager वह घटक है जिसके साथ users और operators आमतौर पर इंटरैक्ट करते हैं। यह image pulls, metadata, logs, networks, volumes, lifecycle operations, और API exposure को संभालता है। यह लेयर अत्यधिक मायने रखती है क्योंकि कई वास्तविक दुनिया के समझौते यहीं होते हैं: runtime socket या daemon API तक पहुंच host compromise के बराबर हो सकती है भले ही low-level runtime स्वयं पूरी तरह से स्वस्थ हो।

### Docker Engine

Docker Engine developers के लिए सबसे पहचानी जाने वाली container platform है और यही एक कारण है कि container vocabulary इतनी Docker‑आकार की बन गई। सामान्य मार्ग `docker` CLI से `dockerd` है, जो बदले में `containerd` और एक OCI runtime जैसे lower‑level घटकों का समन्वय करता है। ऐतिहासिक रूप से, Docker deployments अक्सर **rootful** रहे हैं, और इसलिए Docker socket तक पहुंच एक बहुत शक्तिशाली primitive रही है। इसीलिए कई व्यावहारिक privilege‑escalation सामग्री `docker.sock` पर केंद्रित होती है: यदि कोई process `dockerd` से एक privileged container बनाने, host paths mount करने, या host namespaces में जुड़ने का अनुरोध कर सकता है, तो उसे kernel exploit की ज़रूरत भी नहीं पड़ सकती।

### Podman

Podman को एक अधिक daemonless मॉडल के आसपास डिज़ाइन किया गया था। संचालनात्मक रूप से, यह विचार को मजबूत करने में मदद करता है कि कंटेनर केवल प्रक्रियाएँ हैं जिन्हें standard Linux mechanisms के माध्यम से नियंत्रित किया जाता है बजाय एक लंबे समय तक चलने वाले privileged daemon के। Podman का rootless कहानी भी उन क्लासिक Docker deployments की तुलना में बहुत मजबूत है जिन्हें कई लोगों ने पहली बार सीखा था। इसका मतलब यह नहीं कि Podman अपने आप सुरक्षित है, लेकिन यह default risk profile को काफी बदल देता है, खासकर जब इसे user namespaces, SELinux, और `crun` के साथ जोड़ा जाता है।

### containerd

containerd कई आधुनिक स्टैक्स में एक कोर runtime management घटक है। यह Docker के तहत उपयोग होता है और Kubernetes runtime backend में भी से एक प्रमुख है। यह शक्तिशाली APIs expose करता है, images और snapshots को मैनेज करता है, और अंतिम process creation को एक low-level runtime को सौंपता है। containerd के आसपास सुरक्षा चर्चाएँ यह जोर देनी चाहिए कि containerd socket या `ctr`/`nerdctl` functionality तक पहुंच Docker के API जितनी ही ख़तरनाक हो सकती है, भले ही interface और workflow कम "developer friendly" महसूस हों।

### CRI-O

CRI-O Docker Engine की तुलना में अधिक focused है। एक general-purpose developer platform होने के बजाय, यह Kubernetes Container Runtime Interface को साफ़-सुथरे तरीके से लागू करने के इर्द‑गिर्द बनाया गया है। यही कारण है कि यह Kubernetes distributions और SELinux‑heavy ecosystems जैसे OpenShift में खासा आम है। सुरक्षा के दृष्टिकोण से, वह संकुचित दायरा उपयोगी है क्योंकि यह वैचारिक अव्यवस्था को कम करता है: CRI-O बहुत हद तक "Kubernetes के लिए containers चलाओ" लेयर का हिस्सा है बजाय एक सब कुछ‑प्लेटफ़ॉर्म के।

### Incus, LXD, And LXC

Incus/LXD/LXC सिस्टम्स को Docker‑style application containers से अलग करना उपयोगी है क्योंकि इन्हें अक्सर **system containers** के रूप में उपयोग किया जाता है। एक system container आमतौर पर एक lightweight मशीन की तरह दिखने की उम्मीद की जाती है जिसमें fuller userspace, long‑running services, richer device exposure, और ज्यादा व्यापक host integration होता है। isolation mechanism अभी भी kernel primitives हैं, लेकिन संचालनात्मक अपेक्षाएँ अलग होती हैं। परिणामस्वरूप, यहां गलत कॉन्फ़िगरेशन अक्सर "खराब app‑container defaults" की तरह नहीं दिखते बल्कि lightweight virtualization या host delegation में हुई गलतियों की तरह दिखते हैं।

### systemd-nspawn

systemd-nspawn एक रोचक स्थान घेरता है क्योंकि यह systemd‑native है और testing, debugging, और OS‑like environments चलाने के लिए बहुत उपयोगी है। यह dominant cloud‑native production runtime नहीं है, लेकिन यह labs और distro‑oriented वातावरणों में इतना बार आता है कि इसका उल्लेख आवश्यक है। सुरक्षा विश्लेषण के लिए, यह फिर से याद दिलाता है कि "container" की अवधारणा कई इकोसिस्टम और संचालन शैलियों को फैलाती है।

### Apptainer / Singularity

Apptainer (पूर्व में Singularity) research और HPC वातावरणों में आम है। इसके trust assumptions, user workflow, और execution model Docker/Kubernetes‑centric स्टैक्स से महत्वपूर्ण तरीकों में अलग होते हैं। विशेष रूप से, ये वातावरण अक्सर उपयोगकर्ताओं को packaged workloads चलाने की अनुमति देने पर बहुत ध्यान देते हैं बिना उन्हें व्यापक privileged container‑management शक्तियाँ दिए। यदि कोई समीक्षक मान ले कि हर container वातावरण मूल रूप से "Docker on a server" है, तो वे इन deployments को गंभीर रूप से गलत समझेंगे।

## Build‑Time Tooling

कई सुरक्षा चर्चाएँ केवल runtime के बारे में बात करती हैं, लेकिन build‑time tooling भी मायने रखता है क्योंकि यह image contents, build secrets के leak होने के जोखिम, और कितनी trusted context final artifact में embedded होती है यह निर्धारित करता है।

**BuildKit** और `docker buildx` आधुनिक build backends हैं जो caching, secret mounting, SSH forwarding, और multi‑platform builds जैसे फीचर्स का समर्थन करते हैं। ये उपयोगी सुविधाएँ हैं, लेकिन सुरक्षा के दृष्टिकोण से ये ऐसे स्थान भी बनाते हैं जहाँ secrets image layers में leak कर सकते हैं या जहाँ एक बहुत व्यापक build context उन फ़ाइलों को expose कर सकता है जिन्हें कभी शामिल नहीं होना चाहिए था। **Buildah** OCI‑native इकोसिस्टम में समान भूमिका निभाता है, विशेषकर Podman के आसपास, जबकि **Kaniko** अक्सर CI वातावरणों में उपयोग होता है जो build pipeline को एक privileged Docker daemon देना नहीं चाहते।

मूल पाठ यह है कि image creation और image execution अलग‑अलग चरण हैं, लेकिन एक कमजोर build pipeline runtime posture को काफी पहले कमजोर बना सकती है।

## Orchestration एक और लेयर है, न कि Runtime

Kubernetes को मानसिक रूप से runtime के साथ बराबर नहीं समझना चाहिए। Kubernetes orchestrator है। यह Pods को schedule करता है, desired state स्टोर करता है, और workload configuration के माध्यम से security policy व्यक्त करता है। kubelet तब containerd या CRI‑O जैसे CRI implementation से बात करता है, जो बदले में `runc`, `crun`, `runsc`, या `kata-runtime` जैसे low‑level runtime को invoke करता है।

यह अलगाव इसलिए महत्वपूर्ण है क्योंकि कई लोग गलत तरीके से किसी सुरक्षा को "Kubernetes" का सुरक्षा मान लेते हैं जबकि वह वास्तव में node runtime द्वारा लागू की जा रही होती है, या वे "containerd defaults" को दोष देते हैं उस व्यवहार के लिए जो Pod spec से आया था। व्यावहारिक रूप से, अंतिम सुरक्षा स्थिति एक composition होती है: orchestrator कुछ माँगता है, runtime stack उसे अनुवाद करता है, और kernel अंततः उसे लागू करता है।

## क्यों Runtime पहचान आकलन के दौरान मायने रखती है

यदि आप early में engine और runtime की पहचान कर लेते हैं, तो बाद की कई टिप्पणियाँ समझना आसान हो जाता है। एक rootless Podman container सुझाव देता है कि user namespaces कहानी का हिस्सा हो सकते हैं। किसी workload में mounted Docker socket यह संकेत देता है कि API‑driven privilege escalation एक वास्तविक मार्ग हो सकता है। एक CRI-O/OpenShift node आपको तुरंत SELinux labels और restricted workload policy के बारे में सोचने पर मजबूर कर देनी चाहिए। एक gVisor या Kata वातावरण यह सोचने पर आपको अधिक सतर्क कर देगा कि एक क्लासिक `runc` breakout PoC वैसे ही काम करेगा।

इसीलिए container आकलन के पहले चरणों में से एक हमेशा दो सरल प्रश्नों का उत्तर देना होना चाहिए: **कौन सा component container का प्रबंधन कर रहा है** और **किस runtime ने वास्तव में process लॉन्च किया**। एक बार ये उत्तर स्पष्ट हो जाने पर, बाकी वातावरण को सामान्यतः समझना बहुत आसान हो जाता है।

## Runtime Vulnerabilities

हर container escape operator misconfiguration से नहीं आता। कभी‑कभी runtime स्वयं कमजोर घटक होता है। यह मायने रखता है क्योंकि एक workload ऐसा चल रहा हो सकता है जो दिखता है कि सावधान कॉन्फ़िगरेशन के साथ है और फिर भी low‑level runtime flaw के माध्यम से उजागर हो सकता है।

क्लासिक उदाहरण `runc` में **CVE-2019-5736** है, जहाँ एक malicious container host `runc` बाइनरी को overwrite कर सकता था और फिर बाद में किसी `docker exec` या समान runtime invocation के होने का इंतजार करके attacker‑controlled code trigger करवा सकता था। exploit path एक सरल bind‑mount या capability गलती से बहुत अलग है क्योंकि यह उस तरीके का दुरुपयोग करता है जिससे runtime exec handling के दौरान container process space में वापस प्रवेश करता है।

एक red-team परिप्रेक्ष्य से एक न्यूनतम पुनरुत्पादन workflow है:
```bash
go build main.go
./main
```
फिर, host से:
```bash
docker exec -it <container-name> /bin/sh
```
मुख्य सबक सटीक ऐतिहासिक exploit implementation नहीं है, बल्कि मूल्यांकन का निहितार्थ है: यदि runtime version vulnerable है, तो सामान्य in-container code execution भी host को compromise करने के लिए पर्याप्त हो सकता है, भले ही दिखाई देने वाला container configuration स्पष्ट रूप से कमजोर न लगे।

हाल की runtime CVEs जैसे `CVE-2024-21626` in `runc`, BuildKit mount races, और containerd parsing bugs वही बात पुष्टि करते हैं। Runtime version और patch level security boundary का हिस्सा हैं, केवल रखरखाव-संबंधी तुच्छ बातें नहीं।
{{#include ../../../banners/hacktricks-training.md}}
