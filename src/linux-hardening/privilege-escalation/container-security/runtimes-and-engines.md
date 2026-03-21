# कंटेनर रंटाइम्स, इंज़न्स, बिल्डर्स, और सैंडबॉक्स

{{#include ../../../banners/hacktricks-training.md}}

कंटेनर सुरक्षा में सबसे बड़ा भ्रमों में से एक यह है कि कई पूरी तरह अलग-अलग घटकों को अक्सर एक ही शब्द में समेट दिया जाता है। "Docker" किसी image फॉर्मैट, CLI, daemon, build सिस्टम, runtime stack, या बस कंटेनरों के सामान्य विचार से संबंधित हो सकता है। सुरक्षा कार्य के लिए यह अस्पष्टता समस्या बन जाती है, क्योंकि अलग-अलग परतें अलग-अलग सुरक्षा जिम्मेदारियों के लिए उत्तरदायी होती हैं। एक खराब bind mount से हुआ breakout किसी निम्न-स्तरीय runtime बग से हुए breakout के समान नहीं है, और न ही यह Kubernetes में किसी क्लस्टर नीति की गलती के समान है।

यह पृष्ठ पारिस्थितिकी तंत्र को भूमिका के अनुसार अलग करता है ताकि सेक्शन के बाकी हिस्से ठीक से बता सकें कि कोई सुरक्षा या कमजोरियाँ वास्तव में कहाँ मौजूद हैं।

## OCI को सामान्य भाषा के रूप में

आधुनिक Linux कंटेनर स्टैक अक्सर आपस में इंटरऑपरेट करते हैं क्योंकि वे एक सेट OCI specifications बोलते हैं। **OCI Image Specification** यह बताती है कि images और layers कैसे प्रस्तुत किए जाते हैं। **OCI Runtime Specification** यह बताती है कि runtime को प्रक्रिया कैसे लॉन्च करनी चाहिए, जिसमें namespaces, mounts, cgroups, और सुरक्षा सेटिंग्स शामिल हैं। **OCI Distribution Specification** यह मानकीकृत करता है कि registries कंटेंट कैसे एक्सपोज़ करते हैं।

यह महत्वपूर्ण है क्योंकि यह समझाता है कि एक उपकरण से बनायी गई container image अक्सर दूसरे से चलायी जा सकती है, और कई engines एक ही निम्न-स्तरीय runtime साझा क्यों कर सकते हैं। यह यह भी बताता है कि विभिन्न उत्पादों में सुरक्षा व्यवहार समान क्यों दिख सकता है: उनमें से कई एक ही OCI runtime कॉन्फ़िगरेशन बना रहे होते हैं और इसे उसी छोटे सेट के runtimes को सौंप रहे होते हैं।

## Low-Level OCI Runtimes

निम्न-स्तरीय runtime वह घटक है जो kernel सीमा के सबसे करीब होता है। यह वही भाग है जो वास्तव में namespaces बनाता है, cgroup सेटिंग्स लिखता है, capabilities और seccomp filters लागू करता है, और अंततः `execve()` करके container प्रक्रिया को लॉन्च करता है। जब लोग यांत्रिक स्तर पर "container isolation" पर चर्चा करते हैं, तो वे आम तौर पर इसी परत की बात कर रहे होते हैं, भले ही वे इसे स्पष्ट रूप से न कहें।

### `runc`

`runc` संदर्भ OCI runtime है और सबसे अधिक पहचाना जाने वाला implementation बना हुआ है। यह Docker, containerd, और कई Kubernetes deployments के अंतर्गत भारी रूप से उपयोग होता है। बहुत सारा सार्वजनिक रिसर्च और exploitation सामग्रियाँ `runc`-style environments को लक्ष्य बनाती हैं क्योंकि वे आम हैं और क्योंकि `runc` वह बेसलाइन परिभाषित करता है जो कई लोग Linux container की कल्पना करते समय सोचते हैं। इसलिए `runc` को समझना क्लासिक container isolation के लिए एक मजबूत मानसिक मॉडल देता है।

### `crun`

`crun` एक अन्य OCI runtime है, जो C में लिखा गया है और आधुनिक Podman वातावरणों में व्यापक रूप से उपयोग होता है। इसे अक्सर अच्छे cgroup v2 समर्थन, मजबूत rootless ergonomics, और कम ओवरहेड के लिए सराहना की जाती है। सुरक्षा के परिप्रेक्ष्य से महत्वपूर्ण बात यह नहीं है कि यह किसी अलग भाषा में लिखा गया है, बल्कि यह कि यह अभी भी वही भूमिका निभाता है: यह वह घटक है जो OCI कॉन्फ़िगरेशन को kernel के अंतर्गत एक चलती प्रक्रिया ट्री में बदलता है। एक rootless Podman वर्कफ़्लो अक्सर इसलिए सुरक्षित महसूस होता है क्योंकि इसके चारों ओर वाली स्टैक user namespaces और least privilege की ओर अधिक झुकती है, न कि इसलिए कि `crun` जादुई रूप से सब कुछ ठीक कर देता है।

### `runsc` From gVisor

`runsc` वह runtime है जो gVisor द्वारा उपयोग किया जाता है। यहाँ सीमा का अर्थ अर्थपूर्ण रूप से बदलता है। सामान्य तरीके से अधिकांश syscalls को होस्ट kernel को सीधे पास करने के बजाय, gVisor एक userspace kernel परत डालता है जो Linux इंटरफ़ेस के बड़े हिस्सों को emulate या मध्यस्थता करती है। परिणाम एक सामान्य `runc` कंटेनर कुछ अतिरिक्त फ्लैग्स के साथ नहीं होता; यह एक अलग sandbox डिजाइन है जिसका उद्देश्य host-kernel attack surface को कम करना है। संगतता और प्रदर्शन tradeoffs उस डिजाइन का हिस्सा हैं, इसलिए `runsc` का उपयोग करने वाले वातावरणों का दस्तावेज़ीकरण सामान्य OCI runtime वातावरणों से अलग तरीके से होना चाहिए।

### `kata-runtime`

Kata Containers सीमा को और आगे बढ़ाती हैं, कार्यभार को एक lightweight virtual machine के अंदर लॉन्च करके। प्रशासनिक रूप से, यह अभी भी एक container deployment जैसा दिख सकता है, और orchestration लेयर्स इसे वैसे ही मान सकते हैं, लेकिन अंतर्निहित isolation boundary क्लासिक host-kernel-shared कंटेनर की तुलना में virtualization के करीब होती है। तब जब मजबूत tenant isolation चाहिए और container-केंद्रित वर्कफ़्लो छोड़े बिना, तब Kata उपयोगी होती है।

## Engines And Container Managers

यदि निम्न-स्तरीय runtime वह घटक है जो सीधे kernel से बात करता है, तो engine या manager वह घटक है जिससे उपयोगकर्ता और ऑपरेटर आम तौर पर इंटरैक्ट करते हैं। यह image pulls, metadata, logs, networks, volumes, lifecycle operations, और API exposure को संभालता है। यह परत अत्यधिक महत्वपूर्ण है क्योंकि कई वास्तविक दुनिया के समझौते यहीं होते हैं: runtime socket या daemon API तक पहुंच होस्ट समझौते के समकक्ष हो सकती है भले ही निम्न-स्तरीय runtime स्वयं पूरी तरह से स्वस्थ क्यों न हो।

### Docker Engine

Docker Engine डेवलपर्स के लिए सबसे पहचाना जाने वाला container प्लेटफ़ॉर्म है और व्यक्तिगत कारणों में से एक है कि कंटेनर शब्दावली इतनी Docker-केंद्रित हो गयी। सामान्य पथ `docker` CLI से `dockerd` तक है, जो बदले में `containerd` और एक OCI runtime जैसे निम्न-स्तरीय घटकों का समन्वय करता है। ऐतिहासिक रूप से, Docker deployments अक्सर **rootful** रहे हैं, और Docker socket तक पहुंच इसलिए एक बहुत शक्तिशाली primitive रही है। यही कारण है कि इतना सारा प्रायोगिक privilege-escalation सामग्री `docker.sock` पर केंद्रित है: अगर कोई प्रक्रिया `dockerd` से एक privileged container बनाने, host paths mount करने, या host namespaces में शामिल करने के लिए कह सकती है, तो उसे kernel exploit की ज़रूरत भी नहीं पड़ सकती।

### Podman

Podman को एक अधिक daemonless मॉडल के चारों ओर डिजाइन किया गया था। संचालनात्मक रूप से, यह इस विचार को सुदृढ़ करने में मदद करता है कि कंटेनर सिर्फ प्रक्रियाएँ हैं जिन्हें मानक Linux तंत्रों के माध्यम से नियंत्रित किया जाता है न कि एक लंबे समय तक चलने वाले privileged daemon के माध्यम से। Podman का rootless कथा भी पारंपरिक Docker deployments की तुलना में बहुत मजबूत है जिनसे कई लोगों ने शुरूआत में सीखा था। इसका मतलब यह नहीं कि Podman स्वचालित रूप से सुरक्षित है, लेकिन यह डिफ़ॉल्ट जोखिम प्रोफ़ाइल को काफी हद तक बदल देता है, विशेष रूप से जब इसे user namespaces, SELinux, और `crun` के साथ मिलाया जाता है।

### containerd

containerd कई आधुनिक स्टैक्स में एक कोर runtime management घटक है। यह Docker के तहत उपयोग होता है और Kubernetes runtime बैकएंड्स में भी डोमिनेंट है। यह शक्तिशाली APIs एक्सपोज़ करता है, images और snapshots को मैनेज करता है, और अंतिम प्रक्रिया निर्माण को एक निम्न-स्तरीय runtime को सौंप देता है। containerd के आसपास की सुरक्षा चर्चाओं में यह ज़ोर देना चाहिए कि containerd socket या `ctr`/`nerdctl` फ़ंक्शनैलिटी तक पहुँच Docker के API के समान ही खतरनाक हो सकती है, भले ही इंटरफ़ेस और वर्कफ़्लो कम "डेवलपर फ्रेंडली" महसूस करें।

### CRI-O

CRI-O Docker Engine की तुलना में अधिक फोकस्ड है। यह एक general-purpose developer प्लेटफ़ॉर्म होने के बजाय, Kubernetes Container Runtime Interface को साफ़-सुथरे तरीके से लागू करने के इर्द-गिर्द बना है। यह इसे विशेष रूप से Kubernetes वितरणों और SELinux-भारी इकोसिस्टम जैसे OpenShift में सामान्य बनाता है। सुरक्षा के दृष्टिकोण से, यह सँकुचित दायरा उपयोगी है क्योंकि यह कॉन्सेप्चुअल शोर को कम करता है: CRI-O बहुत हद तक "Kubernetes के लिए कंटेनर चलाएं" परत का हिस्सा है बजाय किसी सब कुछ प्लेटफ़ॉर्म के।

### Incus, LXD, And LXC

Incus/LXD/LXC सिस्टम्स को Docker-शैली के application containers से अलग रखना उपयोगी है क्योंकि इन्हें अक्सर system containers के रूप में उपयोग किया जाता है। एक system container आमतौर पर एक हल्के मशीन के समान दिखने की अपेक्षा की जाती है, जिसमें एक पूरा userspace, लंबे समय तक चलने वाली सेवाएँ, ज्यादा डिवाइस एक्सपोज़र, और अधिक होस्ट इंटीग्रेशन होती है। isolation mechanisms अभी भी kernel primitives हैं, लेकिन संचालनात्मक अपेक्षाएँ अलग होती हैं। नतीजतन, यहाँ की misconfigurations अक्सर "खराब app-container defaults" जैसी नहीं दिखतीं बल्कि हल्के virtualization या host delegation में हुई गलतियों जैसी दिखती हैं।

### systemd-nspawn

systemd-nspawn एक दिलचस्प जगह घेरता है क्योंकि यह systemd- नेटिव है और testing, debugging, और OS-जैसे वातावरण चलाने के लिए बहुत उपयोगी है। यह dominant cloud-native production runtime नहीं है, लेकिन यह labs और distro-उन्मुख वातावरणों में पर्याप्त बार दिखाई देता है कि इसका उल्लेख ज़रूरी है। सुरक्षा विश्लेषण के लिए, यह एक और रिमाइंडर है कि "container" की अवधारणा कई इकोसिस्टम और संचालन शैलियों को पाटती है।

### Apptainer / Singularity

Apptainer (पहले Singularity) research और HPC वातावरणों में आम है। इसके trust assumptions, user workflow, और execution मॉडल Docker/Kubernetes-केंद्रित स्टैक्स से महत्वपूर्ण रूप से अलग होते हैं। विशेष रूप से, ये वातावरण अक्सर उपयोगकर्ताओं को पैकेज्ड वर्कलोड्स चलाने की अनुमति देने के बारे में गहराई से परवाह करते हैं बिना उन्हें व्यापक privileged container-management शक्तियाँ दिए। यदि कोई समीक्षक यह मानता है कि हर कंटेनर वातावरण मूलतः "Docker on a server" है, तो वे इन deployments को बुरी तरह गलत समझेंगे।

## Build-Time Tooling

कई सुरक्षा चर्चाएँ केवल run time की बात करती हैं, लेकिन build-time tooling भी महत्वपूर्ण है क्योंकि यह निर्धारित करता है कि image के अंदर क्या है, build secrets कहाँ से expose होते हैं, और कितना trusted context final artifact में एम्बेड हो जाता है।

**BuildKit** और `docker buildx` आधुनिक build बैकएंड हैं जो caching, secret mounting, SSH forwarding, और multi-platform builds जैसी सुविधाओं का समर्थन करते हैं। ये उपयोगी सुविधाएँ हैं, लेकिन सुरक्षा के दृष्टिकोण से ये ऐसे स्थान भी बनाते हैं जहाँ secrets image layers में leak कर सकते हैं या जहाँ बहुत व्यापक build context उन फ़ाइलों को एक्सपोज़ कर सकता है जिन्हें कभी शामिल नहीं किया जाना चाहिए। **Buildah** OCI-नैटिव इकोसिस्टम में एक समान भूमिका निभाता है, विशेषकर Podman के चारों ओर, जबकि **Kaniko** अक्सर CI वातावरणों में उपयोग होता है जो बिल्ड पाइपलाइन को एक privileged Docker daemon देना नहीं चाहते।

मुख्य सबक यह है कि image creation और image execution अलग चरण हैं, लेकिन एक कमजोर build पाइपलाइन runtime पर कमजोर सुरक्षा स्थिति पहले ही बना सकती है इससे पहले कि कंटेनर लॉन्च हो।

## Orchestration Is Another Layer, Not The Runtime

Kubernetes को मानसिक रूप से runtime के बराबर नहीं समझना चाहिए। Kubernetes orchestrator है। यह Pods को शेड्यूल करता है, desired state को स्टोर करता है, और workload configuration के माध्यम से सुरक्षा नीति व्यक्त करता है। फिर kubelet किसी CRI implementation जैसे containerd या CRI-O से बात करता है, जो बदले में `runc`, `crun`, `runsc`, या `kata-runtime` जैसे निम्न-स्तरीय runtime को invoke करता है।

यह अलगाव इसलिए महत्वपूर्ण है क्योंकि कई लोग गलत रूप से किसी सुरक्षा को "Kubernetes" को श्रेय दे देते हैं जबकि वह वास्तव में node runtime द्वारा लागू होती है, या वे "containerd defaults" को दोष देते हैं उस व्यवहार के लिए जो Pod spec से आया था। व्यवहार में, अंतिम सुरक्षा स्थिति एक composition होती है: orchestrator कुछ मांगता है, runtime stack उसे अनुवादित करता है, और kernel अंततः उसे लागू करता है।

## Why Runtime Identification Matters During Assessment

यदि आप प्रारंभ में engine और runtime की पहचान कर लेते हैं, तो बाद की कई टिप्पणियाँ समझने में आसान हो जाती हैं। एक rootless Podman container यह संकेत देता है कि user namespaces संभवतः कहानी का हिस्सा हैं। किसी workload में Docker socket mount होना यह बताता है कि API-driven privilege escalation एक यथार्थवादी मार्ग है। किसी CRI-O/OpenShift node को देखकर तुरंत SELinux labels और restricted workload policy के बारे में सोचना चाहिए। gVisor या Kata वातावरण यह सावधान कर देना चाहिए कि एक क्लासिक `runc` breakout PoC उसी तरह व्यवहार करेगा, यह मान लेना सुरक्षित नहीं है।

इसीलिए container assessment के पहले चरणों में से एक हमेशा दो सरल प्रश्नों का उत्तर देना होना चाहिए: कौन सा component container को manage कर रहा है और कौन सा runtime वास्तव में प्रक्रिया लॉन्च कर रहा है। एक बार जब ये उत्तर स्पष्ट हो जाते हैं, तो आम तौर पर बाकी वातावरण के बारे में तर्क करना बहुत आसान हो जाता है।

## Runtime Vulnerabilities

हर container escape operator misconfiguration से नहीं आता। कभी-कभी runtime स्वयं कमजोर घटक होता है। यह महत्व रखता है क्योंकि एक workload जो दिखता है जैसे सावधानीपूर्वक कॉन्फ़िगर किया गया है, वह फिर भी एक निम्न-स्तरीय runtime flaw के माध्यम से उजागर हो सकता है।

क्लासिक उदाहरण `runc` में **CVE-2019-5736** है, जहाँ एक malicious container होस्ट `runc` बाइनरी को overwrite कर सकता था और फिर किसी बाद के `docker exec` या समान runtime invocation का इंतज़ार कर के attacker-controlled कोड ट्रिगर कर सकता था। exploit path एक साधारण bind-mount या capability गलती से बहुत अलग था क्योंकि यह runtime के exec handling के दौरान container प्रक्रिया स्पेस में पुनः प्रवेश करने के तरीके का दुरुपयोग करता है।

रेड-टीम के दृष्टिकोण से एक न्यूनतम पुनरुत्पादन वर्कफ़्लो इस प्रकार है:
```bash
go build main.go
./main
```
फिर, host से:
```bash
docker exec -it <container-name> /bin/sh
```
मुख्य सबक सटीक ऐतिहासिक exploit implementation नहीं है, बल्कि आकलन निहितार्थ है: अगर runtime संस्करण vulnerable है, तो साधारण in-container code execution भी host को compromise करने के लिए पर्याप्त हो सकता है, भले ही दिखाई देने वाला container configuration स्पष्ट रूप से कमजोर न लगे।

हालिया runtime CVEs जैसे `CVE-2024-21626` in `runc`, BuildKit mount races, और containerd parsing bugs यही बात और मजबूती से रिइन्फोर्स करते हैं। Runtime संस्करण और patch level सुरक्षा सीमा का हिस्सा हैं, सिर्फ रखरखाव की तुच्छ जानकारी नहीं।
