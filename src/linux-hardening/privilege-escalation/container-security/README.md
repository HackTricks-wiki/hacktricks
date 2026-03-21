# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## What A Container Actually Is

एक व्यावहारिक परिभाषा यह है: एक container एक नियमित Linux process tree है जिसे एक विशिष्ट OCI-style configuration के तहत शुरू किया गया है ताकि वह एक नियंत्रित filesystem, नियंत्रित kernel resources, और एक प्रतिबंधित privilege मॉडल देखे। प्रोसेस यह मान सकता है कि यह PID 1 है, यह मान सकता है कि उसके पास अपना नेटवर्क स्टैक है, यह मान सकता है कि वह अपना hostname और IPC resources मालिक है, और यह अपने user namespace के अंदर root के रूप में भी चल सकता है। लेकिन अंदर से यह अभी भी एक host process है जिसे kernel किसी अन्य की तरह schedule करता है।

इसीलिए container security असल में यह अध्ययन है कि वह illusion कैसे बनाया गया है और वह कैसे फेल होता है। अगर mount namespace कमजोर है, तो प्रोसेस host filesystem देख सकता है। अगर user namespace अनुपस्थित या disabled है, तो container के अंदर का root host पर root के बहुत करीब मैप हो सकता है। अगर seccomp unconfined है और capability set बहुत व्यापक है, तो प्रोसेस ऐसे syscalls और privileged kernel features तक पहुँच सकता है जिन्हें दूर रखा जाना चाहिए था। अगर runtime socket container के अंदर mounted है, तो container को kernel breakout की आवश्यकता भी नहीं पड़ सकती क्योंकि वह सीधे runtime से अनुरोध करके एक अधिक powerful sibling container लॉन्च करवा सकता है या host root filesystem को mount करवा सकता है।

## How Containers Differ From Virtual Machines

एक VM आमतौर पर अपना खुद का kernel और hardware abstraction boundary लेकर चलता है। इसका मतलब है कि guest kernel crash, panic, या exploit हो सकता है बिना यह स्वतः ही host kernel के सीधे नियंत्रण का संकेत दिए। Containers में, workload को अलग kernel नहीं मिलता। बल्कि, उसे उसी kernel का एक सावधानीपूर्वक filtered और namespaced view मिलता है जिसे host उपयोग करता है। परिणामस्वरूप, containers आम तौर पर हल्के होते हैं, तेज़ी से शुरू होते हैं, मशीन पर घनघन पैक करना आसान होता है, और short-lived application deployment के लिए बेहतर होते हैं। कीमत यह है कि isolation boundary बहुत अधिक सीधे सही host और runtime configuration पर निर्भर करती है।

इसका मतलब यह नहीं है कि containers "insecure" हैं और VMs "secure" हैं। इसका मतलब है कि security model अलग है। एक अच्छी तरह से configured container stack जिसमें rootless execution, user namespaces, default seccomp, एक सख्त capability set, कोई host namespace sharing नहीं, और मजबूत SELinux या AppArmor enforcement शामिल हों, बहुत robust हो सकती है। इसके विपरीत, एक container जिसे `--privileged` के साथ शुरू किया गया है, host PID/network sharing है, Docker socket उसके अंदर mounted है, और `/` का writable bind mount है, व्यवहारिक रूप से host root access के बहुत करीब है बजाय एक सुरक्षित तरीके से isolated application sandbox के। फर्क उन लेयर्स से आता है जिन्हें enabled या disabled किया गया था।

एक मध्य मार्ग भी है जिसे पाठक समझें क्योंकि यह वास्तविक वातावरणों में अधिक और अधिक दिखाई देता है। Sandboxed container runtimes जैसे कि gVisor और Kata Containers जानबूझकर boundary को एक क्लासिक `runc` container से कठोर करते हैं। gVisor workload और कई host kernel interfaces के बीच एक userspace kernel layer रखता है, जबकि Kata workload को एक lightweight virtual machine के अंदर लॉन्च करता है। इन्हें अभी भी container ecosystems और orchestration workflows के माध्यम से उपयोग किया जाता है, लेकिन उनकी security properties plain OCI runtimes से भिन्न हैं और इन्हें "normal Docker containers" के साथ एक ही तरह से मानसिक रूप से समूहबद्ध नहीं किया जाना चाहिए मानो सब कुछ एक जैसा व्यवहार कर रहा हो।

## The Container Stack: Several Layers, Not One

जब कोई कहता है "यह container insecure है", तो उपयोगी follow-up सवाल यह है: कौन सी layer ने इसे insecure बनाया? एक containerized workload आम तौर पर कई components के मेल का परिणाम होता है।

ऊपर की ओर अक्सर एक image build layer होता है जैसे BuildKit, Buildah, या Kaniko, जो OCI image और metadata बनाते हैं। low-level runtime के ऊपर, कभी-कभी एक engine या manager होता है जैसे Docker Engine, Podman, containerd, CRI-O, Incus, या systemd-nspawn। cluster environments में, एक orchestrator भी हो सकता है जैसे Kubernetes जो workload configuration के जरिए requested security posture तय करता है। अंत में, kernel ही वह है जो namespaces, cgroups, seccomp, और MAC policy को वास्तव में लागू करता है।

यह layered model defaults को समझने के लिए महत्वपूर्ण है। एक restriction Kubernetes द्वारा request की जा सकती है, CRI के माध्यम से containerd या CRI-O द्वारा translate की जा सकती है, runtime wrapper द्वारा OCI spec में convert की जा सकती है, और फिर `runc`, `crun`, `runsc`, या किसी अन्य runtime द्वारा kernel के खिलाफ enforce की जा सकती है। जब defaults वातावरणों के बीच अलग होते हैं, तो अक्सर इसका कारण यह होता है कि इन लेयर्स में से किसी ने final configuration बदल दी। यही mechanism इसलिए Docker या Podman में CLI flag के रूप में दिखाई दे सकता है, Kubernetes में Pod या `securityContext` field के रूप में, और lower-level runtime stacks में workload के लिए generated OCI configuration के रूप में। इसलिए, इस अनुभाग में CLI उदाहरणों को एक सामान्य container अवधारणा के लिए runtime-specific syntax के रूप में पढ़ा जाना चाहिए, न कि हर tool द्वारा समर्थित सार्वभौमिक flags के रूप में।

## The Real Container Security Boundary

प्रायोगिक रूप से, container security एक single perfect control से नहीं बल्कि overlapping controls से आती है। Namespaces visibility अलग करती हैं। cgroups resource usage को govern और सीमित करते हैं। Capabilities उस चीज़ को घटाते हैं जो एक privileged-लगने वाला प्रोसेस वास्तव में कर सकता है। seccomp खतरनाक syscalls को kernel तक पहुँचने से पहले block करता है। AppArmor और SELinux सामान्य DAC checks के ऊपर Mandatory Access Control जोड़ते हैं। `no_new_privs`, masked procfs paths, और read-only system paths सामान्य privilege और proc/sys abuse chains को कठिन बनाते हैं। runtime भी मायने रखता है क्योंकि वही तय करता है कि mounts, sockets, labels, और namespace joins कैसे बनाए जाते हैं।

इसीलिए बहुत सी container security documentation repetitive लगती है। वही escape chain अक्सर एक साथ कई mechanisms पर निर्भर करती है। उदाहरण के लिए, एक writable host bind mount खराब है, लेकिन यह बहुत अधिक बुरा बन जाता है अगर container भी host पर वास्तविक root के रूप में चलता है, उसके पास `CAP_SYS_ADMIN` है, वह seccomp द्वारा unconfined है, और SELinux या AppArmor द्वारा restricted नहीं है। उसी तरह, host PID sharing एक गंभीर exposure है, लेकिन यह एक attacker के लिए तब काफी अधिक उपयोगी बन जाता है जब इसे `CAP_SYS_PTRACE`, कमजोर procfs protections, या namespace-entry tools जैसे `nsenter` के साथ जोड़ा जाए। इसलिए विषय का सही तरीका यह है कि हर पेज पर एक ही attack को दोहराने के बजाय यह समझाया जाए कि हर layer अंतिम सीमा में क्या योगदान देता है।

## How To Read This Section

यह अनुभाग सबसे सामान्य अवधारणाओं से लेकर सबसे विशिष्ट तक व्यवस्थित है।

runtime और ecosystem overview से शुरू करें:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

फिर उन control planes और supply-chain surfaces की समीक्षा करें जो अक्सर यह तय करते हैं कि attacker को kernel escape की भी आवश्यकता है या नहीं:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

फिर protection model में जाएँ:

{{#ref}}
protections/
{{#endref}}

namespace pages kernel isolation primitives को व्यक्तिगत रूप से समझाते हैं:

{{#ref}}
protections/namespaces/
{{#endref}}

cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths, और read-only system paths पर पेज उन mechanisms को समझाते हैं जो सामान्यतः namespaces के ऊपर परत कर दिए जाते हैं:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## A Good First Enumeration Mindset

जब किसी containerized target का आकलन कर रहे हों, तो प्रसिद्ध escape PoCs पर तुरंत कूदने के बजाय कुछ सटीक technical सवाल पूछना कहीं अधिक उपयोगी है। सबसे पहले, **stack** पहचानें: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, या कुछ और specialized। फिर **runtime** पहचानें: `runc`, `crun`, `runsc`, `kata-runtime`, या कोई अन्य OCI-compatible implementation। उसके बाद जांचें कि environment **rootful or rootless** है, क्या **user namespaces** active हैं, क्या कोई **host namespaces** shared हैं, कौन सी **capabilities** बाकी हैं, क्या **seccomp** enabled है, क्या कोई **MAC policy** वास्तव में enforcing है, क्या **dangerous mounts or sockets** मौजूद हैं, और क्या प्रोसेस container runtime API के साथ interact कर सकता है।

ये उत्तर आपको real security posture के बारे में बेस इमेज नाम से कहीं अधिक बतलाते हैं। कई assessments में, आप final container configuration को समझकर एक single application file पढ़े बिना ही संभावित breakout family की भविष्यवाणी कर सकते हैं।

## Coverage

यह अनुभाग container-oriented organization के अंतर्गत पुराने Docker-focused सामग्री को कवर करता है: runtime और daemon exposure, authorization plugins, image trust और build secrets, sensitive host mounts, distroless workloads, privileged containers, और kernel protections जो सामान्यतः container execution के चारों ओर परतदार होते हैं।
