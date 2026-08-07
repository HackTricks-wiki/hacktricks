# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## Container वास्तव में क्या है

Container को परिभाषित करने का एक व्यावहारिक तरीका यह है: container एक **सामान्य Linux process tree** है, जिसे एक विशिष्ट OCI-style configuration के अंतर्गत शुरू किया गया है, ताकि उसे एक नियंत्रित filesystem, kernel resources का नियंत्रित सेट और restricted privilege model दिखाई दे। Process को लग सकता है कि वह PID 1 है, उसके पास अपना network stack है, उसका अपना hostname और IPC resources हैं, और वह अपने user namespace के अंदर root के रूप में भी चल सकता है। लेकिन अंदर से वह अब भी एक host process है, जिसे kernel किसी भी अन्य process की तरह schedule करता है।

इसी कारण container security वास्तव में इस बात का अध्ययन है कि यह illusion कैसे बनाया जाता है और यह कैसे विफल होता है। यदि mount namespace कमजोर है, तो process host filesystem देख सकता है। यदि user namespace मौजूद नहीं है या disabled है, तो container के अंदर का root host के root से बहुत सीधे map हो सकता है। यदि seccomp unconfined है और capability set बहुत व्यापक है, तो process उन syscalls और privileged kernel features तक पहुंच सकता है जिन्हें पहुंच से बाहर रहना चाहिए था। यदि runtime socket container के अंदर mounted है, तो container को kernel breakout की आवश्यकता भी नहीं हो सकती, क्योंकि वह runtime से अधिक शक्तिशाली sibling container launch करने या host root filesystem को सीधे mount करने के लिए कह सकता है।

## Containers, Virtual Machines से कैसे अलग हैं

एक VM में सामान्यतः अपना kernel और hardware abstraction boundary होता है। इसका अर्थ है कि guest kernel crash, panic या exploit हो सकता है, बिना इसके कि host kernel पर direct control स्वतः मिल जाए। Containers में workload को अलग kernel नहीं मिलता। इसके बजाय, उसे उसी kernel का carefully filtered और namespaced view मिलता है जिसका उपयोग host करता है। परिणामस्वरूप, containers सामान्यतः हल्के होते हैं, जल्दी start होते हैं, किसी machine पर अधिक घनत्व के साथ deploy करना आसान होता है और short-lived application deployment के लिए बेहतर होते हैं। इसकी कीमत यह है कि isolation boundary सही host और runtime configuration पर कहीं अधिक सीधे निर्भर करती है।

इसका अर्थ यह नहीं है कि containers "insecure" और VMs "secure" हैं। इसका अर्थ है कि security model अलग है। Rootless execution, user namespaces, default seccomp, strict capability set, बिना host namespace sharing और मजबूत SELinux या AppArmor enforcement वाला अच्छी तरह configured container stack बहुत robust हो सकता है। इसके विपरीत, `--privileged`, host PID/network sharing, अंदर mounted Docker socket और `/` का writable bind mount के साथ शुरू किया गया container, safely isolated application sandbox की तुलना में host root access के कहीं अधिक करीब होता है। अंतर उन layers से आता है जिन्हें enabled या disabled किया गया है।

एक middle ground भी है जिसे readers को समझना चाहिए, क्योंकि यह वास्तविक environments में लगातार अधिक दिखाई दे रहा है। **Sandboxed container runtimes**, जैसे **gVisor** और **Kata Containers**, classic `runc` container की तुलना में boundary को जानबूझकर अधिक मजबूत बनाते हैं। gVisor workload और कई host kernel interfaces के बीच userspace kernel layer रखता है, जबकि Kata workload को lightweight virtual machine के अंदर launch करता है। इनका उपयोग अभी भी container ecosystems और orchestration workflows के माध्यम से किया जाता है, लेकिन इनके security properties plain OCI runtimes से अलग होते हैं और इन्हें मानसिक रूप से "normal Docker containers" के साथ इस तरह group नहीं करना चाहिए जैसे सभी एक ही तरह काम करते हों।

## Container Stack: एक नहीं, कई Layers

जब कोई कहता है कि "यह container insecure है", तो उपयोगी अगला प्रश्न है: **इसे insecure किस layer ने बनाया?** Containerized workload सामान्यतः कई components के साथ मिलकर बनाया जाता है।

सबसे ऊपर अक्सर **image build layer** होती है, जैसे BuildKit, Buildah या Kaniko, जो OCI image और metadata बनाती है। Low-level runtime के ऊपर **engine या manager** हो सकता है, जैसे Docker Engine, Podman, containerd, CRI-O, Incus या systemd-nspawn। Cluster environments में **orchestrator** भी हो सकता है, जैसे Kubernetes, जो workload configuration के माध्यम से requested security posture तय करता है। अंततः **kernel** ही namespaces, cgroups, seccomp और MAC policy को वास्तव में enforce करता है।

Defaults को समझने के लिए यह layered model महत्वपूर्ण है। कोई restriction Kubernetes द्वारा request की जा सकती है, CRI के माध्यम से containerd या CRI-O द्वारा translate की जा सकती है, runtime wrapper द्वारा OCI spec में convert की जा सकती है और उसके बाद ही `runc`, `crun`, `runsc` या कोई अन्य runtime इसे kernel के विरुद्ध enforce कर सकता है। जब environments के बीच defaults अलग होते हैं, तो अक्सर इसका कारण यह होता है कि इनमें से किसी एक layer ने final configuration बदल दी। इसलिए वही mechanism Docker या Podman में CLI flag, Kubernetes में Pod या `securityContext` field और lower-level runtime stacks में workload के लिए generated OCI configuration के रूप में दिखाई दे सकता है। इसी कारण, इस section में दिए गए CLI examples को **general container concept के लिए runtime-specific syntax** के रूप में पढ़ना चाहिए, न कि हर tool द्वारा supported universal flags के रूप में।

## वास्तविक Container Security Boundary

व्यवहार में, container security **overlapping controls** से आती है, किसी एक perfect control से नहीं। Namespaces visibility को isolate करते हैं। cgroups resource usage को govern और limit करते हैं। Capabilities यह कम करती हैं कि privileged दिखने वाला process वास्तव में क्या कर सकता है। seccomp खतरनाक syscalls को kernel तक पहुंचने से पहले block करता है। AppArmor और SELinux सामान्य DAC checks के ऊपर Mandatory Access Control जोड़ते हैं। `no_new_privs`, masked procfs paths और read-only system paths सामान्य privilege और proc/sys abuse chains को कठिन बनाते हैं। Runtime भी महत्वपूर्ण है, क्योंकि वही तय करता है कि mounts, sockets, labels और namespace joins कैसे बनाए जाएंगे।

इसीलिए container security documentation का काफी भाग repetitive लगता है। वही escape chain अक्सर एक साथ कई mechanisms पर निर्भर करती है। उदाहरण के लिए, writable host bind mount खराब है, लेकिन स्थिति तब कहीं अधिक गंभीर हो जाती है जब container host पर real root के रूप में भी चलता हो, उसके पास `CAP_SYS_ADMIN` हो, वह seccomp से unconfined हो और SELinux या AppArmor द्वारा restricted न हो। इसी तरह, host PID sharing एक गंभीर exposure है, लेकिन attacker के लिए यह तब बहुत अधिक उपयोगी हो जाता है जब इसे `CAP_SYS_PTRACE`, कमजोर procfs protections या `nsenter` जैसे namespace-entry tools के साथ जोड़ा जाए। इसलिए इस topic को document करने का सही तरीका हर page पर उसी attack को दोहराना नहीं है, बल्कि यह समझाना है कि final boundary में प्रत्येक layer का क्या योगदान है।

## इस Section को कैसे पढ़ें

यह section सबसे general concepts से सबसे specific concepts तक organized है।

Runtime और ecosystem overview से शुरुआत करें:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

फिर उन control planes और supply-chain surfaces की समीक्षा करें जो अक्सर यह तय करते हैं कि attacker को kernel escape की आवश्यकता भी होगी या नहीं:

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

फिर protection model पर जाएं:

{{#ref}}
protections/
{{#endref}}

Namespace pages kernel isolation primitives को अलग-अलग समझाते हैं:

{{#ref}}
protections/namespaces/
{{#endref}}

cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths और read-only system paths पर pages उन mechanisms को समझाते हैं जो सामान्यतः namespaces के ऊपर layered होते हैं:

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

## एक अच्छा First Enumeration Mindset

Containerized target का assessment करते समय प्रसिद्ध escape PoCs पर तुरंत जाने की तुलना में कुछ precise technical questions पूछना अधिक उपयोगी होता है। पहले **stack** की पहचान करें: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer या कुछ अधिक specialized। फिर **runtime** की पहचान करें: `runc`, `crun`, `runsc`, `kata-runtime` या कोई अन्य OCI-compatible implementation। इसके बाद जांचें कि environment **rootful या rootless** है, **user namespaces** active हैं या नहीं, कोई **host namespaces** shared हैं या नहीं, कौन-सी **capabilities** बची हुई हैं, **seccomp** enabled है या नहीं, कोई **MAC policy** वास्तव में enforcing है या नहीं, **dangerous mounts या sockets** मौजूद हैं या नहीं और क्या process container runtime API के साथ interact कर सकता है।

ये answers आपको base image name की तुलना में वास्तविक security posture के बारे में कहीं अधिक बताते हैं। कई assessments में, final container configuration को समझकर ही आप किसी application file को पढ़ने से पहले संभावित breakout family का अनुमान लगा सकते हैं।

## Coverage

यह section container-oriented organization के अंतर्गत पुराने Docker-focused material को cover करता है: runtime और daemon exposure, authorization plugins, image trust और build secrets, sensitive host mounts, distroless workloads, privileged containers और वे kernel protections जो सामान्यतः container execution के आसपास layered होती हैं।

{{#include ../../../banners/hacktricks-training.md}}
