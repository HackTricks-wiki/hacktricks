# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## वास्तव में Container क्या है

Container को परिभाषित करने का एक व्यावहारिक तरीका यह है: container एक **सामान्य Linux process tree** है, जिसे किसी विशिष्ट OCI-style configuration के अंतर्गत शुरू किया गया है, ताकि उसे नियंत्रित filesystem, kernel resources का नियंत्रित समूह और restricted privilege model दिखाई दे। Process को लग सकता है कि वह PID 1 है, उसका अपना network stack है, वह अपना hostname और IPC resources रखता है, और वह अपने user namespace के अंदर root के रूप में भी चल सकता है। लेकिन अंदर से वह अब भी host का process है, जिसे kernel किसी अन्य process की तरह schedule करता है।

इसीलिए container security वास्तव में इस बात का अध्ययन है कि यह illusion कैसे बनाई जाती है और कैसे विफल होती है। यदि mount namespace कमजोर है, तो process host filesystem देख सकता है। यदि user namespace मौजूद या enabled नहीं है, तो container के अंदर का root, host के root से बहुत निकटता से map हो सकता है। यदि seccomp unconfined है और capability set बहुत व्यापक है, तो process उन syscalls और privileged kernel features तक पहुंच सकता है जिन्हें पहुंच से बाहर रहना चाहिए था। यदि runtime socket container के अंदर mounted है, तो container को kernel breakout की आवश्यकता भी नहीं हो सकती, क्योंकि वह runtime से अधिक शक्तिशाली sibling container launch करने या host root filesystem को सीधे mount करने के लिए कह सकता है।

## Containers Virtual Machines से कैसे अलग हैं

एक VM में सामान्यतः अपना kernel और hardware abstraction boundary होता है। इसका अर्थ है कि guest kernel crash, panic या exploit हो सकता है, बिना इस बात के कि host kernel पर तुरंत direct control मिल जाए। Containers में workload को अलग kernel नहीं मिलता। इसके बजाय उसे उसी kernel का carefully filtered और namespaced view मिलता है जिसे host उपयोग करता है। परिणामस्वरूप, containers सामान्यतः हल्के होते हैं, जल्दी start होते हैं, किसी machine पर अधिक density के साथ deploy करना आसान होता है और short-lived application deployment के लिए अधिक उपयुक्त होते हैं। इसकी कीमत यह है कि isolation boundary सही host और runtime configuration पर कहीं अधिक सीधे निर्भर करती है।

इसका अर्थ यह नहीं है कि containers "insecure" और VMs "secure" हैं। इसका अर्थ है कि security model अलग है। Rootless execution, user namespaces, default seccomp, strict capability set, host namespace sharing के अभाव और strong SELinux या AppArmor enforcement वाला अच्छी तरह configured container stack बहुत robust हो सकता है। इसके विपरीत, `--privileged`, host PID/network sharing, अंदर mounted Docker socket और `/` का writable bind mount के साथ शुरू किया गया container, safely isolated application sandbox की तुलना में host root access के अधिक करीब होता है। अंतर उन layers से आता है जिन्हें enabled या disabled किया गया है।

एक middle ground भी है, जिसे readers को समझना चाहिए क्योंकि यह real environments में अधिकाधिक दिखाई दे रहा है। **Sandboxed container runtimes**, जैसे **gVisor** और **Kata Containers**, classic `runc` container की तुलना में boundary को जानबूझकर अधिक harden करते हैं। gVisor workload और कई host kernel interfaces के बीच userspace kernel layer रखता है, जबकि Kata workload को lightweight virtual machine के अंदर launch करता है। इनका उपयोग अब भी container ecosystems और orchestration workflows के माध्यम से किया जाता है, लेकिन इनके security properties plain OCI runtimes से अलग होते हैं और इन्हें मानसिक रूप से "normal Docker containers" के साथ इस तरह group नहीं करना चाहिए जैसे सब कुछ एक ही तरह behave करता हो।

## Container Stack: एक नहीं, कई Layers

जब कोई कहता है कि "यह container insecure है", तो उपयोगी follow-up question है: **किस layer ने इसे insecure बनाया?** एक containerized workload सामान्यतः कई components के साथ मिलकर बनता है।

सबसे ऊपर अक्सर **image build layer** होती है, जैसे BuildKit, Buildah या Kaniko, जो OCI image और metadata बनाती है। Low-level runtime के ऊपर कोई **engine या manager** हो सकता है, जैसे Docker Engine, Podman, containerd, CRI-O, Incus या systemd-nspawn। Cluster environments में कोई **orchestrator** भी हो सकता है, जैसे Kubernetes, जो workload configuration के माध्यम से requested security posture तय करता है। अंत में, **kernel** ही namespaces, cgroups, seccomp और MAC policy को वास्तव में enforce करता है।

Defaults को समझने के लिए यह layered model महत्वपूर्ण है। Kubernetes द्वारा मांगी गई restriction को CRI के माध्यम से containerd या CRI-O translate कर सकता है, runtime wrapper इसे OCI spec में convert कर सकता है और उसके बाद ही `runc`, `crun`, `runsc` या कोई अन्य runtime इसे workload के विरुद्ध kernel पर enforce कर सकता है। जब अलग-अलग environments में defaults भिन्न होते हैं, तो अक्सर इसका कारण यह होता है कि इन layers में से किसी एक ने final configuration बदल दी। इसलिए वही mechanism Docker या Podman में CLI flag, Kubernetes में Pod या `securityContext` field और lower-level runtime stacks में workload के लिए generated OCI configuration के रूप में दिखाई दे सकता है। इसी कारण इस section में दिए गए CLI examples को **किसी सामान्य container concept के लिए runtime-specific syntax** समझना चाहिए, न कि हर tool द्वारा supported universal flags।

## वास्तविक Container Security Boundary

व्यवहार में container security **overlapping controls** से आती है, किसी एक perfect control से नहीं। Namespaces visibility को isolate करते हैं। cgroups resource usage को govern और limit करते हैं। Capabilities यह कम करती हैं कि privileged दिखने वाला process वास्तव में क्या कर सकता है। seccomp खतरनाक syscalls को kernel तक पहुंचने से पहले block करता है। AppArmor और SELinux सामान्य DAC checks के ऊपर Mandatory Access Control जोड़ते हैं। `no_new_privs`, masked procfs paths और read-only system paths सामान्य privilege और proc/sys abuse chains को कठिन बनाते हैं। Runtime भी महत्वपूर्ण है, क्योंकि वही तय करता है कि mounts, sockets, labels और namespace joins कैसे बनाए जाएंगे।

इसीलिए container security documentation काफी repetitive लगती है। वही escape chain अक्सर एक साथ कई mechanisms पर निर्भर करती है। उदाहरण के लिए, writable host bind mount खराब है, लेकिन स्थिति और भी गंभीर हो जाती है यदि container host पर real root के रूप में चलता हो, उसके पास `CAP_SYS_ADMIN` हो, seccomp से unconfined हो और SELinux या AppArmor द्वारा restricted न हो। इसी तरह, host PID sharing एक गंभीर exposure है, लेकिन attacker के लिए यह तब बहुत अधिक उपयोगी हो जाता है जब इसके साथ `CAP_SYS_PTRACE`, कमजोर procfs protections या `nsenter` जैसे namespace-entry tools भी मौजूद हों। इसलिए इस विषय को document करने का सही तरीका यह नहीं है कि हर page पर वही attack दोहराया जाए, बल्कि यह समझाया जाए कि final boundary में प्रत्येक layer क्या योगदान देती है।

## इस Section को कैसे पढ़ें

यह section सबसे general concepts से सबसे specific concepts की ओर व्यवस्थित किया गया है।

Runtime और ecosystem overview से शुरुआत करें:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

इसके बाद उन control planes और supply-chain surfaces की समीक्षा करें जो अक्सर यह तय करते हैं कि attacker को kernel escape की आवश्यकता भी होगी या नहीं:

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

इसके बाद protection model पर जाएं:

{{#ref}}
protections/
{{#endref}}

Namespace pages kernel isolation primitives को अलग-अलग समझाते हैं:

{{#ref}}
protections/namespaces/
{{#endref}}

cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths और read-only system paths पर pages उन mechanisms को समझाते हैं जिन्हें सामान्यतः namespaces के ऊपर layered किया जाता है:

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

Containerized target का assessment करते समय famous escape PoCs पर तुरंत जाने की तुलना में precise technical questions का एक छोटा set पूछना कहीं अधिक उपयोगी है। सबसे पहले **stack** identify करें: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer या कुछ अधिक specialized। फिर **runtime** identify करें: `runc`, `crun`, `runsc`, `kata-runtime` या कोई अन्य OCI-compatible implementation। इसके बाद check करें कि environment **rootful या rootless** है, **user namespaces** active हैं या नहीं, कोई **host namespaces** shared हैं या नहीं, कौन-सी **capabilities** बची हैं, **seccomp** enabled है या नहीं, कोई **MAC policy** वास्तव में enforcing है या नहीं, **dangerous mounts या sockets** मौजूद हैं या नहीं और क्या process container runtime API के साथ interact कर सकता है।

ये answers आपको base image name की तुलना में वास्तविक security posture के बारे में कहीं अधिक बताते हैं। कई assessments में, final container configuration को समझकर आप किसी application file को पढ़ने से पहले ही संभावित breakout family का अनुमान लगा सकते हैं।

## Coverage

यह section container-oriented organization के अंतर्गत पुराने Docker-focused material को cover करता है: runtime और daemon exposure, authorization plugins, image trust और build secrets, sensitive host mounts, distroless workloads, privileged containers और वे kernel protections जो सामान्यतः container execution के आसपास layered की जाती हैं।
{{#include ../../../banners/hacktricks-training.md}}
