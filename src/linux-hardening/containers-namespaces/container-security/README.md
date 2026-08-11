# Container Security

## Container वास्तव में क्या है

Container को परिभाषित करने का एक व्यावहारिक तरीका यह है: container एक **regular Linux process tree** है, जिसे एक विशिष्ट OCI-style configuration के अंतर्गत शुरू किया गया है ताकि उसे एक नियंत्रित filesystem, kernel resources का नियंत्रित सेट और restricted privilege model दिखाई दे। Process यह मान सकता है कि वह PID 1 है, उसका अपना network stack है, उसका अपना hostname और IPC resources हैं, और वह अपने user namespace के अंदर root के रूप में भी चल सकता है। लेकिन अंदर से वह अब भी एक host process है, जिसे kernel किसी भी अन्य process की तरह schedule करता है।

इसीलिए container security का वास्तविक अध्ययन इस बात पर केंद्रित है कि यह illusion कैसे बनाया जाता है और यह कैसे विफल होता है। यदि mount namespace कमजोर है, तो process host filesystem देख सकता है। यदि user namespace अनुपस्थित या disabled है, तो container के अंदर का root, host के root से बहुत closely map हो सकता है। यदि seccomp unconfined है और capability set बहुत broad है, तो process उन syscalls और privileged kernel features तक पहुंच सकता है जिन्हें पहुंच से बाहर रहना चाहिए था। यदि runtime socket container के अंदर mount किया गया है, तो container को kernel breakout की आवश्यकता भी नहीं हो सकती, क्योंकि वह runtime से अधिक शक्तिशाली sibling container launch करने या host root filesystem को सीधे mount करने के लिए कह सकता है।

## Containers Virtual Machines से कैसे अलग हैं

VM में सामान्यतः अपना kernel और hardware abstraction boundary होती है। इसका अर्थ है कि guest kernel crash, panic या exploit हो सकता है, बिना इस बात के कि host kernel पर direct control अपने-आप मिल जाए। Containers में workload को अलग kernel नहीं मिलता। इसके बजाय, उसे उसी kernel का carefully filtered और namespaced view मिलता है जिसका उपयोग host करता है। परिणामस्वरूप, containers सामान्यतः हल्के होते हैं, तेजी से शुरू होते हैं, किसी machine पर अधिक घनत्व के साथ चलाए जा सकते हैं और short-lived application deployment के लिए अधिक उपयुक्त होते हैं। इसकी कीमत यह है कि isolation boundary सही host और runtime configuration पर कहीं अधिक सीधे निर्भर करती है।

इसका अर्थ यह नहीं है कि containers "insecure" और VMs "secure" हैं। इसका अर्थ है कि security model अलग है। rootless execution, user namespaces, default seccomp, strict capability set, host namespace sharing न होने और मजबूत SELinux या AppArmor enforcement वाला अच्छी तरह configured container stack बहुत robust हो सकता है। इसके विपरीत, `--privileged`, host PID/network sharing, अंदर mounted Docker socket और `/` का writable bind mount के साथ शुरू किया गया container, safely isolated application sandbox की तुलना में host root access के कहीं अधिक करीब होता है। अंतर उन layers से आता है जिन्हें enabled या disabled किया गया है।

एक middle ground भी है जिसे readers को समझना चाहिए, क्योंकि यह real environments में अधिकाधिक दिखाई दे रहा है। **Sandboxed container runtimes** जैसे **gVisor** और **Kata Containers**, classic `runc` container की तुलना में boundary को जानबूझकर अधिक harden करते हैं। gVisor workload और कई host kernel interfaces के बीच userspace kernel layer रखता है, जबकि Kata workload को lightweight virtual machine के अंदर launch करता है। इनका उपयोग अभी भी container ecosystems और orchestration workflows के माध्यम से किया जाता है, लेकिन इनके security properties plain OCI runtimes से अलग होते हैं और इन्हें मानसिक रूप से "normal Docker containers" के साथ इस तरह group नहीं करना चाहिए जैसे सभी एक ही तरह behave करते हों।

## Container Stack: एक नहीं, कई Layers

जब कोई कहता है कि "this container is insecure", तो उपयोगी follow-up question है: **किस layer ने इसे insecure बनाया?** Containerized workload सामान्यतः कई components के साथ मिलकर तैयार होता है।

सबसे ऊपर अक्सर BuildKit, Buildah या Kaniko जैसी **image build layer** होती है, जो OCI image और metadata बनाती है। Low-level runtime के ऊपर Docker Engine, Podman, containerd, CRI-O, Incus या systemd-nspawn जैसा **engine or manager** हो सकता है। Cluster environments में Kubernetes जैसा **orchestrator** भी हो सकता है, जो workload configuration के माध्यम से requested security posture तय करता है। अंततः **kernel** ही namespaces, cgroups, seccomp और MAC policy को वास्तव में enforce करता है।

Defaults को समझने के लिए यह layered model महत्वपूर्ण है। Kubernetes किसी restriction का अनुरोध कर सकता है, जिसे containerd या CRI-O द्वारा CRI के माध्यम से translate किया जाता है, runtime wrapper द्वारा OCI spec में convert किया जाता है और इसके बाद ही `runc`, `crun`, `runsc` या कोई अन्य runtime उसे kernel के विरुद्ध enforce करता है। जब environments के बीच defaults अलग होते हैं, तो अक्सर इसका कारण यह होता है कि इन layers में से किसी एक ने final configuration बदल दी। इसलिए वही mechanism Docker या Podman में CLI flag के रूप में, Kubernetes में Pod या `securityContext` field के रूप में और lower-level runtime stacks में workload के लिए generated OCI configuration के रूप में दिखाई दे सकता है। इसी कारण इस section में दिए गए CLI examples को **general container concept के लिए runtime-specific syntax** के रूप में पढ़ना चाहिए, न कि हर tool द्वारा supported universal flags के रूप में।

## वास्तविक Container Security Boundary

व्यवहार में, container security **overlapping controls** से आती है, किसी एक perfect control से नहीं। Namespaces visibility को isolate करते हैं। cgroups resource usage को govern और limit करते हैं। Capabilities यह कम करती हैं कि privileged दिखने वाला process वास्तव में क्या कर सकता है। seccomp dangerous syscalls को kernel तक पहुंचने से पहले block करता है। AppArmor और SELinux सामान्य DAC checks के ऊपर Mandatory Access Control जोड़ते हैं। `no_new_privs`, masked procfs paths और read-only system paths सामान्य privilege और proc/sys abuse chains को कठिन बनाते हैं। Runtime भी महत्वपूर्ण है, क्योंकि वही तय करता है कि mounts, sockets, labels और namespace joins कैसे बनाए जाएंगे।

इसीलिए बहुत-सा container security documentation repetitive लगता है। वही escape chain अक्सर एक साथ कई mechanisms पर निर्भर करती है। उदाहरण के लिए, writable host bind mount खराब है, लेकिन यदि container host पर real root के रूप में भी चलता है, उसके पास `CAP_SYS_ADMIN` है, seccomp से unconfined है और SELinux या AppArmor द्वारा restricted नहीं है, तो यह कहीं अधिक खतरनाक हो जाता है। इसी प्रकार, host PID sharing एक serious exposure है, लेकिन `CAP_SYS_PTRACE`, कमजोर procfs protections या `nsenter` जैसे namespace-entry tools के साथ मिलकर यह attacker के लिए बहुत अधिक उपयोगी हो जाता है। इसलिए इस topic को document करने का सही तरीका हर page पर उसी attack को दोहराना नहीं, बल्कि यह समझाना है कि final boundary में प्रत्येक layer का क्या योगदान है।

## इस Section को कैसे पढ़ें

यह section सबसे general concepts से सबसे specific concepts की ओर व्यवस्थित किया गया है।

Runtime और ecosystem overview से शुरू करें:

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

इसके बाद protection model की ओर बढ़ें:

{{#ref}}
protections/
{{#endref}}

Namespace pages kernel isolation primitives को अलग-अलग समझाते हैं:

{{#ref}}
protections/namespaces/
{{#endref}}

cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths और read-only system paths पर pages उन mechanisms को समझाते हैं जिन्हें सामान्यतः namespaces के ऊपर layer किया जाता है:

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

## एक अच्छा पहला Enumeration Mindset

Containerized target का assessment करते समय famous escape PoCs पर तुरंत जाने के बजाय कुछ precise technical questions पूछना अधिक उपयोगी होता है। सबसे पहले **stack** की पहचान करें: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer या कुछ अधिक specialized। फिर **runtime** की पहचान करें: `runc`, `crun`, `runsc`, `kata-runtime` या कोई अन्य OCI-compatible implementation। इसके बाद जांचें कि environment **rootful या rootless** है, **user namespaces** active हैं या नहीं, कोई **host namespaces** shared हैं या नहीं, कौन-सी **capabilities** बची हुई हैं, **seccomp** enabled है या नहीं, **MAC policy** वास्तव में enforcing है या नहीं, कोई **dangerous mounts या sockets** मौजूद हैं या नहीं, और क्या process container runtime API के साथ interact कर सकता है।

ये उत्तर आपको base image name की तुलना में वास्तविक security posture के बारे में कहीं अधिक बताते हैं। कई assessments में, केवल final container configuration समझकर ही आप किसी application file को पढ़ने से पहले संभावित breakout family का अनुमान लगा सकते हैं।

## Coverage

यह section container-oriented organization के अंतर्गत पुराने Docker-focused material को cover करता है: runtime और daemon exposure, authorization plugins, image trust और build secrets, sensitive host mounts, distroless workloads, privileged containers और container execution के आसपास सामान्यतः layered kernel protections।

{{#include ../../../banners/hacktricks-training.md}}
