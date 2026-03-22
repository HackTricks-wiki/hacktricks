# कंटेनर सुरक्षा

{{#include ../../../banners/hacktricks-training.md}}

## कंटेनर असल में क्या है

एक व्यावहारिक परिभाषा यह है: एक कंटेनर एक **सामान्य Linux प्रोसेस ट्री** है जिसे एक विशिष्ट OCI-स्टाइल कॉन्फ़िगरेशन के तहत शुरू किया गया है ताकि वह एक नियंत्रित फ़ाइल सिस्टम, कर्नेल संसाधनों का नियंत्रित सेट, और एक प्रतिबंधित प्रिविलेज मॉडल देखे। प्रोसेस यह मान सकता है कि यह PID 1 है, इसका अपना नेटवर्क स्टैक है, इसका अपना hostname और IPC रिसोर्सेज हैं, और यह अपनी user namespace में root के रूप में भी चल सकता है। लेकिन अंदर से यह फिर भी एक होस्ट प्रोसेस ही है जिसे कर्नेल किसी अन्य की तरह शेड्यूल करता है।

इसीलिए कंटेनर सुरक्षा वास्तव में इस बात का अध्ययन है कि वह भ्रम कैसे बनता है और कहां फेल होता है। अगर mount namespace कमजोर है तो प्रोसेस होस्ट फ़ाइल सिस्टम देख सकता है। अगर user namespace अनुपस्थित या disabled है, तो कंटेनर के अंदर का root होस्ट पर root के बहुत करीब मैप हो सकता है। अगर seccomp अनकन्फ़ाइन्ड है और capability सेट बहुत व्यापक है, तो प्रोसेस उन syscalls और privileged kernel फ़ीचर्स तक पहुँच सकता है जो पहुँच से बाहर रहने चाहिए थे। अगर runtime socket कंटेनर के अंदर माउंट है, तो कंटेनर को kernel breakout की आवश्यकता तक नहीं होगी क्योंकि वह runtime से बस एक अधिक शक्तिशाली sibling container लॉन्च करने या सीधे होस्ट root filesystem माउंट करने के लिए कह सकता है।

## कंटेनर और वर्चुअल मशीन में क्या अंतर है

एक VM आमतौर पर अपना खुद का kernel और हार्डवेयर एब्स्ट्रैक्शन बॉउंड्री लेकर चलता है। इसका मतलब यह है कि guest kernel क्रैश, panic, या exploited हो सकता है बिना स्वतः होस्ट kernel का प्रत्यक्ष नियंत्रण लागू हुए। कंटेनरों में, वर्कलोड को अलग kernel नहीं मिलता। इसके बजाय, उसे उसी kernel का एक सावधानीपूर्वक फ़िल्टर किया गया और namespaced दृश्य मिलता है जिसे होस्ट उपयोग करता है। नतीजतन, कंटेनर आमतौर पर हल्के, तेज़ी से शुरू होने वाले, एक मशीन पर घनीपैक करने में आसान, और short-lived application deployment के लिए बेहतर होते हैं। कीमत यह है कि isolation boundary सही होस्ट और runtime कॉन्फ़िगरेशन पर बहुत अधिक निर्भर करती है।

यह नहीं कहता कि कंटेनर "असुरक्षित" हैं और VMs "सुरक्षित" हैं। इसका अर्थ है कि सुरक्षा मॉडल अलग है। एक अच्छी तरह कॉन्फ़िगर किया गया container stack — rootless execution, user namespaces, default seccomp, एक सख्त capability सेट, कोई host namespace sharing न होना, और मजबूत SELinux या AppArmor enforcement — बहुत मजबूत हो सकता है। इसके विपरीत, एक कंटेनर जिसे `--privileged` के साथ शुरू किया गया हो, host PID/network साझा कर रहा हो, Docker socket उसके अंदर माउंट हो, और `/` का writable bind mount हो — वह व्यवहार में host root access के बहुत करीब होता है बजाय सुरक्षित रूप से अलग किए गए application sandbox के। फर्क उन लेयर्स से आता है जिन्हें सक्षम या निष्क्रिय किया गया था।

एक मध्यवर्ती विकल्प भी है जिसे पाठकों को समझना चाहिए क्योंकि यह वास्तविक पर्यावरणों में अधिक और अधिक दिखाई देता है। **Sandboxed container runtimes** जैसे **gVisor** और **Kata Containers** जानबूझकर बॉउंड्री को क्लासिक `runc` कंटेनर से अधिक मजबूत करते हैं। gVisor वर्कलोड और कई होस्ट कर्नेल इंटरफेस के बीच एक userspace kernel लेयर रखता है, जबकि Kata वर्कलोड को एक lightweight virtual machine के अंदर लॉन्च करता है। इन्हें अभी भी container ecosystems और orchestration workflows के माध्यम से उपयोग किया जाता है, लेकिन उनकी security properties plain OCI runtimes से अलग हैं और इन्हें "normal Docker containers" के साथ एक ही तरह से मानसिक रूप से समूहबद्ध नहीं करना चाहिए जैसे सब कुछ समान व्यवहार कर रहा हो।

## कंटेनर स्टैक: एक नहीं, कई लेयर्स

जब कोई कहता है "यह कंटेनर असुरक्षित है", तो उपयोगी अगला सवाल होता है: **कौन सा लेयर इसे असुरक्षित बनाता है?** एक कंटेनराइज़्ड वर्कलोड आमतौर पर कई घटकों के मिलकर काम करने का परिणाम होता है।

ऊपर, अक्सर एक **image build layer** होती है जैसे BuildKit, Buildah, या Kaniko, जो OCI image और metadata बनाती है। low-level runtime के ऊपर, एक **engine या manager** हो सकता है जैसे Docker Engine, Podman, containerd, CRI-O, Incus, या systemd-nspawn। क्लस्टर वातावरण में, एक **orchestrator** जैसे Kubernetes भी हो सकता है जो वर्कलोड कॉन्फ़िगरेशन के माध्यम से अनुरोधित सुरक्षा स्थिति तय करता है। अंत में, वह **kernel** है जो वास्तव में namespaces, cgroups, seccomp, और MAC policy को लागू करता है।

यह लेयर्ड मॉडल defaults को समझने के लिए महत्वपूर्ण है। एक प्रतिबंध Kubernetes द्वारा अनुरोध किया जा सकता है, containerd या CRI-O द्वारा CRI के माध्यम से अनुवादित किया जा सकता है, runtime wrapper द्वारा OCI spec में परिवर्तित किया जा सकता है, और तभी `runc`, `crun`, `runsc`, या किसी अन्य runtime द्वारा kernel के खिलाफ लागू किया जा सकता है। जब defaults वातावरणों के बीच भिन्न होते हैं, तो अक्सर इसका कारण यह होता है कि इन लेयर्स में से किसी ने अंतिम कॉन्फ़िगरेशन बदला है। इसलिए यही मैकैनिज़्म Docker या Podman में CLI फ्लैग के रूप में, Kubernetes में Pod या `securityContext` फ़ील्ड के रूप में, और lower-level runtime stacks में वर्कलोड के लिए जनरेट की गई OCI कॉन्फ़िगरेशन के रूप में दिखाई दे सकता है। इस कारण से, इस सेक्शन में CLI उदाहरणों को एक सामान्य container अवधारणा के लिए **runtime-specific syntax** के रूप में पढ़ना चाहिए, न कि प्रत्येक टूल द्वारा समर्थित सार्वभौमिक फ्लैग के रूप में।

## असली कंटेनर सुरक्षा बॉउंड्री

व्यवहार में, कंटेनर सुरक्षा **ओवरलैपिंग कंट्रोल्स** से आती है, न कि एक अकेले परफेक्ट कंट्रोल से। Namespaces दृश्यता अलग करते हैं। cgroups संसाधन उपयोग को नियंत्रित और सीमित करते हैं। Capabilities उस चीज़ को घटाती हैं जो एक privileged-सा दिखने वाला प्रोसेस वास्तव में कर सकता है। seccomp खतरनाक syscalls को कर्नेल तक पहुँचने से पहले ब्लॉक करता है। AppArmor और SELinux सामान्य DAC चेक्स के ऊपर Mandatory Access Control जोड़ते हैं। `no_new_privs`, masked procfs paths, और read-only system paths सामान्य privilege और proc/sys abuse चेन को कठिन बनाते हैं। Runtime भी मायने रखता है क्योंकि यह तय करता है कि mounts, sockets, labels, और namespace joins कैसे बनाए जाते हैं।

इसीलिए बहुत सा container security दस्तावेज़ दोहराव वाला लगता है। वही escape chain अक्सर एक साथ कई मेकानिज्म पर निर्भर करता है। उदाहरण के लिए, एक writable host bind mount खराब है, लेकिन यह बहुत बुरा बन जाता है अगर कंटेनर होस्ट पर असली root के रूप में चलता है, `CAP_SYS_ADMIN` है, seccomp से अनकन्फ़ाइन्ड है, और SELinux या AppArmor द्वारा सीमित नहीं है। इसी तरह, host PID sharing एक गंभीर जोखिम है, लेकिन यह किसी हमलावर के लिए नाटकीय रूप से अधिक उपयोगी हो जाता है जब यह `CAP_SYS_PTRACE`, कमजोर procfs सुरक्षा, या namespace-entry टूल्स जैसे `nsenter` के साथ जोड़ा जाता है। इसलिए सही तरीका विषय को दस्तावेज़ित करने का यह है कि हर पेज पर वही हमला बार-बार लिखने के बजाय यह समझाया जाए कि प्रत्येक लेयर अंतिम बॉउंड्री में क्या योगदान देती है।

## इस सेक्शन को कैसे पढ़ें

यह सेक्शन सबसे सामान्य अवधारणाओं से सबसे विशिष्ट तक व्यवस्थित है।

runtime और ecosystem का ओवरव्यू पढ़ें:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

फिर उन control planes और supply-chain सतहों की समीक्षा करें जो अक्सर तय करते हैं कि एक हमलावर को kernel escape की भी ज़रूरत है या नहीं:

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

फिर protection मॉडल की ओर बढ़ें:

{{#ref}}
protections/
{{#endref}}

namespace पेज कर्नेल isolation primitives को व्यक्तिगत रूप से समझाते हैं:

{{#ref}}
protections/namespaces/
{{#endref}}

cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths, और read-only system paths के पेज वे मैकेनिज्म समझाते हैं जो आमतौर पर namespaces के ऊपर लेयर्ड होते हैं:

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

## एक अच्छा प्रारंभिक enumeration माइंडसेट

जब एक कंटेनराइज़्ड टार्गेट का आकलन कर रहे हों, तो प्रसिद्ध escape PoCs पर तुरंत कूदने से बेहतर है कि कुछ छोटे लेकिन सटीक तकनीकी सवाल पूछें। पहले, **stack** की पहचान करें: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, या कुछ और विशिष्ट। फिर **runtime** की पहचान करें: `runc`, `crun`, `runsc`, `kata-runtime`, या कोई अन्य OCI-compatible implementation। इसके बाद जाँचें क्या वातावरण **rootful या rootless** है, क्या **user namespaces** सक्रिय हैं, क्या कोई **host namespaces** साझा किए गए हैं, कौन सी **capabilities** बची हैं, क्या **seccomp** सक्षम है, क्या कोई **MAC policy** वास्तव में लागू कर रही है, क्या **dangerous mounts या sockets** मौजूद हैं, और क्या प्रोसेस container runtime API के साथ इंटरैक्ट कर सकता है।

ये उत्तर वास्तविक सुरक्षा स्थिति के बारे में बेस इमेज नाम से कहीं अधिक बताते हैं। कई आकलनों में, आप अंतिम container कॉन्फ़िगरेशन को समझकर एक एप्लीकेबल breakout परिवार का अनुमान लगा सकते हैं उससे पहले कि आपने कोई भी application फ़ाइल पढ़ी हो।

## कवरेज

यह सेक्शन पुराने Docker-केंद्रित सामग्री को container-ओरिएंटेड संगठन के अंतर्गत कवर करता है: runtime और daemon exposure, authorization plugins, image trust और build secrets, sensitive host mounts, distroless workloads, privileged containers, और सामान्यतः कंटेनर निष्पादन के चारों ओर लेयर्ड kernel protections.
{{#include ../../../banners/hacktricks-training.md}}
