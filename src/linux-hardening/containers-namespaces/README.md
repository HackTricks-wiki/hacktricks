# कंटेनर और Namespaces

{{#include ../../banners/hacktricks-training.md}}

कंटेनर एक Linux process है, जो isolation और privilege configuration के साथ चलता है। Runtime, mounted host resources, दी गई capabilities और namespace settings का एक साथ आकलन करें। [container security overview](container-security/README.md) इन layers को समझाता है और हर control के लिंक देता है।

- [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md) में containerd के management interface तक पहुँच पर ध्यान दिया गया है।
- [RunC privilege escalation](runc-privilege-escalation.md) में runtime-विशिष्ट escalation सामग्री शामिल है।
- [Container security](container-security/README.md) में runtimes, exposed APIs, image risks, sensitive mounts, privileged containers, assessment और namespaces, seccomp तथा mandatory access control जैसे protections समझाए गए हैं।
{{#include ../../banners/hacktricks-training.md}}
