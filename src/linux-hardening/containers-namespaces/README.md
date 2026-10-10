# Containers और Namespaces

{{#include ../../banners/hacktricks-training.md}}

Container एक Linux process है, जो isolation और privilege configuration के साथ चलता है। Runtime, mounted host resources, granted capabilities और namespace settings का एक साथ आकलन करें। [container security overview](container-security/README.md) इन layers को समझाता है और हर control से लिंक करता है।

- [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md) containerd के management interface तक access पर केंद्रित है।
- [RunC privilege escalation](runc-privilege-escalation.md) runtime-विशिष्ट escalation सामग्री को कवर करता है।
- [Container security](container-security/README.md) runtimes, exposed APIs, image risks, sensitive mounts, privileged containers, assessment और namespaces, seccomp तथा mandatory access control जैसे protections को समझाता है।
{{#include ../../banners/hacktricks-training.md}}
