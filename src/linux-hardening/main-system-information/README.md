# मुख्य सिस्टम जानकारी

{{#include ../../banners/hacktricks-training.md}}

स्थानीय privilege escalation तकनीक चुनने से पहले host के kernel, filesystem, privileged helpers और उपलब्ध escape routes की जाँच करें। [privilege escalation checklist](linux-privilege-escalation-checklist.md) में काम करने का संक्षिप्त क्रम दिया गया है।

- [Kernel vulnerability assessment और runtime exposure](kernel-vulnerability-assessment.md) में build applicability, reachability और सक्रिय mitigations की जाँच की जाती है।
- [Kernel modules और modprobe का दुरुपयोग](kernel-modules-and-modprobe.md) में module loading और helper-path exposure शामिल हैं।
- [Sudo command का दुरुपयोग](sudo-command-abuse.md) में उन तरीकों की जाँच की जाती है जिनसे delegated commands privilege boundaries पार कर सकती हैं।
- [Symlinks, hardlinks और file descriptors](filesystem-links-and-file-descriptors.md) में path redirection और inherited या deleted-open files शामिल हैं।
- [Filesystem, inodes और recovery](filesystem-inodes-and-recovery.md) में जाँच-पड़ताल के दौरान उपयोगी filesystem behavior समझाया गया है।
- [Checklist: Linux privilege escalation](linux-privilege-escalation-checklist.md) में host की जाँचें दी गई हैं और अधिक विस्तृत सामग्री के links हैं।
- [Jails से बाहर निकलना](escaping-from-limited-bash.md) में limited shells और constrained environments शामिल हैं।
- [Kernel/LPE/CVE सामग्री](kernel-lpe-cves/README.md) में स्थानीय privilege escalation और vulnerability पर केंद्रित write-ups दिए गए हैं।
{{#include ../../banners/hacktricks-training.md}}
