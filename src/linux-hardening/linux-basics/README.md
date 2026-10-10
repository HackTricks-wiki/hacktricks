# Linux की मूल बातें

{{#include ../../banners/hacktricks-training.md}}

यह Linux host assessment का शुरुआती बिंदु है। इन पेजों में privilege escalation की व्यापक कार्यप्रणाली, व्यावहारिक commands, environment variables और उन सामान्य प्रतिबंधों को शामिल किया गया है जो यह प्रभावित करते हैं कि host पर क्या चलाया जा सकता है।

- [Linux privilege escalation](linux-privilege-escalation/README.md) में enumeration और संभावित local escalation paths के बारे में बताया गया है। कामों की छोटी सूची के लिए [privilege escalation checklist](../main-system-information/linux-privilege-escalation-checklist.md) का उपयोग करें।
- [Shell startup, aliases, and history](shell-startup-aliases-and-history.md) में command resolution, startup-file execution और history से मिलने वाले संकेतों के बारे में बताया गया है।
- [Useful Linux commands](useful-linux-commands.md) में files, processes, services और environment की जाँच के लिए commands संकलित हैं।
- [Linux environment variables](linux-environment-variables.md) में बताया गया है कि environment values execution को कैसे प्रभावित करती हैं और संवेदनशील values कहाँ दिखाई दे सकती हैं।
- [Bypass Linux restrictions](bypass-linux-restrictions/README.md) में constrained shells और execution environments शामिल हैं, जिनमें filesystem protections, `noexec` और distroless systems शामिल हैं।

## Native binary exploitation

यदि assessment के दौरान कोई vulnerable Linux executable मिलता है, तो Binary Exploitation की संबंधित सामग्री देखें:

- [ELF format and loader behavior](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) और [binary protections and bypasses](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) में executable layout और mitigations के बारे में बताया गया है।
- [Stack exploitation](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) और [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) में control-flow attacks शामिल हैं।
- [Libc heap exploitation](../../binary-exploitation/libc-heap/README.md) और [format strings](../../binary-exploitation/format-strings/README.md) में memory corruption के अन्य सामान्य paths शामिल हैं।

Kernel-विशिष्ट case studies के लिंक [Kernel/LPE/CVE material](../main-system-information/kernel-lpe-cves/README.md) में दिए गए हैं।
{{#include ../../banners/hacktricks-training.md}}
