# Linux की मूल बातें

{{#include ../../banners/hacktricks-training.md}}

यह Linux host assessment के लिए शुरुआती बिंदु है। इन पेजों में privilege escalation की व्यापक प्रक्रिया, व्यावहारिक commands, environment variables और host पर क्या चलाया जा सकता है, इसे प्रभावित करने वाली सामान्य पाबंदियाँ शामिल हैं।

- [Linux privilege escalation](linux-privilege-escalation/README.md) में enumeration और संभावित local escalation paths की जानकारी दी गई है। छोटी task list के लिए [privilege escalation checklist](../main-system-information/linux-privilege-escalation-checklist.md) देखें।
- [Shell startup, aliases, and history](shell-startup-aliases-and-history.md) में command resolution, startup files का execution और history से मिलने वाले संकेत समझाए गए हैं।
- [Useful Linux commands](useful-linux-commands.md) में files, processes, services और environment की जाँच करने वाले commands दिए गए हैं।
- [Linux environment variables](linux-environment-variables.md) में बताया गया है कि environment values execution को कैसे प्रभावित करती हैं और sensitive values कहाँ दिखाई दे सकती हैं।
- [Bypass Linux restrictions](bypass-linux-restrictions/README.md) में constrained shells और execution environments शामिल हैं, जैसे filesystem protections, `noexec` और distroless systems।

## Native binary exploitation

यदि assessment के दौरान कोई vulnerable Linux executable मिले, तो Binary Exploitation की संबंधित सामग्री देखें:

- [ELF format and loader behavior](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) और [binary protections and bypasses](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) में executable का layout और mitigations समझाए गए हैं।
- [Stack exploitation](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) और [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) में control-flow attacks शामिल हैं।
- [Libc heap exploitation](../../binary-exploitation/libc-heap/README.md) और [format strings](../../binary-exploitation/format-strings/README.md) में memory corruption के अन्य सामान्य रास्ते शामिल हैं।

Kernel से जुड़े case studies के लिए [Kernel/LPE/CVE material](../main-system-information/kernel-lpe-cves/README.md) देखें।
{{#include ../../banners/hacktricks-training.md}}
