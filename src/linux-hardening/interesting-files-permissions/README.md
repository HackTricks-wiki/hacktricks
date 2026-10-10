# रुचिकर फ़ाइलें और अनुमतियाँ

{{#include ../../banners/hacktricks-training.md}}

फ़ाइल का स्वामित्व, write access, mount options और executable privileges किसी local user की प्रभावी पहुँच बदल सकते हैं। पहले target file या execution path की पहचान करें, फिर संबंधित पेज देखें:

- [SUID, SGID, ACLs और संवेदनशील फ़ाइलें](suid-sgid-and-acl-triage.md) executable privileges और छिपे हुए access grants की जाँच के लिए शुरुआती workflow देता है।
- [root तक arbitrary file write](write-to-root.md) बताता है कि privileged paths में write access को privilege escalation में कैसे बदला जा सकता है।
- [Linux capabilities](linux-capabilities.md) per-process और per-file capabilities समझाता है।
- [SUID shared library और linker का दुरुपयोग](suid-shared-library-and-linker-abuse.md) privileged binaries के आसपास dynamic loading को कवर करता है।
- [`ld.so` privilege escalation का उदाहरण](ld.so.conf-example.md) linker configuration के एक मामले को समझाता है।
- [NFS `no_root_squash` और `no_all_squash` की गलत configuration](nfs-no_root_squash-misconfiguration-pe.md) remote filesystem में identity mapping को कवर करती है।
- [Wildcard spare tricks](wildcards-spare-tricks.md) privileged commands में argument expansion को कवर करता है।
- [SELinux](selinux.md) policy enforcement और जाँच के प्रासंगिक चरण समझाता है।
{{#include ../../banners/hacktricks-training.md}}
