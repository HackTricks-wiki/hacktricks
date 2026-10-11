# दिलचस्प फ़ाइलें और अनुमतियाँ

{{#include ../../banners/hacktricks-training.md}}

फ़ाइल का स्वामित्व, लिखने की पहुँच, mount विकल्प और executable privileges किसी local user की प्रभावी पहुँच बदल सकते हैं। पहले target file या execution path की पहचान करें, फिर संबंधित पेज देखें:

- [SUID, SGID, ACLs और संवेदनशील फ़ाइलें](suid-sgid-and-acl-triage.md) executable privileges और छिपे हुए access grants के लिए शुरुआती workflow देता है।
- [Root तक arbitrary file write](write-to-root.md) बताता है कि privileged paths पर writes को privilege escalation में कैसे बदला जा सकता है।
- [Linux capabilities](linux-capabilities.md) per-process और per-file capabilities समझाता है।
- [SUID shared library और linker का दुरुपयोग](suid-shared-library-and-linker-abuse.md) privileged binaries के आसपास dynamic loading को कवर करता है।
- [`ld.so` privilege escalation का उदाहरण](ld.so.conf-example.md) linker configuration से जुड़ा एक मामला बताता है।
- [NFS `no_root_squash` और `no_all_squash` misconfiguration](nfs-no_root_squash-misconfiguration-pe.md) remote filesystem की identity mapping को कवर करता है।
- [Wildcard spare tricks](wildcards-spare-tricks.md) privileged commands में argument expansion को कवर करता है।
- [SELinux](selinux.md) policy enforcement और उससे जुड़े investigation steps समझाता है।
{{#include ../../banners/hacktricks-training.md}}
