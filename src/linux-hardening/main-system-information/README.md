# Informazioni principali del sistema

{{#include ../../banners/hacktricks-training.md}}

Esamina il kernel dell'host, il filesystem, gli helper con privilegi e le vie di escape disponibili prima di scegliere una tecnica di escalation locale. La [checklist per l'escalation dei privilegi](linux-privilege-escalation-checklist.md) fornisce una sequenza operativa sintetica.

- [Valutazione delle vulnerabilità del kernel e dell'esposizione a runtime](kernel-vulnerability-assessment.md) verifica l'applicabilità alla build, la raggiungibilità e le mitigazioni attive.
- [Moduli del kernel e abuso di modprobe](kernel-modules-and-modprobe.md) tratta il caricamento dei moduli e l'esposizione dei percorsi degli helper.
- [Abuso dei comandi sudo](sudo-command-abuse.md) esamina come i comandi delegati possano oltrepassare i confini dei privilegi.
- [Symlink, hardlink e file descriptor](filesystem-links-and-file-descriptors.md) tratta il reindirizzamento dei percorsi e i file ereditati o aperti ma eliminati.
- [Filesystem, inode e recupero](filesystem-inodes-and-recovery.md) spiega il comportamento del filesystem utile durante le indagini.
- [Checklist: escalation dei privilegi su Linux](linux-privilege-escalation-checklist.md) elenca i controlli sull'host e rimanda ad approfondimenti.
- [Uscire dalle jail](escaping-from-limited-bash.md) tratta le shell limitate e gli ambienti vincolati.
- [Materiale su kernel/LPE/CVE](kernel-lpe-cves/README.md) raccoglie approfondimenti specifici sull'escalation locale dei privilegi e sulle vulnerabilità.
{{#include ../../banners/hacktricks-training.md}}
