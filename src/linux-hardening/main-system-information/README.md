# Informazioni principali sul sistema

{{#include ../../banners/hacktricks-training.md}}

Esamina il kernel dell'host, il filesystem, gli helper privilegiati e le possibili vie di escape prima di scegliere una tecnica di escalation locale. La [checklist per l'escalation dei privilegi](linux-privilege-escalation-checklist.md) fornisce un ordine operativo conciso.

- [Valutazione delle vulnerabilità del kernel ed esposizione in fase di esecuzione](kernel-vulnerability-assessment.md) verifica l'applicabilità alla build, la raggiungibilità e le mitigazioni attive.
- [Moduli del kernel e abuso di modprobe](kernel-modules-and-modprobe.md) tratta il caricamento dei moduli e l'esposizione dei percorsi degli helper.
- [Abuso dei comandi sudo](sudo-command-abuse.md) esamina i modi in cui i comandi delegati possono oltrepassare i confini dei privilegi.
- [Symlink, hardlink e file descriptor](filesystem-links-and-file-descriptors.md) tratta il reindirizzamento dei percorsi e i file ereditati o aperti ma eliminati.
- [Filesystem, inode e recupero](filesystem-inodes-and-recovery.md) spiega il comportamento del filesystem utile durante le indagini.
- [Checklist: escalation dei privilegi su Linux](linux-privilege-escalation-checklist.md) elenca i controlli dell'host e rimanda ad approfondimenti.
- [Escape dalle jail](escaping-from-limited-bash.md) tratta le shell limitate e gli ambienti vincolati.
- [Materiale su Kernel/LPE/CVE](kernel-lpe-cves/README.md) raccoglie guide specifiche sull'escalation locale dei privilegi e sulle vulnerabilità.
{{#include ../../banners/hacktricks-training.md}}
