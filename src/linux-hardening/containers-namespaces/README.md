# Container e namespace

{{#include ../../banners/hacktricks-training.md}}

Un container è un processo Linux eseguito con una configurazione di isolamento e privilegi. Valuta insieme il runtime, le risorse dell’host montate, le capability concesse e le impostazioni dei namespace. La [panoramica sulla sicurezza dei container](container-security/README.md) spiega questi livelli e rimanda ai relativi controlli.

- [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md) si concentra sull’accesso all’interfaccia di gestione di containerd.
- [RunC privilege escalation](runc-privilege-escalation.md) tratta i contenuti sull’escalation specifici del runtime.
- [Sicurezza dei container](container-security/README.md) spiega i runtime, le API esposte, i rischi delle immagini, i mount sensibili, i container privilegiati, la valutazione e le protezioni come i namespace, seccomp e il mandatory access control.

{{#include ../../banners/hacktricks-training.md}}
