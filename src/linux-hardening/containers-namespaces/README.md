# Container e namespace

{{#include ../../banners/hacktricks-training.md}}

Un container è un processo Linux eseguito con una configurazione di isolamento e privilegi. Valuta insieme il runtime, le risorse dell’host montate, le capability concesse e le impostazioni dei namespace. La [panoramica sulla sicurezza dei container](container-security/README.md) illustra questi livelli e rimanda ai relativi controlli.

- [Privilege escalation di Containerd (`ctr`)](containerd-ctr-privilege-escalation.md) si concentra sull’accesso all’interfaccia di gestione di containerd.
- [Privilege escalation di RunC](runc-privilege-escalation.md) tratta i contenuti sulla privilege escalation specifici del runtime.
- [Sicurezza dei container](container-security/README.md) illustra i runtime, le API esposte, i rischi delle immagini, i mount sensibili, i container privilegiati, le attività di assessment e le protezioni come namespace, seccomp e mandatory access control.
{{#include ../../banners/hacktricks-training.md}}
