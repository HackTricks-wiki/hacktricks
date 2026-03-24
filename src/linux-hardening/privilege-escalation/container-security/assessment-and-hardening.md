# Valutazione e hardening

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Una buona valutazione di container dovrebbe rispondere a due domande parallele. Primo, cosa può fare un attacker dal workload corrente? Secondo, quali scelte dell'operatore hanno reso possibile questo? Gli strumenti di enumerazione aiutano con la prima domanda, e le linee guida di hardening aiutano con la seconda. Tenere entrambe su una sola pagina rende la sezione più utile come riferimento sul campo piuttosto che un semplice catalogo di escape tricks.

## Strumenti di enumerazione

Un numero di strumenti rimane utile per caratterizzare rapidamente un ambiente container:

- `linpeas` può identificare molti indicatori di container, socket montati, set di capability, filesystem pericolosi e indizi di breakout.
- `CDK` si concentra specificamente sugli ambienti container e include enumerazione oltre ad alcune verifiche automatiche di escape.
- `amicontained` è leggero e utile per identificare restrizioni del container, capability, esposizione dei namespace e probabili classi di breakout.
- `deepce` è un altro enumerator focalizzato sui container con check orientati al breakout.
- `grype` è utile quando la valutazione include la revisione delle vulnerabilità dei package dell'immagine invece che solo l'analisi di escape a runtime.

Il valore di questi strumenti è la velocità e la copertura, non la certezza. Aiutano a rivelare rapidamente la postura approssimativa, ma i risultati interessanti necessitano ancora di interpretazione manuale rispetto al modello reale di runtime, namespace, capability e mount.

## Priorità di hardening

I principi di hardening più importanti sono concettualmente semplici anche se la loro implementazione varia per piattaforma. Evitare container privilegiati. Evitare socket runtime montati. Non fornire ai container percorsi host scrivibili a meno che non ci sia una ragione molto specifica. Usare user namespaces o rootless execution dove possibile. Rimuovere tutte le capability e riaggiungere solo quelle di cui il workload ha veramente bisogno. Tenere seccomp, AppArmor e SELinux abilitati piuttosto che disabilitarli per risolvere problemi di compatibilità applicativa. Limitare le risorse in modo che un container compromesso non possa facilmente negare il servizio all'host.

L'igiene di image e build conta tanto quanto la postura a runtime. Usare immagini minimali, ricostruirle frequentemente, scansionarle, richiedere provenienza dove praticabile, e mantenere i secrets fuori dai layer. Un container che gira come non-root con un'immagine piccola e una superficie di syscall e capability ristretta è molto più facile da difendere rispetto a una grande immagine di convenienza che gira come root equivalente all'host con strumenti di debug preinstallati.

## Esempi di esaurimento delle risorse

I controlli delle risorse non sono glamour, ma fanno parte della sicurezza dei container perché limitano il blast radius di un compromesso. Senza limiti di memoria, CPU o PID, una semplice shell può essere sufficiente per degradare l'host o i workload vicini.

Esempi di test che impattano l'host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Questi esempi sono utili perché mostrano che non tutti gli esiti pericolosi di un container corrispondono a una netta "escape". Limiti deboli dei cgroup possono comunque trasformare l'esecuzione di codice in un reale impatto operativo.

## Strumenti di hardening

Per ambienti centrati su Docker, `docker-bench-security` rimane una utile baseline di audit lato host perché controlla problemi di configurazione comuni rispetto a linee guida di benchmark ampiamente riconosciute:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Lo strumento non è un sostituto del threat modeling, ma è comunque prezioso per trovare daemon, mount, network e runtime defaults trascurati che si accumulano nel tempo.

## Controlli

Usali come comandi rapidi per una prima valutazione:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Cosa c'è di interessante qui:

- Un processo root con broad capabilities e `Seccomp: 0` merita attenzione immediata.
- Mounts sospetti e runtime sockets spesso forniscono un percorso più rapido all'impatto rispetto a qualsiasi kernel exploit.
- La combinazione di weak runtime posture e weak resource limits di solito indica un ambiente container generalmente permissive piuttosto che un singolo errore isolato.
{{#include ../../../banners/hacktricks-training.md}}
