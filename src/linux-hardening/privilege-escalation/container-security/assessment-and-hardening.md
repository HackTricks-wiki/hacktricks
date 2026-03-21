# Valutazione e Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Una buona valutazione dei container dovrebbe rispondere a due domande parallele. Primo, cosa può fare un attaccante dal carico di lavoro corrente? Secondo, quali scelte dell'operatore hanno reso ciò possibile? Gli strumenti di enumerazione aiutano con la prima domanda, e le linee guida di hardening aiutano con la seconda. Tenere entrambe su una singola pagina rende la sezione più utile come riferimento operativo anziché solo un catalogo di escape tricks.

## Strumenti di enumerazione

Una serie di strumenti rimane utile per caratterizzare rapidamente un ambiente container:

- `linpeas` può identificare molti indicatori di container, socket montati, set di capability, filesystem pericolosi e indizi di breakout.
- `CDK` si concentra specificamente sugli ambienti container e include enumerazione più alcuni controlli automatizzati per escape.
- `amicontained` è leggero e utile per identificare restrizioni del container, capability, esposizione dei namespace e probabili classi di breakout.
- `deepce` è un altro enumerator focalizzato sui container con controlli orientati al breakout.
- `grype` è utile quando la valutazione include la revisione delle vulnerabilità dei package dell'immagine invece che solo l'analisi a runtime degli escape.

Il valore di questi strumenti è la velocità e la copertura, non la certezza. Aiutano a rivelare rapidamente la postura approssimativa, ma i risultati interessanti richiedono ancora interpretazione manuale rispetto al modello reale di runtime, namespace, capability e mount.

## Priorità di hardening

I principi di hardening più importanti sono concettualmente semplici anche se la loro implementazione varia per piattaforma. Evitare i container privilegiati. Evitare socket di runtime montati. Non assegnare ai container percorsi host scrivibili a meno che non ci sia una ragione molto specifica. Utilizzare user namespaces o esecuzione rootless quando possibile. Rimuovere tutte le capability e riaggiungere solo quelle di cui il workload ha realmente bisogno. Tenere seccomp, AppArmor e SELinux abilitati invece di disabilitarli per risolvere problemi di compatibilità delle applicazioni. Limitare le risorse in modo che un container compromesso non possa facilmente negare il servizio all'host.

L'igiene di immagini e build conta tanto quanto la postura a runtime. Usare immagini minimali, ricostruirle frequentemente, scannerizzarle, richiedere la provenienza quando pratico e mantenere i segreti fuori dai layer. Un container eseguito come non-root con un'immagine piccola e una superficie di syscall e capability ridotta è molto più facile da difendere rispetto a un'immagine di comodità grande eseguita come root equivalente all'host con strumenti di debugging preinstallati.

## Esempi di esaurimento delle risorse

I controlli delle risorse non sono appariscenti, ma fanno parte della sicurezza dei container perché limitano il raggio d'impatto di una compromissione. Senza limiti di memoria, CPU o PID, una shell semplice può essere sufficiente a degradare l'host o i workload vicini.

Esempi di test che impattano l'host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Questi esempi sono utili perché mostrano che non ogni esito pericoloso di container è una netta "escape". Limiti deboli di cgroup possono comunque trasformare code execution in un reale impatto operativo.

## Strumenti di hardening

Per ambienti Docker-centric, `docker-bench-security` rimane un'utile baseline di audit sul host perché verifica problemi di configurazione comuni rispetto a linee guida di benchmark ampiamente riconosciute:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Lo strumento non sostituisce la modellazione delle minacce, ma è comunque utile per trovare daemon, mount, network e runtime defaults che si accumulano nel tempo.

## Controlli

Usa questi come comandi rapidi di primo passaggio durante la valutazione:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- Un processo root con ampie capabilities e `Seccomp: 0` merita attenzione immediata.
- Mount sospetti e runtime sockets spesso offrono una via più rapida all'impatto rispetto a qualsiasi kernel exploit.
- La combinazione di una weak runtime posture e di weak resource limits solitamente indica un ambiente container generalmente permissivo, più che un singolo errore isolato.
