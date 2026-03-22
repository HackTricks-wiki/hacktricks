# Valutazione e hardening

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Una buona container assessment dovrebbe rispondere a due domande parallele. Primo: cosa può fare un attacker dall'attuale workload? Secondo: quali scelte dell'operatore hanno reso questo possibile? Gli enumeration tools aiutano con la prima domanda, e le linee guida di hardening aiutano con la seconda. Tenere entrambe su una pagina rende la sezione più utile come riferimento in campo piuttosto che un semplice catalogo di escape tricks.

## Enumeration Tools

Un certo numero di tool rimane utile per caratterizzare rapidamente un ambiente container:

- `linpeas` può identificare molti indicatori di container, mounted sockets, capability sets, filesystem pericolosi e breakout hints.
- `CDK` si concentra specificamente sugli ambienti container e include enumerazione oltre ad alcuni automated escape checks.
- `amicontained` è leggero e utile per identificare container restrictions, capabilities, namespace exposure e probabili breakout classes.
- `deepce` è un altro enumerator focalizzato sui container con controlli orientati al breakout.
- `grype` è utile quando la valutazione include la revisione delle vulnerabilità dei package dell'image invece che solo l'analisi degli escape a runtime.

Il valore di questi tool è velocità e copertura, non certezza. Aiutano a rivelare rapidamente la postura approssimativa, ma i risultati più interessanti richiedono comunque interpretazione manuale rispetto al modello effettivo di runtime, namespace, capability e mount.

## Priorità di hardening

I principi di hardening più importanti sono concettualmente semplici anche se la loro implementazione varia per piattaforma. Evitare privileged containers. Evitare mounted runtime sockets. Non dare ai container host paths scrivibili a meno che non ci sia una ragione molto specifica. Usare user namespaces o rootless execution dove possibile. Drop tutte le capabilities e riaggiungere solo quelle di cui il workload ha veramente bisogno. Tenere seccomp, AppArmor e SELinux abilitati piuttosto che disabilitarli per risolvere problemi di compatibilità delle applicazioni. Limitare le risorse in modo che un container compromesso non possa trivialmente negare il servizio all'host.

Igiene di image e build conta tanto quanto la postura a runtime. Usare immagini minimal, ricostruire frequentemente, scansionarle, richiedere provenance dove pratico e mantenere i secrets fuori dai layer. Un container che gira come non-root con una small image e una superficie syscall e capability ristretta è molto più facile da difendere rispetto a una large convenience image che gira come host-equivalent root con strumenti di debug preinstallati.

## Esempi di esaurimento di risorse

I resource controls non sono glamour, ma fanno parte della sicurezza dei container perché limitano il blast radius di una compromissione. Senza limiti di memory, CPU o PID, una semplice shell può essere sufficiente a degradare l'host o i workloads vicini.

Esempi di test con impatto sull'host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Questi esempi sono utili perché mostrano che non ogni esito pericoloso di un container è un "escape" netto. Limiti cgroup deboli possono comunque trasformare code execution in un impatto operativo reale.

## Strumenti di hardening

Per ambienti centrati su Docker, `docker-bench-security` rimane una utile baseline di audit lato host perché controlla problemi di configurazione comuni rispetto a linee guida di benchmark ampiamente riconosciute:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Lo strumento non è un sostituto per threat modeling, ma è comunque utile per individuare impostazioni predefinite di daemon, mount, network e runtime lasciate incautamente che si accumulano nel tempo.

## Checks

Usa questi come comandi rapidi di primo passaggio durante l'assessment:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- Un processo root con broad capabilities e `Seccomp: 0` richiede attenzione immediata.
- Mounts sospetti e runtime sockets spesso forniscono una via più rapida all'impatto rispetto a qualsiasi kernel exploit.
- La combinazione di weak runtime posture e weak resource limits di solito indica un container environment generalmente permissivo piuttosto che un singolo errore isolato.
{{#include ../../../banners/hacktricks-training.md}}
