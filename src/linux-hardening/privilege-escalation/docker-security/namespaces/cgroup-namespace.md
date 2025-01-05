# CGroup Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

Un cgroup namespace è una funzionalità del kernel Linux che fornisce **isolamento delle gerarchie cgroup per i processi in esecuzione all'interno di un namespace**. I cgroups, abbreviazione di **control groups**, sono una funzionalità del kernel che consente di organizzare i processi in gruppi gerarchici per gestire e applicare **limiti sulle risorse di sistema** come CPU, memoria e I/O.

Sebbene i cgroup namespaces non siano un tipo di namespace separato come gli altri di cui abbiamo discusso in precedenza (PID, mount, network, ecc.), sono correlati al concetto di isolamento dei namespace. **I cgroup namespaces virtualizzano la vista della gerarchia cgroup**, in modo che i processi in esecuzione all'interno di un cgroup namespace abbiano una vista diversa della gerarchia rispetto ai processi in esecuzione nell'host o in altri namespaces.

### Come funziona:

1. Quando viene creato un nuovo cgroup namespace, **inizia con una vista della gerarchia cgroup basata sul cgroup del processo creatore**. Ciò significa che i processi in esecuzione nel nuovo cgroup namespace vedranno solo un sottoinsieme dell'intera gerarchia cgroup, limitato al sottoalbero cgroup radicato nel cgroup del processo creatore.
2. I processi all'interno di un cgroup namespace **vedranno il proprio cgroup come la radice della gerarchia**. Ciò significa che, dalla prospettiva dei processi all'interno del namespace, il proprio cgroup appare come la radice, e non possono vedere o accedere ai cgroups al di fuori del proprio sottoalbero.
3. I cgroup namespaces non forniscono direttamente isolamento delle risorse; **forniscono solo isolamento della vista della gerarchia cgroup**. **Il controllo e l'isolamento delle risorse sono ancora applicati dai sottosistemi cgroup** (ad es., cpu, memoria, ecc.) stessi.

Per ulteriori informazioni sui CGroups controlla:

{{#ref}}
../cgroups.md
{{#endref}}

## Laboratorio:

### Crea diversi Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Montando una nuova istanza del filesystem `/proc` se utilizzi il parametro `--mount-proc`, garantisci che il nuovo namespace di mount abbia una **visione accurata e isolata delle informazioni sui processi specifiche per quel namespace**.

<details>

<summary>Errore: bash: fork: Impossibile allocare memoria</summary>

Quando `unshare` viene eseguito senza l'opzione `-f`, si verifica un errore a causa del modo in cui Linux gestisce i nuovi namespace PID (Process ID). I dettagli chiave e la soluzione sono delineati di seguito:

1. **Spiegazione del Problema**:

- Il kernel Linux consente a un processo di creare nuovi namespace utilizzando la chiamata di sistema `unshare`. Tuttavia, il processo che avvia la creazione di un nuovo namespace PID (denominato processo "unshare") non entra nel nuovo namespace; solo i suoi processi figli lo fanno.
- Eseguire `%unshare -p /bin/bash%` avvia `/bin/bash` nello stesso processo di `unshare`. Di conseguenza, `/bin/bash` e i suoi processi figli si trovano nel namespace PID originale.
- Il primo processo figlio di `/bin/bash` nel nuovo namespace diventa PID 1. Quando questo processo termina, attiva la pulizia del namespace se non ci sono altri processi, poiché PID 1 ha il ruolo speciale di adottare processi orfani. Il kernel Linux disabiliterà quindi l'allocazione PID in quel namespace.

2. **Conseguenza**:

- L'uscita di PID 1 in un nuovo namespace porta alla pulizia del flag `PIDNS_HASH_ADDING`. Questo porta alla funzione `alloc_pid` a non riuscire ad allocare un nuovo PID durante la creazione di un nuovo processo, producendo l'errore "Impossibile allocare memoria".

3. **Soluzione**:
- Il problema può essere risolto utilizzando l'opzione `-f` con `unshare`. Questa opzione fa sì che `unshare` fork un nuovo processo dopo aver creato il nuovo namespace PID.
- Eseguire `%unshare -fp /bin/bash%` garantisce che il comando `unshare` stesso diventi PID 1 nel nuovo namespace. `/bin/bash` e i suoi processi figli sono quindi contenuti in modo sicuro all'interno di questo nuovo namespace, prevenendo l'uscita prematura di PID 1 e consentendo l'allocazione normale dei PID.

Assicurandoti che `unshare` venga eseguito con il flag `-f`, il nuovo namespace PID viene mantenuto correttamente, consentendo a `/bin/bash` e ai suoi subprocessi di operare senza incontrare l'errore di allocazione della memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Controlla in quale namespace si trova il tuo processo
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Trova tutti i namespace CGroup
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entra all'interno di un namespace CGroup
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Inoltre, puoi **entrare in un altro namespace di processo solo se sei root**. E **non puoi** **entrare** in un altro namespace **senza un descrittore** che punti ad esso (come `/proc/self/ns/cgroup`).

## Riferimenti

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
