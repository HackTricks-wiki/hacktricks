# Network Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

Un network namespace è una funzionalità del kernel Linux che fornisce isolamento dello stack di rete, consentendo **a ciascun network namespace di avere la propria configurazione di rete indipendente**, interfacce, indirizzi IP, tabelle di routing e regole del firewall. Questo isolamento è utile in vari scenari, come la containerizzazione, dove ciascun container dovrebbe avere la propria configurazione di rete, indipendente dagli altri container e dal sistema host.

### Come funziona:

1. Quando viene creato un nuovo network namespace, inizia con uno **stack di rete completamente isolato**, con **nessuna interfaccia di rete** tranne l'interfaccia di loopback (lo). Ciò significa che i processi in esecuzione nel nuovo network namespace non possono comunicare con i processi in altri namespace o con il sistema host per impostazione predefinita.
2. **Interfacce di rete virtuali**, come le coppie veth, possono essere create e spostate tra i network namespaces. Questo consente di stabilire connettività di rete tra i namespace o tra un namespace e il sistema host. Ad esempio, un'estremità di una coppia veth può essere posizionata nel network namespace di un container, e l'altra estremità può essere collegata a un **bridge** o a un'altra interfaccia di rete nel namespace host, fornendo connettività di rete al container.
3. Le interfacce di rete all'interno di un namespace possono avere i propri **indirizzi IP, tabelle di routing e regole del firewall**, indipendenti dagli altri namespace. Questo consente ai processi in diversi network namespaces di avere configurazioni di rete diverse e operare come se stessero funzionando su sistemi di rete separati.
4. I processi possono spostarsi tra i namespace utilizzando la chiamata di sistema `setns()`, o creare nuovi namespace utilizzando le chiamate di sistema `unshare()` o `clone()` con il flag `CLONE_NEWNET`. Quando un processo si sposta in un nuovo namespace o ne crea uno, inizierà a utilizzare la configurazione di rete e le interfacce associate a quel namespace.

## Lab:

### Crea diversi Namespaces

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
Montando una nuova istanza del filesystem `/proc` se utilizzi il parametro `--mount-proc`, garantisci che il nuovo namespace di mount abbia una **visione accurata e isolata delle informazioni sui processi specifiche per quel namespace**.

<details>

<summary>Errore: bash: fork: Impossibile allocare memoria</summary>

Quando `unshare` viene eseguito senza l'opzione `-f`, si verifica un errore a causa del modo in cui Linux gestisce i nuovi namespace PID (Process ID). I dettagli chiave e la soluzione sono delineati di seguito:

1. **Spiegazione del problema**:

- Il kernel Linux consente a un processo di creare nuovi namespace utilizzando la chiamata di sistema `unshare`. Tuttavia, il processo che avvia la creazione di un nuovo namespace PID (denominato processo "unshare") non entra nel nuovo namespace; solo i suoi processi figli lo fanno.
- Eseguire `%unshare -p /bin/bash%` avvia `/bin/bash` nello stesso processo di `unshare`. Di conseguenza, `/bin/bash` e i suoi processi figli si trovano nel namespace PID originale.
- Il primo processo figlio di `/bin/bash` nel nuovo namespace diventa PID 1. Quando questo processo termina, attiva la pulizia del namespace se non ci sono altri processi, poiché PID 1 ha il ruolo speciale di adottare processi orfani. Il kernel Linux disabiliterà quindi l'allocazione PID in quel namespace.

2. **Conseguenza**:

- L'uscita di PID 1 in un nuovo namespace porta alla pulizia del flag `PIDNS_HASH_ADDING`. Questo provoca il fallimento della funzione `alloc_pid` nell'allocare un nuovo PID durante la creazione di un nuovo processo, producendo l'errore "Impossibile allocare memoria".

3. **Soluzione**:
- Il problema può essere risolto utilizzando l'opzione `-f` con `unshare`. Questa opzione fa sì che `unshare` fork un nuovo processo dopo aver creato il nuovo namespace PID.
- Eseguire `%unshare -fp /bin/bash%` garantisce che il comando `unshare` stesso diventi PID 1 nel nuovo namespace. `/bin/bash` e i suoi processi figli sono quindi contenuti in modo sicuro all'interno di questo nuovo namespace, prevenendo l'uscita prematura di PID 1 e consentendo l'allocazione normale dei PID.

Assicurandoti che `unshare` venga eseguito con il flag `-f`, il nuovo namespace PID viene mantenuto correttamente, consentendo a `/bin/bash` e ai suoi subprocessi di operare senza incontrare l'errore di allocazione della memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;Controlla in quale namespace si trova il tuo processo
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Trova tutti i namespace di rete
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entra all'interno di un Network namespace
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Inoltre, puoi **entrare in un altro namespace di processo solo se sei root**. E **non puoi** **entrare** in un altro namespace **senza un descrittore** che punti ad esso (come `/proc/self/ns/net`).

## Riferimenti

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
