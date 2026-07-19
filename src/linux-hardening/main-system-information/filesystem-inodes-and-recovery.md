# Filesystem, Inode e recupero

{{#include ../../banners/hacktricks-training.md}}

L'abuso del filesystem riguarda spesso la confusione tra il percorso visibile e l'oggetto che si trova dietro di esso. Le immagini disco possono nascondere un altro filesystem, i mount scrivibili possono essere utilizzati da processi privilegiati, gli hardlink possono esporre lo stesso inode attraverso un nome diverso e i file eliminati possono essere ancora leggibili tramite un file descriptor aperto.

Questa pagina si concentra sulla tecnica, non su un laboratorio o un target specifico.

## Immagini disco e Loop Mounts

Un file normale può contenere un filesystem completo. Le immagini di backup, i block device copiati, gli artifact delle VM o i blob rinominati possono quindi contenere credenziali, script, chiavi SSH, file di configurazione o flag anche quando dall'esterno non sembrano utili.

Identifica le immagini probabili:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Se è consentito effettuare il mounting, monta prima le immagini sconosciute in sola lettura:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Se il montaggio non è disponibile, esamina direttamente i metadati del filesystem:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
La tecnica è utile perché trasforma un file dall’aspetto normale in un secondo albero del filesystem. Considerala un modo per recuperare dati nascosti, non come una tecnica di privilege escalation autonoma.

## Writable Mount Abuse

Un mount scrivibile diventa pericoloso quando un contesto più privilegiato si fida successivamente di qualcosa al suo interno. La domanda importante non è solo "posso scrivere qui?", ma anche "chi leggerà, eseguirà, importerà o caricherà successivamente qualcosa da qui?".

Individua i mount scrivibili e i consumer sospetti:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Pattern comuni di abuso:

- Un cron privilegiato o un'unità systemd esegue uno script scrivibile dal mount.
- Un servizio privilegiato carica plugin, configurazioni, template o binari helper dal mount.
- Un mount contiene file SUID e consente la modifica, la sostituzione o la manipolazione dei path.
- Un container o un chroot espone un percorso basato sull'host, scrivibile dall'ambiente soggetto a restrizioni.

Pattern generico di validazione:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Quando dimostri l'impatto in un laboratorio autorizzato, mantieni il payload osservabile e minimale, ad esempio scrivendo l'output di `id` in un file temporaneo. La tecnica principale consiste nell'esecuzione ritardata tramite una posizione scrivibile attendibile.

## Inode e confusione dei percorsi

Un inode è l'oggetto del filesystem; un percorso è solo un nome che vi punta. Questo è importante perché due percorsi diversi possono puntare allo stesso inode e la cancellazione di un nome di percorso non significa sempre che i dati siano scomparsi.

Confronta i file in base all'inode e al dispositivo:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Trova ogni pathname visibile per lo stesso inode:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Cerca direttamente per numero di inode quando hai solo i metadati:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Questa tecnica è utile quando un file appare con un nome inatteso, quando un'applicazione convalida un percorso ma ne usa un altro, oppure quando un wrapper privilegiato interagisce con un inode raggiungibile anche da un'altra posizione.

## Hardlink Abuse

Gli hardlink creano più nomi per lo stesso inode. Non puntano a un percorso di destinazione come fanno i symlink; sono nomi equivalenti per lo stesso oggetto file.

Trova i file SUID con più hardlink:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Ispeziona un file sospetto:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Perché è importante:

- Un file sensibile potrebbe essere raggiungibile tramite un percorso meno ovvio.
- Un wrapper SUID potrebbe essere nascosto dietro un nome che non sembra privilegiato.
- Una pulizia che rimuove un pathname potrebbe lasciare attivo un altro hardlink.

I kernel moderni e le opzioni di mount possono limitare la creazione di hardlink per ridurre questo tipo di abuso, ma vale comunque la pena verificare gli hardlink esistenti.

## Recupero di file eliminati tramite FD aperti

Quando un processo mantiene aperto un file, i dati del file possono rimanere disponibili anche dopo l'eliminazione del pathname. Linux espone questi descrittori aperti in `/proc/<pid>/fd/`.

Trova i file eliminati ancora aperti:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Recupera i dati quando i permessi lo consentono:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Questa è una tecnica pratica per recuperare log eliminati, secret temporanei, binari rilasciati, file ruotati o script rimossi dopo l'esecuzione.

## Recovery ext Con debugfs

Sui filesystem ext, `debugfs` può ispezionare i metadati degli inode e talvolta eseguire il dump del contenuto dei file da un'immagine del filesystem. Quando possibile, lavorare su una copia o su un'immagine in sola lettura.

Elencare le entry e ispezionare gli inode:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Eseguire il dump di un inode noto:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Questo non garantisce il recupero. Dipende dallo stato del filesystem, dal fatto che i blocchi siano stati riutilizzati e dal fatto che i metadati esistano ancora. La tecnica rimane utile perché consente di ispezionare lo stato a livello di inode senza affidarsi al normale attraversamento dei percorsi.

## Esaurimento e ordinamento degli inode

L'esaurimento degli inode si verifica quando un filesystem esaurisce gli oggetti file anche se è ancora disponibile spazio su disco. Di solito causa problemi di affidabilità, ma può anche spiegare comportamenti anomali durante l'incident response o il lab triage.

Controlla la pressione sugli inode:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
I numeri degli inode e i timestamp possono anche aiutare a ricostruire l'attività in semplici ambienti di laboratorio:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Considera l'ordine come un indizio, non come una prova. Le operazioni di copia, l'estrazione di archivi, il tipo di filesystem, i ripristini e le scritture simultanee possono tutti modificare i pattern di allocazione.

## Note difensive

- Monta le immagini sconosciute in modalità read-only durante l'analisi.
- Mantieni gli script con privilegi, le unità di servizio, i plugin e i percorsi degli helper al di fuori dei mount scrivibili dagli utenti.
- Usa `nosuid`, `nodev` e `noexec` quando appropriato dal punto di vista operativo, ma non considerarli un confine completo.
- Limita, ove possibile, l'accesso a `/proc/<pid>/fd`, ai metadati dei processi e all'ispezione dei processi tra utenti diversi.
- Monitora i mount point scrivibili, gli hardlink imprevisti a file privilegiati e i file sensibili eliminati ma ancora aperti.
{{#include ../../banners/hacktricks-training.md}}
