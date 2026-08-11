# Filesystem, Inodes e Recovery

{{#include ../../banners/hacktricks-training.md}}

L'abuso del filesystem riguarda spesso il confondere la relazione tra un percorso visibile e l'oggetto che si trova dietro di esso.

Le immagini disco possono nascondere un altro filesystem.<sup>[[1]](#references)</sup> I mount scrivibili possono essere utilizzati da processi privilegiati.

Gli hardlink possono esporre lo stesso inode attraverso un nome diverso.<sup>[[3]](#references)</sup> I file eliminati possono essere ancora leggibili tramite un file descriptor aperto.<sup>[[5]](#references)[[6]](#references)</sup>

Questa pagina si concentra sulla tecnica, non su un laboratorio o target specifico.

## Immagini Disco e Loop Mount

Un file normale può contenere un filesystem completo, quindi un'immagine disco può esporre un secondo albero di filesystem quando viene montata.<sup>[[1]](#references)</sup>

Le immagini di backup, i block device copiati, gli artefatti delle VM o i blob rinominati possono quindi contenere credenziali, script, chiavi SSH, file di configurazione o flags, anche quando dall'esterno non sembrano utili.

Identifica le probabili immagini con `file` per classificare un candidato, usa `blkid` per analizzare i metadati riconosciuti del filesystem e `strings -a` per eseguire la scansione dell'intero file alla ricerca di sequenze stampabili.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Quando il montaggio è consentito, usa un loop mount con `ro` affinché l’immagine venga collegata in modalità di sola lettura; il comando `find` riportato di seguito limita la profondità dell’ispezione e il tipo di file.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Se il montaggio non è disponibile e l’immagine è ext2/ext3/ext4, ispeziona direttamente i suoi metadati con `debugfs`.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
La tecnica è utile perché trasforma un file dall’aspetto normale in un secondo albero del filesystem.<sup>[[1]](#references)</sup> Considerala un modo per recuperare dati nascosti, non come una privilege escalation di per sé.

## Abuso dei mount scrivibili

Un mount scrivibile diventa pericoloso quando un contesto con privilegi più elevati si fida successivamente di qualcosa al suo interno. La domanda importante non è solo "posso scrivere qui?", ma "chi leggerà, eseguirà, importerà o caricherà successivamente qualcosa da qui?".

Usa `findmnt` per analizzare i filesystem montati e le relative opzioni.<sup>[[9]](#references)</sup>

Individua i mount scrivibili e i consumer sospetti con i predicati documentati di `find` relativi a permessi, tipo e confini del filesystem, quindi usa `grep` ricorsivo per cercare nella configurazione dei probabili consumer.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Pattern di abuso comuni:

- Un cron job o un servizio systemd esegue uno script scrivibile dal mount.<sup>[[13]](#references)[[14]](#references)</sup>
- Un servizio privilegiato carica plugin, configurazioni, template o binari helper dal mount.
- Un mount contiene file SUID e consente la modifica, la sostituzione o la manipolazione del percorso.
- Un container o chroot espone un percorso supportato dall'host scrivibile dall'ambiente con restrizioni. I mount namespace forniscono gerarchie di mount distinte, mentre `chroot()` modifica solo la risoluzione dei nomi di percorso e non costituisce una sandbox completa.<sup>[[15]](#references)[[16]](#references)</sup>

Pattern di validazione generico che utilizza gli stessi predicati di `find`.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Quando dimostri l’impatto in un lab autorizzato, mantieni il payload osservabile e minimale, ad esempio scrivendo l’output di `id` in un file temporaneo.<sup>[[23]](#references)</sup> La tecnica principale consiste nell’esecuzione ritardata attraverso una posizione scrivibile e considerata trusted.

## Inodes e confusione dei percorsi

Un inode è l’oggetto del filesystem; un percorso è solo un nome che vi fa riferimento. I metadati del dispositivo e dell’inode consentono di distinguere gli oggetti tra filesystem, mentre i conteggi dei link espongono la presenza di più hard link.<sup>[[3]](#references)</sup> Un pathname eliminato non significa sempre che i dati siano scomparsi, finché un processo mantiene il file aperto.<sup>[[5]](#references)</sup>

I predicati `find` riportati di seguito confrontano l’identità dell’inode, i conteggi dei link, i confini dei dispositivi e i timestamp.<sup>[[4]](#references)</sup>

Confronta i file in base all’inode e al dispositivo usando `ls -i` e i formati dei metadati di `stat`.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Trova ogni percorso visibile per lo stesso inode con `find -samefile`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Cerca direttamente per numero di inode con `find -inum` quando hai solo i metadati.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Questa tecnica è utile quando un file appare con un nome imprevisto, quando un'applicazione convalida un percorso ma ne usa un altro oppure quando un wrapper con privilegi interagisce con un inode che è raggiungibile anche altrove.

## Abuso degli hardlink

Gli hardlink creano più nomi per lo stesso inode. Non puntano a un percorso di destinazione come fanno i symlink; sono nomi equivalenti per lo stesso oggetto file.<sup>[[3]](#references)</sup>

Trova i file SUID con più hardlink usando i predicati di `find` relativi ai permessi e al conteggio dei link.<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Ispeziona un file sospetto con `stat` e `find -samefile`.<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Perché è importante:

- Un file sensibile potrebbe essere raggiungibile tramite un percorso meno evidente.
- Un wrapper SUID potrebbe essere nascosto dietro un nome che non sembra privilegiato.
- Un'operazione di pulizia che rimuove un pathname potrebbe lasciare attivo un altro hardlink.

Il sysctl `fs.protected_hardlinks` di Linux può limitare la creazione di hardlink oltre i confini dei privilegi.<sup>[[7]](#references)</sup> Gli hardlink esistenti meritano comunque una verifica.

## Recupero dei file eliminati tramite FD aperti

Quando un processo mantiene aperto un file, la rimozione del suo ultimo pathname lascia il file attivo finché l'ultimo descrittore non viene chiuso; Linux espone tali descrittori sotto `/proc/<pid>/fd/`.<sup>[[5]](#references)[[6]](#references)</sup>

Individua i file aperti ed eliminati elencando i descrittori in `/proc` e filtrando l'output dei file aperti.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Il recupero tramite questi link dipende dalle autorizzazioni, poiché il dereferenziamento di `/proc/<pid>/fd` è soggetto ai controlli di accesso di ptrace e ai permessi dei file.<sup>[[6]](#references)</sup>

Quando è consentito, `readlink` mostra la destinazione del descrittore e `cp` ne copia il contenuto.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Questa è una tecnica pratica per recuperare log eliminati, segreti temporanei, binari rimossi, file ruotati o script rimossi dopo l'esecuzione.

## Recupero ext con debugfs

Nei filesystem ext2/ext3/ext4, `debugfs` può esaminare i metadati degli inode e scaricare il contenuto degli inode da un block device o da un'immagine; senza `-w`, apre il filesystem in sola lettura.<sup>[[2]](#references)</sup> Quando possibile, lavora su una copia o su un'immagine in sola lettura.

Elenca le voci ed esamina gli inode con le richieste di `debugfs` per gli elenchi delle directory, lo stato degli inode e i controlli inode-percorso.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Esegui il dump di un inode noto con il comando `debugfs dump`, quindi classifica l'output recuperato con `file`.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Questa procedura non garantisce il recovery. Dipende dallo stato del filesystem, dal fatto che i blocchi siano stati riutilizzati e dal fatto che i metadati esistano ancora. Per ext3/ext4, il manuale di `debugfs` nota che il recovery degli inode eliminati potrebbe non riuscire perché i blocchi dati degli inode rilasciati non sono più disponibili.<sup>[[2]](#references)</sup> La tecnica rimane utile perché consente di esaminare lo stato a livello di inode senza affidarsi al normale path traversal.

## Esaurimento e ordinamento degli inode

L'esaurimento degli inode si verifica quando un filesystem esaurisce i nodi dei file, anche se rimane spazio libero sul disco.<sup>[[8]](#references)[[17]](#references)</sup> Di solito causa errori di affidabilità, ma può anche spiegare comportamenti anomali durante l'incident response o il lab triage.

Usa `df -i` per riportare le informazioni sugli inode invece dell'utilizzo dei blocchi.<sup>[[8]](#references)</sup>

Verifica la pressione sugli inode con `df` e un conteggio `find` delle directory parent.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
I numeri degli inode e i timestamp possono inoltre aiutare a ricostruire l'attività in semplici ambienti di laboratorio.

Le direttive di formato di `find` riportate di seguito espongono questi campi.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Considera l'ordine come un indizio, non come una prova. Le operazioni di copia, l'estrazione di archivi, il tipo di filesystem, i ripristini e le scritture concorrenti possono modificare i pattern di allocazione.

## Note difensive

- Monta le immagini sconosciute in sola lettura durante l'analisi.<sup>[[1]](#references)</sup>
- Mantieni gli script privilegiati, le unità di servizio, i plugin e i percorsi degli helper al di fuori dei mount scrivibili dagli utenti.
- Usa `nosuid`, `nodev` e `noexec` quando appropriato dal punto di vista operativo; queste opzioni disabilitano rispettivamente l'esecuzione set-ID/capability, l'interpretazione dei device o l'esecuzione diretta di binari sul mount.<sup>[[1]](#references)</sup> Non considerarli un boundary completo.
- Limita l'accesso a `/proc/<pid>/fd`; il dereferencing di questi link è controllato dai controlli di accesso ptrace e dai permessi dei file.<sup>[[6]](#references)</sup> Limita, ove possibile, i metadati più ampi dei processi e l'ispezione tra utenti diversi.
- Monitora i mount point scrivibili, gli hardlink inattesi a file privilegiati e i file sensibili eliminati ma ancora aperti.

## References

- [1] [mount(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — pagina del manuale Linux](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — pagina del manuale Linux](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — pagina del manuale Linux](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — pagina del manuale Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [Documentazione per /proc/sys/fs/ — Documentazione del kernel Linux](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — pagina del manuale Linux](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — pagina del manuale Linux](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — pagina del manuale Linux](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — pagina del manuale Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — pagina del manuale Linux](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — pagina del manuale Linux](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — pagina del manuale Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — pagina del manuale Linux](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — pagina del manuale Linux](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — pagina del manuale Linux](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — pagina del manuale Linux](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — pagina del manuale Linux](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — pagina del manuale Linux](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
