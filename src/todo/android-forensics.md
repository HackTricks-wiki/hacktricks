# Analisi forense di Android

{{#include ../banners/hacktricks-training.md}}

## Dispositivo bloccato

Preferire i metodi di acquisizione che preservano lo stato del dispositivo e documentare ogni azione. Se il dispositivo è bloccato, le opzioni disponibili dipendono dal modello, dalla versione di Android, dal livello delle patch e dal fatto che l'accesso sia stato configurato prima del sequestro. NIST raccomanda di scegliere un metodo in base al dispositivo e all'autorità responsabile dell'esame.<sup>[[1]](#references)</sup>

- Verificare se il debug USB era abilitato e se la workstation di acquisizione è già autorizzata. L'accesso ADB normalmente richiede che l'utente sblocchi il dispositivo e confermi la chiave RSA della workstation.<sup>[[3]](#references)</sup>
- Considerare se l'accesso biometrico è ancora disponibile secondo le norme legali e procedurali applicabili.
- Un **smudge attack** può rivelare un pattern grafico di sblocco dai residui sullo schermo, sebbene i tocchi successivi e la pulizia ne riducano l'affidabilità.<sup>[[2]](#references)</sup>
- Quando gli strumenti autorizzati supportano il dispositivo esatto e la relativa build software, possono tentare il recupero o il brute force di PIN, password o pattern. La verifica delle credenziali supportata dall'hardware, i ritardi tra i tentativi e le policy di wipe rendono questa procedura altamente specifica per il dispositivo; pertanto, non sostituire una tecnica o un risultato relativo a iPhone a un'evidenza che dimostri il supporto di un dispositivo Android.<sup>[[1]](#references)</sup>

## Acquisizione dei dati

Sui dispositivi meno recenti, un [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) legacy può produrre un file `.backup` che Android Backup Extractor è in grado di estrarre:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Non presumere che questo includa ogni applicazione. ADB indica il comando come deprecato e Android 12 esclude i dati delle app destinate al livello API 31 o successivo, a meno che l'app non sia debuggable.<sup>[[4]](#references)</sup>

### Accesso root o debug fisico

Con accesso root a un dispositivo in esecuzione, innanzitutto fai l'inventario delle partizioni e dei mount; i comandi seguenti non si applicano direttamente a un'acquisizione fisica tramite JTAG. Il block device corretto dipende dall'hardware, quindi non presumere che sia sempre `mmcblk0`. Crea un'immagine solo della source verificata su uno storage separato:<sup>[[1]](#references)</sup>

Un'acquisizione JTAG utilizza invece l'interfaccia hardware di test e accesso del dispositivo e apparecchiature di acquisizione compatibili per leggere la memoria accessibile. Pinout, supporto del chipset, stato del dispositivo e distinzione tra target volatili e non volatili dipendono dal dispositivo; documenta il percorso hardware e utilizza una procedura convalidata per quel modello.<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Ad esempio, se l'inventario delle partizioni conferma che `/dev/block/mmcblk0` è l'intero dispositivo flash e che la destinazione dispone di spazio sufficiente, il comando di acquisizione originale diventa:<sup>[[1]](#references)</sup>
```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```
Qui, `df /data` aiuta ad associare `/data` al filesystem montato; non deve essere considerato una prova che `mmcblk0` sia la sorgente corretta dell'intero dispositivo o che `4096` sia l'unica dimensione di blocco valida per `dd`.

Calcola l'hash del risultato e registra il comando esatto, gli identificativi del dispositivo, l'ora e ogni modifica apportata durante l'acquisizione.<sup>[[1]](#references)</sup>

### Memoria

LiME può acquisire la memoria fisica da Linux e da alcuni dispositivi Android, ma il suo modulo kernel deve essere compilato per il kernel di destinazione e caricato con privilegi sufficienti. La firma dei moduli, il kernel lockdown e le moderne misure di hardening di Android possono impedirne il caricamento.<sup>[[5]](#references)</sup>

Il workflow Android del progetto invia il modulo corrispondente tramite ADB, inoltra una porta TCP, carica il modulo da una root shell e cattura lo stream sull'host di analisi:<sup>[[5]](#references)</sup>
```bash
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
```

```bash
nc localhost 4444 > ram.lime
```
LiME può invece scrivere nello storage del dispositivo con `path=/sdcard/ram.lime`, ma ciò modifica lo storage del dispositivo e richiede spazio libero sufficiente. Registra questo effetto collaterale ed esegui l'hash dell'immagine acquisita.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Linee guida sulla computer forensics dei dispositivi mobili](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Attacchi Smudge sui touchscreen degli smartphone](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Restrizioni del backup ADB di Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
