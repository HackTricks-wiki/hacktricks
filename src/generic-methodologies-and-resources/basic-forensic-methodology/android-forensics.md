# Analisi forense Android

{{#include ../../banners/hacktricks-training.md}}

## Dispositivo bloccato

Preferisci metodi di acquisizione che preservino lo stato del dispositivo e documenta ogni azione. Se il dispositivo è bloccato, le opzioni disponibili dipendono dal modello, dalla versione di Android, dal livello delle patch e dal fatto che l'accesso fosse stato configurato prima del sequestro. NIST raccomanda di scegliere un metodo in base al dispositivo e all'autorità che conduce l'esame.<sup>[[1]](#references)</sup>

- Verifica se il debug USB era abilitato e se la workstation di acquisizione è già autorizzata. L'accesso ADB normalmente richiede che l'utente sblocchi il dispositivo e confermi la chiave RSA della workstation.<sup>[[3]](#references)</sup>
- Valuta se l'accesso biometrico è ancora disponibile nel rispetto delle norme legali e procedurali applicabili.
- Un **smudge attack** può rivelare una sequenza di sblocco grafica tramite i residui sullo schermo, anche se tocchi successivi e la pulizia ne riducono l'affidabilità.<sup>[[2]](#references)</sup>
- Se gli strumenti autorizzati supportano il dispositivo esatto e la build del software, possono tentare il recupero o il brute force di PIN, password o sequenza. La verifica delle credenziali supportata dall'hardware, i ritardi tra i tentativi e le policy di cancellazione rendono la procedura altamente specifica per il dispositivo: non usare quindi una tecnica o un risultato per iPhone come prova del supporto di un dispositivo Android.<sup>[[1]](#references)</sup>

## Acquisizione dei dati

Sui dispositivi meno recenti, un [backup ADB](../../mobile-pentesting/android-app-pentesting/adb-commands.md#legacy-adb-backup) legacy può generare un file `.backup` che Android Backup Extractor può estrarre:<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

Non dare per scontato che acquisisca tutte le applicazioni. ADB indica il comando come deprecato e Android 12 esclude i dati delle app con target API level 31 o superiore, a meno che l'app non sia debuggable.<sup>[[4]](#references)</sup>

### Accesso root o debug fisico

Con accesso root a un dispositivo acceso, per prima cosa inventaria le partizioni e i mount; i comandi seguenti non si applicano direttamente a un'acquisizione fisica JTAG. Il dispositivo a blocchi corretto dipende dall'hardware, quindi non dare per scontato che sia sempre `mmcblk0`. Crea un'immagine solo dalla sorgente verificata e salvala su un supporto separato:<sup>[[1]](#references)</sup>

Un'acquisizione JTAG usa invece l'interfaccia hardware di test del dispositivo e apparecchiature di acquisizione compatibili per leggere la memoria accessibile. Pinout, supporto del chipset, stato del dispositivo e distinzione tra target volatili e non volatili dipendono dal dispositivo; documenta il percorso hardware e segui una procedura convalidata per quel modello.<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

Ad esempio, se l'inventario delle partizioni conferma che `/dev/block/mmcblk0` è l'intero dispositivo flash e la destinazione dispone di spazio sufficiente, il comando di acquisizione originale diventa:<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

Qui, `df /data` aiuta ad associare `/data` al filesystem montato; non va considerato una prova che `mmcblk0` sia la sorgente corretta dell'intero dispositivo o che `4096` sia l'unica dimensione di blocco valida per `dd`.

Calcola l'hash del risultato e annota il comando esatto, gli identificativi dei dispositivi, l'ora e qualsiasi modifica apportata durante l'acquisizione.<sup>[[1]](#references)</sup>

### Memoria

LiME può acquisire la memoria fisica da Linux e da alcuni dispositivi Android, ma il suo modulo kernel deve essere compilato per il kernel di destinazione e caricato con privilegi sufficienti. La firma dei moduli, il kernel lockdown e le moderne misure di hardening di Android possono impedirne il caricamento.<sup>[[5]](#references)</sup>

Il workflow Android del progetto invia il modulo corrispondente tramite ADB, inoltra una porta TCP, carica il modulo da una shell root e acquisisce il flusso sull'host di analisi:<sup>[[5]](#references)</sup>

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

LiME può invece scrivere nella memoria del dispositivo con `path=/sdcard/ram.lime`, ma ciò modifica la memoria del dispositivo e richiede spazio libero sufficiente. Registra questo effetto collaterale e calcola l’hash dell’immagine acquisita.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Linee guida per la digital forensics sui dispositivi mobili](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Attacchi Smudge ai touchscreen degli smartphone](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Restrizione del backup ADB in Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Estrattore di memoria Linux (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../../banners/hacktricks-training.md}}
