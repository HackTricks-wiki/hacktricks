# Analisi forense di Android

{{#include ../banners/hacktricks-training.md}}

## Dispositivo bloccato

Preferire i metodi di acquisizione che preservano lo stato del dispositivo e documentare ogni azione. Se il dispositivo è bloccato, le opzioni disponibili dipendono dal modello, dalla versione di Android, dal livello delle patch e dal fatto che l'accesso sia stato configurato prima del sequestro. NIST raccomanda di scegliere un metodo in base al dispositivo e all'autorità responsabile dell'esame.<sup>[[1]](#references)</sup>

- Verificare se il debug USB era abilitato e se la workstation di acquisizione è già autorizzata. L'accesso ADB normalmente richiede che l'utente sblocchi il dispositivo e confermi la chiave RSA della workstation.<sup>[[3]](#references)</sup>
- Valutare se l'accesso biometrico è ancora disponibile secondo le norme legali e procedurali applicabili.
- Un **smudge attack** può rivelare un pattern grafico di sblocco dai residui sullo schermo, anche se i tocchi successivi e la pulizia ne riducono l'affidabilità.<sup>[[2]](#references)</sup>
- Utilizzare strumenti commerciali o di ricerca per il lock-bypass solo quando supportano esplicitamente il dispositivo e la build software esatti.

## Acquisizione dei dati

Sui dispositivi meno recenti, un [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) legacy può produrre un file `.backup` che Android Backup Extractor è in grado di estrarre:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Non presumere che questo acquisisca ogni applicazione. ADB indica il comando come deprecato e Android 12 esclude i dati delle app destinate al livello API 31 o successivo, a meno che l'app non sia debuggable.<sup>[[4]](#references)</sup>

### Accesso root o debug fisico

Con accesso root a un dispositivo attivo, inventaria innanzitutto le partizioni e i mount; i comandi riportati di seguito non si applicano direttamente a un'acquisizione fisica tramite JTAG. Il block device corretto dipende dall'hardware, quindi non presumere che sia sempre `mmcblk0`. Crea un'immagine solo della sorgente verificata su uno storage separato:<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Esegui l'hash del risultato e registra il comando esatto, gli identificatori del dispositivo, l'ora e qualsiasi modifica apportata durante l'acquisizione.<sup>[[1]](#references)</sup>

### Memoria

LiME può acquisire la memoria fisica da Linux e da alcuni dispositivi Android, ma il suo kernel module deve essere compilato per il kernel di destinazione e caricato con privilegi sufficienti. La firma dei moduli, il kernel lockdown e le moderne misure di hardening di Android potrebbero impedirne il caricamento.<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Linee guida per la computer forensics dei dispositivi mobili](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Attacchi Smudge sui touchscreen degli smartphone](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Restrizione del backup ADB in Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
