# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Geslote Toestel

Verkies acquisition methods wat die toestel se toestand behou, en dokumenteer elke handeling. As die toestel gesluit is, hang die beskikbare opsies af van die model, Android-weergawe, patch level en of toegang vóór beslaglegging gekonfigureer is. NIST beveel aan dat ’n metode volgens die toestel en die bevoegdheid vir die ondersoek gekies word.<sup>[[1]](#references)</sup>

- Kontroleer of USB debugging geaktiveer was en of die acquisition workstation reeds gemagtig is. ADB-toegang vereis normaalweg dat die gebruiker die toestel ontsluit en die workstation se RSA key bevestig.<sup>[[3]](#references)</sup>
- Oorweeg of biometriese toegang steeds beskikbaar is ingevolge die toepaslike regs- en prosedurereëls.
- ’n **smudge attack** kan ’n grafiese ontsluitpatroon uit oorblyfsels op die skerm onthul, hoewel daaropvolgende aanrakinge en skoonmaak die betroubaarheid daarvan verminder.<sup>[[2]](#references)</sup>
- Waar gemagtigde tooling die presiese toestel en software build ondersteun, kan dit probeer om PIN-, wagwoord- of patroonherwinning of brute force uit te voer. Hardware-backed credential verification, retry delays en wipe policies maak dit hoogs toestelspesifiek; moet dus nie ’n iPhone-tegniek of -resultaat vervang vir bewys dat ’n Android-toestel ondersteun word nie.<sup>[[1]](#references)</sup>

## Data acquisition

Op ouer toestelle kan ’n legacy [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) ’n `.backup`-lêer produseer wat Android Backup Extractor kan uitpak:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Moenie aanvaar dat dit elke toepassing dek nie. ADB merk die opdrag as verouderd, en Android 12 sluit data van toepassings wat op API-vlak 31 of later teiken uit, tensy die toepassing debuggable is.<sup>[[4]](#references)</sup>

### Root- of fisiese debug-toegang

Met root-toegang op 'n aktiewe toestel, inventariseer eers die partisies en mounts; die opdragte hieronder is nie direk op 'n fisiese JTAG-acquisition van toepassing nie. Die korrekte bloktoestel is hardeware-afhanklik, dus moenie aanvaar dat dit altyd `mmcblk0` is nie. Skryf slegs die geverifieerde bron na aparte berging:<sup>[[1]](#references)</sup>

'n JTAG-acquisition gebruik eerder die toestel se hardeware-toegangskoppelvlak vir toetsing en versoenbare acquisition-toerusting om toeganklike geheue te lees. Pinout, chipset-ondersteuning, toesteltoestand en die onderskeid tussen vlugtige en nie-vlugtige teikens is toestelspesifiek; dokumenteer die hardewarepad en gebruik 'n gevalideerde prosedure vir daardie model.<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Byvoorbeeld, indien die partisielys bevestig dat `/dev/block/mmcblk0` die hele flash-toestel is en die bestemming genoeg spasie het, word die oorspronklike verkrygingsopdrag:<sup>[[1]](#references)</sup>
```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```
Hier help `df /data` om `/data` met sy gemonteerde filesystem te assosieer; dit moet nie beskou word as bewys dat `mmcblk0` die korrekte whole-device source is of dat `4096` die enigste geldige `dd` block size is nie.

Hash die resultaat en teken die presiese command, device identifiers, tyd en enige changes wat tydens acquisition gemaak is, aan.<sup>[[1]](#references)</sup>

### Geheue

LiME kan physical memory van Linux en sommige Android devices acquire, maar sy kernel module moet vir die target kernel gebou en met voldoende privileges gelaai word. Module signing, kernel lockdown en moderne Android hardening kan verhoed dat dit laai.<sup>[[5]](#references)</sup>

Die projek se Android workflow push die matching module met ADB, forward ’n TCP-port, laai die module vanuit ’n root shell, en capture die stream op die examination host:<sup>[[5]](#references)</sup>
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
LiME kan eerder na toestelberging skryf met `path=/sdcard/ram.lime`, maar dit verander die toestel se berging en vereis genoeg vrye ruimte. Teken daardie newe-effek aan en bereken die hash van die verkrygde image.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Riglyne vir mobieletoestelforensika](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smeerlaakaanvalle op slimfoont raakskerms](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB-rugsteunbeperking](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
