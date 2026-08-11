# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Geslote Toestel

Verkies verkrygingsmetodes wat die toestel se toestand bewaar, en dokumenteer elke handeling. As die toestel gesluit is, hang die beskikbare opsies af van die model, Android-weergawe, patchvlak en of toegang voor beslaglegging opgestel is. NIST beveel aan dat ’n metode volgens die toestel en die magtiging vir die ondersoek gekies word.<sup>[[1]](#references)</sup>

- Kontroleer of USB debugging geaktiveer was en of die verkrygingswerkstasie reeds gemagtig is. ADB-toegang vereis normaalweg dat die gebruiker die toestel ontsluit en die werkstasie se RSA-sleutel bevestig.<sup>[[3]](#references)</sup>
- Oorweeg of biometriese toegang steeds beskikbaar is ingevolge die toepaslike wetlike en prosedurele reëls.
- ’n **smudge attack** kan ’n grafiese ontsluitpatroon uit oorblyfsels op die skerm onthul, hoewel latere aanrakinge en skoonmaak die betroubaarheid daarvan verminder.<sup>[[2]](#references)</sup>
- Gebruik kommersiële of navorsingsgerigte lock-bypass tooling slegs wanneer dit uitdruklik die presiese toestel en sagteware-bou ondersteun.

## Data-verkryging

Op ouer toestelle kan ’n legacy [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) ’n `.backup`-lêer produseer wat Android Backup Extractor kan uitpak:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Moenie aanvaar dat dit elke toepassing vasvang nie. ADB merk die opdrag as deprecated, en Android 12 sluit data uit van toepassings wat op API-vlak 31 of later teiken, tensy die toepassing debuggable is.<sup>[[4]](#references)</sup>

### Root- of fisiese debug-toegang

Met root-toegang op ’n aktiewe toestel, inventariseer eers die partisies en mounts; die opdragte hieronder is nie direk op ’n fisiese JTAG-acquisition van toepassing nie. Die korrekte bloktoestel is hardeware-afhanklik, dus moenie aanvaar dat dit altyd `mmcblk0` is nie. Image slegs die geverifieerde bron na aparte stoorspasie:<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Hash die resultaat en teken die presiese command, device identifiers, tyd en enige veranderinge wat tydens acquisition gemaak is, aan.<sup>[[1]](#references)</sup>

### Geheue

LiME kan physical memory van Linux en sommige Android-toestelle acquire, maar sy kernel module moet vir die target kernel gebou en met voldoende privileges gelaai word. Module signing, kernel lockdown en moderne Android hardening kan voorkom dat dit laai.<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Riglyne oor Mobile Device Forensics](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smudge Attacks op Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB backup restriction](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
