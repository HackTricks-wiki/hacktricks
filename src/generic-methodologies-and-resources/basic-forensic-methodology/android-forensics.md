# Android-forensiese ondersoek

{{#include ../../banners/hacktricks-training.md}}

## Geslote toestel

Verkies verkrygingsmetodes wat die toestand van die toestel bewaar, en dokumenteer elke handeling. As die toestel gesluit is, hang die beskikbare opsies af van die model, Android-weergawe, pleistervlak en of toegang voor beslaglegging opgestel is. NIST beveel aan dat ’n metode gekies word volgens die toestel en die magtiging vir die ondersoek.<sup>[[1]](#references)</sup>

- Kyk of USB-ontfouting geaktiveer was en of die verkrygingswerkstasie reeds gemagtig is. ADB-toegang vereis gewoonlik dat die gebruiker die toestel ontsluit en die werkstasie se RSA-sleutel bevestig.<sup>[[3]](#references)</sup>
- Oorweeg of biometriese toegang steeds beskikbaar is ingevolge die toepaslike regs- en prosedurereëls.
- ’n **smudge attack** kan ’n grafiese ontsluitpatroon aan die hand van oorblyfsels op die skerm verklap, hoewel latere aanrakinge en skoonmaak die betroubaarheid daarvan verminder.<sup>[[2]](#references)</sup>
- Waar gemagtigde gereedskap die presiese toestel en sagtewarebou ondersteun, kan dit probeer om ’n PIN, wagwoord of patroon te herstel of met brute force te kraak. Hardewaregebaseerde geloofsbriewe-verifikasie, wagtye tussen pogings en uitveebeleide maak dit hoogs toestelspesifiek. Moet dus nie ’n iPhone-tegniek of -resultaat gebruik as bewys dat ’n Android-toestel ondersteun word nie.<sup>[[1]](#references)</sup>

## Data-verkryging

Op ouer toestelle kan ’n verouderde [ADB-rugsteun](../../mobile-pentesting/android-app-pentesting/adb-commands.md#legacy-adb-backup) ’n `.backup`-lêer oplewer wat Android Backup Extractor kan uitpak:<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

Moenie aanvaar dat dit elke toepassing vaslê nie. ADB merk die opdrag as verouderd, en Android 12 sluit data uit programme wat op API-vlak 31 of later teiken, tensy die toepassing ontfoutbaar is.<sup>[[4]](#references)</sup>

### Root- of fisiese ontfoutingstoegang

Met root-toegang op ’n aktiewe toestel, inventariseer eers die partisies en mount-punte; die opdragte hieronder is nie direk van toepassing op ’n fisiese JTAG-verkryging nie. Die korrekte bloktoestel hang van die hardeware af, dus moet jy nie aanvaar dat dit altyd `mmcblk0` is nie. Skep ’n image van slegs die geverifieerde bron na aparte berging:<sup>[[1]](#references)</sup>

’n JTAG-verkryging gebruik eerder die toestel se hardeware-koppelvlak vir toetstoegang en versoenbare verkrygingstoerusting om toeganklike geheue te lees. Die penuitleg, skyfiestelondersteuning, toesteltoestand en onderskeid tussen vlugtige en nie-vlugtige teikens is toestelspesifiek; dokumenteer die hardewarepad en gebruik ’n gevalideerde prosedure vir daardie model.<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

Byvoorbeeld, indien die partisie-inventaris bevestig dat `/dev/block/mmcblk0` die hele flitsgeheue-toestel is en die bestemming genoeg spasie het, word die oorspronklike verkrygingsopdrag:<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

Hier help `df /data` om `/data` met sy gemonteerde lêerstelsel te assosieer; dit moet nie as bewys beskou word dat `mmcblk0` die korrekte bron vir die hele toestel is of dat `4096` die enigste geldige `dd`-blokgrootte is nie.

Bereken ’n hash van die resultaat en teken die presiese opdrag, toestelidentifiseerders, tyd en enige veranderinge wat tydens verkryging gemaak is, aan.<sup>[[1]](#references)</sup>

### Geheue

LiME kan fisiese geheue van Linux- en sommige Android-toestelle verkry, maar die kernmodule daarvan moet vir die teikenkern gebou en met voldoende voorregte gelaai word. Module-ondertekening, kerninperking en moderne Android-verharding kan verhoed dat dit laai.<sup>[[5]](#references)</sup>

Die projek se Android-werkvloei stoot die ooreenstemmende module met ADB, stuur ’n TCP-poort aan, laai die module vanuit ’n root-shell en neem die stroom op die ondersoekgasheer vas:<sup>[[5]](#references)</sup>

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

LiME kan eerder na toestelberging skryf met `path=/sdcard/ram.lime`, maar dit verander die toestel se berging en vereis genoeg vrye spasie. Teken dié newe-effek aan en has die verkrygde beeld.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Riglyne vir forensiese ondersoek van mobiele toestelle](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smudge-aanvalle op slimfoonskerms](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB-rugsteunbeperking](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../../banners/hacktricks-training.md}}
