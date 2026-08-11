# Uchunguzi wa Android

{{#include ../banners/hacktricks-training.md}}

## Kifaa kilichofungwa

Pendelea mbinu za acquisition zinazohifadhi hali ya kifaa, na uandike kila hatua iliyochukuliwa. Ikiwa kifaa kimefungwa, chaguo zinazopatikana hutegemea modeli, toleo la Android, kiwango cha patch, na ikiwa access iliwekwa kabla ya kifaa kukamatwa. NIST inapendekeza kuchagua mbinu kulingana na kifaa na mamlaka ya uchunguzi.<sup>[[1]](#references)</sup>

- Kagua ikiwa USB debugging ilikuwa imewezeshwa na ikiwa workstation ya acquisition tayari ilikuwa imeidhinishwa. Access ya ADB kwa kawaida huhitaji mtumiaji kufungua kifaa na kuthibitisha RSA key ya workstation.<sup>[[3]](#references)</sup>
- Fikiria ikiwa access ya biometric bado inapatikana chini ya sheria na taratibu zinazotumika.
- **smudge attack** inaweza kufichua mchoro wa graphical unlock kutokana na mabaki kwenye skrini, ingawa miguso ya baadaye na kusafisha hupunguza uaminifu wake.<sup>[[2]](#references)</sup>
- Tumia lock-bypass tooling ya kibiashara au ya utafiti tu ikiwa inasaidia wazi kifaa na software build husika.

## Ukusanyaji wa data

Kwenye vifaa vya zamani, [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) ya zamani inaweza kutoa faili ya `.backup` ambayo Android Backup Extractor inaweza kufungua:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Usidhani kuwa hii inajumuisha kila application. ADB inaweka lebo ya command kuwa deprecated, na Android 12 haijumuishi data kutoka kwa apps zinazolenga API level 31 au ya baadaye isipokuwa app iwe debuggable.<sup>[[4]](#references)</sup>

### Ufikiaji wa root au debug wa kimwili

Ukiwa na ufikiaji wa root kwenye kifaa kinachofanya kazi, anza kwa kuorodhesha partitions na mounts; commands zilizo hapa chini hazitumiki moja kwa moja kwenye physical JTAG acquisition. Block device sahihi hutegemea hardware, kwa hivyo usidhani kuwa daima ni `mmcblk0`. Tengeneza image ya source iliyothibitishwa pekee kwenye storage tofauti:<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Hashi matokeo na uandike amri kamili, vitambulisho vya kifaa, muda, na mabadiliko yoyote yaliyofanywa wakati wa acquisition.<sup>[[1]](#references)</sup>

### Memory

LiME inaweza kupata memory halisi kutoka Linux na baadhi ya vifaa vya Android, lakini kernel module yake lazima ijengwe kwa kernel inayolengwa na ipakizwe ikiwa na privileges za kutosha. Module signing, kernel lockdown, na Android hardening ya kisasa vinaweza kuizuia kupakiwa.<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Miongozo kuhusu Mobile Device Forensics](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Mashambulizi ya Smudge kwenye Skrini za Kugusa za Smartphone](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Kizuizi cha ADB backup cha Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
