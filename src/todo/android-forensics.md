# Forensics ya Android

{{#include ../banners/hacktricks-training.md}}

## Kifaa Kilichofungwa

Pendelea mbinu za acquisition zinazohifadhi hali ya kifaa na uandike kila hatua iliyofanywa. Ikiwa kifaa kimefungwa, chaguo zinazopatikana hutegemea model, toleo la Android, kiwango cha patch, na ikiwa access iliwekwa kabla ya kifaa kukamatwa. NIST inapendekeza kuchagua mbinu kulingana na kifaa na mamlaka ya uchunguzi.<sup>[[1]](#references)</sup>

- Kagua ikiwa USB debugging ilikuwa imewashwa na ikiwa workstation ya acquisition tayari imeidhinishwa. Kwa kawaida, ADB access huhitaji mtumiaji kufungua kifaa na kuthibitisha RSA key ya workstation.<sup>[[3]](#references)</sup>
- Zingatia ikiwa biometric access bado inapatikana chini ya sheria na taratibu husika.
- **Smudge attack** inaweza kufichua graphical unlock pattern kutokana na mabaki kwenye skrini, ingawa touch za baadaye na kusafisha hupunguza uaminifu wake.<sup>[[2]](#references)</sup>
- Pale ambapo tooling iliyoidhinishwa inasaidia kifaa na software build husika, inaweza kujaribu kurejesha au kufanya brute force ya PIN, password, au pattern. Hardware-backed credential verification, retry delays, na wipe policies hufanya hili litofautiane sana kulingana na kifaa; kwa hiyo, usibadilishe technique au matokeo ya iPhone na kuyatumia kama ushahidi kwamba kifaa cha Android kinaungwa mkono.<sup>[[1]](#references)</sup>

## Upatikanaji wa data

Kwenye vifaa vya zamani, [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) ya legacy inaweza kutoa faili la `.backup` ambalo Android Backup Extractor inaweza kulifungua:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Usidhani kuwa hii inahusisha kila application. ADB inaweka lebo ya amri hii kuwa deprecated, na Android 12 haijumuishi data kutoka kwa apps zinazolenga API level 31 au ya baadaye isipokuwa app iwe debuggable.<sup>[[4]](#references)</sup>

### Root au ufikiaji wa kimwili wa debug

Ukiwa na root access kwenye kifaa kinachofanya kazi, kwanza tengeneza orodha ya partitions na mounts; amri zilizo hapa chini hazitumiki moja kwa moja kwenye physical JTAG acquisition. Block device sahihi hutegemea hardware, kwa hivyo usidhani kuwa daima ni `mmcblk0`. Tengeneza image ya source iliyothibitishwa pekee na kuihifadhi kwenye storage tofauti:<sup>[[1]](#references)</sup>

JTAG acquisition badala yake hutumia hardware test-access interface ya kifaa na vifaa vinavyooana vya acquisition ili kusoma memory inayoweza kufikiwa. Pinout, chipset support, hali ya kifaa, na tofauti kati ya volatile na non-volatile targets hutegemea kifaa; andika hardware path na utumie utaratibu uliothibitishwa kwa model hiyo.<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Kwa mfano, ikiwa orodha ya partitions inathibitisha kwamba `/dev/block/mmcblk0` ni kifaa kizima cha flash na eneo lengwa lina nafasi ya kutosha, amri ya awali ya acquisition inakuwa:<sup>[[1]](#references)</sup>
```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```
Hapa, `df /data` husaidia kuhusisha `/data` na filesystem yake iliyomountiwa; haipaswi kuchukuliwa kama uthibitisho kwamba `mmcblk0` ndiyo source sahihi ya kifaa kizima au kwamba `4096` ndiyo ukubwa pekee halali wa block wa `dd`.

Fanya Hash ya matokeo na urekodi command kamili, vitambulisho vya kifaa, muda, na mabadiliko yoyote yaliyofanywa wakati wa acquisition.<sup>[[1]](#references)</sup>

### Kumbukumbu

LiME inaweza kupata physical memory kutoka Linux na baadhi ya vifaa vya Android, lakini kernel module yake lazima ijengwe kwa target kernel na ipakiwe ikiwa na privileges za kutosha. Module signing, kernel lockdown, na Android hardening ya kisasa vinaweza kuizuia kupakiwa.<sup>[[5]](#references)</sup>

Workflow ya Android ya mradi huu inasafirisha module inayolingana kwa kutumia ADB, inaforward TCP port, inapakia module kutoka root shell, na inakamata stream kwenye examination host:<sup>[[5]](#references)</sup>
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
LiME inaweza badala yake kuandika kwenye hifadhi ya kifaa kwa `path=/sdcard/ram.lime`, lakini hilo hubadilisha hifadhi ya kifaa na linahitaji nafasi ya kutosha iliyo wazi. Rekodi athari hiyo na ufanye hash ya image iliyopatikana.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Miongozo ya Forensics ya Vifaa vya Mkononi](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Mashambulizi ya Smudge kwenye Skrini za Kugusa za Smartphone](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Kizuizi cha Android 12 cha ADB backup](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
