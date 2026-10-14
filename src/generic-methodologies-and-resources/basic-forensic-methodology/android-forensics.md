# Uchunguzi wa Kiforensiki wa Android

{{#include ../../banners/hacktricks-training.md}}

## Kifaa Kilichofungwa

Pendelea mbinu za kupata data zinazohifadhi hali ya kifaa na uandike kila hatua. Ikiwa kifaa kimefungwa, chaguo zinazopatikana hutegemea modeli, toleo la Android, kiwango cha patch, na iwapo ufikiaji ulisanidiwa kabla ya kifaa kukamatwa. NIST inapendekeza kuchagua mbinu kulingana na kifaa na mamlaka ya uchunguzi.<sup>[[1]](#references)</sup>

- Angalia iwapo USB debugging ilikuwa imewashwa na iwapo kituo cha kazi cha upatikanaji data tayari kimeidhinishwa. Ufikiaji wa ADB kwa kawaida huhitaji mtumiaji kufungua kifaa na kuthibitisha ufunguo wa RSA wa kituo cha kazi.<sup>[[3]](#references)</sup>
- Fikiria iwapo ufikiaji wa kibayometriki bado unapatikana chini ya sheria na taratibu zinazotumika.
- **Smudge attack** inaweza kufichua mchoro wa kufungua kifaa kwa kutumia mabaki kwenye skrini, ingawa miguso ya baadaye na usafishaji hupunguza uaminifu wake.<sup>[[2]](#references)</sup>
- Pale ambapo zana zilizoidhinishwa zinaunga mkono kifaa na toleo mahususi la programu, zinaweza kujaribu kurejesha au kufanya brute force ya PIN, nenosiri au mchoro. Uthibitishaji wa kitambulisho unaotegemea maunzi, ucheleweshaji wa majaribio na sera za kufuta data hufanya hili litegemee sana kifaa husika. Kwa hiyo, usitumie mbinu au matokeo ya iPhone kama ushahidi kwamba kifaa cha Android kinaungwa mkono.<sup>[[1]](#references)</sup>

## Ukusanyaji wa data

Kwenye vifaa vya zamani, [ADB backup](../../mobile-pentesting/android-app-pentesting/adb-commands.md#legacy-adb-backup) ya zamani inaweza kutoa faili ya `.backup` ambayo Android Backup Extractor inaweza kufungua:<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

Usidhani kuwa hii inajumuisha kila programu. ADB inaweka lebo kuwa amri imepitwa na wakati, na Android 12 haitoi data ya programu zinazolenga API level 31 au matoleo mapya zaidi isipokuwa programu iweze kufanyiwa debug.<sup>[[4]](#references)</sup>

### Root au ufikiaji wa debug wa kimwili

Ukiwa na ufikiaji wa root kwenye kifaa kinachofanya kazi, kwanza orodhesha partitions na mounts; amri zilizo hapa chini hazitumiki moja kwa moja kwa upataji wa kimwili wa JTAG. Block device sahihi hutegemea maunzi, kwa hivyo usidhani kuwa daima ni `mmcblk0`. Tengeneza image ya chanzo kilichothibitishwa pekee, na uihifadhi kwenye hifadhi tofauti:<sup>[[1]](#references)</sup>

Upataji wa JTAG badala yake hutumia kiolesura cha majaribio cha maunzi cha kifaa na vifaa vya upataji vinavyooana ili kusoma kumbukumbu inayoweza kufikiwa. Pinout, usaidizi wa chipset, hali ya kifaa, na tofauti kati ya malengo tete na yasiyo tete hutegemea kifaa; andika njia ya maunzi na utumie utaratibu uliothibitishwa kwa modeli hiyo.<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

Kwa mfano, ikiwa orodha ya partitions inathibitisha kuwa `/dev/block/mmcblk0` ndiyo kifaa kizima cha flash na eneo lengwa lina nafasi ya kutosha, amri ya awali ya kupata nakala inakuwa:<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

Hapa, `df /data` husaidia kuhusisha `/data` na filesystem iliyopachikwa; haipaswi kuchukuliwa kama uthibitisho kwamba `mmcblk0` ndiyo chanzo sahihi cha kifaa kizima au kwamba `4096` ndiyo ukubwa pekee halali wa block wa `dd`.

Hesabu hash ya matokeo na urekodi amri kamili, vitambulishi vya kifaa, muda, na mabadiliko yoyote yaliyofanywa wakati wa upataji.<sup>[[1]](#references)</sup>

### Kumbukumbu

LiME inaweza kupata kumbukumbu halisi kutoka Linux na baadhi ya vifaa vya Android, lakini moduli yake ya kernel lazima ijengwe kwa ajili ya kernel ya kifaa lengwa na ipakiwe ikiwa na ruhusa za kutosha. Kusaini moduli, kernel lockdown, na uimarishaji wa kisasa wa Android vinaweza kuzuia moduli hiyo kupakiwa.<sup>[[5]](#references)</sup>

Mchakato wa Android wa mradi huu hutuma moduli inayolingana kwa kutumia ADB, huforward TCP port, hupakia moduli kutoka kwenye root shell, na kunasa mtiririko kwenye host ya uchunguzi:<sup>[[5]](#references)</sup>

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

LiME inaweza badala yake kuandika kwenye hifadhi ya kifaa kwa kutumia `path=/sdcard/ram.lime`, lakini hilo hubadilisha hifadhi ya kifaa na linahitaji nafasi ya kutosha. Rekodi athari hiyo ya kando na uhesabu hash ya image iliyopatikana.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Miongozo ya Forensics ya Vifaa vya Simu](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smudge Attacks kwenye Skrini za Kugusa za Smartphone](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Kizuizi cha Android 12 cha ADB backup](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Kichimbaji cha Kumbukumbu cha Linux (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../../banners/hacktricks-training.md}}
