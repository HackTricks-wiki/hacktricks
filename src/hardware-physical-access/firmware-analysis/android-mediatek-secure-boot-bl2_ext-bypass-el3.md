# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaandika kuvunjwa kwa secure-boot kwa vitendo kwenye majukwaa kadhaa za MediaTek kwa kutumia mapengo ya uthibitishaji wakati usanidi wa bootloader wa kifaa (seccfg) uko "unlocked". Kasoro hii inaruhusu kuendesha bl2_ext iliyorekebishwa kwenye ARM EL3 ili kuzima uthibitishaji wa saini kwa sehemu zinazofuata, kuvunja mnyororo wa uaminifu na kuruhusu kupakia TEE/GZ/LK/Kernel zisizosainiwa kwa hiari.

> Tahadhari: Kurekebisha mapema wakati wa boot kunaweza kuharibu kabisa vifaa ikiwa offsets si sahihi. Daima hifadhi dumps kamili na njia ya kupona ya kuaminika.

## Mtiririko wa boot uliyoathiriwa (MediaTek)

- Njia ya kawaida: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Njia yenye udhaifu: Wakati seccfg imewekwa kuwa "unlocked", Preloader inaweza kuruka kuthibitisha bl2_ext. Preloader bado inaruka ndani ya bl2_ext kwa EL3, hivyo bl2_ext iliyotengenezwa inaweza kupakia vipengele visivyoidhinishwa baadaye.

Mkatao muhimu wa uaminifu:
- bl2_ext inatekelezwa kwenye EL3 na ina jukumu la kuthibitisha TEE, GenieZone, LK/AEE na kernel. Ikiwa bl2_ext yenyewe haijaidhinishwa, mnyororo wa uaminifu unaweza kupitishwa kwa urahisi.

## Sababu ya mzizi

Kwenye vifaa vilivyoathiriwa, Preloader haitekelezi sharti la uthibitisho kwa sehemu ya bl2_ext wakati seccfg inaonyesha hali ya "unlocked". Hii inaruhusu kuflash bl2_ext inayoendeshwa na mshambuliaji ambayo inaendesha kwenye EL3.

Ndani ya bl2_ext, kazi ya sera ya uthibitishaji inaweza kurekebishwa ili kuripoti bila masharti kuwa uthibitishaji hauhitajiki. Patch ya kimsingi ya dhana ni:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Kwa mabadiliko haya, picha zote zinazofuata (TEE, GZ, LK/AEE, Kernel) zinakubaliwa bila ukaguzi wa kriptografia zinapopakiwa na bl2_ext iliyorekebishwa inayotekelezwa kwenye EL3.

## Jinsi ya kuchambua lengo (expdb logs)

Toa/chunguza boot logs (e.g., expdb) karibu na upakiaji wa bl2_ext. Ikiwa img_auth_required = 0 na certificate verification time ni ~0 ms, enforcement huenda umezimwa na kifaa kinaweza kutumiwa.

Mfano wa kipande cha log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Kumbuka: Vifaa vingine imeripotiwa kuruka uthibitishaji wa bl2_ext hata wakati bootloader imefungwa, jambo ambalo linaongeza athari.

Vifaa vinavyokuja na lk2 secondary bootloader vimeonekana kuwa na pengo la mantiki sawa, hivyo chukua expdb logs kwa partitions za bl2_ext na lk2 ili kuthibitisha ikiwa mojawapo ya njia hizo inatekeleza signatures kabla ya kujaribu porting.

## Mtiririko wa exploitation wa vitendo (Fenrir PoC)

Fenrir ni reference exploit/patching toolkit kwa aina hii ya tatizo. Inasaidia Nothing Phone (2a) (Pacman) na inajulikana kufanya kazi (kwa usaidizi usio kamili) kwenye CMF Phone 1 (Tetris). Porting kwa modeli nyingine inahitaji reverse engineering ya bl2_ext maalum kwa kifaa.

Mchakato wa kiwango cha juu:
- Pata device bootloader image kwa target codename yako na uiweke kama `bin/<device>.bin`
- Jenga patched image inayozima sera ya uthibitishaji ya bl2_ext
- Flash payload iliyotokana kwenye kifaa (fastboot inachukuliwa na helper script)

Amri:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
Iwapo fastboot haipatikani, lazima utumie mbinu mbadala ya flashing inayofaa kwa jukwaa lako.

### Uendeshaji wa ujenzi & debugging ya payload

- `build.sh` sasa inapakua kiotomatiki na ku-export Arm GNU Toolchain 14.2 (aarch64-none-elf) mara ya kwanza unapoendesha, hivyo huhitaji kusimamia cross-compilers kwa mikono.
- Export `DEBUG=1` kabla ya kuita `build.sh` ili kukusanya payloads zenye verbose serial prints, jambo ambalo linasadia sana unapofanya blind-patching ya njia za code za EL3.
- Ujenzi uliofanikiwa hutoa `lk.patched` na `<device>-fenrir.bin`; faili ya mwisho tayari ina payload iliyojazwa ndani na ndiyo unayopaswa flash/boot-test.

## Uwezo wa payload wakati wa utekelezaji (EL3)

Payload ya bl2_ext patched inaweza:
- Sajili amri za fastboot za desturi
- Dhibiti/override boot mode
- Kuita kwa wakati functions za built‑in bootloader wakati wa runtime
- Spoof “lock state” kama locked ilhali iko unlocked ili kupitisha ukaguzi wa uadilifu wenye nguvu zaidi (mazingira mengine yanaweza bado kuhitaji marekebisho ya vbmeta/AVB)

Kizuizi: PoCs za sasa zinaeleza kuwa urekebishaji wa memory wakati wa runtime unaweza kusababisha fault kutokana na vizingiti vya MMU; payloads kwa ujumla huweka kuepuka kuandika memory za moja kwa moja hadi hili litakaposuluhishwa.

## Payload staging patterns (EL3)

Fenrir inagawa instrumentation yake katika hatua tatu za compile-time: stage1 inaendesha kabla ya `platform_init()`, stage2 inaendesha kabla LK inapotuma ishara ya kuingia fastboot, na stage3 inaendesha mara moja kabla LK inapopakua Linux. Kila header ya kifaa chini ya `payload/devices/` hutoa anuani za hooks hizi pamoja na symbols za msaada za fastboot, hivyo hakikisha offsets hizo zinaendana na build unayolenga.

Stage2 ni eneo lenye urahisi kusajili verbs za `fastboot oem`:
```c
void cmd_r0rt1z2(const char *arg, void *data, unsigned int sz) {
video_printf("r0rt1z2 was here...\n");
fastboot_info("pwned by r0rt1z2");
fastboot_okay("");
}

__attribute__((section(".text.main"))) void main(void) {
fastboot_register("oem r0rt1z2", cmd_r0rt1z2, true, false);
notify_enter_fastboot();
}
```
Stage3 inaonyesha jinsi ya kwa muda kubadilisha page-table attributes ili kupachika immutable strings kama onyo la Android "Orange State" bila kuhitaji downstream kernel access:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Kwa sababu stage1 hufanyika kabla ya platform bring-up, ni mahali sahihi kuwaita OEM power/reset primitives au kuingiza additional integrity logging kabla verified boot chain huvunjwa.

## Vidokezo vya kuhamishaji

- Reverse engineer bl2_ext ya kifaa ili kupata mantiki ya verification policy (mfano, sec_get_vfy_policy).
- Tambua tovuti ya kurudisha polisi au tawi la uamuzi na patch ili “no verification required” (return 0 / unconditional allow).
- Hifadhi offsets ziwe maalum kabisa kwa kifaa na firmware; usitumie anwani kati ya variants tofauti.
- Thibitisha kwanza kwenye unit ya kujitoa. Andaa mpango wa recovery (mfano, EDL/BootROM loader/SoC-specific download mode) kabla ya kuflash.
- Vifaa vinavyotumia lk2 secondary bootloader au kuripoti “img_auth_required = 0” kwa bl2_ext hata wakati vimefungwa vinapaswa kutendewa kama nakala zilizo na udhaifu wa aina hii ya bug; Vivo X80 Pro tayari imeonekana kuruka verification licha ya kuripotiwa kuwa kwenye lock state.
- Linganisha expdb logs kutoka katika states zote mbili za locked na unlocked—ikiwa certificate timing inaruka kutoka 0 ms hadi thamani isiyo sifuri mara tu utakaporilock, kuna uwezekano umepatch decision point sahihi lakini bado unahitaji kuimarisha lock-state spoofing ili kuficha mabadiliko.

## Athari za usalama

- Utekelezaji wa code ya EL3 baada ya Preloader na kuyeyuka kwa full chain-of-trust kwa sehemu iliyobaki ya boot path.
- Uwezo wa boot unsigned TEE/GZ/LK/Kernel, kuzunguka secure/verified boot expectations na kuruhusu compromise endelevu.

## Vidokezo kuhusu vifaa

- Imethibitishwa inasaidiwa: Nothing Phone (2a) (Pacman)
- Inajulikana inafanya kazi (msaada usio kamili): CMF Phone 1 (Tetris)
- Imetambuliwa: Vivo X80 Pro imearifiwa kuwa haikufanya verification ya bl2_ext hata wakati imefungwa
- Ufunuo wa tasnia unaonyesha wauzaji wateule wa msingi wa lk2 wakisafirisha kasoro ile ile ya mantiki, hivyo tarajia mwendelezo wa ulinganifu katika releases za MTK za 2024–2025.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}
