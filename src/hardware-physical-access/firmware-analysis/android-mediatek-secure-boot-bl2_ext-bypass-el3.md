# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaelezea kuvunjwa kwa vitendo kwa secure-boot kwenye platform nyingi za MediaTek kwa kutumia pengo la uthibitishaji wakati configuration ya bootloader ya kifaa (seccfg) iko "unlocked". Hitilafu hii inaruhusu kuendesha bl2_ext iliyopigwa patch kwenye ARM EL3 ili kuzima uthibitishaji wa saini wa sehemu zinazofuata, kuangusha chain of trust na kuwezesha upakiaji wa TEE/GZ/LK/Kernel zisizotia saini.

> Caution: Early-boot patching can permanently brick devices if offsets are wrong. Always keep full dumps and a reliable recovery path.

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Key trust boundary:
- bl2_ext executes at EL3 and is responsible for verifying TEE, GenieZone, LK/AEE and the kernel. If bl2_ext itself is not authenticated, the rest of the chain is trivially bypassed.

## Root cause

On affected devices, the Preloader does not enforce authentication of the bl2_ext partition when seccfg indicates an "unlocked" state. This allows flashing an attacker-controlled bl2_ext that runs at EL3.

Inside bl2_ext, the verification policy function can be patched to unconditionally report that verification is not required. A minimal conceptual patch is:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Kwa mabadiliko haya, picha zote zinazofuata (TEE, GZ, LK/AEE, Kernel) zinakubaliwa bila ukaguzi wa kriptografia wakati zinapopakiwa na bl2_ext iliyorekebishwa inayoendesha kwenye EL3.

## Jinsi ya kuchunguza lengo (expdb logs)

Dump/inspect boot logs (e.g., expdb) karibu na bl2_ext load. Ikiwa img_auth_required = 0 na certificate verification time ni takriban ~0 ms, kuna uwezekano kwamba enforcement imezimwa na kifaa kinaweza kuwa exploitable.

Sehemu ya logi ya mfano:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Kumbuka: Kuna ripoti kwamba baadhi ya vifaa hupitisha ukaguzi wa bl2_ext hata ikiwa bootloader imefungwa, jambo ambalo huongeza athari.

Vifaa vinavyoambatana na lk2 secondary bootloader vimeonekana kuwa na pengo la kimantiki sawa, hivyo pata expdb logs za partitions za bl2_ext na lk2 ili kuthibitisha kama mojawapo ya njia hizo inatekeleza signatures kabla ya kujaribu porting.

Ikiwa post-OTA Preloader sasa inarekodi img_auth_required = 1 kwa bl2_ext hata wakati seccfg imefunguliwa, vendor huenda amefunga pengo hilo—angalia maelezo ya OTA persistence hapa chini.

## Mtiririko wa utekelezaji wa vitendo (Fenrir PoC)

Fenrir ni reference exploit/patching toolkit kwa aina hii ya tatizo. Inasaidia Nothing Phone (2a) (Pacman) na inajulikana kufanya kazi (kwa uunga mkono usio kamili) kwenye CMF Phone 1 (Tetris). Kuporting kwa modeli nyingine kunahitaji reverse engineering ya bl2_ext maalum kwa kifaa.

Muhtasari wa mchakato:
- Pata device bootloader image ya codename uliyolenga na weka kama `bin/<device>.bin`
- Jenga patched image inayozima bl2_ext verification policy
- Flash payload inayotokana kwenye kifaa (fastboot inadhaniwa na helper script)

Amri:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
Ikiwa fastboot haipatikani, unapaswa kutumia mbinu mbadala ya flashing inayofaa kwa jukwaa lako.

### OTA-patched firmware: kuendelea kuweka bypass hai (NothingOS 4, mwishoni mwa 2025)

Nothing ilirekebisha Preloader katika OTA thabiti ya NothingOS 4 ya Novemba 2025 (build BP2A.250605.031.A3) ili kulazimisha uthibitisho wa bl2_ext hata wakati seccfg imefunguliwa. Fenrir `pacman-v2.0` inafanya kazi tena kwa kuchanganya Preloader iliyoathirika kutoka NOS 4 beta na LK payload:
```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```
Important:
- Flash the provided Preloader **only** to the matching device/slot; Preloader isiyofaa ni hard brick mara moja.
- Kagua expdb baada ya flashing; img_auth_required inapaswa kurudi 0 kwa bl2_ext, ikithibitisha kwamba Preloader dhaifu inaendesha kabla ya patched LK yako.
- Ikiwa OTAs zijazo zitapataza Preloader na LK, hifadhi nakala ya ndani ya Preloader dhaifu ili kurejesha pengo.

### Build automation & payload debugging

- `build.sh` sasa inafanya auto-download na ku-export Arm GNU Toolchain 14.2 (aarch64-none-elf) mara ya kwanza unapoendesha, hivyo hauitaji kushughulikia cross-compilers kwa mikono.
- Export `DEBUG=1` kabla ya ku-invoke `build.sh` ili kukusanya payloads zenye verbose serial prints, jambo linalosaidia sana unapofanya blind-patching ya EL3 code paths.
- Builds zilizofanikiwa zinaangusha `lk.patched` na `<device>-fenrir.bin`; hii ya mwisho tayari ina payload imeingizwa na ndio unayopaswa flash/boot-test.

## Runtime payload capabilities (EL3)

Patched bl2_ext payload inaweza:
- Sajili amri maalum za fastboot
- Dhibiti/au kubadilisha boot mode
- Kuita kwa njia ya dynamic functions za bootloader zilizojengwa wakati wa runtime
- Udanganye “lock state” kuonekana locked ilhali kwa kweli unlocked, ili kupitisha ukaguzi mkali wa uadilifu (mazingira mengine bado yanaweza kuhitaji marekebisho ya vbmeta/AVB)

Kizuizi: PoCs za sasa zinaonyesha kwamba mabadiliko ya memory wakati wa runtime yanaweza kusababisha fault kutokana na vizuizi vya MMU; payloads kwa kawaida huiepuka kuandika memory moja kwa moja hadi tatizo lifanyiwe kazi.

## Payload staging patterns (EL3)

Fenrir inagawanya instrumentation yake katika hatua tatu za compile-time: stage1 inaendesha kabla ya `platform_init()`, stage2 inaendesha kabla ya LK kuashiria ingizo la fastboot, na stage3 inatekelezwa mara moja kabla ya LK kupakia Linux. Kila header ya kifaa chini ya `payload/devices/` hutoa addresses za hooks hizi pamoja na symbols za msaada wa fastboot, hivyo weka offsets hizo zikihusiana na target build yako.

Stage2 ni eneo rahisi la kusajili verbs yoyote za `fastboot oem`:
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
Stage3 inaonyesha jinsi ya kwa muda mfupi kubadili page-table attributes ili ku-patch immutable strings kama onyo la Android’s “Orange State” bila kuhitaji downstream kernel access:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Kwa sababu stage1 inaanzishwa kabla ya platform bring-up, ni sehemu sahihi ya kuita OEM power/reset primitives au kuingiza logging ya uadilifu ya ziada kabla ya verified boot chain kufutwa.

## Vidokezo vya Porting

- Fanya reverse engineer wa device-specific bl2_ext ili kupata mantiki ya polisi ya uthibitishaji (mf. sec_get_vfy_policy).
- Tambua site ya kurudisha polisi au tawi la uamuzi na uipachike ili “no verification required” (return 0 / unconditional allow).
- Weka offsets ziwe maalum kabisa kwa kifaa na firmware; usitumie addresses kati ya variants.
- Thibitisha kwanza kwenye kifaa cha majaribio. Andaa mpango wa urejeshaji (mf., EDL/BootROM loader/SoC-specific download mode) kabla ya ku-flash.
- Vifaa vinavyotumia lk2 secondary bootloader au kuripoti “img_auth_required = 0” kwa bl2_ext hata vikiwa vimefungwa vinapaswa kutendewa kama nakala zilizo hatarini za aina hii ya mdudu; Vivo X80 Pro tayari imeonekana kupita uthibitisho licha ya hali iliyoripotiwa ya kufungwa.
- Wakati OTA inaanza kutekeleza bl2_ext signatures (img_auth_required = 1) katika hali isiyofungwa, angalia kama Preloader wa zamani (mara nyingi upo katika beta OTAs) unaweza ku-flash kuifungua tena pengo, kisha re-run fenrir na offsets zilizosasishwa kwa LK mpya.

## Athari za usalama

- Utekelezaji wa code EL3 baada ya Preloader na kuanguka kwa full chain-of-trust kwa sehemu zote za mchakato wa boot.
- Uwezo wa ku-boot unsigned TEE/GZ/LK/Kernel, ukiepuka matarajio ya secure/verified boot na kuwezesha kompromisi ya kudumu.

## Vidokezo kuhusu vifaa

- Imethibitishwa kuungwa mkono: Nothing Phone (2a) (Pacman)
- Inajulikana kufanya kazi (msaada usio kamili): CMF Phone 1 (Tetris)
- Imeonekana: Vivo X80 Pro iliripotiwa kutokuwa inathibitisha bl2_ext hata wakati imefungwa
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) ilire-enabled tena uthibitishaji wa bl2_ext; fenrir `pacman-v2.0` inarejesha bypass kwa ku-flash beta Preloader pamoja na LK iliyopachikwa kama ilivyoonyeshwa hapo juu
- Ufunuo wa sekta unaonyesha wauzaji zaidi wanaotegemea lk2 wanaotuma hitilafu ileile ya mantiki, hivyo tarajia ulinganifu zaidi katika utolewaji wa MTK za 2024–2025.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}
