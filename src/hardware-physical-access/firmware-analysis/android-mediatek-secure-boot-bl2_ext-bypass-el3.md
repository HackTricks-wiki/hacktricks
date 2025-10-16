# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaelezea kuvunjwa kwa secure-boot kwa vitendo kwenye majukwaa mbalimbali ya MediaTek kwa kutumia pengo la uthibitisho wakati usanidi wa bootloader wa kifaa (seccfg) uko "unlocked". Hitilafu inaruhusu kuendesha bl2_ext iliyorekebishwa kwa ARM EL3 ili kuzima uthibitisho wa saini zinazofuata, kuangusha chain of trust na kuwezesha upakiaji wa TEE/GZ/LK/Kernel zisizo na saini yoyote.

> Tahadhari: Kupatchi mapema wakati wa boot kunaweza kufanya vifaa kuwa vilivyoharibika kabisa ikiwa offsets sio sahihi. Daima hifadhi dumps kamili na njia ya kupona inayotegemewa.

## Affected boot flow (MediaTek)

- Njia ya kawaida: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Njia dhaifu: Wakati seccfg imewekwa kuwa "unlocked", Preloader inaweza kuruka kuthibitisha bl2_ext. Preloader bado inaelea ndani ya bl2_ext kwa EL3, hivyo bl2_ext iliyotengenezwa inaweza kupakia vipengele visivyothibitishwa baadaye.

Mlipuko muhimu wa uaminifu:
- bl2_ext inaendesha kwa EL3 na inawajibika kuthibitisha TEE, GenieZone, LK/AEE na kernel. Ikiwa bl2_ext yenyewe haijathibitishwa, sehemu nyingine za chain zinaweza kupitishwa kwa urahisi.

## Root cause

Katika vifaa vilivyoathiriwa, Preloader haitekelezi uthibitishaji wa partition ya bl2_ext wakati seccfg inaonyesha hali ya "unlocked". Hii inaruhusu ku-flash bl2_ext inayodhibitiwa na mshambuliaji ambayo inaendesha kwa EL3.

Ndani ya bl2_ext, kazi ya sera ya uthibitisho inaweza kupatchiwa ili kuripoti bila masharti kuwa uthibitisho hauhitajiki. Patch ndogo ya dhana ni:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Kwa mabadiliko haya, images zote zinazofuata (TEE, GZ, LK/AEE, Kernel) zinakubaliwa bila ukaguzi wa kriptografia wakati zinapopakiwa na bl2_ext iliyorekebishwa inayotumia EL3.

## Jinsi ya kuchambua lengo (expdb logs)

Toa/angalia kumbukumbu za boot (kwa mfano, expdb) karibu na upakiaji wa bl2_ext. Ikiwa img_auth_required = 0 na muda wa uthibitishaji wa cheti ni ~0 ms, utekelezaji huenda umezimwa na kifaa kinaweza kushambuliwa.

Mfano wa kifungu cha logi:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Kumbuka: Vifaa vingine, kulingana na ripoti, hupita ukaguzi wa bl2_ext hata bootloader ikiwa imefungwa, jambo linaloongeza athari.

## Mtiririko wa utekelezaji wa exploitation (Fenrir PoC)

Fenrir ni toolkit ya marejeleo ya exploit/patching kwa aina hii ya tatizo. Inasaidia Nothing Phone (2a) (Pacman) na inajulikana kufanya kazi (kwa usaidizi usio kamili) kwenye CMF Phone 1 (Tetris). Kuhamisha kwa mifano mingine kunahitaji reverse engineering ya bl2_ext maalum kwa kifaa.

Mchakato wa ngazi ya juu:
- Pata image ya bootloader ya kifaa kwa codename unayolenga na uiweke kama bin/<device>.bin
- Jenga patched image inayozima sera ya ukaguzi ya bl2_ext
- Flash payload itokanayo kwenye kifaa (fastboot inachukuliwa na script ya msaada)

Amri:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

## Uwezo wa payload za runtime (EL3)

A patched bl2_ext payload can:
- Sajili amri maalum za fastboot
- Dhibiti/override boot mode
- Kuita kwa nguvu kazi za built‑in bootloader wakati wa runtime
- Spoof “lock state” kuwa locked wakati kwa kweli ni unlocked ili kupitisha ukaguzi wa uadilifu wenye nguvu (mazingira mengine yanaweza bado kuhitaji marekebisho ya vbmeta/AVB)

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## Vidokezo vya porting

- Fanya reverse engineering ya bl2_ext maalum kwa kifaa ili kupata mantiki ya sera ya uthibitisho (e.g., sec_get_vfy_policy).
- Tambua tovuti ya kurudishiwa sera au tawi la uamuzi na i-patch ili “no verification required” (return 0 / unconditional allow).
- Hifadhi offsets kuwa maalum kabisa kwa kifaa na firmware; usitumie tena anwani kati ya variants.
- Thibitisha kwanza kwenye kifaa cha majaribio. Andaa mpango wa urejeshaji (e.g., EDL/BootROM loader/SoC-specific download mode) kabla ya kuflash.

## Athari za usalama

- Utekelezaji wa code ya EL3 baada ya Preloader na collapse ya full chain-of-trust kwa sehemu iliyobaki ya boot path.
- Uwezo wa kuanzisha unsigned TEE/GZ/LK/Kernel, ukiepuka matarajio ya secure/verified boot na kuwezesha kompromisi ya kudumu.

## Mawazo ya utambuzi na hardening

- Hakikisha Preloader inathibitisha bl2_ext bila kujali hali ya seccfg.
- Tekeleza matokeo ya authentication na kusanya ushahidi wa ukaguzi (timings > 0 ms, makosa makali kwa mismatch).
- Lock-state spoofing inapaswa kutengenezwa isiyofaa kwa ajili ya attestation (unganisha lock state na maamuzi ya uhalisi ya AVB/vbmeta na fuse-backed state).

## Vidokezo vya kifaa

- Imethibitishwa kuungwa mkono: Nothing Phone (2a) (Pacman)
- Inajulikana kufanya kazi (msaada haujakamilika): CMF Phone 1 (Tetris)
- Imeonekana: Vivo X80 Pro iliripotiwa kuwa haikutathibitisha bl2_ext hata wakati ilipokuwa locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
