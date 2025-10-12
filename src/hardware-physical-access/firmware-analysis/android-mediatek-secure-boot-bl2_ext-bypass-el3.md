# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaelezea kuvunjwa kwa secure-boot katika majukwaa kadhaa za MediaTek kwa kutumia pengo la uthibitishaji wakati usanidi wa bootloader wa kifaa (seccfg) uko "unlocked". Hitilafu hii inaruhusu kuendesha bl2_ext iliyorekebishwa kwenye ARM EL3 ili kuzima ukaguzi wa saini kwa hatua za chini, kuvunja mnyororo wa uaminifu na kuwezesha upakiaji wa TEE/GZ/LK/Kernel zisizosainiwa kwa hiari.

> Tahadhari: Kurekebisha mapema wakati wa boot kunaweza ku-brick vifaa kwa kudumu endapo offsets sio sahihi. Daima hifadhi full dumps na njia ya recovery inayotegemeka.

## Mtiririko wa boot unaoathiriwa (MediaTek)

- Njia ya kawaida: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Njia yenye hatari: Wakati seccfg imewekwa kuwa "unlocked", Preloader inaweza kupuuza kuthibitisha bl2_ext. Preloader bado inaendelea kutekeleza bl2_ext kwenye EL3, hivyo bl2_ext iliyotengenezwa inaweza kupakia vipengele visivyoidhinishwa baadaye.

Mipaka muhimu ya uaminifu:
- bl2_ext inatekelezwa kwenye EL3 na inawajibika kuthibitisha TEE, GenieZone, LK/AEE na kernel. Ikiwa bl2_ext yenyewe haitathibitishwa, mnyororo mzima wa uaminifu unaweza kupitishwa kwa urahisi.

## Chanzo

Kwenye vifaa vinavyoathirika, Preloader haitekelezi uthibitishaji wa partition ya bl2_ext wakati seccfg inaonyesha hali ya "unlocked". Hii inaruhusu kuflash bl2_ext inayodhibitiwa na mshambuliaji inayotekelezwa kwenye EL3.

Ndani ya bl2_ext, kazi ya sera ya uthibitishaji inaweza kufanyiwa patch ili kuripoti bila masharti kuwa uthibitishaji hauhitajiki. Patch ya dhana ndogo ni:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Kwa mabadiliko haya, picha zote zinazofuata (TEE, GZ, LK/AEE, Kernel) zinakubaliwa bila ukaguzi wa kriptografia zinapopakiwa na bl2_ext iliyorekebishwa inayotekelezwa kwenye EL3.

## Jinsi ya kuchambua lengo (expdb logs)

Dump/inspect boot logs (e.g., expdb) karibu na upakiaji wa bl2_ext. Ikiwa img_auth_required = 0 na wakati wa uhakiki wa cheti ni ~0 ms, uwezekano ni kwamba utekekaji umezimwa na kifaa kinaweza kuwa exploitable.

Mfano wa kifungu cha log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Kumbuka: Ripoti zinaonyesha kuwa baadhi ya vifaa hupitisha uidhinishaji wa bl2_ext hata ikiwa bootloader imefungwa, jambo linaloongeza athari.

## Practical exploitation workflow (Fenrir PoC)

Fenrir ni reference exploit/patching toolkit kwa darasa hili la tatizo. Inaunga mkono Nothing Phone (2a) (Pacman) na inajulikana kufanya kazi (kwa msaada usio kamili) kwenye CMF Phone 1 (Tetris). Kurekebisha kwa modeli nyingine kunahitaji reverse engineering ya bl2_ext maalum ya kifaa.

High-level process:
- Pata device bootloader image kwa codename lengwa na uweke kama bin/<device>.bin
- Jenga patched image inayozima bl2_ext verification policy
- Flash payload itokanayo kwenye kifaa (fastboot inachukuliwa na helper script)

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

## Runtime payload capabilities (EL3)

A patched bl2_ext payload can:
- Sajili amri za fastboot maalum
- Dhibiti/override boot mode
- Kuita kwa njia ya dynamic kazi za built‑in za bootloader wakati wa runtime
- Spoof “lock state” as locked while actually unlocked to pass stronger integrity checks (some environments may still require vbmeta/AVB adjustments)

Limitation: PoCs za sasa zinaonyesha kuwa mabadiliko ya kumbukumbu wakati wa runtime yanaweza kusababisha fault kutokana na vikwazo vya MMU; payloads kwa ujumla huepuka kuandika moja kwa moja kwenye kumbukumbu hai hadi hili litakaposuluhishwa.

## Porting tips

- Reverse engineer bl2_ext ya kifaa ili kutambua mantiki ya sera ya uthibitishaji (mf., sec_get_vfy_policy).
- Tambua site ya return ya sera au tawi la uamuzi na patch ili “no verification required” (return 0 / unconditional allow).
- Hifadhi offsets ziwe kabisa device- na firmware-specific; usitumie addresses kati ya variants.
- Validate kwenye kifaa cha majaribio kwanza. Andaa mpango wa recovery (mf., EDL/BootROM loader/SoC-specific download mode) kabla ya flash.

## Security impact

- EL3 code execution after Preloader and full chain-of-trust collapse for the rest of the boot path.
- Uwezo wa boot unsigned TEE/GZ/LK/Kernel, bypassing secure/verified boot expectations and enabling persistent compromise.

## Detection and hardening ideas

- Hakikisha Preloader inathibitisha bl2_ext bila kujali seccfg state.
- Tekeleza authentication results na kusanya ushahidi wa audit (timings > 0 ms, strict errors on mismatch).
- Lock-state spoofing inapaswa kutengenezwa isiyofaa kwa attestation (tie lock state to AVB/vbmeta verification decisions and fuse-backed state).

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
