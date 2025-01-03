{{#include ../../banners/hacktricks-training.md}}

## Uadilifu wa Firmware

**Firmware maalum na/au binaries zilizokusanywa zinaweza kupakiwa ili kutumia udhaifu wa uadilifu au uthibitisho wa saini**. Hatua zifuatazo zinaweza kufuatwa kwa ajili ya uundaji wa backdoor bind shell:

1. Firmware inaweza kutolewa kwa kutumia firmware-mod-kit (FMK).
2. Mchoro wa firmware wa lengo na endianness inapaswa kubainishwa.
3. Mchambuzi wa msalaba unaweza kujengwa kwa kutumia Buildroot au njia nyingine zinazofaa kwa mazingira.
4. Backdoor inaweza kujengwa kwa kutumia mchambuzi wa msalaba.
5. Backdoor inaweza kunakiliwa kwenye saraka ya firmware iliyotolewa /usr/bin.
6. Binary sahihi ya QEMU inaweza kunakiliwa kwenye rootfs ya firmware iliyotolewa.
7. Backdoor inaweza kuigwa kwa kutumia chroot na QEMU.
8. Backdoor inaweza kufikiwa kupitia netcat.
9. Binary ya QEMU inapaswa kuondolewa kutoka kwenye rootfs ya firmware iliyotolewa.
10. Firmware iliyobadilishwa inaweza kufungashwa tena kwa kutumia FMK.
11. Firmware iliyokuwa na backdoor inaweza kupimwa kwa kuigiza kwa kutumia toolkit ya uchambuzi wa firmware (FAT) na kuunganishwa na IP na bandari ya backdoor ya lengo kwa kutumia netcat.

Ikiwa shell ya root tayari imepatikana kupitia uchambuzi wa dynamic, udanganyifu wa bootloader, au upimaji wa usalama wa vifaa, binaries mbaya zilizokusanywa kama vile implants au reverse shells zinaweza kutekelezwa. Zana za payload/implant za kiotomatiki kama vile mfumo wa Metasploit na 'msfvenom' zinaweza kutumika kwa hatua zifuatazo:

1. Mchoro wa firmware wa lengo na endianness inapaswa kubainishwa.
2. Msfvenom inaweza kutumika kubainisha payload ya lengo, IP ya mwenye shambulio, nambari ya bandari inayosikiliza, aina ya faili, mchoro, jukwaa, na faili ya matokeo.
3. Payload inaweza kuhamishwa kwa kifaa kilichovunjwa na kuhakikisha kuwa ina ruhusa za utekelezaji.
4. Metasploit inaweza kuandaliwa kushughulikia maombi yanayokuja kwa kuanzisha msfconsole na kuunda mipangilio kulingana na payload.
5. Meterpreter reverse shell inaweza kutekelezwa kwenye kifaa kilichovunjwa.

{{#include ../../banners/hacktricks-training.md}}
