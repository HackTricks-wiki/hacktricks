# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**Kurekebisha BIOS** kunaweza kufanywa kwa njia kadhaa. Karamani nyingi zina **betri** ambayo, ikiondolewa kwa takriban **dakika 30**, itarejesha mipangilio ya BIOS, ikiwa ni pamoja na nenosiri. Vinginevyo, **jumper kwenye karatasi mama** inaweza kubadilishwa ili kurekebisha mipangilio hii kwa kuunganisha pini maalum.

Kwa hali ambapo marekebisho ya vifaa hayawezekani au si ya vitendo, **zana za programu** zinatoa suluhisho. Kuendesha mfumo kutoka kwa **Live CD/USB** na usambazaji kama **Kali Linux** kunatoa ufikiaji wa zana kama **_killCmos_** na **_CmosPWD_**, ambazo zinaweza kusaidia katika urejeleaji wa nenosiri la BIOS.

Katika matukio ambapo nenosiri la BIOS halijulikani, kuingiza kwa makosa **mara tatu** kawaida husababisha msimbo wa kosa. Msimbo huu unaweza kutumika kwenye tovuti kama [https://bios-pw.org](https://bios-pw.org) ili kupata nenosiri linaloweza kutumika.

### UEFI Security

Kwa mifumo ya kisasa inayotumia **UEFI** badala ya BIOS ya jadi, zana **chipsec** inaweza kutumika kuchambua na kubadilisha mipangilio ya UEFI, ikiwa ni pamoja na kuzima **Secure Boot**. Hii inaweza kufanywa kwa amri ifuatayo:

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM Analysis and Cold Boot Attacks

RAM huhifadhi data kwa muda mfupi baada ya nguvu kukatwa, kawaida kwa **dakika 1 hadi 2**. Ustahimilivu huu unaweza kupanuliwa hadi **dakika 10** kwa kutumia vitu baridi, kama nitrojeni ya kioevu. Wakati huu wa kupanuliwa, **memory dump** inaweza kuundwa kwa kutumia zana kama **dd.exe** na **volatility** kwa uchambuzi.

### Direct Memory Access (DMA) Attacks

**INCEPTION** ni zana iliyoundwa kwa ajili ya **manipulation ya kumbukumbu ya kimwili** kupitia DMA, inayoendana na interfaces kama **FireWire** na **Thunderbolt**. Inaruhusu kupita taratibu za kuingia kwa kubadilisha kumbukumbu ili kukubali nenosiri lolote. Hata hivyo, haiwezi kufanya kazi dhidi ya mifumo ya **Windows 10**.

### Live CD/USB for System Access

Kubadilisha binaries za mfumo kama **_sethc.exe_** au **_Utilman.exe_** kwa nakala ya **_cmd.exe_** kunaweza kutoa dirisha la amri lenye mamlaka ya mfumo. Zana kama **chntpw** zinaweza kutumika kuhariri faili ya **SAM** ya usakinishaji wa Windows, kuruhusu mabadiliko ya nenosiri.

**Kon-Boot** ni zana inayorahisisha kuingia kwenye mifumo ya Windows bila kujua nenosiri kwa kubadilisha kwa muda kernel ya Windows au UEFI. Taarifa zaidi zinaweza kupatikana kwenye [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Handling Windows Security Features

#### Boot and Recovery Shortcuts

- **Supr**: Fikia mipangilio ya BIOS.
- **F8**: Ingia katika hali ya Urejeleaji.
- Kubonyeza **Shift** baada ya bendera ya Windows kunaweza kupita autologon.

#### BAD USB Devices

Vifaa kama **Rubber Ducky** na **Teensyduino** vinatumika kama majukwaa ya kuunda **bad USB** devices, zenye uwezo wa kutekeleza payloads zilizowekwa awali zinapounganishwa na kompyuta lengwa.

#### Volume Shadow Copy

Mamlaka ya msimamizi yanaruhusu kuunda nakala za faili nyeti, ikiwa ni pamoja na faili ya **SAM**, kupitia PowerShell.

### Bypassing BitLocker Encryption

BitLocker encryption inaweza kupita ikiwa **nenosiri la urejeleaji** litapatikana ndani ya faili ya memory dump (**MEMORY.DMP**). Zana kama **Elcomsoft Forensic Disk Decryptor** au **Passware Kit Forensic** zinaweza kutumika kwa kusudi hili.

### Social Engineering for Recovery Key Addition

Nenosiri jipya la urejeleaji la BitLocker linaweza kuongezwa kupitia mbinu za ushirikiano wa kijamii, kumshawishi mtumiaji kutekeleza amri inayoongeza nenosiri jipya lililotengenezwa kwa sifuri, hivyo kurahisisha mchakato wa ufichuzi.

{{#include ../banners/hacktricks-training.md}}
