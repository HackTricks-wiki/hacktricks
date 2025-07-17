# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**Kurekebisha BIOS** kunaweza kufanywa kwa njia kadhaa. Bodi nyingi za mama zina **betri** ambayo, ikiondolewa kwa takriban **dakika 30**, itarejesha mipangilio ya BIOS, ikiwa ni pamoja na nenosiri. Vinginevyo, **jumper kwenye bodi ya mama** inaweza kubadilishwa ili kurekebisha mipangilio hii kwa kuunganisha pini maalum.

Kwa hali ambapo marekebisho ya vifaa hayawezekani au si ya vitendo, **zana za programu** zinatoa suluhisho. Kuendesha mfumo kutoka kwa **Live CD/USB** na usambazaji kama **Kali Linux** kunatoa ufikiaji wa zana kama **_killCmos_** na **_CmosPWD_**, ambazo zinaweza kusaidia katika urejeleaji wa nenosiri la BIOS.

Katika matukio ambapo nenosiri la BIOS halijulikani, kuingiza kwa makosa **mara tatu** kawaida husababisha msimbo wa kosa. Msimbo huu unaweza kutumika kwenye tovuti kama [https://bios-pw.org](https://bios-pw.org) ili kupata nenosiri linaloweza kutumika.

### UEFI Security

Kwa mifumo ya kisasa inayotumia **UEFI** badala ya BIOS ya jadi, zana **chipsec** inaweza kutumika kuchambua na kubadilisha mipangilio ya UEFI, ikiwa ni pamoja na kuzima **Secure Boot**. Hii inaweza kufanywa kwa amri ifuatayo:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Uchambuzi wa RAM na Mashambulizi ya Cold Boot

RAM inashikilia data kwa muda mfupi baada ya nguvu kukatwa, kawaida kwa **dakika 1 hadi 2**. Uthabiti huu unaweza kuongezwa hadi **dakika 10** kwa kutumia vitu baridi, kama nitrojeni ya kioevu. Wakati huu wa nyongeza, **memory dump** inaweza kuundwa kwa kutumia zana kama **dd.exe** na **volatility** kwa uchambuzi.

---

## Mashambulizi ya Direct Memory Access (DMA)

**INCEPTION** ni zana iliyoundwa kwa ajili ya **manipulation ya kumbukumbu ya kimwili** kupitia DMA, inayofaa na interfaces kama **FireWire** na **Thunderbolt**. Inaruhusu kupita taratibu za kuingia kwa kubadilisha kumbukumbu ili kukubali nenosiri lolote. Hata hivyo, haiwezi kufanya kazi dhidi ya mifumo ya **Windows 10**.

---

## CD/USB ya Moja kwa Moja kwa Upatikanaji wa Mfumo

Kubadilisha binaries za mfumo kama **_sethc.exe_** au **_Utilman.exe_** kwa nakala ya **_cmd.exe_** kunaweza kutoa dirisha la amri lenye mamlaka ya mfumo. Zana kama **chntpw** zinaweza kutumika kuhariri faili ya **SAM** ya usakinishaji wa Windows, kuruhusu mabadiliko ya nenosiri.

**Kon-Boot** ni zana inayorahisisha kuingia kwenye mifumo ya Windows bila kujua nenosiri kwa kubadilisha kwa muda kernel ya Windows au UEFI. Taarifa zaidi zinaweza kupatikana kwenye [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Kushughulikia Vipengele vya Usalama wa Windows

### Mifano ya Boot na Urejeleaji

- **Supr**: Fikia mipangilio ya BIOS.
- **F8**: Ingia katika hali ya Urejeleaji.
- Kubonyeza **Shift** baada ya bendera ya Windows kunaweza kupita autologon.

### Vifaa vya BAD USB

Vifaa kama **Rubber Ducky** na **Teensyduino** vinatumika kama majukwaa ya kuunda **bad USB** vifaa, vinavyoweza kutekeleza payload zilizowekwa wakati vinapounganishwa na kompyuta lengwa.

### Nakala ya Kivolumu cha Kivuli

Mamlaka ya msimamizi yanaruhusu kuunda nakala za faili nyeti, ikiwa ni pamoja na faili ya **SAM**, kupitia PowerShell.

---

## Kupita Usimbaji wa BitLocker

Usimbaji wa BitLocker unaweza kupitishwa ikiwa **nenosiri la urejeleaji** linapatikana ndani ya faili ya memory dump (**MEMORY.DMP**). Zana kama **Elcomsoft Forensic Disk Decryptor** au **Passware Kit Forensic** zinaweza kutumika kwa kusudi hili.

---

## Uhandisi wa Kijamii kwa Kuongeza Funguo za Urejeleaji

Funguo mpya ya urejeleaji wa BitLocker inaweza kuongezwa kupitia mbinu za uhandisi wa kijamii, kumshawishi mtumiaji kutekeleza amri inayoongeza funguo mpya ya urejeleaji iliyoundwa kwa sifuri, hivyo kurahisisha mchakato wa ufichuzi.

---

## Kutumia Swichi za Uvunjaji wa Chasi / Matengenezo ili Kurejesha BIOS kwa Kiwango cha Kiwanda

Laptop nyingi za kisasa na desktops za ukubwa mdogo zina **swichi ya uvunjaji wa chasi** inayofuatiliwa na Msimamizi wa Kijijini (EC) na firmware ya BIOS/UEFI. Ingawa kusudi kuu la swichi ni kutoa tahadhari wakati kifaa kinapofunguliwa, wauzaji wakati mwingine wanaweza kutekeleza **mfano wa urejeleaji usioandikwa** unaoanzishwa wakati swichi inabadilishwa kwa muundo maalum.

### Jinsi Shambulizi Linavyofanya Kazi

1. Swichi imeunganishwa na **GPIO interrupt** kwenye EC.
2. Firmware inayotembea kwenye EC inafuatilia **wakati na idadi ya bonyezo**.
3. Wakati muundo wa kudumu unapotambuliwa, EC inaita *mainboard-reset* routine ambayo **inafuta maudhui ya mfumo NVRAM/CMOS**.
4. Katika boot inayofuata, BIOS inachukua thamani za chaguo-msingi – **nenosiri la msimamizi, funguo za Secure Boot, na usanidi wote wa kawaida unafutwa**.

> Mara tu Secure Boot inapozuiliwa na nenosiri la firmware likiondolewa, mshambuliaji anaweza tu kuanzisha picha yoyote ya mfumo wa uendeshaji wa nje na kupata ufikiaji usio na kikomo kwa diski za ndani.

### Mfano wa Uhalisia – Laptop ya Framework 13

Mfano wa urejeleaji kwa Framework 13 (11th/12th/13th-gen) ni:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Baada ya mzunguko wa kumi, EC inaweka bendera inayomwagiza BIOS kufuta NVRAM wakati wa kuanzisha tena. Utaratibu mzima unachukua ~40 s na unahitaji **kitu chochote isipokuwa screwdriver**.

### Utaratibu wa Kijadi wa Kutumia

1. Washa au simamisha-kisha-rejesha lengo ili EC ifanye kazi.
2. Ondoa kifuniko cha chini ili kufichua swichi ya uvamizi/utunzaji.
3. Rudia muundo wa kubadili maalum wa muuzaji (angalia nyaraka, majukwaa, au fanya uhandisi wa nyuma wa firmware ya EC).
4. Jenga tena na uanzishe tena - ulinzi wa firmware unapaswa kuzuiliwa.
5. Boot USB hai (mfano, Kali Linux) na fanya kawaida baada ya kutumia (kuchota hati, uhamasishaji wa data, kuingiza binaries za EFI zenye uharibifu, nk.).

### Ugunduzi & Kupunguza

* Rekodi matukio ya uvamizi wa chasi katika konsoli ya usimamizi wa OS na ulinganishe na marekebisho yasiyotarajiwa ya BIOS.
* Tumia **muhuri wa kuonyesha uharibifu** kwenye screws/kifuniko ili kugundua ufunguzi.
* Hifadhi vifaa katika **maeneo yanayodhibitiwa kimwili**; dhani kwamba ufikiaji wa kimwili unamaanisha kuathiriwa kabisa.
* Pale inapatikana, zima kipengele cha muuzaji "reset ya swichi ya utunzaji" au hitaji idhini ya ziada ya kificho kwa ajili ya marekebisho ya NVRAM.

---

## Marejeo

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mwongozo wa Reset ya Mainboard](https://framewiki.net/guides/mainboard-reset)

{{#include ../banners/hacktricks-training.md}}
