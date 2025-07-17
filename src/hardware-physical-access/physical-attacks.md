# Fisiese Aanvalle

{{#include ../banners/hacktricks-training.md}}

## BIOS Wagwoord Herstel en Stelselsekuriteit

**Herstel van die BIOS** kan op verskeie maniere gedoen word. Meeste moederborde sluit 'n **battery** in wat, wanneer dit vir ongeveer **30 minute** verwyder word, die BIOS-instellings, insluitend die wagwoord, sal herstel. Alternatiewelik kan 'n **jumper op die moederbord** aangepas word om hierdie instellings te herstel deur spesifieke penne te verbind.

Vir situasies waar hardeware-aanpassings nie moontlik of prakties is nie, bied **sagteware gereedskap** 'n oplossing. Om 'n stelsel vanaf 'n **Live CD/USB** met verspreidings soos **Kali Linux** te laat loop, bied toegang tot gereedskap soos **_killCmos_** en **_CmosPWD_**, wat kan help met BIOS wagwoord herstel.

In gevalle waar die BIOS wagwoord onbekend is, sal dit tipies 'n foutkode oplewer as dit verkeerd **drie keer** ingevoer word. Hierdie kode kan op webwerwe soos [https://bios-pw.org](https://bios-pw.org) gebruik word om moontlik 'n bruikbare wagwoord te verkry.

### UEFI Sekuriteit

Vir moderne stelsels wat **UEFI** in plaas van tradisionele BIOS gebruik, kan die hulpmiddel **chipsec** gebruik word om UEFI-instellings te analiseer en te wysig, insluitend die deaktivering van **Secure Boot**. Dit kan met die volgende opdrag gedoen word:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM-analise en Koue Boot-aanvalle

RAM behou data kortliks nadat krag afgesny is, gewoonlik vir **1 tot 2 minute**. Hierdie volharding kan verleng word tot **10 minute** deur koue stowwe, soos vloeibare stikstof, toe te pas. Gedurende hierdie verlengde periode kan 'n **geheue-dump** geskep word met behulp van gereedskap soos **dd.exe** en **volatility** vir analise.

---

## Direkte Geheue Toegang (DMA) Aanvalle

**INCEPTION** is 'n hulpmiddel wat ontwerp is vir **fisiese geheue manipulasie** deur middel van DMA, wat versoenbaar is met interfaces soos **FireWire** en **Thunderbolt**. Dit stel gebruikers in staat om aanmeldprosedures te omseil deur geheue te patch om enige wagwoord te aanvaar. Dit is egter nie effektief teen **Windows 10** stelsels nie.

---

## Live CD/USB vir Stelseloopgang

Die verandering van stelselbinaries soos **_sethc.exe_** of **_Utilman.exe_** met 'n kopie van **_cmd.exe_** kan 'n opdragprompt met stelselsprivileges bied. Gereedskap soos **chntpw** kan gebruik word om die **SAM** lêer van 'n Windows-installasie te redigeer, wat wagwoordveranderinge moontlik maak.

**Kon-Boot** is 'n hulpmiddel wat dit vergemaklik om in Windows-stelsels aan te meld sonder om die wagwoord te ken deur tydelik die Windows-kern of UEFI te verander. Meer inligting kan gevind word by [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Hantering van Windows-sekuriteitskenmerke

### Boot- en Herstel-snelkoppelinge

- **Supr**: Toegang tot BIOS-instellings.
- **F8**: Betree Herstelmodus.
- Deur **Shift** te druk na die Windows-banner kan outologon omseil.

### SLECHTE USB-toestelle

Toestelle soos **Rubber Ducky** en **Teensyduino** dien as platforms om **slegte USB** toestelle te skep, wat in staat is om vooraf gedefinieerde payloads uit te voer wanneer dit aan 'n teikenrekenaar gekoppel word.

### Volume Shadow Copy

Administrateurprivileges stel die skepping van kopieë van sensitiewe lêers, insluitend die **SAM** lêer, deur middel van PowerShell moontlik.

---

## Omseiling van BitLocker-kodering

BitLocker-kodering kan moontlik omseil word as die **herstelwagwoord** in 'n geheue-dump lêer (**MEMORY.DMP**) gevind word. Gereedskap soos **Elcomsoft Forensic Disk Decryptor** of **Passware Kit Forensic** kan vir hierdie doel gebruik word.

---

## Sosiale Ingenieurswese vir Herstel Sleutel Byvoeging

'n Nuwe BitLocker herstel sleutel kan bygevoeg word deur sosiale ingenieurswese taktieke, wat 'n gebruiker oortuig om 'n opdrag uit te voer wat 'n nuwe herstel sleutel wat uit nulles bestaan, byvoeg, wat die ontsleuteling proses vereenvoudig.

---

## Exploiting Chassis Intrusion / Onderhoud Skakelaars om die BIOS te Fabrieksreset

Baie moderne skootrekenaars en klein-formaat desktops sluit 'n **chassis-intrusion skakelaar** in wat deur die Embedded Controller (EC) en die BIOS/UEFI firmware gemonitor word. Terwyl die primêre doel van die skakelaar is om 'n waarskuwing te laat klink wanneer 'n toestel geopen word, implementeer verskaffers soms 'n **onbeplande herstel snelkoppeling** wat geaktiveer word wanneer die skakelaar in 'n spesifieke patroon omgeskakel word.

### Hoe die Aanval Werk

1. Die skakelaar is gekabel aan 'n **GPIO onderbreking** op die EC.
2. Firmware wat op die EC loop hou die **tyd en aantal drukke** dop.
3. Wanneer 'n hard-gecodeerde patroon erken word, roep die EC 'n *hoofbord-reset* routine aan wat die **inhoud van die stelsel NVRAM/CMOS** uitwis.
4. By die volgende opstart laai die BIOS standaardwaardes – **supervisor wagwoord, Secure Boot sleutels, en alle pasgemaakte konfigurasie word verwyder**.

> Sodra Secure Boot gedeaktiveer is en die firmware wagwoord weg is, kan die aanvaller eenvoudig enige eksterne OS beeld opstart en onbeperkte toegang tot die interne skywe verkry.

### Werklike Voorbeeld – Framework 13 Skootrekenaar

Die herstel snelkoppeling vir die Framework 13 (11de/12de/13de generasie) is:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Na die tiende siklus stel die EC 'n vlag in wat die BIOS instrueer om NVRAM by die volgende herlaai te vee. Die hele prosedure neem ~40 s en vereis **niks behalwe 'n skroewedraaier** nie.

### Generiese Exploitasie Prosedure

1. Skakel die teiken aan of sit dit in slaap-modus en herresumeer sodat die EC loop.
2. Verwyder die onderkant se bedekking om die indringing/onderhoud skakelaar bloot te stel.
3. Herproduseer die verskaffer-spesifieke skakelpatroon (raadpleeg dokumentasie, forums, of reverse-engineer die EC firmware).
4. Herverpak en herlaai – firmware beskermings moet gedeaktiveer wees.
5. Laai 'n lewende USB (bv. Kali Linux) en voer gewone post-exploitatie uit (geloofsbriewe dumping, data eksfiltrasie, inplanting van kwaadwillige EFI binêre, ens.).

### Opsporing & Versagting

* Log chassie-indringing gebeurtenisse in die OS bestuurskonsol en korreleer met onverwagte BIOS herlaai.
* Gebruik **tamper-evident seals** op skroewe/bedekkings om opening te detecteer.
* Hou toestelle in **fisies beheerde areas**; neem aan dat fisiese toegang gelyk is aan volle kompromie.
* Waar beskikbaar, deaktiveer die verskaffer “onderhoud skakelaar herset” funksie of vereis 'n addisionele kriptografiese toestemming vir NVRAM hersets.

---

## Verwysings

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)

{{#include ../banners/hacktricks-training.md}}
