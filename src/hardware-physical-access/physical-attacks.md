# Fisiese Aanvalle

{{#include ../banners/hacktricks-training.md}}

## BIOS Wagwoord Herstel en Stelselsekuriteit

**Herstel van die BIOS** kan op verskeie maniere bereik word. Meeste moederborde sluit 'n **batterij** in wat, wanneer dit vir ongeveer **30 minute** verwyder word, die BIOS-instellings, insluitend die wagwoord, sal herstel. Alternatiewelik kan 'n **jumper op die moederbord** aangepas word om hierdie instellings te herstel deur spesifieke penne te verbind.

Vir situasies waar hardeware-aanpassings nie moontlik of prakties is nie, bied **sagteware gereedskap** 'n oplossing. Om 'n stelsel vanaf 'n **Live CD/USB** met verspreidings soos **Kali Linux** te laat loop, bied toegang tot gereedskap soos **_killCmos_** en **_CmosPWD_**, wat kan help met BIOS wagwoord herstel.

In gevalle waar die BIOS wagwoord onbekend is, sal dit gewoonlik 'n foutkode oplewer as dit verkeerd **drie keer** ingevoer word. Hierdie kode kan op webwerwe soos [https://bios-pw.org](https://bios-pw.org) gebruik word om moontlik 'n bruikbare wagwoord te verkry.

### UEFI Sekuriteit

Vir moderne stelsels wat **UEFI** in plaas van tradisionele BIOS gebruik, kan die gereedskap **chipsec** gebruik word om UEFI-instellings te analiseer en te wysig, insluitend die deaktivering van **Secure Boot**. Dit kan met die volgende opdrag gedoen word:

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM Analise en Koue Boot Aanvalle

RAM behou data kortliks nadat krag afgesny is, gewoonlik vir **1 tot 2 minute**. Hierdie volharding kan tot **10 minute** verleng word deur koue stowwe, soos vloeibare stikstof, toe te pas. Gedurende hierdie verlengde periode kan 'n **geheue dump** geskep word met gereedskap soos **dd.exe** en **volatility** vir analise.

### Direkte Geheue Toegang (DMA) Aanvalle

**INCEPTION** is 'n gereedskap wat ontwerp is vir **fisiese geheue manipulasie** deur middel van DMA, wat versoenbaar is met interfaces soos **FireWire** en **Thunderbolt**. Dit maak dit moontlik om aanmeldprosedures te omseil deur geheue te patch om enige wagwoord te aanvaar. Dit is egter nie effektief teen **Windows 10** stelsels nie.

### Live CD/USB vir Stelselaanroep

Om stelselbinaries soos **_sethc.exe_** of **_Utilman.exe_** met 'n kopie van **_cmd.exe_** te verander, kan 'n opdragprompt met stelselsprivileges bied. Gereedskap soos **chntpw** kan gebruik word om die **SAM** lêer van 'n Windows-installasie te redigeer, wat wagwoordveranderinge moontlik maak.

**Kon-Boot** is 'n gereedskap wat die aanmelding by Windows-stelsels vergemaklik sonder om die wagwoord te ken deur tydelik die Windows-kern of UEFI te wysig. Meer inligting kan gevind word by [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Hantering van Windows Sekuriteitskenmerke

#### Boot en Herstel Snelkoppelinge

- **Supr**: Toegang tot BIOS-instellings.
- **F8**: Betree Herstelmodus.
- Deur **Shift** te druk na die Windows-banner kan outologon omseil.

#### BAD USB Toestelle

Toestelle soos **Rubber Ducky** en **Teensyduino** dien as platforms om **bad USB** toestelle te skep, wat in staat is om vooraf gedefinieerde payloads uit te voer wanneer dit aan 'n teikenrekenaar gekoppel word.

#### Volume Skadu Kopie

Administrateurprivileges stel die skepping van kopieë van sensitiewe lêers, insluitend die **SAM** lêer, deur PowerShell moontlik.

### Omseiling van BitLocker Enkripsie

BitLocker enkripsie kan moontlik omseil word as die **herstel wagwoord** in 'n geheue dump lêer (**MEMORY.DMP**) gevind word. Gereedskap soos **Elcomsoft Forensic Disk Decryptor** of **Passware Kit Forensic** kan vir hierdie doel gebruik word.

### Sosiale Ingenieurswese vir Herstel Sleutel Byvoeging

'n Nuwe BitLocker herstel sleutel kan bygevoeg word deur sosiale ingenieurswese taktieke, wat 'n gebruiker oortuig om 'n opdrag uit te voer wat 'n nuwe herstel sleutel bestaande uit nulles byvoeg, wat die ontsleuteling proses vereenvoudig.
{{#include ../banners/hacktricks-training.md}}
