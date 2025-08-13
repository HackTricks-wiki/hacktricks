# Argief Uittrekking Pad Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Baie argief formate (ZIP, RAR, TAR, 7-ZIP, ens.) laat elke inskrywing toe om sy eie **interne pad** te dra. Wanneer 'n uittrekking hulpmiddel blindelings daardie pad eerbiedig, sal 'n vervaardigde lêernaam wat `..` of 'n **absolute pad** (bv. `C:\Windows\System32\`) bevat, buite die gebruiker-gekose gids geskryf word. Hierdie klas kwesbaarheid is algemeen bekend as *Zip-Slip* of **argief uittrekking pad traversie**.

Gevolge wissel van die oorskryding van arbitrêre lêers tot die direkte bereiking van **afgeleë kode uitvoering (RCE)** deur 'n payload in 'n **auto-run** ligging soos die Windows *Startup* gids te laat val.

## Wortel Oorsaak

1. Aanvaller skep 'n argief waar een of meer lêer koppe bevat:
* Relatiewe traversie volgordes (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute pades (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
2. Slachtoffer trek die argief uit met 'n kwesbare hulpmiddel wat die ingebedde pad vertrou in plaas daarvan om dit te saniteer of om uittrekking onder die gekose gids af te dwing.
3. Die lêer word in die aanvaller-beheerde ligging geskryf en uitgevoer/gelai die volgende keer wanneer die stelsel of gebruiker daardie pad aktiveer.

## Regte-Wêreld Voorbeeld – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR vir Windows (insluitend die `rar` / `unrar` CLI, die DLL en die draagbare bron) het gefaal om lêernames tydens uittrekking te valideer. 'n Kwaadwillige RAR argief wat 'n inskrywing soos bevat:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
sal eindig **buite** die geselekte uitvoer gids en binne die gebruiker se *Startup* gids. Na aanmelding voer Windows outomaties alles wat daar teenwoordig is uit, wat *volhoubare* RCE bied.

### Skep 'n PoC Argief (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – stoor lêerpaaie presies soos gegee (moet **nie** leiende `./` snoei nie).

Lewer `evil.rar` aan die slagoffer en instrueer hulle om dit met 'n kwesbare WinRAR-bou te onttrek.

### Geobserveerde Exploitatie in die Wild

ESET het RomCom (Storm-0978/UNC2596) spear-phishing veldtogte gerapporteer wat RAR-argiewe aangeheg het wat CVE-2025-8088 misbruik om pasgemaakte agterdeure te ontplooi en ransomware-operasies te fasiliteer.

## Opsporingwenke

* **Statiese inspeksie** – Lys argiefinskrywings en merk enige naam wat `../`, `..\\`, *absolute paaie* (`C:`) of nie-kanonical UTF-8/UTF-16 kodering bevat.
* **Sandbox onttrekking** – Decomprimeer in 'n weggooibare gids met 'n *veilige* onttrekker (bv. Python se `patool`, 7-Zip ≥ nuutste, `bsdtar`) en verifieer dat die resulterende paaie binne die gids bly.
* **Eindpuntmonitering** – Laat weet oor nuwe uitvoerbare lêers wat kort na 'n argief deur WinRAR/7-Zip/etc. geopen word, in `Startup`/`Run` plekke geskryf word.

## Versagting & Versterking

1. **Werk die onttrekker op** – WinRAR 7.13 implementeer behoorlike pad-sanitizering. Gebruikers moet dit handmatig aflaai omdat WinRAR 'n outo-opdateringsmeganisme ontbreek.
2. Onttrek argiewe met die **“Ignore paths”** opsie (WinRAR: *Extract → "Do not extract paths"*) wanneer moontlik.
3. Open onbetroubare argiewe **binne 'n sandbox** of VM.
4. Implementeer toepassingswitlyste en beperk gebruikers se skrywe toegang tot outo-loop gidses.

## Addisionele Aangetaste / Historiese Gevalle

* 2018 – Massiewe *Zip-Slip* advies deur Snyk wat baie Java/Go/JS biblioteke beïnvloed.
* 2023 – 7-Zip CVE-2023-4011 soortgelyke traversering tydens `-ao` samesmelting.
* Enige pasgemaakte onttrekkingslogika wat versuim om `PathCanonicalize` / `realpath` voor skryf aan te roep.

## Verwysings

- [BleepingComputer – WinRAR zero-day exploited to plant malware on archive extraction](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [WinRAR 7.13 Changelog](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Zip Slip vulnerability write-up](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
