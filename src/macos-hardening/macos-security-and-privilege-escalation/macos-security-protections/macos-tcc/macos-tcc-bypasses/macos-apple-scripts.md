# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

To je skriptni jezik koji se koristi za automatizaciju zadataka uz **interakciju sa udaljenim procesima**. Znatno olakšava da se **zatraži od drugih procesa da izvrše određene radnje**. **Malware** može da zloupotrebi ove funkcije kako bi iskoristio funkcije koje izlažu drugi procesi.\
Na primer, malware bi mogao da **ubaci proizvoljan JS kod u otvorene stranice u browser-u**. Ili da **automatski klikne** na neka allow dopuštenja koja su zatražena od korisnika;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Evo nekoliko primera: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Pronađi više informacija o malware koristeći applescripts [**ovde**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC quirkovi

Apple Events odobrenja su **usmerena**: prompt je za par **source process -> target process**. Kada korisnik klikne **Allow**, budući zahtevi iz istog source ka istom target su dozvoljeni dok se unos ne resetuje. Tokom testiranja, dodeljivanje `Terminal -> Finder` ili `Terminal -> System Events` jednom je dovoljno da se kasnije ponovo iskoristi dozvola bez novog popup-a.
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Ovo je posebno relevantno kada je **target** **Finder**, zato što Finder uvek ima **Full Disk Access** čak i ako se ne pojavljuje u FDA UI. Zato se svaki host koji već ima Automation nad Finder može koristiti kao AppleScript/JXA proxy za pristup TCC-protected fajlovima. Generički Finder i System Events payloads su već dokumentovani na [the main TCC page](../README.md) i na [the Apple Events page](../macos-apple-events.md).

### Modern offensive tradecraft

`/usr/bin/osascript` je samo najvidljivija ulazna tačka. AppleScript i JXA takođe mogu da se izvršavaju iz **Mach-O binaries** preko **`NSAppleScript`** / **`OSAScript`**, što je korisno i za evasion i za living inside host-a koji već ima zanimljive TCC grants.
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Ako napravite custom helper koji direktno šalje Apple Events, davanje **stvarnog app identiteta** ga čini mnogo pouzdanijim za testiranje i operacije. U praksi to znači ugrađivanje `Info.plist` sa `CFBundleIdentifier` i `NSAppleEventsUsageDescription`, potpisivanje binary-ja i dodeljivanje `com.apple.security.automation.apple-events` entitlement-a. U suprotnom, Apple Events prompt se često pripisuje **parent host-u** (na primer `Terminal`) ili `NSAppleScript` izvršavanje jednostavno padne sa zbunjujućim `-1750` / `errOSASystemError` greškama.

Apple scripts mogu lako biti "**compiled**". Ove verzije se mogu lako "**decompiled**" pomoću `osadecompile`

Međutim, ove skripte se takođe mogu **exported as "Read only"** (preko opcije "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
i u ovom slučaju sadržaj ne može da se dekompajlira čak ni sa `osadecompile`

Međutim, i dalje postoje neki alati koji mogu da se koriste za razumevanje ovakve vrste izvršnih fajlova, [**pročitajte ovo istraživanje za više informacija**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Alat [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) sa [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) biće veoma koristan za razumevanje kako skripta radi.

## References

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}
