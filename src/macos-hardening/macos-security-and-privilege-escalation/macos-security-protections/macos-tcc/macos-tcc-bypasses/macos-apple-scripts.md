# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

To je skriptni jezik koji se koristi za automatizaciju zadataka **interakcijom sa udaljenim procesima**. Omogućava veoma lako **traženje od drugih procesa da izvrše određene radnje**. **Malware** može zloupotrebiti ove funkcije kako bi iskoristio funkcije koje drugi procesi eksportuju.\
Na primer, malware bi mogao da **ubaci proizvoljan JS kod u stranice otvorene u browseru**. Ili da **automatski klikne** na neka dugmad Allow za dozvole koje se traže od korisnika;<sup>[[3]](#references)</sup>.
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Here are some examples: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Više informacija o malware-u koji koristi applescripts pronađite [**ovde**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automatizacija / TCC quirks

Odobrenja za Apple Events su **usmerena**: prompt se odnosi na par **izvorni proces -> ciljni proces**. Kada korisnik klikne na **Allow**, budući zahtevi iz istog izvornog procesa ka istom ciljnom procesu biće dozvoljeni sve dok se unos ne resetuje. Tokom testiranja, jednokratno odobravanje `Terminal -> Finder` ili `Terminal -> System Events` dovoljno je da se dozvola kasnije ponovo koristi bez novog iskačućeg prozora.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Ovo je naročito relevantno kada je **target** **Finder**, zato što Finder uvek ima **Full Disk Access**, čak i ako se ne pojavljuje u FDA UI-ju. Zbog toga svaki host koji već ima **Automation** nad Finderom može da se koristi kao AppleScript/JXA proxy za pristup datotekama zaštićenim pomoću TCC-a.<sup>[[1]](#references)</sup> Generički Finder i System Events payloadi već su dokumentovani na [glavnoj TCC stranici](../README.md) i na [Apple Events stranici](../macos-apple-events.md).

### Savremeni offensive tradecraft

`/usr/bin/osascript` je samo najvidljivija ulazna tačka. AppleScript i JXA takođe mogu da se izvršavaju iz **Mach-O binaries** putem **`NSAppleScript`** / **`OSAScript`**, što je korisno i za evasion i za rad unutar hosta koji već ima interesantne TCC grantove.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Ako napravite prilagođeni helper koji direktno šalje Apple Events, dodeljivanje **stvarnog identiteta aplikacije** čini testiranje i operacije mnogo pouzdanijim. U praksi to znači ugrađivanje `Info.plist` datoteke sa `CFBundleIdentifier` i `NSAppleEventsUsageDescription`, potpisivanje binarnog fajla i dodeljivanje entitlement-a `com.apple.security.automation.apple-events`. U suprotnom se Apple Events prompt često pripisuje **parent host-u** (na primer `Terminal`), ili `NSAppleScript` izvršavanje jednostavno ne uspeva uz zbunjujuće greške `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Apple scripts se mogu lako "**compiled**". Ove verzije se mogu lako "**decompiled**" pomoću `osadecompile`

Međutim, ovi script-ovi se takođe mogu **exportovati kao "Read only"** (pomoću opcije "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
i u ovom slučaju sadržaj ne može da se dekompajlira čak ni pomoću `osadecompile`

Međutim, i dalje postoje neki alati koji se mogu koristiti za razumevanje ove vrste izvršnih datoteka, [**pročitajte ovo istraživanje za više informacija**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> Alat [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) zajedno sa alatom [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) biće veoma koristan za razumevanje načina rada skripte.

## Reference

- [1] [Slučajno i namerno zaobilaženje macOS TCC zaštite privatnosti korisnika](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Korišćenje AppleScript-a u macOS CLI alatima: nedokumentovani delovi](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Kako maliciozni akteri koriste AppleScript za napade na macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Avanture u reverse engineeringu malicioznih AppleScript skripti koje se mogu samo izvršavati](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
