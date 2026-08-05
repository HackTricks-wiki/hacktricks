# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

To je scripting language koji se koristi za automatizaciju zadataka **interakcijom sa udaljenim procesima**. Omogućava prilično jednostavno **traženje od drugih procesa da izvrše određene radnje**. **Malware** može zloupotrebiti ove funkcije za zloupotrebu funkcija koje izvoze drugi procesi.\
Na primer, malware može **ubaciti proizvoljan JS kod u stranice otvorene u browseru**. Ili **automatski kliknuti** na neke dozvole za odobravanje koje se traže od korisnika;<sup>[3]</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Ovde možete pronaći neke primere: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Više informacija o malware-u koji koristi AppleScripts pronađite [**ovde**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC specifičnosti

Odobrenja za Apple Events su **usmerena**: prompt se odnosi na par **source process -> target process**. Kada korisnik klikne na **Allow**, budući zahtevi istog source-a prema istom target-u biće dozvoljeni sve dok se unos ne resetuje. Tokom testiranja, dovoljno je jednom odobriti `Terminal -> Finder` ili `Terminal -> System Events` da bi se dozvola kasnije ponovo koristila bez novog popup-a.<sup>[1]</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Ovo je naročito relevantno kada je **target** **Finder**, zato što Finder uvek ima **Full Disk Access**, čak i ako se ne pojavljuje u FDA UI-ju. Zbog toga se svaki host koji već ima Automation nad Finder-om može koristiti kao AppleScript/JXA proxy za pristup TCC-protected fajlovima.<sup>[1]</sup> Generički Finder i System Events payloads su već dokumentovani na [glavnoj TCC stranici](../README.md) i na [Apple Events stranici](../macos-apple-events.md).

### Moderni offensive tradecraft

`/usr/bin/osascript` je samo najvidljivija entry point tačka. AppleScript i JXA se takođe mogu izvršavati iz **Mach-O binaries** putem **`NSAppleScript`** / **`OSAScript`**, što je korisno i za evasion i za delovanje unutar hosta koji već ima interesantne TCC grants.<sup>[2]</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Ako napravite prilagođeni pomoćni program koji direktno šalje Apple Events, dodeljivanje **stvarnog identiteta aplikacije** čini testiranje i rad mnogo pouzdanijim. U praksi to znači ugrađivanje `Info.plist` datoteke sa vrednostima `CFBundleIdentifier` i `NSAppleEventsUsageDescription`, potpisivanje binarne datoteke i dodeljivanje entitlement-a `com.apple.security.automation.apple-events`. U suprotnom, Apple Events prompt se često pripisuje **roditeljskom hostu** (na primer, `Terminal`), ili izvršavanje pomoću `NSAppleScript` jednostavno ne uspeva uz zbunjujuće greške `-1750` / `errOSASystemError`.<sup>[2]</sup>

Apple scripts se mogu lako "**kompajlirati**". Ove verzije se mogu lako "**dekompajlirati**" pomoću `osadecompile`

Međutim, ovi scripts se mogu i **izvesti kao "Samo za čitanje"** (pomoću opcije "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
i u ovom slučaju sadržaj se ne može dekompilirati čak ni pomoću `osadecompile`

Međutim, i dalje postoje neki alati koji se mogu koristiti za razumevanje ove vrste izvršnih datoteka, [**pročitajte ovo istraživanje za više informacija**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[4]</sup> Alat [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) sa [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) biće veoma koristan za razumevanje načina na koji skripta funkcioniše.

## Reference

- [1] [Zaobilaženje macOS TCC zaštite privatnosti korisnika slučajno i namerno](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Korišćenje AppleScript-a u macOS CLI alatima: nedokumentovani delovi](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Kako napadači koriste AppleScript za napade na macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Avanture u reverse engineering-u zlonamernih AppleScript-ova koji se mogu samo pokretati](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
