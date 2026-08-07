# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

To je scripting language koja se koristi za automatizaciju zadataka **interakcijom sa udaljenim procesima**. Omogućava prilično jednostavno **traženje od drugih procesa da izvrše određene radnje**. **Malware** može zloupotrebiti ove funkcije za zloupotrebu funkcija koje drugi procesi exportuju.\
Na primer, malware može **ubaciti proizvoljni JS code u stranice otvorene u browseru**. Ili može **automatski kliknuti** na neke dozvole koje su zatražene od korisnika;<sup>[[3]](#references)</sup>.
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Evo nekoliko primera: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Više informacija o malware-u koji koristi applescripts pronađite [**ovde**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Automation / TCC posebnosti

Apple Events odobrenja su **usmerena**: prompt se odnosi na par **source process -> target process**. Kada korisnik klikne na **Allow**, budući zahtevi istog source-a ka istom target-u biće dozvoljeni dok se entry ne resetuje. Tokom testiranja, jednom dato odobrenje za `Terminal -> Finder` ili `Terminal -> System Events` dovoljno je da se permission kasnije ponovo koristi bez novog popup-a.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Ovo je naročito relevantno kada je **target** **Finder**, zato što Finder uvek ima **Full Disk Access**, čak i ako se ne pojavljuje u FDA UI-ju. Zbog toga se svaki host koji već ima Automation nad Finder-om može koristiti kao AppleScript/JXA proxy za pristup TCC-zaštićenim fajlovima.<sup>[[1]](#references)</sup> Generički Finder i System Events payloads već su dokumentovani na [glavnoj TCC stranici](../README.md) i na [Apple Events stranici](../macos-apple-events.md).

### Moderni ofanzivni tradecraft

`/usr/bin/osascript` je samo najvidljivija ulazna tačka. AppleScript i JXA se takođe mogu izvršavati iz **Mach-O binaries** putem **`NSAppleScript`** / **`OSAScript`**, što je korisno i za evasion i za izvršavanje unutar hosta koji već ima interesantne TCC grantove.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Ako napravite prilagođeni helper koji direktno šalje Apple Events, dodeljivanje **realnog identiteta aplikacije** čini testiranje i rad mnogo pouzdanijim. U praksi to znači ugrađivanje `Info.plist` datoteke sa `CFBundleIdentifier` i `NSAppleEventsUsageDescription`, potpisivanje binarne datoteke i dodeljivanje `com.apple.security.automation.apple-events` entitilementa. U suprotnom, Apple Events prompt se često pripisuje **roditeljskom hostu** (na primer, aplikaciji `Terminal`), ili izvršavanje pomoću `NSAppleScript` jednostavno ne uspeva, uz zbunjujuće greške `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Apple scripts se mogu lako "**compiled**". Ove verzije se mogu lako "**decompiled**" pomoću `osadecompile`

Međutim, ovi scripts se takođe mogu **eksportovati kao "Read only"** (pomoću opcije "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
a u ovom slučaju sadržaj ne može da se dekompajlira čak ni pomoću `osadecompile`

Međutim, i dalje postoje neki alati koji se mogu koristiti za razumevanje ove vrste izvršnih datoteka, [**pročitajte ovo istraživanje za više informacija**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> Alat [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) zajedno sa alatom [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) biće veoma koristan za razumevanje načina rada skripte.

## Reference

- [1] [Slučajno i namerno zaobilaženje macOS TCC zaštite privatnosti korisnika](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Pokretanje AppleScript-a u macOS CLI alatima: nedokumentovani delovi](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Kako Offensive Actors koriste AppleScript za napade na macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Avanture u reverse engineering-u zlonamernih Run-Only AppleScript skripti](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
