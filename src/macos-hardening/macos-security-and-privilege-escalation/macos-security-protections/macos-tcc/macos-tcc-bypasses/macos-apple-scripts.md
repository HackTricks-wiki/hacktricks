# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

AppleScript je jezik za automatizaciju koji može da šalje Apple Events aplikacijama koje podržavaju skriptovanje. Uz odgovarajuće dozvole, malware može da ubaci JavaScript u karticu browsera koji podržava skriptovanje ili da koristi System Events/Accessibility za klik na dijalog za dozvole. Apple Events i Accessibility su zasebni TCC servisi i uglavnom zahtevaju odgovarajuća odobrenja korisnika.<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
`abbeycode/AppleScripts` repository sadrži primere automatizacije.<sup>[[7]](#references)</sup>\
Više informacija o malware-u koji koristi applescripts pronađite [**ovde**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Automatizacija / TCC specifičnosti

Odobrenja za Apple Events su **usmerena**: prompt se odnosi na par **izvorni proces -> ciljni proces**. Kada korisnik klikne na **Allow**, budući zahtevi istog izvora ka istom cilju biće dozvoljeni sve dok se unos ne resetuje. Tokom testiranja, dovoljno je jednom odobriti `Terminal -> Finder` ili `Terminal -> System Events` da bi se dozvola kasnije ponovo koristila bez novog popup-a.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Ovo je naročito relevantno kada je **target** **Finder**, jer Finder uvek ima **Full Disk Access**, čak i ako se ne pojavljuje u FDA UI-ju. Zato se svaki host koji već ima Automation nad Finder-om može koristiti kao AppleScript/JXA proxy za pristup TCC-protected fajlovima.<sup>[[1]](#references)</sup> Generički Finder i System Events payload-i već su dokumentovani na [glavnoj TCC stranici](../README.md) i na [Apple Events stranici](../macos-apple-events.md).

### Moderne offensive tradecraft tehnike

`/usr/bin/osascript` je samo najvidljivija entry tačka. AppleScript i JXA se takođe mogu izvršavati iz **Mach-O binaries** putem **`NSAppleScript`** / **`OSAScript`**, što je korisno i za evasion i za rad unutar hosta koji već ima zanimljive TCC grants.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Ako napravite prilagođeni helper koji direktno šalje Apple Events, dodeljivanje **stvarnog identiteta aplikacije** čini testiranje i rad pouzdanijim. U praksi to znači ugrađivanje `Info.plist` datoteke sa `CFBundleIdentifier` i `NSAppleEventsUsageDescription`, potpisivanje binary datoteke i dodeljivanje `com.apple.security.automation.apple-events` entitlement-a. U suprotnom, Apple Events prompt se često pripisuje **parent host-u** (na primer `Terminal`-u), ili izvršavanje pomoću `NSAppleScript` jednostavno ne uspeva uz zbunjujuće greške `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

AppleScripts se mogu sačuvati u compiled formi i obično decompile-ovati pomoću `osadecompile`.

Međutim, ovi scripts se takođe mogu **export-ovati kao "Read only"** (pomoću opcije "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
U tom slučaju `osadecompile` odbija da povrati uobičajeni source, ali se bytecode i terminologija Apple Event i dalje mogu analizirati.

SentinelOne-ovo istraživanje run-only skripti opisuje kako povratiti strukturu uprkos tom ograničenju. `applescript-disassembler` i `aevt_decompile` pomažu pri pregledanju kompajlirane skripte i Apple Event podataka.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Slučajno i namerno zaobilaženje macOS TCC zaštite privatnosti korisnika](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Kako koristiti AppleScript u macOS CLI alatima: nedokumentovani delovi](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Kako ofanzivni akteri koriste AppleScript za napade na macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Avanture u reverse engineering-u zlonamernih run-only AppleScript skripti](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [abbeycode/Primeri AppleScripts skripti](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
