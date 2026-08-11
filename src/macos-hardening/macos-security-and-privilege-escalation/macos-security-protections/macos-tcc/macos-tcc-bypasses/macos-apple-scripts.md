# Skrypty Apple

{{#include ../../../../../banners/hacktricks-training.md}}

## Skrypty Apple

AppleScript to język automatyzacji, który może wysyłać zdarzenia Apple do aplikacji obsługujących skrypty. Przy odpowiednich uprawnieniach malware może wstrzyknąć JavaScript do karty przeglądarki obsługującej skrypty lub użyć System Events/Accessibility do kliknięcia okna dialogowego z prośbą o przyznanie uprawnień. Apple Events i Accessibility to odrębne usługi TCC i zazwyczaj wymagają osobnych zgód użytkownika.<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Repozytorium `abbeycode/AppleScripts` zawiera przykłady automatyzacji.<sup>[[7]](#references)</sup>\
Więcej informacji o malware wykorzystującym applescripts znajdziesz [**tutaj**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Automatyzacja / osobliwości TCC

Zatwierdzenia Apple Events są **kierunkowe**: monit dotyczy pary **proces źródłowy -> proces docelowy**. Po kliknięciu przez użytkownika przycisku **Allow** przyszłe żądania z tego samego źródła do tego samego celu będą dozwolone do czasu zresetowania wpisu. Podczas testów jednokrotne przyznanie uprawnienia `Terminal -> Finder` lub `Terminal -> System Events` wystarczy, aby później ponownie wykorzystać to uprawnienie bez kolejnego wyskakującego okna.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Jest to szczególnie istotne, gdy **targetem** jest **Finder**, ponieważ Finder zawsze ma **Full Disk Access**, nawet jeśli nie pojawia się on w interfejsie FDA. Dlatego każdy host, który ma już Automation nad Finderem, może zostać użyty jako proxy AppleScript/JXA do uzyskiwania dostępu do plików chronionych przez TCC.<sup>[[1]](#references)</sup> Generyczne payloady Findera i System Events są już udokumentowane na [głównej stronie TCC](../README.md) oraz na [stronie Apple Events](../macos-apple-events.md).

### Modern offensive tradecraft

`/usr/bin/osascript` to tylko najbardziej widoczny punkt wejścia. AppleScript i JXA mogą być również wykonywane z poziomu **binarnych Mach-O** za pośrednictwem **`NSAppleScript`** / **`OSAScript`**, co jest przydatne zarówno do evasion, jak i do działania wewnątrz hosta, który ma już interesujące uprawnienia TCC.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Jeśli zbudujesz własny helper, który wysyła Apple Events bezpośrednio, nadanie mu **prawdziwej tożsamości aplikacji** znacznie zwiększa niezawodność testowania i operacji. W praktyce oznacza to osadzenie `Info.plist` z `CFBundleIdentifier` i `NSAppleEventsUsageDescription`, podpisanie pliku binarnego oraz przyznanie entitlementu `com.apple.security.automation.apple-events`. W przeciwnym razie monit Apple Events jest często przypisywany **nadrzędnemu hostowi** (na przykład `Terminal`), a wykonanie `NSAppleScript` po prostu kończy się mylącymi błędami `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

AppleScripts można zapisywać w skompilowanej formie i zwykle dekompilować za pomocą `osadecompile`.

Skrypty te można jednak również **eksportować jako „Tylko do odczytu”** (za pomocą opcji „Eksportuj...”):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
W takim przypadku `osadecompile` odmawia odzyskania zwykłego kodu źródłowego, ale nadal można analizować bytecode i terminologię Apple Event.

Badania SentinelOne dotyczące run-only opisują, jak odzyskać strukturę pomimo tego ograniczenia. `applescript-disassembler` i `aevt_decompile` pomagają analizować skompilowany skrypt oraz dane Apple Event.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Omijanie zabezpieczeń prywatności użytkownika macOS TCC przez przypadek i z premedytacją](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Uruchamianie AppleScript w narzędziach CLI macOS: nieudokumentowane elementy](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Jak hakerzy wykorzystują AppleScript do atakowania macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Przygody z analizą wsteczną złośliwych skryptów AppleScript typu run-only](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [Przykłady AppleScripts firmy abbeycode](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
