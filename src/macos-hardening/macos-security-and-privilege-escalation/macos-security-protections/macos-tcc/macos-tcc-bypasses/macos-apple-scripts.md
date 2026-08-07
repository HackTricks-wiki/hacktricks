# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

To język skryptowy używany do automatyzacji zadań **poprzez interakcję ze zdalnymi procesami**. Umożliwia dość łatwe **proszenie innych procesów o wykonanie określonych działań**. **Malware** może nadużywać tych funkcji, aby wykorzystywać funkcje eksportowane przez inne procesy.\
Na przykład malware może **wstrzyknąć dowolny kod JS do stron otwartych w przeglądarce**. Może też **automatycznie klikać** niektóre prośby o przyznanie uprawnień wyświetlane użytkownikowi;<sup>[[3]](#references)</sup>.
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Oto kilka przykładów: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Więcej informacji o malware wykorzystującym AppleScripts znajdziesz [**tutaj**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Automatyzacja / osobliwości TCC

Zgody Apple Events są **kierunkowe**: monit dotyczy pary **proces źródłowy -> proces docelowy**. Po kliknięciu przez użytkownika **Allow** kolejne żądania z tego samego źródła do tego samego celu są dozwolone do momentu zresetowania wpisu. Podczas testów jednorazowe przyznanie uprawnienia `Terminal -> Finder` lub `Terminal -> System Events` wystarcza, aby później ponownie użyć tego uprawnienia bez kolejnego wyskakującego okna.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Jest to szczególnie istotne, gdy **targetem** jest **Finder**, ponieważ Finder zawsze ma **Full Disk Access**, nawet jeśli nie pojawia się ono w interfejsie FDA. Dlatego każdy host, który ma już **Automation** nad Finderem, może zostać użyty jako proxy AppleScript/JXA do uzyskiwania dostępu do plików chronionych przez TCC.<sup>[[1]](#references)</sup> Ogólne payloads Findera i System Events zostały już udokumentowane na [głównej stronie TCC](../README.md) oraz na [stronie Apple Events](../macos-apple-events.md).

### Nowoczesny offensive tradecraft

`/usr/bin/osascript` to tylko najbardziej widoczny entry point. AppleScript i JXA mogą być również wykonywane z poziomu **Mach-O binaries** za pośrednictwem **`NSAppleScript`** / **`OSAScript`**, co jest przydatne zarówno do evasion, jak i do działania wewnątrz hosta, który ma już interesujące uprawnienia TCC.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Jeśli utworzysz niestandardowy helper, który wysyła Apple Events bezpośrednio, nadanie mu **rzeczywistej tożsamości aplikacji** sprawi, że testowanie i operacje będą znacznie bardziej niezawodne. W praktyce oznacza to osadzenie `Info.plist` zawierającego `CFBundleIdentifier` i `NSAppleEventsUsageDescription`, podpisanie pliku binarnego oraz przyznanie entitlementu `com.apple.security.automation.apple-events`. W przeciwnym razie monit Apple Events jest często przypisywany do **nadrzędnego hosta** (na przykład `Terminal`), a wykonanie `NSAppleScript` po prostu kończy się niejasnymi błędami `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Skrypty Apple można łatwo "**kompilować**". Te wersje można łatwo "**dekompilować**" za pomocą `osadecompile`

Jednak te skrypty można również **eksportować jako „Tylko do odczytu”** (za pomocą opcji „Export...”):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
a w tym przypadku zawartości nie można zdekompilować nawet za pomocą `osadecompile`

Jednak nadal istnieją narzędzia, których można użyć do zrozumienia tego rodzaju plików wykonywalnych, [**przeczytaj to opracowanie, aby uzyskać więcej informacji**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> Narzędzie [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) wraz z [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) będzie bardzo przydatne do zrozumienia, jak działa skrypt.

## Referencje

- [1] [Omijanie zabezpieczeń macOS TCC chroniących prywatność użytkownika — przypadkowo i celowo](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Uruchamianie AppleScript w narzędziach CLI macOS: nieudokumentowane elementy](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Jak Offensive Actors wykorzystują AppleScript do atakowania macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Przygody związane z reversingiem złośliwych AppleScripts typu Run-Only](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
