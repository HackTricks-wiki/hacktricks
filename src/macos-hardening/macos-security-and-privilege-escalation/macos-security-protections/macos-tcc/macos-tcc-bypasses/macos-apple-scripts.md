# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

To język skryptowy używany do automatyzacji zadań **poprzez interakcję z procesami zdalnymi**. Umożliwia dość łatwe **proszenie innych procesów o wykonanie określonych działań**. **Malware** może nadużywać tych funkcji w celu wykorzystywania funkcji eksportowanych przez inne procesy.\
Na przykład malware może **wstrzyknąć dowolny kod JS do stron otwartych w przeglądarce**. Może też **automatycznie klikać** niektóre prośby o zezwolenie wyświetlane użytkownikowi;<sup>[3]</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Oto kilka przykładów: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Więcej informacji o malware wykorzystującym applescripts znajdziesz [**tutaj**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automatyzacja / osobliwości TCC

Zgody na Apple Events są **kierunkowe**: monit dotyczy pary **proces źródłowy -> proces docelowy**. Gdy użytkownik kliknie **Allow**, przyszłe żądania z tego samego źródła do tego samego celu będą dozwolone do momentu zresetowania wpisu. Podczas testów jednorazowe przyznanie uprawnień dla `Terminal -> Finder` lub `Terminal -> System Events` wystarczy, aby później ponownie korzystać z tego uprawnienia bez kolejnego wyskakującego okna.<sup>[1]</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Jest to szczególnie istotne, gdy **targetem** jest **Finder**, ponieważ Finder zawsze ma **Full Disk Access**, nawet jeśli nie pojawia się on w interfejsie FDA. Dlatego każdy host, który ma już **Automation** względem Findera, może zostać użyty jako proxy AppleScript/JXA do uzyskiwania dostępu do plików chronionych przez TCC.<sup>[1]</sup> Ogólne payloady Findera i System Events zostały już opisane na [głównej stronie TCC](../README.md) oraz na [stronie Apple Events](../macos-apple-events.md).

### Modern offensive tradecraft

`/usr/bin/osascript` jest tylko najbardziej widocznym punktem wejścia. AppleScript i JXA mogą być również wykonywane z **binarnych plików Mach-O** za pośrednictwem **`NSAppleScript`** / **`OSAScript`**, co jest przydatne zarówno do evasion, jak i do działania wewnątrz hosta, który ma już interesujące uprawnienia TCC.<sup>[2]</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Jeśli zbudujesz własny helper, który bezpośrednio wysyła Apple Events, nadanie mu **rzeczywistej tożsamości aplikacji** znacznie zwiększa niezawodność testowania i operacji. W praktyce oznacza to osadzenie `Info.plist` zawierającego `CFBundleIdentifier` i `NSAppleEventsUsageDescription`, podpisanie pliku binarnego oraz przyznanie entitlementu `com.apple.security.automation.apple-events`. W przeciwnym razie monit Apple Events jest często przypisywany **nadrzędnemu hostowi** (na przykład `Terminal`), albo wykonanie `NSAppleScript` kończy się niejasnymi błędami `-1750` / `errOSASystemError`.<sup>[2]</sup>

Skrypty AppleScript można łatwo "**kompilować**". Te wersje można łatwo "**dekompilować**" za pomocą `osadecompile`

Skrypty te można jednak również **eksportować jako „Tylko do odczytu”** (za pomocą opcji „Eksportuj...”):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
a w tym przypadku zawartości nie można zdekompilować nawet za pomocą `osadecompile`

Nadal istnieją jednak narzędzia, których można użyć do zrozumienia tego rodzaju plików wykonywalnych — [**przeczytaj to opracowanie, aby uzyskać więcej informacji**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[4]</sup> Narzędzie [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) wraz z [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) będzie bardzo pomocne w zrozumieniu działania skryptu.

## Referencje

- [1] [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [How Offensive Actors Use AppleScript For Attacking macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Adventures in Reversing Malicious Run-Only AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
