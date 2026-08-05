# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

To język skryptowy używany do automatyzacji zadań poprzez **interakcję ze zdalnymi procesami**. Umożliwia dość łatwe **poproszenie innych procesów o wykonanie określonych działań**. **Malware** może nadużywać tych funkcji w celu wykorzystania funkcji eksportowanych przez inne procesy.\
Na przykład malware może **wstrzykiwać dowolny kod JS do stron otwartych w przeglądarce**. Może też **automatycznie klikać** niektóre żądane przez użytkownika uprawnienia;<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Oto kilka przykładów: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Więcej informacji o malware wykorzystującym applescripts znajdziesz [**tutaj**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automatyzacja / osobliwości TCC

Zatwierdzenia Apple Events są **kierunkowe**: monit dotyczy pary **source process -> target process**. Gdy użytkownik kliknie **Allow**, kolejne żądania z tego samego source do tego samego target są dozwolone do momentu zresetowania wpisu. Podczas testów jednokrotne przyznanie uprawnienia `Terminal -> Finder` lub `Terminal -> System Events` wystarczy, aby później ponownie używać tego uprawnienia bez kolejnego wyskakującego okna.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Jest to szczególnie istotne, gdy **targetem** jest **Finder**, ponieważ Finder zawsze ma **Full Disk Access**, nawet jeśli nie pojawia się on w interfejsie FDA. Dlatego każdy host, który ma już **Automation** wobec Findera, może zostać użyty jako proxy AppleScript/JXA do uzyskiwania dostępu do plików chronionych przez TCC.<sup>[[1]](#references)</sup> Ogólne payloads dla Findera i System Events zostały już opisane na [głównej stronie TCC](../README.md) oraz na [stronie Apple Events](../macos-apple-events.md).

### Współczesne offensive tradecraft

`/usr/bin/osascript` jest tylko najbardziej widocznym punktem wejścia. AppleScript i JXA mogą być również wykonywane z poziomu **Mach-O binaries** za pośrednictwem **`NSAppleScript`** / **`OSAScript`**, co jest przydatne zarówno do evasion, jak i do działania wewnątrz hosta, który ma już interesujące uprawnienia TCC.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Jeśli zbudujesz własne narzędzie pomocnicze, które wysyła Apple Events bezpośrednio, nadanie mu **prawdziwej tożsamości aplikacji** znacznie zwiększa niezawodność testowania i operacji. W praktyce oznacza to osadzenie `Info.plist` zawierającego `CFBundleIdentifier` i `NSAppleEventsUsageDescription`, podpisanie pliku binarnego oraz przyznanie entitlementu `com.apple.security.automation.apple-events`. W przeciwnym razie monit Apple Events jest często przypisywany **hostowi nadrzędnemu** (na przykład `Terminal`), a wykonanie `NSAppleScript` kończy się niepowodzeniem z mylącymi błędami `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Skrypty Apple można łatwo **kompilować**. Te wersje można łatwo **dekompilować** za pomocą `osadecompile`

Skrypty te można jednak również **eksportować jako „Read only”** (za pomocą opcji „Export...”):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
a w tym przypadku zawartości nie można zdekompilować nawet za pomocą `osadecompile`

Nadal jednak istnieją narzędzia, których można użyć do zrozumienia tego rodzaju plików wykonywalnych, [**przeczytaj to opracowanie, aby uzyskać więcej informacji**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> Narzędzie [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) wraz z [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) będzie bardzo pomocne w zrozumieniu działania skryptu.

## Referencje

- [1] [Omijanie ochrony prywatności użytkownika macOS TCC przez przypadek i z założenia](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Uruchamianie AppleScript w narzędziach CLI macOS: nieudokumentowane aspekty](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Jak hakerzy wykorzystują AppleScript do atakowania macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Przygody z reverse engineeringiem złośliwych skryptów AppleScript typu run-only](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
