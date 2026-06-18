# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

To język skryptowy używany do automatyzacji zadań **interakcji ze zdalnymi procesami**. Ułatwia **proszenie innych procesów o wykonanie określonych działań**. **Malware** może nadużywać tych funkcji, aby wykorzystywać funkcje eksportowane przez inne procesy.\
Na przykład malware może **wstrzyknąć dowolny kod JS do otwartych stron w przeglądarce**. Albo **automatycznie klikać** wszelkie prośby o uprawnienia wyświetlane użytkownikowi;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Tutaj masz kilka przykładów: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Więcej informacji o malware używającym applescripts znajdziesz [**tutaj**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC quirks

Zatwierdzenia Apple Events są **kierunkowe**: prompt dotyczy pary **source process -> target process**. Gdy użytkownik kliknie **Allow**, przyszłe żądania z tego samego source do tego samego target są dozwolone, dopóki wpis nie zostanie zresetowany. Podczas testów jednorazowe nadanie `Terminal -> Finder` lub `Terminal -> System Events` wystarcza, aby później ponownie używać tego uprawnienia bez kolejnego popup.
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Jest to szczególnie istotne, gdy **celem** jest **Finder**, ponieważ Finder zawsze ma **Full Disk Access**, nawet jeśli nie pojawia się w UI FDA. Dlatego każdy host, który już ma Automation nad Finderem, może być użyty jako proxy AppleScript/JXA do uzyskiwania dostępu do plików chronionych przez TCC. Ogólne payloady dla Finder i System Events są już opisane na [głównej stronie TCC](../README.md) oraz na [stronie Apple Events](../macos-apple-events.md).

### Modern offensive tradecraft

`/usr/bin/osascript` to tylko najbardziej widoczny punkt wejścia. AppleScript i JXA mogą również wykonywać się z **binarek Mach-O** poprzez **`NSAppleScript`** / **`OSAScript`**, co jest przydatne zarówno do evasion, jak i do działania wewnątrz hosta, który już ma interesujące przyznania TCC.
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Jeśli zbudujesz niestandardowy helper, który wysyła Apple Events bezpośrednio, nadanie mu **prawdziwej tożsamości aplikacji** znacznie ułatwia testowanie i operacje. W praktyce oznacza to osadzenie `Info.plist` z `CFBundleIdentifier` i `NSAppleEventsUsageDescription`, podpisanie binarki oraz nadanie entitlement `com.apple.security.automation.apple-events`. W przeciwnym razie monit Apple Events jest często przypisywany do **rodzica hosta** (na przykład `Terminal`) albo wykonanie `NSAppleScript` po prostu kończy się niejasnymi błędami `-1750` / `errOSASystemError`.

Apple scripts mogą być łatwo "**compiled**". Te wersje można łatwo "**decompiled**" za pomocą `osadecompile`

Jednak te skrypty mogą też zostać **wyeksportowane jako "Read only"** (przez opcję "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
i w tym przypadku zawartości nie da się zdekompilować nawet za pomocą `osadecompile`

Jednak nadal istnieją narzędzia, których można użyć do zrozumienia tego typu plików wykonywalnych, [**przeczytaj to badanie, aby uzyskać więcej informacji**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Narzędzie [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) wraz z [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) będą bardzo przydatne do zrozumienia, jak działa skrypt.

## References

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}
