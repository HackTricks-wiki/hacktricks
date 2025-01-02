# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

To język skryptowy używany do automatyzacji zadań **interagujących z procesami zdalnymi**. Umożliwia dość łatwe **proszę inne procesy o wykonanie pewnych działań**. **Złośliwe oprogramowanie** może nadużywać tych funkcji, aby wykorzystać funkcje eksportowane przez inne procesy.\
Na przykład, złośliwe oprogramowanie mogłoby **wstrzyknąć dowolny kod JS w otwartych stronach przeglądarki**. Lub **automatycznie kliknąć** niektóre pozwolenia wymagane od użytkownika;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Oto kilka przykładów: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Znajdź więcej informacji o złośliwym oprogramowaniu używającym applescriptów [**tutaj**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Apple skrypty mogą być łatwo "**kompilowane**". Te wersje mogą być łatwo "**dekompilowane**" za pomocą `osadecompile`

Jednak te skrypty mogą być również **eksportowane jako "Tylko do odczytu"** (poprzez opcję "Eksportuj..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
i w tym przypadku zawartość nie może być dekompilowana nawet za pomocą `osadecompile`

Jednak nadal istnieją narzędzia, które można wykorzystać do zrozumienia tego rodzaju plików wykonywalnych, [**przeczytaj to badanie, aby uzyskać więcej informacji**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Narzędzie [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) z [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) będzie bardzo przydatne do zrozumienia, jak działa skrypt.

{{#include ../../../../../banners/hacktricks-training.md}}
