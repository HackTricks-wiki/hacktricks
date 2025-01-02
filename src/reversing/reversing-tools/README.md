{{#include ../../banners/hacktricks-training.md}}

# Przewodnik po dekompilacji Wasm i kompilacji Wat

W dziedzinie **WebAssembly** narzędzia do **dekompilacji** i **kompilacji** są niezbędne dla programistów. Ten przewodnik wprowadza niektóre zasoby online i oprogramowanie do obsługi plików **Wasm (WebAssembly binary)** i **Wat (WebAssembly text)**.

## Narzędzia online

- Aby **dekompilować** Wasm do Wat, przydatne jest narzędzie dostępne w [demonstracji wasm2wat Wabt](https://webassembly.github.io/wabt/demo/wasm2wat/index.html).
- Do **kompilacji** Wat z powrotem do Wasm służy [demonstracja wat2wasm Wabt](https://webassembly.github.io/wabt/demo/wat2wasm/).
- Inną opcję dekompilacji można znaleźć w [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Rozwiązania programowe

- Dla bardziej zaawansowanego rozwiązania, [JEB od PNF Software](https://www.pnfsoftware.com/jeb/demo) oferuje rozbudowane funkcje.
- Otwarty projekt [wasmdec](https://github.com/wwwg/wasmdec) jest również dostępny do zadań dekompilacji.

# Zasoby do dekompilacji .Net

Dekompilacja zestawów .Net może być realizowana za pomocą narzędzi takich jak:

- [ILSpy](https://github.com/icsharpcode/ILSpy), które oferuje również [wtyczkę do Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), umożliwiającą użycie na różnych platformach.
- Do zadań związanych z **dekompilacją**, **modyfikacją** i **rekompilacją** zaleca się [dnSpy](https://github.com/0xd4d/dnSpy/releases). **Kliknięcie prawym przyciskiem** na metodzie i wybranie **Modify Method** umożliwia zmiany w kodzie.
- [dotPeek od JetBrains](https://www.jetbrains.com/es-es/decompiler/) to kolejna alternatywa do dekompilacji zestawów .Net.

## Ulepszanie debugowania i logowania z DNSpy

### Logowanie DNSpy

Aby logować informacje do pliku za pomocą DNSpy, wprowadź następujący fragment kodu .Net:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Hasło: " + password + "\n");
%%%

### Debugowanie DNSpy

Aby skutecznie debugować z DNSpy, zaleca się sekwencję kroków w celu dostosowania **atrybutów Assembly** do debugowania, zapewniając, że optymalizacje, które mogą utrudniać debugowanie, są wyłączone. Proces ten obejmuje zmianę ustawień `DebuggableAttribute`, rekompilację zestawu i zapisanie zmian.

Ponadto, aby debugować aplikację .Net uruchamianą przez **IIS**, wykonanie `iisreset /noforce` restartuje IIS. Aby dołączyć DNSpy do procesu IIS w celu debugowania, przewodnik instruuje, aby wybrać proces **w3wp.exe** w DNSpy i rozpocząć sesję debugowania.

Aby uzyskać pełny widok załadowanych modułów podczas debugowania, zaleca się dostęp do okna **Modules** w DNSpy, a następnie otwarcie wszystkich modułów i posortowanie zestawów dla łatwiejszej nawigacji i debugowania.

Ten przewodnik podsumowuje istotę dekompilacji WebAssembly i .Net, oferując ścieżkę dla programistów do łatwego poruszania się po tych zadaniach.

## **Dekompilator Java**

Aby dekompilować bajtkod Java, te narzędzia mogą być bardzo pomocne:

- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Debugowanie DLL**

### Używając IDA

- **Rundll32** jest ładowany z określonych ścieżek dla wersji 64-bitowych i 32-bitowych.
- **Windbg** jest wybierany jako debugger z włączoną opcją wstrzymywania przy ładowaniu/wyładowywaniu biblioteki.
- Parametry wykonania obejmują ścieżkę DLL i nazwę funkcji. Ta konfiguracja zatrzymuje wykonanie przy każdym ładowaniu DLL.

### Używając x64dbg/x32dbg

- Podobnie jak w IDA, **rundll32** jest ładowany z modyfikacjami wiersza poleceń, aby określić DLL i funkcję.
- Ustawienia są dostosowywane, aby przerwać przy wejściu DLL, co pozwala na ustawienie punktu przerwania w żądanym punkcie wejścia DLL.

### Obrazy

- Punkty zatrzymania wykonania i konfiguracje są ilustrowane za pomocą zrzutów ekranu.

## **ARM & MIPS**

- Do emulacji, [arm_now](https://github.com/nongiach/arm_now) jest przydatnym zasobem.

## **Shellcodes**

### Techniki debugowania

- **Blobrunner** i **jmp2it** to narzędzia do alokacji shellcodów w pamięci i debugowania ich za pomocą Ida lub x64dbg.
- Blobrunner [wydania](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [skompilowana wersja](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** oferuje emulację shellcode w oparciu o GUI i inspekcję, podkreślając różnice w obsłudze shellcode jako pliku w porównaniu do bezpośredniego shellcode.

### Deobfuskacja i analiza

- **scdbg** dostarcza informacji na temat funkcji shellcode i możliwości deobfuskacji.
%%%bash
scdbg.exe -f shellcode # Podstawowe informacje
scdbg.exe -f shellcode -r # Raport analizy
scdbg.exe -f shellcode -i -r # Interaktywne haki
scdbg.exe -f shellcode -d # Zrzut zdekodowanego shellcode
scdbg.exe -f shellcode /findsc # Znajdź offset startowy
scdbg.exe -f shellcode /foff 0x0000004D # Wykonaj z offsetu
%%%

- **CyberChef** do deasemblacji shellcode: [przepis CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**

- Obfuskator, który zastępuje wszystkie instrukcje `mov`.
- Przydatne zasoby to [wyjaśnienie na YouTube](https://www.youtube.com/watch?v=2VF_wPkiBJY) oraz [slajdy PDF](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** może odwrócić obfuskację movfuscatora, wymagając zależności takich jak `libcapstone-dev` i `libz3-dev`, oraz instalacji [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).

## **Delphi**

- Dla binarnych plików Delphi, zaleca się [IDR](https://github.com/crypto2011/IDR).

# Kursy

- [https://github.com/
