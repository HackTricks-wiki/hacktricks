# Narzędzia do Reversingu i Podstawowe Metody

{{#include ../../banners/hacktricks-training.md}}

## Narzędzia do Reversingu oparte na ImGui

Oprogramowanie:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Dekompilator Wasm / Kompilator Wat

Online:

- Użyj [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html), aby **dekompilować** z wasm (binarny) do wat (czysty tekst)
- Użyj [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/), aby **kompilować** z wat do wasm
- możesz także spróbować użyć [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/), aby dekompilować

Oprogramowanie:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Dekompilator .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek to dekompilator, który **dekompiluje i bada wiele formatów**, w tym **biblioteki** (.dll), **pliki metadanych Windows** (.winmd) oraz **wykonywalne** (.exe). Po dekompilacji, zestaw można zapisać jako projekt Visual Studio (.csproj).

Zaletą jest to, że jeśli utracony kod źródłowy wymaga przywrócenia z legacy assembly, ta akcja może zaoszczędzić czas. Ponadto, dotPeek zapewnia wygodną nawigację po dekompilowanym kodzie, co czyni go jednym z idealnych narzędzi do **analizy algorytmów Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Dzięki wszechstronnemu modelowi dodatków i API, które rozszerza narzędzie, aby dostosować je do Twoich dokładnych potrzeb, .NET Reflector oszczędza czas i upraszcza rozwój. Przyjrzyjmy się bogactwu usług inżynierii odwrotnej, które to narzędzie oferuje:

- Zapewnia wgląd w to, jak dane przepływają przez bibliotekę lub komponent
- Zapewnia wgląd w implementację i użycie języków i frameworków .NET
- Znajduje nieudokumentowane i nieujawnione funkcjonalności, aby uzyskać więcej z używanych API i technologii.
- Znajduje zależności i różne zestawy
- Śledzi dokładne miejsce błędów w Twoim kodzie, komponentach i bibliotekach osób trzecich.
- Debuguje źródło całego kodu .NET, z którym pracujesz.

### [ILSpy](https://github.com/icsharpcode/ILSpy) i [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy dla Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Możesz go mieć w każdym systemie operacyjnym (możesz zainstalować go bezpośrednio z VSCode, nie ma potrzeby pobierania gita. Kliknij na **Rozszerzenia** i **wyszukaj ILSpy**).\
Jeśli potrzebujesz **dekompilować**, **modyfikować** i **ponownie kompilować**, możesz użyć [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) lub aktywnie utrzymywanego forka, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Kliknij prawym przyciskiem -> Modyfikuj metodę**, aby zmienić coś w funkcji).

### Logowanie DNSpy

Aby **DNSpy logował pewne informacje w pliku**, możesz użyć tego fragmentu:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Aby debugować kod za pomocą DNSpy, musisz:

Najpierw zmienić **atrybuty Assembly** związane z **debugowaniem**:

![](<../../images/image (973).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Przepraszam, nie mogę pomóc w tej sprawie.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
I kliknij na **kompiluj**:

![](<../../images/image (314) (1).png>)

Następnie zapisz nowy plik za pomocą _**Plik >> Zapisz moduł...**_:

![](<../../images/image (602).png>)

Jest to konieczne, ponieważ jeśli tego nie zrobisz, w **czasie wykonywania** kilka **optymalizacji** zostanie zastosowanych do kodu i może się zdarzyć, że podczas debugowania **punkt przerwania nigdy nie zostanie osiągnięty** lub niektóre **zmienne nie istnieją**.

Następnie, jeśli twoja aplikacja .NET jest **uruchamiana** przez **IIS**, możesz ją **zrestartować** za pomocą:
```
iisreset /noforce
```
Aby rozpocząć debugowanie, powinieneś zamknąć wszystkie otwarte pliki, a następnie w **Debug Tab** wybrać **Attach to Process...**:

![](<../../images/image (318).png>)

Następnie wybierz **w3wp.exe**, aby podłączyć się do **serwera IIS** i kliknij **attach**:

![](<../../images/image (113).png>)

Teraz, gdy debugujemy proces, czas go zatrzymać i załadować wszystkie moduły. Najpierw kliknij na _Debug >> Break All_, a następnie kliknij na _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Kliknij dowolny moduł w **Modules** i wybierz **Open All Modules**:

![](<../../images/image (922).png>)

Kliknij prawym przyciskiem myszy dowolny moduł w **Assembly Explorer** i kliknij **Sort Assemblies**:

![](<../../images/image (339).png>)

## Decompiler Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugowanie DLL

### Używając IDA

- **Załaduj rundll32** (64 bity w C:\Windows\System32\rundll32.exe i 32 bity w C:\Windows\SysWOW64\rundll32.exe)
- Wybierz debugger **Windbg**
- Wybierz "**Suspend on library load/unload**"

![](<../../images/image (868).png>)

- Skonfiguruj **parametry** wykonania, podając **ścieżkę do DLL** i funkcję, którą chcesz wywołać:

![](<../../images/image (704).png>)

Następnie, gdy rozpoczniesz debugowanie, **wykonanie zostanie zatrzymane, gdy każda DLL zostanie załadowana**, a gdy rundll32 załaduje twoją DLL, wykonanie zostanie zatrzymane.

Ale jak możesz dotrzeć do kodu DLL, która została załadowana? Używając tej metody, nie wiem jak.

### Używając x64dbg/x32dbg

- **Załaduj rundll32** (64 bity w C:\Windows\System32\rundll32.exe i 32 bity w C:\Windows\SysWOW64\rundll32.exe)
- **Zmień linię poleceń** (_File --> Change Command Line_) i ustaw ścieżkę DLL oraz funkcję, którą chcesz wywołać, na przykład: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Zmień _Options --> Settings_ i wybierz "**DLL Entry**".
- Następnie **rozpocznij wykonanie**, debugger zatrzyma się w każdej głównej DLL, w pewnym momencie **zatrzymasz się w wejściu DLL twojej DLL**. Stamtąd po prostu poszukaj punktów, w których chcesz ustawić punkt przerwania.

Zauważ, że gdy wykonanie zostanie zatrzymane z jakiegokolwiek powodu w win64dbg, możesz zobaczyć **w którym kodzie jesteś**, patrząc na **górę okna win64dbg**:

![](<../../images/image (842).png>)

Następnie, patrząc na to, możesz zobaczyć, kiedy wykonanie zostało zatrzymane w DLL, którą chcesz debugować.

## Aplikacje GUI / Gry wideo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania, gdzie ważne wartości są zapisywane w pamięci działającej gry i ich zmiany. Więcej informacji w:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) to narzędzie front-end/reverse engineering dla GNU Project Debugger (GDB), skoncentrowane na grach. Może być jednak używane do wszelkich związanych z reverse-engineering.

[**Decompiler Explorer**](https://dogbolt.org/) to internetowy front-end do wielu dekompilatorów. Ta usługa internetowa pozwala porównywać wyniki różnych dekompilatorów na małych plikach wykonywalnych.

## ARM & MIPS

{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugowanie shellcode z blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **alokuje** **shellcode** w przestrzeni pamięci, **wskaże** ci **adres pamięci**, w którym shellcode został alokowany i **zatrzyma** wykonanie.\
Następnie musisz **podłączyć debugger** (Ida lub x64dbg) do procesu i ustawić **punkt przerwania w wskazanym adresie pamięci** oraz **wznowić** wykonanie. W ten sposób będziesz debugować shellcode.

Strona z wydaniami na githubie zawiera zips z skompilowanymi wydaniami: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Możesz znaleźć nieco zmodyfikowaną wersję Blobrunner w następującym linku. Aby ją skompilować, po prostu **stwórz projekt C/C++ w Visual Studio Code, skopiuj i wklej kod i zbuduj go**.

{{#ref}}
blobrunner.md
{{#endref}}

### Debugowanie shellcode z jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) jest bardzo podobny do blobrunner. **Alokuje** **shellcode** w przestrzeni pamięci i rozpoczyna **wieczną pętlę**. Następnie musisz **podłączyć debugger** do procesu, **uruchomić, poczekać 2-5 sekund i nacisnąć stop**, a znajdziesz się w **wiecznej pętli**. Przejdź do następnej instrukcji wiecznej pętli, ponieważ będzie to wywołanie do shellcode, a na końcu znajdziesz się w trakcie wykonywania shellcode.

![](<../../images/image (509).png>)

Możesz pobrać skompilowaną wersję [jmp2it na stronie wydań](https://github.com/adamkramer/jmp2it/releases/).

### Debugowanie shellcode za pomocą Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) to GUI radare. Używając cutter, możesz emulować shellcode i dynamicznie go badać.

Zauważ, że Cutter pozwala na "Otwórz plik" i "Otwórz shellcode". W moim przypadku, gdy otworzyłem shellcode jako plik, poprawnie go dekompilował, ale gdy otworzyłem go jako shellcode, nie:

![](<../../images/image (562).png>)

Aby rozpocząć emulację w miejscu, w którym chcesz, ustaw tam punkt przerwania, a Cutter automatycznie rozpocznie emulację stamtąd:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

Możesz zobaczyć stos na przykład w zrzucie heksadecymalnym:

![](<../../images/image (186).png>)

### Deobfuskacja shellcode i uzyskiwanie wywoływanych funkcji

Powinieneś spróbować [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Powie ci rzeczy takie jak **które funkcje** używa shellcode i czy shellcode **dekoduje** się w pamięci.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg posiada również graficzny launcher, w którym możesz wybrać opcje, które chcesz, i wykonać shellcode.

![](<../../images/image (258).png>)

Opcja **Create Dump** zrzuci końcowy shellcode, jeśli jakiekolwiek zmiany zostaną wprowadzone do shellcode dynamicznie w pamięci (przydatne do pobrania zdekodowanego shellcode). **Start offset** może być przydatny do rozpoczęcia shellcode w określonym offsetcie. Opcja **Debug Shell** jest przydatna do debugowania shellcode za pomocą terminala scDbg (jednak uważam, że jakiekolwiek z wcześniej opisanych opcji są lepsze w tej kwestii, ponieważ będziesz mógł używać Ida lub x64dbg).

### Disassembling using CyberChef

Prześlij swój plik shellcode jako wejście i użyj następującego przepisu, aby go dekompilować: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Ten obfuscator **modyfikuje wszystkie instrukcje dla `mov`** (tak, naprawdę fajne). Używa również przerwań do zmiany przepływów wykonania. Aby uzyskać więcej informacji na temat tego, jak to działa:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Jeśli masz szczęście, [demovfuscator](https://github.com/kirschju/demovfuscator) zdeobfuskowuje binarny plik. Ma kilka zależności.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
I [zainstaluj keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Jeśli grasz w **CTF, to obejście w celu znalezienia flagi** może być bardzo przydatne: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Aby znaleźć **punkt wejścia**, przeszukaj funkcje według `::main`, jak w:

![](<../../images/image (1080).png>)

W tym przypadku binarka nazywała się authenticator, więc jest dość oczywiste, że to jest interesująca funkcja główna.\
Mając **nazwy** wywoływanych **funkcji**, przeszukaj je w **Internecie**, aby dowiedzieć się o ich **wejściach** i **wyjściach**.

## **Delphi**

Dla skompilowanych binarek Delphi możesz użyć [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Jeśli musisz zrewersować binarkę Delphi, sugeruję użycie wtyczki IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Po prostu naciśnij **ATL+f7** (importuj wtyczkę python w IDA) i wybierz wtyczkę python.

Ta wtyczka wykona binarkę i dynamicznie rozwiąże nazwy funkcji na początku debugowania. Po rozpoczęciu debugowania naciśnij ponownie przycisk Start (zielony lub f9), a punkt przerwania zatrzyma się na początku rzeczywistego kodu.

Jest to również bardzo interesujące, ponieważ jeśli naciśniesz przycisk w aplikacji graficznej, debugger zatrzyma się w funkcji wywoływanej przez ten przycisk.

## Golang

Jeśli musisz zrewersować binarkę Golang, sugeruję użycie wtyczki IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Po prostu naciśnij **ATL+f7** (importuj wtyczkę python w IDA) i wybierz wtyczkę python.

To rozwiąże nazwy funkcji.

## Skompilowany Python

Na tej stronie możesz znaleźć, jak uzyskać kod python z binarki ELF/EXE skompilowanej w pythonie:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Jeśli zdobędziesz **binarkę** gry GBA, możesz użyć różnych narzędzi do **emulacji** i **debugowania**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Pobierz wersję debugującą_) - Zawiera debugger z interfejsem
- [**mgba** ](https://mgba.io) - Zawiera debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Wtyczka Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Wtyczka Ghidra

W [**no$gba**](https://problemkaputt.de/gba.htm), w _**Options --> Emulation Setup --> Controls**_** ** możesz zobaczyć, jak naciskać **przyciski** Game Boy Advance

![](<../../images/image (581).png>)

Po naciśnięciu każdy **klawisz ma wartość** do jego identyfikacji:
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
W takim programie interesującą częścią będzie **jak program traktuje dane wejściowe użytkownika**. Pod adresem **0x4000130** znajdziesz powszechnie występującą funkcję: **KEYINPUT**.

![](<../../images/image (447).png>)

Na poprzednim obrazie możesz zobaczyć, że funkcja jest wywoływana z **FUN_080015a8** (adresy: _0x080015fa_ i _0x080017ac_).

W tej funkcji, po kilku operacjach inicjalizacyjnych (bez większego znaczenia):
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
Znaleziono ten kod:
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
Ostatni warunek sprawdza, czy **`uVar4`** znajduje się w **ostatnich kluczach** i nie jest aktualnym kluczem, nazywanym również zwolnieniem przycisku (aktualny klucz jest przechowywany w **`uVar1`**).
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
W poprzednim kodzie widać, że porównujemy **uVar1** (miejsce, w którym znajduje się **wartość naciśniętego przycisku**) z pewnymi wartościami:

- Najpierw jest porównywana z **wartością 4** (**przycisk SELECT**): W wyzwaniu ten przycisk czyści ekran.
- Następnie jest porównywana z **wartością 8** (**przycisk START**): W wyzwaniu sprawdza, czy kod jest ważny, aby uzyskać flagę.
- W tym przypadku zmienna **`DAT_030000d8`** jest porównywana z 0xf3, a jeśli wartość jest taka sama, wykonywany jest pewien kod.
- W innych przypadkach sprawdzana jest zmienna cont (`DAT_030000d4`). To jest cont, ponieważ dodaje 1 zaraz po wejściu w kod.\
**Jeśli** jest mniej niż 8, wykonywane jest coś, co polega na **dodawaniu** wartości do **`DAT_030000d8`** (w zasadzie dodaje wartości naciśniętych klawiszy do tej zmiennej, o ile cont jest mniejszy niż 8).

Tak więc, w tym wyzwaniu, znając wartości przycisków, musiałeś **nacisnąć kombinację o długości mniejszej niż 8, której wynikowa suma to 0xf3.**

**Referencja do tego samouczka:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kursy

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (deobfuskacja binarna)

{{#include ../../banners/hacktricks-training.md}}
