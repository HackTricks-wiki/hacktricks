# Zana za Reversing & Mbinu za Msingi

{{#include ../../banners/hacktricks-training.md}}

## Zana za Reversing zenye msingi wa ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Tumia [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) ku **decompile** kutoka wasm (binary) hadi wat (clear text)
- Tumia [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) ku **compile** kutoka wat hadi wasm
- pia unaweza kujaribu kutumia [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) ku decompile

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek ni decompiler ambayo **decompiles and examines multiple formats**, ikijumuisha **libraries** (.dll), **Windows metadata file**s (.winmd), na **executables** (.exe). Mara baada ya decompile, assembly inaweza kuhifadhiwa kama Visual Studio project (.csproj).

Faida hapa ni kwamba ikiwa source code iliyopotea inahitaji kurejeshwa kutoka kwenye legacy assembly, hatua hii inaweza kuokoa muda. Zaidi ya hayo, dotPeek hutoa urambazaji rahisi kupitia code iliyodecompile, na kuifanya kuwa moja ya zana bora kabisa za **Xamarin algorithm analysis.**

### [ .NET Reflector ](https://www.red-gate.com/products/reflector/)

Kwa model ya add-in ya kina na API inayopanua zana ili ilingane na mahitaji yako mahususi, .NET reflector huokoa muda na hurahisisha development. Hebu tuchunguze wingi wa reverse engineering services ambazo zana hii hutoa:

- Hutoa mwanga kuhusu jinsi data inapita kupitia library au component
- Hutoa maarifa kuhusu implementation na matumizi ya .NET languages na frameworks
- Hutafuta functionality isiyoandikwa na isiyoonyeshwa ili kupata zaidi kutoka kwenye APIs na technologies zinazotumika.
- Hutafuta dependencies na assemblies tofauti
- Hufuatilia eneo sahihi la errors katika code yako, third-party components, na libraries.
- Hu-debug kwenye source ya code zote za .NET unazofanyia kazi.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Unaweza kuwa nayo kwenye OS yoyote (unaweza kuiinstall moja kwa moja kutoka VSCode, hakuna haja ya kupakua git. Bofya kwenye **Extensions** na **search ILSpy**).\
Ikiwa unahitaji **decompile**, **modify** na **recompile** tena unaweza kutumia [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) au fork yake inayodumishwa kikamilifu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** kubadilisha kitu ndani ya function).

### DNSpy Logging

Ili kufanya **DNSpy log some information in a file**, unaweza kutumia snippet hii:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Ili ku-debug code ukitumia DNSpy unahitaji:

Kwanza, badilisha **Assembly attributes** zinazohusiana na **debugging**:

![](<../../images/image (973).png>)

Kutoka:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Kwa:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Na ubofye **compile**:

![](<../../images/image (314) (1).png>)

Kisha hifadhi faili jipya kupitia _**File >> Save module...**_:

![](<../../images/image (602).png>)

Hii ni muhimu kwa sababu ukikosa kufanya hivi, wakati wa **runtime** baadhi ya **optimisations** zitatumika kwenye code na huenda wakati wa debugging **break-point is never hit** au baadhi ya **variables don't exist**.

Kisha, kama application yako ya .NET inaendeshwa na **IIS** unaweza kui **restart** kwa:
```
iisreset /noforce
```
Kemudian, untuk memulai debugging Anda harus menutup semua file yang terbuka dan di dalam **Debug Tab** pilih **Attach to Process...**:

![](<../../images/image (318).png>)

Lalu pilih **w3wp.exe** untuk attach ke **IIS server** dan klik **attach**:

![](<../../images/image (113).png>)

Sekarang karena kita sedang men-debug prosesnya, saatnya menghentikannya dan memuat semua modul. Pertama klik _Debug >> Break All_ lalu klik _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Klik modul apa pun di **Modules** dan pilih **Open All Modules**:

![](<../../images/image (922).png>)

Klik kanan modul apa pun di **Assembly Explorer** dan klik **Sort Assemblies**:

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![](<../../images/image (868).png>)

- Configure the **parameters** of the execution putting the **path to the DLL** and the function that you want to call:

![](<../../images/image (704).png>)

Kemudian, saat Anda memulai debugging **eksekusi akan berhenti ketika setiap DLL dimuat**, lalu saat rundll32 memuat DLL Anda, eksekusi akan berhenti.

Tetapi, bagaimana Anda bisa menuju ke kode dari DLL yang telah dimuat? Dengan metode ini, saya tidak tahu caranya.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Perhatikan bahwa ketika eksekusi dihentikan karena alasan apa pun di win64dbg Anda dapat melihat **di kode mana Anda berada** dengan melihat **bagian atas jendela win64dbg**:

![](<../../images/image (842).png>)

Lalu, dengan melihat ini Anda dapat melihat ketika eksekusi dihentikan di dll yang ingin Anda debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) adalah program yang berguna untuk menemukan di mana nilai-nilai penting disimpan di dalam memori game yang sedang berjalan dan mengubahnya. Info lebih lanjut di:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) adalah tool front-end/reverse engineering untuk GNU Project Debugger (GDB), dengan fokus pada games. Namun, tool ini dapat digunakan untuk apa pun yang terkait reverse-engineering

[**Decompiler Explorer**](https://dogbolt.org/) adalah front-end web untuk sejumlah decompiler. Layanan web ini memungkinkan Anda membandingkan output dari decompiler yang berbeda pada executable kecil.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) akan **mengalokasikan** **shellcode** di dalam ruang memori, akan **menunjukkan** kepada Anda **alamat memori** tempat shellcode dialokasikan dan akan **menghentikan** eksekusi.\
Lalu, Anda perlu **attach debugger** (Ida atau x64dbg) ke proses dan memasang **breakpoint pada alamat memori yang ditunjukkan** lalu **melanjutkan** eksekusi. Dengan cara ini Anda akan men-debug shellcode.

Halaman rilis github berisi zip yang berisi rilis yang sudah dikompilasi: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Anda dapat menemukan versi Blobrunner yang sedikit dimodifikasi di tautan berikut. Untuk mengompilasinya cukup **buat project C/C++ di Visual Studio Code, salin dan tempel kodenya lalu build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) sangat mirip dengan blobrunner. Tool ini akan **mengalokasikan** **shellcode** di dalam ruang memori, dan memulai **loop abadi**. Anda kemudian perlu **attach debugger** ke proses, **jalankan start lalu tunggu 2-5 detik dan tekan stop** dan Anda akan mendapati diri Anda berada di dalam **loop abadi**. Lompat ke instruksi berikutnya dari loop abadi karena itu akan menjadi call ke shellcode, dan akhirnya Anda akan mendapati diri Anda mengeksekusi shellcode.

![](<../../images/image (509).png>)

Anda dapat mengunduh versi terkompilasi dari [jmp2it di halaman releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) adalah GUI dari radare. Dengan Cutter Anda dapat mengemulasi shellcode dan memeriksanya secara dinamis.

Perhatikan bahwa Cutter memungkinkan Anda untuk "Open File" dan "Open Shellcode". Dalam kasus saya, ketika saya membuka shellcode sebagai file, ia mendekompilasinya dengan benar, tetapi ketika saya membukanya sebagai shellcode, tidak:

![](<../../images/image (562).png>)

Untuk memulai emulasi di tempat yang Anda inginkan, set bp di sana dan tampaknya Cutter akan otomatis memulai emulasi dari sana:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

Anda dapat melihat stack misalnya di dalam hex dump:

![](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Anda harus mencoba [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Tool ini akan memberi tahu Anda hal-hal seperti **fungsi mana** yang digunakan shellcode dan apakah shellcode **mendekode** dirinya sendiri di memori.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg pia ina launcher ya graphical ambapo unaweza kuchagua options unazotaka na ku-execute shellcode

![](<../../images/image (258).png>)

Option ya **Create Dump** itadump final shellcode ikiwa mabadiliko yoyote yamefanywa kwa shellcode dynamically kwenye memory (inafaa kupakua decoded shellcode). **start offset** inaweza kuwa ya manufaa kuanza shellcode kwenye offset maalum. Option ya **Debug Shell** ni muhimu kwa ku-debug shellcode kwa kutumia terminal ya scDbg (hata hivyo, naona options zozote zilizoelezwa kabla ni bora zaidi kwa jambo hili kwa sababu utaweza kutumia Ida au x64dbg).

### Disassembling using CyberChef

Pakia faili yako ya shellcode kama input na utumie recipe ifuatayo ku-decompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

Obfuscation ya **Mixed Boolean-Arithmetic (MBA)** huficha expressions rahisi kama `x + y` nyuma ya formulas zinazochanganya arithmetic (`+`, `-`, `*`) na bitwise operators (`&`, `|`, `^`, `~`, shifts). Sehemu muhimu ni kwamba identities hizi kwa kawaida huwa sahihi tu chini ya **fixed-width modular arithmetic**, hivyo carries na overflows ni muhimu:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Ukiirahisisha aina hii ya usemi kwa zana za kawaida za aljebra unaweza kupata matokeo yasiyo sahihi kwa urahisi kwa sababu semantiki za bit-width zilipuuzwa.

### Practical workflow

1. **Hifadhi bit-width asili** kutoka kwa code/IR/decompiler output iliyoinuliwa (`8/16/32/64` bits).
2. **Ainisha usemi** kabla ya kujaribu kuuirahisisha:
- **Linear**: weighted sums za bitwise atoms
- **Semilinear**: linear pamoja na constant masks kama `x & 0xFF`
- **Polynomial**: bidhaa hujitokeza
- **Mixed**: bidhaa na bitwise logic huchanganyika, mara nyingi zikiwa na repeated subexpressions
3. **Thibitisha kila candidate rewrite** kwa random testing au SMT proof. Ikiwa equivalence haiwezi kuthibitishwa, hifadhi usemi asili badala ya kubahatisha.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) ni practical MBA simplifier kwa malware analysis na protected-binary reversing. Inaainisha usemi na kuupeleka kupitia specialized pipelines badala ya kutumia generic rewrite pass moja kwa kila kitu.

Quick usage:
```bash
# Recover arithmetic from a logic-heavy MBA
cobra-cli --mba "(x&y)+(x|y)"
# x + y

# Preserve fixed-width wraparound semantics
cobra-cli --mba "(x&0xFF)+(x&0xFF00)" --bitwidth 16
# x

# Ask CoBRA to prove the rewrite with Z3
cobra-cli --mba "(a^b)+(a&b)+(a&b)" --verify
```
Kesi muhimu:

- **Linear MBA**: CoBRA hutathmini usemi kwenye ingizo za Boolean, hutengeneza signature, na hujaribu mbinu kadhaa za recovery kama pattern matching, ANF conversion, na coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms hujengwa upya kwa bit-partitioned reconstruction ili masked regions zibaki sahihi.
- **Polynomial/Mixed MBA**: products hutenganishwa kuwa cores na repeated subexpressions zinaweza kuhamishwa kuwa temporaries kabla ya kurahisisha outer relation.

Mfano wa mixed identity ambayo mara nyingi inafaa kujaribu ku-recover:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Hii inaweza kuporomoka hadi:
```c
x * y
```
### Vidokezo vya Reversing

- Pendelea kuendesha CoBRA kwenye **lifted IR expressions** au output ya decompiler baada ya kutenganisha computation halisi.
- Tumia `--bitwidth` waziwazi wakati expression imetoka kwenye masked arithmetic au narrow registers.
- Ikiwa unahitaji hatua ya uthibitisho yenye nguvu zaidi, angalia local Z3 notes hapa:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA pia inakuja kama **LLVM pass plugin** (`libCobraPass.so`), ambayo ni muhimu unapotaka ku-normalize MBA-heavy LLVM IR kabla ya analysis passes za baadaye.
- Unsupported carry-sensitive mixed-domain residuals zinapaswa kutazamwa kama ishara ya kuacha original expression na kufikiria kuhusu carry path manually.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

This obfuscator **modifies all the instructions for `mov`**(yeah, really cool). Pia hutumia interruptions kubadilisha executions flows. Kwa taarifa zaidi kuhusu jinsi inavyofanya kazi:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Kama una bahati [demovfuscator](https://github.com/kirschju/demovfuscator) ita-deofuscate binary. Ina dependencies kadhaa
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Na [sakinisha keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Ikiwa unacheza **CTF, workaround hii ya kupata flag** inaweza kuwa muhimu sana: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Ili kupata **entry point** tafuta functions kwa `::main` kama katika:

![](<../../images/image (1080).png>)

Katika kesi hii binary iliitwa authenticator, kwa hiyo ni wazi kwamba hiki ndicho main function cha kuvutia.\
Kuwa na **name** ya **functions** zinazopigwa simu, zitafute kwenye **Internet** ili kujifunza kuhusu **inputs** na **outputs** zake.

## **Delphi**

Kwa Delphi compiled binaries unaweza kutumia [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Ukilazimika reverse binary ya Delphi ningependekeza utumie IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Bonyeza tu **ATL+f7** (import python plugin in IDA) na chagua python plugin.

Plugin hii itatekeleza binary na kutatua function names kwa dynamically mwanzoni mwa debugging. Baada ya kuanza debugging bonyeza tena Start button (ile ya kijani au f9) na breakpoint itagonga mwanzo wa real code.

Pia ni ya kuvutia sana kwa sababu ukibonyeza button katika graphic application debugger itasimama kwenye function iliyotekelezwa na hiyo bottom.

## Golang

Ukilazimika reverse binary ya Golang ningependekeza utumie IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Bonyeza tu **ATL+f7** (import python plugin in IDA) na chagua python plugin.

Hii itatatua names za functions.

## Compiled Python

Katika ukurasa huu unaweza kupata jinsi ya kupata python code kutoka kwenye ELF/EXE python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Ukipata **binary** ya game ya GBA unaweza kutumia tools tofauti ku**emulate** na ku**debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Ina debugger yenye interface
- [**mgba** ](https://mgba.io)- Ina CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

Katika [**no$gba**](https://problemkaputt.de/gba.htm), katika _**Options --> Emulation Setup --> Controls**_** ** unaweza kuona jinsi ya kubonyeza Game Boy Advance **buttons**

![](<../../images/image (581).png>)

Inapobonyezwa, kila **key ina value** ya kuitambulisha:
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
Kwa hivyo, katika aina hii ya programu, sehemu ya kuvutia itakuwa **jinsi programu inavyoshughulikia user input**. Katika anwani **0x4000130** utapata function inayopatikana mara nyingi: **KEYINPUT**.

![](<../../images/image (447).png>)

Katika picha ya awali unaweza kuona kwamba function hiyo inaitwa kutoka **FUN_080015a8** (anwani: _0x080015fa_ na _0x080017ac_).

Katika function hiyo, baada ya baadhi ya init operations (bila umuhimu wowote):
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
Imepatikana msimbo huu:
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
If ya mwisho inakagua kwamba **`uVar4`** iko katika **last Keys** na si key ya sasa, pia huitwa kuachia kitufe (key ya sasa imehifadhiwa kwenye **`uVar1`**).
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
Katika code ya awali unaweza kuona kwamba tunalinganisha **uVar1** (mahali ambapo **thamani ya button iliyobanwa** iko) na baadhi ya thamani:

- Kwanza, inalinganishwa na **thamani 4** (**SELECT** button): Katika challenge button hii husafisha screen
- Kisha, inalinganishwa na **thamani 8** (**START** button): Katika challenge hii huangalia kama code ni sahihi ili kupata flag.
- Katika kesi hii var **`DAT_030000d8`** inalinganishwa na 0xf3 na ikiwa thamani ni ile ile baadhi ya code inatekelezwa.
- Katika kesi nyingine yoyote, cont fulani (**`DAT_030000d4`**) hukaguliwa. Ni cont kwa sababu inaongeza 1 mara tu baada ya kuingia kwenye code.\
**K**ama ni chini ya 8 kitu kinachohusisha **kuongeza** thamani kwenye **`DAT_030000d8`** hufanywa (kimsingi inaongeza thamani za keys zilizobanwa kwenye variable hii maadamu cont ni chini ya 8).

Hivyo, katika challenge hii, kwa kujua thamani za buttons, ulipaswa **kubonyeza mchanganyiko wenye urefu mdogo kuliko 8 ambao jumla yake ni 0xf3.**

**Reference for this tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)

{{#include ../../banners/hacktricks-training.md}}
