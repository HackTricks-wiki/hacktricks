# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui Based Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) to **decompile** from wasm (binary) to wat (clear text)
- Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) to **compile** from wat to wasm
- you can also try to use [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) to decompile

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek, **libraries** (.dll), **Windows metadata file**s (.winmd) ve **executables** (.exe) dahil olmak üzere **birden çok formatı decompile eden ve inceleyen** bir decompiler'dır. Decompile edildikten sonra, bir assembly Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantaj, kaybolmuş bir source code’un eski bir assembly'den geri kazanılması gerekiyorsa bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilen code içinde kullanışlı navigation sağlar ve bu da onu **Xamarin algorithm analysis** için mükemmel araçlardan biri yapar.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in modeline ve aracı tam ihtiyaçlarınıza göre genişleten bir API'ye sahip olan .NET reflector, zaman kazandırır ve development sürecini basitleştirir. Bu aracın sunduğu çok sayıdaki reverse engineering service'e bir göz atalım:

- Bir library veya component üzerinden data'nın nasıl aktığına dair insight sağlar
- .NET languages ve frameworks'lerin implementation ve usage'ına dair insight sağlar
- API'ler ve kullanılan technologies'den daha fazla yararlanmak için undocumented ve unexposed functionality bulur.
- Dependencies ve farklı assemblies bulur
- Code'unuzdaki, third-party components ve libraries içindeki hataların tam konumunu izler.
- Çalıştığınız tüm .NET code'un source'una kadar debug eder.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode): Bunu herhangi bir OS üzerinde kullanabilirsiniz (doğrudan VSCode içinden kurabilirsiniz, git'i indirmeye gerek yok. **Extensions**'a tıklayın ve **ILSpy** aratın).\
Eğer tekrar **decompile**, **modify** ve **recompile** etmeniz gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya onun aktif olarak bakımı yapılan bir fork'u olan [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (**Right Click -> Modify Method** ile bir function içindeki bir şeyi değiştirebilirsiniz).

### DNSpy Logging

**DNSpy'nin bir file'a** bazı information'ları log etmesini sağlamak için bu snippet'i kullanabilirsiniz:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

DNSpy kullanarak code debug etmek için şunları yapmanız gerekir:

Önce, **debugging** ile ilgili **Assembly attributes** değiştirin:

![](<../../images/image (973).png>)

From:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Kime:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Ve **compile** üzerine tıklayın:

![](<../../images/image (314) (1).png>)

Ardından yeni dosyayı _**File >> Save module...**_ ile kaydedin:

![](<../../images/image (602).png>)

Bu gereklidir çünkü bunu yapmazsanız, **runtime** sırasında koda çeşitli **optimisations** uygulanır ve bu durumda bir **break-point** hiç tetiklenmeyebilir ya da bazı **variables** var olmayabilir.

Ardından, eğer .NET uygulamanız **IIS** tarafından **run** ediliyorsa, onu şu şekilde **restart** edebilirsiniz:
```
iisreset /noforce
```
Then, debugging işlemine başlamak için açık olan tüm dosyaları kapatmalı ve **Debug Tab** içinde **Attach to Process...** seçmelisiniz:

![](<../../images/image (318).png>)

Ardından **IIS server**’a attach etmek için **w3wp.exe** seçin ve **attach** tıklayın:

![](<../../images/image (113).png>)

Şimdi process’i debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce _Debug >> Break All_ tıklayın ve sonra _**Debug >> Windows >> Modules**_ tıklayın:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

**Modules** içindeki herhangi bir module’a tıklayın ve **Open All Modules** seçin:

![](<../../images/image (922).png>)

**Assembly Explorer** içinde herhangi bir module’a sağ tıklayın ve **Sort Assemblies** tıklayın:

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

- **parameters** bölümünü, **DLL path** ve çağırmak istediğiniz function’u girerek yapılandırın:

![](<../../images/image (704).png>)

Sonra, debugging işlemine başladığınızda **her DLL yüklendiğinde execution duracaktır**, yani rundll32 sizin DLL’inizi yüklediğinde execution duracaktır.

Ama, yüklenen DLL’in code’una nasıl ulaşırsınız? Bu yöntemde bunu bilmiyorum.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Command Line**’ı değiştirin ( _File --> Change Command Line_ ) ve dll’in path’ini ve çağırmak istediğiniz function’u ayarlayın, örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ bölümünü değiştirin ve "**DLL Entry**" seçin.
- Sonra **execution**’ı başlatın, debugger her dll main’de duracaktır; bir noktada **dll’inizin DLL Entry** kısmında duracaksınız. Oradan, breakpoint koymak istediğiniz noktaları arayın.

Execution herhangi bir nedenle win64dbg içinde durduğunda, **win64dbg penceresinin üst kısmına** bakarak **hangi code içinde olduğunuzu** görebileceğinizi unutmayın:

![](<../../images/image (842).png>)

Sonra, buraya bakarak execution’un debug etmek istediğiniz dll içinde durup durmadığını görün.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) çalışan bir oyunun memory’si içinde önemli values’un nerede saklandığını bulmak ve onları değiştirmek için kullanışlı bir programdır. Daha fazla bilgi için:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), oyunlara odaklanan GNU Project Debugger (GDB) için bir front-end/reverse engineering tool’dur. Ancak, reverse-engineering ile ilgili her türlü şey için kullanılabilir

[**Decompiler Explorer**](https://dogbolt.org/) birçok decompiler için web front-end’idir. Bu web service, küçük executable’larda farklı decompiler’ların output’unu karşılaştırmanızı sağlar.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) shellcode’u bir memory alanı içine **allocate** eder, shellcode’un **allocate edildiği memory address**’i size **gösterir** ve execution’u **durdurur**.\
Sonra, process’e bir debugger (**Ida** veya **x64dbg**) **attach** etmeniz ve belirtilen memory address’e bir **breakpoint** koyup execution’u **resume** etmeniz gerekir. Bu şekilde shellcode’u debug ediyor olacaksınız.

Releases github sayfası, compiled releases içeren zip’leri barındırır: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Aşağıdaki linkte Blobrunner’ın biraz değiştirilmiş bir versiyonunu bulabilirsiniz. Compile etmek için sadece **Visual Studio Code içinde bir C/C++ project oluşturun, code’u kopyalayıp yapıştırın ve build edin**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)blobrunner’a çok benzer. Shellcode’u bir memory alanı içine **allocate** eder ve bir **eternal loop** başlatır. Sonra process’e **debugger’ı attach** etmeniz, **play start’a basıp 2-5 saniye beklemeniz ve stop’a basmanız** gerekir; böylece kendinizi **eternal loop** içinde bulursunuz. Eternal loop’un bir sonraki instruction’ına jump edin; çünkü bu shellcode’a bir call olacaktır ve sonunda shellcode’u execute ederken kendinizi bulacaksınız.

![](<../../images/image (509).png>)

[jmp2it’in releases sayfasından](https://github.com/adamkramer/jmp2it/releases/) compiled bir versiyon indirebilirsiniz.

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) radare’nin GUI’sidir. Cutter kullanarak shellcode’u emulate edebilir ve dinamik olarak inspect edebilirsiniz.

Cutter’ın size "Open File" ve "Open Shellcode" seçeneklerini sunduğunu unutmayın. Benim durumumda shellcode’u dosya olarak açtığımda doğru şekilde decompile etti, ama shellcode olarak açtığımda etmedi:

![](<../../images/image (562).png>)

Emulation’u istediğiniz yerde başlatmak için oraya bir bp koyun ve görünüşe göre cutter emulation’u otomatik olarak oradan başlatacaktır:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

Örneğin stack’i bir hex dump içinde görebilirsiniz:

![](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) kullanmayı deneyin.\
Size shellcode’un hangi functions’ı kullandığı ve shellcode’un memory içinde kendini **decoding** edip etmediği gibi şeyleri söyleyecektir.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg ayrıca, istediğiniz seçenekleri seçip shellcode’u çalıştırabileceğiniz bir grafik başlatıcıya da sahiptir

![](<../../images/image (258).png>)

**Create Dump** seçeneği, shellcode dinamik olarak bellekte değiştirildiyse son shellcode’u dump eder (decoded shellcode’u indirmek için kullanışlıdır). **start offset** shellcode’u belirli bir offset’ten başlatmak için faydalı olabilir. **Debug Shell** seçeneği, shellcode’u scDbg terminali kullanarak debug etmek için kullanışlıdır (ancak bu konuda yukarıda açıklanan seçeneklerin herhangi birini daha iyi buluyorum, çünkü Ida veya x64dbg kullanabileceksiniz).

### CyberChef kullanarak disassemble etme

Shellcode dosyanızı input olarak yükleyin ve decompile etmek için aşağıdaki recipe’yi kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` gibi basit ifadeleri aritmetik (`+`, `-`, `*`) ve bitwise operatörleri (`&`, `|`, `^`, `~`, shifts) karıştıran formüllerin arkasına gizler. Önemli kısım şudur: bu özdeşlikler genellikle yalnızca **fixed-width modular arithmetic** altında doğru olur, bu yüzden carry ve overflow’lar önemlidir:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Bu tür bir ifadeyi genel cebir araçlarıyla basitleştirirseniz, bit-width semantiği göz ardı edildiği için kolayca yanlış bir sonuç elde edebilirsiniz.

### Pratik iş akışı

1. **Orijinal bit-width'i koruyun** kaldırılmış kod/IR/decompiler çıktısından (`8/16/32/64` bit).
2. Basitleştirmeye çalışmadan önce ifadeyi **sınıflandırın**:
- **Linear**: bitwise atomların ağırlıklı toplamları
- **Semilinear**: `x & 0xFF` gibi sabit maskelerle birlikte linear
- **Polynomial**: çarpımlar görünür
- **Mixed**: çarpımlar ve bitwise logic iç içe geçmiştir, çoğu zaman tekrarlanan alt ifadelerle
3. Her aday rewrite'ı rastgele testlerle veya bir SMT proof ile **doğrulayın**. Eşdeğerlik kanıtlanamıyorsa, tahmin etmek yerine orijinal ifadeyi koruyun.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) malware analysis ve protected-binary reversing için pratik bir MBA simplifier'dır. İfadeyi sınıflandırır ve her şeye tek bir generic rewrite pass uygulamak yerine onu specialized pipeline'lar üzerinden yönlendirir.

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
Faydalı durumlar:

- **Linear MBA**: CoBRA ifadenin Boolean girdiler üzerindeki değerlendirmesini yapar, bir signature çıkarır ve pattern matching, ANF conversion ve coefficient interpolation gibi birkaç recovery methodunu yarışır.
- **Semilinear MBA**: constant-masked atoms, bit-partitioned reconstruction ile yeniden oluşturulur; böylece masked bölgeler doğru kalır.
- **Polynomial/Mixed MBA**: products core'lara ayrıştırılır ve tekrar eden subexpression'lar dış ilişki sadeleştirilmeden önce temporaries içine lift edilebilir.

Sıklıkla recovery denemeye değer olan mixed identity örneği:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Bu şu hale gelebilir:
```c
x * y
```
### Reversing notes

- Exact computation'ı izole ettikten sonra `CoBRA`yı **lifted IR expressions** veya decompiler çıktısı üzerinde çalıştırmayı tercih et.
- Expression masked arithmetic veya narrow register'lardan geldiyse `--bitwidth` değerini açıkça kullan.
- Daha güçlü bir proof adımına ihtiyacın varsa, yerel Z3 notlarını burada kontrol et:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- `CoBRA`, ayrıca **LLVM pass plugin** (`libCobraPass.so`) olarak da gelir; bu, daha sonraki analysis passes öncesinde MBA-ağır LLVM IR'ı normalize etmek istediğinde faydalıdır.
- Unsupported carry-sensitive mixed-domain residuals, original expression'ı korumak ve carry path'i manuel olarak reason etmek gerektiğine dair bir signal olarak ele alınmalıdır.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, **mov için tüm instructions'ları değiştirir**(evet, gerçekten cool). Ayrıca execution flow'ları değiştirmek için interruptions kullanır. Nasıl çalıştığı hakkında daha fazla bilgi için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Şanslıysan [demovfuscator](https://github.com/kirschju/demovfuscator) binary'yi deofuscate eder. Birkaç dependency'si var
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Ve [keystone yükleyin](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Eğer bir **CTF** oynuyorsanız, **flag'i bulmak için bu workaround** çok faydalı olabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**'i bulmak için fonksiyonları `::main` ile arayın, örneğin:

![](<../../images/image (1080).png>)

Bu durumda binary'nin adı authenticator idi, bu yüzden bunun ilginç main function olduğu oldukça açık.\
Çağrılan **functions**'ların **name**'ine sahip olduktan sonra, bunların **inputs** ve **outputs**'ları hakkında bilgi edinmek için bunları **Internet** üzerinde arayın.

## **Delphi**

Delphi ile derlenmiş binaries için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz

Eğer bir Delphi binary'sini reverse etmeniz gerekiyorsa, IDA eklentisi [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm

Sadece **ATL+f7**'ye basın (IDA içinde python plugin import et) ve python plugin seçin.

Bu plugin binary'yi execute eder ve debugging'in başlangıcında function names'i dinamik olarak çözer. Debugging'i başlattıktan sonra Start butonuna tekrar basın (yeşil olan veya f9) ve gerçek kodun başında bir breakpoint tetiklenecektir.

Ayrıca çok ilginçtir, çünkü grafik uygulamada bir butona basarsanız debugger, o bottom tarafından execute edilen function'da duracaktır.

## Golang

Bir Golang binary'sini reverse etmeniz gerekiyorsa, IDA eklentisi [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm

Sadece **ATL+f7**'ye basın (IDA içinde python plugin import et) ve python plugin seçin.

Bu, function names'i çözecektir.

## Compiled Python

Bu sayfada, bir ELF/EXE python compiled binary'den python code'u nasıl elde edeceğinizi bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Bir GBA oyununun **binary**'sini elde ederseniz, onu **emulate** ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Debug sürümünü indirin_) - Arayüzlü bir debugger içerir
- [**mgba** ](https://mgba.io)- CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünde Game Boy Advance **buttons**'larına nasıl basılacağını görebilirsiniz

![](<../../images/image (581).png>)

Basıldığında, her **key** onu tanımlamak için bir **value**'ya sahiptir:
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
Yani, bu tür bir programda ilginç kısım **programın user input'u nasıl işlediği** olacaktır. **0x4000130** adresinde, yaygın olarak bulunan function olan **KEYINPUT**'u bulacaksınız.

![](<../../images/image (447).png>)

Önceki image'da, function'ın **FUN_080015a8** tarafından çağrıldığını görebilirsiniz (addresses: _0x080015fa_ ve _0x080017ac_).

Bu function'da, bazı init operations'tan sonra (önemli olmayan):
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
Bu kod bulundu:
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
Son `if`, **`uVar4`**’ün **son Keys** içinde olup olmadığını ve mevcut key olmadığını kontrol ediyor; buna aynı zamanda bir butonu bırakmak da denir (mevcut key **`uVar1`** içinde saklanır).
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
Önceki kodda görebileceğiniz gibi, **uVar1**'i (**basılan button'un değeri**nin bulunduğu yer) bazı değerlerle karşılaştırıyoruz:

- İlk olarak, **değer 4** (**SELECT** button) ile karşılaştırılıyor: challenge'da bu button ekranı temizliyor
- Ardından, **değer 8** (**START** button) ile karşılaştırılıyor: challenge'da bu, flag'i almak için code'un geçerli olup olmadığını kontrol ediyor.
- Bu durumda **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılıyor ve değer aynıysa bazı code çalıştırılıyor.
- Diğer herhangi bir durumda, bazı cont (**`DAT_030000d4`**) kontrol ediliyor. Buna cont deniyor çünkü code'a girdikten hemen sonra 1 ekleniyor.\
**E**ğer 8'den küçükse, **`DAT_030000d8`**'e değerler **eklemeyi** içeren bir şey yapılıyor (temelde, cont 8'den küçük olduğu sürece bu değişkende basılan keys'in değerleri toplanıyor).

Yani, bu challenge'da, button değerlerini bilerek, sonucu 0xf3 olan bir toplama elde edecek şekilde **8'den kısa uzunlukta bir kombinasyon basmanız** gerekiyordu.

**Bu tutorial için referans:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

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
