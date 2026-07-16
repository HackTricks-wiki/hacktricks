# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui Tabanlı Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) to **decompile** from wasm (binary) to wat (clear text)
- Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) to **compile** from wat to wasm
- you can also try to use [https://wwwg.github.io/web-webasmdec/](https://wwwg.github.io/web-webasmdec/) to decompile

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek, **birden fazla formatı decompile eden ve inceleyen** bir decompiler'dır; bunlara **libraries** (.dll), **Windows metadata file**ler (.winmd) ve **executables** (.exe) dahildir. Decompile edildikten sonra, bir assembly Visual Studio project (.csproj) olarak kaydedilebilir.

Buradaki avantaj, kaybolmuş bir source code'un eski bir assembly'den geri getirilmesi gerekiyorsa bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilmiş code içinde kullanışlı navigation sağlar ve bu da onu **Xamarin algorithm analysis** için kusursuz tools'lardan biri yapar.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in model ve tool'u tam ihtiyaçlarınıza göre genişleten bir API ile .NET reflector, zaman kazandırır ve development'ı basitleştirir. Bu tool'un sunduğu reverse engineering services bolluğuna bir göz atalım:

- Data'nın bir library veya component üzerinden nasıl aktığına dair insight sağlar
- .NET languages ve frameworks'ün implementation ve usage'ına dair insight sağlar
- APIs ve kullanılan technologies'den daha fazlasını elde etmek için documentation'ı olmayan ve exposed edilmemiş functionality'yi bulur.
- Dependencies ve farklı assemblies'i bulur
- Code'unuzdaki, third-party components ve libraries'deki hataların tam konumunu takip eder.
- Çalıştığınız tüm .NET code'un source'una debug eder.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy plugin](https://github.com/icsharpcode/ilspy-vscode): Bunu herhangi bir OS üzerinde kullanabilirsiniz (doğrudan VSCode içinden kurabilirsiniz, git'i indirmenize gerek yok. **Extensions**'a tıklayın ve **search ILSpy** yapın).\
Eğer **decompile**, **modify** ve tekrar **recompile** etmeniz gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya bunun aktif olarak bakımı yapılan bir fork'u olan [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir fonksiyonun içinde bir şeyi değiştirmek için **Right Click -> Modify Method**).

### DNSpy Logging

**DNSpy'nin** bir dosyaya bilgi loglamasını sağlamak için bu snippet'i kullanabilirsiniz:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

DNSpy kullanarak code debug etmek için şunları yapmanız gerekir:

Önce, **debugging** ile ilgili **Assembly attributes** değerlerini değiştirin:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

From:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
İçin:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Ve **compile** üzerine tıklayın:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Ardından yeni dosyayı _**File >> Save module...**_ ile kaydedin:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Bu gereklidir çünkü bunu yapmazsanız, **runtime** sırasında koda birkaç **optimisation** uygulanır ve debugging yaparken bir **break-point never hit** olabilir veya bazı **variables don't exist** olabilir.

Sonra, eğer .NET uygulamanız **IIS** tarafından **run** ediliyorsa, onu şu şekilde **restart** edebilirsiniz:
```
iisreset /noforce
```
Then, debugging işlemine başlamak için açık tüm dosyaları kapatmalı ve **Debug Tab** içinde **Attach to Process...** seçmelisiniz:

![DNSpy Logging - DNSpy Debugging: Then, in order to start debugging you should close all the opened files and inside the Debug Tab select Attach to Process](<../../images/image (318).png>)

Then **w3wp.exe** seçerek **IIS server**’a attach olun ve **attach** tıklayın:

![DNSpy Logging - DNSpy Debugging: Then select w3wp.exe to attach to the IIS server and click attach](<../../images/image (113).png>)

Şimdi process'i debug ettiğimize göre, onu durdurup tüm module'leri yükleme zamanı. Önce _Debug >> Break All_ tıklayın ve ardından _**Debug >> Windows >> Modules**_ tıklayın:

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (834).png>)

**Modules** içindeki herhangi bir module'a tıklayın ve **Open All Modules** seçin:

![DNSpy Logging - DNSpy Debugging: Click any module on Modules and select Open All Modules](<../../images/image (922).png>)

**Assembly Explorer** içinde herhangi bir module'a sağ tıklayın ve **Sort Assemblies** tıklayın:

![DNSpy Logging - DNSpy Debugging: Right click any module in Assembly Explorer and click Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Select " Suspend on library load/unload "](<../../images/image (868).png>)

- **Çalıştırma parametrelerini** ayarlayın; **DLL yolunu** ve çağırmak istediğiniz function'ı girin:

![Debugging DLLs - Using IDA: Configure the parameters of the execution putting the path to the DLL and the function that you want to call](<../../images/image (704).png>)

Sonra, debugging'e başladığınızda **her DLL yüklendiğinde execution durdurulacaktır**, ardından rundll32 DLL'inizi yüklediğinde execution duracaktır.

Ama, yüklenen DLL'in code'una nasıl ulaşırsınız? Bu yöntemle bilmiyorum.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Command Line**'ı değiştirin ( _File --> Change Command Line_ ) ve dll yolunu ile çağırmak istediğiniz function'ı ayarlayın, örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ kısmını değiştirin ve "**DLL Entry**" seçin.
- Ardından **execution'ı başlatın**, debugger her dll main'de duracaktır, bir noktada **dll'inizin dll Entry'sinde duracaksınız**. Oradan, breakpoint koymak istediğiniz noktaları arayın.

Notice that execution win64dbg'de herhangi bir nedenle durduğunda, **win64dbg window'sunun üst kısmına** bakarak **hangi code içinde olduğunuzu** görebilirsiniz:

![Using IDA - Using x64dbg/x32dbg: Notice that when the execution is stopped by any reason in win64dbg you can see in which code you are looking in the top of the win64dbg window](<../../images/image (842).png>)

Sonra buna bakarak execution'ın debug etmek istediğiniz dll içinde nerede durduğunu görebilirsiniz.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) çalışan bir oyunun memory'si içinde önemli values'ların nerede kaydedildiğini bulmak ve onları değiştirmek için kullanışlı bir programdır. Daha fazla bilgi için:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) GNU Project Debugger (GDB) için games odaklı bir front-end/reverse engineering tool'dur. Ancak reverse-engineering ile ilgili her türlü şey için kullanılabilir

[**Decompiler Explorer**](https://dogbolt.org/) çeşitli decompiler'lar için web front-end'dir. Bu web service, küçük executables üzerinde farklı decompiler'ların output'unu karşılaştırmanızı sağlar.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **shellcode**'u bir memory alanı içine **allocate** eder, size shellcode'un allocate edildiği **memory address**'i **indicate** eder ve execution'ı **stop** eder.\
Sonra process'e bir **debugger attach** etmeniz gerekir (Ida veya x64dbg) ve belirtilen memory address'e bir **breakpoint** koyup execution'ı **resume** etmelisiniz. Bu şekilde shellcode'u debug ediyor olacaksınız.

Releases github sayfası, compiled releases içeren zip'leri barındırır: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Aşağıdaki linkte Blobrunner'ın biraz değiştirilmiş bir sürümünü bulabilirsiniz. Bunu compile etmek için sadece Visual Studio Code'da bir C/C++ project oluşturun, code'u kopyalayıp yapıştırın ve build edin.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) blobrunner'a çok benzer. **shellcode**'u bir memory alanı içine **allocate** eder ve bir **eternal loop** başlatır. Sonra process'e **debugger attach** etmeniz, **play start wait 2-5 secs and press stop** yapmanız gerekir ve kendinizi **eternal loop** içinde bulursunuz. Eternal loop'un bir sonraki instruction'ına atlayın; çünkü bu shellcode'a yapılacak bir call olacaktır ve sonunda shellcode'u execute ederken kendinizi bulursunuz.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it is very similar to blobrunner. It will allocate the shellcode inside a space of memory, and start an...](<../../images/image (509).png>)

Compiled bir [jmp2it sürümünü releases page](https://github.com/adamkramer/jmp2it/releases/) içinde indirebilirsiniz.

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) radare'ın GUI'sidir. Cutter kullanarak shellcode'u emulate edebilir ve dinamik olarak inspect edebilirsiniz.

Cutter'ın "Open File" ve "Open Shellcode" seçeneklerine izin verdiğine dikkat edin. Benim durumumda shellcode'u file olarak açtığımda doğru şekilde decompile etti, ama shellcode olarak açtığımda etmedi:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it...](<../../images/image (562).png>)

Emulation'ı istediğiniz yerde başlatmak için oraya bir bp ayarlayın; görünüşe göre cutter emulation'ı otomatik olarak oradan başlatacaktır:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görebilirsiniz:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: You can see the stack for example inside a hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) denemelisiniz.\
Size **shellcode**'un hangi **functions**'ları kullandığını ve shellcode'un memory içinde kendini **decoding** edip etmediğini söyler.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg ayrıca, istediğiniz seçenekleri seçip shellcode'u çalıştırabileceğiniz bir graphical launcher ile de gelir

![Cutter kullanarak shellcode debugging - Shellcode obfuscation'ı kaldırma ve executed functions alma: scDbg ayrıca, istediğiniz seçenekleri seçip...](<../../images/image (258).png>)

**Create Dump** seçeneği, shellcode memory içinde dinamik olarak herhangi bir değişiklik yapılırsa son shellcode'u dump eder (decoded shellcode'u download etmek için kullanışlıdır). **start offset** belirli bir offset'ten shellcode'u başlatmak için kullanışlı olabilir. **Debug Shell** seçeneği, shellcode'u scDbg terminali kullanarak debug etmek için faydalıdır (ancak bu iş için önce açıklanan seçeneklerin herhangi birini daha iyi buluyorum, çünkü Ida veya x64dbg kullanabilirsiniz).

### CyberChef kullanarak Disassembling

Shellcode dosyanızı input olarak upload edin ve onu decompile etmek için aşağıdaki recipe'yi kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` gibi basit ifadeleri aritmetik (`+`, `-`, `*`) ve bitwise operatörleri (`&`, `|`, `^`, `~`, shifts) karıştıran formüllerin arkasına gizler. Buradaki önemli nokta, bu identities'in genellikle yalnızca **fixed-width modular arithmetic** altında doğru olmasıdır; yani carry ve overflow önemlidir:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Bu tür bir ifadeyi genel cebir araçlarıyla basitleştirirseniz, bit-width semantiği göz ardı edildiği için kolayca yanlış bir sonuç elde edebilirsiniz.

### Pratik iş akışı

1. **Orijinal bit-width’i koruyun** lifted code/IR/decompiler output’tan (`8/16/32/64` bits).
2. İfadeyi basitleştirmeye çalışmadan önce **sınıflandırın**:
- **Linear**: bitwise atomların ağırlıklı toplamları
- **Semilinear**: `x & 0xFF` gibi sabit maskelerle birlikte linear
- **Polynomial**: çarpımlar görünür
- **Mixed**: çarpımlar ve bitwise logic iç içe geçmiştir, çoğu zaman tekrar eden alt ifadelerle birlikte
3. Her aday yeniden yazımı **rastgele testler** veya bir **SMT proof** ile doğrulayın. Eşdeğerlik kanıtlanamıyorsa, tahmin etmek yerine orijinal ifadeyi koruyun.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) malware analysis ve protected-binary reversing için pratik bir MBA simplifier’dır. Tek bir genel rewrite pass’i her şeye uygulamak yerine ifadeyi sınıflandırır ve onu specialized pipeline’lardan geçirir.

Hızlı kullanım:
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

- **Linear MBA**: CoBRA ifadeyi Boolean girdiler üzerinde değerlendirir, bir signature türetir ve pattern matching, ANF conversion ve coefficient interpolation gibi birkaç recovery methodunu yarıştırır.
- **Semilinear MBA**: constant-masked atomlar bit-partitioned reconstruction ile yeniden oluşturulur, böylece masked bölgeler doğru kalır.
- **Polynomial/Mixed MBA**: çarpımlar cores olarak ayrıştırılır ve outer relation'ı sadeleştirmeden önce repeated subexpressions temporaries içine alınabilir.

Yaygın olarak recovery denenmeye değer bir mixed identity örneği:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Bu şu şekilde basitleştirilebilir:
```c
x * y
```
### Reversing notes

- Isolated exact computation sonrasında **lifted IR expressions** veya decompiler output üzerinde CoBRA çalıştırmayı tercih et.
- İfade masked arithmetic ya da narrow registers içinden geldiyse `--bitwidth` değerini açıkça kullan.
- Daha güçlü bir proof step gerekiyorsa, local Z3 notlarını burada kontrol et:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca bir **LLVM pass plugin** (`libCobraPass.so`) olarak da gelir; bu, sonraki analysis passes öncesinde MBA-heavy LLVM IR'yi normalize etmek istediğinde kullanışlıdır.
- Unsupported carry-sensitive mixed-domain residuals, original expression'ı korumak ve carry path üzerinde manuel reasoning yapmak gerektiğine dair bir signal olarak ele alınmalıdır.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator **`mov` için tüm instructions'ı değiştirir**(evet, gerçekten cool). Ayrıca executions flows'u değiştirmek için interruptions kullanır. Nasıl çalıştığı hakkında daha fazla bilgi için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Şanslıysan [demovfuscator](https://github.com/kirschju/demovfuscator) binary'yi deofuscate eder. Birkaç dependency'si vardır
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
And [keystone'u yükleyin](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Eğer bir **CTF** oynuyorsanız, **flag'i bulmak için bu workaround** çok faydalı olabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**'i bulmak için fonksiyonları `::main` ile arayın, şu örnekteki gibi:

![Movfuscator - Rust: To find the entry point search the functions by ::main like in](<../../images/image (1080).png>)

Bu durumda binary'nin adı authenticator olduğu için, bunun ilginç main fonksiyonu olduğu oldukça açık.\
Çağrılan **functions**'ların **name**'ini alıp, **inputs** ve **outputs**'larını öğrenmek için bunları **Internet**'te arayın.

### Recovering Rust strings from ELF firmware

**Rust ELF** binary'lerinde, birçok static string C-style NUL-terminated pointer olarak referans edilmez. Yaygın bir `rustc` düzeni, gerçek string blob'una işaret eden **`.data.rel.ro`** içinde bir **pointer/length tuple**'ıdır; bu blob **`.rodata`** içinde saklanır:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Bu, `strings` veya varsayılan Ghidra analizi komşu stringleri birleştirebilir ya da çapraz referansları tamamen kaçırabilir demektir.

Hızlı iş akışı:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`** sanal adresini ve boyutunu alın.
2. **`.data.rel.ro`** bölümünü birer word olacak şekilde enumerate edin.
3. `.rodata` adres aralığındaki herhangi bir değeri aday string pointer olarak kabul edin.
4. Sonraki word'ü aday length olarak kabul edin.
5. Sanity filtreleri uygulayın (örneğin, length değerlerini **4** ile **100** byte arasında tutun).
6. `0x00` değerine kadar taramak yerine `.rodata` içinden tam olarak `length` byte okuyun.

Minimal extractor logic:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Bu, firmware reversing’de özellikle faydalıdır çünkü kurtarılan Rust string’leri çoğu zaman **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers ve auth-related logic** ortaya çıkarır.

Eğer Ghidra bu string’leri kaçırıyorsa, aynı heuristic’i uygulayan ve referans verilen `.rodata` offset’lerinde string data oluşturan özel bir script/plugin çalıştırın. Pen Test Partners tarafından yayınlanan `rust-strings` ve `RustStrings.py` araçları, bu fikri diğer **word sizes, endianness ve section layouts** için uyarlamada iyi referanslardır.

## **Delphi**

Delphi compiled binaries için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz

Eğer bir Delphi binary reverse etmeniz gerekiyorsa, IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm

Sadece **ATL+f7** (IDA içinde python plugin import et) tuşuna basın ve python plugin’i seçin.

Bu plugin binary’yi çalıştıracak ve debugging’in başlangıcında function names’i dinamik olarak resolve edecektir. Debugging başladıktan sonra Start düğmesine tekrar basın (yeşil olan veya f9) ve gerçek code’un başında bir breakpoint tetiklenecektir.

Ayrıca çok ilginçtir çünkü graphic application’da bir butona basarsanız debugger, o buton tarafından çalıştırılan function’da duracaktır.

## Golang

Eğer bir Golang binary reverse etmeniz gerekiyorsa, IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm

Sadece **ATL+f7** (IDA içinde python plugin import et) tuşuna basın ve python plugin’i seçin.

Bu, function names’i resolve edecektir.

## Compiled Python

Bu sayfada bir ELF/EXE python compiled binary’den python code’u nasıl alacağınızı bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Bir GBA oyununun **binary** dosyasını elde ederseniz, onu **emulate** ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Interface’e sahip bir debugger içerir
- [**mgba** ](https://mgba.io)- CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünde Game Boy Advance **buttons** nasıl basılır görebilirsiniz

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Basıldığında, her **key** onu tanımlamak için bir **value**’ya sahiptir:
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
Bu tür bir programda ilginç olan kısım, **programın user input’u nasıl işlediğidir**. **0x4000130** adresinde, sık görülen fonksiyon olan **KEYINPUT**’i bulacaksınız.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

Önceki görselde, fonksiyonun **FUN_080015a8** içinden çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

Bu fonksiyonda, bazı init işlemlerinden sonra (önem taşımayan):
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
Son `if`, **`uVar4`**'ün **son Keys** içinde olup olmadığını ve mevcut key olmamasını kontrol ediyor; bu aynı zamanda bir butonu bırakma olarak da adlandırılır (mevcut key **`uVar1`** içinde saklanır).
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
Önceki kodda **uVar1**'i (**basılan düğmenin değeri** olan yer) bazı değerlerle karşılaştırdığımızı görebilirsiniz:

- İlk olarak, **4 değeri** ile (**SELECT** düğmesi) karşılaştırılıyor: Challenge'da bu düğme ekranı temizliyor
- Sonra, **8 değeri** ile (**START** düğmesi) karşılaştırılıyor: Challenge'da bu, flag'i almak için kodun geçerli olup olmadığını kontrol ediyor.
- Bu durumda **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılıyor ve değer aynıysa bazı kodlar çalıştırılıyor.
- Diğer tüm durumlarda, bir cont (**`DAT_030000d4`**) kontrol ediliyor. Buna cont denmesinin nedeni, koda girildikten hemen sonra 1 ekleniyor olması.\
**E**ğer 8'den küçükse, **`DAT_030000d8`**'e değer **eklemeyi** içeren bir şey yapılıyor (temelde, cont 8'den küçük olduğu sürece bu değişkende basılan tuşların değerleri ekleniyor).

Dolayısıyla, bu challenge'da düğmelerin değerlerini bilerek, **uzunluğu 8'den küçük olan ve sonuçta toplamı 0xf3 eden bir kombinasyon basmanız gerekiyordu.**

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
- [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)

{{#include ../../banners/hacktricks-training.md}}
