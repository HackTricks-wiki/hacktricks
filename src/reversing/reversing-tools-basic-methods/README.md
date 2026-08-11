# Reversing Araçları ve Temel Yöntemler

{{#include ../../banners/hacktricks-training.md}}

## ImGui Tabanlı Reversing araçları

Yazılım:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Wasm'den (binary) wat'a (açık metin) **decompile** etmek için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kullanın
- Wat'tan wasm'e **compile** etmek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kullanın
- Decompilation için [web-wasmdec](https://wwwg.github.io/web-wasmdec/) aracını da deneyebilirsiniz.

Yazılım:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek; **library** (.dll), **Windows metadata dosyaları** (.winmd) ve **executable** (.exe) dahil olmak üzere **birden fazla formatı decompile eder ve inceler**. Decompile edildikten sonra bir assembly, Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantaj, kaybolmuş source code'un bir legacy assembly'den geri yüklenmesi gerektiğinde bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilmiş code içinde kullanışlı bir gezinme olanağı sunarak onu **Xamarin algorithm analysis** için en uygun araçlardan biri haline getirir.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in modeli ve aracı tam ihtiyaçlarınıza uyarlayan bir API ile .NET Reflector zamandan kazandırır ve geliştirmeyi kolaylaştırır. Bu aracın sunduğu çok sayıda reverse engineering hizmetine göz atalım:

- Verilerin bir library veya component içinde nasıl aktığına dair içgörü sağlar
- .NET dilleri ve framework'lerinin uygulanması ve kullanımı hakkında içgörü sağlar
- Kullanılan API'lerden ve teknolojilerden daha fazla yararlanmak için belgelenmemiş ve dışa açılmamış işlevleri bulur.
- Bağımlılıkları ve farklı assembly'leri bulur
- Code'unuzdaki, third-party component'lerdeki ve library'lerdeki hataların tam konumunu tespit eder.
- Çalıştığınız tüm .NET code'unun source'una kadar debug yapar.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy plugin'i](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir OS üzerinde kullanabilirsiniz (doğrudan VSCode'dan kurabilirsiniz; git'i indirmenize gerek yoktur. **Extensions**'a tıklayın ve **ILSpy** araması yapın).\
Yeniden **decompile**, **modify** ve **recompile** etmeniz gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak sürdürülen fork'u [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir function içindeki bir şeyi değiştirmek için **Right Click -> Modify Method**).

### DNSpy Logging

**DNSpy'ın bazı bilgileri bir file'a loglamasını** sağlamak için şu snippet'i kullanabilirsiniz:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

DNSpy kullanarak code debug etmek için şunları yapmanız gerekir:

Öncelikle **debugging** ile ilgili **Assembly attributes** değerlerini değiştirin:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

Şu konumdan:
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

![DNSpy Logging - DNSpy Debugging: Derleme üzerine tıklayın](<../../images/image (314) (1).png>)

Ardından yeni dosyayı _**File >> Save module...**_ aracılığıyla kaydedin:

![DNSpy Logging - DNSpy Debugging: Ardından yeni dosyayı File Save module aracılığıyla kaydedin](<../../images/image (602).png>)

Bunu yapmak gereklidir; çünkü bunu yapmazsanız **runtime** sırasında koda çeşitli **optimisations** uygulanır ve debugging sırasında bir **break-point**'e hiçbir zaman ulaşılamaması veya bazı **variables**'ların mevcut olmaması mümkün olabilir.

Ardından, .NET uygulamanız **IIS** tarafından **run** ediliyorsa şu komutla **restart** edebilirsiniz:
```
iisreset /noforce
```
Ardından debugging işlemine başlamak için açılmış tüm dosyaları kapatmalı ve **Debug Tab** içinde **Attach to Process...** seçeneğini seçmelisiniz:

![DNSpy Logging - DNSpy Debugging: Ardından debugging işlemine başlamak için açılmış tüm dosyaları kapatmalı ve Debug Tab içinde Attach to Process seçeneğini seçmelisiniz](<../../images/image (318).png>)

Ardından **IIS server**'a bağlanmak için **w3wp.exe**'yi seçin ve **attach**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Ardından IIS server'a bağlanmak için w3wp.exe'yi seçin ve attach'e tıklayın](<../../images/image (113).png>)

Artık process'i debug ettiğimize göre onu durdurmanın ve tüm modülleri yüklemenin zamanı geldi. Önce _Debug >> Break All_'a, ardından _**Debug >> Windows >> Modules**_'a tıklayın:

![DNSpy Logging - DNSpy Debugging: Artık process'i debug ettiğimize göre onu durdurmanın ve tüm modülleri yüklemenin zamanı geldi. Önce Debug Break All'a, ardından Debug Windows Modules'a tıklayın](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Artık process'i debug ettiğimize göre onu durdurmanın ve tüm modülleri yüklemenin zamanı geldi. Önce Debug Break All'a, ardından Debug Windows Modules'a tıklayın](<../../images/image (834).png>)

**Modules** içindeki herhangi bir modüle tıklayın ve **Open All Modules** seçeneğini seçin:

![DNSpy Logging - DNSpy Debugging: Modules içindeki herhangi bir modüle tıklayın ve Open All Modules seçeneğini seçin](<../../images/image (922).png>)

**Assembly Explorer** içindeki herhangi bir modüle sağ tıklayın ve **Sort Assemblies** seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer içindeki herhangi bir modüle sağ tıklayın ve Sort Assemblies seçeneğine tıklayın](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'leri Debug Etme

### IDA Kullanımı

- **rundll32'yi yükleyin** (64bit sürümü C:\Windows\System32\rundll32.exe içinde, 32bit sürümü ise C:\Windows\SysWOW64\rundll32.exe içindedir)
- **Windbg** debugger'ını seçin
- "**Suspend on library load/unload**" seçeneğini seçin

![Debugging DLLs - Using IDA: " Suspend on library load/unload " seçeneğini seçin](<../../images/image (868).png>)

- **path to the DLL**'yi ve çağırmak istediğiniz function'ı belirterek çalıştırmanın **parameters**'ını yapılandırın:

![Debugging DLLs - Using IDA: DLL'nin path'ini ve çağırmak istediğiniz function'ı belirterek çalıştırmanın parameters'ını yapılandırın](<../../images/image (704).png>)

Ardından debugging işlemini başlattığınızda **her DLL yüklendiğinde execution durdurulur**; rundll32 DLL'nizi yüklediğinde de execution durdurulur.

Bu method module-load event'lerinde durur, ancak yüklenen DLL'nin entry point'ine ulaşmak aşağıdaki x64dbg workflow'unda olduğundan daha az doğrudandır.

### x64dbg/x32dbg Kullanımı

- **rundll32'yi yükleyin** (64bit sürümü C:\Windows\System32\rundll32.exe içinde, 32bit sürümü ise C:\Windows\SysWOW64\rundll32.exe içindedir)
- **Command Line'ı değiştirin** ( _File --> Change Command Line_ ) ve dll'nin path'ini ve çağırmak istediğiniz function'ı ayarlayın; örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ bölümünü değiştirin ve "**DLL Entry**" seçeneğini seçin.
- Ardından **execution'ı başlatın**; debugger her dll main'de duracaktır. Bir noktada **kendi dll'nizin dll Entry'sinde duracaksınız**. Buradan sonra yalnızca breakpoint koymak istediğiniz noktaları arayın.

Execution herhangi bir nedenle win64dbg tarafından durdurulduğunda, **win64dbg window'unun üst kısmına** bakarak **hangi code içinde olduğunuzu** görebileceğinizi unutmayın:

![Using IDA - Using x64dbg/x32dbg: Execution herhangi bir nedenle win64dbg tarafından durdurulduğunda win64dbg window'unun üst kısmına bakarak hangi code içinde olduğunuzu görebileceğinizi unutmayın](<../../images/image (842).png>)

Bu indicator, execution'ın debug etmek istediğiniz DLL'nin içinde durduğunu doğrular.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun memory'si içinde önemli değerlerin nerede saklandığını bulmak ve bunları değiştirmek için kullanışlı bir programdır. Daha fazla bilgi:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), GNU Project Debugger (GDB) için games üzerine odaklanan bir front-end/reverse engineering tool'dur. Ancak reverse-engineering ile ilgili her türlü işlem için kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/), çeşitli decompiler'lar için web tabanlı bir front-end'dir. Bu web service, küçük executable'lar üzerinde farklı decompiler'ların output'unu karşılaştırmanıza olanak tanır.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode'lar

### blobrunner ile bir shellcode'u debug etme

[**BlobRunner**](https://github.com/OALabs/BlobRunner), **shellcode** için memory allocate eder, **memory address**'ini yazdırır ve execution'ı duraklatır.\
IDA veya x64dbg gibi bir debugger bağlayın, yazdırılan address'e bir breakpoint koyun ve shellcode'u debug etmek için execution'ı sürdürün.

Releases github page, derlenmiş release'leri içeren zip dosyalarını barındırır: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
BlobRunner'ın biraz değiştirilmiş bir version'ını aşağıdaki linkte bulabilirsiniz. Derlemek için yalnızca **Visual Studio Code'da bir C/C++ project oluşturun, code'u kopyalayıp yapıştırın ve build edin**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile bir shellcode'u debug etme

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner'a benzer. Shellcode için memory allocate eder ve sonsuz bir loop'a girer. Debugger'ı bağlayın, **2–5 saniye** boyunca devam edin, bu loop'un içinde duraklatın ve execution'ı allocate edilmiş shellcode'a aktaran sonraki call'a step edin.

![Debugger, allocate edilmiş shellcode'a yapılan call'dan hemen önce jmp2it'in sonsuz loop'unda duraklatılmış](<../../images/image (509).png>)

Derlenmiş bir version'ı [releases page içindeki jmp2it](https://github.com/adamkramer/jmp2it/releases/) üzerinden indirebilirsiniz.

### Cutter kullanarak shellcode debug etme

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'ın GUI'sidir. Cutter kullanarak shellcode'u emulate edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Open File" ve "Open Shellcode" seçeneklerine izin verdiğini unutmayın. Benim durumumda shellcode'u file olarak açtığımda doğru şekilde decompile etti; ancak shellcode olarak açtığımda bunu yapmadı:

![Cutter'ın aynı byte'ları file veya shellcode olarak açarken farklı analysis sonuçları göstermesi](<../../images/image (562).png>)

Emulation'ı istediğiniz yerde başlatmak için oraya bir bp koyun; görünüşe göre Cutter emulation'ı otomatik olarak oradan başlatacaktır:

![Cutter emulation'ını başlatmadan önce istenen shellcode entry'sine breakpoint koyma](<../../images/image (589).png>)

![Cutter emulator'ının seçilen shellcode breakpoint'inde duraklatılması](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görebilirsiniz:

![Cutter'ın hex dump'ında emulate edilmiş shellcode stack'ini görüntüleme](<../../images/image (186).png>)

### Shellcode'un obfuscation'ını kaldırma ve çalıştırılan function'ları bulma

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)'yi denemelisiniz.\
Shellcode'un **hangi function'ları** kullandığı ve memory içinde kendisini **decode edip etmediği** gibi bilgileri size söyler.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg ayrıca istediğiniz seçenekleri seçip shellcode'u çalıştırabileceğiniz grafiksel bir launcher içerir

![Shellcode emülasyonu ve tracing seçeneklerini belirlemek için scDbg grafiksel launcher'ı](<../../images/image (258).png>)

**Create Dump** seçeneği, shellcode bellekte dinamik olarak değiştirilmişse nihai shellcode'u dump eder (decoded shellcode'u indirmek için kullanışlıdır). **start offset**, shellcode'u belirli bir offset'ten başlatmak için kullanılabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'u debug etmek için kullanışlıdır (ancak bu işlem için daha önce açıklanan seçeneklerden herhangi birini daha iyi buluyorum; çünkü Ida veya x64dbg kullanabileceksiniz).

### CyberChef kullanarak Disassembling

Shellcode dosyanızı input olarak yükleyin ve decompile etmek için aşağıdaki recipe'i kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` gibi basit ifadeleri arithmetic (`+`, `-`, `*`) ve bitwise operatörlerini (`&`, `|`, `^`, `~`, shift'ler) birleştiren formüllerin arkasına gizler. Önemli nokta, bu identity'lerin genellikle yalnızca **fixed-width modular arithmetic** altında doğru olmasıdır; dolayısıyla carry'ler ve overflow'lar önemlidir:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Bu tür bir ifadeyi generic algebra tooling ile sadeleştirirseniz, bit-width semantiği göz ardı edildiği için kolayca yanlış bir sonuç elde edebilirsiniz.<sup>[[1]](#references)</sup>

### Pratik iş akışı

1. **Orijinal bit-width değerini koruyun**: lifted code/IR/decompiler çıktısından (`8/16/32/64` bit).
2. **Sadeleştirmeye çalışmadan önce ifadeyi sınıflandırın**:
- **Linear**: bitwise atomların ağırlıklı toplamları
- **Semilinear**: `x & 0xFF` gibi sabit maskelerle birlikte linear ifadeler
- **Polynomial**: çarpımlar bulunur
- **Mixed**: çarpımlar ve bitwise logic iç içedir; genellikle tekrarlanan alt ifadeler bulunur
3. **Her olası yeniden yazımı** random testing veya bir SMT proof ile doğrulayın. Eşdeğerlik kanıtlanamıyorsa tahminde bulunmak yerine orijinal ifadeyi koruyun.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA), malware analysis ve protected-binary reversing için pratik bir MBA simplifier'dır. İfadeyi sınıflandırır ve her şeye tek bir generic rewrite pass uygulamak yerine, specialized pipeline'lara yönlendirir.<sup>[[2]](#references)</sup>

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
Yararlı kullanım alanları:

- **Linear MBA**: CoBRA, ifadeyi Boolean girdiler üzerinde değerlendirir, bir imza türetir ve pattern matching, ANF conversion ve coefficient interpolation gibi çeşitli recovery yöntemlerini yarıştırır.
- **Semilinear MBA**: constant-masked atomlar, masked bölgelerin doğru kalmasını sağlamak için bit-partitioned reconstruction ile yeniden oluşturulur.
- **Polynomial/Mixed MBA**: products, core'lara ayrıştırılır ve tekrarlanan subexpression'lar, dış relation'ı simplify etmeden önce temporaries içine alınabilir.

Kurtarılmayı denemeye genellikle değer bir mixed identity örneği:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Şu şekilde kısaltılabilir:
```c
x * y
```
### Tersine mühendislik notları

- Tam hesaplamayı izole ettikten sonra CoBRA'yı **lifted IR ifadeleri** veya decompiler çıktısı üzerinde çalıştırmayı tercih edin.
- İfade masked arithmetic veya dar register'lar kaynaklıysa `--bitwidth` seçeneğini açıkça kullanın.
- Daha güçlü bir proof adımına ihtiyacınız varsa yerel Z3 notlarını burada kontrol edin:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca, sonraki analiz pass'lerinden önce MBA ağırlıklı LLVM IR'ı normalize etmek istediğinizde kullanışlı olan bir **LLVM pass plugin'i** (`libCobraPass.so`) olarak da sunulur.
- Desteklenmeyen carry-sensitive mixed-domain residual'lar, orijinal ifadeyi koruyup carry path'i manuel olarak analiz etmeniz gerektiğine dair bir sinyal olarak değerlendirilmelidir.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, program işlemlerini `mov` tabanlı instruction dizileriyle değiştirir ve control flow'u değiştirmek için signal/exception handling kullanır. Ayrıntılar için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Desteklenen binary'ler için [demovfuscator](https://github.com/kirschju/demovfuscator) sonucu deobfuscate edebilir. Birkaç bağımlılığı vardır.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Ve [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Eğer bir **CTF oynuyorsanız, flag'i bulmak için bu workaround** oldukça kullanışlı olabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**Entry point'i** bulmak için fonksiyonları aşağıdaki örnekte olduğu gibi `::main` ifadesine göre arayın:

![Ghidra'da fonksiyon adlarında çift iki nokta main ifadesini arayarak Rust entry point'ini bulma](<../../images/image (1080).png>)

Bu durumda binary'nin adı authenticator olduğundan, bunun ilgi çekici main fonksiyonu olduğu oldukça açık.\
Çağrılan **fonksiyonların** **adlarını** kullanarak **Internet'te** arama yapın ve **input'ları** ile **output'ları** hakkında bilgi edinin.

### ELF firmware'inden Rust string'lerini kurtarma

**Rust ELF** binary'lerinde birçok static string, C-style NUL-terminated pointer'lar olarak referanslanmaz. Yaygın bir `rustc` yerleşiminde, gerçek string blob'una işaret eden bir **pointer/length tuple'ı** **`.data.rel.ro`** içinde bulunur; gerçek string blob'u ise **`.rodata`** içinde depolanır:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Bu, `strings` veya varsayılan Ghidra analizinin bitişik string'leri birleştirebileceği ya da cross-reference'ları tamamen gözden kaçırabileceği anlamına gelir.<sup>[[3]](#references)</sup>

Hızlı iş akışı:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`** bölümünün sanal adresini ve boyutunu alın.
2. **`.data.rel.ro`** bölümünü her seferinde bir word olacak şekilde numaralandırın.
3. **`.rodata`** adres aralığındaki her değeri olası bir string pointer olarak değerlendirin.
4. Sonraki word'ü olası uzunluk olarak değerlendirin.
5. Sanity filtreleri uygulayın (örneğin, uzunlukları **4** ile **100** byte arasında olanları tutun).
6. `0x00` değerine kadar taramak yerine, `.rodata` bölümünden tam olarak `length` byte okuyun.

Minimal extractor mantığı:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Bu, kurtarılan Rust string'leri genellikle **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers ve auth-related logic** ortaya çıkardığından firmware reversing sırasında özellikle kullanışlıdır.

Ghidra bu string'leri kaçırırsa aynı heuristic'i uygulayan ve referans verilen `.rodata` offset'lerinde string data oluşturan özel bir script/plugin çalıştırın. Pen Test Partners tarafından yayımlanan `rust-strings` ve `RustStrings.py` araçları, bu fikri diğer **word sizes, endianness ve section layouts** için uyarlamak adına iyi referanslardır.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi derlenmiş binary'leri için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Bir Delphi binary'sini reverse etmeniz gerekiyorsa IDA plugin'i olarak [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

IDA'da bir Python plugin yüklemek için **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu plugin binary'yi çalıştırır ve debugging başlangıcında function names'leri dinamik olarak çözer. Debugging'i başlattıktan sonra Start düğmesine (yeşil düğme veya f9) tekrar basın; gerçek code'un başlangıcında bir breakpoint tetiklenir.

Graphical application içinde bir düğmeye basarsanız debugger, o düğmenin çağırdığı function'da durabilir.

## Golang

Bir Golang binary'sini reverse etmeniz gerekiyorsa IDA plugin'i olarak [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm.

IDA'da bir Python plugin yüklemek için **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu, function names'leri çözer.

## Compiled Python

Bu sayfada, ELF/EXE Python derlenmiş bir binary'den Python code'unu nasıl alabileceğinizi bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Bir GBA oyununun **binary** dosyasını elde ederseniz, onu **emulate** ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug sürümünü indirin_) - Interface'e sahip bir debugger içerir
- [**mgba** ](https://mgba.io)- CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin'i
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin'i

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünde Game Boy Advance **buttons**'larına nasıl basılacağını görebilirsiniz.

![Game Boy Advance düğme eşlemelerini gösteren no$gba controls configuration](<../../images/image (581).png>)

Basınca her **key'in onu tanımlayan bir değeri vardır**:
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
Bu tür bir programda ilginç kısım, programın **kullanıcı girdisini nasıl işlediği** olacaktır. **0x4000130** adresinde yaygın olarak bulunan şu function'ı bulacaksınız: **KEYINPUT**.

![0x4000130 adresinde KEYINPUT'e referans veren bir GBA binary'sinin Ghidra görünümü](<../../images/image (447).png>)

Önceki görselde function'ın **FUN_080015a8**'den çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

Bu function'da, bazı init işlemlerinden sonra (herhangi bir önemi olmayan):
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
Şu kod bulundu:
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
Son if, **`uVar4`** değerinin **son Keys** içinde olduğunu ve mevcut key olmadığını kontrol eder; buna aynı zamanda bir tuşu bırakmak da denir (mevcut key **`uVar1`** içinde saklanır).
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
Önceki kodda, **uVar1** (**basılan düğmenin değerinin** bulunduğu yer) ile bazı değerleri karşılaştırdığımızı görebilirsiniz:

- İlk olarak **4 değeri** (**SELECT** düğmesi) ile karşılaştırılır: Challenge'da bu düğme ekranı temizler
- Ardından değer **8** (**START** düğmesi) ile karşılaştırılır; bu challenge'da bu yol, girilen kodun geçerli olup olmadığını kontrol eder.
- Bu durumda **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılır ve değer aynıysa bazı kodlar yürütülür.
- Diğer tüm durumlarda bir sayaç (`DAT_030000d4`) kontrol edilir ve artırılır.\
Sayaç 8'in altındayken, basılan tuş değerleri `DAT_030000d8` içinde biriktirilir.

Dolayısıyla bu challenge'da, düğmelerin değerlerini bildiğinizde, **uzunluğu 8'den küçük olan ve toplamı 0xf3 eden bir kombinasyona basmanız gerekiyordu.**

**Bu tutorial için referans:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kurslar

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRA ile MBA obfuscation'ını basitleştirme](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA deposu](https://github.com/trailofbits/CoBRA)
- [3] [Rust string'lerini decode etme - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (arşivlenmiş)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
