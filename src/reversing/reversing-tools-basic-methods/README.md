# Reversing Araçları ve Temel Yöntemler

{{#include ../../banners/hacktricks-training.md}}

## ImGui Tabanlı Reversing araçları

Yazılım:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Çevrimiçi:

- wasm'dan (binary) wat'a (düz metin) **decompile** etmek için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kullanın
- wat'ı wasm'a **compile** etmek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kullanın
- Decompilation için [web-wasmdec](https://wwwg.github.io/web-wasmdec/) aracını da deneyebilirsiniz.

Yazılım:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek, **library**'ler (.dll), **Windows metadata file**'ları (.winmd) ve **executable**'lar (.exe) dahil olmak üzere **birden fazla formatı decompile ve examine eden** bir decompiler'dır. Decompile edildikten sonra bir assembly, Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantaj, kayıp source code'un bir legacy assembly'den geri yüklenmesi gerektiğinde bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilmiş code içinde kullanışlı bir navigation sağlar ve bu da onu **Xamarin algorithm analysis** için mükemmel araçlardan biri hâline getirir.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in modeli ve aracı tam ihtiyaçlarınıza uyacak şekilde genişleten bir API ile .NET Reflector zaman kazandırır ve development sürecini basitleştirir. Bu aracın sunduğu reverse engineering hizmetlerine göz atalım:

- Verilerin bir library veya component içinde nasıl aktığına dair insight sağlar
- .NET language ve framework'lerinin implementation ve kullanımına dair insight sağlar
- Kullanılan API'lerden ve teknolojilerden daha fazla yararlanmak için undocumented ve unexposed functionality'yi bulur.
- Dependency'leri ve farklı assembly'leri bulur
- Code'unuzdaki, third-party component'lerdeki ve library'lerdeki hataların tam konumunu tespit eder.
- Çalıştığınız tüm .NET code'unun source'una debug yapar.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir OS üzerinde kullanabilirsiniz (doğrudan VSCode'dan kurabilirsiniz; git'i indirmenize gerek yoktur. **Extensions**'a tıklayın ve **search ILSpy** yapın).\
**Decompile**, **modify** ve tekrar **recompile** etmeniz gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak sürdürülen bir fork'u olan [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir function içindeki bir şeyi değiştirmek için **Right Click -> Modify Method**).

### DNSpy Logging

**DNSpy'nin bazı bilgileri bir file'a loglamasını** sağlamak için şu snippet'i kullanabilirsiniz:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

DNSpy kullanarak code debug etmek için:

Öncelikle **Assembly attributes** içindeki **debugging** ile ilgili ayarları değiştirin:

![DNSpy Logging - DNSpy Debugging: Öncelikle Assembly attributes içindeki debugging ile ilgili ayarları değiştirin](<../../images/image (973).png>)

Şuradan:
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

![DNSpy Logging - DNSpy Debugging: Ve compile üzerine tıklayın](<../../images/image (314) (1).png>)

Ardından yeni dosyayı _**File >> Save module...**_ aracılığıyla kaydedin:

![DNSpy Logging - DNSpy Debugging: Ardından yeni dosyayı File Save module aracılığıyla kaydedin](<../../images/image (602).png>)

Bu gereklidir; çünkü bunu yapmazsanız **runtime** sırasında koda çeşitli **optimizasyonlar** uygulanır ve debugging sırasında bir **break-point'in hiçbir zaman tetiklenmemesi** veya bazı **değişkenlerin mevcut olmaması** mümkün olabilir.

Ardından .NET uygulamanız **IIS** tarafından **çalıştırılıyorsa**, uygulamayı şu komutla **yeniden başlatabilirsiniz**:
```
iisreset /noforce
```
Ardından, debugging işlemini başlatmak için açılmış tüm dosyaları kapatmalı ve **Debug Tab** içinde **Attach to Process...** seçeneğini seçmelisiniz:

![DNSpy Logging - DNSpy Debugging: Ardından, debugging işlemini başlatmak için açılmış tüm dosyaları kapatmalı ve Debug Tab içinde Attach to Process seçeneğini seçmelisiniz](<../../images/image (318).png>)

Ardından **IIS server**'a bağlanmak için **w3wp.exe**'yi seçin ve **attach**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Ardından IIS server'a bağlanmak için w3wp.exe'yi seçin ve attach'e tıklayın](<../../images/image (113).png>)

Artık process'i debug ettiğimize göre onu durdurup tüm modülleri yüklemenin zamanı geldi. Önce _Debug >> Break All_ seçeneğine, ardından _**Debug >> Windows >> Modules**_ seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Artık process'i debug ettiğimize göre onu durdurup tüm modülleri yüklemenin zamanı geldi. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Artık process'i debug ettiğimize göre onu durdurup tüm modülleri yüklemenin zamanı geldi. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (834).png>)

**Modules** içindeki herhangi bir modüle tıklayın ve **Open All Modules** seçeneğini seçin:

![DNSpy Logging - DNSpy Debugging: Modules içindeki herhangi bir modüle tıklayın ve Open All Modules seçeneğini seçin](<../../images/image (922).png>)

**Assembly Explorer** içindeki herhangi bir modüle sağ tıklayın ve **Sort Assemblies** seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer içindeki herhangi bir modüle sağ tıklayın ve Sort Assemblies seçeneğine tıklayın](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'leri debug etme

### IDA kullanma

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe konumunda, 32 bit sürümü ise C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Windbg** debugger'ını seçin
- "**Suspend on library load/unload**" seçeneğini seçin

![DLL'leri Debug Etme - IDA Kullanma: " Suspend on library load/unload " seçeneğini seçin](<../../images/image (868).png>)

- Execution'ın **parameters**'ını, **DLL path**'ini ve çağırmak istediğiniz function'ı belirterek yapılandırın:

![DLL'leri Debug Etme - IDA Kullanma: Execution'ın parameters'ını, DLL path'ini ve çağırmak istediğiniz function'ı belirterek yapılandırın](<../../images/image (704).png>)

Ardından debugging'i başlattığınızda **her DLL yüklendiğinde execution durdurulur**; dolayısıyla rundll32 DLL'inizi yüklediğinde execution durdurulur.

Bu method module-load event'lerinde durur, ancak yüklenen DLL'in entry point'ine ulaşmak aşağıdaki x64dbg workflow'undakinden daha az doğrudandır.

### x64dbg/x32dbg kullanma

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe konumunda, 32 bit sürümü ise C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Command Line'ı değiştirin** ( _File --> Change Command Line_ ) ve dll'in path'ini ve çağırmak istediğiniz function'ı ayarlayın; örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ seçeneğini değiştirin ve "**DLL Entry**" seçeneğini seçin.
- Ardından **execution'ı başlatın**; debugger her dll main'de durur ve bir noktada **kendi dll'inizin dll Entry'sinde durursunuz**. Buradan, breakpoint koymak istediğiniz noktaları aramanız yeterlidir.

Execution herhangi bir nedenle win64dbg tarafından durdurulduğunda **win64dbg penceresinin üst kısmına** bakarak **hangi code içinde olduğunuzu** görebileceğinizi unutmayın:

![Using IDA - Using x64dbg/x32dbg: Execution herhangi bir nedenle win64dbg tarafından durdurulduğunda win64dbg penceresinin üst kısmına bakarak hangi code içinde olduğunuzu görebileceğinizi unutmayın](<../../images/image (842).png>)

Bu gösterge, execution'ın debug etmek istediğiniz DLL'in içinde durduğunu doğrular.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun memory'si içinde önemli değerlerin nerede saklandığını bulup bunları değiştirmek için kullanışlı bir programdır. Daha fazla bilgi:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), GNU Project Debugger (GDB) için oyunlara odaklanan bir front-end/reverse engineering aracıdır. Ancak reverse-engineering ile ilgili her türlü iş için kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/), çeşitli decompiler'lar için web tabanlı bir front-end'dir. Bu web service, küçük executable'larda farklı decompiler'ların output'unu karşılaştırmanıza olanak tanır.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode'lar

### blobrunner ile bir shellcode'u debug etme

[**BlobRunner**](https://github.com/OALabs/BlobRunner), **shellcode** için memory'de yer ayırır, **memory address**'ini yazdırır ve execution'ı duraklatır.\
IDA veya x64dbg gibi bir debugger bağlayın, yazdırılan address'te bir breakpoint ayarlayın ve shellcode'u debug etmek için execution'ı devam ettirin.

Releases github page'i derlenmiş release'leri içeren zip dosyalarını barındırır: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Aşağıdaki linkte Blobrunner'ın biraz değiştirilmiş bir sürümünü bulabilirsiniz. Derlemek için **Visual Studio Code'da bir C/C++ project'i oluşturun, code'u kopyalayıp yapıştırın ve build edin**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile bir shellcode'u debug etme

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner'a benzer. Shellcode için memory'de yer ayırır ve sonsuz bir loop'a girer. Debugger'ı bağlayın, **2–5 saniye** boyunca devam ettirin, bu loop'un içinde duraklatın ve execution'ı ayrılan shellcode'a aktaran bir sonraki call'a step uygulayın.

![jmp2it'in sonsuz loop'unda, ayrılan shellcode'a yapılan call'dan hemen önce duraklatılmış debugger](<../../images/image (509).png>)

Derlenmiş bir [jmp2it sürümünü releases page'inden](https://github.com/adamkramer/jmp2it/releases/) indirebilirsiniz.

### Cutter kullanarak shellcode debug etme

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'ın GUI'sidir. Cutter kullanarak shellcode'u emulate edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Open File" ve "Open Shellcode" seçeneklerini sunduğunu unutmayın. Benim durumumda shellcode'u file olarak açtığımda doğru şekilde decompile etti; ancak shellcode olarak açtığımda bunu yapmadı:

![Aynı byte'lar file veya shellcode olarak açıldığında Cutter'ın farklı analysis sonuçlarını göstermesi](<../../images/image (562).png>)

Emulation'ı istediğiniz yerde başlatmak için oraya bir bp ayarlayın; görünüşe göre Cutter emulation'ı otomatik olarak oradan başlatacaktır:

![Cutter emulation'ını başlatmadan önce istenen shellcode entry'sinde breakpoint ayarlanması](<../../images/image (589).png>)

![Cutter emulator'ının seçilen shellcode breakpoint'inde duraklatılması](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görebilirsiniz:

![Emüle edilen shellcode stack'inin Cutter'ın hex dump'ında görüntülenmesi](<../../images/image (186).png>)

### Shellcode'u deobfuscate etme ve çalıştırılan function'ları bulma

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)'yi denemelisiniz.\
Shellcode'un kullandığı **function'lar** ve memory'de kendisini **decode edip etmediği** gibi bilgileri size gösterecektir.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg ayrıca istediğiniz seçenekleri seçip shellcode'u çalıştırabileceğiniz grafiksel bir launcher içerir

![Shellcode emülasyonu ve tracing seçeneklerini seçmek için scDbg grafiksel launcher'ı](<../../images/image (258).png>)

**Create Dump** seçeneği, shellcode bellekte dinamik olarak değiştirildiyse son shellcode'u dump eder (decode edilmiş shellcode'u indirmek için kullanışlıdır). **start offset**, shellcode'u belirli bir offset'ten başlatmak için kullanılabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'u debug etmek için kullanışlıdır (ancak bu konu için daha önce açıklanan seçeneklerden herhangi birini daha iyi buluyorum; çünkü Ida veya x64dbg kullanabilirsiniz).

### CyberChef kullanarak disassembling

Shellcode dosyanızı input olarak yükleyin ve decompile etmek için aşağıdaki recipe'i kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, aritmetik (`+`, `-`, `*`) ve bitwise operatörlerini (`&`, `|`, `^`, `~`, shift'ler) birleştiren formüller kullanarak `x + y` gibi basit ifadeleri gizler. Önemli nokta, bu özdeşliklerin genellikle yalnızca **sabit genişlikli modular arithmetic** altında doğru olmasıdır; bu nedenle carry ve overflow önem taşır:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Bu tür ifadeleri generic algebra tooling ile basitleştirirseniz, bit-width semantiği göz ardı edildiği için kolayca yanlış bir sonuç elde edebilirsiniz.<sup>[[1]](#references)</sup>

### Pratik iş akışı

1. **Orijinal bit-width değerini koruyun** lifted code/IR/decompiler çıktısından (`8/16/32/64` bit).
2. Basitleştirmeye çalışmadan önce **ifadeyi sınıflandırın**:
- **Linear**: bitwise atomların ağırlıklı toplamları
- **Semilinear**: `x & 0xFF` gibi sabit maskelerle birlikte linear ifadeler
- **Polynomial**: çarpımlar bulunur
- **Mixed**: çarpımlar ve bitwise logic iç içe geçmiştir; çoğu zaman tekrarlanan alt ifadeler içerir
3. Her olası yeniden yazımı random testing veya bir SMT proof ile **doğrulayın**. Eşdeğerlik kanıtlanamıyorsa tahminde bulunmak yerine orijinal ifadeyi koruyun.

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
Yararlı durumlar:

- **Linear MBA**: CoBRA, ifadeyi Boolean girdiler üzerinde değerlendirir, bir imza türetir ve pattern matching, ANF conversion ve coefficient interpolation gibi çeşitli recovery yöntemlerini yarıştırır.
- **Semilinear MBA**: constant-masked atomlar, maskelenmiş bölgelerin doğruluğunu korumak için bit-partitioned reconstruction ile yeniden oluşturulur.
- **Polynomial/Mixed MBA**: çarpımlar core'lara ayrılır ve outer relation sadeleştirilmeden önce tekrarlanan subexpression'lar temporaries içine alınabilir.

Kurtarılmaya genellikle değer bir mixed identity örneği:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Şu şekilde sadeleştirilebilir:
```c
x * y
```
### Reversing notları

- CoBRA'yı **lifted IR expressions** veya kesin hesaplamayı izole ettikten sonraki decompiler çıktısı üzerinde çalıştırmayı tercih edin.
- İfade masked arithmetic veya narrow registers kaynaklıysa `--bitwidth` seçeneğini açıkça kullanın.
- Daha güçlü bir proof step gerekiyorsa yerel Z3 notlarına buradan göz atın:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca, sonraki analysis pass'lerinden önce MBA-heavy LLVM IR'ı normalize etmek istediğinizde kullanışlı olan bir **LLVM pass plugin** (`libCobraPass.so`) olarak da gelir.
- Desteklenmeyen carry-sensitive mixed-domain residuals, orijinal ifadeyi koruyup carry path'i manuel olarak analiz etmeniz gerektiğini gösteren bir sinyal olarak değerlendirilmelidir.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, program operasyonlarını `mov` tabanlı instruction sequence'leriyle değiştirir ve control flow'u değiştirmek için signal/exception handling kullanır. Ayrıntılar için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Desteklenen binary'ler için [demovfuscator](https://github.com/kirschju/demovfuscator) sonucu deobfuscate edebilir. Birkaç dependency'si vardır.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Ve [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Eğer bir **CTF oynuyorsanız, flag'i bulmak için bu workaround** oldukça kullanışlı olabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**'i bulmak için, aşağıdaki örnekte olduğu gibi fonksiyonları `::main` ifadesiyle arayın:

![Ghidra'da fonksiyon adlarında çift iki nokta üst üste main ifadesi aranarak Rust entry point'inin bulunması](<../../images/image (1080).png>)

Bu durumda binary'nin adı authenticator olduğundan, bunun ilgi çekici main fonksiyonu olduğu oldukça açıktır.\
Çağrılan **fonksiyonların** **adlarını** kullanarak, **girdileri** ve **çıktıları** hakkında bilgi edinmek için bunları **Internet** üzerinde arayın.

### ELF firmware'den Rust string'lerini kurtarma

**Rust ELF** binary'lerinde birçok static string, C-style NUL-terminated pointer'lar olarak referanslanmaz. Yaygın bir `rustc` yerleşimi, gerçek string blob'una **`.rodata`** içinde işaret eden, **`.data.rel.ro`** içinde bulunan bir **pointer/length tuple**'ıdır:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Bu, `strings` veya varsayılan Ghidra analizinin bitişik dizeleri birleştirebileceği ya da cross-reference'ları tamamen atlayabileceği anlamına gelir.<sup>[[3]](#references)</sup>

Hızlı iş akışı:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`** bölümünün sanal adresini ve boyutunu alın.
2. **`.data.rel.ro`** bölümünü her seferinde bir word olacak şekilde enumerate edin.
3. **`.rodata`** adres aralığındaki her değeri aday string pointer olarak değerlendirin.
4. Sonraki word'ü aday length olarak değerlendirin.
5. Sanity filtreleri uygulayın (örneğin, **4** ile **100** byte arasındaki length değerlerini koruyun).
6. `0x00` değerini tarayarak durmak yerine, `.rodata` bölümünden tam olarak `length` byte okuyun.

Minimal extractor logic:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Bu, kurtarılan Rust string'leri sıklıkla **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers ve auth-related logic** ortaya çıkardığından firmware reversing sırasında özellikle kullanışlıdır.

Ghidra bu string'leri kaçırırsa aynı heuristic'i uygulayan ve referans verilen `.rodata` offset'lerinde string data oluşturan özel bir script/plugin çalıştırın. Pen Test Partners tarafından yayımlanan `rust-strings` ve `RustStrings.py` araçları, bu fikri diğer **word sizes, endianness ve section layouts** için uyarlamak açısından iyi referanslardır.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Bir Delphi binary'sini reverse etmeniz gerekiyorsa IDA plugin'i olarak [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

Bir Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu plugin binary'yi çalıştırır ve debugging başlangıcında function names'leri dinamik olarak çözümler. Debugging'i başlattıktan sonra Start button'a (yeşil olan veya f9) tekrar basın; gerçek code'un başlangıcında bir breakpoint tetiklenir.

Graphical application içinde bir button'a basarsanız debugger, o button tarafından çağrılan function'da durabilir.

## Golang

Bir Golang binary'sini reverse etmeniz gerekiyorsa IDA plugin'i olarak [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm.

Bir Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu, function names'leri çözer.

## Compiled Python

Bu sayfada, Python compiled bir ELF/EXE binary'sinden Python code'u nasıl alabileceğinizi bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Bir GBA oyununun **binary** dosyasını elde ederseniz onu **emulate** ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Debug version'ı indirin_) - Interface'e sahip bir debugger içerir
- [**mgba** ](https://mgba.io)- Bir CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin'i
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin'i

[**no$gba**](https://problemkaputt.de/gba.htm) içinde _**Options --> Emulation Setup --> Controls**_** bölümünde Game Boy Advance **buttons**'larına nasıl basacağınızı görebilirsiniz.

![Game Boy Advance button mapping'lerini gösteren no$gba controls configuration](<../../images/image (581).png>)

Basıldığında her **key'in onu tanımlayan bir değeri vardır**:
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
Yani bu tür bir programda ilgi çekici kısım, **programın kullanıcı girdisini nasıl ele aldığı** olacaktır. **0x4000130** adresinde yaygın olarak bulunan şu function'ı bulabilirsiniz: **KEYINPUT**.

![0x4000130 adresinde KEYINPUT'e başvuran bir GBA binary'sinin Ghidra görünümü](<../../images/image (447).png>)

Önceki görselde function'ın **FUN_080015a8** içinden çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

Bu function içinde, bazı init işlemlerinden sonra (herhangi bir önemi yok):
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
Bu kodu buldu:
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
Son if, **`uVar4`**'ün **son Keys** içinde olduğunu ve mevcut tuş olmadığını kontrol eder; bu, bir düğmeyi bırakma olarak da adlandırılır (mevcut tuş **`uVar1`** içinde saklanır).
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
Önceki kodda **uVar1**'i (**basılan düğmenin değerinin** bulunduğu yer) bazı değerlerle karşılaştırdığımızı görebilirsiniz:

- İlk olarak **4 değeriyle** (**SELECT** düğmesi) karşılaştırılır: Challenge'da bu düğme ekranı temizler
- Ardından değer **8** (**START** düğmesi) ile karşılaştırılır; bu challenge'da bu yol, girilen kodun geçerli olup olmadığını kontrol eder.
- Bu durumda **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılır ve değer aynıysa bazı code çalıştırılır.
- Diğer tüm durumlarda bir sayaç (`DAT_030000d4`) kontrol edilir ve artırılır.\
Sayaç 8'in altındayken, basılan tuşların değerleri `DAT_030000d8` içinde biriktirilir.

Dolayısıyla bu challenge'da, düğmelerin değerlerini bilerek, **uzunluğu 8'den küçük olan ve sonucundaki toplamın 0xf3 olduğu bir kombinasyona basmanız gerekiyordu.**

**Bu tutorial için referans:** [arşivlenmiş Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kurslar

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRA ile MBA obfuscation'ını basitleştirme](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust string'lerini decode etme - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (arşivlenmiş)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
