# Reversing Araçları ve Temel Yöntemler

{{#include ../../banners/hacktricks-training.md}}

## ImGui Tabanlı Reversing araçları

Yazılım:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- wasm'dan (binary) wat'a (plain text) **decompile** etmek için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kullanın
- wat'ı wasm'a **compile** etmek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kullanın
- decompile etmek için [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) kullanmayı da deneyebilirsiniz

Yazılım:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek, **library**'ler (.dll), **Windows metadata file**'ları (.winmd) ve **executable**'lar (.exe) dahil olmak üzere **birden fazla formatı decompile eder ve inceler**. Decompile edildikten sonra bir assembly, Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantaj, kayıp source code'un legacy bir assembly'den geri yüklenmesi gerekiyorsa bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilmiş code boyunca kullanışlı bir navigation özelliği sunarak onu **Xamarin algorithm analysis** için mükemmel araçlardan biri haline getirir.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in modeli ve aracı tam ihtiyaçlarınıza uyacak şekilde genişleten bir API ile .NET reflector zaman kazandırır ve development'ı kolaylaştırır. Bu aracın sunduğu çok sayıdaki reverse engineering hizmetine göz atalım:

- Verilerin bir library veya component üzerinden nasıl aktığına dair insight sağlar
- .NET dilleri ve framework'lerinin implementation'ı ve kullanımına dair insight sağlar
- Kullanılan API'lerden ve teknolojilerden daha fazla yararlanmak için undocumented ve unexposed functionality'yi bulur.
- Dependency'leri ve farklı assembly'leri bulur
- Code'unuzdaki, third-party component'lerdeki ve library'lerdeki hataların tam konumunu tespit eder.
- Çalıştığınız tüm .NET code'unun source'una girerek debug eder.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir OS'te kullanabilirsiniz (doğrudan VSCode üzerinden kurabilirsiniz; git'i download etmenize gerek yoktur. **Extensions**'a tıklayın ve **search ILSpy** yapın).\
Tekrar **decompile**, **modify** ve **recompile** etmeniz gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak sürdürülen bir fork'u olan [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir function'ın içindeki bir şeyi değiştirmek için **Right Click -> Modify Method**.)

### DNSpy Logging

**DNSpy'nin bazı bilgileri bir file'a loglamasını sağlamak** için şu snippet'i kullanabilirsiniz:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

DNSpy kullanarak code debug etmek için şunları yapmanız gerekir:

İlk olarak, **debugging** ile ilgili **Assembly attributes** değerlerini değiştirin:

![DNSpy Logging - DNSpy Debugging: İlk olarak, debugging ile ilgili Assembly attributes değerlerini değiştirin](<../../images/image (973).png>)

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
Ve **compile** öğesine tıklayın:

![DNSpy Logging - DNSpy Debugging: Ve compile öğesine tıklayın](<../../images/image (314) (1).png>)

Ardından _**File >> Save module...**_ aracılığıyla yeni dosyayı kaydedin:

![DNSpy Logging - DNSpy Debugging: Ardından File Save module aracılığıyla yeni dosyayı kaydedin](<../../images/image (602).png>)

Bunu yapmak gereklidir; aksi takdirde **runtime** sırasında koda çeşitli **optimisations** uygulanır ve debugging yaparken bir **break-point**'in hiçbir zaman tetiklenmemesi veya bazı **variables**'ın mevcut olmaması mümkün olabilir.

Ardından, .NET uygulamanız **IIS** tarafından **run** ediliyorsa şu komutla **restart** edebilirsiniz:
```
iisreset /noforce
```
Ardından debugging işlemine başlamak için açık olan tüm dosyaları kapatmalı ve **Debug Tab** içinde **Attach to Process...** seçeneğini seçmelisiniz:

![DNSpy Logging - DNSpy Debugging: Ardından debugging işlemine başlamak için açık olan tüm dosyaları kapatmalı ve Debug Tab içinde Attach to Process seçeneğini seçmelisiniz](<../../images/image (318).png>)

Ardından **IIS server**'a attach olmak için **w3wp.exe**'yi seçin ve **attach**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Ardından IIS server'a attach olmak için w3wp.exe'yi seçin ve attach'e tıklayın](<../../images/image (113).png>)

Şimdi process'i debug ettiğimize göre onu durdurmanın ve tüm modülleri yüklemenin zamanı geldi. Önce _Debug >> Break All_ seçeneğine, ardından _**Debug >> Windows >> Modules**_ seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Şimdi process'i debug ettiğimize göre onu durdurmanın ve tüm modülleri yüklemenin zamanı geldi. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Şimdi process'i debug ettiğimize göre onu durdurmanın ve tüm modülleri yüklemenin zamanı geldi. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (834).png>)

**Modules** içindeki herhangi bir modüle tıklayın ve **Open All Modules** seçeneğini seçin:

![DNSpy Logging - DNSpy Debugging: Modules içindeki herhangi bir modüle tıklayın ve Open All Modules seçeneğini seçin](<../../images/image (922).png>)

**Assembly Explorer** içindeki herhangi bir modüle sağ tıklayın ve **Sort Assemblies** seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer içindeki herhangi bir modüle sağ tıklayın ve Sort Assemblies seçeneğine tıklayın](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'leri Debug Etme

### IDA Kullanımı

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe konumunda, 32 bit sürümü ise C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Windbg** debugger'ını seçin
- "**Suspend on library load/unload**" seçeneğini seçin

![Debugging DLLs - Using IDA: " Suspend on library load/unload " seçeneğini seçin](<../../images/image (868).png>)

- Çalıştırmanın **parameters**'ını, **DLL path**'ini ve çağırmak istediğiniz fonksiyonu girerek yapılandırın:

![Debugging DLLs - Using IDA: DLL path'ini ve çağırmak istediğiniz fonksiyonu girerek çalıştırmanın parameters'ını yapılandırın](<../../images/image (704).png>)

Ardından debugging işlemini başlattığınızda **her DLL yüklendiğinde çalıştırma durdurulur**; dolayısıyla rundll32 DLL'inizi yüklediğinde çalıştırma durdurulacaktır.

Peki yüklenen DLL'in koduna nasıl ulaşabilirsiniz? Bu yöntemi kullanarak bunun nasıl yapılacağını bilmiyorum.

### x64dbg/x32dbg Kullanımı

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe konumunda, 32 bit sürümü ise C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Command Line'ı değiştirin** ( _File --> Change Command Line_ ) ve DLL'in path'ini ve çağırmak istediğiniz fonksiyonu ayarlayın; örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ seçeneğini değiştirin ve "**DLL Entry**" seçeneğini seçin.
- Ardından **çalıştırmayı başlatın**; debugger her DLL main'de duracaktır ve bir noktada **DLL'inizin DLL Entry'sinde duracaktır**. Buradan itibaren breakpoint koymak istediğiniz noktaları aramanız yeterlidir.

win64dbg'de çalıştırma herhangi bir nedenle durdurulduğunda, **win64dbg penceresinin üst kısmına** bakarak **hangi kodda olduğunuzu** görebileceğinizi unutmayın:

![Using IDA - Using x64dbg/x32dbg: win64dbg'de çalıştırma herhangi bir nedenle durdurulduğunda, win64dbg penceresinin üst kısmına bakarak hangi kodda olduğunuzu görebileceğinizi unutmayın](<../../images/image (842).png>)

Ardından buna bakarak çalıştırmanın debug etmek istediğiniz DLL'de durdurulduğunu görebilirsiniz.

## GUI Uygulamaları / Video Oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bunları değiştirmek için kullanışlı bir programdır. Daha fazla bilgi:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), oyunlara odaklanan GNU Project Debugger (GDB) için bir front-end/reverse engineering aracıdır. Ancak reverse engineering ile ilgili her türlü iş için kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/), çeşitli decompiler'lar için web tabanlı bir front-end'dir. Bu web service, küçük executable'lar üzerinde farklı decompiler'ların çıktısını karşılaştırmanıza olanak tanır.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode'lar

### blobrunner ile bir shellcode'u debug etme

[**Blobrunner**](https://github.com/OALabs/BlobRunner), **shellcode**'u bir bellek alanı içinde **allocate eder**, size shellcode'un allocate edildiği **memory address**'i **gösterir** ve çalıştırmayı **durdurur**.\
Ardından process'e bir **debugger attach etmeniz** (Ida veya x64dbg), **belirtilen memory address'e bir breakpoint koymanız** ve çalıştırmayı **resume etmeniz** gerekir. Böylece shellcode'u debug edebilirsiniz.

GitHub releases sayfası, derlenmiş release'leri içeren zip dosyalarını barındırır: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blobrunner'ın biraz değiştirilmiş bir versiyonunu aşağıdaki linkte bulabilirsiniz. Derlemek için **Visual Studio Code'da bir C/C++ project oluşturun, kodu kopyalayıp yapıştırın ve build edin**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile bir shellcode'u debug etme

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), blobrunner'a çok benzer. **shellcode**'u bir bellek alanı içinde **allocate eder** ve bir **eternal loop** başlatır. Ardından **debugger'ı** process'e **attach etmeniz**, **start'a basıp 2-5 saniye beklemeniz ve stop'a basmanız** gerekir; böylece kendinizi **eternal loop** içinde bulursunuz. Eternal loop'un bir sonraki instruction'ına atlayın; bu instruction shellcode'a yapılan bir call olacaktır ve sonunda shellcode'u çalıştırırken bulacaksınız.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it blobrunner'a çok benzer. Shellcode'u bir bellek alanı içinde allocate eder ve bir...](<../../images/image (509).png>)

Derlenmiş bir [jmp2it sürümünü releases sayfasından indirebilirsiniz](https://github.com/adamkramer/jmp2it/releases/).

### Cutter kullanarak shellcode debug etme

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'ın GUI'sidir. Cutter'ı kullanarak shellcode'u emulate edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Open File" ve "Open Shellcode" seçeneklerine izin verdiğini unutmayın. Benim durumumda shellcode'u file olarak açtığımda doğru şekilde decompile etti; ancak shellcode olarak açtığımda bunu yapmadı:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Cutter'ın "Open File" ve "Open Shellcode" seçeneklerine izin verdiğini unutmayın. Benim durumumda shellcode'u file olarak açtığımda...](<../../images/image (562).png>)

Emulation'ı istediğiniz yerde başlatmak için oraya bir bp koyun; görünen o ki Cutter emulation'ı otomatik olarak oradan başlatacaktır:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Emulation'ı istediğiniz yerde başlatmak için oraya bir bp koyun; görünen o ki Cutter emulation'ı otomatik olarak...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Emulation'ı istediğiniz yerde başlatmak için oraya bir bp koyun; görünen o ki Cutter emulation'ı otomatik olarak...](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görebilirsiniz:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Örneğin stack'i bir hex dump içinde görebilirsiniz](<../../images/image (186).png>)

### Shellcode'u deobfuscate etme ve çalıştırılan fonksiyonları elde etme

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)'yi denemelisiniz.\
Shellcode'un **hangi fonksiyonları** kullandığı ve bellekte kendisini **decode edip etmediği** gibi bilgileri size gösterir.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg ayrıca, istediğiniz seçenekleri seçip shellcode'u çalıştırabileceğiniz grafiksel bir launcher ile birlikte gelir

![Cutter kullanarak shellcode debug etme - Shellcode obfuscation'ını kaldırma ve çalıştırılan işlevleri elde etme: scDbg ayrıca, istediğiniz seçenekleri seçip shellcode'u çalıştırabileceğiniz...](<../../images/image (258).png>)

**Create Dump** seçeneği, shellcode bellekte dinamik olarak değiştirildiyse son shellcode'u dump eder (decoded shellcode'u indirmek için kullanışlıdır). **start offset**, shellcode'u belirli bir offset'ten başlatmak için yararlı olabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'u debug etmek için kullanışlıdır (ancak bu konu için daha önce açıklanan seçeneklerden herhangi birini daha iyi buluyorum; çünkü Ida veya x64dbg kullanabileceksiniz).

### CyberChef kullanarak Disassembling

Shellcode dosyanızı input olarak yükleyin ve decompile etmek için aşağıdaki recipe'i kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` gibi basit ifadeleri aritmetik (`+`, `-`, `*`) ve bitwise operatörleri (`&`, `|`, `^`, `~`, shift'ler) bir araya getiren formüllerin arkasına gizler. Buradaki önemli nokta, bu özdeşliklerin genellikle yalnızca **sabit genişlikli modular arithmetic** altında doğru olmasıdır; bu nedenle carry'ler ve overflow'lar önemlidir:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Bu tür bir ifadeyi generic algebra tooling ile sadeleştirirseniz bit-width semantics göz ardı edildiği için kolayca yanlış bir sonuç elde edebilirsiniz.

### Practical workflow

1. **Orijinal bit-width değerini koruyun**: lifted code/IR/decompiler çıktısındaki (`8/16/32/64` bit).
2. **Sadeleştirmeye çalışmadan önce ifadeyi sınıflandırın**:
- **Linear**: bitwise atomların ağırlıklı toplamları
- **Semilinear**: `x & 0xFF` gibi sabit maskeler içeren linear ifadeler
- **Polynomial**: çarpımlar bulunur
- **Mixed**: çarpımlar ve bitwise logic iç içe geçmiştir; genellikle tekrarlanan alt ifadeler bulunur
3. **Her olası rewrite işlemini** random testing veya bir SMT proof ile doğrulayın. Eşdeğerlik kanıtlanamıyorsa tahmin yürütmek yerine orijinal ifadeyi koruyun.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA), malware analysis ve protected-binary reversing için pratik bir MBA simplifier'dır. İfadeyi sınıflandırır ve her şeye tek bir generic rewrite pass uygulamak yerine specialized pipeline'lara yönlendirir.<sup>[[1]](#references)[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA, ifadeyi Boolean girdileri üzerinde değerlendirir, bir signature türetir ve pattern matching, ANF conversion ve coefficient interpolation gibi çeşitli recovery yöntemlerini eşzamanlı olarak dener.
- **Semilinear MBA**: constant-masked atomlar, bit-partitioned reconstruction ile yeniden oluşturulur; böylece masked bölgeler doğru kalır.
- **Polynomial/Mixed MBA**: çarpımlar core'lara ayrılır ve outer relation'ı sadeleştirmeden önce tekrarlanan alt ifadeler temporaries içine alınabilir.

Kurtarılması genellikle denenmeye değer bir mixed identity örneği:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Bu şu hale indirgenebilir:
```c
x * y
```
### Reversing notları

- CoBRA'yı **lifted IR expressions** veya tam hesaplamayı izole ettikten sonra decompiler çıktısı üzerinde çalıştırmayı tercih edin.
- İfade masked arithmetic veya narrow registers kaynaklıysa `--bitwidth` seçeneğini açıkça kullanın.
- Daha güçlü bir proof adımına ihtiyacınız varsa yerel Z3 notlarını buradan inceleyin:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca bir **LLVM pass plugin** (`libCobraPass.so`) olarak da gelir; bu, sonraki analysis pass'lerinden önce MBA-heavy LLVM IR'yi normalize etmek istediğinizde kullanışlıdır.
- Desteklenmeyen carry-sensitive mixed-domain residuals, original expression'ı koruyup carry path'i manuel olarak analiz etmeye devam etmeniz gerektiğine işaret eder.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator **`mov` için tüm instruction'ları değiştirir** (evet, gerçekten çok havalı). Ayrıca execution flow'larını değiştirmek için interruption'ları kullanır. Nasıl çalıştığı hakkında daha fazla bilgi için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Şanslıysanız [demovfuscator](https://github.com/kirschju/demovfuscator) binary'nin deofuscate işlemini gerçekleştirebilir. Birkaç dependency'si vardır
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Ve [keystone'u yükleyin](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Eğer bir **CTF oynuyorsanız, flag'i bulmak için bu workaround** oldukça faydalı olabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**'i bulmak için fonksiyonları aşağıdaki örnekte olduğu gibi `::main` ile arayın:

![Movfuscator - Rust: entry point'i bulmak için fonksiyonları ::main ile arayın](<../../images/image (1080).png>)

Bu durumda binary'nin adı authenticator idi; dolayısıyla bunun ilgi çekici main fonksiyonu olduğu oldukça açık.\
Çağrılan **fonksiyonların** **adlarını** kullanarak, **input** ve **output**'ları hakkında bilgi edinmek için bunları **İnternet'te** arayın.

### ELF firmware'inden Rust string'lerini kurtarma

**Rust ELF** binary'lerinde birçok statik string, C tarzı NUL sonlandırılmış pointer'lar olarak referanslanmaz. Yaygın bir `rustc` yerleşimi, gerçek string blob'una **`.rodata`** içinde işaret eden, **`.data.rel.ro`** içindeki bir **pointer/length tuple**'ıdır:<sup>[[3]](#references)</sup>
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Bu, `strings` veya varsayılan Ghidra analizinin bitişik string'leri birleştirebileceği ya da cross-reference'ları tamamen gözden kaçırabileceği anlamına gelir.

Hızlı iş akışı:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`** bölümünün sanal adresini ve boyutunu alın.
2. **`.data.rel.ro`** bölümünü her seferinde bir word olacak şekilde enumerate edin.
3. **`.rodata`** adres aralığındaki tüm değerleri aday string pointer olarak değerlendirin.
4. Sonraki word'ü aday uzunluk olarak değerlendirin.
5. Mantıklılık filtreleri uygulayın (örneğin, uzunluğu **4** ile **100** byte arasında olanları tutun).
6. `0x00` değerine kadar taramak yerine, `.rodata` içinden tam olarak `length` byte okuyun.

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

Ghidra bu string'leri kaçırırsa aynı heuristic'i uygulayan ve referans verilen `.rodata` offset'lerinde string data oluşturan özel bir script/plugin çalıştırın. Pen Test Partners tarafından yayımlanan `rust-strings` ve `RustStrings.py` araçları, bu fikri diğer **word sizes, endianness ve section layouts** için uyarlamak üzere iyi referanslardır.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Delphi compiled binary'leri için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Bir Delphi binary'sini reverse etmeniz gerekiyorsa IDA plugin'i [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

**ATL+f7** tuşlarına basın (IDA'da python plugin import etme) ve python plugin'ini seçin.

Bu plugin binary'yi çalıştırır ve debugging başlangıcında function names'i dinamik olarak çözer. Debugging'i başlattıktan sonra Start button'a (yeşil olan veya f9) tekrar basın; gerçek code'un başlangıcında bir breakpoint'e ulaşılır.

Ayrıca oldukça ilginçtir; çünkü graphic application içinde bir button'a basarsanız debugger, o button tarafından çalıştırılan function'da durur.

## Golang

Bir Golang binary'sini reverse etmeniz gerekiyorsa IDA plugin'i [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm.

**ATL+f7** tuşlarına basın (IDA'da python plugin import etme) ve python plugin'ini seçin.

Bu, function names'i çözer.

## Compiled Python

Bu sayfada ELF/EXE python compiled binary'sinden python code'unu nasıl alacağınızı bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Bir GBA oyununun **binary** dosyasını elde ederseniz, onu **emulate** ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Interface içeren bir debugger
- [**mgba** ](https://mgba.io)- CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin'i
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin'i

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünde Game Boy Advance **buttons**'larına nasıl basılacağını görebilirsiniz.

![Game Boy Advance button mappings'i gösteren no$gba controls configuration](<../../images/image (581).png>)

Basıldığında her **key'in onu tanımlamak için bir value'su** vardır:
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
Yani, bu tür bir programda ilgi çekici kısım, **programın kullanıcı girdisini nasıl işlediği** olacaktır. **0x4000130** adresinde yaygın olarak bulunan **KEYINPUT** işlevini bulabilirsiniz.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

Önceki görüntüde, işlevin **FUN_080015a8** tarafından çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

Bu işlevde, bazı init işlemlerinden sonra (herhangi bir önemi olmayan):
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
Son `if`, **`uVar4`** değerinin **son Keys** içinde olup olmadığını ve mevcut tuş olmadığını kontrol eder; buna aynı zamanda bir tuşu bırakma denir (mevcut tuş **`uVar1`** içinde saklanır).
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
Önceki kodda **uVar1**'i (basılan button'ın **value'sunun bulunduğu yer**) bazı değerlerle karşılaştırdığımızı görebilirsiniz:

- İlk olarak **4 değeri** (**SELECT** button'ı) ile karşılaştırılıyor: Challenge'da bu button ekranı temizliyor
- Ardından **8 değeri** (**START** button'ı) ile karşılaştırılıyor: Challenge'da bu, flag'i almak için kodun geçerli olup olmadığını kontrol ediyor.
- Bu durumda **`DAT_030000d8`** var'ı 0xf3 ile karşılaştırılıyor ve değer aynıysa bazı code çalıştırılıyor.
- Diğer tüm durumlarda bir cont (**`DAT_030000d4`**) kontrol ediliyor. Bu bir cont çünkü code'a girdikten hemen sonra 1 ekleniyor.\
**E**ğer 8'den küçükse **`DAT_030000d8`**'e değerlerin **eklenmesini** içeren bir işlem yapılıyor (temel olarak cont 8'den küçük olduğu sürece basılan tuşların değerleri bu var'a ekleniyor).

Dolayısıyla bu challenge'da, button değerlerini bildiğinizde, **uzunluğu 8'den küçük olan ve sonucundaki toplamı 0xf3 yapan bir kombinasyona basmanız** gerekiyordu.<sup>[[6]](#references)</sup>

**Bu tutorial için referans:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kurslar

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## Referanslar

- [1] [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
