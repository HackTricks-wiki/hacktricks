# Reversing Araçları ve Temel Yöntemler

{{#include ../../banners/hacktricks-training.md}}

## ImGui Tabanlı Reversing araçları

Yazılım:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- wasm'dan (binary) wat'a (clear text) **decompile** etmek için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kullanın
- wat'tan wasm'a **compile** etmek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kullanın
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

dotPeek, **kütüphaneler** (.dll), **Windows metadata dosya**ları (.winmd) ve **çalıştırılabilir dosyalar** (.exe) dahil olmak üzere **birden çok formatı decompile eder ve inceler**. Decompile işleminin ardından bir assembly, Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantaj, kaybolmuş kaynak kodunun eski bir assembly'den geri yüklenmesi gerektiğinde bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilmiş kod boyunca kullanışlı bir gezinme olanağı sunarak onu **Xamarin algorithm analysis** için mükemmel araçlardan biri haline getirir.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Aracı tam ihtiyaçlarınıza uyarlayan kapsamlı bir add-in modeli ve API ile .NET Reflector zamandan tasarruf sağlar ve geliştirmeyi kolaylaştırır. Bu aracın sunduğu çok sayıdaki reverse engineering hizmetine göz atalım:

- Verilerin bir kütüphane veya component içinde nasıl aktığına dair içgörü sağlar
- .NET dilleri ve framework'lerinin uygulanışı ve kullanımı hakkında içgörü sağlar
- Kullanılan API'lerden ve teknolojilerden daha fazla yararlanmak için belgelenmemiş ve dışa açılmamış işlevleri bulur.
- Bağımlılıkları ve farklı assembly'leri bulur
- Kodunuzdaki, third-party component'lerdeki ve kütüphanelerdeki hataların tam konumunu tespit eder.
- Birlikte çalıştığınız tüm .NET kodlarının source code'una debug işlemi uygular.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy plugin'i](https://github.com/icsharpcode/ilspy-vscode): Bunu herhangi bir OS'te kullanabilirsiniz (doğrudan VSCode'dan kurabilirsiniz; git'i indirmenize gerek yoktur. **Extensions**'a tıklayın ve **search ILSpy** yapın).\
**decompile**, **modify** ve tekrar **recompile** etmeniz gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak sürdürülen bir fork'u olan [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir function içindeki bir şeyi değiştirmek için **Right Click -> Modify Method**).

### DNSpy Logging

**DNSpy'nin bazı bilgileri bir dosyaya loglamasını** sağlamak için şu snippet'i kullanabilirsiniz:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

DNSpy kullanarak kodu debug etmek için şunları yapmanız gerekir:

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
Ve **compile** seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Ve compile seçeneğine tıklayın](<../../images/image (314) (1).png>)

Ardından yeni dosyayı _**File >> Save module...**_ üzerinden kaydedin:

![DNSpy Logging - DNSpy Debugging: Ardından yeni dosyayı File Save module üzerinden kaydedin](<../../images/image (602).png>)

Bunu yapmak gereklidir; çünkü bunu yapmazsanız **runtime** sırasında koda çeşitli **optimisations** uygulanır ve debugging sırasında bir **break-point**'in hiçbir zaman tetiklenmemesi veya bazı **variables**'ın mevcut olmaması mümkün olabilir.

Ardından, .NET uygulamanız **IIS** tarafından **run** ediliyorsa şu komutla **restart** edebilirsiniz:
```
iisreset /noforce
```
Ardından debugging işlemine başlamak için açılmış tüm dosyaları kapatmalı ve **Debug Tab** içinde **Attach to Process...** seçeneğini seçmelisiniz:

![DNSpy Logging - DNSpy Debugging: Ardından debugging işlemine başlamak için açılmış tüm dosyaları kapatmalı ve Debug Tab içinde Attach to Process seçeneğini seçmelisiniz](<../../images/image (318).png>)

Ardından **IIS server**'a bağlanmak için **w3wp.exe**'yi seçin ve **attach**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Ardından IIS server'a bağlanmak için w3wp.exe'yi seçin ve attach'e tıklayın](<../../images/image (113).png>)

Şimdi process'i debug ettiğimize göre onu durdurup tüm modülleri yüklemenin zamanı geldi. Önce _Debug >> Break All_ seçeneğine, ardından _**Debug >> Windows >> Modules**_ seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Şimdi process'i debug ettiğimize göre onu durdurup tüm modülleri yüklemenin zamanı geldi. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Şimdi process'i debug ettiğimize göre onu durdurup tüm modülleri yüklemenin zamanı geldi. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (834).png>)

**Modules** içindeki herhangi bir modüle tıklayın ve **Open All Modules** seçeneğini seçin:

![DNSpy Logging - DNSpy Debugging: Modules içindeki herhangi bir modüle tıklayın ve Open All Modules seçeneğini seçin](<../../images/image (922).png>)

**Assembly Explorer** içindeki herhangi bir modüle sağ tıklayın ve **Sort Assemblies** seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer içindeki herhangi bir modüle sağ tıklayın ve Sort Assemblies seçeneğine tıklayın](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'leri Debug Etme

### IDA kullanımı

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe içinde, 32 bit sürümü ise C:\Windows\SysWOW64\rundll32.exe içindedir)
- **Windbg** debugger'ını seçin
- "**Suspend on library load/unload**" seçeneğini seçin

![Debugging DLLs - Using IDA: " Suspend on library load/unload " seçeneğini seçin](<../../images/image (868).png>)

- Çalıştırma işleminin **parametrelerini**, **DLL yolunu** ve çağırmak istediğiniz fonksiyonu ekleyerek yapılandırın:

![Debugging DLLs - Using IDA: DLL yolunu ve çağırmak istediğiniz fonksiyonu ekleyerek çalıştırma işleminin parametrelerini yapılandırın](<../../images/image (704).png>)

Ardından debugging işlemini başlattığınızda **her DLL yüklendiğinde çalıştırma durdurulur**; rundll32 DLL'nizi yüklediğinde de çalıştırma durdurulur.

Bu yöntem modül yükleme olaylarında durur, ancak yüklenen DLL'nin entry point'ine ulaşmak aşağıdaki x64dbg workflow'unda olduğundan daha az doğrudandır.

### x64dbg/x32dbg kullanımı

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe içinde, 32 bit sürümü ise C:\Windows\SysWOW64\rundll32.exe içindedir)
- **Command Line'ı değiştirin** ( _File --> Change Command Line_ ) ve DLL'nin yolunu ve çağırmak istediğiniz fonksiyonu ayarlayın; örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ seçeneğini değiştirin ve "**DLL Entry**" seçeneğini seçin.
- Ardından **çalıştırmayı başlatın**; debugger her DLL main'de duracaktır. Bir noktada **DLL'nizin dll Entry'sinde duracaksınız**. Buradan sonra breakpoint koymak istediğiniz noktaları aramanız yeterlidir.

win64dbg'de çalıştırma herhangi bir nedenle durduğunda, **win64dbg penceresinin üst kısmına** bakarak **hangi code içinde olduğunuzu** görebileceğinizi unutmayın:

![Using IDA - Using x64dbg/x32dbg: Çalıştırma win64dbg'de herhangi bir nedenle durduğunda, win64dbg penceresinin üst kısmına bakarak hangi code içinde olduğunuzu görebilirsiniz](<../../images/image (842).png>)

Bu gösterge, çalıştırmanın debug etmek istediğiniz DLL'in içinde durduğunu doğrular.

## GUI Uygulamaları / Video oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede kaydedildiğini bulmak ve bunları değiştirmek için kullanışlı bir programdır. Daha fazla bilgi:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), oyunlara odaklanan GNU Project Debugger (GDB) için bir front-end/reverse engineering aracıdır. Ancak reverse-engineering ile ilgili her türlü işlem için kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/), çeşitli decompiler'lar için web tabanlı bir front-end'dir. Bu web service, küçük executable'lar üzerindeki farklı decompiler'ların çıktısını karşılaştırmanızı sağlar.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner ile bir shellcode'u debug etme

[**BlobRunner**](https://github.com/OALabs/BlobRunner), **shellcode** için bellek ayırır, **memory address'ini** yazdırır ve çalıştırmayı duraklatır.\
IDA veya x64dbg gibi bir debugger'a bağlanın, yazdırılan adreste bir breakpoint ayarlayın ve shellcode'u debug etmek için çalıştırmaya devam edin.

Releases github sayfası, derlenmiş release'leri içeren zip dosyalarını barındırır: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blobrunner'ın biraz değiştirilmiş bir sürümünü aşağıdaki linkte bulabilirsiniz. Derlemek için **Visual Studio Code'da bir C/C++ projesi oluşturun, kodu kopyalayıp yapıştırın ve build edin**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile bir shellcode'u debug etme

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner'a benzer. Shellcode için bellek ayırır ve sonsuz bir döngüye girer. Debugger'a bağlanın, **2–5 saniye** boyunca çalıştırmaya devam edin, bu döngünün içinde duraklatın ve ayrılmış shellcode'a çalıştırmayı aktaran sonraki call'a step yapın.

![Ayrılmış shellcode'a yapılan call'dan hemen önce jmp2it'in sonsuz döngüsünde duraklatılmış debugger](<../../images/image (509).png>)

Derlenmiş bir [jmp2it sürümünü releases sayfasından](https://github.com/adamkramer/jmp2it/releases/) indirebilirsiniz.

### Cutter kullanarak shellcode debug etme

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'ın GUI'sidir. Cutter'ı kullanarak shellcode'u emulate edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Open File" ve "Open Shellcode" seçeneklerini sunduğunu unutmayın. Benim durumumda shellcode'u file olarak açtığımda doğru şekilde decompile etti, ancak shellcode olarak açtığımda bunu yapmadı:

![Aynı byte'lar file veya shellcode olarak açıldığında Cutter'ın farklı analiz sonuçlarını göstermesi](<../../images/image (562).png>)

Emulation'ı istediğiniz yerde başlatmak için oraya bir bp koyun; görünüşe göre Cutter emulation'ı otomatik olarak oradan başlatacaktır:

![Cutter emulation'ını başlatmadan önce istenen shellcode entry'sine breakpoint ayarlanması](<../../images/image (589).png>)

![Seçilen shellcode breakpoint'inde duraklatılmış Cutter emulator'ı](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görebilirsiniz:

![Cutter'ın hex dump'ında emulate edilen shellcode stack'inin görüntülenmesi](<../../images/image (186).png>)

### Shellcode'u deobfuscate etme ve çalıştırılan fonksiyonları elde etme

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)'yi denemelisiniz.\
Shellcode'un kullandığı **fonksiyonların hangileri** olduğunu ve shellcode'un bellekte kendisini **decode edip etmediğini** size söyleyecektir.
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

**Create Dump** seçeneği, shellcode bellekte dinamik olarak değiştirilmişse son shellcode'u dump eder (decode edilmiş shellcode'u indirmek için kullanışlıdır). **start offset**, shellcode'u belirli bir offset'ten başlatmak için kullanılabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'u debug etmek için kullanışlıdır (ancak bu amaçla daha önce açıklanan seçeneklerden herhangi birini daha iyi buluyorum; çünkü Ida veya x64dbg kullanabilirsiniz).

### CyberChef kullanarak disassembly yapma

Shellcode dosyanızı input olarak yükleyin ve decompile etmek için aşağıdaki recipe'i kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` gibi basit ifadeleri aritmetik (`+`, `-`, `*`) ve bit düzeyi operatörleri (`&`, `|`, `^`, `~`, shift'ler) birleştiren formüllerin arkasına gizler. Önemli nokta, bu özdeşliklerin genellikle yalnızca **sabit genişlikli modüler aritmetik** altında doğru olmasıdır; bu nedenle carry'ler ve overflow'lar önem taşır:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Bu tür bir ifadeyi generic algebra tooling ile sadeleştirirseniz, bit-width semantics göz ardı edildiği için kolayca yanlış bir sonuç elde edebilirsiniz.<sup>[[1]](#references)</sup>

### Pratik iş akışı

1. **Orijinal bit genişliğini koruyun**: lifted code/IR/decompiler çıktısından (`8/16/32/64` bit).
2. Sadeleştirmeye çalışmadan önce **ifadeyi sınıflandırın**:
- **Linear**: bitwise atomların ağırlıklı toplamları
- **Semilinear**: `x & 0xFF` gibi sabit maskelerle birlikte linear ifadeler
- **Polynomial**: çarpımlar bulunur
- **Mixed**: çarpımlar ve bitwise logic iç içedir; genellikle tekrarlanan alt ifadeler bulunur
3. **Her aday yeniden yazımı** random testing veya bir SMT proof ile doğrulayın. Eşdeğerlik kanıtlanamıyorsa tahminde bulunmak yerine orijinal ifadeyi koruyun.

### Dar bir execution slice ile flattened control flow'u bypass edin

Eksiksiz control-flow graph'ı kurtarmak çoğu zaman gereksizdir. Control-flow flattening, opaque predicates, büyük dispatcher'lar veya MBA-heavy code ile karşılaştığınızda, encrypted blob'lara ve output buffer'larına yönelik referansları takip ederek bunları dönüştüren en küçük routine'i bulun. Ardından yalnızca bu data-flow slice'ı yeniden üretin veya bağımsız olarak çalıştırın; ilgili state doğrudan initialize edilebiliyorsa dispatcher gerekli çözümün parçası değildir.<sup>[[7]](#references)</sup>

Pratik bir iş akışı şöyledir:<sup>[[7]](#references)</sup>

1. Executable ve data section'larını, relocation'ları ve cross-reference'ları envanterleyin. Byte order ve element width değerlerini koruyarak `.rodata` içindeki aday table'ları dump edin.
2. Plaintext'i veya output buffer'ını yazan son routine'i belirleyin. Bu routine'in input'larını, referans verdiği table'ları, imported call'larını ve ihtiyaç duyduğu global state'i kaydedin.
3. Yalnızca bu operation'ları fixed-width bir Python modeline lift edin. Slice hâlâ çok fazla state'e bağlıysa, tüm programı emulate etmek yerine routine'i Unicorn, QEMU veya bir debugger altında çalıştırın ve ilgisiz import'ları hook'layın.
4. Extractor'ın output'unu gerçekten sağlanan binary'den türettiğini doğrulayın: silent fallback'leri kaldırın, binary içinde embedded answer'lar arayın ve extractor'ı string'lerin, key'lerin, identifier'ların, layout'ların ve obfuscation seed'lerinin değiştirildiği unseen build'ler üzerinde çalıştırın.

İlk geçişte kullanılabilecek yararlı command'lar şunlardır:<sup>[[7]](#references)</sup>
```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```
#### Sabit değerler olarak gizlenmiş MBA ifadelerini tespit etme

Görünüşte girdiye bağlı olan bir byte ifadesi, girdisini tamamen etkisiz hâle getirebilir. Tablolarını çıkardıktan sonra ifadeyi 8 bitlik tam domain üzerinde değerlendirin; tek elemanlı bir çıktı kümesi, çevreleyen durum makinesini kurtarmadan bu byte'ın sabit olduğunu kanıtlar.<sup>[[7]](#references)</sup>
```python
def mba(a, b, c, d, e, x):
return ((((a | (~x & 0xff)) & c) +
((x | b) & d)) ^ e) & 0xff

decoded = bytearray()
for row in zip(A, B, C, D, E):
outputs = {mba(*row, x) for x in range(256)}
if len(outputs) != 1:
raise ValueError("expression depends on x")
decoded.append(outputs.pop())
print(decoded)
```
Son maskeyi koruyun; çünkü özgün toplama işlemi byte-width wraparound içerir. Daha geniş bir domain için, iki aynı genişlikteki sembolik girdi için `f(x1) != f(x2)` ifadesinin satisfiable olup olmadığını bir SMT solver'a sorun: `unsat`, invariance'ı kanıtlarken `sat` bir karşı örnek sağlar ve girdinin atılamayacağı anlamına gelir.<sup>[[7]](#references)</sup>

#### Ortama bağlı decoding'i tanıyın

Anti-analysis kontrollerinin branch oluşturması veya programı crash ettirmesi gerekmez. Bir decoder, bir sensor sonucunu anahtar bitine, opaque-predicate sabitine veya flattened-dispatcher state'ine karıştırabilir; normal şekilde devam edebilir ve bir emulator'da makul görünen ancak yanlış plaintext üretebilir. Bu nedenle yalnızca görünür failure branch'lerini patch'lemek yetersizdir; environment probe'larından decoder state'ine uzanan data dependency'lerini izleyin, aynı slice'ı authentic device ve emulator üzerinde karşılaştırın ve her sensor sonucunu zorlamanın final buffer'ı nasıl değiştirdiğini test edin.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA), malware analysis ve protected-binary reversing için pratik bir MBA simplifier'dır. İfadeyi sınıflandırır ve her şeye tek bir generic rewrite pass uygulamak yerine specialized pipeline'lara yönlendirir.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA, ifadeyi Boolean girdiler üzerinde değerlendirir, bir signature türetir ve pattern matching, ANF conversion ve coefficient interpolation gibi çeşitli recovery yöntemlerini aynı anda dener.
- **Semilinear MBA**: constant-masked atomlar, maskelenmiş bölgelerin doğruluğunu korumak için bit-partitioned reconstruction ile yeniden oluşturulur.
- **Polynomial/Mixed MBA**: çarpımlar core'lara ayrıştırılır ve basitleştirme öncesinde tekrarlanan subexpression'lar temporaries içine alınarak dış relation sadeleştirilebilir.

Kurtarılması genellikle denenmeye değer, yaygın bir mixed identity örneği:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Şuna indirgenebilir:
```c
x * y
```
### Reversing notları

- CoBRA'yı, **lifted IR expressions** veya tam hesaplamayı izole ettikten sonra decompiler output üzerinde çalıştırmayı tercih edin.
- Expression masked arithmetic veya narrow registers kaynaklıysa `--bitwidth` seçeneğini açıkça kullanın.
- Daha güçlü bir proof adımına ihtiyacınız varsa buradaki yerel Z3 notlarını inceleyin:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca bir **LLVM pass plugin** (`libCobraPass.so`) olarak gelir; bu, sonraki analysis pass'lerinden önce MBA-heavy LLVM IR'ı normalize etmek istediğinizde kullanışlıdır.
- Desteklenmeyen carry-sensitive mixed-domain residuals, original expression'ı koruyup carry path'i manuel olarak analiz etmeye devam etmeniz gerektiğine dair bir sinyal olarak değerlendirilmelidir.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, program operasyonlarını `mov` tabanlı instruction sequence'lerle değiştirir ve control flow'u değiştirmek için signal/exception handling kullanır. Ayrıntılar için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Desteklenen binary'ler için [demovfuscator](https://github.com/kirschju/demovfuscator) sonucu deobfuscate edebilir. Birkaç dependency'si vardır.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Ve [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Eğer bir **CTF oynuyorsanız, flag'i bulmak için bu workaround** çok kullanışlı olabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**'i bulmak için aşağıdaki örnekte olduğu gibi fonksiyonları `::main` ifadesiyle arayın:

![Ghidra'da fonksiyon adlarında çift iki nokta üst üste main ifadesini arayarak bir Rust entry point'i bulma](<../../images/image (1080).png>)

Bu durumda binary'nin adı authenticator olduğundan, bunun ilgi çekici main fonksiyonu olduğu oldukça açık.\
Çağrılan **fonksiyonların** **adlarını** kullanarak, **girdileri** ve **çıktıları** hakkında bilgi edinmek için bunları **Internet'te** arayın.

### ELF firmware'inden Rust string'lerini kurtarma

**Rust ELF** binary'lerinde birçok static string, C-style NUL-terminated pointer'lar olarak referanslanmaz. Yaygın bir `rustc` yerleşimi, gerçek string blob'una işaret eden ve **`.rodata`** içinde depolanan bir **pointer/length tuple**'ını **`.data.rel.ro`** içinde barındırır:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Bu, `strings` veya varsayılan Ghidra analizinin bitişik dizeleri birleştirebileceği ya da çapraz referansları tamamen kaçırabileceği anlamına gelir.<sup>[[3]](#references)</sup>

Hızlı iş akışı:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. **`.rodata`** bölümünün sanal adresini ve boyutunu alın.
2. **`.data.rel.ro`** bölümünü her seferinde bir word olacak şekilde enumerate edin.
3. **`.rodata`** adres aralığındaki herhangi bir değeri aday string pointer olarak değerlendirin.
4. Sonraki word'ü aday uzunluk olarak değerlendirin.
5. Sanity filter'ları uygulayın (örneğin, uzunluğu **4** ile **100** byte arasında olanları tutun).
6. `0x00` değerine kadar taramak yerine, **`.rodata`** bölümünden tam olarak `length` byte okuyun.

Minimal extractor mantığı:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Bu, kurtarılan Rust string'leri genellikle **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers ve auth-related logic** ortaya çıkardığından firmware reversing işlemlerinde özellikle kullanışlıdır.

Ghidra bu string'leri kaçırırsa aynı heuristic'i uygulayan ve referans verilen `.rodata` offset'lerinde string data oluşturan özel bir script/plugin çalıştırın. Pen Test Partners tarafından yayımlanan `rust-strings` ve `RustStrings.py` araçları, bu fikri diğer **word sizes, endianness ve section layouts** yapılarına uyarlamak için iyi referanslardır.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi compiled binaries için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Bir Delphi binary'sini reverse etmeniz gerekiyorsa IDA plugin'i [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın ve ardından plugin dosyasını seçin.

Bu plugin binary'yi çalıştırır ve debugging başlangıcında function names'leri dinamik olarak çözümler. Debugging'i başlattıktan sonra Start düğmesine (yeşil olan veya f9) tekrar basın; gerçek code'un başlangıcında bir breakpoint tetiklenir.

Graphical application içinde bir düğmeye basarsanız debugger, o düğme tarafından çağrılan function'da durabilir.

## Golang

Bir Golang binary'sini reverse etmeniz gerekiyorsa IDA plugin'i [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm.

Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın ve ardından plugin dosyasını seçin.

Bu, functions'ların names'lerini çözer.

## Compiled Python

Bu sayfada ELF/EXE python compiled binary'sinden python code'unu nasıl alabileceğinizi bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Bir GBA oyununun **binary** dosyasını elde ederseniz onu **emulate** ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Interface içeren bir debugger
- [**mgba** ](https://mgba.io)- Bir CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin'i
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin'i

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünde Game Boy Advance **buttons**'larına nasıl basılacağını görebilirsiniz.

![Game Boy Advance button mapping'lerini gösteren no$gba controls configuration](<../../images/image (581).png>)

Basıldığında her **key,** onu tanımlamak için bir **value**'ya sahiptir:
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
Yani bu tür bir programda ilgi çekici kısım, **programın kullanıcı girdisini nasıl işlediği** olacaktır. **0x4000130** adresinde yaygın olarak bulunan **KEYINPUT** işlevini bulabilirsiniz.

![0x4000130 adresinde KEYINPUT'e başvuran bir GBA binary'sinin Ghidra görünümü](<../../images/image (447).png>)

Önceki görselde işlevin **FUN_080015a8**'den çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

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
Son **`if`**, **`uVar4`**'ün **son Keys** içinde olduğunu ve mevcut anahtar olmadığını kontrol ediyor; bu aynı zamanda bir düğmeyi bırakma olarak da adlandırılır (mevcut anahtar **`uVar1`** içinde saklanır).
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
Önceki kodda, **uVar1** (**basılan düğmenin değerinin** bulunduğu yer) değişkenini bazı değerlerle karşılaştırdığımızı görebilirsiniz:

- İlk olarak **4 değeri** (**SELECT** düğmesi) ile karşılaştırılır: Challenge'da bu düğme ekranı temizler.
- Ardından değer **8** (**START** düğmesi) ile karşılaştırılır; bu challenge'da ilgili yol, girilen kodun geçerli olup olmadığını kontrol eder.
- Bu durumda **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılır ve değer aynıysa bazı kodlar çalıştırılır.
- Diğer tüm durumlarda bir sayaç (`DAT_030000d4`) kontrol edilir ve artırılır.\
Sayaç 8'in altındayken, basılan tuşların değerleri `DAT_030000d8` içinde biriktirilir.

Dolayısıyla bu challenge'da, düğmelerin değerlerini bildiğiniz için, **uzunluğu 8'den küçük ve sonucundaki toplamı 0xf3 olan bir kombinasyona basmanız** gerekiyordu.

**Bu tutorial için referans:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Eğitimler

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [MBA obfuscation'ı CoBRA ile basitleştirme](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust string'lerini decode etme - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (arşivlenmiş)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI-Assisted Reverse Engineering'i yenmek veya en azından denemek](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
