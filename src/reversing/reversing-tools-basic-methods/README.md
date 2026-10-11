# Reversing Araçları ve Temel Yöntemler

{{#include ../../banners/hacktricks-training.md}}

## ImGui Tabanlı Reversing Araçları

Yazılım:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Windows kernel debugging

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Çevrimiçi:

- wasm'ı (binary) wat'a (düz metin) **decompile** etmek için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) adresini kullanın
- wat'ı wasm'a **compile** etmek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) adresini kullanın
- Decompilation için [web-wasmdec](https://wwwg.github.io/web-wasmdec/) aracını da deneyebilirsiniz.

Yazılım:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 önbelleğe alınmış bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek; **libraries** (.dll), **Windows metadata file**s (.winmd) ve **executables** (.exe) dahil olmak üzere birden fazla formatı **decompile eder ve inceler**. Decompile edildikten sonra bir assembly, Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantaj, kaybolmuş kaynak kodunun eski bir assembly'den geri yüklenmesi gerektiğinde bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilmiş kodda kullanışlı gezinme özellikleri sunar ve bu da onu **Xamarin algoritma analizi** için ideal araçlardan biri yapar.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in modeli ve aracı tam ihtiyaçlarınıza göre uyarlayan bir API ile .NET Reflector zamandan tasarruf sağlar ve geliştirmeyi kolaylaştırır. Bu aracın sunduğu çok sayıda reverse engineering hizmetine göz atalım:

- Bir library veya component içindeki veri akışına dair fikir verir
- .NET dilleri ve framework'lerinin uygulanışı ve kullanımı hakkında bilgi sağlar
- Kullanılan API'lerden ve teknolojilerden daha fazla yararlanmak için belgelenmemiş ve dışarıya açılmamış işlevleri bulur.
- Bağımlılıkları ve farklı assembly'leri bulur
- Kodunuzdaki, üçüncü taraf component'lerdeki ve library'lerdeki hataların tam konumunu tespit eder.
- Üzerinde çalıştığınız tüm .NET kodlarının kaynak kodunda debug yapar.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy plugin'i](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir işletim sisteminde kullanabilirsiniz (doğrudan VSCode üzerinden yükleyebilirsiniz; git'i indirmeniz gerekmez. **Extensions**'a tıklayın ve **ILSpy**'ı arayın).\
Tekrar **decompile**, **modify** ve **recompile** etmeniz gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak bakımı yapılan fork'u [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir fonksiyonun içindeki bir şeyi değiştirmek için **Right Click -> Modify Method** seçeneğine tıklayın).

### DNSpy Logging

**DNSpy'nin bazı bilgileri bir dosyaya loglamasını** sağlamak için bu snippet'i kullanabilirsiniz:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

DNSpy kullanarak kodda debug işlemi yapmak için şunları yapmanız gerekir:

İlk olarak, **debugging** ile ilgili **Assembly attributes** değerlerini değiştirin:

![DNSpy Logging - DNSpy Debugging: İlk olarak, debugging ile ilgili Assembly attributes değerlerini değiştirin](<../../images/image (973).png>)

Şundan:

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Ardından yeni dosyayı _**File >> Save module...**_ seçeneğiyle kaydedin:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Bunu yapmak gerekir; çünkü yapmazsanız **runtime** sırasında koda çeşitli **optimizasyonlar** uygulanır ve **debugging** sırasında bir **break-point'e hiç ulaşılmaması** veya bazı **değişkenlerin mevcut olmaması** mümkündür.

Ardından, .NET uygulamanız **IIS** tarafından **çalıştırılıyorsa**, şu komutla **yeniden başlatabilirsiniz**:

```
iisreset /noforce
```

Ardından debugging işlemini başlatmak için açılmış tüm dosyaları kapatmalı ve **Debug Tab** içinde **Attach to Process...** seçeneğini seçmelisiniz:

![DNSpy Logging - DNSpy Debugging: Ardından debugging işlemini başlatmak için açılmış tüm dosyaları kapatmalı ve Debug Tab içinde Attach to Process seçeneğini seçmelisiniz](<../../images/image (318).png>)

Ardından **IIS server**'a bağlanmak için **w3wp.exe**'yi seçin ve **attach**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Ardından IIS server'a bağlanmak için w3wp.exe'yi seçin ve attach'e tıklayın](<../../images/image (113).png>)

Artık process'i debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce _Debug >> Break All_ seçeneğine, ardından _**Debug >> Windows >> Modules**_ seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Artık process'i debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Artık process'i debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (834).png>)

**Modules** içindeki herhangi bir modüle tıklayın ve **Open All Modules** seçeneğini seçin:

![DNSpy Logging - DNSpy Debugging: Modules içindeki herhangi bir modüle tıklayın ve Open All Modules seçeneğini seçin](<../../images/image (922).png>)

**Assembly Explorer** içindeki herhangi bir modüle sağ tıklayın ve **Sort Assemblies**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer içindeki herhangi bir modüle sağ tıklayın ve Sort Assemblies'e tıklayın](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'leri debugging

### IDA kullanımı

- **rundll32'yi yükleyin** (64 bit için C:\Windows\System32\rundll32.exe, 32 bit için C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debugger'ını seçin
- "**Suspend on library load/unload**" seçeneğini seçin

![Debugging DLLs - Using IDA: " Suspend on library load/unload " seçeneğini seçin](<../../images/image (868).png>)

- **DLL'in yolunu** ve çağırmak istediğiniz fonksiyonu girerek çalıştırma **parametrelerini** yapılandırın:

![Debugging DLLs - Using IDA: DLL'in yolunu ve çağırmak istediğiniz fonksiyonu girerek çalıştırma parametrelerini yapılandırın](<../../images/image (704).png>)

Ardından, debugging'i başlattığınızda **her DLL yüklendiğinde çalıştırma durdurulur**; yani rundll32 DLL'inizi yüklediğinde çalıştırma durdurulur.

Bu yöntem modül yükleme olaylarında durur, ancak yüklenen DLL'in entry point'ine ulaşmak aşağıdaki x64dbg iş akışına kıyasla daha dolaylıdır.

### x64dbg/x32dbg kullanımı

- **rundll32'yi yükleyin** (64 bit için C:\Windows\System32\rundll32.exe, 32 bit için C:\Windows\SysWOW64\rundll32.exe)
- **Command Line'ı değiştirin** (_File --> Change Command Line_) ve DLL'in yolunu ve çağırmak istediğiniz fonksiyonu ayarlayın. Örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ bölümünü değiştirin ve "**DLL Entry**" seçeneğini seçin.
- Ardından **çalıştırmayı başlatın**; debugger her DLL main'de durur ve bir noktada **DLL'inizin Entry noktasında durursunuz**. Buradan, breakpoint koymak istediğiniz noktaları aramanız yeterlidir.

win64dbg'de çalıştırma herhangi bir nedenle durduğunda, **win64dbg penceresinin üst kısmına** bakarak **hangi kodda olduğunuzu** görebileceğinizi unutmayın:

![Using IDA - Using x64dbg/x32dbg: win64dbg'de çalıştırma herhangi bir nedenle durduğunda, win64dbg penceresinin üst kısmına bakarak hangi kodda olduğunuzu görebileceğinizi unutmayın](<../../images/image (842).png>)

Bu gösterge, çalıştırmanın debug etmek istediğiniz DLL'in içinde durduğunu doğrular.

## GUI uygulamaları / Video oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bunları değiştirmek için kullanışlı bir programdır. Daha fazla bilgi:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), oyunlara odaklanan GNU Project Debugger (GDB) için bir front-end/reverse engineering aracıdır. Bununla birlikte, reverse engineering ile ilgili her türlü iş için kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/), birçok decompiler için web tabanlı bir front-end'dir. Bu web servisi, küçük executable'lar üzerinde farklı decompiler'ların çıktılarını karşılaştırmanızı sağlar.

## ARM ve MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode'lar

### blobrunner ile shellcode debugging

[**BlobRunner**](https://github.com/OALabs/BlobRunner), **shellcode** için bellek ayırır, **bellek adresini** yazdırır ve çalıştırmayı duraklatır.\
Debugger'ı (IDA veya x64dbg gibi) bağlayın, yazdırılan adreste bir breakpoint ayarlayın ve shellcode'u debug etmek için çalıştırmaya devam edin.

Releases GitHub sayfasında derlenmiş sürümlerin bulunduğu zip dosyaları vardır: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
BlobRunner'ın biraz değiştirilmiş bir sürümünü aşağıdaki bağlantıda bulabilirsiniz. Derlemek için **Visual Studio Code'da bir C/C++ projesi oluşturun, kodu kopyalayıp yapıştırın ve build edin**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile shellcode debugging

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner'a benzer. Shellcode için bellek ayırır ve sonsuz bir döngüye girer. Debugger'ı bağlayın, **2–5 saniye** boyunca devam ettirin, bu döngünün içinde duraklatın ve ayrılan shellcode'a çalıştırmayı aktaran bir sonraki çağrıya ilerleyin.

![jmp2it'in sonsuz döngüsünde, ayrılan shellcode'a yapılan çağrıdan hemen önce duraklatılmış debugger](<../../images/image (509).png>)

Derlenmiş jmp2it sürümünü [releases sayfasından indirebilirsiniz](https://github.com/adamkramer/jmp2it/releases/).

### Cutter kullanarak shellcode debugging

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'ın GUI'sidir. Cutter kullanarak shellcode'u emulate edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Open File" ve "Open Shellcode" seçeneklerini sunduğunu unutmayın. Benim durumumda shellcode'u dosya olarak açtığımda doğru şekilde decompile etti, ancak shellcode olarak açtığımda etmedi:

![Aynı baytları dosya ve shellcode olarak açtığında farklı analiz sonuçları gösteren Cutter](<../../images/image (562).png>)

Emulation'ı istediğiniz noktada başlatmak için oraya bir bp ayarlayın; görünüşe göre Cutter emulation'ı otomatik olarak o noktadan başlatacaktır:

![Cutter emulation'ını başlatmadan önce istenen shellcode entry noktasına breakpoint koyma](<../../images/image (589).png>)

![Seçilen shellcode breakpoint'inde duraklatılmış Cutter emulator'ı](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görebilirsiniz:

![Emüle edilen shellcode stack'inin Cutter'ın hex dump'ında görüntülenmesi](<../../images/image (186).png>)

### Shellcode'u deobfuscate etme ve çalıştırılan fonksiyonları bulma

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)'yi deneyebilirsiniz.\
Shellcode'un hangi fonksiyonları kullandığı ve bellekte kendisini decode edip etmediği gibi bilgileri gösterir.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg ayrıca istediğiniz seçenekleri belirleyip shellcode'u çalıştırabileceğiniz grafiksel bir başlatıcı da sunar

![Shellcode emülasyonu ve izleme seçeneklerini belirlemek için scDbg grafiksel başlatıcısı](<../../images/image (258).png>)

**Create Dump** seçeneği, shellcode bellekte dinamik olarak değiştirilmişse son halini döker (çözümlenmiş shellcode'u indirmek için kullanışlıdır). **start offset**, shellcode'u belirli bir offset'ten başlatmak için kullanışlı olabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'da hata ayıklamak için kullanışlıdır (ancak bu amaçla, önceki seçeneklerden herhangi birini daha iyi buluyorum; çünkü Ida veya x64dbg kullanabilirsiniz).

### CyberChef kullanarak disassemble etme

Shellcode dosyanızı girdi olarak yükleyin ve disassemble etmek için şu tarifi kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation'ı çözme

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` gibi basit ifadeleri aritmetik (`+`, `-`, `*`) ve bit düzeyinde operatörleri (`&`, `|`, `^`, `~`, kaydırmalar) bir araya getiren formüllerin arkasına gizler. Önemli nokta, bu özdeşliklerin genellikle yalnızca **sabit genişlikli modüler aritmetikte** doğru olmasıdır; bu nedenle elde kalan bitler ve taşmalar önemlidir:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Bu tür bir ifadeyi genel amaçlı cebir araçlarıyla sadeleştirirseniz, bit genişliği semantiği göz ardı edildiği için kolayca yanlış sonuç elde edebilirsiniz.<sup>[[1]](#references)</sup>

### Uygulamalı iş akışı

1. **Orijinal bit genişliğini koruyun**: lifted kod/IR/decompiler çıktısındaki (`8/16/32/64` bit) genişliği kullanın.
2. **Sadeleştirmeye çalışmadan önce ifadeyi sınıflandırın**:
   - **Doğrusal**: bit düzeyindeki atomların ağırlıklı toplamları
   - **Yarı doğrusal**: `x & 0xFF` gibi sabit maskelerle birlikte doğrusal ifadeler
   - **Polinom**: çarpımlar içerir
   - **Karma**: çarpımlar ve bit düzeyindeki mantık iç içe geçmiştir; genellikle yinelenen alt ifadeler bulunur
3. **Aday her yeniden yazımı** rastgele testlerle veya bir SMT kanıtıyla doğrulayın. Eşdeğerlik kanıtlanamıyorsa tahminde bulunmak yerine özgün ifadeyi koruyun.

### Dar bir yürütme dilimiyle düzleştirilmiş kontrol akışını atlatın

Kontrol akış grafiğinin tamamını yeniden oluşturmak çoğu zaman gereksizdir. Control-flow flattening, opaque predicate'ler, büyük dispatcher'lar veya MBA ağırlıklı kod söz konusu olduğunda, şifrelenmiş blob'lardan ve çıktı tamponlarından bunları dönüştüren en küçük rutine giden başvuruları izleyin. Ardından yalnızca bu data-flow slice'ı yeniden oluşturun veya bağımsız olarak çalıştırın; ilgili durum doğrudan başlatılabiliyorsa dispatcher gerekli çözümün parçası değildir.<sup>[[7]](#references)</sup>

Uygulamalı bir iş akışı şöyledir:<sup>[[7]](#references)</sup>

1. Yürütülebilir ve veri bölümlerini, relocation'ları ve çapraz başvuruları envanterleyin. Bayt sırasını ve öğe genişliğini koruyarak `.rodata` içindeki aday tabloları dökün.
2. Plaintext'i veya çıktı tamponunu en son yazan rutini belirleyin. Girdilerini, başvurduğu tabloları, import edilmiş çağrıları ve gereken global durumu kaydedin.
3. Yalnızca bu işlemleri sabit genişlikli bir Python modeline aktarın. Dilim hâlâ çok fazla duruma bağlıysa, programın tamamını emüle etmek yerine rutini Unicorn, QEMU veya bir debugger altında çağırın ve ilgisiz import'lar için hook ekleyin.
4. Extractor'ın çıktısını gerçekten sağlanan binary'den türettiğini doğrulayın: sessiz fallback'leri kaldırın, içine gömülü yanıtları arayın ve değişen dizeler, anahtarlar, tanımlayıcılar, yerleşimler ve obfuscation seed'leri içeren, daha önce görülmemiş build'lerde çalıştırın.

İlk aşamada işe yarayan komutlar:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Sabit değerler olarak gizlenmiş MBA ifadelerini tespit etme

Görünüşte girdiye bağlı olan bir byte ifadesi, girdisini tamamen iptal edebilir. Tablolarını çıkardıktan sonra ifadeyi 8 bitlik tüm değerler için değerlendirin; çıktı kümesinin tek bir değerden oluşması, çevresindeki durum makinesini çözmeden bu byte'ın sabit olduğunu kanıtlar.<sup>[[7]](#references)</sup>

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

Son `mask` değerini koruyun; çünkü özgün toplama işleminde byte genişliğinde taşma vardır. Daha geniş bir alan için, bir SMT solver'a aynı genişlikteki iki sembolik girdi için `f(x1) != f(x2)` ifadesinin sağlanabilir olup olmadığını sorun: `unsat` değişmezliği kanıtlar; `sat` ise bir karşı örnek sunar ve girdinin atılamayacağı anlamına gelir.<sup>[[7]](#references)</sup>

#### Ortama bağlı çözümlemeyi tanıma

Anti-analysis kontrollerinin dallanması veya çökmeye yol açması şart değildir. Bir decoder, sensör sonucunu bir anahtar bitine, opaque-predicate sabitine veya flattened dispatcher durumuna karıştırabilir; normal şekilde devam edip bir emülatörde makul görünen ancak yanlış plaintext üretebilir. Bu nedenle yalnızca görünür hata dallarını yamamak yeterli değildir; ortam problarından decoder durumuna uzanan veri bağımlılıklarını izleyin, aynı dilimi gerçek cihazda ve emülatörde karşılaştırın ve her sensör sonucunu zorlamanın son buffer'ı nasıl değiştirdiğini test edin.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA), malware analizi ve korumalı binary'leri tersine mühendislikle inceleme için pratik bir MBA sadeleştiricisidir. Her şeye tek bir genel yeniden yazma geçişi uygulamak yerine ifadeyi sınıflandırır ve özel işlem hatlarına yönlendirir.<sup>[[2]](#references)</sup>

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

Kullanışlı durumlar:

- **Linear MBA**: CoBRA, ifadeyi Boolean girdiler üzerinde değerlendirir, bir imza çıkarır ve pattern matching, ANF dönüşümü ve katsayı interpolasyonu gibi çeşitli kurtarma yöntemlerini yarıştırır.
- **Semilinear MBA**: Sabit maskeli atomlar, maskelenmiş bölgelerin doğruluğunu korumak için bit bölümlü yeniden oluşturmayla yeniden kurulur.
- **Polynomial/Mixed MBA**: Çarpımlar çekirdek bileşenlerine ayrılır ve dış ilişki basitleştirilmeden önce tekrarlanan alt ifadeler geçici değişkenlere alınabilir.

Sıklıkla kurtarılmaya değer, karma bir özdeşlik örneği:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Bu, şu şekilde sadeleştirilebilir:

```c
x * y
```

### Tersine mühendislik notları

- CoBRA'yı **lifted IR ifadeleri** üzerinde veya tam hesaplamayı izole ettikten sonra decompiler çıktısında çalıştırmayı tercih edin.
- İfade maskelenmiş aritmetikten veya dar yazmaçlardan kaynaklanıyorsa `--bitwidth` değerini açıkça belirtin.
- Daha güçlü bir kanıtlama adımına ihtiyacınız varsa buradaki yerel Z3 notlarına göz atın:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca bir **LLVM pass plugin** (`libCobraPass.so`) olarak da gelir. Bu, sonraki analiz pass'lerinden önce MBA ağırlıklı LLVM IR'yi normalize etmek istediğinizde kullanışlıdır.
- Desteklenmeyen, carry'ye duyarlı karma alan kalıntılarını özgün ifadeyi koruyup carry yolunu elle analiz etmeniz gerektiğine dair bir işaret olarak değerlendirin.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, program işlemlerini `mov` tabanlı komut dizileriyle değiştirir ve kontrol akışını değiştirmek için signal/exception handling kullanır. Ayrıntılar için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Desteklenen binary'ler için [demovfuscator](https://github.com/kirschju/demovfuscator) sonucu deobfuscate edebilir. Birkaç bağımlılığı vardır.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Ve [keystone'u kurun](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Bir **CTF oynuyorsanız, flag'i bulmaya yönelik bu workaround** çok işinize yarayabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**Entry point**'i bulmak için, aşağıdaki örnekte olduğu gibi `::main` ifadesini arayarak fonksiyonları bulun:

![Ghidra'da fonksiyon adlarında çift iki nokta ve main ifadesini arayarak Rust entry point'ini bulma](<../../images/image (1080).png>)

Bu durumda binary'nin adı authenticator'dı; dolayısıyla ilgilendiğimiz main fonksiyonunun hangisi olduğu oldukça açık.\
Çağrılan **fonksiyonların** **adlarını** öğrendikten sonra, **girdileri** ve **çıktıları** hakkında bilgi edinmek için bunları **Internet**'te arayın.

### ELF firmware'inden Rust string'lerini kurtarma

**Rust ELF** binary'lerinde birçok statik string, C tarzı NUL sonlandırmalı pointer'larla referans gösterilmez. Yaygın bir `rustc` yerleşiminde, **`.data.rel.ro`** içindeki bir **pointer/length tuple**, gerçek string verisinin **`.rodata`** içinde saklandığı yere işaret eder:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Bu, `strings` veya varsayılan Ghidra analizinin bitişik dizeleri birleştirebileceği ya da çapraz başvuruları tamamen kaçırabileceği anlamına gelir.<sup>[[3]](#references)</sup>

Hızlı iş akışı:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** bölümünün sanal adresini ve boyutunu alın.
2. **`.data.rel.ro`** bölümünü her seferinde bir kelime olacak şekilde numaralandırın.
3. **`.rodata`** adres aralığındaki tüm değerleri aday string işaretçisi olarak değerlendirin.
4. Sonraki kelimeyi aday uzunluk olarak değerlendirin.
5. Makuliyet filtreleri uygulayın (örneğin, uzunluğu **4** ile **100** bayt arasında olanları tutun).
6. `0x00` değerine kadar taramak yerine, **`.rodata`** bölümünden tam olarak `length` bayt okuyun.

Minimal çıkarıcı mantığı:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Bu, firmware reversing sırasında özellikle kullanışlıdır; çünkü kurtarılan Rust string’leri genellikle **HTTP rotalarını, RPC adlarını, günlük mesajlarını, assertion’ları, dosya adlarını, config anahtarlarını, komut işleyicilerini ve kimlik doğrulamayla ilgili mantığı** ortaya çıkarır.

Ghidra bu string’leri bulamazsa aynı heuristic’i uygulayan ve başvurulan `.rodata` offset’lerinde string verileri oluşturan özel bir script/plugin çalıştırın. Pen Test Partners tarafından yayımlanan `rust-strings` ve `RustStrings.py` araçları, bu fikri diğer **word size, endianness ve section layout** yapılarına uyarlamak için iyi kaynaklardır.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi ile derlenmiş binary’ler için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Bir Delphi binary’sini reverse etmeniz gerekiyorsa IDA plugin’i [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

Python plugin’i yüklemek için IDA’da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu plugin, binary’yi çalıştırır ve debugging başlangıcında function adlarını dinamik olarak çözümler. Debugging başladıktan sonra Start düğmesine (yeşil olan veya f9) tekrar basın; gerçek kodun başlangıcında bir breakpoint’e ulaşılır.

Grafik uygulamasında bir düğmeye basarsanız debugger, o düğmenin çağırdığı function’da durabilir.

## Golang

Bir Golang binary’sini reverse etmeniz gerekiyorsa IDA plugin’i [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm.

Python plugin’i yüklemek için IDA’da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu, function adlarını çözümler.

## Compiled Python

Bu sayfada, derlenmiş bir ELF/EXE Python binary’sinden Python kodunun nasıl elde edileceğini bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Bir GBA oyununun **binary** dosyasını elde ederseniz, onu **emulate** ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Debug sürümünü indirin_) - Arayüzlü bir debugger içerir
- [**mgba** ](https://mgba.io)- Bir CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin’i
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin’i

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünden Game Boy Advance **düğmelerine** nasıl basılacağını görebilirsiniz.

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Basılı tutulduğunda her **tuşun onu tanımlayan bir değeri** vardır:

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

Bu tür programlarda ilgi çekici olan kısım, **programın kullanıcı girdisini nasıl işlediğidir**. **0x4000130** adresinde sıkça karşılaşılan **KEYINPUT** işlevini bulabilirsiniz.

![KEYINPUT'e 0x4000130 adresinde başvuran bir GBA binary'sinin Ghidra görünümü](<../../images/image (447).png>)

Önceki görselde, işlevin **FUN_080015a8**'den çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

Bu işlevde, bazı önemsiz başlatma işlemlerinden sonra:

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

Şu kodu bulur:

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

Son if, **`uVar4`**'ün önceki **Keys** arasında olup olmadığını ve mevcut tuş olmadığını kontrol ediyor; bu, bir tuşu bırakmak olarak da bilinir (mevcut tuş **`uVar1`** içinde saklanır).

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

Önceki kodda **uVar1**'ın (**basılan düğmenin değerinin** bulunduğu yer) bazı değerlerle karşılaştırıldığını görebilirsiniz:

- İlk olarak **4 değeriyle** (**SELECT** düğmesi) karşılaştırılır: Challenge'da bu düğme ekranı temizler.
- Ardından değer **8** (**START** düğmesi) ile karşılaştırılır; bu challenge'da bu yol, girilen kodun geçerli olup olmadığını kontrol eder.
  - Bu durumda **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılır ve değer aynıysa bazı kodlar çalıştırılır.
- Diğer tüm durumlarda bir sayaç (`DAT_030000d4`) kontrol edilir ve artırılır.\
  Sayaç 8'in altındayken basılan tuşların değerleri `DAT_030000d8` içinde biriktirilir.

Dolayısıyla bu challenge'da, düğmelerin değerlerini bilerek, **uzunluğu 8'den kısa ve toplamı 0xf3 olan bir kombinasyona basmanız gerekiyordu.**

**Bu eğitim için referans:** [arşivlenmiş Nostalgia challenge yazısı](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kurslar

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRA ile MBA obfuscation'ı basitleştirme](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust string'lerini çözümleme - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing eğitimi (arşivlenmiş)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI destekli reverse engineering'i yenmek veya en azından denemek](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
