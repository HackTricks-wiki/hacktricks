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

- wasm'den (binary) wat'e (düz metin) **decompile** etmek için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) adresini kullanın
- wat'ten wasm'e **compile** etmek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) adresini kullanın
- Decompilation için [web-wasmdec](https://wwwg.github.io/web-wasmdec/) aracını da deneyebilirsiniz.

Yazılım:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 önbelleğe alınmış bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Sanallaştırılmış payload'lar ve özel VM'ler

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek; **library**'ler (.dll), **Windows metadata dosyaları** (.winmd) ve **executable**'lar (.exe) dahil olmak üzere birçok formatı **decompile edip inceleyen** bir decompiler'dır. Decompile edildikten sonra bir assembly, Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantajı, kaybolmuş bir kaynak kodunun eski bir assembly'den geri yüklenmesi gerektiğinde bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilmiş kodda kolay gezinme olanağı sunar; bu da onu **Xamarin algoritma analizi** için ideal araçlardan biri yapar.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in modeli ve aracı tam ihtiyaçlarınıza uyarlayan bir API ile .NET Reflector zaman kazandırır ve geliştirme sürecini kolaylaştırır. Bu aracın sunduğu çok sayıda reverse engineering hizmetine göz atalım:

- Verilerin bir library veya component içinde nasıl aktığına dair bilgi sağlar
- .NET dilleri ve framework'lerinin uygulanışı ve kullanımı hakkında bilgi sağlar
- Kullanılan API ve teknolojilerden daha fazla yararlanmak için belgelenmemiş ve dışarıya açılmamış işlevleri bulur.
- Bağımlılıkları ve farklı assembly'leri bulur
- Kodunuzdaki, üçüncü taraf component'lerdeki ve library'lerdeki hataların tam konumunu tespit eder.
- Üzerinde çalıştığınız tüm .NET kodlarının kaynağında debug yapar.

### [ILSpy](https://github.com/icsharpcode/ILSpy) ve [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy eklentisi](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir işletim sisteminde kullanabilirsiniz (doğrudan VSCode üzerinden yükleyebilirsiniz; git'i indirmeniz gerekmez. **Extensions**'a tıklayın ve **ILSpy** araması yapın).\
Yeniden **decompile** etmeniz, **değiştirmeniz** ve **recompile** etmeniz gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak sürdürülen fork'u [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir fonksiyonun içindeki bir şeyi değiştirmek için **Right Click -> Modify Method**.)

### DNSpy Logging

**DNSpy'nin bazı bilgileri bir dosyaya loglamasını** sağlamak için şu snippet'i kullanabilirsiniz:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy ile Hata Ayıklama

DNSpy kullanarak kodda hata ayıklamak için şunları yapmanız gerekir:

Önce, **debugging** ile ilgili **Assembly attributes** değerlerini değiştirin:

![DNSpy Logging - DNSpy ile Hata Ayıklama: Önce, debugging ile ilgili Assembly attributes değerlerini değiştirin](<../../images/image (973).png>)

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

Ve **derle**'ye tıklayın:

![DNSpy Logging - DNSpy Debugging: Ve derle'ye tıklayın](<../../images/image (314) (1).png>)

Ardından yeni dosyayı _**Dosya >> Modülü kaydet...**_ üzerinden kaydedin:

![DNSpy Logging - DNSpy Debugging: Ardından yeni dosyayı Dosya Modülü kaydet üzerinden kaydedin](<../../images/image (602).png>)

Bu gereklidir; çünkü bunu yapmazsanız, **runtime** sırasında koda çeşitli **optimizasyonlar** uygulanır ve debugging sırasında bir **breakpoint'e hiç ulaşılmaması** veya bazı **değişkenlerin bulunmaması** mümkündür.

Ardından, .NET uygulamanız **IIS** tarafından **çalıştırılıyorsa**, uygulamayı şu komutla **yeniden başlatabilirsiniz**:

```
iisreset /noforce
```

Ardından debugging'e başlamak için açılmış tüm dosyaları kapatın ve **Debug Tab** içinde **Attach to Process...** seçeneğini seçin:

![DNSpy Logging - DNSpy Debugging: Ardından debugging'e başlamak için açılmış tüm dosyaları kapatın ve Debug Tab içinde Attach to Process seçeneğini seçin](<../../images/image (318).png>)

**IIS server**'a bağlanmak için **w3wp.exe**'yi seçin ve **attach**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: IIS server'a bağlanmak için w3wp.exe'yi seçin ve attach'e tıklayın](<../../images/image (113).png>)

Süreci debug ettiğimize göre şimdi durdurup tüm modülleri yükleyebiliriz. Önce _Debug >> Break All_'a, ardından _**Debug >> Windows >> Modules**_'a tıklayın:

![DNSpy Logging - DNSpy Debugging: Süreci debug ettiğimize göre şimdi durdurup tüm modülleri yükleyebiliriz. Önce Debug Break All'a, ardından Debug Windows Modules'a tıklayın](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Süreci debug ettiğimize göre şimdi durdurup tüm modülleri yükleyebiliriz. Önce Debug Break All'a, ardından Debug Windows Modules'a tıklayın](<../../images/image (834).png>)

**Modules** içindeki herhangi bir modüle tıklayın ve **Open All Modules**'ı seçin:

![DNSpy Logging - DNSpy Debugging: Modules içindeki herhangi bir modüle tıklayın ve Open All Modules'ı seçin](<../../images/image (922).png>)

**Assembly Explorer** içindeki herhangi bir modüle sağ tıklayın ve **Sort Assemblies**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer içindeki herhangi bir modüle sağ tıklayın ve Sort Assemblies'e tıklayın](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'leri debug etme

### IDA kullanarak

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe, 32 bit sürümü C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Windbg** debugger'ını seçin
- "**Suspend on library load/unload**" seçeneğini seçin

![Debugging DLLs - Using IDA: "Suspend on library load/unload" seçeneğini seçin](<../../images/image (868).png>)

- Yürütmenin **parameters**'ını, **DLL'nin path**'ini ve çağırmak istediğiniz fonksiyonu belirterek yapılandırın:

![Debugging DLLs - Using IDA: DLL'nin path'ini ve çağırmak istediğiniz fonksiyonu belirterek yürütmenin parameters'ını yapılandırın](<../../images/image (704).png>)

Ardından debugging'i başlattığınızda **her DLL yüklendiğinde yürütme durur**; yani rundll32 DLL'nizi yüklediğinde yürütme duracaktır.

Bu yöntem modül yükleme olaylarında durur; ancak yüklenen DLL'nin entry point'ine ulaşmak, aşağıdaki x64dbg iş akışına kıyasla daha dolaylıdır.

### x64dbg/x32dbg kullanarak

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe, 32 bit sürümü C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Command Line'ı değiştirin** ( _File --> Change Command Line_ ) ve DLL'nin path'ini ve çağırmak istediğiniz fonksiyonu belirtin; örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ bölümüne gidin ve "**DLL Entry**"yi seçin.
- Ardından **yürütmeyi başlatın**; debugger her DLL main'de duracaktır. Bir noktada **DLL'nizin DLL Entry noktasında duracaksınız**. Buradan, breakpoint koymak istediğiniz noktaları arayın.

win64dbg'de yürütme herhangi bir nedenle durduğunda, **win64dbg penceresinin üst kısmına** bakarak **hangi kodun içinde olduğunuzu** görebileceğinizi unutmayın:

![Using IDA - Using x64dbg/x32dbg: Yürütme herhangi bir nedenle win64dbg'de durduğunda, win64dbg penceresinin üst kısmına bakarak hangi kodun içinde olduğunuzu görebilirsiniz](<../../images/image (842).png>)

Bu gösterge, yürütmenin debug etmek istediğiniz DLL'nin içinde durduğunu doğrular.

## GUI uygulamaları / video oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bu değerleri değiştirmek için kullanışlı bir programdır. Daha fazla bilgi:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), oyunlara odaklanan GNU Project Debugger (GDB) için bir front-end/reverse engineering aracıdır. Ancak reverse engineering ile ilgili her türlü iş için kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/), çeşitli decompiler'lara web front-end'i sağlayan bir araçtır. Bu web servisi, küçük executable dosyalarında farklı decompiler'ların çıktısını karşılaştırmanıza olanak tanır.

## ARM ve MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode'lar

### blobrunner ile shellcode debug etme

[**BlobRunner**](https://github.com/OALabs/BlobRunner), **shellcode** için bellek ayırır, **bellek adresini** yazdırır ve yürütmeyi duraklatır.\
IDA veya x64dbg gibi bir debugger bağlayın, yazdırılan adrese breakpoint koyun ve shellcode'u debug etmek için yürütmeye devam edin.

Releases GitHub sayfasında derlenmiş sürümlerin bulunduğu zip dosyaları vardır: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Aşağıdaki bağlantıda Blobrunner'ın biraz değiştirilmiş bir sürümünü bulabilirsiniz. Derlemek için **Visual Studio Code'da bir C/C++ projesi oluşturun, kodu kopyalayıp yapıştırın ve derleyin**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile shellcode debug etme

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner'a benzer. Shellcode için bellek ayırır ve sonsuz bir döngüye girer. Debugger'ı bağlayın, **2–5 saniye** devam ettirin, bu döngünün içinde duraklatın ve ayrılan shellcode'a yürütmeyi aktaran sonraki çağrıya kadar step edin.

![jmp2it'in sonsuz döngüsünde, ayrılan shellcode'a yapılan çağrının hemen öncesinde duraklatılmış debugger](<../../images/image (509).png>)

Derlenmiş jmp2it sürümünü [releases sayfasından](https://github.com/adamkramer/jmp2it/releases/) indirebilirsiniz.

### Cutter kullanarak shellcode debug etme

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'ın GUI'sidir. Cutter ile shellcode'u emulate edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Open File" ve "Open Shellcode" seçenekleri sunduğunu unutmayın. Benim durumumda shellcode'u dosya olarak açtığımda doğru şekilde decompile etti; ancak shellcode olarak açtığımda bunu yapamadı:

![Aynı baytları dosya veya shellcode olarak açarken farklı analiz sonuçları gösteren Cutter](<../../images/image (562).png>)

Emülasyonu istediğiniz noktada başlatmak için oraya bir bp koyun; Cutter görünüşe göre emülasyonu otomatik olarak o noktadan başlatacaktır:

![Cutter emülasyonunu başlatmadan önce istenen shellcode giriş noktasına breakpoint koyma](<../../images/image (589).png>)

![Seçilen shellcode breakpoint'inde duraklatılmış Cutter emulator](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görebilirsiniz:

![Emüle edilen shellcode stack'ini Cutter'ın hex dump'inde görüntüleme](<../../images/image (186).png>)

### Shellcode'u deobfuscate etme ve yürütülen fonksiyonları bulma

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) aracını deneyin.\
Shellcode'un hangi **fonksiyonları** kullandığı ve bellekte kendisini **decode** edip etmediği gibi bilgileri gösterir.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg ayrıca istediğiniz seçenekleri belirleyip shellcode'u çalıştırabileceğiniz grafiksel bir başlatıcı da sunar

![scDbg shellcode emülasyonu ve izleme seçeneklerini belirlemek için kullanılan grafiksel başlatıcı](<../../images/image (258).png>)

**Create Dump** seçeneği, bellekte shellcode üzerinde dinamik olarak herhangi bir değişiklik yapılmışsa son hâlini dump eder (decode edilmiş shellcode'u indirmek için kullanışlıdır). **start offset**, shellcode'u belirli bir offset'ten başlatmak için kullanışlı olabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'da debug yapmak için kullanışlıdır (ancak bu iş için önceden açıkladığım seçeneklerden herhangi birini daha iyi buluyorum; çünkü Ida veya x64dbg kullanabilirsiniz).

### CyberChef kullanarak disassemble etme

Shellcode dosyanızı girdi olarak yükleyin ve decompile etmek için şu tarifi kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, aritmetik (`+`, `-`, `*`) ve bit düzeyinde işleçleri (`&`, `|`, `^`, `~`, kaydırmalar) birleştiren formüllerin ardına `x + y` gibi basit ifadeleri gizler. Önemli nokta, bu özdeşliklerin genellikle yalnızca **sabit genişlikli modüler aritmetik** altında doğru olmasıdır; bu nedenle elde taşımalar ve taşmalar önemlidir:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Bu tür bir ifadeyi genel amaçlı cebir araçlarıyla sadeleştirirseniz bit genişliği semantiği göz ardı edildiği için kolayca yanlış bir sonuç elde edebilirsiniz.<sup>[[1]](#references)</sup>

### Pratik iş akışı

1. Kaldırılmış kod/IR/decompiler çıktısındaki **orijinal bit genişliğini** koruyun (`8/16/32/64` bit).
2. Sadeleştirmeye çalışmadan önce ifadeyi **sınıflandırın**:
   - **Doğrusal**: bit düzeyindeki atomların ağırlıklı toplamları
   - **Yarı doğrusal**: `x & 0xFF` gibi sabit maskelerle birlikte doğrusal ifadeler
   - **Polinom**: çarpımlar içerir
   - **Karma**: çarpımlar ile bit düzeyindeki mantık iç içe geçmiştir; genellikle tekrarlanan alt ifadeler bulunur
3. Aday her yeniden yazımı rastgele testlerle veya bir SMT kanıtıyla **doğrulayın**. Eşdeğerliği kanıtlayamıyorsanız tahminde bulunmak yerine özgün ifadeyi koruyun.

### Dar bir yürütme dilimiyle düzleştirilmiş control flow'u atlatın

Tam control-flow graph'ını çıkarmak çoğu zaman gereksizdir. Control-flow flattening, opaque predicate'ler, büyük dispatcher'lar veya MBA ağırlıklı kod söz konusu olduğunda, şifrelenmiş blob'lardan ve output buffer'lardan bunları dönüştüren en küçük rutine giden referansları izleyin. Ardından yalnızca bu data-flow dilimini yeniden oluşturun veya bağımsız olarak çalıştırın; ilgili state doğrudan başlatılabiliyorsa dispatcher gerekli çözümün parçası değildir.<sup>[[7]](#references)</sup>

Pratik bir iş akışı şöyledir:<sup>[[7]](#references)</sup>

1. Çalıştırılabilir ve veri bölümlerini, relocation'ları ve çapraz referansları envanterleyin. Bayt sırasını ve öğe genişliğini koruyarak `.rodata` içindeki olası tabloları dökün.
2. Plaintext'i veya output buffer'ı yazan son rutini belirleyin. Girdilerini, başvurduğu tabloları, import edilmiş çağrıları ve gerekli global state'i kaydedin.
3. Yalnızca bu işlemleri sabit genişlikli bir Python modeline aktarın. Dilim hâlâ çok fazla state'e bağlıysa tüm programı emüle etmek yerine rutini Unicorn, QEMU veya bir debugger altında çağırın ve ilgisiz import'ları hook'layın.
4. Extractor'un çıktısını gerçekten verilen binary'den türettiğini doğrulayın: sessiz fallback'leri kaldırın, gömülü yanıtlar için binary'de arama yapın ve değişen string'ler, key'ler, identifier'lar, layout'lar ve obfuscation seed'leri içeren, daha önce görülmemiş build'lerde çalıştırın.

İlk aşamada kullanışlı komutlar şunlardır:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Gizlenmiş sabitler olan MBA ifadelerini tespit etme

Görünüşte girdiye bağlı olan bir byte ifadesi, girdisini tamamen etkisiz hâle getirebilir. Tablolarını çıkardıktan sonra ifadeyi 8 bitlik tüm değerler üzerinde değerlendirin; tek elemanlı bir çıktı kümesi, çevresindeki durum makinesini çözmeden bu byte'ın sabit olduğunu kanıtlar.<sup>[[7]](#references)</sup>

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

Orijinal toplama byte genişliğinde sarma içerdiğinden son maskeyi koruyun. Daha geniş bir alanda, aynı genişlikteki iki sembolik girdi için bir SMT solver'a `f(x1) != f(x2)` ifadesinin sağlanabilir olup olmadığını sorun: `unsat` değişmezliği kanıtlar; `sat` ise bir karşı örnek sunar ve girdinin elenemeyeceği anlamına gelir.<sup>[[7]](#references)</sup>

#### Ortama bağlı çözümlemeyi tanıma

Anti-analysis kontrollerinin dallanması veya çökmesi gerekmez. Bir decoder, sensör sonucunu bir anahtar bitine, opaque predicate sabitine ya da flattened dispatcher durumuna katıp normal şekilde devam edebilir ve emulator'da makul görünen ancak yanlış plaintext üretebilir. Bu nedenle yalnızca görünür hata dallarını patch etmek yeterli değildir; ortam problarından decoder durumuna uzanan veri bağımlılıklarını izleyin, aynı kod kesitini gerçek cihaz ve emulator üzerinde karşılaştırın ve her sensör sonucunu zorlamanın son buffer'ı nasıl değiştirdiğini test edin.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA), malware analizi ve korumalı binary'lerin tersine mühendisliği için pratik bir MBA sadeleştiricisidir. İfadeyi sınıflandırır ve her şeye tek bir genel yeniden yazma adımı uygulamak yerine, onu özelleştirilmiş işlem hatlarına yönlendirir.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA, ifadeyi Boolean girdiler üzerinde değerlendirir, bir imza çıkarır ve pattern matching, ANF dönüşümü ve katsayı enterpolasyonu gibi çeşitli kurtarma yöntemlerini yarıştırır.
- **Semilinear MBA**: Sabit maskeli atomlar, maskelenmiş bölgelerin doğruluğunu korumak için bit-parçalı yeniden oluşturmayla tekrar oluşturulur.
- **Polynomial/Mixed MBA**: Çarpımlar çekirdeklerine ayrıştırılır ve dış ilişki sadeleştirilmeden önce yinelenen alt ifadeler geçici değişkenlere taşınabilir.

Sıklıkla kurtarılmaya değer, karma bir özdeşlik örneği:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Bu, şu şekilde sadeleştirilebilir:

```c
x * y
```

### Tersine mühendislik notları

- CoBRA'yı **lifted IR ifadeleri** veya tam hesaplamayı yalıttıktan sonra decompiler çıktısı üzerinde çalıştırmayı tercih edin.
- İfade maskelenmiş aritmetikten veya dar register'lardan kaynaklanıyorsa `--bitwidth` seçeneğini açıkça kullanın.
- Daha güçlü bir ispat adımına ihtiyacınız varsa buradaki yerel Z3 notlarına bakın:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca bir **LLVM pass plugin** (`libCobraPass.so`) olarak da gelir. Bu eklenti, sonraki analiz pass'lerinden önce MBA ağırlıklı LLVM IR'yi normalize etmek istediğinizde kullanışlıdır.
- Desteklenmeyen, carry'ye duyarlı karma alan kalıntıları, orijinal ifadeyi koruyup carry yolunu elle incelemeniz gerektiğini gösterir.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, program işlemlerini `mov` tabanlı komut dizileriyle değiştirir ve kontrol akışını değiştirmek için signal/exception handling kullanır. Ayrıntılar için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Desteklenen binary'ler için [demovfuscator](https://github.com/kirschju/demovfuscator) sonucu deobfuscate edebilir. Birkaç bağımlılığı vardır.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

And [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Bir **CTF oynuyorsanız, flag'i bulmaya yönelik bu workaround** çok işinize yarayabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**Entry point**'i bulmak için, aşağıdaki örnekte olduğu gibi fonksiyonları `::main` ifadesine göre arayın:

![Ghidra'da fonksiyon adlarında çift iki nokta ve main ifadesini arayarak Rust entry point'ini bulma](<../../images/image (1080).png>)

Bu örnekte binary'nin adı authenticator'dı; dolayısıyla bunun ilgi çekici main fonksiyonu olduğu oldukça açık.\
Çağrılan **fonksiyonların** **adlarını** öğrendikten sonra, **girdileri** ve **çıktıları** hakkında bilgi edinmek için bunları **İnternet'te** arayın.

### ELF firmware'inden Rust string'lerini kurtarma

**Rust ELF** binary'lerinde birçok statik string, C tarzı NUL ile sonlandırılmış pointer'lar olarak referans alınmaz. Yaygın bir `rustc` yerleşiminde, **`.data.rel.ro`** içinde bulunan bir **pointer/length tuple**, **`.rodata`** içinde saklanan gerçek string blob'una işaret eder:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Bu, `strings`'in veya varsayılan Ghidra analizinin bitişik dizeleri birleştirebileceği ya da çapraz başvuruları tamamen gözden kaçırabileceği anlamına gelir.<sup>[[3]](#references)</sup>

Hızlı iş akışı:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`**'nın sanal adresini ve boyutunu alın.
2. **`.data.rel.ro`**'yu her seferinde bir word olacak şekilde sıralayın.
3. **`.rodata`** adres aralığındaki her değeri olası bir string pointer olarak değerlendirin.
4. Sonraki word'ü olası uzunluk olarak değerlendirin.
5. Sağlama filtreleri uygulayın (örneğin, uzunluğu **4** ile **100** byte arasında olanları tutun).
6. `0x00` değerine kadar taramak yerine **`.rodata`**'dan tam olarak `length` byte okuyun.

Minimal extractor mantığı:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Bu, firmware reversing sırasında özellikle kullanışlıdır; çünkü kurtarılan Rust string'leri genellikle **HTTP route'larını, RPC adlarını, log mesajlarını, assertion'ları, dosya adlarını, config key'lerini, command handler'larını ve auth ile ilgili mantığı** ortaya çıkarır.

Ghidra bu string'leri bulamazsa aynı heuristic'i uygulayan ve referans verilen `.rodata` offset'lerinde string verisi oluşturan özel bir script/plugin çalıştırın. Pen Test Partners tarafından yayımlanan `rust-strings` ve `RustStrings.py` araçları, bu fikri diğer **word size'lara, endianness türlerine ve section layout'larına** uyarlamak için iyi referanslardır.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi ile derlenmiş binary'ler için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Bir Delphi binary'sini reverse etmeniz gerekiyorsa IDA plugin'i [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

Bir Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu plugin, binary'yi çalıştırır ve debugging başladığında function adlarını dinamik olarak çözümler. Debugging'i başlattıktan sonra Start düğmesine (yeşil olan veya f9) tekrar basın; gerçek code'un başlangıcında bir breakpoint tetiklenir.

Grafik uygulamasında bir düğmeye basarsanız debugger, bu düğmenin çağırdığı function'da durabilir.

## Golang

Sıradan Go binary'leri için [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper), runtime structure'larını kurtarabilir ve IDA'daki function adlarını iyileştirebilir. Python plugin'ini yüklemek için **Alt+F7** tuşlarına basın.

### Symbol table olmadan metadata'yı kurtarma

Stripped bir Go executable'ı, program counter'ları function'lara eşlemek için yine de runtime metadata'sına ihtiyaç duyar. [GoReSym](https://github.com/mandiant/GoReSym), Go runtime'ından türetilen code'u kullanarak `pclntab` ve `moduledata` gibi structure'ları bulup ayrıştırır. Bu sayede geleneksel symbol table'a bağlı kalmadan function sınırları, adları, source path'leri, type'lar ve build ayrıntıları kurtarılabilir.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Bir obfuscator, kurtarılan adları değiştirirken bu yapıları kullanılabilir durumda bırakabilir. Örneğin Garble, identifier'ları ve package path'lerini hash'ler; build, module ve debug bilgilerini kaldırır.<sup>[[12]](#references)</sup> Obfuscated package token'ı, o package'teki işlevler arasında tutarlı kalmalıdır. İşlevleri tekrarlanan token'a göre gruplayın, callees, string'ler ve API'lerden bir package çıkarımı yapın, ardından bu package etiketini grubun tamamına uygulayın.<sup>[[13]](#references)</sup>

### GoResolver ile Garble adlarını kurtarma

[GoResolver](https://github.com/volexity/GoResolver), runtime-symbol extraction işlemini clean-reference generation ve control-flow-graph (CFG) matching ile birleştirir. Şu adımları izleyin:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler sürümünü belirleyin.** Önce `BuildInfo` ve gömülü sürüm string'lerini deneyin. Obfuscator bunları kaldırdıysa, bundled Go runtime'ın bölümlerini sürümlendirilmiş reference runtime'larla karşılaştırın. Volexity testlerinde, Go'nun major sürümlerini ayırt etmek için runtime'ın yaklaşık `%2`'si yeterliydi. Bunu evrensel bir eşik değil, deneysel bir optimizasyon olarak değerlendirin.<sup>[[13]](#references)</sup>
2. **Eşleşen reference'lar oluşturun.** Belirlenen Go sürümü, hedef mimari ve olası library'ler için clean binary'ler oluşturun. Toolchain'in eşleşmesi, compiler tarafından oluşturulan CFG farklılıklarını azaltır.<sup>[[10]](#references)[[13]](#references)</sup>
3. **İşlevleri karşılaştırın.** GoGrapher, işlev CFG'lerini eşleştirir ve `0.0` ile `1.0` arasında normalize edilmiş skorlar üretir. Temel blok eşleştirmesi, benzer instruction'ların ağırlıklı karşılaştırmasına dayanır. Yüksek güvenilirlikli eşleşmeler, randomize edilmiş işlevleri clean implementation ile eşler. Daha zayıf eşleşmeler yine de bir package veya module belirleyebilir.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Doğrulayın ve içe aktarın.** Önerilen adları call ilişkileri, constant'lar, string'ler ve yan etkilerle doğrulayın; ardından GoResolver plugin'ini kullanarak JSON raporunu IDA veya Ghidra'ya aktarın.<sup>[[10]](#references)[[13]](#references)</sup>

Toolchain'i kurun ve birleştirilmiş extractor ile graph matcher'ı çalıştırın:<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

Varsayılan anlamlı eşleşme eşiği `0.9`'dur. `--extract` ve `--graph` seçenekleri aşamalardan birini yalıtabilir; varsayılan olarak ikisi de çalıştırılır, çünkü kurtarılan runtime metadata ve CFG kanıtları birbirini tamamlar.<sup>[[10]](#references)</sup> CFG skorları sezgiseldir: inlining, build flags, mimari ve library version farklılıkları grafiğin şeklini değiştirebilir. Bu nedenle düşük güvenli adları zorla atamak yerine çözümlenmemiş fonksiyonları koruyun.<sup>[[13]](#references)</sup>

## Derlenmiş Python

Bu sayfada, ELF/EXE Python derlenmiş bir binary'den Python kodunun nasıl elde edileceğini bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Bir GBA oyununun **binary** dosyasını edinirseniz, onu **emulate** etmek ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug sürümünü indirin_) - Arayüzlü bir debugger içerir
- [**mgba** ](https://mgba.io)- Bir CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin'i
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin'i

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünde Game Boy Advance **düğmelerine** nasıl basılacağını görebilirsiniz.

![Game Boy Advance düğme eşleştirmelerini gösteren no$gba kontrolleri yapılandırması](<../../images/image (581).png>)

Basınca, her **tuşun onu tanımlayan bir değeri** vardır:

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

Yani bu tür bir programda ilgi çekici olan kısım, **programın kullanıcı girdisini nasıl işlediğidir**. **0x4000130** adresinde sıkça karşılaşılan **KEYINPUT** işlevini bulabilirsiniz.

![0x4000130 adresinde KEYINPUT'e başvuran bir GBA binary'sinin Ghidra görünümü](<../../images/image (447).png>)

Önceki görselde, bu işlevin **FUN_080015a8** içinden çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

Bu işlevde, bazı önemsiz init işlemlerinden sonra:

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

Son if, **`uVar4`** değerinin **last Keys** içinde olup olmadığını ve mevcut tuş olmadığını kontrol ediyor; bu, düğmeyi bırakma olarak da adlandırılır (mevcut tuş **`uVar1`** içinde saklanır).

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

Önceki kodda **uVar1**'in (**basılan düğmenin değerinin** bulunduğu yer) bazı değerlerle karşılaştırıldığını görebilirsiniz:

- İlk olarak **4 değeriyle** (**SELECT** düğmesi) karşılaştırılır: Bu challenge'da bu düğme ekranı temizler.
- Ardından değer **8** (**START** düğmesi) ile karşılaştırılır; bu challenge'da bu yol, girilen kodun geçerli olup olmadığını kontrol eder.
  - Bu durumda **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılır ve değer aynıysa bazı kodlar çalıştırılır.
- Diğer tüm durumlarda bir sayaç (`DAT_030000d4`) kontrol edilir ve artırılır.\
  Sayaç 8'in altındayken basılan düğme değerleri `DAT_030000d8` içinde biriktirilir.

Dolayısıyla bu challenge'da, düğmelerin değerlerini bildiğinizde, toplamı 0xf3 eden ve uzunluğu 8'den küçük bir kombinasyona **basmanız** gerekiyordu.

**Bu eğitim için referans:** [arşivlenmiş Nostalgia challenge yazısı](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kurslar

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [MBA obfuscation'ını CoBRA ile basitleştirme](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA deposu](https://github.com/trailofbits/CoBRA)
- [3] [Rust string'lerini çözümleme - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing eğitimi (arşivlenmiş)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI Destekli Reverse Engineering'i Engellemek ya da En Azından Denemek](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Temel Blok Eşleştirmeye Dayalı Kontrol Akış Grafiği Karşılaştırma Yaklaşımı](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mekanizması](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Golang ikili dosyalarını otomatik olarak deobfuscate etmek için kontrol akış grafiği benzerliğini kullanma](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
