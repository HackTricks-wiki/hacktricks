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

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek, **kütüphaneler** (.dll), **Windows metadata dosyaları** (.winmd) ve **çalıştırılabilir dosyalar** (.exe) dâhil olmak üzere birden fazla biçimi **decompile edip inceleyen** bir decompiler'dır. Decompile edildikten sonra bir assembly, Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantaj, kaybolmuş kaynak kodunun eski bir assembly'den geri yüklenmesi gerektiğinde bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilmiş kodda kolay gezinme olanağı sunarak **Xamarin algoritma analizi** için ideal araçlardan biri olmasını sağlar.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in modeli ve aracı tam ihtiyaçlarınıza uyarlayan bir API ile .NET Reflector zaman kazandırır ve geliştirme sürecini kolaylaştırır. Bu aracın sunduğu çok sayıda reverse engineering hizmetine göz atalım:

- Verilerin bir kütüphane veya bileşen içinde nasıl aktığına dair fikir verir
- .NET dilleri ve framework'lerinin uygulanışı ve kullanımı hakkında fikir verir
- Kullanılan API ve teknolojilerden daha fazla yararlanmak için belgelenmemiş ve dışarı açılmamış işlevleri bulur.
- Bağımlılıkları ve farklı assembly'leri bulur
- Kodunuzdaki, üçüncü taraf bileşenlerdeki ve kütüphanelerdeki hataların tam konumunu belirler.
- Üzerinde çalıştığınız tüm .NET kodlarının kaynağında debug yapar.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy plugin'i](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir işletim sisteminde kullanabilirsiniz (VSCode içinden doğrudan yükleyebilirsiniz; git'i indirmeniz gerekmez. **Extensions**'a tıklayıp **ILSpy**'ı arayın).\
**Decompile** etmek, **değişiklik yapmak** ve yeniden **compile** etmek istiyorsanız [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ya da aktif olarak sürdürülen fork'u [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir fonksiyonun içindeki bir şeyi değiştirmek için **Right Click -> Modify Method**).

### DNSpy Logging

**DNSpy'nin bazı bilgileri bir dosyaya loglamasını** sağlamak için şu snippet'i kullanabilirsiniz:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy ile Hata Ayıklama

DNSpy kullanarak kodda hata ayıklamak için şunları yapmanız gerekir:

İlk olarak, **hata ayıklamayla** ilgili **Assembly özniteliklerini** değiştirin:

![DNSpy Logging - DNSpy ile Hata Ayıklama: İlk olarak, hata ayıklamayla ilgili Assembly özniteliklerini değiştirin](<../../images/image (973).png>)

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

Ve **compile**'a tıklayın:

![DNSpy Logging - DNSpy Debugging: Derle'ye tıklayın](<../../images/image (314) (1).png>)

Ardından yeni dosyayı _**File >> Save module...**_ üzerinden kaydedin:

![DNSpy Logging - DNSpy Debugging: Ardından yeni dosyayı File Save module üzerinden kaydedin](<../../images/image (602).png>)

Bunu yapmak gerekir; aksi takdirde **runtime** sırasında koda çeşitli **optimizasyonlar** uygulanır ve debug ederken bir **breakpoint'e hiç ulaşılamaması** veya bazı **değişkenlerin mevcut olmaması** mümkündür.

Ardından, .NET uygulamanız **IIS** tarafından **çalıştırılıyorsa**, uygulamayı şu komutla **yeniden başlatabilirsiniz**:

```
iisreset /noforce
```

Then, hata ayıklamaya başlamak için açılmış tüm dosyaları kapatın ve **Debug Tab** içinden **Attach to Process...** seçeneğini belirleyin:

![DNSpy Logging - DNSpy Debugging: Hata ayıklamaya başlamak için açılmış tüm dosyaları kapatın ve Debug Tab içinden Attach to Process seçeneğini belirleyin](<../../images/image (318).png>)

**IIS server**'a bağlanmak için **w3wp.exe**'yi seçin ve **attach**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: IIS server'a bağlanmak için w3wp.exe'yi seçin ve attach'e tıklayın](<../../images/image (113).png>)

Artık süreci debug ettiğimize göre, durdurup tüm modülleri yükleyelim. Önce _Debug >> Break All_ seçeneğine, ardından _**Debug >> Windows >> Modules**_ seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Süreci debug ettiğimize göre durdurup tüm modülleri yükleyelim. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Süreci debug ettiğimize göre durdurup tüm modülleri yükleyelim. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (834).png>)

**Modules** içindeki herhangi bir modüle tıklayın ve **Open All Modules** seçeneğini belirleyin:

![DNSpy Logging - DNSpy Debugging: Modules içindeki herhangi bir modüle tıklayın ve Open All Modules seçeneğini belirleyin](<../../images/image (922).png>)

**Assembly Explorer** içindeki herhangi bir modüle sağ tıklayın ve **Sort Assemblies** seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer içindeki herhangi bir modüle sağ tıklayın ve Sort Assemblies seçeneğine tıklayın](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'lerde hata ayıklama

### IDA kullanarak

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe, 32 bit sürümü ise C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Windbg** debugger'ını seçin
- "**Suspend on library load/unload**" seçeneğini belirleyin

![Debugging DLLs - Using IDA: "Suspend on library load/unload" seçeneğini belirleyin](<../../images/image (868).png>)

- Yürütmenin **parametrelerini**, **DLL'nin yolunu** ve çağırmak istediğiniz işlevi girerek yapılandırın:

![Debugging DLLs - Using IDA: DLL'nin yolunu ve çağırmak istediğiniz işlevi girerek yürütme parametrelerini yapılandırın](<../../images/image (704).png>)

Ardından, debug etmeye başladığınızda **her DLL yüklendiğinde yürütme durdurulur**. Yani rundll32 DLL'nizi yüklediğinde yürütme durdurulur.

Bu yöntem, modül yükleme olaylarında durur; ancak yüklenen DLL'nin giriş noktasına ulaşmak aşağıdaki x64dbg iş akışına kıyasla daha dolaylıdır.

### x64dbg/x32dbg kullanarak

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe, 32 bit sürümü ise C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Command Line'ı değiştirin** ( _File --> Change Command Line_ ) ve dll'nin yolunu ve çağırmak istediğiniz işlevi girin. Örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ bölümünden "**DLL Entry**" seçeneğini belirleyin.
- Ardından **yürütmeyi başlatın**. Debugger her dll main'de durur; bir noktada **dll'nizin Entry noktasında durur**. Buradan, breakpoint koymak istediğiniz noktaları arayın.

win64dbg'de yürütme herhangi bir nedenle durduğunda, **win64dbg penceresinin üst kısmına** bakarak **hangi kodda olduğunuzu** görebileceğinizi unutmayın:

![Using IDA - Using x64dbg/x32dbg: Yürütme win64dbg'de herhangi bir nedenle durduğunda, win64dbg penceresinin üst kısmına bakarak hangi kodda olduğunuzu görebilirsiniz](<../../images/image (842).png>)

Bu gösterge, yürütmenin debug etmek istediğiniz DLL içinde durduğunu doğrular.

## GUI uygulamaları / video oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bunları değiştirmek için kullanışlı bir programdır. Daha fazla bilgi:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), oyunlara odaklanan, GNU Project Debugger (GDB) için bir front-end/reverse engineering aracıdır. Ancak reverse engineering ile ilgili her türlü işte kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/), çeşitli decompiler'lara web üzerinden erişim sağlayan bir front-end'dir. Bu web hizmeti, küçük yürütülebilir dosyalarda farklı decompiler'ların çıktısını karşılaştırmanızı sağlar.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner ile shellcode debug etme

[**BlobRunner**](https://github.com/OALabs/BlobRunner), **shellcode** için bellek ayırır, **bellek adresini** yazdırır ve yürütmeyi duraklatır.\
IDA veya x64dbg gibi bir debugger bağlayın, yazdırılan adrese breakpoint koyun ve shellcode'u debug etmek için yürütmeyi sürdürün.

GitHub releases sayfasında derlenmiş sürümlerin zip dosyaları bulunur: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Aşağıdaki bağlantıda Blobrunner'ın biraz değiştirilmiş bir sürümünü bulabilirsiniz. Derlemek için **Visual Studio Code'da bir C/C++ projesi oluşturun, kodu kopyalayıp yapıştırın ve build edin**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile shellcode debug etme

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner'a benzer. Shellcode için bellek ayırır ve sonsuz bir döngüye girer. Debugger'ı bağlayın, **2–5 saniye** boyunca yürütmeyi sürdürün, o döngünün içinde duraklatın ve ayrılan shellcode'a yürütme aktarımı yapan sonraki çağrıya ilerleyin.

![jmp2it'in sonsuz döngüsünde, ayrılan shellcode'a yapılan çağrının hemen öncesinde duraklatılmış debugger](<../../images/image (509).png>)

Derlenmiş bir [jmp2it sürümünü releases sayfasından](https://github.com/adamkramer/jmp2it/releases/) indirebilirsiniz.

### Cutter kullanarak shellcode debug etme

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'ın GUI'sidir. Cutter ile shellcode'u emulate edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Open File" ve "Open Shellcode" seçenekleri sunduğunu unutmayın. Benim durumumda shellcode'u dosya olarak açtığımda doğru şekilde decompile etti, ancak shellcode olarak açtığımda etmedi:

![Cutter, aynı baytları dosya veya shellcode olarak açarken farklı analiz sonuçları gösteriyor](<../../images/image (562).png>)

Emülasyonu istediğiniz yerde başlatmak için oraya bir bp koyun; görünüşe göre Cutter emülasyonu otomatik olarak o noktadan başlatıyor:

![Cutter emülasyonunu başlatmadan önce istenen shellcode giriş noktasına breakpoint koyma](<../../images/image (589).png>)

![Cutter emulator, seçilen shellcode breakpoint'inde duraklatılmış](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görebilirsiniz:

![Cutter'ın hex dump'inde emulate edilen shellcode stack'ini görüntüleme](<../../images/image (186).png>)

### Shellcode'u deobfuscate etme ve yürütülen işlevleri bulma

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) aracını deneyin.\
Shellcode'un hangi **işlevleri** kullandığı ve bellekte kendini **decode** edip etmediği gibi bilgileri gösterir.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg ayrıca istediğiniz seçenekleri seçip shellcode'u çalıştırabileceğiniz grafiksel bir başlatıcı da içerir

![Shellcode emülasyonu ve tracing seçeneklerini seçmek için scDbg grafiksel başlatıcısı](<../../images/image (258).png>)

**Create Dump** seçeneği, shellcode bellekte dinamik olarak değiştirilmişse son halini dump eder (decoded shellcode'u indirmek için kullanışlıdır). **start offset**, shellcode'u belirli bir offset'te başlatmak için kullanışlı olabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'da debug yapmaya yarar (ancak bu amaçla daha önce açıklanan seçeneklerden herhangi birini daha iyi buluyorum; çünkü Ida veya x64dbg kullanabilirsiniz).

### CyberChef Kullanarak Disassemble Etme

Shellcode dosyanızı girdi olarak yükleyin ve decompile etmek için şu recipe'yi kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` gibi basit ifadeleri aritmetik (`+`, `-`, `*`) ve bit düzeyinde operatörleri (`&`, `|`, `^`, `~`, kaydırmalar) birleştiren formüllerin arkasına gizler. Önemli olan, bu özdeşliklerin genellikle yalnızca **sabit genişlikli modüler aritmetik** altında doğru olmasıdır; bu nedenle elde taşımalar ve taşmalar önemlidir:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Bu tür bir ifadeyi genel amaçlı cebir araçlarıyla sadeleştirirseniz, bit genişliği semantiği göz ardı edildiği için kolayca yanlış bir sonuç elde edebilirsiniz.<sup>[[1]](#references)</sup>

### Uygulamalı iş akışı

1. **Orijinal bit genişliğini koruyun**: lift edilmiş kod/IR/decompiler çıktısındaki (`8/16/32/64` bit) değeri kullanın.
2. Sadeleştirmeye çalışmadan önce **ifadeyi sınıflandırın**:
   - **Doğrusal**: bit düzeyindeki atomların ağırlıklı toplamları
   - **Yarı doğrusal**: `x & 0xFF` gibi sabit maskeler içeren doğrusal ifadeler
   - **Polinomsal**: çarpımlar bulunur
   - **Karma**: çarpımlar ve bit düzeyinde mantık iç içe geçmiştir; genellikle yinelenen alt ifadeler içerir
3. Aday her yeniden yazımı rastgele testlerle veya bir SMT ispatıyla doğrulayın. Eşdeğerlik ispatlanamıyorsa tahminde bulunmak yerine orijinal ifadeyi koruyun.

### Dar bir yürütme dilimiyle düzleştirilmiş kontrol akışını atlatma

Kontrol akış grafiğinin tamamını çıkarmak çoğu zaman gereksizdir. Control-flow flattening, opaque predicate'ler, büyük dispatcher'lar veya MBA ağırlıklı kod durumlarında, şifrelenmiş blob'lardan ve çıktı buffer'larından bunları dönüştüren en küçük rutine kadar referansları izleyin. Ardından yalnızca bu data-flow dilimini yeniden oluşturun veya bağımsız olarak çalıştırın; ilgili state doğrudan başlatılabiliyorsa dispatcher gerekli çözümün parçası değildir.<sup>[[7]](#references)</sup>

Uygulamalı bir iş akışı:<sup>[[7]](#references)</sup>

1. Yürütülebilir ve veri bölümlerini, relocation'ları ve çapraz referansları envanterleyin. Bayt sıralamasını ve öğe genişliğini koruyarak `.rodata` içindeki aday tabloları dökün.
2. Plaintext'i veya çıktı buffer'ını yazan son rutini belirleyin. Girdilerini, başvurduğu tabloları, import edilmiş çağrıları ve gereken global state'i kaydedin.
3. Yalnızca bu işlemleri sabit genişlikli bir Python modeline lift edin. Dilim hâlâ çok fazla state'e bağlıysa, tüm programı emüle etmek yerine rutini Unicorn, QEMU veya bir debugger altında çağırın ve ilgisiz import'ları hook'layın.
4. Extractor'ın çıktısını gerçekten sağlanan binary'den türettiğini doğrulayın: sessiz fallback'leri kaldırın, gömülü yanıtları bulmak için binary'yi tarayın ve değişen string'ler, key'ler, identifier'lar, layout'lar ve obfuscation seed'leri içeren görülmemiş build'lerde çalıştırın.

İlk aşamada kullanılabilecek komutlar:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Sabit kılığına girmiş MBA ifadelerini tespit et

Görünüşte girdiye bağlı olan bir bayt ifadesi, girdisini tamamen yok edebilir. Tablolarını çıkardıktan sonra ifadeyi 8 bitlik tam tanım kümesinde değerlendir; çıktı kümesinin tek elemanlı olması, çevresindeki durum makinesini çözmeden bu baytın sabit olduğunu kanıtlar.<sup>[[7]](#references)</sup>

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

Son maskeyi koruyun; çünkü özgün toplama işleminde bayt genişliğinde taşma vardır. Daha geniş bir etki alanı için, aynı genişlikteki iki sembolik girdi için bir SMT solver'a `f(x1) != f(x2)` ifadesinin sağlanabilir olup olmadığını sorun: `unsat` değişmezliği kanıtlar; `sat` ise bir karşı örnek sunar ve girdinin atılamayacağı anlamına gelir.<sup>[[7]](#references)</sup>

#### Ortama bağlı çözümlemeyi tanıyın

Anti-analysis kontrollerinin dallanması veya çökmesi gerekmez. Bir decoder, sensör sonucunu bir anahtar bitine, bir opaque-predicate sabitine veya flattened-dispatcher durumuna karıştırabilir, normal şekilde çalışmaya devam edebilir ve bir emulator'da makul görünen ancak yanlış olan düz metin üretebilir. Bu nedenle, yalnızca görünür hata dallarını yamamak yeterli değildir; ortam yoklamalarından decoder durumuna kadar veri bağımlılıklarını izleyin, aynı dilimi gerçek cihazda ve emulator'da karşılaştırın ve her sensör sonucunu zorlamanın son buffer'ı nasıl değiştirdiğini test edin.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA), malware analizi ve korumalı binary'leri tersine mühendislikle incelemek için pratik bir MBA sadeleştiricisidir. İfadeyi sınıflandırır ve her şeye tek bir genel yeniden yazma geçişi uygulamak yerine, onu özel işlem hatlarına yönlendirir.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA, ifadeyi Boolean girdiler üzerinde değerlendirir, bir imza çıkarır ve pattern matching, ANF conversion ve coefficient interpolation gibi çeşitli kurtarma yöntemlerini paralel olarak yarıştırır.
- **Semilinear MBA**: Sabit maskeli atomlar, maskelenmiş bölgelerin doğruluğunu koruyacak şekilde bit-partitioned reconstruction ile yeniden oluşturulur.
- **Polynomial/Mixed MBA**: Çarpımlar bileşenlerine ayrılır ve dış ilişki sadeleştirilmeden önce tekrarlanan alt ifadeler geçici değişkenlere taşınabilir.

Sıklıkla kurtarılmaya değer olan karma bir özdeşlik örneği:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Bu, şu şekilde sadeleştirilebilir:

```c
x * y
```

### Tersine mühendislik notları

- CoBRA'yı, tam hesaplamayı izole ettikten sonra **lifted IR ifadeleri** veya decompiler çıktısı üzerinde çalıştırmayı tercih edin.
- İfade maskelenmiş aritmetikten veya dar register'lardan kaynaklanıyorsa açıkça `--bitwidth` kullanın.
- Daha güçlü bir kanıtlama adımına ihtiyacınız varsa buradaki yerel Z3 notlarına bakın:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca **LLVM pass plugin** (`libCobraPass.so`) olarak da sunulur; bu, sonraki analiz pass'lerinden önce MBA ağırlıklı LLVM IR'yi normalize etmek istediğinizde kullanışlıdır.
- Desteklenmeyen, taşıma duyarlı karma alan kalıntıları; özgün ifadeyi koruyup taşıma yolunu elle incelemeniz gerektiğini gösterir.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, program işlemlerini `mov` tabanlı komut dizileriyle değiştirir ve kontrol akışını değiştirmek için sinyal/istisna işlemeyi kullanır. Ayrıntılar için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Desteklenen binary'ler için [demovfuscator](https://github.com/kirschju/demovfuscator), sonucu deobfuscate edebilir. Birkaç bağımlılığı vardır.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Ve [keystone'u yükleyin](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTF oynuyorsanız, flag'i bulmak için bu geçici çözüm** çok işinize yarayabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**Giriş noktasını** bulmak için, aşağıdaki örnekte olduğu gibi fonksiyon adlarında `::main` arayın:

![Ghidra'da fonksiyon adlarında çift iki nokta ve main arayarak bir Rust giriş noktasını bulma](<../../images/image (1080).png>)

Bu örnekte binary'nin adı authenticator olduğundan, ilginç olan main fonksiyonunu bulmak oldukça kolay.\
Çağrılan **fonksiyonların** **adlarını** öğrendikten sonra, **girdileri** ve **çıktıları** hakkında bilgi edinmek için bunları **Internet'te** arayın.

### ELF firmware'inden Rust string'lerini kurtarma

**Rust ELF** binary'lerinde, birçok statik string'e C tarzı NUL ile sonlandırılmış pointer'lar üzerinden başvurulmaz. Yaygın bir `rustc` düzeninde, **`.data.rel.ro`** içindeki bir **pointer/length tuple**, **`.rodata`** içinde saklanan asıl string blob'una işaret eder:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Bu, `strings` veya varsayılan Ghidra analizinin bitişik dizeleri birleştirebileceği ya da çapraz başvuruları tamamen gözden kaçırabileceği anlamına gelir.<sup>[[3]](#references)</sup>

Hızlı iş akışı:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** bölümünün sanal adresini ve boyutunu alın.
2. **`.data.rel.ro`** bölümünü her seferinde bir word olacak şekilde listeleyin.
3. `.rodata` adres aralığındaki her değeri olası bir string pointer olarak değerlendirin.
4. Sonraki word'ü olası uzunluk olarak değerlendirin.
5. Mantıklılık filtreleri uygulayın (örneğin, uzunluğu **4** ile **100** bayt arasında olanları tutun).
6. `0x00` değerine kadar taramak yerine `.rodata` bölümünden tam olarak `length` bayt okuyun.

Minimum extractor mantığı:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Bu, firmware reversing sırasında özellikle kullanışlıdır; çünkü kurtarılan Rust string'leri genellikle **HTTP rotalarını, RPC adlarını, log mesajlarını, assertion'ları, dosya adlarını, config anahtarlarını, komut işleyicilerini ve auth ile ilgili mantığı** ortaya çıkarır.

Ghidra bu string'leri bulamazsa, aynı sezgisel yöntemi uygulayan ve başvurulan `.rodata` offset'lerinde string verileri oluşturan özel bir script/plugin çalıştırın. Pen Test Partners'ın yayımladığı `rust-strings` ve `RustStrings.py` araçları, bu fikri diğer **word size'lara, endianness türlerine ve section düzenlerine** uyarlamak için iyi referanslardır.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi ile derlenmiş binary'ler için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Bir Delphi binary'sini reverse etmeniz gerekiyorsa, IDA plugin'i [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

Bir Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın ve ardından plugin dosyasını seçin.

Bu plugin, binary'yi çalıştırır ve debugging başladığında fonksiyon adlarını dinamik olarak çözümler. Debugging'i başlattıktan sonra Start düğmesine (yeşil olana veya f9'a) tekrar basın; gerçek kodun başlangıcında bir breakpoint'e ulaşılır.

Grafik uygulamasında bir düğmeye basarsanız, debugger bu düğmenin çağırdığı fonksiyonda durabilir.

## Golang

Standart Go binary'leri için [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper), runtime yapılarını kurtarabilir ve IDA'daki fonksiyon adlarını iyileştirebilir. Python plugin'ini yüklemek için **Alt+F7** tuşlarına basın.

### Sembol tablosu olmadan metadata'yı kurtarma

Stripped bir Go executable'ı, program counter'ları fonksiyonlarla eşleştirmek için yine de runtime metadata'sına ihtiyaç duyar. [GoReSym](https://github.com/mandiant/GoReSym), Go runtime'ından türetilen kodu kullanarak `pclntab` ve `moduledata` gibi yapıları bulup ayrıştırır. Geleneksel sembol tablosuna bağlı kalmadan fonksiyon sınırlarını, adları, kaynak yollarını, türleri ve build ayrıntılarını kurtarabilir.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Bir obfuscator, kurtarılan adları değiştirirken bu yapıları kullanılabilir durumda bırakabilir. Örneğin Garble, tanımlayıcıları ve paket yollarını hash'ler; build, module ve debug bilgilerini kaldırır.<sup>[[12]](#references)</sup> Obfuscate edilmiş paket token'ı, o paketteki işlevler arasında tutarlı kalmalıdır. İşlevleri tekrar eden token'a göre gruplayın, çağıran işlevlerinden, string'lerden ve API'lerden bir paketi çıkarın, ardından bu paket etiketini grubun tamamına uygulayın.<sup>[[13]](#references)</sup>

### GoResolver ile Garble adlarını kurtarma

[GoResolver](https://github.com/volexity/GoResolver), runtime sembolü çıkarmayı temiz referans oluşturma ve control-flow graph (CFG) eşleştirmeyle birleştirir. Şu adımları izleyin:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler sürümünü belirleyin.** Önce `BuildInfo` ve gömülü sürüm string'lerini kontrol edin. Obfuscator bunları kaldırdıysa, paketlenmiş Go runtime'ın bazı bölümlerini sürümlenmiş referans runtime'larla karşılaştırın. Volexity testlerinde runtime'ın yaklaşık `2%`'si, ana Go sürümlerini ayırt etmek için yeterliydi. Bunu evrensel bir eşik değil, deneysel bir optimizasyon olarak değerlendirin.<sup>[[13]](#references)</sup>
2. **Eşleşen referanslar oluşturun.** Belirlenen Go sürümü, hedef mimari ve olası kütüphaneler için temiz binary'ler oluşturun. Toolchain eşleşmesi, compiler tarafından oluşturulan CFG farklılıklarını azaltır.<sup>[[10]](#references)[[13]](#references)</sup>
3. **İşlevleri karşılaştırın.** GoGrapher, işlev CFG'lerini eşleştirir ve `0.0` ile `1.0` arasında normalize edilmiş skorlar üretir. Basic block eşleştirmesi, benzer instruction'ların ağırlıklı karşılaştırmasına dayanır. Yüksek güvenilirlikli eşleşmeler, rastgeleleştirilmiş işlevleri temiz uygulamayla eşleştirir. Daha zayıf eşleşmeler bile bir paketi veya modülü belirleyebilir.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Doğrulayın ve içe aktarın.** Önerilen adları çağrı ilişkileri, sabitler, string'ler ve yan etkilerle doğrulayın, ardından JSON raporunu IDA veya Ghidra için GoResolver plugin'iyle içe aktarın.<sup>[[10]](#references)[[13]](#references)</sup>

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

Varsayılan significant-match eşiği `0.9` değeridir. `--extract` ve `--graph` seçenekleri aşamalardan birini ayrı ayrı çalıştırabilir; varsayılan olarak ikisi de çalıştırılır, çünkü elde edilen runtime metadata ve CFG kanıtları birbirini tamamlar.<sup>[[10]](#references)</sup> CFG skorları sezgiseldir: inlining, build flags, mimari ve library-version farklılıkları graph şeklini değiştirebilir. Bu nedenle düşük güvenli adları zorla atamak yerine çözümlenmemiş işlevleri koruyun.<sup>[[13]](#references)</sup>

## Derlenmiş Python

Bu sayfada, ELF/EXE biçiminde derlenmiş bir Python binary dosyasından Python kodunu nasıl elde edebileceğinizi bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Bir GBA oyununun **binary** dosyasını elde ederseniz, oyunu **emüle etmek** ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Debug sürümünü indirin_) - Arayüzlü bir debugger içerir
- [**mgba** ](https://mgba.io)- Bir CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin'i
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin'i

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünde Game Boy Advance **düğmelerine** nasıl basılacağını görebilirsiniz.

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Basılınca, her **tuşun onu tanımlayan bir değeri** olur:

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

Bu tür programlarda ilgi çekici olan kısım **programın kullanıcı girdisini nasıl işlediğidir**. **0x4000130** adresinde sıkça karşılaşılan **KEYINPUT** fonksiyonunu bulabilirsiniz.

![0x4000130 adresinde KEYINPUT'e başvuran bir GBA binary dosyasının Ghidra görünümü](<../../images/image (447).png>)

Önceki görselde, fonksiyonun **FUN_080015a8**'den çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

Bu fonksiyonda, bazı önemsiz init işlemlerinden sonra:

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

Şu kodu buldu:

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

Son if, **`uVar4`**'ün **son Keys** içinde olup olmadığını ve mevcut key olmadığını kontrol ediyor; bu, bir tuşu bırakmak olarak da adlandırılır (mevcut key **`uVar1`** içinde saklanır).

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

- Önce **4 değeriyle** (**SELECT** düğmesi) karşılaştırılır: Challenge'da bu düğme ekranı temizler.
- Ardından değer **8** (**START** düğmesi) ile karşılaştırılır; bu challenge'da bu yol, girilen kodun geçerli olup olmadığını kontrol eder.
  - Bu durumda **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılır ve değer aynıysa bazı kodlar çalıştırılır.
- Diğer tüm durumlarda bir sayaç (`DAT_030000d4`) kontrol edilir ve artırılır.\
  Sayaç 8'in altındayken basılan tuşların değerleri `DAT_030000d8` içinde biriktirilir.

Dolayısıyla bu challenge'da, düğmelerin değerlerini bilerek, **toplamı 0xf3 olan ve uzunluğu 8'den küçük bir kombinasyona basmanız gerekiyordu.**

**Bu eğitim için referans:** [Nostalgia challenge çözüm yazısının arşivlenmiş sürümü](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRA ile MBA obfuscation'ı basitleştirme](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust string'lerini çözümleme - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing eğitimi (arşivlenmiş)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI destekli Reverse Engineering'i yenmek, ya da en azından denemek](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic Block eşleştirmeye dayalı Control Flow Graph karşılaştırma yaklaşımı](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mekanizması](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Go binary'lerini otomatik olarak deobfuscate etmek için Control-Flow Graph benzerliğinden yararlanma](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
