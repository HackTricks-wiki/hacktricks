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

- wasm'den (binary) wat'e (düz metin) **decompile** etmek için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kullanın
- wat'ten wasm'e **compile** etmek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kullanın
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

dotPeek, **kütüphaneler** (.dll), **Windows metadata dosyaları** (.winmd) ve **çalıştırılabilir dosyalar** (.exe) dahil olmak üzere birden fazla formatı **decompile edip inceleyen** bir decompiler'dır. Decompile edildikten sonra bir assembly, Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantajı, kaybolmuş kaynak kodunun eski bir assembly'den geri yüklenmesi gerektiğinde bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilmiş kodda kullanışlı gezinme özellikleri sunar; bu da onu **Xamarin algoritma analizi** için ideal araçlardan biri yapar.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in modeli ve aracı tam ihtiyaçlarınıza göre uyarlayan bir API ile .NET Reflector zamandan tasarruf sağlar ve geliştirmeyi kolaylaştırır. Bu aracın sunduğu çok sayıda reverse engineering hizmetine göz atalım:

- Bir kütüphane veya bileşen içindeki veri akışını anlamaya yardımcı olur
- .NET dilleri ve framework'lerinin uygulamaları ve kullanımları hakkında bilgi sağlar
- Kullanılan API'lerden ve teknolojilerden daha fazla yararlanmak için belgelenmemiş ve dışarıya açılmamış işlevleri bulur.
- Bağımlılıkları ve farklı assembly'leri bulur
- Kodunuzdaki, üçüncü taraf bileşenlerdeki ve kütüphanelerdeki hataların tam konumunu belirler.
- Çalıştığınız tüm .NET kodlarının kaynağında debugging yapar.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy plugin'i](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir işletim sisteminde kullanabilirsiniz (VSCode'dan doğrudan yükleyebilirsiniz; git'i indirmeniz gerekmez. **Extensions**'a tıklayıp **ILSpy**'ı arayın).\
Tekrar **decompile**, **modify** ve **recompile** etmeniz gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak sürdürülen bir fork'u olan [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir fonksiyonun içindeki bir şeyi değiştirmek için **Right Click -> Modify Method**'a tıklayın).

### REA ile çalıştırma gerektirmeyen managed inspection

**REA**, assembly'yi yüklemeden PE/CLI metadata'sını ve CIL'i inceleyebilir. Önce artifact kimliğini belirleyin, ardından üyeleri ve tanımlı native sınırları inceleyin; bu, decompiler kullanmadan veya programı çalıştırmadan önce şüpheli çağrıları gözden geçirmek için yararlıdır.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Sürümler arasındaki farkları karşılaştırırken `compare_managed_members`, metadata token'larını derlemeler arasında sabit kabul etmek yerine ham CIL/imza kimliğini ve decoded-instruction parmak izlerini kullanır. Bir P/Invoke bildirimi, native kodun çalıştığını kanıtlamaz; bu sınırı denetlemek için `verify_managed_native_boundaries`, eşleşen native export veya function kanıtına ihtiyaç duyar. Artifact digest'i, MVID'yi ve çözümlenmemiş eşlemeleri sonuçla birlikte saklayın.<sup>[[17]](#references)</sup>

### DNSpy Günlük Kaydı

**DNSpy'nin bazı bilgileri bir dosyaya kaydetmesini** sağlamak için şu snippet'i kullanabilirsiniz:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

DNSpy kullanarak kodda debugging yapmak için:

Öncelikle, **debugging** ile ilgili **Assembly attributes** değerlerini değiştirin:

![DNSpy Logging - DNSpy Debugging: Öncelikle, debugging ile ilgili Assembly attributes değerlerini değiştirin](<../../images/image (973).png>)

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

Ardından yeni dosyayı _**File >> Save module...**_ üzerinden kaydedin:

![DNSpy Logging - DNSpy Debugging: Ardından yeni dosyayı File Save module üzerinden kaydedin](<../../images/image (602).png>)

Bunu yapmanız gerekir; aksi takdirde **çalışma zamanında** koda çeşitli **optimizasyonlar** uygulanır ve hata ayıklama sırasında bir **kesme noktasına hiç ulaşılamaması** veya bazı **değişkenlerin mevcut olmaması** mümkündür.

Ardından, .NET uygulamanız **IIS** tarafından **çalıştırılıyorsa** uygulamayı şu komutla **yeniden başlatabilirsiniz**:

```
iisreset /noforce
```

Ardından hata ayıklamayı başlatmak için açtığınız tüm dosyaları kapatın ve **Debug Tab** içinde **Attach to Process...** seçeneğini belirleyin:

![DNSpy Logging - DNSpy Debugging: Ardından hata ayıklamayı başlatmak için açtığınız tüm dosyaları kapatın ve Debug Tab içinden Attach to Process seçeneğini belirleyin](<../../images/image (318).png>)

Ardından **IIS server**'a bağlanmak için **w3wp.exe**'yi seçin ve **attach**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Ardından IIS server'a bağlanmak için w3wp.exe'yi seçin ve attach'e tıklayın](<../../images/image (113).png>)

Süreci hata ayıkladığımıza göre, şimdi durdurup tüm modülleri yüklememiz gerekiyor. Önce _Debug >> Break All_ seçeneğine, ardından _**Debug >> Windows >> Modules**_ seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Süreci hata ayıkladığımıza göre, şimdi durdurup tüm modülleri yüklememiz gerekiyor. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Süreci hata ayıkladığımıza göre, şimdi durdurup tüm modülleri yüklememiz gerekiyor. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (834).png>)

**Modules** içindeki herhangi bir modüle tıklayın ve **Open All Modules** seçeneğini belirleyin:

![DNSpy Logging - DNSpy Debugging: Modules içindeki herhangi bir modüle tıklayın ve Open All Modules seçeneğini belirleyin](<../../images/image (922).png>)

**Assembly Explorer** içindeki herhangi bir modüle sağ tıklayın ve **Sort Assemblies** seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer içindeki herhangi bir modüle sağ tıklayın ve Sort Assemblies seçeneğine tıklayın](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'lerde hata ayıklama

### IDA kullanımı

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe, 32 bit sürümü C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Windbg** debugger'ını seçin
- "**Suspend on library load/unload**" seçeneğini belirleyin

![Debugging DLLs - Using IDA: " Suspend on library load/unload " seçeneğini belirleyin](<../../images/image (868).png>)

- **parameters** bölümünü, **DLL'nin path'ini** ve çağırmak istediğiniz işlevi belirterek yapılandırın:

![Debugging DLLs - Using IDA: DLL'nin path'ini ve çağırmak istediğiniz işlevi belirterek execution parametrelerini yapılandırın](<../../images/image (704).png>)

Ardından hata ayıklamayı başlattığınızda **her DLL yüklendiğinde execution durur**; rundll32 DLL'nizi yüklediğinde de execution duracaktır.

Bu yöntem modül yükleme olaylarında durur, ancak yüklenen DLL'nin entry point'ine ulaşmak aşağıdaki x64dbg iş akışına kıyasla daha dolaylıdır.

### x64dbg/x32dbg kullanımı

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe, 32 bit sürümü C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Command Line'ı değiştirin** ( _File --> Change Command Line_ ) ve DLL'nin path'ini ve çağırmak istediğiniz işlevi girin. Örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ seçeneğini değiştirin ve "**DLL Entry**"yi belirleyin.
- Ardından **execution'ı başlatın**; debugger her DLL main'de duracaktır. Bir noktada **kendi DLL'nizin DLL Entry'sinde duracaksınız**. Buradan, breakpoint koymak istediğiniz noktaları arayın.

Execution herhangi bir nedenle win64dbg'de durduğunda, **win64dbg penceresinin üst kısmına** bakarak **hangi kodda olduğunuzu** görebileceğinizi unutmayın:

![Using IDA - Using x64dbg/x32dbg: Execution win64dbg'de herhangi bir nedenle durduğunda, win64dbg penceresinin üst kısmına bakarak hangi kodda olduğunuzu görebileceğinizi unutmayın](<../../images/image (842).png>)

Bu gösterge, execution'ın hata ayıklamak istediğiniz DLL içinde durduğunu doğrular.

## GUI uygulamaları / video oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bunları değiştirmek için kullanışlı bir programdır. Daha fazla bilgi:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), oyunlara odaklanan GNU Project Debugger (GDB) için bir front-end/reverse engineering aracıdır. Bununla birlikte, reverse engineering ile ilgili her türlü iş için kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/), çeşitli decompiler'lara yönelik web tabanlı bir front-end'dir. Bu web hizmeti, küçük executable dosyaların farklı decompiler'lar tarafından üretilen çıktılarını karşılaştırmanızı sağlar.

## REA ile kanıta dayalı native inceleme

**REA**, Hopper, Ghidra ve IDA analizlerini CLI ve MCP üzerinden sunar. Node.js 22.x (en az 22.19), 24.x (en az 24.11) veya 26+ sürümü ve npm gerektirir. Önce mevcut bir native provider'ı yapılandırın; `rea providers --json` komutunu kontrol edin ve hedefi birden fazla provider destekliyorsa birini açıkça seçin. Aşağıdaki `0x1000` yerine envanterde gözlemlenen bir işlev adını veya adresi kullanın.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Bir feature string veya symbol ile başlayın, references ve callers'ı izleyin, ardından seçilen function dossier'ını ve pseudocode'u `rea decompile` ile inceleyin. REA, bir failure sonrasında sessizce başka bir provider'a geçmek yerine session'ı seçilen provider'a bağlar. Tekrarlanabilir sorgular için `--snapshot PATH` yalnızca eşleşen artifact bytes, provider, settings, operation ve parameters'ı yeniden kullanır; snapshot, kaydedilmiş bir provider database değil, yerel bir cache'dir. Döndürülen Evidence'ı ve açık unknown'ları koruyun; çıkarımla bulunan paths veya decompiler metnini orijinal source olarak değerlendirmeyin.<sup>[[16]](#references)[[18]](#references)</sup>

JavaScript/Electron entry point'lerinden native add-on'lara giden yollar için [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea) sayfasına bakın.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner ile bir shellcode'u debug etme

[**BlobRunner**](https://github.com/OALabs/BlobRunner), **shellcode** için bellek ayırır, **bellek adresini** yazdırır ve yürütmeyi duraklatır.\
IDA veya x64dbg gibi bir debugger bağlayın, yazdırılan adreste bir breakpoint ayarlayın ve shellcode'u debug etmek için yürütmeyi sürdürün.

Releases GitHub sayfasında derlenmiş sürümleri içeren zip dosyaları bulunur: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Aşağıdaki bağlantıda Blobrunner'ın biraz değiştirilmiş bir sürümünü bulabilirsiniz. Derlemek için **Visual Studio Code'da bir C/C++ projesi oluşturup kodu kopyalayıp yapıştırın ve build edin**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile bir shellcode'u debug etme

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner'a benzer. Shellcode için bellek ayırır ve sonsuz bir döngüye girer. Debugger'ı bağlayıp **2–5 saniye** boyunca yürütmeyi sürdürün, o döngünün içinde duraklatın ve yürütmeyi ayrılan shellcode'a aktaran sonraki call'a kadar adım adım ilerleyin.

![jmp2it'in sonsuz döngüsünde, ayrılan shellcode'a yapılan call'un hemen öncesinde duraklatılmış debugger](<../../images/image (509).png>)

[jmp2it'in derlenmiş sürümünü releases sayfasından](https://github.com/adamkramer/jmp2it/releases/) indirebilirsiniz.

### Cutter kullanarak shellcode debug etme

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'ın GUI'sidir. Cutter'ı kullanarak shellcode'u emulate edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Open File" ve "Open Shellcode" seçenekleri sunduğunu unutmayın. Benim durumumda shellcode'u bir file olarak açtığımda doğru şekilde decompile etti, ancak shellcode olarak açtığımda etmedi:

![Aynı byte'lar file veya shellcode olarak açıldığında farklı analiz sonuçları gösteren Cutter](<../../images/image (562).png>)

Emulation'ı istediğiniz konumda başlatmak için orada bir bp ayarlayın; görünen o ki Cutter emulation'ı otomatik olarak o noktadan başlatıyor:

![Cutter emulation'ı başlatmadan önce istenen shellcode giriş noktasında breakpoint ayarlama](<../../images/image (589).png>)

![Seçilen shellcode breakpoint'inde duraklatılmış Cutter emulator'ı](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görebilirsiniz:

![Cutter'ın hex dump'inde emule edilmiş shellcode stack'ini görüntüleme](<../../images/image (186).png>)

### Shellcode'u deobfuscate etme ve yürütülen function'ları bulma

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) aracını deneyebilirsiniz.\
Shellcode'un hangi **function'ları** kullandığını ve bellekte kendisini **decode** edip etmediğini gösterir.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg ayrıca istediğiniz seçenekleri seçip shellcode'u çalıştırabileceğiniz grafiksel bir başlatıcıya da sahiptir

![Shellcode emülasyonu ve tracing seçeneklerini belirlemek için scDbg grafiksel başlatıcısı](<../../images/image (258).png>)

**Create Dump** seçeneği, bellekte shellcode üzerinde dinamik olarak herhangi bir değişiklik yapılırsa son hâlini dump eder (decoded shellcode'u indirmek için kullanışlıdır). **start offset**, shellcode'u belirli bir offset'te başlatmak için kullanışlı olabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'da debug yapmak için kullanışlıdır (ancak bu amaçla, önce açıklanan seçeneklerden herhangi birinin daha iyi olduğunu düşünüyorum; çünkü Ida veya x64dbg kullanabileceksiniz).

### CyberChef kullanarak disassembly

Shellcode dosyanızı girdi olarak yükleyin ve disassemble etmek için aşağıdaki tarifi kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation'ı çözme

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` gibi basit ifadeleri aritmetik (`+`, `-`, `*`) ve bit düzeyinde operatörleri (`&`, `|`, `^`, `~`, shift'ler) bir araya getiren formüllerle gizler. Önemli olan, bu özdeşliklerin genellikle yalnızca **sabit genişlikli modüler aritmetik** altında doğru olmasıdır; bu nedenle carry ve overflow önemlidir:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Bu tür bir ifadeyi genel cebir araçlarıyla sadeleştirirseniz, bit genişliği semantiği göz ardı edildiği için kolayca yanlış bir sonuç elde edebilirsiniz.<sup>[[1]](#references)</sup>

### Pratik iş akışı

1. **Orijinal bit genişliğini** lifted kod/IR/decompiler çıktısından koruyun (`8/16/32/64` bit).
2. Sadeleştirmeye çalışmadan önce **ifadeyi sınıflandırın**:
   - **Doğrusal**: bit düzeyindeki atomların ağırlıklı toplamları
   - **Yarı doğrusal**: `x & 0xFF` gibi sabit maskelerle birlikte doğrusal ifadeler
   - **Polinom**: çarpımlar içerir
   - **Karma**: çarpımlar ve bit düzeyindeki mantık iç içe geçmiştir; genellikle tekrarlanan alt ifadeler bulunur
3. Her olası yeniden yazımı rastgele testlerle veya bir SMT kanıtıyla **doğrulayın**. Eşdeğerlik kanıtlanamıyorsa tahminde bulunmak yerine orijinal ifadeyi koruyun.

### Dar bir yürütme dilimiyle düzleştirilmiş control flow'u atlatma

Tam control-flow graph'ı çıkarmak çoğu zaman gereksizdir. Control-flow flattening, opaque predicate'ler, büyük dispatcher'lar veya MBA ağırlıklı kod söz konusu olduğunda, şifrelenmiş blob'lara ve çıktı buffer'larına yapılan referansları izleyerek bunları dönüştüren en küçük rutini bulun. Ardından yalnızca bu data-flow dilimini yeniden oluşturun veya bağımsız olarak çalıştırın; ilgili state doğrudan başlatılabiliyorsa dispatcher gerekli çözümün parçası değildir.<sup>[[7]](#references)</sup>

Pratik bir iş akışı şöyledir:<sup>[[7]](#references)</sup>

1. Yürütülebilir ve veri bölümlerini, relocation'ları ve cross-reference'ları envanterleyin. Bayt sırasını ve öğe genişliğini koruyarak `.rodata` içindeki olası tabloları dökün.
2. Plaintext'i veya çıktı buffer'ını yazan son rutini belirleyin. Girdilerini, başvurduğu tabloları, içe aktarılan çağrıları ve gereken global state'i kaydedin.
3. Yalnızca bu işlemleri sabit genişlikli bir Python modeline aktarın. Dilim hâlâ çok fazla state'e bağlıysa tüm programı emüle etmek yerine rutini Unicorn, QEMU veya bir debugger altında çalıştırın ve ilgisiz import'ları hook'layın.
4. Extractor'ın çıktısını gerçekten sağlanan binary'den türettiğini doğrulayın: sessiz fallback'leri kaldırın, gömülü yanıtları arayın ve değişmiş string'ler, anahtarlar, tanımlayıcılar, düzenler ve obfuscation seed'leri içeren daha önce görülmemiş build'lerde çalıştırın.

İlk aşamada kullanışlı komutlar:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Sabit gibi gizlenmiş MBA ifadelerini tespit etme

Görünüşte girdiye bağlı olan bir bayt ifadesi, girdisini tamamen iptal edebilir. Tablolarını çıkardıktan sonra ifadeyi 8 bitlik tam tanım kümesinde değerlendirin; tek elemanlı bir çıktı kümesi, çevresindeki durum makinesini çözmeden bu baytın sabit olduğunu kanıtlar.<sup>[[7]](#references)</sup>

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

Son maskeyi koruyun; çünkü özgün toplama byte genişliğinde sarma davranışına sahiptir. Daha geniş bir alanda, aynı genişlikte iki sembolik girdi için `f(x1) != f(x2)` ifadesinin sağlanabilir olup olmadığını bir SMT solver'a sorun: `unsat` değişmezliği kanıtlar; `sat` ise bir karşı örnek verir ve girdinin elenemeyeceği anlamına gelir.<sup>[[7]](#references)</sup>

#### Ortama bağlı çözümlemeyi tanıma

Anti-analysis kontrollerinin dallanma veya çökme oluşturması gerekmez. Bir decoder, sensör sonucunu bir anahtar bitine, opaque-predicate sabitine veya flattened-dispatcher durumuna karıştırabilir; normal biçimde çalışmayı sürdürürken emulator'da makul görünen ancak yanlış plaintext üretebilir. Bu nedenle yalnızca görünür hata dallarını patch'lemek yeterli değildir; ortam sorgularından decoder durumuna uzanan veri bağımlılıklarını izleyin, aynı kod parçasını gerçek cihazda ve emulator'da karşılaştırın ve her sensör sonucunu zorlamanın son buffer'ı nasıl değiştirdiğini test edin.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA), malware analizi ve korumalı ikili dosyaların tersine mühendisliği için kullanışlı bir MBA sadeleştiricisidir. İfadeyi sınıflandırır ve her şeye tek bir genel yeniden yazma geçişi uygulamak yerine, ifadeyi özel işlem hatlarına yönlendirir.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA, ifadeyi Boolean girdiler üzerinde değerlendirir, bir imza çıkarır ve pattern matching, ANF dönüşümü ve katsayı interpolasyonu gibi çeşitli çözümleme yöntemlerini paralel olarak dener.
- **Semilinear MBA**: Sabit maskeli atomlar, maskelenmiş bölgelerin doğru kalmasını sağlayan bit bölümlü yeniden yapılandırmayla oluşturulur.
- **Polynomial/Mixed MBA**: Çarpımlar çekirdeklerine ayrılır ve dış ilişki basitleştirilmeden önce yinelenen alt ifadeler geçici değişkenlere alınabilir.

Sıklıkla kurtarılmaya çalışılması faydalı olan karma bir özdeşlik örneği:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Bu, şu hâle indirgenebilir:

```c
x * y
```

### Tersine mühendislik notları

- CoBRA'yı **lifted IR ifadeleri** üzerinde veya tam hesaplamayı izole ettikten sonra decompiler çıktısında çalıştırmayı tercih edin.
- İfade maskelenmiş aritmetikten veya dar register'lardan kaynaklanıyorsa `--bitwidth` değerini açıkça belirtin.
- Daha güçlü bir kanıt adımına ihtiyacınız varsa buradaki yerel Z3 notlarına göz atın:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca bir **LLVM pass plugin** (`libCobraPass.so`) olarak da gelir. Bu, sonraki analiz pass'lerinden önce MBA ağırlıklı LLVM IR'yi normalize etmek istediğinizde kullanışlıdır.
- Desteklenmeyen, carry'ye duyarlı karma alan artıklarını özgün ifadeyi koruyup carry yolunu elle incelemeniz gerektiğinin bir işareti olarak değerlendirin.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, program işlemlerini `mov` tabanlı komut dizileriyle değiştirir ve kontrol akışını değiştirmek için signal/exception handling kullanır. Ayrıntılar için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Desteklenen binary'lerde [demovfuscator](https://github.com/kirschju/demovfuscator) sonucu deobfuscate edebilir. Birkaç bağımlılığı vardır.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Ve [keystone’u kurun](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTF oynuyorsanız, flag’i bulmak için bu geçici çözüm** çok işinize yarayabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**Giriş noktasını** bulmak için, aşağıdaki örnekte olduğu gibi fonksiyonları `::main` ifadesini aratarak bulun:

![Ghidra’da fonksiyon adlarında çift iki nokta ve main aratarak Rust giriş noktasını bulma](<../../images/image (1080).png>)

Bu durumda binary’nin adı authenticator’dı; dolayısıyla bunun ilgi çekici main fonksiyonu olduğu oldukça açık.\
Çağrılan **fonksiyonların adlarını** öğrendikten sonra, **girdileri** ve **çıktıları** hakkında bilgi edinmek için bunları **Internet’te** arayın.

### ELF firmware’den Rust string’lerini kurtarma

**Rust ELF** binary’lerinde birçok statik string, C tarzı NUL ile sonlandırılmış pointer’lar tarafından referans gösterilmez. Yaygın bir `rustc` düzeninde, **`.data.rel.ro`** içinde **pointer/uzunluk ikilisi** bulunur ve bu ikili, **`.rodata`** içinde saklanan gerçek string blob’una işaret eder:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Bu, `strings` veya Ghidra'nın varsayılan analizinin bitişik dizeleri birleştirebileceği ya da çapraz referansları tamamen gözden kaçırabileceği anlamına gelir.<sup>[[3]](#references)</sup>

Hızlı iş akışı:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`**’nın sanal adresini ve boyutunu alın.
2. **`.data.rel.ro`** bölümünü her seferinde bir kelime olacak şekilde sıralayın.
3. `.rodata` adres aralığındaki her değeri olası bir string pointer’ı olarak değerlendirin.
4. Sonraki kelimeyi olası uzunluk olarak değerlendirin.
5. Sağlamlık filtreleri uygulayın (örneğin, uzunluğu **4** ile **100** byte arasında tutun).
6. `0x00` bulana kadar taramak yerine `.rodata`’dan tam olarak `length` byte okuyun.

Minimal çıkarıcı mantığı:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Bu, özellikle firmware reversing sırasında oldukça kullanışlıdır; çünkü kurtarılan Rust string'leri genellikle **HTTP route'larını, RPC adlarını, log mesajlarını, assertion'ları, dosya adlarını, config anahtarlarını, command handler'larını ve auth ile ilgili mantığı** ortaya çıkarır.

Ghidra bu string'leri bulamazsa aynı sezgisel yöntemi uygulayan ve başvurulan `.rodata` offset'lerinde string verileri oluşturan özel bir script/plugin çalıştırın. Pen Test Partners'ın yayımladığı `rust-strings` ve `RustStrings.py` araçları, bu fikri diğer **kelime boyutlarına, endianness değerlerine ve section yerleşimlerine** uyarlamak için iyi referanslardır.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi ile derlenmiş binary'ler için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Bir Delphi binary'sini reverse etmeniz gerekiyorsa IDA plugin'i [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

Bir Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu plugin, binary'yi çalıştırır ve debugging başladığında function adlarını dinamik olarak çözümler. Debugging'i başlattıktan sonra Start düğmesine (yeşil olan veya f9) tekrar basın; gerçek kodun başlangıcında bir breakpoint tetiklenir.

Grafik uygulamasında bir düğmeye basarsanız debugger, o düğmenin çağırdığı function'da durabilir.

## Golang

Sıradan Go binary'leri için [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper), runtime yapılarını kurtarabilir ve IDA'daki function adlarını iyileştirebilir. Python plugin'ini **Alt+F7** tuşlarıyla yükleyin.

Bir Golang binary'sini reverse etmeniz gerekiyorsa IDA plugin'i [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm.

Bir Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu, function adlarını çözümler.

### Symbol table olmadan metadata'yı kurtarma

Stripped bir Go executable'ı, program counter'ları function'lara eşlemek için yine de runtime metadata'sına ihtiyaç duyar. [GoReSym](https://github.com/mandiant/GoReSym), Go runtime'ından türetilen kodu kullanarak `pclntab` ve `moduledata` gibi yapıları bulur ve ayrıştırır. Böylece geleneksel symbol table'a bağlı kalmadan function sınırları, adları, kaynak yolları, type'lar ve build ayrıntıları kurtarılabilir.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Bir obfuscator, kurtarılan adları değiştirirken bu yapıların kullanılabilir kalmasını sağlayabilir. Örneğin Garble, identifier'ları ve package path'lerini hash'ler; build, module ve debug bilgilerini kaldırır.<sup>[[12]](#references)</sup> Obfuscated package token'ı, o package'teki tüm function'larda aynı kalmalıdır. Function'ları tekrarlanan token'a göre gruplandırın, callees, string'ler ve API'lerden yola çıkarak bir package çıkarımı yapın, ardından bu package etiketini grubun tamamına uygulayın.<sup>[[13]](#references)</sup>

### GoResolver ile Garble adlarını kurtarma

[GoResolver](https://github.com/volexity/GoResolver), runtime sembolü çıkarımını temiz referans oluşturma ve control-flow graph (CFG) eşleştirmesiyle birleştirir. Şu sırayı izleyin:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler sürümünü belirleyin.** Önce `BuildInfo` ve gömülü sürüm string'lerini deneyin. Obfuscator bunları kaldırdıysa, bundled Go runtime'ın bazı bölümlerini sürümlenmiş referans runtime'larla karşılaştırın. Volexity'nin testlerinde, Go'nun major sürümlerini ayırt etmek için runtime'ın yaklaşık `2%`'si yeterliydi. Bunu evrensel bir eşik değil, deneysel bir optimizasyon olarak değerlendirin.<sup>[[13]](#references)</sup>
2. **Eşleştirme referansları oluşturun.** Belirlenen Go sürümü, hedef mimari ve olası library'ler için temiz binary'ler oluşturun. Toolchain'i eşleştirmek, compiler tarafından oluşturulan CFG farklılıklarını azaltır.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Function'ları karşılaştırın.** GoGrapher, function CFG'lerini eşleştirir ve `0.0` ile `1.0` arasında normalize edilmiş skorlar üretir. Basic block eşleştirmesi, benzer instruction'ların ağırlıklı karşılaştırmasına dayanır. Güven düzeyi yüksek eşleşmeler, rastgeleleştirilmiş function'ları temiz implementation'la eşleştirir. Daha düşük güven düzeyindeki eşleşmeler yine de bir package veya module belirleyebilir.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Doğrulayın ve içe aktarın.** Önerilen adları call ilişkileri, constant'lar, string'ler ve side effect'lerle doğrulayın; ardından GoResolver plugin'ini kullanarak JSON raporunu IDA veya Ghidra'ya aktarın.<sup>[[10]](#references)[[13]](#references)</sup>

Toolchain'i kurun ve birleşik extractor ile graph matcher'ı çalıştırın:<sup>[[10]](#references)</sup>

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

Varsayılan anlamlı eşleşme eşiği `0.9`'dur. `--extract` ve `--graph` anahtarları iki aşamadan birini tek başına çalıştırabilir; varsayılan olarak ikisi de çalıştırılır, çünkü kurtarılan runtime metadata'sı ile CFG kanıtları birbirini tamamlar.<sup>[[10]](#references)</sup> CFG puanları sezgiseldir: inline etme, build flag'leri, mimari ve kütüphane sürümü farklılıkları grafiğin şeklini değiştirebilir. Bu nedenle düşük güvenli adları zorla atamak yerine çözümlenemeyen işlevleri koruyun.<sup>[[13]](#references)</sup>

### Go string tablosunu kurtarma

Go binary'leri, bağlantılı tüm paketlerdeki string baytlarını tek bir bitişik tabloda tutar. Girdiler NUL ile sonlandırılmaz ve runtime yapıları tablonun başlangıç adresini veya boyutunu göstermez. Ancak derleyici, işletim sistemleri ve mimariler arasında girdileri önce uzunluğa, sonra alfabetik sıraya göre düzenler. Bu nedenle bir girdi bulduktan sonra analist, bitişik girdiler arasında ilerleyebilir ve string'leri kodla ilişkilendirmek için veri çapraz referanslarını kullanabilir.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor), bu iş akışını IDA Pro ve Ghidra'da otomatikleştirir. Eklenti veri segmenti çapraz referanslarını kullandığından önce otomatik analizin tamamlanmasını bekleyin. Varsayılan anchor, runtime string'i `entersyscall`'dır. Eklenti bundan sonra her iki yönde de tarama yapabilir, kurtarılan string'leri veritabanında tanımlayabilir ve string'leri bunlara referans veren işlevlerle eşleştiren bir JSON çıktısı oluşturabilir.<sup>[[14]](#references)</sup>

Uygulama veya malware kodunu bağlantılı kütüphanelerin oluşturduğu gürültüden ayırmak için raporu, referans veren işlevin paketine göre filtreleyin. Bu teknik, Garble'ın `-literals` dönüşümü gibi obfuscation yöntemleriyle yok edilmiş literal'ları kurtaramaz. Yine de obfuscation uygulanmamış runtime string'lerini düzenlemek için kullanılabilir.<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime türlerini kurtarma

Go, garbage collection gibi özelliklerin kullandığı runtime tür bilgilerini binary'ye ekler. Build bilgileri kaldırıldığında veya disassembler bu metadata'yı ayrıştıramadığında, talimatlar rastgele veri adreslerini yüklüyormuş gibi görünebilir ve hedef bölge tür bilgisi olmadan kalır. Bu metadata'yı kurtarmak, bu adresleri okunabilir tür referanslarına dönüştürür ve paketlerin yeteneklerini anlamayı kolaylaştırır.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver), sembolleri çıkarabilir ve runtime türlerini ayrıştırarak JSON raporu oluşturabilir. Güncel CLI, `resolve` alt komutunu kullanır:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` seçeneği type ayrıştırmayı etkinleştirir. Kurtarılan type’ları tanımlamak ve referanslarını analiz veritabanında uygulamak için raporu GoResolver'ın IDA Pro veya Ghidra plugin’iyle içe aktarın. Bu özellikle tanıtılan rapor biçiminde, `-y` seçeneği kullanılmadığında RTTI adresi ve kurtarılan type üyeleri null kalır.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver, x86, AMD64, ARM ve ARM64 için PE, ELF ve Mach-O örneklerini destekler; bu nedenle aynı iş akışı Windows, Linux ve macOS için Go binary’lerinde de uygulanabilir.<sup>[[10]](#references)</sup>

## Derlenmiş Python

Bu sayfada, ELF/EXE biçiminde derlenmiş bir Python binary’sinden Python kodunu nasıl çıkaracağınızı bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Bir GBA oyununun **binary** dosyasını aldıysanız, onu **emüle etmek** ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Debug sürümünü indirin_) - Arayüzlü bir debugger içerir
- [**mgba** ](https://mgba.io)- CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin’i
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin’i

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünde Game Boy Advance **düğmelerine** nasıl basacağınızı görebilirsiniz.

![Game Boy Advance düğme eşleştirmelerini gösteren no$gba kontroller yapılandırması](<../../images/image (581).png>)

Basıldığında, her **tuşun onu tanımlayan bir değeri vardır**:

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

Yani bu tür bir programda ilgi çekici kısım, **programın kullanıcı girdisini nasıl işlediği** olacaktır. **0x4000130** adresinde sıkça karşılaşılan **KEYINPUT** işlevini bulabilirsiniz.

![0x4000130 adresinde KEYINPUT'e başvuran bir GBA binary dosyasının Ghidra görünümü](<../../images/image (447).png>)

Önceki görselde, işlevin **FUN_080015a8**'den çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

Bu işlevde, bazı başlatma işlemlerinden sonra (önemli değiller):

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

Son if, **`uVar4`**'ün **önceki Keys** içinde olup olmadığını ve geçerli tuş olmadığını kontrol ediyor; buna bir düğmeyi bırakmak da denir (geçerli tuş **`uVar1`** içinde saklanır).

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
  Sayaç 8'den küçük olduğu sürece basılan tuşların değerleri `DAT_030000d8` içinde biriktirilir.

Yani bu challenge'da, düğmelerin değerlerini bilerek **toplamı 0xf3 olan ve uzunluğu 8'den küçük bir tuş kombinasyonuna basmanız gerekiyordu.**

**Bu eğitim için referans:** [Nostalgia challenge yazısının arşivlenmiş kopyası](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [3] [Rust string'lerini çözümleme - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing eğitimi (arşivlenmiş)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI Destekli Reverse Engineering'i Engellemek ya da En Azından Denemek](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic Block Eşleştirmesine Dayalı Control Flow Graph Karşılaştırma Yaklaşımı](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver deposu](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mekanizması](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Golang binary'lerini otomatik olarak deobfuscate etmek için Control-Flow Graph benzerliğinden yararlanma](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor deposu](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang araçlarına güncellemeler](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Her Şeyi Reverse Engineer Et](https://github.com/morluto/rea)
- [17] [REA managed-code analizi](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI ve Evidence kılavuzu](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
