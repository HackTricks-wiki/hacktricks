# Reversing Araçları ve Temel Yöntemler

{{#include ../../banners/hacktricks-training.md}}

## ImGui Tabanlı Reversing Araçları

Yazılımlar:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg kullanıcı modu otomasyonu

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows kernel hata ayıklama

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Çevrimiçi:

- wasm'den (binary) wat'a (düz metin) **decompile** etmek için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kullanın
- wat'tan wasm'a **compile** etmek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kullanın
- Decompilation için [web-wasmdec](https://wwwg.github.io/web-wasmdec/) aracını da deneyebilirsiniz.

Yazılımlar:

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

Buradaki avantaj, kaybolmuş kaynak kodun eski bir assembly'den geri yüklenmesi gerektiğinde bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilmiş kodda kolayca gezinme olanağı sunar; bu da onu **Xamarin algoritma analizi** için ideal araçlardan biri yapar.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in modeli ve aracı tam ihtiyaçlarınıza göre uyarlayan bir API ile .NET Reflector zamandan tasarruf sağlar ve geliştirmeyi kolaylaştırır. Bu aracın sunduğu çok sayıdaki reverse engineering hizmetine göz atalım:

- Bir kütüphane veya bileşen içindeki veri akışını anlamaya yardımcı olur
- .NET dilleri ve framework'lerinin uygulanışı ve kullanımı hakkında bilgi verir
- Kullanılan API'lerden ve teknolojilerden daha fazla yararlanmak için belgelenmemiş ve dışa açılmamış işlevleri bulur.
- Bağımlılıkları ve farklı assembly'leri bulur
- Kodunuzdaki, üçüncü taraf bileşenlerdeki ve kütüphanelerdeki hataların tam konumunu tespit eder.
- Üzerinde çalıştığınız tüm .NET kodlarının kaynağında hata ayıklamanızı sağlar.

### [ILSpy](https://github.com/icsharpcode/ILSpy) ve [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy plugin'i](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir OS'te kullanabilirsiniz (doğrudan VSCode'dan yükleyebilirsiniz; git'i indirmeniz gerekmez. **Extensions**'a tıklayın ve **ILSpy**'ı arayın).\
**Decompile**, **modify** ve yeniden **recompile** etmeniz gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak sürdürülen fork'u [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir fonksiyonun içindeki bir şeyi değiştirmek için **Right Click -> Modify Method**).

### REA ile çalıştırma gerektirmeyen managed inceleme

**REA**, assembly'yi yüklemeden PE/CLI metadata'sını ve CIL'i inceleyebilir. Önce artifact'in kimliğini belirleyin, ardından üyeleri ve tanımlı native sınırları inceleyin; bu, decompiler kullanmadan veya programı çalıştırmadan önce şüpheli çağrıları incelerken faydalıdır.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Sürüm farklarını karşılaştırmak için `compare_managed_members`, metadata token’larını derlemeler arasında sabit kabul etmek yerine ham CIL/imza kimliğini ve çözümlenmiş talimat parmak izlerini kullanır. Bir P/Invoke bildirimi, yerel kodun çalıştığını kanıtlamaz; bu sınırı denetlemek için `verify_managed_native_boundaries` eşleşen yerel dışa aktarımlara veya işlev kanıtlarına ihtiyaç duyar. Artifact özeti, MVID ve çözümlenmemiş eşlemeleri sonuçla birlikte saklayın.<sup>[[17]](#references)</sup>

### DNSpy Günlük Kaydı

**DNSpy’nin bazı bilgileri bir dosyaya kaydetmesini** sağlamak için şu kod parçasını kullanabilirsiniz:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

DNSpy kullanarak kodda hata ayıklamak için şunları yapmanız gerekir:

Öncelikle **debugging** ile ilgili **Assembly attributes** değerlerini değiştirin:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Ardından yeni dosyayı _**File >> Save module...**_ üzerinden kaydedin:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Bunu yapmak gerekir; aksi takdirde **runtime** sırasında koda çeşitli **optimizasyonlar** uygulanır ve hata ayıklama sırasında bir **breakpoint'e hiç ulaşılmaması** veya bazı **değişkenlerin bulunmaması** mümkün olabilir.

Ardından, .NET uygulamanız **IIS** tarafından **çalıştırılıyorsa** onu şu komutla **yeniden başlatabilirsiniz**:

```
iisreset /noforce
```

Ardından hata ayıklamayı başlatmak için açık olan tüm dosyaları kapatmalı ve **Debug Tab** içinden **Attach to Process...** seçmelisiniz:

![DNSpy Logging - DNSpy Debugging: Ardından hata ayıklamayı başlatmak için açık olan tüm dosyaları kapatmalı ve Debug Tab içinden Attach to Process seçmelisiniz](<../../images/image (318).png>)

Ardından **IIS server**'a bağlanmak için **w3wp.exe**'yi seçin ve **attach**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Ardından IIS server'a bağlanmak için w3wp.exe'yi seçin ve attach'e tıklayın](<../../images/image (113).png>)

Artık süreci hata ayıklayıcıda izlediğimize göre, durdurup tüm modülleri yükleme zamanı. Önce _Debug >> Break All_'a, ardından _**Debug >> Windows >> Modules**_'a tıklayın:

![DNSpy Logging - DNSpy Debugging: Artık süreci hata ayıklayıcıda izlediğimize göre, durdurup tüm modülleri yükleme zamanı. Önce Debug Break All'a, ardından Debug Windows Modules'a tıklayın](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Artık süreci hata ayıklayıcıda izlediğimize göre, durdurup tüm modülleri yükleme zamanı. Önce Debug Break All'a, ardından Debug Windows Modules'a tıklayın](<../../images/image (834).png>)

**Modules** içindeki herhangi bir modüle tıklayın ve **Open All Modules**'ı seçin:

![DNSpy Logging - DNSpy Debugging: Modules içindeki herhangi bir modüle tıklayın ve Open All Modules'ı seçin](<../../images/image (922).png>)

**Assembly Explorer** içindeki herhangi bir modüle sağ tıklayın ve **Sort Assemblies**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer içindeki herhangi bir modüle sağ tıklayın ve Sort Assemblies'e tıklayın](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'lerde hata ayıklama

### IDA kullanımı

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe konumunda, 32 bit sürümü ise C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Windbg** hata ayıklayıcısını seçin
- "**Suspend on library load/unload**" seçeneğini işaretleyin

![Debugging DLLs - Using IDA: "Suspend on library load/unload" seçeneğini işaretleyin](<../../images/image (868).png>)

- **DLL'nin yolunu** ve çağırmak istediğiniz işlevi belirterek çalıştırma **parametrelerini** yapılandırın:

![Debugging DLLs - Using IDA: DLL'nin yolunu ve çağırmak istediğiniz işlevi belirterek çalıştırma parametrelerini yapılandırın](<../../images/image (704).png>)

Ardından hata ayıklamayı başlattığınızda **her DLL yüklendiğinde çalıştırma durur**; yani rundll32 DLL'nizi yüklediğinde çalıştırma durdurulur.

Bu yöntem modül yükleme olaylarında durur, ancak yüklenen DLL'nin giriş noktasına ulaşmak, aşağıdaki x64dbg iş akışına kıyasla daha dolaylıdır.

### x64dbg/x32dbg kullanımı

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe konumunda, 32 bit sürümü ise C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Komut satırını değiştirin** ( _File --> Change Command Line_ ) ve DLL'nin yolunu ve çağırmak istediğiniz işlevi ayarlayın. Örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ bölümünü açın ve "**DLL Entry**"yi seçin.
- Ardından **çalıştırmayı başlatın**; hata ayıklayıcı her DLL main'de durur ve bir noktada **DLL'nizin Entry noktasında durur**. Buradan, breakpoint koymak istediğiniz noktaları aramanız yeterlidir.

win64dbg'de çalıştırma herhangi bir nedenle durduğunda, **win64dbg penceresinin üst kısmına** bakarak **hangi kodda olduğunuzu** görebileceğinizi unutmayın:

![Using IDA - Using x64dbg/x32dbg: Çalıştırma win64dbg'de herhangi bir nedenle durduğunda, win64dbg penceresinin üst kısmına bakarak hangi kodda olduğunuzu görebileceğinizi unutmayın](<../../images/image (842).png>)

Bu gösterge, çalıştırmanın hata ayıklamak istediğiniz DLL'nin içinde durduğunu doğrular.

## GUI uygulamaları / Video oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bunları değiştirmek için kullanışlı bir programdır. Daha fazla bilgi:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), oyunlara odaklanan, GNU Project Debugger (GDB) için bir ön yüz/tersine mühendislik aracıdır. Ancak tersine mühendislikle ilgili her türlü iş için kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/), çeşitli decompiler'lar için web tabanlı bir ön yüzdür. Bu web hizmeti, küçük yürütülebilir dosyalar üzerinde farklı decompiler'ların çıktılarını karşılaştırmanıza olanak tanır.

## REA ile kanıta dayalı native inceleme

**REA**, Hopper, Ghidra ve IDA analizlerini CLI ve MCP üzerinden sunar. Node.js 22.x (en az 22.19), 24.x (en az 24.11) veya 26+ sürümlerini ve npm'yi gerektirir. Önce mevcut bir native provider'ı yapılandırın; `rea providers --json` komutunu çalıştırın ve birden fazla provider hedefi destekliyorsa birini açıkça seçin. Aşağıda `0x1000` yerine envanterde gözlemlenen bir işlev adını veya adresini kullanın.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Bir feature string veya symbol ile başlayın, ardından references ve callers'ı takip edin; sonra seçilen function dossier'ı ve pseudocode'u `rea decompile` ile inceleyin. REA, başarısızlık sonrasında oturumu sessizce değiştirmek yerine seçilen provider'a bağlar. Tekrarlanabilir sorgular için `--snapshot PATH` yalnızca eşleşen artifact bytes, provider, settings, operation ve parameters değerlerini yeniden kullanır; snapshot, kaydedilmiş bir provider database değil, yerel bir cache'dir. Döndürülen Evidence'ı ve açıkça belirtilen unknowns değerlerini koruyun; çıkarımla elde edilen paths'leri veya decompiler metnini orijinal kaynak olarak değerlendirmeyin.<sup>[[16]](#references)[[18]](#references)</sup>

Native add-ons'a yönlendiren JavaScript/Electron entry points için bkz. [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner ile shellcode debug etme

[**BlobRunner**](https://github.com/OALabs/BlobRunner), **shellcode**'u belleğe ayırır, **memory address**'ini yazdırır ve yürütmeyi duraklatır.\
IDA veya x64dbg gibi bir debugger bağlayın, yazdırılan adreste bir breakpoint ayarlayın ve shellcode'u debug etmek için yürütmeyi sürdürün.

Releases github sayfasında derlenmiş sürümleri içeren zip dosyaları bulunur: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blobrunner'ın biraz değiştirilmiş bir sürümünü aşağıdaki bağlantıda bulabilirsiniz. Derlemek için **Visual Studio Code'da bir C/C++ projesi oluşturun, kodu kopyalayıp yapıştırın ve build edin**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile shellcode debug etme

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner'a benzer. Shellcode'u belleğe ayırır ve sonsuz bir döngüye girer. Debugger'ı bağlayın, **2–5 saniye** boyunca yürütmeyi sürdürün, döngünün içindeyken duraklatın ve yürütmeyi ayrılmış shellcode'a aktaran sonraki call'a ilerleyin.

![Debugger jmp2it'in sonsuz döngüsünde, ayrılmış shellcode'a yapılan call'dan hemen önce duraklatılmış](<../../images/image (509).png>)

Derlenmiş bir jmp2it sürümünü [releases sayfasından indirebilirsiniz](https://github.com/adamkramer/jmp2it/releases/).

### Cutter kullanarak shellcode debug etme

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'ın GUI'sidir. Cutter'ı kullanarak shellcode'u emulate edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Open File" ve "Open Shellcode" seçenekleri sunduğunu unutmayın. Benim durumumda shellcode'u dosya olarak açtığımda doğru şekilde decompile etti, ancak shellcode olarak açtığımda etmedi:

![Cutter, aynı byte'ları dosya veya shellcode olarak açarken farklı analiz sonuçları gösteriyor](<../../images/image (562).png>)

Emulation'ı istediğiniz noktada başlatmak için orada bir bp ayarlayın; anlaşılan Cutter emulation'ı otomatik olarak o noktadan başlatacaktır:

![Cutter emulation'ını başlatmadan önce istenen shellcode entry noktasında breakpoint ayarlama](<../../images/image (589).png>)

![Cutter emulator, seçilen shellcode breakpoint'inde duraklatılmış](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görebilirsiniz:

![Cutter'ın hex dump'inde emulate edilen shellcode stack'ini görüntüleme](<../../images/image (186).png>)

### Shellcode'u deobfuscate etme ve yürütülen function'ları bulma

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) aracını deneyin.\
Shellcode'un hangi **function'ları** kullandığı ve bellekte kendini **decode** edip etmediği gibi bilgileri gösterir.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg ayrıca istediğiniz seçenekleri seçip shellcode'u çalıştırabileceğiniz grafiksel bir başlatıcı da içerir

![shellcode emülasyonu ve izleme seçeneklerini seçmek için scDbg grafiksel başlatıcısı](<../../images/image (258).png>)

**Create Dump** seçeneği, bellekte shellcode üzerinde dinamik olarak herhangi bir değişiklik yapılırsa son halini dump eder (çözülmüş shellcode'u indirmek için kullanışlıdır). **start offset**, shellcode'u belirli bir offset'te başlatmak için yararlı olabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'da debug yapmak için kullanışlıdır (ancak bu amaçla önceki seçeneklerden herhangi birini daha iyi buluyorum; çünkü Ida veya x64dbg kullanabilirsiniz).

### CyberChef ile Disassembly

Shellcode dosyanızı girdi olarak yükleyin ve decompile etmek için şu tarifi kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation'ı çözme

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` gibi basit ifadeleri aritmetik (`+`, `-`, `*`) ve bit düzeyindeki operatörleri (`&`, `|`, `^`, `~`, shift'ler) birleştiren formüllerin arkasına gizler. Önemli nokta, bu özdeşliklerin genellikle yalnızca **sabit genişlikli modüler aritmetik** altında doğru olmasıdır; bu nedenle elde edilen bitler ve taşmalar önemlidir:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Bu tür bir ifadeyi genel cebir araçlarıyla sadeleştirirseniz, bit genişliği semantiği göz ardı edildiğinden kolayca yanlış bir sonuç elde edebilirsiniz.<sup>[[1]](#references)</sup>

### Pratik iş akışı

1. **Orijinal bit genişliğini** lifted code/IR/decompiler çıktısından koruyun (`8/16/32/64` bit).
2. Sadeleştirmeye çalışmadan önce ifadeyi **sınıflandırın**:
   - **Linear**: bit düzeyindeki atomların ağırlıklı toplamları
   - **Semilinear**: `x & 0xFF` gibi sabit maskelerin eklendiği linear ifadeler
   - **Polynomial**: çarpımlar içerir
   - **Mixed**: çarpımlar ile bit düzeyindeki mantık iç içe geçer; genellikle tekrarlanan alt ifadeler bulunur
3. Her olası yeniden yazımı random testing veya bir SMT proof ile **doğrulayın**. Eşdeğerlik kanıtlanamıyorsa tahmin yürütmek yerine özgün ifadeyi koruyun.

### Dar bir yürütme dilimiyle düzleştirilmiş control flow'u atlatma

Control-flow graph'ın tamamını çıkarmak çoğu zaman gereksizdir. Control-flow flattening, opaque predicate'ler, büyük dispatcher'lar veya MBA ağırlıklı kod söz konusu olduğunda, şifrelenmiş blob'lara ve output buffer'lara yapılan referansları izleyerek bunları dönüştüren en küçük routine'i bulun. Ardından yalnızca bu data-flow dilimini yeniden oluşturun veya bağımsız olarak çalıştırın; ilgili state doğrudan başlatılabiliyorsa dispatcher gerekli çözümün parçası değildir.<sup>[[7]](#references)</sup>

Pratik bir iş akışı:<sup>[[7]](#references)</sup>

1. Executable ve data section'larını, relocation'ları ve cross-reference'ları envanterleyin. Byte sırasını ve element genişliğini koruyarak `.rodata` içindeki olası tabloları dump edin.
2. Plaintext'i veya output buffer'ı yazan son routine'i belirleyin. Girdilerini, referans verdiği tabloları, imported call'ları ve gerekli global state'i kaydedin.
3. Yalnızca bu işlemleri fixed-width bir Python modeline aktarın. Dilim hâlâ çok fazla state'e bağlıysa tüm programı emüle etmek yerine routine'i Unicorn, QEMU veya bir debugger altında çalıştırın ve ilgisiz import'ları hook edin.
4. Extractor'ın çıktısını gerçekten verilen binary'den türettiğini doğrulayın: sessiz fallback'leri kaldırın, içine gömülü yanıtları arayın ve değişen string'ler, key'ler, identifier'lar, layout'lar ve obfuscation seed'leri içeren, daha önce görülmemiş build'lerde çalıştırın.

İlk incelemede işe yarayan komutlar:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Sabit değerler olarak gizlenmiş MBA ifadelerini tespit etme

Görünüşte girdiye bağlı olan bir bayt ifadesi, girdisini tamamen etkisiz hâle getirebilir. Tablolarını çıkardıktan sonra ifadeyi 8 bitlik tüm değerler üzerinde değerlendirin; tek elemanlı bir çıktı kümesi, çevresindeki durum makinesini çözmeden bu baytın sabit olduğunu kanıtlar.<sup>[[7]](#references)</sup>

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

Son maskeyi koruyun; çünkü özgün toplama işleminde byte genişliğinde taşma vardır. Daha geniş bir domain için, bir SMT solver'a aynı genişlikteki iki sembolik girdi için `f(x1) != f(x2)` ifadesinin sağlanabilir olup olmadığını sorun: `unsat` değişmezliği kanıtlar; `sat` ise bir karşı örnek sunar ve girdinin atılamayacağı anlamına gelir.<sup>[[7]](#references)</sup>

#### Ortama bağlı çözümlemeyi tanıyın

Anti-analysis kontrollerinin dallanması veya çökmesi gerekmez. Bir decoder, sensör sonucunu bir key bitine, opaque-predicate sabitine veya flattened-dispatcher durumuna karıştırabilir; normal şekilde çalışmaya devam edip bir emülatörde makul görünen ancak yanlış bir plaintext üretebilir. Bu nedenle yalnızca görünür hata dallarını patch etmek yeterli değildir; ortam problarından decoder durumuna uzanan veri bağımlılıklarını izleyin, aynı dilimi gerçek cihazda ve emülatörde karşılaştırın ve her sensör sonucunu zorlamanın son buffer'ı nasıl değiştirdiğini test edin.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA), malware analizi ve korumalı binary'leri tersine mühendislikle incelemek için pratik bir MBA sadeleştiricisidir. İfadeyi sınıflandırır ve her şeye tek bir genel yeniden yazma geçişi uygulamak yerine, ifadeyi özelleşmiş işlem hatlarına yönlendirir.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA, ifadeyi Boolean girdiler üzerinde değerlendirir, bir imza türetir ve pattern matching, ANF dönüşümü ve katsayı interpolasyonu gibi çeşitli kurtarma yöntemlerini yarıştırır.
- **Semilinear MBA**: Sabit maskeli atomlar, maskeli bölgelerin doğruluğunu korumak için bit bölümlü yeniden oluşturma kullanılarak yeniden oluşturulur.
- **Polynomial/Mixed MBA**: Çarpımlar çekirdeklere ayrılır ve dış ilişki basitleştirilmeden önce tekrar eden alt ifadeler geçici değişkenlere alınabilir.

Sıklıkla kurtarmaya çalışmaya değer bir karma özdeşlik örneği:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Bu şu şekilde sadeleştirilebilir:

```c
x * y
```

### Tersine mühendislik notları

- CoBRA'yı, tam hesaplamayı izole ettikten sonra **lifted IR ifadeleri** veya decompiler çıktısı üzerinde çalıştırmayı tercih edin.
- İfade maskelenmiş aritmetikten veya dar register'lardan kaynaklanıyorsa `--bitwidth` seçeneğini açıkça kullanın.
- Daha güçlü bir ispat adımına ihtiyacınız varsa buradaki Z3 notlarına göz atın:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca **LLVM pass plugin** (`libCobraPass.so`) olarak da sunulur. Bu, sonraki analiz pass'lerinden önce MBA ağırlıklı LLVM IR'yi normalize etmek istediğinizde kullanışlıdır.
- Desteklenmeyen, carry'ye duyarlı karma alan artıkları; orijinal ifadeyi koruyup carry yolunu elle analiz etmeniz gerektiğinin işareti olarak değerlendirilmelidir.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, program işlemlerini `mov` tabanlı instruction dizileriyle değiştirir ve control flow'u değiştirmek için signal/exception handling kullanır. Ayrıntılar için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Desteklenen binary'ler için [demovfuscator](https://github.com/kirschju/demovfuscator), sonucu deobfuscate edebilir. Birkaç bağımlılığı vardır.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Ve [keystone'u yükleyin](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Bir **CTF oynuyorsanız, flag'i bulmak için bu geçici çözüm** çok işinize yarayabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**Giriş noktasını** bulmak için, aşağıdaki örnekte olduğu gibi fonksiyon adlarında `::main` araması yapın:

![Ghidra'da fonksiyon adlarında çift iki nokta ve main arayarak Rust giriş noktasını bulma](<../../images/image (1080).png>)

Bu örnekte binary'nin adı authenticator'dı; dolayısıyla ilgi çekici main fonksiyonunu bulmak oldukça kolay.\
Çağrılan **fonksiyonların** **adlarını** öğrendikten sonra, **girdileri** ve **çıktıları** hakkında bilgi edinmek için bu adları **İnternet'te** arayın.

### ELF firmware'inden Rust string'lerini kurtarma

**Rust ELF** binary'lerinde birçok statik string'e, C tarzı NUL ile sonlandırılmış pointer'lar üzerinden başvurulmaz. Yaygın bir `rustc` düzeninde, **`.data.rel.ro`** içinde gerçek string blob'una işaret eden bir **pointer/length tuple** bulunur; bu blob **`.rodata`** içinde saklanır:

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
2. **`.data.rel.ro`** bölümünü her seferinde bir word olacak şekilde sıralayın.
3. **`.rodata`** adres aralığındaki her değeri olası bir string pointer olarak değerlendirin.
4. Sonraki word’ü olası uzunluk olarak değerlendirin.
5. Mantıklılık filtreleri uygulayın (örneğin, uzunluğu **4** ile **100** byte arasında olanları tutun).
6. `0x00` görene kadar taramak yerine, **`.rodata`** bölümünden tam olarak `length` byte okuyun.

Minimal extractor mantığı:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Bu, firmware reversing sırasında özellikle kullanışlıdır; çünkü kurtarılan Rust string'leri genellikle **HTTP rotalarını, RPC adlarını, log mesajlarını, assertion'ları, dosya adlarını, config anahtarlarını, komut işleyicilerini ve auth ile ilgili mantığı** ortaya çıkarır.

Ghidra bu string'leri bulamazsa aynı sezgisel yöntemi uygulayan ve başvurulan `.rodata` offset'lerinde string verileri oluşturan özel bir script/plugin çalıştırın. Pen Test Partners'ın yayımladığı `rust-strings` ve `RustStrings.py` araçları, bu fikri diğer **word size'lara, endianness değerlerine ve section düzenlerine** uyarlamak için iyi kaynaklardır.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi ile derlenmiş binary'ler için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Bir Delphi binary'sini reverse etmeniz gerekiyorsa, IDA plugin'i [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın ve ardından plugin dosyasını seçin.

Bu plugin, binary'yi çalıştırır ve debugging başladığında fonksiyon adlarını dinamik olarak çözümler. Debugging'i başlattıktan sonra Start düğmesine (yeşil olan veya f9) tekrar basın; gerçek kodun başlangıcında bir breakpoint tetiklenir.

Grafik uygulamada bir düğmeye basarsanız debugger, o düğmenin çağırdığı fonksiyonda durabilir.

## Golang

Sıradan Go binary'leri için [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper), runtime yapılarını kurtarabilir ve IDA'daki fonksiyon adlarını iyileştirebilir. Python plugin'ini yüklemek için **Alt+F7** tuşlarına basın.

Bir Golang binary'sini reverse etmeniz gerekiyorsa, IDA plugin'i [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm.

Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın ve ardından plugin dosyasını seçin.

Bu, fonksiyonların adlarını çözümler.

### Sembol tablosu olmadan metadata'yı kurtarma

Stripped bir Go executable'ı, program counter'ları fonksiyonlara eşlemek için yine de runtime metadata'sına ihtiyaç duyar. [GoReSym](https://github.com/mandiant/GoReSym), Go runtime'ından türetilen kodu kullanarak `pclntab` ve `moduledata` gibi yapıları bulup ayrıştırır. Bu sayede geleneksel sembol tablosuna bağlı kalmadan fonksiyon sınırları, adları, kaynak yolları, türler ve build ayrıntıları kurtarılabilir.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Bir obfuscator, kurtarılan adları değiştirirken bu yapıları kullanılabilir durumda bırakabilir. Örneğin Garble, identifier'ları ve package path'lerini hash'ler; build, module ve debug bilgilerini kaldırır.<sup>[[12]](#references)</sup> Obfuscate edilmiş package token'ı, o package'taki fonksiyonlar arasında tutarlı kalmalıdır. Fonksiyonları tekrarlanan token'a göre gruplayın, callees, string'ler ve API'lerden bir package çıkarımı yapın, ardından bu package etiketini grubun tamamına uygulayın.<sup>[[13]](#references)</sup>

### GoResolver ile Garble adlarını kurtarma

[GoResolver](https://github.com/volexity/GoResolver), runtime sembolü çıkarımını temiz referans oluşturma ve control-flow graph (CFG) eşleştirmeyle birleştirir. Şu sırayı izleyin:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler sürümünü belirleyin.** Önce `BuildInfo` ve gömülü sürüm string'lerini deneyin. Obfuscator bunları kaldırdıysa, paketlenmiş Go runtime'ın bazı bölümlerini sürümlenmiş referans runtime'larla karşılaştırın. Volexity'nin testlerinde, Go'nun ana sürümlerini ayırt etmek için runtime'ın yaklaşık `2%`'si yeterli oldu. Bunu evrensel bir eşik değil, deneysel bir optimizasyon olarak değerlendirin.<sup>[[13]](#references)</sup>
2. **Eşleşen referanslar oluşturun.** Belirlenen Go sürümü, hedef mimari ve olası kütüphaneler için temiz binary'ler oluşturun. Toolchain'i eşleştirmek, compiler tarafından oluşturulan CFG farklılıklarını azaltır.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Fonksiyonları karşılaştırın.** GoGrapher, fonksiyon CFG'lerini eşleştirir ve `0.0` ile `1.0` arasında normalize edilmiş skorlar üretir. Temel blok eşleştirmesi, benzer talimatların ağırlıklı karşılaştırmasına dayanır. Yüksek güven düzeyine sahip eşleşmeler, rastgeleleştirilmiş fonksiyonları temiz implementasyonla eşleştirir. Daha zayıf eşleşmeler yine de bir package veya module belirleyebilir.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Doğrulayın ve içe aktarın.** Önerilen adları call ilişkileri, sabitler, string'ler ve yan etkilerle doğrulayın; ardından JSON raporunu IDA veya Ghidra için GoResolver plugin'iyle içe aktarın.<sup>[[10]](#references)[[13]](#references)</sup>

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

Varsayılan önemli eşleşme eşiği `0.9` değeridir. `--extract` ve `--graph` seçenekleri aşamalardan birini tek başına çalıştırabilir; varsayılan olarak ikisi de çalıştırılır, çünkü kurtarılan runtime metadata ile CFG kanıtları birbirini tamamlar.<sup>[[10]](#references)</sup> CFG skorları buluşsal yöntemlere dayanır: inline etme, build flag'leri, mimari ve kütüphane sürümü farklılıkları grafiğin şeklini değiştirebilir. Bu nedenle, güven düzeyi düşük isimleri zorla atamak yerine çözümlenemeyen fonksiyonları olduğu gibi bırakın.<sup>[[13]](#references)</sup>

### Go string tablosunu kurtarma

Go binary'leri, bağlantısı kurulmuş tüm paketlerin string byte'larını bitişik bir tabloda tutar. Girdiler NUL ile sonlandırılmaz ve runtime yapıları tablonun başlangıç adresini veya boyutunu göstermez. Bununla birlikte derleyici, girdileri tüm işletim sistemleri ve mimarilerde önce uzunluklarına, ardından alfabetik sıraya göre düzenler. Bu nedenle analist, bir girdi bulduktan sonra bitişik girdiler arasında ilerleyebilir ve string'leri kodla ilişkilendirmek için veri çapraz başvurularından yararlanabilir.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor), bu iş akışını IDA Pro ve Ghidra'da otomatikleştirir. Eklenti veri segmenti çapraz başvurularına bağlı olduğundan önce otomatik analizin tamamlanmasını bekleyin. Varsayılan anchor, runtime string'i `entersyscall` değeridir. Ardından eklenti her iki yönde tarama yapabilir, kurtarılan string'leri veritabanında tanımlayabilir ve string'leri bunlara başvuran fonksiyonlarla eşleştiren bir JSON dosyası dışa aktarabilir.<sup>[[14]](#references)</sup>

Uygulama veya malware kodunu bağlantısı kurulmuş kütüphanelerden gelen gürültüden ayırmak için raporu, başvuran fonksiyonun paketine göre filtreleyin. Bu teknik, Garble'ın `-literals` dönüşümü gibi obfuscation yöntemleriyle yok edilmiş literal'leri kurtaramaz. Yine de obfuscation uygulanmamış runtime string'lerini düzenlemeye yardımcı olabilir.<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime türlerini kurtarma

Go, garbage collection gibi özelliklerde kullanılan runtime type bilgilerini binary'ye ekler. Build bilgileri kaldırıldığında veya disassembler bu metadata'yı ayrıştıramadığında, talimatlar rastgele veri adreslerini yüklüyormuş gibi görünebilir ve hedef bölge tür bilgisi olmadan kalabilir. Bu metadata'yı kurtarmak, bu adresleri okunabilir tür referanslarına dönüştürür ve paketlerin yeteneklerini anlamayı kolaylaştırır.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver), sembolleri çıkarabilir ve runtime türlerini ayrıştırarak bir JSON raporu oluşturabilir. Güncel CLI'da `resolve` alt komutu kullanılır:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` seçeneği type parsing özelliğini etkinleştirir. Kurtarılan type’ları tanımlamak ve referanslarını analiz veritabanına uygulamak için raporu GoResolver’ın IDA Pro veya Ghidra plugin’iyle içe aktarın. Bu özellikle sunulan rapor formatında, `-y` seçeneği kullanılmadığında RTTI adresi ve kurtarılan type’lara ait alanlar null olur.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver; x86, AMD64, ARM ve ARM64 için PE, ELF ve Mach-O örneklerini destekler. Bu nedenle aynı iş akışı Windows, Linux ve macOS’taki Go binary’leri için de geçerlidir.<sup>[[10]](#references)</sup>

## Derlenmiş Python

Bu sayfada, bir ELF/EXE Python derlenmiş binary’sinden Python kodunu nasıl çıkarabileceğinizi bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Bir GBA oyununun **binary**’sini elde ederseniz, onu **emüle etmek** ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Debug sürümünü indirin_) - Arayüzlü bir debugger içerir
- [**mgba** ](https://mgba.io)- CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin’i
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin’i

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünde Game Boy Advance **düğmelerine** nasıl basacağınızı görebilirsiniz.

![Game Boy Advance düğme eşlemelerini gösteren no$gba kontrolleri yapılandırması](<../../images/image (581).png>)

Basılınca her **tuşun onu tanımlayan bir değeri** olur:

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

Bu tür bir programda ilgi çekici olan kısım, **programın kullanıcı girdisini nasıl işlediğidir**. **0x4000130** adresinde sıkça karşılaşılan **KEYINPUT** işlevini bulabilirsiniz.

![0x4000130 adresinde KEYINPUT'e başvuran bir GBA binary'sinin Ghidra görünümü](<../../images/image (447).png>)

Önceki görselde, işlevin **FUN_080015a8** içinden çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

Bu işlevde, bazı başlangıç işlemlerinden sonra (bunların önemi yoktur):

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

Son if, **`uVar4`**'ün **son Keys** içinde olup olmadığını ve geçerli tuş olmadığını kontrol ediyor; bu, bir tuşu bırakmak olarak da adlandırılır (geçerli tuş **`uVar1`** içinde saklanır).

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

- İlk olarak **4 değeriyle** (**SELECT** düğmesi) karşılaştırılır: Bu challenge'da bu düğme ekranı temizler.
- Ardından değer **8** (**START** düğmesi) ile karşılaştırılır; bu challenge'da bu yol, girilen kodun geçerli olup olmadığını kontrol eder.
  - Bu durumda **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılır ve değer aynıysa bazı kodlar çalıştırılır.
- Diğer tüm durumlarda bir sayaç (`DAT_030000d4`) kontrol edilir ve artırılır.\
  Sayaç 8'den küçük olduğu sürece, basılan tuşların değerleri `DAT_030000d8` içinde biriktirilir.

Dolayısıyla bu challenge'da, düğmelerin değerlerini bilerek, toplamı 0xf3 olan ve uzunluğu 8'den küçük bir kombinasyona **basmanız** gerekiyordu.

**Bu eğitim için referans:** [arşivlenmiş Nostalgia challenge yazısı](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRA ile MBA obfuscation'ı basitleştirme](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA deposu](https://github.com/trailofbits/CoBRA)
- [3] [Rust string'lerini çözümleme - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing eğitimi (arşivlenmiş)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI destekli reverse engineering'i yenmek veya en azından denemek](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Temel blok eşleştirmeye dayalı bir kontrol akış grafiği karşılaştırma yaklaşımı](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver deposu](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mekanizması](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Golang binary'lerini otomatik olarak deobfuscate etmek için kontrol akış grafiği benzerliğini kullanma](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor deposu](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang araçlarındaki güncellemeler](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Her Şeyi Tersine Mühendislikle İnceleyin](https://github.com/morluto/rea)
- [17] [REA managed-code analizi](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI ve Evidence kılavuzu](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
