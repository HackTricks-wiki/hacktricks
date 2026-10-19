# Reversing Araçları ve Temel Yöntemler

{{#include ../../banners/hacktricks-training.md}}

## ImGui Tabanlı Reversing Araçları

Yazılım:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg user-mode otomasyonu

{{#ref}}
windbg-automation.md
{{#endref}}

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

dotPeek; **kütüphaneler** (.dll), **Windows metadata dosyaları** (.winmd) ve **çalıştırılabilir dosyalar** (.exe) dahil olmak üzere birden fazla formatı **decompile edip inceleyen** bir decompiler'dır. Decompile edildikten sonra bir assembly, Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantajı, kaybolan kaynak kodun eski bir assembly'den geri yüklenmesi gerektiğinde bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilmiş kodda kolay gezinme olanağı sunar ve bu da onu **Xamarin algoritma analizi** için ideal araçlardan biri yapar.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in modeli ve aracı tam ihtiyaçlarınıza göre uyarlayan bir API ile .NET Reflector zamandan tasarruf sağlar ve geliştirmeyi kolaylaştırır. Bu aracın sunduğu çok sayıdaki reverse engineering hizmetine göz atalım:

- Bir kütüphane veya bileşen üzerinden verilerin nasıl aktığına dair bilgi sağlar
- .NET dilleri ve framework'lerinin uygulanışı ve kullanımı hakkında bilgi sağlar
- Kullanılan API'lerden ve teknolojilerden daha fazla yararlanmak için belgelenmemiş ve dışarı açılmamış işlevleri bulur.
- Bağımlılıkları ve farklı assembly'leri bulur
- Kodunuzdaki, üçüncü taraf bileşenlerdeki ve kütüphanelerdeki hataların tam konumunu bulur.
- Üzerinde çalıştığınız tüm .NET kodlarının kaynak kodunda debugging yapar.

### [ILSpy](https://github.com/icsharpcode/ILSpy) ve [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy eklentisi](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir işletim sisteminde kullanabilirsiniz (doğrudan VSCode'dan yükleyebilirsiniz; git'i indirmeniz gerekmez. **Extensions**'a tıklayın ve **ILSpy**'ı arayın).\
Tekrar **decompile**, **modify** ve **recompile** etmeniz gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak bakımı yapılan fork'u [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir fonksiyon içindeki bir şeyi değiştirmek için **Right Click -> Modify Method**.)

### REA ile çalıştırma gerektirmeyen managed inceleme

**REA**, assembly'yi yüklemeden PE/CLI metadata'sını ve CIL'i inceleyebilir. Önce artifact'in kimliğini belirleyin, ardından üyeleri ve tanımlanmış native sınırları inceleyin; bu, bir decompiler kullanmadan veya programı çalıştırmadan önce şüpheli çağrıları gözden geçirmek için faydalıdır.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Sürümler arası karşılaştırmada `compare_managed_members`, metadata token’larını derlemeler arasında sabit kabul etmek yerine ham CIL/imza kimliğini ve çözümlenmiş talimat parmak izlerini kullanır. Bir P/Invoke bildirimi, native kodun çalıştığını kanıtlamaz; bu sınırı denetlemek için `verify_managed_native_boundaries` işlevinin eşleşen native export veya işlev kanıtına ihtiyacı vardır. Artifact özeti, MVID ve çözümlenmemiş eşlemeleri sonuçla birlikte saklayın.<sup>[[17]](#references)</sup>

### DNSpy Günlüğü

**DNSpy’nin bazı bilgileri bir dosyaya kaydetmesini** sağlamak için şu snippet’i kullanabilirsiniz:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy ile Hata Ayıklama

DNSpy kullanarak kodda hata ayıklamak için şunları yapmanız gerekir:

Önce, **hata ayıklamayla** ilgili **Assembly özniteliklerini** değiştirin:

![DNSpy Logging - DNSpy ile Hata Ayıklama: Önce, hata ayıklamayla ilgili Assembly özniteliklerini değiştirin](<../../images/image (973).png>)

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

Bunu yapmak gerekir; çünkü yapmazsanız **runtime** sırasında koda çeşitli **optimizasyonlar** uygulanır ve hata ayıklama sırasında bir **break-point'e hiç ulaşılmaması** veya bazı **değişkenlerin mevcut olmaması** mümkündür.

Ardından, .NET uygulamanız **IIS** tarafından **çalıştırılıyorsa** şu komutla **yeniden başlatabilirsiniz**:

```
iisreset /noforce
```

Ardından debugging'e başlamak için açık olan tüm dosyaları kapatın ve **Debug Tab** içinden **Attach to Process...** seçeneğini seçin:

![DNSpy Logging - DNSpy Debugging: Ardından debugging'e başlamak için açık olan tüm dosyaları kapatın ve Debug Tab içinden Attach to Process seçeneğini seçin](<../../images/image (318).png>)

Sonra **IIS server**'a bağlanmak için **w3wp.exe**'yi seçin ve **attach**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Sonra IIS server'a bağlanmak için w3wp.exe'yi seçin ve attach'e tıklayın](<../../images/image (113).png>)

Şimdi süreci debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce _Debug >> Break All_ seçeneğine, ardından _**Debug >> Windows >> Modules**_ seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Şimdi süreci debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Şimdi süreci debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (834).png>)

**Modules** içindeki herhangi bir modüle tıklayın ve **Open All Modules** seçeneğini seçin:

![DNSpy Logging - DNSpy Debugging: Modules içindeki herhangi bir modüle tıklayın ve Open All Modules seçeneğini seçin](<../../images/image (922).png>)

**Assembly Explorer** içindeki herhangi bir modüle sağ tıklayın ve **Sort Assemblies** seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer içindeki herhangi bir modüle sağ tıklayın ve Sort Assemblies seçeneğine tıklayın](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL Debugging

### IDA ile

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe konumunda, 32 bit sürümü ise C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Windbg** debugger'ını seçin
- "**Suspend on library load/unload**" seçeneğini seçin

![Debugging DLLs - Using IDA: " Suspend on library load/unload " seçeneğini seçin](<../../images/image (868).png>)

- **DLL'nin yolunu** ve çağırmak istediğiniz işlevi girerek yürütmenin **parameters**'ını yapılandırın:

![Debugging DLLs - Using IDA: DLL'nin yolunu ve çağırmak istediğiniz işlevi girerek yürütmenin parameters'ını yapılandırın](<../../images/image (704).png>)

Ardından debugging'i başlattığınızda **her DLL yüklendiğinde yürütme durdurulur**; dolayısıyla rundll32 DLL'nizi yüklediğinde yürütme durdurulacaktır.

Bu yöntem, modül yükleme olaylarında durur; ancak yüklenen DLL'nin entry point'ine ulaşmak, aşağıdaki x64dbg iş akışına kıyasla daha dolaylıdır.

### x64dbg/x32dbg ile

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe konumunda, 32 bit sürümü ise C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Command Line'ı değiştirin** ( _File --> Change Command Line_ ) ve dll'nin yolunu ve çağırmak istediğiniz işlevi ayarlayın; örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ bölümünü açın ve "**DLL Entry**" seçeneğini seçin.
- Ardından **yürütmeyi başlatın**; debugger her dll main'de duracaktır. Bir noktada **dll'nizin DLL Entry noktasında duracaksınız**. Buradan, breakpoint koymak istediğiniz noktaları aramanız yeterli.

win64dbg'de yürütme herhangi bir nedenle durduğunda, **win64dbg penceresinin üst kısmına** bakarak **hangi kodda olduğunuzu** görebileceğinizi unutmayın:

![Using IDA - Using x64dbg/x32dbg: Yürütme herhangi bir nedenle win64dbg'de durduğunda, win64dbg penceresinin üst kısmına bakarak hangi kodda olduğunuzu görebileceğinizi unutmayın](<../../images/image (842).png>)

Bu gösterge, yürütmenin debug etmek istediğiniz DLL içinde durduğunu doğrular.

## GUI Uygulamaları / Video Oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bunları değiştirmek için kullanışlı bir programdır. Daha fazla bilgi:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), GNU Project Debugger (GDB) için, oyunlara odaklanan bir front-end/reverse engineering aracıdır. Bununla birlikte, reverse engineering ile ilgili her türlü iş için kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/), çeşitli decompiler'lara web arayüzü sağlayan bir araçtır. Bu web hizmeti, küçük executable dosyalarında farklı decompiler'ların çıktılarını karşılaştırmanıza olanak tanır.

## REA ile kanıta dayalı native inceleme

**REA**, Hopper, Ghidra ve IDA analizlerini CLI ve MCP üzerinden sunar. Node.js 22.x (en az 22.19), 24.x (en az 24.11) veya 26+ ve npm gerektirir. Önce mevcut bir native provider'ı yapılandırın; `rea providers --json` komutunu kontrol edin ve hedefi destekleyen birden fazla provider varsa birini açıkça seçin. Aşağıda `0x1000` yerine envanterdeki gözlemlenmiş bir işlev adını veya adresini kullanın.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Bir feature string veya symbol ile başlayın, references ve callers'ı takip edin, ardından seçilen function dossier'ı ve pseudocode'u `rea decompile` ile inceleyin. REA, bir başarısızlıktan sonra sessizce başka bir provider'a geçmek yerine oturumu seçilen provider'a bağlar. Tekrarlanabilir sorgular için `--snapshot PATH` yalnızca eşleşen artifact bytes, provider, settings, operation ve parameters değerlerini yeniden kullanır; snapshot, kaydedilmiş bir provider database'i değil, yerel bir cache'tir. Çıkarımsal yolları veya decompiler metnini özgün kaynak olarak değerlendirmek yerine döndürülen Evidence'ı ve açıkça belirtilen unknowns değerlerini koruyun.<sup>[[16]](#references)[[18]](#references)</sup>

Native add-on'lara giden JavaScript/Electron giriş noktaları için bkz. [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner ile shellcode hata ayıklama

[**BlobRunner**](https://github.com/OALabs/BlobRunner), **shellcode** için bellek ayırır, **bellek adresini** yazdırır ve yürütmeyi duraklatır.\
IDA veya x64dbg gibi bir debugger bağlayın, yazdırılan adrese bir breakpoint koyun ve shellcode'da hata ayıklamak için yürütmeye devam edin.

Releases GitHub sayfasında derlenmiş sürümleri içeren zip dosyaları bulunur: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blobrunner'ın biraz değiştirilmiş bir sürümünü aşağıdaki bağlantıda bulabilirsiniz. Derlemek için **Visual Studio Code'da bir C/C++ projesi oluşturun, kodu kopyalayıp yapıştırın ve build edin**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile shellcode hata ayıklama

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner'a benzer. Shellcode için bellek ayırır ve sonsuz bir döngüye girer. Debugger'ı bağlayın, **2–5 saniye** yürütmeye devam edin, döngünün içindeyken duraklatın ve yürütmeyi ayrılan shellcode'a aktaran sonraki call'a kadar ilerleyin.

![Debugger, ayrılan shellcode'a yapılan call'dan hemen önce jmp2it'in sonsuz döngüsünde duraklatılmış](<../../images/image (509).png>)

Derlenmiş bir [jmp2it sürümünü releases sayfasından](https://github.com/adamkramer/jmp2it/releases/) indirebilirsiniz.

### Cutter kullanarak shellcode hata ayıklama

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'ın GUI'sidir. Cutter ile shellcode'u emulate edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Open File" ve "Open Shellcode" seçenekleri sunduğunu unutmayın. Benim durumumda shellcode'u dosya olarak açtığımda doğru şekilde decompile etti, ancak shellcode olarak açtığımda etmedi:

![Cutter, aynı byte'lar dosya veya shellcode olarak açıldığında farklı analiz sonuçları gösteriyor](<../../images/image (562).png>)

Emülasyonu istediğiniz yerde başlatmak için oraya bir bp koyun; görünen o ki Cutter emülasyonu otomatik olarak o noktadan başlatacaktır:

![Cutter emülasyonunu başlatmadan önce istenen shellcode girişine breakpoint koyma](<../../images/image (589).png>)

![Cutter emulator, seçilen shellcode breakpoint'inde duraklatılmış](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görebilirsiniz:

![Cutter'ın hex dump'inde emulate edilen shellcode stack'ini görüntüleme](<../../images/image (186).png>)

### Shellcode'u deobfuscate etme ve yürütülen function'ları bulma

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) aracını deneyebilirsiniz.\
Shellcode'un hangi **function'ları** kullandığı ve bellekte kendi kendisini **decode** edip etmediği gibi bilgileri gösterir.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg ayrıca istediğiniz seçenekleri seçip shellcode'u çalıştırabileceğiniz grafiksel bir başlatıcı da içerir

![Shellcode emülasyonu ve izleme seçeneklerini belirlemek için scDbg grafiksel başlatıcısı](<../../images/image (258).png>)

**Create Dump** seçeneği, shellcode bellekte dinamik olarak değiştirilirse son halini dump eder (decode edilmiş shellcode'u indirmek için kullanışlıdır). **start offset**, shellcode'u belirli bir offset'te başlatmak için kullanışlı olabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'da hata ayıklamak için kullanışlıdır (ancak bu iş için önceki seçeneklerden herhangi birini daha iyi buluyorum; çünkü Ida veya x64dbg kullanabilirsiniz).

### CyberChef kullanarak disassemble etme

Shellcode dosyanızı girdi olarak yükleyin ve disassemble etmek için aşağıdaki tarifi kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation'ı çözme

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` gibi basit ifadeleri aritmetik (`+`, `-`, `*`) ve bit düzeyinde işleçleri (`&`, `|`, `^`, `~`, kaydırmalar) birleştiren formüllerin arkasına gizler. Önemli nokta, bu özdeşliklerin genellikle yalnızca **sabit genişlikli modüler aritmetikte** doğru olmasıdır; bu nedenle elde kalan bitler ve taşmalar önemlidir:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Bu tür bir ifadeyi genel cebir araçlarıyla basitleştirirseniz bit genişliği semantiği göz ardı edildiği için kolayca yanlış bir sonuç elde edebilirsiniz.<sup>[[1]](#references)</sup>

### Pratik iş akışı

1. Lift edilmiş kodun/IR'ın/decompiler çıktısının **orijinal bit genişliğini** koruyun (`8/16/32/64` bit).
2. Basitleştirmeye çalışmadan önce ifadeyi **sınıflandırın**:
   - **Doğrusal**: bit düzeyindeki atomların ağırlıklı toplamları
   - **Yarı doğrusal**: `x & 0xFF` gibi sabit maskelerle birlikte doğrusal ifade
   - **Polinomsal**: çarpımlar içerir
   - **Karma**: çarpımlar ve bit düzeyindeki mantık iç içe geçmiştir; genellikle yinelenen alt ifadeler bulunur
3. Aday yeniden yazımların her birini rastgele testlerle veya bir SMT ispatıyla **doğrulayın**. Eşdeğerlik ispatlanamıyorsa tahminde bulunmak yerine özgün ifadeyi koruyun.

### Dar bir yürütme dilimiyle düzleştirilmiş kontrol akışını atlatma

Kontrol akış çizgesinin tamamını yeniden oluşturmak çoğu zaman gereksizdir. Kontrol akışı düzleştirme, opak yüklemler, büyük dağıtıcılar veya MBA ağırlıklı kod söz konusu olduğunda, şifrelenmiş blob'lara ve çıktı arabelleklerine yapılan başvuruları izleyerek bunları dönüştüren en küçük rutini bulun. Ardından yalnızca bu veri akışı dilimini yeniden üretin veya bağımsız olarak yürütün; ilgili durum doğrudan başlatılabiliyorsa dağıtıcı gerekli çözümün parçası değildir.<sup>[[7]](#references)</sup>

Pratik bir iş akışı:<sup>[[7]](#references)</sup>

1. Yürütülebilir ve veri bölümlerini, relocation'ları ve çapraz başvuruları envanterleyin. Bayt sırasını ve öğe genişliğini koruyarak `.rodata` içindeki aday tabloları dökün.
2. Düz metni veya çıktı arabelleğini yazan son rutini belirleyin. Girdilerini, başvurduğu tabloları, içe aktarılan çağrıları ve gereken global durumu kaydedin.
3. Yalnızca bu işlemleri sabit genişlikli bir Python modeline aktarın. Dilim hâlâ çok fazla duruma bağlıysa tüm programı emüle etmek yerine rutini Unicorn, QEMU veya bir debugger altında çağırın ve ilgisiz içe aktarımları hook'layın.
4. Çıkarıcının çıktısını gerçekten sağlanan binary'den türettiğini doğrulayın: sessiz fallback'leri kaldırın, gömülü yanıtları arayın ve değişen dizeler, anahtarlar, tanımlayıcılar, yerleşimler ve obfuscation seed'leri içeren görülmemiş build'lerde çalıştırın.

İlk aşamada kullanışlı komutlar:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Sabit değer kılığına girmiş MBA ifadelerini tespit et

Görünüşte girdiye bağlı olan bir byte ifadesi, girdisini tamamen etkisiz hâle getirebilir. Tablolarını çıkardıktan sonra ifadeyi 8 bitlik alanın tamamında değerlendir; tek elemanlı bir çıktı kümesi, çevresindeki durum makinesini çözmeden bu byte’ın sabit olduğunu kanıtlar.<sup>[[7]](#references)</sup>

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

Son maskeyi koruyun; çünkü özgün toplama işleminde bayt genişliğinde taşma sarması vardır. Daha geniş bir alan için, bir SMT solver'a aynı genişlikteki iki sembolik girdi için `f(x1) != f(x2)` ifadesinin sağlanabilir olup olmadığını sorun: `unsat` değişmezliği kanıtlar, `sat` ise bir karşı örnek sunar ve girdinin atılamayacağı anlamına gelir.<sup>[[7]](#references)</sup>

#### Ortama bağlı çözümlemeyi tanıyın

Anti-analysis kontrollerinin dallanması veya çökmeye yol açması gerekmez. Bir decoder, sensör sonucunu bir anahtar bitine, bir opaque-predicate sabitine veya flattened-dispatcher durumuna karıştırabilir; normal şekilde çalışmayı sürdürüp emülatörde makul görünen ancak yanlış plaintext üretebilir. Bu nedenle yalnızca görünür hata dallarını yamalamak yeterli değildir; ortam yoklamalarından decoder durumuna uzanan veri bağımlılıklarını izleyin, aynı kod parçasını gerçek cihazda ve emülatörde karşılaştırın ve her sensör sonucunu zorlamanın son buffer'ı nasıl değiştirdiğini test edin.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA), malware analizi ve korumalı binary'lerin reverse engineering işlemleri için pratik bir MBA sadeleştiricisidir. Her şeye tek bir genel yeniden yazma geçişi uygulamak yerine ifadeyi sınıflandırır ve uygun özel işlem hatlarına yönlendirir.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA, ifadeyi Boolean girdiler üzerinde değerlendirir, bir imza türetir ve pattern matching, ANF dönüşümü ve katsayı interpolasyonu gibi çeşitli kurtarma yöntemlerini aynı anda dener.
- **Semilinear MBA**: Sabit maskeli atomlar, maskelenmiş bölgelerin doğruluğunu korumak için bit bölümlü yeniden oluşturmayla yeniden kurulur.
- **Polynomial/Mixed MBA**: Çarpımlar çekirdeklere ayrılır ve dış ilişki basitleştirilmeden önce yinelenen alt ifadeler geçici değişkenlere taşınabilir.

Sıklıkla kurtarılmaya değer, karma bir özdeşlik örneği:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Bu, şu şekilde sadeleştirilebilir:

```c
x * y
```

### Tersine mühendislik notları

- CoBRA'yı, tam hesaplamayı izole ettikten sonra **lifted IR ifadeleri** veya decompiler çıktısı üzerinde çalıştırmayı tercih edin.
- İfade maskelenmiş aritmetikten veya dar yazmaçlardan kaynaklanıyorsa `--bitwidth` seçeneğini açıkça kullanın.
- Daha güçlü bir kanıtlama adımına ihtiyacınız varsa buradaki yerel Z3 notlarına bakın:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca bir **LLVM pass plugin** (`libCobraPass.so`) olarak da sunulur. Bu, sonraki analiz pass'lerinden önce MBA ağırlıklı LLVM IR'yi normalleştirmek istediğinizde kullanışlıdır.
- Desteklenmeyen, carry'ye duyarlı karma alan artıkları; özgün ifadeyi koruyup carry yolunu elle incelemeniz gerektiğine işaret eder.

## XOR-state control-flow flattening'i geri kazanma

OLLVM tarzı bir flattener, geçerli basic block durumunu iki adet 64 bit yazmaçta tutup dispatcher'da XOR ile yeniden oluşturabilir. Her özgün block, sonraki duruma ait yazmaç çiftini yazar ve dispatcher'a geri dallanır. Koşullu bir block, çiftin bir yarısını CPU flag'lerine göre değiştirmek için `CMOVcc` kullanabilir; bu nedenle yalnızca görünür branch komutlarını takip etmek iki successor'ı gözden kaçırır. Indirect-jump dispatcher'dan farklı olarak bu yapı, her yerde doğrudan geri kenarlar kullanabilir.<sup>[[19]](#references)[[20]](#references)</sup>

Grafiği geri kazanmak için dispatcher karşılaştırma ağacını ve iki durum yazmacını belirleyin, karşılaştırılan her XOR durumunu hedef block'a eşleyin, ardından her özgün block'ta yazmaç çiftine ulaşan yazmaları izleyin. Koşullu yazmalarda flag'leri ayarlayan komutu ve her iki `CMOVcc` sonucunu da hesaba katın. Her block'un dispatcher çıkışını çözümlenmiş doğrudan successor'a veya koşullu branch'e dönüştürün; böylece binary'yi patch etmeden dispatcher erişilemez hâle gelir. Bu, tam bir CFG yaklaşımıdır; yalnızca tek bir decoder önemliyse yukarıdaki [dar execution-slice iş akışı](#bypass-flattened-control-flow-with-a-narrow-execution-slice) daha hızlı olabilir.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis), bu yapıyı Binary Ninja'da otomatikleştirir. `plugins/DispatchThis` klasörünü Binary Ninja kullanıcı plugin dizinine kopyalayıp yeniden başlatın. Etkilenen işlevde **Function Settings**'i açıp `OLLVM_XOR_64`'ü seçin; analiz başlamazsa **Analysis → Reanalyze All Functions** seçeneğini kullanın. Bu mod dosya byte'larını değil, MLIL control-flow kenarlarını yeniden yazar ve Z3'e ya da indirect-jump resolver'a ihtiyaç duymaz. Binary Ninja 5.3.9757+ sürümlerinde denenmiştir; block başına ölü durum yazmalarını kaldırmaz, bu nedenle bunları hâlâ canlı olan geçişlerle karıştırmayın.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, program işlemlerini `mov` tabanlı komut dizileriyle değiştirir ve control flow'u değiştirmek için signal/exception handling kullanır. Ayrıntılar için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Desteklenen binary'lerde [demovfuscator](https://github.com/kirschju/demovfuscator) sonucu deobfuscate edebilir. Birkaç bağımlılığı vardır.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Ve [keystone'u yükleyin](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Bir **CTF oynuyorsanız, flag'i bulmaya yönelik bu workaround** çok işinize yarayabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**Entry point**'i bulmak için fonksiyonlarda `::main` ifadesini arayın. Örneğin:

![Ghidra'da fonksiyon adlarında çift iki nokta üst üste ve main ifadesini arayarak Rust entry point'ini bulma](<../../images/image (1080).png>)

Bu durumda binary'nin adı authenticator'dı; dolayısıyla bunun ilgi çekici main fonksiyonu olduğu oldukça açık.\
Çağrılan **fonksiyonların** **adlarını** öğrendikten sonra, **input** ve **output**'larını öğrenmek için **İnternet**'te arayın.

### ELF firmware'inden Rust string'lerini kurtarma

**Rust ELF** binary'lerinde birçok statik string, C tarzı NUL sonlandırmalı pointer'lar tarafından referans gösterilmez. Yaygın bir `rustc` yerleşiminde, gerçek string blob'una işaret eden bir **pointer/length tuple'ı** **`.data.rel.ro`** içinde bulunur; string blob'u ise **`.rodata`** içinde saklanır:

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
2. **`.data.rel.ro`** bölümünü her seferinde bir word olacak şekilde sıralayın.
3. `.rodata` adres aralığındaki her değeri olası bir string pointer olarak değerlendirin.
4. Sonraki word'ü olası uzunluk olarak değerlendirin.
5. Makuliyet filtreleri uygulayın (örneğin, uzunluğu **4** ile **100** bayt arasında olanları tutun).
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

Bu, firmware tersine mühendisliğinde özellikle kullanışlıdır; çünkü kurtarılan Rust dizeleri genellikle **HTTP route'larını, RPC adlarını, günlük mesajlarını, assertion'ları, dosya adlarını, config anahtarlarını, komut işleyicilerini ve auth ile ilgili mantığı** ortaya çıkarır.

Ghidra bu dizeleri bulamazsa aynı sezgisel yöntemi uygulayan ve başvurulan `.rodata` ofsetlerinde string verileri oluşturan özel bir script/plugin çalıştırın. Pen Test Partners tarafından yayımlanan `rust-strings` ve `RustStrings.py` araçları, bu fikri diğer **word size'lara, endianness türlerine ve section düzenlerine** uyarlamak için iyi referanslardır.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi ile derlenmiş binary'ler için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Bir Delphi binary'sini tersine mühendislikle incelemeniz gerekiyorsa IDA plugin'i [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

Bir Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu plugin, debugging başladığında binary'yi çalıştırıp fonksiyon adlarını dinamik olarak çözer. Debugging'i başlattıktan sonra Start düğmesine (yeşil düğme veya f9) tekrar basın; gerçek kodun başlangıcında bir breakpoint'e ulaşılır.

Grafik uygulamasında bir düğmeye basarsanız debugger, o düğmenin çağırdığı fonksiyonda durabilir.

## Golang

Standart Go binary'leri için [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper), runtime yapılarını kurtarabilir ve IDA'daki fonksiyon adlarını iyileştirebilir. Python plugin'ini yüklemek için **Alt+F7** tuşlarına basın.

Bir Golang binary'sini tersine mühendislikle incelemeniz gerekiyorsa IDA plugin'i [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm.

Bir Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu, fonksiyon adlarını çözer.

### Sembol tablosu olmadan metadata'yı kurtarma

Stripped bir Go executable'ı, program counter'ları fonksiyonlara eşlemek için yine de runtime metadata'ya ihtiyaç duyar. [GoReSym](https://github.com/mandiant/GoReSym), Go runtime'ından türetilen kodu kullanarak `pclntab` ve `moduledata` gibi yapıları bulup ayrıştırır. Böylece geleneksel sembol tablosuna bağlı kalmadan fonksiyon sınırları, adlar, kaynak yolları, türler ve build ayrıntıları kurtarılabilir.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Bir obfuscator, kurtarılan adları değiştirirken bu yapıları kullanılabilir durumda bırakabilir. Örneğin Garble, tanımlayıcıları ve package path'lerini hash'ler; build, module ve debug bilgilerini kaldırır.<sup>[[12]](#references)</sup> Obfuscate edilmiş package token'ı, o package'teki işlevlerde tutarlı kalmalıdır. İşlevleri tekrarlanan token'a göre gruplayın, çağırdığı işlevlerden, string'lerden ve API'lerden bir package çıkarımı yapın, ardından bu package etiketini grubun tamamına uygulayın.<sup>[[13]](#references)</sup>

### GoResolver ile Garble adlarını kurtarma

[GoResolver](https://github.com/volexity/GoResolver), runtime sembolü çıkarımını temiz referans oluşturma ve kontrol akış grafiği (CFG) eşleştirmesiyle birleştirir. Şu sırayı izleyin:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler sürümünü belirleyin.** Önce `BuildInfo` ve gömülü sürüm string'lerini deneyin. Obfuscator bunları kaldırdıysa, Go runtime'ın paketlenmiş bölümlerini sürümlü referans runtime'larla karşılaştırın. Volexity'nin testlerinde runtime'ın yaklaşık `2%`'si, ana Go sürümlerini ayırt etmek için yeterliydi. Bunu evrensel bir eşik değil, deneysel bir optimizasyon olarak değerlendirin.<sup>[[13]](#references)</sup>
2. **Eşleşen referanslar oluşturun.** Belirlenen Go sürümü, hedef mimari ve olası kütüphaneler için temiz binary'ler oluşturun. Toolchain'in eşleşmesi, compiler tarafından oluşturulan CFG farklılıklarını azaltır.<sup>[[10]](#references)[[13]](#references)</sup>
3. **İşlevleri karşılaştırın.** GoGrapher, işlev CFG'lerini eşleştirir ve `0.0` ile `1.0` arasında normalize edilmiş skorlar üretir. Temel blok eşleştirmesi, benzer instruction'ların ağırlıklı karşılaştırmasına dayanır. Yüksek güvenli eşleşmeler, rastgeleleştirilmiş işlevleri temiz implementasyonla eşleştirir. Daha zayıf eşleşmeler yine de bir package veya module'ü belirleyebilir.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Doğrulayın ve içe aktarın.** Önerilen adları çağrı ilişkileri, sabitler, string'ler ve yan etkilerle doğrulayın; ardından JSON raporunu IDA veya Ghidra için GoResolver plugin'iyle içe aktarın.<sup>[[10]](#references)[[13]](#references)</sup>

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

Varsayılan anlamlı eşleşme eşiği `0.9` değeridir. `--extract` ve `--graph` seçenekleri aşamalardan birini yalıtabilir; varsayılan ayar ise kurtarılan runtime metadata ile CFG kanıtları birbirini tamamladığı için her iki aşamayı da çalıştırır.<sup>[[10]](#references)</sup> CFG puanları sezgiseldir: inlining, build flags, mimari ve library sürümü farklılıkları grafiğin şeklini değiştirebilir; bu nedenle düşük güvenli adları zorla atamak yerine çözümlenmemiş işlevleri koruyun.<sup>[[13]](#references)</sup>

### Go string tablosunu kurtarma

Go binary dosyaları, bağlı her paketteki string byte’larını tek bir bitişik tabloda tutar. Girdiler NUL ile sonlandırılmaz ve runtime yapıları tablonun başlangıç adresini veya boyutunu göstermez. Ancak derleyici girdileri tüm işletim sistemleri ve mimarilerde önce uzunluğa, sonra alfabetik sıraya göre düzenler. Bu nedenle bir girdi bulduktan sonra analist bitişik girdiler arasında ilerleyebilir ve string’leri kodla ilişkilendirmek için veri çapraz referanslarını kullanabilir.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor), bu iş akışını IDA Pro ve Ghidra’da otomatikleştirir. Eklenti veri segmenti çapraz referanslarına bağlı olduğundan önce otomatik analizin tamamlanmasını bekleyin. Varsayılan anchor, `entersyscall` runtime string’idir. Ardından eklenti her iki yönde tarama yapabilir, kurtarılan string’leri veritabanında tanımlayabilir ve string’leri bunlara başvuran işlevlerle eşleştiren bir JSON çıktısı oluşturabilir.<sup>[[14]](#references)</sup>

Bağlı library’lerin oluşturduğu gürültüyü uygulama veya malware kodundan ayırmak için raporu, başvuran işlevin paketine göre filtreleyin. Bu teknik, Garble’ın `-literals` dönüşümü gibi obfuscation yöntemleriyle yok edilmiş literal’leri kurtaramaz. Yine de obfuscation uygulanmamış runtime string’lerini düzenlemeye yardımcı olabilir.<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime türlerini kurtarma

Go, garbage collection gibi özellikler tarafından kullanılan runtime tür bilgilerini binary dosyalara gömer. Build bilgileri kaldırıldığında veya disassembler bu metadata’yı ayrıştıramadığında, talimatlar gelişigüzel veri adreslerini yüklüyormuş gibi görünebilir ve hedef bölge tür bilgisi olmadan kalır. Metadata’yı kurtarmak, bu adresleri okunabilir tür referanslarına dönüştürür ve paketlerin yeteneklerini anlamayı kolaylaştırır.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver), sembolleri çıkarabilir ve runtime türlerini ayrıştırarak JSON raporu oluşturabilir. Güncel CLI, `resolve` alt komutunu kullanır:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` seçeneği type parsing'i etkinleştirir. Kurtarılan türleri tanımlamak ve bunların referanslarını analiz veritabanına uygulamak için raporu GoResolver'ın IDA Pro veya Ghidra plugin'i ile içe aktarın. Bu özelliğin kullanıma sunulduğu rapor formatında, `-y` seçeneği kullanılmadığında RTTI adresi ve kurtarılan türler üyeleri null olur.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver; x86, AMD64, ARM ve ARM64 için PE, ELF ve Mach-O örneklerini destekler. Bu nedenle aynı iş akışı Windows, Linux ve macOS'tan Go binary'leri için de geçerlidir.<sup>[[10]](#references)</sup>

## Derlenmiş Python

Bu sayfada, ELF/EXE olarak derlenmiş bir Python binary'sinden Python kodunu nasıl elde edebileceğinizi bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Bir GBA oyununun **binary** dosyasını edindiyseniz, onu **emulate** etmek ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_debug sürümünü indirin_) - Arayüzlü bir debugger içerir
- [**mgba** ](https://mgba.io)- CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin'i
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin'i

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünde Game Boy Advance **düğmelerine** nasıl basılacağını görebilirsiniz.

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Her **tuşa basıldığında, tuşu tanımlamak için bir değer** kullanılır:

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

Yani bu tür bir programda ilginç olan kısım **programın kullanıcı girdisini nasıl işlediği** olacaktır. **0x4000130** adresinde sıkça karşılaşılan **KEYINPUT** işlevini bulabilirsiniz.

![0x4000130 adresinde KEYINPUT'e başvuran bir GBA binary dosyasının Ghidra görünümü](<../../images/image (447).png>)

Önceki görselde, işlevin **FUN_080015a8**'den çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

Bu işlevde, bazı önemsiz başlatma işlemlerinin ardından:

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

Son if, **`uVar4`**'ün önceki Keys içinde olup mevcut tuş olmadığını kontrol ediyor; bu, bir tuşu bırakmak olarak da adlandırılır (mevcut tuş **`uVar1`** içinde saklanır).

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
- Ardından değer **8** ile (**START** düğmesi) karşılaştırılır; bu challenge'da bu yol, girilen kodun geçerli olup olmadığını kontrol eder.
  - Bu durumda **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılır ve değer aynıysa bazı kodlar yürütülür.
- Diğer tüm durumlarda bir sayaç (`DAT_030000d4`) kontrol edilip artırılır.\
  Sayaç 8'in altındayken basılan tuşların değerleri `DAT_030000d8` içinde biriktirilir.

Dolayısıyla bu challenge'da, düğmelerin değerlerini bildiğinizde, toplamı 0xf3 olan ve uzunluğu 8'den küçük bir kombinasyona **basmanız gerekiyordu.**

**Bu eğitim için kaynak:** [Nostalgia challenge çözüm yazısının arşivlenmiş hâli](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [3] [Rust string'lerini çözümleme - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing eğitimi (arşivlenmiş)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI destekli Reverse Engineering'i alt etmek (ya da en azından denemek)](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic Block Matching'e Dayalı Control Flow Graph'larını Karşılaştırma Yaklaşımı](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repository](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mekanizması](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Golang binary'lerini otomatik olarak deobfuscate etmek için Control-Flow Graph benzerliğini kullanma](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repository](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang araçlarında güncellemeler](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Her Şeyi Tersine Mühendislikle İnceleyin](https://github.com/morluto/rea)
- [17] [REA managed-code analizi](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI ve Evidence kılavuzu](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninja control-flow unflattening iş akışı](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF Zero-Day saldırısı, Java Loader, Web Shell ve AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
{{#include ../../banners/hacktricks-training.md}}
