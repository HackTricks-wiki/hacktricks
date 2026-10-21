# Reversing Araçları ve Temel Yöntemler

{{#include ../../banners/hacktricks-training.md}}

## ImGui Tabanlı Reversing Araçları

Yazılım:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg user-mode otomasyonu

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows exception-driven control flow

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Windows kernel debugging

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Çevrimiçi:

- wasm'den (binary) wat'e (düz metin) **decompile** etmek için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) adresini kullanın.
- wat'ten wasm'e **compile** etmek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) adresini kullanın.
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

dotPeek, **kitaplıklar** (.dll), **Windows metadata dosyaları** (.winmd) ve **çalıştırılabilir dosyalar** (.exe) dahil olmak üzere birden fazla formatı **decompile edip inceleyen** bir decompiler'dır. Decompile edildikten sonra bir assembly, Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantaj, kayıp bir kaynak kodun eski bir assembly'den geri yüklenmesi gerektiğinde bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilmiş kodda kolay gezinme olanağı sunarak onu **Xamarin algoritma analizi** için ideal araçlardan biri hâline getirir.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in modeli ve aracı tam ihtiyaçlarınıza göre uyarlayan bir API ile .NET Reflector zamandan tasarruf sağlar ve geliştirmeyi kolaylaştırır. Bu aracın sunduğu kapsamlı reverse engineering hizmetlerine göz atalım:

- Verilerin bir kitaplık veya bileşen içinde nasıl aktığına dair bilgi sağlar.
- .NET dilleri ve framework'lerinin uygulama biçimi ve kullanımı hakkında bilgi sağlar.
- Kullanılan API'lerden ve teknolojilerden daha fazla yararlanmak için belgelenmemiş ve dışa açılmamış işlevleri bulur.
- Bağımlılıkları ve farklı assembly'leri bulur.
- Kodunuzdaki, üçüncü taraf bileşenlerdeki ve kitaplıklardaki hataların tam konumunu belirler.
- Çalıştığınız tüm .NET kodlarının kaynağında debug yapar.

### [ILSpy](https://github.com/icsharpcode/ILSpy) ve [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy eklentisi](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir işletim sisteminde kullanabilirsiniz (VSCode içinden doğrudan yükleyebilirsiniz; git'i indirmeniz gerekmez. **Extensions**'a tıklayıp **ILSpy** aratın).\
Yeniden **decompile**, **modify** ve **recompile** etmeniz gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak bakımı yapılan bir fork'u olan [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) aracını kullanabilirsiniz. (Bir fonksiyonun içindeki bir şeyi değiştirmek için **Right Click -> Modify Method**.)

### REA ile çalıştırma gerektirmeyen managed inceleme

**REA**, assembly'yi yüklemeden PE/CLI metadata ve CIL'i inceleyebilir. Önce artifact kimliğini belirleyin, ardından üyeleri ve tanımlanmış native sınırları inceleyin. Bu, bir decompiler kullanmadan veya programı çalıştırmadan önce şüpheli çağrıları gözden geçirirken yararlıdır.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Sürüm farklarını karşılaştırmak için `compare_managed_members`, metadata token'larını derlemeler arasında sabit kabul etmek yerine ham CIL/imza kimliğini ve decoded-instruction parmak izlerini kullanır. Bir P/Invoke bildirimi, native kodun çalıştığının kanıtı değildir; bu sınırı denetlemek için `verify_managed_native_boundaries` işlevinin eşleşen bir native export veya işlev kanıtına ihtiyacı vardır. Artifact özeti, MVID ve çözümlenmemiş eşlemeleri sonuçla birlikte saklayın.<sup>[[17]](#references)</sup>

### DNSpy Günlükleme

**DNSpy'nin bazı bilgileri bir dosyaya kaydetmesini** sağlamak için şu kod parçasını kullanabilirsiniz:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Hata Ayıklama

DNSpy kullanarak kodda hata ayıklamak için şunları yapmanız gerekir:

İlk olarak, **hata ayıklamayla** ilgili **Assembly özniteliklerini** değiştirin:

![DNSpy Logging - DNSpy Hata Ayıklama: İlk olarak, hata ayıklamayla ilgili Assembly özniteliklerini değiştirin](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: Ve compile'a tıklayın](<../../images/image (314) (1).png>)

Ardından yeni dosyayı _**File >> Save module...**_ aracılığıyla kaydedin:

![DNSpy Logging - DNSpy Debugging: Ardından yeni dosyayı File Save module aracılığıyla kaydedin](<../../images/image (602).png>)

Bunu yapmak gerekir; aksi takdirde **runtime** sırasında koda çeşitli **optimizasyonlar** uygulanır ve **debugging** sırasında bir **breakpoint'e hiç ulaşılmaması** veya bazı **değişkenlerin mevcut olmaması** mümkündür.

Ardından, .NET uygulamanız **IIS** tarafından **çalıştırılıyorsa**, uygulamayı şu şekilde **yeniden başlatabilirsiniz**:

```
iisreset /noforce
```

Ardından debugging işlemini başlatmak için açık olan tüm dosyaları kapatın ve **Debug Tab** içinden **Attach to Process...** seçeneğini seçin:

![DNSpy Logging - DNSpy Debugging: Ardından debugging işlemini başlatmak için açık olan tüm dosyaları kapatın ve Debug Tab içinden Attach to Process seçeneğini seçin](<../../images/image (318).png>)

**IIS server**'a bağlanmak için **w3wp.exe**'yi seçin ve **attach**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: IIS server'a bağlanmak için w3wp.exe'yi seçin ve attach'e tıklayın](<../../images/image (113).png>)

Şimdi süreci debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce _Debug >> Break All_ seçeneğine, ardından _**Debug >> Windows >> Modules**_ seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Şimdi süreci debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Şimdi süreci debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (834).png>)

**Modules** içindeki herhangi bir modüle tıklayın ve **Open All Modules** seçeneğini seçin:

![DNSpy Logging - DNSpy Debugging: Modules içindeki herhangi bir modüle tıklayın ve Open All Modules seçeneğini seçin](<../../images/image (922).png>)

**Assembly Explorer** içindeki herhangi bir modüle sağ tıklayın ve **Sort Assemblies**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer içindeki herhangi bir modüle sağ tıklayın ve Sort Assemblies'e tıklayın](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'leri Debug Etme

### IDA Kullanarak

- **rundll32'yi yükleyin** (64 bit için C:\Windows\System32\rundll32.exe, 32 bit için C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** debugger'ını seçin
- "**Suspend on library load/unload**" seçeneğini seçin

![Debugging DLLs - Using IDA: " Suspend on library load/unload " seçeneğini seçin](<../../images/image (868).png>)

- **DLL'nin yolunu** ve çağırmak istediğiniz fonksiyonu belirterek çalıştırmanın **parametrelerini** yapılandırın:

![Debugging DLLs - Using IDA: DLL'nin yolunu ve çağırmak istediğiniz fonksiyonu belirterek çalıştırmanın parametrelerini yapılandırın](<../../images/image (704).png>)

Ardından debugging'i başlattığınızda **her DLL yüklendiğinde çalıştırma durur**; rundll32 DLL'nizi yüklediğinde çalıştırma duracaktır.

Bu yöntem, modül yükleme olaylarında durur; ancak yüklenen DLL'nin giriş noktasına ulaşmak, aşağıdaki x64dbg iş akışına kıyasla daha dolaylıdır.

### x64dbg/x32dbg Kullanarak

- **rundll32'yi yükleyin** (64 bit için C:\Windows\System32\rundll32.exe, 32 bit için C:\Windows\SysWOW64\rundll32.exe)
- **Komut satırını değiştirin** ( _File --> Change Command Line_ ) ve DLL'nin yolunu ve çağırmak istediğiniz fonksiyonu belirtin. Örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ bölümünü açın ve "**DLL Entry**" seçeneğini seçin.
- Ardından **çalıştırmayı başlatın**; debugger her dll main'de durur ve bir noktada **DLL'nizin DLL Entry noktasında durur**. Buradan, breakpoint koymak istediğiniz noktaları aramanız yeterlidir.

Çalıştırma herhangi bir nedenle win64dbg'de durduğunda, **win64dbg penceresinin üst kısmına** bakarak **hangi kodun içinde olduğunuzu** görebilirsiniz:

![Using IDA - Using x64dbg/x32dbg: Çalıştırma herhangi bir nedenle win64dbg'de durduğunda, win64dbg penceresinin üst kısmına bakarak hangi kodun içinde olduğunuzu görebilirsiniz](<../../images/image (842).png>)

Bu gösterge, çalıştırmanın debug etmek istediğiniz DLL'nin içinde durduğunu doğrular.

## GUI Uygulamaları / Video Oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bunları değiştirmek için kullanışlı bir programdır. Daha fazla bilgi:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), oyunlara odaklanan, GNU Project Debugger (GDB) için bir ön uç/tersine mühendislik aracıdır. Ancak tersine mühendislikle ilgili her türlü iş için kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/), çeşitli decompiler'lara yönelik web tabanlı bir ön uçtur. Bu web hizmeti, küçük çalıştırılabilir dosyalarda farklı decompiler'ların çıktısını karşılaştırmanıza olanak tanır.

## REA ile kanıta dayalı native inceleme

**REA**, Hopper, Ghidra ve IDA analizlerini CLI ve MCP üzerinden sunar. Node.js 22.x (en az 22.19), 24.x (en az 24.11) veya 26+ sürümünü ve npm'yi gerektirir. Önce mevcut bir native provider'ı yapılandırın; `rea providers --json` komutunu kontrol edin ve hedefi destekleyen birden fazla provider varsa birini açıkça seçin. Aşağıda `0x1000` yerine envanterde gözlemlenmiş bir fonksiyon adını veya adresini kullanın.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Bir feature string veya symbol ile başlayın, references ve callers'ı izleyin, ardından seçilen function dossier'ını ve pseudocode'u `rea decompile` ile inceleyin. REA, bir hata sonrasında sessizce başka bir provider'a geçmek yerine oturumu seçilen provider'a bağlar. Tekrarlanabilir sorgular için `--snapshot PATH`, yalnızca eşleşen artifact bytes, provider, settings, operation ve parameters değerlerini yeniden kullanır; snapshot, yerel bir cache'tir, kaydedilmiş bir provider database değildir. Döndürülen Evidence'ı ve açıkça belirtilen unknowns değerlerini koruyun; çıkarımla belirlenen yolları veya decompiler metnini orijinal source olarak değerlendirmeyin.<sup>[[16]](#references)[[18]](#references)</sup>

JavaScript/Electron entry point'lerinden native add-on'lara giden yollar için bkz. [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Yerel TCP bridge ile betiklenmiş IDA ve Ghidra analizi

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge), **önceden açılmış** bir IDA database'i veya Ghidra CodeBrowser programı içinde çalışır ve ayrı bir script'in o analiz database'ini sorgulayıp değiştirmesine olanak tanır. IDA'nın Python CLI'ından `ID_Server.py` dosyasını (`import ID_Server`), Ghidra'nın Script Manager'ından ise `Ghidra_Server.py` dosyasını çalıştırın. IDA, `127.0.0.1` adresinde `5073` numaralı porttan başlayarak daha yüksek portları tarar. Mevcut Ghidra script'i `5093` numaralı porttan başlar ve `5102` dahil on portu dener; Java socket'i yalnızca loopback'e değil, tüm adreslere bağlanır. Bağlanmadan önce instance'ın yazdırdığı portu kontrol edin. Headless analyzer'dan farklı olarak bu bridge, o GUI instance'ında o anda açık olan program üzerinde çalışır.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

**Her bağlantı için satır sonuyla biten tek bir komut gönderin** ve satır sonuyla biten yanıtı okuyun. Sonuç genellikle JSON'dur. Örneğin, bir input path ile ilgili imported API'yi bulduktan sonra `IMPORTXREF`, çağrı noktalarını bulur; `DECOMP_XREF` ise seçilen bir adresin callers'ını toplu olarak decompile eder. `FUNC` bir function'ı incelerken `PCODE`, decompiler'ın ara gösterimini döndürür. Farklı bir base address'e göre yeniden konumlandırılmış bir binary'den kopyalanan adresi değil, etkin database'deki adresi kullanın. Aşağıdaki örnek IDA'nın varsayılan portunu kullanır; Ghidra için script'in yazdırdığı portu kullanın.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Aynı kanal **analiz veritabanını değiştirebilir**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` ve `PATCH`; adları, türleri, yapı tanımlarını, fonksiyon sınırlarını veya saklanan baytları değiştirir. `PATCH`, **veritabanında yapılan bir düzenlemedir**; canlı bir süreçte patch uygulandığının kanıtı değildir. Hiçbir listener kimlik doğrulamayı belgelemez. IDA yalnızca loopback üzerinden erişilebilir, ancak Ghidra ağ arayüzleri üzerinden erişilebilir olabilir; Ghidra listener'ını kullanırken erişimi kısıtlayın. `QUIT` her iki listener'ı da durdurur; ayrıca IDA, `ida_bridge_stop()` işlevini sunar.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner ile shellcode hata ayıklama

[**BlobRunner**](https://github.com/OALabs/BlobRunner), **shellcode** için bellek ayırır, **bellek adresini** yazdırır ve çalıştırmayı duraklatır.\
IDA veya x64dbg gibi bir debugger bağlayın, yazdırılan adrese breakpoint koyun ve shellcode'da hata ayıklamak için çalıştırmayı sürdürün.

GitHub releases sayfasında derlenmiş sürümleri içeren zip dosyaları bulunur: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Aşağıdaki bağlantıda Blobrunner'ın biraz değiştirilmiş bir sürümünü bulabilirsiniz. Derlemek için **Visual Studio Code'da bir C/C++ projesi oluşturmanız, kodu kopyalayıp yapıştırmanız ve build etmeniz** yeterlidir.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile shellcode hata ayıklama

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner'a benzer. Shellcode için bellek ayırır ve sonsuz bir döngüye girer. Debugger'ı bağlayın, **2–5 saniye** boyunca çalıştırmayı sürdürün, döngünün içinde duraklatın ve ayrılan shellcode'a yürütmeyi aktaran bir sonraki çağrıya kadar ilerleyin.

![jmp2it'in sonsuz döngüsünde, ayrılan shellcode'a yapılan çağrının hemen öncesinde duraklatılmış debugger](<../../images/image (509).png>)

Derlenmiş bir [jmp2it sürümünü releases sayfasından](https://github.com/adamkramer/jmp2it/releases/) indirebilirsiniz.

### Cutter kullanarak shellcode hata ayıklama

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'ın GUI'sidir. Cutter ile shellcode'u emulate edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Open File" ve "Open Shellcode" seçeneklerini sunduğunu unutmayın. Benim durumumda shellcode'u dosya olarak açtığımda doğru şekilde decompile etti, ancak shellcode olarak açtığımda doğru şekilde decompile etmedi:

![Aynı baytları dosya veya shellcode olarak açtığında farklı analiz sonuçları gösteren Cutter](<../../images/image (562).png>)

Emülasyonu istediğiniz konumda başlatmak için oraya bir bp koyun; görünüşe göre Cutter emülasyonu otomatik olarak o konumdan başlatıyor:

![Cutter emülasyonunu başlatmadan önce istenen shellcode giriş noktasına breakpoint koyma](<../../images/image (589).png>)

![Seçilen shellcode breakpoint'inde duraklatılmış Cutter emülatörü](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görüntüleyebilirsiniz:

![Emüle edilmiş shellcode stack'inin Cutter'ın hex dump'ında görüntülenmesi](<../../images/image (186).png>)

### Shellcode'u deobfuscate etme ve çalıştırılan fonksiyonları bulma

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) aracını deneyebilirsiniz.\
Shellcode'un hangi **fonksiyonları** kullandığı ve bellekte kendini **decode** edip etmediği gibi bilgileri gösterir.

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

**Create Dump** seçeneği, shellcode bellekte dinamik olarak değiştirilirse son halini döker (çözümlenmiş shellcode'u indirmek için kullanışlıdır). **start offset**, shellcode'u belirli bir offset'ten başlatmak için kullanışlı olabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'da hata ayıklamak için kullanışlıdır (ancak bu amaçla önceki seçeneklerden herhangi birini daha iyi buluyorum; çünkü IDA veya x64dbg kullanabilirsiniz).

### CyberChef kullanarak Disassemble etme

Shellcode dosyanızı girdi olarak yükleyin ve onu disassemble etmek için şu tarifi kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` gibi basit ifadeleri aritmetik (`+`, `-`, `*`) ve bit düzeyinde işleçleri (`&`, `|`, `^`, `~`, kaydırmalar) birleştiren formüllerin arkasına gizler. Önemli nokta, bu özdeşliklerin genellikle **sabit genişlikli modüler aritmetik** altında doğru olmasıdır; bu nedenle elde oluşumu ve taşmalar önem taşır:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Bu tür bir ifadeyi genel cebir araçlarıyla sadeleştirirseniz, bit genişliği semantiği göz ardı edildiği için kolayca yanlış sonuç elde edebilirsiniz.<sup>[[1]](#references)</sup>

### Uygulamalı iş akışı

1. **Orijinal bit genişliğini koruyun**: yükseltilmiş kod/IR/decompiler çıktısındaki (`8/16/32/64` bit) genişliği kullanın.
2. **Sadeleştirmeye çalışmadan önce ifadeyi sınıflandırın**:
   - **Doğrusal**: bit düzeyindeki atomların ağırlıklı toplamları
   - **Yarı doğrusal**: `x & 0xFF` gibi sabit maskelerle birlikte doğrusal ifadeler
   - **Polinom**: çarpımların yer aldığı ifadeler
   - **Karma**: çarpımlar ile bit düzeyindeki mantığın iç içe geçtiği, genellikle yinelenen alt ifadeler içeren ifadeler
3. **Aday her yeniden yazımı** rastgele testlerle veya bir SMT kanıtıyla doğrulayın. Eşdeğerlik kanıtlanamıyorsa tahmin yürütmek yerine özgün ifadeyi koruyun.

### Dar bir yürütme dilimiyle düzleştirilmiş control flow'u aşın

Control-flow graph'ın tamamını çıkarmak çoğu zaman gereksizdir. Control-flow flattening, opaque predicates, büyük dispatcher'lar veya MBA ağırlıklı kod içeren durumlarda, şifrelenmiş blob'lara ve çıktı buffer'larına yapılan referansları izleyerek bunları dönüştüren en küçük rutini bulun. Ardından yalnızca bu data-flow slice'ı yeniden oluşturun veya bağımsız olarak yürütün; ilgili state doğrudan başlatılabiliyorsa dispatcher gerekli çözümün parçası değildir.<sup>[[7]](#references)</sup>

Uygulamalı bir iş akışı:<sup>[[7]](#references)</sup>

1. Çalıştırılabilir ve veri bölümlerini, relocation'ları ve çapraz referansları envanterleyin. Aday tabloları `.rodata` bölümünden, byte sıralamasını ve eleman genişliğini koruyarak alın.
2. Plaintext'i veya çıktı buffer'ını yazan son rutini belirleyin. Girdilerini, referans verdiği tabloları, import edilmiş çağrıları ve gerekli global state'i kaydedin.
3. Yalnızca bu işlemleri sabit genişlikli bir Python modeline aktarın. Dilim hâlâ çok fazla state'e bağlıysa tüm programı emüle etmek yerine rutini Unicorn, QEMU veya bir debugger altında çağırıp ilgisiz import'lara hook ekleyin.
4. Extractor'ın çıktısını gerçekten sağlanan binary'den türettiğini doğrulayın: sessiz fallback'leri kaldırın, gömülü yanıtları arayın ve değişen string'ler, anahtarlar, tanımlayıcılar, yerleşimler ve obfuscation seed'leri içeren, daha önce görülmemiş build'ler üzerinde çalıştırın.

İlk aşamada kullanılabilecek komutlar:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Sabit gibi gizlenmiş MBA ifadelerini tespit etme

Görünüşte girdiye bağlı olan bir byte ifadesi, girdisini tamamen yok edebilir. Tablolarını çıkardıktan sonra ifadeyi 8 bitlik alanın tamamında değerlendirin; tek elemanlı bir çıktı kümesi, çevresindeki durum makinesini çözmeden bu byte'ın sabit olduğunu kanıtlar.<sup>[[7]](#references)</sup>

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

Son maskeyi koruyun; çünkü özgün toplama işleminde byte genişliğinde taşma vardır. Daha geniş bir etki alanı için, bir SMT solver'a aynı genişlikteki iki sembolik girdi için `f(x1) != f(x2)` ifadesinin sağlanabilir olup olmadığını sorun: `unsat` değişmezliği kanıtlar; `sat` ise bir karşı örnek sunar ve girdinin göz ardı edilemeyeceği anlamına gelir.<sup>[[7]](#references)</sup>

#### Ortama bağlı çözümlemeyi tanıyın

Anti-analysis kontrollerinin dallanması veya çökmeye yol açması gerekmez. Bir decoder, sensör sonucunu bir anahtar bitine, opaque predicate sabitine veya düzleştirilmiş dispatcher durumuna karıştırabilir; normal şekilde çalışmaya devam edip emülatörde makul görünen ancak yanlış bir plaintext üretebilir. Bu nedenle yalnızca görünür hata dallarını patch'lemek yeterli değildir; ortam problarından decoder durumuna uzanan veri bağımlılıklarını izleyin, aynı kod parçasını gerçek cihazda ve emülatörde karşılaştırın ve her sensör sonucunu zorlamanın son buffer'ı nasıl değiştirdiğini test edin.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA), zararlı yazılım analizi ve korumalı binary'leri reverse engineering için pratik bir MBA sadeleştiricisidir. İfadeyi sınıflandırır ve her şeye tek bir genel yeniden yazma geçişi uygulamak yerine, ifadeyi özelleştirilmiş işlem hatlarına yönlendirir.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA, ifadeyi Boolean girdiler üzerinde değerlendirir, bir imza çıkarır ve pattern matching, ANF dönüşümü ve katsayı interpolasyonu gibi çeşitli recovery yöntemlerini yarıştırır.
- **Semilinear MBA**: Sabit maskeli atomlar, maskelenmiş bölgelerin doğruluğunu koruyan bit bölümlü yeniden yapılandırmayla yeniden oluşturulur.
- **Polynomial/Mixed MBA**: Çarpımlar çekirdeklerine ayrılır ve dış ilişki sadeleştirilmeden önce tekrarlanan alt ifadeler geçici değişkenlere taşınabilir.

Sıklıkla kurtarılmaya değer, karma bir özdeşlik örneği:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Bu, şu şekilde sadeleştirilebilir:

```c
x * y
```

### Tersine mühendislik notları

- CoBRA'yı **lifted IR ifadeleri** veya tam hesaplamayı izole ettikten sonra decompiler çıktısı üzerinde çalıştırmayı tercih edin.
- İfade maskelenmiş aritmetikten veya dar yazmaçlardan kaynaklanıyorsa `--bitwidth` seçeneğini açıkça kullanın.
- Daha güçlü bir kanıtlama adımına ihtiyacınız varsa buradaki yerel Z3 notlarına bakın:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca **LLVM pass plugin** (`libCobraPass.so`) olarak da gelir. Bu, sonraki analiz pass'lerinden önce MBA ağırlıklı LLVM IR'yi normalize etmeniz gerektiğinde kullanışlıdır.
- Desteklenmeyen, carry'ye duyarlı karma-domain kalıntıları, özgün ifadeyi koruyup carry yolunu elle incelemeniz gerektiğinin işareti olarak değerlendirilmelidir.

## XOR-state control-flow flattening'i geri çıkarma

OLLVM tarzı bir flattener, geçerli basic block durumunu iki adet 64-bit yazmaçta tutabilir ve dispatcher'da XOR ile yeniden oluşturabilir. Her özgün block, sonraki durumu için yazmaç çiftini yazar ve dispatcher'a geri dallanır. Koşullu bir block, CPU flag'lerine göre çiftin bir yarısını değiştirmek için `CMOVcc` kullanabilir; bu nedenle yalnızca görünür branch talimatlarını izlemek iki ardılı gözden kaçırır. Indirect-jump dispatcher'dan farklı olarak bu yapı, her yerde doğrudan geri kenarlar kullanabilir.<sup>[[19]](#references)[[20]](#references)</sup>

Grafiği geri çıkarmak için dispatcher karşılaştırma ağacını ve iki durum yazmacını belirleyin; karşılaştırılan her XOR durumunu hedef block ile eşleyin, ardından özgün her block'taki yazmaç çiftine ulaşan yazmaları izleyin. Koşullu yazmalarda flag'leri ayarlayan talimatı ve her iki `CMOVcc` sonucunu da dahil edin. Her block'un dispatcher çıkışını çözümlenmiş doğrudan ardılına veya koşullu branch'ine dönüştürün; böylece binary'yi patch'lemeden dispatcher erişilemez hale gelir. Bu, tam bir CFG yaklaşımıdır; yalnızca tek bir decoder önemliyse yukarıdaki [dar execution-slice iş akışı](#bypass-flattened-control-flow-with-a-narrow-execution-slice) daha hızlı olabilir.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis), bu yapıyı Binary Ninja'da otomatikleştirir. `plugins/DispatchThis` klasörünü Binary Ninja kullanıcı plugin dizinine kopyalayıp uygulamayı yeniden başlatın. Etkilenen işlevde **Function Settings**'i açıp `OLLVM_XOR_64`'ü seçin; analiz başlamazsa **Analysis → Reanalyze All Functions**'ı kullanın. Bu mod dosya baytlarını değil, MLIL control-flow kenarlarını yeniden yazar ve Z3'e ya da indirect-jump resolver'a ihtiyaç duymaz. Binary Ninja 5.3.9757+ üzerinde test edilmiştir; block başına kullanılmayan durum yazmalarını kaldırmadığından bunları hâlâ etkin geçişlerle karıştırmayın.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, program işlemlerini `mov` tabanlı talimat dizileriyle değiştirir ve control flow'u değiştirmek için signal/exception handling kullanır. Ayrıntılar için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Desteklenen binary'ler için [demovfuscator](https://github.com/kirschju/demovfuscator) sonucu deobfuscate edebilir. Birkaç bağımlılığı vardır.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Ve [keystone'u kurun](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

**CTF oynuyorsanız, flag'i bulmak için bu geçici çözüm** çok işinize yarayabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**Giriş noktasını** bulmak için fonksiyon adlarında `::main` arayın. Örneğin:

![Ghidra'da fonksiyon adlarında çift iki nokta ve main arayarak Rust giriş noktasını bulma](<../../images/image (1080).png>)

Bu durumda binary'nin adı authenticator olduğundan, bunun ilginç main fonksiyonu olduğu oldukça açık.\
Çağrılan **fonksiyonların** **adlarını** öğrendikten sonra, **girdileri** ve **çıktıları** hakkında bilgi edinmek için onları **İnternet'te** arayın.

### ELF firmware'inden Rust dizelerini kurtarma

**Rust ELF** binary'lerinde birçok statik dize, C tarzı NUL sonlandırmalı işaretçilerle gösterilmez. Yaygın bir `rustc` düzeninde, **`.data.rel.ro`** içindeki bir **işaretçi/uzunluk demeti**, **`.rodata`** içinde saklanan gerçek dize blob'una işaret eder:

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
3. **`.rodata`** adres aralığındaki her değeri olası bir string pointer'ı olarak değerlendirin.
4. Sonraki word'ü olası uzunluk olarak değerlendirin.
5. Mantıklılık filtreleri uygulayın (örneğin, uzunluğu **4** ile **100** byte arasında olanları tutun).
6. `0x00` değerine kadar tarama yapmak yerine, **`.rodata`** bölümünden tam olarak `length` byte okuyun.

Minimal extractor mantığı:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Bu, özellikle firmware reversing sırasında kullanışlıdır; çünkü kurtarılan Rust string'leri genellikle **HTTP rotalarını, RPC adlarını, log mesajlarını, assertion'ları, dosya adlarını, config anahtarlarını, command handler'ları ve kimlik doğrulamayla ilgili mantığı** ortaya çıkarır.

Ghidra bu string'leri bulamazsa aynı sezgisel yöntemi uygulayan ve referans verilen `.rodata` offset'lerinde string verileri oluşturan özel bir script/plugin çalıştırın. Pen Test Partners tarafından yayımlanan `rust-strings` ve `RustStrings.py` araçları, bu fikri diğer **word size'lara, endianness seçeneklerine ve section düzenlerine** uyarlamak için iyi kaynaklardır.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi ile derlenmiş binary'ler için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Bir Delphi binary'sini reverse etmeniz gerekiyorsa IDA plugin'i [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

Bir Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu plugin, binary'yi çalıştırır ve debugging başladığında function adlarını dinamik olarak çözümler. Debugging'i başlattıktan sonra Start düğmesine (yeşil olan veya f9) tekrar basın; gerçek kodun başlangıcında bir breakpoint tetiklenir.

Grafik uygulamasında bir düğmeye basarsanız debugger, o düğmenin çağırdığı function'da durabilir.

## Golang

Standart Go binary'leri için [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper), runtime yapılarını kurtarıp IDA'daki function adlarını iyileştirebilir. Python plugin'ini **Alt+F7** ile yükleyin.

Bir Golang binary'sini reverse etmeniz gerekiyorsa IDA plugin'i [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm.

Bir Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu, function adlarını çözümler.

### Sembol tablosu olmadan metadata'yı kurtarma

Stripped bir Go executable'ı, program counter'ları function'lara eşlemek için yine de runtime metadata'ya ihtiyaç duyar. [GoReSym](https://github.com/mandiant/GoReSym), Go runtime'ından türetilen kodu kullanarak `pclntab` ve `moduledata` gibi yapıları bulup ayrıştırır. Bu yöntem, standart sembol tablosuna bağlı kalmadan function sınırlarını, adlarını, kaynak kodu yollarını, türleri ve build ayrıntılarını kurtarabilir.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Bir obfuscator, kurtarılan adları değiştirirken bu yapıları kullanılabilir durumda bırakabilir. Örneğin Garble, tanımlayıcıları ve paket yollarını hash'ler; build, module ve debug bilgilerini kaldırır.<sup>[[12]](#references)</sup> Obfuscate edilmiş paket belirteci, o paketteki fonksiyonlar arasında tutarlı kalmalıdır. Fonksiyonları tekrarlanan belirtece göre gruplayın, çağrılan fonksiyonlardan, string'lerden ve API'lerden bir paketi çıkarın, ardından bu paket etiketini grubun tamamına uygulayın.<sup>[[13]](#references)</sup>

### GoResolver ile Garble adlarını kurtarma

[GoResolver](https://github.com/volexity/GoResolver), runtime sembolü çıkarmayı temiz referans oluşturma ve kontrol akış grafiği (CFG) eşleştirmeyle birleştirir. Şu sırayı izleyin:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Derleyici sürümünü belirleyin.** Önce `BuildInfo` ve gömülü sürüm dizelerini deneyin. Obfuscator bunları kaldırdıysa, paketlenmiş Go runtime'ının bölümlerini sürümü bilinen referans runtime'larla karşılaştırın. Volexity'nin testlerinde runtime'ın yaklaşık `%2`'si ana Go sürümlerini ayırt etmeye yetti. Bunu evrensel bir eşik olarak değil, deneysel bir optimizasyon olarak değerlendirin.<sup>[[13]](#references)</sup>
2. **Eşleşen referanslar oluşturun.** Belirlenen Go sürümü, hedef mimari ve olası kütüphaneler için temiz binary'ler oluşturun. Toolchain'in eşleşmesi, derleyici tarafından oluşturulan CFG farklılıklarını azaltır.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Fonksiyonları karşılaştırın.** GoGrapher, fonksiyon CFG'lerini eşleştirir ve `0.0` ile `1.0` arasında normalize edilmiş skorlar üretir. Temel blok eşleştirmesi, benzer talimatların ağırlıklı karşılaştırmasına dayanır. Güven düzeyi yüksek eşleşmeler, rastgeleleştirilmiş fonksiyonları temiz uygulamayla eşleştirir. Daha zayıf eşleşmeler de bir paketi veya modülü belirleyebilir.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
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

Varsayılan anlamlı eşleşme eşiği `0.9` değerindedir. `--extract` ve `--graph` seçenekleri aşamalardan herhangi birini tek başına çalıştırabilir; varsayılan olarak ikisi de çalıştırılır çünkü elde edilen runtime metadata ve CFG kanıtları birbirini tamamlar.<sup>[[10]](#references)</sup> CFG puanları sezgiseldir: inlining, build bayrakları, mimari ve kütüphane sürümü farklılıkları grafiğin şeklini değiştirebilir. Bu nedenle düşük güvenli adları zorla atamak yerine çözümlenmemiş işlevleri koruyun.<sup>[[13]](#references)</sup>

### Go string tablosunu kurtarma

Go binary dosyaları, bağlı tüm paketlerdeki string baytlarını tek bir bitişik tabloda tutar. Girdiler NUL ile sonlandırılmaz ve runtime yapıları tablonun taban adresini veya boyutunu göstermez. Bununla birlikte derleyici, girdileri tüm işletim sistemleri ve mimarilerde önce uzunluğa, sonra alfabetik sıraya göre düzenler. Bu nedenle bir girdi bulduktan sonra analist, bitişik girdiler arasında ilerleyebilir ve string'leri kodla ilişkilendirmek için veri çapraz referanslarından yararlanabilir.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor), bu iş akışını IDA Pro ve Ghidra'da otomatikleştirir. Eklenti veri segmenti çapraz referanslarına dayandığı için önce otomatik analizin tamamlanmasını bekleyin. Varsayılan dayanak noktası `entersyscall` runtime string'idir. Ardından eklenti her iki yönde tarama yapabilir, kurtarılan string'leri veritabanında tanımlayabilir ve string'leri bunlara başvuran işlevlerle eşleyen bir JSON dosyası dışa aktarabilir.<sup>[[14]](#references)</sup>

Uygulama veya malware kodunu bağlı kütüphanelerden gelen gürültüden ayırmak için raporu, başvuran işlevin paketine göre filtreleyin. Bu teknik, Garble'ın `-literals` dönüşümü gibi obfuscation işlemleriyle bozulan literal'ları kurtaramaz. Yine de obfuscation uygulanmamış runtime string'lerini düzenlemeye yardımcı olabilir.<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime türlerini kurtarma

Go, garbage collection gibi özellikler tarafından kullanılan runtime türü bilgilerini içerir. Build bilgileri kaldırıldığında veya disassembler bu metadata'yı ayrıştıramadığında, talimatlar rastgele veri adreslerini yüklüyormuş gibi görünebilir ve hedef bölge tür bilgisi içermeden kalır. Metadata'yı kurtarmak, bu adresleri okunabilir tür başvurularına dönüştürür ve paketlerin neler yapabildiğini anlamayı kolaylaştırır.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver), sembolleri çıkarabilir ve runtime türlerini ayrıştırarak bir JSON raporuna aktarabilir. Mevcut CLI, `resolve` alt komutunu kullanır:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` seçeneği type ayrıştırmayı etkinleştirir. Kurtarılan type'ları tanımlamak ve referanslarını analiz veritabanına uygulamak için raporu GoResolver'ın IDA Pro veya Ghidra plugin'iyle içe aktarın. Bu özellikle sunulan rapor formatında `-y` seçeneği kullanılmadığında RTTI adresi ve kurtarılan type üyeleri null olur.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver x86, AMD64, ARM ve ARM64 mimarilerindeki PE, ELF ve Mach-O örneklerini destekler; bu nedenle aynı iş akışı Windows, Linux ve macOS için derlenmiş Go binary'leri üzerinde de uygulanabilir.<sup>[[10]](#references)</sup>

## Derlenmiş Python

Bu sayfada, ELF/EXE biçiminde derlenmiş bir Python binary'sinden Python kodunu nasıl alabileceğinizi bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Bir GBA oyununun **binary** dosyasını edindiyseniz, onu **emulate** etmek ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Debug sürümünü indirin_) - Arayüzlü bir debugger içerir
- [**mgba** ](https://mgba.io)- Bir CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin'i
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin'i

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünde Game Boy Advance **butonlarına** nasıl basılacağını görebilirsiniz.

![Game Boy Advance buton eşlemelerini gösteren no$gba kontrol yapılandırması](<../../images/image (581).png>)

Her **tuşun basıldığında** onu tanımlayan bir değeri vardır:

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

Yani bu tür bir programda ilginç olan kısım, **programın kullanıcı girdisini nasıl işlediğidir**. **0x4000130** adresinde sıkça karşılaşılan **KEYINPUT** fonksiyonunu bulabilirsiniz.

![0x4000130 adresinde KEYINPUT'e başvuran bir GBA binary'sinin Ghidra görünümü](<../../images/image (447).png>)

Önceki görselde, fonksiyonun **FUN_080015a8**'den çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

Bu fonksiyonda, bazı init işlemlerinden sonra (önemli değiller):

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

Son if, **`uVar4`**'ün son Keys içinde olup olmadığını ve geçerli key olmadığını kontrol ediyor; buna düğmeyi bırakma da denir (geçerli key **`uVar1`** içinde saklanır).

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

Önceki kodda **uVar1**’in (yani **basılan düğmenin değerinin** bulunduğu yerin) bazı değerlerle karşılaştırıldığını görebilirsiniz:

- Önce **4 değeriyle** (**SELECT** düğmesi) karşılaştırılır: Bu challenge’da bu düğme ekranı temizler.
- Ardından değer **8** (**START** düğmesi) ile karşılaştırılır; bu challenge’da bu yol, girilen kodun geçerli olup olmadığını denetler.
  - Bu durumda **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılır ve değer eşleşirse bazı kodlar çalıştırılır.
- Diğer tüm durumlarda bir sayaç (`DAT_030000d4`) denetlenir ve artırılır.\
  Sayaç 8’in altındayken basılan tuşların değerleri `DAT_030000d8` içinde biriktirilir.

Dolayısıyla bu challenge’da, düğmelerin değerlerini bilerek, toplamı 0xf3 olan ve uzunluğu 8’den küçük bir kombinasyona **basmanız** gerekiyordu.

**Bu eğitim için kaynak:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kurslar

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRA ile MBA obfuscation'ını sadeleştirme](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Rust string'lerini çözümleme - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing eğitimi (arşivlenmiş)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI destekli reverse engineering'i engellemek ya da en azından denemek](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic block eşleştirmeye dayalı control flow graph karşılaştırma yaklaşımı](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repository](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mekanizması](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Golang binary'lerini otomatik olarak deobfuscate etmek için control-flow graph benzerliğini kullanma](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repository](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang araçlarındaki güncellemeler](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Her şeyi reverse engineer edin](https://github.com/morluto/rea)
- [17] [REA managed-code analizi](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI ve Evidence kılavuzu](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninja control-flow unflattening iş akışı](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF zero-day saldırısı, Java loader, web shell ve AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [IDA bridge server uygulaması](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Ghidra bridge server uygulaması](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int), wildcard address'e bağlanır](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
