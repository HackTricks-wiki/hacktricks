# Reversing Araçları ve Temel Yöntemler

{{#include ../../banners/hacktricks-training.md}}

## ImGui Tabanlı Reversing araçları

Yazılım:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg kullanıcı modu otomasyonu

{{#ref}}
windbg-automation.md
{{#endref}}

## Office belge makrosu analizi

Şüpheli Office belgelerinde [VBA makro junk code ve gizli UserForm denetimlerini](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms) inceleyin.

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

- wasm'ı (binary) wat'a (düz metin) **decompile** etmek için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) adresini kullanın.
- wat'ı wasm'a **compile** etmek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) adresini kullanın.
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

dotPeek, **kütüphaneler** (.dll), **Windows metadata dosyaları** (.winmd) ve **çalıştırılabilir dosyalar** (.exe) dahil olmak üzere birden çok formatı **decompile edip inceleyen** bir decompiler'dır. Decompile edildikten sonra bir assembly, Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantaj, kaybolmuş kaynak kodunun eski bir assembly'den geri yüklenmesi gerektiğinde bu işlemin zaman kazandırmasıdır. Ayrıca dotPeek, decompile edilmiş kodda kullanışlı bir gezinme olanağı sunar ve bu da onu **Xamarin algoritma analizi** için ideal araçlardan biri yapar.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in modeli ve aracı tam ihtiyaçlarınıza göre uyarlayan bir API ile .NET Reflector zaman kazandırır ve geliştirmeyi kolaylaştırır. Bu aracın sunduğu çok sayıda reverse engineering hizmetine göz atalım:

- Verilerin bir kütüphane veya bileşen içinde nasıl aktığına dair fikir verir.
- .NET dilleri ve framework'lerinin uygulamaları ve kullanımları hakkında bilgi sağlar.
- Kullanılan API'lerden ve teknolojilerden daha fazla yararlanmak için belgelenmemiş ve dışarıya açılmamış işlevleri bulur.
- Bağımlılıkları ve farklı assembly'leri bulur.
- Kodunuzdaki, üçüncü taraf bileşenlerdeki ve kütüphanelerdeki hataların tam konumunu tespit eder.
- Üzerinde çalıştığınız tüm .NET kodlarının kaynağında debugging yapar.

### [ILSpy](https://github.com/icsharpcode/ILSpy) ve [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy plugin'i](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir işletim sisteminde kullanabilirsiniz (doğrudan VSCode'dan yükleyebilirsiniz; git'i indirmeniz gerekmez. **Extensions**'a tıklayın ve **ILSpy** araması yapın).\
Yeniden **decompile**, **modify** ve **recompile** etmeniz gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak bakımı yapılan fork'u [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir fonksiyonun içindeki bir şeyi değiştirmek için **Right Click -> Modify Method**.)

### REA ile çalıştırma gerektirmeyen managed inceleme

**REA**, assembly'yi yüklemeden PE/CLI metadata'sını ve CIL'i inceleyebilir. Önce artifact'in kimliğini belirleyin, ardından üyeleri ve tanımlanmış native sınırları inceleyin. Bu, decompiler kullanmadan veya programı çalıştırmadan önce şüpheli çağrıları gözden geçirmek için kullanışlıdır.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Sürüm karşılaştırması için `compare_managed_members`, metadata token’larını derlemeler arasında sabit kabul etmek yerine ham CIL/imza kimliğini ve çözümlenmiş talimat parmak izlerini kullanır. Bir P/Invoke bildirimi, native kodun çalıştığını kanıtlamaz; bu sınırı doğrulamak için `verify_managed_native_boundaries` eşleşen bir native export veya function Evidence gerektirir. Artifact digest, MVID ve çözümlenemeyen eşlemeleri sonuçla birlikte saklayın.<sup>[[17]](#references)</sup>

### DNSpy Günlüğü

**DNSpy’nin bazı bilgileri bir dosyaya kaydetmesini** sağlamak için şu kod parçacığını kullanabilirsiniz:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy ile Hata Ayıklama

DNSpy kullanarak kodda hata ayıklamak için şunları yapmanız gerekir:

Öncelikle, **hata ayıklamayla** ilgili **Assembly özniteliklerini** değiştirin:

![DNSpy Logging - DNSpy ile Hata Ayıklama: Öncelikle, hata ayıklamayla ilgili Assembly özniteliklerini değiştirin](<../../images/image (973).png>)

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

Ve **compile**'a tıklayın:

![DNSpy Logging - DNSpy Debugging: Derle'ye tıklayın](<../../images/image (314) (1).png>)

Ardından yeni dosyayı _**File >> Save module...**_ ile kaydedin:

![DNSpy Logging - DNSpy Debugging: Yeni dosyayı File Save module ile kaydedin](<../../images/image (602).png>)

Bunu yapmanız gerekir; aksi hâlde **runtime** sırasında koda çeşitli **optimizasyonlar** uygulanır ve hata ayıklama yaparken bir **breakpoint'e hiç ulaşılmaması** veya bazı **değişkenlerin bulunmaması** mümkündür.

Ardından, .NET uygulamanız **IIS** tarafından **çalıştırılıyorsa** şu komutla **yeniden başlatabilirsiniz**:

```
iisreset /noforce
```

Ardından, debugging işlemine başlamak için açık olan tüm dosyaları kapatın ve **Debug Tab** içinde **Attach to Process...** seçeneğini belirleyin:

![DNSpy Logging - DNSpy Debugging: Ardından, debugging işlemine başlamak için açık olan tüm dosyaları kapatın ve Debug Tab içinde Attach to Process seçeneğini belirleyin](<../../images/image (318).png>)

Ardından **IIS server**'a bağlanmak için **w3wp.exe**'yi seçin ve **attach**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Ardından IIS server'a bağlanmak için w3wp.exe'yi seçin ve attach'e tıklayın](<../../images/image (113).png>)

Artık süreci debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce _Debug >> Break All_ seçeneğine, ardından _**Debug >> Windows >> Modules**_ seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Artık süreci debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Artık süreci debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (834).png>)

**Modules** içindeki herhangi bir modüle tıklayın ve **Open All Modules**'ı seçin:

![DNSpy Logging - DNSpy Debugging: Modules içindeki herhangi bir modüle tıklayın ve Open All Modules'ı seçin](<../../images/image (922).png>)

**Assembly Explorer** içindeki herhangi bir modüle sağ tıklayın ve **Sort Assemblies**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer içindeki herhangi bir modüle sağ tıklayın ve Sort Assemblies'e tıklayın](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'leri Debug Etme

### IDA Kullanarak

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe'de, 32 bit sürümü C:\Windows\SysWOW64\rundll32.exe'de bulunur)
- **Windbg** debugger'ını seçin
- "**Suspend on library load/unload**" seçeneğini belirleyin

![Debugging DLLs - Using IDA: " Suspend on library load/unload " seçeneğini belirleyin](<../../images/image (868).png>)

- Yürütmenin **parametrelerini**, **DLL'nin yolunu** ve çağırmak istediğiniz işlevi girecek şekilde yapılandırın:

![Debugging DLLs - Using IDA: DLL'nin yolunu ve çağırmak istediğiniz işlevi girerek yürütme parametrelerini yapılandırın](<../../images/image (704).png>)

Ardından debugging'i başlattığınızda **her DLL yüklendiğinde yürütme durdurulur**. Böylece rundll32 DLL'nizi yüklediğinde yürütme durur.

Bu yöntem modül yükleme olaylarında durur; ancak yüklenen DLL'nin giriş noktasına ulaşmak, aşağıdaki x64dbg iş akışına kıyasla daha dolaylıdır.

### x64dbg/x32dbg Kullanarak

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe'de, 32 bit sürümü C:\Windows\SysWOW64\rundll32.exe'de bulunur)
- **Command Line'ı değiştirin** ( _File --> Change Command Line_ ) ve DLL'nin yolunu ve çağırmak istediğiniz işlevi ayarlayın. Örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ bölümüne gidin ve "**DLL Entry**" seçeneğini belirleyin.
- Ardından **yürütmeyi başlatın**. Debugger her DLL main'de durur; bir noktada **DLL'nizin DLL Entry noktasında durur**. Buradan, breakpoint koymak istediğiniz noktaları aramanız yeterlidir.

win64dbg'de yürütme herhangi bir nedenle durduğunda, **win64dbg penceresinin üst kısmına** bakarak **hangi kodda olduğunuzu** görebileceğinizi unutmayın:

![Using IDA - Using x64dbg/x32dbg: Yürütme herhangi bir nedenle win64dbg'de durduğunda, win64dbg penceresinin üst kısmına bakarak hangi kodda olduğunuzu görebileceğinizi unutmayın](<../../images/image (842).png>)

Bu gösterge, yürütmenin debug etmek istediğiniz DLL'nin içinde durduğunu doğrular.

## GUI Uygulamaları / Video Oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bunları değiştirmek için kullanışlı bir programdır. Daha fazla bilgi için:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), oyunlara odaklanan GNU Project Debugger (GDB) için bir front-end/reverse engineering aracıdır. Bununla birlikte, reverse engineering ile ilgili her türlü iş için kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/), çeşitli decompiler'lara yönelik web tabanlı bir front-end'dir. Bu web servisi, küçük yürütülebilir dosyalarda farklı decompiler'ların çıktılarını karşılaştırmanızı sağlar.

### Godot PCK şifre çözme ve proje kurtarma

Dağıtılmış bir Godot oyunu için PCK dosyasını bağımsız bir `.pck` dosyasında, eklenmiş veya gömülü bir executable pack'te ya da APK'nın `assets` dizininde bulun. [gore](https://github.com/figurophobia/gore) pack'i inceleyip çıkarabilir. Script ve kaynakların tamamen yeniden oluşturulması için GDRE Tools gerekir (`gore setup` bunu yükler veya `--gdre` kullanın). Bu iş akışında araç, Godot 4.x PCK biçimleri v2–v4'ü destekler; v1 başlıklarını algılayabilir ancak v1 için sağlanan bir anahtar gerekir.<sup>[[25]](#references)</sup>

Otomatik anahtar kurtarma için şifrelenmiş bir file table gerekir; yalnızca dosya içerikleri şifrelenmişse bilinen bir anahtar sağlayın. Kurtarma işleminin başarısız olması, pack'in şifrelenmemiş olduğunu kanıtlamaz.<sup>[[28]](#references)</sup>

Anahtar araması bir AES-256 keyspace saldırısı **değildir**. Şifrelenmiş bir file table, düz metninin MD5 değerini, düz metin uzunluğunu, IV'yi ve AES-256-CFB ciphertext'ini açığa çıkarır.<sup>[[27]](#references)</sup> `gore`, oyun executable'ı veya yakındaki dosyalardaki 32 baytlık pencereleri olası anahtarlar olarak test eder. Adayları, çözülen yol uzunluğu ve önekinin makul olup olmadığını denetleyerek filtreler; ardından binary scan ile bulunan eşleşmeleri tüm table'ı çözerek ve MD5 değerini kontrol ederek doğrular.<sup>[[26]](#references)[[28]](#references)</sup> Önce başlatılmış PE/ELF veri bölümlerinde arama yapar, ardından tüm dosyada tarama yapar; `--scan` diğer aday dosyaları da aramaya ekler.<sup>[[28]](#references)</sup>

Gömülü bir anahtar bulunmazsa, yerleşik küçük bir parola listesi denenir; diğer adayları sağlamak için `--wordlist` kullanılır. Her parola, engine'in paroladan türetilen anahtar gösterimi, sıfırlarla doldurulmuş literal veya 64 karakterlik hex anahtar olarak test edilir. Binary scan eşleşmelerinden farklı olarak bu uygulamada wordlist eşleşmeleri yalnızca yol yapısı filtresinden geçer. Pack'i açıp çıkarılan varlıkları doğrulayarak eşleşmeleri teyit edin.<sup>[[26]](#references)[[28]](#references)</sup>

Oyun dosyası yerel olarak mevcutsa analiz için gereken aşamayı seçin. `recover`, açılabilir bir projeyi yeniden oluşturmak için GDRE'yi çalıştırırken `extract` yalnızca ham dosyaları çıkarır. `key`, başka bir araçta kullanmak üzere olası bir anahtarı yazdırır.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## REA ile kanıta dayalı native inceleme

**REA**, Hopper, Ghidra ve IDA analizlerini CLI ve MCP üzerinden sunar. Node.js 22.x (en az 22.19), 24.x (en az 24.11) veya 26+ ve npm gerektirir. Önce mevcut bir native provider yapılandırın; `rea providers --json` komutunu kontrol edin ve hedefi destekleyen birden fazla provider varsa birini açıkça seçin. Aşağıdaki `0x1000` yerine envanterdeki gözlemlenmiş bir işlev adını veya adresini kullanın.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Bir feature string veya symbol ile başlayın, references ve callers'ı izleyin, ardından seçilen function dossier'ını ve `rea decompile` ile pseudocode'u inceleyin. REA, bir failure sonrasında sessizce değiştirmek yerine session'ı seçilen provider'a bağlar. Tekrarlanabilir sorgular için `--snapshot PATH`, yalnızca eşleşen artifact bytes, provider, settings, operation ve parameters değerlerini yeniden kullanır; snapshot, kaydedilmiş bir provider database'i değil, yerel bir cache'dir. Çıkarımla bulunan paths'leri veya decompiler metnini orijinal source olarak değerlendirmek yerine, döndürülen Evidence'ı ve açıkça belirtilen bilinmeyenleri koruyun.<sup>[[16]](#references)[[18]](#references)</sup>

JavaScript/Electron entry point'lerinden native add-on'lara giden yollar için bkz. [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Yerel TCP bridge ile script tabanlı IDA ve Ghidra analizi

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge), **önceden açılmış** bir IDA database'i veya Ghidra CodeBrowser programı içinde çalışır ve ayrı bir script'in bu analiz database'ini sorgulayıp değiştirmesini sağlar. IDA'nın Python CLI'ından (`import ID_Server`) `ID_Server.py` dosyasını veya Ghidra'nın Script Manager'ından `Ghidra_Server.py` dosyasını çalıştırın. IDA, `127.0.0.1` adresine `5073` portundan başlayarak bağlanır ve daha yüksek portları tarar. Mevcut Ghidra script'i `5093` portundan başlayıp `5102`'ye kadar on portu dener; Java socket'i yalnızca loopback'e değil, wildcard adrese bağlanır. Bağlanmadan önce instance tarafından yazdırılan portu kontrol edin. Headless analyzer'dan farklı olarak bu bridge, GUI instance'ında o anda açık olan program üzerinde çalışır.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

**Her bağlantı için satır sonuyla biten tek bir command gönderin** ve satır sonuyla biten yanıtı okuyun. Sonuç genellikle JSON'dur. Örneğin, bir input path ile ilgili import edilmiş bir API'yi bulduktan sonra `IMPORTXREF` onun call site'larını bulur; ardından `DECOMP_XREF`, seçilen bir address'in caller'larını toplu olarak decompile eder. `FUNC` bir function'ı incelerken `PCODE` decompiler'ın intermediate representation'ını döndürür. Farklı bir base address'e göre yeniden konumlandırılmış bir binary'den kopyalanmış address yerine, etkin database'deki address'i kullanın. Aşağıdaki örnek IDA'nın varsayılan portunu kullanır; Ghidra için script'in yazdırdığı portu kullanın.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Aynı kanal **analysis database'ini değiştirebilir**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` ve `PATCH`; adları, türleri, structure tanımlarını, function sınırlarını veya kayıtlı byte'ları değiştirir. `PATCH`, database düzenlemesidir; **live process'e patch uygulandığının** kanıtı değildir. Her iki listener için de authentication belgelenmemiştir. IDA yalnızca loopback üzerinden erişilebilirken Ghidra network interface'leri üzerinden erişilebilir olabilir; kullanırken Ghidra listener'a erişimi kısıtlayın. `QUIT` her iki listener'ı da durdurur; IDA ayrıca `ida_bridge_stop()` işlevini sunar.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner ile shellcode hata ayıklama

[**BlobRunner**](https://github.com/OALabs/BlobRunner), **shellcode** için bellek ayırır, **memory address**'ini yazdırır ve execution'ı duraklatır.\
IDA veya x64dbg gibi bir debugger'a bağlanın, yazdırılan adrese breakpoint koyun ve shellcode hata ayıklamak için execution'ı sürdürün.

GitHub releases sayfasında derlenmiş sürümlerin bulunduğu zip dosyaları yer alır: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
BlobRunner'ın biraz değiştirilmiş bir sürümünü aşağıdaki linkte bulabilirsiniz. Derlemek için **Visual Studio Code'da bir C/C++ projesi oluşturun, kodu kopyalayıp yapıştırın ve build edin**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile shellcode hata ayıklama

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner'a benzer. Shellcode için bellek ayırır ve sonsuz bir loop'a girer. Debugger'ı bağlayın, **2–5 saniye** boyunca execution'ı sürdürün, loop'un içinde duraklatın ve ayrılan shellcode'a execution'ı aktaran sonraki çağrıya kadar adım adım ilerleyin.

![Debugger, jmp2it'in sonsuz loop'unda ayrılan shellcode'a yapılan çağrının hemen öncesinde duraklatılmış](<../../images/image (509).png>)

Derlenmiş jmp2it sürümünü [releases sayfasından indirebilirsiniz](https://github.com/adamkramer/jmp2it/releases/).

### Cutter kullanarak shellcode hata ayıklama

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'ın GUI'sidir. Cutter ile shellcode'u emüle edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'da "Open File" ve "Open Shellcode" seçenekleri olduğunu unutmayın. Benim durumumda shellcode'u file olarak açtığımda doğru şekilde decompile etti, ancak shellcode olarak açtığımda etmedi:

![Aynı byte'lar file veya shellcode olarak açıldığında Cutter'ın farklı analysis sonuçları gösterdiği görünüm](<../../images/image (562).png>)

Emulation'ı istediğiniz yerde başlatmak için oraya bir bp koyun; görünüşe göre Cutter emulation'ı otomatik olarak oradan başlatır:

![Cutter emulation'ını başlatmadan önce istenen shellcode girişine breakpoint koyulması](<../../images/image (589).png>)

![Cutter emulator'ının seçilen shellcode breakpoint'inde duraklatılması](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görebilirsiniz:

![Cutter'ın hex dump görünümünde emüle edilen shellcode stack'inin incelenmesi](<../../images/image (186).png>)

### Shellcode deobfuscation ve çalıştırılan function'ları bulma

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) aracını deneyebilirsiniz.\
Shellcode'un hangi **function'ları** kullandığı ve bellekte kendini **decode** edip etmediği gibi bilgileri gösterir.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg ayrıca grafik arayüzlü bir başlatıcıya da sahiptir; buradan istediğiniz seçenekleri belirleyip shellcode'u çalıştırabilirsiniz.

![Shellcode emülasyonu ve izleme seçeneklerini belirlemek için scDbg grafik arayüzlü başlatıcısı](<../../images/image (258).png>)

**Create Dump** seçeneği, bellekte shellcode üzerinde dinamik olarak bir değişiklik yapılırsa son halini dump eder (çözümlenmiş shellcode'u indirmek için kullanışlıdır). **start offset**, shellcode'u belirli bir offset'ten başlatmak için kullanışlı olabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'da hata ayıklamak için kullanışlıdır (ancak bu iş için daha önce açıklanan seçeneklerden herhangi birini daha iyi buluyorum; çünkü Ida veya x64dbg kullanabilirsiniz).

### CyberChef kullanarak disassembly

Shellcode dosyanızı girdi olarak yükleyin ve dosyayı decompile etmek için şu tarifi kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation'ını çözme

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` gibi basit ifadeleri aritmetik (`+`, `-`, `*`) ve bit düzeyindeki operatörleri (`&`, `|`, `^`, `~`, kaydırmalar) birleştiren formüllerin arkasına gizler. Önemli nokta, bu özdeşliklerin genellikle yalnızca **sabit genişlikli modüler aritmetikte** doğru olmasıdır; bu nedenle elde taşımalar ve taşmalar önemlidir:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Bu tür bir ifadeyi genel amaçlı cebir araçlarıyla sadeleştirirseniz, bit genişliği semantiği göz ardı edildiği için kolayca yanlış bir sonuç elde edebilirsiniz.<sup>[[1]](#references)</sup>

### Pratik iş akışı

1. **Özgün bit genişliğini** lifted code/IR/decompiler çıktısından koruyun (`8/16/32/64` bit).
2. Sadeleştirmeye çalışmadan önce ifadeyi **sınıflandırın**:
   - **Doğrusal**: bit düzeyindeki atomların ağırlıklı toplamları
   - **Yarı doğrusal**: `x & 0xFF` gibi sabit maskeler içeren doğrusal ifadeler
   - **Polinom**: çarpımlar içerir
   - **Karma**: çarpımlar ve bit düzeyindeki mantık iç içe geçmiştir; genellikle tekrarlanan alt ifadeler bulunur
3. Aday her yeniden yazımı rastgele testlerle veya bir SMT ispatıyla **doğrulayın**. Eşdeğerlik kanıtlanamıyorsa tahminde bulunmak yerine özgün ifadeyi kullanın.

### Dar bir yürütme dilimiyle düzleştirilmiş control flow'u atlatma

Tam control-flow graph'ını yeniden oluşturmak çoğu zaman gereksizdir. Control-flow flattening, opaque predicates, büyük dispatcher'lar veya MBA ağırlıklı kod söz konusu olduğunda, şifrelenmiş blob'lara ve output buffer'lara yapılan başvuruları izleyerek bunları dönüştüren en küçük rutine ulaşın. Ardından yalnızca bu data-flow dilimini yeniden oluşturun veya bağımsız olarak çalıştırın; ilgili state doğrudan başlatılabiliyorsa dispatcher gerekli çözümün parçası değildir.<sup>[[7]](#references)</sup>

Pratik bir iş akışı:<sup>[[7]](#references)</sup>

1. Çalıştırılabilir ve veri bölümlerinin, relocation'ların ve cross-reference'ların envanterini çıkarın. Bayt sırasını ve eleman genişliğini koruyarak `.rodata` içinden aday tabloları dökümleyin.
2. Plaintext'i veya output buffer'ı yazan son rutini belirleyin. Girdilerini, başvurduğu tabloları, import edilen çağrıları ve gerekli global state'i kaydedin.
3. Yalnızca bu işlemleri sabit genişlikli bir Python modeline aktarın. Dilim hâlâ çok fazla state'e bağlıysa, tüm programı emüle etmek yerine rutini Unicorn, QEMU veya bir debugger altında çalıştırın ve ilgisiz import'lar için hook kullanın.
4. Extractor'ın çıktısını gerçekten sağlanan binary'den türettiğini doğrulayın: sessiz fallback'leri kaldırın, binary içinde gömülü yanıtları arayın ve extractor'ı string'leri, key'leri, identifier'ları, layout'ları ve obfuscation seed'leri değiştirilmiş, daha önce görülmemiş build'lerde çalıştırın.

İlk aşamada kullanabileceğiniz komutlar:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Sabitler olarak gizlenmiş MBA ifadelerini tespit etme

Görünüşte girdiye bağlı olan bir bayt ifadesi, girdisini tamamen yok edebilir. Tablolarını çıkardıktan sonra ifadeyi 8 bitlik tam etki alanında değerlendirin; tek elemanlı bir çıktı kümesi, çevresindeki durum makinesini çözmeden bu baytın sabit olduğunu kanıtlar.<sup>[[7]](#references)</sup>

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

Son maskeyi koruyun; çünkü özgün toplama işleminde bayt genişliğinde taşma oluşur. Daha geniş bir etki alanı için, bir SMT solver'a aynı genişlikteki iki sembolik girdi için `f(x1) != f(x2)` ifadesinin sağlanabilir olup olmadığını sorun: `unsat` değişmezliği kanıtlar; `sat` ise bir karşı örnek verir ve girdinin elenemeyeceği anlamına gelir.<sup>[[7]](#references)</sup>

#### Ortama bağlı çözümlemeyi tanıyın

Anti-analysis kontrollerinin dallanma yapması veya çökmeye yol açması gerekmez. Bir çözücü, sensör sonucunu bir anahtar bitine, opaque predicate sabitine veya flattened dispatcher durumuna katabilir; normal şekilde çalışmaya devam edip emülatörde makul görünen ancak yanlış bir açık metin üretebilir. Bu nedenle yalnızca görünür hata dallarını yamamak yeterli değildir; ortam yoklamalarından çözücü durumuna uzanan veri bağımlılıklarını izleyin, aynı kod kesitini gerçek cihazda ve emülatörde karşılaştırın ve her sensör sonucunu zorlamanın son arabelleği nasıl değiştirdiğini test edin.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA), malware analizi ve korumalı binary'leri tersine mühendislikle incelemek için kullanışlı bir MBA sadeleştiricisidir. İfadeyi sınıflandırır ve her şeye tek bir genel yeniden yazma geçişi uygulamak yerine özel işlem hatlarına yönlendirir.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA, ifadeyi Boolean girdiler üzerinde değerlendirir, bir imza çıkarır ve pattern matching, ANF dönüşümü ve katsayı interpolasyonu gibi çeşitli kurtarma yöntemlerini paralel olarak dener.
- **Semilinear MBA**: Sabit maskeli atomlar, maskelenmiş bölgelerin doğruluğunu koruyacak şekilde bit bölümlendirmeli yeniden yapılandırmayla oluşturulur.
- **Polynomial/Mixed MBA**: Çarpımlar çekirdeklerine ayrılır ve dış ilişki sadeleştirilmeden önce yinelenen alt ifadeler geçici değişkenlere alınabilir.

Sıklıkla kurtarılmaya çalışılan karma bir özdeşlik örneği:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Bu, şu şekilde sadeleştirilebilir:

```c
x * y
```

### Tersine mühendislik notları

- CoBRA'yı, **lifted IR ifadeleri** veya tam hesaplamayı izole ettikten sonra decompiler çıktısı üzerinde çalıştırmayı tercih edin.
- İfade maskelenmiş aritmetikten veya dar register'lardan kaynaklanıyorsa `--bitwidth` değerini açıkça belirtin.
- Daha güçlü bir kanıtlama adımına ihtiyacınız varsa yerel Z3 notlarına göz atın:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca **LLVM pass plugin** (`libCobraPass.so`) olarak da gelir. Bu, sonraki analiz pass'lerinden önce MBA ağırlıklı LLVM IR'yi normalize etmek istediğinizde kullanışlıdır.
- Desteklenmeyen, carry'ye duyarlı karma alan kalıntılarını; özgün ifadeyi koruyup carry yolunu elle incelemeniz gerektiğine dair bir işaret olarak değerlendirin.

## XOR-state control-flow flattening'i çözümleme

OLLVM tarzı bir flattener, geçerli basic block durumunu iki adet 64-bit register'da tutup dispatcher'da XOR ile yeniden oluşturabilir. Her özgün block, sonraki durumuna ait register çiftini yazar ve dispatcher'a geri atlar. Koşullu bir block, CPU flag'lerine göre çiftin bir yarısını değiştirmek için `CMOVcc` kullanabilir; bu nedenle yalnızca görünür branch komutlarını izlemek, iki ardılı da gözden kaçırır. Indirect-jump dispatcher'ın aksine bu yapı, her yerde doğrudan geri kenarlar kullanabilir.<sup>[[19]](#references)[[20]](#references)</sup>

Grafiği yeniden oluşturmak için dispatcher karşılaştırma ağacını ve iki durum register'ını belirleyin; karşılaştırılan her XOR durumunu hedef block'uyla eşleştirin, ardından her özgün block'ta register çiftine yazan reaching write'ları izleyin. Koşullu yazımlarda flag'leri ayarlayan komutu ve her iki `CMOVcc` sonucunu da hesaba katın. Her block'un dispatcher çıkışını çözümlenmiş doğrudan ardılına veya koşullu branch'ine dönüştürün; böylece binary'yi patch'lemeden dispatcher erişilemez hâle gelir. Bu, tam-CFG yaklaşımıdır; yalnızca bir decoder önemliyse yukarıdaki [dar execution-slice iş akışı](#bypass-flattened-control-flow-with-a-narrow-execution-slice) daha hızlı olabilir.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis), Binary Ninja'da bu yapıyı otomatikleştirir. `plugins/DispatchThis` dizinini Binary Ninja kullanıcı plugin dizinine kopyalayıp uygulamayı yeniden başlatın. Etkilenen fonksiyonda **Function Settings**'i açıp `OLLVM_XOR_64`'ü seçin; analiz başlamazsa **Analysis → Reanalyze All Functions**'ı kullanın. Bu mod dosya baytlarını değil, MLIL control-flow kenarlarını yeniden yazar ve Z3 ya da indirect-jump resolver gerektirmez. Binary Ninja 5.3.9757+ üzerinde denenmiştir; block başına ölü durum yazımlarını kaldırmaz, bu nedenle bunları hâlâ canlı geçişler sanmayın.<sup>[[19]](#references)</sup>

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

Bir **CTF oynuyorsanız, flag'i bulmak için bu geçici çözüm** çok işinize yarayabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**Giriş noktasını** bulmak için, aşağıdaki örnekteki gibi fonksiyonlarda `::main` araması yapın:

![Fonksiyon adlarında çift iki nokta ve main araması yaparak Ghidra'da Rust giriş noktası bulma](<../../images/image (1080).png>)

Bu durumda binary'nin adı authenticator'dı, dolayısıyla bunun ilgi çekici main fonksiyonu olduğu oldukça açık.\
Çağrılan **fonksiyonların** **adlarını** öğrendikten sonra, **girdileri** ve **çıktıları** hakkında bilgi edinmek için bunları **İnternet'te** arayın.

### ELF firmware'inden Rust string'lerini kurtarma

**Rust ELF** binary'lerinde birçok statik string, C tarzı NUL ile sonlandırılmış pointer'lar olarak referans gösterilmez. Yaygın bir `rustc` yerleşiminde, **`.data.rel.ro`** içinde, gerçek string blob'unun saklandığı **`.rodata`** bölümünü işaret eden bir **pointer/length tuple** bulunur:

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
2. **`.data.rel.ro`** bölümünü word word enumerate edin.
3. `.rodata` adres aralığındaki tüm değerleri aday string pointer'ı olarak değerlendirin.
4. Sonraki word'ü aday uzunluk olarak değerlendirin.
5. Makullük filtreleri uygulayın (örneğin, uzunluğu **4** ile **100** byte arasında olanları tutun).
6. `0x00` değerine kadar taramak yerine, `.rodata` bölümünden tam olarak `length` byte okuyun.

Minimal extractor logic:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Bu, özellikle firmware reversing sırasında kullanışlıdır; çünkü kurtarılan Rust string'leri genellikle **HTTP rotalarını, RPC adlarını, log mesajlarını, assertion'ları, dosya adlarını, config anahtarlarını, command handler'ları ve auth ile ilgili mantığı** ortaya çıkarır.

Ghidra bu string'leri bulamazsa, aynı sezgisel yöntemi uygulayan ve başvurulan `.rodata` offset'lerinde string verisi oluşturan özel bir script/plugin çalıştırın. Pen Test Partners'ın yayımladığı `rust-strings` ve `RustStrings.py` araçları, bu fikri diğer **word size, endianness ve section düzenlerine** uyarlamak için iyi referanslardır.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi ile derlenmiş binary'ler için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Bir Delphi binary'sini reverse etmeniz gerekiyorsa, IDA plugin'i [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

Bir Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu plugin, binary'yi çalıştırır ve debugging başladığında function adlarını dinamik olarak çözümler. Debugging başladıktan sonra Start düğmesine (yeşil düğme veya f9) tekrar basın; gerçek kodun başlangıcında bir breakpoint tetiklenir.

Grafik uygulamasında bir düğmeye basarsanız, debugger bu düğmenin çağırdığı function'da durabilir.

## Golang

Standart Go binary'leri için [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper), runtime yapılarını kurtarabilir ve IDA'daki function adlarını iyileştirebilir. Python plugin'ini yüklemek için **Alt+F7** tuşlarına basın.

Bir Golang binary'sini reverse etmeniz gerekiyorsa, IDA plugin'i [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm.

Bir Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu, function adlarını çözümler.

### Symbol table olmadan metadata kurtarma

Strip edilmiş bir Go executable'ı, program sayaçlarını function'lara eşlemek için yine de runtime metadata'sına ihtiyaç duyar. [GoReSym](https://github.com/mandiant/GoReSym), Go runtime'ından türetilen kodu kullanarak `pclntab` ve `moduledata` gibi yapıları bulur ve ayrıştırır. Böylece geleneksel symbol table'a bağlı kalmadan function sınırları, adları, kaynak yolları, türler ve build ayrıntıları kurtarılabilir.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Bir obfuscator, kurtarılan adları değiştirirken bu yapıları kullanılabilir durumda bırakabilir. Örneğin Garble, tanımlayıcıları ve paket yollarını hash'ler; build, module ve debug bilgilerini kaldırır.<sup>[[12]](#references)</sup> Obfuscate edilmiş paket belirteci, o paketteki işlevler arasında tutarlı kalmalıdır. İşlevleri tekrarlanan belirtece göre gruplayın, çağırdıkları işlevlerden, string'lerden ve API'lerden bir paketi çıkarın, ardından bu paket etiketini grubun tamamına uygulayın.<sup>[[13]](#references)</sup>

### GoResolver ile Garble adlarını kurtarma

[GoResolver](https://github.com/volexity), runtime sembolü çıkarımını, temiz referans oluşturma ve kontrol akış grafiği (CFG) eşleştirmeyle birleştirir. Şu sırayı izleyin:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler sürümünü belirleyin.** Önce `BuildInfo` ve gömülü sürüm string'lerini kontrol edin. Obfuscator bunları kaldırmışsa, Go runtime'ın bölümlerini sürümü bilinen referans runtime'larla karşılaştırın. Volexity'nin testlerinde runtime'ın yaklaşık `2%`'si, başlıca Go sürümlerini ayırt etmek için yeterliydi. Bunu evrensel bir eşik değil, deneysel bir optimizasyon olarak değerlendirin.<sup>[[13]](#references)</sup>
2. **Eşleşen referanslar oluşturun.** Belirlenen Go sürümü, hedef mimari ve olası kütüphaneler için temiz binary'ler oluşturun. Toolchain'in eşleşmesi, compiler tarafından oluşturulan CFG farklılıklarını azaltır.<sup>[[10]](#references)[[13]](#references)</sup>
3. **İşlevleri karşılaştırın.** GoGrapher, işlev CFG'lerini eşleştirir ve `0.0` ile `1.0` arasında normalize edilmiş skorlar üretir. Temel blok eşleştirmesi, benzer talimatların ağırlıklı karşılaştırmasına dayanır. Yüksek güvenilirlikli eşleşmeler, rastgeleleştirilmiş işlevleri temiz implementasyonla eşleştirir. Daha düşük güvenilirlikli eşleşmeler yine de bir paketi veya modülü belirleyebilir.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Doğrulayın ve içe aktarın.** Önerilen adları çağrı ilişkileri, sabitler, string'ler ve yan etkilerle doğrulayın; ardından GoResolver plugin'i aracılığıyla JSON raporunu IDA veya Ghidra'ya aktarın.<sup>[[10]](#references)[[13]](#references)</sup>

Toolchain'i kurun ve birleştirilmiş çıkarıcıyı ve grafik eşleştiriciyi çalıştırın:<sup>[[10]](#references)</sup>

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

Varsayılan anlamlı eşleşme eşiği `0.9` değeridir. `--extract` ve `--graph` seçenekleri aşamalardan birini tek başına çalıştırabilir; varsayılan ayar ise kurtarılan runtime metadata ve CFG kanıtları birbirini tamamladığı için her iki aşamayı da çalıştırır.<sup>[[10]](#references)</sup> CFG skorları sezgiseldir: inlining, build flags, mimari ve library sürümü farklılıkları grafiğin şeklini değiştirebilir. Bu nedenle düşük güvenli isimleri zorla atamak yerine çözümlenemeyen fonksiyonları koruyun.<sup>[[13]](#references)</sup>

### Go string tablosunu kurtarma

Go binary'leri, linklenen tüm package'lardaki string byte'larını bitişik tek bir tabloda tutar. Girdiler NUL ile sonlandırılmaz ve runtime yapıları tablonun başlangıç adresini veya boyutunu göstermez. Ancak compiler, farklı işletim sistemleri ve mimarilerde girdileri önce uzunluklarına, sonra alfabetik sıraya göre düzenler. Bu nedenle bir girdiyi bulduktan sonra analist, bitişik girdiler arasında ilerleyebilir ve string'leri kodla ilişkilendirmek için data cross-reference'larını kullanabilir.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor), bu iş akışını IDA Pro ve Ghidra'da otomatikleştirir. Plugin, data segment cross-reference'larına dayandığından önce auto-analysis'in tamamlanmasını bekleyin. Varsayılan anchor, runtime'daki `entersyscall` string'idir. Ardından plugin her iki yönde tarama yapabilir, kurtarılan string'leri veritabanında tanımlayabilir ve string'leri bunlara başvuran fonksiyonlarla eşleyen bir JSON dosyası dışa aktarabilir.<sup>[[14]](#references)</sup>

Uygulama veya malware kodunu linklenen library'lerden gelen gürültüden ayırmak için raporu, başvuran fonksiyonun package'ına göre filtreleyin. Bu teknik, Garble'ın `-literals` dönüşümü gibi obfuscation nedeniyle yok edilen literal'leri kurtaramaz. Yine de obfuscation uygulanmamış runtime string'lerini düzenlemeye yardımcı olabilir.<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime type'larını kurtarma

Go, garbage collection gibi özelliklerin kullandığı runtime type bilgilerini binary'ye gömer. Build bilgileri kaldırıldığında veya disassembler bu metadata'yı ayrıştıramadığında, talimatlar rastgele data adreslerini yüklüyormuş gibi görünebilir ve hedef bölge typesız kalabilir. Metadata'yı kurtarmak, bu adresleri okunabilir type referanslarına dönüştürür ve package yeteneklerini anlamayı kolaylaştırır.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver), symbol'ları çıkarabilir ve runtime type'larını ayrıştırarak JSON raporu oluşturabilir. Mevcut CLI, `resolve` subcommand'ini kullanır:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

The `-y`/`--types` seçeneği type parsing'i etkinleştirir. Kurtarılan type'ları tanımlamak ve referanslarını analiz veritabanına uygulamak için raporu GoResolver'ın IDA Pro veya Ghidra plugin'i ile içe aktarın. Bu özellik ile sunulan rapor formatında, `-y` seçeneği kullanılmazsa RTTI adresi ve kurtarılan type üyeleri null kalır.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver, x86, AMD64, ARM ve ARM64 mimarilerinde PE, ELF ve Mach-O örneklerini destekler; dolayısıyla aynı iş akışı Windows, Linux ve macOS için Go binary'lerinde de uygulanabilir.<sup>[[10]](#references)</sup>

## Compiled Python

Bu sayfada, ELF/EXE biçiminde derlenmiş bir Python binary'sinden Python kodunu nasıl elde edebileceğinizi bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Bir GBA oyununun **binary** dosyasını elde ederseniz, onu **emulate** etmek ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Debug sürümünü indirin_) - Arayüzlü bir debugger içerir
- [**mgba** ](https://mgba.io)- CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin'i
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin'i

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünde Game Boy Advance **düğmelerine** nasıl basılacağını görebilirsiniz.

![Game Boy Advance düğme eşlemelerini gösteren no$gba kontrolleri yapılandırması](<../../images/image (581).png>)

Basılı tutulduğunda, her **tuşun onu tanımlayan bir değeri** vardır:

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

Yani, bu tür bir programda ilgi çekici kısım **programın kullanıcı girdisini nasıl işlediği** olacaktır. **0x4000130** adresinde sıkça karşılaşılan **KEYINPUT** işlevini bulabilirsiniz.

![KEYINPUT'e 0x4000130 adresinde başvuran bir GBA binary dosyasının Ghidra görünümü](<../../images/image (447).png>)

Önceki görselde, işlevin **FUN_080015a8** içinden çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

Bu işlevde, bazı başlangıç işlemlerinden sonra (önem taşımayan):

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

Son if, **`uVar4`**'ün **son Keys** içinde olup olmadığını ve mevcut key olmadığını kontrol ediyor; bu, bir düğmenin bırakılması anlamına da gelir (mevcut key **`uVar1`** içinde saklanır).

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

Önceki kodda **uVar1**'ı (**basılan düğmenin değerinin** bulunduğu yer) bazı değerlerle karşılaştırdığımızı görebilirsiniz:

- İlk olarak **4 değeriyle** (**SELECT** düğmesi) karşılaştırılır: Bu challenge'da bu düğme ekranı temizler.
- Ardından değer **8** (**START** düğmesi) ile karşılaştırılır; bu challenge'da bu yol, girilen kodun geçerli olup olmadığını kontrol eder.
  - Bu durumda **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılır ve değer aynıysa bazı kodlar çalıştırılır.
- Diğer tüm durumlarda bir sayaç (`DAT_030000d4`) kontrol edilip artırılır.\
  Sayaç 8'in altındayken basılan tuşların değerleri `DAT_030000d8` içinde biriktirilir.

Dolayısıyla bu challenge'da, düğmelerin değerlerini bilerek, **uzunluğu 8'den küçük ve toplamı 0xf3 olan bir kombinasyona basmanız gerekiyordu.**

**Bu eğitim için referans:** [arşivlenmiş Nostalgia challenge çözüm yazısı](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Kurslar

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRA ile MBA obfuscation'ı basitleştirme](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA deposu](https://github.com/trailofbits/CoBRA)
- [3] [Rust string'lerini çözme - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing eğitimi (arşivlenmiş)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI destekli Reverse Engineering'i engellemek ya da en azından denemek](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic Block eşleştirmeye dayalı Control Flow Graph karşılaştırma yaklaşımı](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver deposu](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mekanizması](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Golang binary'lerini otomatik olarak deobfuscate etmek için Control-Flow Graph benzerliğini kullanma](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor deposu](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang araçlarındaki güncellemeler](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Her Şeyi Reverse Engineer Edin](https://github.com/morluto/rea)
- [17] [REA managed-code analizi](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI ve Evidence kılavuzu](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninja control-flow unflattening iş akışı](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF Zero-Day saldırısı, Java Loader, Web Shell ve AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [IDA bridge sunucu uygulaması](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Ghidra bridge sunucu uygulaması](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) wildcard adresine bind olur](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Godot reverse engineering araç seti](https://github.com/figurophobia/gore)
- [26] [gore key-recovery uygulaması](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [gore şifreli blob formatı](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [gore komut ve recovery uygulaması](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
