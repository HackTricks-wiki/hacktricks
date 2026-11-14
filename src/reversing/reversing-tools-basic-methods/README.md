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

- wasm'dan (binary) wat'a (açık metin) **decompile** etmek için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kullanın
- wat'ı wasm'a **compile** etmek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kullanın
- Decompilation için [web-wasmdec](https://wwwg.github.io/web-wasmdec/) aracını da deneyebilirsiniz.

Yazılım:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 önbelleğe alınmış bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Virtualized payload'lar ve özel VM'ler

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek; **library**'ler (.dll), **Windows metadata file**'ları (.winmd) ve **executable**'lar (.exe) dahil olmak üzere birden fazla formatı **decompile edip inceleyen** bir decompiler'dır. Decompile edildikten sonra bir assembly, Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantajı, kaybolmuş bir source code'un eski bir assembly'den kurtarılması gerektiğinde bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilmiş kodda kullanışlı gezinme özellikleri sunarak onu **Xamarin algorithm analysis** için ideal araçlardan biri hâline getirir.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in modeli ve aracı tam ihtiyaçlarınıza göre uyarlayan bir API ile .NET Reflector zamandan tasarruf sağlar ve geliştirmeyi kolaylaştırır. Bu aracın sunduğu çok sayıdaki reverse engineering hizmetine göz atalım:

- Verilerin bir library veya component içinde nasıl aktığına dair içgörü sağlar
- .NET dilleri ve framework'lerinin uygulanışı ve kullanımı hakkında içgörü sağlar
- Kullanılan API'lerden ve teknolojilerden daha fazla yararlanmak için belgelenmemiş ve dışa açılmamış işlevleri bulur.
- Bağımlılıkları ve farklı assembly'leri bulur
- Kodunuzdaki, üçüncü taraf component'lerdeki ve library'lerdeki hataların tam konumunu belirler.
- Üzerinde çalıştığınız tüm .NET kodlarının source'unu debug eder.

### [ILSpy](https://github.com/icsharpcode/ILSpy) ve [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy plugin'i](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir OS'te kullanabilirsiniz (doğrudan VSCode'dan yükleyebilirsiniz; git'i indirmeniz gerekmez. **Extensions**'a tıklayın ve **ILSpy**'ı arayın).\
Tekrar **decompile** etmek, **değiştirmek** ve **recompile** etmek istiyorsanız [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak sürdürülen fork'u [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir fonksiyonun içindeki bir şeyi değiştirmek için **Right Click -> Modify Method**).

### REA ile çalıştırma gerektirmeyen managed inceleme

**REA**, assembly'yi yüklemeden PE/CLI metadata'sını ve CIL'i inceleyebilir. Artifact kimliğini belirleyerek başlayın, ardından üyeleri ve tanımlanmış native sınırları inceleyin; bu, decompiler kullanmadan veya programı çalıştırmadan önce şüpheli çağrıları gözden geçirmek için yararlıdır.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Sürüm farklarını karşılaştırırken `compare_managed_members`, metadata token'larının derlemeler arasında sabit kaldığını varsaymak yerine ham CIL/imza kimliğini ve çözümlenmiş talimat parmak izlerini kullanır. Bir P/Invoke bildirimi, native kodun çalıştığını kanıtlamaz; `verify_managed_native_boundaries`, bu sınırı doğrulamak için eşleşen bir native export veya işlev kanıtına ihtiyaç duyar. Sonuçla birlikte artifact özeti, MVID ve çözümlenmemiş eşlemeleri saklayın.<sup>[[17]](#references)</sup>

### DNSpy Günlük Kaydı

**DNSpy'nin bazı bilgileri bir dosyaya kaydetmesini** istiyorsanız, bu snippet'i kullanabilirsiniz:

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

Ve **derle**'ye tıklayın:

![DNSpy Günlüğü - DNSpy Hata Ayıklama: Ve derle'ye tıklayın](<../../images/image (314) (1).png>)

Ardından yeni dosyayı _**Dosya >> Modülü Kaydet...**_ üzerinden kaydedin:

![DNSpy Günlüğü - DNSpy Hata Ayıklama: Ardından yeni dosyayı Dosya Modülü Kaydet üzerinden kaydedin](<../../images/image (602).png>)

Bu gereklidir; çünkü bunu yapmazsanız **çalışma zamanında** koda çeşitli **optimizasyonlar** uygulanır ve hata ayıklarken bir **kesme noktasına hiç ulaşılmaması** veya bazı **değişkenlerin mevcut olmaması** mümkün olabilir.

Ardından, .NET uygulamanız **IIS** tarafından **çalıştırılıyorsa** onu şu komutla **yeniden başlatabilirsiniz**:

```
iisreset /noforce
```

Ardından debugging işlemine başlamak için açık olan tüm dosyaları kapatın ve **Debug Tab** içinden **Attach to Process...** seçeneğini belirleyin:

![DNSpy Logging - DNSpy Debugging: Ardından debugging işlemine başlamak için açık olan tüm dosyaları kapatın ve Debug Tab içinden Attach to Process seçeneğini belirleyin](<../../images/image (318).png>)

Ardından **IIS server**'a bağlanmak için **w3wp.exe**'yi seçin ve **attach**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Ardından IIS server'a bağlanmak için w3wp.exe'yi seçin ve attach'e tıklayın](<../../images/image (113).png>)

Artık process'i debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce _Debug >> Break All_ seçeneğine, ardından _**Debug >> Windows >> Modules**_ seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Artık process'i debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Artık process'i debug ettiğimize göre, onu durdurup tüm modülleri yükleme zamanı. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (834).png>)

**Modules** içindeki herhangi bir modüle tıklayın ve **Open All Modules**'ı seçin:

![DNSpy Logging - DNSpy Debugging: Modules içindeki herhangi bir modüle tıklayın ve Open All Modules'ı seçin](<../../images/image (922).png>)

**Assembly Explorer** içindeki herhangi bir modüle sağ tıklayın ve **Sort Assemblies**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer içindeki herhangi bir modüle sağ tıklayın ve Sort Assemblies'e tıklayın](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL Debugging

### IDA kullanımı

- **rundll32'yi yükleyin** (64 bit sürüm C:\Windows\System32\rundll32.exe, 32 bit sürüm C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Windbg** debugger'ını seçin
- "**Suspend on library load/unload**" seçeneğini belirleyin

![Debugging DLLs - IDA kullanımı: " Suspend on library load/unload " seçeneğini belirleyin](<../../images/image (868).png>)

- Yürütmenin **parametrelerini**, **DLL'nin yolunu** ve çağırmak istediğiniz fonksiyonu girerek yapılandırın:

![Debugging DLLs - IDA kullanımı: DLL'nin yolunu ve çağırmak istediğiniz fonksiyonu girerek yürütmenin parametrelerini yapılandırın](<../../images/image (704).png>)

Ardından debugging'i başlattığınızda **her DLL yüklendiğinde yürütme durur**; dolayısıyla rundll32 DLL'nizi yüklediğinde yürütme duracaktır.

Bu yöntem modül yükleme olaylarında durur; ancak yüklenen DLL'nin entry point'ine ulaşmak, aşağıdaki x64dbg iş akışına kıyasla daha dolaylıdır.

### x64dbg/x32dbg kullanımı

- **rundll32'yi yükleyin** (64 bit sürüm C:\Windows\System32\rundll32.exe, 32 bit sürüm C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Command Line'ı değiştirin** ( _File --> Change Command Line_ ) ve DLL'nin yolunu ve çağırmak istediğiniz fonksiyonu ayarlayın; örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ seçeneğini değiştirin ve "**DLL Entry**"yi seçin.
- Ardından **yürütmeyi başlatın**; debugger her dll main'de duracaktır. Bir noktada **DLL'nizin Entry noktasında duracaksınız**. Buradan, breakpoint koymak istediğiniz noktaları aramanız yeterlidir.

win64dbg'de yürütme herhangi bir nedenle durduğunda, **win64dbg penceresinin üst kısmına** bakarak **hangi kodda olduğunuzu** görebileceğinizi unutmayın:

![IDA kullanımı - x64dbg/x32dbg kullanımı: Yürütme herhangi bir nedenle win64dbg'de durduğunda, win64dbg penceresinin üst kısmına bakarak hangi kodda olduğunuzu görebileceğinizi unutmayın](<../../images/image (842).png>)

Bu gösterge, yürütmenin debug etmek istediğiniz DLL'nin içinde durduğunu doğrular.

## GUI Uygulamaları / Video Oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bu değerleri değiştirmek için kullanışlı bir programdır. Daha fazla bilgi:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), oyunlara odaklanan, GNU Project Debugger (GDB) için bir front-end/reverse engineering aracıdır. Ancak reverse engineering ile ilgili her türlü iş için kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/), çeşitli decompiler'lara yönelik web tabanlı bir front-end'dir. Bu web hizmeti, küçük executable dosyalardaki farklı decompiler'ların çıktılarını karşılaştırmanıza olanak tanır.

### Godot PCK şifre çözme ve proje kurtarma

Dağıtılmış bir Godot oyunu için PCK dosyasını bağımsız bir `.pck` dosyasında, executable dosyasına eklenmiş veya gömülü bir pack'te ya da APK'nin `assets` dizininde bulun. [gore](https://github.com/figurophobia/gore) pack'i inceleyip çıkartabilir; script ve resource'ların tamamen yeniden oluşturulması içinse GDRE Tools gerekir (`gore setup` bunu yükler veya `--gdre` kullanın). Bu iş akışında araç, Godot 4.x PCK formatlarının v2–v4 sürümlerini destekler; v1 header'larını algılayabilir ancak v1 için bir key sağlanması gerekir.<sup>[[25]](#references)</sup>

Otomatik key kurtarma için şifrelenmiş bir file table gerekir; yalnızca dosya içerikleri şifrelenmişse bunun yerine bilinen bir key sağlayın. Kurtarma işleminin başarısız olması, pack'in şifrelenmemiş olduğunu kanıtlamaz.<sup>[[28]](#references)</sup>

Key arama işlemi bir **AES-256 keyspace saldırısı değildir**. Şifrelenmiş bir file table, düz metninin MD5 değerini, düz metin uzunluğunu, IV'yi ve AES-256-CFB ciphertext'ini açığa çıkarır.<sup>[[27]](#references)</sup> `gore`, oyun executable'ının veya yakındaki dosyaların 32 baytlık bölümlerini olası key'ler olarak dener. Olası çözülen path uzunluğu ve prefix değerlerine göre adayları filtreler, ardından tüm table'ı çözüp MD5 değerini kontrol ederek binary-scan bulgularını doğrular.<sup>[[26]](#references)[[28]](#references)</sup> Önce başlatılmış PE/ELF data section'larını arar, ardından tüm dosyada tarama yapar; `--scan` diğer aday dosyaları da aramaya ekler.<sup>[[28]](#references)</sup>

Gömülü bir key bulunmazsa, önceden tanımlı küçük bir parola listesi denenir; diğer adayları sağlamak için `--wordlist` kullanılır. Her parola, engine'in paroladan türetilen key temsili, sıfırlarla doldurulmuş literal veya 64 karakterlik hexadecimal key olarak denenir. Binary-scan bulgularının aksine, bu uygulamada wordlist bulguları yalnızca path yapısı filtresini geçer. Pack'i açıp çıkartılan asset'leri doğrulayarak bunları teyit edin.<sup>[[26]](#references)[[28]](#references)</sup>

Oyun dosyası yerel olarak mevcutsa, analiz için gereken aşamayı seçin. `recover`, açılabilir bir projeyi yeniden oluşturmak için GDRE'yi çalıştırırken `extract` yalnızca ham dosyaları açar. `key`, başka bir araçta kullanılabilecek olası bir key'i yazdırır.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## REA ile kanıtlarla desteklenen native inceleme

**REA**, Hopper, Ghidra ve IDA analizlerini CLI ve MCP üzerinden sunar. Node.js 22.x (en az 22.19), 24.x (en az 24.11) veya 26+ ile npm gerektirir. Önce mevcut bir native provider yapılandırın; `rea providers --json` komutunu çalıştırın ve birden fazla provider hedefi destekliyorsa açıkça bir provider seçin. Aşağıda `0x1000` yerine envanterdeki gözlemlenmiş bir fonksiyon adını veya adresini kullanın.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Bir feature string veya symbol ile başlayın, references ve callers'ı izleyin, ardından `rea decompile` ile seçilen function dossier'ı ve pseudocode'u inceleyin. REA, başarısızlık durumunda session'ı sessizce değiştirmek yerine seçilen provider'a bağlar. Tekrarlanabilir sorgular için `--snapshot PATH`, yalnızca eşleşen artifact byte'larını, provider'ı, ayarları, operation'ı ve parametreleri yeniden kullanır; snapshot, kaydedilmiş bir provider database'i değil, yerel bir cache'tir. Çıkarımla belirlenen yolları veya decompiler metnini orijinal kaynak olarak değerlendirmek yerine, döndürülen Evidence'ı ve açıkça belirtilen bilinmeyenleri koruyun.<sup>[[16]](#references)[[18]](#references)</sup>

Native add-on'lara giden JavaScript/Electron entry point'leri için bkz. [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Yerel TCP bridge ile betiklenmiş IDA ve Ghidra analizi

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge), **önceden açık olan** bir IDA database'i veya Ghidra CodeBrowser programı içinde çalışır ve ayrı bir script'in bu analiz database'ini sorgulayıp değiştirmesine olanak tanır. IDA'nın Python CLI'ından (`import ID_Server`) `ID_Server.py` dosyasını veya Ghidra'nın Script Manager'ından `Ghidra_Server.py` dosyasını çalıştırın. IDA, `127.0.0.1` adresinde `5073` portundan başlayarak daha yüksek portları tarar. Mevcut Ghidra script'i `5093` portundan başlar ve `5102`'ye kadar on portu dener; Java socket'i yalnızca loopback'e değil, wildcard adrese bağlanır. Bağlanmadan önce instance tarafından yazdırılan portu kontrol edin. Headless analyzer'ın aksine bu bridge, söz konusu GUI instance'ında o anda açık olan program üzerinde çalışır.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Her bağlantıda **newline ile sonlandırılmış tek bir komut** gönderin ve newline ile sonlandırılmış yanıtı okuyun. Sonuç normalde JSON'dur. Örneğin, bir input path ile ilgili imported API'yi bulduktan sonra, `IMPORTXREF` onun call site'larını bulur; ardından `DECOMP_XREF`, seçilen bir adresin callers'ını toplu olarak decompile eder. `FUNC` bir function'ı incelerken `PCODE`, decompiler'ın intermediate representation'ını döndürür. Farklı bir rebase işleminden geçmiş bir binary'den kopyalanan adresi değil, aktif database'deki adresi kullanın. Aşağıdaki örnek IDA'nın varsayılan portunu kullanır; Ghidra için script'in yazdırdığı portu kullanın.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Aynı kanal **analysis database'i değiştirebilir**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` ve `PATCH`; adları, türleri, structure tanımlarını, function sınırlarını veya saklanan byte'ları değiştirir. `PATCH`, bir database düzenlemesidir; **live-process patch uygulandığının kanıtı değildir**. İki listener da authentication'ı belgelemiyor. IDA yalnızca loopback üzerinden erişilebilir, ancak Ghidra network interface'leri üzerinden erişilebilir olabilir; kullanırken Ghidra listener'ına erişimi kısıtlayın. `QUIT` iki listener'ı da durdurur ve IDA ayrıca `ida_bridge_stop()` fonksiyonunu sunar.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner ile shellcode debugging

[**BlobRunner**](https://github.com/OALabs/BlobRunner), **shellcode** için bellek ayırır, **memory address**'ini yazdırır ve execution'ı duraklatır.\
IDA veya x64dbg gibi bir debugger bağlayın, yazdırılan adrese breakpoint koyun ve shellcode'u debug etmek için execution'ı sürdürün.

Releases GitHub sayfasında derlenmiş sürümlerin bulunduğu zip dosyaları var: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Aşağıdaki linkte Blobrunner'ın biraz değiştirilmiş bir sürümünü bulabilirsiniz. Derlemek için **Visual Studio Code'da bir C/C++ project oluşturun, kodu kopyalayıp yapıştırın ve build edin**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile shellcode debugging

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner'a benzer. Shellcode için bellek ayırır ve sonsuz bir döngüye girer. Debugger'ı bağlayın, **2–5 saniye** boyunca execution'ı sürdürün, döngünün içinde duraklatın ve execution'ı ayrılan shellcode'a aktaran sonraki call'a kadar step edin.

![jmp2it'in sonsuz döngüsünde, ayrılan shellcode'a yapılan call'dan hemen önce duraklatılmış debugger](<../../images/image (509).png>)

Derlenmiş bir [jmp2it sürümünü releases sayfasından indirebilirsiniz](https://github.com/adamkramer/jmp2it/releases/).

### Cutter kullanarak shellcode debugging

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'ın GUI'sidir. Cutter ile shellcode'u emulate edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Open File" ve "Open Shellcode" seçeneklerini sunduğunu unutmayın. Benim durumumda shellcode'u file olarak açtığımda doğru şekilde decompile etti, ancak shellcode olarak açtığımda etmedi:

![Aynı byte'lar file veya shellcode olarak açıldığında farklı analysis sonuçları gösteren Cutter](<../../images/image (562).png>)

Emulation'ı istediğiniz konumda başlatmak için oraya bir bp koyun; görünüşe göre Cutter emulation'ı otomatik olarak oradan başlatıyor:

![Cutter emulation'ını başlatmadan önce istenen shellcode giriş noktasına breakpoint koyma](<../../images/image (589).png>)

![Seçilen shellcode breakpoint'inde duraklatılmış Cutter emulator](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görebilirsiniz:

![Cutter'ın hex dump'ında emule edilmiş shellcode stack'ini görüntüleme](<../../images/image (186).png>)

### Shellcode'u deobfuscate etme ve çalıştırılan function'ları bulma

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)'yi deneyin.\
Shellcode'un hangi function'ları kullandığı ve memory'de kendi kendini **decode** edip etmediği gibi bilgileri gösterir.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg ayrıca istediğiniz seçenekleri seçip shellcode'u çalıştırabileceğiniz grafiksel bir başlatıcı da sunar

![Shellcode emülasyonu ve izleme seçeneklerini belirlemek için kullanılan scDbg grafiksel başlatıcısı](<../../images/image (258).png>)

**Create Dump** seçeneği, shellcode bellekte dinamik olarak değiştirildiyse son hâlini döker (çözümlenmiş shellcode'u indirmek için kullanışlıdır). **start offset**, shellcode'u belirli bir offset'te başlatmak için kullanışlı olabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'da hata ayıklamak için kullanışlıdır (ancak bu amaçla önceki seçeneklerden herhangi birini daha iyi buluyorum; çünkü Ida veya x64dbg kullanabileceksiniz).

### CyberChef kullanarak disassemble etme

Shellcode dosyanızı girdi olarak yükleyin ve onu decompile etmek için şu tarifi kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation'ını çözme

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` gibi basit ifadeleri aritmetik (`+`, `-`, `*`) ve bit düzeyinde operatörleri (`&`, `|`, `^`, `~`, kaydırmalar) bir araya getiren formüllerin ardına gizler. Önemli nokta, bu özdeşliklerin genellikle yalnızca **sabit genişlikli modüler aritmetik** altında doğru olmasıdır; bu nedenle elde taşımalar ve taşmalar önemlidir:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Bu tür bir ifadeyi genel cebir araçlarıyla sadeleştirirseniz, bit genişliği semantiği göz ardı edildiği için kolayca yanlış sonuç elde edebilirsiniz.<sup>[[1]](#references)</sup>

### Pratik iş akışı

1. **Özgün bit genişliğini** lifted code/IR/decompiler çıktısından koruyun (`8/16/32/64` bit).
2. Sadeleştirmeye çalışmadan önce ifadeyi **sınıflandırın**:
   - **Doğrusal**: bitwise atomların ağırlıklı toplamları
   - **Yarı-doğrusal**: `x & 0xFF` gibi sabit maskelerle birlikte doğrusal ifadeler
   - **Polinom**: çarpımlar içerir
   - **Karma**: çarpımlar ve bitwise mantık iç içedir; genellikle yinelenen alt ifadeler bulunur
3. Her olası yeniden yazımı random testing veya SMT proof ile doğrulayın. Eşdeğerlik kanıtlanamıyorsa tahmin yürütmek yerine özgün ifadeyi koruyun.

### Dar bir yürütme dilimiyle düzleştirilmiş control flow'u aşın

Tam control-flow graph'ı yeniden oluşturmak çoğu zaman gereksizdir. Control-flow flattening, opaque predicates, büyük dispatcher'lar veya MBA ağırlıklı kod söz konusu olduğunda, şifrelenmiş blob'lara ve output buffer'lara yapılan referansları izleyerek bunları dönüştüren en küçük rutini bulun. Ardından yalnızca bu data-flow slice'ını yeniden oluşturun veya bağımsız olarak çalıştırın; ilgili state doğrudan başlatılabiliyorsa dispatcher gerekli çözümün parçası değildir.<sup>[[7]](#references)</sup>

Pratik iş akışı:<sup>[[7]](#references)</sup>

1. Çalıştırılabilir ve veri bölümlerini, relocation'ları ve cross-reference'ları envanterleyin. Bayt sıralamasını ve öğe genişliğini koruyarak `.rodata` içindeki olası tabloları dump edin.
2. Plaintext veya output buffer'a yazan son rutini bulun. Girdilerini, başvurduğu tabloları, import edilmiş çağrıları ve gereken global state'i kaydedin.
3. Yalnızca bu işlemleri sabit genişlikli bir Python modeline aktarın. Slice hâlâ çok fazla state'e bağlıysa tüm programı emüle etmek yerine rutini Unicorn, QEMU veya debugger altında çağırıp ilgisiz import'ları hook edin.
4. Extractor'ın çıktısını gerçekten sağlanan binary'den türettiğini doğrulayın: sessiz fallback'leri kaldırın, gömülü yanıtları arayın ve değişmiş string'ler, key'ler, identifier'lar, layout'lar ve obfuscation seed'leri içeren daha önce görülmemiş build'lerde çalıştırın.

İlk aşamada kullanışlı komutlar:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Sabit gibi görünmeyen MBA ifadelerini tespit etme

Görünüşte girdiye bağlı olan bir bayt ifadesi, girdisini tamamen etkisiz hâle getirebilir. Tablolarını çıkardıktan sonra ifadeyi 8 bitlik tüm olası değerler için değerlendirin; tek elemanlı bir çıktı kümesi, çevresindeki durum makinesini çözmeden bu baytın sabit olduğunu kanıtlar.<sup>[[7]](#references)</sup>

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

Son maskeyi koruyun; çünkü özgün toplama işleminde bayt genişliğinde taşma ve sarma vardır. Daha geniş bir etki alanı için, aynı genişlikteki iki sembolik girdi için `f(x1) != f(x2)` ifadesinin sağlanabilir olup olmadığını bir SMT solver'a sorun: `unsat` değişmezliği kanıtlar; `sat` ise bir karşı örnek verir ve girdinin atılamayacağı anlamına gelir.<sup>[[7]](#references)</sup>

#### Ortama bağlı çözümlemeyi tanıyın

Anti-analysis kontrollerinin dallanması veya çökmesi gerekmez. Bir decoder, sensör sonucunu bir anahtar bitine, bir opaque-predicate sabitine veya flattened-dispatcher durumuna karıştırıp normal şekilde devam edebilir ve emülatörde makul görünen ama yanlış bir düz metin üretebilir. Bu nedenle yalnızca görünür hata dallarını yamamak yeterli değildir; ortam yoklamalarından decoder durumuna giden veri bağımlılıklarını izleyin, aynı dilimi gerçek cihazda ve emülatörde karşılaştırın ve her sensör sonucunu zorlamanın son arabelleği nasıl değiştirdiğini test edin.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA), malware analizi ve korumalı binary'lerin tersine mühendisliği için pratik bir MBA sadeleştiricisidir. İfadeyi sınıflandırır ve her şeye tek bir genel yeniden yazım geçişi uygulamak yerine, ifadeyi özelleşmiş işlem hatlarına yönlendirir.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA, ifadeyi Boolean girdiler üzerinde değerlendirir, bir imza çıkarır ve pattern matching, ANF conversion ve coefficient interpolation gibi çeşitli çözümleme yöntemlerini yarıştırır.
- **Semilinear MBA**: Sabit maskeli atomlar, maskelenmiş bölgelerin doğruluğunu korumak için bit-partitioned reconstruction ile yeniden oluşturulur.
- **Polynomial/Mixed MBA**: Çarpımlar çekirdeklere ayrılır ve dış ilişki sadeleştirilmeden önce yinelenen alt ifadeler geçici değişkenlere aktarılabilir.

Sıklıkla kurtarılmaya değer, karma bir özdeşlik örneği:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Bu, şu hâle indirgenebilir:

```c
x * y
```

### Reversing notları

- CoBRA'yı **lifted IR expressions** veya tam hesaplamayı izole ettikten sonra decompiler çıktısı üzerinde çalıştırmayı tercih edin.
- İfade masked arithmetic veya dar register'lar kaynaklıysa `--bitwidth` değerini açıkça belirtin.
- Daha güçlü bir kanıtlama adımına ihtiyacınız varsa buradaki yerel Z3 notlarına bakın:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca **LLVM pass plugin** (`libCobraPass.so`) olarak da gelir. Daha sonraki analiz pass'lerinden önce MBA ağırlıklı LLVM IR'yi normalize etmek istediğinizde kullanışlıdır.
- Desteklenmeyen, carry'ye duyarlı karma-domain kalıntıları, özgün ifadeyi koruyup carry yolunu elle incelemeniz gerektiğinin işareti olarak değerlendirilmelidir.

## XOR-state control-flow flattening'i çözümleme

OLLVM tarzı bir flattener, mevcut basic block durumunu iki adet 64-bit register'da tutabilir ve dispatcher'da XOR ile yeniden oluşturabilir. Her özgün block, sonraki durumu belirten register çiftini yazar ve dispatcher'a geri dallanır. Koşullu bir block, CPU flags'e göre çiftin bir yarısını değiştirmek için `CMOVcc` kullanabilir; bu nedenle yalnızca görünür branch talimatlarını izlemek iki ardılı gözden kaçırır. Indirect-jump dispatcher'dan farklı olarak bu yapı, her yerde doğrudan geri kenarlar kullanabilir.<sup>[[19]](#references)[[20]](#references)</sup>

Grafiği çözümlemek için dispatcher karşılaştırma ağacını ve iki state register'ını belirleyin, karşılaştırılan her XOR state'i hedef block'uyla eşleştirin, ardından her özgün block'ta register çiftine yapılan reaching write'ları izleyin. Koşullu write'larda, flags'i ayarlayan talimatı ve her iki `CMOVcc` sonucunu da dahil edin. Her block'un dispatcher çıkışını, çözümlenmiş doğrudan ardılına veya koşullu branch'ine dönüştürün; böylece binary'yi patch'lemeden dispatcher erişilemez hale gelir. Bu, tüm CFG'yi kapsayan bir yaklaşımdır; yalnızca tek bir decoder önemliyse yukarıdaki [dar execution-slice iş akışı](#bypass-flattened-control-flow-with-a-narrow-execution-slice) daha hızlı olabilir.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis), bu yapıyı Binary Ninja'da otomatikleştirir. `plugins/DispatchThis` dizinini Binary Ninja user plugin dizinine kopyalayıp yeniden başlatın. Etkilenen fonksiyonda **Function Settings**'i açıp `OLLVM_XOR_64`'ü seçin; analiz başlamazsa **Analysis → Reanalyze All Functions**'ı kullanın. Bu mod dosya baytlarını değil, MLIL control-flow edge'lerini yeniden yazar ve Z3'e veya indirect-jump resolver'a ihtiyaç duymaz. Binary Ninja 5.3.9757+ üzerinde test edilmiştir; block başına ölü state write'larını kaldırmaz, bu nedenle bunları hâlâ etkin geçişler sanmayın.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, program işlemlerini `mov` tabanlı talimat dizileriyle değiştirir ve control flow'u değiştirmek için signal/exception handling kullanır. Ayrıntılar için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Desteklenen binary'ler için [demovfuscator](https://github.com/kirschju/demovfuscator) sonucu deobfuscate edebilir. Birkaç bağımlılığı vardır.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Ve [keystone'u yükleyin](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Bir **CTF oynuyorsanız, flag'i bulmak için bu geçici çözüm** çok işinize yarayabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**Giriş noktasını** bulmak için, aşağıdaki örnekte olduğu gibi `::main` ifadesini aratarak fonksiyonları bulun:

![Ghidra'da fonksiyon adlarında çift iki nokta ve main ifadesini aratarak Rust giriş noktasını bulma](<../../images/image (1080).png>)

Bu örnekte binary'nin adı authenticator'dı, bu yüzden ilgi çekici main fonksiyonunun hangisi olduğu oldukça açık.\
Çağrılan **fonksiyonların** **adlarını** öğrendikten sonra **girdileri** ve **çıktıları** hakkında bilgi edinmek için **İnternet'te** aratın.

### ELF firmware'den Rust string'lerini kurtarma

**Rust ELF** binary'lerinde birçok statik string, C tarzı NUL sonlandırmalı işaretçilerle gösterilmez. Yaygın bir `rustc` düzeninde, **`.data.rel.ro`** içindeki **işaretçi/uzunluk demeti**, gerçek string verisinin bulunduğu **`.rodata`** bölümünü gösterir:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Bu, `strings` veya Ghidra’nın varsayılan analizinin bitişik string’leri birleştirebileceği ya da cross-reference’ları tamamen kaçırabileceği anlamına gelir.<sup>[[3]](#references)</sup>

Hızlı iş akışı:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`** bölümünün sanal adresini ve boyutunu alın.
2. **`.data.rel.ro`** bölümünü her seferinde bir word olacak şekilde enumerate edin.
3. **`.rodata`** adres aralığındaki değerleri olası string pointer'ları olarak değerlendirin.
4. Sonraki word'ü olası uzunluk olarak değerlendirin.
5. Sanity filter'ları uygulayın (örneğin, uzunluğu **4** ile **100** byte arasında tutun).
6. `0x00` değerine kadar taramak yerine **`.rodata`** bölümünden tam olarak `length` byte okuyun.

Minimal extractor mantığı:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Bu, firmware tersine mühendisliğinde özellikle kullanışlıdır; çünkü kurtarılan Rust dizeleri genellikle **HTTP rotalarını, RPC adlarını, günlük mesajlarını, assertions, dosya adlarını, config anahtarlarını, komut işleyicilerini ve auth ile ilgili mantığı** ortaya çıkarır.

Ghidra bu dizeleri bulamazsa aynı sezgisel yöntemi uygulayan ve başvurulan `.rodata` offset’lerinde string verisi oluşturan özel bir script/plugin çalıştırın. Pen Test Partners tarafından yayımlanan `rust-strings` ve `RustStrings.py` araçları, bu fikri diğer **word boyutlarına, endianness değerlerine ve bölüm düzenlerine** uyarlamak için iyi referanslardır.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi ile derlenmiş ikili dosyalar için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Bir Delphi ikilisini tersine mühendislikten geçirmeniz gerekiyorsa IDA plugin’i [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

IDA’da Python plugin’i yüklemek için **Alt+F7** tuşlarına basın ve ardından plugin dosyasını seçin.

Bu plugin, ikili dosyayı çalıştırır ve debugging başladığında fonksiyon adlarını dinamik olarak çözümler. Debugging başladıktan sonra Start düğmesine (yeşil düğme veya f9) tekrar basın; gerçek kodun başlangıcında bir breakpoint tetiklenir.

Grafik arayüzündeki bir düğmeye basarsanız debugger, o düğmenin çağırdığı fonksiyonda durabilir.

## Golang

Sıradan Go ikilileri için [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper), runtime yapılarını kurtarıp IDA’daki fonksiyon adlarını iyileştirebilir. Python plugin’ini yüklemek için **Alt+F7** tuşlarına basın.

Bir Golang ikilisini tersine mühendislikten geçirmeniz gerekiyorsa IDA plugin’i [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm.

IDA’da Python plugin’i yüklemek için **Alt+F7** tuşlarına basın ve ardından plugin dosyasını seçin.

Bu, fonksiyon adlarını çözümler.

### Recover metadata without the symbol table

Stripped bir Go çalıştırılabilir dosyası, program sayaçlarını fonksiyonlara eşlemek için yine de runtime metadata’sına ihtiyaç duyar. [GoReSym](https://github.com/mandiant/GoReSym), Go runtime’ından türetilen kodu kullanarak `pclntab` ve `moduledata` gibi yapıları bulup ayrıştırır. Bu sayede geleneksel symbol table’a bağlı kalmadan fonksiyon sınırları, adlar, kaynak yolları, türler ve derleme ayrıntıları kurtarılabilir.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Bir obfuscator, kurtarılan adları değiştirirken bu yapıları kullanılabilir durumda bırakabilir. Örneğin Garble, tanımlayıcıları ve paket yollarını hash'ler; build, module ve debug bilgilerini kaldırır.<sup>[[12]](#references)</sup> Obfuscate edilmiş paket token'ı, o paketteki fonksiyonlar arasında tutarlı kalmalıdır. Fonksiyonları tekrarlanan token'a göre gruplayın, çağırdıkları fonksiyonlardan, string'lerden ve API'lerden bir paketi çıkarın, ardından bu paket etiketini tüm gruba uygulayın.<sup>[[13]](#references)</sup>

### GoResolver ile Garble adlarını kurtarma

[GoResolver](https://github.com/volexity/GoResolver), runtime sembolü çıkarmayı temiz referans oluşturma ve control-flow-graph (CFG) eşleştirmeyle birleştirir. Şu sırayı izleyin:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Derleyici sürümünü belirleyin.** Önce `BuildInfo` ve gömülü sürüm string'lerini deneyin. Obfuscator bunları kaldırdıysa, paketlenmiş Go runtime'ının bölümlerini sürümlenmiş referans runtime'larıyla karşılaştırın. Volexity'nin testlerinde, Go'nun ana sürümlerini ayırt etmek için runtime'ın yaklaşık `%2`'si yeterliydi. Bunu evrensel bir eşik olarak değil, deneysel bir optimizasyon olarak değerlendirin.<sup>[[13]](#references)</sup>
2. **Eşleşen referanslar oluşturun.** Belirlenen Go sürümü, hedef mimari ve olası kütüphaneler için temiz binary'ler oluşturun. Toolchain'i eşleştirmek, derleyici tarafından oluşturulan CFG farklılıklarını azaltır.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Fonksiyonları karşılaştırın.** GoGrapher, fonksiyon CFG'lerini eşleştirir ve `0.0` ile `1.0` arasında normalize edilmiş skorlar üretir. Temel blok eşleştirmesi, benzer talimatların ağırlıklı karşılaştırmasına dayanır. Güven düzeyi yüksek eşleşmeler, rastgele adlandırılmış fonksiyonları temiz implementasyonla eşleştirir. Daha zayıf eşleşmeler yine de bir paketi veya modülü belirleyebilir.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
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

Varsayılan anlamlı eşleşme eşiği `0.9` değerindedir. `--extract` ve `--graph` seçenekleri aşamalardan birini tek başına çalıştırabilir. Varsayılan olarak ikisi de çalıştırılır; çünkü kurtarılan runtime metadata ve CFG kanıtları birbirini tamamlar.<sup>[[10]](#references)</sup> CFG puanları sezgiseldir: inline işlemleri, build flags, mimari ve kütüphane sürümü farklılıkları grafiğin şeklini değiştirebilir. Bu nedenle düşük güvenli adları zorla atamak yerine çözümlenemeyen işlevleri koruyun.<sup>[[13]](#references)</sup>

### Go string tablosunu kurtarma

Go binary dosyaları, bağlantısı yapılan tüm paketlerdeki string byte'larını tek bir bitişik tabloda tutar. Girdiler NUL ile sonlandırılmaz ve runtime yapıları tablonun başlangıç adresini veya boyutunu göstermez. Ancak derleyici, farklı işletim sistemleri ve mimarilerde girdileri önce uzunluklarına, sonra alfabetik sıraya göre düzenler. Bu nedenle bir girdi bulduktan sonra analist, bitişik girdileri tarayabilir ve string'leri koddaki referanslarla ilişkilendirmek için veri çapraz referanslarını kullanabilir.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor), bu iş akışını IDA Pro ve Ghidra'da otomatikleştirir. Eklenti veri segmenti çapraz referanslarına bağlı olduğundan, önce otomatik analizin tamamlanmasını bekleyin. Varsayılan anchor, `entersyscall` runtime string'idir. Eklenti daha sonra her iki yönde de tarama yapabilir, kurtarılan string'leri veritabanında tanımlayabilir ve string'leri referans veren işlevlerle eşleştiren bir JSON çıktısı oluşturabilir.<sup>[[14]](#references)</sup>

Uygulama veya malware kodunu bağlantısı yapılan kütüphanelerin oluşturduğu gürültüden ayırmak için raporu, referans veren işlevin paketine göre filtreleyin. Bu teknik, Garble'ın `-literals` dönüşümü gibi obfuscation yöntemleriyle yok edilen literal'ları kurtaramaz. Ancak obfuscation uygulanmamış runtime string'lerini düzenlemeye yardımcı olabilir.<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime türlerini kurtarma

Go, garbage collection gibi özelliklerin kullandığı runtime türü bilgilerini binary dosyaya gömer. Build bilgileri kaldırıldığında veya disassembler bu metadata'yı ayrıştıramadığında, talimatlar gelişigüzel veri adreslerini yüklüyor gibi görünebilir ve hedef bölge türlendirilmemiş kalır. Metadata'nın kurtarılması, bu adresleri okunabilir tür referanslarına dönüştürür ve paketlerin yeteneklerini anlamayı kolaylaştırır.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver), sembolleri çıkarıp runtime türlerini ayrıştırarak bir JSON raporu oluşturabilir. Mevcut CLI'da `resolve` alt komutu kullanılır:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` seçeneği type parsing'i etkinleştirir. Kurtarılan type'ları tanımlamak ve referanslarını analiz veritabanına uygulamak için raporu GoResolver'ın IDA Pro veya Ghidra plugin'iyle içe aktarın. Bu özellik ile sunulan rapor formatında `-y` seçeneği kullanılmazsa RTTI adresi ve kurtarılan type üyeleri null kalır.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver; x86, AMD64, ARM ve ARM64 için PE, ELF ve Mach-O örneklerini destekler, böylece aynı iş akışı Windows, Linux ve macOS'tan Go binary dosyaları için de geçerlidir.<sup>[[10]](#references)</sup>

## Derlenmiş Python

Bu sayfada, ELF/EXE biçiminde derlenmiş bir Python binary dosyasından Python kodunun nasıl elde edileceğini bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Bir GBA oyununun **binary** dosyasını elde ederseniz, oyunu **emulate** etmek ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Debug sürümünü indirin_) - Arayüzlü bir debugger içerir
- [**mgba** ](https://mgba.io)- CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin'i
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin'i

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünde Game Boy Advance **düğmelerine** nasıl basılacağını görebilirsiniz

![Game Boy Advance düğme eşlemelerini gösteren no$gba kontrol yapılandırması](<../../images/image (581).png>)

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

Yani, bu tür bir programda ilgi çekici kısım **programın kullanıcı girdisini nasıl işlediği** olacaktır. **0x4000130** adresinde sıkça karşılaşılan **KEYINPUT** fonksiyonunu bulabilirsiniz.

![0x4000130 adresinde KEYINPUT'e başvuran bir GBA binary dosyasının Ghidra görünümü](<../../images/image (447).png>)

Önceki görselde, fonksiyonun **FUN_080015a8**'den çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

Bu fonksiyonda, bazı başlangıç işlemlerinden sonra (önemli olmayan):

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

Şu kod bulunur:

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

Son if, **uVar4**'ün önceki Keys içinde bulunduğunu ve geçerli tuş olmadığını kontrol ediyor; buna bir düğmeyi bırakma da denir (geçerli tuş **uVar1** içinde saklanır).

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

Önceki kodda, **uVar1**'in (**basılan düğmenin değerinin** bulunduğu yer) bazı değerlerle karşılaştırıldığını görebilirsiniz:

- İlk olarak **4 değeriyle** (**SELECT** düğmesi) karşılaştırılır: Challenge'da bu düğme ekranı temizler.
- Ardından değer **8** (**START** düğmesi) ile karşılaştırılır; bu challenge'da bu yol, girilen kodun geçerli olup olmadığını denetler.
  - Bu durumda **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılır ve değer aynıysa bazı kodlar çalıştırılır.
- Diğer tüm durumlarda bir sayaç (`DAT_030000d4`) kontrol edilir ve artırılır.\
  Sayaç 8'den küçükken basılan tuşların değerleri `DAT_030000d8` içinde biriktirilir.

Dolayısıyla bu challenge'da, düğmelerin değerlerini bildiğinizde **toplamı 0xf3 eden, uzunluğu 8'den küçük bir tuş kombinasyonuna basmanız gerekiyordu.**

**Bu eğitim için referans:** [arşivlenmiş Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [3] [Rust dizelerini çözümleme - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing eğitimi (arşivlenmiş)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI destekli reverse engineering'i yenmek ya da en azından denemek](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Temel blok eşleştirmeye dayalı bir kontrol akış grafiği karşılaştırma yaklaşımı](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver deposu](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mekanizması](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Golang binary'lerini otomatik olarak deobfuscate etmek için kontrol akış grafiği benzerliğini kullanma](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor deposu](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang araçlarındaki güncellemeler](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Her Şeyi Tersine Mühendislik Et](https://github.com/morluto/rea)
- [17] [REA managed-code analizi](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI ve kanıt kılavuzu](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninja kontrol akışını düzleştirme kaldırma iş akışı](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF Zero-Day saldırısı, Java Loader, Web Shell ve AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [IDA bridge sunucu uygulaması](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Ghidra bridge sunucu uygulaması](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int), wildcard adresine bağlanır](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Godot reverse engineering araç seti](https://github.com/figurophobia/gore)
- [26] [gore anahtar kurtarma uygulaması](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [gore şifrelenmiş blob biçimi](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [gore komut ve kurtarma uygulaması](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
