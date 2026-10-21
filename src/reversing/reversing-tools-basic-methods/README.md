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

- wasm'dan (binary) wat'a (açık metin) **decompile** etmek için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) adresini kullanın
- wat'tan wasm'a **compile** etmek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) adresini kullanın
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

Buradaki avantaj, kaybolmuş kaynak kodunun eski bir assembly'den geri yüklenmesi gerektiğinde bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilmiş kodda kolay gezinme imkânı sunar ve bu da onu **Xamarin algoritma analizi** için ideal araçlardan biri yapar.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in modeli ve aracı tam ihtiyaçlarınıza uyarlayan bir API ile .NET Reflector zamandan tasarruf sağlar ve geliştirmeyi kolaylaştırır. Bu aracın sunduğu çok sayıda reverse engineering hizmetine göz atalım:

- Bir kütüphane veya bileşen içindeki veri akışına dair bilgi sağlar
- .NET dilleri ve framework'lerinin uygulanması ve kullanımı hakkında bilgi sağlar
- Kullanılan API ve teknolojilerden daha fazla yararlanmak için belgelenmemiş ve dışarıya açılmamış işlevleri bulur.
- Bağımlılıkları ve farklı assembly'leri bulur
- Kodunuzdaki, üçüncü taraf bileşenlerdeki ve kütüphanelerdeki hataların tam konumunu bulur.
- Üzerinde çalıştığınız tüm .NET kodlarının kaynağında debugging yapar.

### [ILSpy](https://github.com/icsharpcode/ILSpy) ve [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy plugin'i](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir işletim sisteminde kullanabilirsiniz (doğrudan VSCode'dan yükleyebilirsiniz; git'i indirmeniz gerekmez. **Extensions**'a tıklayın ve **ILSpy**'ı arayın).\
Yeniden **decompile**, **modify** ve **recompile** etmeniz gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak bakımı yapılan bir fork'u olan [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir fonksiyonun içindeki bir şeyi değiştirmek için **Right Click -> Modify Method** seçeneğini kullanın).

### REA ile çalıştırmadan managed inceleme

**REA**, assembly'yi yüklemeden PE/CLI metadata'sını ve CIL'i inceleyebilir. Önce artifact kimliğini belirleyin, ardından üyeleri ve tanımlanmış native sınırları inceleyin; bu, bir decompiler kullanmadan veya programı çalıştırmadan önce şüpheli çağrıları gözden geçirirken faydalıdır.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Sürüm karşılaştırması için `compare_managed_members`, metadata token'larını derlemeler arasında sabit kabul etmek yerine ham CIL/imza kimliğini ve çözümlenmiş talimat parmak izlerini kullanır. Bir P/Invoke bildirimi, native kodun çalıştığını kanıtlamaz; bu sınırı doğrulamak için `verify_managed_native_boundaries`, eşleşen bir native export veya function Evidence gerektirir. Artifact digest, MVID ve çözümlenmemiş eşlemeleri sonuçla birlikte saklayın.<sup>[[17]](#references)</sup>

### DNSpy Günlük Kaydı

**DNSpy'nin bazı bilgileri bir dosyaya kaydetmesini** sağlamak için şu snippet'i kullanabilirsiniz:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy'de Hata Ayıklama

DNSpy kullanarak kodda hata ayıklamak için şunları yapmanız gerekir:

İlk olarak, **debugging** ile ilgili **Assembly attributes** değerlerini değiştirin:

![DNSpy Logging - DNSpy'de Hata Ayıklama: İlk olarak, debugging ile ilgili Assembly attributes değerlerini değiştirin](<../../images/image (973).png>)

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

Ve **derle**'ye tıklayın:

![DNSpy Logging - DNSpy Debugging: Derle'ye tıklayın](<../../images/image (314) (1).png>)

Ardından yeni dosyayı _**Dosya >> Modülü kaydet...**_ üzerinden kaydedin:

![DNSpy Logging - DNSpy Debugging: Yeni dosyayı Dosya Modülü kaydet üzerinden kaydedin](<../../images/image (602).png>)

Bu gereklidir; çünkü bunu yapmazsanız, **çalışma zamanında** koda çeşitli **optimizasyonlar** uygulanır ve hata ayıklama sırasında bir **break-point'e hiç ulaşılamaması** veya bazı **değişkenlerin mevcut olmaması** mümkündür.

Ardından, .NET uygulamanız **IIS** tarafından **çalıştırılıyorsa**, uygulamayı şu komutla **yeniden başlatabilirsiniz**:

```
iisreset /noforce
```

Ardından hata ayıklamaya başlamak için açtığınız tüm dosyaları kapatın ve **Debug Tab** içinde **Attach to Process...** seçeneğini belirleyin:

![DNSpy Logging - DNSpy Debugging: Ardından hata ayıklamaya başlamak için açtığınız tüm dosyaları kapatın ve Debug Tab içinde Attach to Process seçeneğini belirleyin](<../../images/image (318).png>)

Ardından **IIS server**'a bağlanmak için **w3wp.exe**'yi seçip **attach**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Ardından IIS server'a bağlanmak için w3wp.exe'yi seçip attach'e tıklayın](<../../images/image (113).png>)

Artık süreci hata ayıklayıcıda izlediğimize göre, süreci durdurup tüm modülleri yükleme zamanı. Önce _Debug >> Break All_ öğesine, ardından _**Debug >> Windows >> Modules**_ öğesine tıklayın:

![DNSpy Logging - DNSpy Debugging: Artık süreci hata ayıklayıcıda izlediğimize göre, süreci durdurup tüm modülleri yükleme zamanı. Önce Debug Break All öğesine, ardından Debug Windows Modules öğesine tıklayın](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Artık süreci hata ayıklayıcıda izlediğimize göre, süreci durdurup tüm modülleri yükleme zamanı. Önce Debug Break All öğesine, ardından Debug Windows Modules öğesine tıklayın](<../../images/image (834).png>)

**Modules** içindeki herhangi bir modüle tıklayıp **Open All Modules**'ı seçin:

![DNSpy Logging - DNSpy Debugging: Modules içindeki herhangi bir modüle tıklayıp Open All Modules'ı seçin](<../../images/image (922).png>)

**Assembly Explorer** içindeki herhangi bir modüle sağ tıklayıp **Sort Assemblies**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer içindeki herhangi bir modüle sağ tıklayıp Sort Assemblies'e tıklayın](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'lerde hata ayıklama

### IDA kullanarak

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe, 32 bit sürümü C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Windbg** debugger'ını seçin
- "**Suspend on library load/unload**" seçeneğini belirleyin

![Debugging DLLs - Using IDA: " Suspend on library load/unload " seçeneğini belirleyin](<../../images/image (868).png>)

- **Parameters**'ı, **DLL'nin yolunu** ve çağırmak istediğiniz işlevi belirterek yapılandırın:

![Debugging DLLs - Using IDA: Parameters'ı, DLL'nin yolunu ve çağırmak istediğiniz işlevi belirterek yapılandırın](<../../images/image (704).png>)

Ardından hata ayıklamayı başlattığınızda **her DLL yüklendiğinde yürütme durdurulur**; rundll32 DLL'nizi yüklediğinde de yürütme durdurulur.

Bu yöntem modül yükleme olaylarında durur; ancak yüklenen DLL'nin giriş noktasına ulaşmak, aşağıdaki x64dbg iş akışına kıyasla daha dolaylıdır.

### x64dbg/x32dbg kullanarak

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe, 32 bit sürümü C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Command Line'ı değiştirin** ( _File --> Change Command Line_ ) ve DLL'nin yolunu ve çağırmak istediğiniz işlevi belirtin. Örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ seçeneğini değiştirip "**DLL Entry**"yi seçin.
- Ardından **yürütmeyi başlatın**. Debugger her dll main'de duracaktır; bir noktada **DLL'nizin Entry noktasında durur**. Buradan, breakpoint koymak istediğiniz noktaları aramanız yeterlidir.

win64dbg'de yürütme herhangi bir nedenle durduğunda, **win64dbg penceresinin üst kısmına** bakarak **hangi kodun içinde olduğunuzu** görebileceğinizi unutmayın:

![Using IDA - Using x64dbg/x32dbg: Yürütme win64dbg'de herhangi bir nedenle durduğunda, win64dbg penceresinin üst kısmına bakarak hangi kodun içinde olduğunuzu görebileceğinizi unutmayın](<../../images/image (842).png>)

Bu gösterge, yürütmenin hata ayıklamak istediğiniz DLL içinde durduğunu doğrular.

## GUI uygulamaları / video oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bu değerleri değiştirmek için kullanışlı bir programdır. Daha fazla bilgi:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), oyunlara odaklanan GNU Project Debugger (GDB) için bir front-end/reverse engineering aracıdır. Ancak reverse engineering ile ilgili her türlü iş için kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/), çeşitli decompiler'lar için web tabanlı bir front-end'dir. Bu web hizmeti, küçük executable dosyalarında farklı decompiler'ların çıktılarını karşılaştırmanıza olanak tanır.

## REA ile kanıta dayalı native inceleme

**REA**, Hopper, Ghidra ve IDA analizlerini CLI ve MCP üzerinden sunar. Node.js 22.x (en az 22.19), 24.x (en az 24.11) veya 26+ sürümü ve npm gerektirir. Önce mevcut bir native provider'ı yapılandırın; `rea providers --json` komutunu çalıştırıp hedefi destekleyen birden fazla provider varsa bunlardan birini açıkça seçin. Aşağıdaki `0x1000` yerine envanterde gözlemlenen bir işlev adını veya adresini kullanın.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Bir özellik dizesi veya sembolle başlayın; referansları ve çağıranları izleyin, ardından seçilen işlev dosyasını ve `rea decompile` ile üretilen pseudocode'u inceleyin. REA, başarısızlık sonrasında sessizce başka bir provider'a geçmek yerine oturumu seçilen provider'a bağlar. Tekrarlanabilir sorgular için `--snapshot PATH` yalnızca eşleşen artifact baytlarını, provider'ı, ayarları, işlemi ve parametreleri yeniden kullanır; snapshot, kaydedilmiş bir provider veritabanı değil, yerel bir önbellektir. Çıkarımla oluşturulan yolları veya decompiler metnini özgün kaynak olarak değerlendirmek yerine döndürülen Evidence'ı ve açıkça belirtilen bilinmeyenleri koruyun.<sup>[[16]](#references)[[18]](#references)</sup>

Native add-on'lara giden JavaScript/Electron giriş noktaları için bkz. [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Yerel TCP köprüsüyle betiklenmiş IDA ve Ghidra analizi

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge), **zaten açık** bir IDA veritabanı veya Ghidra CodeBrowser programı içinde çalışır ve ayrı bir betiğin bu analiz veritabanını sorgulamasına ve değiştirmesine olanak tanır. IDA'nın Python CLI'ından `ID_Server.py` dosyasını (`import ID_Server`) veya Ghidra'nın Script Manager'ından `Ghidra_Server.py` dosyasını çalıştırın. IDA, `127.0.0.1` adresinde `5073` numaralı porttan başlayarak çalışır ve daha yüksek numaralı portları tarar. Mevcut Ghidra betiği `5093` numaralı porttan başlar ve `5102` dahil on portu dener; Java soketi yalnızca loopback adresine değil, tüm adreslere bağlanır. Bağlanmadan önce örneğin yazdırdığı portu kontrol edin. Headless analyzer'dan farklı olarak bu köprü, o GUI örneğinde hâlihazırda açık olan program üzerinde çalışır.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Her bağlantıda **satır sonuyla biten tek bir komut** gönderin ve satır sonuyla biten yanıtı okuyun. Sonuç genellikle JSON'dur. Örneğin, bir giriş yoluyla ilgili içe aktarılmış API'yi bulduktan sonra `IMPORTXREF` çağrı noktalarını bulur; ardından `DECOMP_XREF`, seçilen bir adresin çağıranlarını toplu olarak decompile eder. `FUNC` bir işlevi incelerken `PCODE` decompiler'ın ara gösterimini döndürür. Farklı bir taban adresine taşınmış bir binary'den kopyalanan adresi değil, etkin veritabanındaki adresi kullanın. Aşağıdaki örnek IDA'nın varsayılan portunu kullanır; Ghidra için betiğin yazdırdığı portu kullanın.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Aynı kanal **analiz veritabanını değiştirebilir**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` ve `PATCH`; adları, türleri, yapı tanımlarını, fonksiyon sınırlarını veya kayıtlı baytları değiştirir. `PATCH`, veritabanında yapılan bir düzenlemedir; çalışan bir sürece yama uygulandığının kanıtı **değildir**. Dinleyicilerin hiçbiri kimlik doğrulamayı belgelemiyor. IDA yalnızca loopback üzerinden erişilebilir; ancak Ghidra ağ arayüzleri üzerinden erişilebilir olabilir. Ghidra kullanırken Ghidra dinleyicisine erişimi kısıtlayın. `QUIT` her iki dinleyiciyi de durdurur; IDA ayrıca `ida_bridge_stop()` işlevini sunar.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode'lar

### blobrunner ile shellcode debug etme

[**BlobRunner**](https://github.com/OALabs/BlobRunner), **shellcode** için bellek ayırır, **bellek adresini** yazdırır ve yürütmeyi duraklatır.\
IDA veya x64dbg gibi bir debugger bağlayın, yazdırılan adreste bir breakpoint ayarlayın ve shellcode'u debug etmek için yürütmeyi sürdürün.

GitHub releases sayfasında derlenmiş sürümleri içeren zip dosyaları bulunur: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
BlobRunner'ın biraz değiştirilmiş bir sürümünü aşağıdaki bağlantıda bulabilirsiniz. Derlemek için **Visual Studio Code'da bir C/C++ projesi oluşturun, kodu kopyalayıp yapıştırın ve build edin**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile shellcode debug etme

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner'a benzer. Shellcode için bellek ayırır ve sonsuz bir döngüye girer. Debugger'ı bağlayın, **2–5 saniye** boyunca yürütmeyi sürdürün, döngünün içinde duraklatın ve yürütmeyi ayrılan shellcode'a aktaran sonraki çağrıya kadar adım adım ilerleyin.

![jmp2it'in sonsuz döngüsünde, ayrılan shellcode'a yapılan çağrıdan hemen önce duraklatılmış debugger](<../../images/image (509).png>)

Derlenmiş [jmp2it sürümünü releases sayfasından](https://github.com/adamkramer/jmp2it/releases/) indirebilirsiniz.

### Cutter kullanarak shellcode debug etme

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'ın GUI'sidir. Cutter ile shellcode'u emulate edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Open File" ve "Open Shellcode" seçenekleri sunduğunu unutmayın. Benim durumumda shellcode'u dosya olarak açtığımda doğru şekilde decompile etti, ancak shellcode olarak açtığımda bunu yapmadı:

![Aynı baytları dosya veya shellcode olarak açınca farklı analiz sonuçları gösteren Cutter](<../../images/image (562).png>)

Emulation'ı istediğiniz konumda başlatmak için orada bir bp ayarlayın; görünüşe göre Cutter emulation'ı otomatik olarak o noktadan başlatacaktır:

![Cutter emulation'ı başlatmadan önce istenen shellcode girişine breakpoint ayarlanması](<../../images/image (589).png>)

![Seçili shellcode breakpoint'inde duraklatılmış Cutter emulator'ü](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görebilirsiniz:

![Cutter'ın hex dump'inde emule edilen shellcode stack'inin görüntülenmesi](<../../images/image (186).png>)

### Shellcode'un obfuscation'ını kaldırma ve yürütülen fonksiyonları bulma

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) aracını deneyebilirsiniz.\
Shellcode'un hangi **fonksiyonları** kullandığı ve bellekte kendi **decoding** işlemini yapıp yapmadığı gibi bilgileri verir.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg ayrıca istediğiniz seçenekleri seçip shellcode'u çalıştırabileceğiniz grafik bir başlatıcı da sunar

![Shellcode emülasyonu ve izleme seçeneklerini seçmek için scDbg grafik başlatıcısı](<../../images/image (258).png>)

**Create Dump** seçeneği, shellcode bellekte dinamik olarak değiştirilirse son halini dump eder (decoded shellcode'u indirmek için kullanışlıdır). **start offset**, shellcode'u belirli bir offset'ten başlatmak için kullanışlı olabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'da debug yapmanızı sağlar (ancak bu amaçla daha önce açıklanan seçeneklerden birini tercih ediyorum; çünkü Ida veya x64dbg kullanabilirsiniz).

### CyberChef kullanarak disassemble etme

Shellcode dosyanızı girdi olarak yükleyin ve onu disassemble etmek için şu tarifi kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` gibi basit ifadeleri aritmetik (`+`, `-`, `*`) ve bit düzeyinde işleçleri (`&`, `|`, `^`, `~`, kaydırmalar) bir araya getiren formüllerin arkasına gizler. Önemli nokta, bu özdeşliklerin genellikle yalnızca **sabit genişlikli modüler aritmetik** altında doğru olmasıdır; bu nedenle elde taşımalar ve taşmalar önemlidir:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Bu tür bir ifadeyi genel cebir araçlarıyla sadeleştirirseniz, bit genişliği semantiği göz ardı edildiği için kolayca yanlış bir sonuç elde edebilirsiniz.<sup>[[1]](#references)</sup>

### Uygulamalı iş akışı

1. Lift edilmiş kod/IR/decompiler çıktısındaki **orijinal bit genişliğini** koruyun (`8/16/32/64` bit).
2. Sadeleştirmeye çalışmadan önce ifadeyi **sınıflandırın**:
   - **Lineer**: bit düzeyindeki atomların ağırlıklı toplamları
   - **Semilineer**: `x & 0xFF` gibi sabit maskeler içeren lineer ifadeler
   - **Polinomsal**: çarpımlar içerir
   - **Karma**: çarpımlar ve bit düzeyindeki mantık iç içe geçmiştir; çoğu zaman yinelenen alt ifadeler bulunur
3. Aday her yeniden yazımı rastgele testlerle veya bir SMT kanıtıyla doğrulayın. Eşdeğerlik kanıtlanamıyorsa tahminde bulunmak yerine özgün ifadeyi koruyun.

### Dar bir yürütme dilimiyle düzleştirilmiş control-flow'u atlatma

Tam control-flow graph'ını çıkarmak çoğu zaman gereksizdir. Control-flow flattening, opaque predicate'ler, büyük dispatcher'lar veya MBA ağırlıklı kodlarda, şifrelenmiş blob'lara ve çıktı buffer'larına yapılan referansları izleyerek bunları dönüştüren en küçük rutini bulun. Ardından yalnızca bu data-flow dilimini yeniden üretin veya bağımsız olarak çalıştırın; ilgili state doğrudan başlatılabiliyorsa dispatcher gerekli çözümün parçası değildir.<sup>[[7]](#references)</sup>

Uygulamalı bir iş akışı:<sup>[[7]](#references)</sup>

1. Yürütülebilir ve veri bölümlerini, relocation'ları ve cross-reference'ları envantere alın. Bayt sıralamasını ve öğe genişliğini koruyarak `.rodata` içindeki olası tabloları dökümleyin.
2. Plaintext'i veya çıktı buffer'ını yazan son rutini belirleyin. Girdilerini, başvurduğu tabloları, import edilmiş çağrıları ve gerekli global state'i kaydedin.
3. Yalnızca bu işlemleri sabit genişlikli bir Python modeline aktarın. Dilim hâlâ çok fazla state'e bağlıysa, tüm programı emüle etmek yerine rutini Unicorn, QEMU veya bir debugger altında çağırın ve ilgisiz import'lara hook ekleyin.
4. Extractor'ın çıktısını gerçekten sağlanan binary'den türettiğini doğrulayın: sessiz fallback'leri kaldırın, gömülü yanıtları arayın ve değiştirilmiş string'ler, key'ler, identifier'lar, layout'lar ve obfuscation seed'leri içeren, daha önce görülmemiş build'lerde çalıştırın.

İlk aşamada kullanışlı komutlar:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Gizlenmiş sabitler olan MBA ifadelerini tespit etme

Görünüşte girdiye bağlı bir byte ifadesi, girdisini tamamen etkisiz hâle getirebilir. Tablolarını çıkardıktan sonra ifadeyi 8 bitlik tüm değerler üzerinde değerlendirin; tek elemanlı bir çıktı kümesi, çevresindeki durum makinesini çözmeden bu byte’ın sabit olduğunu kanıtlar.<sup>[[7]](#references)</sup>

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

Son maskeyi koruyun; çünkü özgün toplama işleminde byte genişliğinde taşma olur. Daha geniş bir domain için, bir SMT solver'a aynı genişlikteki iki sembolik girdi için `f(x1) != f(x2)` ifadesinin satisfiable olup olmadığını sorun: `unsat`, değişmezliği kanıtlarken `sat` bir karşı örnek verir ve girdinin atılamayacağı anlamına gelir.<sup>[[7]](#references)</sup>

#### Ortama bağlı decoding'i tanıyın

Anti-analysis kontrollerinin dallanma oluşturması veya çökmeye yol açması gerekmez. Bir decoder, sensör sonucunu bir key bitine, opaque-predicate sabitine veya flattened-dispatcher durumuna katabilir; normal şekilde çalışmaya devam edip emulator'da makul görünen ama yanlış plaintext üretebilir. Bu nedenle yalnızca görünür hata dallarını patch'lemek yeterli değildir; ortam yoklamalarından decoder durumuna uzanan veri bağımlılıklarını izleyin, aynı dilimi gerçek cihazda ve emulator'da karşılaştırın ve her sensör sonucunu zorlamanın son buffer'ı nasıl değiştirdiğini test edin.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA), malware analizi ve korumalı binary'lerin reverse engineering'i için pratik bir MBA sadeleştiricisidir. İfadeyi sınıflandırır ve her şeye tek bir genel rewrite pass uygulamak yerine özel işlem hatlarına yönlendirir.<sup>[[2]](#references)</sup>

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

Useful cases:

- **Linear MBA**: CoBRA, ifadeyi Boolean girdilerinde değerlendirir, bir imza türetir ve pattern matching, ANF conversion ve coefficient interpolation gibi çeşitli recovery yöntemlerini yarıştırır.
- **Semilinear MBA**: Sabit maskeli atomlar, maskelenmiş bölgelerin doğruluğunu korumak için bit-partitioned reconstruction ile yeniden oluşturulur.
- **Polynomial/Mixed MBA**: Çarpımlar bileşenlerine ayrılır ve dış ilişkiyi sadeleştirmeden önce yinelenen alt ifadeler geçici değişkenlere taşınabilir.

Sıklıkla kurtarılmaya değer, karma bir özdeşlik örneği:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Bu, şu şekilde sadeleştirilebilir:

```c
x * y
```

### Reversing notları

- Tam hesaplamayı izole ettikten sonra CoBRA'yı **lifted IR ifadeleri** veya decompiler çıktısı üzerinde çalıştırmayı tercih edin.
- İfade maskelenmiş aritmetikten veya dar yazmaçlardan kaynaklanıyorsa `--bitwidth` seçeneğini açıkça kullanın.
- Daha güçlü bir kanıtlama adımına ihtiyacınız varsa buradaki yerel Z3 notlarına göz atın:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca **LLVM pass plugin** (`libCobraPass.so`) olarak da sunulur; sonraki analiz pass'lerinden önce MBA ağırlıklı LLVM IR'yi normalleştirmek istediğinizde kullanışlıdır.
- Desteklenmeyen, carry'ye duyarlı, karma alanlı artık ifadeler; özgün ifadeyi koruyup carry yolunu elle incelemeniz gerektiğine işaret eder.

## XOR durumlu control-flow flattening'i geri çıkarma

OLLVM tarzı bir flattener, geçerli basic block durumunu iki adet 64 bit yazmaçta tutup dispatcher'da XOR ile yeniden oluşturabilir. Her özgün block, sonraki durumu için bu ikiliyi yazar ve dispatcher'a geri dallanır. Koşullu bir block, CPU bayraklarına göre ikilinin bir yarısını değiştirmek için `CMOVcc` kullanabilir; bu nedenle yalnızca görünen branch talimatlarını izlemek, iki ardılı da gözden kaçırır. Indirect-jump dispatcher'dan farklı olarak bu yapı, her yerde doğrudan geri kenarlar kullanabilir.<sup>[[19]](#references)[[20]](#references)</sup>

Grafiği geri çıkarmak için dispatcher karşılaştırma ağacını ve iki durum yazmacını belirleyin, karşılaştırılan her XOR durumunu hedef block'uyla eşleştirin, ardından her özgün block'ta yazmaç ikilisine ulaşan yazmaları izleyin. Koşullu yazmalarda bayrakları ayarlayan talimatı ve `CMOVcc`'nin her iki sonucunu da hesaba katın. Her block'un dispatcher çıkışını, çözümlenmiş doğrudan ardılına veya koşullu branch'ine dönüştürün; böylece binary'ye patch uygulamadan dispatcher erişilemez hâle gelir. Bu, tam bir CFG yaklaşımıdır; yalnızca tek bir decoder önemliyse yukarıdaki [dar execution-slice iş akışı](#bypass-flattened-control-flow-with-a-narrow-execution-slice) daha hızlı olabilir.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis), bu yapıyı Binary Ninja'da otomatikleştirir. `plugins/DispatchThis` dizinini Binary Ninja kullanıcı plugin dizinine kopyalayıp yeniden başlatın. Etkilenen function üzerinde **Function Settings**'i açıp `OLLVM_XOR_64`'ü seçin; analiz başlamazsa **Analysis → Reanalyze All Functions** seçeneğini kullanın. Bu mod dosya baytlarını değil, MLIL control-flow kenarlarını yeniden yazar ve Z3'e ya da indirect-jump resolver'a ihtiyaç duymaz. Binary Ninja 5.3.9757+ sürümlerinde test edilmiştir; block başına düşen ölü durum yazmalarını kaldırmadığından bunları hâlâ etkin olan geçişlerle karıştırmayın.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, program işlemlerini `mov` tabanlı talimat dizileriyle değiştirir ve control flow'u değiştirmek için signal/exception handling kullanır. Ayrıntılar için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Desteklenen binary'lerde [demovfuscator](https://github.com/kirschju/demovfuscator), sonucu deobfuscate edebilir. Birkaç bağımlılığı vardır.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Ve [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Bir **CTF oynuyorsanız, flag'i bulmak için bu geçici çözüm** çok işinize yarayabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**Entry point**'i bulmak için fonksiyon adlarında `::main` araması yapın:

![Ghidra'da fonksiyon adlarında çift iki nokta ve main arayarak Rust entry point'ini bulma](<../../images/image (1080).png>)

Bu durumda binary'nin adı authenticator'dı, dolayısıyla bunun ilgi çekici main fonksiyonu olduğu oldukça açık.\
Çağrılan **fonksiyonların** **adlarını** öğrendikten sonra, **girdileri** ve **çıktıları** hakkında bilgi edinmek için bunları **Internet**'te arayın.

### ELF firmware'inden Rust string'lerini kurtarma

**Rust ELF** binary'lerinde, birçok statik string, C tarzı NUL-terminated pointer'larla gösterilmez. Yaygın bir `rustc` düzeninde, gerçek string blob'una işaret eden **pointer/length tuple**'ı **`.data.rel.ro`** içinde bulunur; string blob'u ise **`.rodata`** içinde saklanır:

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
2. **`.data.rel.ro`** bölümünü her seferinde bir word olacak şekilde numaralandırın.
3. **`.rodata`** adres aralığındaki her değeri olası bir string işaretçisi olarak değerlendirin.
4. Sonraki word’ü olası uzunluk olarak değerlendirin.
5. Mantıklılık filtreleri uygulayın (örneğin, uzunluğu **4** ile **100** bayt arasında olanları tutun).
6. `0x00` değerine kadar taramak yerine, `.rodata` bölümünden tam olarak `length` bayt okuyun.

Minimum extractor mantığı:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Bu, özellikle firmware reversing sırasında çok kullanışlıdır; çünkü kurtarılan Rust string'leri genellikle **HTTP rotalarını, RPC adlarını, log mesajlarını, assertion'ları, dosya adlarını, config anahtarlarını, command handler'larını ve auth ile ilgili mantığı** ortaya çıkarır.

Ghidra bu string'leri bulamazsa, aynı heuristic'i uygulayan ve referans verilen `.rodata` offset'lerinde string verisi oluşturan özel bir script/plugin çalıştırın. Pen Test Partners tarafından yayımlanan `rust-strings` ve `RustStrings.py` araçları, bu yaklaşımı diğer **word size değerlerine, endianness türlerine ve section layout'larına** uyarlamak için iyi referanslardır.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi ile derlenmiş binary'ler için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Bir Delphi binary'sini reverse etmeniz gerekiyorsa IDA plugin'i [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

Bir Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu plugin, binary'yi çalıştırır ve debugging başladığında function adlarını dinamik olarak çözümler. Debugging'i başlattıktan sonra Start düğmesine (yeşil düğme veya f9) tekrar basın; gerçek kodun başlangıcında bir breakpoint tetiklenir.

Grafik uygulamasında bir düğmeye basarsanız debugger, o düğmenin çağırdığı function'da durabilir.

## Golang

Standart Go binary'leri için [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper), runtime yapılarını kurtarıp IDA'daki function adlarını iyileştirebilir. Python plugin'ini yüklemek için **Alt+F7** tuşlarına basın.

Bir Golang binary'sini reverse etmeniz gerekiyorsa IDA plugin'i [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm.

Bir Python plugin'i yüklemek için IDA'da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu, function adlarını çözümler.

### Symbol table olmadan metadata'yı kurtarma

Stripped bir Go executable'ı, program counter'ları function'lara eşlemek için yine de runtime metadata'sına ihtiyaç duyar. [GoReSym](https://github.com/mandiant/GoReSym), Go runtime'ından türetilen kodu kullanarak `pclntab` ve `moduledata` gibi yapıları bulup parse eder. Bu sayede geleneksel symbol table'a bağlı kalmadan function sınırları, adları, kaynak yolları, türler ve build ayrıntıları kurtarılabilir.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Bir obfuscator, kurtarılan adları değiştirirken bu yapıları kullanılabilir durumda bırakabilir. Örneğin Garble, tanımlayıcıları ve paket yollarını hash'ler, ayrıca build, module ve debug bilgilerini kaldırır.<sup>[[12]](#references)</sup> Obfuscate edilmiş paket token'ı, o paketteki işlevler arasında tutarlı kalmalıdır. İşlevleri tekrarlanan token'a göre gruplayın, çağrılan işlevlerden, string'lerden ve API'lerden bir paketi çıkarın, ardından bu paket etiketini grubun tamamına uygulayın.<sup>[[13]](#references)</sup>

### GoResolver ile Garble adlarını kurtarma

[GoResolver](https://github.com/volexity/GoResolver), runtime sembolü çıkarmayı temiz referans oluşturma ve control-flow-graph (CFG) eşleştirmeyle birleştirir. Şu sırayı izleyin:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Compiler sürümünü belirleyin.** Önce `BuildInfo` ve gömülü sürüm string'lerini deneyin. Obfuscator bunları kaldırmışsa, paketlenmiş Go runtime'ın bazı bölümlerini sürümlenmiş referans runtime'larla karşılaştırın. Volexity'nin testlerinde runtime'ın yaklaşık `2%`'si, ana Go sürümlerini ayırt etmeye yetti. Bunu evrensel bir eşik değil, deneysel bir optimizasyon olarak değerlendirin.<sup>[[13]](#references)</sup>
2. **Eşleşen referanslar oluşturun.** Belirlenen Go sürümü, hedef mimari ve olası kütüphaneler için temiz binary'ler üretin. Toolchain'in eşleşmesi, compiler tarafından oluşturulan CFG farklılıklarını azaltır.<sup>[[10]](#references)[[13]](#references)</sup>
3. **İşlevleri karşılaştırın.** GoGrapher, işlev CFG'lerini eşleştirir ve `0.0` ile `1.0` arasında normalize edilmiş skorlar üretir. Basic block eşleştirmesi, benzer talimatların ağırlıklı karşılaştırmasına dayanır. Yüksek güvenli eşleşmeler, rastgeleleştirilmiş işlevleri temiz implementasyonla eşler. Daha düşük güvenli eşleşmeler bile bir paketi veya modülü belirleyebilir.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Doğrulayın ve içe aktarın.** Önerilen adları çağrı ilişkileri, sabitler, string'ler ve yan etkilerle doğrulayın; ardından GoResolver plugin'ini kullanarak JSON raporunu IDA veya Ghidra'ya aktarın.<sup>[[10]](#references)[[13]](#references)</sup>

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

Varsayılan anlamlı eşleşme eşiği `0.9` değerindedir. `--extract` ve `--graph` anahtarları aşamalardan herhangi birini tek başına çalıştırabilir; varsayılan olarak her ikisi de çalıştırılır, çünkü kurtarılan runtime metadata ve CFG kanıtları birbirini tamamlar.<sup>[[10]](#references)</sup> CFG puanları sezgiseldir: inline etme, build flags, mimari ve kütüphane sürümü farklılıkları grafiğin şeklini değiştirebilir. Bu nedenle düşük güvenli adları zorla atamak yerine çözümlenmemiş işlevleri koruyun.<sup>[[13]](#references)</sup>

### Go string tablosunun kurtarılması

Go binary'leri, bağlı tüm paketlerin string baytlarını tek bir bitişik tabloda tutar. Girdiler NUL ile sonlandırılmaz ve runtime yapıları tablonun başlangıç adresini veya boyutunu göstermez. Ancak derleyici, girdileri işletim sistemleri ve mimariler arasında önce uzunluğa, sonra alfabetik sıraya göre düzenler. Bu nedenle bir girdi bulduktan sonra analist, bitişik girdiler arasında ilerleyebilir ve string'leri kodla ilişkilendirmek için veriye yönelik çapraz referansları kullanabilir.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor), bu iş akışını IDA Pro ve Ghidra'da otomatikleştirir. Eklenti veriye yönelik çapraz referanslara dayandığından önce otomatik analizin tamamlanmasını bekleyin. Varsayılan anchor, `entersyscall` runtime string'idir. Eklenti daha sonra her iki yönde de tarama yapabilir, kurtarılan string'leri veritabanında tanımlayabilir ve string'leri başvuran işlevlerle eşleştiren bir JSON çıktısı verebilir.<sup>[[14]](#references)</sup>

Uygulama veya malware kodunu bağlı kütüphanelerin oluşturduğu gürültüden ayırmak için raporu, başvuran işlevin paketine göre filtreleyin. Bu teknik, Garble'ın `-literals` dönüşümü gibi obfuscation yöntemleriyle gizlenen literal'ları kurtaramaz. Yine de obfuscation uygulanmamış runtime string'lerini düzenlemeye yardımcı olabilir.<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime türlerinin kurtarılması

Go, garbage collection gibi özelliklerin kullandığı runtime türü bilgilerini binary'ye gömer. Build bilgileri silindiğinde veya disassembler bu metadata'yı ayrıştıramadığında, talimatlar rastgele veri adreslerini yüklüyor gibi görünebilir ve hedef bölge türsüz kalabilir. Metadata'yı kurtarmak, bu adresleri okunabilir tür başvurularına dönüştürür ve paketlerin yeteneklerini anlamayı kolaylaştırır.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver), sembolleri çıkarabilir ve runtime türlerini ayrıştırarak bir JSON raporu oluşturabilir. Mevcut CLI'da `resolve` alt komutu kullanılır:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` seçeneği type parsing'i etkinleştirir. Kurtarılan type'ları tanımlamak ve referanslarını analiz veritabanına uygulamak için raporu GoResolver'ın IDA Pro veya Ghidra plugin'i ile içe aktarın. Bu özellikle sunulan rapor formatında, `-y` kullanılmadığında RTTI adresi ve kurtarılan type üyeleri null olur.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver, x86, AMD64, ARM ve ARM64 için PE, ELF ve Mach-O örneklerini destekler; bu nedenle aynı workflow Windows, Linux ve macOS'taki Go binary'leri için de geçerlidir.<sup>[[10]](#references)</sup>

## Derlenmiş Python

Bu sayfada, ELF/EXE Python derlenmiş bir binary'den Python kodunu nasıl alabileceğinizi bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Bir GBA oyununun **binary** dosyasını edinirseniz, onu **emüle etmek** ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Debug sürümünü indirin_) - Arayüzlü bir debugger içerir
- [**mgba** ](https://mgba.io)- CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin'i
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin'i

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünde Game Boy Advance **düğmelerine** nasıl basacağınızı görebilirsiniz.

![Game Boy Advance düğme eşlemelerini gösteren no$gba kontrol yapılandırması](<../../images/image (581).png>)

Basıldığında her **tuşun onu tanımlayan bir değeri** vardır:

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

Bu tür programlarda ilginç olan kısım **programın kullanıcı girdisini nasıl işlediğidir**. **0x4000130** adresinde sıkça bulunan **KEYINPUT** işlevini bulabilirsiniz.

![0x4000130 adresinde KEYINPUT'e başvuran bir GBA binary'sinin Ghidra görünümü](<../../images/image (447).png>)

Önceki görselde bu işlevin **FUN_080015a8**'den çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

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

Son if, **`uVar4`**'ün **son Keys** içinde olup olmadığını ve mevcut tuş olmadığını kontrol ediyor; buna bir tuşu bırakmak da denir (mevcut tuş **`uVar1`** içinde saklanır).

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
  Sayaç 8'in altındayken, basılan tuşların değerleri `DAT_030000d8` içinde biriktirilir.

Dolayısıyla bu challenge'da, düğmelerin değerlerini bilerek, toplamı 0xf3 olan ve uzunluğu 8'den küçük bir kombinasyona **basmanız gerekiyordu.**

**Bu eğitim için kaynak:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [CoBRA ile MBA obfuscation'ını basitleştirme](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA deposu](https://github.com/trailofbits/CoBRA)
- [3] [Rust string'lerini çözümleme - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing eğitimi (arşivlenmiş)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI destekli reverse engineering'i yenmek ya da en azından denemek](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic block eşleştirmesine dayalı kontrol akış grafiği karşılaştırma yaklaşımı](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver deposu](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mekanizması](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Golang ikililerini otomatik olarak deobfuscate etmek için kontrol akış grafiği benzerliğini kullanma](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor deposu](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang araçlarına güncellemeler](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Her şeyi reverse engineer edin](https://github.com/morluto/rea)
- [17] [REA managed-code analizi](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI ve kanıt kılavuzu](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninja kontrol akışını düzleştirmeyi kaldırma iş akışı](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF Zero-Day saldırısı, Java Loader, Web Shell ve AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [IDA bridge sunucu uygulaması](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Ghidra bridge sunucu uygulaması](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int), wildcard adresine bağlanır](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
