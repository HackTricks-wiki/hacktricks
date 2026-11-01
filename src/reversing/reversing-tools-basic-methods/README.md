# Tersine Mühendislik Araçları ve Temel Yöntemler

{{#include ../../banners/hacktricks-training.md}}

## ImGui Tabanlı Tersine Mühendislik Araçları

Yazılım:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## WinDbg kullanıcı modu otomasyonu

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows istisna güdümlü kontrol akışı

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Windows kernel hata ayıklama

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Çevrimiçi:

- wasm (binary) dosyasından wat (düz metin) dosyasına **decompile** etmek için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) adresini kullanın
- wat dosyasından wasm dosyasına **compile** etmek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) adresini kullanın
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

dotPeek, **library'ler** (.dll), **Windows metadata dosyaları** (.winmd) ve **çalıştırılabilir dosyalar** (.exe) dahil olmak üzere çeşitli biçimleri **decompile edip inceleyen** bir decompiler'dır. Decompile edildikten sonra bir assembly, Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantaj, kayıp kaynak kodunun eski bir assembly'den geri yüklenmesi gerektiğinde bu işlemin zaman kazandırabilmesidir. Ayrıca dotPeek, decompile edilmiş kodda kullanışlı gezinme olanağı sunarak **Xamarin algoritma analizi** için en uygun araçlardan biri olmasını sağlar.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir add-in modeli ve aracı tam ihtiyaçlarınıza göre uyarlayan bir API ile .NET Reflector zamandan tasarruf sağlar ve geliştirme sürecini basitleştirir. Bu aracın sunduğu çok sayıdaki tersine mühendislik hizmetine göz atalım:

- Bir library veya component içindeki veri akışı hakkında bilgi sağlar
- .NET dilleri ve framework'lerinin uygulanışı ve kullanımı hakkında bilgi sağlar
- Kullanılan API ve teknolojilerden daha fazla yararlanmak için belgelenmemiş ve dışarıya açılmamış işlevleri bulur.
- Bağımlılıkları ve farklı assembly'leri bulur
- Kodunuzdaki, üçüncü taraf component'lerdeki ve library'lerdeki hataların tam konumunu bulur.
- Çalıştığınız tüm .NET kodlarının kaynağında debug işlemi yapar.

### [ILSpy](https://github.com/icsharpcode/ILSpy) ve [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy plugin'i](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir OS'te kullanabilirsiniz (VSCode'dan doğrudan yükleyebilirsiniz; git'i indirmeniz gerekmez. **Extensions** bölümüne tıklayıp **ILSpy** araması yapın).\
**Decompile** etmek, **değişiklik yapmak** ve yeniden **compile** etmek istiyorsanız [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak bakımı yapılan bir fork'u olan [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (Bir fonksiyon içindeki bir şeyi değiştirmek için **Right Click -> Modify Method** seçeneğini kullanın).

### REA ile çalıştırma gerektirmeyen managed inceleme

**REA**, assembly'yi yüklemeden PE/CLI metadata'sını ve CIL'i inceleyebilir. Önce artifact'in kimliğini belirleyin, ardından üyeleri ve tanımlı native sınırları inceleyin; bu, bir decompiler kullanmadan veya programı çalıştırmadan önce şüpheli çağrıları gözden geçirirken faydalıdır.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Sürüm karşılaştırması için `compare_managed_members`, metadata token’larını derlemeler arasında kararlı kabul etmek yerine ham CIL/imza kimliğini ve çözümlenmiş talimat parmak izlerini kullanır. Bir P/Invoke bildirimi, native kodun çalıştığının kanıtı değildir; `verify_managed_native_boundaries`, bu sınırı denetlemek için eşleşen bir native export veya function Evidence gerektirir. Artifact digest, MVID ve çözümlenmemiş eşlemeleri sonuçla birlikte saklayın.<sup>[[17]](#references)</sup>

### DNSpy Logging

**DNSpy'nin bir dosyaya bazı bilgileri loglamasını** sağlamak için şu kod parçasını kullanabilirsiniz:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Hata Ayıklama

DNSpy kullanarak kodda hata ayıklamak için şunları yapmanız gerekir:

İlk olarak, **hata ayıklamayla** ilgili **Assembly özniteliklerini** değiştirin:

![DNSpy Logging - DNSpy Hata Ayıklama: İlk olarak, hata ayıklamayla ilgili Assembly özniteliklerini değiştirin](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: Ve compile'a tıklayın](<../../images/image (314) (1).png>)

Ardından yeni dosyayı _**File >> Save module...**_ üzerinden kaydedin:

![DNSpy Logging - DNSpy Debugging: Ardından yeni dosyayı File Save module üzerinden kaydedin](<../../images/image (602).png>)

Bunu yapmak gerekir; aksi takdirde **runtime** sırasında koda çeşitli **optimizasyonlar** uygulanır ve debugging yaparken bir **break-point'e hiç ulaşılmayabilir** ya da bazı **değişkenler bulunmayabilir**.

Ardından, .NET uygulamanız **IIS** tarafından **çalıştırılıyorsa**, uygulamayı şu komutla **yeniden başlatabilirsiniz**:

```
iisreset /noforce
```

Ardından debugging işlemine başlamak için açık olan tüm dosyaları kapatın ve **Debug Tab** içinden **Attach to Process...** seçeneğini seçin:

![DNSpy Logging - DNSpy Debugging: Debugging işlemine başlamak için açık olan tüm dosyaları kapatın ve Debug Tab içinden Attach to Process seçeneğini seçin](<../../images/image (318).png>)

Ardından **IIS server**'a bağlanmak için **w3wp.exe**'yi seçin ve **attach**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: IIS server'a bağlanmak için w3wp.exe'yi seçin ve attach'e tıklayın](<../../images/image (113).png>)

Artık process'i debug ettiğimize göre onu durdurup tüm modülleri yükleme zamanı. Önce _Debug >> Break All_ seçeneğine, ardından _**Debug >> Windows >> Modules**_ seçeneğine tıklayın:

![DNSpy Logging - DNSpy Debugging: Artık process'i debug ettiğimize göre onu durdurup tüm modülleri yükleme zamanı. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Artık process'i debug ettiğimize göre onu durdurup tüm modülleri yükleme zamanı. Önce Debug Break All seçeneğine, ardından Debug Windows Modules seçeneğine tıklayın](<../../images/image (834).png>)

**Modules** içindeki herhangi bir modüle tıklayın ve **Open All Modules**'ı seçin:

![DNSpy Logging - DNSpy Debugging: Modules içindeki herhangi bir modüle tıklayın ve Open All Modules'ı seçin](<../../images/image (922).png>)

**Assembly Explorer** içindeki herhangi bir modüle sağ tıklayın ve **Sort Assemblies**'e tıklayın:

![DNSpy Logging - DNSpy Debugging: Assembly Explorer içindeki herhangi bir modüle sağ tıklayın ve Sort Assemblies'e tıklayın](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'lerde debugging

### IDA kullanımı

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe konumunda, 32 bit sürümü ise C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Windbg** debugger'ını seçin
- "**Suspend on library load/unload**" seçeneğini seçin

![Debugging DLLs - Using IDA: "Suspend on library load/unload" seçeneğini seçin](<../../images/image (868).png>)

- Çalıştırma **parametrelerini**, **DLL'nin yolunu** ve çağırmak istediğiniz işlevi belirterek yapılandırın:

![Debugging DLLs - Using IDA: DLL'nin yolunu ve çağırmak istediğiniz işlevi belirterek çalıştırma parametrelerini yapılandırın](<../../images/image (704).png>)

Ardından debugging'i başlattığınızda **her DLL yüklendiğinde çalıştırma durdurulur**; rundll32 DLL'nizi yüklediğinde de çalıştırma durdurulur.

Bu yöntem modül yükleme olaylarında durur, ancak yüklenen DLL'nin entry point'ine ulaşmak aşağıdaki x64dbg iş akışına kıyasla daha dolaylıdır.

### x64dbg/x32dbg kullanımı

- **rundll32'yi yükleyin** (64 bit sürümü C:\Windows\System32\rundll32.exe konumunda, 32 bit sürümü ise C:\Windows\SysWOW64\rundll32.exe konumundadır)
- **Command Line'ı değiştirin** ( _File --> Change Command Line_ ) ve dll'nin yolunu ve çağırmak istediğiniz işlevi belirtin. Örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ bölümüne gidin ve "**DLL Entry**" seçeneğini seçin.
- Ardından **çalıştırmayı başlatın**; debugger her dll main'de durur ve bir noktada **dll'nizin DLL Entry noktasında durur**. Buradan, breakpoint koymak istediğiniz noktaları arayın.

win64dbg'de çalıştırma herhangi bir nedenle durduğunda, **win64dbg penceresinin üst kısmına** bakarak **hangi kodun içinde olduğunuzu** görebilirsiniz:

![Using IDA - Using x64dbg/x32dbg: Çalıştırma herhangi bir nedenle win64dbg'de durduğunda, win64dbg penceresinin üst kısmına bakarak hangi kodun içinde olduğunuzu görebilirsiniz](<../../images/image (842).png>)

Bu gösterge, çalıştırmanın debug etmek istediğiniz DLL'nin içinde durduğunu doğrular.

## GUI uygulamaları / video oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php), çalışan bir oyunun belleğinde önemli değerlerin nerede saklandığını bulmak ve bu değerleri değiştirmek için kullanışlı bir programdır. Daha fazla bilgi:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE), oyunlara odaklanan, GNU Project Debugger (GDB) için bir front-end/reverse engineering aracıdır. Bununla birlikte, reverse engineering ile ilgili her türlü iş için kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/), çeşitli decompiler'lara web üzerinden erişim sağlayan bir front-end'dir. Bu web hizmeti, küçük executable dosyalarda farklı decompiler'ların çıktılarını karşılaştırmanızı sağlar.

### Godot PCK şifre çözme ve proje kurtarma

Dağıtılmış bir Godot oyunu için PCK dosyasını bağımsız bir `.pck` dosyasında, executable'a eklenmiş veya gömülü bir pakette ya da APK'nın `assets` dizininde bulun. [gore](https://github.com/figurophobia/gore) paketi inceleyip çıkarabilir; tüm script ve kaynakların yeniden oluşturulması için GDRE Tools gerekir (`gore setup` bunu yükler veya `--gdre` kullanın). Bu iş akışında araç Godot 4.x PCK biçimleri v2–v4'ü destekler; v1 başlıklarını algılayabilir ancak v1 için sağlanan bir anahtar gerekir.<sup>[[25]](#references)</sup>

Otomatik anahtar kurtarma için şifrelenmiş bir file table gerekir; yalnızca dosya içerikleri şifrelenmişse bunun yerine bilinen bir anahtar sağlayın. Kurtarma işleminin başarısız olması, paketin şifrelenmemiş olduğunu kanıtlamaz.<sup>[[28]](#references)</sup>

Anahtar araması **AES-256 keyspace saldırısı değildir**. Şifrelenmiş bir file table, düz metninin MD5 değerini, düz metin uzunluğunu, IV'yi ve AES-256-CFB şifreli metnini açığa çıkarır.<sup>[[27]](#references)</sup> `gore`, aday anahtarlar olarak oyun executable'ından veya yakındaki dosyalardan alınan 32 baytlık pencereleri dener. Adayları makul düz metin yol uzunluğuna ve önekine göre filtreler; ardından binary-scan eşleşmelerini tablonun tamamının şifresini çözerek ve MD5 değerini kontrol ederek doğrular.<sup>[[26]](#references)[[28]](#references)</sup> Önce başlatılmış PE/ELF veri bölümlerinde arama yapar, ardından tüm dosyayı tarar; `--scan` diğer aday dosyaları da ekler.<sup>[[28]](#references)</sup>

Gömülü bir anahtar bulunmazsa, önceden tanımlanmış küçük bir parola listesi denenir; diğer adayları sağlamak için `--wordlist` kullanılır. Her parola; engine'in paroladan türetilmiş anahtar gösterimi, sıfırlarla doldurulmuş bir literal veya 64 hex karakterlik bir anahtar olarak denenir. Binary-scan eşleşmelerinin aksine, bu uygulamada wordlist eşleşmeleri yalnızca yol yapısı filtresini geçer. Paketi açıp çıkarılan asset'leri doğrulayarak bunları teyit edin.<sup>[[26]](#references)[[28]](#references)</sup>

Oyun dosyası yerel olarak mevcutsa analiz için gereken aşamayı seçin. `recover`, açılabilir bir projeyi yeniden oluşturmak için GDRE'yi çalıştırırken `extract` yalnızca ham dosyaları çıkarır. `key`, başka bir araçta kullanmak üzere aday bir anahtarı yazdırır.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## REA ile kanıta dayalı yerel inceleme

**REA**, Hopper, Ghidra ve IDA analizlerini CLI ve MCP üzerinden sunar. Node.js 22.x (en az 22.19), 24.x (en az 24.11) veya 26+ sürümü ve npm gerektirir. Önce mevcut bir yerel sağlayıcıyı yapılandırın; `rea providers --json` komutunu çalıştırın ve birden fazla sağlayıcı hedefi destekliyorsa açıkça bir sağlayıcı seçin. Aşağıdaki `0x1000` yerine envanterde gözlemlenen bir işlev adını veya adresini kullanın.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Bir feature string veya sembolden başlayın, referansları ve çağıranları izleyin, ardından seçilen fonksiyonun dökümünü ve sözde kodunu `rea decompile` ile inceleyin. REA, başarısızlık durumunda sessizce başka bir sağlayıcıya geçmek yerine oturumu seçilen sağlayıcıya bağlar. Tekrarlanabilir sorgular için `--snapshot PATH` yalnızca eşleşen artifact baytlarını, sağlayıcıyı, ayarları, işlemi ve parametreleri yeniden kullanır; snapshot yerel bir önbellektir, kaydedilmiş bir sağlayıcı veritabanı değildir. Döndürülen Evidence ve açıkça belirtilen bilinmeyenleri koruyun; çıkarımla bulunan yolları veya decompiler metnini özgün kaynak kodu olarak değerlendirmeyin.<sup>[[16]](#references)[[18]](#references)</sup>

JavaScript/Electron giriş noktalarından native add-on'lara uzanan yollar için bkz. [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Yerel TCP köprüsüyle IDA ve Ghidra üzerinden betikli analiz

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge), **önceden açık** bir IDA veritabanı veya Ghidra CodeBrowser programı içinde çalışır ve ayrı bir betiğin bu analiz veritabanını sorgulayıp değiştirmesini sağlar. IDA'nın Python CLI'ından (`import ID_Server`) `ID_Server.py` dosyasını veya Ghidra'nın Script Manager'ından `Ghidra_Server.py` dosyasını çalıştırın. IDA, `127.0.0.1` adresinde `5073` portundan başlayarak daha yüksek portları tarar. Mevcut Ghidra betiği `5093` portundan başlar ve `5102` dahil olmak üzere on portu dener; Java socket'i yalnızca loopback'e değil, tüm arayüzlere bağlanır. Bağlanmadan önce örnek tarafından yazdırılan portu kontrol edin. Headless analyzer'dan farklı olarak bu köprü, GUI örneğinde o anda açık olan program üzerinde çalışır.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

**Her bağlantıda satır sonuyla biten tek bir komut** gönderin ve satır sonuyla biten yanıtı okuyun. Sonuç genellikle JSON olur. Örneğin, bir giriş yoluyla ilgili içe aktarılmış API'yi bulduktan sonra `IMPORTXREF` çağrı noktalarını bulur; ardından `DECOMP_XREF`, seçilen bir adresin çağıranlarını toplu olarak decompile eder. `FUNC` bir fonksiyonu incelerken `PCODE` decompiler'ın ara gösterimini döndürür. Farklı bir taban adresine göre yeniden konumlandırılmış bir binary'den kopyalanmış adres yerine etkin veritabanındaki adresi kullanın. Aşağıdaki örnek IDA'nın varsayılan portunu kullanır; Ghidra için betiğin yazdırdığı portu kullanın.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Aynı kanal **analysis database'i değiştirebilir**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` ve `PATCH`; adları, türleri, structure tanımlarını, function sınırlarını veya kaydedilmiş byte'ları değiştirir. `PATCH`, database'de yapılan bir düzenlemedir; canlı bir process'e patch uygulandığının kanıtı **değildir**. Her iki listener da authentication belgeleri sunmaz. IDA yalnızca loopback'te dinler; Ghidra ise network interface'leri üzerinden erişilebilir olabilir. Ghidra'yı kullanırken erişimi listener ile kısıtlayın. `QUIT` her iki listener'ı da durdurur; IDA ayrıca `ida_bridge_stop()` işlevini sunar.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### blobrunner ile shellcode debug etme

[**BlobRunner**](https://github.com/OALabs/BlobRunner), **shellcode** için bellek ayırır, **bellek adresini** yazdırır ve yürütmeyi duraklatır.\
IDA veya x64dbg gibi bir debugger bağlayın, yazdırılan adreste bir breakpoint ayarlayın ve shellcode'u debug etmek için yürütmeyi sürdürün.

Releases GitHub sayfasında derlenmiş sürümlerin bulunduğu zip dosyaları yer alır: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
BlobRunner'ın biraz değiştirilmiş bir sürümünü aşağıdaki bağlantıda bulabilirsiniz. Derlemek için **Visual Studio Code'da bir C/C++ projesi oluşturup kodu kopyalayıp yapıştırın ve build edin**.


{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile shellcode debug etme

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4), BlobRunner'a benzer. Shellcode için bellek ayırır ve sonsuz bir döngüye girer. Debugger'ı bağlayın, **2–5 saniye** boyunca yürütmeyi sürdürün, döngünün içinde duraklatın ve ayrılan shellcode'a yürütmeyi aktaran sonraki çağrıya kadar step edin.

![jmp2it'in sonsuz döngüsünde, ayrılan shellcode'a yapılan çağrıdan hemen önce duraklatılmış debugger](<../../images/image (509).png>)

Derlenmiş bir [jmp2it sürümünü releases sayfasından indirebilirsiniz](https://github.com/adamkramer/jmp2it/releases/).

### Cutter kullanarak shellcode debug etme

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0), radare'ın GUI'sidir. Cutter ile shellcode'u emulate edip dinamik olarak inceleyebilirsiniz.

Cutter'ın "Open File" ve "Open Shellcode" seçenekleri sunduğunu unutmayın. Benim durumumda shellcode'u dosya olarak açtığımda doğru şekilde decompile etti; shellcode olarak açtığımda ise etmedi:

![Aynı byte'lar dosya veya shellcode olarak açıldığında Cutter'ın farklı analysis sonuçları gösterdiği ekran](<../../images/image (562).png>)

Emülasyonu istediğiniz konumda başlatmak için oraya bir bp ayarlayın; görünüşe göre Cutter emülasyonu otomatik olarak o noktadan başlatacaktır:

![Cutter emülasyonunu başlatmadan önce istenen shellcode giriş noktasında breakpoint ayarlama](<../../images/image (589).png>)

![Cutter emulator'ün seçilen shellcode breakpoint'inde duraklatılmış hâli](<../../images/image (387).png>)

Örneğin stack'i bir hex dump içinde görebilirsiniz:

![Cutter'ın hex dump'inde emüle edilen shellcode stack'ini görüntüleme](<../../images/image (186).png>)

### Shellcode'un obfuscation'ını çözme ve yürütülen function'ları bulma

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) aracını deneyebilirsiniz.\
Shellcode'un hangi **function'ları** kullandığı ve bellekte kendisini **decode** edip etmediği gibi bilgileri gösterir.

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

**Create Dump** seçeneği, shellcode bellekte dinamik olarak değiştirilmişse son halini döker (decoded shellcode'u indirmek için kullanışlıdır). **start offset**, shellcode'u belirli bir offset'te başlatmak için kullanışlı olabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'da hata ayıklamak için kullanışlıdır (ancak bu amaç için önceki seçeneklerden herhangi birini daha iyi buluyorum; çünkü Ida veya x64dbg kullanabilirsiniz).

### CyberChef kullanarak disassemble etme

Shellcode dosyanızı girdi olarak yükleyin ve disassemble etmek için şu recipe'yi kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation'ını çözme

**Mixed Boolean-Arithmetic (MBA)** obfuscation, `x + y` gibi basit ifadeleri; aritmetik (`+`, `-`, `*`) ve bit düzeyindeki işleçleri (`&`, `|`, `^`, `~`, kaydırmalar) birleştiren formüllerin arkasına gizler. Önemli nokta, bu özdeşliklerin genellikle yalnızca **sabit genişlikli modüler aritmetik** altında doğru olmasıdır; dolayısıyla elde taşımalar ve taşmalar önemlidir:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Bu tür bir ifadeyi genel amaçlı cebir araçlarıyla sadeleştirirseniz bit genişliği semantiği göz ardı edildiği için kolayca yanlış sonuç elde edebilirsiniz.<sup>[[1]](#references)</sup>

### Uygulamalı iş akışı

1. Lift edilmiş kod/IR/decompiler çıktısındaki **orijinal bit genişliğini** koruyun (`8/16/32/64` bit).
2. Sadeleştirmeye çalışmadan önce **ifadeyi sınıflandırın**:
   - **Doğrusal**: bit düzeyindeki atomların ağırlıklı toplamları
   - **Yarı doğrusal**: `x & 0xFF` gibi sabit maskelerle birlikte doğrusal ifadeler
   - **Polinom**: çarpımlar içerir
   - **Karma**: çarpımlar ve bit düzeyindeki mantık iç içe geçmiştir; genellikle yinelenen alt ifadeler bulunur
3. Aday yeniden yazımların her birini random testing veya SMT proof ile doğrulayın. Eşdeğerlik kanıtlanamıyorsa tahmin yürütmek yerine özgün ifadeyi koruyun.

### Dar bir yürütme dilimiyle düzleştirilmiş kontrol akışını atlatma

Kontrol akış grafiğinin tamamını çıkarmak çoğu zaman gereksizdir. Control-flow flattening, opaque predicates, büyük dispatcher'lar veya MBA ağırlıklı kod içeren durumlarda, şifrelenmiş blob'lardan ve çıktı buffer'larından bunları dönüştüren en küçük routine'e giden referansları izleyin. Ardından yalnızca bu data-flow slice'ı yeniden oluşturun veya bağımsız olarak çalıştırın; ilgili state doğrudan başlatılabiliyorsa dispatcher gerekli çözümün parçası değildir.<sup>[[7]](#references)</sup>

Uygulamalı bir iş akışı:<sup>[[7]](#references)</sup>

1. Yürütülebilir ve veri bölümlerini, relocation'ları ve cross-reference'ları envantere alın. Bayt sırasını ve öğe genişliğini koruyarak `.rodata` içinden aday tabloları dump edin.
2. Plaintext'i veya çıktı buffer'ını yazan son routine'i belirleyin. Girdilerini, başvurduğu tabloları, import edilmiş çağrıları ve gereken global state'i kaydedin.
3. Yalnızca bu işlemleri sabit genişlikli bir Python modeline lift edin. Dilim hâlâ çok fazla state'e bağlıysa tüm programı emüle etmek yerine routine'i Unicorn, QEMU veya bir debugger altında çalıştırıp ilgisiz import'lara hook ekleyin.
4. Extractor'ın çıktısını gerçekten sağlanan binary'den türettiğini doğrulayın: sessiz fallback'leri kaldırın, binary'de gömülü yanıtları arayın ve değişen string'ler, key'ler, identifier'lar, layout'lar ve obfuscation seed'leri içeren görülmemiş build'lerde çalıştırın.

İlk aşamada kullanılabilecek komutlar:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Gizlenmiş sabitler olan MBA ifadelerini tespit etme

Görünüşte girdiye bağlı olan bir byte ifadesi, girdisini tamamen iptal edebilir. Tablolarını çıkardıktan sonra ifadeyi 8 bitlik tam tanım kümesinde değerlendirin; tek elemanlı bir çıktı kümesi, çevresindeki durum makinesini kurtarmadan bu byte’ın sabit olduğunu kanıtlar.<sup>[[7]](#references)</sup>

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

Son maskeyi koruyun; çünkü özgün toplama işleminde bayt genişliğinde taşma olur. Daha geniş bir etki alanı için, bir SMT solver'a aynı genişlikteki iki sembolik girdi için `f(x1) != f(x2)` ifadesinin sağlanabilir olup olmadığını sorun: `unsat`, değişmezliği kanıtlarken `sat`, bir karşı örnek sunar ve girdinin elenemeyeceği anlamına gelir.<sup>[[7]](#references)</sup>

#### Ortama bağlı çözümlemeyi tanıma

Anti-analysis kontrollerinin dallanması veya çökmeye yol açması gerekmez. Bir decoder; bir sensör sonucunu anahtar bitine, opaque predicate sabitine veya düzleştirilmiş dispatcher durumuna karıştırıp normal şekilde çalışmaya devam edebilir ve bir emülatörde makul görünen ancak yanlış bir açık metin üretebilir. Bu nedenle yalnızca görünür hata dallarını patch etmek yeterli değildir; ortam kontrollerinden decoder durumuna uzanan veri bağımlılıklarını izleyin, aynı kod parçasını gerçek cihazda ve emülatörde karşılaştırın ve her sensör sonucunu zorlamanın son buffer'ı nasıl değiştirdiğini test edin.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA), malware analizi ve korumalı binary'leri tersine mühendislikle inceleme için kullanışlı bir MBA sadeleştiricisidir. İfadeyi sınıflandırır ve her şeye tek bir genel yeniden yazma geçişi uygulamak yerine, ifadeyi özel işlem hatlarına yönlendirir.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA, ifadeyi Boolean girdiler üzerinde değerlendirir, bir imza çıkarır ve pattern matching, ANF dönüşümü ve katsayı interpolasyonu gibi çeşitli kurtarma yöntemlerini yarıştırır.
- **Semilinear MBA**: Sabit maskeli atomlar, maskelenmiş bölgelerin doğruluğu korunacak şekilde bit-bölümlü yeniden yapılandırmayla yeniden oluşturulur.
- **Polynomial/Mixed MBA**: Çarpımlar çekirdeklerine ayrıştırılır ve dış ilişki sadeleştirilmeden önce tekrarlanan alt ifadeler geçici değişkenlere taşınabilir.

Kurtarmaya çalışmaya değer, yaygın bir karma özdeşlik örneği:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Bu şu şekilde sadeleştirilebilir:

```c
x * y
```

### Tersine mühendislik notları

- CoBRA'yı, tam hesaplamayı izole ettikten sonra **lifted IR expressions** veya decompiler çıktısı üzerinde çalıştırmayı tercih edin.
- İfade maskelenmiş aritmetikten veya dar yazmaçlardan kaynaklanıyorsa `--bitwidth` seçeneğini açıkça kullanın.
- Daha güçlü bir kanıtlama adımına ihtiyacınız varsa, buradaki yerel Z3 notlarına bakın:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA ayrıca bir **LLVM pass plugin** (`libCobraPass.so`) olarak da sunulur; bu, sonraki analiz pass'lerinden önce MBA ağırlıklı LLVM IR'yi normalleştirmek istediğinizde kullanışlıdır.
- Desteklenmeyen, carry'ye duyarlı karma etki alanı kalıntıları, özgün ifadeyi koruyup carry yolunu elle incelemeniz gerektiğinin işareti olarak değerlendirilmelidir.

## XOR durumlu control-flow flattening'i geri kazanma

OLLVM tarzı bir flattener, mevcut basic block durumunu iki 64 bit yazmaçta tutup dispatcher'da XOR ile yeniden oluşturabilir. Her özgün blok, sonraki durum için yazmaç çiftini yazar ve dispatcher'a geri atlar. Koşullu bir blok, CPU bayraklarına göre çiftin bir yarısını değiştirmek için `CMOVcc` kullanabilir; bu nedenle yalnızca görünür branch talimatlarını izlemek iki ardılı da gözden kaçırır. Indirect-jump dispatcher'dan farklı olarak bu yapı, her yerde doğrudan geri kenarlar kullanabilir.<sup>[[19]](#references)[[20]](#references)</sup>

Grafiği geri kazanmak için dispatcher karşılaştırma ağacını ve iki durum yazmacını belirleyin, karşılaştırılan her XOR durumunu hedef bloğuyla eşleştirin, ardından her özgün blokta yazmaç çiftine ulaşan yazmaları izleyin. Koşullu yazmalarda bayrakları ayarlayan talimatı ve her iki `CMOVcc` sonucunu da dahil edin. Her bloğun dispatcher çıkışını çözümlenmiş doğrudan ardılına veya koşullu branch'ine dönüştürün; böylece binary'ye patch uygulamadan dispatcher erişilemez hale gelir. Bu, tam-CFG yaklaşımıdır; yalnızca tek bir decoder önemliyse yukarıdaki [dar execution-slice iş akışı](#bypass-flattened-control-flow-with-a-narrow-execution-slice) daha hızlı olabilir.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis), bu yapıyı Binary Ninja'da otomatikleştirir. `plugins/DispatchThis` dizinini Binary Ninja kullanıcı plugin dizinine kopyalayın ve yeniden başlatın. Etkilenen fonksiyonda **Function Settings**'i açıp `OLLVM_XOR_64`'ü seçin; analiz başlamazsa **Analysis → Reanalyze All Functions**'ı kullanın. Bu mod, dosya baytlarını değil MLIL control-flow kenarlarını yeniden yazar ve Z3'e veya indirect-jump resolver'a ihtiyaç duymaz. Binary Ninja 5.3.9757+ sürümlerinde test edilmiştir; blok başına ölü durum yazmalarını kaldırmaz, bu nedenle bunları hâlâ etkin olan geçişlerle karıştırmayın.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator, program işlemlerini `mov` tabanlı talimat dizileriyle değiştirir ve control flow'u değiştirmek için signal/exception handling kullanır. Ayrıntılar için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Desteklenen binary'lerde, [demovfuscator](https://github.com/kirschju/demovfuscator) sonucu deobfuscate edebilir. Birkaç bağımlılığı vardır.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Ve [keystone'u kurun](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Bir **CTF oynuyorsanız, flag'i bulmak için bu geçici çözüm** çok işinize yarayabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**entry point**'i bulmak için, aşağıdaki örnekte olduğu gibi fonksiyon adlarında `::main` araması yapın:

![Ghidra'da fonksiyon adlarında çift iki nokta üst üste ve main arayarak Rust entry point'ini bulma](<../../images/image (1080).png>)

Bu örnekte binary'nin adı authenticator'dı; bu nedenle bunun ilgi çekici main fonksiyonu olduğu oldukça açık.\
Çağrılan **fonksiyonların** **adlarını** öğrendikten sonra, **girdileri** ve **çıktıları** hakkında bilgi edinmek için onları **İnternet'te** arayın.

### ELF firmware'den Rust stringlerini kurtarma

**Rust ELF** binary'lerinde, birçok statik string C tarzı NUL ile sonlandırılmış pointer'lar tarafından referans gösterilmez. Yaygın bir `rustc` yerleşiminde, gerçek string blob'una **`.rodata`** içinde işaret eden bir **pointer/length tuple** **`.data.rel.ro`** içinde bulunur:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Bu, `strings` veya varsayılan Ghidra analizinin bitişik dizeleri birleştirebileceği ya da çapraz başvuruları tamamen gözden kaçırabileceği anlamına gelir.<sup>[[3]](#references)</sup>

Hızlı iş akışı:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. **`.rodata`**’nın sanal adresini ve boyutunu alın.
2. **`.data.rel.ro`** bölümünü her seferinde bir word olacak şekilde sıralayın.
3. `.rodata` adres aralığındaki her değeri olası bir string işaretçisi olarak değerlendirin.
4. Sonraki word’ü olası uzunluk olarak değerlendirin.
5. Makuliyet filtreleri uygulayın (örneğin, uzunluğu **4** ile **100** byte arasında olanları tutun).
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

Bu, firmware reversing işlemlerinde özellikle kullanışlıdır; çünkü kurtarılan Rust string’leri genellikle **HTTP rotalarını, RPC adlarını, log mesajlarını, assertion’ları, dosya adlarını, config anahtarlarını, komut işleyicilerini ve auth ile ilgili mantığı** ortaya çıkarır.

Ghidra bu string’leri bulamazsa aynı sezgisel yöntemi uygulayan ve referans verilen `.rodata` offset’lerinde string verileri oluşturan özel bir script/plugin çalıştırın. Pen Test Partners tarafından yayımlanan `rust-strings` ve `RustStrings.py` araçları, bu fikri diğer **word size, endianness ve section layout** düzenlerine uyarlamak için iyi referanslardır.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Delphi ile derlenmiş binary’ler için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) aracını kullanabilirsiniz.

Bir Delphi binary’sini reverse etmeniz gerekiyorsa IDA plugin’i [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

Bir Python plugin’i yüklemek için IDA’da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu plugin, debugging başlarken binary’yi çalıştırır ve fonksiyon adlarını dinamik olarak çözümler. Debugging’i başlattıktan sonra Start düğmesine (yeşil olan veya f9) tekrar basın; gerçek kodun başlangıcında bir breakpoint’e ulaşılır.

Grafik uygulamasında bir düğmeye basarsanız debugger, o düğmenin çağırdığı fonksiyonda durabilir.

## Golang

Sıradan Go binary’leri için [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper), runtime yapılarını kurtarabilir ve IDA’daki fonksiyon adlarını iyileştirebilir. Python plugin’ini yüklemek için **Alt+F7** tuşlarına basın.

Bir Golang binary’sini reverse etmeniz gerekiyorsa IDA plugin’i [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm.

Bir Python plugin’i yüklemek için IDA’da **Alt+F7** tuşlarına basın, ardından plugin dosyasını seçin.

Bu, fonksiyon adlarını çözümler.

### Symbol table olmadan metadata kurtarma

Strip edilmiş bir Go executable’ı, program counter’ları fonksiyonlara eşlemek için yine de runtime metadata’sına ihtiyaç duyar. [GoReSym](https://github.com/mandiant/GoReSym), Go runtime’ından türetilen kodu kullanarak `pclntab` ve `moduledata` gibi yapıları bulup ayrıştırır. Bu araç, geleneksel symbol table’a bağlı kalmadan fonksiyon sınırlarını, adlarını, kaynak yollarını, türleri ve build ayrıntılarını kurtarabilir.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Bir obfuscator, kurtarılan adları değiştirirken bu yapıların kullanılabilir kalmasını sağlayabilir. Örneğin Garble, tanımlayıcıları ve paket yollarını hash'ler; build, module ve debug bilgilerini kaldırır.<sup>[[12]](#references)</sup> Obfuscate edilmiş paket token'ı, o paketteki fonksiyonlar arasında tutarlı kalmalıdır. Fonksiyonları tekrarlanan token'a göre gruplayın, çağırdığı fonksiyonlardan, string'lerden ve API'lerden bir paketi çıkarın, ardından bu paket etiketini grubun tamamına uygulayın.<sup>[[13]](#references)</sup>

### GoResolver ile Garble adlarını kurtarma

[GoResolver](https://github.com/volexity/GoResolver), runtime sembollerinin çıkarılmasını temiz referans oluşturma ve control-flow graph (CFG) eşleştirmesiyle birleştirir. Şu sırayı izleyin:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Derleyici sürümünü belirleyin.** Önce `BuildInfo` ve gömülü sürüm string'lerini deneyin. Obfuscator bunları kaldırdıysa, paketlenmiş Go runtime'ın bölümlerini sürümlendirilmiş referans runtime'larla karşılaştırın. Volexity'nin testlerinde runtime'ın yaklaşık `2%`'si, büyük Go sürümlerini ayırt etmeye yetti. Bunu evrensel bir eşik değil, deneysel bir optimizasyon olarak değerlendirin.<sup>[[13]](#references)</sup>
2. **Eşleşen referanslar oluşturun.** Belirlenen Go sürümü, hedef mimari ve olası kütüphaneler için temiz binary'ler oluşturun. Toolchain'i eşleştirmek, derleyici tarafından oluşturulan CFG farklılıklarını azaltır.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Fonksiyonları karşılaştırın.** GoGrapher, fonksiyon CFG'lerini eşleştirir ve `0.0` ile `1.0` arasında normalize edilmiş skorlar üretir. Basic-block eşleştirmesi, benzer talimatların ağırlıklı karşılaştırmasına dayanır. Yüksek güvenilirlikli eşleşmeler, rastgeleleştirilmiş fonksiyonları temiz uygulamayla eşleştirir. Daha düşük güvenilirlikli eşleşmeler yine de bir paketi veya modülü tanımlayabilir.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
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

Varsayılan anlamlı eşleşme eşiği `0.9`'dur. `--extract` ve `--graph` seçenekleri aşamalardan birini ayrı ayrı çalıştırabilir; varsayılan olarak ikisi de çalıştırılır çünkü kurtarılan runtime metadata ve CFG kanıtları birbirini tamamlar.<sup>[[10]](#references)</sup> CFG skorları sezgiseldir: inlining, build flags, mimari ve library sürümü farklılıkları graph yapısını değiştirebilir. Bu nedenle düşük güvenli adları zorla atamak yerine çözümlenmemiş fonksiyonları koruyun.<sup>[[13]](#references)</sup>

### Go string tablosunu kurtarma

Go binary'leri, bağlantısı yapılan her paketin string byte'larını tek bir bitişik tabloda tutar. Girdiler NUL ile sonlandırılmaz ve runtime yapıları tablonun başlangıç adresini ya da boyutunu göstermez. Ancak derleyici, işletim sistemleri ve mimariler arasında girdileri önce uzunluğa, ardından alfabetik sıraya göre düzenler. Bu nedenle analist, bir girdi bulduktan sonra bitişik girdilerde ilerleyebilir ve string'leri kodla ilişkilendirmek için data cross-reference'larını kullanabilir.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor), bu iş akışını IDA Pro ve Ghidra'da otomatikleştirir. Eklenti data segment cross-reference'larına dayandığından, önce auto-analysis'in tamamlanmasını bekleyin. Varsayılan anchor, `entersyscall` runtime string'idir. Eklenti buradan sonra her iki yönde de tarama yapabilir, kurtarılan string'leri veritabanında tanımlayabilir ve string'leri onlara referans veren fonksiyonlarla eşleyen bir JSON çıktısı oluşturabilir.<sup>[[14]](#references)</sup>

Uygulama veya malware kodunu bağlantısı yapılmış library'lerden gelen gürültüden ayırmak için raporu, referans veren fonksiyonun package'ına göre filtreleyin. Bu teknik, Garble'ın `-literals` dönüşümü gibi obfuscation yöntemleriyle yok edilen literal'ları kurtaramaz. Ancak obfuscation uygulanmamış runtime string'lerini düzenlemeye yardımcı olabilir.<sup>[[14]](#references)[[15]](#references)</sup>

### Go runtime türlerini kurtarma

Go, garbage collection gibi özelliklerin kullandığı runtime type bilgilerini binary'ye ekler. Build bilgileri kaldırıldığında veya disassembler bu metadata'yı ayrıştıramadığında, talimatlar rastgele data adreslerini yüklüyormuş gibi görünebilir ve hedef bölge türlendirilmeden kalır. Metadata'yı kurtarmak, bu adresleri okunabilir type referanslarına dönüştürür ve package'ın yeteneklerini anlamayı kolaylaştırır.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver), symbol'ları çıkarabilir ve runtime type bilgilerini ayrıştırarak bir JSON raporu oluşturabilir. Mevcut CLI, `resolve` subcommand'ini kullanır:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

`-y`/`--types` seçeneği type parsing'i etkinleştirir. Kurtarılan type'ları tanımlamak ve referanslarını analysis database'e uygulamak için raporu GoResolver'ın IDA Pro veya Ghidra plugin'i ile içe aktarın. Bu özellikle sunulan rapor formatında, `-y` seçeneği kullanılmadığında RTTI adresi ve kurtarılan type üyeleri null kalır.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver, x86, AMD64, ARM ve ARM64 için PE, ELF ve Mach-O örneklerini destekler; böylece aynı workflow Windows, Linux ve macOS'tan Go binary'leri için de geçerlidir.<sup>[[10]](#references)</sup>

## Derlenmiş Python

Bu sayfada, ELF/EXE Python derlenmiş bir binary'den Python kodunun nasıl elde edileceğini bulabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Bir GBA oyununun **binary** dosyasını elde ederseniz, onu **emulate** ve **debug** etmek için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Debug sürümünü indirin_) - Arayüzlü bir debugger içerir
- [**mgba** ](https://mgba.io)- CLI debugger içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin'i
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin'i

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Options --> Emulation Setup --> Controls**_** ** bölümünde Game Boy Advance **düğmelerine** nasıl basılacağını görebilirsiniz.

![Game Boy Advance düğme eşlemelerini gösteren no$gba kontrol yapılandırması](<../../images/image (581).png>)

Basıldığında, her **tuşun onu tanımlayan bir değeri** vardır:

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

Yani bu tür programlarda ilgi çekici kısım, **programın kullanıcı girdisini nasıl ele aldığı** olacaktır. **0x4000130** adresinde sıkça karşılaşılan **KEYINPUT** fonksiyonunu bulabilirsiniz.

![0x4000130 adresinde KEYINPUT'e başvuran bir GBA binary dosyasının Ghidra görünümü](<../../images/image (447).png>)

Önceki görselde, fonksiyonun **FUN_080015a8** içinden çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

Bu fonksiyonda, bazı başlangıç işlemlerinden sonra (önemli değiller):

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

Son if, **`uVar4`**'ün **son Keys** içinde olup olmadığını ve mevcut tuş olmadığını kontrol eder; bu, bir düğmeyi bırakma olarak da bilinir (mevcut tuş **`uVar1`** içinde saklanır).

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

Önceki kodda **uVar1**’in (**basılan düğmenin değerinin** bulunduğu yer) bazı değerlerle karşılaştırıldığını görebilirsiniz:

- Önce **4 değeriyle** (**SELECT** düğmesi) karşılaştırılır: Bu challenge’da bu düğme ekranı temizler.
- Ardından değer **8** (**START** düğmesi) ile karşılaştırılır; bu challenge’da bu yol, girilen kodun geçerli olup olmadığını kontrol eder.
  - Bu durumda **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılır ve değer aynıysa bazı kodlar çalıştırılır.
- Diğer tüm durumlarda bir sayaç (`DAT_030000d4`) kontrol edilir ve artırılır.\
  Sayaç 8’in altındayken basılan tuşların değerleri `DAT_030000d8` içinde toplanır.

Dolayısıyla bu challenge’da, düğmelerin değerlerini bilerek, toplamı 0xf3 olan ve uzunluğu 8’den küçük bir **kombinasyona basmanız** gerekiyordu.

**Bu eğitim için referans:** [Nostalgia challenge çözüm yazısının arşivlenmiş hâli](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [3] [Rust dizelerinin kodunu çözme - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing eğitimi (arşivlenmiş)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [AI destekli Reverse Engineering'i yenmek ya da en azından denemek](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Basic Block eşleştirmeye dayalı Control Flow Graph karşılaştırma yaklaşımı](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver deposu](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mekanizması](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Golang ikililerini otomatik olarak deobfuscate etmek için Control-Flow Graph benzerliğini kullanma](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor deposu](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Volexity Golang araçlarındaki güncellemeler](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Her Şeyi Reverse Engineer Et](https://github.com/morluto/rea)
- [17] [REA managed-code analizi](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI ve kanıt kılavuzu](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninja control-flow unflattening iş akışı](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF Zero-Day saldırısı, Java Loader, Web Shell ve AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [IDA bridge sunucu uygulaması](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Ghidra bridge sunucu uygulaması](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) wildcard address'e bağlanır](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Godot reverse engineering araç seti](https://github.com/figurophobia/gore)
- [26] [gore key-recovery uygulaması](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [gore encrypted-blob biçimi](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [gore komut ve kurtarma uygulaması](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
