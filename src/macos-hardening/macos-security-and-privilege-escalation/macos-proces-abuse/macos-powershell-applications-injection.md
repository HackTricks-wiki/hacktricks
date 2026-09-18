# Injeção de aplicações PowerShell no macOS

{{#include ../../../banners/hacktricks-training.md}}

PowerShell é multiplataforma: o mesmo binário `pwsh` é executado no macOS, Linux e Windows, e é uma aplicação **.NET (Core)**. Isso fornece a um atacante que controla o ambiente de uma invocação de `pwsh` várias primitivas de variável de ambiente → execução de código que funcionam de forma idêntica nos três sistemas operacionais, além de algumas exclusivas do Windows. Todas elas são executadas **antes** (ou em vez) do `-Command`/`-File` que a vítima pretendia executar, o que as torna ideais contra wrappers privilegiados, jobs de cron/`launchd`/systemd e CI runners que executam `pwsh` com um ambiente herdado.

## `XDG_CONFIG_HOME` e profiles do PowerShell

No macOS e no Linux, o PowerShell usa caminhos de configuração XDG e executa scripts de profile quando o `pwsh` é iniciado. Redirecionar `XDG_CONFIG_HOME` altera o diretório que contém `powershell/profile.ps1` e o `powershell/Microsoft.PowerShell_profile.ps1` específico do console host; portanto, um arquivo controlado nesse local pode ser executado antes de um payload `-Command`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Isso se aplica ao PowerShell 6+ (`pwsh`) em plataformas não Windows; o Windows PowerShell usa locais de perfil diferentes. `pwsh -NoProfile` impede o carregamento do perfil. Inspecione também `HOME` e os nomes de perfil específicos do host, pois outros hosts do PowerShell podem selecionar scripts diferentes.

> [!TIP]
> No **Windows**, os caminhos do perfil são derivados de `$HOME` / da pasta conhecida *Documents* (por exemplo, `Documents\PowerShell\Microsoft.PowerShell_profile.ps1` para `pwsh`, `Documents\WindowsPowerShell\...` para o Windows PowerShell); portanto, influenciar `HOME`/`USERPROFILE` — ou simplesmente gravar esse arquivo — é a primitiva equivalente.

## `PSModulePath` module auto-loading hijack

Desde o PowerShell 3.0, o **module auto-loading** importa um módulo automaticamente na primeira vez que um comando exportado por ele é referenciado (invocado, usado com `Get-Command` ou por conclusão de tabulação). O PowerShell pesquisa recursivamente em todos os diretórios listados em **`$Env:PSModulePath`** por arquivos `.psd1`/`.psm1` e, em sistemas não Windows, o `PSModulePath` herdado pelo processo é respeitado como está. Portanto, se você puder **adicionar um diretório ao início de `PSModulePath`**, poderá implantar um módulo que corresponda a um comando chamado pelo script da vítima ou a um nome de módulo que o script use com `Import-Module` — e o código no escopo do módulo será executado no momento da importação.<sup>[[3]](#references)</sup>

Como a resolução de comandos do PowerShell segue a ordem *Alias → Function → Cmdlet → Application*, uma **function exportada pelo seu módulo pode ocultar um cmdlet integrado** usado pelo alvo (por exemplo, `Get-ChildItem`), portanto você nem precisa que a vítima importe algo explicitamente pelo nome.
```bash
# Attacker-controlled module dir prepended to PSModulePath
mkdir -p /tmp/evil/Hijack
cat >/tmp/evil/Hijack/Hijack.psm1 <<'PS1'
# Top-level module code runs at import time
New-Item -ItemType File -Path /tmp/psmodulepath-executed -Force | Out-Null
function Invoke-Report { 'hijacked' }   # shadows whatever the victim calls
Export-ModuleMember -Function Invoke-Report
PS1
cat >/tmp/evil/Hijack/Hijack.psd1 <<'PS1'
@{ ModuleVersion = '1.0'; RootModule = 'Hijack.psm1'; FunctionsToExport = @('Invoke-Report') }
PS1

# Victim runs pwsh with an inherited/attacker-influenced PSModulePath and calls Invoke-Report
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/psmodulepath-executed && echo 'PSModulePath auto-load executed'
```
No **Windows**, o mesmo se aplica (caminhos separados por `;`); `PSModulePath` também obtém valores de `HKCU:\Environment` e `HKLM:\...\Session Manager\Environment`, portanto, um valor gravável no escopo do usuário também é uma primitiva de persistência. O carregamento automático pode ser desativado com `$PSModuleAutoloadingPreference = 'None'`, e `pwsh -NoProfile` **não** o impede.

## Injeção de profiler do CLR (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh` é executado no .NET Core, portanto, a **API de profiling do CLR** carrega uma DLL/`.so`/`.dylib do atacante no processo durante a inicialização, exclusivamente a partir do ambiente — sem assinatura e sem necessidade de registro COM, pois as variáveis `*_PATH` têm precedência sobre o registro. A biblioteca do profiler executa seu `DllMain`/ponto de entrada dentro do processo do PowerShell, o que constitui uma técnica clássica de execução de código em processo e persistência (MITRE ATT&CK **T1574.012**).<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- No **.NET 8+**, as variáveis também podem usar o prefixo mais recente `DOTNET_` (`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`); `CORECLR_*` é mantido para compatibilidade retroativa.
- No **Windows PowerShell 5.1** (`powershell.exe`, .NET Framework), o trio equivalente é **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`** e **`COR_PROFILER_PATH=C:\evil.dll`**.

A DLL do profiler só precisa ser uma biblioteca COM/ICorProfilerCallback válida (ou simplesmente executar seu trabalho a partir de `DllMain`). Launchers defensivos devem remover `COR_*`/`CORECLR_*`/`DOTNET_*` de ambientes privilegiados.

## `DOTNET_STARTUP_HOOKS` (hook do .NET antes de `Main`)

Como `pwsh` é uma aplicação .NET Core, **`DOTNET_STARTUP_HOOKS`** aponta para um assembly gerenciado cujo `StartupHook.Initialize()` é executado de forma síncrona antes do `Main` do host — ou seja, antes de o próprio PowerShell ser iniciado. Essa é a primitiva de código gerenciado mais limpa e é compartilhada com todos os outros apps .NET:

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (bypass de controle do Windows)

No Windows, definir a variável de ambiente **`$Env:PSExecutionPolicyPreference`** (por exemplo, como `Bypass` ou `Unrestricted`) substitui a Execution Policy efetiva desse processo — é exatamente isso que `Set-ExecutionPolicy -Scope Process` grava. Isso, por si só, não executa código, mas remove a proteção de que "scripts não assinados são bloqueados", que frequentemente é o elo ausente para fazer com que uma das primitivas acima (um profile / module plantado) seja realmente executada. A Execution Policy é exclusiva do Windows e nunca foi uma security boundary.<sup>[[5]](#references)</sup>

## References

- [1] [Variáveis de ambiente do PowerShell e caminhos XDG](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Profiles do PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath e auto-loading de modules](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [Configurações de debugging e profiling do .NET (variáveis de profiler CORECLR_/DOTNET_)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies (PSExecutionPolicyPreference)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
