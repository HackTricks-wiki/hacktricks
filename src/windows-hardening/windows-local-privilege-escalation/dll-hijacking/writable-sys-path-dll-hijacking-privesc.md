# Writable System PATH + DLL Hijacking: Escalação de Privilégios

{{#include ../../../banners/hacktricks-training.md}}

## Introdução

Se você puder **escrever em um diretório no `PATH` de todo o sistema** (não apenas no `PATH` do seu usuário), poderá conseguir **escalar privilégios** no sistema.

Isso pode ser explorado por meio de **DLL hijacking** quando um serviço ou processo com mais privilégios tenta carregar uma DLL que não existe em seus locais de pesquisa anteriores e, por fim, pesquisa no diretório gravável do sistema presente no `PATH`.

Uma entrada gravável no `PATH` da Machine é apenas um **primitivo**, não uma prova de execução de código. Para uma aplicação não empacotada que usa a ordem de pesquisa padrão, o `PATH` é consultado depois de redirection, API sets, SxS, a lista de módulos carregados, KnownDLLs, os diretórios da aplicação e do Windows e o diretório atual. Um caminho completo ou uma política `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` pode excluir completamente o `PATH`.<sup>[[4]](#references)</sup>

Para obter mais informações sobre **DLL hijacking**, consulte:

{{#ref}}
./
{{#endref}}

## Privesc with DLL Hijacking

### Encontrando uma DLL Ausente

Primeiro, **identifique um processo** em execução com **mais privilégios** que tente **carregar uma DLL de um diretório gravável do sistema presente no `PATH`**.

Lembre-se de que essa técnica depende de uma entrada no **Machine/System PATH**, não apenas no seu **User PATH**. Portanto, antes de passar tempo usando o Procmon, vale a pena enumerar as entradas do **Machine PATH** e verificar quais são graváveis:<sup>[[1]](#references)</sup>
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
O texto das ACLs pode ser enganoso, pois a associação a grupos, as ACEs de negação e as permissões herdadas afetam o resultado. Em um teste autorizado, uma verificação de criação/exclusão verifica o **acesso efetivo do token atual** (é intrusiva e pode gerar alertas):<sup>[[1]](#references)</sup>
```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
$probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
catch { }
}
```
### Confirme o `PATH` efetivo do alvo

O `PATH` da máquina lido do registro é um dado de configuração; o loader usa o bloco de ambiente do **processo alvo**. Cada processo possui um bloco de ambiente, e um processo filho normalmente herda uma cópia do ambiente do pai. Consequentemente, um serviço de longa execução pode manter um valor antigo, e um serviço iniciado com um ambiente personalizado pode diferir do valor visto no seu shell. Considere uma sondagem do Procmon que observe o diretório exato pelo PID alvo como a fonte de verdade; após alterar o `PATH` em um lab, reinicie a árvore de processos relevante ou reinicie o sistema antes de concluir que a busca não ocorre.<sup>[[5]](#references)</sup>

O problema nesses casos é que esses processos provavelmente já estão em execução. Para identificar DLLs que os serviços tentam carregar sem sucesso, inicie o Procmon o mais cedo possível (antes do início dos processos) e, em seguida:

> [!WARNING]
> Adicionar um diretório gravável pelo usuário ao `PATH` da máquina **cria a condição vulnerável**. Faça isso somente em uma VM de pesquisa isolada para revelar quais processos privilegiados acessam o `PATH`; em um host avaliado, monitore a entrada gravável existente sem alterar a configuração do sistema.<sup>[[1]](#references)</sup>

- **Crie** a pasta `C:\privesc_hijacking` e adicione o caminho `C:\privesc_hijacking` à **variável de ambiente System Path**. Você pode fazer isso **manualmente** ou com **PS**:
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- Inicie o **`procmon`** e acesse **`Options`** --> **`Enable boot logging`**, depois pressione **`OK`** no prompt.
- Em seguida, **reinicie** o computador. Quando o computador for reiniciado, o **`procmon`** começará a **registrar** eventos imediatamente.
- Quando o **Windows** for **iniciado, execute o `procmon`** novamente. Ele informará que estava em execução e **perguntará se você deseja armazenar** os eventos em um arquivo. Responda **sim** e **armazene os eventos em um arquivo**.
- **Depois** que o **arquivo** for **gerado**, **feche** a janela do **`procmon`** aberta e **abra o arquivo de eventos**.
- Adicione estes **filtros** para encontrar todas as DLLs que um **processo tentou carregar** da pasta gravável do System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> O **boot logging** só é necessário para serviços que iniciam **cedo demais** para serem observados de outra forma. Se você puder **acionar o serviço/programa-alvo sob demanda** (por exemplo, interagindo com sua interface COM, reiniciando o serviço ou iniciando novamente uma tarefa agendada), geralmente é mais rápido manter uma captura normal do Procmon com filtros como **`Path contains .dll`**, **`Result is NAME NOT FOUND`** e **`Path begins with <writable_machine_path>`**.

### DLLs perdidas

Executando isso em uma máquina **virtual (vmware) gratuita com Windows 11**, obtive estes resultados:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Nesse caso, ignore os resultados `.exe`. As tentativas de carregar DLLs ausentes vieram de:

| Serviço                         | Dll                | Linha CMD                                                           |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

O exemplo a seguir usa a técnica descrita neste artigo sobre [**abusing `WptsExtensions.dll` for privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Outros candidatos que vale a pena analisar

`WptsExtensions.dll` é um bom exemplo, mas não é a única **phantom DLL** recorrente que aparece em serviços privilegiados. As regras modernas de hunting e os catálogos públicos de hijacking ainda monitoram nomes como:<sup>[[2]](#references)</sup>

| Serviço / Cenário | DLL ausente | Observações |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidato clássico a **SYSTEM** em sistemas cliente. É uma boa opção quando o diretório gravável está no **Machine PATH** e o serviço procura a DLL durante a inicialização. |
| NetMan no Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interessante em **server editions** porque o serviço é executado como **SYSTEM** e pode ser **acionado sob demanda por um usuário normal** em algumas builds, tornando-o melhor do que casos que exigem apenas uma reinicialização. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Normalmente resulta primeiro em **`NT AUTHORITY\LOCAL SERVICE`**. Isso geralmente ainda é suficiente porque o token possui **`SeImpersonatePrivilege`**, permitindo encadeá-lo com [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Trate esses nomes como **dicas para triagem**, não como garantias de sucesso: eles dependem da **SKU/build**, e a Microsoft pode alterar o comportamento entre versões. O ponto principal é procurar **DLLs ausentes em serviços privilegiados que percorrem o Machine PATH**, especialmente se o serviço puder ser **acionado novamente sem reinicialização**.

### Validar um candidato antes de weaponizing

Um evento `NAME NOT FOUND` isolado não é suficiente. Antes de inserir um payload, verifique a cadeia completa:<sup>[[1]](#references)[[4]](#references)</sup>

1. O evento pertence ao **PID, à linha de comando, à conta de serviço e ao nível de integridade** esperados, e o caminho ausente é exatamente o diretório gravável do Machine `PATH`.
2. Para o mesmo basename da DLL, nenhum diretório anterior retorna `SUCCESS`, e o módulo não é atendido pela lista de módulos carregados, por KnownDLLs, redirection ou um manifesto SxS.
3. A tentativa se repete quando um usuário com poucos privilégios invoca o trigger pretendido. Uma busca que ocorre apenas durante o boot pode ser usada, mas é operacionalmente muito pior do que uma acionada sob demanda.
4. A arquitetura do payload corresponde à do processo. Se a aplicação resolver exports posteriormente, faça proxy da DLL legítima ou exporte os símbolos esperados; consulte [Creating and compiling DLLs](README.md#creating-and-compiling-dlls).
5. Primeiro, use uma DLL canary inofensiva que registre o PID, a identidade e o timestamp. No Procmon, exija um **`Load Image`** bem-sucedido a partir do caminho plantado, em vez de presumir que uma consulta de arquivo anterior causou a execução.

### Exploitation

Para **escalar privilégios**, faça hijack de **`WptsExtensions.dll`**. Depois que o **caminho** e o **nome** forem conhecidos, gere a DLL maliciosa.

Você pode [**tentar usar qualquer um destes exemplos**](README.md#creating-and-compiling-dlls). Você poderia executar payloads como: obter uma rev shell, adicionar um usuário, executar um beacon...

> [!WARNING]
> Observe que **nem todos os serviços são executados** como **`NT AUTHORITY\SYSTEM`**. Alguns são executados como **`NT AUTHORITY\LOCAL SERVICE`**, que tem **menos privilégios**, portanto abusar de um desses serviços pode não permitir a criação de um novo usuário.\
> No entanto, essa conta possui o direito de usuário **`SeImpersonatePrivilege`**, então você pode usar a [**Potato suite para escalar privilégios**](../roguepotato-and-printspoofer.md). Nesse caso, uma reverse shell é uma opção melhor do que tentar criar um usuário.

O serviço **Task Scheduler** normalmente é executado como **`NT AUTHORITY\SYSTEM`**, mas verifique a implantação real e não deduza a identidade de execução apenas pelo nome do serviço:<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
Tendo **gerado a Dll maliciosa** (_no meu caso, usei um x64 rev shell e obtive um shell de volta, mas o Defender o encerrou porque era do msfvenom_), salve-a no Caminho do Sistema com permissão de escrita usando o nome **WptsExtensions.dll** e **reinicie** o computador (ou reinicie o serviço, ou faça o necessário para executar novamente o serviço/programa afetado).

Quando o serviço for reiniciado, a **DLL deverá ser carregada e executada** (você pode **reutilizar** o truque do **Procmon** para verificar se a **biblioteca foi carregada conforme esperado**).

> [!NOTE]
> Planeje a limpeza antes de disparar. Um serviço pode manter a DLL mapeada e bloquear o arquivo até ser parado; para `WptsExtensions.dll`, interromper o Agendador de Tarefas exige direitos elevados. Depois de obter o contexto pretendido, pare o alvo com segurança, remova o payload e restaure qualquer alteração em `PATH` feita apenas para o laboratório.<sup>[[1]](#references)</sup>

### Remediação / detecção

Remova permissões de escrita fracas de todos os diretórios do `PATH` da máquina e remova entradas obsoletas. Os desenvolvedores devem carregar bibliotecas confiáveis usando o caminho completo ou restringir a resolução com `SetDefaultDllDirectories` / flags de pesquisa de `LoadLibraryEx`. Os defensores podem correlacionar alterações no `PATH` da máquina com processos privilegiados carregando DLLs de diretórios que não sejam do sistema e tenham permissão de escrita para usuários.<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Hijacking de DLL do Windows (espero que) esclarecido](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [DLL suspeita carregada para persistência ou escalada de privilégios](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Escalada de privilégios no Windows](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Ordem de pesquisa de bibliotecas de vínculo dinâmico](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Variáveis de ambiente](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
