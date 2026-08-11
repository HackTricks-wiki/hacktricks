# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Quando o serviço Windows Telephony (TapiSrv, `tapisrv.dll`) é configurado como um **TAPI server**, ele expõe a **interface MSRPC `tapsrv` por meio do named pipe `\pipe\tapsrv`** para clientes SMB autenticados. A CVE-2026-20931 na entrega de eventos assíncronos permite que um atacante transforme um suposto handle de mailslot em uma **escrita controlada de 4 bytes em um arquivo preexistente gravável por `NETWORK SERVICE`**. A chain publicada sobrescreve a lista de administradores do Telephony, depois alcança um carregamento de DLL exclusivo para administradores e executa como `NETWORK SERVICE`.<sup>[[1]](#references)[[2]](#references)</sup>

## Attack Surface

- **Exposição remota somente quando habilitado**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` deve permitir o compartilhamento (ou ser configurado por meio de `TapiMgmt.msc` / `tcmsetup /c <server>`). Por padrão, `tapsrv` é somente local.
- Interface: MS-TRP (`tapsrv`) por meio de **SMB named pipe**, portanto o atacante precisa de autenticação SMB válida.
- Conta do serviço: `NETWORK SERVICE` (início manual, sob demanda).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` inicializa a entrega de eventos assíncronos. No modo pull, o serviço faz:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
sem validar se `pszDomainUser` é um caminho de mailslot (`\\*\MAILSLOT\...`). Qualquer **caminho existente do filesystem** gravável por `NETWORK SERVICE` é aceito.
- Cada escrita de evento assíncrono armazena um único **`DWORD` = `InitContext`** (controlado pelo atacante na solicitação `Initialize` subsequente) no handle aberto, resultando em **write-what/write-where (4 bytes)**.<sup>[[1]](#references)</sup>

## Forcing Deterministic Writes
1. **Open target file**: `ClientAttach` com `pszDomainUser = <existing writable path>` (por exemplo, `C:\Windows\TAPI\tsec.ini`).
2. Para cada `DWORD` a ser escrito, execute esta sequência RPC em `ClientRequest`:
- `Initialize` (`Req_Func 47`): defina `InitContext = <4-byte value>` e `pszModuleName = DIALER.EXE` (ou outra entrada no topo da per-user priority list).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registra o line app e recalcula o recipient de maior prioridade).
- `TRequestMakeCall` (`Req_Func 121`): força `NotifyHighestPriorityRequestRecipient`, gerando o evento assíncrono.
- `GetAsyncEvents` (`Req_Func 0`): remove da fila e conclui a escrita.
- `LRegisterRequestRecipient` novamente com `bEnable = 0` (remove o registro).
- `Shutdown` (`Req_Func 86`) para desmontar o line app.
- Controle de prioridade: o recipient de “maior prioridade” é escolhido comparando `pszModuleName` com `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (lido enquanto representa o client). Se necessário, insira o nome do seu módulo por meio de `LSetAppPriority` (`Req_Func 69`).
- O arquivo **já deve existir**, pois `OPEN_EXISTING` é usado. Candidatos comuns graváveis por `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## From DWORD Write to RCE inside TapiSrv
1. **Conceda a si mesmo o “admin” do Telephony**: direcione `C:\Windows\TAPI\tsec.ini` e acrescente `[TapiAdministrators]\r\n<DOMAIN\\user>=1` usando as escritas de 4 bytes acima. Inicie uma **nova** sessão (`ClientAttach`) para que o serviço releia o INI e defina `ptClient->dwFlags |= 9` para sua conta.
2. **Admin-only DLL load**: envie `GetUIDllName` com `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` e forneça um caminho por meio de `dwProviderFilenameOffset`. Para admins, o serviço faz `LoadLibrary(path)` e depois chama o export `TSPI_providerUIIdentify`:
- Funciona com caminhos UNC para um Windows SMB share real; alguns SMB servers de ataque falham com `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternativa: faça o drop lento de uma DLL local usando a mesma primitive de 4-byte write e depois carregue-a.
3. **Payload**: o export é executado sob `NETWORK SERVICE`. Uma DLL minimalista pode executar `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` e retornar um valor diferente de zero (por exemplo, `0x1337`) para que o serviço descarregue a DLL, confirmando a execução.<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- Instale a security update da Microsoft para a CVE-2026-20931. Independentemente disso, desabilite o TAPI server mode, a menos que seja necessário, e bloqueie o acesso remoto a `\pipe\tapsrv`.
- Imponha a validação do namespace de mailslot (`\\*\MAILSLOT\`) antes de abrir caminhos fornecidos pelo client.
- Restrinja as ACLs de `C:\Windows\TAPI\tsec.ini` e monitore alterações; gere alertas para chamadas `GetUIDllName` que carreguem caminhos não padrão.<sup>[[1]](#references)</sup>

## References

- [1] [Quem está na linha? Explorando RCE no Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
