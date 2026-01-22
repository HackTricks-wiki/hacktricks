# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Quando o Windows Telephony service (TapiSrv, `tapisrv.dll`) é configurado como um **TAPI server**, ele expõe a **interface MSRPC `tapsrv` over the `\pipe\tapsrv` named pipe** para clientes SMB autenticados. Um bug de design na entrega assíncrona de eventos para clientes remotos permite que um atacante transforme um handle de mailslot em uma **escrita controlada de 4 bytes (DWORD) para qualquer arquivo pré-existente gravável por `NETWORK SERVICE`**. Esse primitivo pode ser encadeado para sobrescrever a lista de administradores do Telephony e abusar de um **carregamento arbitrário de DLLs restrito a administradores** para executar código como `NETWORK SERVICE`.

## Attack Surface
- **Remote exposure only when enabled**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` deve permitir compartilhamento (ou configurado via `TapiMgmt.msc` / `tcmsetup /c <server>`). Por padrão `tapsrv` é local-only.
- Interface: MS-TRP (`tapsrv`) over **SMB named pipe**, então o atacante precisa de autenticação SMB válida.
- Service account: `NETWORK SERVICE` (start manual, on-demand).

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` inicializa a entrega assíncrona de eventos. Em pull mode, o serviço faz:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
sem validar que `pszDomainUser` é um caminho de mailslot (`\\*\MAILSLOT\...`). Qualquer **caminho de filesystem existente** gravável por `NETWORK SERVICE` é aceito.
- Cada escrita de evento assíncrono armazena um único **`DWORD` = `InitContext`** (controlado pelo atacante na requisição `Initialize` subsequente) no handle aberto, resultando em **write-what/write-where (4 bytes)**.

## Forcing Deterministic Writes
1. **Open target file**: `ClientAttach` com `pszDomainUser = <existing writable path>` (por exemplo, `C:\Windows\TAPI\tsec.ini`).
2. Para cada `DWORD` a escrever, execute esta sequência RPC contra `ClientRequest`:
- `Initialize` (`Req_Func 47`): defina `InitContext = <4-byte value>` e `pszModuleName = DIALER.EXE` (ou outra entrada superior na lista de prioridade por usuário).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (registra o line app, recalcula o recipient de maior prioridade).
- `TRequestMakeCall` (`Req_Func 121`): força `NotifyHighestPriorityRequestRecipient`, gerando o evento assíncrono.
- `GetAsyncEvents` (`Req_Func 0`): remove da fila/completa a escrita.
- `LRegisterRequestRecipient` novamente com `bEnable = 0` (unregister).
- `Shutdown` (`Req_Func 86`) para desmontar o line app.
- Controle de prioridade: o “highest priority” recipient é escolhido comparando `pszModuleName` contra `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (lido enquanto se faz impersonation do cliente). Se necessário, insira seu nome de módulo via `LSetAppPriority` (`Req_Func 69`).
- O arquivo **deve já existir** porque `OPEN_EXISTING` é usado. Candidatos comuns graváveis por `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.

## From DWORD Write to RCE inside TapiSrv
1. **Grant yourself Telephony “admin”**: mire `C:\Windows\TAPI\tsec.ini` e anexe `[TapiAdministrators]\r\n<DOMAIN\\user>=1` usando as escritas de 4 bytes acima. Inicie uma sessão **nova** (`ClientAttach`) para que o serviço releia o INI e defina `ptClient->dwFlags |= 9` para sua conta.
2. **Admin-only DLL load**: envie `GetUIDllName` com `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` e forneça um caminho via `dwProviderFilenameOffset`. Para administradores, o serviço faz `LoadLibrary(path)` e então chama a export `TSPI_providerUIIdentify`:
- Funciona com caminhos UNC para um share SMB real do Windows; alguns servidores SMB do atacante falham com `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternativa: soltar lentamente uma DLL local usando o mesmo primitivo de escrita de 4 bytes, então carregá-la.
3. **Payload**: a export executa sob `NETWORK SERVICE`. Uma DLL mínima pode executar `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` e retornar um valor não-zero (por exemplo, `0x1337`) para que o serviço descarregue a DLL, confirmando a execução.

## Hardening / Detection Notes
- Disable TAPI server mode a menos que necessário; bloqueie acesso remoto a `\pipe\tapsrv`.
- Enforce mailslot namespace validation (`\\*\MAILSLOT\`) antes de abrir caminhos fornecidos pelo cliente.
- Restrinja ACLs de `C:\Windows\TAPI\tsec.ini` e monitore mudanças; alerte em chamadas `GetUIDllName` que carreguem caminhos não padrão.

## References
- [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
