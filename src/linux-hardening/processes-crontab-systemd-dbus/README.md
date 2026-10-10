# Processos, Crontab, Systemd e D-Bus

{{#include ../../banners/hacktricks-training.md}}

Tarefas agendadas e comunicação entre processos podem executar código com privilégios diferentes dos do chamador. Antes de testá-los, inspecione o proprietário, o comando e as entradas graváveis de um serviço ou tarefa.

- [Enumeração de processos e caminhos de serviços](process-enumeration-and-service-paths.md) aborda árvores de processos, arquivos de runtime e cadeias de execução do systemd.
- [Tarefas cron e timers do systemd](cron-and-systemd-timers.md) aborda a descoberta de tarefas agendadas e entradas graváveis.
- [Enumeração do D-Bus e escalação de privilégios por command injection](d-bus-enumeration-and-command-injection-privilege-escalation.md) aborda o barramento de mensagens e os métodos de serviços privilegiados.
- [Payloads para executar](payloads-to-execute.md) reúne payloads que podem ser usados quando um caminho de execução é identificado.

Para uma análise mais ampla de tarefas cron e serviços do systemd, use a [lista de verificação de escalação de privilégios no Linux](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
