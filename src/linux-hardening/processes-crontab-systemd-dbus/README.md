# Processos, Crontab, Systemd e D-Bus

{{#include ../../banners/hacktricks-training.md}}

Tarefas agendadas e comunicação entre processos podem executar código com privilégios diferentes dos do chamador. Inspecione o proprietário, o comando e as entradas graváveis de um serviço ou tarefa antes de testá-los.

- [Enumeração de processos e caminhos de serviços](process-enumeration-and-service-paths.md) aborda árvores de processos, arquivos de runtime e cadeias de execução do systemd.
- [Tarefas Cron e timers do systemd](cron-and-systemd-timers.md) aborda a descoberta de tarefas agendadas e entradas graváveis.
- [Enumeração do D-Bus e escalada de privilégios por injeção de comandos](d-bus-enumeration-and-command-injection-privilege-escalation.md) aborda o barramento de mensagens e métodos de serviços privilegiados.
- [Payloads para executar](payloads-to-execute.md) reúne payloads que podem ser usados quando um caminho de execução tiver sido identificado.

Para uma análise mais ampla das tarefas Cron e dos serviços systemd, use a [lista de verificação de escalada de privilégios no Linux](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
