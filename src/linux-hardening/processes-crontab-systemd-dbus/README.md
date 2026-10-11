# Procesos, Crontab, Systemd y D-Bus

{{#include ../../banners/hacktricks-training.md}}

Las tareas programadas y la comunicación entre procesos pueden ejecutar código con privilegios distintos de los del proceso que las invoca. Antes de probar un servicio o una tarea, inspecciona su propietario, comando y entradas modificables.

- [Enumeración de procesos y rutas de servicios](process-enumeration-and-service-paths.md) abarca los árboles de procesos, los archivos de tiempo de ejecución y las cadenas de ejecución de systemd.
- [Tareas de cron y temporizadores de systemd](cron-and-systemd-timers.md) abarca la detección de tareas programadas y las entradas modificables.
- [Enumeración de D-Bus y escalada de privilegios mediante inyección de comandos](d-bus-enumeration-and-command-injection-privilege-escalation.md) abarca el bus de mensajes y los métodos de servicios privilegiados.
- [Payloads para ejecutar](payloads-to-execute.md) reúne payloads que pueden utilizarse cuando se ha identificado una vía de ejecución.

Para revisar en más detalle las tareas de cron y los servicios de systemd, consulta la [lista de comprobación para la escalada de privilegios en Linux](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
