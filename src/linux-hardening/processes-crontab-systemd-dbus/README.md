# Procesos, Crontab, Systemd y D-Bus

{{#include ../../banners/hacktricks-training.md}}

Los trabajos programados y la comunicación entre procesos pueden ejecutar código con privilegios distintos de los del usuario que los inicia. Antes de probar un servicio o trabajo, inspecciona su propietario, comando y entradas modificables.

- [Enumeración de procesos y rutas de servicios](process-enumeration-and-service-paths.md) abarca los árboles de procesos, los archivos de tiempo de ejecución y las cadenas de ejecución de systemd.
- [Trabajos cron y temporizadores de systemd](cron-and-systemd-timers.md) abarca la búsqueda de tareas programadas y las entradas modificables.
- [Enumeración de D-Bus e inyección de comandos para la escalada de privilegios](d-bus-enumeration-and-command-injection-privilege-escalation.md) abarca el bus de mensajes y los métodos de servicios privilegiados.
- [Payloads para ejecutar](payloads-to-execute.md) reúne payloads que pueden utilizarse cuando se ha identificado una ruta de ejecución.

Para revisar cron jobs y servicios systemd más ampliamente, consulta la [lista de comprobación para la escalada de privilegios en Linux](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
