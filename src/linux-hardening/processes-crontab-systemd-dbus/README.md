# Procesos, Crontab, Systemd y D-Bus

{{#include ../../banners/hacktricks-training.md}}

Los trabajos programados y la comunicación entre procesos pueden ejecutar código con privilegios distintos de los del usuario que los invoca. Antes de probar un servicio o trabajo, inspecciona su propietario, comando y entradas con permisos de escritura.

- [Enumeración de procesos y rutas de servicios](process-enumeration-and-service-paths.md) cubre los árboles de procesos, los archivos de ejecución y las cadenas de ejecución de systemd.
- [Trabajos de Cron y temporizadores de systemd](cron-and-systemd-timers.md) cubre la detección de tareas programadas y las entradas con permisos de escritura.
- [Enumeración de D-Bus y escalada de privilegios mediante command injection](d-bus-enumeration-and-command-injection-privilege-escalation.md) cubre el bus de mensajes y los métodos de servicios privilegiados.
- [Payloads para ejecutar](payloads-to-execute.md) reúne payloads que pueden usarse cuando se ha identificado una ruta de ejecución.

Para revisar más a fondo los trabajos de Cron y los servicios de systemd, consulta la [lista de comprobación de escalada de privilegios en Linux](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
