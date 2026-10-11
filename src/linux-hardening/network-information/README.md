# Información de red

{{#include ../../banners/hacktricks-training.md}}

Los servicios que escuchan localmente, los sockets Unix y el software expuesto a la red pueden revelar rutas que no son visibles en un escaneo externo. Empieza por revisar los servicios que escuchan en el host y el proceso propietario de cada punto de conexión.

- [Captura de tráfico, firewall y análisis de tráfico saliente](traffic-capture-and-firewall-egress.md) abarca la captura de paquetes, el filtrado, los proxies y las pruebas de conectividad.
- [Análisis de la red local y los sockets](local-network-and-socket-triage.md) abarca los servicios de loopback, los sockets Unix y las redes de contenedores.
- [Inyección de comandos mediante sockets](socket-command-injection.md) abarca los comandos aceptados a través de sockets locales expuestos.
- [Cisco vManage](cisco-vmanage.md) documenta un objetivo específico de producto y las comprobaciones relacionadas.
{{#include ../../banners/hacktricks-training.md}}
