# Información de red

{{#include ../../banners/hacktricks-training.md}}

Los servicios locales en escucha, los sockets Unix y el software expuesto a la red pueden revelar rutas que no son visibles desde un escaneo externo. Empieza por los servicios en escucha del host y el proceso propietario de cada endpoint.

- [Captura de tráfico, firewall y análisis de egress](traffic-capture-and-firewall-egress.md) cubre la captura de paquetes, el filtrado, los proxies y las pruebas de conectividad.
- [Análisis de la red local y los sockets](local-network-and-socket-triage.md) cubre los servicios de loopback, los sockets Unix y las redes de contenedores.
- [Inyección de comandos mediante sockets](socket-command-injection.md) cubre los comandos aceptados a través de sockets locales expuestos.
- Para obtener acceso inicial a un appliance Cisco SD-WAN Manager, consulta [escalada local de privilegios en vManage](../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md); su CLI de ConfD, la REST API y las rutas de importación propiedad de root son distintos del análisis general de sockets.
{{#include ../../banners/hacktricks-training.md}}
