# Captura de tráfico, firewall y triage de egress

{{#include ../../banners/hacktricks-training.md}}

Después de localizar [listeners locales y sockets Unix](local-network-and-socket-triage.md), inspecciona qué interfaces transportan su tráfico y qué reglas de firewall o proxy afectan la conectividad. Un servicio solo accesible mediante loopback puede transportar encabezados HTTP sensibles aunque no sea accesible desde otro host.

## Comprobar los permisos de captura y elegir una interfaz

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` puede tener capacidades de captura de paquetes aunque el usuario actual no tenga acceso a sudo. Comprueba las capacidades reales del ejecutable y los permisos del grupo. Captura en la interfaz durante el menor tiempo posible y con el filtro más específico que resulte útil; una captura puede contener credenciales o datos personales.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` reconstruye flujos TCP en texto sin cifrar; `tshark` puede filtrar y extraer campos de una captura. Para el tráfico TLS, el descifrado requiere claves del endpoint o un cliente compatible configurado con `SSLKEYLOGFILE` antes de la conexión. La [página de análisis inicial de la red local](local-network-and-socket-triage.md#tls-key-logging) muestra ese flujo de trabajo. No consideres que una captura cifrada se puede leer como texto sin cifrar.

Los artefactos de incidentes almacenados pueden cambiar esa evaluación. Un [volcado de memoria de Linux es una imagen de la memoria del proceso](https://man7.org/linux/man-pages/man5/core.5.html), que puede conservar una clave de sesión; si un volcado legible y una captura de paquetes proceden del mismo proceso y la misma sesión, un analista podría descifrar ese tráfico. Primero inventaría las rutas y los permisos de los artefactos; luego verifica por separado la identidad del proceso, la hora de la captura, el protocolo y el formato de la clave. El tráfico descifrado o un archivo comprimido recuperado son indicios de divulgación, no pruebas de acceso a otra cuenta: cualquier material parcial de una clave SSH aún debe reconstruirse, compararse con la clave pública correspondiente y aceptarse según la política SSH de esa cuenta. Evita volcar el contenido de volcados de memoria o las cargas útiles de las capturas en la salida de enumeraciones generales.

## Identificar las capas del firewall

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` e `iptables` pueden estar expuestos mediante herramientas de gestión de la distribución, como UFW o firewalld. Lee las reglas activas y la configuración persistente de la herramienta; una regla visible en una representación puede haber sido generada por otra herramienta. Antes de atribuir un servicio bloqueado a una regla concreta, inspecciona la interfaz, la dirección, el origen, el destino, el protocolo, el puerto y el estado de conexión. Consulta [revisión de reglas de nftables](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) para ver un ejemplo específico.

## Prueba el tráfico saliente y el comportamiento del proxy

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Separa los fallos de DNS de los fallos de TCP, TLS o proxy. Prueba el destino y el protocolo específicos pertinentes para la evaluación; que haya conectividad ICMP no implica que TCP o UDP estén permitidos. Si hay un proxy configurado, compara la solicitud que debería pasar por el proxy con una solicitud al mismo destino aplicando las reglas `no_proxy` correspondientes. Un reenvío de puertos local también puede hacer que un servicio de loopback esté disponible en otro lugar, así que revisa los listeners activos y los túneles SSH cuando la configuración del firewall y la exposición observada no coincidan.
{{#include ../../banners/hacktricks-training.md}}
