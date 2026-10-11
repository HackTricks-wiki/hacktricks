# Captura de tráfico, firewall y evaluación de la salida

{{#include ../../banners/hacktricks-training.md}}

Después de localizar [las escuchas locales y los sockets Unix](local-network-and-socket-triage.md), inspecciona qué interfaces transportan su tráfico y qué reglas de firewall o proxy afectan a su accesibilidad. Un servicio accesible solo mediante loopback puede transportar encabezados HTTP sensibles aunque no sea accesible desde otro host.

## Comprueba los permisos de captura y elige una interfaz

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` puede tener capacidades de captura de paquetes incluso si el usuario actual no tiene acceso a sudo. Comprueba las capacidades reales del ejecutable y los permisos del grupo. Captura en la interfaz, durante el tiempo y con el filtro mínimos que sean útiles; una captura puede contener credenciales o datos personales.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` reconstruye streams TCP en texto plano; `tshark` puede filtrar y extraer campos de una captura. Para el tráfico TLS, el descifrado requiere claves del endpoint o un cliente compatible configurado para `SSLKEYLOGFILE` antes de la conexión. La [página de triaje de la red local](local-network-and-socket-triage.md#tls-key-logging) muestra ese flujo de trabajo. No trates una captura cifrada como texto plano legible.

Los artefactos de incidentes almacenados pueden cambiar esa evaluación. Un [core dump de Linux es una imagen de la memoria del proceso](https://man7.org/linux/man-pages/man5/core.5.html), que puede conservar una clave de sesión; si un dump legible y una captura de paquetes proceden del mismo proceso y sesión, un analista podría descifrar ese tráfico. Primero inventaría las rutas y los permisos de los artefactos; luego verifica por separado la identidad del proceso, la hora de captura, el protocolo y el formato de la clave. El tráfico descifrado o un archivo recuperado son indicios de divulgación, no pruebas de acceso a otra cuenta: cualquier material parcial de una clave SSH aún debe reconstruirse, cotejarse con la clave pública correspondiente y ser aceptado por la política SSH de esa cuenta. Evita volcar el contenido de los core dumps o las cargas útiles de las capturas en salidas de enumeración amplias.

## Identificar las capas del firewall

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` e `iptables` pueden exponerse mediante wrappers de la distribución, como UFW o firewalld. Lee las reglas activas y la configuración persistente del wrapper; una regla visible en una representación puede haber sido generada por otra herramienta. Inspecciona la interfaz, la dirección, el origen, el destino, el protocolo, el puerto y el estado de la conexión antes de atribuir el bloqueo de un servicio a una regla concreta. Consulta [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) para ver un ejemplo específico.

## Probar el tráfico saliente y el comportamiento del proxy

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Separa los fallos de DNS de los fallos de TCP, TLS o del proxy. Prueba el destino y el protocolo específicos pertinentes para la evaluación; que haya conectividad ICMP no implica que se permita TCP o UDP. Si hay un proxy configurado, compara la solicitud prevista a través del proxy con una solicitud al mismo destino que aplique las reglas correspondientes de `no_proxy`. Un reenvío de puerto local también puede hacer que un servicio de loopback esté disponible en otro lugar, así que revisa los listeners activos y los túneles SSH cuando la vista del firewall y la exposición observada no coincidan.
{{#include ../../banners/hacktricks-training.md}}
