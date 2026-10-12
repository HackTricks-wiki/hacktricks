# Eliminación del marcador de skb reenviado de Open vSwitch para escribir en la caché de páginas de ESP

{{#include ../../../banners/hacktricks-training.md}}

Un patrón útil de explotación del kernel de Linux consiste en **falsear los metadatos de propiedad de un skb sin eliminar sus fragmentos ajenos** y, luego, dirigir ese skb a un consumidor que escribe in situ. En el caso de Open vSwitch (OVS), un fallo de upcall a espacio de usuario borra `SKBFL_SHARED_FRAG` de un skb `MSG_ZEROCOPY` que sigue activo; posteriormente, ESP descifra directamente sobre un folio de la caché de páginas de un archivo de solo lectura. Esto permite escribir de forma determinista en la caché de páginas local y se ha seguido mediante CVE-2026-90049, CVE-2026-89487 y CVE-2026-80977.<sup>[[1]](#references)[[2]](#references)</sup>

Se trata de un problema de la clase Copy Fail/Dirty Frag, no de corrupción clásica de memoria: no se necesita una condición de carrera ni la divulgación de direcciones, basta con que el archivo sea legible y los bytes modificados existen en la caché de páginas, no en el disco.<sup>[[2]](#references)[[3]](#references)</sup>

## Invariante de seguridad: los fragmentos ajenos deben permanecer marcados

`SKBFL_SHARED_FRAG` indica a los consumidores que escriben in situ que un fragmento del skb puede hacer referencia a almacenamiento que no poseen de forma privada. La ruta rápida de ESP en `esp_input()` solo puede descifrar in situ un skb no lineal y sin clonar cuando `skb_has_shared_frag()` es falso; de lo contrario, `skb_cow_data()` crea primero almacenamiento privado. Esta comprobación del lado del consumidor se añadió después de Dirty Frag.<sup>[[5]](#references)</sup>

Por lo tanto, el invariante consta de dos partes independientes:<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. Los escritores in situ deben comprobar `SKBFL_SHARED_FRAG` y copiar los datos compartidos antes de modificarlos.
2. Todas las rutas de clonación, coalescencia, transferencia o reenvío deben preservar el marcador mientras la página ajena siga asociada.

Fragnesia infringió la segunda regla al mover descriptores de fragmentos en `skb_try_coalesce()`. La ruta de OVS es sutilmente diferente: no transfiere el fragmento; borra el marcador **in situ en el skb original y luego continúa reenviándolo**.<sup>[[2]](#references)[[4]](#references)</sup>

## Accesibilidad de OVS sin privilegios

El datapath del kernel de OVS se controla mediante familias genéricas de netlink, como `ovs_datapath`, `ovs_vport`, `ovs_flow` y `ovs_packet`. Sus operaciones de modificación usan `GENL_UNS_ADMIN_PERM`, que tiene en cuenta los namespaces, por lo que un proceso ejecutado con `unshare -Urn` obtiene el `CAP_NET_ADMIN` necesario para crear un datapath, conectar un veth e instalar acciones de flujo dentro de su propio namespace de red. Resolver la familia OVS también puede cargar automáticamente `openvswitch.ko`; esta superficie de ataque no requiere `CAP_SYS_MODULE` en el host, `ovs-vsctl` ni `ovs-vswitchd`.<sup>[[2]](#references)[[7]](#references)</sup>

La distinción importante está entre dos tipos de upcall:<sup>[[2]](#references)[[7]](#references)</sup>

- Un **fallo de flujo** envía el paquete a `ovs-vswitchd`; si el upcall falla, normalmente se descarta el paquete.
- Una acción explícita `OVS_ACTION_ATTR_USERSPACE` envía una copia prestada a un ID de puerto seleccionado y, luego, ejecuta las acciones posteriores en el skb original.

Por lo tanto, un atacante puede instalar un flujo con esta estructura:<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

Ningún listener es propietario del ID de puerto seleccionado, por lo que la acción de userspace falla de forma predecible, mientras que la acción `OUTPUT` siguiente mantiene vivo el paquete original.<sup>[[1]](#references)[[2]](#references)</sup>

## Causa raíz: `skb_tx_error()` en un paquete que sobrevive

La ruta de error de upcall vulnerable de OVS llama a `skb_tx_error(skb)`. Ese helper se diseñó para una transmisión fallida después de la cual se libera el skb; completa el bookkeeping de zerocopy mediante `skb_zcopy_clear()`, cuya máscara de flags también eliminaba históricamente `SKBFL_SHARED_FRAG`. OVS ignoró el error de la acción de userspace y continuó con su lista de acciones, incumpliendo el contrato de vida útil del helper.<sup>[[1]](#references)[[2]](#references)</sup>

La transición de estado explotable es:<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

Esto solo funciona cuando `skb_zcopy()` encuentra un estado zerocopy. Un fragmento que solo lleve `SKBFL_SHARED_FRAG` no es suficiente; `MSG_ZEROCOPY` es útil porque crea `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG` y también establece `SKBFL_DONT_ORPHAN`. Esto último hace que `skb_orphan_frags()` omita la sustitución de las páginas ajenas durante la copia de OVS en espacio de usuario.<sup>[[2]](#references)[[3]](#references)</sup>

## Construcción de la primitiva de escritura

El activador de extremo a extremo consta de los siguientes componentes.<sup>[[2]](#references)[[3]](#references)</sup>

1. Entrar en namespaces privados de usuario y de red con `unshare -Urn`.
2. Mapear un archivo objetivo legible con `PROT_READ | MAP_SHARED`.
3. Usar un netns de envío separado y un par veth; el loopback local copiaría las páginas prestadas y destruiría la primitiva.
4. Crear un datapath de OVS y el flow fallido `USERSPACE` seguido de `OUTPUT`.
5. Instalar un estado XFRM ESP-in-UDP en modo transporte usando `rfc4106(gcm(aes))` y el puerto UDP 4500.
6. Enviar un datagrama `MSG_ZEROCOPY` con un iovec estructurado como `[cabecera ESP | bytes del archivo mapeado | ICV no válido]`.

El estado XFRM usa 20 bytes de material de clave AES-128-GCM: 16 bytes de clave AES seguidos de la sal de cuatro bytes de RFC 4106. Para un IV explícito de ocho bytes elegido, la confidencialidad del payload comienza con el bloque contador `salt || IV || be32(2)`; el valor de contador 1 enmascara el resultado de autenticación.<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

Una vez que OVS elimina el marcador, ESP sigue su ruta no-copy y realiza `plaintext = ciphertext XOR keystream` sobre el fragmento respaldado por archivo. La autenticación se comprueba **después** de esta transformación, por lo que un ICV no válido compuesto únicamente por ceros hace que el paquete falle con `-EBADMSG` solo después de que los bytes de la page-cache ya hayan cambiado.<sup>[[2]](#references)</sup>

### Convertir GCM en bytes elegidos

Para el byte actual `C` y el byte deseado `P`, el primer byte del keystream del payload debe ser `C XOR P`. Con la clave AES y el salt fijos, recorre un sufijo de 16 bits del IV explícito y precalcula un sufijo para cada posible primer byte del keystream:<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

La implementación pública limita el texto cifrado a 32 bytes y avanza un byte el fragmento del archivo por cada paquete. El primer byte elegido sobrescribe el primer byte colateral del paquete anterior; `pread()` actualiza `C` antes de cada paquete, se omiten los bytes iguales y el paquete final se acorta para que las escrituras no excedan el rango solicitado. Así, una tabla de búsqueda de 256 entradas convierte la primitiva en una escritura de contenido elegido, byte a byte, en la caché de páginas, a razón de aproximadamente un paquete por cada byte distinto.<sup>[[2]](#references)[[3]](#references)</sup>

## Escritura en la caché de páginas para obtener root

Un objetivo práctico es un ejecutable setuid-root existente. El PoC reemplaza los primeros 160 bytes por un ELF estático completo que contiene un `PT_LOAD` de lectura y ejecución en una dirección fija, no tiene `PT_INTERP` y ejecuta código que llama a `setuid(0)` antes de `execve("/bin/sh", ...)`. Esto evita hacer suposiciones sobre el punto de entrada del binario original, la disposición de PIE, el cargador dinámico o las reubicaciones.<sup>[[2]](#references)[[3]](#references)</sup>

La modificación es visible en todos los espacios de nombres de usuario porque la caché de páginas no está aislada por espacios de nombres. El folio alterado no se marca como dirty, por lo que no se vuelve a escribir; ejecuta el objetivo mientras permanezca en memoria y luego descarta la corrupción temporal con `posix_fadvise(..., POSIX_FADV_DONTNEED)` para que las lecturas posteriores vuelvan a cargar el contenido original del disco.<sup>[[2]](#references)[[3]](#references)</sup>

## Comprobaciones de exposición y mitigación

Comprueba primero el kernel del proveedor en uso. Los factores relevantes para determinar la exposición son los espacios de nombres de usuario sin privilegios, la disponibilidad o presencia de OVS y una implementación ESP disponible.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

Actualiza a un kernel que incluya la serie completa de correcciones; la reparación final cubre la ruta de recirculación y evita modificar el estado compartido de `skb_shinfo()`, además de corregir un caso relacionado en `skb_zerocopy()`.<sup>[[1]](#references)[[2]](#references)</sup>

Si no se usa OVS, impide tanto la carga por alias como por nombre mediante una regla `install` de modprobe, en lugar de depender solo de `blacklist`. Si el host no termina IPsec y ESP es modular, el mismo control puede eliminar el sumidero de descifrado.<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

Estas reglas no ayudan cuando un módulo ya está cargado o la función está integrada en el kernel. Deshabilitar los user namespaces sin privilegios también elimina la fuente de capacidades de namespace, pero puede impedir el funcionamiento de navegadores, Flatpak, Podman y otras cargas de trabajo de sandboxing y contenedores.<sup>[[2]](#references)</sup>

## Lecciones de la revisión

Al auditar redes zero-copy, no limites la búsqueda a los helpers que copian o mueven fragmentos. Identifica también los helpers de error/finalización que borran flags agrupados y verifica que cada caller respete el contrato documentado sobre el ciclo de vida de skb. Un bit de propiedad de página agrupado con bits del ciclo de vida de zerocopy es sensible desde el punto de vista de la seguridad, incluso cuando el código que lo borra nunca accede directamente a un fragmento.<sup>[[1]](#references)[[2]](#references)</sup>

Una solución robusta debe cubrir todas las rutas por las que el skb puede sobrevivir, incluida la continuación de acciones y la recirculación, y debe tener en cuenta que los clones comparten `skb_shinfo()`. En el lado del consumidor, un fallo de autenticación no revierte las escrituras de texto plano que ya haya realizado una transformación AEAD in-place, por lo que las comprobaciones de almacenamiento ajeno deben realizarse antes de iniciar el descifrado.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Serie de correcciones de Doyensec en netdev: net: no elimines los marcadores de frag de zerocopy de un skb reenviado](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec: la eliminación de marcadores de skb reenviados en Open vSwitch permite un LPE determinista en la caché de páginas ESP](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Prueba de concepto `ovs-pagecache-write` de Doyensec](https://github.com/doyensec/ovs-pagecache-write)
- [4] [Corrección de Linux para la ruta de coalescencia original de Fragnesia (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Comprobación de fragmentos compartidos del consumidor ESP de Linux (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106: Uso del modo Galois/Counter (GCM) en IPsec ESP](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Documentación del datapath del kernel de Open vSwitch](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}
