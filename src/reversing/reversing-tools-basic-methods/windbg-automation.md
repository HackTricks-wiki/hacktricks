# Automatyzacja WinDbg na potrzeby ukierunkowanej instrumentacji

{{#include ../../banners/hacktricks-training.md}}

WinDbg i WinDbgX mogą uruchamiać polecenia debuggera podczas startu, przy wyjątkach oraz po trafieniu w breakpointy. Dzięki temu podczas sesji fuzzingowej lub reverse engineeringu można zbierać stan tylko w obrębie ścieżki wywołanej danymi wejściowymi, zamiast ręcznie zatrzymywać program przy każdym zdarzeniu.<sup>[[1]](#references)</sup>

## Rozpocznij od przydatnego wyjątku

`-c` uruchamia polecenia przy pierwszym zatrzymaniu debuggera. Dodaj `;g`, aby wznowić działanie po konfiguracji. W przypadku nienadzorowanego uruchomienia WinDbg Classic opcja `-logo` zapisuje zawartość okna poleceń do pliku dziennika, `-Q` wyłącza automatyczne zapisywanie obszaru roboczego, a `-G` ignoruje końcowy breakpoint, aby sesja zakończyła się po wyjściu procesu docelowego. WinDbgX również obsługuje `-c`; skonfigurowane polecenia startowe uruchamiają się później.<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

W przypadku naruszeń dostępu **`sxe av` przerywa działanie przy pierwszej szansie**, **`sxd av` pomija pierwszą szansę, ale przerywa działanie przy nieobsłużonej drugiej szansie**, a **`sxi av` ignoruje obie szanse**. Opisy `sxi`/`sxd` w artykule są tu odwrócone: Microsoft opisuje `sxd` jako filtr drugiej szansy, a `sxi` jako ignorowanie. Użyj `-c` dla polecenia wykonywanego przy pierwszej szansie, a `-c2` dla polecenia wykonywanego przy drugiej szansie; procedura obsługi `-c` dla pierwszej szansy nie staje się procedurą obsługi drugiej szansy tylko dlatego, że filtr to `sxd`. Sprawdź aktywne filtry poleceniem `sx`.<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

Pierwsze polecenie zbiera rejestry, ślad stosu i analizę wyjątku tylko w przypadku nieobsłużonego naruszenia dostępu. Drugie uruchamia `lm` po załadowaniu modułu. Zdarzenia breakpoint (`bp`), ładowania modułu (`ld`) i naruszenia dostępu (`av`) mają różne cykle życia, dlatego nie ignoruj globalnie `bp`, jeśli korzystasz z breakpointów debuggera.<sup>[[1]](#references)[[2]](#references)</sup>

## Ogranicz kosztowne breakpointy za pomocą kontrolowanego wyzwalacza

Wybierz funkcję widoczną dla skryptu lub sterowaną w inny sposób przez dane wejściowe, którą można wywołać bezpośrednio przed interesującą Cię ścieżką. Ustaw **action breakpoints** na allocatorze, parserze lub wywołaniach API, które chcesz sprawdzić. Wyłącz je według ID za pomocą `bd`. Ustaw **trigger breakpoint** z dołączonym poleceniem, które włącza te ID za pomocą `be`, a następnie wznawia wykonanie poleceniem `g`; drugi kontrolowany wyzwalacz może je ponownie wyłączyć. Sprawdź ID poleceniem `bl` przed skonfigurowaniem wyzwalacza, ponieważ zależą one od kolejności tworzenia breakpointów. Dzięki temu tanie punkty kontrolne są oddzielone od kosztownego śledzenia, a zmiany w czasie działania celu i układzie heap są ograniczone.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Po ustaleniu dwóch symboli zastosuj poniższy wzorzec polecenia. Zastąp symbole w nawiasach kwadratowych i ID action breakpointu zwrócone przez `bl`; nie zakładaj, że wynosi zero.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

Polecenia breakpointów akcji mogą wypisywać `@$ip` i `%y` (adres zdekodowany przez symbole), zrzucać wybrane argumenty lub pamięć, a następnie kontynuować. Jeśli warunkowy breakpoint loguje tylko wskaźniki z wybranego zakresu, najpierw sprawdź, czy zakres rzeczywiście obejmuje dane wejściowe testu; błędny warunek po cichu powoduje utratę dowodów.<sup>[[1]](#references)</sup>

### Znajdź wyzwalacz przy użyciu symboli

Jeśli nie wiadomo, który moduł zawiera implementację, przeszukaj wszystkie załadowane moduły. `bm` ustawia breakpointy na każdym pasującym symbolu; wywołaj funkcję widoczną dla skryptu i sprawdź, który breakpoint zostanie aktywowany. Na przykład źródło wywołuje `Math.cos(0)` w debugowanym rendererze, a nie w dowolnym procesie przeglądarki.<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

Gdy trafienie wskaże dokładną funkcję, użyj `lm a <symbol>`, aby ustalić obraz, który ją zawiera, oraz `? <symbol> - <module>`, aby obliczyć offset względem modułu. WinDbg może wyświetlać tę samą krótką nazwę modułu dla pliku wykonywalnego i DLL, dlatego przed użyciem offsetu w innym procesie sprawdź ścieżkę obrazu. Zawęź wildcard breakpoints do zweryfikowanego symbolu, aby uniknąć narzutu.<sup>[[1]](#references)</sup>

### Znajdź kandydata bez symboli

Oparty na Frida skrypt Corelan `corelan_trigscan.py` skanuje wybrany moduł procesu w poszukiwaniu wzorców instrukcji zmiennoprzecinkowych, SSE, AVX i trygonometrycznych. Generuje polecenia breakpointów WinDbg w pliku `corelan_trigscan.bps` oraz mniejsze, ponumerowane pliki `.bps`. Uruchom go za pomocą Pythona i `frida-tools` na procesie docelowym **bez podłączonego innego debuggera**; następnie podłącz WinDbg do tego samego procesu/modułu i załaduj możliwą do obsłużenia partię breakpointów.<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

Dla znanego przesunięcia względem modułu sprawdź, czy przechodzi ono przez progi, zanim zaimportujesz wszystkie wygenerowane punkty przerwania:<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` to gęstość istotnych instrukcji, `--min-relevant` i `--min-total` ustawiają dolne limity liczby instrukcji, a `--min-trig` wymaga silnych sygnałów przypominających instrukcje trygonometryczne. Jeśli nie wykryto znanej funkcji, przekaż jej offset **względem modułu** do `--check-offset`, aby sprawdzić jej prolog, gęstość, liczbę instrukcji i wywołania pośrednie. Cienki wrapper może mieć niską gęstość i nie zawierać instrukcji trygonometrycznych. Obniż progi, a jeśli szukasz wrapperów, użyj rzeczywistej opcji skryptu `--min-icall 1` (nie `--min-ical`); wywołania bezpośrednie są analizowane, ale nie można niezawodnie śledzić celów wywołań pośrednich. Mniejsze partie `--splitsize` pomagają, gdy wiele wygenerowanych breakpointów spowalnia WinDbg. Kandydat nie jest potwierdzony, dopóki zamierzone dane wejściowe nie spowodują zadziałania jego breakpointu.<sup>[[1]](#references)[[6]](#references)</sup>

## Małe programy debuggera i PyKD

Używaj `.if`, gdy warunek jest wiarygodny, `.foreach`, aby iterować po danych wyjściowych rozdzielonych białymi znakami, a `.for` z rejestrami pseudo, aby przeglądać pamięć lub struktury. `.foreach` **nie** zachowuje kolumn: na przykład dane wyjściowe `lm` o zmiennej szerokości są słabym źródłem danych, podczas gdy `lm 1m` zwraca po jednej nazwie modułu na token. Najpierw loguj niefiltrowane dane, jeśli przypuszczalny warunek mógłby ukryć ścieżkę prowadzącą do błędu.<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

Aliasy utworzone za pomocą `as name value` są podstawieniami tekstowymi, a nie typowanymi zmiennymi. `al` wyświetla listę aliasów, `ad name` usuwa alias, a `${name}` wymusza jednoznaczne rozwinięcie. Unikaj nazw takich jak `bp`, `x` czy `r`, ponieważ alias może przesłonić wbudowane polecenie. Wyrażenia MASM sprawdzają się przy arytmetyce wskaźników, np. `poi(@$t0)`; `@@c++(...)` umożliwia dostęp do typowanych pól, gdy dostępne są symbole, dzięki czemu nie trzeba wpisywać na stałe przesunięć w strukturach.<sup>[[1]](#references)</sup>

Umieszczaj dłuższe sekwencje poleceń w pliku poleceń. `$$><filename` łączy wiersze w jeden blok poleceń i umożliwia dodanie po nim polecenia debuggera oddzielonego średnikiem. Wielowierszowe instrukcje sterujące bywają nadal zawodne; umieszczaj każdą instrukcję `.if` lub `.for` w jednym wierszu. Ten sam plik można uruchomić przy starcie za pomocą `-c`.<sup>[[1]](#references)[[8]](#references)</sup>

W przypadku logiki trudnej do zapisania w języku poleceń PyKD udostępnia Pythonowi typowane struktury, rejestry, pamięć i dane wyjściowe debuggera. Na przykład `pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())` umożliwia dostęp do pól PEB, `pykd.loadBytes(address, size)` odczytuje pamięć, a `pykd.dbgCommand("lm")` zwraca dane wyjściowe debuggera do przetworzenia. W przypadku danych, które mogą nie być zakończone terminatorem, wybieraj ograniczone odczyty `loadChars`/`loadWChars` zamiast odczytów ciągów o nieograniczonej długości. `disasm(address).asm(instruction)` w PyKD **zapisuje złożone bajty pod danym adresem**, więc jeśli używasz go do uzyskania kodów operacji w działającym procesie, zachowaj oryginalną zawartość pamięci i przywróć ją.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan: Debugowanie — automatyzacja i skrypty WinDBG(X) — część 1](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft: sx, sxd, sxe, sxi, sxn, sxr, sx- (ustawianie wyjątków)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft: be (włączanie punktu przerwania)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft: bd (wyłączanie punktu przerwania)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft: bp, bu, bm (ustawianie punktu przerwania)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Kod źródłowy Corelan trigscan](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft: opcje wiersza poleceń WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft: uruchamianie pliku skryptu](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
