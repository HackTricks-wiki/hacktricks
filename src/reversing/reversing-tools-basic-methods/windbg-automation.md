# WinDbg-Automatisierung für gezielte Instrumentierung

{{#include ../../banners/hacktricks-training.md}}

WinDbg und WinDbgX können beim Start, bei Ausnahmen und beim Auslösen von Breakpoints Debugger-Befehle ausführen. So kann eine Fuzzing- oder Reversing-Sitzung den Zustand nur rund um einen eingabegetriebenen Pfad erfassen, statt bei jedem Ereignis manuell anzuhalten.<sup>[[1]](#references)</sup>

## Bei einer nützlichen Ausnahme starten

`-c` führt Befehle beim anfänglichen Debugger-Halt aus. Hänge `;g` an, um nach der Einrichtung fortzufahren. Bei einem unbeaufsichtigten WinDbg-Classic-Lauf schreibt `-logo` das Befehlsfenster in ein Log, deaktiviert `-Q` das automatische Speichern des Arbeitsbereichs und ignoriert `-G` den letzten Breakpoint, sodass die Sitzung endet, wenn das Ziel beendet wird. WinDbgX akzeptiert ebenfalls `-c`; seine konfigurierten Startup-Befehle werden danach ausgeführt.<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

Bei Zugriffsverletzungen **bricht `sxe av` beim First-Chance-Ausnahmeereignis ab**, **überspringt `sxd av` das First-Chance-Ereignis, bricht aber bei einer nicht behandelten Second-Chance-Ausnahme ab**, und **ignoriert `sxi av` beide Ereignisse**. Die Beschreibungen von `sxi` und `sxd` im Artikel sind hier vertauscht: Microsoft dokumentiert `sxd` als Filter für Second-Chance-Ausnahmen und `sxi` als „ignorieren“. Verwende `-c` für einen Befehl bei einer First-Chance-Ausnahme und `-c2` für einen Befehl bei einer Second-Chance-Ausnahme; ein First-Chance-Handler mit `-c` wird nicht allein dadurch zu einem Second-Chance-Handler, dass der Filter `sxd` ist. Prüfe die aktiven Filter mit `sx`.<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

Der erste Befehl erfasst Register, einen Stacktrace und eine Ausnahmeanalyse, jedoch nur bei einer nicht behandelten Zugriffsverletzung. Der zweite führt `lm` aus, wenn ein Modul geladen wird. Breakpoint- (`bp`), Modul-Lade- (`ld`) und Zugriffsverletzungsereignisse (`av`) haben unterschiedliche Lebenszyklen. Ignorieren Sie daher `bp` nicht global, wenn Sie sich auf Debugger-Breakpoints verlassen.<sup>[[1]](#references)[[2]](#references)</sup>

## Aufwendige Breakpoints mit einem kontrollierten Auslöser aktivieren

Wählen Sie eine für Skripte sichtbare oder anderweitig durch Eingaben steuerbare Funktion, die unmittelbar vor dem relevanten Ausführungspfad aufgerufen werden kann. Setzen Sie **Aktions-Breakpoints** auf die zu untersuchenden Aufrufe des Allokators, Parsers oder der API. Deaktivieren Sie sie anhand ihrer ID mit `bd`. Setzen Sie einen **Auslöser-Breakpoint**, dessen zugehöriger Befehl diese IDs mit `be` aktiviert und dann mit `g` fortfährt. Mit einem zweiten kontrollierten Auslöser können Sie sie wieder deaktivieren. Prüfen Sie die IDs mit `bl`, bevor Sie den Auslöser einrichten, da sie von der Reihenfolge abhängen, in der die Breakpoints erstellt wurden. So werden einfache Kontrollpunkte von der aufwendigen Ablaufverfolgung getrennt und Änderungen am Timing und Heap-Layout des Ziels begrenzt.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Nachdem Sie die beiden Symbole aufgelöst haben, verwenden Sie das folgende Befehlsmuster. Ersetzen Sie die Symbole in eckigen Klammern und die ID des Aktions-Breakpoints, die `bl` zurückgibt. Gehen Sie nicht davon aus, dass sie null ist.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

Action-Breakpoint-Befehle können `@$ip` und `%y` (symbolisierte Adresse) ausgeben, ausgewählte Argumente oder Speicherinhalte dumpen und dann fortfahren. Wenn ein bedingter Breakpoint nur Zeiger innerhalb eines ausgewählten Bereichs protokolliert, prüfe zuerst, ob der Bereich die Testeingabe tatsächlich abdeckt; eine falsche Bedingung lässt Belege unbemerkt verloren gehen.<sup>[[1]](#references)</sup>

### Einen Trigger mit Symbolen finden

Durchsuche alle geladenen Module, wenn das Implementierungsmodul unbekannt ist. `bm` setzt Breakpoints auf jedes passende Symbol; führe die skriptseitig sichtbare Funktion aus und prüfe, welcher Breakpoint ausgelöst wird. Beispielsweise ruft die Quelle `Math.cos(0)` im Renderer auf, der gerade debuggt wird, und nicht in irgendeinem Browserprozess.<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

Sobald ein Treffer die genaue Funktion identifiziert, verwenden Sie `lm a <symbol>`, um das zugehörige Image aufzulösen, und `? <symbol> - <module>`, um einen modulrelativen Offset zu berechnen. WinDbg kann für eine ausführbare Datei und eine DLL denselben kurzen Modulnamen anzeigen. Überprüfen Sie daher den Image-Pfad, bevor Sie den Offset in einem anderen Prozess verwenden. Schränken Sie die Wildcard-Breakpoints auf das bestätigte Symbol ein, um den Overhead zu vermeiden.<sup>[[1]](#references)</sup>

### Einen Kandidaten ohne Symbole finden

Corelans Frida-basiertes `corelan_trigscan.py` durchsucht ein ausgewähltes Prozessmodul nach Mustern für Gleitkomma-, SSE-, AVX- und trigonometrische Instruktionen. Das Skript gibt WinDbg-Breakpoint-Befehle in `corelan_trigscan.bps` sowie kleinere nummerierte `.bps`-Dateien aus. Führen Sie es mit Python und `frida-tools` für das Ziel aus, **ohne dass ein weiterer Debugger angehängt ist**. Hängen Sie WinDbg anschließend an denselben Prozess bzw. dasselbe Modul an und laden Sie einen überschaubaren Breakpoint-Satz.<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

Für einen bekannten modulrelativen Offset prüfen, ob er die Schwellenwerte übersteht, bevor alle ausgegebenen Breakpoints importiert werden:<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` ist die Dichte relevanter Instruktionen, `--min-relevant` und `--min-total` legen Mindestanzahlen für Instruktionen fest, und `--min-trig` erfordert starke trig-ähnliche Signale. Wird eine bekannte Funktion nicht gefunden, übergib ihren relativen Offset im Modul an `--check-offset`, um Prolog, Dichte, Anzahlen und indirekte Aufrufe zu prüfen. Ein einfacher Wrapper kann eine geringe Dichte und keine Trig-Instruktion aufweisen. Senke die Schwellenwerte und verwende bei der Suche nach Wrappern die tatsächliche Option des Skripts `--min-icall 1` (nicht `--min-ical`); direkte Aufrufe werden analysiert, indirekte Ziele lassen sich jedoch nicht zuverlässig verfolgen. Kleinere `--splitsize`-Batches helfen, wenn viele generierte Breakpoints WinDbg verlangsamen. Ein Kandidat gilt erst dann als bestätigt, wenn die vorgesehene Eingabe seinen Breakpoint auslöst.<sup>[[1]](#references)[[6]](#references)</sup>

## Kleine Debugger-Programme und PyKD

Verwende `.if`, wenn eine Bedingung zuverlässig ist, `.foreach`, um durch Leerzeichen getrennte Ausgaben zu durchlaufen, und `.for` mit Pseudoregistern, um Speicher oder Strukturen zu durchlaufen. `.foreach` erhält **keine** Spalten: Eine Ausgabe von `lm` mit variabler Breite ist beispielsweise eine schlechte Eingabe, während `lm 1m` einen Modulnamen pro Token liefert. Protokolliere zuerst ungefilterte Daten, wenn eine vermutete Bedingung den fehlerhaften Ausführungspfad verbergen könnte.<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

Mit `as name value` erstellte Aliases sind Textersetzungen und keine typisierten Variablen. `al` listet sie auf, `ad name` löscht einen Alias, und `${name}` erzwingt eine eindeutige Expansion. Vermeide Namen wie `bp`, `x` oder `r`, da ein Alias einen integrierten Befehl überschreiben kann. MASM-Ausdrücke eignen sich für Zeigerarithmetik wie `poi(@$t0)`; mit `@@c++(...)` lassen sich bei vorhandenen Symbolen typisierte Felder abrufen, ohne feste Struktur-Offsets zu verwenden.<sup>[[1]](#references)</sup>

Lege längere Befehlsfolgen in einer Befehlsdatei ab. `$$><filename` fügt Zeilen zu einem einzelnen Befehlsblock zusammen und erlaubt einen nachfolgenden, durch Semikolon getrennten Debugger-Befehl. Mehrzeilige Kontrollstrukturen können weiterhin fehleranfällig sein; schreibe jede `.if`- oder `.for`-Anweisung in eine Zeile. Dieselbe Datei lässt sich beim Start mit `-c` aufrufen.<sup>[[1]](#references)[[8]](#references)</sup>

Für Logik, die sich nur umständlich in der Befehlssprache ausdrücken lässt, stellt PyKD Python typisierte Strukturen, Register, Speicher und Debugger-Ausgaben bereit. Beispielsweise greift `pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())` auf PEB-Felder zu, `pykd.loadBytes(address, size)` liest Speicher, und `pykd.dbgCommand("lm")` gibt Debugger-Ausgaben zum Parsen zurück. Verwende für möglicherweise nicht nullterminierte Daten vorzugsweise begrenzte Aufrufe von `loadChars`/`loadWChars` statt unbegrenzter String-Lesevorgänge. PyKDs `disasm(address).asm(instruction)` **schreibt assemblierte Bytes an diese Adresse**. Wenn du die Funktion in einem laufenden Prozess zum Abrufen von Opcodes verwendest, sichere daher den ursprünglichen Speicherinhalt und stelle ihn anschließend wieder her.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan: Debugging – WinDBG(X)-Automatisierung und Scripting – Teil 1](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft: sx, sxd, sxe, sxi, sxn, sxr, sx- (Ausnahmen festlegen)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft: be (Breakpoint aktivieren)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft: bd (Breakpoint deaktivieren)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft: bp, bu, bm (Breakpoint setzen)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Corelan trigscan-Quellcode](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft: WinDbg-Befehlszeilenoptionen](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft: Skriptdatei ausführen](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
