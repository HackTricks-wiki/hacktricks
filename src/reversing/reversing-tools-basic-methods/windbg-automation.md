# WinDbg automatizacija ciljane instrumentacije

{{#include ../../banners/hacktricks-training.md}}

WinDbg i WinDbgX mogu da pokreću debugger komande pri pokretanju, pri izuzecima i kada se aktiviraju breakpoint-i. Tako sesija fuzzing-a ili reverznog inženjerstva može da prikuplja stanje samo oko putanje pokrenute ulaznim podacima, umesto da se ručno zaustavlja pri svakom događaju.<sup>[[1]](#references)</sup>

## Počnite od korisnog izuzetka

`-c` pokreće komande pri početnom zaustavljanju debuggera. Dodajte `;g` da biste nastavili nakon podešavanja. Za WinDbg Classic pokretanje bez nadzora, `-logo` upisuje prozor komandi u log, `-Q` isključuje automatsko čuvanje workspace-a, a `-G` ignoriše završni breakpoint kako bi se sesija završila kada se ciljni program ugasi. WinDbgX takođe prihvata `-c`; njegove konfigurisane Startup komande pokreću se nakon toga.<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

Za povrede pristupa, **`sxe av` prekida izvršavanje pri prvom izuzetku**, **`sxd av` preskače prvi izuzetak, ali prekida izvršavanje ako neobrađeni izuzetak nastupi pri drugom**, a **`sxi av` ignoriše oba izuzetka**. Opisi za `sxi`/`sxd` u članku su obrnuti: Microsoft dokumentuje `sxd` kao filter za drugi izuzetak, a `sxi` kao opciju za ignorisanje. Koristite `-c` za komandu pri prvom izuzetku, a `-c2` za komandu pri drugom; rukovalac `-c` za prvi izuzetak ne postaje rukovalac za drugi samo zato što je filter `sxd`. Potvrdite aktivne filtere pomoću `sx`.<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

Prva komanda prikuplja registre, stek-trag i analizu izuzetka samo za neobrađeni prekršaj pristupa. Druga pokreće `lm` kada se modul učita. Događaji za breakpoint (`bp`), učitavanje modula (`ld`) i prekršaj pristupa (`av`) imaju različite životne cikluse, zato nemojte globalno ignorisati `bp` ako se oslanjate na breakpoint-ove debagera.<sup>[[1]](#references)[[2]](#references)</sup>

## Aktivirajte skupe breakpoint-ove kontrolisanim okidačem

Izaberite funkciju dostupnu skripti ili na drugi način kontrolisanu ulaznim podacima, koju možete pozvati neposredno pre putanje od interesa. Postavite **action breakpoint-ove** na pozive alokatora, parsera ili API-ja koje želite da pregledate. Onemogućite ih po ID-u pomoću `bd`. Postavite **trigger breakpoint** sa pridruženom komandom koja omogućava te ID-jeve pomoću `be`, a zatim nastavlja izvršavanje pomoću `g`; drugi kontrolisani okidač može ponovo da ih onemogući. Proverite ID-jeve pomoću `bl` pre povezivanja okidača, jer zavise od redosleda kreiranja breakpoint-ova. Tako razdvajate jeftine kontrolne tačke od skupog praćenja i ograničavate promene u tajmingu ciljnog procesa i rasporedu heap-a.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Kada razrešite dva simbola, koristite obrazac komandi ispod. Zamenite simbole u uglastim zagradama i ID action breakpoint-a koji je vratio `bl`; nemojte pretpostaviti da je nula.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

Action breakpoint komande mogu da ispišu `@$ip` i `%y` (simbolizovanu adresu), prikažu izabrane argumente ili memoriju, a zatim nastave izvršavanje. Ako uslovni breakpoint beleži samo pokazivače iz izabranog opsega, prvo proverite da li taj opseg zaista obuhvata testni ulaz; pogrešan uslov neprimetno dovodi do gubitka dokaza.<sup>[[1]](#references)</sup>

### Pronalaženje okidača pomoću simbola

Pretražite sve učitane module ako nije poznat modul koji sadrži implementaciju. `bm` postavlja breakpointe na svaki simbol koji se poklapa; pozovite funkciju dostupnu skripti i proverite koji breakpoint se aktivira. Na primer, izvorni kod pokreće `Math.cos(0)` u renderer-u koji se debaguje, a ne u bilo kom procesu pregledača.<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

Kada pogodak identifikuje tačnu funkciju, upotrebite `lm a <symbol>` da biste pronašli sliku koja je sadrži, a `? <symbol> - <module>` da biste izračunali pomeraj u odnosu na modul. WinDbg može da prikaže isto kratko ime modula za izvršnu datoteku i DLL, zato proverite putanju do slike pre nego što upotrebite pomeraj u drugom procesu. Sužite wildcard breakpoints na potvrđeni simbol da biste izbegli dodatno opterećenje.<sup>[[1]](#references)</sup>

### Pronađite kandidata bez simbola

Corelan-ov `corelan_trigscan.py`, zasnovan na Frida-i, skenira izabrani modul procesa tražeći obrasce instrukcija s pokretnim zarezom, SSE, AVX i trigonometrijske instrukcije. Ispisuje WinDbg komande za breakpoint-ove u `corelan_trigscan.bps` i manje numerisane `.bps` datoteke. Pokrenite ga pomoću Python-a i `frida-tools` nad ciljnom aplikacijom **bez prikačenog drugog debagera**; zatim prikačite WinDbg na isti proces/modul i učitajte breakpoint batch kojim se može upravljati.<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

Za poznati pomeraj relativan u odnosu na modul, proverite da li prolazi pragove pre uvoza svih emitovanih tačaka prekida:<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` je gustina relevantnih instrukcija, `--min-relevant` i `--min-total` postavljaju donje granice broja instrukcija, a `--min-trig` zahteva snažne trig-like signale. Ako poznata funkcija nije pronađena, prosledite njen **relativni ofset u modulu** opciji `--check-offset` da biste pregledali njen prolog, gustinu, broj instrukcija i indirect calls. Tanak wrapper može imati nisku gustinu i nijednu trig instrukciju. Snizite pragove i, ako tražite wrappe, koristite stvarnu opciju skripte `--min-icall 1` (ne `--min-ical`); analiziraju se direktni pozvani ciljevi, ali indirect targets nije moguće pouzdano pratiti. Manji paketi `--splitsize` pomažu kada veliki broj generisanih breakpointova usporava WinDbg. Kandidat nije potvrđen dok se njegov breakpoint ne aktivira za predviđeni ulaz.<sup>[[1]](#references)[[6]](#references)</sup>

## Mali debugger programi i PyKD

Koristite `.if` kada je uslov pouzdan, `.foreach` za iteraciju kroz izlaz razdvojen razmacima, a `.for` sa pseudo-registers za prolazak kroz memoriju ili strukture. `.foreach` **ne čuva kolone**: izlaz `lm` sa promenljivom širinom, na primer, nije dobar ulaz, dok `lm 1m` daje po jedan naziv modula za svaki token. Prvo zabeležite nefiltrirane podatke ako bi pretpostavljeni uslov mogao da sakrije putanju koja dovodi do greške.<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

Alias-i kreirani pomoću `as name value` predstavljaju tekstualne zamene, a ne tipizirane promenljive. `al` ih izlistava, `ad name` briše alias, a `${name}` forsira nedvosmisleno proširenje. Izbegavajte nazive kao što su `bp`, `x` ili `r`, jer alias može da zaseni ugrađenu komandu. MASM izrazi odgovaraju za aritmetiku pokazivača, kao što je `poi(@$t0)`; `@@c++(...)` može da pristupi tipiziranim poljima kada su simboli dostupni, čime se izbegavaju hardkodirani pomaci u strukturama.<sup>[[1]](#references)</sup>

Duže nizove komandi smestite u komandnu datoteku. `$$><filename` spaja redove u jedan blok komandi i dozvoljava narednu komandu debuggera razdvojenu tačkom i zarezom. Višelinijske kontrolne strukture i dalje mogu biti nepouzdane; svaku `.if` ili `.for` naredbu držite u jednom redu. Ista datoteka može da se pozove pomoću `-c` pri pokretanju.<sup>[[1]](#references)[[8]](#references)</sup>

Za logiku koju je nezgodno izraziti u komandnom jeziku, PyKD Python-u izlaže tipizirane strukture, registre, memoriju i izlaz debuggera. Na primer, `pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())` pristupa poljima PEB-a, `pykd.loadBytes(address, size)` čita memoriju, a `pykd.dbgCommand("lm")` vraća izlaz debuggera za parsiranje. Za podatke koji možda nisu terminirani, radije koristite ograničene funkcije `loadChars`/`loadWChars` nego čitanje stringova bez ograničenja. PyKD funkcija `disasm(address).asm(instruction)` **upisuje asemblirane bajtove na tu adresu**, zato sačuvajte i vratite originalnu memoriju ako je koristite za pribavljanje opcode-ova u živom procesu.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan: Debugging - WinDBG(X) automatizacija i skriptovanje - 1. deo](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft: sx, sxd, sxe, sxi, sxn, sxr, sx- (Postavljanje izuzetaka)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft: be (Omogućavanje breakpoint-a)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft: bd (Onemogućavanje breakpoint-a)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft: bp, bu, bm (Postavljanje breakpoint-a)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Izvor Corelan trigscan](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft: Opcije komandne linije WinDbg-a](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft: Pokretanje skriptne datoteke](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
