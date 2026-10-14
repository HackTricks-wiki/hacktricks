# WinDbg-outomatisering vir geteikende instrumentering

{{#include ../../banners/hacktricks-training.md}}

WinDbg en WinDbgX kan debugger-opdragte laat loop wanneer dit begin, wanneer uitsonderings voorkom en wanneer breakpoints afgaan. Dit laat ’n fuzzing- of reversing-sessie toe om slegs toestand rondom ’n invoergedrewe pad vas te lê, eerder as om elke gebeurtenis handmatig te stop.<sup>[[1]](#references)</sup>

## Begin by ’n nuttige uitsondering

`-c` voer opdragte uit by die aanvanklike debugger-breekpunt. Voeg `;g` by om ná die opstelling te hervat. Vir ’n onbewaakte WinDbg Classic-sessie skryf `-logo` die opdragvenster na ’n loglêer, deaktiveer `-Q` outomatiese stoor van werkruimtes, en ignoreer `-G` die finale breakpoint sodat die sessie eindig wanneer die teiken afsluit. WinDbgX aanvaar ook `-c`; sy gekonfigureerde Startup commands loop daarna.<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

Vir access violations **`sxe av` breek met first chance**, **`sxd av` slaan first chance oor, maar breek met ’n onbehandelde second chance**, en **`sxi av` ignoreer albei kanse**. Die artikel se beskrywings van `sxi`/`sxd` is hier omgeruil: Microsoft dokumenteer `sxd` as die second-chance-filter en `sxi` as ignoreer. Gebruik `-c` vir ’n first-chance-opdrag en `-c2` vir ’n second-chance-opdrag; ’n first-chance-`-c`-hanteerder word nie ’n second-chance-hanteerder bloot omdat die filter `sxd` is nie. Bevestig aktiewe filters met `sx`.<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

Die eerste opdrag versamel registers, 'n stack trace en uitsonderingsanalise slegs vir 'n onbehandelde access violation. Die tweede voer `lm` uit wanneer 'n module laai. Breakpoint- (`bp`), modulelaai- (`ld`) en access-violation- (`av`) gebeurtenisse het verskillende lewensiklusse, dus moenie `bp` wêreldwyd ignoreer wanneer jy op debugger-breakpoints staatmaak nie.<sup>[[1]](#references)[[2]](#references)</sup>

## Beheer duur breakpoints met 'n beheerde sneller

Kies 'n funksie wat vir 'n script sigbaar is of andersins deur invoer beheer word, en wat onmiddellik voor die interessante pad aangeroep kan word. Stel **action breakpoints** in op die allocator-, parser- of API-oproepe wat jy wil inspekteer. Deaktiveer hulle volgens ID met `bd`. Stel 'n **trigger breakpoint** in waarvan die aangehegte opdrag daardie ID's met `be` aktiveer en dan met `g` voortgaan; 'n tweede beheerde sneller kan hulle weer deaktiveer. Gaan ID's met `bl` na voordat jy die sneller instel, want hulle hang af van die volgorde waarin breakpoints geskep is. Só word goedkoop beheerpunte van duur tracing geskei en word veranderinge aan die teiken se tydsberekening en heap-uitleg beperk.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Nadat jy die twee simbole opgelos het, gebruik die onderstaande opdragpatroon. Vervang die simbole tussen hakies en die ID van die action breakpoint wat `bl` teruggee; moenie aanneem dat dit nul is nie.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

Aksiebreekpunt-opdragte kan `@$ip` en `%y` (gesimboliseerde adres) druk, geselekteerde argumente of geheue dump, en dan voortgaan. As ’n voorwaardelike breekpunt slegs wysers in ’n geselekteerde reeks aanteken, moet jy eers bevestig dat die reeks die toetsinvoer dek; ’n verkeerde voorwaarde laat bewyse ongemerk verlore gaan.<sup>[[1]](#references)</sup>

### Vind ’n sneller met simbole

Deursoek alle gelaaide modules as die implementasiemodule onbekend is. `bm` stel breekpunte op elke simbool wat ooreenstem; roep die skrip-sigbare funksie aan en kyk watter breekpunt aktiveer. Die bron dryf byvoorbeeld `Math.cos(0)` in die renderer wat ontfout word, nie sommer enige blaaierproses nie.<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

Sodra ’n treffer die presiese funksie identifiseer, gebruik `lm a <symbol>` om die image te bepaal waarin dit voorkom en `? <symbol> - <module>` om ’n module-relatiewe offset te bereken. WinDbg kan dieselfde kort modulenaam vir ’n uitvoerbare lêer en ’n DLL vertoon, dus moet jy die image-pad verifieer voordat jy die offset in ’n ander proses gebruik. Beperk die wildcard-breekpunte tot die geverifieerde simbool om oorhoofse koste te vermy.<sup>[[1]](#references)</sup>

### Vind ’n kandidaat sonder simbole

Corelan se Frida-gebaseerde `corelan_trigscan.py` skandeer ’n geselekteerde prosesmodule vir patrone van floating-point-, SSE-, AVX- en trigonometriese instruksies. Dit genereer WinDbg-breekpuntopdragte in `corelan_trigscan.bps` en kleiner genommerde `.bps`-lêers. Voer dit met Python en `frida-tools` teen die teiken uit **sonder dat ’n ander debugger aangeheg is**; heg WinDbg daarna aan dieselfde proses/module en laai ’n hanteerbare bondel breekpunte.<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

Vir ’n bekende module-relatiewe offset, valideer dat dit die drempels oorleef voordat alle gegenereerde breakpoints ingevoer word:<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` is relevante-instruksiedigtheid, `--min-relevant` en `--min-total` stel minimumaantalle instruksies in, en `--min-trig` vereis sterk trig-agtige seine. As ’n bekende funksie gemis word, gee sy **module-relatiewe** offset aan `--check-offset` deur om die proloog, digtheid, tellings en indirekte oproepe te inspekteer. ’n Dun wrapper het moontlik ’n lae digtheid en geen trig-instruksie nie. Verlaag die drempels en gebruik, as jy na wrappers soek, die script se werklike `--min-icall 1`-opsie (nie `--min-ical` nie); direkte callees word ontleed, maar indirekte teikens kan nie betroubaar gevolg word nie. Kleiner `--splitsize`-groottes help wanneer baie gegenereerde breakpoints WinDbg vertraag. ’n Kandidaat is eers bevestig wanneer die bedoelde invoer sy breakpoint laat aktiveer.<sup>[[1]](#references)[[6]](#references)</sup>

## Klein debugger-programme en PyKD

Gebruik `.if` wanneer ’n voorwaarde betroubaar is, `.foreach` om deur spasieskeide uitvoer te itereer, en `.for` met pseudo-registers om deur geheue of strukture te loop. `.foreach` behou **nie** kolomme nie: uitvoer van `lm` met veranderlike breedte is byvoorbeeld swak invoer, terwyl `lm 1m` een modulenaam per token lewer. Teken eers ongefiltreerde data aan as ’n geraaide voorwaarde die foutiewe pad kan verberg.<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

Aliases wat met `as name value` geskep word, is tekstuele vervangings, nie getikte veranderlikes nie. `al` lys hulle, `ad name` skrap een, en `${name}` dwing ’n ondubbelsinnige uitbreiding af. Vermy name soos `bp`, `x` of `r`, want ’n alias kan ’n ingeboude opdrag oorskadu. MASM-uitdrukkings is geskik vir wyserrekenkunde soos `poi(@$t0)`; `@@c++(...)` kan getikte velde benader wanneer simbole beskikbaar is, en vermy so hardgekodeerde struktuurafwykings.<sup>[[1]](#references)</sup>

Plaas langer opdragreekse in ’n opdraglêer. `$$><filename` voeg reëls saam in ’n enkele opdragblok en laat toe dat ’n debugger-opdrag, geskei deur ’n kommapunt, daarna volg. Multilyn-beheerstrukture kan steeds broos wees; hou elke `.if`- of `.for`-stelling op een reël. Dieselfde lêer kan met `-c` tydens aanvang uitgevoer word.<sup>[[1]](#references)[[8]](#references)</sup>

Vir logika wat ongemaklik is in die opdragtaal, stel PyKD getikte strukture, registers, geheue en debugger-uitvoer aan Python beskikbaar. Byvoorbeeld, `pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())` kry toegang tot PEB-velde, `pykd.loadBytes(address, size)` lees geheue, en `pykd.dbgCommand("lm")` gee debugger-uitvoer terug om te ontleed. Verkies begrensde `loadChars`/`loadWChars` bo onbeperkte stringlesings vir data wat moontlik nie nulbeëindig is nie. PyKD se `disasm(address).asm(instruction)` **skryf saamgestelde grepe by daardie adres**, dus moet jy die oorspronklike geheue bewaar en herstel as jy dit gebruik om opkodes in ’n lewendige proses te kry.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan: Ontfouting - WinDBG(X)-outomatisering en skriptering - Deel 1](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft: sx, sxd, sxe, sxi, sxn, sxr, sx- (Stel uitsonderings in)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft: be (Aktiveer breekpunt)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft: bd (Deaktiveer breekpunt)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft: bp, bu, bm (Stel breekpunt in)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Corelan trigscan-bronkode](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft: WinDbg-opdragreëlopsies](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft: Voer skriplêer uit](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
