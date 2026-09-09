# Statička deobfuskacija Node.js/V8 keširanog bytecode-a

{{#include ../../banners/hacktricks-training.md}}

V8 keširani podaci su **reprezentacija zavisna od verzije i sa gubitkom podataka**, a ne JavaScript source kod niti konvencionalni native executable. Zbog toga je koristan statički workflow sledeći: ukloniti svaki spoljašnji packing, disasemblirati keš pomoću odgovarajućeg V8 build-a, podići ga u model međukoda u obliku pseudokoda i primeniti transformacije koje uzimaju u obzir zavisnosti, bez izvršavanja sample-a. [View8](https://github.com/suleram/View8) i [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implementiraju ovaj pristup za Node.js payloads zaštićene pomoću `javascript-obfuscator`-a.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Preuzimanje i disasembliranje keša

Najpre analizirajte preload/launcher umesto da pretpostavite da svaki `.jsc` fajl ima isti wrapper. Na primer, launcher kao što je `node.exe -r preflight.js app.jsc` izvršava `preflight.js` pre glavnog modula; u analiziranoj familiji preload je uklanjao Brotli sloj. Nakon unpacking-a, utvrdite tačnu Node.js/V8 generaciju iz bundled runtime-a. Keš koji je proizvela jedna V8 verzija može biti odbijen ili neispravno dekodiran drugom verzijom, zato build-ujte ili nabavite `v8dasm` za precizno određeni V8 tag i primenite neophodne View8 zakrpe i zakrpe za ispis stringova.<sup>[[1]](#references)[[2]](#references)</sup>

Workflow toolkit-a koji ne izvršava kod je:<sup>[[2]](#references)</sup>
```bash
brotli -d app.jsc -o app.decompressed.jsc
/path/to/matching-v8dasm app.decompressed.jsc > app.jsc.disasm.txt
mkdir -p decompiled deobfuscated
python3 View8/view8.py --input_format disassembled \
--inp app.jsc.disasm.txt --normalize \
--out decompiled/app.dec.txt \
--export_format decompiled serialized
python3 deobf_all.py --inp decompiled/app.dec.pkl \
--out deobfuscated/app.deobf.txt \
--export_format decompiled serialized
```
`--normalize` daje generisanim funkcijama stabilne identifikatore kroz različita pokretanja. Tekstualni izlaz služi za inspekciju; serijalizovani graf objekata omogućava nezavisnim prolazima da očuvaju odnose između funkcija, deklaratora, opsega i metapodataka. On **nije rekonstruisani niti izvršivi JavaScript**.<sup>[[1]](#references)[[2]](#references)</sup>

### Čitanje pseudokoda View8 kao IR-a

Tipična imena su `func_<name>_0x<address>`, argumenti su `a0...aN`, virtuelni registri su `r0...rN`, a `ACCU` je V8 accumulator. `start` je korenski deklarator, dok `Scope[...]`, globals i dictionaries predstavljaju vrednosti koje su uhvatile ili dele ugnježdene funkcije. Nemojte svaki izraz parsirati kao JavaScript sintaksu: na primer, View8-ov `!r6 === "0"` predstavlja negaciju kompletnog poređenja (`r6 !== "0"`), što je važno prilikom ponovne izgradnje grana.<sup>[[1]](#references)[[3]](#references)</sup>

## Deobfuskacija zasnovana na zavisnostima

Primeni transformacije redosledom koji otkriva ulaze potrebne sledećem prolazu i ponavljaj propagaciju dok se izlaz ne stabilizuje. Praktičan redosled je:<sup>[[1]](#references)[[2]](#references)</sup>

1. Prođi kroz hijerarhiju deklaratora i propagiraj vrednosti iz globals, registara, dictionaries i `Scope[...]` referenci.
2. Rekonstruiši argumente string-decoder-a i zameni šifrovane pozive plaintext-om.
3. Spoji susedne string delove; dobijena imena svojstava i stringovi redosleda dispatcher-a otključavaju kasnije prolaze.
4. Raspljošti control flow, umetni call proxy-je i wrappers za atomic operations, i razreši reference funkcija smeštene u dictionaries.
5. Ponovo propagiraj vrednosti jer svaki razrešeni string, ključ ili proxy može otkriti novi sloj indirekcije.
6. Sažmi prepoznate one-shot initialization thunk-ove i ukloni mrtve pomoćne funkcije tek nakon razrešavanja njihovih call site-ova.

### Rekonstruiši pomerene RC4 string nizove kao crnu kutiju

Uobičajeni `javascript-obfuscator` raspored čuva Base64-kodirane RC4 delove u jednom nizu. Decoder wrappers prosleđuju numerički offset i kratak ključ, ponekad obrnutim redosledom argumenata, a zatim dodaju ili oduzimaju konstante uhvaćene u closure scope-ovima. Kada je korenski decoder previše obfuskiran, empirijski rekonstruiši nepoznati pomak indeksa niza umesto da ponovo izgradiš celu funkciju.<sup>[[1]](#references)</sup>

Za niz od `N` delova i nekoliko poziva istom decoder-u:<sup>[[1]](#references)</sup>
```text
for each observed (numeric_argument, rc4_key):
candidates = {}
for shift in 0 .. N-1:
index = apply_observed_sign(numeric_argument, shift)
plaintext = RC4(Base64Decode(chunks[index]), rc4_key)
if plaintext passes encoding/printability checks:
candidates.add(shift)
root_shift = intersection(candidate_sets)
```
Ne prihvatajte pomeranje na osnovu jednog dešifrovanog rezultata koji se može ispisati: pogrešan ciphertext slučajno može izgledati kao tekst koji se može ispisati. Koristite najmanje tri različita zapažanja i prihvatite samo jedinstveno pomeranje koje daje smislen tekst za sva zapažanja. Zatim prođite kroz graf wrapper/declarer funkcija, sabirajući svako sabiranje ili oduzimanje i beležeći da li numerički argument dolazi prvi. Keširajte ove metapodatke po uzorku, zamenite pozive decoder-a, spojite susedne delove plaintext-a i zasebno izvezite stringove radi trijaže.<sup>[[1]](#references)[[2]](#references)</sup>

### Očuvanje semantike pri uklanjanju ravnanja

Za dispatcher petlje kojima upravljaju stringovi kao što je `3|2|1|0|4`, dekodirajte string redosleda, mapirajte svako poređenje stanja na njegov blok, uzmite u obzir View8-ovu notaciju sa negiranim uslovom, a zatim emitujte blokove redosledom dispatcher-a. Ugnježdeni `continue` može predstavljati rani skok nazad na dispatcher, a ne uobičajeni fall-through. Prilikom uklanjanja petlje, obrišite taj `continue` i premestite naredbe koje su prvobitno sledile njegovom obuhvatajućem `if` bloku u generisanu `else` granu; samo brisanje dispatcher-a menja ponašanje.<sup>[[1]](#references)</sup>

### Inline proxies, operacije i lazy thunks

Normalizujte forwarding helper-e kao što je `return a0(a1, a2)` pre zamene njihovih call site-ova direktnim pozivima. Na isti način tretirajte wrapper-e za oduzimanje, deljenje, poređenje, membership testove ili invocation. Pošto sama referenca na helper može biti sačuvana iza dešifrovanog ključa dictionary-ja ili closure vrednosti, sprovedite propagaciju stringova i strukture pre i posle inlining-a.<sup>[[1]](#references)</sup>

Takođe prepoznajte closure-e koji jednom pozivaju sačuvanu funkciju, brišu njenu referencu, keširaju rezultat i pri narednim pozivima vraćaju taj keš. Uklanjanje takvog thunk-a na mestu inicijalizacije otkriva osnovni dispatcher ili capability funkciju, ali zabeležite da je prvobitno izvršavanje bilo **one-shot i keširano**, umesto da svaki poziv modelujete kao novu invokaciju.<sup>[[1]](#references)</sup>

## Napomene o bezbednosti i validaciji

- Python `pickle` učitavanje može izvršiti kod. Učitavajte samo `.pkl` datoteke lokalno generisane pouzdanim View8 pokretanjem; pickle koji potiče iz uzorka nikada nemojte tretirati kao podatke.<sup>[[2]](#references)</sup>
- Pass-ovi zasnovani na pattern-ima nisu opšti JavaScript decompiler. Očuvajte nerazrešene izraze i ručno proverite dvosmislene varijante dispatcher-a, umesto da forsirate rewrite.<sup>[[1]](#references)[[2]](#references)</sup>
- Nazivi funkcija dobijeni uz pomoć LLM-a predstavljaju savete za navigaciju, a ne dokaze. Ako ih koristite, obrađujte dependencies leaf-first, ali proverite svaku oznaku u odnosu na telo funkcije, argumente, stringove, data flow, API-je i sporedne efekte.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Breaking the Seal: Static Deobfuscation of JSCeal's Compiled V8 Bytecode](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
