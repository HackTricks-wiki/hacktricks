# Statička deobfuskacija Node.js/V8 keširanog bajtkoda

{{#include ../../banners/hacktricks-training.md}}

V8 keširani podaci su **reprezentacija zavisna od verzije, sa gubitkom informacija**, a ne JavaScript izvorni kod niti uobičajena nativna izvršna datoteka. Zato koristan statički postupak obuhvata uklanjanje spoljnog pakovanja, disasembliranje keša pomoću odgovarajuće verzije V8, prevođenje u model međukoda u obliku pseudokoda i primenu transformacija koje uzimaju u obzir zavisnosti — bez izvršavanja uzorka. [View8](https://github.com/suleram/View8) i [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) primenjuju ovaj pristup na Node.js payload-e zaštićene pomoću `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Preuzimanje i disasembliranje keša

Najpre pregledajte preload/launcher umesto da pretpostavite kako svaka `.jsc` datoteka ima isti omotač. Na primer, launcher kao što je `node.exe -r preflight.js app.jsc` izvršava `preflight.js` pre glavnog modula; u analiziranoj porodici preload je uklanjao Brotli sloj. Nakon raspakivanja, utvrdite tačnu generaciju Node.js/V8 okruženja iz priloženog runtime-a. Keš kreiran jednom verzijom V8 može biti odbijen ili pogrešno dekodiran drugom verzijom, zato napravite ili pribavite `v8dasm` za tu tačnu V8 oznaku i primenite neophodne zakrpe za View8 i ispis stringova.<sup>[[1]](#references)[[2]](#references)</sup>

Radni postupak alata bez izvršavanja je:<sup>[[2]](#references)</sup>

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

`--normalize` daje generisanim funkcijama stabilne identifikatore između pokretanja. Tekstualni izlaz služi za pregled; serijalizovani graf objekata omogućava nezavisnim prolazima da očuvaju odnose između funkcija, deklaratora, opsega i metapodataka. To **nije rekonstruisan JavaScript koji može da se izvršava**.<sup>[[1]](#references)[[2]](#references)</sup>

### Analiza keša bez izgradnje V8

Za sirov keš ili keš obavijen Brotli kompresijom, `jscd` može da identifikuje zaglavlje i izlista konstante i funkcije bez učitavanja uzorka u Node.js. Najpre ga upotrebite da proverite da li tabele verzija podržavaju datoteku i da odredite prioritet funkcija pre primene specijalizovanijih View8 prolaza za deobfuskaciju.<sup>[[4]](#references)</sup>

Hash verzije je smernica za identifikaciju, a ne dokaz da samostalni disassembler koristi iste zastavice ili snapshot samo za čitanje kao program koji je kreirao datoteku.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` emituje listing kompatibilan sa View8, pa gornja View8 komanda može da koristi taj izlaz umesto `v8dasm` kada je cache podržan. Pregledajte stringove zajedno sa stablom funkcija da biste pronašli pozive decoder-a i verovatne ulazne tačke; nemojte tretirati približni JavaScript izlaz alata `jscd` kao originalni izvorni kod. Ako alat odbije verziju ili ostavi placeholders iz read-only heap-a, vratite se na odgovarajuću V8 verziju ili obezbedite mapu imena iz iste verzije umesto da nagađate nazive svojstava.<sup>[[4]](#references)</sup>

Za cache unutar Electron aplikacije, prvo [izdvojite ASAR i pregledajte njene main i preload ulazne tačke](../../network-services-pentesting/pentesting-web/electron-desktop-apps/). Electron i Node cache mogu da se razlikuju po rasporedu snapshot-a i pointer compression-a čak i kada se njihovi V8 version stringovi podudaraju.<sup>[[4]](#references)</sup>

### Čitanje View8 pseudokoda kao IR-a

Uobičajeni nazivi su `func_<name>_0x<address>`, argumenti su `a0...aN`, virtuelni registri su `r0...rN`, a `ACCU` je V8 accumulator. `start` je korenski deklarator, dok `Scope[...]`, globalne promenljive i rečnici predstavljaju vrednosti koje su uhvaćene ili deljene među ugnježdenim funkcijama. Nemojte parsirati svaki izraz kao JavaScript sintaksu: na primer, `!r6 === "0"` u View8 predstavlja negaciju čitavog poređenja (`r6 !== "0"`), što je važno prilikom rekonstrukcije grananja.<sup>[[1]](#references)[[3]](#references)</sup>

## Deobfuskacija koja uzima u obzir zavisnosti

Primenjujte transformacije redosledom koji otkriva ulaze potrebne za sledeći prolaz i ponavljajte propagaciju dok se izlaz ne stabilizuje. Praktičan redosled je:<sup>[[1]](#references)[[2]](#references)</sup>

1. Prođite kroz hijerarhiju deklaratora i propagirajte vrednosti iz globalnih promenljivih, registara, rečnika i referenci `Scope[...]`.
2. Rekonstruišite argumente string-decoder-a i zamenite šifrovane pozive običnim tekstom.
3. Spojite susedne delove stringova; tako dobijeni nazivi svojstava i stringovi redosleda dispatcher-a otključavaju naredne prolaze.
4. Uklonite spljoštavanje toka kontrole, inline-ujte call proxy-je i omotače atomskih operacija i razrešite reference na funkcije smeštene u rečnicima.
5. Ponovite propagaciju jer svaki razrešeni string, ključ ili proxy može da otkrije novi nivo indirekcije.
6. Sažmite prepoznate one-shot initialization thunk-ove i uklonite neaktivne pomoćne funkcije tek nakon što razrešite mesta na kojima se pozivaju.

### Rekonstrukcija pomerenih RC4 nizova stringova kao crne kutije

Čest raspored u `javascript-obfuscator`-u čuva Base64-kodirane RC4 delove u jednom nizu. Decoder wrapper-i prosleđuju numerički pomeraj i kratak ključ, ponekad obrnutim redosledom argumenata, a zatim dodaju ili oduzimaju konstante uhvaćene u closure scope-ovima. Kada je root decoder previše zamaskiran, empirijski utvrdite nepoznati pomeraj indeksa niza umesto da rekonstruišete celu funkciju.<sup>[[1]](#references)</sup>

Za niz od `N` delova i nekoliko poziva istog decoder-a:<sup>[[1]](#references)</sup>

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

Ne prihvataj pomeraj na osnovu samo jednog dešifrovanja koje daje štampive znakove: pogrešan ciphertext može slučajno da izgleda štampivo. Koristi najmanje tri različita zapažanja i prihvati samo jedinstveni pomeraj koji daje smislen tekst za sva zapažanja. Zatim prođi kroz graf wrapper/declarer, saberi svako sabiranje ili oduzimanje i zabeleži da li je numerički argument prvi. Keširaj ove metapodatke za svaki uzorak, zameni pozive decoder-a, konkateniraj susedne plaintext segmente i zasebno izvezi stringove za triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Očuvanje semantike pri uklanjanju flattening-a

Za dispatcher petlje koje pokreću stringovi kao što je `3|2|1|0|4`, dekodiraj string redosleda, poveži svako poređenje stanja sa odgovarajućim blokom, uzmi u obzir View8-ovu notaciju negiranih uslova, pa zatim emituj blokove redosledom dispatcher-a. Ugnježdeni `continue` može da predstavlja rani skok nazad na dispatcher, a ne običan fall-through. Pri uklanjanju petlje izbriši taj `continue` i premesti naredbe koje su prvobitno sledile iza njegovog obuhvatnog `if` u generisanu `else` granu; samo brisanje dispatcher-a menja ponašanje.<sup>[[1]](#references)</sup>

### Inline proxy-je, operacije i lazy thunk-ove

Normalizuj pomoćne funkcije za prosleđivanje, kao što je `return a0(a1, a2)`, pre nego što njihove pozive zameniš direktnim pozivima. Slično tretiraj wrapper-e za oduzimanje, deljenje, poređenje, testiranje pripadnosti ili pozivanje. Pošto i sama referenca na pomoćnu funkciju može da bude sačuvana iza dešifrovanog ključa rečnika ili vrednosti closure-a, izvrši propagaciju stringova i strukture pre i posle inline-ovanja.<sup>[[1]](#references)</sup>

Prepoznaj i closure-e koji jednom pozovu sačuvanu funkciju, obrišu njenu referencu, keširaju rezultat i pri narednim pozivima vraćaju taj keš. Svođenje takvog thunk-a na poziv na mestu inicijalizacije otkriva osnovni dispatcher ili capability funkciju, ali naznači da je prvobitno izvršavanje bilo **jednokratno i keširano**, umesto da modeliraš svaki poziv kao novo pozivanje.<sup>[[1]](#references)</sup>

## Napomene o bezbednosti i validaciji

- Učitavanje Python `pickle` fajlova može da izvrši kod. Učitavaj samo `.pkl` fajlove koje je lokalno generisalo pouzdano View8 pokretanje; nikada ne tretiraj pickle koji je dostavio uzorak kao podatke.<sup>[[2]](#references)</sup>
- Nedostajuće telo funkcije ne dokazuje da izvorni kod nije sadržao tu funkciju: V8 može da serijalizuje lazy funkciju samo kao metapodatke dok se ne kompajlira pri prvom pozivu. Tokom statičkog triage-a takve funkcije označi kao nerazrešene.<sup>[[6]](#references)</sup>
- Prolazi zasnovani na obrascima nisu opšti JavaScript decompiler. Sačuvaj nerazrešene izraze i ručno proveri dvosmislene varijante dispatcher-a umesto da na silu namećeš transformaciju.<sup>[[1]](#references)[[2]](#references)</sup>
- Imena funkcija predložena uz pomoć LLM-a služe kao navigacioni nagoveštaji, a ne kao dokaz. Ako ih koristiš, obradi zavisnosti od listova ka korenu, ali proveri svaku oznaku prema telu funkcije, argumentima, stringovima, toku podataka, API-jima i sporednim efektima.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Razbijanje pečata: statička deobfuskacija kompajliranog V8 bytecode-a JSCeal-a](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [Zaglavlje V8 SerializedCodeData](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Keš koda Node.js vm.Script](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
