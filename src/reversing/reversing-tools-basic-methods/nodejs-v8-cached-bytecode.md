# Statička deobfuskacija keširanog Node.js/V8 bytecode-a

{{#include ../../banners/hacktricks-training.md}}

V8 cached data je **reprezentacija sa gubicima, zavisna od verzije**, a ne JavaScript izvorni kod niti konvencionalni nativni izvršni fajl. Zato je koristan statički postupak sledeći: ukloniti spoljašnje pakovanje, disasemblirati keš odgovarajućom V8 verzijom, prevesti ga u model pseudokoda međureprezentacije i primeniti transformacije koje uvažavaju zavisnosti, bez izvršavanja uzorka. [View8](https://github.com/suleram/View8) i [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) primenjuju ovaj pristup na Node.js payload-e zaštićene pomoću `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Preuzimanje i disasembliranje keša

Najpre pregledajte preload/launcher, umesto da pretpostavite kako sve `.jsc` datoteke koriste isti wrapper. Na primer, launcher kao što je `node.exe -r preflight.js app.jsc` izvršava `preflight.js` pre glavnog modula; u analiziranoj porodici preload je uklanjao Brotli sloj. Nakon raspakivanja, utvrdite tačnu generaciju Node.js/V8 iz priloženog runtime-a. Keš koji je proizvela jedna V8 verzija može biti odbijen ili pogrešno dekodiran pomoću druge verzije, zato napravite ili nabavite `v8dasm` za tačan V8 tag i primenite neophodne View8 zakrpe i zakrpe za ispis stringova.<sup>[[1]](#references)[[2]](#references)</sup>

Postupak u toolkit-u koji ne izvršava uzorak je:<sup>[[2]](#references)</sup>

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

`--normalize` daje generisanim funkcijama stabilne identifikatore u različitim pokretanjima. Tekstualni izlaz služi za pregled; serijalizovani graf objekata omogućava nezavisnim prolazima da očuvaju odnose između funkcija, deklaratora, opsega i metapodataka. To **nije rekonstruisani niti izvršivi JavaScript**.<sup>[[1]](#references)[[2]](#references)</sup>

### Analizirajte keš bez izgradnje V8

Za sirovi keš ili keš umotan u Brotli, `jscd` može da prepozna zaglavlje i izlista konstante i funkcije bez učitavanja uzorka u Node.js. Najpre ga upotrebite da proverite da li njegove tabele verzija podržavaju datoteku i da odredite prioritet funkcija pre primene specijalizovanijih View8 prolaza za deobfuskaciju.<sup>[[4]](#references)</sup>

Hash verzije služi kao nagoveštaj za identifikaciju, a ne kao dokaz da samostalni disassembler koristi iste zastavice ili snapshot samo za čitanje kao program koji je kreirao datoteku.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` emituje listing kompatibilan sa View8, tako da View8 komanda iznad može da koristi taj izlaz umesto `v8dasm` kada je cache podržan. Pregledajte stringove zajedno sa stablom funkcija da biste pronašli pozive decoder-a i verovatne entry point-e; nemojte tretirati približan JavaScript izlaz alata `jscd` kao izvorni kod. Ako alat odbaci verziju ili ostavi placeholder-e za read-only heap, vratite se na odgovarajući V8 build ili navedite mapu imena iz istog build-a umesto da nagađate nazive svojstava.<sup>[[4]](#references)</sup>

Za cache unutar Electron aplikacije, prvo [izvucite ASAR i pregledajte main i preload entry point-e](../../desktop-application-security/electron-desktop-apps/). Electron i Node cache-ovi mogu da se razlikuju po snapshot i pointer-compression rasporedu čak i kada se njihove V8 verzije podudaraju.<sup>[[4]](#references)</sup>

### Čitanje View8 pseudokoda kao IR-a

Tipični nazivi su `func_<name>_0x<address>`, argumenti su `a0...aN`, virtuelni registri su `r0...rN`, a `ACCU` je V8 accumulator. `start` je root deklarator, dok `Scope[...]`, globals i dictionaries modeluju vrednosti koje su uhvaćene ili deljene među ugnježdenim funkcijama. Nemojte svaki izraz parsirati kao JavaScript sintaksu: na primer, `!r6 === "0"` u View8 predstavlja negaciju celog poređenja (`r6 !== "0"`), što je važno pri rekonstrukciji grana.<sup>[[1]](#references)[[3]](#references)</sup>

## Deobfuskacija svesna zavisnosti

Primenjujte transformacije redosledom koji otkriva ulaze potrebne za sledeći prolaz i ponavljajte propagaciju dok se izlaz ne stabilizuje. Praktičan redosled je:<sup>[[1]](#references)[[2]](#references)</sup>

1. Prođite kroz hijerarhiju deklaratora i propagirajte vrednosti iz globals, registara, dictionaries i referenci `Scope[...]`.
2. Rekonstruišite argumente string-decoder-a i zamenite šifrovane pozive običnim tekstom.
3. Spojite susedne string segmente; dobijeni nazivi svojstava i stringovi redosleda dispatcher-a otključavaju kasnije prolaze.
4. Uklonite flattening kontrolnog toka, inline-ujte call proxy-je i omotače atomskih operacija i razrešite reference na funkcije čuvane u dictionaries.
5. Ponovo propagirajte, jer svaki razrešeni string, ključ ili proxy može da otkrije još jedan nivo indirekcije.
6. Sažmite prepoznate one-shot initialization thunk-ove i uklonite neiskorišćene pomoćne funkcije tek nakon razrešavanja njihovih call site-ova.

### Rekonstrukcija pomerenih RC4 string nizova kao black box-a

Uobičajen raspored u `javascript-obfuscator` čuva Base64-kodirane RC4 segmente u jednom nizu. Decoder omotači prosleđuju numerički pomak i kratak ključ, ponekad obrnutim redosledom argumenata, a zatim dodaju ili oduzimaju konstante uhvaćene u closure scope-ovima. Kada je root decoder previše obfuskovan, empirijski utvrdite nepoznati pomak indeksa niza umesto da rekonstruišete celu funkciju.<sup>[[1]](#references)</sup>

Za niz od `N` segmenata i nekoliko poziva istog decoder-a:<sup>[[1]](#references)</sup>

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

Ne prihvataj pomeraj na osnovu jednog dešifrovanja koje daje štampive znakove: pogrešan ciphertext može slučajno izgledati štampivo. Koristi najmanje tri različita opažanja i prihvati samo jedinstveni pomeraj koji daje smislen tekst za sva opažanja. Zatim prođi kroz graf wrappera/deklaratora, sabirajući svako sabiranje ili oduzimanje i beležeći da li je numerički argument prvi. Keširaj ove metapodatke za svaki uzorak, zameni pozive dekodera, spoji susedne segmente otvorenog teksta i zasebno izvezi stringove za trijažu.<sup>[[1]](#references)[[2]](#references)</sup>

### Očuvanje semantike pri uklanjanju spljoštavanja

Kod petlji dispatcher-a kojima upravljaju stringovi kao što je `3|2|1|0|4`, dekodiraj string redosleda, mapiraj svako poređenje stanja na njegov blok, uzmi u obzir negiranu notaciju uslova u View8, a zatim iznesi blokove redosledom dispatcher-a. Ugnježdeni `continue` može predstavljati ranokosni skok nazad ka dispatcher-u, a ne običan prelaz na sledeći deo koda. Pri uklanjanju petlje izbriši taj `continue` i premesti naredbe koje su prvobitno sledile nakon nadređenog `if` u generisanu granu `else`; samo brisanje dispatcher-a menja ponašanje.<sup>[[1]](#references)</sup>

### Umetanje proxy-ja, operacija i lenjih thunk-ova

Normalizuj pomoćne funkcije za prosleđivanje, kao što je `return a0(a1, a2)`, pre zamene njihovih poziva direktnim pozivima. Slično postupi sa wrapperima za oduzimanje, deljenje, poređenje, testiranje članstva ili pozivanje. Pošto referenca pomoćne funkcije može biti smeštena iza dešifrovanog ključa rečnika ili vrednosti closure-a, propagiraj stringove i strukture pre i posle umetanja.<sup>[[1]](#references)</sup>

Prepoznaj i closure-e koji jednom pozivaju sačuvanu funkciju, brišu njenu referencu, keširaju rezultat i vraćaju taj keš pri narednim pozivima. Uklanjanje takvog thunk-a na mestu inicijalizacije otkriva osnovni dispatcher ili funkciju sa određenim mogućnostima, ali naznači da je prvobitno izvršavanje bilo **jednokratno i keširano**, umesto da modeluješ svaki poziv kao novo izvršavanje.<sup>[[1]](#references)</sup>

## Napomene o bezbednosti i validaciji

- Učitavanje Python `pickle` datoteka može da izvrši kod. Učitavaj samo `.pkl` datoteke koje je lokalno generisalo pouzdano pokretanje View8; nikada nemoj tretirati pickle datoteku koju je dostavio uzorak kao podatke.<sup>[[2]](#references)</sup>
- Nedostajuće telo funkcije ne dokazuje da izvorni kod nije sadržao tu funkciju: V8 može da serijalizuje lenju funkciju kao metapodatke dok se ona prvi put ne kompajlira pri pozivu. Tokom statičke trijaže ostavi takve funkcije označene kao nerazrešene.<sup>[[6]](#references)</sup>
- Prolazi zasnovani na obrascima nisu univerzalni JavaScript dekompajler. Sačuvaj nerazrešene izraze i ručno pregledaj nejasne varijante dispatcher-a umesto da namećeš transformaciju.<sup>[[1]](#references)[[2]](#references)</sup>
- Imena funkcija koja predloži LLM služe za navigaciju, a ne predstavljaju dokaz. Ako ih koristiš, obradi zavisnosti počevši od listova, ali proveri svaku oznaku prema telu funkcije, argumentima, stringovima, toku podataka, API-jima i sporednim efektima.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Razbijanje pečata: statička deobfuskacija kompajliranog V8 bajtkoda JSCeal-a](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [Zaglavlje V8 SerializedCodeData](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Keš koda Node.js vm.Script](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
