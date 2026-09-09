# Statyczna deobfuskacja Node.js/V8 Cached Bytecode

{{#include ../../banners/hacktricks-training.md}}

V8 cached data to **zależna od wersji, stratna reprezentacja**, a nie kod źródłowy JavaScript ani konwencjonalny natywny plik wykonywalny. Dlatego użyteczny workflow statyczny obejmuje: usunięcie zewnętrznego pakowania, zdisasemblowanie cache za pomocą pasującego buildu V8, podniesienie go do pośredniego modelu pseudokodu oraz zastosowanie transformacji uwzględniających zależności bez wykonywania próbki. [View8](https://github.com/suleram/View8) i [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implementują to podejście dla payloadów Node.js chronionych przez `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Pozyskanie i disasemblacja cache

Najpierw przeanalizuj preload/launcher zamiast zakładać, że każdy plik `.jsc` ma ten sam wrapper. Na przykład launcher taki jak `node.exe -r preflight.js app.jsc` wykonuje `preflight.js` przed głównym modułem; w analizowanej rodzinie preload usuwał warstwę Brotli. Po rozpakowaniu określ dokładną generację Node.js/V8 na podstawie dołączonego runtime. Cache utworzony przez jedną wersję V8 może zostać odrzucony lub nieprawidłowo zdekodowany przez inną, dlatego zbuduj lub uzyskaj `v8dasm` dla dokładnego tagu V8 i zastosuj wymagane patche View8 oraz drukowania stringów.<sup>[[1]](#references)[[2]](#references)</sup>

Workflow toolkitu bez wykonywania jest następujący:<sup>[[2]](#references)</sup>
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
`--normalize` zapewnia wygenerowanym funkcjom stabilne identyfikatory między uruchomieniami. Wynik tekstowy służy do inspekcji; serializowany graf obiektów pozwala niezależnym passom zachować relacje między funkcjami, deklaratorami, scope'ami i metadanymi. **Nie jest to odtworzony ani wykonywalny JavaScript**.<sup>[[1]](#references)[[2]](#references)</sup>

### Odczyt pseudokodu View8 jako IR

Typowe nazwy to `func_<name>_0x<address>`, argumenty to `a0...aN`, rejestry wirtualne to `r0...rN`, a `ACCU` to accumulator V8. `start` jest głównym deklaratorem, natomiast `Scope[...]`, zmienne globalne i słowniki modelują wartości przechwytywane lub współdzielone przez funkcje zagnieżdżone. Nie należy analizować każdego wyrażenia jako składni JavaScript: na przykład `!r6 === "0"` w View8 oznacza negację całego porównania (`r6 !== "0"`), co ma znaczenie przy odtwarzaniu gałęzi.<sup>[[1]](#references)[[3]](#references)</sup>

## Deobfuskacja uwzględniająca zależności

Stosuj transformacje w kolejności, która ujawnia dane wejściowe wymagane przez kolejny pass, i powtarzaj propagację do momentu ustabilizowania wyniku. Praktyczna kolejność to:<sup>[[1]](#references)[[2]](#references)</sup>

1. Przejdź przez hierarchię deklaratorów i propaguj wartości z globali, rejestrów, słowników oraz odwołań `Scope[...]`.
2. Odzyskaj argumenty dekodera stringów i zastąp zaszyfrowane wywołania plaintextem.
3. Połącz sąsiednie fragmenty stringów; wynikowe nazwy właściwości i stringi określające kolejność dispatchera odblokują kolejne passy.
4. Usuń spłaszczanie control flow, wstaw proxy wywołań i wrappery operacji atomowych oraz rozwiąż odwołania do funkcji przechowywane w słownikach.
5. Ponownie wykonaj propagację, ponieważ każdy rozwiązany string, klucz lub proxy może ujawnić kolejną warstwę indirection.
6. Zwiń rozpoznane jednorazowe thunki inicjalizacyjne i usuń martwe helpery dopiero po rozwiązaniu miejsc ich wywołań.

### Odzyskiwanie przesuniętych tablic stringów RC4 jako czarnej skrzynki

Typowy układ `javascript-obfuscator` przechowuje zakodowane w Base64 fragmenty RC4 w jednej tablicy. Wrappery dekodera przekazują numeryczny offset i krótki klucz, czasami w odwrotnej kolejności argumentów, a następnie dodają lub odejmują stałe przechwycone w scope'ach closure. Gdy główny dekoder jest zbyt mocno obfuskowany, odzyskaj empirycznie nieznane przesunięcie indeksu tablicy zamiast odtwarzać całą funkcję.<sup>[[1]](#references)</sup>

Dla tablicy zawierającej `N` fragmentów i kilku wywołań tego samego dekodera:<sup>[[1]](#references)</sup>
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
Nie akceptuj przesunięcia na podstawie pojedynczego odszyfrowania dającego tekst drukowalny: nieprawidłowy ciphertext może przypadkowo wyglądać na drukowalny. Użyj co najmniej trzech odrębnych obserwacji i zaakceptuj wyłącznie unikalne przesunięcie, które daje wiarygodny tekst dla wszystkich z nich. Następnie przejdź przez graf wrapperów/deklaratorów, sumując każde dodawanie lub odejmowanie i zapisując, czy argument numeryczny występuje jako pierwszy. Cache’uj te metadane dla każdej próbki, zastępuj wywołania decoderów, łącz sąsiadujące fragmenty plaintextu i eksportuj stringi oddzielnie do triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Zachowanie semantyki podczas unflatteningu

W przypadku pętli dispatcherów sterowanych przez stringi, takie jak `3|2|1|0|4`, zdekoduj string określający kolejność, przypisz każde porównanie stanu do jego bloku, uwzględnij notację negowanego warunku View8, a następnie emituj bloki w kolejności dispatchera. Zagnieżdżone `continue` może oznaczać wcześniejszy skok z powrotem do dispatchera, a nie zwykłe przejście dalej. Podczas usuwania pętli usuń to `continue` i przenieś instrukcje, które pierwotnie znajdowały się za otaczającym je `if`, do wygenerowanej gałęzi `else`; samo usunięcie dispatchera zmienia działanie programu.<sup>[[1]](#references)</sup>

### Inlining proxy, operacji i lazy thunks

Przed zastąpieniem ich miejsc wywołań bezpośrednimi wywołaniami normalizuj helpery przekazujące, takie jak `return a0(a1, a2)`. Podobnie traktuj wrappery odejmowania, dzielenia, porównania, testów członkostwa lub wywołania. Ponieważ referencja do helpera może być przechowywana za odszyfrowanym kluczem dictionary albo wartością closure, wykonuj propagację stringów i struktur przed inliningiem oraz po nim.<sup>[[1]](#references)</sup>

Rozpoznawaj również closures, które jednokrotnie wywołują przechowywaną funkcję, czyszczą jej referencję, cache’ują wynik i zwracają ten cache przy kolejnych wywołaniach. Złożenie takiego thunka w miejscu inicjalizacji ujawnia bazowy dispatcher lub funkcję capability, ale zaznacz, że pierwotne wykonanie było **jednorazowe i cache’owane**, zamiast modelować każde wywołanie jako nowe wywołanie.<sup>[[1]](#references)</sup>

## Uwagi dotyczące bezpieczeństwa i walidacji

- Ładowanie za pomocą Pythona `pickle` może wykonywać kod. Ładuj wyłącznie pliki `.pkl` wygenerowane lokalnie przez zaufane uruchomienie View8; nigdy nie traktuj pickle dostarczonego wraz z próbką jako danych.<sup>[[2]](#references)</sup>
- Przebiegi oparte na patternach nie są ogólnym decompilerem JavaScript. Zachowuj nierozwiązane wyrażenia i ręcznie sprawdzaj niejednoznaczne warianty dispatcherów, zamiast wymuszać rewrite.<sup>[[1]](#references)[[2]](#references)</sup>
- Nazwy funkcji sugerowane przez LLM są wskazówkami nawigacyjnymi, a nie dowodami. Jeśli ich używasz, przetwarzaj dependencies od liści w górę, ale weryfikuj każdą etykietę na podstawie body, argumentów, stringów, data flow, API i efektów ubocznych.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Breaking the Seal: Static Deobfuscation of JSCeal's Compiled V8 Bytecode](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
