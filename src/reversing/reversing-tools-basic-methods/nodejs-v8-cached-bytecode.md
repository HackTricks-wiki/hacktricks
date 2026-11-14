# Statyczna deobfuskacja buforowanego bytecode Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Dane cache V8 to **zależna od wersji, stratna reprezentacja**, a nie kod źródłowy JavaScript ani konwencjonalny natywny plik wykonywalny. Przydatny statyczny workflow obejmuje więc usunięcie zewnętrznego pakowania, deasemblację cache przy użyciu zgodnej kompilacji V8, przekształcenie go do pośredniego modelu pseudokodu oraz zastosowanie transformacji uwzględniających zależności — bez uruchamiania próbki. [View8](https://github.com/suleram/View8) i [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implementują to podejście dla payloadów Node.js zabezpieczonych przez `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Pozyskiwanie i deasemblacja cache

Najpierw sprawdź preload/launcher, zamiast zakładać, że każdy plik `.jsc` ma ten sam wrapper. Na przykład launcher taki jak `node.exe -r preflight.js app.jsc` uruchamia `preflight.js` przed głównym modułem; w analizowanej rodzinie preload usuwał warstwę Brotli. Po rozpakowaniu ustal dokładną generację Node.js/V8 na podstawie dołączonego runtime'u. Cache utworzony przez jedną wersję V8 może zostać odrzucony lub nieprawidłowo zdekodowany przez inną, dlatego zbuduj lub zdobądź `v8dasm` dla dokładnie tego tagu V8 i zastosuj wymagane poprawki View8 oraz drukowania stringów.<sup>[[1]](#references)[[2]](#references)</sup>

Workflow zestawu narzędzi, który nie uruchamia próbki, wygląda następująco:<sup>[[2]](#references)</sup>

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

`--normalize` nadaje generowanym funkcjom stabilne identyfikatory między uruchomieniami. Wynik tekstowy służy do inspekcji; serializowany graf obiektów pozwala niezależnym przebiegom zachować powiązania między funkcją, deklarującym ją elementem, zakresem i metadanymi. To **nie jest odtworzony ani wykonywalny kod JavaScript**.<sup>[[1]](#references)[[2]](#references)</sup>

### Wstępna analiza cache bez kompilowania V8

W przypadku surowego cache lub cache opakowanego w Brotli `jscd` może rozpoznać nagłówek i wyliczyć stałe oraz funkcje bez ładowania próbki w Node.js. Użyj go najpierw, aby sprawdzić, czy jego tabele wersji obsługują plik, i ustalić priorytet funkcji przed zastosowaniem bardziej wyspecjalizowanych przebiegów deobfuskacji View8.<sup>[[4]](#references)</sup>

Hash wersji jest wskazówką identyfikacyjną, a nie dowodem, że samodzielny disassembler używa tych samych flag lub migawki tylko do odczytu co program, który ją utworzył.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` emituje listing zgodny z View8, więc powyższe polecenie View8 może użyć jego wyniku zamiast `v8dasm`, jeśli cache jest obsługiwany. Analizuj ciągi znaków wraz z drzewem funkcji, aby znaleźć wywołania decoderów i prawdopodobne punkty wejścia; nie traktuj przybliżonego kodu JavaScript generowanego przez `jscd` jako oryginalnego źródła. Jeśli narzędzie odrzuci wersję lub pozostawi placeholdery read-only heap, wróć do zgodnego builda V8 albo dostarcz mapę nazw z tego samego builda, zamiast zgadywać nazwy właściwości.<sup>[[4]](#references)</sup>

W przypadku cache’a wewnątrz aplikacji Electron najpierw [wyodrębnij ASAR i sprawdź punkty wejścia main oraz preload](../../desktop-application-security/electron-desktop-apps/). Układy snapshotu i kompresji wskaźników w cache’ach Electron i Node mogą się różnić, nawet gdy ich ciągi wersji V8 są takie same.<sup>[[4]](#references)</sup>

### Interpretuj pseudokod View8 jako IR

Typowe nazwy to `func_<name>_0x<address>`, argumenty mają postać `a0...aN`, rejestry wirtualne — `r0...rN`, a `ACCU` to akumulator V8. `start` jest deklaratorem głównym, natomiast `Scope[...]`, zmienne globalne i słowniki modelują wartości przechwycone przez funkcje zagnieżdżone lub współdzielone między nimi. Nie interpretuj każdego wyrażenia jako składni JavaScript: na przykład `!r6 === "0"` w View8 oznacza negację całego porównania (`r6 !== "0"`), co ma znaczenie przy odtwarzaniu rozgałęzień.<sup>[[1]](#references)[[3]](#references)</sup>

## Deobfuskacja uwzględniająca zależności

Stosuj transformacje w kolejności, która ujawnia dane wejściowe potrzebne w kolejnym przebiegu, i powtarzaj propagację, aż wynik przestanie się zmieniać. Praktyczna kolejność:<sup>[[1]](#references)[[2]](#references)</sup>

1. Przejdź hierarchię deklaratorów i propaguj wartości ze zmiennych globalnych, rejestrów, słowników oraz odwołań `Scope[...]`.
2. Odtwórz argumenty string-decoderów i zastąp zaszyfrowane wywołania tekstem jawnym.
3. Połącz sąsiadujące fragmenty ciągów znaków; uzyskane nazwy właściwości i ciągi określające kolejność dispatcherów odblokowują kolejne przebiegi.
4. Usuń spłaszczanie przepływu sterowania, wstawiaj bezpośrednio proxy wywołań i wrappery operacji atomowych oraz rozwiązuj odwołania do funkcji przechowywane w słownikach.
5. Ponownie propaguj wartości, ponieważ każdy rozwiązany ciąg znaków, klucz lub proxy może ujawnić kolejną warstwę pośrednictwa.
6. Redukuj rozpoznane, jednorazowe thunki inicjalizacyjne i usuwaj nieużywane helpery dopiero po rozwiązaniu miejsc ich wywołań.

### Odtwórz przesunięte tablice ciągów znaków RC4 jako black box

Typowy układ `javascript-obfuscator` przechowuje zakodowane w Base64 fragmenty RC4 w jednej tablicy. Wrappery decoderów przekazują przesunięcie numeryczne i krótki klucz, czasem w odwrotnej kolejności argumentów, a następnie dodają lub odejmują stałe przechwycone w zakresach domknięcia. Gdy główny decoder jest zbyt mocno zaciemniony, empirycznie odtwórz nieznane przesunięcie indeksów tablicy, zamiast rekonstruować całą funkcję.<sup>[[1]](#references)</sup>

Dla tablicy zawierającej `N` fragmentów i kilku wywołań tego samego decodera:<sup>[[1]](#references)</sup>

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

Nie akceptuj przesunięcia na podstawie pojedynczego odszyfrowania dającego znaki drukowalne: błędny szyfrogram może przypadkowo wyglądać na tekst. Wykorzystaj co najmniej trzy różne obserwacje i zaakceptuj tylko unikalne przesunięcie, które daje wiarygodny tekst we wszystkich przypadkach. Następnie przejdź przez graf wrapperów/deklaratorów, sumując każde dodawanie lub odejmowanie i zapisując, czy argument liczbowy występuje jako pierwszy. Buforuj te metadane dla każdej próbki, zastąp wywołania dekoderów, łącz sąsiadujące fragmenty tekstu jawnego i eksportuj ciągi znaków osobno na potrzeby triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Zachowaj semantykę podczas odtwarzania struktury

W przypadku pętli dyspozytora sterowanych ciągami takimi jak `3|2|1|0|4` zdekoduj ciąg określający kolejność, przypisz każde porównanie stanu do bloku, uwzględnij zapis warunków z negacją stosowany przez View8, a następnie emituj bloki w kolejności dyspozytora. Zagnieżdżone `continue` może oznaczać wcześniejszy skok z powrotem do dyspozytora, a nie zwykłe przejście do kolejnej instrukcji. Przy usuwaniu pętli usuń to `continue` i przenieś instrukcje, które pierwotnie następowały po obejmującym je `if`, do wygenerowanej gałęzi `else`; samo usunięcie dyspozytora zmienia zachowanie.<sup>[[1]](#references)</sup>

### Wstawianie proxy, operacji i leniwych thunków

Przed zastąpieniem miejsc wywołania bezpośrednimi wywołaniami normalizuj funkcje przekazujące wywołanie, takie jak `return a0(a1, a2)`. Podobnie potraktuj wrappery odejmowania, dzielenia, porównywania, testów przynależności lub wywołań. Ponieważ odwołanie do funkcji pomocniczej może być przechowywane za odszyfrowanym kluczem słownika lub wartością domknięcia, propaguj ciągi znaków i strukturę przed wstawianiem funkcji i po nim.<sup>[[1]](#references)</sup>

Rozpoznawaj też domknięcia, które jednokrotnie wywołują przechowywaną funkcję, czyszczą jej odwołanie, buforują wynik i zwracają ten bufor przy kolejnych wywołaniach. Zredukowanie takiego thunk przy inicjalizacji ujawnia podstawowy dyspozytor lub funkcję udostępniającą możliwości, ale zaznacz, że pierwotne wykonanie było **jednorazowe i buforowane**, zamiast modelować każde wywołanie jako nowe wykonanie.<sup>[[1]](#references)</sup>

## Uwagi dotyczące bezpieczeństwa i walidacji

- Wczytywanie Python `pickle` może wykonywać kod. Wczytuj wyłącznie pliki `.pkl` wygenerowane lokalnie przez zaufane uruchomienie View8; nigdy nie traktuj pickle dostarczonego z próbką jako danych.<sup>[[2]](#references)</sup>
- Brak treści funkcji nie dowodzi, że funkcja nie występowała w kodzie źródłowym: V8 może serializować leniwą funkcję jako metadane, dopóki nie zostanie skompilowana przy pierwszym wywołaniu. Podczas statycznego triage oznaczaj takie funkcje jako nierozstrzygnięte.<sup>[[6]](#references)</sup>
- Przebiegi oparte na wzorcach nie są uniwersalnym dekompilatorem JavaScript. Zachowuj nierozstrzygnięte wyrażenia i ręcznie sprawdzaj niejednoznaczne warianty dyspozytora, zamiast wymuszać przepisanie.<sup>[[1]](#references)[[2]](#references)</sup>
- Nazwy funkcji sugerowane przez LLM to wskazówki ułatwiające nawigację, a nie dowody. Jeśli z nich korzystasz, przetwarzaj zależności od liści, ale weryfikuj każdą etykietę na podstawie treści funkcji, argumentów, ciągów znaków, przepływu danych, API i efektów ubocznych.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Złamać pieczęć: statyczna deobfuskacja skompilowanego bytecode V8 w JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [Nagłówek V8 SerializedCodeData](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Cache kodu Node.js vm.Script](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
