# Statyczna deobfuskacja buforowanego bytecode’u Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Buforowane dane V8 to **zależna od wersji, stratna reprezentacja**, a nie kod źródłowy JavaScript ani konwencjonalny natywny plik wykonywalny. Przydatny statyczny workflow obejmuje więc usunięcie zewnętrznego pakowania, zdisasemblowanie cache’a przy użyciu zgodnej kompilacji V8, podniesienie go do pośredniego modelu pseudokodu oraz zastosowanie transformacji uwzględniających zależności bez uruchamiania próbki. [View8](https://github.com/suleram/View8) i [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implementują to podejście dla payloadów Node.js chronionych przez `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Pozyskanie i disasemblacja cache’a

Najpierw sprawdź preload/launcher, zamiast zakładać, że każdy plik `.jsc` ma ten sam wrapper. Na przykład launcher taki jak `node.exe -r preflight.js app.jsc` wykonuje `preflight.js` przed głównym modułem; w analizowanej rodzinie preload usuwał warstwę Brotli. Po rozpakowaniu ustal dokładną generację Node.js/V8 na podstawie dołączonego środowiska uruchomieniowego. Cache utworzony przez jedną wersję V8 może zostać odrzucony lub nieprawidłowo zdekodowany przez inną, dlatego skompiluj lub pobierz `v8dasm` dla dokładnie tej wersji V8 i zastosuj wymagane poprawki View8 oraz wypisywania ciągów znaków.<sup>[[1]](#references)[[2]](#references)</sup>

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

`--normalize` nadaje generowanym funkcjom stabilne identyfikatory między uruchomieniami. Tekstowy wynik służy do inspekcji; serializowany graf obiektów pozwala niezależnym passom zachować powiązania między funkcjami, deklaratorami, zakresami i metadanymi. To **nie jest odtworzony ani wykonywalny JavaScript**.<sup>[[1]](#references)[[2]](#references)</sup>

### Wstępna analiza cache bez kompilowania V8

W przypadku surowego cache lub cache opakowanego w Brotli `jscd` może rozpoznać nagłówek i wyliczyć stałe oraz funkcje bez ładowania próbki w Node.js. Użyj go najpierw, aby sprawdzić, czy jego tabele wersji obsługują plik, i ustalić priorytety funkcji przed użyciem bardziej wyspecjalizowanych passów deobfuskacji View8.<sup>[[4]](#references)</sup>

Hash wersji jest wskazówką identyfikacyjną, a nie dowodem na to, że samodzielny disassembler używa tych samych flag lub migawki tylko do odczytu co program, który utworzył plik.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` emituje listing zgodny z View8, więc powyższe polecenie View8 może użyć tego wyjścia zamiast `v8dasm`, jeśli obsługiwana jest dana pamięć podręczna. Analizuj ciągi znaków razem z drzewem funkcji, aby znaleźć wywołania dekoderów i prawdopodobne punkty wejścia; nie traktuj przybliżonego kodu JavaScript generowanego przez `jscd` jako oryginalnego kodu źródłowego. Jeśli narzędzie odrzuca wersję lub pozostawia symbole zastępcze dla sterty tylko do odczytu, wróć do zgodnej kompilacji V8 albo podaj mapę nazw z tej samej kompilacji, zamiast zgadywać nazwy właściwości.<sup>[[4]](#references)</sup>

W przypadku pamięci podręcznej w aplikacji Electron najpierw [wyodrębnij ASAR i sprawdź punkty wejścia main oraz preload](../../network-services-pentesting/pentesting-web/electron-desktop-apps/). Układy snapshotów i kompresji wskaźników w pamięciach podręcznych Electron i Node mogą się różnić, nawet jeśli ich ciągi wersji V8 są takie same.<sup>[[4]](#references)</sup>

### Odczyt pseudokodu View8 jako IR

Typowe nazwy to `func_<name>_0x<address>`, argumenty mają postać `a0...aN`, rejestry wirtualne — `r0...rN`, a `ACCU` to akumulator V8. `start` jest głównym deklaratorem, natomiast `Scope[...]`, zmienne globalne i słowniki odwzorowują wartości przechwycone przez funkcje zagnieżdżone lub współdzielone między nimi. Nie parsuj każdego wyrażenia jako składni JavaScript: na przykład `!r6 === "0"` w View8 oznacza negację całego porównania (`r6 !== "0"`), co ma znaczenie przy odtwarzaniu gałęzi.<sup>[[1]](#references)[[3]](#references)</sup>

## Usuwanie obfuskacji z uwzględnieniem zależności

Stosuj transformacje w kolejności, która ujawnia dane wejściowe wymagane przez kolejny etap, i powtarzaj propagację aż do ustabilizowania wyniku. Praktyczna kolejność:<sup>[[1]](#references)[[2]](#references)</sup>

1. Przejdź hierarchię deklaratorów i propaguj wartości ze zmiennych globalnych, rejestrów, słowników oraz odwołań `Scope[...]`.
2. Odtwórz argumenty dekoderów ciągów znaków i zastąp zaszyfrowane wywołania tekstem jawnym.
3. Połącz sąsiadujące fragmenty ciągów znaków; powstałe nazwy właściwości i ciągi określające kolejność dyspozytora odblokowują kolejne etapy.
4. Spłaszcz przepływ sterowania, wstawiaj proxy wywołań i opakowania operacji atomowych oraz rozwiązuj odwołania do funkcji przechowywane w słownikach.
5. Ponownie propaguj wartości, ponieważ każdy rozwiązany ciąg znaków, klucz lub proxy może ujawnić kolejną warstwę pośrednictwa.
6. Usuń rozpoznane funkcje inicjalizacyjne jednorazowego użytku i nieużywane funkcje pomocnicze dopiero po rozwiązaniu miejsc ich wywołań.

### Odtwarzanie tablic ciągów znaków RC4 z przesunięciem metodą czarnoskrzynkową

Typowy układ `javascript-obfuscator` przechowuje w jednej tablicy fragmenty RC4 zakodowane w Base64. Opakowania dekodera podają przesunięcie numeryczne i krótki klucz, czasami w odwrotnej kolejności argumentów, a następnie dodają lub odejmują stałe przechwycone w zakresach domknięcia. Gdy główny dekoder jest zbyt mocno obfuskowany, odtwórz nieznane przesunięcie indeksu tablicy empirycznie, zamiast rekonstruować całą funkcję.<sup>[[1]](#references)</sup>

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

Nie akceptuj przesunięcia na podstawie pojedynczego czytelnego wyniku deszyfrowania: błędny szyfrogram może przypadkiem dać czytelny tekst. Użyj co najmniej trzech różnych obserwacji i zaakceptuj tylko unikatowe przesunięcie, które daje wiarygodny tekst we wszystkich przypadkach. Następnie przejdź przez graf wrapperów/deklaratorów, sumując każde dodawanie lub odejmowanie i odnotowując, czy argument numeryczny występuje jako pierwszy. Buforuj te metadane dla każdej próbki, zastąp wywołania dekodera, połącz sąsiadujące fragmenty plaintextu i wyeksportuj osobno ciągi znaków do triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Zachowanie semantyki podczas usuwania spłaszczonej struktury sterowania

W przypadku pętli dispatcherów sterowanych ciągami takimi jak `3|2|1|0|4` zdekoduj ciąg określający kolejność, przypisz każde porównanie stanu do bloku, uwzględnij negowaną notację warunków View8, a następnie wyemituj bloki w kolejności dispatchera. Zagnieżdżone `continue` może oznaczać wczesny skok z powrotem do dispatchera, a nie zwykłe przejście do kolejnej instrukcji. Usuwając pętlę, usuń to `continue` i przenieś instrukcje, które pierwotnie znajdowały się za obejmującym je `if`, do wygenerowanej gałęzi `else`; samo usunięcie dispatchera zmienia zachowanie.<sup>[[1]](#references)</sup>

### Inlining proxy, operacji i leniwych thunków

Przed zastąpieniem miejsc wywołań bezpośrednimi wywołaniami ujednolić pomocnicze funkcje przekazujące wywołanie, takie jak `return a0(a1, a2)`. Podobnie traktuj wrappery odejmowania, dzielenia, porównywania, testów przynależności lub wywołań. Ponieważ odwołanie do pomocnika może być przechowywane za odszyfrowanym kluczem słownika lub wartością closure, wykonuj propagację ciągów znaków i struktury przed inliningiem i po nim.<sup>[[1]](#references)</sup>

Rozpoznawaj również closure, które jednokrotnie wywołują przechowywaną funkcję, usuwają do niej odwołanie, buforują wynik i zwracają ten bufor przy kolejnych wywołaniach. Zredukowanie takiego thunka w miejscu inicjalizacji ujawnia bazowy dispatcher lub funkcję z capability, ale odnotuj, że pierwotne wykonanie było **jednorazowe i buforowane**, zamiast modelować każde wywołanie jako nowe wywołanie.<sup>[[1]](#references)</sup>

## Uwagi dotyczące bezpieczeństwa i walidacji

- Wczytywanie Python `pickle` może wykonywać kod. Wczytuj tylko pliki `.pkl` wygenerowane lokalnie przez zaufane uruchomienie View8; nigdy nie traktuj pickle dostarczonego przez próbkę jako danych.<sup>[[2]](#references)</sup>
- Brak treści funkcji nie dowodzi, że źródło jej nie zawierało: V8 może serializować funkcję leniwą jako metadane, dopóki nie zostanie skompilowana przy pierwszym wywołaniu. Podczas statycznego triage oznaczaj takie funkcje jako nierozstrzygnięte.<sup>[[6]](#references)</sup>
- Przebiegi oparte na wzorcach nie są uniwersalnym dekompilatorem JavaScript. Zachowuj nierozstrzygnięte wyrażenia i ręcznie sprawdzaj niejednoznaczne warianty dispatcherów, zamiast wymuszać przepisanie.<sup>[[1]](#references)[[2]](#references)</sup>
- Nazwy funkcji sugerowane przez LLM to wskazówki ułatwiające nawigację, a nie dowody. Jeśli z nich korzystasz, przetwarzaj zależności od liści w górę, ale weryfikuj każdą etykietę na podstawie treści funkcji, argumentów, ciągów znaków, przepływu danych, API i efektów ubocznych.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Złamać pieczęć: statyczna deobfuskacja skompilowanego kodu bajtowego V8 z JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [Nagłówek V8 SerializedCodeData](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Pamięć podręczna kodu Node.js vm.Script](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
