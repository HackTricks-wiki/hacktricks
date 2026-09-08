# Protokoły płatności chroniące prywatność

{{#include ../banners/hacktricks-training.md}}

Zaawansowane systemy płatności mogą ukrywać płatnika przed merchantem, ukrywać odbiorcę lub kwotę przed publicznym ledgerem albo uniemożliwiać mintowi powiązanie wypłaty z realizacją. Są to różne właściwości. Żadna z nich nie usuwa zapisów dotyczących nabycia, urządzenia, sieci, dostawy, księgowości, sankcji ani endpointów.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) zapewnia ustandaryzowane wpisy `Pros`, `Cons`, krok po kroku `Procedure` oraz `Detection` dla każdej rodziny płatności. Ta strona rozwija temat zaawansowanych protokołów.

{% hint style="danger" %}
Używaj wyłącznie legalnych środków i legalnych kontrahentów. Nie używaj protokołów prywatności do obchodzenia wymaganej identyfikacji, sankcji, obowiązków podatkowych, kontroli źródła środków ani raportowania transakcji. Nie prowadź exchange, mint ani usługi transmisji bez zrozumienia wymogów licencyjnych, zasad custody, AML i ochrony konsumentów.
{% endhint %}

## Porównanie zaawansowanych opcji

| Protocol | Ukrywa przed publicznym odbiorcą/merchantem | Zaufana lub obserwująca strona | Dojrzałość/dostępność |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Osoby z zewnątrz nie mogą powiązać wielokrotnego kodu płatności z jego jednorazowymi outputami | Publiczny graf Bitcoin pozostaje widoczny; wallet/index server może widzieć skany | Specyfikacja ukończona; obsługa walletów jest różna |
| Zcash fully shielded Orchard | Nadawca, odbiorca i kwota są szyfrowane on-chain | Backend walleta/sieć oraz acquisition/off-ramp pozostają widoczne | Wdrożone; obsługa shielded różni się w zależności od walleta/exchange |
| GNU Taler | Merchant nie musi znać tożsamości płatnika; przychody merchanta pozostają rozliczalne | Taler exchange/bank widzi funding; merchant widzi zamówienie | Wdrożenia są ograniczone geograficznie |
| Federated Chaumian e-cash | Federacja nie powinna łączyć wydanych note z wewnętrznymi transferami/realizacją | Kworum guardianów przechowuje rezerwy; gatewaye widzą aktywność na granicach | Wschodzące wdrożenia społecznościowe |
| Lightning BOLT 12/route blinding | Ogranicza ujawnianie odbiorcy/węzła i trasy | Endpointy, wybrane hopy, łańcuch funding oraz usługi walleta | Obsługa zależy od walleta |
| Virtual card/token | Merchant otrzymuje ograniczone credential, a nie wielokrotnego użytku PAN | Issuer/network zachowują informacje o płatniku i transakcji | Dojrzałe i szeroko dostępne |

## Bitcoin Silent Payments (BIP 352)

Silent Payments pozwalają odbiorcy opublikować jeden statyczny kod płatności, podczas gdy każdy nadawca wyprowadza unikalny output Taproot. Zewnętrzny obserwator chaina nie może bezpośrednio powiązać tych outputów z opublikowanym kodem, a interaktywne żądanie adresu ani on-chainowy output powiadomienia nie są wymagane. BIP 352 ma status **Complete**, ale wprowadza koszt skanowania i jest niezgodny z walletami, które go nie zaimplementowały.<sup>[[1]](#references)</sup>

### Workflow odbiorcy

1. Wybierz utrzymywany wallet, który wyraźnie obsługuje odbieranie BIP 352; zweryfikuj tę funkcję w aktualnej dokumentacji walleta, a nie na podstawie twierdzenia z social media.
2. Wykonaj backup seeda walleta oraz materiału descriptor/key Silent Payment, korzystając z udokumentowanej przez wallet metody odzyskiwania. Przetestuj wykrywanie na małej kwocie testnet/mainnet przed opublikowaniem kodu.
3. Wygeneruj osobne **labels** dla kampanii, invoice lub kontrahentów, jeśli wallet obsługuje labels BIP 352. Labels pomagają w lokalnej księgowości bez publikowania adresów umożliwiających linkowanie.
4. Opublikuj statyczny kod Silent Payment przez uwierzytelniony kanał. Jest wielokrotnego użytku, ale impostor może podmienić go na własny kod.
5. Gdy to możliwe, skanuj za pośrednictwem lokalnego full node. Zewnętrzny index/scanning server może poznać czas żądań lub dane filtrów, nawet jeśli nie może wydawać środków.
6. Zachowaj wykryte UTXO z labelami i stosuj te same zasady coin control co przy zwykłym Bitcoinie. Wydawanie lub konsolidowanie ich może ujawnić powiązania własności.
7. Potwierdź, że odzyskiwanie wykrywa płatności bez polegania na niezbackupowanym zewnętrznym indeksie.

### Workflow nadawcy

1. Potwierdź, że wallet obsługuje wysyłanie do danej wersji adresu, i uwierzytelnij długi statyczny kod odbiorcy.
2. Pozwól walletowi skonstruować output; nigdy nie konwertuj ani nie skracaj kodu ręcznie.
3. Uważnie sprawdź wybrane inputy. Silent Payments poprawiają prywatność adresu odbiorcy, ale inputy nadawcy nadal znajdują się w publicznym grafie.
4. Używaj obsługiwanych przez wallet mechanizmów fee bumping/PSBT. BIP 352 wymaga ponownego wyprowadzenia outputu, jeśli inputy się zmienią, a niektóre tryby podpisywania są niebezpieczne.
5. Zachowaj zaszyfrowany receipt lub proof potrzebny do sporów/księgowości.

Silent Payments rozwiązują problem wielokrotnego publikowania adresu odbiorcy. Nie ukrywają kwoty, czasu transakcji, klastra nadawcy, historii nabycia ani późniejszego współwydawania.

## Zcash fully shielded payments

Zcash obsługuje transparent i shielded value pools. Shielded transactions Orchard używają zero-knowledge proofs, dzięki czemu node mogą weryfikować poprawność, gdy szczegóły transakcji pozostają zaszyfrowane; Unified Addresses mogą zawierać wiele typów odbiorców.<sup>[[2]](#references)</sup> Prywatność zależy od rzeczywistej ścieżki wybranej przez wallet, a nie od pierwszego znaku wyświetlanego adresu.

### Shielded workflow

1. Wybierz utrzymywany wallet, który jasno określa działanie **shielded-by-default** i aktualną obsługę Orchard. Zweryfikuj download oraz wykonaj backup/test seeda.
2. Uzyskaj ZEC legalnie i zapisz podstawę/źródło. Exchange nadal zna nabycie i withdrawal.
3. Odbierz środki na Unified Address obsługiwany przez wallet, a następnie sprawdź, czy transakcja trafiła do shielded pool. Nie zakładaj automatycznego shielding bez potwierdzenia działania walleta.
4. Preferuj transfery **shielded-to-shielded**. Ruchy transparent-to-shielded i shielded-to-transparent na granicy ujawniają publiczne wartości/czas i mogą umożliwiać korelację kwot; specyfikacja Orchard wskazuje, że wydanie na adres non-Orchard ujawnia wartość transakcji.<sup>[[3]](#references)</sup>
5. Unikaj charakterystycznych transferów tam i z powrotem z dokładną kwotą oraz natychmiastowego przekraczania granic. Jest to higiena prywatności, a nie zezwolenie na ukrywanie własności lub raportowania.
6. Korzystaj z obsługiwanej przez wallet ścieżki prywatności sieciowej. Shielded cryptography nie ukrywa IP/czasu przed serwerami walleta ani peerami.
7. Zachowaj wewnętrzne zapisy compliance i używaj viewing keys wyłącznie do celowego audytu/ujawnienia po zrozumieniu ich zakresu.
8. Potwierdź obsługę przez wallet/exchange odbiorcy przed wysłaniem; wymuszony transparent receiver zmienia właściwość prywatności.

## GNU Taler: anonimowy płatnik, rozliczalny merchant

GNU Taler to otwarty protokół płatności elektronicznych wykorzystujący tradycyjne waluty, blind signatures oraz integrację z regulowanym exchange/bank. Jego założeniem jest zachowanie anonimowości klientów wobec merchantów przy jednoczesnym zapewnieniu identyfikowalności i opodatkowania merchantów.<sup>[[4]](#references)</sup> Nie jest kryptowalutą, a dostępność zależy od kompatybilnego regionalnego exchange, banku, walleta i merchanta.

### Workflow użytkownika tam, gdzie jest wdrożony

1. Zidentyfikuj działający Taler exchange i merchanta w odpowiedniej walucie/jurysdykcji; przeczytaj ich aktualne warunki, opłaty, KYC i informacje o prywatności.
2. Zainstaluj oficjalny wallet i zweryfikuj jego źródło. Chroń dane backupu/odzyskiwania walleta jak gotówkę, ponieważ wartość walleta może być bearer asset.
3. Wypłać wartość przez obsługiwaną ścieżkę bank/exchange, używając prawdziwych informacji. Instytucja finansująca/exchange może znać withdrawal, mimo że blind signatures przerywają bezpośrednie powiązanie monety z withdrawal.
4. Sprawdź merchant contract w wallet: tożsamość merchanta, produkt/podsumowanie, kwotę, opłaty, refund oraz warunki dostawy.
5. Zapłać i zachowaj dane receipt wymagane do refund, gwarancji, księgowości lub podatków.
6. Nie używaj ponownie opcjonalnych identyfikatorów sesji/konta merchanta, jeśli wymagana jest unlinkability wobec merchanta.
7. Uwzględnij metadane walleta, sieci i dostawy w threat model; kryptografia płatności Taler nie ukrywa adresu wysyłki ani przejętego endpointu.

Merchant i exchange pozostają rozliczalne, a prowadzenie któregokolwiek z tych komponentów może być regulowaną działalnością usług płatniczych.

## Federated Chaumian e-cash

Chaumian e-cash używa blind signatures, aby mint podpisywał token bez ujawniania później wydawanego unblinded token. Fedimint rozdziela custody rezerw i podpisywanie między federację guardianów; dokumentacja stwierdza, że guardianowie widzą zagregowane rezerwy/outstanding notes, ale nie powinni widzieć indywidualnego salda ani tego, kto komu zapłacił wewnątrz federacji.<sup>[[5]](#references)</sup>

Jest to **custodial bearer value**. Wystarczające kworum guardianów kontroluje rezerwy; awaria federacji, nieuczciwi guardianowie, błędy software’u lub utrata stanu klienta mogą spowodować stratę. Depozyty, withdrawals i gatewaye Lightning są widocznymi zdarzeniami granicznymi i mogą korelować czas/kwotę.

### Workflow ograniczonego ryzyka

1. Używaj wyłącznie małej kwoty, którą możesz stracić. Traktuj publiczne/nieznane federacje jako bardziej ryzykowne niż guardianów ponoszących rzeczywistą odpowiedzialność.
2. Zweryfikuj invite federacji przez uwierzytelniony kanał i zapisz tożsamości guardianów, kworum, jurysdykcję, opłaty, recovery oraz politykę zamknięcia.
3. Zainstaluj utrzymywany kompatybilny wallet, zweryfikuj go i zrozum jego schemat backupu przed wpłatą.
4. Wpłać legalnie nabyty Bitcoin przez udokumentowaną ścieżkę. Zapisz peg-in do celów księgowych i załóż, że jego czas/kwota są publiczne lub znane na granicy.
5. Wewnątrz federacji używaj świeżych payment requests i unikaj dodawania identyfikatorów konta/chatu/dostawy, które odtworzyłyby powiązanie usunięte przez blind signature.
6. W przypadku płatności Lightning traktuj gateway jako dodatkowego obserwatora invoice i czasu zdarzeń granicznych.
7. Zrealizuj/wycofaj środki zgodnie z polityką, zakładając, że charakterystyczna kwota i natychmiastowy czas mogą korelować z depozytem lub zewnętrzną płatnością.
8. Zachowaj prywatnie zapisy podatkowe/źródła/autoryzacji; nie proś guardianów ani gatewayów o fałszowanie aktywności.

Nie opisuj federated e-cash jako trustless, self-custodial ani gwarantującego anonimowość.

## BOLT 12 offers i route blinding

BOLT 12 offers mogą być wielokrotnego użytku bez publikowania stabilnego adresu on-chain i mogą używać blinded paths, dzięki czemu płatnik nie musi poznawać jawnej tożsamości/ścieżki node odbiorcy. Uzupełnia to istniejący onion routing Lightning, ale go nie zastępuje.

Przed użyciem:

1. Potwierdź, że wallety nadawcy i odbiorcy obsługują te same aktualne funkcje BOLT 12; nie wnioskuj o obsłudze na podstawie ogólnego brandingu „Lightning”.
2. Uwierzytelnij offer out of band i sprawdź kwotę, issuer/description oraz reguły recurrence.
3. Użyj świeżego kontekstu invoice/payment wygenerowanego z offer.
4. Ogranicz do minimum aliasy node, publiczne informacje kontaktowe i stabilne endpointy sieciowe.
5. Załóż, że nadawca/odbiorca, pierwszy/ostatni hop, usługa walleta, graf kanałów oraz on-chain funding/closure nadal ujawniają części relacji.

## Możliwość audytu bez publicznego ujawnienia

Prywatność i audyt mogą współistnieć:

- Przechowuj labels, invoice, autoryzację, cost basis i mapowanie własności zaszyfrowane poza publicznym protokołem.
- Oddziel **view/audit key** od spending key, gdy protokół zapewnia taką możliwość; najpierw przetestuj dokładny zakres ujawnienia na przykładowym wallet.
- Przekazuj auditorowi minimalny proof o określonym zakresie, a nie seed ani nieograniczony spending credential.
- W chwili transakcji zapisuj wersję software’u, protokół/pool, transaction ID lub proof, cel kontrahenta oraz źródło kursu wymiany.
- Zdefiniuj przechowywanie i usuwanie zamiast gromadzenia trwałego, niezaszyfrowanego grafu tożsamości.

## Lista kontrolna wyboru

- [ ] Ukrywane pole i obserwator są precyzyjnie określone.
- [ ] Obsługa walleta/protokołu została zweryfikowana na dzień transakcji.
- [ ] Powiązania dotyczące nabycia, sieci, node/RPC, kontrahenta, dostawy i późniejszego wydania zostały udokumentowane.
- [ ] Ryzyka custody, recovery, płynności, wypłacalności issuera/federacji oraz refund zostały zaakceptowane.
- [ ] Wymagane zapisy dotyczące tożsamości, podatków, sankcji, źródła i organizacji pozostały zgodne z prawdą.
- [ ] Mały test end-to-end, obejmujący recovery i proof audytowy, zakończył się powodzeniem.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [GNU Taler Documentation](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — How it works](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
