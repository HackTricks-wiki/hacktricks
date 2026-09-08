# Protokoły płatności chroniące prywatność

Zaawansowane systemy płatności mogą ukrywać płatnika przed sprzedawcą, ukrywać odbiorcę lub kwotę przed publicznym ledgerem albo uniemożliwiać mintowi powiązanie wypłaty z realizacją. Są to różne właściwości. Żadna z nich nie usuwa zapisów dotyczących nabycia, urządzenia, sieci, dostawy, księgowości, sankcji ani punktu końcowego.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) zapewnia ustandaryzowane sekcje `Pros`, `Cons`, krok po kroku `Procedure` oraz `Detection` dla każdej rodziny płatności. Ta strona rozwija temat zaawansowanych protokołów.

{% hint style="danger" %}
Używaj wyłącznie legalnych środków i korzystaj z legalnych kontrahentów. Nie używaj protokołów prywatności do omijania wymaganej identyfikacji, sankcji, podatków, kontroli źródła środków ani raportowania transakcji. Nie prowadź giełdy, minta ani usługi transmisji bez zrozumienia obowiązków związanych z licencjonowaniem, custody, AML i ochroną konsumentów.
{% endhint %}

## Porównanie zaawansowanych opcji

| Protokół | Co ukrywa przed publicznym ledgerem/sprzedawcą | Zaufana lub obserwująca strona | Dojrzałość/dostępność |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Zewnętrzni obserwatorzy nie mogą powiązać wielokrotnego kodu płatności z jego jednorazowymi outputami | Publiczny graf Bitcoin pozostaje widoczny; wallet/index server może widzieć skanowania | Specyfikacja ukończona; obsługa walletów jest różna |
| Zcash fully shielded Orchard | Nadawca, odbiorca i kwota są szyfrowane on-chain | Backend walleta/sieć oraz acquisition/off-ramp pozostają widoczne | Wdrożone; obsługa shielded jest różna w zależności od walleta/exchange |
| GNU Taler | Sprzedawca nie musi poznawać tożsamości płatnika; przychód sprzedawcy pozostaje rozliczalny | Taler exchange/bank widzi finansowanie; sprzedawca widzi zamówienie | Wdrożenia są ograniczone geograficznie |
| Federated Chaumian e-cash | Federacja nie powinna łączyć wydanych tokenów z wewnętrznymi transferami/realizacją | Kworum guardianów przechowuje rezerwy; gatewaye widzą aktywność na granicach systemu | Wschodzące wdrożenia społecznościowe |
| Lightning BOLT 12/route blinding | Ogranicza ujawnianie odbiorcy/węzła i trasy | Endpointy, wybrane hopy, łańcuch finansowania i usługi walleta | Obsługa zależy od walleta |
| Virtual card/token | Sprzedawca otrzymuje ograniczone poświadczenie, a nie wielokrotnego użytku PAN | Issuer/network zachowują informacje o płatniku i transakcji | Dojrzałe i szeroko dostępne |

## Bitcoin Silent Payments (BIP 352)

Silent Payments pozwalają odbiorcy opublikować jeden statyczny kod płatności, podczas gdy każdy nadawca generuje unikalny output Taproot. Zewnętrzny obserwator chaina nie może bezpośrednio powiązać tych outputów z opublikowanym kodem, a interaktywne żądanie adresu ani on-chain notification output nie są wymagane. BIP 352 ma status **Complete**, ale wprowadza koszt skanowania i jest niekompatybilny z walletami, które go nie zaimplementowały.<sup>[[1]](#references)</sup>

### Workflow odbiorcy

1. Wybierz utrzymywany wallet, który wyraźnie obsługuje odbieranie BIP 352; zweryfikuj tę funkcję w aktualnej dokumentacji walleta, a nie na podstawie twierdzenia z mediów społecznościowych.
2. Wykonaj backup seeda walleta oraz materiału Silent Payment descriptor/key, korzystając z udokumentowanej przez walleta metody odzyskiwania. Przetestuj wykrywanie na małej kwocie testnet/mainnet przed opublikowaniem kodu.
3. Generuj osobne **labels** dla kampanii, faktur lub kontrahentów, jeśli wallet obsługuje labels BIP 352. Labels ułatwiają lokalną księgowość bez publikowania adresów, które można ze sobą powiązać.
4. Opublikuj statyczny kod Silent Payment przez uwierzytelniony kanał. Można go wielokrotnie używać, ale impostor może podstawić własny kod.
5. Gdy jest to praktyczne, skanuj przez lokalny full node. Zewnętrzny serwer indeksujący/skanujący może poznać czas żądań lub dane filtrów, nawet jeśli nie może wydawać środków.
6. Zachowuj wykryte UTXO z labels i stosuj te same zasady coin-control co w przypadku zwykłego Bitcoin. Wydawanie lub konsolidowanie ich może ujawnić relacje własności.
7. Potwierdź, że recovery wykrywa płatności bez polegania na zewnętrznym indeksie, którego nie objęto backupem.

### Workflow nadawcy

1. Potwierdź, że wallet obsługuje wysyłanie do danej wersji adresu, i uwierzytelnij długi, statyczny kod odbiorcy.
2. Pozwól walletowi skonstruować output; nigdy ręcznie nie konwertuj ani nie skracaj kodu.
3. Uważnie sprawdź wybrane inputy. Silent Payments poprawiają prywatność adresu odbiorcy, ale inputy nadawcy nadal znajdują się w publicznym grafie.
4. Używaj obsługiwanej przez wallet funkcji fee bumping/PSBT. BIP 352 wymaga ponownego wyprowadzenia outputu, jeśli inputy się zmienią, a niektóre tryby podpisywania są niebezpieczne.
5. Zachowaj zaszyfrowany receipt lub proof potrzebny w sporach/księgowości.

Silent Payments rozwiązują problem wielokrotnego publikowania adresu odbiorcy. Nie ukrywają kwoty, czasu transakcji, klastra nadawcy, historii nabycia ani późniejszego współwydawania.

## Płatności Zcash w pełni shielded

Zcash obsługuje transparentne i shielded pule wartości. Shielded transactions Orchard używają zero-knowledge proofs, dzięki czemu nody mogą weryfikować poprawność, podczas gdy szczegóły transakcji są szyfrowane; Unified Addresses mogą zawierać wiele typów odbiorców.<sup>[[2]](#references)</sup> Prywatność zależy od rzeczywistej ścieżki wybranej przez wallet, a nie od pierwszego znaku wyświetlanego adresu.

### Workflow shielded

1. Wybierz utrzymywany wallet, który jasno wskazuje działanie **shielded-by-default** i aktualną obsługę Orchard. Zweryfikuj download oraz wykonaj backup/test seeda.
2. Pozyskaj ZEC legalnie i zapisz podstawę/źródło. Exchange nadal zna nabycie i withdrawal.
3. Odbierz środki na Unified Address obsługiwany przez wallet, a następnie sprawdź, czy transakcja trafiła do shielded pool. Nie zakładaj automatycznego shieldingu bez potwierdzenia działania walleta.
4. Preferuj transfery **shielded-to-shielded**. Ruchy transparent-to-shielded i shielded-to-transparent na granicy ujawniają publiczne wartości/czas i mogą umożliwiać korelację kwot; specyfikacja Orchard wskazuje, że wydanie na adres non-Orchard ujawnia wartość transakcji.<sup>[[3]](#references)</sup>
5. Unikaj charakterystycznych przelewów tam i z powrotem z dokładną kwotą oraz natychmiastowego przekraczania granic. Jest to higiena prywatności, a nie zezwolenie na ukrywanie własności lub raportowania.
6. Korzystaj z obsługiwanej przez wallet ścieżki prywatności sieciowej. Shielded cryptography nie ukrywa IP/czasu przed serwerami walleta ani peerami.
7. Zachowuj wewnętrzne dokumenty compliance i używaj viewing keys wyłącznie do celowego audytu/ujawnienia po zrozumieniu ich zakresu.
8. Potwierdź obsługę walleta/exchange odbiorcy przed wysłaniem; wymuszony transparent receiver zmienia właściwość prywatności.

## GNU Taler: anonimowy płatnik, rozliczalny sprzedawca

GNU Taler to otwarty protokół płatności elektronicznych wykorzystujący tradycyjne waluty, blind signatures oraz integrację z regulowanym exchange/bank. Jego projekt ma zapewniać anonimowość klientów wobec sprzedawców, przy jednoczesnym zachowaniu identyfikowalności i opodatkowania sprzedawców.<sup>[[4]](#references)</sup> Nie jest kryptowalutą, a dostępność zależy od kompatybilnego regionalnego exchange, banku, walleta i sprzedawcy.

### Workflow użytkownika w dostępnych wdrożeniach

1. Zidentyfikuj działający Taler exchange i sprzedawcę w odpowiedniej walucie/jurysdykcji; przeczytaj ich aktualne warunki, opłaty, KYC i informacje o prywatności.
2. Zainstaluj oficjalny wallet i zweryfikuj jego źródło. Chroń dane backup/recovery walleta jak gotówkę, ponieważ wartość walleta może być bearer asset.
3. Wypłać środki przez obsługiwany przepływ bank/exchange, używając prawdziwych informacji. Instytucja finansująca/exchange może znać withdrawal, mimo że blind signatures przerywają bezpośrednie powiązanie monety z wypłatą.
4. Sprawdź w walletcie kontrakt sprzedawcy: tożsamość sprzedawcy, przedmiot/podsumowanie, kwotę, opłaty, refund i warunki dostawy.
5. Zapłać i zachowaj dane receipt wymagane do refund, gwarancji, księgowości lub podatków.
6. Nie używaj ponownie opcjonalnych identyfikatorów sesji/konta sprzedawcy, jeśli wymagana jest unlinkability wobec sprzedawcy.
7. Uwzględnij w threat modelu metadane walleta, sieci i dostawy; kryptografia płatności Taler nie ukrywa adresu wysyłki ani przejętego endpointu.

Sprzedawca i exchange pozostają rozliczalni, a prowadzenie któregokolwiek z tych komponentów może być regulowaną działalnością usług płatniczych.

## Federated Chaumian e-cash

Chaumian e-cash używa blind signatures, dzięki czemu mint podpisuje token bez wglądu w token po jego unblind i późniejszym wydaniu. Fedimint rozdziela custody rezerw i podpisywanie między federację guardianów; dokumentacja wskazuje, że guardiani widzą zagregowane rezerwy/wartość niezrealizowanych tokenów, ale nie powinni widzieć indywidualnego salda ani tego, kto komu zapłacił wewnątrz federacji.<sup>[[5]](#references)</sup>

Jest to **custodial bearer value**. Wystarczające kworum guardianów kontroluje rezerwy; awaria federacji, nieuczciwi guardiani, błędy oprogramowania lub utrata stanu klienta mogą spowodować stratę. Deposits, withdrawals i Lightning gatewaye są widocznymi zdarzeniami na granicach systemu i mogą korelować czas/kwotę.

### Workflow ograniczonego ryzyka

1. Używaj wyłącznie małej kwoty, na której utratę możesz sobie pozwolić. Traktuj publiczne/nieznane federacje jako bardziej ryzykowne niż guardianów ponoszących rzeczywistą odpowiedzialność.
2. Zweryfikuj zaproszenie do federacji przez uwierzytelniony kanał i zapisz tożsamości guardianów, kworum, jurysdykcję, opłaty, recovery oraz politykę zamknięcia.
3. Zainstaluj utrzymywany kompatybilny wallet, zweryfikuj go i zrozum jego schemat backupu przed dokonaniem depozytu.
4. Wpłać legalnie pozyskany Bitcoin przez udokumentowaną ścieżkę. Zapisz peg-in dla księgowości i załóż, że jego czas/kwota są publiczne lub znane na granicy systemu.
5. Wewnątrz federacji używaj świeżych payment requests i unikaj dodawania identyfikatorów konta/czatu/dostawy, które odtworzyłyby powiązanie usunięte przez blind signature.
6. W przypadku płatności Lightning traktuj gateway jako dodatkowego obserwatora invoice'ów i czasu zdarzeń na granicy systemu.
7. Zrealizuj/wypłać środki zgodnie z polityką, zakładając, że charakterystyczna kwota i natychmiastowy czas mogą korelować z depozytem lub płatnością zewnętrzną.
8. Zachowuj prywatnie dokumenty podatkowe/źródłowe/autoryzacyjne; nie proś guardianów ani gatewayów o fałszywe przedstawianie aktywności.

Nie opisuj federated e-cash jako trustless, self-custodial ani gwarantującego anonimowość.

## BOLT 12 offers i route blinding

BOLT 12 offers mogą być wielokrotnie używane bez publikowania stabilnego adresu on-chain i mogą używać blinded paths, dzięki czemu płatnik nie musi poznawać jawnej tożsamości/ścieżki węzła odbiorcy. Uzupełnia to istniejący onion routing Lightning, ale go nie zastępuje.

Przed użyciem:

1. Potwierdź, że wallety nadawcy i odbiorcy obsługują te same aktualne funkcje BOLT 12; nie wyciągaj wniosku o obsłudze na podstawie ogólnego oznaczenia „Lightning”.
2. Uwierzytelnij offer out of band i sprawdź kwotę, issuer/description oraz zasady cykliczności.
3. Użyj świeżego kontekstu invoice/payment wygenerowanego z offer.
4. Ogranicz do minimum aliasy nodów, publiczne informacje kontaktowe i stabilne endpointy sieciowe.
5. Załóż, że sender/receiver, first/last hop, usługa walleta, graf kanałów oraz on-chain funding/closure nadal ujawniają części relacji.

## Możliwość audytu bez publicznego ujawnienia

Prywatność i audyt mogą współistnieć:

- Przechowuj labels, invoices, autoryzację, cost basis i mapowanie własności w formie zaszyfrowanej poza publicznym protokołem.
- Oddziel **view/audit key** od spending key, gdy protokół zapewnia taką możliwość; najpierw przetestuj dokładny zakres ujawnienia na przykładowym walletcie.
- Przekazuj auditorowi minimalny proof o określonym zakresie zamiast seeda lub nieograniczonego poświadczenia wydawania.
- W czasie transakcji zapisuj wersję oprogramowania, protocol/pool, transaction ID lub proof, cel kontrahenta oraz źródło kursu wymiany.
- Zdefiniuj okres przechowywania i usuwania zamiast gromadzić trwały, niezaszyfrowany graf tożsamości.

## Lista kontrolna wyboru

- [ ] Ukrywane pole i obserwator są precyzyjnie określone.
- [ ] Obsługa walleta/protokołu została zweryfikowana na dzień transakcji.
- [ ] Powiązania z acquisition, siecią, node/RPC, kontrahentem, dostawą i późniejszym wydaniem są udokumentowane.
- [ ] Ryzyka custody, recovery, płynności, wypłacalności issuera/federacji i refund zostały zaakceptowane.
- [ ] Wymagane dokumenty dotyczące tożsamości, podatków, sankcji, źródła i organizacji pozostają prawidłowe.
- [ ] Mały test end-to-end, obejmujący recovery i proof audytowy, zakończył się powodzeniem.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [Dokumentacja GNU Taler](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — Jak to działa](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
