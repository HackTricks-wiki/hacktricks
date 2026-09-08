# Katalog technik anonimowych płatności

Katalog obejmuje **rodziny** płatności: od zwykłej gotówki po e-cash oparty na blind signatures i zaciemnianie publicznych łańcuchów. „Anonimowe” zawsze oznacza anonimowe względem określonego obserwatora. Merchant, issuer, mint, exchange, analityk blockchaina, provider sieci, pracodawca i obserwator fizyczny widzą różne informacje.

Poniższe procedury dotyczą legalnych środków, prawdziwych kont i autoryzowanych zakupów. Techniki, których celem w cytowanych przypadkach było pranie pieniędzy, obchodzenie sankcji lub kradzież tożsamości, są wyjaśnione i wykrywane, ale ich procedura jest syntetycznym ćwiczeniem forensic, a nie instrukcją popełnienia przestępstwa.

## Coverage matrix

| Rodzina | Główna właściwość prywatności | Główny obserwator/zaufanie | Sposób ujęcia |
|---|---|---|---|
| Gotówka i ekwiwalenty gotówki | brak zdalnego zapisu w sieci płatniczej | odbiorca i otoczenie fizyczne | legalny workflow |
| Wartość prepaid/gift/voucher | oddziela realizację od głównej karty | sprzedawca, issuer i usługa realizacji | legalny workflow, zależny od jurysdykcji |
| Karta wirtualna/tokenizowana | ukrywa wielokrotnego użytku PAN lub oddziela merchantów | issuer/network/wallet nadal identyfikuje płatnika | legalny workflow |
| Payment app/intermediary | merchant może widzieć alias/intermediary | app gromadzi tożsamość, urządzenie i transakcję | punkt odniesienia |
| Bitcoin hygiene/Silent Payments | pseudonimy i niepowiązywalność odbiorcy | publiczny graf i granica wallet/network | możliwe do wdrożenia |
| PayJoin/CoinJoin | osłabia heurystyki wspólnej własności/powiązań | uczestnicy/coordinator/network/publiczny graf | możliwe tam, gdzie wspierane; review prawny |
| Lightning/BOLT 12 | routing off-chain i ograniczenie ścieżki odbiorcy | endpoints, hops, usługi i graf kanałów | możliwe tam, gdzie wspierane |
| Monero/Zcash/MWEB | poufność on-chain na poziomie protokołu | nabycie, endpoint, sieć i granice nadal pozostają | możliwe tam, gdzie legalne/wspierane |
| Aplikacja Ethereum ZK | ukrywa określone twierdzenie/powiązanie działania | public inputs, RPC, relayer i app | zależne od aplikacji |
| Cashu/Fedimint/Taler | prywatność płatnika dzięki blind signatures | custody mint/federation/exchange i granice | rozwijające się/zależne od wdrożenia |
| Stablecoiny | wygodne cyfrowe rozliczenie | transparentny chain oraz issuer freeze/control | nie są bazą anonimowości |
| Swapy/bridge/DEX | przenosi wartość między aktywami/łańcuchami | oba grafy, kontrakty i providerzy | mechanika forensic; tylko zwykłe legalne swapy |
| Mixery/peel/structuring | zwiększa niejednoznaczność i nakład pracy | graf wejścia/wyjścia i zapisy usługi | wyłącznie syntetyczne ćwiczenie wykrywania |
| Nominees/mules/OTC/fronts | wstawia pośredników ludzkich/biznesowych | facilitators, banki, komunikacja | wyłącznie analiza nadużyć kryminalnych |
| Reusable/stealth payment addresses | nowy adres odbiorcy dla każdej płatności | publiczne ogłoszenie/powiadomienie i granice walleta | możliwe tam, gdzie wspierane |
| Confidential sidechain/state channel | ukrywa kwotę/aktywo lub aktualizacje pośrednie | peers, bridge/federation i rozliczenie cyklu życia | zależne od protokołu |
| Carrier/open-banking/platform billing | ukrywa główną kartę przed merchantem | carrier, bank/PISP lub platforma identyfikuje klienta | zwykła zidentyfikowana płatność |
| Mutual credit/net settlement | mniej zewnętrznych zapisów rozliczeń | prywatny operator ledgeru ma pełne mapowanie | tylko zidentyfikowani uczestnicy |

## Cash

**Mechanika:** fizyczna wartość bearer przechodzi z rąk do rąk bez internetowej autoryzacji issuer ani publicznego ledgeru.

**Zalety:** merchant nie musi znać tożsamości bankowej/kartowej; brak zdalnego grafu transakcji; metoda powszechnie zrozumiała i zasadniczo finalna.

**Wady:** wyłącznie face-to-face; kradzież/utrata; reszta, paragon, serial lub kontrole raportowe; wypłata, kamery, świadkowie i lokalizacja nadal mogą powiązać płatnika.

**Procedura:** (1) potwierdź legalność/akceptację gotówki oraz limity i obowiązki raportowe; (2) wypłać lub otrzymaj ją legalnie i prowadź prywatną ewidencję; (3) zapłać zwykłemu merchantowi bez niepotrzebnych identyfikatorów lojalnościowych/kont; (4) poproś tylko o wymagany paragon; (5) unikaj danych wysyłkowych/kontowych, jeśli zakup ich nie wymaga; (6) wewnętrznie zapisz legalny cel biznesowy.

**Wykrywanie:** uzgadniaj kasę, paragony i inventory z kamerami oraz logami dostępu zgodnie z polityką; badaj nietypowe zwroty gotówkowe lub powtarzalne kwoty tuż poniżej kontroli, nie uznając zwykłego używania gotówki za samoistnie podejrzane.

## Money order, postal order, cashier instrument i cash on delivery

**Mechanika:** regulowany issuer zamienia gotówkę/środki z konta na numerowany instrument płatny wskazanemu odbiorcy; COD odracza pobranie do dostawy.

**Zalety:** odbiorca może nie otrzymać głównego numeru bankowego/kartowego płatnika; użyteczne, gdy gotówki nie można wysłać zdalnie; jasny paragon.

**Wady:** issuer/retailer zachowuje wymagane dane zakupu/tożsamości; śledzenie serialu; adres odbiorcy/dostawy; ryzyko utraty/oszustwa i ograniczenia regionalne; zasadniczo brak anonimowości.

**Procedura:** (1) sprawdź zasady issuera, limity, identyfikację i akceptację odbiorcy; (2) kup za legalne środki i podaj prawdziwe dane; (3) natychmiast uzupełnij payee/kwotę; (4) zachowaj serial/paragon; (5) użyj śledzonej dostawy adekwatnej do wartości; (6) uzgodnij realizację/zwrot.

**Wykrywanie:** zapisy zakupu/realizacji issuera, serial instrumentu, retailer/kamera, wysyłka i konto odbiorcy; oznaczaj modyfikacje, duplikaty seriali i szybką geograficznie niespójną realizację.

## Open-loop prepaid card

**Mechanika:** przechowywany przez sieć credential autoryzuje płatność z salda prepaid zamiast z głównego konta kredytowego.

**Zalety:** ogranicza ekspozycję merchantowi i straty; oddziela merchantów od głównego PAN; działa online tam, gdzie jest akceptowany.

**Wady:** zapisy zakupu/aktywacji/doładowania/rejestracji i urządzenia; KYC i limity są różne; problemy z billing address; ograniczenia cash-out/zwrotów; „brak nazwiska” nie oznacza braku zapisu u issuera.

**Procedura:** (1) sprawdź aktualną tożsamość issuera, opłaty, KYC, geografię oraz obsługę online/recurring; (2) pozyskaj kartę przez autoryzowanego sprzedawcę za legalne środki; (3) zarejestruj wymagane prawdziwe dane; (4) używaj jej dla jednego celu/kontekstu; (5) nie strukturyzuj doładowań ani nie fałszuj rezydencji; (6) zachowaj dowody zakupu/wydatków i zamknij/utylizuj kartę zgodnie z warunkami issuera.

**Wykrywanie:** łącz dane sprzedawcy/aktywacji, finansowania, urządzenia/IP, autoryzacji merchanta, sprawdzeń salda i realizacji/zwrotu. Ważniejsze są wzorce niż sama etykieta prepaid.

## Closed-loop gift card, voucher i transferable service credit

**Mechanika:** numerowana wartość może być zrealizowana wyłącznie u jednego merchanta/usługi lub w jednym ekosystemie. Airtime, game i store credits są wariantami.

**Zalety:** merchant odbiorcy może widzieć tylko kod/saldo; ograniczony zasięg skutków; łatwe giftowanie i rozdzielenie budżetu.

**Wady:** sprzedawca i usługa zapisują zakup/aktywację/realizację; konto, urządzenie i dostawa nadal łączą aktywność; oszustwa, rabaty odsprzedaży oraz limity wygaśnięcia/regionu; słaba ochrona zwrotów.

**Procedura:** (1) kupuj wyłącznie autoryzowanymi kanałami; (2) zapisz wartość kodu bez ujawniania sekretu; (3) nie dołączaj niepotrzebnego konta loyalty; (4) realizuj przez oddzielne, legalne konto/kontekst merchanta; (5) zachowaj paragon do akceptacji; (6) nigdy nie kupuj kodów na niezamówione żądanie „podatku/support/ransom”.

**Wykrywanie:** czas emisji/realizacji kodu, zbieżność urządzenia/konta, zakupy hurtowe lub progowe, jedno urządzenie sprawdzające wiele sald i szybka odległa realizacja.

## Cryptocurrency-funded card lub gift-code broker

**Mechanika:** intermediary przyjmuje kryptowalutę i wydaje kartę, voucher lub kod merchanta. Jest to konwersja między rails: merchant widzi zwykłą kartę/wartość gift, a broker łączy depozyt on-chain z wydaniem i dostawą.

**Zalety:** merchant nie otrzymuje funding walleta; użyteczne dla legalnych merchantów nieakceptujących crypto; ograniczona wartość stored-value.

**Wady:** brak anonimowości wobec brokera/issuera; KYC, sanctions, exchange i zasady card-program; publiczny graf depozytu; konto/urządzenie/email i realizacja kodu ponownie łączą obie strony; ryzyko oszustwa/niewypłacalności.

**Procedura:** (1) zweryfikuj osobę prawną, card issuer, obsługiwaną jurysdykcję, KYC, opłaty i politykę zwrotów; (2) używaj wyłącznie legalnych, udokumentowanych środków; (3) przetestuj najmniejszy nominał; (4) przed zakupem sprawdź ograniczenia network/merchant; (5) zachowaj transakcję blockchain i paragon brokera do celów księgowych; (6) nigdy nie korzystaj z brokera obiecującego identity fraud, obejście sankcji lub „untraceable” cash-out.

**Wykrywanie:** koreluj adresy depozytowe brokera, unikalną kwotę/czas, konto/urządzenie oraz autoryzację wydanej karty lub realizację kodu; zapisy issuera i brokera łączą publiczny chain z merchantem.

## Virtual lub merchant-locked card

**Mechanika:** issuer mapuje wygenerowany PAN/token na rzeczywiste konto, często ograniczając merchanta, kwotę lub expiry.

**Zalety:** zapobiega ujawnieniu wielokrotnego użytku PAN; compartmentation merchantów; limity wydatków i łatwe unieważnienie; dojrzała fraud control.

**Wady:** issuer nadal zna płatnika, finansowanie, merchanta, urządzenie/IP i czas; merchant widzi konto/dostawę; niektóre zwroty/recurring charges zawodzą; brak anonimowości.

**Procedura:** (1) używaj oficjalnej funkcji regulowanego issuera; (2) utwórz kartę dla jednego merchanta/engagement; (3) ustaw najmniejszy użyteczny limit i expiry; (4) stosuj poprawny billing, gdy wymagany; (5) sprawdź statement descriptor i zachowanie zwrotów; (6) po finalnym rozliczeniu zamroź/usuń kartę, zachowując audit evidence.

**Wykrywanie:** mapowanie token-to-account u issuera, autoryzacja merchanta, urządzenie i dostawa. Defenders używają sygnałów merchant-specific reuse, velocity i account takeover.

## Mobile-wallet network token

**Mechanika:** tokenizacja płatności EMV zastępuje PAN ograniczonym credentialem, często powiązanym z urządzeniem, merchantem lub scenariuszem płatności.<sup>[[1]](#references)</sup>

**Zalety:** merchant nie otrzymuje wielokrotnego użytku PAN; kryptografia urządzenia i dane dynamiczne ograniczają klonowanie; można unieważnić token bez wymiany karty.

**Wady:** issuer, token service, wallet platform i network zachowują mapowania/transakcje; konto platformy, urządzenie i lokalizacja mogą identyfikować płatnika.

**Procedura:** (1) zarejestruj legalną kartę w oficjalnym wallet; (2) zabezpiecz konto platformy/urządzenie silnym uwierzytelnianiem; (3) przy zakupie sprawdź token urządzenia i ostatnie cyfry; (4) wyłącz zbędną lokalizację/analytics, jeśli wspierane; (5) natychmiast wyłącz tokeny utraconych urządzeń; (6) przeglądaj zapisy issuera i walleta.

**Wykrywanie:** token requestor/device cryptogram i mapowanie u issuera, telemetry walleta/konta, terminal merchanta i dowody fizyczne.

## Payment app, marketplace wallet i centralized intermediary

**Mechanika:** usługa utrzymuje konta i transferuje środki wewnętrznie lub przez rails bank/card; merchant może widzieć alias, podczas gdy usługa widzi obie strony.

**Zalety:** wygoda, mechanizmy sporów/zwrotów; odbiorca nie musi otrzymać danych bankowych/kartowych.

**Wady:** scentralizowany graf tożsamości, społeczny, transakcyjny i urządzeń; freezes i legal process; counterparties mogą ujawnić profil; użycie danych może wykraczać poza konieczność płatniczą.<sup>[[2]](#references)</sup>

**Procedura:** (1) przeczytaj zasady identity, privacy, retention i buyer protection; (2) ogranicz opcjonalną synchronizację profilu/kontaktów; (3) używaj oddzielnego prawdziwego konta tylko, gdy pozwalają na to warunki; (4) włącz MFA/alerty; (5) sprawdź odbiorcę oraz prywatność memo/profilu; (6) eksportuj zapisy i zamykaj nieużywane powiązania.

**Wykrywanie:** konto providera, urządzenie/IP, graf kontaktów, finansowanie/wypłata, memo i zapisy merchanta. Alias oznacza pseudonimowość wobec counterparty, nie anonimowość wobec platformy.

## Bank transfer, ACH, wire i instant-account payment

**Mechanika:** regulowane instytucje przesyłają wartość między zidentyfikowanymi kontami i wymieniają wymagane dane płatnicze.

**Zalety:** szybkość, rozliczalność, ograniczona odwracalność, silne zapisy; virtual account numbers mogą ograniczyć ujawnienie merchantowi.

**Wady:** banki/processors znają obie strony; statements i references; brak anonimowości; dane cross-border oraz Travel Rule/AML.

**Procedura:** używaj wyłącznie, gdy akceptowalna jest rozliczalność: niezależnie zweryfikuj beneficiary, ogranicz opcjonalne memo, użyj bankowego virtual account/reference, jeśli dostępny, włącz alerty, zachowaj invoice i uzgodnij płatność.

**Wykrywanie:** deterministyczne zapisy bank/payment, własność beneficiary/account, urządzenie/session i fraud controls. To punkt odniesienia, nie technika anonimowości.

## Account i merchant compartmentation

**Mechanika:** oddzielne legalne tożsamości/konta, aliasy email, karty i konteksty dostawy uniemożliwiają niezależnym merchantom proste łączenie aktywności, podczas gdy issuer/controller zachowuje mapowanie.

**Zalety:** ogranicza wycieki i łączenie między merchantami; łatwa kontrola; kompatybilne z regulowanymi płatnościami.

**Wady:** provider nadal mapuje compartmenty; recovery phone/device/IP i shipping mogą je połączyć; polityka może zabraniać wielu kont.

**Procedura:** (1) zdefiniuj jeden cel; (2) twórz wyłącznie aliasy/subkonta zgodne z warunkami; (3) używaj merchant-specific token/card; (4) wyłącz cross-account contact/ad personalization; (5) prowadź zaszyfrowany controller ledger; (6) wycofuj identyfikatory po zakończeniu potrzeb zwrotów/retention.

**Wykrywanie:** providerzy łączą recovery, urządzenie, finansowanie i IP; merchant łączy dostawę, browser i zachowanie konta. Defenders powinni odróżniać legalną compartmentation od synthetic identity fraud.

## Controlled red-team procurement

**Mechanika:** SOC nie zna zakupu, podczas gdy exercise controller zachowuje mapowanie legal entity, operatora i infrastruktury.

**Zalety:** realistyczne ćwiczenie detection; brak ekspozycji osobistej; natychmiastowe deconfliction i audit.

**Wady:** brak anonimowości wobec organizacji/providera; narzut governance; leak w razie niewłaściwego obchodzenia się z controller ledgerem.

**Procedura:** (1) przydziel engagement-specific organization card/wallet/budget; (2) oddziel role purchaser/operator; (3) zapisz asset, kwotę, usługę, cel i kill date; (4) przechowuj mapowanie atrybucji z ograniczonym dostępem controllera; (5) nigdy nie używaj false identity/mule/stolen funds; (6) przy zamknięciu ujawnij i uzgodnij indicators oraz zwroty.

**Wykrywanie:** controller mapuje invoice providera i asset; SOC testuje niezależne wykrywanie przez domain, certificate, hosting i traffic, a nie dane cardholdera.

## Bitcoin address hygiene i coin control

**Mechanika:** nowe receive addresses, lokalne etykiety i selektywne wydawanie UTXO ograniczają reuse adresów i przypadkowe łączenie compartmentów w publicznym ledgerze.

**Zalety:** szerokie wsparcie; self-custodial; unikanie najprostszych publicznych powiązań.

**Wady:** wszystkie transakcje/kwoty pozostają publiczne; common-input/change/timing i późniejsza konsolidacja łączą aktywność; pozostają zapisy acquisition/RPC/network.

**Procedura:** (1) zainstaluj i zweryfikuj utrzymywany wallet; (2) wykonaj backup i przetestuj seed recovery; (3) używaj nowego adresu dla każdego invoice; (4) lokalnie oznacz źródło/cel; (5) użyj coin control, aby nie łączyć kontekstów; (6) preferuj własny node lub privacy-aware connection; (7) sprawdź change/fees i zachowaj legalną księgowość.<sup>[[3]](#references)</sup>

**Wykrywanie:** address graph, heurystyki common-input/change z uwzględnieniem niepewności, exact amount/time, consolidation, service deposits, czas broadcastu node/RPC i zapisy off-chain.

## Bitcoin Silent Payments

**Mechanika:** BIP 352 pozwala odbiorcy publikować static code, podczas gdy senderzy wyprowadzają unikalne Taproot outputs przez ECDH; obserwatorzy zewnętrzni nie mogą bezpośrednio połączyć outputów z kodem.<sup>[[4]](#references)</sup>

**Zalety:** wielokrotnego użytku public identifier bez address reuse; brak interaktywnego żądania adresu lub notification output; wpisuje się w Taproot outputs.

**Wady:** koszt skanowania po stronie odbiorcy; różne wsparcie walletów; graf kwoty/sendera i spending pozostają publiczne; index server może obserwować skany.

**Procedura:** (1) wybierz aktualny wallet BIP 352; (2) wykonaj backup/test descriptor i scanning recovery; (3) wygeneruj opisany code, jeśli wspierany; (4) uwierzytelnij publikowany code; (5) sender sprawdza inputs i wysyła mały test; (6) receiver skanuje najlepiej przez własny node; (7) przechowuj otrzymane UTXO oddzielnie.

**Wykrywanie:** z założenia output sam w sobie nie jest niezawodnie identyfikowalny; analysts używają sender inputs, amount/time, późniejszego spending, wallet/network/index i zapisów counterparty.

## PayJoin

**Mechanika:** payer i payee wnoszą inputs do jednej payment transaction, łamiąc założenie, że wszystkie inputs mają jednego właściciela.<sup>[[5]](#references)</sup>

**Zalety:** zwykła płatność z lepszą prywatnością; korzyść dla całego grafu przez osłabienie common heuristic; nie wymaga equal-output crowd.

**Wady:** wymóg interaktywności/wsparcia; dostępność endpointu odbiorcy; kwota i final transaction są publiczne; implementation i fallback metadata.

**Procedura:** (1) potwierdź, że oba utrzymywane wallety obsługują tę samą wersję PayJoin; (2) uwierzytelnij invoice/endpoint; (3) rozpocznij z walletowego PayJoin-enabled payment URI; (4) sprawdź final amount/fee i podpisuj tylko oczekiwane inputs; (5) unikaj ręcznej edycji transakcji; (6) potwierdź broadcast i receipt; (7) zapisz fallback, jeśli negotiation się nie powiedzie.

**Wykrywanie:** blockchain analysts nie powinni wymuszać common-input clustering; endpoint/provider może logować negotiation; używaj danych wallet/network i późniejszego spending, a nie samego kształtu transakcji.

## CoinJoin

**Mechanika:** wielu uczestników wspólnie tworzy transaction z wieloma inputs/outputs, zwykle o równych nominałach, zwiększając niejednoznaczność mapowania input-output.

**Zalety:** większy on-chain ambiguity set; istnieją konstrukcje self-custodial; mierzalna struktura rund.

**Wady:** metadata coordinator/peer/network; fees/liquidity; rozpoznawalny transaction shape; toxic change i późniejsza consolidation niszczą korzyści; dostępność prawna/providera jest różna.

**Procedura:** (1) sprawdź aktualną dostępność wallet/coordinator i legalność; (2) zainstaluj official wallet i wykonaj backup; (3) używaj wyłącznie legalnych UTXO; (4) zrozum denomination, fee i model coordinatora; (5) oznaczaj i rozdziel change oraz mixed outputs; (6) nigdy nie konsoliduj ich razem; (7) kieruj traffic zgodnie z oficjalnym wsparciem i zachowaj accounting.

**Wykrywanie:** identyfikuj collaborative structure bez zakładania przestępstwa; obliczaj możliwe mappings/anonymity set, a następnie obserwuj change/consolidation, service boundaries i zapisy network/coordinator.

## Lightning Network

**Mechanika:** płatności HTLC przechodzą przez onion-routed channels; większość szczegółów płatności nie jest publikowana on-chain, lecz funding/closing i public channel information pozostają widoczne.

**Zalety:** szybkość, niska opłata; pośrednicy zwykle widzą sąsiednie hops; zwykłe szczegóły płatności pozostają off-chain.

**Wady:** sender/receiver i pierwszy/ostatni hop wiedzą więcej; probing, timing, channel graph, liquidity/wallet/LSP records; custodial wallety identyfikują użytkowników.

**Procedura:** (1) świadomie wybierz self-custodial lub custodial; (2) sprawdź wallet/seed/channel recovery; (3) używaj invoice dla dokładnej płatności; (4) korzystaj z private channels/LSP features dopiero po poznaniu tradeoffs; (5) chroń node IP przez wspierany Tor, gdy jest to potrzebne; (6) unikaj ponownego używania identyfikujących invoice; (7) prowadź accounting kanałów i płatności.<sup>[[6]](#references)</sup>

**Wykrywanie:** logi node/LSP/custodian, channel graph/probes, payment failure/timing oraz on-chain funding/closure; brak publicznej transakcji nie oznacza braku zapisów.

## BOLT 12 offers i route blinding

**Mechanika:** reusable offer tworzy świeże invoices i może reklamować blinded paths, dzięki czemu payer nie musi poznać jawnego node/path odbiorcy.

**Zalety:** prywatność odbiorcy; wielokrotnego użytku donation/payment endpoint bez static invoice; integracja z Lightning onion routing.

**Wady:** różne wsparcie walletów; endpoints, wybrane hops i funding pozostają; public contact lub network endpoint może ponownie zidentyfikować odbiorcę.

**Procedura:** (1) potwierdź zgodność wsparcia BOLT 12; (2) uwierzytelnij offer; (3) zażądaj świeżego invoice; (4) sprawdź amount/issuer/recurrence; (5) zapłać przez wallet; (6) potwierdź receipt/refund behavior; (7) ogranicz alias/contact node i zachowaj accounting.<sup>[[7]](#references)</sup>

**Wykrywanie:** telemetry wallet/LSP i first/last hop, konto dystrybucji offer, timing/value i funding graph; route blinding celowo ogranicza widoczność po stronie payera.

## Monero

**Mechanika:** one-time stealth addresses ukrywają powiązanie odbiorcy, RingCT ukrywa kwoty, a ring signatures zapewniają niejednoznaczność nadawcy.

**Zalety:** domyślna prywatność on-chain; poufność sender/receiver/amount; dojrzały ekosystem dedykowanych walletów/node.

**Wady:** zapisy acquisition/off-ramp i endpoint/network/counterparty; remote node widzi queries/IP; wsparcie exchange i traktowanie prawne są różne; drobne błędy operacyjne nadal łączą konteksty.

**Procedura:** (1) pozyskaj legalnie i zachowaj podstawę/źródło; (2) zainstaluj i zweryfikuj oficjalny utrzymywany wallet; (3) wykonaj backup/test seed; (4) użyj local node lub udokumentowanej ścieżki Tor/I2P remote-node; (5) używaj nowego subaddress dla każdego payer/invoice; (6) lokalnie oznaczaj konteksty; (7) ujawniaj transaction proof/view access tylko świadomie.<sup>[[8]](#references)</sup>

**Wykrywanie:** skup się na evidence z exchange/merchant/device/network i przejętego walleta; samo użycie protokołu nie jest podejrzane, a public chain celowo ujawnia mniej.

## Zcash fully shielded Orchard

**Mechanika:** zero-knowledge proofs potwierdzają shielded transfers, podczas gdy sender, receiver i amount są zaszyfrowane; transparent pools i przejścia między poolami pozostają publiczne.

**Zalety:** silna shielded on-chain confidentiality; viewing keys umożliwiają ograniczony audit; poprawność wymuszana przez protokół.

**Wady:** wsparcie wallet/exchange i wybór poola są różne; korelacja czasu/wartości na transparent boundary; pozostają network/RPC i endpoint.

**Procedura:** (1) wybierz utrzymywany Orchard shielded-by-default wallet; (2) zweryfikuj i wykonaj backup; (3) legalnie pozyskaj ZEC; (4) odbierz na wspierany Unified Address i potwierdź pool; (5) preferuj shielded-to-shielded; (6) używaj wspieranej network privacy; (7) przed audytem przetestuj ujawnienie viewing key na małym wallet.<sup>[[9]](#references)</sup>

**Wykrywanie:** transparent boundary i service records, wallet/network metadata oraz viewing keys, gdy są legalnie udostępnione; nie zakładaj, że każda płatność Unified Address była shielded.

## Mimblewimble i Litecoin MWEB

**Mechanika:** confidential transactions ukrywają kwoty, a agregacja w stylu Mimblewimble usuwa konwencjonalną historię bogatą w adresy; Litecoin implementuje opcjonalny extension block obok transparent chain.

**Zalety:** poufne kwoty i lepsza fungibility w prywatnej domenie; efektywne pruning/aggregation.

**Wady:** opt-in boundary peg-in/out jest publiczne i możliwe do korelacji; zależność od wallet/exchange; różnice modelu interaktywnego/adresowego; zapisy network i acquisition.

**Procedura:** (1) wybierz utrzymywany wallet z jawnym wsparciem MWEB; (2) zweryfikuj/wykonaj backup i przetestuj małą kwotę; (3) pozyskaj środki legalnie; (4) wykonaj peg do MWEB i sprawdź domenę salda; (5) transaktuj tylko z kompatybilnym odbiorcą; (6) unikaj natychmiastowego distinctive peg-out; (7) zachowaj prywatne audit records.<sup>[[10]](#references)</sup>

**Wykrywanie:** publiczne timing/value peg-in/out, dane exchange/wallet/node i późniejsze transparent spends; wewnętrzne szczegóły transferów confidential są celowo ograniczone.

## Ethereum zero-knowledge privacy applications

**Mechanika:** circuit dowodzi twierdzenia — membership, valid note ownership lub authorization — bez ujawniania sekretu; verifier contract sprawdza dowód. Deposits, withdrawals, public inputs, events i gas nadal mogą ujawniać powiązania.

**Zalety:** programowalne selective disclosure; aplikacje z anonymous set; weryfikowalne reguły bez ujawniania wszystkich danych.

**Wady:** błędy contract/circuit; mały anonymity set; public boundaries; RPC/IP/session/analytics/gas funding; ryzyko aplikacyjne i sankcyjne/prawne.

**Procedura:** (1) dokładnie określ, co proof ukrywa; (2) używaj audytowanej, utrzymywanej aplikacji, jeśli jest legalna; (3) sprawdź public inputs/events i reguły deposit/withdraw; (4) oddziel action wallet i gas sponsorship zgodnie z protokołem; (5) używaj privacy-aware RPC/network path; (6) testuj małą wartością; (7) zachowaj compliance records.<sup>[[11]](#references)</sup>

**Wykrywanie:** contract events, deposit/withdraw timing/value, relayer/paymaster, RPC/session, frontend storage/analytics i późniejsze granice exchange/merchant. Nie twierdź, że ZK proof ukrywa pola zadeklarowane jako publiczne.

## Stablecoins

**Mechanika:** tokeny transferują wartość na public chain; scentralizowani issuerzy mogą zamrażać/blacklistować lub realizować tokeny wobec zidentyfikowanych kont.

**Zalety:** stabilność ceny, liquidity i wsparcie merchantów; szybkie settlement; łatwe accounting.

**Wady:** transparentny graf address/amount/contract; gas funding; kontrola/tożsamość issuerów i exchanges; sanctions screening; zasadniczo słaba anonimowość.

**Procedura:** traktuj jako zidentyfikowaną płatność: używaj świeżego business address wyłącznie do compartmentation, zweryfikuj token contract/network, przetestuj małą kwotę, chroń wallet, używaj trusted RPC/local node, zachowaj basis/source i screenuj wymagane strony.

**Wykrywanie:** pełny token event graph, issuer freeze list/actions, exchange/RPC/device i relacje gas-funding.

## Cashu Chaumian e-cash

**Mechanika:** mint blind-signs sekrety bearer wygenerowane przez klienta, zabezpieczone rezerwami Bitcoin/Lightning mint; może zapobiegać double-spend bez bezpośredniego łączenia emisji z późniejszą realizacją.

**Zalety:** accountless bearer tokens; natychmiastowy transfer peer; mint nie może bezpośrednio połączyć blinded withdrawal ze spend; tokeny mogą być przesyłane jako dane/QR.

**Wady:** custody/solvency/censorship mint; utrata/kradzież danych bearer; denomination/timing i granice Lightning; metadata sieci; wczesny ekosystem software.<sup>[[12]](#references)</sup>

**Procedura:** (1) najpierw użyj official test mint lub niewielkiej disposable value; (2) zainstaluj utrzymywany wallet i przetestuj ograniczenia backup/restore; (3) uwierzytelnij mint i sprawdź custody/fees; (4) wyemituj małą kwotę; (5) wyślij token przez uwierzytelniony prywatny channel/QR; (6) receiver wymień token przed uznaniem go za finalny; (7) redeem i uzgodnij. Nigdy nie przechowuj istotnej wartości w niezaufanym mint.

**Wykrywanie:** mint widzi network, issue/redeem/Lightning boundaries i spent-token set, lecz blinding usuwa bezpośrednie token linkage; endpoints/messages oraz charakterystyczne amount/timing mogą przywrócić powiązania.

## Fedimint federated e-cash

**Mechanika:** quorum guardianów utrzymuje reserves i blind-signs e-cash; wewnętrzne bearer transfers są prywatne wobec guardianów, a Lightning gateways łączą płatności zewnętrzne.

**Zalety:** rozproszona custody; prywatny transfer wewnętrzny; community governance; pojedynczy guardian nie kontroluje reserve poniżej threshold.

**Wady:** ryzyko quorum/custody/software guardianów; gateway obserwuje invoices/timing; granice deposit/withdraw; złożone odzyskiwanie stanu klienta.

**Procedura:** (1) zweryfikuj federation invite/guardians/quorum/jurisdiction; (2) zainstaluj utrzymanego clienta i przetestuj recovery; (3) wpłać małą legalną kwotę; (4) używaj świeżych internal payment requests; (5) traktuj gateway jako obserwatora Lightning; (6) przetestuj redemption; (7) przechowuj source/tax records poza publicznymi danymi płatności.<sup>[[13]](#references)</sup>

**Wykrywanie:** federation widzi aggregate issuance/redemption, gateways widzą external invoices, Bitcoin/Lightning pokazują granice, a evidence endpoint/communication może połączyć transfery wewnętrzne.

## GNU Taler

**Mechanika:** zintegrowany z bankiem e-cash oparty na blind signatures ma zachować anonimowość płatnika wobec merchantów, podczas gdy merchant i dochód pozostają rozliczalne.

**Zalety:** privacy płatnika z założenia; zwykła waluta; accountability/refunds merchanta; brak potrzeby spekulacyjnego tokena.

**Wady:** ograniczone wdrożenia; exchange/bank widzi funding; merchant widzi order/delivery; ryzyko bearer wallet/recovery; regulowani operatorzy.

**Procedura:** (1) znajdź aktualny exchange/merchant dla jurysdykcji/waluty; (2) przeczytaj KYC/fees/privacy; (3) zainstaluj official wallet; (4) wypłać legalnie z obsługiwanego banku/exchange; (5) przejrzyj merchant contract; (6) zapłać i zachowaj receipt/refund data; (7) unikaj niepotrzebnych merchant session identifiers.<sup>[[14]](#references)</sup>

**Wykrywanie:** bank/exchange withdrawal i merchant deposit są rozliczalnymi granicami; merchant order/device/delivery i timing mogą korelować nawet przy blinded coins.

## Cross-chain bridge, atomic swap i decentralized exchange

**Mechanika:** contract/service blokuje lub spala jeden asset i uwalnia/emituje inny, albo counterparties dokonują atomic exchange. Rozbija to widok pojedynczego ledgeru, ale nie ciągłość ekonomiczną.

**Zalety:** interoperability asset/network; możliwość uniknięcia jednego scentralizowanego custodiana; zwykłe zastosowania portfolio/liquidity.

**Wady:** oba chains są publiczne; time/value/fees/liquidity i contracts korelują; zapisy bridge/relayer/frontend/RPC; ryzyko smart-contract/counterparty i regulacyjne.

**Procedura dla legalnych swapów:** (1) zweryfikuj official contract/service i legal availability; (2) sprawdź custody/audit/fees/slippage; (3) wykonaj mały test; (4) zapisz oba transaction IDs i rate; (5) chroń approvals; (6) uzgodnij asset docelowy i odwołaj zbędne approvals. Nie używaj swapów do ukrywania źródła środków.

**Wykrywanie:** bridge deposit/withdraw events, unikalna kwota pomniejszona o fees, kolejność czasowa, liquidity, relayer/RPC/frontend i późniejsze service deposits.

## Centralized mixer lub tumbler

**Mechanika:** usługa przyjmuje deposits do poola i później zwraca inne units, próbując ukryć bezpośrednie mapowanie input-output.

**Zalety:** teoretycznie może zwiększyć niejednoznaczność transakcji.

**Wady:** operator może kraść/logować; analiza timing/value wejścia/wyjścia; sankcje, money-transmission i ekspozycja kryminalna; seizures ujawniają mappings; ryzyko taint/rejection.

**Procedura:** nie podano operacyjnego przewodnika mieszania. Bezpiecznie odtwórz graf, rozszerzając [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): utwórz syntetyczne deposits, pooled outputs, fees i delays; przekaż analystom niepełne mappings; zmierz działanie heurystyk; następnie ujawnij ground truth.

**Wykrywanie:** identyfikacja service wallet/contract, candidate sets wejścia/wyjścia, amount/fee/timing, reuse adresów depozytowych, seized/provider logs i downstream consolidation. Atrybucję oznaczaj jako probabilistic.

## Peel chains, fan-out/fan-in i structuring

**Mechanika:** powtarzające się transakcje odcinają małe płatności z change, dzielą wartość na wiele adresów, ponownie łączą collectors lub dzielą kwoty w celu uniknięcia review.

**Zalety:** zwiększa obciążenie naiwnych analystów i liczbę adresów.

**Wady:** rozpoznawalna ciągłość value/cadence/transactions; consolidation i service endpoints; structuring może być samo w sobie nielegalne; fees i błędy operacyjne.

**Procedura:** używaj wyłącznie syntetycznych CSV/testnet data: generuj duże source, powtarzalne payment/change edges, równoległe branches i jeden collector; dodaj łagodne przykłady podobne do exchange; dostrajaj detection i dokumentuj false positives.

**Wykrywanie:** graph continuity, repeated change pattern, cadence, kwoty tuż poniżej kontroli, wspólny service endpoint i off-chain records. Exchange hot wallets mogą przypominać te wzorce, dlatego kontekst jest konieczny.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker i front company

**Mechanika:** inna osoba/account/company otrzymuje, konwertuje lub wydaje środki, wstawiając warstwy prawne i operacyjne między controllerem a transakcją.

**Zalety dla adversary:** nazwane konto nie identyfikuje od razu controllera; możliwość łączenia gotówki, crypto, dóbr i jurysdykcji.

**Wady:** ekspozycja na identity fraud/money laundering; każdy uczestnik dodaje communications, bank/company/tax/shipping records, fees, niespójności i świadków; ponowne używanie facilitatorów tworzy hubs.

**Procedura:** nie emuluj tego z prawdziwymi ludźmi/contami. Zbuduj syntetyczny graf z controllerem, recruiterem, mule, OTC, shell merchantem i beneficiary; dodaj edges device/IP/message/bank; poproś investigatorów o odróżnienie account holdera od controllera i zapisanie confidence evidence.

**Wykrywanie:** wspólne device/IP/recovery, nietypowy beneficiary/velocity, wielu niepowiązanych senderów, natychmiastowy onward movement, niespójność company/director/invoice, communications oraz dostawa gotówki/commodity.

## NFTs, gambling, merchant goods i refund loops

**Mechanika:** wartość jest konwertowana na self-priced asset, saldo bettingowe, odsprzedawalne towary lub refund, aby stworzyć inną narrację transakcyjną.

**Zalety dla adversary:** zmiana formy aktywa i wprowadzenie pośredników marketplace/merchant.

**Wady:** graf marketplace/account/device i wash-trade; records odds/play/refund; evidence delivery/resale; fees/losses; odpowiedzialność fraud/laundering.

**Procedura:** brak workflow ukrywania. Używaj syntetycznych marketplace data z related-wallet self-trades, nieprawdopodobnymi cenami, minimalnym play, mismatched refund instrument i wspólną wysyłką; waliduj detection wobec legalnych collectors/customers.

**Wykrywanie:** circular/self-funded trades, common ownership/funding, price outliers, immediate resale/refund, minimal economic activity, wspólne device/delivery i ponowna konwergencja proceeds.

## Physical bearer wallet lub offline token transfer

**Mechanika:** urządzenie, paper/QR, hardware bearer instrument lub e-cash token przekazuje kontrolę nad sekretem zamiast broadcastować płatność przy handover.

**Zalety:** brak bieżącego network event podczas wymiany; użycie offline; custody podobne do gotówki fizycznej.

**Wady:** copy/kradzież/utrata i niepewna wyłączność; późniejsze redemption/broadcast może powiązać; spotkanie/wysyłka fizyczna; ryzyko counterfeit/tampering.

**Procedura:** (1) używaj wyłącznie sprawdzonego instrumentu/protokołu; (2) prywatnie zainicjalizuj i zweryfikuj autentyczność; (3) załaduj tylko małą legalną wartość; (4) przeprowadź transfer w udokumentowanym, autoryzowanym kontekście; (5) odbiorca szybko zweryfikuje lub sweepnie token zgodnie z protokołem; (6) nigdy nie zakładaj, że sender nie zachował kopii; (7) prywatnie zapisz ownership/tax evidence.

**Wykrywanie:** purchase/funding i późniejszy sweep/redemption, serial urządzenia/evidence tampering, delivery/meeting i endpoint records.

## Merchant-scoped invoice lub one-time payment request

**Mechanika:** merchant tworzy jednorazowe żądanie z kwotą, expiry i order reference. Payer rozlicza je przez obsługiwany rail bez bezpośredniego ujawniania merchantowi reusable credential; issuer/payment processor nadal może identyfikować obie strony.

**Zalety:** ogranicza reuse credential i przypadkowe cross-merchant identifiers; exact amount/expiry zmniejszają błędy; kompatybilne z accounting i refunds.

**Wady:** invoice, delivery, browser, processor i issuer nadal łączą order; unikalna kwota/czas może wzmocnić korelację; złośliwe payment links są częste.

**Procedura:** (1) niezależnie uwierzytelnij merchanta; (2) poproś o świeży invoice z dokładną kwotą, asset/network i expiry; (3) sprawdź destination i refund rules; (4) zapłać z zatwierdzonego engagement compartment; (5) potwierdź, że merchant uznaje ten sam invoice; (6) zachowaj receipt i transaction reference; (7) wygaszaj zamiast ponownie używać request.

**Wykrywanie:** merchant i processor łączą invoice, session i settlement; unikalne amounts/timing i delivery identyfikują płatnika. **Captured wallet/device:** historia invoice ujawnia counterparties i cel; ogranicz memo data, zaszyfruj urządzenie i trzymaj authoritative accounting w kontrolowanym finance system.

## Prepaid service credit i capability token

**Mechanika:** usługa zamienia konwencjonalną płatność na ograniczone credits wewnętrzne lub bearer capability. Późniejsze użycie API/resource może nie przedstawiać oryginalnej karty przy każdym żądaniu, ale usługa zwykle może mapować issuance na redemption.

**Zalety:** ogranicza spend i straty po compromise; oddziela codziennych workers od credentialu finansującego; umożliwia budżety per-project i revocation.

**Wady:** zwykle pseudonimowość, nie anonimowość; service database, redemption IP i unikalny usage pattern łączą aktywność; bearer tokens mogą zostać skradzione; refunds mogą wymagać pierwotnego płatnika.

**Procedura:** (1) kup credits przez organization account; (2) utwórz jeden project i budget; (3) wydaj wąski token z ograniczeniami service/amount/expiry; (4) przechowuj go wyłącznie w zatwierdzonym secret managerze lub workload identity path; (5) przetestuj odrzucenie poza zakresem i po expiry; (6) monitoruj consumption; (7) revoke i uzgodnij niewykorzystaną wartość.

**Wykrywanie:** provider łączy funding account, project, token issuance i usage; defenders alertują na zmiany geograficzne/process oraz anomalous consumption. **Captured node:** zakładaj, że jego pozostała capability może zostać wydana; stosuj krótki expiry, niski balance, audience binding i natychmiastowe server-side revocation.

## Privacy Pass lub blinded authorization token

**Mechanika:** issuer tworzy privacy-preserving authorization token, który origin może zweryfikować bez łączenia redemption z issuance. Może reprezentować opłacone uprawnienie lub limitowany dostęp, lecz nie jest ogólną walutą. Architektura rozdziela role client, attester, issuer i origin oraz ostrzega, że IP/timing lub collusion może zniszczyć unlinkability.<sup>[[18]](#references)</sup>

**Zalety:** unlinkable redemption dla wspieranych usług; brak reusable account cookie u origin; cached tokens mogą czasowo oddzielać issuance i use.

**Wady:** zależność od aplikacji; zaufanie do issuer/attester i partycjonowanie anonymity set; pozostają IP i browser metadata; kradzież tokena lub charakterystyczny issuance timing może korelować użycie.

**Procedura:** (1) użyj implementacji zgodnej z właściwym Privacy Pass token type; (2) określ dokładnie entitlement potwierdzany przez token; (3) rozdziel administrację issuer i origin, gdy wymaga tego threat model; (4) ogranicz challenge metadata; (5) wydaj kilka tokenów testowych i raz zrealizuj każdy we własnych origins; (6) porównaj logi pod kątem zakazanych stable identifiers; (7) przetestuj replay, expiry oraz revocation/abuse controls.

**Wykrywanie:** origins widzą redemption IP/time i token validity; issuers/attesters widzą issuance context; analysts testują timing i metadata partitions bez zakładania cryptographic break. **Captured client:** niewydane bearer tokens mogą być użyte; ogranicz ich wartość, lifetime i audience, a credentialu finansującego nigdy nie cache'uj razem z nimi.

## Delegated organization procurement lub fiscal sponsor

**Mechanika:** autoryzowany procurement team, reseller lub fiscal sponsor zawiera umowę i płaci, a operational team otrzymuje ograniczoną usługę. Jest to role separation z prawdziwymi zapisami, nie nominee ani false identity.

**Zalety:** vendors nie muszą otrzymywać tożsamości każdego operatora ani jego osobistych danych płatniczych; central compliance, podatki i refunds; jasny budget/offboarding.

**Wady:** sponsor zna beneficiary i purpose; contracts, approvals, delivery i accounts pozostają; opóźnienia/opłaty; słaba separacja, gdy ta sama osoba administruje każdą warstwą.

**Procedura:** (1) udokumentuj business purpose, beneficiary i approving authority; (2) wybierz organization-approved intermediary; (3) zawrzyj umowę pod prawdziwymi danymi; (4) udostępnij project-scoped subaccount bez personal billing credential; (5) oddziel finance administrators od operators; (6) uzgodnij invoices/access; (7) przy closeout zakończ service i delegated access.

**Wykrywanie:** procurement, identity-provider, vendor i delivery records łączą cały chain. **Captured operational device:** powinien ujawniać service project, ale nie finance credentials; invoices i payer identities trzymaj w finance system, nie na field nodes.

## Escrow lub conditional settlement

**Mechanika:** zaufany escrow agent lub smart contract przechowuje wartość do spełnienia udokumentowanych warunków. Może ograniczyć bezpośrednie ujawnienie między payerem i payee, lecz escrow i rails płatnicze zachowują relację.

**Zalety:** ochrona sporu i dostawy; payer i merchant mogą ujawniać sobie mniej reusable credentials; audytowalne warunki release.

**Wady:** custody/contract risk escrow, opłaty i obowiązki identyfikacyjne; on-chain contracts są publiczne; order, shipping i dispute data pozostają; brak anonimowości wobec intermediary.

**Procedura:** (1) zweryfikuj legal entity, custody, fees, dispute forum i supported assets; (2) utwórz dokładny pisemny milestone i refund path; (3) finansuj z zatwierdzonego organization account; (4) niezależnie zweryfikuj receipt i release authorization; (5) release tylko po evidence; (6) zachowaj pełny audit record; (7) zamknij niewykorzystane permissions/contract approvals.

**Wykrywanie:** escrow account/contract events, funding/release time, beneficiary i dispute records ujawniają transakcję. **Captured device:** session tokens lub contract approvals mogą umożliwić release; wymagaj oddzielnego approvera/MFA i revoke aktywnych sessions po utracie.

## Batched lub pooled organization settlement

**Mechanika:** wiele zatwierdzonych zobowiązań agreguje się i rozlicza w mniejszej liczbie transactions bankowych/blockchainowych, z prywatnym ledgerem przypisującym każdą część. Batching może ograniczyć publiczny detail per purchase, ale coordinator zachowuje pełną atrybucję.

**Zalety:** niższe fees; mniej public graph edges; ukrycie pojedynczych line items przed publicznym obserwatorem po agregacji; proste wewnętrzne accounting.

**Wady:** coordinator jest pełnym obserwatorem i cennym celem; distinctive totals/timing mogą korelować; custody/reconciliation risk; nadużycie może przypominać structuring.

**Procedura:** (1) zdefiniuj participants i legal obligations w accounting system; (2) ustal regularne, biznesowo uzasadnione batch window, a nie progi mające omijać kontrole; (3) wymagaj dual approval aggregate; (4) rozliczaj z uwierzytelnionymi recipients; (5) uzgodnij każdą internal line z batchem; (6) traktuj refunds jako linked corrections; (7) chroń ledger access i zachowaj go zgodnie z polityką.

**Wykrywanie:** coordinator ledger, approval i beneficiary records dają ground truth; public analysts ostrożnie używają clusteringu input/output/value/time. **Captured payer device:** powinien zawierać wyłącznie requisition, nie pool signing key ani participant ledger.

## Account-abstraction paymaster lub sponsored gas

**Mechanika:** relayer/bundler przesyła smart-account operation, a paymaster opłaca transaction fees, eliminując bezpośrednią native-gas funding edge z user wallet. Poprawia jedną właściwość grafu, lecz operation, contract i service telemetry pozostają publiczne lub obserwowalne.<sup>[[19]](#references)</sup>

**Zalety:** usuwa typowe gas-funding link; umożliwia scoped sponsorship i rate limits; ułatwia onboarding legalnych privacy applications.

**Wady:** paymaster/bundler/RPC/frontend może korelować requests; contract events i public inputs pozostają; sponsorship policy tworzy fingerprint cohort; złośliwe contracts/approvals mogą kraść assets.

**Procedura:** (1) używaj audytowanego smart account i paymaster na właściwej sieci; (2) sprawdź public fields i logs sponsora; (3) ogranicz sponsorship przez contract, function, amount, nonce i expiry; (4) testuj małą wartością; (5) wysyłaj przez zamierzoną privacy-aware path aplikacji; (6) zweryfikuj operation i fee payer on-chain; (7) revoke allowances/session keys i zachowaj compliance records.

**Wykrywanie:** łącz UserOperation, EntryPoint, paymaster, bundler/RPC i application logs; ostrożnie grupuj identyczne sponsorship policies. **Captured wallet:** session keys i pending approvals mogą być użyte nawet bez gas; ogranicz je i revoke przez recovery policy konta.

## Threshold lub multisignature payment authorization

**Mechanika:** spending wymaga threshold niezależnych signerów. Nie ukrywa transakcji, ale oddziela payment authority od przejętego laptopa, field node lub pojedynczego operatora.

**Zalety:** silna odporność na compromise i insiderów; accountable approval; pojedyncze field device nie posiada pełnej signing authority; recovery.

**Wady:** coordination i availability; metadata signer/device/account może korelować uczestników; zły backup powoduje utratę; publiczne multisig patterns mogą być rozpoznawalne.

**Procedura:** (1) przed fundingiem określ signers, threshold, limits i recovery; (2) inicjalizuj na oddzielnym supported hardware/accounts; (3) niezależnie zweryfikuj addresses i backups; (4) daj field workloads wyłącznie unsigned requisition capability; (5) wymagaj out-of-band review recipient, amount i purpose; (6) przetestuj recovery i utratę jednego signera na małej wartości; (7) po compromise rotuj signera.

**Wykrywanie:** approval system, signer device i public script/contract dostarczają evidence; defenders alertują na policy lub signer-set changes. **Captured node:** powinien ujawnić najwyżej jeden low-authority session key lub unsigned request; nigdy nie cache'uj quorum material razem.

## Closed-loop community lub event currency

**Mechanika:** cooperative, conference lub private test environment wydaje credits realizowane wyłącznie między enrolled participants. Internal transfer może ujawniać mniej globalnym payment networks, lecz operator kontroluje issuance i redemption.

**Zalety:** ograniczona domena ekonomiczna; możliwość testowania offline/privacy-preserving payment UX; ograniczona ekspozycja zewnętrznej karty; jasne experimental controls.

**Wady:** mały anonymity set; operator i merchant obserwują aktywność; ograniczona akceptacja/redemption; licencje, consumer protection i tax rules mogą mieć zastosowanie także do lokalnej wartości.

**Procedura:** (1) uzyskaj legal/compliance review i opublikuj issuer terms; (2) zapisz consenting test participants; (3) ogranicz issuance i zabroń cash-like misuse; (4) używaj świeżych payment requests i minimalizuj public participant identifiers; (5) zapisuj aggregate reserves i prywatne individual receipts; (6) testuj loss/refund/redemption; (7) zamknij ledger i zwróć residual value zgodnie z obietnicą.

**Wykrywanie:** issuer ledger, enrollment, merchant i redemption records odtwarzają przepływy; nietypowe circular transfers lub rapid cash-out wymagają review. **Captured wallet:** może ujawnić lokalne saldo i counterparties; ogranicz wartość, szyfruj state i wspieraj issuer-side freeze/reissue z audytowalnym zapisem.

## Bitcoin reusable payment codes i private payment instructions

**Mechanika:** BIP 47 payment codes używają reusable public identifier oraz ECDH-derived one-time deposit addresses; BIP 351 opisuje nowszy private-payment instruction design. Ograniczają public address reuse, umożliwiając odbiorcy publikowanie stabilnych payment instructions. Notification, wsparcie walleta, funding i późniejszy coin selection nadal wpływają na prywatność.<sup>[[20]](#references)</sup>

**Zalety:** jeden public instruction może generować różne addresses; odbiorca nie musi publikować każdego invoice address; kompatybilne wallety mogą monitorować derived payments; użyteczne dla powtarzalnych legalnych donors/customers.

**Wady:** różna interoperacyjność walletów; notification transactions lub public payment code łączą relationship context; sender, recipient i public graph nadal widzą transactions; niedbała consolidation/change handling niweluje korzyść.

**Procedura:** (1) potwierdź, że oba utrzymywane wallety obsługują tę samą specification/version; (2) wykonaj backup i recovery test na low-value wallet; (3) uwierzytelnij recipient payment code out-of-band; (4) wyślij mały legalny test; (5) sprawdź użycie świeżego derived address; (6) lokalnie oznacz relację i stosuj coin control; (7) przed użyciem produkcyjnym przetestuj recovery i refund behavior.

**Wykrywanie:** analysts badają notification patterns, funding/change, późniejszą consolidation i service boundaries; publikacja public code identyfikuje recipient context, nawet gdy deposit addresses są różne. **Capture-resilient OPSEC:** trzymaj spend keys poza field devices i ujawniaj najwyżej watch-only relationship view. **Monitoring:** alertuj na nieoczekiwane notification transactions, reused derived addresses, wallet gap-limit/recovery errors i nieplanowaną consolidation.

## EVM stealth addresses (ERC-5564)

**Mechanika:** sender wyprowadza one-time stealth account z stealth meta-address odbiorcy i publikuje announcement z ephemeral public key oraz view tag. Receiver skanuje announcements za pomocą viewing key i wyprowadza corresponding spend key. Powiązanie odbiorcy jest lepsze, ale sender, amount/token, gas, announcement i późniejsze spending pozostają widoczne.<sup>[[21]](#references)</sup>

**Zalety:** non-interactive fresh receiver address; reusable meta-address; oddzielne viewing/spending roles; działanie z obsługiwanymi EVM assets/applications.

**Wady:** announcement scanning i spam; finansowanie gas nowego adresu może ponownie go powiązać; sender zna recipient; public token/amount i późniejsza consolidation pozostają; różne wsparcie implementacji/walletów.

**Procedura:** (1) najpierw użyj audytowanej implementacji na test network; (2) wygeneruj oddzielne viewing/spending material i wykonaj backup; (3) uwierzytelnij meta-address; (4) wyślij low-value test i announcement; (5) zeskanuj i wyprowadź stealth account; (6) przetestuj supported gas sponsorship bez personal funding edge; (7) zapisz public fields i zachowaj legal accounting.

**Wykrywanie:** śledź announcement caller, token/amount, timing, gas sponsor, spending i consolidation; view key może dowieść receipt bez nadania spend. **Capture-resilient OPSEC:** networked scanner powinien mieć tylko viewing role, jeśli wspierana; spend i recovery keys trzymaj gdzie indziej. **Monitoring:** alertuj na malformed/spam announcements, view-key access, unexpected spend derivation i stealth outputs moved bez approval.

## Liquid Confidential Transactions

**Mechanika:** Liquid domyślnie blinds output amounts i asset types za pomocą commitments/proofs, pozostawiając widoczne transaction graph, input/output count, fee i block time. Peg-in/peg-out oraz service boundaries pozostają linkowalne, a użytkownicy mogą selektywnie ujawniać blinding data.<sup>[[22]](#references)</sup>

**Zalety:** confidential amount i asset type domyślnie; szybki sidechain settlement; selective audit przez blinding keys/descriptors; ukrycie wrażliwych wartości komercyjnych przed public observer.

**Wady:** graph structure i timing pozostają; federation/bridge i exchange trust; peg boundaries i unconfidential outputs; wallet/node/network records; sender i receiver znają swoją transakcję.

**Procedura:** (1) wybierz utrzymywany Liquid wallet i sprawdź model backupu; (2) użyj testnet lub małej legalnej kwoty; (3) odbierz na confidential address i potwierdź, że wallet oznacza output jako blinded; (4) wyślij testową confidential transaction; (5) sprawdź, jakie explorer fields pozostają publiczne; (6) eksportuj tylko zakres blinding proof potrzebny do audytu; (7) udokumentuj peg/exchange boundaries i uzgodnij środki.

**Wykrywanie:** analizuj visible graph/fee/time, peg i exchange records, network metadata oraz późniejsze unblinding evidence; nie wyprowadzaj ukrytej amount/asset. **Capture-resilient OPSEC:** oddziel spend seed, blinding/view data i watch-only operations. **Monitoring:** alertuj na accidental unconfidential addresses, unknown peg requests, descriptor changes i niezatwierdzony blinding-key export.

## General payment lub state channel

**Mechanika:** uczestnicy blokują funds, wymieniają podpisane off-chain state updates i publikują on-chain tylko opening, closing lub disputed state. Intermediate payments nie są globalnie broadcastowane, lecz peers i routing/intermediary services widzą swoją część, a endpoints muszą zachować ostatni enforceable state.<sup>[[23]](#references)</sup>

**Zalety:** wiele szybkich, niskokosztowych interakcji prywatnych wobec public ledger; mniej globalnych transaction details; ograniczone channel balance; użyteczne dla metered services i repeated counterparties.

**Wady:** channel peers znają się i mogą zachowywać updates; opening/closing/value/timing korelują; monitoring online może być wymagany podczas challenge windows; implementation/liquidity risk; sam kanał nie daje dużego anonymity set.

**Procedura:** (1) wybierz utrzymywaną, audytowaną implementację i poznaj dispute window; (2) otwórz low-value test channel między własnymi parties; (3) wymieniaj signed state updates z unikalnymi nonces; (4) wykonaj backup latest enforceable state; (5) zamknij kooperacyjnie; (6) przećwicz stale-state rejection na testnet; (7) zachowaj accounting i channel-peer records.

**Wykrywanie:** public chain pokazuje lifecycle/disputes; peers, watch services i application transport ujawniają off-chain timing/parties. **Capture-resilient OPSEC:** ogranicz hot balance i przechowuj latest signed state w zaszyfrowanym, odzyskiwalnym storage oddzielonym od field nodes. **Monitoring:** stale-state publication, missed backup, peer-key change i zbliżający się challenge deadline wymagają ciągłego monitoringu.

## Mobile carrier billing

**Mechanika:** online service obciąża mobile subscription lub prepaid balance przez carrier billing. Merchant może otrzymać carrier authorization zamiast danych karty/banku, podczas gdy carrier zna subscriber/line, device/network context, merchant, amount i time.<sup>[[24]](#references)</sup>

**Zalety:** brak numeru karty u merchanta; szeroka dostępność telefoniczna; użyteczne dla niskowartościowych dóbr cyfrowych; carrier może ograniczać i odwracać charges.

**Wady:** silna identyfikacja przez SIM/account i często urządzenie; małe limity i wysokie opłaty; ograniczenia kategorii merchantów; ryzyko account takeover/SIM-swap; carrier i aggregator tworzą pełny trail.

**Procedura:** (1) potwierdź availability, limit, fee i refund terms z organization carrier account; (2) włącz tylko na dedykowanej organization line, jeśli uzasadnione; (3) ustaw najniższy użyteczny spend cap; (4) kup benign test item; (5) zweryfikuj merchant/carrier receipts; (6) wyłącz recurring authorization; (7) uzgodnij i wyłącz funkcję po assessment.

**Wykrywanie:** carrier, aggregator i merchant records łączą line, subscriber, IP/device i charge; enterprise telecom invoices ujawniają użycie. **Capture-resilient OPSEC:** nie używaj osobistego numeru i wymagaj carrier-account MFA poza field device. **Monitoring:** włącz instant charge/SIM-change alerts i zatrzymaj się przy nieoczekiwanym premium-service enrollment, forwarding lub account recovery.

## Open-banking payment initiation

**Mechanika:** za wyraźną zgodą użytkownika regulowany PISP prosi bank prowadzący konto o zainicjowanie transferu. Merchant może nie otrzymać card credentials, ale PISP i banki przechowują regulowane records płatnika, payee, consent, device i transaction.<sup>[[25]](#references)</sup>

**Zalety:** brak reusable card number przy checkout; silne bank authentication; dokładny account-to-account settlement; consent/status APIs; przejrzyste reconciliation.

**Wady:** brak anonimowości wobec banków/PISP; payee często widzi legal account details lub reference; phishing/redirect risk; różne jurysdykcje i refund protection; consent metadata dodaje kolejnego obserwatora.

**Procedura:** (1) sprawdź, czy PISP jest aktualnie regulowany, a merchant callback domain autentyczny; (2) zacznij od merchant request; (3) w banku sprawdź payee, amount, reference i żądany consent; (4) autoryzuj tylko pojedynczą payment; (5) niezależnie potwierdź final status; (6) revoke residual consent, jeśli istnieje; (7) zachowaj receipt i uzgodnij.

**Wykrywanie:** bank/PISP/merchant logs i transfer references zapewniają silną atrybucję. **Capture-resilient OPSEC:** trzymaj bank authentication i recovery poza operational/field devices; urządzenie powinno posiadać tylko paid-service entitlement. **Monitoring:** używaj bank transaction/consent alerts i badaj nowe PISP grants, zmienionego payee lub status callbacks poza oczekiwaną sesją.

## Platform wallet, app-store balance lub in-app credit

**Mechanika:** platforma obciąża użytkownika lub realizuje account credit, a następnie wydaje signed receipt/entitlement aplikacji. Developer aplikacji może nie otrzymać pierwotnego funding instrument, lecz platforma mapuje account, device, funding, product i redemption.<sup>[[26]](#references)</sup>

**Zalety:** merchant/developer nie otrzymuje primary PAN; fraud/refund i family/business controls; małe prepaid balance ogranicza ekspozycję; signed receipts ułatwiają entitlement verification.

**Wady:** platform account jest silnym hubem identity/behavior; device i storefront geography; gift-balance purchase/redemption trail; ograniczony cash-out; fraud controls mogą zamrozić funds; brak cross-platform money.

**Procedura:** (1) używaj organization-managed platform account, gdy polityka na to pozwala; (2) sprawdź funding, region, refund i transferable-value rules; (3) dodaj wyłącznie zatwierdzony budget; (4) kup benign product przez official store; (5) sprawdź, czy app otrzymuje tylko oczekiwane receipt fields; (6) wyłącz recurring purchase; (7) uzgodnij i usuń account z operational hardware.

**Wykrywanie:** platform receipts/server notifications, account/device login i funding records odtwarzają zakup. **Capture-resilient OPSEC:** nigdy nie loguj field node do personal store account; gdzie możliwe, przekazuj wyłącznie scoped app entitlement. **Monitoring:** włącz new-device/purchase alerts i badaj receipt replay, family/account changes oraz unexpected restore events.

## Mutual credit, clearing lub periodic net settlement

**Mechanika:** uczestnicy zapisują zobowiązania w prywatnym ledgerze i okresowo rozliczają tylko pozycję netto. Pojedyncze service events nie muszą tworzyć oddzielnych public payments, lecz operator ledgeru i counterparties zachowują szczegółową atrybucję.

**Zalety:** mniej zewnętrznych transakcji i opłat; public observers widzą tylko net settlement; przydatne dla powtarzalnych organizations; jawne credit limits ograniczają ekspozycję.

**Wady:** scentralizowany ledger jest pełnym dowodem i celem fraud; ryzyko counterparty/default; obowiązki prawne/accounting/tax; mała membership set; nietypowe net transfers nadal mogą ujawniać relacje.

**Procedura:** (1) używaj wyłącznie zidentyfikowanych, wyrażających zgodę organizations po legal/accounting approval; (2) określ unit, credit limit, settlement interval i dispute rules; (3) zapisuj każde zobowiązanie z immutable approval; (4) oddzielne finance roles obliczają i zatwierdzają net positions; (5) rozliczaj zwykłym legalnym railem; (6) uzgadniaj individual lines z settlement; (7) zamknij dostęp i przechowuj zapisy zgodnie z polityką.

**Wykrywanie:** ledger, invoices, approvals i final bank/chain settlement dają ground truth; analysts nie powinni wyprowadzać brakującej gross activity wyłącznie z net transfer. **Capture-resilient OPSEC:** operational devices mogą składać ograniczone requisitions, ale nie edytować balances ani autoryzować settlement. **Monitoring:** alertuj na credit-limit breach, backdated entries, administrator changes, reconciliation mismatch i settlement do nowego beneficiary.

## Capture/compromise exposure matrix

Dotyczy to każdego rodzaju techniki. Celem jest ograniczenie spend authority i ujawnienia niezwiązanej tożsamości przy zachowaniu legal accounting — nie usuwanie transakcji ani udaremnianie śledztwa.

| Rodzina techniki | Co może ujawnić przejęty wallet/device/account | Minimalna autoryzowana kontrola |
|---|---|---|
| Cash, money order, COD, physical bearer value | paragony, seriale, notatki, pozostała wartość bearer i kontakty fizyczne | tylko zatwierdzona kwota; oddzielne accounting; szybkie zgłoszenie utraty; brak fałszywych zapisów |
| Prepaid, gift, voucher, service credits | saldo, issuer, aktywacja, realizacja i account/session tokens | niskie saldo; jeden cel; prawdziwa rejestracja; issuer freeze/revocation, jeśli dostępne |
| Virtual/tokenized card, wallet token, payment app | konto issuera, device token, transakcje, recovery i merchant history | device lock; transaction alerts; merchant scope; remote issuer suspension; brak wspólnego recovery account |
| Bank compartment, delegated procurement, red-team procurement | organization, approvers, vendor, invoices i project | role separation; least-privilege subaccount; finance credentials nigdy na operational/field nodes |
| Invoice, escrow, batch settlement | counterparty, purpose, pending approval, coordinator lub dispute trail | single-use request; oddzielny approver; ograniczona sesja; central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, addresses, transaction graph i network configuration | hardware/offline signing; encrypted wallet; ograniczenia passphrase; watch-only field view; documented recovery |
| Lightning/BOLT 12 | seed, channels, invoices, peers/LSP i payment database | minimal hot balance; encrypted backup; oddzielna node identity; close/recover zgodnie z planem |
| Monero, Zcash, MWEB, ZK applications | spend/view keys, local wallet history, RPC i boundary transactions | oddzielne spend/view roles; hardware support; brak exchange session na field node |
| Stablecoins, swaps, bridges i DEX | transparent graph, approvals, RPC/front-end state i destination assets | revoke allowances; verified contracts; low-value test; pełne reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, issuance/redemption cache | małe saldo; encrypted backup zgodnie z protokołem; redeem/reissue; nie łącz funding credential |
| Paymaster, multisig/threshold | session key, jeden signer, pending operations i sponsor policy | narrow session key; niezależny quorum; signer rotation; field device bez dostępu do threshold |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider, communications, graph i participant records | brak użycia operacyjnego; tylko synthetic/testnet emulation |
| Community/event currency | enrollment, local balance, counterparties i redemption | capped value; issuer freeze/reissue; consent i prywatny audytowalny ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys, relationship metadata, announcements i derived outputs | watch/view-only network role; offline/hardware spend role; brak personal funding session |
| Liquid confidential/state channels | seed, blinding data/latest state, peers, boundaries i disputes | oddzielne spend/view/state backups; low hot balance; niezależny dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account, consent, receipt, device i funding source | organization account; external MFA; low limit; brak personal account na field hardware |
| Mutual-credit clearing | members, obligations, limits, approvals i settlement ledger | wyłącznie operational requisition; oddzielny immutable ledger i dual finance approval |

## Monitoring possible discovery or payment compromise

Odmowa płatności, compliance review lub przejście walleta offline nie dowodzi istnienia śledztwa. Monitoruj wyłącznie accounts, ledgers i infrastructure, które organizacja ma prawo obserwować; nigdy nie sonduj providerów ani counterparties, aby sprawdzać, czy współpracują z investigatorami.

| Objęte techniki | Bezpieczne sygnały monitoringu | Warunek freeze/stop |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch, duplicate serial, unexpected redemption/refund lub loss report | missing instrument, redemption poza zatwierdzonym order, altered receipt lub custody break |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alerts, new device/consent/payee, token reuse, SIM/account recovery | unknown authorization, payee change, new recovery factor, SIM swap lub recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project, role/token/budget change, invoice i consumption | cross-project token, unknown admin, limit breach, invoice mismatch lub unsupported destination |
| Invoice, escrow, pooled settlement, mutual credit | request expiry, approval/release, ledger integrity, reconciliation i beneficiary change | altered amount/payee, backdated ledger, unilateral release lub unreconciled batch |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transactions, notification/scan state, address reuse, UTXO labels i consolidation | unknown spend, reused recipient output, wallet gap/recovery failure lub unapproved merge |
| PayJoin/CoinJoin | proposal inputs/outputs/fees, coordinator availability, final transaction equality | substituted output, excessive fee, unexpected input disclosure lub coordinator policy change |
| Lightning/BOLT12/general channels | channel backup, invoice/offer use, liquidity, peer/LSP i chain dispute | unknown invoice payment, peer-key change, stale close lub approaching dispute deadline |
| Monero/Zcash/MWEB/Liquid CT | view/watch events, pool/domain/address type, descriptor i boundary transaction | spend bez approval, transparent/unconfidential downgrade, key export lub unknown boundary |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session key i issuer action | wrong contract/public field, unknown approval/spend, paymaster change lub issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health, token double-spend/replay, gateway i bearer balance | unknown redemption, mint key/terms change, restore failure lub balance inconsistency |
| Swaps/bridges/DEX | verified contract, allowance, both-chain confirmations, rate i destination | contract/route mismatch, unlimited approval, missing destination lub bridge incident |
| Multisig/threshold | signer-set/policy change, pending proposal, quorum i recovery audit | unknown proposal/signer, threshold reduction, recovery activation lub policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | wyłącznie synthetic lab ground truth i detection output | jakiekolwiek real account, person lub value wchodzące do emulacji: natychmiast stop |

## Selection and verification workflow

1. Określ, która strona nie może poznać którego pola.
2. Zidentyfikuj issuer/mint/custodian, public ledger, network/RPC, merchant i physical observers.
3. Zweryfikuj aktualne wsparcie, legalność, limity, custody, recovery i refund behavior.
4. Wykonaj mały, legalny end-to-end test.
5. Sprawdź merchant receipt, provider statement, public chain oraz wallet/node logs.
6. Przetestuj backup/recovery i zamierzone audit disclosure.
7. Prowadź wymagane source, ownership, tax, sanctions i engagement records jako prawdziwe, lecz kontroluj do nich dostęp.

## References

- [1] [EMVCo — Tokenizacja płatności](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Obserwacje dotyczące gromadzenia danych przez duże platformy płatnicze](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Chroń swoją prywatność](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Prosta propozycja Payjoin](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Protokół Onion Routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Specyfikacje techniczne i prywatność sieci](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Tworzenie aplikacji prywatności z użyciem zero-knowledge proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protokół i ograniczenia prywatności](https://docs.cashu.space/faq)
- [13] [Fedimint — Jak to działa](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Wskaźniki ryzyka dotyczące Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administratorzy, exchangers i użytkownicy virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — Informacje o transferach i crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — Architektura Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State and payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
