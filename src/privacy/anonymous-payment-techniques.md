# Katalog technik anonimowych płatności

{{#include ../banners/hacktricks-training.md}}

Ten katalog obejmuje **rodziny** płatności — od zwykłej gotówki, przez e-cash z blind signatures, po zaciemnianie transakcji w publicznych łańcuchach. „Anonimowość” zawsze oznacza anonimowość względem określonego obserwatora. Merchant, issuer, mint, exchange, blockchain analyst, network provider, employer i obserwator fizyczny widzą różne informacje.

Poniższe procedury dotyczą legalnych środków, prawdziwych danych oraz autoryzowanych zakupów. Techniki, których celem w przytoczonych przypadkach było pranie pieniędzy, omijanie sankcji lub fraud tożsamości, są objaśniane i wykrywane, ale ich procedura jest syntetycznym ćwiczeniem forensic — nie instrukcją popełnienia przestępstwa.

## Macierz zakresu

| Rodzina | Główna właściwość prywatności | Główny obserwator/zaufanie | Sposób ujęcia |
|---|---|---|---|
| Gotówka i ekwiwalenty gotówki | brak zdalnego rekordu w sieci płatniczej | odbiorca i środowisko fizyczne | legalny workflow |
| Wartość prepaid/gift/voucher | oddziela realizację od głównej karty | seller, issuer i redemption service | legalny workflow, zależny od jurysdykcji |
| Karta wirtualna/tokenized | ukrywa wielokrotnego użytku PAN lub rozdziela merchantów | issuer/network/wallet nadal identyfikuje płatnika | legalny workflow |
| Payment app/intermediary | merchant może widzieć alias/intermediary | app zbiera tożsamość, urządzenie i transakcję | punkt odniesienia |
| Bitcoin hygiene/Silent Payments | pseudonimy i unlinkability odbiorcy | public graph i granica wallet/network | możliwe do wdrożenia |
| PayJoin/CoinJoin | osłabia heurystyki wspólnej własności/linkage | uczestnicy/coordinator/network/public graph | możliwe tam, gdzie wspierane; wymaga przeglądu prawnego |
| Lightning/BOLT 12 | routing off-chain i ograniczenie ścieżki odbiorcy | endpoints, hops, services i channel graph | możliwe tam, gdzie wspierane |
| Monero/Zcash/MWEB | poufność on-chain na poziomie protokołu | acquisition, endpoint, network i granice nadal pozostają | możliwe tam, gdzie legalne/wspierane |
| Ethereum ZK application | ukrywa określone powiązanie statement/action | public inputs, RPC, relayer i app | zależne od aplikacji |
| Cashu/Fedimint/Taler | prywatność płatnika dzięki blind signatures | custody mint/federation/exchange i granice | rozwijające się/zależne od wdrożenia |
| Stablecoins | wygodne cyfrowe rozliczenie | transparent chain oraz issuer freeze/control | nie jest bazą anonimowości |
| Swaps/bridges/DEX | przenosi wartość między aktywami/łańcuchami | oba graphy, contracts i providers | mechanizmy forensic; wyłącznie zwykłe legalne swapy |
| Mixers/peel/structuring | zwiększa niejednoznaczność/wymaganą pracę analityczną grafu | entry/exit graph i service records | wyłącznie syntetyczne ćwiczenie detekcyjne |
| Nominees/mules/OTC/fronts | wstawia pośredników osobowych/biznesowych | facilitators, banks, communications | wyłącznie analiza nadużyć kryminalnych |
| Reusable/stealth payment addresses | nowy adres odbiorcy dla każdej płatności | public announcement/notification i granice wallet | możliwe tam, gdzie wspierane |
| Confidential sidechain/state channel | ukrywa kwotę/asset lub aktualizacje pośrednie | peers, bridge/federation i lifecycle settlement | zależne od protokołu |
| Carrier/open-banking/platform billing | ukrywa główną kartę przed merchantem | carrier, bank/PISP lub platform identyfikuje klienta | zwykła zidentyfikowana płatność |
| Mutual credit/net settlement | mniej zewnętrznych rekordów settlement | prywatny operator ledger ma pełne mapowanie | wyłącznie zidentyfikowani uczestnicy |

## Gotówka

**Mechanika:** fizyczna wartość bearer przechodzi z rąk do rąk bez internetowej autoryzacji issuer lub public ledger.

**Zalety:** merchant nie musi poznawać tożsamości bankowej/kartowej; brak zdalnego graph transakcji; rozwiązanie powszechnie zrozumiałe i finalne.

**Wady:** tylko face-to-face; kradzież/utrata; kontrola wydawania reszty, paragonów, numerów seryjnych lub raportowania; wypłata, kamery, świadkowie i lokalizacja nadal mogą połączyć płatnika.

**Procedura:** (1) potwierdź legalność/akceptację gotówki oraz limity i obowiązki raportowe; (2) wypłać lub otrzymaj ją legalnie i prowadź prywatną ewidencję; (3) zapłać zwykłemu merchantowi bez zbędnych identyfikatorów loyalty/account; (4) poproś tylko o wymagany paragon; (5) unikaj danych wysyłkowych/account, jeśli zakup ich nie wymaga; (6) wewnętrznie zapisz legalny cel biznesowy.

**Detekcja:** uzgadniaj kasę, paragony i inventory z kamerami oraz access logs zgodnie z polityką; badaj nietypowe refundy gotówkowe lub powtarzające się kwoty tuż poniżej kontroli, nie uznając zwykłego użycia gotówki za podejrzane samo w sobie.

## Money order, postal order, cashier instrument i cash on delivery

**Mechanika:** regulowany issuer zamienia gotówkę/środki z konta na numerowany instrument płatny wskazanemu odbiorcy; COD odracza pobranie do dostawy.

**Zalety:** odbiorca może nie otrzymać głównego numeru banku/karty płatnika; użyteczne, gdy gotówki nie można przesłać zdalnie; jasny receipt.

**Wady:** issuer/retailer przechowuje wymagane dane zakupu/tożsamości; tracking numeru seryjnego; adres odbiorcy/dostawy; ryzyko utraty/fraudu i ograniczenia regionalne; zasadniczo nieanonimowe.

**Procedura:** (1) sprawdź zasady issuer, limity, identyfikację i akceptację odbiorcy; (2) kup za legalne środki i z prawdziwymi danymi; (3) natychmiast uzupełnij payee/kwotę; (4) zachowaj numer seryjny/receipt; (5) użyj śledzonej dostawy odpowiedniej do wartości; (6) uzgodnij realizację/refund.

**Detekcja:** rekord zakupu/realizacji issuer, numer seryjny instrumentu, retailer/camera, shipping i konto odbiorcy; oznaczaj modyfikacje, duplikaty numerów oraz szybką geograficznie niespójną realizację.

## Open-loop prepaid card

**Mechanika:** credential z logo network autoryzuje transakcję względem salda prepaid zamiast głównego rachunku kredytowego.

**Zalety:** ogranicza ekspozycję merchant i straty; oddziela merchant od głównego PAN; działa online tam, gdzie jest akceptowana.

**Wady:** rekordy zakupu/aktywacji/doładowania/rejestracji i urządzenia; KYC i limity zależą od issuer; problemy z billing address; ograniczenia cash-out/refund; „brak nazwiska” nie oznacza braku rekordu issuer.

**Procedura:** (1) sprawdź aktualną tożsamość issuer, opłaty, KYC, region oraz obsługę online/recurring; (2) pozyskaj kartę przez autoryzowanego sellera za legalne środki; (3) podaj prawdziwe wymagane dane; (4) używaj jej do jednego celu/segmentu; (5) nie strukturyzuj loads ani nie fałszuj rezydencji; (6) zachowaj dowody zakupu/wydatku i zamknij/usuń kartę zgodnie z warunkami issuer.

**Detekcja:** łącz seller/activation, funding, device/IP, merchant authorization, balance checks i redemption/refund. Ważniejsze są wzorce niż sama etykieta prepaid.

## Closed-loop gift card, voucher i transferable service credit

**Mechanika:** numerowana wartość może być zrealizowana wyłącznie u jednego merchant/service lub w jednym ekosystemie. Airtime/game/store credits są wariantami.

**Zalety:** merchant odbiorcy może widzieć tylko kod/saldo; ograniczony blast radius; łatwe gifting i rozdzielenie budżetu.

**Wady:** seller i service logują zakup/aktywację/realizację; account/device/delivery nadal łączą aktywność; scams, discounts przy odsprzedaży oraz ograniczenia terminu/regionu; słaba ochrona refund.

**Procedura:** (1) kupuj tylko autoryzowanymi kanałami; (2) zapisz wartość kodu bez ujawniania sekretu; (3) nie dołączaj niepotrzebnego loyalty account; (4) realizuj przez odrębny legalny merchant account/context; (5) zachowaj receipt do akceptacji; (6) nigdy nie kupuj kodów na niezamówione żądanie „podatku/support/ransom”.

**Detekcja:** czas wydania/realizacji kodu, zbieżność device/account, zakupy masowe lub progowe, jedno urządzenie sprawdzające wiele sald oraz szybka odległa realizacja.

## Cryptocurrency-funded card lub gift-code broker

**Mechanika:** intermediary przyjmuje cryptocurrency i wydaje kartę, voucher lub merchant code. To konwersja cross-rail: merchant widzi zwykłą wartość karty/gift, a broker łączy deposit on-chain z wydaniem i dostawą.

**Zalety:** merchant nie otrzymuje funding wallet; użyteczne dla legalnych merchantów nieakceptujących crypto; ograniczona wartość stored value.

**Wady:** brak anonimowości wobec broker/issuer; KYC, sanctions, exchange i card-program rules; public deposit graph; account/device/email i code redemption ponownie łączą obie strony; ryzyko oszustwa/niewypłacalności.

**Procedura:** (1) zweryfikuj legal entity, card issuer, obsługiwany region, KYC, opłaty i refund policy; (2) używaj wyłącznie legalnych, udokumentowanych środków; (3) przetestuj najmniejszy nominał; (4) sprawdź ograniczenia network/merchant; (5) zachowaj blockchain transaction i broker receipt do księgowości; (6) nigdy nie korzystaj z brokera obiecującego identity fraud, sanctions bypass lub „untraceable” cash-out.

**Detekcja:** koreluj broker deposit addresses, unikalną kwotę/czas, account/device oraz issued-card authorization lub gift-code redemption; rekordy issuer i broker łączą public chain z merchantem.

## Virtual lub merchant-locked card

**Mechanika:** issuer mapuje wygenerowany PAN/token na rzeczywiste konto, często ograniczając merchant, kwotę lub expiry.

**Zalety:** zapobiega ujawnieniu wielokrotnego użytku PAN; compartmentation merchant; limity wydatków i łatwe revocation; dojrzała kontrola fraud.

**Wady:** issuer nadal zna płatnika, funding, merchant, device/IP i czas; merchant widzi account/delivery; część refundów/recurring charges nie działa; brak anonimowości.

**Procedura:** (1) używaj oficjalnej funkcji regulowanego issuer; (2) utwórz kartę dla jednego merchant/engagement; (3) ustaw najmniejszy użyteczny limit i expiry; (4) podaj prawidłowy billing, gdy wymagany; (5) sprawdź statement descriptor/refund behavior; (6) zamroź/usuń kartę po final settlement, zachowując audit evidence.

**Detekcja:** issuer token-to-account mapping, merchant authorization, device i delivery. Defenders wykorzystują merchant-specific reuse, velocity i sygnały account takeover.

## Mobile-wallet network token

**Mechanika:** EMV payment tokenization zastępuje PAN ograniczonym credential, często związanym z device, merchantem lub scenariuszem płatności.<sup>[[1]](#references)</sup>

**Zalety:** merchant nie otrzymuje wielokrotnego użytku PAN; device cryptography/dynamic data ograniczają cloning; można odwołać token bez wymiany karty.

**Wady:** issuer, token service, wallet platform i network zachowują mapowania/transakcje; konto platformy, device i lokalizacja mogą identyfikować płatnika.

**Procedura:** (1) zarejestruj legalną kartę w oficjalnym wallet; (2) zabezpiecz platform account/device silnym authentication; (3) sprawdź device token/ostatnie cyfry przy zakupie; (4) wyłącz zbędną lokalizację/analytics, jeśli wspierane; (5) natychmiast usuń tokeny z utraconych urządzeń; (6) przeglądaj rekordy issuer i wallet.

**Detekcja:** token requestor/device cryptogram i issuer mapping, telemetry wallet/account, merchant terminal oraz dowody fizyczne.

## Payment app, marketplace wallet i centralized intermediary

**Mechanika:** service utrzymuje konta i transfery wewnętrznie lub przez bank/card rails; merchant może widzieć alias, podczas gdy service widzi obie strony.

**Zalety:** wygoda, mechanizmy dispute/refund, odbiorca nie musi widzieć danych bank/card.

**Wady:** scentralizowany graph identity/social/transaction/device; freezes i legal process; counterparties mogą ujawnić profil; użycie danych może wykraczać poza potrzeby płatności.<sup>[[2]](#references)</sup>

**Procedura:** (1) przeczytaj warunki identity, privacy, retention i buyer protection; (2) ogranicz opcjonalną synchronizację profilu/kontaktów; (3) używaj oddzielnego prawdziwego konta tylko gdy zezwalają na to warunki; (4) włącz MFA/alerts; (5) zweryfikuj odbiorcę oraz prywatność memo/profile; (6) eksportuj rekordy i zamykaj nieużywane powiązania.

**Detekcja:** konto provider, device/IP, contact graph, funding/withdrawal, memo i merchant records. Alias oznacza pseudonymity wobec counterparty, nie anonimowość wobec platformy.

## Bank transfer, ACH, wire i instant-account payment

**Mechanika:** regulowane instytucje przenoszą wartość między zidentyfikowanymi kontami i wymieniają wymagane dane płatnicze.

**Zalety:** szybkość, rozliczalność, ograniczona odwracalność, silne rekordy; virtual account numbers mogą ograniczyć ujawnienie danych merchantowi.

**Wady:** banki/processors znają obie strony; statementy i referencje; brak anonimowości; dane cross-border i Travel Rule/AML.

**Procedura:** używaj wyłącznie, gdy akceptujesz rozliczalność: niezależnie zweryfikuj beneficiary, ogranicz opcjonalne memo, użyj bankowego virtual account/reference, jeśli dostępny, włącz alerts, zachowaj invoice i uzgodnij płatność.

**Detekcja:** deterministyczne rekordy bank/payment, własność beneficiary/account, device/session i fraud controls. To punkt odniesienia, nie technika anonimowości.

## Account i merchant compartmentation

**Mechanika:** rozdzielne legalne identity/accounts, email aliases, cards i delivery contexts uniemożliwiają niektórym merchantom łatwe łączenie niezwiązanej aktywności, choć issuer/controller zachowuje mapowanie.

**Zalety:** ogranicza breach i cross-merchant linkage; łatwe audytowanie; zgodne z regulowanymi płatnościami.

**Wady:** provider nadal mapuje compartments; recovery phone/device/IP i shipping mogą je połączyć; polityka może zabraniać wielu kont.

**Procedura:** (1) określ jeden cel; (2) utwórz wyłącznie zgodne z warunkami aliases/subaccounts; (3) użyj merchant-specific token/card; (4) wyłącz cross-account contact/ad personalization; (5) prowadź zaszyfrowany controller ledger; (6) wycofaj identyfikatory po zakończeniu potrzeb refund/retention.

**Detekcja:** providers łączą recovery, device, funding i IP; merchants łączą delivery, browser i account behavior. Defenders powinni odróżniać legalną compartmentation od synthetic identity fraud.

## Controlled red-team procurement

**Mechanika:** SOC nie zna zakupu, podczas gdy exercise controller zachowuje mapowanie legal entity, operatora i infrastruktury.

**Zalety:** realistyczne ćwiczenie detekcyjne; brak ekspozycji danych osobowych; natychmiastowa deconfliction i audit.

**Wady:** brak anonimowości wobec organization/provider; narzut governance; ryzyko leak przy niewłaściwym obchodzeniu się z controller ledger.

**Procedura:** (1) przydziel engagement-specific organization card/wallet/budget; (2) rozdziel role purchaser/operator; (3) zapisz asset, kwotę, service, cel i kill date; (4) przechowuj attribution mapping z ograniczonym dostępem controller; (5) nigdy nie używaj false identity/mule/stolen funds; (6) przy zamknięciu ujawnij i uzgodnij indicators oraz refunds.

**Detekcja:** controller mapuje provider invoice i asset; SOC testuje niezależne wykrycie przez domain, certificate, hosting i traffic, a nie dane cardholder.

## Bitcoin address hygiene i coin control

**Mechanika:** nowe receive addresses, lokalne labels i selektywne wydawanie UTXO ograniczają reuse adresów oraz przypadkowe łączenie segmentów na public ledger.

**Zalety:** szerokie wsparcie; self-custodial; unika najprostszych public linkages.

**Wady:** wszystkie transakcje/kwoty pozostają publiczne; common-input/change/timing i późniejsza consolidation mogą połączyć aktywność; pozostają acquisition/RPC/network records.

**Procedura:** (1) zainstaluj i zweryfikuj utrzymywany wallet; (2) wykonaj backup i sprawdź seed recovery; (3) używaj nowego adresu dla każdej invoice; (4) lokalnie oznacz source/purpose; (5) użyj coin control, aby nie łączyć kontekstów; (6) preferuj local node lub privacy-aware connection; (7) sprawdź change/fees i zachowaj legal accounting.<sup>[[3]](#references)</sup>

**Detekcja:** address graph, common-input/change heuristics z uwzględnieniem niepewności, exact amount/time, consolidation, service deposits, node/RPC broadcast timing i off-chain records.

## Bitcoin Silent Payments

**Mechanika:** BIP 352 pozwala odbiorcy publikować static code, podczas gdy senders wyprowadzają unikalne Taproot outputs za pomocą ECDH; obserwatorzy zewnętrzni nie mogą bezpośrednio połączyć outputs z code.<sup>[[4]](#references)</sup>

**Zalety:** reusable public identifier bez address reuse; brak interaktywnego żądania adresu lub notification output; podobieństwo do Taproot outputs.

**Wady:** koszt skanowania po stronie odbiorcy; różne wsparcie wallet; graph amount/sender i spending pozostają publiczne; index server może obserwować scans.

**Procedura:** (1) wybierz aktualny wallet BIP 352; (2) wykonaj backup/test descriptor i scanning recovery; (3) wygeneruj labeled code, jeśli wspierane; (4) uwierzytelnij opublikowany code; (5) sender sprawdza inputs i wysyła mały test; (6) receiver skanuje najlepiej przez własny node; (7) przechowuj received UTXOs oddzielnie.

**Detekcja:** z założenia nie da się wiarygodnie rozpoznać tego wyłącznie po output; analysts używają sender inputs, amount/time, later spending, wallet/network/index i counterparty records.

## PayJoin

**Mechanika:** payer i payee dostarczają inputs do jednej payment transaction, łamiąc założenie, że wszystkie inputs mają jednego ownera.<sup>[[5]](#references)</sup>

**Zalety:** zwykła płatność z lepszą prywatnością; osłabia common heuristic w całym graph; nie wymaga grupy równych outputs.

**Wady:** wymóg interakcji/wsparcia; dostępność endpoint receiver; amount i final transaction są publiczne; metadata implementacji i fallback.

**Procedura:** (1) potwierdź, że oba utrzymywane wallety wspierają tę samą wersję PayJoin; (2) uwierzytelnij invoice/endpoint; (3) rozpocznij przez walletowe PayJoin-enabled payment URI; (4) sprawdź final amount/fee i podpisz wyłącznie oczekiwane inputs; (5) unikaj ręcznej modyfikacji transaction; (6) zweryfikuj broadcast i receipt; (7) zapisz fallback, jeśli negotiation się nie powiedzie.

**Detekcja:** blockchain analysts nie powinni wymuszać common-input clustering; endpoint/provider może logować negotiation; używaj wallet/network i późniejszych spend evidence, a nie samego kształtu transaction.

## CoinJoin

**Mechanika:** wielu participants wspólnie tworzy transakcję z wieloma inputs/outputs, często o równych nominałach, zwiększając niejednoznaczność mapowania input-output.

**Zalety:** większy on-chain ambiguity set; istnieją self-custodial designs; mierzalna struktura rund.

**Wady:** coordinator/peer/network metadata; fees/liquidity; rozpoznawalny transaction shape; toxic change i późniejsza consolidation niszczą korzyści; dostępność prawna/provider zależy od regionu.

**Procedura:** (1) sprawdź aktualną dostępność wallet/coordinator i legalność; (2) zainstaluj oficjalny wallet i wykonaj backup; (3) używaj wyłącznie legalnych UTXOs; (4) zrozum denomination, fee i coordinator model; (5) oznacz i rozdziel change oraz mixed outputs; (6) nigdy nie konsoliduj ich razem; (7) kieruj network traffic zgodnie z oficjalnym wsparciem i zachowaj accounting.

**Detekcja:** rozpoznaj collaborative structure bez zakładania przestępstwa; oblicz możliwe mappings/anonymity set, następnie obserwuj change/consolidation, service boundaries i network/coordinator records.

## Lightning Network

**Mechanika:** płatności HTLC przechodzą przez onion-routed channels; większość szczegółów płatności nie jest publikowana on-chain, natomiast funding/closing i public channel information są widoczne.

**Zalety:** szybkość, niskie fee; intermediaries zwykle widzą sąsiednie hops; rutynowe szczegóły płatności pozostają off-chain.

**Wady:** sender/receiver oraz first/last hop wiedzą więcej; probing, timing, channel graph, liquidity/wallet/LSP records; custodial wallets identyfikują użytkowników.

**Procedura:** (1) świadomie wybierz self-custodial lub custodial; (2) sprawdź wallet/seed/channel recovery; (3) użyj invoice dla dokładnej płatności; (4) preferuj private channels/LSP features dopiero po poznaniu kompromisów; (5) chroń node IP przez wspierany Tor, gdy potrzebne; (6) nie używaj ponownie identyfikujących invoices; (7) prowadź channel i payment accounting.<sup>[[6]](#references)</sup>

**Detekcja:** node/LSP/custodian logs, channel graph/probes, payment failure/timing oraz on-chain funding/closure; brak public transaction nie oznacza braku rekordów.

## BOLT 12 offers i route blinding

**Mechanika:** reusable offer tworzy świeże invoices i może reklamować blinded paths, aby payer nie musiał poznać jawnego node/path odbiorcy.

**Zalety:** prywatność receiver; reusable donation/payment endpoint bez static invoice; integracja z Lightning onion routing.

**Wady:** różne wsparcie wallet; endpoints, selected hops i funding pozostają; public contact lub network endpoint może ponownie zidentyfikować receiver.

**Procedura:** (1) potwierdź zgodne wsparcie BOLT 12; (2) uwierzytelnij offer; (3) zażądaj fresh invoice; (4) sprawdź amount/issuer/recurrence; (5) zapłać przez wallet; (6) zweryfikuj receipt/refund behavior; (7) ogranicz node alias/contact i zachowaj accounting.<sup>[[7]](#references)</sup>

**Detekcja:** wallet/LSP i first/last-hop telemetry, offer distribution account, timing/value i funding graph; route blinding celowo ogranicza widoczność payer.

## Monero

**Mechanika:** one-time stealth addresses ukrywają powiązanie odbiorcy, RingCT ukrywa kwoty, a ring signatures zapewniają niejednoznaczność sender.

**Zalety:** prywatność domyślna on-chain; poufność sender/receiver/amount; dojrzały ekosystem dedykowanych wallet/node.

**Wady:** acquisition/off-ramp i endpoint/network/counterparty records; remote node widzi queries/IP; exchange support i legal treatment są zmienne; błędy operacyjne nadal mogą łączyć konteksty.

**Procedura:** (1) pozyskaj legalnie i zachowaj basis/source; (2) zainstaluj/zweryfikuj oficjalny utrzymywany wallet; (3) wykonaj backup/test seed; (4) użyj local node lub udokumentowanej ścieżki Tor/I2P remote-node; (5) używaj nowego subaddress per payer/invoice; (6) lokalnie oznaczaj konteksty; (7) ujawniaj transaction proof/view access tylko celowo.<sup>[[8]](#references)</sup>

**Detekcja:** skup się na exchange/merchant/device/network oraz seized-wallet evidence; samo użycie protokołu nie jest podejrzane, a public chain celowo ujawnia mniej.

## Zcash fully shielded Orchard

**Mechanika:** zero-knowledge proofs weryfikują shielded transfers, podczas gdy sender, receiver i amount są zaszyfrowane; transparent pools i pool transitions pozostają publiczne.

**Zalety:** silna shielded on-chain confidentiality; viewing keys umożliwiają ograniczony audit; validity wymuszona przez protokół.

**Wady:** wsparcie wallet/exchange i faktyczny wybór pool są zmienne; transparent boundary timing/value correlation; network/RPC i endpoint pozostają widoczne.

**Procedura:** (1) wybierz utrzymywany wallet Orchard shielded-by-default; (2) zweryfikuj i wykonaj backup; (3) pozyskaj ZEC legalnie; (4) odbierz na wspierany Unified Address i potwierdź pool; (5) preferuj shielded-to-shielded; (6) użyj wspieranego network privacy; (7) przed audytem przetestuj viewing-key disclosure na małym wallet.<sup>[[9]](#references)</sup>

**Detekcja:** transparent boundary i service records, wallet/network metadata oraz viewing keys, jeśli zostały legalnie udostępnione; nie zakładaj, że wszystkie płatności Unified Address były shielded.

## Mimblewimble i Litecoin MWEB

**Mechanika:** confidential transactions ukrywają amounts, a agregacja typu Mimblewimble usuwa typową, bogatą w adresy historię; Litecoin implementuje opcjonalny extension block obok transparent chain.

**Zalety:** poufne amounts i lepsza fungibility w prywatnej domenie; efektywne pruning/aggregation.

**Wady:** opt-in boundary peg-in/out jest publiczne i korelowalne; wallet/exchange support; różnice modelu interakcji/adresów; network i acquisition records.

**Procedura:** (1) wybierz utrzymywany wallet z wyraźnym wsparciem MWEB; (2) zweryfikuj/wykonaj backup i przetestuj małą kwotę; (3) pozyskaj legalnie; (4) wykonaj peg do MWEB i sprawdź balance domain; (5) transaktuj wyłącznie z kompatybilnym receiver; (6) unikaj natychmiastowego charakterystycznego peg-out; (7) zachowaj prywatne audit records.<sup>[[10]](#references)</sup>

**Detekcja:** public peg-in/out timing/value, exchange/wallet/node data i późniejsze transparent spends; szczegóły wewnętrznych confidential transfers są celowo ograniczone.

## Ethereum zero-knowledge privacy applications

**Mechanika:** circuit dowodzi statement — membership, valid note ownership lub authorization — bez ujawniania sekretu; verifier contract sprawdza dowód. Deposits, withdrawals, public inputs, events i gas nadal mogą ujawniać powiązania.

**Zalety:** programmable selective disclosure; applications z anonymous set; weryfikowalne reguły bez ujawniania wszystkich danych.

**Wady:** błędy contract/circuit; mały anonymity set; public boundaries; RPC/IP/session/analytics/gas funding; ryzyko aplikacyjne, sankcyjne i prawne.

**Procedura:** (1) dokładnie określ, co ukrywa proof; (2) używaj audytowanej, utrzymywanej aplikacji, gdy jest to legalne; (3) sprawdź public inputs/events i zasady deposit/withdraw; (4) rozdziel action wallet i gas sponsorship zgodnie z protokołem; (5) użyj privacy-aware RPC/network path; (6) testuj małą wartością; (7) zachowaj compliance records.<sup>[[11]](#references)</sup>

**Detekcja:** contract events, deposit/withdraw timing/value, relayer/paymaster, RPC/session, frontend storage/analytics i późniejsza granica exchange/merchant. Nie twierdź, że ZK proof ukrywa pola zadeklarowane jako publiczne.

## Stablecoins

**Mechanika:** tokeny są transferowane na public chain; centralized issuers mogą freeze/blacklist lub redeem względem zidentyfikowanych kont.

**Zalety:** stabilność ceny, liquidity i merchant support; szybki settlement; łatwa księgowość.

**Wady:** transparent address/amount/contract graph; gas funding; issuer i exchange identity/control; sanctions screening; ogólnie słaba anonimowość.

**Procedura:** traktuj jako zidentyfikowaną płatność: użyj fresh business address wyłącznie do compartmentation, sprawdź token contract/network, przetestuj małą kwotą, chroń wallet, użyj trusted RPC/local node, zachowaj basis/source i screen required parties.

**Detekcja:** pełny token event graph, issuer freeze list/actions, exchange/RPC/device oraz gas-funding relationships.

## Cashu Chaumian e-cash

**Mechanika:** mint podpisuje blind podpisem client-generated bearer secrets zabezpieczone rezerwami mint Bitcoin/Lightning; może zapobiegać double-spend bez bezpośredniego łączenia issuance z późniejszym redemption.

**Zalety:** accountless bearer tokens; natychmiastowy peer transfer; mint nie może bezpośrednio połączyć blinded withdrawal ze spend; tokens mogą być przesyłane jako data/QR.

**Wady:** custody/solvency/censorship mint; utrata/kradzież bearer data; denomination/timing i Lightning boundaries; network metadata; wczesny ekosystem software.<sup>[[12]](#references)</sup>

**Procedura:** (1) najpierw użyj official test mint lub bardzo małej, disposable value; (2) zainstaluj utrzymywany wallet i sprawdź ograniczenia backup/restore; (3) uwierzytelnij mint i poznaj custody/fees; (4) wyemituj małą kwotę; (5) wyślij token przez authenticated private channel/QR; (6) receiver wymienia token przed uznaniem go za finalny; (7) redeem i reconcile. Nigdy nie przechowuj istotnej wartości w niezaufanym mint.

**Detekcja:** mint widzi network, issue/redeem/Lightning boundaries i spent-token set, ale blinding usuwa bezpośrednie token linkage; endpoints/messages i charakterystyczne amount/timing mogą przywrócić powiązania.

## Fedimint federated e-cash

**Mechanika:** threshold guardians przechowują reserves i podpisują blind e-cash; wewnętrzne bearer transfers są prywatne względem guardians, a Lightning gateways łączą płatności zewnętrzne.

**Zalety:** rozproszona custody; prywatny transfer wewnętrzny; community governance; pojedynczy guardian nie kontroluje reserve poniżej threshold.

**Wady:** guardian quorum/custody/software risk; gateway obserwuje invoices/timing; deposit/withdraw boundaries; trudniejszy recovery client state.

**Procedura:** (1) zweryfikuj federation invite/guardians/quorum/jurisdiction; (2) zainstaluj utrzymywany client i przetestuj recovery; (3) wpłać małą legalną kwotę; (4) używaj świeżych internal payment requests; (5) traktuj gateway jako obserwatora Lightning; (6) przetestuj redemption; (7) przechowuj source/tax records poza public payment data.<sup>[[13]](#references)</sup>

**Detekcja:** federation widzi aggregate issuance/redemption, gateways widzą external invoices, Bitcoin/Lightning pokazują boundaries, a endpoint/communication evidence może połączyć transfery wewnętrzne.

## GNU Taler

**Mechanika:** bank-integrated blind-signature e-cash ma utrzymywać anonimowość payer wobec merchantów, podczas gdy merchants i income pozostają rozliczalne.

**Zalety:** prywatność payer by design; zwykła waluta; merchant accountability/refunds; brak potrzeby speculative token.

**Wady:** ograniczone deployments; exchange/bank widzi funding; merchant widzi order/delivery; ryzyko bearer wallet/recovery; regulated operators.

**Procedura:** (1) znajdź aktualny exchange/merchant dla jurysdykcji/waluty; (2) przeczytaj KYC/fees/privacy; (3) zainstaluj official wallet; (4) wykonaj legal withdrawal ze wspieranego bank/exchange; (5) sprawdź merchant contract; (6) zapłać i zachowaj receipt/refund data; (7) unikaj zbędnych merchant session identifiers.<sup>[[14]](#references)</sup>

**Detekcja:** bank/exchange withdrawal i merchant deposit są rozliczalnymi boundaries; merchant order/device/delivery i timing mogą korelować nawet przy blind coins.

## Cross-chain bridge, atomic swap i decentralized exchange

**Mechanika:** contract/service blokuje/burns jeden asset i zwalnia/mints inny albo counterparties dokonują atomic exchange. Łamie to widok pojedynczego ledger, nie ciągłość ekonomiczną.

**Zalety:** interoperacyjność asset/network; możliwość uniknięcia jednego centralized custodian; zwykłe portfolio/liquidity use.

**Wady:** oba chains są publiczne; time/value/fees/liquidity i contracts korelują; bridge/relayer/frontend/RPC records; ryzyko smart-contract/counterparty i regulacyjne.

**Procedura dla legalnych swaps:** (1) zweryfikuj official contract/service i dostępność prawną; (2) sprawdź custody/audit/fees/slippage; (3) wykonaj mały test; (4) zapisz oba transaction IDs i rate; (5) chroń approvals; (6) uzgodnij destination asset i revoke niepotrzebne approvals. Nie używaj swaps do ukrywania źródła środków.

**Detekcja:** bridge deposit/withdraw events, unikalna kwota pomniejszona o fees, kolejność czasowa, liquidity, relayer/RPC/frontend i późniejsze service deposits.

## Centralized mixer lub tumbler

**Mechanika:** service przyjmuje deposits do pool i później zwraca inne units, próbując ukryć bezpośrednie input-output mapping.

**Zalety:** teoretycznie może zwiększać transaction ambiguity.

**Wady:** operator może ukraść/logować; analiza entry/exit timing/value; sanctions/money-transmission i criminal exposure; seizure ujawnia mappings; ryzyko taint/rejection.

**Procedura:** nie udostępniamy operacyjnego poradnika mixing. Bezpiecznie odtwórz graph, rozszerzając [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): utwórz syntetyczne deposits, pooled outputs, fees i delays; przekaż analysts niepełne mappings; zmierz skuteczność heurystyk; następnie ujawnij ground truth.

**Detekcja:** identyfikacja service wallet/contract, entry/exit candidate sets, amount/fee/timing, reuse deposit address, seized/provider logs i downstream consolidation. Oznaczaj probabilistic attribution.

## Peel chains, fan-out/fan-in i structuring

**Mechanika:** powtarzające się transactions odrywają małe payments od change, dzielą value na wiele addresses, łączą je ponownie w collectors albo dzielą amounts, aby uniknąć review.

**Zalety:** zwiększa obciążenie naiwnego analityka i liczbę addresses.

**Wady:** rozpoznawalna value/cadence/transaction continuity; consolidation i service endpoints; structuring może być samo w sobie nielegalne; fees i błędy operacyjne.

**Procedura:** używaj wyłącznie syntetycznych CSV/testnet data: wygeneruj duży source, powtarzające się payment/change edges, równoległe branches i jeden collector; dodaj łagodne exchange-like examples; dostrój detection i opisz false positives.

**Detekcja:** graph continuity, repeated change pattern, cadence, amounts tuż poniżej kontroli, common service endpoint i off-chain records. Exchange hot wallets mogą przypominać te wzorce, więc kontekst jest konieczny.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker i front company

**Mechanika:** inna osoba/account/company odbiera, konwertuje lub wydaje funds, wstawiając legalne i operacyjne warstwy między controller a transaction.

**Zalety dla adversary:** named account nie identyfikuje natychmiast controller; może łączyć cash, crypto, goods i jurisdictions.

**Wady:** identity fraud/money-laundering exposure; każdy uczestnik dodaje communications, bank/company/tax/shipping records, fees, niespójności i świadków; ponowne użycie facilitator tworzy hubs.

**Procedura:** nie emuluj tego z prawdziwymi osobami/accounts. Zbuduj synthetic graph z controller, recruiter, mule, OTC, shell merchant i beneficiary; dodaj device/IP/message/bank edges; poproś investigators o odróżnienie account holder od controller i zapisanie confidence evidence.

**Detekcja:** shared device/IP/recovery, nietypowy beneficiary/velocity, wielu niezwiązanych senders, natychmiastowy onward movement, niespójność company/director/invoice, communications oraz cash/commodity delivery.

## NFTs, gambling, merchant goods i refund loops

**Mechanika:** wartość jest zamieniana na self-priced asset, wagering balance, odsprzedawalne goods lub refunds, aby stworzyć inną narrację transakcji.

**Zalety dla adversary:** zmiana formy asset i wprowadzenie marketplace/merchant intermediaries.

**Wady:** marketplace/account/device i wash-trade graph; odds/play i refund records; evidence delivery/resale; fees/losses; odpowiedzialność za fraud/laundering.

**Procedura:** brak workflow ukrywania. Użyj syntetycznych marketplace data z related-wallet self-trades, nieprawdopodobnym pricing, minimal play, mismatched refund instrument i common shipping; zweryfikuj detection wobec legalnych collectors/customers.

**Detekcja:** circular/self-funded trades, common ownership/funding, price outliers, immediate resale/refund, minimal economic activity, shared device/delivery i proceeds reconvergence.

## Physical bearer wallet lub offline token transfer

**Mechanika:** device, paper/QR, hardware bearer instrument lub e-cash token przekazuje kontrolę nad sekretem zamiast broadcast payment podczas handover.

**Zalety:** brak live network event przy wymianie; użyteczne offline; custody podobna do gotówki fizycznej.

**Wady:** copy/theft/loss i niepewna wyłączność; późniejszy redemption/broadcast łączy transakcję; physical meeting/shipping; ryzyko counterfeit/tamper.

**Procedura:** (1) używaj tylko sprawdzonego instrument/protocol; (2) prywatnie initialize/verify authenticity; (3) załaduj tylko małą legalną wartość; (4) przekaż w udokumentowanym autoryzowanym kontekście; (5) receiver weryfikuje lub sweepuje zgodnie z protokołem; (6) nigdy nie zakładaj, że sender nie zachował kopii; (7) prywatnie zapisz evidence ownership/tax.

**Detekcja:** purchase/funding i późniejszy sweep/redemption, device serial/tamper evidence, delivery/meeting i endpoint records.

## Merchant-scoped invoice lub one-time payment request

**Mechanika:** merchant tworzy jednorazowe żądanie z amount, expiry i order reference. Payer reguluje je przez wspierany rail bez ujawniania merchantowi reusable credential; issuer/payment processor może nadal identyfikować obie strony.

**Zalety:** ogranicza credential reuse i przypadkowe cross-merchant identifiers; exact amount/expiry zmniejszają błędy; zgodne ze zwykłą księgowością i refunds.

**Wady:** invoice, delivery, browser, processor i issuer nadal łączą order; unikalny amount/time może zwiększać korelację; malicious payment links są częste.

**Procedura:** (1) niezależnie uwierzytelnij merchant; (2) zażądaj fresh invoice z exact amount, asset/network i expiry; (3) sprawdź destination i refund rules; (4) zapłać z approved engagement compartment; (5) potwierdź, że merchant uznał tę samą invoice; (6) zachowaj receipt i transaction reference; (7) wygaszaj zamiast ponownie używać request.

**Detekcja:** merchant i processor łączą invoice, session i settlement; unique amounts/timing i delivery identyfikują payer. **Captured wallet/device:** historia invoice ujawnia counterparties i purpose; ogranicz zbędne memo data, szyfruj device i przechowuj authoritative accounting w controlled finance system.

## Prepaid service credit i capability token

**Mechanika:** service zamienia konwencjonalną płatność na ograniczone credits wewnętrzne lub bearer capability. Późniejsze użycie API/resource może nie wymagać podawania pierwotnej karty przy każdym request, ale service często może połączyć issuance z redemption.

**Zalety:** ogranicza spend i straty po compromise; oddziela codziennych workers od funding credential; wspiera budżety per-project i revocation.

**Wady:** zwykle pseudonymous, nie anonymous; service database, redemption IP i unikalny usage pattern łączą aktywność; bearer tokens mogą zostać skradzione; refunds mogą wymagać pierwotnego payer.

**Procedura:** (1) kup credits przez organization account; (2) utwórz jeden project i budget; (3) wydaj wąski token z ograniczeniami service, amount i expiry; (4) przechowuj go wyłącznie w zatwierdzonym secret manager lub workload identity path; (5) przetestuj odrzucenie poza zakresem i po expiry; (6) monitoruj consumption; (7) revoke i reconcile unused value.

**Detekcja:** provider łączy funding account, project, token issuance i usage; defenders alertują na zmiany geografii/procesu i anomalous consumption. **Captured node:** załóż, że pozostała capability może zostać wydana; używaj krótkiego expiry, niskiego balance, audience binding i natychmiastowego server-side revocation.

## Privacy Pass lub blinded authorization token

**Mechanika:** issuer tworzy privacy-preserving authorization token, który origin może zweryfikować bez łączenia redemption z issuance. Może oznaczać paid entitlement lub rate-limited access, ale nie jest general currency. Architektura rozdziela role client, attester, issuer i origin oraz ostrzega, że IP/timing lub collusion mogą zniweczyć unlinkability.<sup>[[18]](#references)</sup>

**Zalety:** unlinkable redemption dla wspieranych services; brak reusable account cookie u origin; cached tokens mogą rozdzielić issuance i use w czasie.

**Wady:** application-specific; zaufanie do issuer/attester i partitioning anonymity set; IP i browser metadata pozostają; token theft lub charakterystyczny issuance timing mogą korelować użycie.

**Procedura:** (1) używaj implementacji zgodnej z właściwym Privacy Pass token type; (2) dokładnie określ entitlement dowodzony przez token; (3) rozdziel issuer i origin administration, gdy wymaga tego threat model; (4) ogranicz challenge metadata; (5) wydaj kilka testowych tokens i zrealizuj każdy raz w posiadanych origins; (6) porównaj logs pod kątem zakazanych stable identifiers; (7) przetestuj replay, expiry i revocation/abuse controls.

**Detekcja:** origins widzą redemption IP/time i token validity; issuers/attesters widzą issuance context; analysts testują timing i metadata partitions bez zakładania cryptographic break. **Captured client:** niewydane bearer tokens mogą być użyte; ogranicz ich value, lifetime i audience oraz nigdy nie przechowuj obok nich funding credential.

## Delegated organization procurement lub fiscal sponsor

**Mechanika:** autoryzowany procurement team, reseller lub fiscal sponsor zawiera umowę i płaci, podczas gdy operational team otrzymuje ograniczoną usługę. To role separation z prawdziwymi records, a nie nominee lub false identity.

**Zalety:** vendors nie muszą otrzymywać tożsamości każdego operatora ani osobistych payment details; central compliance, tax i refund handling; jasny budget i offboarding.

**Wady:** sponsor zna beneficiary i purpose; contracts, approvals, delivery i accounts pozostają; dodatkowe opóźnienia/fees; słaba separacja, gdy ta sama osoba administruje każdą warstwą.

**Procedura:** (1) udokumentuj business purpose, beneficiary i approving authority; (2) wybierz organization-approved intermediary; (3) zawrzyj contract z prawdziwymi danymi; (4) provision project-scoped subaccount bez personal billing credential; (5) rozdziel finance administrators od operators; (6) reconcile invoices i access; (7) zakończ service oraz delegated access przy closeout.

**Detekcja:** procurement, identity-provider, vendor i delivery records łączą chain. **Captured operational device:** powinien ujawnić service project, ale nie finance credentials; invoice i payer identities przechowuj w finance system, nie na field nodes.

## Escrow lub conditional settlement

**Mechanika:** trusted escrow agent lub smart contract przechowuje value do spełnienia udokumentowanych warunków. Może ograniczyć bezpośrednie ujawnienie między payer i payee, ale escrow i underlying payment rails zachowują relację.

**Zalety:** ochrona dispute i delivery; payer i merchant mogą ujawnić sobie mniej reusable credentials; audytowalne release conditions.

**Wady:** custody/contract risk escrow, fees i identity obligations; on-chain contracts są publiczne; order, shipping i dispute data pozostają; brak anonimowości wobec intermediary.

**Procedura:** (1) zweryfikuj legal entity, custody, fees, dispute forum i supported assets; (2) utwórz dokładny pisemny milestone i refund path; (3) funduj z approved organization account; (4) niezależnie zweryfikuj receipt i release authorization; (5) release dopiero po evidence; (6) zachowaj kompletny audit record; (7) zamknij nieużywane permissions/contract approvals.

**Detekcja:** escrow account/contract events, funding i release time, beneficiary oraz dispute records ujawniają transakcję. **Captured device:** session tokens lub contract approvals mogą pozwolić na release; wymagaj oddzielnego approver/MFA i revoke active sessions po utracie.

## Batched lub pooled organization settlement

**Mechanika:** wiele zatwierdzonych obligations agreguje się i rozlicza mniejszą liczbą bank/blockchain transactions, a prywatny internal ledger przypisuje udziały. Batching może ograniczyć public per-purchase detail, ale coordinator zachowuje pełną attribution.

**Zalety:** niższe fees; mniej public graph edges; ukrycie pojedynczych line items przed public observerem, gdy kwoty są agregowane; prosta internal accounting.

**Wady:** coordinator jest pełnym observerem i atrakcyjnym celem; charakterystyczne totals/timing mogą korelować; custody i reconciliation risk; nadużycie może przypominać structuring.

**Procedura:** (1) określ participants i legal obligations w accounting system; (2) ustal regular batch window uzasadniony biznesowo, a nie thresholds mające omijać controls; (3) wymagaj dual approval aggregate; (4) rozliczaj do authenticated recipients; (5) uzgadniaj każdą internal line z batch; (6) refunds obsługuj jako linked corrections; (7) chroń ledger access i zachowuj go zgodnie z policy.

**Detekcja:** coordinator ledger, approval i beneficiary records dają ground truth; public analysts ostrożnie używają input/output/value/time clustering. **Captured payer device:** powinien zawierać tylko requisition, nie pool signing key ani participant ledger.

## Account-abstraction paymaster lub sponsored gas

**Mechanika:** relayer/bundler wysyła smart-account operation, a paymaster opłaca transaction fees, eliminując bezpośrednią native-gas funding edge z user wallet. Poprawia jedną właściwość graph, ale operation, contract i service telemetry pozostają publiczne lub obserwowalne.<sup>[[19]](#references)</sup>

**Zalety:** usuwa typowe gas-funding link; wspiera scoped sponsorship i rate limits; ułatwia onboarding legalnych privacy applications.

**Wady:** paymaster/bundler/RPC/front end może korelować requests; contract events i public inputs pozostają; sponsorship policy fingerprintuje cohort; złośliwe contracts/approvals mogą kraść assets.

**Procedura:** (1) używaj audytowanego utrzymywanego smart account i paymaster na właściwym network; (2) sprawdź public fields i logowanie sponsora; (3) ogranicz sponsorship według contract, function, amount, nonce i expiry; (4) testuj małą wartością; (5) wysyłaj przez intended privacy-aware path aplikacji; (6) zweryfikuj operation i fee payer on-chain; (7) revoke allowances/session keys i zachowaj compliance records.

**Detekcja:** łącz UserOperation, EntryPoint, paymaster, bundler/RPC i application logs; ostrożnie klasteryzuj identyczne sponsorship policies. **Captured wallet:** session keys i pending approvals mogą być użyte nawet bez gas; ogranicz je i revoke przez recovery policy konta.

## Threshold lub multisignature payment authorization

**Mechanika:** spending wymaga threshold niezależnych signers. Nie ukrywa transaction, ale pozwala oddzielić payment authority od przejętego laptopa, field node lub pojedynczego operatora.

**Zalety:** silna odporność na compromise i insider; accountable approval; żadne pojedyncze field device nie ma pełnej signing authority; recovery.

**Wady:** coordination i availability; signer/device/account metadata może korelować participants; zły backup powoduje loss; public multisig patterns mogą być rozpoznawalne.

**Procedura:** (1) określ signers, threshold, limits i recovery przed funding; (2) initialize na oddzielnym wspieranym hardware/accounts; (3) niezależnie sprawdź addresses i backups; (4) daj field workloads wyłącznie unsigned requisition capability; (5) wymagaj out-of-band review recipient, amount i purpose; (6) przetestuj recovery i loss jednego signer na małej wartości; (7) rotate signer po compromise.

**Detekcja:** approval system, signer device i public script/contract dostarczają evidence; defenders alertują na zmiany policy lub signer-set. **Captured node:** powinien ujawnić najwyżej jeden low-authority session key lub unsigned request; nigdy nie przechowuj quorum material razem.

## Closed-loop community lub event currency

**Mechanika:** cooperative, conference lub private test environment wydaje credits realizowane wyłącznie wśród enrolled participants. Internal transfer może być mniej widoczny dla global payment networks, lecz operator kontroluje issuance i redemption.

**Zalety:** ograniczona domena ekonomiczna; możliwość testowania offline lub privacy-preserving payment UX; ograniczenie zewnętrznej ekspozycji kart; jasne controls eksperymentu.

**Wady:** mały anonymity set; operator i merchants obserwują activity; ograniczona akceptacja/redemption; nawet lokalna wartość może podlegać licensing, consumer-protection i tax rules.

**Procedura:** (1) uzyskaj legal/compliance review i opublikuj issuer terms; (2) zapisz consenting test participants; (3) ogranicz issuance i zabroń misuse podobnego do gotówki; (4) używaj fresh payment requests i ogranicz public participant identifiers; (5) rejestruj aggregate reserves oraz prywatne individual receipts; (6) testuj loss/refund/redemption; (7) zamknij ledger i zwróć residual value zgodnie z obietnicą.

**Detekcja:** issuer ledger, enrollment, merchant i redemption records odtwarzają flows; nietypowe circular transfers lub szybki cash-out wymagają review. **Captured wallet:** local balance i counterparties mogą zostać ujawnione; ogranicz value, szyfruj state i wspieraj issuer-side freeze/reissue z audytowalnym record.

## Bitcoin reusable payment codes i private payment instructions

**Mechanika:** BIP 47 payment codes używają reusable public identifier oraz ECDH-derived one-time deposit addresses; BIP 351 określa nowszy private-payment instruction design. Ograniczają public address reuse, pozwalając receiverowi publikować stabilne payment instructions. Notification, wallet support, funding i subsequent coin selection nadal wpływają na prywatność.<sup>[[20]](#references)</sup>

**Zalety:** jedna public instruction może dawać różne addresses; receiver nie musi publikować każdego invoice address; kompatybilne wallety mogą monitorować derived payments; użyteczne dla powtarzających się legalnych donors/customers.

**Wady:** zmienna interoperability wallet; notification transactions lub published payment code łączą relationship context; sender, receiver i public graph nadal widzą transactions; nieuważna consolidation/change handling niweluje korzyść.

**Procedura:** (1) potwierdź, że oba utrzymywane wallety wspierają dokładnie tę samą specification/version; (2) wykonaj backup i test recovery na low-value wallet; (3) out-of-band uwierzytelnij recipient payment code; (4) wyślij mały legalny test; (5) zweryfikuj użycie fresh derived address; (6) lokalnie oznacz relationship i zastosuj coin control; (7) przed użyciem produkcyjnym przetestuj recovery/refund.

**Detekcja:** analysts badają notification patterns, funding/change, later consolidation i service boundaries; publikacja public code identyfikuje recipient context, nawet gdy deposit addresses są różne. **Capture-resilient OPSEC:** trzymaj spend keys poza field devices i ujawniaj najwyżej watch-only relationship view. **Monitoring:** alertuj na unexpected notification transactions, reused derived addresses, wallet gap-limit/recovery errors i unplanned consolidation.

## EVM stealth addresses (ERC-5564)

**Mechanika:** sender wyprowadza one-time stealth account z recipient stealth meta-address i publikuje announcement zawierający ephemeral public key oraz view tag. Receiver skanuje announcements viewing key i wyprowadza odpowiedni spend key. Recipient linkage jest lepsze, lecz sender, amount/token, gas, announcement i późniejsze spending pozostają widoczne.<sup>[[21]](#references)</sup>

**Zalety:** non-interactive fresh receiver address; reusable meta-address; rozdzielenie viewing/spending roles; działanie z obsługiwanymi EVM assets/applications.

**Wady:** announcement scanning i spam; funding gas dla nowego address może ponownie połączyć identity; sender zna receiver; public token/amount i późniejsza consolidation pozostają; zmienne implementation/wallet support.

**Procedura:** (1) najpierw użyj audytowanej utrzymywanej implementacji na test network; (2) wygeneruj oddzielne viewing/spending material i wykonaj backup; (3) uwierzytelnij meta-address; (4) wyślij low-value test i announcement; (5) zeskanuj i wyprowadź stealth account; (6) przetestuj supported gas sponsorship bez personal funding edge; (7) zapisz public fields i zachowaj legal accounting.

**Detekcja:** śledź announcement caller, token/amount, timing, gas sponsor, spending i consolidation; view key może dowodzić receipt bez prawa spend. **Capture-resilient OPSEC:** networked scanner powinien mieć wyłącznie viewing role, jeśli wspierane; spend i recovery keys przechowuj gdzie indziej. **Monitoring:** alertuj na malformed/spam announcements, view-key access, unexpected spend derivation i stealth outputs moved without approval.

## Liquid Confidential Transactions

**Mechanika:** Liquid domyślnie blinds output amounts i asset types za pomocą commitments/proofs, pozostawiając widoczne transaction graph, input/output count, fee i block time. Peg-in/peg-out i service boundaries pozostają linkable, a users mogą selektywnie ujawniać blinding data.<sup>[[22]](#references)</sup>

**Zalety:** confidential amount i asset type domyślnie; szybki sidechain settlement; selective audit przez blinding keys/descriptors; ukrywa commercial values przed public observers.

**Wady:** graph structure i timing pozostają; federation/bridge i exchange trust; peg boundaries i unconfidential outputs; wallet/node/network records; receiver i sender znają swoją transakcję.

**Procedura:** (1) wybierz utrzymywany Liquid wallet i sprawdź model backup; (2) użyj testnet lub małej legalnej kwoty; (3) odbierz na confidential address i sprawdź, czy wallet oznacza output jako blinded; (4) wyślij test confidential transaction; (5) sprawdź, które explorer fields pozostają publiczne; (6) eksportuj tylko scoped blinding proof potrzebny do audytu; (7) udokumentuj peg/exchange boundaries i reconcile funds.

**Detekcja:** analizuj visible graph/fee/time, peg i exchange records, network metadata oraz późniejsze unblinding evidence; nie wnioskuj ukrytego amount ani asset. **Capture-resilient OPSEC:** rozdziel spend seed, blinding/view data i watch-only operations. **Monitoring:** alertuj na accidental unconfidential addresses, unknown peg requests, descriptor changes i unapproved unblinding-key export.

## General payment lub state channel

**Mechanika:** participants blokują funds, wymieniają signed off-chain state updates i publikują on-chain tylko opening, closing lub disputed state. Intermediate payments nie są globalnie broadcast, ale peers i routing/intermediary services widzą swoją część, a endpoints muszą przechowywać latest enforceable state.<sup>[[23]](#references)</sup>

**Zalety:** wiele szybkich, niskokosztowych interakcji private-to-public-ledger; mniej global transaction detail; bounded channel balance; przydatne dla metered services i powtarzających się counterparties.

**Wady:** channel peers znają siebie i mogą przechowywać updates; opening/closing/value/timing korelują; podczas challenge windows może być wymagane online monitoring; implementation/liquidity risk; samo w sobie nie tworzy dużego anonymity set.

**Procedura:** (1) wybierz utrzymywaną, audytowaną implementację i poznaj dispute window; (2) otwórz low-value test channel między własnymi parties; (3) wymieniaj signed state updates z unique nonces; (4) wykonaj backup latest enforceable state; (5) zamknij cooperatively; (6) przećwicz stale-state rejection na testnet; (7) zachowaj accounting i channel-peer records.

**Detekcja:** public chain ujawnia lifecycle/disputes; peers, watch services i application transport ujawniają off-chain timing i parties. **Capture-resilient OPSEC:** ogranicz hot balance i przechowuj latest signed state w zaszyfrowanym, odzyskiwalnym storage oddzielonym od field nodes. **Monitoring:** stale obserwuj stale-state publication, missed backup, peer-key change i zbliżający się challenge deadline.

## Mobile carrier billing

**Mechanika:** online service obciąża zakup subskrypcję mobile lub prepaid balance przez carrier billing system. Merchant może otrzymać carrier authorization zamiast danych card/bank, podczas gdy carrier zna subscriber/line, device/network context, merchant, amount i time.<sup>[[24]](#references)</sup>

**Zalety:** brak numeru karty u merchant; szeroka dostępność telefonu; użyteczne dla low-value digital goods; carrier może ograniczać i odwracać charges.

**Wady:** silna identyfikacja przez SIM/account i często device; małe limity i wysokie fees; restrictions kategorii merchant; account takeover/SIM-swap risk; carrier i aggregator tworzą pełny trail transaction.

**Procedura:** (1) potwierdź availability, limit, fee i refund terms z organization carrier account; (2) włącz tylko na dedicated organization line, jeśli uzasadnione; (3) ustaw najniższy użyteczny spend cap; (4) kup benign test item; (5) zweryfikuj merchant i carrier receipts; (6) wyłącz recurring authorization; (7) reconcile i wyłącz funkcję po assessment.

**Detekcja:** carrier, aggregator i merchant records łączą line, subscriber, IP/device i charge; enterprise telecom invoices ujawniają transakcję. **Capture-resilient OPSEC:** nie używaj personal number i wymagaj carrier-account MFA poza field device. **Monitoring:** włącz instant charge/SIM-change alerts i zatrzymaj się przy nieoczekiwanym premium-service enrollment, forwarding lub account recovery.

## Open-banking payment initiation

**Mechanika:** za wyraźną zgodą usera regulated payment-initiation service provider (PISP) prosi account-servicing bank o zainicjowanie transferu. Merchant może nie otrzymać card credentials, ale PISP i banks zachowują regulowane rekordy payer, payee, consent, device i transaction.<sup>[[25]](#references)</sup>

**Zalety:** brak reusable card number przy checkout; silne bank authentication; dokładny account-to-account settlement; consent/status APIs; jasne reconciliation.

**Wady:** brak anonimowości wobec banks/PISP; payee często widzi legal account details lub reference; phishing/redirect risk; różne jurisdiction/refund protections; consent metadata dodaje kolejnego observera.

**Procedura:** (1) zweryfikuj, że PISP jest aktualnie regulowany i merchant callback domain autentyczny; (2) rozpocznij od merchant request; (3) sprawdź payee, amount, reference i requested consent w banku; (4) autoryzuj tylko pojedynczą płatność; (5) niezależnie zweryfikuj final status; (6) revoke residual consent, jeśli istnieje; (7) zachowaj receipt i reconcile.

**Detekcja:** bank/PISP/merchant logs i transfer references zapewniają silną attribution. **Capture-resilient OPSEC:** trzymaj banking authentication i recovery poza operational/field devices; device powinien przechowywać wyłącznie paid-service entitlement. **Monitoring:** używaj bank transaction/consent alerts i badaj nowe PISP grants, changed payee lub status callbacks poza oczekiwaną sesją.

## Platform wallet, app-store balance lub in-app credit

**Mechanika:** platform obciąża usera lub redeemuje account credit, a następnie wydaje signed receipt albo entitlement aplikacji. App developer może nie otrzymać pierwotnego funding instrument, podczas gdy platform mapuje account, device, funding, product i redemption.<sup>[[26]](#references)</sup>

**Zalety:** merchant/developer nie otrzymuje primary PAN; fraud/refund oraz family/business controls; małe prepaid balance ogranicza exposure; signed receipts upraszczają entitlement verification.

**Wady:** platform account jest silnym hubem identity/behavior; device i storefront geography; trail zakupu/redemption gift balance; ograniczony cash-out; fraud controls mogą zamrozić funds; nie jest to money cross-platform.

**Procedura:** (1) używaj organization-managed platform account, jeśli policy na to pozwala; (2) sprawdź funding, region, refund i transferable-value rules; (3) dodaj tylko zatwierdzony budget; (4) kup benign product przez official store; (5) zweryfikuj, że application otrzymuje tylko oczekiwane receipt fields; (6) wyłącz recurring purchase; (7) reconcile i usuń account z operational hardware.

**Detekcja:** platform receipts/server notifications, account/device login i funding records odtwarzają zakup. **Capture-resilient OPSEC:** nigdy nie loguj field node do personal store account; zapewniaj wyłącznie scoped app entitlement, jeśli możliwe. **Monitoring:** włącz new-device/purchase alerts i badaj receipt replay, family/account changes lub unexpected restore events.

## Mutual credit, clearing lub periodic net settlement

**Mechanika:** participants rejestrują obligations w prywatnym ledger i okresowo rozliczają wyłącznie swoje net positions. Pojedyncze service events nie muszą tworzyć osobnych public payments, ale ledger operator i counterparties zachowują szczegółową attribution.

**Zalety:** mniej external transactions i fees; public observers widzą tylko net settlement; działa dla powtarzających się organizations; explicit credit limits ograniczają exposure.

**Wady:** centralized ledger jest pełnym dowodem i celem fraud; counterparty/default risk; obowiązki legal/accounting/tax; mała membership set; nietypowe net transfers mogą nadal ujawnić relacje.

**Procedura:** (1) używaj tylko identified consenting organizations z legal/accounting approval; (2) określ unit, credit limit, settlement interval i dispute rules; (3) rejestruj każdą obligation z immutable approval; (4) oddzielne role finance obliczają i zatwierdzają net positions; (5) settlement wykonuj zwykłym legalnym railem; (6) reconcile individual lines z settlement; (7) zamknij access i zachowaj records zgodnie z policy.

**Detekcja:** ledger, invoices, approvals i final bank/chain settlement zapewniają ground truth; analysts nie powinni wywnioskować brakującej gross activity wyłącznie z net transfer. **Capture-resilient OPSEC:** operational devices mogą składać bounded requisitions, ale nie mogą edytować balances ani autoryzować settlement. **Monitoring:** alertuj na credit-limit breach, backdated entries, administrator changes, reconciliation mismatch i settlement do nowego beneficiary.

## Capture/compromise exposure matrix

Dotyczy to testu seizure/loss dla każdej rodziny. Celem jest ograniczenie spend authority i ujawnienia niezwiązanej tożsamości przy zachowaniu legal accounting — nie kasowanie transakcji ani utrudnianie investigation.

| Rodzina techniki | Co może ujawnić przejęty wallet/device/account | Minimalna autoryzowana kontrola |
|---|---|---|
| Cash, money order, COD, physical bearer value | paragony, numery seryjne, notatki, pozostałą wartość bearer i kontakty fizyczne | przenoś tylko zatwierdzoną kwotę; oddziel prywatną księgowość; szybko zgłoś utratę; bez fałszywych records |
| Prepaid, gift, voucher, service credits | balance, issuer, activation, redemption i account/session tokens | niskie saldo; jeden cel; prawdziwa rejestracja; issuer freeze/revocation, gdy dostępne |
| Virtual/tokenized card, wallet token, payment app | issuer account, device token, transactions, recovery i merchant history | device lock; transaction alerts; merchant scope; remote issuer suspension; bez wspólnego recovery account |
| Bank compartment, delegated procurement, red-team procurement | organization, approvers, vendor, invoices i project | role separation; least-privilege subaccount; finance credentials nigdy na operational/field nodes |
| Invoice, escrow, batch settlement | counterparty, purpose, pending approval, coordinator lub dispute trail | single-use request; oddzielny approver; limited session; central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, addresses, transaction graph i network configuration | hardware/offline signing; encrypted wallet; passphrase limits; watch-only field view; documented recovery |
| Lightning/BOLT 12 | seed, channels, invoices, peers/LSP i payment database | minimal hot balance; encrypted backup; separate node identity; close/recover zgodnie z dokumentacją |
| Monero, Zcash, MWEB, ZK applications | spend/view keys, local wallet history, RPC i boundary transactions | separate spend/view roles; hardware support, jeśli dostępne; bez exchange session na field node |
| Stablecoins, swaps, bridges i DEX | transparent graph, approvals, RPC/front-end state i destination assets | revoke allowances; verified contracts; low-value test; complete reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, issuance/redemption cache | small balance; encrypted backup zgodnie z protokołem; redeem/reissue; nigdy nie łącz funding credential |
| Paymaster, multisig/threshold | session key, one signer, pending operations i sponsor policy | narrow session key; independent quorum; signer rotation; field device bez dostępu do threshold |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider, communications, graph i participant records | brak użycia operacyjnego; emulacja wyłącznie syntetyczna/testnet |
| Community/event currency | enrollment, local balance, counterparties i redemption | capped value; issuer freeze/reissue; consent i prywatny audytowalny ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys, relationship metadata, announcements i derived outputs | watch/view-only network role; offline/hardware spend role; bez personal funding session |
| Liquid confidential/state channels | seed, blinding data/latest state, peers, boundaries i disputes | separate spend/view/state backup; low hot balance; independent dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account, consent, receipt, device i funding source | organization account; external MFA; low limit; bez personal account na field hardware |
| Mutual-credit clearing | members, obligations, limits, approvals i settlement ledger | operational requisition only; separate immutable ledger i dual finance approval |

## Monitoring possible discovery lub payment compromise

Odmowa płatności, compliance review lub przejście wallet offline nie dowodzi istnienia investigation. Monitoruj tylko accounts, ledgers i infrastructure, które organization ma prawo obserwować; nigdy nie sonduj providers ani counterparties, aby sprawdzić, czy współpracują z investigators.

| Objęte techniki | Bezpieczne sygnały monitoringu | Warunek freeze/stop |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch, duplicate serial, unexpected redemption/refund lub loss report | missing instrument, redemption poza approved order, altered receipt lub custody break |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alerts, new device/consent/payee, token reuse, SIM/account recovery | unknown authorization, payee change, new recovery factor, SIM swap lub recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project, role/token/budget change, invoice i consumption | cross-project token, unknown admin, limit breach, invoice mismatch lub unsupported destination |
| Invoice, escrow, pooled settlement, mutual credit | request expiry, approval/release, ledger integrity, reconciliation i beneficiary change | altered amount/payee, backdated ledger, unilateral release lub unreconciled batch |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transactions, notification/scan state, address reuse, UTXO labels i consolidation | unknown spend, reused recipient output, wallet gap/recovery failure lub unapproved merge |
| PayJoin/CoinJoin | proposal inputs/outputs/fees, coordinator availability, final transaction equality | substituted output, excessive fee, unexpected input disclosure lub coordinator policy change |
| Lightning/BOLT12/general channels | channel backup, invoice/offer use, liquidity, peer/LSP i chain dispute | unknown invoice payment, peer-key change, stale close lub approaching dispute deadline |
| Monero/Zcash/MWEB/Liquid CT | view/watch events, pool/domain/address type, descriptor i boundary transaction | spend without approval, transparent/unconfidential downgrade, key export lub unknown boundary |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session key i issuer action | wrong contract/public field, unknown approval/spend, paymaster change lub issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health, token double-spend/replay, gateway i bearer balance | unknown redemption, mint key/terms change, restore failure lub balance inconsistency |
| Swaps/bridges/DEX | verified contract, allowance, both-chain confirmations, rate i destination | contract/route mismatch, unlimited approval, missing destination lub bridge incident |
| Multisig/threshold | signer-set/policy change, pending proposal, quorum i recovery audit | unknown proposal/signer, threshold reduction, recovery activation lub policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | wyłącznie synthetic lab ground truth i detection output | jakiekolwiek real account, person lub value w emulacji: natychmiast stop |

## Workflow wyboru i weryfikacji

1. Określ, która strona nie może poznać którego pola.
2. Zidentyfikuj issuer/mint/custodian, public ledger, network/RPC, merchant i physical observers.
3. Zweryfikuj aktualne support, legality, limits, custody, recovery i refund behavior.
4. Wykonaj mały, legalny test end-to-end.
5. Sprawdź merchant receipt, provider statement, public chain oraz wallet/node logs.
6. Przetestuj backup/recovery i celowe audit disclosure.
7. Utrzymuj wymagane source, ownership, tax, sanctions i engagement records dokładne, lecz access-controlled.

## References

- [1] [EMVCo — Tokenizacja płatności](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Obserwacje dotyczące zbierania danych przez duże platformy płatnicze](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Chroń swoją prywatność](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Prosta propozycja Payjoin](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Protokół Onion Routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Specyfikacje techniczne i prywatność sieci](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Tworzenie aplikacji privacy z użyciem zero-knowledge proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Ograniczenia protokołu i prywatności](https://docs.cashu.space/faq)
- [13] [Fedimint — Jak to działa](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Wskaźniki ryzyka dotyczące Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administrators, exchangers and users of virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
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
{{#include ../banners/hacktricks-training.md}}
