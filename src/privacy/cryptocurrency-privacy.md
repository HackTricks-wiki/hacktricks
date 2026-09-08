# Prywatność kryptowalut

{{#include ../banners/hacktricks-training.md}}

Prywatność kryptowalut to kwestia protokołu i operacji, a nie synonim tajemnicy ani bezkarności. Publiczne ledger, giełdy, serwery portfeli, peery sieciowe, sprzedawcy i późniejsze transakcje ujawniają różne części grafu.

Zacznij od [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md), aby zapoznać się z formatem pros/cons/procedure/detection dla poszczególnych technik. Ta strona rozwija mechanizmy specyficzne dla kryptowalut i ograniczenia operacyjne.

{% hint style="danger" %}
Ten rozdział dotyczy zgodnego z prawem self-custody i minimalizacji danych. Nie używaj go do prania środków, obchodzenia sankcji/podatków/obowiązków sprawozdawczych, przeprowadzania transakcji z podmiotami objętymi zakazem, wprowadzania w błąd regulowanego dostawcy ani prowadzenia nielicencjonowanej usługi transferu. Technologia prywatności nie zmienia legalnego pochodzenia ani własności środków.
{% endhint %}

## Model zagrożeń według warstwy

| Warstwa | Obserwator | Typowe ujawniane informacje |
|---|---|---|
| Acquisition/off-ramp | Giełda, bank, broker, kontrahent P2P | Tożsamość, konto finansujące, cel, urządzenie, IP, czas |
| Ledger | Każdy prowadzący analytics | Adresy/outputy, kwoty i czas w transparentnych chainach; metadane specyficzne dla protokołu w innych miejscach |
| Backend portfela | Dostawca RPC, explorer, zdalny node | Zapytania o adresy, salda, IP, broadcast transakcji |
| Sieć | ISP, peery, wejście do anonymity-network | IP, czas, wolumen i użycie protokołu |
| Kontrahent | Płatnik/odbiorca | Invoice/adres, dostawa, rozmowa, konto i czas |
| Endpoint | Malware, cloud backup, fizyczne przejęcie | Seed, klucze, etykiety, historia, screenshoty i schowek |

Self-custody może usunąć custodian z procesu kontroli, ale nie usuwa ledger, rekordu nabycia, metadanych sieciowych ani dowodów na endpoint.

## Porównanie protokołów

| Metoda | Przydatna właściwość prywatności | Istotne ograniczenia |
|---|---|---|
| Bitcoin on-chain | Self-custody; fresh addresses unikają prostego ponownego użycia adresu | Publiczny, trwały graf transakcji; heurystyki kwoty/czasu i wydawania |
| Bitcoin PayJoin | Input odbiorcy może przełamać heurystykę common-input-ownership | Oba portfele muszą obsługiwać tę funkcję; transakcja pozostaje publiczna; wsparcie jest nierówne |
| Bitcoin CoinJoin | Tworzy niejednoznaczność między skoordynowanymi uczestnikami | Rozpoznawalne wzorce, linki przed/po, konsolidacja, ryzyko związane z polityką/prawem/dostawcą |
| Lightning | Płatności routowane onion nie są globalnie publikowane jako zwykłe transfery | Otwarcie/zamknięcie kanałów odbywa się on-chain; endpointy, peery, probe lub custodian mogą wnioskować o danych |
| Monero | Silniejsza domyślna poufność on-chain odbiorcy, kwoty i zbioru nadawców | Powiązania z giełdą, nodem, czasem, endpointem i kontrahentem pozostają |
| Ethereum/stablecoins | Szeroka dostępność i interoperacyjność smart-contractów | Publiczny stan/działania; metadane RPC; scentralizowani issuerzy mogą blokować/freezować/raportować |

## Bitcoin: podstawowy poziom ochrony prywatności

Bitcoin jest pseudonimowy, a nie anonimowy. Potwierdzone transakcje są publiczne i trwałe; ponowne używanie adresów, common-input ownership, wykrywanie change oraz publicznie zidentyfikowane adresy mogą tworzyć klastry.<sup>[[1]](#references)</sup>

### Workflow

1. **Wybierz utrzymywany portfel self-custody.** Pobierz go z oficjalnego projektu, weryfikuj podpisy/hashe, jeśli są dostępne, i stosuj security updates.
2. **Utwórz portfel na zaufanym endpoincie.** Zapisz recovery seed offline; nigdy nie umieszczaj go w emailu, chacie, screenshotach ani zwykłych notatkach w chmurze. Przetestuj recovery przed przechowywaniem znaczącej wartości.
3. **Przechowuj hot tylko środki operacyjne.** Dla wartości długoterminowej używaj odpowiedniego offline/hardware custody wraz z planem recovery, który nie ujawnia seeda w jednym podatnym miejscu.
4. **Generuj fresh receive address/invoice dla każdej transakcji.** Nie publikuj statycznego adresu, gdy możliwe jest użycie invoice servera lub uwierzytelnionej prywatnej dostawy.
5. **W miarę możliwości używaj własnego full node.** Zewnętrzny explorer/electrum server może poznać odpytywane adresy i metadane IP. Konfiguruj wyłącznie obsługiwane przez portfel zachowanie Tor/proxy; Tor ukrywa krawędź sieci, a nie graf blockchaina.
6. **Prywatnie opisuj każdy UTXO** źródłem, właścicielem, przeznaczeniem i statusem compliance. Włącz coin control, aby niezwiązane ze sobą konteksty tożsamości nie były wydawane razem.
7. **Przejrzyj transakcję:** wybrane inputy, cel change, kwotę, fee, kontrahenta i to, czy wydatek łączy rozdzielone segmenty. Unikaj niepotrzebnej konsolidacji.
8. **Przechowuj zgodne z prawem rejestry oddzielnie i w formie zaszyfrowanej.** Zachowaj podstawę nabycia, faktury, autoryzację i informacje podatkowe/sprawozdawcze bez publikowania mapowania.
9. **Traktuj późniejsze wydawanie jako część tej samej decyzji dotyczącej prywatności.** Dobrze odseparowany odbiór może zostać ponownie powiązany, gdy jego output zostanie wydany razem ze zidentyfikowanymi środkami.

Dokumentacja prywatności Bitcoin Core wyjaśnia, że full node zapobiega ujawnianiu zapytań portfela zewnętrznym serwerom, ale broadcast transakcji i publiczna historia nadal wymagają analizy.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin to współdzielona płatność, w której odbiorca dodaje input. Uniemożliwia to uproszczone założenie, że wszystkie inputy należą do nadawcy. BIP 78 opisuje oryginalny interaktywny protokół; draft BIP 77 definiuje asynchroniczny projekt v2 wykorzystujący zaszyfrowaną skrzynkę pocztową/OHTTP.<sup>[[3]](#references)</sup>

Bezpieczne użycie:

1. Potwierdź, że oba utrzymywane portfele obsługują tę samą wersję PayJoin.
2. Uzyskaj invoice obsługujący PayJoin przez uwierzytelniony kanał; chroń go tak jak każde żądanie płatności.
3. Sprawdź pierwotną kwotę i cel, a następnie pozwól portfelowi zweryfikować proposal/PSBT, udział w fee i niedozwolone zamiany.
4. Potwierdź końcowe podsumowanie portfela. Nie zatwierdzaj ręcznie nieoczekiwanego outputu, kwoty ani nadmiernego fee.
5. Jeśli negocjacja się nie powiedzie, sprawdź, czy portfel bezpiecznie przechodzi do zwykłej płatności, czy wymaga nowego invoice.
6. Zachowaj prywatny odbiór/rejestry wymagane do potwierdzenia własności, księgowości i rozstrzygania sporów.

PayJoin poprawia jedną heurystykę chain analysis; nie ukrywa płatności przed stronami, platformą nabycia, endpointami ani publicznym ledgerem.

## CoinJoin: korzyści i ograniczenia

CoinJoin koordynuje wielu użytkowników w jednej transakcji, aby mapowanie input-output było mniej pewne. Badania konkretnych historycznych projektów Wasabi i Samourai wykazały wysoce rozpoznawalne transakcje oraz pokazały, że zachowanie przed/po mixie może znacznie zawężać anonimowość.<sup>[[4]](#references)</sup> Wyniku tego nie należy uogólniać na każdą implementację ani przyszłą wersję, ale pokazuje on, dlaczego liczba „anonymity-set” nie jest gwarancją.

Przed jakimkolwiek zgodnym z prawem użyciem:

- sprawdź aktualne lokalne prawo, status sankcji, politykę giełdy/custodiana oraz obowiązki podatkowe/sprawozdawcze;
- używaj utrzymywanego, non-custodial software uzyskanego z oficjalnego projektu;
- zrozum model coordinatora, fee, mechanizmy ochrony przed denial-of-service oraz to, czy bieżąca usługa nadal działa — zkSNACKs zakończył działanie swojego coordinatora w 2024 roku, choć mogą istnieć inni coordinatorzy Wasabi;
- prywatnie zachowuj rejestry źródła środków i transakcji;
- nigdy nie przyjmuj nieznanych środków w imieniu innej osoby ani nie używaj custodial „mixera” obiecującego nieśledzalne wypłaty;
- utrzymuj outputy oddzielnie według źródła/kontekstu i unikaj późniejszej konsolidacji, która niszczy zamierzoną niejednoznaczność.

Skutki prawne zależą od faktów i jurysdykcji. Przyznanie się założycieli Samourai do winy w 2025 roku dotyczyło świadomego prowadzenia nielicencjonowanego money transmittera, który przenosił środki pochodzące z przestępstw; nie ustanawia to zasady, że każda transakcja collaborative ani każdy użytkownik poszukujący prywatności jest przestępcą.<sup>[[5]](#references)</sup>

## Lightning Network

Sphinx onion routing w Lightning został zaprojektowany tak, aby pośredni hop poznawał swojego poprzednika i następcę, a nie całą trasę.<sup>[[6]](#references)</sup> Nie zapewnia to pełnej anonimowości: finansowanie/zamykanie kanałów jest publiczne, nody ogłaszają topologię, kontrahenci znają endpointy, routing/probing może ujawniać salda lub strony, a custodial wallet widzi aktywność konta użytkownika.

Dla lepszej prywatności:

1. Jeśli prywatność pośrednika ma znaczenie, preferuj utrzymywany non-custodial wallet; najpierw zaplanuj backup/recovery kanałów.
2. Używaj fresh invoice lub offer dla każdej płatności. Sprawdź, czy konkretny portfel obsługuje BOLT 12/route blinding, zamiast zakładać, że tak jest.
3. Unikaj publikowania niepotrzebnych aliasów noda, danych kontaktowych i stabilnych endpointów sieciowych.
4. W razie potrzeby łącz się przez obsługiwaną privacy network, rozumiejąc, że wzorce dostępności/czasu nadal mogą być korelowane.
5. Nie zakładaj, że płatność off-chain nie pozostawia rejestrów: nadawca, odbiorca, peery, watchtowers, dostawcy płynności i usługi portfela mogą zachowywać obserwacje.

Opublikowane badania wykazały możliwość wnioskowania o nadawcy/odbiorcy i saldzie kanału na podstawie danych publicznych oraz aktywnego probing, choć ataki i środki zaradcze ewoluują.<sup>[[7]](#references)</sup>

## Monero

Monero używa jednorazowych stealth addresses dla outputów, RingCT do ukrywania kwot oraz ring signatures zapewniających probabilistyczną niejednoznaczność nadawcy; aktualne specyfikacje techniczne dokumentują ring size równy 16 (15 decoy).<sup>[[8]](#references)</sup> Są to silniejsze domyślne mechanizmy poufności on-chain niż w transparentnych ledgerach, ale nie stanowią magicznej ochrony przed błędami endpointu ani operacji.

### Zgodny z prawem workflow

1. **Pozyskuj środki zgodnie z prawem.** Regulowana giełda może znać zakup i wypłatę, nawet gdy późniejsze szczegóły on-chain są poufne. Zachowaj informacje o źródle, podstawie i raportowaniu.
2. **Zainstaluj oficjalny utrzymywany wallet** i zweryfikuj pobranie zgodnie z instrukcjami projektu. Utwórz backup seeda offline i przetestuj przywracanie na małej kwocie.
3. **Preferuj lokalny node** dla maksymalnej prywatności zapytań portfela. Jeśli jest to niepraktyczne, wybierz zaufany remote node dostępny przez oficjalnie obsługiwaną konfigurację onion/I2P. Remote node może rejestrować IP, żądania, czas i transaction IDs; niektóre lekkie projekty ujawniają view key.
4. **Używaj nowego subaddress dla każdego płatnika, campaign lub invoice.** Płatnik może skorelować wielokrotne użycie tego samego subaddress.<sup>[[9]](#references)</sup>
5. **Lokalnie opisuj konteksty przychodzące.** Unikaj operacyjnego łączenia odseparowanych wpływów, gdy świadomy tego płatnik mógłby rozpoznać późniejsze zachowanie.
6. **Chroń metadane sieciowe.** Stosuj oficjalną konfigurację anonymity-network; uwzględniaj udokumentowane leaki wynikające ze znaczników czasu, przerywanej synchronizacji, kształtu przepustowości i ponownego użycia streamów.<sup>[[10]](#references)</sup>
7. **Przechowuj prywatnie dane compliance/audytu.** Ujawniaj view key lub dowód transakcji wyłącznie celowo, zamierzonemu audytorowi/stronie, i dokładnie rozumiej, co ujawnia.

Historyczne badania traceability obejmują błędy i epoki wyboru decoy, które od tego czasu uległy zmianie; nie stosuj dawnych odsetków skuteczności do obecnych transakcji. Podobnie FCMP++ pozostaje pracą roadmapową na dzień końca badań do tego rozdziału, czyli wrzesień 2026 roku, a nie wdrożoną ochroną.<sup>[[11]](#references)</sup>

## Ethereum i stablecoins

Materiały Ethereum dotyczące prywatności wskazują, że działania on-chain są widoczne, a infrastruktura portfela/RPC zwiększa ekspozycję IP i metadanych.<sup>[[12]](#references)</sup> Transfery tokenów, approvals, interakcje ze smart-contractami, name services i finansowanie gas mogą łączyć tożsamości.

Scentralizowane stablecoins dodają kontrolę issuera. Aktualne warunki USDC i Tether zastrzegają uprawnienia do blokowania/freezing adresów lub aktywów oraz do przestrzegania obowiązków prawnych/procesowych.<sup>[[13]](#references)</sup> Mogą być użytecznymi instrumentami płatniczymi, ale są złym wyborem, gdy wymaganiem jest odporność na cenzurę lub anonimowość on-chain.

## Granice compliance

- Zalecenia FATF są wdrażane przez prawo krajowe i zmieniają się z czasem; aktualizacja z 2026 roku podkreśla licencjonowanie/rejestrację VASP i wdrażanie Travel Rule.<sup>[[14]](#references)</sup>
- W USA FinCEN odróżnia osobę używającą convertible virtual currency do własnych towarów/usług od firmy, która ją przyjmuje i transmituje lub wymienia; znaczenie mają fakty i późniejsze przepisy.<sup>[[15]](#references)</sup>
- Unijne rozporządzenie Transfer of Funds wymaga informacji o originatorze/beneficjencie, gdy zaangażowany jest dostawca usług crypto-asset, oraz dodaje zasady weryfikacji dla określonych transferów do/z adresów self-hosted.<sup>[[16]](#references)</sup>
- Sankcje i obowiązki podatkowe nadal obowiązują. Wymagany screening, odmawiaj podmiotom objętym zakazem i przechowuj rejestry; listy oraz status prawny mogą szybko się zmieniać.<sup>[[17]](#references)</sup>

Przed przechowywaniem znacznej wartości, działalnością transgraniczną, koordynacją privacy-enhancing lub wymianą/transferem o charakterze biznesowym uzyskaj aktualną profesjonalną poradę dla odpowiednich jurysdykcji.

W przypadku Bitcoin Silent Payments, w pełni shielded Zcash, GNU Taler, federated Chaumian e-cash i BOLT 12 przejdź do [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Chroń swoją prywatność](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Funkcje prywatności](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Prosta propozycja Payjoin](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Adopcja i rzeczywista prywatność zdecentralizowanych implementacji CoinJoin w Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Założyciele Samourai Wallet przyznają się do winy (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Protokół Onion Routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Empiryczna analiza prywatności w Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) oraz [Specyfikacje techniczne](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Networks](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Ewolucja prywatności Monero (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Prywatność w Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — Warunki USDC](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Ukierunkowana aktualizacja dotycząca Virtual Assets i VASP z 2026 roku](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Zastosowanie przepisów FinCEN do osób administrujących, wymieniających lub używających Virtual Currencies](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Rozporządzenie (UE) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Wytyczne dotyczące zgodności z sankcjami dla branży Virtual Currency](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
{{#include ../banners/hacktricks-training.md}}
