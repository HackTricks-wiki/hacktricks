# Prywatność kryptowalut

Prywatność kryptowalut to kwestia protokołu i operacji, a nie synonim tajemnicy lub odporności na ujawnienie. Publiczne rejestry, giełdy, serwery portfeli, peerzy sieci, sprzedawcy i późniejsze transakcje ujawniają różne części grafu.

Zacznij od [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md), aby zapoznać się z formatem pros/cons/procedure/detection dla poszczególnych technik. Ta strona rozwija mechanizmy specyficzne dla kryptowalut i ograniczenia operacyjne.

{% hint style="danger" %}
Ten rozdział dotyczy zgodnego z prawem self-custody i minimalizacji danych. Nie używaj go do prania środków, obchodzenia sankcji, zobowiązań podatkowych lub sprawozdawczych, zawierania transakcji z podmiotami objętymi zakazem, wprowadzania w błąd regulowanego dostawcy ani prowadzenia nielicencjonowanej usługi transferu. Technologia prywatności nie zmienia legalnego pochodzenia ani własności środków.
{% endhint %}

## Model zagrożeń według warstwy

| Warstwa | Obserwator | Typowe ujawniane informacje |
|---|---|---|
| Nabycie/off-ramp | Giełda, bank, broker, kontrahent P2P | Tożsamość, konto finansujące, miejsce docelowe, urządzenie, IP, czas |
| Ledger | Każdy prowadzący analytics | Adresy/wyjścia, kwoty i czas w transparentnych chainach; specyficzne dla protokołu metadane w innych miejscach |
| Backend portfela | Dostawca RPC, explorer, zdalny node | Zapytania o adresy, salda, IP, broadcast transakcji |
| Sieć | ISP, peery, wejście do anonymity-network | IP, czas, wolumen i użycie protokołu |
| Kontrahent | Płatnik/odbiorca | Invoice/adres, dostawa, rozmowa, konto i czas |
| Endpoint | Malware, backup cloud, fizyczne przejęcie | Seed, klucze, etykiety, historia, zrzuty ekranu i schowek |

Self-custody może usunąć custodian z ścieżki kontroli, ale nie usuwa ledgera, zapisu nabycia, metadanych sieci ani dowodów na endpoincie.

## Porównanie protokołów

| Metoda | Przydatna właściwość prywatności | Istotne ograniczenia |
|---|---|---|
| Bitcoin on-chain | Self-custody; świeże adresy unikają prostego ponownego użycia adresu | Publiczny, trwały graf transakcji; heurystyki kwot/czasu i wydawania |
| Bitcoin PayJoin | Input odbiorcy może złamać heurystykę common-input-ownership | Oba portfele muszą obsługiwać tę funkcję; transakcja pozostaje publiczna; wsparcie jest nierówne |
| Bitcoin CoinJoin | Tworzy niejednoznaczność między skoordynowanymi uczestnikami | Rozpoznawalne wzorce, powiązania przed/po, konsolidacja, ryzyko związane z polityką, prawem i dostawcą |
| Lightning | Płatności routowane onion nie są globalnie publikowane jako zwykłe transfery | Kanały są otwierane/zamykane on-chain; endpointy, peery, probe'y lub custodian mogą wywnioskować dane |
| Monero | Silniejsza domyślna poufność on-chain odbiorcy, kwoty i zbioru nadawców | Powiązania z giełdą, nodem, czasem, endpointem i kontrahentem pozostają |
| Ethereum/stablecoins | Szeroka dostępność i interoperacyjność smart-contractów | Publiczny stan/działania; metadane RPC; scentralizowani emitenci mogą blokować/freezować/raportować |

## Bitcoin: baseline zachowujący prywatność

Bitcoin jest pseudonimowy, a nie anonimowy. Potwierdzone transakcje są publiczne i trwałe; ponowne użycie adresu, common-input ownership, wykrywanie change oraz publicznie zidentyfikowane adresy mogą tworzyć klastry.<sup>[[1]](#references)</sup>

### Workflow

1. **Wybierz utrzymywany portfel self-custody.** Pobierz go z oficjalnego projektu, weryfikuj podpisy/hash'e, gdy są udostępniane, i stosuj aktualizacje bezpieczeństwa.
2. **Utwórz portfel na zaufanym endpoincie.** Zapisz recovery seed offline; nigdy nie umieszczaj go w e-mailu, chacie, zrzutach ekranu ani zwykłych notatkach cloud. Przetestuj odzyskiwanie przed przechowywaniem większej wartości.
3. **Trzymaj hot tylko środki operacyjne.** Dla wartości długoterminowej używaj odpowiedniego offline/hardware custody, z planem odzyskiwania, który nie ujawnia seeda w jednym podatnym miejscu.
4. **Generuj świeży adres odbiorczy/invoice dla każdej transakcji.** Nie publikuj statycznego adresu, gdy możliwy jest invoice server lub uwierzytelniona prywatna dostawa.
5. **W miarę możliwości używaj własnego full node'a.** Zewnętrzny explorer/serwer electrum może poznać wyszukiwane adresy i metadane IP. Konfiguruj wyłącznie obsługiwane przez portfel zachowanie Tor/proxy; Tor ukrywa krawędź sieci, a nie graf blockchaina.
6. **Oznaczaj każdy UTXO prywatnie** źródłem, właścicielem, celem i stanem compliance. Włącz coin control, aby niepowiązane konteksty tożsamości nie były wydawane wspólnie.
7. **Podglądaj transakcję:** wybrane inputy, miejsce docelowe change, kwotę, fee, kontrahenta oraz to, czy wydatek łączy przegródki. Unikaj niepotrzebnej konsolidacji.
8. **Przechowuj zgodne z prawem dokumenty oddzielnie i szyfruj je.** Zachowuj podstawę nabycia, faktury, autoryzację oraz informacje podatkowe/sprawozdawcze bez publikowania mapowania.
9. **Traktuj późniejsze wydawanie jako część tej samej decyzji dotyczącej prywatności.** Dobrze odseparowany odbiór może zostać ponownie powiązany, gdy jego output zostanie wydany wspólnie ze zidentyfikowanymi środkami.

Dokumentacja prywatności Bitcoin Core wyjaśnia, że full node nie ujawnia zapytań portfela zewnętrznym serwerom, ale broadcast transakcji i publiczna historia nadal wymagają analizy.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin to współpracująca płatność, w której odbiorca dodaje input. Pokonuje to uproszczone założenie, że wszystkie inputy należą do nadawcy. BIP 78 opisuje pierwotny interaktywny protokół; draft BIP 77 definiuje asynchroniczny projekt v2 wykorzystujący szyfrowaną skrzynkę/OHTTP.<sup>[[3]](#references)</sup>

Bezpieczne użycie:

1. Potwierdź, że oba utrzymywane portfele obsługują tę samą wersję PayJoin.
2. Uzyskaj invoice obsługujący PayJoin przez uwierzytelniony kanał; chroń go jak każde żądanie płatności.
3. Sprawdź pierwotną kwotę i miejsce docelowe, a następnie pozwól portfelowi zweryfikować propozycję/PSBT, udział w fee i niedozwolone podmiany.
4. Potwierdź końcowe podsumowanie portfela. Nie zatwierdzaj ręcznie nieoczekiwanego outputu, kwoty ani nadmiernego fee.
5. Jeśli negocjacja się nie powiedzie, sprawdź, czy portfel bezpiecznie przechodzi do zwykłej płatności, czy wymaga nowego invoice.
6. Zachowaj prywatny odbiór/dokumentację wymaganą do celów własności, księgowości i sporów.

PayJoin poprawia jedną heurystykę chain analysis; nie ukrywa płatności przed stronami, platformą nabycia, endpointami ani publicznym ledgerem.

## CoinJoin: korzyści i ograniczenia

CoinJoin koordynuje wielu użytkowników w jednej transakcji, aby utrudnić pewne powiązanie inputów z outputami. Badania konkretnych historycznych projektów Wasabi i Samourai wykazały wysoce rozpoznawalne transakcje oraz pokazały, że zachowanie przed i po mixie może znacznie zawęzić anonimowość.<sup>[[4]](#references)</sup> Nie należy uogólniać tego wyniku na każdą implementację ani przyszłą wersję, ale pokazuje on, dlaczego liczba „anonymity-set” nie jest gwarancją.

Przed jakimkolwiek zgodnym z prawem użyciem:

- sprawdź aktualne lokalne prawo, status sankcji, politykę giełdy/custodiana oraz obowiązki podatkowe/sprawozdawcze;
- używaj utrzymywanego, non-custodial software uzyskanego z oficjalnego projektu;
- zrozum model coordinatora, opłaty, mechanizmy ochrony przed denial-of-service oraz to, czy dana usługa nadal działa — zkSNACKs zakończył działanie swojego coordinatora w 2024 roku, choć mogą istnieć inni coordinatorzy Wasabi;
- zachowuj prywatnie dokumentację źródła środków i transakcji;
- nigdy nie przyjmuj nieznanych środków w imieniu innej osoby ani nie używaj custodial „mixera” obiecującego nieśledzalne wypłaty;
- utrzymuj separację outputów według źródła/kontekstu i unikaj późniejszej konsolidacji, która niszczy zamierzoną niejednoznaczność.

Skutki prawne zależą od faktów i jurysdykcji. Przyznanie się założycieli Samourai w 2025 roku dotyczyło świadomego prowadzenia nielicencjonowanego money transmittera, który przenosił środki pochodzące z przestępstw; nie oznacza to, że każda współpracująca transakcja lub użytkownik poszukujący prywatności jest przestępcą.<sup>[[5]](#references)</sup>

## Lightning Network

Onion routing Sphinx w Lightning został zaprojektowany tak, aby pośredni hop poznawał swojego poprzednika i następcę, a nie całą trasę.<sup>[[6]](#references)</sup> Nie jest to pełna anonimowość: finansowanie/zamykanie kanałów jest publiczne, node'y ogłaszają topologię, kontrahenci znają endpointy, routing/probing może ujawniać salda lub strony, a custodial wallet widzi aktywność konta użytkownika.

Dla lepszej prywatności:

1. Jeśli prywatność pośrednika ma znaczenie, wybierz utrzymywany non-custodial wallet; najpierw zaplanuj backup/odzyskiwanie kanałów.
2. Używaj świeżego invoice lub offer dla każdej płatności. Sprawdź, czy dany portfel dokładnie obsługuje BOLT 12/route blinding, zamiast zakładać, że tak jest.
3. Unikaj publikowania niepotrzebnych aliasów node'ów, danych kontaktowych i stabilnych endpointów sieciowych.
4. W razie potrzeby łącz się przez obsługiwaną sieć prywatności, pamiętając, że wzorce dostępności/czasu nadal mogą być korelowane.
5. Nie zakładaj, że płatność off-chain nie pozostawia zapisów: nadawca, odbiorca, peery, watchtowers, dostawcy liquidity i usługi portfela mogą przechowywać obserwacje.

Opublikowane badania wykazały możliwość wnioskowania o nadawcy/odbiorcy i saldzie kanału na podstawie danych publicznych oraz aktywnego probingu, choć ataki i środki zaradcze ewoluują.<sup>[[7]](#references)</sup>

## Monero

Monero używa jednorazowych stealth addresses dla outputów, RingCT do ukrywania kwot oraz ring signatures zapewniających probabilistyczną niejednoznaczność nadawcy; aktualne specyfikacje techniczne dokumentują ring size równy 16 (15 decoyów).<sup>[[8]](#references)</sup> Są to silniejsze domyślne zabezpieczenia poufności on-chain niż w transparentnych ledgerach, ale nie stanowią magicznej ochrony przed błędami endpointu ani operacyjnymi.

### Zgodny z prawem workflow

1. **Pozyskuj zgodnie z prawem.** Regulowana giełda może znać zakup i wypłatę, nawet gdy późniejsze szczegóły on-chain są poufne. Zachowuj informacje o źródle, podstawie i sprawozdawczości.
2. **Zainstaluj oficjalny, utrzymywany wallet** i zweryfikuj pobranie zgodnie z instrukcjami projektu. Wykonaj backup seeda offline i przetestuj przywracanie niewielką kwotą.
3. **Preferuj lokalny node** dla maksymalnej prywatności zapytań portfela. Jeśli jest to niepraktyczne, wybierz zaufany remote node dostępny przez oficjalnie obsługiwaną konfigurację onion/I2P. Remote node może rejestrować IP, żądania, czas i identyfikatory transakcji; niektóre lekkie projekty ujawniają view key.
4. **Używaj nowego subaddress dla każdego płatnika, campaign lub invoice.** Płatnik może skorelować wielokrotne użycie tego samego subaddress.<sup>[[9]](#references)</sup>
5. **Oznaczaj lokalnie konteksty wpływów.** Unikaj operacyjnego łączenia oddzielonych wpływów, gdy świadomy płatnik mógłby rozpoznać późniejsze zachowanie.
6. **Chroń metadane sieciowe.** Postępuj zgodnie z oficjalną konfiguracją anonymity-network; uwzględnij udokumentowane leaki wynikające ze znaczników czasu, przerywanej synchronizacji, kształtu przepustowości i ponownego użycia strumieni.<sup>[[10]](#references)</sup>
7. **Przechowuj prywatnie dane compliance/audytu.** Ujawniaj view key lub dowód transakcji wyłącznie świadomie, zamierzonemu audytorowi/stronie, i dokładnie rozumiej, co ujawnia.

Historyczne badania traceability obejmują bugi i okresy stosowania określonych metod wyboru decoyów, które od tego czasu się zmieniły; nie stosuj dawnych odsetków skuteczności do obecnych transakcji. Podobnie FCMP++ pozostaje pracą roadmapową na dzień cutoffu badania tego rozdziału we wrześniu 2026 roku, a nie wdrożonym zabezpieczeniem.<sup>[[11]](#references)</sup>

## Ethereum i stablecoins

Materiały Ethereum dotyczące prywatności wskazują, że działania on-chain są widoczne, a infrastruktura portfela/RPC zwiększa ekspozycję IP i metadanych.<sup>[[12]](#references)</sup> Transfery tokenów, approvals, interakcje ze smart-contractami, name services i finansowanie gas mogą łączyć tożsamości.

Scentralizowane stablecoins dodają kontrolę emitenta. Aktualne warunki USDC i Tether zastrzegają uprawnienia do blokowania/freezowania adresów lub aktywów oraz do wykonywania obowiązków prawnych i procesowych.<sup>[[13]](#references)</sup> Mogą być użytecznymi instrumentami płatniczymi, ale są złym wyborem, gdy wymaganiem jest odporność na cenzurę lub anonimowość on-chain.

## Granice compliance

- Zalecenia FATF są wdrażane przez prawo krajowe i zmieniają się z czasem; aktualizacja z 2026 roku kładzie nacisk na licencjonowanie/rejestrację VASP oraz wdrażanie Travel Rule.<sup>[[14]](#references)</sup>
- W USA FinCEN odróżnia osobę używającą convertible virtual currency do własnych towarów/usług od firmy przyjmującej i transmitującej lub wymieniającej ją; znaczenie mają fakty i późniejsze regulacje.<sup>[[15]](#references)</sup>
- Unijne rozporządzenie Transfer of Funds Regulation wymaga informacji o nadawcy/beneficjencie, gdy zaangażowany jest crypto-asset service provider, oraz dodaje zasady weryfikacji dla określonych transferów do/z self-hosted addresses.<sup>[[16]](#references)</sup>
- Sankcje i obowiązki podatkowe nadal obowiązują. Wykonuj wymagany screening, odmawiaj podmiotom objętym zakazem i prowadź dokumentację; listy oraz status prawny mogą szybko się zmieniać.<sup>[[17]](#references)</sup>

Przed zaangażowaniem większej wartości, działalnością transgraniczną, koordynacją privacy-enhancing lub wymianą/transmisją o charakterze biznesowym uzyskaj aktualną profesjonalną poradę dotyczącą odpowiednich jurysdykcji.

W przypadku Bitcoin Silent Payments, w pełni shielded Zcash, GNU Taler, federated Chaumian e-cash oraz BOLT 12 przejdź do [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Chroń swoją prywatność](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Funkcje prywatności](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Prosta propozycja PayJoin](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Adopcja i rzeczywista prywatność zdecentralizowanych implementacji CoinJoin w Bitcoinie (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Założyciele Samourai Wallet przyznają się do winy (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Protokół Onion Routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Empiryczna analiza prywatności w Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) oraz [Specyfikacje techniczne](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Sieci](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Badanie ewolucji prywatności Monero (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Prywatność w Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — Warunki USDC](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Ukierunkowana aktualizacja dotycząca aktywów wirtualnych i VASP z 2026 roku](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Zastosowanie regulacji FinCEN do osób administrujących, wymieniających lub używających walut wirtualnych](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Rozporządzenie (UE) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Wytyczne dotyczące zgodności z sankcjami dla branży walut wirtualnych](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
