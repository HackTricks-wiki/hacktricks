# Systemy operacyjne ukierunkowane na prywatność

Systemy operacyjne skoncentrowane na prywatności ograniczają błędy routingu i utrwalania danych, ale żaden z nich nie zrekompensuje zachowania ujawniającego tożsamość ani przejętego sprzętu.

## Wybór modelu izolacji

| System | Najlepiej sprawdza się w | Utrwalanie danych | Egzekwowanie routingu sieciowego | Główny kompromis |
|---|---|---|---|---|
| **Tor Browser na utrzymywanym systemie operacyjnym** | Okazjonalnym anonimowym przeglądaniu sieci | Stan przeglądarki zwykle ograniczony do sesji | Tylko ruch przeglądarki | Pozostałe aplikacje i host pozostają poza Tor |
| **Tails** | Przenośnych, amnezyjnych sesjach do jednego zastosowania | Opcjonalny, szyfrowany Persistent Storage | Ruch internetowy wymuszany przez Tor | Ponowne uruchamianie i utrudnienia w pracy; zaufanie do firmware/sprzętu |
| **Whonix** | Trwałych aplikacjach wymagających wymuszonego routingu przez Tor | Trwałe maszyny wirtualne | Podział na Gateway/Workstation | Host, hypervisor i mieszanie tożsamości pozostają zagrożeniami |
| **Qubes-Whonix** | Silnym rozdzielaniu compartmentów dla zaawansowanych użytkowników | Per-qube | Dedykowane qubes sieciowe i Whonix | Wymagania sprzętowe i złożoność operacyjna |

## Tails

Tails uruchamia się niezależnie z nośnika wymiennego, kieruje ruch internetowy przez Tor i został zaprojektowany tak, aby pozostawiać minimalny lokalny stan. Jego własne ostrzeżenia podkreślają, że nie zapewnia ochrony przed przejętym BIOS-em/firmware/sprzętem, ujawnieniami umożliwiającymi identyfikację, metadanymi plików ani potężnym obserwatorem korelującym oba końce połączenia.<sup>[[1]](#references)</sup>

### Workflow Tails do jednego zastosowania

1. Pobierz Tails z oficjalnej strony na zaufanym, zaktualizowanym komputerze i postępuj zgodnie z oficjalnym procesem weryfikacji/instalacji.
2. Używaj obsługiwanego dysku USB wyłącznie do uruchamiania Tails; nie używaj go również jako ogólnego dysku do transferu plików.
3. Uruchamiaj system na sprzęcie, nad którym masz fizyczną kontrolę. Live OS nie może zneutralizować sprzętowego keyloggera ani złośliwego firmware.
4. Pozostaw Persistent Storage wyłączony, chyba że workflow rzeczywiście go wymaga. Jeśli zostanie włączony, utrwalaj wyłącznie wymagane kategorie i użyj silnego hasła.
5. Połącz się z siecią zgodną z prawem. Jeśli captive portal jest nieunikniony, użyj Unsafe Browser w Tails wyłącznie do obsługi portalu, nie ujawniaj zbędnych danych dotyczących tożsamości, zamknij go natychmiast i połącz się z Tor przed wykonaniem jakiejkolwiek wrażliwej czynności.<sup>[[2]](#references)</sup>
6. Skonfiguruj Tor bridge, jeśli istotna jest widoczność bezpośredniego ruchu Tor lub jego blokowanie.
7. Wykonuj **jedną kontekstową tożsamość/funkcję w ramach jednej sesji**. Tails zaleca ponowne uruchomienie systemu między czynnościami, które nie powinny być ze sobą powiązane.<sup>[[1]](#references)</sup>
8. Sprawdzaj i oczyszczaj pliki przed ich opublikowaniem. Nie otwieraj pobranych aktywnych dokumentów w aplikacji, która mogłaby ominąć zamierzony kontekst.
9. Po zakończeniu całkowicie wyłącz system i przechowuj USB w bezpiecznym miejscu.

## Whonix

Whonix oddziela kierujący ruch przez Tor **Gateway** od **Workstation**, którego aplikacje nie mogą bezpośrednio poznać zewnętrznego adresu IP. Znacząco ogranicza to błędy proxy/DNS, ale host, hypervisor, zachowanie i dokumenty nadal mogą ujawniać tożsamość. Whonix wyraźnie ostrzega przed używaniem jednej Workstation dla wielu tożsamości lub łączeniem aktywności anonimowej i nieanonimowej.<sup>[[3]](#references)</sup>

### Workflow compartmentów

1. Zweryfikuj obraz Whonix i platformę wirtualizacji na podstawie oficjalnych źródeł.
2. Przed użyciem zaktualizuj hosta, hypervisora, Gateway i Workstation.
3. Klonuj świeżą Workstation dla każdej tożsamości lub zlecenia; nigdy nie klonuj VM po wprowadzeniu do niej stanu zawierającego dane tożsamości.
4. Nie udostępniaj Workstation osobistych kont, współdzielonych folderów hosta, synchronizacji schowka, urządzeń USB ani danych o czasie/lokalizacji.
5. Używaj snapshotów do odzyskiwania, a nie jako zamiennika backupów lub rozdzielania tożsamości.
6. Potwierdź, że Workstation nie może uzyskać dostępu do Internetu po zatrzymaniu Gateway.
7. W przypadku szczególnie ryzykownych plików użyj disposable VM/qube i wyeksportuj wyłącznie oczyszczony wynik.

## Qubes OS i Qubes-Whonix

Qubes zapewnia bezpieczeństwo poprzez compartmentalization z użyciem qubes opartych na Xen. Jego projekt ogranicza możliwość automatycznego przedostania się przejęcia z jednej domeny do innych, ale aplikacje znajdujące się w **tym samym** qube nie są od siebie izolowane.<sup>[[4]](#references)</sup> Disposable qubes zapewniają świeży stan dla niezaufanych stron, plików i urządzeń.<sup>[[5]](#references)</sup>

Praktyczny układ:
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
Zasady:

- Nadaj każdemu qube jeden poziom zaufania i jedno przeznaczenie związane z tożsamością.
- Przechowuj sekrety w offline vault qube i używaj jawnych operacji kopiowania między qubes oraz operacji na plikach.
- Otwieraj niezamówione pliki i linki w disposables.
- Kieruj tylko zamierzone qubes przez Whonix lub dedykowany VPN qube.
- Wyraźnie oznaczaj okna i zatrzymuj niezwiązane qubes podczas wrażliwej pracy.
- Nie zakładaj, że dwa qubes zapobiegają korelacji, jeśli współdzielą konta, treści, harmonogramy lub płatności.

## Weryfikacja i utrzymanie

- Weryfikuj podpisy i sumy kontrolne instalatorów zgodnie z oficjalnymi instrukcjami.
- Najpierw aktualizuj templates, a następnie uruchamiaj ponownie zależne qubes/VMs.
- Potwierdź działanie blokowania sieci, DNS, IPv6, zegara, schowka, współdzielonych katalogów i przypisywania USB.
- Sprawdzaj Persistent Storage i migawki VM pod kątem starych danych powiązanych z tożsamością.
- Przechowuj zaszyfrowane offline kopie zapasowe seedów/kluczy i testuj ich przywracanie w izolowanym środowisku.
- Odbuduj compartment po podejrzeniu kompromitacji; zmiana wychodzącego adresu IP jest niewystarczająca.

## References

- [1] [Tails — Ostrzeżenia: Tails jest bezpieczny, ale nie jest magiczny](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Logowanie do sieci za pomocą captive portal](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Ograniczenia Whonix i Tor](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Cele projektu dotyczące bezpieczeństwa](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Jak używać disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
