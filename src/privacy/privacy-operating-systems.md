# Systemy operacyjne ukierunkowane na prywatność

{{#include ../banners/hacktricks-training.md}}

Systemy operacyjne ukierunkowane na prywatność ograniczają błędy związane z routingiem i utrwalaniem danych, ale żaden z nich nie zrekompensuje zachowań ujawniających tożsamość ani przejętego sprzętu.

## Wybór modelu izolacji

| System | Najlepsze zastosowanie | Utrwalanie danych | Egzekwowanie routingu sieciowego | Główny kompromis |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | Okazjonalne anonimowe przeglądanie sieci | Stan przeglądarki jest zazwyczaj ograniczony do sesji | Tylko ruch przeglądarki | Pozostałe aplikacje i host pozostają poza Tor |
| **Tails** | Przenośne, amnezyjne sesje do jednego celu | Opcjonalne szyfrowane Persistent Storage | Ruch internetowy jest wymuszany przez Tor | Konieczność ponownego uruchamiania i utrudnienia w workflow; zaufanie do firmware/sprzętu |
| **Whonix** | Trwałe aplikacje wymagające wymuszonego routingu przez Tor | Trwałe VM | Podział na Gateway/Workstation | Host/hypervisor i mieszanie tożsamości nadal pozostają problemem |
| **Qubes-Whonix** | Silna separacja compartmentów dla zaawansowanych użytkowników | Osobno dla każdego qube | Dedykowane network qubes i Whonix | Wymagania sprzętowe i złożoność operacyjna |

## Tails

Tails uruchamia się niezależnie z nośnika wymiennego, kieruje ruch internetowy przez Tor i został zaprojektowany tak, aby pozostawiać minimalną ilość lokalnego stanu. Własne ostrzeżenia Tails podkreślają, że nie chroni on przed przejętym BIOS/firmware/sprzętem, ujawnieniem informacji umożliwiających identyfikację, metadanymi plików ani potężnym obserwatorem korelującym oba końce komunikacji.<sup>[[1]](#references)</sup>

### Workflow Tails do jednego celu

1. Pobierz Tails z oficjalnej strony na zaufanym, zaktualizowanym komputerze i wykonaj oficjalny proces weryfikacji/instalacji.
2. Używaj obsługiwanego dysku USB wyłącznie do uruchamiania Tails; nie używaj go jednocześnie jako ogólnego dysku do transferu plików.
3. Uruchamiaj system na sprzęcie, nad którym masz fizyczną kontrolę. Live OS nie może zneutralizować sprzętowego keyloggera ani złośliwego firmware.
4. Pozostaw Persistent Storage wyłączone, chyba że workflow rzeczywiście go wymaga. Jeśli je włączysz, utrwalaj tylko wymagane kategorie i użyj silnego hasła.
5. Połącz się z legalną siecią. Jeśli captive portal jest nieunikniony, użyj Unsafe Browser w Tails wyłącznie do obsługi portalu, nie ujawniaj zbędnych informacji o tożsamości, natychmiast go zamknij i połącz się z Tor przed wykonaniem jakichkolwiek wrażliwych działań.<sup>[[2]](#references)</sup>
6. Skonfiguruj bridge Tor, jeśli bezpośrednia widoczność Tor lub blokowanie ma znaczenie.
7. Wykonuj **jedną kontekstową tożsamość/rolę na sesję**. Tails zaleca ponowne uruchomienie systemu między aktywnościami, które nie powinny być ze sobą powiązane.<sup>[[1]](#references)</sup>
8. Sprawdzaj i oczyszczaj pliki przed ich publikacją. Nie otwieraj pobranych aktywnych dokumentów w aplikacji, która mogłaby ominąć zamierzony kontekst.
9. Po zakończeniu całkowicie wyłącz system i przechowuj USB w bezpiecznym miejscu.

## Whonix

Whonix oddziela kierujący ruch przez Tor **Gateway** od **Workstation**, którego aplikacje nie mogą bezpośrednio poznać zewnętrznego adresu IP. Ogranicza to w istotny sposób błędy proxy/DNS, ale host, hypervisor, zachowanie użytkownika i dokumenty nadal mogą ujawnić tożsamość. Whonix wyraźnie ostrzega przed używaniem jednej workstation dla wielu tożsamości lub łączeniem aktywności anonimowej i nieanonimowej.<sup>[[3]](#references)</sup>

### Workflow compartmentów

1. Zweryfikuj obraz Whonix i platformę wirtualizacji na podstawie oficjalnych źródeł.
2. Przed użyciem zaktualizuj host, hypervisor, Gateway i Workstation.
3. Klonuj świeżą Workstation dla każdej tożsamości lub każdego engagementu; nigdy nie klonuj VM po wprowadzeniu stanu zawierającego informacje o tożsamości.
4. Nie umieszczaj w Workstation osobistych kont, współdzielonych folderów hosta, synchronizacji schowka, urządzeń USB ani danych o czasie/lokalizacji.
5. Używaj snapshotów do odzyskiwania, a nie jako zamiennika backupów lub separacji tożsamości.
6. Potwierdź, że Workstation nie może uzyskać dostępu do Internetu po zatrzymaniu Gateway.
7. W przypadku szczególnie ryzykownych plików użyj disposable VM/qube i eksportuj wyłącznie oczyszczony rezultat.

## Qubes OS i Qubes-Whonix

Qubes zapewnia bezpieczeństwo poprzez compartmentalization z wykorzystaniem qubes opartych na Xen. Jego konstrukcja ogranicza możliwość automatycznego przedostania się kompromitacji z jednej domeny do innych, ale aplikacje znajdujące się w **tym samym** qube nie są od siebie odizolowane.<sup>[[4]](#references)</sup> Disposable qubes zapewniają świeży stan dla niezaufanych stron, plików i urządzeń.<sup>[[5]](#references)</sup>

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

- Nadaj każdemu qube jeden poziom zaufania i cel związany z tożsamością.
- Przechowuj sekrety w offline vault qube i używaj jawnych operacji kopiowania między qubes oraz operacji na plikach.
- Nieoczekiwane pliki i linki otwieraj w disposables.
- Kieruj tylko zamierzone qubes przez Whonix lub dedykowany VPN qube.
- Wyraźnie oznaczaj okna i zatrzymuj niezwiązane qubes podczas wrażliwej pracy.
- Nie zakładaj, że dwa qubes zapobiegają korelacji, jeśli współdzielą konta, treści, harmonogramy lub płatności.

## Weryfikacja i konserwacja

- Weryfikuj podpisy/sumy kontrolne instalatorów zgodnie z oficjalnymi instrukcjami.
- Najpierw aktualizuj templates, a następnie restartuj zależne qubes/VMs.
- Potwierdź działanie blokowania sieci, DNS, IPv6, zegara, schowka, współdzielonych katalogów i przypisywania USB.
- Sprawdzaj Persistent Storage i snapshoty VM pod kątem starych danych ujawniających tożsamość.
- Przechowuj zaszyfrowane offline kopie zapasowe seedów/kluczy i testuj ich przywracanie w izolowanym środowisku.
- Odbuduj compartment po podejrzeniu kompromitacji; zmiana jego egress IP jest niewystarczająca.

## References

- [1] [Tails — Ostrzeżenia: Tails jest bezpieczny, ale nie jest magiczny](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Logowanie do sieci przy użyciu captive portal](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Ograniczenia Whonix i Tor](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Cele projektowe bezpieczeństwa](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Jak używać disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
{{#include ../banners/hacktricks-training.md}}
