# Authorized Red-Team Infrastructure

{{#include ../banners/hacktricks-training.md}}

W przypadku trwałych urządzeń on-site użyj projektu [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) oraz procedury suspected-discovery.

W profesjonalnym red teamie celem jest **kontrolowane przypisanie źródła**, a nie uniknięcie odpowiedzialności. Cel nie powinien móc w prosty sposób zobaczyć domowego adresu IP operatora ani jego osobistych kont, natomiast właściciel engagementu musi mieć możliwość ustalenia źródła, zatrzymania operacji, obsługi zgłoszeń dotyczących nadużyć, zachowania dowodów i wykazania istnienia autoryzacji.

Ta strona stanowi bazową konfigurację wdrożenia dla zgodnego z prawem engagementu. Aby poznać adversary tradecraft, który ma być emulowany — w tym przejęte ORB-y, residential relays, fronting, dead drops i nearby wireless pivots — zacznij od [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) oraz [Government and APT Case Studies](government-and-apt-case-studies.md), a następnie odtwórz wymaganą telemetrię w [authorized labs](authorized-adversary-emulation-labs.md).

NIST definiuje rules of engagement (ROE) jako wcześniej ustalone ograniczenia, które przyznają uprawnienia do określonych działań testowych.<sup>[[1]](#references)</sup> Architektura prywatności nie może rozszerzać tych uprawnień.

## Wybór wzorca egress

| Wzorzec | Najlepsze zastosowanie | Co widzi cel | Co widzi provider/lokalny obserwator | Accountability |
|---|---|---|---|---|
| VPN/jump host dostarczony przez klienta | Większość assessmentów | Zakres adresów klienta | Tożsamość klienta i dostęp operatora | Najsilniejsza |
| Bastion organizacji red team | Powtarzalny, kontrolowany egress | Zakres organizacji | Hosting provider i organizacja | Silna |
| VPS przeznaczony dla engagementu | Izolowanie klientów/kampanii | Adres VPS | Konto hosta, billing, control plane i logi dostępu | Silna, jeśli udokumentowana |
| Zatwierdzony komercyjny VPN | Research/skanowanie dozwolone przez providera i ROE | Współdzielony/dedykowany egress VPN | Konto VPN i połączenie źródłowe | Średnia |
| Tor Browser | Research web wymagający unlinkability względem celu | Węzeł wyjściowy Tor | Sieć lokalna widzi Tor/bridge; cel widzi Tor | Słabe dopasowanie do atrybucji źródła opartej na allowliście |
| Zatwierdzony przez klienta on-site drop | Symulacja wewnętrzna | Urządzenie/adres on-site | Sieć obiektu i zdalny provider tunelu | Silna, jeśli ujęta w inwentaryzacji |
| Zgodne z prawem guest Wi-Fi | Niskiego ryzyka zastosowania administracyjne/research | Publiczny adres IP obiektu lub egress tunelu | Obiekt, ISP, VPN/Tor | Słaba i fizycznie obserwowalna |

W większości prac egress o stałym adresie, dostarczony przez klienta lub kontrolowany przez organizację, jest bezpieczniejszy i szybszy niż konsumenckie usługi anonimowości. Umożliwia też obrońcom dodanie znanych zakresów źródłowych do allowlisty, monitorowanie ich lub celowe **nieumieszczanie ich na allowliście**, zgodnie z projektem ćwiczenia.

## Aneks infrastruktury ROE

Przed wdrożeniem zapisz:

- podmioty prawne udzielające i otrzymujące autoryzację;
- dokładne cele i jawne wykluczenia;
- godziny rozpoczęcia/zakończenia, strefę czasową i dozwolone techniki;
- źródłowe adresy IP, nazwy autonomous system/providerów, domeny, redirectory, infrastrukturę mailową i identyfikatory urządzeń on-site;
- czy dozwolone są phishing, C2, credential capture, testy wireless, dostęp fizyczny, denial-of-service, persistence lub usługi stron trzecich;
- zatwierdzenia klienta i providera, w tym wszelkie identyfikatory wcześniejszych powiadomień;
- frazę awaryjnego zatrzymania, całodobowe kontakty klienta i providera ds. nadużyć oraz maksymalny czas reakcji;
- klasy danych, które mogą zostać zebrane, szyfrowanie, dostęp, retencję i usuwanie;
- wymagania dotyczące dowodów i logowania, w tym informację, kto przechowuje mapowanie publicznej infrastruktury na operatora;
- teardown, wygaśnięcie domeny, unieważnienie certyfikatów, rotację poświadczeń, odzyskanie urządzeń i końcowe poświadczenie.

Zweryfikuj, czy publiczne adresy IP i domeny są faktycznie kontrolowane przez stronę udzielającą autoryzacji lub zostały jawnie uwzględnione w zakresie. NIST SP 800-115 zaleca potwierdzenie, że publiczne adresy celów znajdują się pod kontrolą organizacji przed rozpoczęciem testów.<sup>[[2]](#references)</sup>

## Szybki egress przeznaczony dla engagementu

### Workflow budowy

1. **Utwórz konto/projekt engagementu** w organizacji red team, używając prawidłowych danych rozliczeniowych i danych właściciela. Oddziel role, klucze API, budżety i logi audytowe od innych klientów.
2. **Sprawdź politykę każdego providera.** Providerzy cloud, VPS, CDN, domen, poczty i VPN mają różne zasady. AWS na przykład zezwala na określone assessmenty, ale wymaga wcześniejszej zgody na hosted C2/covert simulations i zabrania wymienionych działań.<sup>[[3]](#references)</sup>
3. **Przydziel stałe adresy egress** i umieść je w aneksie ROE. Unikaj szybkiej rotacji adresów IP/zasobów; komplikuje ona incident response i może naruszać politykę providera.
4. **Zabezpiecz zarządzanie:** SSH wyłącznie z użyciem kluczy lub identity-aware management plane, phishing-resistant MFA, oddzielna sieć administracyjna, least privilege, załatane obrazy, brak publicznych portów administracyjnych i szyfrowane przechowywanie sekretów.
5. **Utwórz ścieżkę full-tunnel** z endpointu operatora do bastiona. Celowo kieruj DNS i IPv6 oraz wymuś blokadę firewalla, gdy tunel jest wyłączony.
6. **Ogranicz wychodzące destination i porty** do autoryzowanego zakresu, gdy jest to możliwe. Ograniczaj rate skanerów i umieszczaj nieodwracalne/destrukcyjne techniki za oddzielnym etapem zatwierdzania.
7. **Loguj na potrzeby accountability, nie surveillance:** uwierzytelnianie operatora, zmiany konfiguracji, rozpoczęcie/zatrzymanie, adres źródłowy, destination objęty zakresem oraz identyfikatory narzędzi/zadań. Unikaj przechwytywania payloadów/poświadczeń, chyba że wymaga tego ćwiczenie i są one chronione przez plan danych.
8. **Przeprowadź walidację przez kontrolowany endpoint** należący do organizacji: zaobserwowane IPv4/IPv6, ścieżka DNS, reverse DNS, zegar, zachowanie portu źródłowego, awarie/ponowne połączenia oraz kontakt providera ds. nadużyć.
9. **Udostępnij mapę atrybucji w bezpieczny sposób** kontrolerowi ćwiczenia lub uzgodnionemu kontaktowi escrow. Nie publikuj jej zespołowi celu, jeśli blind detection jest częścią testu.

### Architektura
```text
dedicated operator context
|
fail-closed tunnel
|
engagement bastion / fixed egress ---- management + audit plane
|
scope allowlist / rate limits
|
authorized targets
```
VPS jest pseudonimowy wyłącznie dla miejsca docelowego. Host może posiadać dane kontaktowe, rozliczeniowe, dotyczące tożsamości, źródłowych adresów IP, API, urządzeń, lokalizacji i użytkowania; sama historia AWS CloudTrail widoczna dla klienta może ujawnić aktywność zarządzania.<sup>[[4]](#references)</sup> Płacenie za hosting kryptowalutą nie usuwa tych danych.

## Domains and certificates

- Używaj konta registrar utworzonego na potrzeby konkretnego engagementu i należącego do organizacji.
- Włącz registrar lock, DNSSEC tam, gdzie jest obsługiwany, MFA/security keys oraz auto-renew wyłącznie na zatwierdzony okres.
- Używaj registration privacy, aby ograniczyć publiczną ekspozycję, a nie w celu fałszowania informacji o registrant. Polityka ICANN wymaga od registrarów gromadzenia danych rejestracyjnych, nawet gdy ich publiczne wyświetlanie jest ograniczone lub odbywa się przez proxy.<sup>[[5]](#references)</sup>
- Unikaj nazw, które bezprawnie podszywają się pod niepowiązane strony. Domeny typosquatting/lookalike wymagają wyraźnej zgody klienta i providera.
- Zinwentaryzuj DNS, certyfikaty, konfigurację CDN/redirectorów oraz analitykę stron trzecich, która mogłaby ujawnić operatorów lub klientów.
- Podczas teardown usuń rekordy, unieważnij certyfikaty/tokeny, zachowaj uzgodnione dowody i zdecyduj, czy domena powinna zostać zachowana defensywnie.

## Authorized on-site drop nodes

Raspberry Pi lub podobne appliance jest dopuszczalne wyłącznie wtedy, gdy właściciel nieruchomości/sieci i klient wyraźnie zatwierdzą jego dokładne umiejscowienie oraz działanie. Bezpieczny plan:

1. Zapisz numer seryjny urządzenia, MAC/politykę private-MAC, zdjęcie, właściciela, dokładną zatwierdzoną lokalizację, źródło zasilania, termin odbioru oraz kontakt w sprawie naruszenia.
2. Użyj minimalnego, podpisanego obrazu, zaszyfrowanych sekretów, pamięci tylko do odczytu lub możliwej do odzyskania, host firewall, automatycznych security updates tam, gdzie jest to praktyczne, oraz bez domyślnych credentials.
3. Skonfiguruj komunikację wyłącznie wychodzącą do wskazanego endpointu engagementu. Nie wystawiaj nieuwierzytelnionego listenera.
4. Ogranicz dozwolone destinations i capabilities. Packet capture, credential collection, wireless impersonation oraz lateral movement muszą być osobno wyraźnie zatwierdzone.
5. Użyj mutual authentication, krótkotrwałych kluczy, remote kill, raportowania stanu oraz limitów bandwidth.
6. Upewnij się, że utrata lub kradzież nie ujawni możliwych do ponownego użycia credentials ani danych klienta.
7. Umieść odbiór oraz secure wipe/decommission w kalendarzu; uzyskaj podpisany rekord odzyskania.

Nie ukrywaj hardware'u w kawiarni, hotelu, współdzielonym biurze, na posesji sąsiada ani w miejscu publicznym bez pisemnej zgody właściciela/operatora.

## Guest networks and travel routers

Jeśli autoryzowany scenariusz wymaga dostępu gościnnego:

- zweryfikuj SSID i acceptable-use policy z obiektem/klientem;
- użyj należącego do organizacji travel routera lub low-trust bridge device, aby odizolować uprzywilejowaną stację roboczą;
- obsługuj captive portals poza uprzywilejowaną stacją roboczą;
- uruchom zatwierdzony tunnel przed rozpoczęciem assessment traffic;
- potwierdź, że tethered devices rzeczywiście korzystają z tego tunelu;
- załóż, że obiekt może skorelować radio association, portal, fizyczną obecność oraz dane z kamer i płatności;
- nigdy nie omijaj access control, nie klonuj innego urządzenia, nie atakuj Wi-Fi ani nie pozostawiaj sprzętu.

## Operational separation

- Jeden klient/engagement na endpoint compartment, cloud project, secrets set, domain group, redirector set oraz evidence store.
- Nie używaj prywatnego e-maila, synchronizacji przeglądarki, numeru telefonu, cloud drive, klucza SSH/GPG, tożsamości code-signing ani zwrotu płatności poza zatwierdzonymi systemami organizacji.
- Nie używaj ponownie charakterystycznej konfiguracji payloadu, ścieżek callback, certyfikatów ani publicznych repozytoriów między klientami, chyba że projekt ćwiczenia akceptuje fingerprinting.
- Ustal dla infrastruktury kill date i alert budżetowy. Osierocone systemy stają się zagrożeniem zarówno dla klienta, jak i Internetu.
- Zachowaj wystarczające wewnętrzne dane umożliwiające zbadanie wypadków. „Brak logów” jest zazwyczaj niezgodny z profesjonalnymi obowiązkami dotyczącymi dowodów i bezpieczeństwa.

## Blind to defenders, attributable to the controller

Gdy celem ćwiczenia jest pomiar detekcji, a nie testowanie allowlisty, docelowy SOC może pozostać niepoinformowany bez pozbawiania operacji rozliczalności:

1. Controller ćwiczenia zatwierdza każde publiczne źródło, domenę, certyfikat i urządzenie on-site, ale nie przekazuje tej listy SOC.
2. Controller przechowuje mapowanie source-to-engagement/operator w osobnym, zaszyfrowanym vault z awaryjnym dostępem wymagającym dwóch osób.
3. Każdy job operatora otrzymuje podpisany manifest zawierający scope, time window, source compartment oraz nieodwracalny job identifier. Cel nie musi widzieć manifestu podczas normalnego działania.
4. Zdarzenia audit z bastionu są łączone lub wysyłane append-only do storage controllera, aby operator nie mógł po cichu zmienić atrybucji po incydencie.
5. Provider-abuse contact działający 24/7 posiada verification phrase/reference potwierdzające autoryzację bez publicznego ujawniania klienta.
6. Każda ścieżka implementuje out-of-band stop channel, który nie zależy od assessment C2, sieci celu ani konta jednego operatora.
7. Przed live testing wyślij benign canaries z każdego źródła. Potwierdź, że controller może je zidentyfikować i zatrzymać w czasie reakcji określonym przez ROE.
8. Po ćwiczeniu porównaj telemetry SOC z ledgerem controllera, ujawnij listę źródeł oraz wyjaśnij pominięte/błędne detekcje.

Nie dodawaj anti-forensics, niszczenia logów, compromised relays ani fałszywych tożsamości subscriberów. Takie działania podważają rozliczalne testowanie, zamiast je ulepszać.

## Teardown checklist

- [ ] Controller ćwiczenia potwierdza zatrzymanie.
- [ ] C2, tunnels, redirectors, mail, VPN oraz scheduled jobs są wyłączone.
- [ ] Urządzenia on-site zostały fizycznie odzyskane i uzgodnione z ewidencją.
- [ ] Tokeny, API keys, SSH keys, certyfikaty oraz przechwycone credentials zostały unieważnione/zmienione.
- [ ] Zasoby DNS i cloud zostały usunięte lub przekazane do defensywnego zachowania.
- [ ] Dane klienta zostały zwrócone, zachowane lub zniszczone zgodnie z umową.
- [ ] Wymagane dane finansowe, audit oraz authorization records nadal są zaszyfrowane i objęte kontrolą dostępu.
- [ ] Sprawy związane z provider abuse zostały zamknięte, a klient otrzymał końcowe source indicators.
- [ ] Drugi operator potwierdza, że żadna infrastruktura nie pozostaje aktywna.

## References

- [1] [NIST CSRC — Zasady Rules of Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Customer Support Policy for Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Privacy Notice](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Registration Data Policy](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
