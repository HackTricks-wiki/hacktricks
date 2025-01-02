# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Lista Kontroli Dostępu (ACL)**

Lista Kontroli Dostępu (ACL) składa się z uporządkowanego zestawu Wpisów Kontroli Dostępu (ACEs), które określają zabezpieczenia dla obiektu i jego właściwości. W istocie, ACL definiuje, które działania przez które podmioty bezpieczeństwa (użytkowników lub grupy) są dozwolone lub zabronione na danym obiekcie.

Istnieją dwa typy ACL:

- **Lista Kontroli Dostępu na Własny Użytek (DACL):** Określa, którzy użytkownicy i grupy mają lub nie mają dostępu do obiektu.
- **Systemowa Lista Kontroli Dostępu (SACL):** Reguluje audyt prób dostępu do obiektu.

Proces uzyskiwania dostępu do pliku polega na tym, że system sprawdza opis zabezpieczeń obiektu w porównaniu do tokena dostępu użytkownika, aby określić, czy dostęp powinien być przyznany oraz w jakim zakresie, na podstawie ACEs.

### **Kluczowe Komponenty**

- **DACL:** Zawiera ACEs, które przyznają lub odmawiają uprawnień dostępu użytkownikom i grupom do obiektu. To zasadniczo główna ACL, która dyktuje prawa dostępu.
- **SACL:** Używana do audytowania dostępu do obiektów, gdzie ACEs definiują rodzaje dostępu, które mają być rejestrowane w Dzienniku Zdarzeń Zabezpieczeń. Może to być nieocenione w wykrywaniu nieautoryzowanych prób dostępu lub rozwiązywaniu problemów z dostępem.

### **Interakcja Systemu z ACLs**

Każda sesja użytkownika jest powiązana z tokenem dostępu, który zawiera informacje o zabezpieczeniach istotne dla tej sesji, w tym tożsamości użytkownika, grupy i uprawnienia. Ten token zawiera również SID logowania, który unikalnie identyfikuje sesję.

Lokalna Władza Bezpieczeństwa (LSASS) przetwarza żądania dostępu do obiektów, badając DACL w poszukiwaniu ACEs, które pasują do podmiotu bezpieczeństwa próbującego uzyskać dostęp. Dostęp jest natychmiast przyznawany, jeśli nie znaleziono odpowiednich ACEs. W przeciwnym razie, LSASS porównuje ACEs z SID podmiotu bezpieczeństwa w tokenie dostępu, aby określić uprawnienia dostępu.

### **Podsumowany Proces**

- **ACLs:** Definiują uprawnienia dostępu poprzez DACLs i zasady audytu poprzez SACLs.
- **Token Dostępu:** Zawiera informacje o użytkowniku, grupie i uprawnieniach dla sesji.
- **Decyzja o Dostępie:** Podejmowana poprzez porównanie ACEs DACL z tokenem dostępu; SACLs są używane do audytu.

### ACEs

Istnieją **trzy główne typy Wpisów Kontroli Dostępu (ACEs)**:

- **ACE Odrzucony Dostęp:** Ten ACE wyraźnie odmawia dostępu do obiektu dla określonych użytkowników lub grup (w DACL).
- **ACE Dozwolony Dostęp:** Ten ACE wyraźnie przyznaje dostęp do obiektu dla określonych użytkowników lub grup (w DACL).
- **ACE Audytu Systemowego:** Umieszczony w Systemowej Liście Kontroli Dostępu (SACL), ten ACE jest odpowiedzialny za generowanie dzienników audytu po próbach dostępu do obiektu przez użytkowników lub grupy. Dokumentuje, czy dostęp został przyznany, czy odrzucony oraz charakter dostępu.

Każdy ACE ma **cztery kluczowe komponenty**:

1. **Identyfikator Zabezpieczeń (SID)** użytkownika lub grupy (lub ich nazwa główna w graficznej reprezentacji).
2. **Flaga**, która identyfikuje typ ACE (odmowa dostępu, dozwolony lub audyt systemowy).
3. **Flagi dziedziczenia**, które określają, czy obiekty podrzędne mogą dziedziczyć ACE od ich rodzica.
4. [**Maska dostępu**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), 32-bitowa wartość określająca przyznane prawa obiektu.

Określenie dostępu odbywa się poprzez sekwencyjne badanie każdego ACE, aż do:

- **ACE Odrzucony Dostęp** wyraźnie odmawia żądanych praw zaufanemu podmiotowi zidentyfikowanemu w tokenie dostępu.
- **ACE Dozwolony Dostęp** wyraźnie przyznaje wszystkie żądane prawa zaufanemu podmiotowi w tokenie dostępu.
- Po sprawdzeniu wszystkich ACEs, jeśli jakiekolwiek żądane prawo **nie zostało wyraźnie przyznane**, dostęp jest domyślnie **odmówiony**.

### Kolejność ACEs

Sposób, w jaki **ACEs** (zasady mówiące, kto może lub nie może uzyskać dostęp do czegoś) są umieszczane na liście zwanej **DACL**, jest bardzo ważny. Dzieje się tak, ponieważ gdy system przyznaje lub odmawia dostępu na podstawie tych zasad, przestaje patrzeć na resztę.

Istnieje najlepszy sposób organizacji tych ACEs, zwany **"kolejnością kanoniczną."** Ta metoda pomaga zapewnić, że wszystko działa płynnie i sprawiedliwie. Oto jak to wygląda w systemach takich jak **Windows 2000** i **Windows Server 2003**:

- Najpierw umieść wszystkie zasady, które są **specjalnie dla tego elementu**, przed tymi, które pochodzą z innego miejsca, jak folder nadrzędny.
- W tych specyficznych zasadach umieść te, które mówią **"nie" (odmowa)** przed tymi, które mówią **"tak" (zezwolenie)**.
- Dla zasad pochodzących z innego miejsca, zacznij od tych z **najbliższego źródła**, jak rodzic, a następnie wróć stamtąd. Ponownie, umieść **"nie"** przed **"tak."**

Ta konfiguracja pomaga na dwa główne sposoby:

- Zapewnia, że jeśli istnieje konkretne **"nie,"** jest ono respektowane, niezależnie od innych zasad **"tak."**
- Pozwala właścicielowi elementu mieć **ostateczne zdanie** na temat tego, kto ma dostęp, zanim jakiekolwiek zasady z folderów nadrzędnych lub dalszych wejdą w grę.

Dzięki temu właściciel pliku lub folderu może być bardzo precyzyjny co do tego, kto ma dostęp, zapewniając, że odpowiednie osoby mogą wejść, a niewłaściwe nie.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Tak więc, ta **"kolejność kanoniczna"** ma na celu zapewnienie, że zasady dostępu są jasne i działają dobrze, umieszczając zasady specyficzne na pierwszym miejscu i organizując wszystko w inteligentny sposób.

### Przykład GUI

[**Przykład stąd**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

To klasyczna zakładka zabezpieczeń folderu pokazująca ACL, DACL i ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Jeśli klikniemy przycisk **Zaawansowane**, otrzymamy więcej opcji, takich jak dziedziczenie:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

A jeśli dodasz lub edytujesz Podmiot Zabezpieczeń:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

A na koniec mamy SACL w zakładce Audyt:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Wyjaśnienie Kontroli Dostępu w Uproszczony Sposób

Zarządzając dostępem do zasobów, takich jak folder, używamy list i zasad znanych jako Listy Kontroli Dostępu (ACL) i Wpisy Kontroli Dostępu (ACEs). Te definiują, kto może lub nie może uzyskać dostęp do określonych danych.

#### Odrzucenie Dostępu dla Konkretnej Grupy

Wyobraź sobie, że masz folder o nazwie Koszt, i chcesz, aby wszyscy mieli do niego dostęp, z wyjątkiem zespołu marketingowego. Poprzez poprawne ustawienie zasad możemy zapewnić, że zespół marketingowy jest wyraźnie pozbawiony dostępu przed zezwoleniem wszystkim innym. Robimy to, umieszczając zasadę odmawiającą dostępu zespołowi marketingowemu przed zasadą, która zezwala na dostęp dla wszystkich.

#### Zezwolenie na Dostęp dla Konkretnego Członka Odrzuconej Grupy

Powiedzmy, że Bob, dyrektor marketingu, potrzebuje dostępu do folderu Koszt, mimo że zespół marketingowy generalnie nie powinien mieć dostępu. Możemy dodać konkretną zasadę (ACE) dla Boba, która przyznaje mu dostęp, i umieścić ją przed zasadą, która odmawia dostępu zespołowi marketingowemu. W ten sposób Bob uzyskuje dostęp pomimo ogólnego ograniczenia dla jego zespołu.

#### Zrozumienie Wpisów Kontroli Dostępu

ACEs to indywidualne zasady w ACL. Identyfikują użytkowników lub grupy, określają, jaki dostęp jest dozwolony lub odrzucony, i ustalają, jak te zasady mają zastosowanie do elementów podrzędnych (dziedziczenie). Istnieją dwa główne typy ACEs:

- **Ogólne ACEs:** Te mają zastosowanie szeroko, wpływając na wszystkie typy obiektów lub rozróżniając tylko między kontenerami (takimi jak foldery) a nie-kontenerami (takimi jak pliki). Na przykład zasada, która pozwala użytkownikom zobaczyć zawartość folderu, ale nie uzyskać dostępu do plików w nim.
- **Specyficzne dla Obiektu ACEs:** Te zapewniają bardziej precyzyjną kontrolę, pozwalając na ustawienie zasad dla konkretnych typów obiektów lub nawet pojedynczych właściwości w obiekcie. Na przykład, w katalogu użytkowników zasada może pozwolić użytkownikowi zaktualizować swój numer telefonu, ale nie godziny logowania.

Każdy ACE zawiera ważne informacje, takie jak do kogo zasada ma zastosowanie (używając Identyfikatora Zabezpieczeń lub SID), co zasada pozwala lub odmawia (używając maski dostępu) oraz jak jest dziedziczona przez inne obiekty.

#### Kluczowe Różnice Między Typami ACE

- **Ogólne ACEs** są odpowiednie dla prostych scenariuszy kontroli dostępu, gdzie ta sama zasada ma zastosowanie do wszystkich aspektów obiektu lub do wszystkich obiektów w kontenerze.
- **Specyficzne dla Obiektu ACEs** są używane w bardziej złożonych scenariuszach, szczególnie w środowiskach takich jak Active Directory, gdzie może być konieczne kontrolowanie dostępu do konkretnych właściwości obiektu w inny sposób.

Podsumowując, ACLs i ACEs pomagają definiować precyzyjne kontrole dostępu, zapewniając, że tylko odpowiednie osoby lub grupy mają dostęp do wrażliwych informacji lub zasobów, z możliwością dostosowania praw dostępu do poziomu pojedynczych właściwości lub typów obiektów.

### Układ Wpisu Kontroli Dostępu

| Pole ACE    | Opis                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Typ         | Flaga, która wskazuje typ ACE. Windows 2000 i Windows Server 2003 obsługują sześć typów ACE: Trzy ogólne typy ACE, które są przypisane do wszystkich obiektów zabezpieczających. Trzy specyficzne dla obiektu typy ACE, które mogą występować dla obiektów Active Directory.                                                                                                                                                                                                                                                            |
| Flagi       | Zestaw bitowych flag, które kontrolują dziedziczenie i audyt.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Rozmiar     | Liczba bajtów pamięci, które są przydzielane dla ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Maska dostępu | 32-bitowa wartość, której bity odpowiadają prawom dostępu do obiektu. Bity mogą być ustawione w trybie włączonym lub wyłączonym, ale znaczenie ustawienia zależy od typu ACE. Na przykład, jeśli bit odpowiadający prawu do odczytu uprawnień jest włączony, a typ ACE to Odrzuć, ACE odmawia prawa do odczytu uprawnień obiektu. Jeśli ten sam bit jest ustawiony w trybie włączonym, ale typ ACE to Zezwól, ACE przyznaje prawo do odczytu uprawnień obiektu. Więcej szczegółów dotyczących maski dostępu znajduje się w następnej tabeli. |
| SID         | Identyfikuje użytkownika lub grupę, których dostęp jest kontrolowany lub monitorowany przez ten ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Układ Maski Dostępu

| Bit (Zakres) | Znaczenie                            | Opis/Przykład                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Specyficzne Prawa Dostępu do Obiektu      | Odczyt danych, Wykonanie, Dodanie danych           |
| 16 - 22     | Standardowe Prawa Dostępu             | Usunięcie, Zapisz ACL, Zapisz Właściciela            |
| 23          | Może uzyskać dostęp do ACL zabezpieczeń            |                                           |
| 24 - 27     | Zarezerwowane                           |                                           |
| 28          | Ogólne WSZYSTKO (Odczyt, Zapis, Wykonanie) | Wszystko poniżej                          |
| 29          | Ogólne Wykonanie                    | Wszystko, co jest potrzebne do wykonania programu |
| 30          | Ogólne Zapis                      | Wszystko, co jest potrzebne do zapisu do pliku   |
| 31          | Ogólne Odczyt                       | Wszystko, co jest potrzebne do odczytu pliku       |

## Odnośniki

- [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
- [https://www.coopware.in2.info/\_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

{{#include ../../banners/hacktricks-training.md}}
