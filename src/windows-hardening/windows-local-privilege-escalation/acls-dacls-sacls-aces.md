# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Access Control List (ACL) składa się z uporządkowanego zestawu Access Control Entries (ACE), które określają zabezpieczenia obiektu i jego właściwości. Zasadniczo ACL definiuje, które działania wykonywane przez określone security principals (użytkowników lub grupy) są dozwolone lub zabronione dla danego obiektu.

Istnieją dwa typy ACL:

- **Discretionary Access Control List (DACL):** Określa, którzy użytkownicy i grupy mają lub nie mają dostępu do obiektu.
- **System Access Control List (SACL):** Zarządza audytowaniem prób dostępu do obiektu.

Proces uzyskiwania dostępu do pliku obejmuje sprawdzenie przez system deskryptora zabezpieczeń obiektu względem access token użytkownika w celu ustalenia, czy dostęp powinien zostać przyznany oraz jaki powinien być jego zakres, na podstawie ACE.<sup>[[1]](#references)</sup>

### **Key Components**

- **DACL:** Zawiera ACE, które przyznają lub odmawiają użytkownikom i grupom uprawnień dostępu do obiektu. Jest to zasadniczo główna ACL określająca prawa dostępu.
- **SACL:** Służy do audytowania dostępu do obiektów, gdzie ACE definiują typy dostępu zapisywane w Security Event Log. Może to być niezwykle przydatne do wykrywania nieautoryzowanych prób dostępu lub rozwiązywania problemów z dostępem.<sup>[[1]](#references)</sup>

### **System Interaction with ACLs**

Każda sesja użytkownika jest powiązana z access token zawierającym informacje związane z zabezpieczeniami tej sesji, w tym tożsamości użytkownika i grup oraz uprawnienia. Token zawiera również logon SID, który jednoznacznie identyfikuje sesję.

Local Security Authority (LSASS) przetwarza żądania dostępu do obiektów, sprawdzając DACL pod kątem ACE pasujących do security principal próbującego uzyskać dostęp. Dostęp jest natychmiast przyznawany, jeśli nie znaleziono odpowiednich ACE. W przeciwnym razie LSASS porównuje ACE z SID security principal w access token, aby określić, czy dostęp może zostać przyznany.<sup>[[1]](#references)</sup>

### **Summarized Process**

- **ACLs:** Definiują uprawnienia dostępu za pośrednictwem DACL oraz reguły audytowania za pośrednictwem SACL.
- **Access Token:** Zawiera informacje o użytkowniku, grupie i uprawnieniach dla sesji.
- **Access Decision:** Jest podejmowana przez porównanie ACE w DACL z access token; SACL służą do audytowania.<sup>[[1]](#references)</sup>

### ACEs

Istnieją **trzy główne typy Access Control Entries (ACE)**:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: Ta ACE jawnie odmawia dostępu do obiektu określonym użytkownikom lub grupom (w DACL).
- **Access Allowed ACE**: Ta ACE jawnie przyznaje dostęp do obiektu określonym użytkownikom lub grupom (w DACL).
- **System Audit ACE**: Umieszczona w System Access Control List (SACL), ta ACE odpowiada za generowanie logów audytowych podczas prób dostępu użytkowników lub grup do obiektu. Dokumentuje, czy dostęp został dozwolony lub odrzucony, a także jego rodzaj.

Każda ACE ma **cztery kluczowe elementy**:<sup>[[1]](#references)</sup>

1. **Security Identifier (SID)** użytkownika lub grupy (albo nazwa principal w reprezentacji graficznej).
2. **Flaga** identyfikująca typ ACE (odmowa dostępu, zezwolenie na dostęp lub audyt systemowy).
3. **Flagi dziedziczenia** określające, czy obiekty podrzędne mogą dziedziczyć ACE po obiekcie nadrzędnym.
4. [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), 32-bitowa wartość określająca prawa przyznane do obiektu.

Ustalanie dostępu odbywa się poprzez sekwencyjne sprawdzanie każdej ACE aż do momentu, gdy:<sup>[[1]](#references)</sup>

- **Access-Denied ACE** jawnie odmawia trustee zidentyfikowanemu w access token żądanych praw.
- **Access-Allowed ACE** jawnie przyznają trustee w access token wszystkie żądane prawa.
- Po sprawdzeniu wszystkich ACE, jeśli którekolwiek żądane prawo **nie zostało jawnie dozwolone**, dostęp jest domyślnie **odrzucany**.

### Order of ACEs

Sposób umieszczenia **ACE** (reguł określających, kto może lub nie może uzyskać dostępu do czegoś) na liście zwanej **DACL** jest bardzo ważny. Dzieje się tak, ponieważ gdy system przyzna lub odmówi dostępu na podstawie tych reguł, przestaje sprawdzać pozostałe.<sup>[[1]](#references)</sup>

Istnieje najlepszy sposób organizowania tych ACE, nazywany **„canonical order”**. Metoda ta pomaga zapewnić prawidłowe i przewidywalne działanie. Dla systemów takich jak **Windows 2000** i **Windows Server 2003** wygląda to następująco:

- Najpierw umieść wszystkie reguły utworzone **bezpośrednio dla tego elementu**, a dopiero potem reguły pochodzące z innego miejsca, takiego jak folder nadrzędny.
- Wśród tych bezpośrednich reguł umieść reguły mówiące **„nie” (deny)** przed regułami mówiącymi **„tak” (allow)**.
- W przypadku reguł pochodzących z innego miejsca zacznij od reguł z **najbliższego źródła**, takiego jak obiekt nadrzędny, a następnie przechodź dalej. Ponownie umieść **„nie”** przed **„tak”**.

Taka konfiguracja zapewnia dwie ważne korzyści:

- Gwarantuje, że konkretne **„nie”** będzie respektowane niezależnie od innych reguł **„tak”**.
- Pozwala właścicielowi elementu mieć **ostateczne zdanie** na temat tego, kto uzyska dostęp, zanim zastosowane zostaną reguły z folderów nadrzędnych lub dalszych poziomów.

Dzięki takiemu uporządkowaniu właściciel pliku lub folderu może precyzyjnie określić, kto uzyska dostęp, zapewniając dostęp właściwym osobom i blokując go niewłaściwym.

![Diagram kolejności Access Control Entries w NTFS](https://www.ntfs.com/images/screenshots/ACEs.gif)

Ten **„canonical order”** ma więc zapewnić przejrzystość i prawidłowe działanie reguł dostępu poprzez umieszczenie reguł bezpośrednich na początku i odpowiednie uporządkowanie pozostałych.

### GUI Example

[**Przykład stąd**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

To klasyczna karta zabezpieczeń folderu pokazująca ACL, DACL i ACE:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Po kliknięciu przycisku **Advanced** otrzymamy więcej opcji, takich jak dziedziczenie:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

Po dodaniu lub edycji Security Principal:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Na końcu mamy SACL na karcie Auditing:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explaining Access Control in a Simplified Manner

Podczas zarządzania dostępem do zasobów, takich jak folder, używamy list i reguł znanych jako Access Control Lists (ACL) oraz Access Control Entries (ACE). Określają one, kto może, a kto nie może uzyskać dostępu do określonych danych.<sup>[[1]](#references)</sup>

#### Denying Access to a Specific Group

Załóżmy, że masz folder o nazwie Cost i chcesz, aby każdy miał do niego dostęp z wyjątkiem zespołu marketingowego. Poprzez prawidłowe skonfigurowanie reguł możemy zapewnić, że zespołowi marketingowemu dostęp zostanie jawnie zabroniony, zanim dostęp zostanie przyznany wszystkim pozostałym. Osiąga się to poprzez umieszczenie reguły odmawiającej dostępu zespołowi marketingowemu przed regułą zezwalającą na dostęp wszystkim.

#### Allowing Access to a Specific Member of a Denied Group

Załóżmy, że Bob, dyrektor marketingu, potrzebuje dostępu do folderu Cost, mimo że zespół marketingowy zasadniczo nie powinien mieć do niego dostępu. Możemy dodać konkretną regułę (ACE) dla Boba, która przyzna mu dostęp, i umieścić ją przed regułą odmawiającą dostępu zespołowi marketingowemu. W ten sposób Bob uzyska dostęp pomimo ogólnego ograniczenia dotyczącego jego zespołu.

#### Understanding Access Control Entries

ACE to pojedyncze reguły w ACL. Identyfikują użytkowników lub grupy, określają, jaki dostęp jest dozwolony lub zabroniony, oraz definiują sposób stosowania tych reguł do elementów podrzędnych (dziedziczenie). Istnieją dwa główne typy ACE:

- **Generic ACEs**: Mają szerokie zastosowanie i dotyczą wszystkich typów obiektów albo rozróżniają wyłącznie kontenery (takie jak foldery) i obiekty niebędące kontenerami (takie jak pliki). Przykładem jest reguła zezwalająca użytkownikom na wyświetlanie zawartości folderu, ale nie na dostęp do znajdujących się w nim plików.
- **Object-Specific ACEs**: Zapewniają bardziej precyzyjną kontrolę, umożliwiając ustawienie reguł dla określonych typów obiektów, a nawet pojedynczych właściwości obiektu. Na przykład w katalogu użytkowników reguła może zezwalać użytkownikowi na aktualizowanie numeru telefonu, ale nie jego godzin logowania.

Każda ACE zawiera ważne informacje, takie jak podmiot, którego dotyczy reguła (z użyciem Security Identifier lub SID), działania dozwolone lub zabronione przez regułę (z użyciem access mask) oraz sposób dziedziczenia reguły przez inne obiekty.

#### Key Differences Between ACE Types

- **Generic ACEs** nadają się do prostych scenariuszy kontroli dostępu, w których ta sama reguła dotyczy wszystkich aspektów obiektu lub wszystkich obiektów w kontenerze.
- **Object-Specific ACEs** są używane w bardziej złożonych scenariuszach, szczególnie w środowiskach takich jak Active Directory, gdzie może być konieczne różne kontrolowanie dostępu do konkretnych właściwości obiektu.

Podsumowując, ACL i ACE pomagają definiować precyzyjną kontrolę dostępu, zapewniając dostęp do poufnych informacji lub zasobów wyłącznie właściwym osobom lub grupom oraz umożliwiając dostosowanie praw dostępu aż do poziomu pojedynczych właściwości lub typów obiektów.

### Access Control Entry Layout

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Flaga wskazująca typ ACE. Windows 2000 i Windows Server 2003 obsługują sześć typów ACE: trzy ogólne typy ACE dołączane do wszystkich obiektów podlegających zabezpieczeniom oraz trzy typy ACE specyficzne dla obiektów, które mogą występować dla obiektów Active Directory.                                                                                                                                                                                                                                                            |
| Flags       | Zestaw flag bitowych kontrolujących dziedziczenie i audytowanie.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | Liczba bajtów pamięci przydzielonych dla ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | 32-bitowa wartość, której bity odpowiadają prawom dostępu do obiektu. Bity mogą być ustawione lub wyłączone, ale znaczenie ustawienia zależy od typu ACE. Na przykład jeśli bit odpowiadający prawu odczytu uprawnień jest włączony, a typ ACE to Deny, ACE odmawia prawa do odczytu uprawnień obiektu. Jeśli ten sam bit jest ustawiony, ale typ ACE to Allow, ACE przyznaje prawo do odczytu uprawnień obiektu. Więcej informacji o access mask znajduje się w następnej tabeli. |
| SID         | Identyfikuje użytkownika lub grupę, których dostęp jest kontrolowany lub monitorowany przez tę ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Object Specific Access Rights      | Odczyt danych, wykonywanie, dołączanie danych           |
| 16 - 22     | Standard Access Rights             | Usuwanie, zapis ACL, zapis właściciela            |
| 23          | Can access security ACL            |                                           |
| 24 - 27     | Reserved                           |                                           |
| 28          | Generic ALL (Read, Write, Execute) | Wszystko poniżej                          |
| 29          | Generic Execute                    | Wszystko, co jest niezbędne do wykonania programu |
| 30          | Generic Write                      | Wszystko, co jest niezbędne do zapisu w pliku   |
| 31          | Generic Read                       | Wszystko, co jest niezbędne do odczytu pliku       |

## References

- [1] [How the System Uses ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL and the ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

{{#include ../../banners/hacktricks-training.md}}
