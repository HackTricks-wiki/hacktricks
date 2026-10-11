# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Access Control List (ACL) składa się z uporządkowanego zestawu Access Control Entries (ACE), które określają zabezpieczenia obiektu i jego właściwości. Zasadniczo ACL definiuje, jakie działania mogą lub nie mogą wykonywać określone podmioty zabezpieczeń (użytkownicy lub grupy) wobec danego obiektu.

Istnieją dwa typy ACL:

- **Discretionary Access Control List (DACL):** Określa, którzy użytkownicy i grupy mają lub nie mają dostępu do obiektu.
- **System Access Control List (SACL):** Reguluje audyt prób dostępu do obiektu.

Podczas uzyskiwania dostępu do pliku system sprawdza deskryptor zabezpieczeń obiektu względem tokenu dostępu użytkownika, aby ustalić, czy dostęp powinien zostać przyznany i jaki powinien być jego zakres, na podstawie ACE.<sup>[[1]](#references)</sup>

Jeśli katalog nadrzędny przyznaje Full Control, ale plik podrzędny odmawia odczytu, osobno sprawdź efektywną DACL, właściciela i dziedziczenie **pliku podrzędnego**. Zmiana DACL tego pliku wymaga uprawnienia `WRITE_DAC` do pliku lub odpowiedniego uprawnienia właściciela; [Microsoft definiuje `WRITE_DAC`](https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) i [opisuje niejawne uprawnienia właściciela](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object). Same uprawnienia do katalogu nadrzędnego nie oznaczają, że można odczytać plik podrzędny ani zmienić jego DACL.

### **Key Components**

- **DACL:** Zawiera ACE przyznające lub odmawiające użytkownikom i grupom uprawnień dostępu do obiektu. To zasadniczo główna ACL określająca prawa dostępu.
- **SACL:** Służy do audytowania dostępu do obiektów; zawarte w niej ACE określają, jakie rodzaje dostępu mają być rejestrowane w Security Event Log. Może to być niezwykle przydatne przy wykrywaniu nieautoryzowanych prób dostępu lub rozwiązywaniu problemów z dostępem.<sup>[[1]](#references)</sup>

### **System Interaction with ACLs**

Każda sesja użytkownika jest powiązana z tokenem dostępu zawierającym informacje o zabezpieczeniach istotne dla tej sesji, w tym tożsamości użytkownika i grup oraz uprawnienia. Token zawiera również logon SID, który jednoznacznie identyfikuje sesję.

Local Security Authority (LSASS) obsługuje żądania dostępu do obiektów, sprawdzając DACL pod kątem ACE pasujących do podmiotu zabezpieczeń próbującego uzyskać dostęp. Jeśli nie znaleziono odpowiednich ACE, dostęp jest natychmiast przyznawany. W przeciwnym razie LSASS porównuje ACE z SID-em podmiotu zabezpieczeń w tokenie dostępu, aby ustalić, czy dostęp może zostać przyznany.<sup>[[1]](#references)</sup>

### **Summarized Process**

- **ACL:** Określają uprawnienia dostępu za pomocą DACL, a reguły audytu za pomocą SACL.
- **Access Token:** Zawiera informacje o użytkowniku, grupach i uprawnieniach przypisanych do sesji.
- **Access Decision:** Podejmowana przez porównanie ACE z DACL z tokenem dostępu; SACL służą do audytu.<sup>[[1]](#references)</sup>

### ACEs

Istnieją **trzy główne typy Access Control Entries (ACE)**:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: Jawnie odmawia dostępu do obiektu określonym użytkownikom lub grupom (w DACL).
- **Access Allowed ACE**: Jawnie przyznaje dostęp do obiektu określonym użytkownikom lub grupom (w DACL).
- **System Audit ACE**: Umieszczona w System Access Control List (SACL), odpowiada za generowanie logów audytu przy próbach dostępu użytkowników lub grup do obiektu. Zapisuje, czy dostęp został przyznany, czy odmówiony, oraz określa jego rodzaj.

Każda ACE ma **cztery kluczowe składniki**:<sup>[[1]](#references)</sup>

1. **Security Identifier (SID)** użytkownika lub grupy (lub nazwa podmiotu w reprezentacji graficznej).
2. **Flaga** określająca typ ACE (odmowa dostępu, zezwolenie na dostęp lub audyt systemowy).
3. **Flagi dziedziczenia** określające, czy obiekty podrzędne mogą dziedziczyć ACE od obiektu nadrzędnego.
4. [**Access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), 32-bitowa wartość określająca przyznane prawa do obiektu.

Dostęp jest ustalany przez kolejne sprawdzanie ACE, aż do spełnienia jednego z poniższych warunków:<sup>[[1]](#references)</sup>

- **Access-Denied ACE** jawnie odmawia żądanych uprawnień zaufanemu podmiotowi wskazanemu w tokenie dostępu.
- **Access-Allowed ACE** jawnie przyznaje zaufanemu podmiotowi w tokenie dostępu wszystkie żądane uprawnienia.
- Po sprawdzeniu wszystkich ACE dostęp zostaje niejawnie **odmówiony**, jeśli choć jedno żądane uprawnienie nie zostało **jawnie przyznane**.

### Order of ACEs

Kolejność **ACE** (reguł określających, kto może, a kto nie może uzyskać dostępu do czegoś) na liście zwanej **DACL** jest bardzo ważna. Gdy system przyzna lub odmówi dostępu na podstawie tych reguł, przestaje sprawdzać pozostałe.<sup>[[1]](#references)</sup>

Istnieje zalecany sposób porządkowania ACE, nazywany **„porządkiem kanonicznym”**. Pomaga on zapewnić prawidłowe i przewidywalne działanie. Oto zasady stosowane w systemach takich jak **Windows 2000** i **Windows Server 2003**:

- Najpierw umieść wszystkie reguły utworzone **specjalnie dla tego obiektu**, a dopiero potem reguły pochodzące z innych miejsc, na przykład z folderu nadrzędnego.
- Wśród reguł utworzonych dla tego obiektu umieść najpierw te, które mówią **„nie” (odmowa)**, a później te, które mówią **„tak” (zezwolenie)**.
- W przypadku reguł pochodzących z innych miejsc zacznij od reguł z **najbliższego źródła**, na przykład folderu nadrzędnego, a następnie uwzględnij dalsze źródła. Ponownie umieść **„nie”** przed **„tak”**.

Takie ustawienie ma dwie istotne zalety:

- Zapewnia, że konkretna reguła **„nie”** zostanie uwzględniona niezależnie od innych reguł **„tak”**.
- Pozwala właścicielowi obiektu **ostatecznie zdecydować**, kto uzyska dostęp, zanim zaczną obowiązywać reguły z folderów nadrzędnych lub dalszych źródeł.

Dzięki takiemu podejściu właściciel pliku lub folderu może precyzyjnie określić, kto ma dostęp, zapewniając go właściwym osobom i odmawiając go pozostałym.

![Diagram kolejności wpisów kontroli dostępu NTFS](https://www.ntfs.com/images/screenshots/ACEs.gif)

Ten **„porządek kanoniczny”** ma więc na celu zapewnienie jasnych i skutecznych reguł dostępu: najpierw umieszcza reguły dotyczące konkretnego obiektu, a następnie porządkuje pozostałe w przemyślany sposób.

### GUI Example

[**Przykład z tej strony**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Oto klasyczna karta zabezpieczeń folderu, przedstawiająca ACL, DACL i ACE:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Po kliknięciu przycisku **Advanced** pojawi się więcej opcji, takich jak dziedziczenie:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

A po dodaniu lub edycji podmiotu zabezpieczeń:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Na koniec, w karcie Auditing znajduje się SACL:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explaining Access Control in a Simplified Manner

Do zarządzania dostępem do zasobów, takich jak foldery, używamy list i reguł znanych jako Access Control Lists (ACL) oraz Access Control Entries (ACE). Określają one, kto może, a kto nie może uzyskać dostępu do określonych danych.<sup>[[1]](#references)</sup>

#### Denying Access to a Specific Group

Wyobraź sobie folder o nazwie Cost, do którego wszyscy mają mieć dostęp z wyjątkiem zespołu marketingowego. Odpowiednio konfigurując reguły, możemy jawnie odmówić dostępu zespołowi marketingowemu, a następnie zezwolić na niego wszystkim pozostałym. W tym celu regułę odmawiającą dostępu zespołowi marketingowemu umieszczamy przed regułą zezwalającą na dostęp wszystkim.

#### Allowing Access to a Specific Member of a Denied Group

Załóżmy, że Bob, dyrektor marketingu, potrzebuje dostępu do folderu Cost, mimo że zespół marketingowy zasadniczo nie powinien mieć do niego dostępu. Możemy dodać osobną regułę (ACE) przyznającą dostęp Bobowi i umieścić ją przed regułą odmawiającą dostępu zespołowi marketingowemu. Dzięki temu Bob uzyska dostęp mimo ogólnego ograniczenia dotyczącego jego zespołu.

#### Understanding Access Control Entries

ACE to pojedyncze reguły ACL. Wskazują użytkowników lub grupy, określają, jaki dostęp jest dozwolony lub zabroniony, oraz ustalają, jak te reguły mają być stosowane do elementów podrzędnych (dziedziczenie). Istnieją dwa główne typy ACE:

- **Generic ACEs**: Stosuje się je szeroko — obejmują wszystkie typy obiektów albo rozróżniają jedynie kontenery (takie jak foldery) i obiekty niebędące kontenerami (takie jak pliki). Przykładem jest reguła zezwalająca użytkownikom na wyświetlanie zawartości folderu, ale nie na dostęp do znajdujących się w nim plików.
- **Object-Specific ACEs**: Zapewniają dokładniejszą kontrolę, umożliwiając definiowanie reguł dla określonych typów obiektów, a nawet poszczególnych właściwości obiektu. Na przykład w katalogu użytkowników reguła może zezwalać użytkownikowi na zmianę numeru telefonu, ale nie godzin logowania.

Każda ACE zawiera ważne informacje, takie jak podmiot, którego dotyczy reguła (identyfikowany za pomocą Security Identifier lub SID), uprawnienia przyznawane lub odmawiane przez regułę (określane za pomocą maski dostępu) oraz sposób dziedziczenia reguły przez inne obiekty.

#### Key Differences Between ACE Types

- **Generic ACEs** nadają się do prostych scenariuszy kontroli dostępu, w których ta sama reguła dotyczy wszystkich aspektów obiektu lub wszystkich obiektów w kontenerze.
- **Object-Specific ACEs** stosuje się w bardziej złożonych scenariuszach, zwłaszcza w środowiskach takich jak Active Directory, gdzie może być konieczne różne kontrolowanie dostępu do określonych właściwości obiektu.

Podsumowując, ACL i ACE umożliwiają precyzyjne definiowanie kontroli dostępu, dzięki czemu dostęp do poufnych informacji lub zasobów mają tylko właściwe osoby i grupy. Pozwalają też dostosować prawa dostępu do poziomu poszczególnych właściwości lub typów obiektów.

### Access Control Entry Layout

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Flaga wskazująca typ ACE. Windows 2000 i Windows Server 2003 obsługują sześć typów ACE: trzy ogólne typy ACE przypisywane do wszystkich obiektów zabezpieczanych oraz trzy typy ACE specyficzne dla obiektów, które mogą występować w obiektach Active Directory.                                                                                                                                                                                                                                                            |
| Flags       | Zestaw flag bitowych sterujących dziedziczeniem i audytem.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | Liczba bajtów pamięci przydzielonych dla ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | 32-bitowa wartość, której bity odpowiadają prawom dostępu do obiektu. Bity mogą być włączone lub wyłączone, ale znaczenie ustawienia zależy od typu ACE. Na przykład jeśli włączony jest bit odpowiadający prawu odczytu uprawnień, a typ ACE to Deny, ACE odmawia prawa odczytu uprawnień obiektu. Jeśli ten sam bit jest włączony, a typ ACE to Allow, ACE przyznaje prawo odczytu uprawnień obiektu. Więcej informacji o masce dostępu znajduje się w następnej tabeli. |
| SID         | Identyfikuje użytkownika lub grupę, których dostęp jest kontrolowany lub monitorowany przez tę ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Prawa dostępu specyficzne dla obiektu | Odczyt danych, wykonanie, dopisywanie danych |
| 16 - 22     | Standardowe prawa dostępu             | Usuwanie, zapis ACL, zapis właściciela            |
| 23          | Może uzyskać dostęp do security ACL   |                                           |
| 24 - 27     | Zarezerwowane                          |                                           |
| 28          | Generic ALL (odczyt, zapis, wykonanie) | Wszystko poniżej                          |
| 29          | Generic Execute                       | Wszystko, co niezbędne do uruchomienia programu |
| 30          | Generic Write                         | Wszystko, co niezbędne do zapisu w pliku   |
| 31          | Generic Read                          | Wszystko, co niezbędne do odczytu pliku       |

## References

- [1] [Jak system używa ACL — NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL i ACE — secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
{{#include ../../banners/hacktricks-training.md}}
