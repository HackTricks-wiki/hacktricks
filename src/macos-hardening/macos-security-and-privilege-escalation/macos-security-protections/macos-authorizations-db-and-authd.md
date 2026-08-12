# Baza danych autoryzacji macOS i Authd

{{#include ../../../banners/hacktricks-training.md}}

## Baza danych autoryzacji

Usługi autoryzacji frameworka Security umożliwiają uprzywilejowanym helperom i innym komponentom ocenianie nazwanych uprawnień autoryzacji. W obecnych wersjach macOS wiele z tych reguł jest przechowywanych w `/var/db/auth.db` i ocenianych przez `authd`; ten plik oraz jego schemat SQLite są szczegółami implementacji i mogą się zmieniać między wydaniami.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Domyślne ustawienia systemu były historycznie inicjalizowane na podstawie `/System/Library/Security/authorization.plist`, a instalatory lub uprzywilejowane usługi mogą dodawać nazwane uprawnienia. Zamiast bezpośredniej edycji bazy danych należy używać obsługiwanego interfejsu `security authorizationdb read|write|remove`.<sup>[[3]](#references)</sup>

Tabela `rules` zaobserwowana w udokumentowanej kompilacji zawiera następujące kolumny. Należy traktować to jako mapę kryminalistyczną, a nie stabilny publiczny schemat:

- **id**: Unikalny identyfikator każdej reguły, automatycznie zwiększany i pełniący funkcję klucza głównego.
- **name**: Unikalna nazwa reguły używana do jej identyfikowania i odwoływania się do niej w systemie autoryzacji.
- **type**: Określa typ reguły; do definiowania jej logiki autoryzacji dozwolone są wartości 1 lub 2.
- **class**: Kategoryzuje regułę według określonej klasy; wartość musi być dodatnią liczbą całkowitą.
- Typowe klasy reguł obejmują `allow`, `deny`, `user`, `rule` i `evaluate-mechanisms`. Mechanizmy mogą być wbudowane lub dostarczane jako plug-iny Security Agent w `/System/Library/CoreServices/SecurityAgentPlugins/` lub `/Library/Security/SecurityAgentPlugins/`.<sup>[[2]](#references)</sup>
- **group**: Wskazuje grupę użytkownika powiązaną z regułą na potrzeby autoryzacji opartej na grupach.
- **kofn**: Reprezentuje parametr „k-of-n”, określający, ile podreguł spośród łącznej liczby musi zostać spełnionych.
- **timeout**: Określa czas w sekundach, po którym autoryzacja przyznana przez regułę wygasa.
- **flags**: Zawiera różne flagi modyfikujące zachowanie i właściwości reguły.
- **tries**: Ogranicza liczbę dozwolonych prób autoryzacji w celu zwiększenia bezpieczeństwa.
- **version**: Śledzi wersję reguły na potrzeby kontroli wersji i aktualizacji.
- **created**: Zapisuje znacznik czasu utworzenia reguły na potrzeby audytu.
- **modified**: Przechowuje znacznik czasu ostatniej modyfikacji reguły.
- **hash**: Zawiera wartość hash reguły w celu zapewnienia jej integralności i wykrywania manipulacji.
- **identifier**: Udostępnia unikalny identyfikator tekstowy, taki jak UUID, na potrzeby zewnętrznych odwołań do reguły.
- **requirement**: Zawiera zserializowane dane definiujące określone wymagania autoryzacji i mechanizmy reguły.
- **comment**: Zawiera czytelny dla człowieka opis lub komentarz dotyczący reguły, ułatwiający jej dokumentowanie i zrozumienie.

### Przykład
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
Poniższa zdekodowana reguła ilustruje `authenticate-admin-nonshared` w udokumentowanej wersji macOS:<sup>[[1]](#references)</sup>
```json
{
"allow-root": "false",
"authenticate-user": "true",
"class": "user",
"comment": "Authenticate as an administrator.",
"group": "admin",
"session-owner": "false",
"shared": "false",
"timeout": "30",
"tries": "10000",
"version": "1"
}
```
## Authd

`authd` to usługa XPC, która ocenia żądania Authorization Services. W obecnych kompilacjach macOS jej pakiet można sprawdzić pod adresem `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc`; ścieżka ta jest szczegółem implementacyjnym i może różnić się w zależności od wersji. Starsze wersje zapisywały logi w `/var/log/authd.log`; obecne wersje korzystają głównie z systemu unified logging, który można przeszukiwać za pomocą `log show`/`log stream`, używając predykatu procesu `authd`.<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

Narzędzie `security` udostępnia kilka operacji Authorization Services. Historyczny przykład wywołuje `AuthorizationExecuteWithPrivileges` za pomocą `security execute-with-privileges /bin/ls`. Apple oznaczyło to API jako deprecated w macOS 10.7; współczesne uprzywilejowane helpery powinny korzystać z helpera zarządzanego przez launchd oraz autoryzacji XPC.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

W wersjach, które nadal to obsługują, używany jest `/usr/libexec/security_authtrampoline`, a przed uruchomieniem polecenia jako root wyświetlany jest monit autoryzacyjny:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Omówienie uprawnienia autoryzacyjnego macOS](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Przewodnik programowania Apple Authorization Services (archiwum)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [Strona podręcznika macOS `security(1)`](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Przewodnik programowania daemonów i usług: tworzenie zadań launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Projekt Security firmy Apple o otwartym kodzie źródłowym - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
