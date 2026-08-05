# Baza danych autoryzacji macOS i Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Baza danych autoryzacji**

Baza danych znajdująca się w `/var/db/auth.db` służy do przechowywania uprawnień do wykonywania wrażliwych operacji. Operacje te są wykonywane całkowicie w **user space** i zwykle są używane przez **usługi XPC**, które muszą sprawdzić, **czy wywołujący klient jest uprawniony** do wykonania określonej czynności, sprawdzając tę bazę danych.

Początkowo baza danych jest tworzona na podstawie zawartości `/System/Library/Security/authorization.plist`. Następnie niektóre usługi mogą dodawać lub modyfikować tę bazę danych, aby wprowadzić do niej dodatkowe uprawnienia.

Reguły są przechowywane w tabeli `rules` wewnątrz bazy danych i zawierają następujące kolumny:

- **id**: Unikalny identyfikator każdej reguły, automatycznie zwiększany i pełniący funkcję klucza głównego.
- **name**: Unikalna nazwa reguły używana do jej identyfikowania i odwoływania się do niej w systemie autoryzacji.
- **type**: Określa typ reguły; dozwolone są wartości 1 lub 2 definiujące jej logikę autoryzacji.
- **class**: Kategoryzuje regułę do określonej klasy, zapewniając, że jest ona dodatnią liczbą całkowitą.
- "allow" oznacza zezwolenie, "deny" oznacza odmowę, "user" jest używane, jeśli właściwość group wskazuje grupę, której członkostwo umożliwia dostęp, "rule" wskazuje w tablicy regułę, która musi zostać spełniona, a "evaluate-mechanisms" jest poprzedzone tablicą `mechanisms`, zawierającą elementy będące wbudowanymi mechanizmami albo nazwą bundle znajdującego się w `/System/Library/CoreServices/SecurityAgentPlugins/` lub `/Library/Security//SecurityAgentPlugins`
- **group**: Wskazuje grupę użytkowników powiązaną z regułą na potrzeby autoryzacji opartej na grupach.
- **kofn**: Reprezentuje parametr „k-of-n”, określający, ile podreguł z całkowitej liczby musi zostać spełnionych.
- **timeout**: Określa czas w sekundach, po którym autoryzacja przyznana przez regułę wygasa.
- **flags**: Zawiera różne flagi modyfikujące działanie i właściwości reguły.
- **tries**: Ogranicza liczbę dozwolonych prób autoryzacji w celu zwiększenia bezpieczeństwa.
- **version**: Śledzi wersję reguły na potrzeby kontroli wersji i aktualizacji.
- **created**: Zapisuje znacznik czasu utworzenia reguły na potrzeby audytu.
- **modified**: Przechowuje znacznik czasu ostatniej modyfikacji reguły.
- **hash**: Zawiera wartość hash reguły, aby zapewnić jej integralność i wykrywać manipulacje.
- **identifier**: Udostępnia unikalny identyfikator tekstowy, taki jak UUID, na potrzeby zewnętrznych odwołań do reguły.
- **requirement**: Zawiera serializowane dane definiujące określone wymagania autoryzacji i mechanizmy reguły.
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
Ponadto na stronie [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) można znaleźć znaczenie `authenticate-admin-nonshared`:<sup>[1]</sup>
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

Jest to daemon, który odbiera żądania autoryzacji klientów do wykonywania poufnych działań. Działa jako usługa XPC zdefiniowana w folderze `XPCServices/` i zapisuje swoje logi w `/var/log/authd.log`.

Ponadto za pomocą narzędzia security można testować wiele interfejsów API `Security.framework`. Na przykład uruchomienie `AuthorizationExecuteWithPrivileges`: `security execute-with-privileges /bin/ls`

Spowoduje to wykonanie fork i exec `/usr/libexec/security_authtrampoline /bin/ls` z uprawnieniami root, co wyświetli monit o zgodę na wykonanie ls jako root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Przegląd uprawnienia autoryzacji systemu macOS](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
