# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie <a href="#3f17" id="3f17"></a>

**Sprawdź oryginalny wpis, aby poznać [wszystkie informacje o tej technice](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Podsumowując, kontrola nad atrybutem **`msDS-KeyCredentialLink`** użytkownika lub komputera może umożliwić atakującemu dodanie poświadczenia klucza, uwierzytelnienie się jako ten obiekt za pomocą PKINIT oraz — jeśli KDC i konto obsługują wymagane przepływy — użycie uzyskanego biletu z `S4U2Self`/user-to-user w celu odzyskania skrótu NT obiektu.<sup>[[1]](#references)</sup>

W artykule opisano metodę konfiguracji **poświadczeń uwierzytelniania kluczem publicznym i prywatnym** w celu uzyskania unikatowego **Service Ticket** zawierającego hash NTLM celu. Proces ten wykorzystuje zaszyfrowany NTLM_SUPPLEMENTAL_CREDENTIAL w Privilege Attribute Certificate (PAC), który można odszyfrować.<sup>[[1]](#references)</sup>

### Wymagania

Aby zastosować tę technikę, muszą być spełnione określone warunki:<sup>[[1]](#references)</sup>

- Wymagany jest co najmniej jeden kontroler domeny Windows Server 2016.
- Na kontrolerze domeny musi być zainstalowany certyfikat cyfrowy uwierzytelniania serwera.
- Schemat katalogu musi zawierać `msDS-KeyCredentialLink`; praktyczne wymagania platformy opisane w badaniu to kontroler domeny Windows Server 2016 lub nowszy oraz certyfikat na KDC obsługujący PKINIT. Sprawdź schemat domeny i wersje jej kontrolerów zamiast zakładać, że o możliwości wykorzystania podatności decyduje wyłącznie poziom funkcjonalności domeny.
- Wymagane jest konto z delegowanymi uprawnieniami do modyfikowania atrybutu msDS-KeyCredentialLink obiektu docelowego.

## Nadużycie

Nadużycie Key Trust w przypadku obiektów komputerów obejmuje więcej kroków niż samo uzyskanie Ticket Granting Ticket (TGT) i skrótu NTLM. Dostępne opcje to:<sup>[[1]](#references)</sup>

1. Utworzenie **RC4 silver ticket**, aby działać jako uprzywilejowani użytkownicy na wybranym hoście.
2. Użycie TGT z **S4U2Self** do podszywania się pod **uprzywilejowanych użytkowników**; wymaga to zmodyfikowania Service Ticket w celu dodania klasy usługi do nazwy usługi.

Istotną zaletą nadużycia Key Trust jest to, że ogranicza się ono do klucza prywatnego wygenerowanego przez atakującego, nie wymaga delegowania uprawnień do potencjalnie podatnych kont ani tworzenia konta komputera, którego usunięcie może być problematyczne.<sup>[[1]](#references)</sup>

## Narzędzia

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker używa DSInternals do manipulowania `msDS-KeyCredentialLink` z poziomu C#. Whisker i jego odpowiednik w Pythonie, **pyWhisker**, obsługują dodawanie, wyświetlanie, usuwanie i czyszczenie poświadczeń kluczy.<sup>[[2]](#references)[[4]](#references)</sup>

Funkcje **Whisker** obejmują:

- **Add**: Generuje parę kluczy i dodaje poświadczenie klucza.
- **List**: Wyświetla wszystkie wpisy poświadczeń kluczy.
- **Remove**: Usuwa wskazane poświadczenie klucza.
- **Clear**: Usuwa wszystkie poświadczenia kluczy, co może zakłócić prawidłowe działanie WHfB.

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker przenosi ten workflow na **systemy typu UNIX** z użyciem Impacket i PyDSInternals, umożliwiając wyświetlanie, dodawanie i usuwanie oraz import i eksport JSON.<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray wylicza obiekty domenowe, do których operator ma uprawnienia takie jak `GenericWrite`/`GenericAll`, próbuje szeroko dodawać poświadczenia klucza oraz udostępnia tryby czyszczenia i rekurencyjny. Szerokie rozpylanie jest zakłócające i rzuca się w oczy; używaj jawnie wskazanych celów i zapisuj każdy dodany DeviceID, aby móc go precyzyjnie usunąć.<sup>[[3]](#references)</sup>

ADWS może przenosić zapis poświadczeń klucza, gdy bezpośrednie połączenia LDAP są filtrowane. Zobacz [workflow SOAPy ADWS](../adws-enumeration.md#shadow-credentials-over-adws).<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials: nadużywanie mapowania kont na podstawie Key Trust w celu przejęcia konta](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker — narzędzie do przejmowania kont AD przez manipulowanie msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray — narzędzie do rozpylania Shadow Credentials w domenie](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker — wersja narzędzia Shadow Credentials napisana w Pythonie](https://github.com/ShutdownRepo/pywhisker)
- [5] [Wiki SOAPy — post-exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
