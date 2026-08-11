# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie <a href="#3f17" id="3f17"></a>

**Sprawdź oryginalny post, aby uzyskać [wszystkie informacje na temat tej techniki](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Podsumowując, kontrola nad atrybutem **`msDS-KeyCredentialLink`** użytkownika lub komputera może pozwolić atakującemu dodać key credential, uwierzytelnić się jako ten obiekt za pomocą PKINIT oraz — gdy KDC i konto obsługują wymagane przepływy — użyć uzyskanego biletu z `S4U2Self`/user-to-user w celu odzyskania NT hash obiektu.<sup>[[1]](#references)</sup>

W poście przedstawiono metodę konfigurowania **public-private key authentication credentials** w celu uzyskania unikalnego **Service Ticket**, który zawiera hash NTLM celu. Proces ten obejmuje zaszyfrowany NTLM_SUPPLEMENTAL_CREDENTIAL wewnątrz Privilege Attribute Certificate (PAC), który można odszyfrować.<sup>[[1]](#references)</sup>

### Wymagania

Aby zastosować tę technikę, muszą zostać spełnione określone warunki:<sup>[[1]](#references)</sup>

- Wymagany jest co najmniej jeden Windows Server 2016 Domain Controller.
- Domain Controller musi mieć zainstalowany digital certificate do server authentication.
- Schemat katalogu musi zawierać `msDS-KeyCredentialLink`; Windows Server 2016 lub nowszy DC oraz certificate obsługujący PKINIT na KDC to praktyczne wymagania platformy opisane w badaniu. Należy zweryfikować schemat domeny i zestaw DC, zamiast zakładać, że sama etykieta domain functional-level decyduje o możliwości wykorzystania tej techniki.
- Wymagane jest konto z delegowanymi uprawnieniami do modyfikowania atrybutu msDS-KeyCredentialLink docelowego obiektu.

## Nadużycie

Nadużycie Key Trust w przypadku obiektów komputerów obejmuje kroki wykraczające poza uzyskanie Ticket Granting Ticket (TGT) i hash NTLM. Dostępne opcje obejmują:<sup>[[1]](#references)</sup>

1. Utworzenie **RC4 silver ticket** w celu działania jako uprzywilejowani użytkownicy na określonym hoście.
2. Użycie TGT z **S4U2Self** do impersonacji **uprzywilejowanych użytkowników**, co wymaga modyfikacji Service Ticket w celu dodania service class do service name.

Istotną zaletą nadużycia Key Trust jest ograniczenie go do private key wygenerowanego przez atakującego, dzięki czemu nie jest potrzebna delegacja do potencjalnie podatnych kont ani tworzenie konta komputera, którego usunięcie mogłoby być trudne.<sup>[[1]](#references)</sup>

## Narzędzia

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker używa DSInternals do manipulowania `msDS-KeyCredentialLink` z poziomu C#. Whisker i jego odpowiednik w Pythonie, **pyWhisker**, obsługują dodawanie, wyświetlanie, usuwanie oraz czyszczenie key credentials.<sup>[[2]](#references)[[4]](#references)</sup>

Funkcje **Whisker** obejmują:

- **Add**: Generuje key pair i dodaje key credential.
- **List**: Wyświetla wszystkie wpisy key credential.
- **Remove**: Usuwa określony key credential.
- **Clear**: Usuwa wszystkie key credentials, co może zakłócić prawidłowe działanie WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker przenosi ten workflow do **systemów typu UNIX** za pomocą Impacket i PyDSInternals, zapewniając operacje list/add/remove oraz importu/eksportu JSON.<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray wylicza obiekty domeny, względem których operator ma uprawnienia takie jak `GenericWrite`/`GenericAll`, próbuje szeroko dodawać key credentials oraz obsługuje tryby cleanup/recursive. Szerokie rozpylanie jest destrukcyjne i łatwe do wykrycia; używaj jawnie określonych celów i zachowuj każdy dodany DeviceID, aby umożliwić precyzyjne usunięcie.<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials: nadużywanie mapowania kont przez Key Trust w celu przejęcia konta](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - narzędzie do przejmowania kont AD przez manipulowanie msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - narzędzie do rozpylania Shadow Credentials w domenie](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - wersja narzędzia Shadow Credentials napisana w Pythonie](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}
