# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie <a href="#3f17" id="3f17"></a>

**Sprawdź oryginalny post, aby uzyskać [wszystkie informacje o tej technice](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

**Podsumowując**: jeśli możesz zapisywać właściwość **msDS-KeyCredentialLink** użytkownika/komputera, możesz pobrać **NT hash tego obiektu**.<sup>[[1]](#references)</sup>

W poście opisano metodę konfigurowania **poświadczeń uwierzytelniania opartych na kluczu publicznym i prywatnym** w celu uzyskania unikalnego **Service Ticket**, który zawiera hash NTLM celu. Proces ten obejmuje zaszyfrowany NTLM_SUPPLEMENTAL_CREDENTIAL w obrębie Privilege Attribute Certificate (PAC), który można odszyfrować.<sup>[[1]](#references)</sup>

### Wymagania

Aby zastosować tę technikę, muszą zostać spełnione określone warunki:<sup>[[1]](#references)</sup>

- Wymagany jest co najmniej jeden kontroler domeny Windows Server 2016.
- Na kontrolerze domeny musi być zainstalowany cyfrowy certyfikat uwierzytelniania serwera.
- Active Directory musi działać na poziomie funkcjonalnym Windows Server 2016.
- Wymagane jest konto z delegowanymi uprawnieniami do modyfikowania atrybutu msDS-KeyCredentialLink docelowego obiektu.

## Abuse

Wykorzystanie Key Trust dla obiektów komputerów obejmuje kroki wykraczające poza uzyskanie Ticket Granting Ticket (TGT) i hasha NTLM. Dostępne opcje obejmują:<sup>[[1]](#references)</sup>

1. Utworzenie **RC4 silver ticket** w celu działania jako uprzywilejowani użytkownicy na docelowym hoście.
2. Użycie TGT wraz z **S4U2Self** do impersonacji **uprzywilejowanych użytkowników**, co wymaga modyfikacji Service Ticket w celu dodania klasy usługi do nazwy usługi.

Istotną zaletą wykorzystania Key Trust jest ograniczenie do prywatnego klucza wygenerowanego przez atakującego, co pozwala uniknąć delegowania do potencjalnie podatnych kont i nie wymaga tworzenia konta komputera, którego usunięcie mogłoby być trudne.<sup>[[1]](#references)</sup>

## Narzędzia

### [**Whisker**](https://github.com/eladshamir/Whisker)

Jest oparty na DSInternals i zapewnia interfejs C# dla tego ataku. Whisker oraz jego odpowiednik w Pythonie, **pyWhisker**, umożliwiają manipulowanie atrybutem `msDS-KeyCredentialLink` w celu przejęcia kontroli nad kontami Active Directory. Narzędzia te obsługują różne operacje, takie jak dodawanie, wyświetlanie, usuwanie i czyszczenie key credentials z docelowego obiektu.

Funkcje **Whisker** obejmują:

- **Add**: Generuje parę kluczy i dodaje key credential.
- **List**: Wyświetla wszystkie wpisy key credential.
- **Remove**: Usuwa określony key credential.
- **Clear**: Usuwa wszystkie key credentials, potencjalnie zakłócając prawidłowe działanie WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Rozszerza funkcjonalność Whisker na **systemy oparte na UNIX**, wykorzystując Impacket i PyDSInternals do kompleksowych możliwości exploitation, w tym wyświetlania, dodawania i usuwania KeyCredentials, a także importowania i eksportowania ich w formacie JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray ma na celu **wykorzystywanie uprawnień GenericWrite/GenericAll, które szerokie grupy użytkowników mogą mieć do obiektów domeny**, aby szeroko stosować ShadowCredentials. Obejmuje to logowanie do domeny, sprawdzanie poziomu funkcjonalnego domeny, enumerację obiektów domeny oraz próby dodawania KeyCredentials w celu uzyskania TGT i ujawnienia hasha NT. Opcje czyszczenia i taktyki rekurencyjnego wykorzystywania zwiększają jego użyteczność.

## Referencje

- [1] [Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Tool for taking over AD accounts by manipulating msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Tool to spray Shadow Credentials across a domain](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python version of the Shadow Credentials tool](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
