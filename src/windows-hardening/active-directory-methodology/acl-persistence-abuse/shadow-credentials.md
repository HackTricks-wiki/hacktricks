# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#3f17" id="3f17"></a>

**Sprawdź oryginalny post, aby uzyskać [wszystkie informacje na temat tej techniki](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

Jako **podsumowanie**: jeśli możesz zapisać do właściwości **msDS-KeyCredentialLink** użytkownika/komputera, możesz odzyskać **NT hash tego obiektu**.

W poście opisano metodę ustawienia **uwierzytelniania za pomocą klucza publicznego-prywatnego**, aby uzyskać unikalny **Service Ticket**, który zawiera hash NTLM celu. Proces ten obejmuje zaszyfrowane NTLM_SUPPLEMENTAL_CREDENTIAL w Certyfikacie Atrybutów Uprawnień (PAC), który można odszyfrować.

### Wymagania

Aby zastosować tę technikę, muszą być spełnione określone warunki:

- Wymagany jest co najmniej jeden kontroler domeny Windows Server 2016.
- Kontroler domeny musi mieć zainstalowany cyfrowy certyfikat uwierzytelniania serwera.
- Active Directory musi być na poziomie funkcjonalnym Windows Server 2016.
- Wymagane jest konto z delegowanymi uprawnieniami do modyfikacji atrybutu msDS-KeyCredentialLink obiektu docelowego.

## Nadużycie

Nadużycie Key Trust dla obiektów komputerowych obejmuje kroki wykraczające poza uzyskanie Ticket Granting Ticket (TGT) i hasha NTLM. Opcje obejmują:

1. Utworzenie **RC4 silver ticket**, aby działać jako uprzywilejowani użytkownicy na zamierzonym hoście.
2. Użycie TGT z **S4U2Self** do impersonacji **uprzywilejowanych użytkowników**, co wymaga zmian w Service Ticket, aby dodać klasę usługi do nazwy usługi.

Znaczną zaletą nadużycia Key Trust jest jego ograniczenie do prywatnego klucza generowanego przez atakującego, unikając delegacji do potencjalnie wrażliwych kont i nie wymagając tworzenia konta komputerowego, co może być trudne do usunięcia.

## Narzędzia

### [**Whisker**](https://github.com/eladshamir/Whisker)

Opiera się na DSInternals, zapewniając interfejs C# do tego ataku. Whisker i jego odpowiednik w Pythonie, **pyWhisker**, umożliwiają manipulację atrybutem `msDS-KeyCredentialLink`, aby uzyskać kontrolę nad kontami Active Directory. Narzędzia te wspierają różne operacje, takie jak dodawanie, wyświetlanie, usuwanie i czyszczenie poświadczeń klucza z obiektu docelowego.

Funkcje **Whisker** obejmują:

- **Add**: Generuje parę kluczy i dodaje poświadczenie klucza.
- **List**: Wyświetla wszystkie wpisy poświadczeń klucza.
- **Remove**: Usuwa określone poświadczenie klucza.
- **Clear**: Usuwa wszystkie poświadczenia klucza, potencjalnie zakłócając legalne użycie WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Rozszerza funkcjonalność Whisker do **systemów opartych na UNIX**, wykorzystując Impacket i PyDSInternals do kompleksowych możliwości eksploatacji, w tym listowania, dodawania i usuwania KeyCredentials, a także importowania i eksportowania ich w formacie JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray ma na celu **wykorzystanie uprawnień GenericWrite/GenericAll, które szerokie grupy użytkowników mogą mieć nad obiektami domeny**, aby szeroko stosować ShadowCredentials. Obejmuje to logowanie do domeny, weryfikację poziomu funkcjonalnego domeny, enumerację obiektów domeny oraz próbę dodania KeyCredentials w celu uzyskania TGT i ujawnienia NT hash. Opcje czyszczenia i taktyki rekurencyjnego wykorzystywania zwiększają jego użyteczność.

## References

- [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
- [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
- [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
