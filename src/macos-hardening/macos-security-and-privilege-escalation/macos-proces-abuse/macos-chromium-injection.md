# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne Informacije

Browserski programi zasnovani na Chromium-u, kao što su Google Chrome, Microsoft Edge, Brave i drugi. Ovi pregledači su izgrađeni na Chromium open-source projektu, što znači da dele zajedničku osnovu i, stoga, imaju slične funkcionalnosti i opcije za programere.

#### `--load-extension` Zastavica

Zastavica `--load-extension` se koristi prilikom pokretanja pregledača zasnovanog na Chromium-u iz komandne linije ili skripte. Ova zastavica omogućava **automatsko učitavanje jedne ili više ekstenzija** u pregledač prilikom pokretanja.

#### `--use-fake-ui-for-media-stream` Zastavica

Zastavica `--use-fake-ui-for-media-stream` je još jedna opcija komandne linije koja se može koristiti za pokretanje pregledača zasnovanih na Chromium-u. Ova zastavica je dizajnirana da **obiđe normalne korisničke poruke koje traže dozvolu za pristup medijskim tokovima sa kamere i mikrofona**. Kada se ova zastavica koristi, pregledač automatski odobrava pristup bilo kojoj veb stranici ili aplikaciji koja traži pristup kameri ili mikrofonu.

### Alati

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Primer
```bash
# Intercept traffic
voodoo intercept -b chrome
```
Pronađite više primera u linkovima alata

## Reference

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}
