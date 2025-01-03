# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Vivinjari vinavyotegemea Chromium kama Google Chrome, Microsoft Edge, Brave, na vinginevyo. Vivinjari hivi vimejengwa kwenye mradi wa wazi wa Chromium, ambayo inamaanisha vinashiriki msingi wa kawaida na, kwa hivyo, vina kazi na chaguzi za maendeleo zinazofanana.

#### `--load-extension` Flag

Lipu la `--load-extension` linatumika wakati wa kuanzisha kivinjari kinachotegemea Chromium kutoka kwa mstari wa amri au skripti. Lipu hili linaruhusu **kuongeza moja au zaidi ya nyongeza** kwenye kivinjari wakati wa kuanzisha.

#### `--use-fake-ui-for-media-stream` Flag

Lipu la `--use-fake-ui-for-media-stream` ni chaguo jingine la mstari wa amri ambalo linaweza kutumika kuanzisha vivinjari vinavyotegemea Chromium. Lipu hili limetengenezwa ili **kupita maonyo ya kawaida ya mtumiaji yanayouliza ruhusa ya kufikia mitiririko ya media kutoka kwa kamera na kipaza sauti**. Wakati lipu hili linatumika, kivinjari kinatoa ruhusa moja kwa moja kwa tovuti au programu yoyote inayohitaji kufikia kamera au kipaza sauti.

### Tools

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Example
```bash
# Intercept traffic
voodoo intercept -b chrome
```
Pata mifano zaidi katika viungo vya zana

## Marejeleo

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}
