# macOS Chromium Inspuiting

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Chromium-gebaseerde blaaiers soos Google Chrome, Microsoft Edge, Brave, en ander. Hierdie blaaiers is gebou op die Chromium open-source projek, wat beteken dat hulle 'n gemeenskaplike basis deel en, gevolglik, soortgelyke funksies en ontwikkelaar opsies het.

#### `--load-extension` Vlag

Die `--load-extension` vlag word gebruik wanneer 'n Chromium-gebaseerde blaier vanaf die opdraglyn of 'n skrif begin word. Hierdie vlag stel in staat om **outomaties een of meer uitbreidings** in die blaier te laai by opstart.

#### `--use-fake-ui-for-media-stream` Vlag

Die `--use-fake-ui-for-media-stream` vlag is 'n ander opdraglyn opsie wat gebruik kan word om Chromium-gebaseerde blaaiers te begin. Hierdie vlag is ontwerp om **die normale gebruikersprompt te omseil wat toestemming vra om toegang tot media strome van die kamera en mikrofoon te verkry**. Wanneer hierdie vlag gebruik word, gee die blaier outomaties toestemming aan enige webwerf of toepassing wat toegang tot die kamera of mikrofoon vra.

### Gereedskap

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Voorbeeld
```bash
# Intercept traffic
voodoo intercept -b chrome
```
Vind meer voorbeelde in die hulpmiddel skakels

## Verwysings

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}
