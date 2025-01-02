# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Les navigateurs basés sur Chromium comme Google Chrome, Microsoft Edge, Brave, et d'autres. Ces navigateurs sont construits sur le projet open-source Chromium, ce qui signifie qu'ils partagent une base commune et, par conséquent, ont des fonctionnalités et des options de développement similaires.

#### Drapeau `--load-extension`

Le drapeau `--load-extension` est utilisé lors du démarrage d'un navigateur basé sur Chromium depuis la ligne de commande ou un script. Ce drapeau permet de **charger automatiquement une ou plusieurs extensions** dans le navigateur au démarrage.

#### Drapeau `--use-fake-ui-for-media-stream`

Le drapeau `--use-fake-ui-for-media-stream` est une autre option de ligne de commande qui peut être utilisée pour démarrer des navigateurs basés sur Chromium. Ce drapeau est conçu pour **contourner les invites utilisateur normales qui demandent la permission d'accéder aux flux multimédias de la caméra et du microphone**. Lorsque ce drapeau est utilisé, le navigateur accorde automatiquement la permission à tout site web ou application qui demande l'accès à la caméra ou au microphone.

### Outils

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Exemple
```bash
# Intercept traffic
voodoo intercept -b chrome
```
Trouvez plus d'exemples dans les liens des outils

## Références

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}
