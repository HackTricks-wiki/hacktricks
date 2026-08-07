# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Payloads básicos

- **Lista simples:** Apenas uma lista contendo uma entrada em cada linha
- **Arquivo em runtime:** Uma lista lida em runtime (não carregada na memória). Para suportar listas grandes.
- **Modificação de maiúsculas/minúsculas:** Aplicar algumas alterações a uma lista de strings (Sem alteração, para minúsculas, para MAIÚSCULAS, para Nome próprio - primeira letra maiúscula e o restante em minúsculas -, para Nome Próprio - primeira letra maiúscula e o restante permanece igual-.
- **Números:** Gerar números de X a Y usando o passo Z ou aleatoriamente.
- **Brute Forcer:** Conjunto de caracteres, comprimento mínimo e máximo.

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : Payload para executar comandos e obter a saída por meio de requisições DNS para burpcollab.

{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ../banners/hacktricks-training.md}}
