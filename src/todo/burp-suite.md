# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Tipos de payload do Intruder

O Burp Intruder inclui os seguintes geradores e transformações de payload integrados:<sup>[[1]](#references)</sup>

- **Simple list:** Usa uma lista configurada de strings como payloads.
- **Runtime file:** Lê um payload por linha durante a execução. Isso é útil para listas grandes, pois o Burp não carrega o arquivo inteiro na memória.
- **Case modification:** Gera o valor não modificado, as formas em minúsculas e maiúsculas, `Propername` (primeira letra maiúscula e o restante em minúsculas) ou `ProperName` (primeira letra maiúscula com os caracteres restantes inalterados). O Burp descarta resultados duplicados.
- **Numbers:** Gera números sequenciais ou aleatórios dentro de um intervalo configurado.
- **Brute forcer:** Gera todas as permutações para um conjunto de caracteres e um tamanho mínimo/máximo escolhidos.

## Extensões e ferramentas complementares

- **Collabfiltrator** gera payloads que executam comandos e exfiltram sua saída por meio de consultas DNS para o Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** exporta findings do Burp para uso em outros fluxos de trabalho de relatório.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** converte requisições HTTP em scripts em várias linguagens.<sup>[[4]](#references)</sup>

## References

- [1] [Documentação do PortSwigger - tipos de payload do Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
