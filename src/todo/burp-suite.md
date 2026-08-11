# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Tipos de payload de Intruder

- **Simple list:** Usa una lista configurada de strings como payloads.
- **Runtime file:** Lee un payload por línea durante la ejecución. Esto es útil para listas grandes porque Burp no carga todo el archivo en memoria.
- **Case modification:** Cambia las mayúsculas y minúsculas de un string de entrada, por ejemplo a minúsculas, mayúsculas, formato de oración o formato de título.
- **Numbers:** Genera números secuenciales o aleatorios dentro de un rango configurado.
- **Brute forcer:** Genera todas las permutaciones para un conjunto de caracteres y una longitud mínima/máxima elegidos.<sup>[[1]](#references)</sup>

## Extensiones y herramientas complementarias

- **Collabfiltrator** genera payloads que ejecutan comandos y exfiltran su salida mediante consultas DNS a Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** exporta los hallazgos de Burp para usarlos en otros workflows de reporting.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** convierte solicitudes HTTP en scripts en varios lenguajes.<sup>[[4]](#references)</sup>

## References

- [1] [Documentación de PortSwigger - tipos de payload de Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
