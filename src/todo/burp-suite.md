# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Payloads básicos

- **Simple List:** Solo una lista que contiene una entrada en cada línea
- **Runtime File:** Una lista leída durante la ejecución (no cargada en memoria). Para admitir listas grandes.
- **Case Modification:** Aplicar algunos cambios a una lista de strings (sin cambios, a minúsculas, a MAYÚSCULAS, a nombre propio -la primera letra en mayúscula y el resto en minúsculas-, a Nombre Propio -la primera letra en mayúscula y el resto permanece igual-.
- **Numbers:** Generar números de X a Y usando un paso Z o aleatoriamente.
- **Brute Forcer:** Conjunto de caracteres, longitud mínima y máxima.

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : Payload para ejecutar comandos y obtener el resultado mediante solicitudes DNS a burpcollab.

{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ../banners/hacktricks-training.md}}
