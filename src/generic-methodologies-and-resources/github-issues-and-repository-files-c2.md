# Issues de GitHub y archivos del repositorio como canal C2

{{#include ../banners/hacktricks-training.md}}

Un repositorio privado puede separar el **estado de sesión** de la **transferencia de payloads**: las issues registran cada host y el estado de su handshake, mientras que los archivos del repositorio transportan datos cifrados en ambas direcciones. Esto es más que simplemente consultar el cuerpo de una issue en busca de comandos. La implementación observada usa un token de acceso personal (PAT) de GitHub para acceder a ambas API.<sup>[[1]](#references)</sup> Para un PAT de granularidad fina, crear o actualizar issues requiere permiso de escritura en Issues, y subir archivos requiere permiso de escritura en Contents. En cambio, un PAT clásico necesita el scope `repo`. Cualquiera que obtenga un token con suficientes privilegios puede acceder al mismo canal.<sup>[[2]](#references)[[3]](#references)</sup>

## Handshake de issues y archivos

Un flujo de trabajo observado usa un ID de host hexadecimal corto y la siguiente máquina de estados. El rango exacto de IDs, las cadenas y los prefijos son marcadores del protocolo, no requisitos de la API de GitHub.<sup>[[1]](#references)</sup>

1. Al iniciarse, consulta las issues abiertas y cerradas con `GET /repos/{owner}/{repo}/issues?state=open` (y `state=closed`) para encontrar el estado de sesiones anteriores. Crea una issue abierta titulada `1[ID]` con el cuerpo `hel` mediante `POST /repos/{owner}/{repo}/issues`.
2. Lee un archivo del repositorio cuyo nombre comience por `2[ID]`; este proporciona la clave pública RSA del servidor. Genera una clave de sesión nueva de 16 bytes, la cifra con RSA y sube el resultado en un archivo con el prefijo `1[ID]`.
3. Obtén el IV siguiente mediante XOR entre el IV incrustado y esa clave de sesión. Para cada archivo intercambiado, usa la clave aleatoria de 16 bytes del nombre del archivo para cifrar o descifrar el contenido con AES. El prefijo `2` indica datos del servidor al host; el prefijo `1` indica datos del host al servidor. Así, el nombre del archivo contiene la información de enrutamiento y el material de clave por archivo, mientras que la issue contiene el estado.
4. Lee el siguiente archivo con el prefijo `2` y exige que su contenido descifrado sea igual a `hel`. Sube la información cifrada del host y luego cambia el cuerpo de la issue a `hey` con `PATCH /repos/{owner}/{repo}/issues/{issue_number}`. Solo entonces comienza el polling de comandos.

La API Contents de GitHub lee un archivo mediante `GET /repos/{owner}/{repo}/contents/{path}` y crea o reemplaza uno mediante `PUT` en esa ruta. Para archivos de hasta 1 MB, la respuesta JSON predeterminada incluye el contenido codificado en Base64; los archivos de entre 1 y 100 MB requieren el tipo de medio raw para recuperar su contenido. El cuerpo de la solicitud de subida necesita un mensaje de commit y el contenido del archivo codificado en Base64; para reemplazar un archivo existente, también se necesita el SHA de su blob actual. Estos detalles de la API son distintos del protocolo de cifrado anterior.<sup>[[2]](#references)[[3]](#references)</sup>

En un repositorio de pruebas autorizado, la parte de control mediante issues se puede probar con la API REST (sustituye los valores por un repositorio y un PAT de prueba). No pongas un token activo en la URL, el cuerpo de una issue ni un archivo confirmado en el repositorio.<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

El mecanismo **no** requiere el título del issue, los marcadores `hel`/`hey` ni las opciones de cifrado concretas que se muestran aquí; esos elementos identifican una implementación. La idea reutilizable es separar el estado mutable del host de los objetos cifrados bidireccionales y vincular ambos a un ID de host.<sup>[[1]](#references)</sup> Para otro transporte basado en GitHub issues, consulta las [notas sobre el listener personalizado de AdaptixC2](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema). Para una alternativa basada en comentarios de issues que rota las credenciales del repositorio en lugar de transportar el estado de la sesión, consulta [Servicios web y resolutores dead-drop](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers).

## References

- [1] [Kaspersky Securelist – Operación FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub Docs – Endpoints de la API REST para issues](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub Docs – Endpoints de la API REST para el contenido de repositorios](https://docs.github.com/en/rest/repos/contents)
