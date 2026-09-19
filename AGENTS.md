# AGENTS.md

Orientación para futuros agentes que trabajen en este repositorio.

## Contexto del repositorio

Este es el repositorio principal de HackTricks mdBook. El libro relacionado con cloud se encuentra en:

`/Users/carlospolop/git/hacktricks-cloud`

Los cambios en el comportamiento compartido del tema o de la búsqueda a menudo deben aplicarse en ambos repositorios.

## Contrato de carga del índice de búsqueda

La interfaz de búsqueda personalizada se encuentra en:

`theme/ht_searcher.js`

También puede existir una copia generada en:

`book/theme/ht_searcher.js`

Si production está despleciendo el directorio `book/` ya compilado, actualiza ambas copias o vuelve a compilar el
book antes del despliegue.

La política de origen del índice de búsqueda es importante y sensible a los costes:

- En hosts públicos, carga todos los candidatos específicos de cada idioma y de fallback únicamente desde
`HackTricks-wiki/hacktricks-searchindex`. Nunca uses como fallback el output de mdBook del mismo origen;
servir el índice grande desde `hacktricks.wiki` en production es caro.
- En localhost, hosts `.local`/`.internal`, loopback, RFC1918, NAT de nivel de operador, direcciones link-local o
direcciones IPv6 privadas, carga únicamente el output de mdBook del mismo origen para que los despliegues
locales/de contenedor sigan siendo autocontenidos.

Para este repositorio, el fallback local esperado es:

`/searchindex.js`

En hosts privados, el índice cloud no está disponible desde este origen y no debe provocar una descarga remota.
En hosts públicos debe usar los archivos remotos `searchindex-cloud-<lang>.js.gz`.

## Publicación del índice de búsqueda

Los workflows que publican índices de búsqueda comprimidos y cifrados en
`HackTricks-wiki/hacktricks-searchindex` son:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

El archivo fuente generado es `book/searchindex.js`. Los nombres de los artefactos remotos publicados son:

- `searchindex-v2-en.json.gz` (índice compacto preferido)
- `searchindex-v2-<lang>.json.gz` (índice compacto preferido)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

El loader del navegador prefiere el artefacto compacto v2 y conserva el artefacto `.js.gz` como
fallback heredado. Ambos son payloads gzip cifrados mediante XOR usando la clave definida en `theme/ht_searcher.js`.

El loader debe seguir siendo lazy: la navegación normal por las páginas no debe crear el search worker ni descargar un
índice hasta que el visitante abra o use la búsqueda. Las respuestas remotas comprimidas se guardan en Cache
Storage durante 24 horas por origen para que las páginas posteriores puedan reutilizarlas. Conserva el
fallback de caché obsoleta cuando falla la actualización de una entrada caducada.

## Compilación y validación

Comprobaciones locales habituales:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Si `mdbook build` falla, comprueba:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Notas de edición

- Prefiere `rg` para buscar.
- Mantén el output generado de `book/` fuera de los commits salvo que se solicite explícitamente. Las correcciones del
loader de búsqueda son una excepción cuando las páginas ya compiladas deban corregirse de inmediato.
- Si cambias el comportamiento compartido del tema, compara y actualiza el archivo correspondiente en
`/Users/carlospolop/git/hacktricks-cloud`.
- No reviertas cambios locales no relacionados.
