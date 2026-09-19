# AGENTS.md

Guía para futuros agentes que trabajen en este repositorio.

## Contexto del repositorio

Este es el repositorio principal de HackTricks mdBook. El libro relacionado con cloud se encuentra en:

`/Users/carlospolop/git/hacktricks-cloud`

Los cambios en el comportamiento compartido de theme/search a menudo deben aplicarse en ambos repositorios.

## Contrato de carga del índice de búsqueda

La interfaz de búsqueda personalizada se encuentra en:

`theme/ht_searcher.js`

También puede existir una copia generada en:

`book/theme/ht_searcher.js`

Si production está implementando el directorio `book/` ya compilado, actualiza ambas copias o vuelve a compilar el
book antes del deployment.

La política de origen del índice de búsqueda es importante y sensible a los costes:

- En public hosts, carga cada candidato específico del idioma y de fallback únicamente desde
`HackTricks-wiki/hacktricks-searchindex`. Nunca hagas fallback al output de mdBook del mismo origen;
servir el índice grande desde `hacktricks.wiki` en production es caro.
- En localhost, hosts `.local`/`.internal`, loopback, RFC1918, carrier-grade NAT, link-local o
direcciones IPv6 privadas, carga únicamente el output de mdBook del mismo origen para que los deployments
locales/en contenedores sigan siendo autocontenidos. Para una página que no esté en inglés, prueba primero
la ruta local con prefijo de idioma (por ejemplo `/es/searchindex.js`) y usa el índice raíz en inglés solo como fallback.

Para este repo, el fallback local esperado es:

`/searchindex.js`

En private hosts, el índice de cloud no está disponible desde este origen y no debe activar una
descarga remota. En public hosts debe usar los archivos remotos `searchindex-cloud-<lang>.js.gz`.

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

El browser loader da prioridad al artefacto compacto v2 y mantiene el artefacto `.js.gz` como
fallback legacy. Ambos son payloads gzip cifrados mediante XOR usando la key definida en `theme/ht_searcher.js`.

El loader debe seguir siendo lazy: la navegación normal por las páginas no debe crear el search worker ni descargar un índice
hasta que el visitante abra o use la búsqueda. Las respuestas remotas comprimidas se almacenan en Cache
Storage durante 24 horas por origin para que las páginas posteriores puedan reutilizarlas. Conserva el fallback de
stale-cache cuando falla la actualización de una entrada expirada.

## Compilación y validación

Comprobaciones locales habituales:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Si `mdbook build` falla, comprueba:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Notas de edición

- Prefiere `rg` para buscar.
- Mantén el output generado de `book/` fuera de los commits salvo que se solicite explícitamente. Las correcciones del search loader
son una excepción cuando las páginas ya compiladas deban corregirse inmediatamente.
- Si cambias el comportamiento compartido de theme, compara y actualiza el archivo correspondiente en
`/Users/carlospolop/git/hacktricks-cloud`.
- No reviertas cambios locales no relacionados.
