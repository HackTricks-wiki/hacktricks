# AGENTS.md

Orientación para futuros agentes que trabajen en este repositorio.

## Contexto del repositorio

Este es el repositorio principal de mdBook de HackTricks. El libro relacionado sobre cloud se encuentra en:

`/Users/carlospolop/git/hacktricks-cloud`

Los cambios en el comportamiento compartido del theme/search a menudo deben aplicarse en ambos repositorios.

## Contrato de carga del índice de búsqueda

La UI de búsqueda personalizada se encuentra en:

`theme/ht_searcher.js`

También puede existir una copia generada en:

`book/theme/ht_searcher.js`

Si production está desplegando el directorio `book/` ya construido, actualiza ambas copias o vuelve a construir el
book antes del deployment.

El orden de carga del índice de búsqueda es importante y sensible a los costes:

1. Carga todos los índices de búsqueda específicos de cada idioma y de respaldo desde el repositorio de GitHub:
`HackTricks-wiki/hacktricks-searchindex`
2. Solo si fallan todos los candidatos alojados en GitHub, usa como alternativa el output de mdBook del mismo origen.

No coloques la alternativa local `/searchindex.js` antes de cualquier alternativa alojada en GitHub, como
`searchindex-en.js.gz`. Servir `searchindex.js` desde `hacktricks.wiki` en production es caro.

Para este repositorio, la alternativa local esperada es:

`/searchindex.js`

El índice de cloud no debe usar una alternativa local de este origen. Debe depender de los archivos remotos
`searchindex-cloud-<lang>.js.gz`.

## Publicación del índice de búsqueda

Los workflows que publican índices de búsqueda comprimidos y encrypted en
`HackTricks-wiki/hacktricks-searchindex` son:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

El archivo fuente generado es `book/searchindex.js`. Los nombres de los artifacts remotos publicados son:

- `searchindex-v2-en.json.gz` (índice compacto preferido)
- `searchindex-v2-<lang>.json.gz` (índice compacto preferido)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

El browser loader prioriza el artifact compacto v2 y mantiene el artifact `.js.gz` como alternativa legacy.
Ambos son payloads gzip encrypted con XOR usando la key definida en `theme/ht_searcher.js`.

El loader debe seguir siendo lazy: la navegación normal por las páginas no debe crear el search worker ni descargar un índice hasta que el visitante abra o use la búsqueda. Las respuestas remotas comprimidas se guardan en Cache Storage durante 24 horas por origin para que las páginas posteriores puedan reutilizarlas. Conserva la alternativa de la stale-cache al actualizar una entrada expirada si falla la actualización.

## Build y validación

Comprobaciones locales habituales:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Si `mdbook build` falla, comprueba:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Notas de edición

- Prioriza `rg` para las búsquedas.
- Mantén el output generado de `book/` fuera de los commits salvo que se solicite explícitamente. Las correcciones del search loader son una excepción cuando las páginas ya construidas deban corregirse inmediatamente.
- Si cambias el comportamiento compartido del theme, compara y actualiza el archivo correspondiente en
`/Users/carlospolop/git/hacktricks-cloud`.
- No reviertas cambios locales no relacionados.
