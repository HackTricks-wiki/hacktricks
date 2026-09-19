# AGENTS.md

Consignes pour les futurs agents travaillant dans ce repository.

## Contexte du repository

Il s'agit du repository mdBook principal de HackTricks. Le livre cloud associé se trouve à l'adresse :

`/Users/carlospolop/git/hacktricks-cloud`

Les modifications du comportement partagé du thème/de la recherche doivent souvent être appliquées dans les deux repositories.

## Contrat de chargement de l'index de recherche

L'interface de recherche personnalisée se trouve dans :

`theme/ht_searcher.js`

Une copie générée peut également se trouver dans :

`book/theme/ht_searcher.js`

Si la production déploie le répertoire `book/` déjà construit, mettez à jour les deux copies ou reconstruisez le
book avant le déploiement.

La stratégie de source de l'index de recherche est importante et sensible aux coûts :

- Sur les hosts publics, chargez chaque candidat spécifique à une langue et de fallback uniquement depuis
`HackTricks-wiki/hacktricks-searchindex`. Ne faites jamais de fallback vers la sortie mdBook de la même origine ;
servir le grand index depuis `hacktricks.wiki` en production coûte cher.
- Sur localhost, les hosts `.local`/`.internal`, les adresses loopback, RFC1918, carrier-grade NAT, link-local ou
les adresses IPv6 privées, chargez uniquement la sortie mdBook de la même origine afin que les déploiements
locaux/de conteneurs restent autonomes. Pour une page dans une langue autre que l'anglais, essayez d'abord le
chemin local préfixé par la langue (par exemple `/es/searchindex.js`) et utilisez l'index anglais racine uniquement
comme fallback.

Pour ce repo, le fallback local attendu est :

`/searchindex.js`

Sur les hosts privés, l'index cloud est indisponible depuis cette origine et ne doit pas déclencher de
téléchargement distant. Sur les hosts publics, il doit utiliser les fichiers distants
`searchindex-cloud-<lang>.js.gz`.

## Publication de l'index de recherche

Les workflows qui publient les index de recherche compressés et chiffrés vers
`HackTricks-wiki/hacktricks-searchindex` sont :

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Le fichier source généré est `book/searchindex.js`. Les noms des artefacts distants publiés sont :

- `searchindex-v2-en.json.gz` (index compact préféré)
- `searchindex-v2-<lang>.json.gz` (index compact préféré)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Le browser loader donne la priorité à l'artefact compact v2 et conserve l'artefact `.js.gz` comme
fallback legacy. Les deux sont des payloads gzip chiffrés avec XOR utilisant la clé définie dans
`theme/ht_searcher.js`.

Le loader doit rester lazy : la navigation normale entre les pages ne doit pas créer le search worker ni
télécharger un index tant que le visiteur n'ouvre pas ou n'utilise pas la recherche. Les réponses distantes
compressées sont conservées dans le Cache Storage pendant 24 heures par origine afin que les pages suivantes
puissent les réutiliser. Préservez le fallback vers le cache périmé lorsqu'une actualisation d'une entrée
expirée échoue.

## Build et validation

Vérifications locales courantes :

- `node --check theme/ht_searcher.js`
- `mdbook build`

Si `mdbook build` échoue, vérifiez :

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Notes d'édition

- Préférez `rg` pour les recherches.
- Gardez la sortie `book/` générée hors des commits, sauf demande explicite. Les corrections du search loader
  sont une exception lorsque les pages déjà construites doivent être corrigées immédiatement.
- En cas de modification du comportement partagé du thème, comparez et mettez à jour le fichier correspondant dans
`/Users/carlospolop/git/hacktricks-cloud`.
- N'annulez pas les modifications locales sans rapport.
