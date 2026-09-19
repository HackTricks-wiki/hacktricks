# AGENTS.md

Instructions pour les futurs agents travaillant dans ce repository.

## Contexte du repository

Il s’agit du repository principal HackTricks mdBook. Le livre cloud associé se trouve à l’emplacement :

`/Users/carlospolop/git/hacktricks-cloud`

Les modifications du comportement partagé du thème/de la recherche doivent souvent être appliquées dans les deux repositories.

## Contrat de chargement de l’index de recherche

L’interface de recherche personnalisée se trouve dans :

`theme/ht_searcher.js`

Il peut également exister une copie générée à l’emplacement :

`book/theme/ht_searcher.js`

Si la production déploie le répertoire `book/` déjà généré, mettez à jour les deux copies ou rebuild le
book avant le déploiement.

L’ordre de chargement de l’index de recherche est important et sensible aux coûts :

1. Charger chaque index de recherche spécifique à une langue ainsi que l’index de secours depuis le repository GitHub :
`HackTricks-wiki/hacktricks-searchindex`
2. Utiliser le fallback mdBook same-origin uniquement si tous les candidats hébergés sur GitHub échouent.

Ne placez pas le fallback local `/searchindex.js` avant un fallback hébergé sur GitHub tel que
`searchindex-en.js.gz`. Servir `searchindex.js` depuis `hacktricks.wiki` en production coûte cher.

Pour ce repo, le fallback local attendu est :

`/searchindex.js`

L’index cloud ne doit pas utiliser de fallback local depuis cette origin. Il doit s’appuyer sur les fichiers distants
`searchindex-cloud-<lang>.js.gz`.

## Publication de l’index de recherche

Les workflows qui publient les index de recherche compressés et chiffrés dans
`HackTricks-wiki/hacktricks-searchindex` sont :

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Le fichier source généré est `book/searchindex.js`. Les noms des artifacts distants publiés sont :

- `searchindex-v2-en.json.gz` (index compact préféré)
- `searchindex-v2-<lang>.json.gz` (index compact préféré)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Le browser loader donne la priorité à l’artifact compact v2 et conserve l’artifact `.js.gz` comme
fallback legacy. Les deux sont des payloads gzip chiffrés avec XOR à l’aide de la clé définie dans `theme/ht_searcher.js`.

Le loader doit rester lazy : la navigation normale entre les pages ne doit pas créer le search worker ni télécharger
un index tant que le visiteur n’ouvre pas ou n’utilise pas la recherche. Les réponses distantes compressées sont
conservées dans le Cache Storage pendant 24 heures par origin afin que les pages suivantes puissent les réutiliser.
Conservez le fallback du cache obsolète lorsqu’une actualisation d’une entrée expirée échoue.

## Build et validation

Vérifications locales courantes :

- `node --check theme/ht_searcher.js`
- `mdbook build`

Si `mdbook build` échoue, vérifiez :

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Notes d’édition

- Préférez `rg` pour effectuer les recherches.
- Évitez de committer la sortie `book/` générée, sauf demande explicite. Les corrections du search loader
font exception lorsque les pages déjà buildées doivent être corrigées immédiatement.
- En cas de modification du comportement partagé du thème, comparez et mettez à jour le fichier correspondant dans
`/Users/carlospolop/git/hacktricks-cloud`.
- Ne rétablissez pas les modifications locales sans rapport.
