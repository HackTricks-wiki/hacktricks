# AGENTS.md

Directives pour les futurs agents travaillant dans ce dépôt.

## Contexte du dépôt

Il s'agit du dépôt principal HackTricks mdBook. Le livre cloud associé se trouve à l'adresse suivante :

`/Users/carlospolop/git/hacktricks-cloud`

Les modifications du comportement partagé du thème/de la recherche doivent souvent être appliquées dans les deux dépôts.

## Contrat de chargement de l'index de recherche

L'interface de recherche personnalisée se trouve dans :

`theme/ht_searcher.js`

Il peut également y avoir une copie générée dans :

`book/theme/ht_searcher.js`

Si la production déploie le répertoire `book/` déjà compilé, mettez à jour les deux copies ou recompilez
le livre avant le déploiement.

La politique concernant la source de l'index de recherche est importante et sensible aux coûts :

- Sur les hôtes publics, chargez chaque candidat spécifique à une langue et de fallback uniquement depuis
`HackTricks-wiki/hacktricks-searchindex`. Ne faites jamais de fallback vers la sortie mdBook du même origin ; servir le gros index depuis `hacktricks.wiki` en production est coûteux.
- Sur localhost, les hôtes `.local`/`.internal`, les adresses loopback, RFC1918, CGNAT, link-local ou
les adresses IPv6 privées, chargez uniquement la sortie mdBook du même origin afin que les déploiements locaux/de conteneurs restent autonomes.

Pour ce dépôt, le fallback local attendu est :

`/searchindex.js`

Sur les hôtes privés, l'index cloud n'est pas disponible depuis cette origin et ne doit pas déclencher
de téléchargement distant. Sur les hôtes publics, il doit utiliser les fichiers distants
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

Le chargeur privilégie l'artefact compact v2 et conserve l'artefact `.js.gz` comme fallback
legacy. Les deux sont des payloads gzip chiffrés avec XOR utilisant la clé définie dans
`theme/ht_searcher.js`.

Le chargeur doit rester lazy : la navigation normale entre les pages ne doit pas créer le search worker ni télécharger d'index tant que le visiteur n'ouvre pas ou n'utilise pas la recherche. Les réponses distantes compressées sont conservées dans Cache Storage pendant 24 heures par origin afin que les pages suivantes puissent les réutiliser. Préservez le fallback vers le cache obsolète lorsqu'une actualisation d'une entrée expirée échoue.

## Compilation et validation

Vérifications locales courantes :

- `node --check theme/ht_searcher.js`
- `mdbook build`

Si `mdbook build` échoue, vérifiez :

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Notes de modification

- Préférez `rg` pour les recherches.
- Gardez la sortie `book/` générée en dehors des commits, sauf demande explicite. Les correctifs du search loader font exception lorsque les pages déjà compilées doivent être corrigées immédiatement.
- Si vous modifiez le comportement partagé du thème, comparez et mettez à jour le fichier correspondant dans
`/Users/carlospolop/git/hacktricks-cloud`.
- Ne rétablissez pas les modifications locales sans rapport.
