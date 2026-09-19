# AGENTS.md

Instructions destinées aux futurs agents travaillant dans ce dépôt.

## Contexte du dépôt

Il s'agit du dépôt principal mdBook de HackTricks. Le livre cloud associé se trouve à l'adresse suivante :

`/Users/carlospolop/git/hacktricks-cloud`

Les modifications apportées au comportement partagé du thème/de la recherche doivent souvent être appliquées aux deux dépôts.

## Contrat de chargement de l'index de recherche

L'interface de recherche personnalisée se trouve dans :

`theme/ht_searcher.js`

Il peut également y avoir une copie générée à l'emplacement suivant :

`book/theme/ht_searcher.js`

Si la production déploie le répertoire `book/` déjà construit, mettez à jour les deux copies ou reconstruisez le
livre avant le déploiement.

L'ordre de chargement de l'index de recherche est important et sensible aux coûts :

1. Chargez chaque index de recherche spécifique à une langue ainsi que l'index de secours depuis le dépôt GitHub :
`HackTricks-wiki/hacktricks-searchindex`
2. Ce n'est que si tous les candidats hébergés sur GitHub échouent qu'il faut utiliser le contenu mdBook de même origine comme solution de secours.

Ne placez pas la solution de secours locale `/searchindex.js` avant une solution de secours hébergée sur GitHub telle que
`searchindex-en.js.gz`. Servir `searchindex.js` depuis `hacktricks.wiki` en production coûte cher.

Pour ce dépôt, la solution de secours locale attendue est :

`/searchindex.js`

L'index cloud ne doit pas utiliser de solution de secours locale provenant de cette origine. Il doit s'appuyer sur les fichiers distants
`searchindex-cloud-<lang>.js.gz`.

## Publication de l'index de recherche

Les workflows qui publient les index de recherche compressés et chiffrés vers
`HackTricks-wiki/hacktricks-searchindex` sont :

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Le fichier source généré est `book/searchindex.js`. Les noms des artefacts distants publiés sont :

- `searchindex-v2-en.json.gz` (index compact recommandé)
- `searchindex-v2-<lang>.json.gz` (index compact recommandé)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Le loader du navigateur donne la priorité à l'artefact compact v2 et conserve l'artefact `.js.gz` comme solution de secours héritée. Les deux sont des payloads gzip chiffrés par XOR utilisant la clé définie dans `theme/ht_searcher.js`.

## Compilation et validation

Vérifications locales courantes :

- `node --check theme/ht_searcher.js`
- `mdbook build`

Si `mdbook build` échoue, consultez :

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Notes de modification

- Préférez `rg` pour les recherches.
- Gardez la sortie `book/` générée en dehors des commits, sauf demande explicite. Les corrections du loader de recherche font exception lorsque les pages déjà construites doivent être corrigées immédiatement.
- En cas de modification du comportement partagé du thème, comparez et mettez à jour le fichier correspondant dans
`/Users/carlospolop/git/hacktricks-cloud`.
- N'annulez pas les modifications locales sans rapport.
