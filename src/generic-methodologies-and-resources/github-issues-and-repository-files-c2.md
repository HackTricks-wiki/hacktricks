# GitHub Issues et fichiers de dépôt comme canal C2

{{#include ../banners/hacktricks-training.md}}

Un dépôt privé peut séparer **l’état de session** du **transfert de payload** : les issues consignent chaque hôte et l’état de son handshake, tandis que les fichiers du dépôt transportent des données chiffrées dans les deux sens. Il ne s’agit pas simplement de consulter le corps d’une issue pour y trouver des commandes. L’implémentation observée utilise un jeton d’accès personnel GitHub (PAT) pour accéder aux deux API.<sup>[[1]](#references)</sup> Pour un PAT à granularité fine, la création ou la mise à jour d’issues nécessite l’autorisation d’écriture Issues, et l’envoi de fichiers nécessite l’autorisation d’écriture Contents. Un PAT classique nécessite plutôt le scope `repo`. Toute personne qui obtient un jeton suffisamment privilégié peut accéder au même canal.<sup>[[2]](#references)[[3]](#references)</sup>

## Handshake avec les issues et les fichiers

Un workflow observé utilise un ID d’hôte hexadécimal court et la machine à états suivante. La plage exacte des ID, les chaînes et les préfixes sont des marqueurs de protocole, pas des exigences de l’API GitHub.<sup>[[1]](#references)</sup>

1. Au démarrage, interroger les issues ouvertes et fermées avec `GET /repos/{owner}/{repo}/issues?state=open` (et `state=closed`) pour trouver l’état d’une session précédente. Créer une issue ouverte intitulée `1[ID]` avec le corps `hel` à l’aide de `POST /repos/{owner}/{repo}/issues`.
2. Lire un fichier du dépôt dont le nom commence par `2[ID]` ; il fournit la clé publique RSA du serveur. Générer une nouvelle clé de session de 16 octets, la chiffrer avec RSA et envoyer le résultat dans un fichier préfixé par `1[ID]`.
3. Dériver l’IV suivant en effectuant un XOR entre l’IV intégré et cette clé de session. Pour chaque fichier échangé, utiliser la clé aléatoire de 16 octets contenue dans son nom de fichier pour chiffrer ou déchiffrer son contenu avec AES. Le préfixe `2` désigne les données du serveur vers l’hôte ; le préfixe `1` désigne les données de l’hôte vers le serveur. Le nom du fichier contient donc les informations de routage et le matériau de clé propre au fichier, tandis que l’issue contient l’état.
4. Lire le fichier suivant préfixé par `2` et vérifier que son contenu déchiffré est égal à `hel`. Envoyer les informations chiffrées sur l’hôte, puis remplacer le corps de l’issue par `hey` avec `PATCH /repos/{owner}/{repo}/issues/{issue_number}`. Ce n’est qu’ensuite que la consultation des commandes commence.

L’API Contents de GitHub permet de lire un fichier via `GET /repos/{owner}/{repo}/contents/{path}` et d’en créer ou remplacer un via `PUT` sur ce chemin. Pour les fichiers d’au plus 1 Mo, la réponse JSON par défaut inclut le contenu encodé en Base64 ; les fichiers de 1 à 100 Mo nécessitent le type de média brut pour récupérer leur contenu. Le corps de la requête d’envoi nécessite un message de commit et le contenu du fichier encodé en Base64 ; le remplacement d’un fichier existant nécessite également le SHA de son blob actuel. Ces détails d’API sont distincts du protocole de chiffrement décrit ci-dessus.<sup>[[2]](#references)[[3]](#references)</sup>

Dans un dépôt de test autorisé, la partie de contrôle par issue peut être testée avec l’API REST (remplacez par un dépôt et un PAT de test). Ne placez pas de jeton actif dans l’URL, le corps d’une issue ou un fichier commité.<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

Le mécanisme ne nécessite **pas** le titre de l’issue, les marqueurs `hel`/`hey` ni les choix de chiffrement particuliers présentés ici ; ceux-ci identifient une implémentation. L’idée réutilisable consiste à séparer l’état mutable de l’hôte des objets chiffrés bidirectionnels, et à lier les deux à un ID d’hôte.<sup>[[1]](#references)</sup> Pour un autre transport basé sur les issues GitHub, consultez les [notes sur le listener personnalisé d’AdaptixC2](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema). Pour une solution de repli utilisant des commentaires d’issue et faisant tourner les identifiants du dépôt au lieu de transporter l’état de session, consultez [Services web et résolveurs dead-drop](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers).

## References

- [1] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub Docs – Points de terminaison de l’API REST pour les issues](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub Docs – Points de terminaison de l’API REST pour le contenu des dépôts](https://docs.github.com/en/rest/repos/contents)
