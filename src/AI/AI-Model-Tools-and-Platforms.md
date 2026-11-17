# Outils et plateformes de modèles d’IA

{{#include ../banners/hacktricks-training.md}}

## Exécuter et entraîner des modèles localement

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers est une bibliothèque open source permettant de charger, d’entraîner et de servir des modèles préentraînés pour des tâches liées au texte, à la vision, à l’audio, à la vidéo et au multimodal. L’hébergement des modèles et des jeux de données est assuré séparément par le Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain est un framework permettant de créer des applications et des agents pilotés par des modèles, avec des outils de construction de prompts, de gestion de l’historique et de l’état des conversations, de récupération, ainsi que des intégrations de modèles, d’API et de bases de données.<sup>[[2]](#references)</sup>

#### Tester la réactivation d’objets sérialisés LangChain

Lorsqu’une application accepte des entrées utilisateur ou des sorties de modèle **structurées**, vérifiez si les dictionnaires imbriqués sont conservés dans `metadata`, `additional_kwargs`, `response_metadata`, l’historique de chat enregistré ou un flux d’exécution. LangChain utilise des dictionnaires balisés `lc` comme objets sérialisés. Dans les allers-retours `dumps()`/`dumpd()` → `load()`/`loads()` concernés, un dictionnaire contrôlé par un attaquant pourrait être réactivé en tant qu’objet du framework au lieu de rester des données. Charger directement un manifeste non fiable est également dangereux ; une entrée sous forme de chaîne simple qui n’est jamais analysée comme un dictionnaire ne remplit pas ce prérequis.<sup>[[10]](#references)[[11]](#references)</sup>

Pour un test autorisé, soumettez un canari inoffensif ayant la forme d’un constructeur **sous forme d’objet JSON imbriqué**, et non d’une chaîne, puis vérifiez si l’historique ou le flux en aval contient un objet `AIMessage` plutôt que le dictionnaire d’origine :<sup>[[11]](#references)</sup>

```json
{"lc":1,"type":"constructor","id":["langchain_core","messages","ai","AIMessage"],"kwargs":{"content":"serialization-canary"}}
```

Vérifiez `RunnableWithMessageHistory`, `astream_log()` et `astream_events(version="v1")` lorsqu’ils sont réellement utilisés. La restauration réussie d’un objet peut contaminer l’historique de conversation ultérieur ; des listes d’autorisation plus larges peuvent instancier d’autres classes de confiance dont les constructeurs ont des effets de bord. N’assimilez pas cela à l’exécution arbitraire de pickle. La faille d’évasion initiale a été corrigée dans `langchain-core` 0.3.81/1.2.5, et un correctif ultérieur concernant les listes d’autorisation trop larges et les marqueurs secrets a été intégré dans les versions 0.3.85/1.3.3. Pour les manifestes non fiables, utilisez une version actuelle et limitez `allowed_objects` aux classes de messages ou à une liste sûre explicite, avec `secrets_from_env=False`.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup> Pour la [cartographie des frontières de confiance des agents](AI-Agent-Security-Methodology.md), distinguez bien cela de la [RCE liée au chargement de fichiers de modèles](AI-Models-RCE.md).

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT fournit des implémentations lisibles et des workflows en ligne de commande pour le préentraînement, le fine-tuning, l’évaluation et le déploiement de modèles de langage pris en charge.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Description :**\
LitServe est un framework de serving de modèles de Lightning AI permettant d’exposer des API d’inférence avec des mécanismes de batching, de streaming, d’accélération et de mise à l’échelle.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl est un framework open source de post-training et de fine-tuning piloté par une configuration YAML. Il prend en charge des techniques telles que le fine-tuning complet, LoRA/QLoRA, l’optimisation des préférences et l’entraînement multi-GPU ; ce n’est pas en soi une plateforme de déploiement cloud.<sup>[[5]](#references)</sup>

## Essayer des modèles en ligne

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** est une plateforme et une communauté de premier plan dans le domaine du machine learning, particulièrement connue pour ses travaux en traitement du langage naturel (NLP). Elle fournit des outils, des bibliothèques et des ressources qui facilitent le développement, le partage et le déploiement de modèles de machine learning.\
Le Hub propose plusieurs sections pertinentes :<sup>[[6]](#references)</sup>

* **Models** : un vaste dépôt de **modèles de machine learning pré-entraînés** que les utilisateurs peuvent parcourir, télécharger et intégrer pour diverses tâches comme la génération de texte, la traduction, la reconnaissance d’images et bien d’autres.
* **Datasets :** une **collection complète de jeux de données** utilisés pour entraîner et évaluer des modèles. Elle facilite l’accès à diverses sources de données, permettant aux utilisateurs de trouver et d’utiliser les données adaptées à leurs projets de machine learning.
* **Spaces :** une plateforme d’hébergement et de partage d’**applications interactives de machine learning** et de démos. Elle permet aux développeurs de **présenter** leurs modèles en action, de créer des interfaces conviviales et de collaborer en partageant des démos en direct.

#### Inspecter les journaux d’exécution des Spaces publics

Le code du dépôt d’un Space public peut révéler quelles entrées et variables d’environnement son application consigne dans les journaux. Dans le cadre d’une évaluation autorisée, examinez séparément le flux de journaux **run**, indépendamment de l’interface de l’application. Hugging Face documente le endpoint SSE des journaux des Spaces ; des recherches ont montré que les journaux des Spaces publics pouvaient être lus par d’autres utilisateurs du Hub et contenir parfois des clés API, des prompts utilisateur ou un jeton d’accès Dev Mode consigné dans une URL de requête. Un jeton dans un journal n’est important que si le mode privilégié correspondant est toujours activé et que le jeton est encore valide.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
SPACE='owner/space-name'
curl -NsS -H "Authorization: Bearer $HF_TOKEN" \
  "https://huggingface.co/api/spaces/$SPACE/logs/run?tail=100"
```

Utilisez un token associé à votre compte Hub autorisé ; il ne s’agit **pas** d’une demande visant à obtenir le secret du propriétaire du Space. La réponse est un flux SSE (lignes `data:`). Faites correspondre les valeurs exposées au code du Space et à l’environnement d’exécution actuel, plutôt que de supposer qu’une variable a fuité simplement à cause de son nom. Pour un [endpoint Gradio ou model-runner auto-hébergé](AI-Exposed-Self-Hosted-AI-Services.md), consultez plutôt cette page.<sup>[[13]](#references)[[14]](#references)</sup>

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** est un dépôt et une bibliothèque de composants de modèles entraînés réutilisables, notamment des modules utilisés avec TensorFlow/Keras. **Kaggle** propose séparément des notebooks, des jeux de données, des compétitions et des modèles.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules :** Une vaste collection de modèles pré-entraînés et de composants de modèles que les utilisateurs peuvent parcourir, télécharger et intégrer pour des tâches telles que la classification d’images, la représentation vectorielle de texte, et bien plus.
* **Tutoriels :** Des guides détaillés et des exemples qui aident les utilisateurs à implémenter et à affiner des modèles avec TensorFlow Hub.
* **Documentation :** Des guides complets et des références d’API qui aident les développeurs à utiliser efficacement les ressources du dépôt.

## [**Replicate**](https://replicate.com/home)

**Replicate** est une plateforme hébergée permettant d’exécuter des modèles de machine learning empaquetés via une interface web ou une API.<sup>[[8]](#references)</sup>

* **Modèles :** Un dépôt de modèles de machine learning proposés par la communauté, que les utilisateurs peuvent parcourir et essayer, puis intégrer à leurs applications avec un minimum d’effort.
* **Accès à l’API :** Des API permettant d’appeler des modèles depuis des applications sans gérer l’infrastructure d’inférence sous-jacente.

## Attaquer des services d’IA auto-hébergés exposés

Pour le fingerprinting en boîte noire et les tests de model runners auto-hébergés, de constructeurs d’agents, d’interfaces de démonstration ML, de clusters de calcul et de bases de données vectorielles, consultez [Services d’IA auto-hébergés exposés](AI-Exposed-Self-Hosted-AI-Services.md).



## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Documentation du Hub Hugging Face](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Documentation de Replicate](https://replicate.com/docs)
- [9] [Documentation de Kaggle](https://www.kaggle.com/docs)
- [10] [Avis de sécurité sur l’injection de sérialisation dans LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm)
- [11] [Avis de sécurité sur la réhydratation non sécurisée d’objets dans LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724)
- [12] [API load et modèle de menace de LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/core/langchain_core/load/load.py)
- [13] [API des journaux des Spaces Hugging Face](https://huggingface.co/docs/hub/main/en/spaces-gpus#streaming-logs-events-and-metrics)
- [14] [Votre Space est ma zone : risques de sécurité des applications d’IA sur les hubs de modèles](https://arxiv.org/abs/2606.30373)
{{#include ../banners/hacktricks-training.md}}
