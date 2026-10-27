# Burp MCP : examen du trafic assisté par LLM

{{#include ../banners/hacktricks-training.md}}

## Aperçu

L’extension **MCP Server** de Burp peut exposer le trafic HTTP(S) intercepté aux clients LLM compatibles avec MCP afin qu’ils puissent **raisonner sur des requêtes/réponses réelles** pour découvrir des vulnérabilités et rédiger des rapports. Gardez Burp comme source de vérité : privilégiez l’analyse passive ou les relectures délibérées avec une seule variable modifiée plutôt que le scan à l’aveugle.<sup>[[8]](#references)</sup>

## Architecture

- **Burp MCP Server (BApp)** écoute par défaut sur `127.0.0.1:9876` et expose le trafic intercepté via MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** fait le lien entre stdio (côté client) et le point de terminaison MCP SSE de Burp.
- **Proxy inverse local facultatif** (Caddy) normalise les en-têtes pour les vérifications strictes de la négociation MCP.
- **Clients/backends** : Codex CLI (cloud), Gemini CLI (cloud) ou Ollama (local).

## Configuration

### 1) Installer Burp MCP Server

Installez **MCP Server** depuis le Burp BApp Store et vérifiez qu’il écoute sur `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Extraire le proxy JAR

Dans l’onglet MCP Server, cliquez sur **Extraire le JAR proxy du serveur** et enregistrez `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Configurer un client MCP (exemple avec Codex)

Indiquez au client le chemin du proxy JAR et le point de terminaison SSE direct de Burp. Le proxy fourni fait le lien entre stdio et SSE ; il ne remplace pas le listener de Burp.<sup>[[7]](#references)</sup>

```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```

La commande Codex équivalente est :<sup>[[7]](#references)[[8]](#references)</sup>

```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
```

Lancez ensuite Codex et répertoriez les outils MCP :

```bash
codex
# inside Codex: /mcp
```

### 4) Corriger la validation stricte de Origin/des en-têtes avec Caddy (si nécessaire)

Si la négociation MCP échoue à cause de vérifications strictes de `Origin` ou d’en-têtes supplémentaires, utilisez un proxy inverse local pour normaliser les en-têtes (cela reprend le contournement du problème de validation stricte de Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

```bash
brew install caddy
mkdir -p ~/burp-mcp
cat >~/burp-mcp/Caddyfile <<'EOF'
:19876

reverse_proxy 127.0.0.1:9876 {
  # lock Host/Origin to the Burp listener
  header_up Host "127.0.0.1:9876"
  header_up Origin "http://127.0.0.1:9876"

  # strip client headers that trigger Burp's 403 during SSE init
  header_up -User-Agent
  header_up -Accept
  header_up -Accept-Encoding
  header_up -Connection
}
EOF
```

Démarrez le proxy et le client, et modifiez le `--sse-url` configuré en `http://127.0.0.1:19876` uniquement lorsque vous utilisez cet écouteur Caddy :<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Associer l’état du navigateur aux preuves du proxy (Playwright MCP)

Configurez Playwright MCP pour que son navigateur utilise le proxy de Burp. L’agent peut ainsi corréler l’état du DOM et de l’accessibilité rendu avec l’historique HTTP exact qui l’a produit.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Adaptez l’adresse d’écoute, redémarrez Codex et utilisez `/mcp` pour vérifier les deux intégrations. L’exemple désactive les erreurs de certificat du navigateur afin que l’interception HTTPS ne soit pas bloquée par le certificat généré localement par Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Automatisation du navigateur compatible avec le proxy (OpenBurp)

La connexion Burp MCP et le chemin du navigateur intercepté sont des flux de données distincts. Le service MCP expose les outils Burp sur `127.0.0.1:9876`, tandis qu’une instance Chromium dédiée envoie son trafic HTTP(S) via le proxy Burp sur `127.0.0.1:8080`. Les requêtes générées directement par un outil MCP peuvent donc ne pas apparaître dans **Proxy > HTTP history** ; utilisez le navigateur passant par le proxy lorsque la requête/réponse doit être observable, modifiable ou conservée comme preuve.<sup>[[2]](#references)[[9]](#references)</sup>

Un client prenant en charge SSE peut enregistrer Burp directement. Un client qui prend uniquement en charge stdio peut plutôt lancer le JAR proxy de PortSwigger. Dans les deux cas, enregistrez un second MCP de contrôle du navigateur et pointez-le vers le Chromium intégré de Burp (`BURP_CHROMIUM` est un chemin local vers un exécutable) :<sup>[[9]](#references)</sup>

```bash
# Claude Code: direct SSE plus a proxied browser
claude mcp add -s project -t sse burpsuite http://127.0.0.1:9876/
claude mcp add -s project -t stdio chrome-devtools -- chrome-devtools-mcp \
  --executablePath "$BURP_CHROMIUM" --proxy-server=http://127.0.0.1:8080 \
  --accept-insecure-certs --isolated

# Codex: SSE-to-stdio bridge plus a proxied browser
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
codex mcp add burp-browser -- npx -y @playwright/mcp@latest \
  --executable-path "$BURP_CHROMIUM" --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors --isolated
```

L’option TLS-bypass accepte les certificats générés par le proxy d’interception, tandis que `--isolated` empêche l’évaluation de réutiliser le profil de navigateur habituel de l’opérateur. L’isolation protège l’état du profil, mais ne constitue **pas un sandbox de sécurité** : le contrôleur peut toujours accéder aux sessions authentifiées ouvertes dans ce navigateur de test, et le MCP Burp peut exposer des requêtes, des réponses et des configurations sensibles.<sup>[[9]](#references)</sup>

Testez le listener SSE séparément avant de déboguer le pont client :<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Un listener opérationnel renvoie `Content-Type: text/event-stream`. Un timeout après les en-têtes est attendu, car un flux SSE reste ouvert pour recevoir de futurs événements. Si le client échoue toujours, vérifiez la route configurée pour l’extension : PortSwigger indique que l’endpoint peut être le chemin racine ou `/sse`, selon le client et la configuration de l’extension.<sup>[[9]](#references)[[7]](#references)</sup>

## Utiliser différents clients

### Codex CLI

- Configurez `~/.codex/config.toml` comme ci-dessus.
- Lancez `codex`, puis `/mcp` pour vérifier la liste des outils Burp.

### Gemini CLI

Le dépôt **burp-mcp-agents** fournit des scripts de lancement :<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (local)

Utilisez le lanceur fourni et sélectionnez un modèle local :

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Exemples de modèles locaux et besoins approximatifs en VRAM :

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Relecture et validation fondées sur des preuves

Ne laissez pas l’agent prendre une explication plausible ou une réponse intermédiaire pour une preuve. Appuyez-vous sur les requêtes/réponses Burp et sur l’état du navigateur observé indépendamment pour rendre chaque test réfutable.<sup>[[8]](#references)</sup>

1. Enregistrez une paire requête/réponse de référence et identifiez précisément le composant contrôlé par l’attaquant.
2. Pour comparer les autorisations, capturez séparément le même workflow avec les deux comptes avant de modifier les identifiants, les cookies ou les tokens.
3. Avant de rejouer une modification, consignez l’hypothèse, l’emplacement des preuves, le signal attendu et le résultat qui la réfuterait.
4. Modifiez un seul composant à la fois, conservez la paire obtenue et distinguez les observations directes des déductions.
5. Classez chaque piste comme `open`, `blocked`, `rejected` ou `confirmed` ; réexaminez-la uniquement si de nouveaux éléments modifient le mécanisme ou une condition préalable.
6. Confirmez le contrôle par l’attaquant, l’accessibilité, la reproductibilité, le contournement des contraintes, l’impact et l’état final de l’application. Une redirection ou un appel d’outil réussi ne constitue pas une preuve si le changement d’état revendiqué intervient en aval.

Conservez les détails d’exploitation dans la page consacrée à la technique pertinente. Par exemple, les pistes liées aux messages du navigateur relèvent de [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), tandis que le comportement de sélection de clé des tokens relève de [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Une fiche d’hypothèse concise évite aux agents travaillant en parallèle de répéter la même piste séduisante :<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Triage des trames WebSocket avec Burp MCP

L’extension officielle expose `get_proxy_websocket_history_regex` pour effectuer des recherches paginées en lecture seule dans l’historique WebSocket de Burp. Elle prend `regex`, `count` et `offset` ; contrairement à `send_http1_request`, elle n’envoie pas de trame WebSocket. Burp enregistre les messages dans les deux directions, même lorsque Intercept est désactivé. Filtrez donc l’historique avant de transmettre au modèle un petit ensemble de trames pertinentes.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. Déclenchez la même action utilisant WebSocket dans le navigateur configuré via le proxy Burp avec deux comptes de test authentifiés indépendamment. Conservez ensemble chaque handshake de mise à niveau et ses cookies, l’ID de connexion, la direction de la trame et les trames de réponse ; un événement serveur vers client sur la connexion du premier compte ne prouve pas que le second compte l’a reçu.
2. Lancez une recherche avec `get_proxy_websocket_history_regex` en utilisant une expression ciblée, par exemple `(?i)(subscribe|room|tenant|objectId)`, `count: 20` et `offset: 0`. Augmentez `offset` pour examiner les correspondances suivantes. Comparez l’identifiant d’objet ou de topic de la trame sortante à la réponse sur **cette même connexion**.
3. Dans **Proxy > WebSockets history**, envoyez la trame sortante candidate à Repeater. Associez-la à la connexion ouverte appropriée ou reconnectez-vous avec le handshake du second compte. Modifiez uniquement l’identifiant d’objet ou de topic, puis comparez les messages serveur et l’état de l’application aux deux références. L’outil MCP d’historique ne peut pas effectuer cette relecture ; WebSocket Repeater permet de modifier, renvoyer et reconnecter les trames.

Pour les tests propres au protocole, comme le cross-site WebSocket hijacking et l’autorisation des topics du broker, consultez [WebSocket Attacks](../pentesting-web/websocket-attacks.md). Ne considérez pas qu’un handshake accepté ou un écho côté client prouve la réussite d’un abonnement protégé.

## Validation ciblée hors bande avec Burp MCP

Burp Suite Professional expose `generate_collaborator_payload` et `get_collaborator_interactions` via l’extension MCP officielle. Combinez-les avec `get_proxy_http_history_regex` et une seule relecture via `send_http1_request` pour tester une suspicion de récupération d’URL côté serveur sans scanner toute la cible. Burp peut demander une autorisation distincte pour consulter l’historique et envoyer une requête.<sup>[[2]](#references)[[10]](#references)</sup>

1. Filtrez l’historique pour repérer une requête candidate contenant une URL, par exemple une requête contenant `url=`, `webhook` ou `callback`. Enregistrez la requête et la réponse d’origine. L’outil d’historique prend `regex`, `count` et `offset` ; parcourez les résultats par pages plutôt que de demander au modèle d’examiner toutes les entrées.<sup>[[10]](#references)</sup>
2. Générez un nouveau payload Collaborator et conservez l’**ID de payload** renvoyé. Rejouez la requête capturée vers le même hôte et le même port, en ne modifiant que l’URL candidate pour utiliser une URL HTTPS sous le domaine du payload. Pour `send_http1_request`, transmettez la requête HTTP/1.1 complète dans `content`, ainsi que `targetHostname`, `targetPort` et `usesHttps` ; les champs de destination désignent l’**application**, et non l’hôte Collaborator.<sup>[[10]](#references)</sup>
3. Interrogez périodiquement `get_collaborator_interactions` avec cet ID de payload et corrélez l’heure de l’interaction avec la relecture. Une interaction HTTP indique qu’une récupération a eu lieu, tandis qu’une résolution DNS seule prouve la résolution, mais pas l’achèvement d’une requête HTTP. Vérifiez la source de l’interaction et les en-têtes de la requête pour distinguer le trafic sortant du serveur du chargement côté navigateur, puis recommencez avec un nouveau payload afin d’écarter tout trafic sans rapport.<sup>[[10]](#references)[[11]](#references)</sup>

L’outil de requête MCP renvoie directement la réponse et ne l’ajoute pas nécessairement à **Proxy > HTTP history**. Conservez le résultat de la requête/réponse ou utilisez le navigateur configuré via le proxy ou Repeater pour obtenir une preuve enregistrée dans l’historique. Pour choisir des payloads SSRF et effectuer les tests suivants, consultez le [chapitre SSRF](../pentesting-web/ssrf-server-side-request-forgery/) plutôt que de considérer un callback hors bande comme une preuve d’impact sur le réseau interne. Pour tester le serveur MCP lui-même, consultez [MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Ensemble de prompts pour l’examen passif

Le dépôt **burp-mcp-agents** comprend des modèles de prompts pour analyser le trafic Burp en s’appuyant sur des éléments probants :<sup>[[4]](#references)</sup>

- `passive_hunter.md` : détection passive générale des vulnérabilités.
- `idor_hunter.md` : IDOR/BOLA, dérive des objets et des tenants, et incohérences d’authentification.
- `auth_flow_mapper.md` : comparaison des chemins authentifiés et non authentifiés.
- `ssrf_redirect_hunter.md` : candidats SSRF/open-redirect à partir des paramètres de récupération d’URL et des chaînes de redirection.
- `logic_flaw_hunter.md` : failles logiques en plusieurs étapes.
- `session_scope_hunter.md` : mauvaise utilisation de l’audience ou de la portée des tokens.
- `rate_limit_abuse_hunter.md` : lacunes de limitation de débit et d’anti-abus.
- `report_writer.md` : rapports centrés sur les éléments probants.

## Marquage d’attribution facultatif

Pour marquer le trafic Burp/LLM dans les logs, ajoutez une réécriture d’en-tête (proxy ou Burp Match/Replace) :<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Consignes de sécurité

- Privilégiez les **modèles locaux** lorsque le trafic contient des données sensibles.
- Ne partagez que les éléments de preuve minimum nécessaires pour un finding.
- Gardez Burp comme source de vérité ; utilisez le modèle pour **l’analyse et le reporting**, pas pour le scanning.

## Burp AI Agent (triage assisté par l’IA + outils MCP)

**Burp AI Agent** est une extension Burp qui associe des LLM locaux/Cloud à l’analyse passive/active (62 classes de vulnérabilités) et expose plus de 53 outils MCP pour permettre aux clients MCP externes d’orchestrer Burp.<sup>[[5]](#references)</sup> Points forts :

- **Triage depuis le menu contextuel** : capturez le trafic via Proxy, ouvrez **Proxy > HTTP History**, faites un clic droit sur une requête → **Extensions > Burp AI Agent > Analyze this request** pour ouvrir un chat IA associé à cette requête/réponse.
- **Backends** (sélectionnables par profil) :
  - HTTP local : **Ollama**, **LM Studio**.
  - HTTP distant : endpoint compatible avec **OpenAI** (URL de base + nom du modèle).
  - CLI Cloud : **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ou `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (connexion spécifique au fournisseur).
- **Profils d’agent** : des modèles de prompt sont installés automatiquement dans `~/.burp-ai-agent/AGENTS/` ; ajoutez-y des fichiers `*.md` pour créer des comportements personnalisés d’analyse/scanning.
- **Serveur MCP** : activez-le via **Settings > MCP Server** pour exposer les opérations Burp à n’importe quel client MCP (plus de 53 outils). Claude Desktop peut se connecter au serveur en modifiant `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ou `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Contrôles de confidentialité** : STRICT / BALANCED / OFF masquent les données sensibles des requêtes avant leur envoi aux modèles distants ; privilégiez les backends locaux lors du traitement de secrets.
- **Journalisation d’audit** : journaux JSONL avec hachage d’intégrité SHA-256 pour chaque entrée, afin d’assurer la traçabilité des actions IA/MCP et de détecter toute altération.
- **Build/chargement** : téléchargez le JAR de la release ou effectuez le build avec Java 21 :

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Mises en garde opérationnelles : les backends cloud peuvent exfiltrer des cookies de session/des PII si le mode confidentialité n’est pas activé ; l’exposition de MCP permet l’orchestration à distance de Burp. Limitez donc l’accès aux agents de confiance et surveillez le journal d’audit dont l’intégrité est vérifiée par hachage.



## References

- [1] [Intégration de Burp MCP et Codex CLI et correctif du handshake Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problème de validation stricte de l’Origin/header dans le serveur MCP de PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agents Burp MCP (workflows, launchers, pack de prompts)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Agent IA Burp](https://github.com/six2dez/burp-ai-agent)
- [6] [MCP Playwright de Microsoft](https://github.com/microsoft/playwright-mcp)
- [7] [Serveur MCP de PortSwigger Burp Suite](https://github.com/PortSwigger/mcp-server)
- [8] [Comment utiliser Codex pour la recherche de bug bounty : explorer largement, valider rigoureusement](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp : orchestration de Burp Suite pour Claude Code et Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Implémentations et paramètres des outils du serveur MCP de PortSwigger](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Vulnérabilités SSRF aveugles](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger - Historique WebSockets](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger - Travailler avec les messages WebSocket dans Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
