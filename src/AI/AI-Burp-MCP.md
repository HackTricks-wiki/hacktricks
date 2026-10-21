# Burp MCP : revue du trafic assistée par LLM

{{#include ../banners/hacktricks-training.md}}

## Présentation

L’extension **MCP Server** de Burp peut exposer le trafic HTTP(S) intercepté aux clients LLM compatibles avec MCP afin qu’ils puissent **raisonner sur des requêtes/réponses réelles** pour détecter des vulnérabilités et rédiger des rapports. Burp reste la source de vérité : privilégiez l’analyse passive ou les relectures délibérées avec une seule variable plutôt que le scan à l’aveugle.<sup>[[8]](#references)</sup>

## Architecture

- **Burp MCP Server (BApp)** écoute par défaut sur `127.0.0.1:9876` et expose le trafic intercepté via MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** fait le lien entre stdio (côté client) et le point de terminaison MCP SSE de Burp.
- **Reverse proxy local facultatif** (Caddy) normalise les en-têtes pour répondre aux vérifications strictes de la négociation MCP.
- **Clients/backends** : Codex CLI (cloud), Gemini CLI (cloud) ou Ollama (local).

## Configuration

### 1) Installer Burp MCP Server

Installez **MCP Server** depuis la boutique BApp de Burp et vérifiez qu’il écoute sur `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Extraire le proxy JAR

Dans l’onglet MCP Server, cliquez sur **Extract server proxy jar** et enregistrez `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Configurer un client MCP (exemple avec Codex)

Dirigez le client vers le proxy JAR et le point de terminaison SSE direct de Burp. Le proxy fourni fait le lien entre stdio et SSE ; il ne remplace pas le listener de Burp.<sup>[[7]](#references)</sup>

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

Lancez ensuite Codex et listez les outils MCP :

```bash
codex
# inside Codex: /mcp
```

### 4) Corriger la validation stricte de l’Origin/des en-têtes avec Caddy (si nécessaire)

Si le handshake MCP échoue en raison de vérifications strictes de l’`Origin` ou d’en-têtes supplémentaires, utilisez un proxy inverse local pour normaliser les en-têtes (cela reprend le contournement du problème de validation stricte de Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

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

Démarrez le proxy et le client, et définissez `--sse-url` sur `http://127.0.0.1:19876` uniquement lorsque vous utilisez ce listener Caddy :<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Associer l’état du navigateur aux preuves du proxy (Playwright MCP)

Configurez Playwright MCP pour que son navigateur utilise le proxy de Burp. L’agent peut ainsi mettre en corrélation l’état du DOM et de l’accessibilité rendu avec l’historique HTTP exact qui l’a produit.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Adaptez l’adresse du listener, redémarrez Codex et utilisez `/mcp` pour vérifier les deux intégrations. L’exemple désactive les erreurs de certificat du navigateur afin que l’interception HTTPS ne soit pas bloquée par le certificat généré localement par Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Automatisation du navigateur compatible avec le proxy (OpenBurp)

La connexion Burp MCP et le trafic du navigateur intercepté sont deux flux de données distincts. Le service MCP expose les outils Burp sur `127.0.0.1:9876`, tandis qu’une instance Chromium dédiée achemine son trafic HTTP(S) via le proxy Burp sur `127.0.0.1:8080`. Les requêtes générées directement par un outil MCP peuvent donc ne pas apparaître dans **Proxy > HTTP history** ; utilisez le navigateur configuré avec le proxy lorsque les requêtes/réponses doivent être observables, modifiables ou conservées comme preuves.<sup>[[2]](#references)[[9]](#references)</sup>

Un client prenant en charge SSE peut se connecter directement à Burp. Un client limité à stdio peut plutôt lancer le JAR proxy de PortSwigger. Dans les deux cas, enregistrez un second MCP de contrôle du navigateur et indiquez-lui le chemin vers Chromium intégré à Burp (`BURP_CHROMIUM` est un chemin d’exécutable local) :<sup>[[9]](#references)</sup>

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

L’option TLS-bypass accepte les certificats générés par le proxy d’interception, tandis que `--isolated` empêche l’évaluation de réutiliser le profil de navigateur habituel de l’opérateur. L’isolation protège l’état du profil, mais ne constitue **pas un bac à sable de sécurité** : le contrôleur peut toujours accéder aux sessions authentifiées ouvertes dans ce navigateur de test, et le Burp MCP peut exposer des requêtes, des réponses et une configuration sensibles.<sup>[[9]](#references)</sup>

Testez le listener SSE indépendamment avant de déboguer le bridge client :<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Un listener fonctionnel renvoie `Content-Type: text/event-stream`. Un délai d’attente après les en-têtes est attendu, car un flux SSE reste ouvert en attente de futurs événements. Si le client échoue toujours, vérifiez la route configurée pour l’extension : PortSwigger indique que l’endpoint peut être le chemin racine ou `/sse`, selon le client et la configuration de l’extension.<sup>[[9]](#references)[[7]](#references)</sup>

## Utiliser différents clients

### Codex CLI

- Configurez `~/.codex/config.toml` comme indiqué ci-dessus.
- Lancez `codex`, puis `/mcp` pour vérifier la liste des outils Burp.

### Gemini CLI

Le dépôt **burp-mcp-agents** fournit des assistants de lancement :<sup>[[4]](#references)</sup>

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

## Rejeu et validation fondés sur les preuves

Ne laissez pas l’agent considérer une explication plausible ou une réponse intermédiaire comme une preuve. Utilisez les requêtes/réponses Burp et l’état du navigateur observé indépendamment pour rendre chaque test falsifiable.<sup>[[8]](#references)</sup>

1. Enregistrez une paire requête/réponse de référence et identifiez précisément le composant contrôlé par l’attaquant.
2. Pour les comparaisons d’autorisation, capturez le même workflow indépendamment avec les deux comptes avant de modifier les identifiants, les cookies ou les tokens.
3. Avant de rejouer une modification, consignez l’hypothèse, l’emplacement des preuves, le signal attendu et le résultat qui la réfuterait.
4. Modifiez un seul composant à la fois, conservez la paire obtenue et distinguez les observations directes des déductions.
5. Attribuez à chaque piste l’un des états suivants : `open`, `blocked`, `rejected` ou `confirmed` ; réexaminez-la uniquement si de nouveaux éléments modifient le mécanisme ou une condition préalable.
6. Confirmez le contrôle par l’attaquant, l’accessibilité, la répétabilité, le contournement des restrictions, l’impact et l’état final de l’application. Une redirection ou un appel d’outil réussi ne constitue pas une preuve si le changement d’état allégué se produit en aval.

Conservez les détails d’exploitation dans la page consacrée à la technique concernée. Par exemple, les pistes liées aux messages du navigateur relèvent de [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), tandis que le comportement de sélection de clé des tokens relève de [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Un enregistrement concis des hypothèses évite aux agents travaillant en parallèle de répéter la même piste séduisante :<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Validation ciblée hors bande avec Burp MCP

Burp Suite Professional expose `generate_collaborator_payload` et `get_collaborator_interactions` via l’extension MCP officielle. Combinez-les avec `get_proxy_http_history_regex` et un unique rejeu avec `send_http1_request` pour tester une suspicion de récupération d’URL côté serveur sans scanner toute la cible. Burp peut nécessiter une approbation distincte pour lire l’historique et envoyer une requête.<sup>[[2]](#references)[[10]](#references)</sup>

1. Filtrez l’historique pour trouver une requête candidate contenant une URL, par exemple avec `url=`, `webhook` ou `callback`. Enregistrez la requête et la réponse d’origine. L’outil d’historique utilise `regex`, `count` et `offset` ; parcourez les résultats par pages plutôt que de demander au modèle d’examiner chaque entrée.<sup>[[10]](#references)</sup>
2. Générez un nouveau payload Collaborator et conservez son **payload ID**. Rejouez la requête capturée vers le même hôte et le même port, en ne modifiant que l’URL candidate pour utiliser une URL HTTPS sur le domaine de ce payload. Pour `send_http1_request`, transmettez la requête HTTP/1.1 complète dans `content`, ainsi que `targetHostname`, `targetPort` et `usesHttps` ; les champs de destination désignent l’**application**, et non l’hôte Collaborator.<sup>[[10]](#references)</sup>
3. Interrogez `get_collaborator_interactions` avec cet ID de payload et faites correspondre l’heure de l’interaction avec celle du rejeu. Une interaction HTTP indique qu’une récupération a probablement eu lieu, tandis qu’une interaction DNS seule montre une résolution, mais pas qu’une requête HTTP a abouti. Examinez la source de l’interaction et les en-têtes de la requête pour distinguer une sortie réseau du serveur d’un chargement côté navigateur, puis recommencez avec un nouveau payload afin d’écarter tout trafic sans rapport.<sup>[[10]](#references)[[11]](#references)</sup>

L’outil de requête MCP renvoie directement la réponse et ne remplit pas nécessairement **Proxy > HTTP history**. Conservez le résultat de la requête et de la réponse, ou utilisez le navigateur configuré via le proxy ou Repeater pour obtenir une preuve dans l’historique. Pour le choix des payloads SSRF et les tests complémentaires, consultez le [chapitre SSRF](../pentesting-web/ssrf-server-side-request-forgery/) plutôt que de considérer un callback hors bande comme une preuve d’impact sur le réseau interne. Pour tester le serveur MCP lui-même, consultez [le test du serveur MCP](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Ensemble de prompts pour une revue passive

Le dépôt **burp-mcp-agents** comprend des modèles de prompts pour l’analyse du trafic Burp fondée sur des preuves :<sup>[[4]](#references)</sup>

- `passive_hunter.md` : détection passive générale de vulnérabilités.
- `idor_hunter.md` : IDOR/BOLA, dérive des objets/tenants et incohérences d’authentification.
- `auth_flow_mapper.md` : comparaison des parcours authentifiés et non authentifiés.
- `ssrf_redirect_hunter.md` : candidats SSRF et open redirect issus des paramètres de récupération d’URL et des chaînes de redirection.
- `logic_flaw_hunter.md` : failles logiques en plusieurs étapes.
- `session_scope_hunter.md` : utilisation abusive de l’audience ou de la portée des tokens.
- `rate_limit_abuse_hunter.md` : lacunes de limitation du débit et d’anti-abus.
- `report_writer.md` : rédaction de rapports axés sur les preuves.

## Marquage d’attribution facultatif

Pour marquer le trafic Burp/LLM dans les logs, ajoutez une réécriture d’en-tête (proxy ou Burp Match/Replace) :<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Consignes de sécurité

- Privilégiez les **modèles locaux** lorsque le trafic contient des données sensibles.
- Ne partagez que les éléments de preuve minimum nécessaires pour un résultat.
- Gardez Burp comme source faisant autorité ; utilisez le modèle pour **l’analyse et la rédaction de rapports**, pas pour le scan.

## Burp AI Agent (triage assisté par IA + outils MCP)

**Burp AI Agent** est une extension Burp qui associe des LLM locaux/cloud à l’analyse passive/active (62 classes de vulnérabilités) et expose plus de 53 outils MCP pour permettre aux clients MCP externes d’orchestrer Burp.<sup>[[5]](#references)</sup> Points forts :

- **Triage via le menu contextuel** : capturez le trafic via Proxy, ouvrez **Proxy > HTTP History**, faites un clic droit sur une requête → **Extensions > Burp AI Agent > Analyze this request** pour lancer une conversation IA associée à cette requête/réponse.
- **Backends** (sélectionnables pour chaque profil) :
  - HTTP local : **Ollama**, **LM Studio**.
  - HTTP distant : endpoint compatible **OpenAI** (URL de base + nom du modèle).
  - CLIs cloud : **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ou `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (connexion propre au fournisseur).
- **Profils d’agent** : les modèles de prompt sont installés automatiquement dans `~/.burp-ai-agent/AGENTS/` ; déposez-y des fichiers `*.md` supplémentaires pour ajouter des comportements personnalisés d’analyse/scan.
- **Serveur MCP** : activez-le via **Settings > MCP Server** pour exposer les opérations Burp à n’importe quel client MCP (plus de 53 outils). Pour connecter Claude Desktop au serveur, modifiez `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ou `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Contrôles de confidentialité** : STRICT / BALANCED / OFF masquent les données sensibles des requêtes avant leur envoi aux modèles distants ; privilégiez les backends locaux lors du traitement de secrets.
- **Journalisation d’audit** : journaux JSONL avec hachage d’intégrité SHA-256 pour chaque entrée, assurant une traçabilité qui révèle toute falsification des actions IA/MCP.
- **Compilation/chargement** : téléchargez le JAR de la version publiée ou compilez avec Java 21 :

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Précautions opérationnelles : les backends cloud peuvent exfiltrer des cookies de session/PII, sauf si le mode de confidentialité est activé ; l’exposition de MCP permet l’orchestration à distance de Burp. Limitez donc l’accès aux agents de confiance et surveillez le journal d’audit dont l’intégrité est protégée par hachage.



## References

- [1] [Intégration de Burp MCP et Codex CLI, et correctif du handshake Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problème de validation stricte de l’en-tête Origin du serveur MCP de PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agents Burp MCP (workflows, lanceurs, pack de prompts)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Agent IA Burp](https://github.com/six2dez/burp-ai-agent)
- [6] [Playwright MCP de Microsoft](https://github.com/microsoft/playwright-mcp)
- [7] [Serveur MCP de PortSwigger Burp Suite](https://github.com/PortSwigger/mcp-server)
- [8] [Comment utiliser Codex pour la recherche de bug bounty : explorer largement, valider rigoureusement](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp : orchestration de Burp Suite pour Claude Code et Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Implémentations des outils et paramètres du serveur MCP de PortSwigger](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Vulnérabilités SSRF aveugles](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
