# Burp MCP : analyse du trafic assistée par un LLM

{{#include ../banners/hacktricks-training.md}}

## Vue d'ensemble

L'extension **MCP Server** de Burp peut exposer le trafic HTTP(S) intercepté à des clients LLM compatibles avec MCP afin qu'ils puissent **raisonner sur de vraies requêtes/réponses** pour détecter des vulnérabilités et rédiger des rapports. Gardez Burp comme source de vérité : utilisez une analyse passive ou des replays délibérés en ne modifiant qu'une variable à la fois plutôt qu'un scanning aveugle.<sup>[[8]](#references)</sup>

## Architecture

- **Burp MCP Server (BApp)** écoute par défaut sur `127.0.0.1:9876` et expose le trafic intercepté via MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** fait le lien entre stdio (côté client) et l'endpoint MCP SSE de Burp.
- **Reverse proxy local optionnel** (Caddy) normalise les headers pour les vérifications strictes du handshake MCP.
- **Clients/backends** : Codex CLI (cloud), Gemini CLI (cloud) ou Ollama (local).

## Configuration

### 1) Installer Burp MCP Server

Installez **MCP Server** depuis le Burp BApp Store et vérifiez qu'il écoute sur `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Extraire le proxy JAR

Dans l'onglet MCP Server, cliquez sur **Extract server proxy jar** et enregistrez `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Configurer un client MCP (exemple avec Codex)

Configurez le client pour utiliser le proxy JAR et l'endpoint SSE direct de Burp. Le proxy fourni est un bridge stdio-to-SSE ; il ne remplace pas le listener de Burp.<sup>[[7]](#references)</sup>
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
Exécutez ensuite Codex et listez les outils MCP :
```bash
codex
# inside Codex: /mcp
```
### 4) Corriger la validation stricte de Origin/des headers avec Caddy (si nécessaire)

Si le handshake MCP échoue en raison de vérifications strictes de `Origin` ou de headers supplémentaires, utilisez un reverse proxy local pour normaliser les headers (cela correspond au workaround pour le problème de validation stricte de Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Démarrez le proxy et le client, et modifiez la valeur configurée de `--sse-url` pour `http://127.0.0.1:19876` uniquement lors de l’utilisation de ce listener Caddy:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Associer l'état du navigateur aux preuves du proxy (Playwright MCP)

Configurez Playwright MCP afin que son navigateur utilise le proxy de Burp. Cela permet à l'agent de corréler l'état rendu du DOM/de l'accessibilité avec l'historique HTTP exact qui l'a produit.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Adaptez l'adresse du listener, redémarrez Codex et utilisez `/mcp` pour vérifier les deux intégrations. L'exemple désactive les erreurs de certificat du navigateur afin que l'interception HTTPS ne soit pas bloquée par le certificat généré localement par Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Utiliser différents clients

### Codex CLI

- Configurez `~/.codex/config.toml` comme ci-dessus.
- Exécutez `codex`, puis `/mcp` pour vérifier la liste des outils Burp.

### Gemini CLI

Le dépôt **burp-mcp-agents** fournit des assistants de lancement :<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Utilisez l’assistant de lancement fourni et sélectionnez un modèle local :
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Exemples de modèles locaux et besoins approximatifs en VRAM :

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Relecture et validation fondées sur les preuves

Ne laissez pas l'agent considérer une explication plausible ou une réponse intermédiaire comme une preuve. Utilisez les requêtes/réponses Burp et l'état du navigateur observé indépendamment afin de rendre chaque test falsifiable.<sup>[[8]](#references)</sup>

1. Enregistrez une paire requête/réponse de référence et identifiez le composant contrôlé exactement par l'attaquant.
2. Pour les comparaisons d'autorisation, capturez indépendamment le même workflow avec les deux comptes avant de modifier les identifiants, les cookies ou les tokens.
3. Avant de rejouer une mutation, consignez l'hypothèse, l'emplacement de la preuve, le signal attendu et le résultat qui l'infirmerait.
4. Modifiez un seul composant à la fois, conservez la paire obtenue et distinguez les observations directes des inférences.
5. Suivez chaque candidat avec l'état `open`, `blocked`, `rejected` ou `confirmed` ; ne le réexaminez que lorsque de nouvelles preuves modifient le mécanisme ou un prérequis.
6. Confirmez le contrôle par l'attaquant, l'accessibilité, la répétabilité, le contournement des contraintes, l'impact et l'état final de l'application. Une redirection ou un appel d'outil réussi ne constitue pas une preuve si le changement d'état revendiqué est effectué en aval.

Conservez les détails de l'exploitation dans la page de la technique concernée. Par exemple, les candidats liés aux messages du navigateur appartiennent à [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), tandis que le comportement de sélection de clé des tokens appartient à [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Un enregistrement compact des hypothèses empêche les agents parallèles de répéter la même piste séduisante :<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Pack de prompts pour la revue passive

Le repo **burp-mcp-agents** inclut des modèles de prompts pour l’analyse fondée sur des preuves du trafic Burp :<sup>[[4]](#references)</sup>

- `passive_hunter.md` : détection passive étendue de vulnérabilités.
- `idor_hunter.md` : dérive IDOR/BOLA/objet/tenant et incohérences d’authentification.
- `auth_flow_mapper.md` : comparaison des chemins authentifiés et non authentifiés.
- `ssrf_redirect_hunter.md` : candidats SSRF/open-redirect à partir des paramètres de récupération d’URL et des chaînes de redirection.
- `logic_flaw_hunter.md` : failles logiques multi-étapes.
- `session_scope_hunter.md` : utilisation abusive de l’audience ou du scope des tokens.
- `rate_limit_abuse_hunter.md` : failles de throttling et d’abus.
- `report_writer.md` : rédaction de rapports axée sur les preuves.

## Marquage d’attribution facultatif

Pour marquer le trafic Burp/LLM dans les logs, ajoutez une réécriture d’en-tête (proxy ou Burp Match/Replace) :<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Notes de sécurité

- Privilégiez les **modèles locaux** lorsque le trafic contient des données sensibles.
- Ne partagez que les éléments de preuve minimum nécessaires pour un finding.
- Gardez Burp comme source de vérité ; utilisez le modèle pour l'**analyse et le reporting**, pas pour le scanning.

## Burp AI Agent (triage assisté par l'IA + outils MCP)

**Burp AI Agent** est une extension Burp qui associe des LLM locaux/cloud à une analyse passive/active (62 classes de vulnérabilités) et expose plus de 53 outils MCP afin que des clients MCP externes puissent orchestrer Burp.<sup>[[5]](#references)</sup> Points forts :

- **Triage via le menu contextuel** : capturez le trafic via Proxy, ouvrez **Proxy > HTTP History**, cliquez avec le bouton droit sur une requête → **Extensions > Burp AI Agent > Analyze this request** pour ouvrir un chat IA associé à cette requête/réponse.
- **Backends** (sélectionnables par profile) :
- HTTP local : **Ollama**, **LM Studio**.
- HTTP distant : endpoint **compatible OpenAI** (URL de base + nom du modèle).
- CLIs cloud : **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ou `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (login spécifique au provider).
- **Agent profiles** : les templates de prompts sont automatiquement installés sous `~/.burp-ai-agent/AGENTS/` ; déposez-y des fichiers `*.md` supplémentaires pour ajouter des comportements d'analyse/scanning personnalisés.
- **Serveur MCP** : activez-le via **Settings > MCP Server** pour exposer les opérations Burp à n'importe quel client MCP (plus de 53 outils). Claude Desktop peut être configuré pour utiliser le serveur en modifiant `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ou `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Contrôles de confidentialité** : STRICT / BALANCED / OFF masquent les données sensibles des requêtes avant leur envoi aux modèles distants ; privilégiez les backends locaux lors du traitement de secrets.
- **Audit logging** : logs JSONL avec un hachage d'intégrité SHA-256 pour chaque entrée, afin d'assurer une traçabilité inviolable des actions IA/MCP.
- **Build/load** : téléchargez le JAR de release ou compilez avec Java 21 :
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Précautions opérationnelles : les backends cloud peuvent exfiltrer les session cookies/PII à moins que le privacy mode soit appliqué ; l’exposition de MCP permet l’orchestration à distance de Burp. Restreignez donc l’accès aux agents de confiance et surveillez l’intégrité du journal d’audit haché.

## References

- [1] [Intégration de Burp MCP avec Codex CLI et correction de la négociation Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problème de validation stricte de l’en-tête Origin du serveur MCP de PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agents Burp MCP (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Agent IA Burp](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [Serveur MCP de PortSwigger Burp Suite](https://github.com/PortSwigger/mcp-server)
- [8] [Comment utiliser Codex pour la recherche Bug Bounty : explorer largement, valider rigoureusement](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
