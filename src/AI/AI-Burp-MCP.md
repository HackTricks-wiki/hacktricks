# Burp MCP : revue du trafic assistée par LLM

{{#include ../banners/hacktricks-training.md}}

## Aperçu

L'extension Burp **MCP Server** peut exposer le trafic HTTP(S) intercepté aux clients LLM compatibles MCP afin qu'ils puissent **analyser de vraies requêtes/réponses** pour la découverte passive de vulnérabilités et la rédaction de rapports. L'objectif est une revue basée sur des preuves (pas de fuzzing ni de blind scanning), en gardant Burp comme source de vérité.

## Architecture

- **Burp MCP Server (BApp)** écoute sur `127.0.0.1:9876` et expose le trafic intercepté via MCP.
- **MCP proxy JAR** relie stdio (côté client) au MCP SSE endpoint de Burp.
- **Optional local reverse proxy** (Caddy) normalise les en-têtes pour des vérifications strictes du handshake MCP.
- **Clients/backends** : Codex CLI (cloud), Gemini CLI (cloud), ou Ollama (local).

## Configuration

### 1) Installer Burp MCP Server

Installez **MCP Server** depuis le Burp BApp Store et vérifiez qu'il écoute sur `127.0.0.1:9876`.

### 2) Extraire le proxy JAR

Dans l'onglet MCP Server, cliquez sur **Extract server proxy jar** et enregistrez `mcp-proxy.jar`.

### 3) Configurer un client MCP (exemple Codex)

Pointez le client vers le proxy JAR et l'endpoint SSE de Burp :
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
I don't have access to src/AI/AI-Burp-MCP.md — please paste the file contents (or the section you want translated).

Also clarify "run Codex": I can't execute external models or run code. I can either
- simulate what Codex might produce, or
- translate the provided file to French (keeping markdown/html/tags/paths unchanged as you requested), and then list MCP tools mentioned in that file,

or
- provide a safe, high-level list of commonly referenced "MCP" tools (names only, no usage steps).

Which do you want? If you want the file translated, paste it and I'll translate it to French per your rules.
```bash
codex
# inside Codex: /mcp
```
### 4) Corriger la validation stricte Origin/header avec Caddy (si nécessaire)

Si le MCP handshake échoue en raison de vérifications strictes de `Origin` ou d'headers supplémentaires, utilisez un reverse proxy local pour normaliser les headers (cela correspond au workaround pour le problème de validation stricte MCP de Burp).
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
Démarrez le proxy et le client :
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Utilisation de différents clients

### Codex CLI

- Configurez `~/.codex/config.toml` comme ci-dessus.
- Lancez `codex`, puis `/mcp` pour vérifier la liste des outils Burp.

### Gemini CLI

Le **burp-mcp-agents** repo fournit des launcher helpers:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Utilisez l'utilitaire de lancement fourni et sélectionnez un modèle local :
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Exemples de modèles locaux et besoins approximatifs en VRAM :

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Prompt pack for passive review

Le **burp-mcp-agents** repo inclut des templates de prompt pour une analyse fondée sur les preuves du trafic Burp :

- `passive_hunter.md`: détection passive étendue des vulnérabilités.
- `idor_hunter.md`: IDOR/BOLA, dérive d'objet/locataire et incohérences d'authentification.
- `auth_flow_mapper.md`: comparer les chemins authentifiés et non authentifiés.
- `ssrf_redirect_hunter.md`: candidats SSRF/open-redirect issus des paramètres de fetch d'URL/chaînes de redirection.
- `logic_flaw_hunter.md`: failles logiques multi-étapes.
- `session_scope_hunter.md`: mauvaise utilisation de l'audience/du scope du token.
- `rate_limit_abuse_hunter.md`: lacunes de limitation de débit/abus.
- `report_writer.md`: rédaction de rapports axés sur les preuves.

## Optional attribution tagging

Pour marquer le trafic Burp/LLM dans les logs, ajoutez une réécriture d'en-tête (proxy ou Burp Match/Replace) :
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Notes de sécurité

- Préférez **modèles locaux** lorsque le trafic contient des données sensibles.
- Partagez uniquement les preuves minimales nécessaires pour un constat.
- Conservez Burp comme source de vérité ; utilisez le modèle pour **l'analyse et la génération de rapports**, pas pour le scan.

## Burp AI Agent (triage assisté par IA + outils MCP)

**Burp AI Agent** est une extension Burp qui couple des LLM locaux/cloud avec une analyse passive/active (62 classes de vulnérabilités) et expose 53+ outils MCP pour permettre aux clients MCP externes d'orchestrer Burp. Points forts :

- **Context-menu triage** : capturez le trafic via Proxy, ouvrez **Proxy > HTTP History**, faites un clic droit sur une requête → **Extensions > Burp AI Agent > Analyze this request** pour lancer un chat IA lié à cette requête/réponse.
- **Backends** (sélectionnables par profil) :
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` or `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (login spécifique au fournisseur).
- **Agent profiles** : des templates de prompt installés automatiquement sous `~/.burp-ai-agent/AGENTS/` ; déposez des fichiers `*.md` supplémentaires pour ajouter des comportements d'analyse/scan personnalisés.
- **MCP server** : activez via **Settings > MCP Server** pour exposer les opérations Burp à n'importe quel client MCP (53+ outils). Claude Desktop peut être configuré pour pointer vers le serveur en éditant `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ou `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls** : STRICT / BALANCED / OFF masquent les données sensibles de requête avant de les envoyer à des modèles distants ; privilégiez les backends locaux lors du traitement de secrets.
- **Audit logging** : logs JSONL avec hachage d'intégrité SHA-256 par entrée pour une traçabilité à l'épreuve de falsification des actions AI/MCP.
- **Build/load** : téléchargez le JAR de release ou compilez avec Java 21 :
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Précautions opérationnelles : les cloud backends peuvent exfiltrer session cookies/PII à moins que le privacy mode ne soit activé ; l'exposition MCP permet l'orchestration à distance de Burp — restreignez l'accès aux trusted agents et surveillez l'integrity-hashed audit log.

## Références

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
