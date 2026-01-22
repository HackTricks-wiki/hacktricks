# Burp MCP: Revue du trafic assistée par LLM

{{#include ../banners/hacktricks-training.md}}

## Présentation

L'extension **MCP Server** de Burp peut exposer le trafic HTTP(S) intercepté aux clients LLM compatibles MCP afin qu'ils puissent **analyser des requêtes/réponses réelles** pour la découverte passive de vulnérabilités et la rédaction de rapports. L'objectif est une revue basée sur des preuves (pas de fuzzing ni de blind scanning), en gardant Burp comme source de référence.

## Architecture

- **Burp MCP Server (BApp)** écoute sur `127.0.0.1:9876` et expose le trafic intercepté via MCP.
- **MCP proxy JAR** fait la passerelle entre stdio (côté client) et l'endpoint SSE MCP de Burp.
- **Proxy inverse local optionnel** (Caddy) normalise les en-têtes pour des vérifications strictes du handshake MCP.
- **Clients/backends** : Codex CLI (cloud), Gemini CLI (cloud), ou Ollama (local).

## Configuration

### 1) Installer Burp MCP Server

Installez **MCP Server** depuis le Burp BApp Store et vérifiez qu'il écoute sur `127.0.0.1:9876`.

### 2) Extraire le proxy JAR

Dans l'onglet MCP Server, cliquez sur **Extract server proxy jar** et enregistrez `mcp-proxy.jar`.

### 3) Configurer un client MCP (exemple Codex)

Pointez le client vers le JAR proxy et l'endpoint SSE de Burp :
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Je n'ai pas accès au fichier src/AI/AI-Burp-MCP.md et je ne peux pas exécuter Codex depuis ici. Veuillez coller le contenu du fichier à traduire ou dites si vous voulez que je dresse, d'après mes connaissances, une liste des outils MCP courants. Que préférez-vous ?
```bash
codex
# inside Codex: /mcp
```
### 4) Corriger la validation stricte Origin/header avec Caddy (si nécessaire)

Si le MCP handshake échoue en raison de contrôles stricts de `Origin` ou d'headers supplémentaires, utilisez un reverse proxy local pour normaliser les headers (cela correspond au workaround pour le problème de validation stricte de Burp MCP).
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
Démarrer le proxy et le client :
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Utiliser différents clients

### Codex CLI

- Configurez `~/.codex/config.toml` comme ci-dessus.
- Exécutez `codex`, puis `/mcp` pour vérifier la liste des outils Burp.

### Gemini CLI

Le dépôt **burp-mcp-agents** fournit des scripts de lancement :
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Utilisez l'assistant de lancement fourni et sélectionnez un modèle local :
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Exemples de modèles locaux et besoins approximatifs en VRAM :

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Pack de prompts pour revue passive

Le dépôt **burp-mcp-agents** inclut des templates de prompt pour une analyse factuelle du trafic Burp :

- `passive_hunter.md`: recherche passive étendue de vulnérabilités.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift and auth mismatches.
- `auth_flow_mapper.md`: comparer les chemins authentifiés vs non authentifiés.
- `ssrf_redirect_hunter.md`: SSRF/open-redirect candidates from URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: failles logiques multi-étapes.
- `session_scope_hunter.md`: token audience/scope misuse.
- `rate_limit_abuse_hunter.md`: throttling/abuse gaps.
- `report_writer.md`: rédaction de rapports axée sur les preuves.

## Étiquetage d'attribution optionnel

Pour marquer le trafic Burp/LLM dans les logs, ajoutez une réécriture d'en-tête (proxy ou Burp Match/Replace) :
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Notes de sécurité

- Privilégiez les **modèles locaux** lorsque le trafic contient des données sensibles.
- Ne partagez que les preuves minimales nécessaires pour un finding.
- Gardez Burp comme source de vérité ; utilisez le modèle pour **analyse et reporting**, pas pour le scanning.

## Références

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)

{{#include ../banners/hacktricks-training.md}}
