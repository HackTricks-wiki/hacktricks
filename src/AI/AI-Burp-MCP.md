# Burp MCP : revue du trafic assistée par LLM

{{#include ../banners/hacktricks-training.md}}

## Vue d'ensemble

L'extension **MCP Server** de Burp peut exposer le trafic HTTP(S) intercepté aux clients LLM compatibles avec MCP afin qu'ils puissent **raisonner sur de vraies requêtes/réponses** pour la détection passive de vulnérabilités et la rédaction de rapports. L'objectif est une revue fondée sur des preuves (sans fuzzing ni scanning aveugle), tout en conservant Burp comme source de vérité.

## Architecture

- **Burp MCP Server (BApp)** écoute sur `127.0.0.1:9876` et expose le trafic intercepté via MCP.<sup>[[1]](#references)[[2]](#references)</sup>
- **MCP proxy JAR** fait le pont entre stdio (côté client) et le endpoint MCP SSE de Burp.
- **Reverse proxy local optionnel** (Caddy) normalise les headers pour les vérifications strictes du handshake MCP.
- **Clients/backends** : Codex CLI (cloud), Gemini CLI (cloud) ou Ollama (local).

## Configuration

### 1) Installer Burp MCP Server

Installez **MCP Server** depuis le Burp BApp Store et vérifiez qu'il écoute sur `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Extraire le proxy JAR

Dans l'onglet MCP Server, cliquez sur **Extract server proxy jar** et enregistrez `mcp-proxy.jar`.

### 3) Configurer un client MCP (exemple avec Codex)

Pointez le client vers le proxy JAR et le endpoint SSE de Burp :
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Ensuite, exécutez Codex et répertoriez les outils MCP :
```bash
codex
# inside Codex: /mcp
```
### 4) Corriger la validation stricte de Origin/des en-têtes avec Caddy (si nécessaire)

Si le handshake MCP échoue en raison de vérifications strictes de `Origin` ou d’en-têtes supplémentaires, utilisez un reverse proxy local pour normaliser les en-têtes (cela correspond au workaround pour le problème de validation stricte de Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
## Utiliser différents clients

### Codex CLI

- Configurez `~/.codex/config.toml` comme indiqué ci-dessus.
- Exécutez `codex`, puis `/mcp` pour vérifier la liste des outils Burp.

### Gemini CLI

Le repo **burp-mcp-agents** fournit des helpers de lancement :<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

Utilisez l’assistant de lancement fourni et sélectionnez un modèle local :
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Exemples de modèles locaux et besoins approximatifs en VRAM :

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Prompt pack pour une revue passive

Le repo **burp-mcp-agents** inclut des modèles de prompts pour l'analyse fondée sur les preuves du trafic Burp :<sup>[[4]](#references)</sup>

- `passive_hunter.md` : détection passive étendue de vulnérabilités.
- `idor_hunter.md` : IDOR/BOLA, dérives d'objets/tenants et incohérences d'auth.
- `auth_flow_mapper.md` : comparaison des chemins authentifiés et non authentifiés.
- `ssrf_redirect_hunter.md` : candidats SSRF/open-redirect à partir des paramètres de récupération d'URL et des chaînes de redirection.
- `logic_flaw_hunter.md` : failles logiques multi-étapes.
- `session_scope_hunter.md` : utilisation abusive de l'audience/du scope des tokens.
- `rate_limit_abuse_hunter.md` : lacunes de throttling/abus.
- `report_writer.md` : reporting axé sur les preuves.

## Marquage d'attribution facultatif

Pour marquer le trafic Burp/LLM dans les logs, ajoutez une réécriture d'en-tête (proxy ou Burp Match/Replace) :<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Notes de sécurité

- Privilégiez les **modèles locaux** lorsque le trafic contient des données sensibles.
- Ne partagez que les preuves minimales nécessaires pour un finding.
- Gardez Burp comme source de vérité ; utilisez le modèle pour **l’analyse et le reporting**, pas pour le scanning.

## Burp AI Agent (triage assisté par AI + outils MCP)

**Burp AI Agent** est une extension Burp qui associe des LLM locaux/cloud à une analyse passive/active (62 classes de vulnérabilités) et expose plus de 53 outils MCP afin que des clients MCP externes puissent orchestrer Burp.<sup>[[5]](#references)</sup> Points forts :

- **Triage depuis le menu contextuel** : capturez le trafic via Proxy, ouvrez **Proxy > HTTP History**, cliquez avec le bouton droit sur une requête → **Extensions > Burp AI Agent > Analyze this request** pour lancer un chat AI associé à cette requête/réponse.
- **Backends** (sélectionnables par profil) :
- Local HTTP : **Ollama**, **LM Studio**.
- Remote HTTP : endpoint compatible **OpenAI** (base URL + nom du modèle).
- Cloud CLIs : **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` ou `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (login spécifique au provider).
- **Profils d’agent** : les modèles de prompt sont installés automatiquement dans `~/.burp-ai-agent/AGENTS/` ; déposez-y des fichiers `*.md` supplémentaires pour ajouter des comportements personnalisés d’analyse/scanning.
- **Serveur MCP** : activez-le via **Settings > MCP Server** pour exposer les opérations Burp à n’importe quel client MCP (plus de 53 outils). Claude Desktop peut être configuré pour utiliser le serveur en modifiant `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) ou `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Contrôles de confidentialité** : STRICT / BALANCED / OFF masquent les données sensibles des requêtes avant leur envoi aux modèles distants ; privilégiez les backends locaux lors du traitement de secrets.
- **Journalisation d’audit** : journaux JSONL avec hachage d’intégrité SHA-256 pour chaque entrée, afin d’assurer une traçabilité infalsifiable des actions AI/MCP.
- **Build/load** : téléchargez le JAR de release ou construisez avec Java 21 :
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Précautions opérationnelles : les backends cloud peuvent exfiltrer des cookies de session/des données personnelles (PII) sauf si le mode de confidentialité est appliqué ; l’exposition de MCP permet l’orchestration à distance de Burp. Restreignez donc l’accès aux agents de confiance et surveillez l’intégrité du journal d’audit haché.

## Références

- [1] [Intégration de Burp MCP + Codex CLI et correction de la négociation Caddy](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problème de validation stricte de l’en-tête/Origin du serveur MCP de PortSwigger](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Agents Burp MCP (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
