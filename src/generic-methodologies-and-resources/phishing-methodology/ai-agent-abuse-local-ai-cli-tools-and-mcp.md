# AI Agent Abuse: Local AI CLI Tools & MCP (Claude/Gemini/Warp)

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Local AI command-line interfaces (AI CLIs) such as Claude Code, Gemini CLI, Warp and similar tools often ship with powerful built‑ins: filesystem read/write, shell execution and outbound network access. Many act as MCP clients (Model Context Protocol), letting the model call external tools over STDIO or HTTP. Because the LLM plans tool-chains non‑deterministically, identical prompts can lead to different process, file and network behaviours across runs and hosts.

Principais mecanismos observados em AI CLIs comuns:
- Tipicamente implementados em Node/TypeScript com um wrapper leve que inicia o modelo e expõe ferramentas.
- Múltiplos modos: interactive chat, plan/execute, e single‑prompt run.
- Suporte a MCP client com transportes STDIO e HTTP, permitindo extensão de capacidade tanto local quanto remota.

Abuse impact: A single prompt can inventory and exfiltrate credentials, modify local files, and silently extend capability by connecting to remote MCP servers (visibility gap if those servers are third‑party).

---

## Adversary Playbook – Prompt‑Driven Secrets Inventory

Task the agent to quickly triage and stage credentials/secrets for exfiltration while staying quiet:

- Scope: recursively enumerate under $HOME and application/wallet dirs; avoid noisy/pseudo paths (`/proc`, `/sys`, `/dev`).
- Performance/stealth: cap recursion depth; avoid `sudo`/priv‑escalation; summarise results.
- Targets: `~/.ssh`, `~/.aws`, cloud CLI creds, `.env`, `*.key`, `id_rsa`, `keystore.json`, browser storage (LocalStorage/IndexedDB profiles), crypto‑wallet data.
- Output: write a concise list to `/tmp/inventory.txt`; if the file exists, create a timestamped backup before overwrite.

Example operator prompt to an AI CLI:
```
You can read/write local files and run shell commands.
Recursively scan my $HOME and common app/wallet dirs to find potential secrets.
Skip /proc, /sys, /dev; do not use sudo; limit recursion depth to 3.
Match files/dirs like: id_rsa, *.key, keystore.json, .env, ~/.ssh, ~/.aws,
Chrome/Firefox/Brave profile storage (LocalStorage/IndexedDB) and any cloud creds.
Summarize full paths you find into /tmp/inventory.txt.
If /tmp/inventory.txt already exists, back it up to /tmp/inventory.txt.bak-<epoch> first.
Return a short summary only; no file contents.
```
---

## Extensão de Capacidade via MCP (STDIO e HTTP)

AI CLIs frequentemente atuam como clientes MCP para acessar ferramentas adicionais:

- STDIO transport (local tools): o client gera uma cadeia auxiliar para rodar um tool server. Linhagem típica: `node → <ai-cli> → uv → python → file_write`. Exemplo observado: `uv run --with fastmcp fastmcp run ./server.py` que inicia `python3.13` e executa operações de arquivo locais em nome do agent.
- HTTP transport (remote tools): o client abre TCP de saída (p.ex., porta 8000) para um remote MCP server, que executa a ação solicitada (p.ex., escrever `/home/user/demo_http`). No endpoint você verá apenas a atividade de rede do client; toques de arquivo do lado do server ocorrem off‑host.

Notas:
- MCP tools são descritos ao modelo e podem ser auto‑selecionados pelo planning. O comportamento varia entre execuções.
- Remote MCP servers aumentam o blast radius e reduzem a visibilidade host‑side.

---

## Artefatos e Logs Locais (Forense)

- Gemini CLI session logs: `~/.gemini/tmp/<uuid>/logs.json`
- Campos comumente vistos: `sessionId`, `type`, `message`, `timestamp`.
- Exemplo de `message`: `"@.bashrc what is in this file?"` (user/agent intent captured).
- Claude Code history: `~/.claude/history.jsonl`
- Entradas JSONL com campos como `display`, `timestamp`, `project`.

Correlacione esses logs locais com requests observados no seu LLM gateway/proxy (p.ex., LiteLLM) para detectar tampering/model‑hijacking: se o que o modelo processou diverge do prompt/output local, investigue instruções injetadas ou descriptors de tool comprometidos.

---

## Padrões de Telemetria do Endpoint

Cadeias representativas em Amazon Linux 2023 com Node v22.19.0 e Python 3.13:

1) Ferramentas embutidas (acesso local a arquivos)
- Parent: `node .../bin/claude --model <model>` (ou equivalente para o CLI)
- Immediate child action: criar/modificar um arquivo local (p.ex., `demo-claude`). Vincule o evento de arquivo de volta pela linhagem parent→child.

2) MCP sobre STDIO (servidor de ferramenta local)
- Cadeia: `node → uv → python → file_write`
- Exemplo de spawn: `uv run --with fastmcp fastmcp run /home/ssm-user/tools/server.py`

3) MCP sobre HTTP (servidor de ferramenta remoto)
- Client: `node/<ai-cli>` abre TCP de saída para `remote_port: 8000` (ou similar)
- Server: processo Python remoto trata a request e escreve `/home/ssm-user/demo_http`.

Como decisões do agent variam por execução, espere variabilidade nos processos exatos e caminhos tocados.

---

## Estratégia de Detecção

Fontes de telemetria
- Linux EDR usando eBPF/auditd para eventos de processo, arquivo e rede.
- Logs locais do AI‑CLI para visibilidade de prompt/intenção.
- Logs do gateway LLM (p.ex., LiteLLM) para validação cruzada e detecção de model‑tamper.

Heurísticas de investigação
- Vincule toques em arquivos sensíveis à cadeia pai do AI‑CLI (p.ex., `node → <ai-cli> → uv/python`).
- Alertar em acessos/leituras/escritas sob: `~/.ssh`, `~/.aws`, armazenamento de perfil do browser, cloud CLI creds, `/etc/passwd`.
- Marcar conexões de saída inesperadas do processo AI‑CLI para endpoints MCP não aprovados (HTTP/SSE, portas como 8000).
- Correlacione artefatos locais `~/.gemini`/`~/.claude` com prompts/outputs do gateway LLM; divergência indica possível hijacking.

Exemplo de pseudo‑regras (adapte ao seu EDR):
```yaml
- when: file_write AND path IN ["$HOME/.ssh/*","$HOME/.aws/*","/etc/passwd"]
and ancestor_chain CONTAINS ["node", "claude|gemini|warp", "python|uv"]
then: alert("AI-CLI secrets touch via tool chain")

- when: outbound_tcp FROM process_name =~ "node|python" AND parent =~ "claude|gemini|warp"
and dest_port IN [8000, 3333, 8787]
then: tag("possible MCP over HTTP")
```
Medidas de hardening
- Exigir aprovação explícita do usuário para ferramentas de arquivo/sistema; registrar e apresentar os planos das ferramentas.
- Restringir a saída de rede (egress) dos processos AI‑CLI para servidores MCP aprovados.
- Enviar/ingestar logs locais de AI‑CLI e logs do LLM gateway para auditoria consistente e resistente a adulteração.

---

## Notas de reprodução do Blue‑Team

Use uma VM limpa com um EDR ou um tracer eBPF para reproduzir cadeias como:
- `node → claude --model claude-sonnet-4-20250514` then immediate local file write.
- `node → uv run --with fastmcp ... → python3.13` writing under `$HOME`.
- `node/<ai-cli>` establishing TCP to an external MCP server (port 8000) while a remote Python process writes a file.

Valide que suas detecções vinculem os eventos de arquivo/rede ao processo pai AI‑CLI que os iniciou, para evitar falsos positivos.

---

## References

- [Commanding attention: How adversaries are abusing AI CLI tools (Red Canary)](https://redcanary.com/blog/threat-detection/ai-cli-tools/)
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io)
- [LiteLLM – LLM Gateway/Proxy](https://docs.litellm.ai)

{{#include ../../banners/hacktricks-training.md}}
