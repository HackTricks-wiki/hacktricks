# Bypasses do Sandbox do Office no macOS

{{#include ../../../../../banners/hacktricks-training.md}}

### Bypass do Sandbox do Word via Launch Agents

O aplicativo usa um **Sandbox personalizado** usando a autorização **`com.apple.security.temporary-exception.sbpl`** e esse sandbox personalizado permite escrever arquivos em qualquer lugar, desde que o nome do arquivo comece com `~$`: `(require-any (require-all (v
