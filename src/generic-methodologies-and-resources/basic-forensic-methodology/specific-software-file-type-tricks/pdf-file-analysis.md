# Analyse de fichiers PDF

{{#include ../../../banners/hacktricks-training.md}}

**Pour plus de détails, consultez :** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

Le format PDF est connu pour sa complexité et son potentiel de dissimulation de données, ce qui en fait un point central des challenges de forensics CTF. Il combine des éléments en texte brut avec des objets binaires, qui peuvent être compressés ou chiffrés, et peut inclure des scripts dans des langages comme JavaScript ou Flash. Pour comprendre la structure des PDF, il est possible de consulter le [matériel d'introduction](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) de Didier Stevens, ou d'utiliser des outils comme un éditeur de texte ou un éditeur spécifique aux PDF tel qu'Origami.

Pour une exploration approfondie ou la manipulation de PDF, des outils comme [qpdf](https://github.com/qpdf/qpdf) et [Origami](https://github.com/mobmewireless/origami-pdf) sont disponibles. Les données cachées dans les PDF peuvent être dissimulées dans :

- Des couches invisibles
- Le format de métadonnées XMP d'Adobe
- Des générations incrémentielles
- Du texte de la même couleur que l'arrière-plan
- Du texte derrière des images ou des images superposées
- Des commentaires non affichés

Pour une analyse personnalisée des PDF, des bibliothèques Python comme [PeepDF](https://github.com/jesparza/peepdf) peuvent être utilisées afin de créer des scripts de parsing sur mesure. En outre, le potentiel des PDF pour stocker des données cachées est si vaste que des ressources comme le guide de la NSA sur les risques liés aux PDF et les contre-mesures, bien qu'il ne soit plus hébergé à son emplacement d'origine, fournissent toujours des informations précieuses. Une [copie du guide](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) et une collection d'[astuces sur le format PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) par Ange Albertini peuvent fournir des informations complémentaires sur le sujet.

## Constructions malveillantes courantes

Les attackers abusent souvent de certains objets et actions PDF qui s'exécutent automatiquement lorsque le document est ouvert ou utilisé. Mots-clés à rechercher :

* **/OpenAction, /AA** – actions automatiques exécutées à l'ouverture ou lors d'événements spécifiques.
* **/JS, /JavaScript** – JavaScript intégré (souvent obfusqué ou réparti entre plusieurs objets).
* **/Launch, /SubmitForm, /URI, /GoToE** – lanceurs de processus externes / URL.
* **/RichMedia, /Flash, /3D** – objets multimédias pouvant dissimuler des payloads.
* **/EmbeddedFile /Filespec** – pièces jointes (EXE, DLL, OLE, etc.).
* **/ObjStm, /XFA, /AcroForm** – flux d'objets ou formulaires couramment utilisés pour dissimuler du shell-code.
* **Mises à jour incrémentielles** – plusieurs marqueurs %%EOF ou un offset **/Prev** très important peuvent indiquer que des données ont été ajoutées après la signature afin de contourner l'AV.

Lorsque l'un des tokens précédents apparaît avec des chaînes suspectes (powershell, cmd.exe, calc.exe, base64, etc.), le PDF mérite une analyse plus approfondie.

---

## Aide-mémoire de l'analyse statique
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – decompress/inspect the object tree
pdf-parser.py -f suspicious.pdf                # interactive
pdf-parser.py -a suspicious.pdf                # automatic report

# Search for JavaScript and pretty-print it
pdf-parser.py -search "/JS" -raw suspicious.pdf | js-beautify -

# Dump embedded files
peepdf "open suspicious.pdf" "objects embeddedfile" "extract 15 16 17" -o dumps/

# Remove passwords / encryptions before processing with other tools
qpdf --password='secret' --decrypt suspicious.pdf clean.pdf

# Lint the file with a Go verifier (checks structure violations)
pdfcpu validate -mode strict clean.pdf
```
Projets supplémentaires utiles (activement maintenus en 2023-2025) :
* **pdfcpu** – bibliothèque/CLI Go capable de *lint*, *decrypt*, *extract*, *compress* et *sanitize* des PDFs.
* **pdf-inspector** – visualiseur basé sur un navigateur qui affiche le graphe des objets et les streams.
* **PyMuPDF (fitz)** – moteur Python scriptable capable de rendre les pages en images en toute sécurité afin de déclencher le JavaScript intégré dans un sandbox renforcé.

---

## Techniques d’attaque récentes (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC a observé des threat actors ajouter un document Word basé sur MHT avec des macros VBA après le dernier **%%EOF**, produisant un fichier qui est à la fois un PDF valide et un DOC valide. Les moteurs antivirus qui analysent uniquement la couche PDF ne détectent pas la macro. Les mots-clés PDF statiques sont propres, mais `file` affiche toujours `%PDF`. Considérez tout PDF contenant également la chaîne `<w:WordDocument>` comme hautement suspect.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – des adversaires détournent la fonctionnalité de mise à jour incrémentielle pour insérer un second **/Catalog** avec un `/OpenAction` malveillant, tout en conservant la première révision bénigne signée. Les outils qui inspectent uniquement la première table xref sont contournés.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – une fonction vulnérable de **CoolType.dll** peut être atteinte via des polices CIDType2 intégrées, permettant une exécution de code à distance avec les privilèges de l’utilisateur lorsqu’un document conçu à cette fin est ouvert. Corrigé dans APSB24-29, en mai 2024.<sup>[[3]](#references)</sup>

---

## Modèle rapide de règle YARA
```yara
rule Suspicious_PDF_AutoExec {
meta:
description = "Generic detection of PDFs with auto-exec actions and JS"
author      = "HackTricks"
last_update = "2025-07-20"
strings:
$pdf_magic = { 25 50 44 46 }          // %PDF
$aa        = "/AA" ascii nocase
$openact   = "/OpenAction" ascii nocase
$js        = "/JS" ascii nocase
condition:
$pdf_magic at 0 and ( all of ($aa, $openact) or ($openact and $js) )
}
```
---

## Conseils défensifs

1. **Patchez rapidement** – maintenez Acrobat/Reader sur la dernière version de la Continuous track ; la plupart des chaînes de RCE observées dans la nature exploitent des vulnérabilités n-day corrigées plusieurs mois auparavant.
2. **Supprimez le contenu actif au niveau de la passerelle** – utilisez `pdfcpu sanitize` ou `qpdf --qdf --remove-unreferenced` pour supprimer le JavaScript, les fichiers intégrés et les actions de lancement des PDF entrants.
3. **Content Disarm & Reconstruction (CDR)** – convertissez les PDF en images (ou au format PDF/A) sur un hôte sandbox afin de préserver la fidélité visuelle tout en supprimant les objets actifs.
4. **Bloquez les fonctionnalités rarement utilisées** – les paramètres « Enhanced Security » de Reader permettent de désactiver le JavaScript, le multimédia et le rendu 3D dans les environnements d’entreprise.
5. **Sensibilisez les utilisateurs** – l’ingénierie sociale (leurres utilisant des factures et des CV) reste le vecteur initial ; apprenez aux employés à transférer les pièces jointes suspectes à l’équipe IR.

## Références

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update available for Adobe Acrobat and Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)

{{#include ../../../banners/hacktricks-training.md}}
