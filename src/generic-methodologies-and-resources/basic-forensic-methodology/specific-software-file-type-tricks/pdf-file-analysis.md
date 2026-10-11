# Analyse de fichiers PDF

{{#include ../../../banners/hacktricks-training.md}}

**Pour plus de détails, consultez :** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Le format PDF est connu pour sa complexité et sa capacité à dissimuler des données, ce qui en fait un sujet central des défis de forensics en CTF. Il combine des éléments en texte brut avec des objets binaires, qui peuvent être compressés ou chiffrés, et peut inclure des scripts dans des langages comme JavaScript ou Flash. Pour comprendre la structure des PDF, consultez le [guide d'introduction](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) de Didier Stevens ou utilisez des outils comme un éditeur de texte ou un éditeur spécifique aux PDF comme Origami.

Pour explorer ou manipuler les PDF en profondeur, des outils comme [qpdf](https://github.com/qpdf/qpdf) et [Origami](https://github.com/mobmewireless/origami-pdf) sont disponibles. Les données cachées dans les PDF peuvent être dissimulées dans :

- Des calques invisibles
- Le format de métadonnées XMP d'Adobe
- Des générations incrémentales
- Du texte de la même couleur que l'arrière-plan
- Du texte derrière des images ou des images qui se chevauchent
- Des commentaires non affichés

Pour analyser des PDF de façon personnalisée, des bibliothèques Python comme [PeepDF](https://github.com/jesparza/peepdf) permettent d'écrire des scripts d'analyse sur mesure. En outre, le potentiel des PDF pour stocker des données cachées est si vaste que des ressources comme le guide de la NSA sur les risques liés aux PDF et les contre-mesures, bien qu'il ne soit plus hébergé à son emplacement d'origine, restent une source précieuse d'informations. Une [copie du guide](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) et un recueil d'[astuces sur le format PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) par Ange Albertini peuvent approfondir le sujet.<sup>[[4]](#references)[[5]](#references)</sup>

## Constructions malveillantes courantes

Les attaquants détournent souvent certains objets et actions PDF qui s'exécutent automatiquement à l'ouverture ou lors de l'interaction avec le document. Mots-clés à rechercher :

* **/OpenAction, /AA** – actions automatiques exécutées à l'ouverture ou lors d'événements spécifiques.
* **/JS, /JavaScript** – JavaScript intégré (souvent obfusqué ou réparti sur plusieurs objets).
* **/Launch, /SubmitForm, /URI, /GoToE** – lanceurs de processus externes ou d'URL.
* **/RichMedia, /Flash, /3D** – objets multimédias susceptibles de dissimuler des payloads.
* **/EmbeddedFile /Filespec** – pièces jointes (EXE, DLL, OLE, etc.).
* **/ObjStm, /XFA, /AcroForm** – flux d'objets ou formulaires souvent détournés pour dissimuler du shell-code.
* **Mises à jour incrémentales** – plusieurs marqueurs %%EOF ou un décalage **/Prev** très important peuvent indiquer que des données ont été ajoutées après la signature pour contourner l'AV.

Lorsque l'un des jetons précédents apparaît avec des chaînes suspectes (powershell, cmd.exe, calc.exe, base64, etc.), le PDF mérite une analyse plus approfondie.

---

## Aide-mémoire pour l'analyse statique

Les exemples ci-dessous utilisent les interfaces en ligne de commande documentées de `pdf-parser.py`, qpdf et pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – pass supported streams through their declared filters
pdf-parser.py -f suspicious.pdf
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

La pixellisation d’une image dans un PDF ne supprime pas les pixels sous-jacents. Si un document lisible semble masquer un identifiant de cette manière, extrayez l’image intégrée pour l’inspecter hors ligne de manière autorisée ; le résultat dépend de l’image et de la disponibilité d’une référence appropriée, et la récupération visuelle n’est pas garantie. Un mot de passe récupéré doit encore être vérifié séparément sur le compte dont les privilèges sont pertinents. N’incluez pas l’extraction de PDF ni la récupération d’images dans un scan de routine des hôtes.

Autres projets utiles (activement maintenus de 2023 à 2025) :
* **pdfcpu** – bibliothèque/CLI Go capable de valider, déchiffrer, extraire, optimiser et manipuler des PDF.<sup>[[9]](#references)</sup>
* **pdf-inspector** – visualiseur basé sur un navigateur qui affiche le graphe d’objets et les flux.
* **PyMuPDF** – bindings Python scriptables permettant d’inspecter des PDF et de rendre les pages sous forme d’images matricielles. Considérez le parser/rendeur comme une surface d’attaque exposée aux fichiers non fiables et exécutez-le dans un environnement d’analyse convenablement isolé.<sup>[[8]](#references)</sup>

---

## Techniques d’attaque récentes (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC a signalé une technique qui ajoute à un PDF un fichier MHT créé avec Word et contenant des macros VBA. Le fichier conserve la signature magique PDF tout en pouvant aussi s’ouvrir dans Word. Les outils d’analyse PDF uniquement, les sandboxes ou les antivirus peuvent ne pas détecter la macro, car le comportement malveillant se produit lors de l’ouverture dans Word ; recherchez le marqueur `<w:WordDocument>` ainsi que d’autres indicateurs MHT.<sup>[[2]](#references)</sup>
* **Attaques par shadow sur les PDF signés** – des attaquants peuvent placer du contenu masqué dans un PDF avant sa signature, puis ajouter une mise à jour incrémentielle qui modifie le catalogue ou les références d’objets afin que les visionneuses affichent le contenu masqué alors que la signature d’origine reste valide. Cette technique peut contourner les visionneuses qui considèrent ces mises à jour comme inoffensives.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe classe cette vulnérabilité critique comme un use-after-free pouvant entraîner l’exécution de code arbitraire ; APSB24-29 a été publié le 14 mai 2024.<sup>[[3]](#references)</sup>

---

## Modèle de règle YARA rapide

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

## Conseils de défense

1. **Appliquer rapidement les correctifs** – maintenir Acrobat/Reader sur la dernière version Continuous ; la plupart des chaînes RCE observées dans la nature exploitent des vulnérabilités n-day corrigées plusieurs mois auparavant.
2. **Supprimer le contenu actif à la passerelle** – utiliser un produit d’assainissement spécialement conçu et contrôlé par des règles, ou un produit CDR, qui supprime explicitement JavaScript, les fichiers incorporés, les actions de lancement, les formulaires et le contenu multimédia. `qpdf --qdf` facilite l’inspection des objets PDF, tandis que pdfcpu fournit des fonctions de validation et de manipulation ; aucune de ces commandes ne prouve à elle seule que le contenu actif a été supprimé.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – convertir les PDF en images (ou en PDF/A) sur un hôte sandbox afin de préserver la fidélité visuelle tout en supprimant les objets actifs.
4. **Bloquer les fonctionnalités rarement utilisées** – les paramètres « Enhanced Security » pour les entreprises dans Reader permettent de désactiver JavaScript, le contenu multimédia et le rendu 3D.
5. **Sensibiliser les utilisateurs** – l’ingénierie sociale (leurres de facture et de CV) reste le vecteur initial ; apprendre aux employés à transmettre les pièces jointes suspectes à l’équipe IR.

## References

- [1] [Guide de terrain Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Contournement de la détection en incorporant un fichier Word malveillant dans un fichier PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Bulletin de sécurité Adobe – Mise à jour de sécurité disponible pour Adobe Acrobat et Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - copie du guide](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - Astuces sur le format PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Attaques Shadow : dissimulation et remplacement du contenu dans les PDF signés](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Tutoriel PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Options de ligne de commande qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
