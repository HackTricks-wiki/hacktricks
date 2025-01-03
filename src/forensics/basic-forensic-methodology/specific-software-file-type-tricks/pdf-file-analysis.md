# Analyse de fichiers PDF

{{#include ../../../banners/hacktricks-training.md}}

**Pour plus de détails, consultez :** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

Le format PDF est connu pour sa complexité et son potentiel à dissimuler des données, ce qui en fait un point focal pour les défis de forensique CTF. Il combine des éléments en texte brut avec des objets binaires, qui peuvent être compressés ou chiffrés, et peut inclure des scripts dans des langages comme JavaScript ou Flash. Pour comprendre la structure des PDF, on peut se référer au [matériel d'introduction](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) de Didier Stevens, ou utiliser des outils comme un éditeur de texte ou un éditeur spécifique aux PDF tel qu'Origami.

Pour une exploration ou une manipulation approfondie des PDF, des outils comme [qpdf](https://github.com/qpdf/qpdf) et [Origami](https://github.com/mobmewireless/origami-pdf) sont disponibles. Les données cachées dans les PDF peuvent être dissimulées dans :

- Couches invisibles
- Format de métadonnées XMP par Adobe
- Générations incrémentales
- Texte de la même couleur que l'arrière-plan
- Texte derrière des images ou images superposées
- Commentaires non affichés

Pour une analyse PDF personnalisée, des bibliothèques Python comme [PeepDF](https://github.com/jesparza/peepdf) peuvent être utilisées pour créer des scripts de parsing sur mesure. De plus, le potentiel des PDF pour le stockage de données cachées est si vaste que des ressources comme le guide de la NSA sur les risques et contre-mesures des PDF, bien qu'il ne soit plus hébergé à son emplacement d'origine, offrent toujours des informations précieuses. Une [copie du guide](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) et une collection de [trucs sur le format PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) par Ange Albertini peuvent fournir des lectures supplémentaires sur le sujet.

{{#include ../../../banners/hacktricks-training.md}}
