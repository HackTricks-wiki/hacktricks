# Divers CTF crypto

{{#include ../../banners/hacktricks-training.md}}

Cette section rassemble des techniques qui apparaissent dans les défis de cryptographie, mais qui ne correspondent pas clairement aux autres catégories.

## Langages ésotériques

### Technique

Utilisez ce processus lorsqu’un défi nécessite d’exécuter un programme écrit dans un langage ésotérique et de décoder sa sortie.

Si un défi vous fournit du code qui ne ressemble pas à un langage courant :

- Identifiez le langage en recherchant un token distinctif ou une séquence d’instructions.
- Utilisez un interpréteur en ligne ou une image Docker.
- Si la sortie est étrange, recherchez un encodage ou une compression appliqués après l’exécution.

Le wiki Esolang constitue un index utile.<sup>[[1]](#references)</sup> Pour les couches classiques d’encodage et de compression, utilisez le [Crypto CTF workflow](../ctf-workflow/). Si l’indice est un texte invisible plutôt qu’une syntaxe exécutable, consultez [text steganography](../../stego/text/).

### Exfiltration de l’état préchargé d’un interpréteur

Si un défi accepte du code source dans un langage ésotérique et l’exécute dans un **interpréteur personnalisé**, inspectez sa mémoire initiale, sa pile et ses instructions de sortie avant de considérer le code source comme une énigme de décodage. Lorsque l’interpréteur précharge un secret sur une pile Befunge, un court programme peut dépiler et afficher les octets déjà présents sans les calculer. Cela nécessite de pouvoir contrôler le code source exécuté et de disposer d’un opcode de sortie ; cette méthode ne fonctionne pas avec un interpréteur normal dont l’état initial est vide. Dans un défi Befunge, le code ci-dessous a affiché à plusieurs reprises les caractères d’un flag préchargé sur la pile dans l’ordre inverse.<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>` lance l'exécution vers la droite, `,` dépile et affiche un caractère, et `<` renvoie le pointeur d'instruction à `,`. Vérifiez le comportement de l'interpréteur personnalisé en cas de dépilement d'une pile vide et de dépassement de la limite d'instructions : l'implémentation citée s'arrête lorsque la pile est épuisée ou après 1 024 instructions. Si le secret ne se trouve pas directement sur la pile, examinez les autres états initialisés et les instructions de sortie/lecture disponibles au lieu de supposer que la sémantique standard de Befunge s'applique.<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang, le wiki des langages de programmation ésotériques](https://esolangs.org/wiki/Main_Page)
- [2] [WolvCTF 2024 : writeup original de Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [WolvCTF 2024 : source de l'interpréteur de Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Référence du langage Befunge](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}
