# Outils de reversing et méthodes de base

{{#include ../../banners/hacktricks-training.md}}

## Outils de reversing basés sur ImGui

Logiciel :

- ReverseKit : [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automatisation de WinDbg en mode utilisateur

{{#ref}}
windbg-automation.md
{{#endref}}

## Flux de contrôle piloté par les exceptions sous Windows

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Débogage du noyau Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Décompilateur Wasm / compilateur Wat

En ligne :

- Utilisez [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) pour **décompiler** du wasm (binaire) vers du wat (texte lisible)
- Utilisez [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) pour **compiler** du wat vers du wasm
- Vous pouvez également essayer [web-wasmdec](https://wwwg.github.io/web-wasmdec/) pour la décompilation.

Logiciels :

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode mis en cache de Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Payloads virtualisés et machines virtuelles personnalisées

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Décompilateur .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek est un décompilateur qui **décompile et examine plusieurs formats**, notamment les **bibliothèques** (.dll), les **fichiers de métadonnées Windows** (.winmd) et les **exécutables** (.exe). Une fois décompilé, un assembly peut être enregistré en tant que projet Visual Studio (.csproj).

L’intérêt est que si le code source perdu doit être restauré à partir d’un assembly ancien, cette opération peut faire gagner du temps. De plus, dotPeek permet de naviguer facilement dans le code décompilé, ce qui en fait l’un des outils parfaits pour **l’analyse d’algorithmes Xamarin**.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Grâce à son modèle de modules complémentaires complet et à une API qui étend l’outil pour répondre précisément à vos besoins, .NET Reflector fait gagner du temps et simplifie le développement. Voyons la multitude de services de reverse engineering fournis par cet outil :

- Donne un aperçu de la circulation des données dans une bibliothèque ou un composant
- Donne un aperçu de l’implémentation et de l’utilisation des langages et frameworks .NET
- Repère les fonctionnalités non documentées et non exposées afin de tirer davantage parti des API et technologies utilisées.
- Repère les dépendances et les différents assemblies
- Identifie l’emplacement exact des erreurs dans votre code, les composants tiers et les bibliothèques.
- Permet de déboguer le code source de tout le code .NET avec lequel vous travaillez.

### [ILSpy](https://github.com/icsharpcode/ILSpy) et [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy pour Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode) : vous pouvez l’utiliser sur n’importe quel OS (vous pouvez l’installer directement depuis VSCode, sans avoir besoin de télécharger le dépôt git. Cliquez sur **Extensions** puis **recherchez ILSpy**).\
Si vous devez **décompiler**, **modifier** puis **recompiler**, vous pouvez utiliser [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou son fork activement maintenu, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic droit -> Modify Method** pour modifier quelque chose dans une fonction).

### Inspection managée sans exécution avec REA

**REA** peut inspecter les métadonnées PE/CLI et le CIL sans charger l’assembly. Commencez par identifier l’artefact, puis inspectez ses membres et les limites natives déclarées ; cette approche est utile pour examiner les appels suspects avant d’utiliser un décompilateur ou d’exécuter le programme.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Pour comparer des versions, `compare_managed_members` utilise l’identité brute du CIL/de la signature et des empreintes des instructions décodées, plutôt que de considérer les jetons de métadonnées comme stables d’une compilation à l’autre. Une déclaration P/Invoke ne prouve pas que du code natif a été exécuté ; `verify_managed_native_boundaries` nécessite un export natif correspondant ou une preuve de fonction pour vérifier cette frontière. Conservez le digest de l’artefact, le MVID et les correspondances non résolues avec le résultat.<sup>[[17]](#references)</sup>

### Journalisation de DNSpy

Pour que **DNSpy consigne certaines informations dans un fichier**, vous pouvez utiliser cet extrait :

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Débogage avec DNSpy

Pour déboguer du code avec DNSpy, vous devez :

Tout d’abord, modifier les **attributs de l’assembly** liés au **débogage** :

![Journalisation DNSpy - Débogage avec DNSpy : tout d’abord, modifier les attributs de l’assembly liés au débogage](<../../images/image (973).png>)

Depuis :

```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```

À :

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```

Et cliquez sur **compile** :

![DNSpy Logging - DNSpy Debugging: Et cliquez sur compile](<../../images/image (314) (1).png>)

Ensuite, enregistrez le nouveau fichier via _**File >> Save module...**_ :

![DNSpy Logging - DNSpy Debugging: Ensuite, enregistrez le nouveau fichier via File Save module](<../../images/image (602).png>)

C'est nécessaire, car sinon, à **l'exécution**, plusieurs **optimisations** seront appliquées au code et il se peut qu'un **break-point ne soit jamais atteint** lors du debugging ou que certaines **variables n'existent pas**.

Ensuite, si votre application .NET est **exécutée** par **IIS**, vous pouvez la **redémarrer** avec :

```
iisreset /noforce
```

Ensuite, pour commencer le débogage, vous devez fermer tous les fichiers ouverts et sélectionner **Attach to Process...** dans l’onglet **Debug** :

![DNSpy Logging - DNSpy Debugging : Ensuite, pour commencer le débogage, vous devez fermer tous les fichiers ouverts et sélectionner Attach to Process dans l’onglet Debug](<../../images/image (318).png>)

Sélectionnez ensuite **w3wp.exe** pour vous attacher au **serveur IIS**, puis cliquez sur **attach** :

![DNSpy Logging - DNSpy Debugging : Sélectionnez ensuite w3wp.exe pour vous attacher au serveur IIS, puis cliquez sur attach](<../../images/image (113).png>)

Maintenant que nous déboguons le processus, il est temps de l’arrêter et de charger tous les modules. Cliquez d’abord sur _Debug >> Break All_, puis sur _**Debug >> Windows >> Modules**_ :

![DNSpy Logging - DNSpy Debugging : Maintenant que nous déboguons le processus, il est temps de l’arrêter et de charger tous les modules. Cliquez d’abord sur Debug Break All, puis sur Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging : Maintenant que nous déboguons le processus, il est temps de l’arrêter et de charger tous les modules. Cliquez d’abord sur Debug Break All, puis sur Debug Windows Modules](<../../images/image (834).png>)

Cliquez sur n’importe quel module dans **Modules**, puis sélectionnez **Open All Modules** :

![DNSpy Logging - DNSpy Debugging : Cliquez sur n’importe quel module dans Modules, puis sélectionnez Open All Modules](<../../images/image (922).png>)

Faites un clic droit sur n’importe quel module dans **Assembly Explorer**, puis cliquez sur **Sort Assemblies** :

![DNSpy Logging - DNSpy Debugging : Faites un clic droit sur n’importe quel module dans Assembly Explorer, puis cliquez sur Sort Assemblies](<../../images/image (339).png>)

## Décompilateur Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Débogage des DLL

### Avec IDA

- **Chargez rundll32** (64 bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe)
- Sélectionnez le débogueur **Windbg**
- Sélectionnez "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA : Sélectionnez « Suspend on library load/unload »](<../../images/image (868).png>)

- Configurez les **paramètres** d’exécution en indiquant le **chemin vers la DLL** et la fonction que vous souhaitez appeler :

![Debugging DLLs - Using IDA : Configurez les paramètres d’exécution en indiquant le chemin vers la DLL et la fonction que vous souhaitez appeler](<../../images/image (704).png>)

Ensuite, lorsque vous démarrez le débogage, **l’exécution s’arrête au chargement de chaque DLL**. Ainsi, lorsque rundll32 chargera votre DLL, l’exécution s’arrêtera.

Cette méthode s’arrête lors des événements de chargement de module, mais atteindre le point d’entrée de la DLL chargée est moins direct qu’avec le workflow x64dbg ci-dessous.

### Avec x64dbg/x32dbg

- **Chargez rundll32** (64 bits dans C:\Windows\System32\rundll32.exe et 32 bits dans C:\Windows\SysWOW64\rundll32.exe)
- **Modifiez la ligne de commande** ( _File --> Change Command Line_ ) et indiquez le chemin de la DLL et la fonction que vous souhaitez appeler, par exemple : "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Modifiez _Options --> Settings_ et sélectionnez "**DLL Entry**".
- **Démarrez ensuite l’exécution**. Le débogueur s’arrêtera à chaque dll main ; à un moment donné, il **s’arrêtera au point d’entrée de votre DLL**. À partir de là, recherchez simplement les points où vous souhaitez placer un breakpoint.

Notez que lorsque l’exécution s’arrête pour une raison quelconque dans win64dbg, vous pouvez voir **dans quel code vous vous trouvez** en regardant **en haut de la fenêtre win64dbg** :

![Using IDA - Using x64dbg/x32dbg : Notez que lorsque l’exécution s’arrête pour une raison quelconque dans win64dbg, vous pouvez voir dans quel code vous vous trouvez en regardant en haut de la fenêtre win64dbg](<../../images/image (842).png>)

Cet indicateur confirme que l’exécution s’est arrêtée dans la DLL que vous souhaitez déboguer.

## Applications GUI / jeux vidéo

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) est un programme pratique pour trouver où les valeurs importantes sont stockées en mémoire dans un jeu en cours d’exécution et les modifier. Plus d’informations dans :

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) est un outil front-end/de reverse engineering pour le GNU Project Debugger (GDB), axé sur les jeux. Il peut toutefois être utilisé pour tout ce qui concerne le reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) est un front-end web pour plusieurs décompilateurs. Ce service web vous permet de comparer les résultats de différents décompilateurs sur de petits exécutables.

### Déchiffrement de PCK Godot et récupération de projet

Pour un jeu Godot distribué, localisez son PCK dans un fichier `.pck` autonome, un pack ajouté à un exécutable ou intégré à celui-ci, ou dans le répertoire `assets` d’un APK. [gore](https://github.com/figurophobia/gore) peut inspecter et extraire le pack, tandis que la reconstruction complète des scripts et des ressources nécessite GDRE Tools (`gore setup` l’installe, ou utilisez `--gdre`). Pour ce workflow, l’outil prend en charge les formats PCK v2–v4 de Godot 4.x ; il peut détecter les en-têtes v1, mais nécessite une clé fournie pour v1.<sup>[[25]](#references)</sup>

La récupération automatique de la clé nécessite une table de fichiers chiffrée ; si seuls les contenus des fichiers sont chiffrés, fournissez plutôt une clé connue. Un échec de la récupération ne prouve pas qu’un pack n’est pas chiffré.<sup>[[28]](#references)</sup>

La recherche de clé n’est **pas** une attaque par force brute sur l’espace de clés AES-256. Une table de fichiers chiffrée expose le MD5 de son texte en clair, sa longueur, son IV et son texte chiffré AES-256-CFB.<sup>[[27]](#references)</sup> `gore` teste des fenêtres de 32 octets de l’exécutable du jeu ou des fichiers voisins comme clés candidates. Il filtre les candidats en fonction d’une longueur et d’un préfixe plausibles du chemin déchiffré, puis confirme les résultats du scan binaire en déchiffrant toute la table et en vérifiant son MD5.<sup>[[26]](#references)[[28]](#references)</sup> Il recherche d’abord dans les sections de données initialisées de PE/ELF, puis effectue un scan de l’ensemble du fichier ; `--scan` ajoute d’autres fichiers candidats.<sup>[[28]](#references)</sup>

Si aucune clé intégrée n’est trouvée, une petite liste de mots de passe incluse est testée ; `--wordlist` permet de fournir d’autres candidats. Chaque mot de passe est testé sous forme de représentation de clé dérivée d’un mot de passe par le moteur, de valeur littérale complétée par des zéros ou de clé hexadécimale de 64 caractères. Contrairement aux résultats du scan binaire, les résultats de la wordlist ne passent que le filtre de structure des chemins dans cette implémentation. Confirmez-les en ouvrant le pack et en validant les ressources extraites.<sup>[[26]](#references)[[28]](#references)</sup>

Une fois l’artefact du jeu disponible localement, choisissez l’étape nécessaire à l’analyse. `recover` fait appel à GDRE pour reconstruire un projet qui peut être ouvert, tandis que `extract` décompresse uniquement les fichiers bruts. `key` affiche une clé candidate à utiliser avec un autre outil.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Investigation native étayée par des preuves avec REA

**REA** expose les analyses de Hopper, Ghidra et IDA via CLI et MCP. Il nécessite Node.js 22.x (au moins 22.19), 24.x (au moins 24.11) ou 26+, ainsi que npm. Configurez d’abord un fournisseur natif existant ; vérifiez `rea providers --json` et sélectionnez explicitement un fournisseur lorsque plusieurs prennent en charge la cible. Remplacez `0x1000` ci-dessous par un nom de fonction ou une adresse observé dans l’inventaire.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Commencez par une chaîne caractéristique ou un symbole, suivez les références et les appelants, puis examinez le dossier de la fonction sélectionnée et son pseudocode avec `rea decompile`. REA lie une session au fournisseur sélectionné au lieu de le remplacer silencieusement après un échec. Pour des requêtes reproductibles, `--snapshot PATH` réutilise uniquement les octets d’artefact, le fournisseur, les paramètres, l’opération et les paramètres de requête correspondants ; un snapshot est un cache local, pas une base de données du fournisseur enregistrée. Conservez les Evidence renvoyées et les inconnues explicites au lieu de traiter les chemins déduits ou le texte du décompilateur comme du code source d’origine.<sup>[[16]](#references)[[18]](#references)</sup>

Pour les points d’entrée JavaScript/Electron qui mènent à des modules complémentaires natifs, voir [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Analyse scriptée d’IDA et de Ghidra avec un pont TCP local

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) s’exécute dans une base de données IDA ou un programme CodeBrowser de Ghidra **déjà ouvert** et permet à un script distinct d’interroger et de modifier cette base de données d’analyse. Exécutez `ID_Server.py` depuis la CLI Python d’IDA (`import ID_Server`) ou `Ghidra_Server.py` depuis le Script Manager de Ghidra. IDA se lie à `127.0.0.1` à partir du port `5073` et analyse les ports supérieurs. Le script Ghidra actuel commence au port `5093` et essaie dix ports jusqu’à `5102` ; son socket Java se lie à l’adresse générique, et pas uniquement à l’interface de bouclage. Vérifiez le port affiché par l’instance avant de vous connecter. Contrairement à un analyseur headless, ce pont fonctionne sur le programme actuellement ouvert dans cette instance de l’interface graphique.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Envoyez **une commande terminée par un retour à la ligne par connexion** et lisez la réponse terminée par un retour à la ligne. Le résultat est normalement au format JSON. Par exemple, après avoir trouvé une API importée pertinente pour un chemin d’entrée, `IMPORTXREF` trouve ses sites d’appel ; `DECOMP_XREF` décompile ensuite par lots les appelants d’une adresse sélectionnée. `FUNC` examine une fonction, tandis que `PCODE` renvoie la représentation intermédiaire du décompilateur. Utilisez l’adresse de la base de données active, et non une adresse copiée depuis un binaire dont la base de chargement est différente. L’exemple ci-dessous utilise le port par défaut d’IDA ; pour Ghidra, utilisez le port affiché par son script.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Le même canal peut **modifier la base d’analyse** : `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` et `PATCH` modifient les noms, les types, les définitions de structures, les limites des fonctions ou les octets stockés. `PATCH` est une modification de la base de données, **pas** la preuve d’un patch appliqué à un processus en cours d’exécution. Aucun des deux listeners ne documente de mécanisme d’authentification. IDA est accessible uniquement via loopback, mais Ghidra peut être accessible depuis les interfaces réseau ; restreignez l’accès au listener de Ghidra lorsque vous l’utilisez. `QUIT` arrête l’un ou l’autre listener, et IDA expose également `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Déboguer un shellcode avec blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alloue le **shellcode**, affiche son **adresse mémoire** et met l’exécution en pause.\
Attachez un debugger tel qu’IDA ou x64dbg, placez un breakpoint à l’adresse affichée, puis reprenez l’exécution pour déboguer le shellcode.

La page GitHub des versions contient des archives ZIP avec les versions compilées : [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Vous trouverez une version légèrement modifiée de Blobrunner au lien suivant. Pour la compiler, **créez simplement un projet C/C++ dans Visual Studio Code, copiez-collez le code et créez le build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Déboguer un shellcode avec jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) est similaire à BlobRunner. Il alloue le shellcode et entre dans une boucle infinie. Attachez le debugger, reprenez l’exécution pendant **2 à 5 secondes**, mettez-la en pause dans cette boucle, puis avancez jusqu’à l’appel suivant, qui transfère l’exécution au shellcode alloué.

![Debugger en pause dans la boucle infinie de jmp2it, juste avant l’appel au shellcode alloué](<../../images/image (509).png>)

Vous pouvez télécharger une version compilée de [jmp2it sur la page des versions](https://github.com/adamkramer/jmp2it/releases/).

### Déboguer un shellcode avec Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) est l’interface graphique de radare. Cutter permet d’émuler le shellcode et de l’inspecter dynamiquement.

Notez que Cutter permet de choisir « Open File » ou « Open Shellcode ». Dans mon cas, lorsque j’ai ouvert le shellcode comme un fichier, il l’a décompilé correctement, mais lorsque je l’ai ouvert comme un shellcode, ce n’était pas le cas :

![Cutter affichant des résultats d’analyse différents pour les mêmes octets ouverts comme fichier ou comme shellcode](<../../images/image (562).png>)

Pour lancer l’émulation à l’endroit souhaité, placez-y un bp ; Cutter semble alors démarrer automatiquement l’émulation à cet endroit :

![Breakpoint placé à l’entrée souhaitée du shellcode avant de lancer l’émulation de Cutter](<../../images/image (589).png>)

![Émulateur de Cutter en pause au breakpoint sélectionné dans le shellcode](<../../images/image (387).png>)

Vous pouvez, par exemple, afficher la stack dans un hex dump :

![Stack du shellcode émulé affichée dans le hex dump de Cutter](<../../images/image (186).png>)

### Déobfusquer un shellcode et récupérer les fonctions exécutées

Essayez [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Il vous indiquera notamment **quelles fonctions** le shellcode utilise et s’il se **décode** lui-même en mémoire.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg dispose également d’un lanceur graphique qui permet de sélectionner les options souhaitées et d’exécuter le shellcode

![Lanceur graphique scDbg permettant de sélectionner les options d’émulation et de traçage du shellcode](<../../images/image (258).png>)

L’option **Create Dump** enregistre le shellcode final si celui-ci est modifié dynamiquement en mémoire (utile pour télécharger le shellcode décodé). L’option **start offset** peut être utile pour démarrer le shellcode à un offset spécifique. L’option **Debug Shell** permet de déboguer le shellcode à l’aide du terminal scDbg (je trouve toutefois que les options expliquées précédemment sont plus adaptées, car elles permettent d’utiliser Ida ou x64dbg).

### Désassemblage avec CyberChef

Chargez votre fichier shellcode en entrée et utilisez la recette suivante pour le désassembler : [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Déobfuscation de l’obfuscation MBA

L’obfuscation **Mixed Boolean-Arithmetic (MBA)** dissimule des expressions simples telles que `x + y` derrière des formules qui combinent des opérations arithmétiques (`+`, `-`, `*`) et des opérateurs bit à bit (`&`, `|`, `^`, `~`, décalages). L’essentiel est que ces identités ne sont généralement valides qu’en **arithmétique modulaire à largeur fixe** : les retenues et les dépassements de capacité comptent.

```c
(x ^ y) + 2 * (x & y) == x + y
```

Si vous simplifiez ce type d’expression avec des outils d’algèbre génériques, vous pouvez facilement obtenir un résultat erroné, car la sémantique de largeur des bits a été ignorée.<sup>[[1]](#references)</sup>

### Workflow pratique

1. **Conservez la largeur de bits d’origine** issue du code/IR décompilé ou relevé (`8/16/32/64` bits).
2. **Classez l’expression** avant d’essayer de la simplifier :
   - **Linéaire** : sommes pondérées d’atomes bit à bit
   - **Semi-linéaire** : expression linéaire avec des masques constants, comme `x & 0xFF`
   - **Polynomiale** : présence de produits
   - **Mixte** : produits et logique bit à bit entremêlés, souvent avec des sous-expressions répétées
3. **Vérifiez chaque réécriture candidate** par des tests aléatoires ou une preuve SMT. Si l’équivalence ne peut pas être prouvée, conservez l’expression d’origine au lieu de faire une supposition.

### Contourner le flux de contrôle aplati avec une tranche d’exécution étroite

Il est souvent inutile de reconstituer le graphe de flux de contrôle complet. En présence d’un aplatissement du flux de contrôle, de prédicats opaques, de grands répartiteurs ou de code riche en MBA, suivez les références depuis les blocs chiffrés et les buffers de sortie jusqu’à la plus petite routine qui les transforme. Puis reproduisez uniquement cette tranche du flux de données, ou exécutez-la indépendamment ; le répartiteur ne fait pas partie de la solution nécessaire si l’état pertinent peut être initialisé directement.<sup>[[7]](#references)</sup>

Voici un workflow pratique :<sup>[[7]](#references)</sup>

1. Inventoriez les sections exécutables et de données, les relocalisations et les références croisées. Extrayez les tables candidates de `.rodata` en préservant l’ordre des octets et la largeur des éléments.
2. Identifiez la dernière routine qui écrit le texte en clair ou le buffer de sortie. Notez ses entrées, les tables référencées, les appels importés et l’état global requis.
3. Ne traduisez que ces opérations en un modèle Python à largeur fixe. Si la tranche dépend encore d’un trop grand nombre d’éléments d’état, invoquez la routine avec Unicorn, QEMU ou un débogueur, et interceptez les imports non pertinents au lieu d’émuler tout le programme.
4. Vérifiez que l’extracteur dérive réellement sa sortie du binaire fourni : supprimez les replis silencieux, recherchez les réponses intégrées et testez-le sur des builds inconnus présentant des chaînes, clés, identifiants, dispositions et graines d’obfuscation différents.

Voici quelques commandes utiles pour un premier passage :<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Détecter les expressions MBA déguisées en constantes

Une expression sur un octet apparemment dépendante de l’entrée peut annuler complètement cette dernière. Après avoir extrait ses tables, évaluez l’expression sur l’ensemble du domaine 8 bits ; un ensemble de sorties réduit à un seul élément prouve que cet octet est constant, sans qu’il soit nécessaire de retrouver la machine à états qui l’entoure.<sup>[[7]](#references)</sup>

```python
def mba(a, b, c, d, e, x):
    return ((((a | (~x & 0xff)) & c) +
             ((x | b) & d)) ^ e) & 0xff

decoded = bytearray()
for row in zip(A, B, C, D, E):
    outputs = {mba(*row, x) for x in range(256)}
    if len(outputs) != 1:
        raise ValueError("expression depends on x")
    decoded.append(outputs.pop())
print(decoded)
```

Conservez le masque final, car l’addition d’origine entraîne un retour à zéro à la largeur d’un octet. Pour un domaine plus large, demandez à un solveur SMT si `f(x1) != f(x2)` est satisfaisable pour deux entrées symboliques de même largeur : `unsat` prouve l’invariance, tandis que `sat` fournit un contre-exemple et signifie que l’entrée ne peut pas être écartée.<sup>[[7]](#references)</sup>

#### Reconnaître un décodage lié à l’environnement

Les vérifications anti-analyse ne provoquent pas nécessairement un branchement ou un crash. Un décodeur peut intégrer le résultat d’un capteur à un bit de clé, à une constante de prédicat opaque ou à l’état d’un dispatcher aplati, continuer normalement et produire un texte en clair plausible mais erroné dans un émulateur. Par conséquent, corriger uniquement les branches d’échec visibles ne suffit pas ; suivez les dépendances des données depuis les sondes de l’environnement jusqu’à l’état du décodeur, comparez la même slice sur l’appareil authentique et l’émulateur, et vérifiez comment forcer chaque résultat de capteur modifie le buffer final.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) est un simplificateur MBA pratique pour l’analyse de malware et le reverse engineering de binaires protégés. Il classe l’expression et la dirige vers des pipelines spécialisés au lieu d’appliquer une passe de réécriture générique à tout.<sup>[[2]](#references)</sup>

Utilisation rapide :

```bash
# Recover arithmetic from a logic-heavy MBA
cobra-cli --mba "(x&y)+(x|y)"
# x + y

# Preserve fixed-width wraparound semantics
cobra-cli --mba "(x&0xFF)+(x&0xFF00)" --bitwidth 16
# x

# Ask CoBRA to prove the rewrite with Z3
cobra-cli --mba "(a^b)+(a&b)+(a&b)" --verify
```

Cas utiles :

- **Linear MBA** : CoBRA évalue l’expression sur des entrées booléennes, en déduit une signature et lance en parallèle plusieurs méthodes de récupération, comme le pattern matching, la conversion en ANF et l’interpolation des coefficients.
- **Semilinear MBA** : les atomes masqués par des constantes sont reconstruits à l’aide d’une reconstruction partitionnée par bits afin de préserver la correction des régions masquées.
- **Polynomial/Mixed MBA** : les produits sont décomposés en éléments de base et les sous-expressions répétées peuvent être extraites dans des variables temporaires avant de simplifier la relation externe.

Exemple d’identité mixte qu’il vaut souvent la peine d’essayer de retrouver :

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Cela peut se réduire à :

```c
x * y
```

### Notes de reverse engineering

- Privilégiez l’exécution de CoBRA sur des **expressions IR relevées** ou sur la sortie du décompilateur, après avoir isolé le calcul exact.
- Utilisez explicitement `--bitwidth` lorsque l’expression provient d’opérations masquées ou de registres de largeur réduite.
- Si vous avez besoin d’une étape de preuve plus robuste, consultez les notes locales sur Z3 ici :

{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA est également fourni sous forme de plugin de passe **LLVM** (`libCobraPass.so`), utile pour normaliser les IR LLVM riches en MBA avant les passes d’analyse ultérieures.
- Les résidus mixtes de domaines sensibles aux retenues qui ne sont pas pris en charge doivent vous inciter à conserver l’expression d’origine et à analyser manuellement le chemin des retenues.

## Aplatissement du flot de contrôle à état XOR

Un flattener de type OLLVM peut stocker l’état du bloc de base courant dans deux registres 64 bits et le reconstituer avec XOR dans un dispatcher. Chaque bloc d’origine écrit la paire correspondant à son prochain état, puis revient au dispatcher. Un bloc conditionnel peut utiliser `CMOVcc` pour remplacer une moitié de la paire en fonction des flags du CPU ; suivre uniquement les instructions de branchement visibles ne permet donc pas de repérer les deux successeurs. Contrairement à un dispatcher à saut indirect, cette structure peut utiliser uniquement des arcs de retour directs.<sup>[[19]](#references)[[20]](#references)</sup>

Pour retrouver le graphe, repérez l’arbre de comparaisons du dispatcher et les deux registres d’état, associez chaque état XOR comparé à son bloc cible, puis remontez les écritures atteignantes de la paire de registres dans chaque bloc d’origine. Pour les écritures conditionnelles, incluez l’instruction qui définit les flags et les deux résultats de `CMOVcc`. Remplacez la sortie du dispatcher de chaque bloc par son successeur direct résolu ou par une branche conditionnelle ; le dispatcher devient alors inaccessible sans modifier le binaire. Il s’agit d’une approche sur l’ensemble du CFG ; si un seul décodeur vous intéresse, le [workflow d’analyse de tranche d’exécution ciblée](#bypass-flattened-control-flow-with-a-narrow-execution-slice) ci-dessus peut être plus rapide.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatise cette structure dans Binary Ninja. Copiez `plugins/DispatchThis` dans le répertoire des plugins utilisateur de Binary Ninja, puis redémarrez. Pour la fonction concernée, ouvrez **Function Settings** et sélectionnez `OLLVM_XOR_64` ; si l’analyse ne démarre pas, utilisez **Analysis → Reanalyze All Functions**. Ce mode réécrit les arêtes de flot de contrôle MLIL, pas les octets du fichier, et ne nécessite ni Z3 ni le résolveur de sauts indirects. Il a été testé avec Binary Ninja 5.3.9757+ ; il ne supprime pas les écritures d’état mortes dans chaque bloc, ne les confondez donc pas avec des transitions encore actives.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Cet obfuscateur remplace les opérations du programme par des séquences d’instructions basées sur `mov` et utilise la gestion des signaux et des exceptions pour modifier le flot de contrôle. Pour plus de détails :

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Pour les binaires pris en charge, [demovfuscator](https://github.com/kirschju/demovfuscator) peut déobfusquer le résultat. Il a plusieurs dépendances.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Et [installez keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si vous participez à un **CTF, cette méthode de contournement pour trouver le flag** pourrait vous être très utile : [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Pour trouver le **point d'entrée**, recherchez les fonctions contenant `::main`, comme ici :

![Trouver un point d'entrée Rust dans Ghidra en recherchant les noms de fonctions contenant deux-points deux-points main](<../../images/image (1080).png>)

Dans cet exemple, le binaire s'appelait authenticator ; il est donc assez évident que c'est la fonction main intéressante.\
Avec le **nom** des **fonctions** appelées, recherchez-les sur **Internet** pour découvrir leurs **entrées** et leurs **sorties**.

### Récupérer les chaînes Rust depuis un firmware ELF

Dans les binaires **ELF Rust**, de nombreuses chaînes statiques ne sont pas référencées par des pointeurs terminés par un octet NUL, comme en C. Une disposition courante de `rustc` utilise un **tuple pointeur/longueur** dans **`.data.rel.ro`**, qui pointe vers le véritable bloc de chaînes stocké dans **`.rodata`** :

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Cela signifie que `strings` ou l’analyse par défaut de Ghidra peut fusionner des chaînes adjacentes ou ne pas détecter du tout les références croisées.<sup>[[3]](#references)</sup>

Flux de travail rapide :

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Récupérez l’adresse virtuelle et la taille de **`.rodata`**.
2. Énumérez **`.data.rel.ro`** un mot à la fois.
3. Traitez toute valeur comprise dans la plage d’adresses de `.rodata` comme un pointeur candidat vers une chaîne.
4. Traitez le mot suivant comme la longueur candidate.
5. Appliquez des filtres de cohérence (par exemple, conservez les longueurs comprises entre **4** et **100** octets).
6. Lisez exactement `length` octets depuis `.rodata` au lieu de parcourir les données jusqu’à `0x00`.

Logique minimale de l’extracteur :

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

C'est particulièrement utile pour la rétro-ingénierie de firmware, car les chaînes Rust récupérées révèlent souvent des **routes HTTP, des noms RPC, des messages de journalisation, des assertions, des noms de fichiers, des clés de configuration, des gestionnaires de commandes et de la logique liée à l'authentification**.

Si Ghidra ne détecte pas ces chaînes, exécutez un script/plugin personnalisé qui applique la même heuristique et crée des données de chaîne aux offsets `.rodata` référencés. Les outils `rust-strings` et `RustStrings.py` publiés par Pen Test Partners sont de bonnes références pour adapter cette idée à d'autres **tailles de mot, ordres des octets et dispositions de sections**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Pour les binaires compilés avec Delphi, vous pouvez utiliser [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si vous devez faire la rétro-ingénierie d'un binaire Delphi, je vous suggère d'utiliser le plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Appuyez sur **Alt+F7** dans IDA pour charger un plugin Python, puis sélectionnez le fichier du plugin.

Ce plugin exécutera le binaire et résoudra dynamiquement les noms des fonctions au début du débogage. Après avoir lancé le débogage, appuyez de nouveau sur le bouton Start (le bouton vert ou f9) : un point d'arrêt sera atteint au début du code réel.

Si vous cliquez sur un bouton dans l'application graphique, le débogueur peut s'arrêter dans la fonction appelée par ce bouton.

## Golang

Pour les binaires Go ordinaires, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) peut récupérer les structures d'exécution et améliorer les noms des fonctions dans IDA. Chargez son plugin Python avec **Alt+F7**.

Si vous devez faire la rétro-ingénierie d'un binaire Golang, je vous suggère d'utiliser le plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Appuyez sur **Alt+F7** dans IDA pour charger un plugin Python, puis sélectionnez le fichier du plugin.

Cela résoudra les noms des fonctions.

### Récupérer les métadonnées sans la table des symboles

Un exécutable Go dépouillé de ses symboles a toujours besoin de métadonnées d'exécution pour associer les compteurs de programme aux fonctions. [GoReSym](https://github.com/mandiant/GoReSym) localise et analyse des structures telles que `pclntab` et `moduledata` à l'aide de code dérivé du runtime Go. Il peut ainsi récupérer les limites des fonctions, les noms, les chemins sources, les types et les détails de compilation sans dépendre de la table des symboles habituelle.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Un obfuscateur peut laisser ces structures utilisables tout en remplaçant les noms récupérés. Garble, par exemple, hache les identifiants et les chemins de packages et supprime les informations de build, de module et de débogage.<sup>[[12]](#references)</sup> Le token obfusqué d’un package doit rester cohérent entre les fonctions de ce package. Regroupez les fonctions par token répété, déduisez un package à partir de ses fonctions appelées, de ses chaînes et de ses API, puis propagez ce libellé de package à l’ensemble du groupe.<sup>[[13]](#references)</sup>

### Récupérer les noms Garble avec GoResolver

[GoResolver](https://github.com/volexity/GoResolver) combine l’extraction de symboles à l’exécution, la génération de références propres et la mise en correspondance de graphes de flot de contrôle (CFG). Suivez cette séquence :<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifiez la version du compilateur.** Essayez d’abord `BuildInfo` et les chaînes de version intégrées. Si l’obfuscateur les a supprimées, comparez des portions du runtime Go intégré avec des runtimes de référence versionnés. Dans les tests de Volexity, environ `2%` du runtime suffisait à distinguer les versions majeures de Go. Considérez cela comme une optimisation empirique, et non comme un seuil universel.<sup>[[13]](#references)</sup>
2. **Construisez des références correspondantes.** Générez des binaires propres pour la version de Go identifiée, l’architecture cible et les bibliothèques probables. La correspondance de la chaîne d’outils réduit les différences de CFG générées par le compilateur.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Comparez les fonctions.** GoGrapher met en correspondance les CFG des fonctions et produit des scores normalisés de `0.0` à `1.0`. La mise en correspondance des blocs de base repose sur une comparaison pondérée d’instructions similaires. Les correspondances très fiables relient les fonctions randomisées à l’implémentation propre. Les correspondances moins fiables peuvent tout de même permettre d’identifier un package ou un module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Validez et importez.** Confirmez les noms proposés à l’aide des relations d’appel, des constantes, des chaînes et des effets de bord, puis importez le rapport JSON avec le plugin GoResolver pour IDA ou Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Installez la chaîne d’outils et exécutez l’extracteur et le comparateur de graphes combinés :<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

Le seuil de correspondance significative par défaut est `0.9`. Les options `--extract` et `--graph` permettent d’isoler l’une ou l’autre étape, tandis que le comportement par défaut exécute les deux, car les métadonnées runtime récupérées et les indices du CFG se complètent.<sup>[[10]](#references)</sup> Les scores du CFG sont heuristiques : l’inlining, les options de build, l’architecture et les différences de version des bibliothèques peuvent modifier la forme du graphe. Il vaut donc mieux conserver les fonctions non résolues plutôt que de leur attribuer des noms avec un faible niveau de confiance.<sup>[[13]](#references)</sup>

### Récupération de la table de chaînes Go

Les binaires Go placent les octets des chaînes de tous les packages liés dans une table contiguë. Les entrées ne sont pas terminées par NUL et les structures runtime n’exposent ni la base ni la taille de la table. Toutefois, le compilateur classe les entrées d’abord par longueur, puis par ordre alphabétique, sur tous les systèmes d’exploitation et toutes les architectures. Après avoir trouvé une entrée, un analyste peut donc parcourir les entrées adjacentes et utiliser les références croisées de données pour associer les chaînes au code.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatise ce processus dans IDA Pro et Ghidra. Attendez que l’auto-analyse soit terminée, car le plugin s’appuie sur les références croisées du segment de données. Son point d’ancrage par défaut est la chaîne runtime `entersyscall`. Il peut ensuite analyser dans les deux sens, définir les chaînes récupérées dans la base de données et exporter un mapping JSON des chaînes vers les fonctions qui y font référence.<sup>[[14]](#references)</sup>

Filtrez le rapport selon le package de la fonction qui fait référence à la chaîne afin de séparer le code de l’application ou du malware du bruit généré par les bibliothèques liées. Cette technique ne permet pas de récupérer les littéraux détruits par l’obfuscation, comme la transformation `-literals` de Garble. Elle peut toutefois organiser les chaînes runtime qui restent non obfusquées.<sup>[[14]](#references)[[15]](#references)</sup>

### Récupération des types runtime Go

Go intègre des informations sur les types runtime utilisées par des fonctionnalités telles que le garbage collector. Lorsque les informations de build sont supprimées ou que le désassembleur n’analyse pas ces métadonnées, les instructions peuvent sembler charger des adresses de données arbitraires et la région cible reste sans type. Récupérer ces métadonnées transforme ces adresses en références de type lisibles et facilite la compréhension des capacités du package.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) peut extraire les symboles et analyser les types runtime pour générer un rapport JSON. La CLI actuelle utilise la sous-commande `resolve` :<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

L’option `-y`/`--types` active l’analyse des types. Importez le rapport à l’aide du plugin IDA Pro ou Ghidra de GoResolver pour définir les types récupérés et appliquer leurs références dans la base de données d’analyse. Dans le format de rapport introduit avec cette fonctionnalité, si vous omettez `-y`, les membres correspondant à l’adresse RTTI et aux types récupérés restent nuls.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver prend en charge les échantillons PE, ELF et Mach-O pour x86, AMD64, ARM et ARM64. Le même flux de travail s’applique donc aux binaires Go de Windows, Linux et macOS.<sup>[[10]](#references)</sup>

## Python compilé

Cette page explique comment récupérer le code Python à partir d’un binaire Python compilé ELF/EXE :

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Si vous obtenez le **binaire** d’un jeu GBA, vous pouvez utiliser différents outils pour l’**émuler** et le **déboguer** :

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Téléchargez la version debug_) - Contient un debugger avec interface
- [**mgba** ](https://mgba.io)- Contient un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

Dans [**no$gba**](https://problemkaputt.de/gba.htm), vous pouvez voir comment appuyer sur les **boutons** de la Game Boy Advance dans _**Options --> Emulation Setup --> Controls**_** **

![Configuration des contrôles de no$gba montrant les correspondances des boutons de la Game Boy Advance](<../../images/image (581).png>)

Lorsqu’on appuie dessus, chaque **touche a une valeur** qui permet de l’identifier :

```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```

Ainsi, dans ce type de programme, la partie intéressante sera **la manière dont le programme traite l’entrée utilisateur**. À l’adresse **0x4000130**, vous trouverez la fonction couramment rencontrée : **KEYINPUT**.

![Vue de Ghidra d’un binaire GBA référençant KEYINPUT à l’adresse 0x4000130](<../../images/image (447).png>)

Dans l’image précédente, vous pouvez voir que la fonction est appelée depuis **FUN_080015a8** (adresses : _0x080015fa_ et _0x080017ac_).

Dans cette fonction, après quelques opérations d’initialisation (sans importance) :

```c
void FUN_080015a8(void)

{
  ushort uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  ushort uVar4;
  int iVar5;
  ushort *puVar6;
  undefined *local_2c;

  DISPCNT = 0x1140;
  FUN_08000a74();
  FUN_08000ce4(1);
  DISPCNT = 0x404;
  FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
  FUN_08000354(&DAT_030000dc,0x3c);
  uVar4 = DAT_030004d8;
```

On trouve ce code :

```c
  do {
    DAT_030004da = uVar4; //This is the last key pressed
    DAT_030004d8 = KEYINPUT | 0xfc00;
    puVar6 = &DAT_0200b03c;
    uVar4 = DAT_030004d8;
    do {
      uVar2 = DAT_030004dc;
      uVar1 = *puVar6;
      if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```

Le dernier if vérifie que **`uVar4`** fait partie des **dernières touches** et qu’il ne s’agit pas de la touche actuelle, ce qui correspond au relâchement d’un bouton (la touche actuelle est stockée dans **`uVar1`**).

```c
        if (uVar1 == 4) {
          DAT_030000d4 = 0;
          uVar3 = FUN_08001c24(DAT_030004dc);
          FUN_08001868(uVar2,0,uVar3);
          DAT_05000000 = 0x1483;
          FUN_08001844(&DAT_0200ba18);
          FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
          DAT_030000d8 = 0;
          uVar4 = DAT_030004d8;
        }
        else {
          if (uVar1 == 8) {
            if (DAT_030000d8 == 0xf3) {
              DISPCNT = 0x404;
              FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
              FUN_08000354(&DAT_030000dc,0x3c);
              uVar4 = DAT_030004d8;
            }
          }
          else {
            if (DAT_030000d4 < 8) {
              DAT_030000d4 = DAT_030000d4 + 1;
              FUN_08000864();
              if (uVar1 == 0x10) {
                DAT_030000d8 = DAT_030000d8 + 0x3a;
```

Dans le code précédent, on voit que nous comparons **uVar1** (l’emplacement où se trouve la **valeur du bouton pressé**) à certaines valeurs :

- D’abord, on le compare à la **valeur 4** (bouton **SELECT**) : dans le challenge, ce bouton efface l’écran.
- Ensuite, on compare la valeur à **8** (bouton **START**) ; dans ce challenge, cette branche vérifie si le code saisi est valide.
  - Dans ce cas, la variable **`DAT_030000d8`** est comparée à 0xf3 et, si les valeurs sont identiques, du code est exécuté.
- Dans tous les autres cas, un compteur (`DAT_030000d4`) est vérifié puis incrémenté.\
  Tant que le compteur est inférieur à 8, les valeurs des touches pressées sont additionnées dans `DAT_030000d8`.

Ainsi, dans ce challenge, connaissant les valeurs des boutons, il fallait **appuyer sur une combinaison de moins de 8 boutons dont la somme obtenue est égale à 0xf3.**

**Référence pour ce tutoriel :** [writeup archivé du challenge Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cours

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (désobfuscation de binaires)

## References

- [1] [Simplifier l’obfuscation MBA avec CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Dépôt Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Décodage des chaînes Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - chaînes Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutoriel de reverse engineering GBA (archivé)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Vaincre le reverse engineering assisté par l’IA, ou du moins essayer](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Une approche de comparaison des graphes de flot de contrôle basée sur la mise en correspondance des blocs de base](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Dépôt Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mécanisme d’obfuscation Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver : utiliser la similarité des graphes de flot de contrôle pour désobfusquer automatiquement les binaires Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Dépôt Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em : mises à jour des outils Golang de Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA : faire du reverse engineering sur n’importe quoi](https://github.com/morluto/rea)
- [17] [Analyse du code managé de REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Guide de REA CLI et des éléments de preuve](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis : workflow de déflattening du flot de contrôle avec Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire : intrusion zero-day dans PaperCut MF, chargeur Java, web shell et AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README d’IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implémentation du serveur bridge IDA](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implémentation du serveur bridge Ghidra](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) se lie à l’adresse générique](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore : boîte à outils de reverse engineering Godot](https://github.com/figurophobia/gore)
- [26] [Implémentation de la récupération de clé de gore](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [Format de blob chiffré de gore](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [Implémentation des commandes et de la récupération de gore](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
