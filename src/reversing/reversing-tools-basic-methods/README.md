# Outils de reversing & méthodes de base

{{#include ../../banners/hacktricks-training.md}}

## Outils de reversing basés sur ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Décompilateur Wasm / compilateur Wat

Online:

- Utilise [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) pour **décompiler** de wasm (binaire) vers wat (texte clair)
- Utilise [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) pour **compiler** de wat vers wasm
- tu peux aussi essayer d'utiliser [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) pour décompiler

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Décompilateur .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek est un décompilateur qui **décompile et examine plusieurs formats**, y compris les **libraries** (.dll), les **Windows metadata file**s (.winmd) et les **executables** (.exe). Une fois décompilé, un assembly peut être enregistré comme projet Visual Studio (.csproj).

L'intérêt ici est que si un code source perdu doit être restauré à partir d'un assembly legacy, cette action peut faire gagner du temps. De plus, dotPeek fournit une navigation pratique à travers le code décompilé, ce qui en fait l'un des outils parfaits pour l'**analyse d'algorithmes Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Avec un modèle d'add-in complet et une API qui étend l'outil pour répondre exactement à tes besoins, .NET reflector fait gagner du temps et simplifie le développement. Voyons la multitude de services de reverse engineering que cet outil fournit :

- Donne un aperçu de la façon dont les données circulent à travers une library ou un composant
- Donne un aperçu de l'implémentation et de l'utilisation des langages et frameworks .NET
- Trouve des fonctionnalités non documentées et non exposées pour tirer davantage parti des APIs et technologies utilisées.
- Trouve les dépendances et les différents assemblies
- Localise l'emplacement exact des erreurs dans ton code, dans les composants tiers et dans les libraries.
- Débogue dans le code source de tout le code .NET avec lequel tu travailles.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Tu peux l'avoir sur n'importe quel OS (tu peux l'installer directement depuis VSCode, pas besoin de télécharger le git. Clique sur **Extensions** et **search ILSpy**).\
Si tu dois **décompiler**, **modifier** et **recompiler** à nouveau, tu peux utiliser [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou un fork maintenu activement, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** pour changer quelque chose à l'intérieur d'une fonction).

### Journalisation DNSpy

Afin de faire en sorte que **DNSpy enregistre certaines informations dans un fichier**, tu peux utiliser cet extrait :
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Afin de déboguer du code avec DNSpy, vous devez :

Tout d’abord, modifier les **Assembly attributes** liés au **debugging** :

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

De :
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
À :
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Et cliquez sur **compile** :

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Puis enregistrez le nouveau fichier via _**File >> Save module...**_ :

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Ceci est nécessaire car si vous ne le faites pas, à **runtime** plusieurs **optimisations** seront appliquées au code et il est possible qu’en débogage un **break-point ne soit jamais atteint** ou que certaines **variables n’existent pas**.

Ensuite, si votre application .NET est **run** par **IIS**, vous pouvez la **restart** avec :
```
iisreset /noforce
```
Then, in order to start debugging you should close all the opened files and inside the **Debug Tab** select **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Then, in order to start debugging you should close all the opened files and inside the Debug Tab select Attach to Process](<../../images/image (318).png>)

Then select **w3wp.exe** to attach to the **IIS server** and click **attach**:

![DNSpy Logging - DNSpy Debugging: Then select w3wp.exe to attach to the IIS server and click attach](<../../images/image (113).png>)

Now that we are debugging the process, it's time to stop it and load all the modules. First click on _Debug >> Break All_ and then click on _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (834).png>)

Click any module on **Modules** and select **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Click any module on Modules and select Open All Modules](<../../images/image (922).png>)

Right click any module in **Assembly Explorer** and click **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Right click any module in Assembly Explorer and click Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Select " Suspend on library load/unload "](<../../images/image (868).png>)

- Configure the **parameters** of the execution putting the **path to the DLL** and the function that you want to call:

![Debugging DLLs - Using IDA: Configure the parameters of the execution putting the path to the DLL and the function that you want to call](<../../images/image (704).png>)

Then, when you start debugging **the execution will be stopped when each DLL is loaded**, then, when rundll32 load your DLL the execution will be stopped.

But, how can you get to the code of the DLL that was lodaded? Using this method, I don't know how.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Notice that when the execution is stopped by any reason in win64dbg you can see **in which code you are** looking in the **top of the win64dbg window**:

![Using IDA - Using x64dbg/x32dbg: Notice that when the execution is stopped by any reason in win64dbg you can see in which code you are looking in the top of the win64dbg window](<../../images/image (842).png>)

Then, looking to this ca see when the execution was stopped in the dll you want to debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is a useful program to find where important values are saved inside the memory of a running game and change them. More info in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is a front-end/reverse engineering tool for the GNU Project Debugger (GDB), focused on games. However, it can be used for any reverse-engineering related stuff

[**Decompiler Explorer**](https://dogbolt.org/) is a web front-end to a number of decompilers. This web service lets you compare the output of different decompilers on small executables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) will **allocate** the **shellcode** inside a space of memory, will **indicate** you the **memory address** were the shellcode was allocated and will **stop** the execution.\
Then, you need to **attach a debugger** (Ida or x64dbg) to the process and put a **breakpoint the indicated memory address** and **resume** the execution. This way you will be debugging the shellcode.

The releases github page contains zips containing the compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
You can find a slightly modified version of Blobrunner in the following link. In order to compile it just **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)is very similar to blobrunner. It will **allocate** the **shellcode** inside a space of memory, and start an **eternal loop**. You then need to **attach the debugger** to the process, **play start wait 2-5 secs and press stop** and you will find yourself inside the **eternal loop**. Jump to the next instruction of the eternal loop as it will be a call to the shellcode, and finally you will find yourself executing the shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it is very similar to blobrunner. It will allocate the shellcode inside a space of memory, and start an...](<../../images/image (509).png>)

You can download a compiled version of [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is the GUI of radare. Using cutter you can emulate the shellcode and inspect it dynamically.

Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it decompiled it correctly, but when I opened it as a shellcode it didn't:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it...](<../../images/image (562).png>)

In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically start the emulation from there:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (387).png>)

You can see the stack for example inside a hex dump:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: You can see the stack for example inside a hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

You should try [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
It will tell you things like **which functions** is the shellcode using and if the shellcode is **decoding** itself in memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg dispose également d'un lanceur graphique où vous pouvez sélectionner les options souhaitées et exécuter le shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg also counts with a graphical launcher where you can select the options you want and...](<../../images/image (258).png>)

L'option **Create Dump** va dumper le shellcode final si une modification est effectuée dynamiquement en mémoire sur le shellcode (utile pour télécharger le shellcode décodé). L'option **start offset** peut être utile pour démarrer le shellcode à un offset spécifique. L'option **Debug Shell** est utile pour déboguer le shellcode à l'aide du terminal scDbg (cependant, je trouve que l'une des options expliquées précédemment est meilleure pour cela, car vous pourrez utiliser Ida ou x64dbg).

### Disassembling using CyberChef

Téléchargez votre fichier shellcode comme entrée et utilisez la recette suivante pour le décompiler : [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

L'obfuscation **Mixed Boolean-Arithmetic (MBA)** masque des expressions simples comme `x + y` derrière des formules qui mélangent des opérateurs arithmétiques (`+`, `-`, `*`) et bit à bit (`&`, `|`, `^`, `~`, décalages). L'important est que ces identités ne sont généralement correctes que sous une **arithmétique modulaire à largeur fixe**, donc les retenues et les dépassements comptent :
```c
(x ^ y) + 2 * (x & y) == x + y
```
Si vous simplifiez ce type d’expression avec des outils algébriques génériques, vous pouvez facilement obtenir un mauvais résultat parce que la sémantique de bit-width a été ignorée.

### Flux de travail pratique

1. **Conservez le bit-width original** provenant du code/IR/decompiler output lifté (`8/16/32/64` bits).
2. **Classifiez l’expression** avant d’essayer de la simplifier :
- **Linear** : sommes pondérées d’atomes bitwise
- **Semilinear** : linear plus des masques constants comme `x & 0xFF`
- **Polynomial** : des produits apparaissent
- **Mixed** : les produits et la logique bitwise sont imbriqués, souvent avec des sous-expressions répétées
3. **Vérifiez chaque réécriture candidate** avec des tests aléatoires ou une preuve SMT. Si l’équivalence ne peut pas être prouvée, conservez l’expression originale au lieu de deviner.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) est un simplificateur MBA pratique pour l’analyse de malware et le reversing de protected-binary. Il classe l’expression et l’envoie vers des pipelines spécialisés au lieu d’appliquer un seul passage de réécriture générique à tout.

Utilisation rapide:
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
Cas d'utilisation utiles :

- **Linear MBA** : CoBRA évalue l'expression sur des entrées booléennes, dérive une signature, et lance plusieurs méthodes de récupération comme le pattern matching, la conversion ANF, et l'interpolation de coefficients.
- **Semilinear MBA** : les atomes masqués par des constantes sont reconstruits avec une reconstruction bit-partitioned afin que les régions masquées restent correctes.
- **Polynomial/Mixed MBA** : les produits sont décomposés en cores et les sous-expressions répétées peuvent être remontées dans des temporaries avant de simplifier la relation externe.

Exemple d'une identité mixed généralement utile à tenter de recover :
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Cela peut se réduire à :
```c
x * y
```
### Reversing notes

- Préférez exécuter CoBRA sur des **lifted IR expressions** ou sur la sortie du decompiler après avoir isolé exactement le calcul.
- Utilisez `--bitwidth` explicitement lorsque l'expression provient d'arithmétique masquée ou de registres étroits.
- Si vous avez besoin d'une étape de preuve plus forte, consultez les notes locales Z3 ici :


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA est aussi fourni comme **LLVM pass plugin** (`libCobraPass.so`), ce qui est utile lorsque vous voulez normaliser du LLVM IR fortement MBA avant d'autres passes d'analyse.
- Les résidus mixed-domain dépendants du carry non pris en charge doivent être considérés comme un signal qu'il faut conserver l'expression originale et raisonner manuellement sur le chemin du carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

This obfuscator **modifies all the instructions for `mov`**(yeah, really cool). It also uses interruptions to change executions flows. For more information about how does it works:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

If you are lucky [demovfuscator](https://github.com/kirschju/demovfuscator) will deofuscate the binary. It has several dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Et installez [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si vous jouez à un **CTF, ce contournement pour trouver le flag** peut être très utile : [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Pour trouver le **point d'entrée**, cherchez les fonctions avec `::main` comme dans :

![Movfuscator - Rust: To find the entry point search the functions by ::main like in](<../../images/image (1080).png>)

Dans ce cas, le binaire s'appelait authenticator, donc il est assez évident qu'il s'agit de la fonction main intéressante.\
En ayant le **nom** des **fonctions** appelées, cherchez-les sur **Internet** pour apprendre leurs **entrées** et **sorties**.

### Recovering Rust strings from ELF firmware

Dans les binaires **Rust ELF**, de nombreuses chaînes statiques ne sont pas référencées comme des pointeurs de style C terminés par NUL. Un agencement courant de **rustc** est un **tuple pointeur/longueur** dans **`.data.rel.ro`** pointant vers le véritable blob de chaîne stocké dans **`.rodata`** :
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Cela signifie que `strings` ou l’analyse Ghidra par défaut peuvent fusionner des chaînes adjacentes ou manquer complètement des références croisées.

Workflow rapide :
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Obtenez l’adresse virtuelle et la taille de **`.rodata`**.
2. Énumérez **`.data.rel.ro`** un mot à la fois.
3. Traitez toute valeur à l’intérieur de la plage d’adresses `.rodata` comme un pointeur de chaîne candidat.
4. Traitez le mot suivant comme la longueur candidate.
5. Appliquez des filtres de cohérence (par exemple, gardez les longueurs entre **4** et **100** octets).
6. Lisez exactement `length` octets depuis `.rodata` au lieu de scanner jusqu’à `0x00`.

Logique minimale d’extraction:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Ceci est particulièrement utile dans le reversing de firmware, car les chaînes Rust récupérées révèlent souvent **des routes HTTP, des noms RPC, des messages de log, des assertions, des noms de fichiers, des clés de config, des gestionnaires de commandes et de la logique liée à l’auth**.

Si Ghidra manque ces chaînes, exécutez un script/plugin personnalisé qui applique la même heuristique et crée des données de chaîne aux offsets `.rodata` référencés. Les outils publiés `rust-strings` et `RustStrings.py` de Pen Test Partners sont de bonnes références pour adapter l’idée à d’autres **tailles de mot, endianness et layouts de sections**.

## **Delphi**

Pour les binaires compilés avec Delphi, vous pouvez utiliser [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si vous devez faire du reversing d’un binaire Delphi, je vous suggère d’utiliser le plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Appuyez simplement sur **ATL+f7** (import python plugin dans IDA) et sélectionnez le plugin python.

Ce plugin exécutera le binaire et résoudra les noms des fonctions dynamiquement au début du debugging. Après avoir lancé le debugging, appuyez à nouveau sur le bouton Start (le vert ou f9) et un breakpoint sera atteint au début du vrai code.

C’est aussi très intéressant, car si vous appuyez sur un bouton dans l’application graphique, le debugger s’arrêtera dans la fonction exécutée par ce bouton.

## Golang

Si vous devez faire du reversing d’un binaire Golang, je vous suggère d’utiliser le plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Appuyez simplement sur **ATL+f7** (import python plugin dans IDA) et sélectionnez le plugin python.

Cela résoudra les noms des fonctions.

## Python compilé

Sur cette page, vous pouvez trouver comment récupérer le code Python à partir d’un binaire Python compilé ELF/EXE :


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Si vous obtenez le **binaire** d’un jeu GBA, vous pouvez utiliser différents outils pour l’**émuler** et le **debug** :

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Téléchargez la version debug_) - Contient un debugger avec interface
- [**mgba** ](https://mgba.io)- Contient un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

Dans [**no$gba**](https://problemkaputt.de/gba.htm), dans _**Options --> Emulation Setup --> Controls**_** ** vous pouvez voir comment appuyer sur les **boutons** de la Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Lorsqu’on appuie dessus, chaque **touche a une valeur** pour l’identifier :
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
Donc, dans ce type de programme, la partie intéressante sera **comment le programme traite l'entrée utilisateur**. À l'adresse **0x4000130**, vous trouverez la fonction couramment présente : **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

Dans l'image précédente, vous pouvez voir que la fonction est appelée depuis **FUN_080015a8** (adresses : _0x080015fa_ et _0x080017ac_).

Dans cette fonction, après quelques opérations d'initialisation (sans aucune importance) :
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
Ce code a été trouvé :
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
Le dernier `if` vérifie que **`uVar4`** est dans les **dernières Keys** et n’est pas la clé actuelle, aussi appelé relâcher un bouton (la clé actuelle est stockée dans **`uVar1`**).
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
Dans le code précédent, on peut voir que nous comparons **uVar1** (l’endroit où se trouve **la valeur du bouton pressé**) avec certaines valeurs :

- D’abord, elle est comparée avec la **valeur 4** (**SELECT** button) : Dans le challenge, ce button efface l’écran
- Ensuite, elle est comparée avec la **valeur 8** (**START** button) : Dans le challenge, cela vérifie si le code est valide pour obtenir le flag.
- Dans ce cas, la var **`DAT_030000d8`** est comparée à 0xf3 et si la valeur est la même, un certain code est exécuté.
- Dans tous les autres cas, un cont (**`DAT_030000d4`**) est vérifié. C’est un cont parce qu’il ajoute 1 juste après l’entrée dans le code.\
**Si** c’est inférieur à 8, quelque chose impliquant l’**addition** de valeurs à **`DAT_030000d8`** est fait (en gros, il additionne les valeurs des touches pressées dans cette variable tant que le cont est inférieur à 8).

Donc, dans ce challenge, en connaissant les valeurs des buttons, il fallait **appuyer sur une combinaison de longueur inférieure à 8 dont l’addition résultante est 0xf3.**

**Reference for this tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)

{{#include ../../banners/hacktricks-training.md}}
