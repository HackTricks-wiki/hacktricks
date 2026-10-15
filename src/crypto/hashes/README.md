# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Motifs CTF courants

- « Signature » correspond en réalité à `hash(secret || message)` → length extension.
- Les hashes de mots de passe sans salt → cracking répété plus rapide et attaques par recherche pré-calculée.
- Confusion entre hash et MAC (hash != authentification).

## Recherches de hashes MD5 à entrée choisie

Ces exemples Python recherchent deux motifs de sortie différents : un suffixe MD5 choisi et une valeur MD5 commençant par `0e` et suivie uniquement de chiffres. Le second motif est pertinent lorsqu’une application compare des chaînes numériques de manière permissive ; voir le comportement spécifique à PHP et les réserves concernant les versions dans [les comparaisons permissives de PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute force de suffixe de hash MD5

```python
import hashlib

target = '2f2e2e' #/..
candidate = 0
while True:
    plaintext = str(candidate)
    hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
    if hash[-1*(len(target)):] == target: #End in target
        print('plaintext:"' + plaintext + '", md5:' + hash)
        break
    candidate = candidate + 1
```

### Génération de hash MD5 0e pour des comparaisons laxistes

```python
#From isHaacK
import hashlib
from multiprocessing import Process, Queue, cpu_count


def loose_comparison(queue, num):
	target = '0e'
	plaintext = f"a_prefix{str(num)}a_suffix"
	hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()

	if hash[:len(target)] == target and not any(x in "abcdef" for x in hash[2:]):
		print('plaintext: ' + plaintext + ', md5: ' + hash)
		queue.put("done") # triggers program exit

def worker(queue, thread_i, threads):
	for num in range(thread_i, 100**50, threads):
		loose_comparison(queue, num)

def main():
	procs = []
	queue = Queue()
	threads = cpu_count() # 2

	for thread_i in range(threads):
		proc = Process(target=worker, args=(queue, thread_i, threads ))
		proc.daemon = True # kill all subprocess when main process exits.
		procs.append(proc)
		proc.start()

	while queue.empty(): # exits when a subprocess is done
		pass
	return 0

main()
```

## Hash length extension attack

### Technique

Une attaque par extension de longueur peut être possible lorsqu’un serveur calcule une « signature » comme suit :

`sig = HASH(secret || message)`

et utilise un hash Merkle-Damgård tel que MD5, SHA-1 ou SHA-256.

Si vous connaissez :

- `message`
- `sig`
- la fonction de hash
- (ou pouvez brute-forcer) `len(secret)`

Vous pouvez alors calculer une signature valide pour :

`message || padding || appended_data`

sans connaître le secret.<sup>[[1]](#references)</sup>

### Limitation importante : HMAC n’est pas affecté

Les attaques par extension de longueur s’appliquent aux constructions préfixées vulnérables telles que `HASH(secret || message)`. Elles ne permettent pas de compromettre la construction HMAC (par exemple, HMAC-SHA256), qui combine une clé avec des applications de hash internes et externes distinctes.<sup>[[1]](#references)[[2]](#references)</sup>

### Outils

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), bindings Python pour l’outil d’extension de longueur HashPump<sup>[[7]](#references)</sup>

### Bonne explication

[Tout ce qu’il faut savoir sur les attaques par extension de longueur de hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hachage de tuples ambigus et MAC

### Boundary-confusion attack

Les API de hash incrémental n’authentifient pas les limites entre les appels. `update(A); update(B)` calcule le hash de la même chaîne d’octets que `update(A + B)`. Par conséquent, hacher ou calculer un MAC sur une concaténation brute n’authentifie pas un tuple. Si les champs adjacents ont des longueurs variables, un attaquant peut répartir les octets différemment pour former un autre tuple sans trouver de collision dans le hash sous-jacent :<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Cela devient exploitable lorsque le vérificateur croit que le digest lie la signification des champs, mais qu’une entrée contrôlée par l’attaquant peut atteindre un autre parseur ou une autre étape du protocole qui attribue d’autres limites. Les commitments peuvent alors avoir plusieurs ouvertures, et les transcripts Fiat-Shamir peuvent être interprétés comme des énoncés différents. HMAC empêche [l’extension de longueur du hash](#hash-length-extension-attack), mais `HMAC(K, A || B)` présente toujours cette ambiguïté d’encodage des tuples, car les deux tuples produisent les mêmes octets de message.<sup>[[8]](#references)[[9]](#references)</sup>

Utilisez cette procédure d’audit pour vérifier si un encodage ambigu de tuple franchit une frontière de sécurité.<sup>[[8]](#references)[[9]](#references)</sup>

1. Repérez `HASH(A || B)`, `HMAC(K, A || B)` et les appels consécutifs à `update()`/`Write()` sur deux champs ou plus.
2. Repérez chaque champ contrôlé par l’attaquant ou de longueur variable. Essayez de déplacer des octets d’un côté à l’autre de chaque limite tout en conservant la concaténation complète. Incluez les champs vides.
3. Vérifiez les schémas de délimitation pour détecter les octets de délimitation que les entrées peuvent contenir, les divergences d’échappement et les conceptions qui n’encodent la longueur que de certains champs.
4. Suivez la manière dont chaque consommateur analyse les octets authentifiés. Un cas potentiel n’est pertinent que si une partition alternative modifie une décision de sécurité, un énoncé de preuve, un enregistrement, une transaction ou une ouverture de commitment. Des champs de largeur fixe ou une sérialisation canonique et injective empêchent cette attaque spécifique.
5. Vérifiez si le même digest encodé est accepté dans une autre version du protocole, un autre type de message, un autre round ou une autre application. Liez explicitement ces contextes au lieu de compter sur les appelants pour les maintenir séparés.

### SequenceHash et SequenceMAC

SequenceHash est une construction indépendante du hash pour les séquences de chaînes d’octets. Chaque opération `add()` est atomique : elle ajoute la valeur au hash interne, suivie d’un suffixe fixe de 16 octets indiquant la longueur en little-endian. Les valeurs vides restent des objets distincts. Un hash externe empêche l’exposition d’un état interne susceptible d’extension de longueur, tandis qu’une chaîne de personnalisation facultative fournit une séparation de domaine. Ne remplacez pas `add()` par les appels d’écriture ordinaires de l’API de hash sous-jacente.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Choisissez le paramètre de personnalisation dans le cadre de la définition du protocole, en fournissant suffisamment d’informations pour distinguer l’application, la version du protocole, le type de message et le tour. SequenceHash exige toujours que toutes les parties s’accordent sur l’ordre des champs, l’encodage des octets et la sérialisation canonique, et ne peut pas protéger un champ omis. Les ports doivent être vérifiés à l’aide des vecteurs de test intermédiaires et finaux de C2SP.<sup>[[8]](#references)[[11]](#references)</sup>

Pour l’authentification, SequenceMAC fournit la même interface d’encodage atomique et de personnalisation. Il exige une clé d’au moins 32 octets. Contrairement au prétraitement des clés de HMAC, ses en-têtes engagent la longueur exacte de la clé : une clé brute longue n’équivaut pas à son préhachage, et l’ajout d’octets nuls modifie la clé. Cette distinction est importante lorsque les composants acceptent des représentations de clés ou des métadonnées de longueur différentes.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

L’API Python ainsi que les implémentations équivalentes en Go et Rust sont disponibles à titre de référence, mais les implémentations du protocole doivent suivre la spécification C2SP actuelle plutôt que de recréer l’encodage à partir de ce résumé.<sup>[[8]](#references)[[10]](#references)</sup>

## Hachage et cracking de mots de passe

### Premières questions<sup>[[4]](#references)</sup>

- Est-il **salé** ? (recherchez les formats `salt$hash`)
- S’agit-il d’un **hachage rapide** (MD5/SHA1/SHA256) ou d’une **KDF lente** (bcrypt/scrypt/argon2/PBKDF2) ?
- Disposez-vous d’un **indice sur le format** (mode hashcat / format John) ?

### Flux de travail pratique<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifiez le hachage :
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. S’il n’est pas salé et qu’il est courant : essayez les bases de données en ligne et les outils d’identification de la section sur le flux de travail crypto.
3. Sinon, lancez le cracking :
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Erreurs courantes exploitables

- Même mot de passe réutilisé par plusieurs utilisateurs → cassez-en un, puis pivotez.
- Hachages tronqués / transformations personnalisées → normalisez et réessayez.
- Paramètres KDF faibles (par ex., peu d’itérations PBKDF2) → restent cassables.

### Oracle bcrypt à entrée choisie avec secret ajouté

Un utilitaire appelable qui renvoie `bcrypt(user_input || secret)` peut révéler des informations sur un secret ajouté si son implémentation bcrypt tronque silencieusement l’entrée après 72 **octets**. Une limite sur le nombre de caractères appliquée avant l’encodage UTF-8 ne garantit pas cette limite en octets : des caractères multioctets peuvent remplir l’entrée bcrypt tout en ne laissant de place que pour un petit préfixe du secret. Les entrées choisies et les hachages renvoyés peuvent alors permettre de vérifier hors ligne des octets de suffixe candidats. Cela nécessite de contrôler l’entrée de l’utilitaire, de connaître précisément sa transformation et son encodage, et que l’implémentation tronque effectivement l’entrée ; la présence d’un utilitaire appelable ou d’un hachage bcrypt ne suffit pas à établir cette chaîne. [pyca/bcrypt documente](https://github.com/pyca/bcrypt#maximum-password-length) que la fonction `hashpw` actuelle renvoie une erreur pour les entrées de plus de 72 octets, alors que les versions précédentes les tronquaient silencieusement. D’autres wrappers peuvent préhacher ou rejeter les entrées longues : vérifiez donc l’implémentation installée au lieu de supposer qu’elle tronque.

Utiliser un secret récupéré sur un autre compte exige également des preuves que le hachage exposé de ce compte a été généré avec le **même** secret et la même transformation, ainsi qu’un moyen distinct d’accéder aux identifiants ou de se connecter. Un utilitaire de hachage exécuté en tant que root ne doit être considéré comme un oracle que si l’utilisateur moins privilégié peut l’appeler selon la politique effective ; l’énumération passive de l’hôte n’a pas besoin de l’appeler ni de lui soumettre des mots de passe choisis.

## References

- [1] [SkullSecurity - Tout ce qu’il faut savoir sur les attaques par extension de longueur de hachage](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Code d’authentification de message par hachage à clé](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Aide-mémoire sur le stockage des mots de passe](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Exemples de hachages hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Options de ligne de commande de John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI : liaisons Python de `hashpumpy` pour HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - Spécification SequenceHash et SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash : le multihachage pour tous](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - Implémentation Python de SequenceHash](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - Vecteurs de test SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)
