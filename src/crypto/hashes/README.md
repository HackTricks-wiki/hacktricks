# Hashes, MACs et KDFs

{{#include ../../banners/hacktricks-training.md}}

## Patterns courants en CTF

- « Signature » correspond en réalité à `hash(secret || message)` → length extension.
- Hashes de mots de passe sans salt → cracking répété plus rapide et attaques par lookup précalculé.
- Confusion entre hash et MAC (hash != authentification).

## Recherche de hashes MD5 avec entrée choisie

Ces exemples Python recherchent deux motifs de sortie différents : un suffixe MD5 choisi et une valeur MD5 commençant par `0e` et suivie uniquement de chiffres. Le second motif est pertinent lorsqu’une application compare des chaînes numériques de manière souple ; consultez le comportement spécifique à PHP et les réserves concernant les versions dans [les comparaisons souples en PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute force d’un suffixe de hash MD5

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

### Génération de hash MD5 0e pour des comparaisons non strictes

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

et utilise une fonction de hachage Merkle-Damgård telle que MD5, SHA-1 ou SHA-256.

Si vous connaissez :

- `message`
- `sig`
- la fonction de hachage
- (ou pouvez deviner par force brute) `len(secret)`

vous pouvez calculer une signature valide pour :

`message || padding || appended_data`

sans connaître le secret.<sup>[[1]](#references)</sup>

### Limitation importante : HMAC n’est pas affecté

Les attaques par extension de longueur s’appliquent aux constructions vulnérables avec préfixe, telles que `HASH(secret || message)`. Elles ne permettent pas de compromettre la construction HMAC (par exemple, HMAC-SHA256), qui combine une clé avec des applications distinctes du hachage interne et externe.<sup>[[1]](#references)[[2]](#references)</sup>

Pour savoir comment trouver et tester ces signatures dans les API web, consultez [Request and parameter signatures](../../pentesting-web/web-api-pentesting.md#request-and-parameter-signatures).

### Outils

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), bindings Python pour l’outil d’extension de longueur HashPump<sup>[[7]](#references)</sup>

### Bonne explication

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hachage de tuples ambigus et MAC

### Boundary-confusion attack

Les API de hachage incrémentiel n’authentifient pas les limites entre les appels. `update(A); update(B)` calcule le hachage de la même chaîne d’octets que `update(A + B)`. Par conséquent, hacher ou calculer un MAC sur une concaténation brute n’authentifie pas un tuple. Si des champs adjacents ont une longueur variable, un attaquant peut répartir les octets différemment pour obtenir un autre tuple, sans trouver de collision dans la fonction de hachage sous-jacente :<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Cela devient exploitable lorsque le vérificateur croit que le digest lie la signification des champs, alors qu’une entrée contrôlée par l’attaquant peut atteindre un autre parseur ou une autre étape du protocole qui attribue d’autres limites. Les engagements peuvent alors avoir des ouvertures alternatives, et les transcripts Fiat-Shamir peuvent être interprétés comme des énoncés différents. HMAC empêche [hash length extension](#hash-length-extension-attack), mais `HMAC(K, A || B)` présente toujours cette ambiguïté d’encodage de tuple, car les deux tuples produisent les mêmes octets de message.<sup>[[8]](#references)[[9]](#references)</sup>

Utilisez ce processus d’audit pour vérifier si un encodage de tuple ambigu franchit une frontière de sécurité.<sup>[[8]](#references)[[9]](#references)</sup>

1. Repérez `HASH(A || B)`, `HMAC(K, A || B)` et les appels consécutifs à `update()`/`Write()` portant sur au moins deux champs.
2. Marquez chaque champ contrôlé par l’attaquant ou de longueur variable. Essayez de déplacer des octets d’une limite à l’autre tout en conservant la concaténation complète. Incluez les champs vides.
3. Vérifiez si les schémas de délimitation permettent aux entrées de contenir les octets délimiteurs, s’il existe des désaccords d’échappement et si certains champs seulement sont encodés avec leur longueur.
4. Suivez la façon dont chaque consommateur analyse les octets authentifiés. Une partition alternative n’est pertinente que si elle modifie une décision de sécurité, un énoncé de preuve, un enregistrement, une transaction ou une ouverture d’engagement. Des champs de largeur fixe ou une sérialisation canonique et injective empêchent cette attaque spécifique.
5. Vérifiez si le même digest encodé est accepté dans une autre version du protocole, un autre type de message, tour ou application. Liez explicitement ces contextes au lieu de compter sur les appelants pour les séparer.

### SequenceHash et SequenceMAC

SequenceHash est une construction indépendante de la fonction de hachage, conçue pour les séquences de chaînes d’octets. Chaque opération `add()` est atomique : elle ajoute la valeur et un suffixe de longueur fixe de 16 octets, en little-endian, au hash interne. Les valeurs vides restent des objets distincts. Un hash externe empêche d’exposer un état interne susceptible d’être prolongé par une attaque de longueur, tandis qu’une chaîne de personnalisation facultative assure la séparation de domaine. Ne remplacez pas `add()` par les appels ordinaires à l’API de la fonction de hachage sous-jacente.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Choisissez le customizer dans la définition du protocole, en incluant suffisamment d’informations pour distinguer l’application, la version du protocole, le type de message et le round. SequenceHash exige toujours que toutes les parties s’accordent sur l’ordre des champs, l’encodage des octets et la sérialisation canonique, et ne peut pas protéger un champ omis. Les ports doivent être vérifiés à l’aide des vecteurs de test intermédiaires et finaux de C2SP.<sup>[[8]](#references)[[11]](#references)</sup>

Pour l’authentification, SequenceMAC fournit la même interface d’encodage atomique et de personnalisation. Il exige une clé d’au moins 32 octets. Contrairement au prétraitement de clé de HMAC, ses en-têtes engagent la longueur exacte de la clé : une clé brute longue n’est pas équivalente à son préhachage, et l’ajout d’octets nuls modifie la clé. Cette distinction est importante lorsque des composants acceptent des représentations de clé ou des métadonnées de longueur différentes.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

L’API Python ainsi que les implémentations équivalentes en Go et Rust sont disponibles comme références, mais les implémentations du protocole doivent suivre la spécification C2SP à jour plutôt que de recréer l’encodage à partir de ce résumé.<sup>[[8]](#references)[[10]](#references)</sup>

## Hachage et cracking de mots de passe

### Premières questions<sup>[[4]](#references)</sup>

- Est-ce **salé** ? (recherchez les formats `salt$hash`)
- S’agit-il d’un **hachage rapide** (MD5/SHA1/SHA256) ou d’une **KDF lente** (bcrypt/scrypt/argon2/PBKDF2) ?
- Avez-vous une **indication sur le format** (mode hashcat / format John) ?

### Flux de travail pratique<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifiez le hachage :
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. S’il n’est pas salé et qu’il est courant : essayez les bases de données en ligne et les outils d’identification de la section sur le flux de travail crypto.
3. Sinon, lancez le cracking :
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Erreurs courantes dont vous pouvez tirer parti

- Même mot de passe réutilisé par plusieurs utilisateurs → crackez-en un, puis pivotez.
- Hachages tronqués / transformations personnalisées → normalisez et réessayez.
- Paramètres KDF faibles (p. ex., un faible nombre d’itérations PBKDF2) → le cracking reste possible.

### Oracle bcrypt à entrée choisie avec secret ajouté

Une fonction auxiliaire appelable qui renvoie `bcrypt(user_input || secret)` peut révéler des informations sur un secret ajouté si son implémentation de bcrypt tronque silencieusement l’entrée après 72 **octets**. Une limite de caractères appliquée avant l’encodage UTF-8 ne garantit pas cette limite en octets : des caractères multioctets peuvent remplir l’entrée bcrypt tout en ne laissant qu’un petit préfixe du secret. Les entrées choisies et les hachages renvoyés peuvent alors permettre de vérifier hors ligne des octets de suffixe candidats. Cela nécessite de contrôler l’entrée de la fonction auxiliaire, de connaître sa transformation et son encodage exacts, et de disposer d’une implémentation qui tronque effectivement l’entrée ; la seule présence d’une fonction auxiliaire appelable ou d’un hachage bcrypt ne suffit pas à établir cette chaîne. [La documentation de pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) indique que `hashpw` lève désormais une erreur pour les entrées de plus de 72 octets, alors que les versions antérieures les tronquaient silencieusement. D’autres wrappers peuvent pré-hacher ou rejeter les entrées trop longues : vérifiez donc l’implémentation installée au lieu de supposer qu’elle tronque.

L’utilisation d’un secret récupéré sur un autre compte exige également des preuves que le hachage exposé de celui-ci a été généré avec le **même** secret et la même transformation, ainsi qu’un identifiant ou un chemin de connexion distinct. Un utilitaire de hachage exécuté en tant que root ne doit être considéré comme un oracle que si l’utilisateur moins privilégié peut l’invoquer selon la politique effective ; l’énumération passive de l’hôte n’exige pas de l’appeler ni de lui soumettre des mots de passe choisis.

## References

- [1] [SkullSecurity - Tout ce qu’il faut savoir sur les attaques par extension de longueur de hachage](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Code d’authentification de message par hachage à clé](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Guide-mémo sur le stockage des mots de passe](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat - Hachages d’exemple](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper - Options de la ligne de commande](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI : `hashpumpy`, bindings Python pour HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - Spécification de SequenceHash et SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash : le multihachage pour tous](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - Implémentation Python de SequenceHash](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - Vecteurs de test de SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)
