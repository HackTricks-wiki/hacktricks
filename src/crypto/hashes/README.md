# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Häufige CTF-Muster

- „Signatur“ ist tatsächlich `hash(secret || message)` → length extension.
- Ungesalzene Passwort-Hashes → schnelleres wiederholtes cracking und vorberechnete Lookup-Angriffe.
- Hash mit MAC verwechseln (hash != Authentifizierung).

## MD5-Hash-Suchen mit gewählter Eingabe

Diese Python-Beispiele suchen nach zwei unterschiedlichen Ausgabemustern: einem gewählten MD5-Suffix und einem MD5-Wert, der mit `0e` beginnt, gefolgt von Ziffern. Das zweite Muster ist relevant, wenn eine Anwendung numerische Zeichenfolgen nicht strikt vergleicht; siehe das PHP-spezifische Verhalten und die Versionshinweise unter [PHP loose comparisons](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute Force für MD5-Hash-Suffixe

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

### MD5-0e-Hash-Generierung für nicht-strikte Vergleiche

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

### Technik

Ein length-extension attack kann möglich sein, wenn ein Server eine „Signatur“ wie folgt berechnet:

`sig = HASH(secret || message)`

und einen Merkle-Damgård-Hash wie MD5, SHA-1 oder SHA-256 verwendet.

Wenn du Folgendes kennst:

- `message`
- `sig`
- die Hashfunktion
- (oder die Länge von `secret` brute-forcen kannst)

Dann kannst du eine gültige Signatur für Folgendes berechnen:

`message || padding || appended_data`

ohne das Secret zu kennen.<sup>[[1]](#references)</sup>

### Wichtige Einschränkung: HMAC ist nicht betroffen

Length-extension attacks betreffen anfällige Prefix-Konstruktionen wie `HASH(secret || message)`. Sie ermöglichen keinen Angriff auf die HMAC-Konstruktion (zum Beispiel HMAC-SHA256), die einen Schlüssel mit separaten inneren und äußeren Hash-Anwendungen kombiniert.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python-Bindings für das HashPump-Tool für length-extension attacks<sup>[[7]](#references)</sup>

### Gute Erklärung

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Mehrdeutiges Tuple-Hashing und MACs

### Boundary-confusion attack

Inkrementelle Hash-APIs authentifizieren keine Aufrufgrenzen. `update(A); update(B)` hasht dieselbe Bytefolge wie `update(A + B)`. Daher authentifiziert das Hashen oder MACen einer rohen Verkettung kein Tuple. Haben benachbarte Felder variable Längen, kann ein Angreifer die Bytes in ein anderes Tuple aufteilen, ohne eine Kollision im zugrunde liegenden Hash zu finden:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Dies wird ausnutzbar, wenn der Verifier davon ausgeht, dass der Digest die Bedeutung der Felder bindet, vom Angreifer kontrollierte Eingaben jedoch einen anderen Parser oder Protokollschritt erreichen können, der andere Grenzen zuweist. Commitments können dadurch alternative Öffnungen erhalten, und Fiat-Shamir-Transkripte können als andere Aussagen interpretiert werden. HMAC verhindert [hash length extension](#hash-length-extension-attack), aber `HMAC(K, A || B)` weist weiterhin diese Mehrdeutigkeit der Tupel-Kodierung auf, da beide Tupel dieselben Nachrichtenbytes erzeugen.<sup>[[8]](#references)[[9]](#references)</sup>

Verwende diesen Audit-Workflow, um zu prüfen, ob eine mehrdeutige Tupel-Kodierung eine Sicherheitsgrenze überschreitet.<sup>[[8]](#references)[[9]](#references)</sup>

1. Finde `HASH(A || B)`, `HMAC(K, A || B)` und aufeinanderfolgende `update()`-/`Write()`-Aufrufe mit mindestens zwei Feldern.
2. Markiere alle vom Angreifer kontrollierten oder variabel langen Felder. Versuche, Bytes über jede Grenze hinweg zu verschieben, während die vollständige Verkettung unverändert bleibt. Berücksichtige auch leere Felder.
3. Prüfe bei Trennzeichenverfahren, ob Eingaben Trennzeichenbytes enthalten können, ob es Abweichungen beim Escaping gibt und ob nur einige Felder längenkodiert werden.
4. Verfolge, wie jeder Verbraucher die authentifizierten Bytes parst. Ein möglicher Angriff ist nur dann relevant, wenn eine alternative Aufteilung eine Sicherheitsentscheidung, einen Beweis, einen Datensatz, eine Transaktion oder eine Commitment-Öffnung verändert. Felder mit fester Breite oder eine kanonische, injektive Serialisierung verhindern diesen konkreten Angriff.
5. Prüfe, ob derselbe kodierte Digest in einer anderen Protokollversion, einem anderen Nachrichtentyp, einer anderen Runde oder einer anderen Anwendung akzeptiert wird. Binde diese Kontexte explizit ein, statt darauf zu vertrauen, dass Aufrufer sie getrennt halten.

### SequenceHash und SequenceMAC

SequenceHash ist eine hash-unabhängige Konstruktion für Folgen von Byte-Strings. Jede `add()`-Operation ist atomar: Sie hängt den Wert und ein festes 16-Byte-Längensuffix im Little-Endian-Format an den inneren Hash an. Leere Werte bleiben unterschiedliche Objekte. Ein äußerer Hash verhindert, dass ein durch Längenverlängerung erweiterbarer innerer Zustand offengelegt wird, während eine optionale Customization-Zeichenfolge die Domain Separation ermöglicht. Ersetze `add()` nicht durch die gewöhnlichen Schreibaufrufe der zugrunde liegenden Hash-API.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Wählen Sie den Customizer als Teil der Protokolldefinition und geben Sie genügend Informationen an, um die Anwendung, die Protokollversion, den Nachrichtentyp und den Round zu unterscheiden. SequenceHash erfordert weiterhin, dass sich alle Parteien auf die Feldreihenfolge, die Byte-Kodierung und die kanonische Serialisierung einigen, und kann ein ausgelassenes Feld nicht schützen. Portierungen sollten anhand der C2SP-Zwischen- und finalen Testvektoren geprüft werden.<sup>[[8]](#references)[[11]](#references)</sup>

Für die Authentifizierung bietet SequenceMAC dieselbe atomare Kodierungs- und Customization-Schnittstelle. Es erfordert einen Schlüssel von mindestens 32 Byte. Anders als bei der HMAC-Schlüsselvorverarbeitung legen seine Header die exakte Schlüssellänge fest: Ein langer Rohschlüssel ist nicht gleichwertig mit seinem Prehash, und das Anhängen von Null-Bytes ändert den Schlüssel. Dieser Unterschied ist wichtig, wenn Komponenten unterschiedliche Schlüsseldarstellungen oder Längenmetadaten akzeptieren.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Die Python-API sowie entsprechende Implementierungen in Go und Rust sind als Referenzen verfügbar. Protokollimplementierungen sollten sich jedoch an der aktuellen C2SP-Spezifikation orientieren, statt die Kodierung anhand dieser Zusammenfassung nachzubilden.<sup>[[8]](#references)[[10]](#references)</sup>

## Passwort-Hashing und Cracking

### Erste Fragen<sup>[[4]](#references)</sup>

- Ist der Hash **gesalzen**? (Achte auf Formate wie `salt$hash`.)
- Handelt es sich um einen **schnellen Hash** (MD5/SHA1/SHA256) oder eine **langsame KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Gibt es einen **Format-Hinweis** (Hashcat-Modus / John-Format)?

### Praktischer Ablauf<sup>[[5]](#references)[[6]](#references)</sup>

1. Hash identifizieren:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Bei einem ungesalzenen, verbreiteten Hash: Online-Datenbanken und Identifizierungstools aus dem Abschnitt zum Krypto-Workflow ausprobieren.
3. Andernfalls cracken:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Häufige Fehler, die du ausnutzen kannst

- Dasselbe Passwort wird von mehreren Benutzern verwendet → eines cracken und weiter pivoten.
- Abgeschnittene Hashes / benutzerdefinierte Transformationen → normalisieren und erneut versuchen.
- Schwache KDF-Parameter (z. B. zu wenige PBKDF2-Iterationen) → lassen sich trotzdem cracken.

### Bcrypt-Oracle mit gewählter Eingabe und angehängtem Secret

Ein aufrufbarer Helfer, der `bcrypt(user_input || secret)` zurückgibt, kann Informationen über ein angehängtes Secret preisgeben, wenn seine bcrypt-Implementierung Eingaben nach 72 **Bytes** stillschweigend abschneidet. Eine Begrenzung der Zeichenanzahl vor der UTF-8-Kodierung setzt dieses Byte-Limit nicht durch: Mehrbytezeichen können die bcrypt-Eingabe füllen und nur Platz für ein kurzes Präfix des Secrets lassen. Gewählte Eingaben und die zugehörigen zurückgegebenen Hashes können dann Offline-Prüfungen möglicher Suffix-Bytes erlauben. Dafür musst du die Eingabe des Helfers kontrollieren und seine genaue Transformation und Kodierung kennen; außerdem muss die Implementierung tatsächlich abschneiden. Ein aufrufbarer Helfer oder ein bcrypt-Hash allein belegt diese Angriffskette nicht. [pyca/bcrypt dokumentiert](https://github.com/pyca/bcrypt#maximum-password-length), dass die aktuelle `hashpw`-Funktion bei Eingaben über 72 Bytes einen Fehler auslöst, während frühere Versionen sie stillschweigend abgeschnitten haben. Andere Wrapper können lange Eingaben vorab hashen oder zurückweisen. Prüfe daher die installierte Implementierung, statt ein Abschneiden anzunehmen.

Ein wiederhergestelltes Secret für ein anderes Konto zu verwenden, setzt außerdem Belege dafür voraus, dass dessen offengelegter Hash mit demselben Secret und derselben Transformation erzeugt wurde, sowie einen separaten Zugangsdaten- oder Anmeldepfad. Ein Hashing-Helfer, der als root läuft, sollte nur dann als Oracle betrachtet werden, wenn der Benutzer mit geringeren Rechten ihn gemäß den geltenden Richtlinien aufrufen kann. Bei der passiven Host-Aufzählung muss der Helfer weder aufgerufen noch müssen ihm gewählte Passwörter übergeben werden.

## References

- [1] [SkullSecurity – Alles, was du über Hash-Length-Extension-Angriffe wissen musst](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 – Der keyed-hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP-Leitfaden zur Passwortspeicherung](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat-Beispiel-Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Befehlszeilenoptionen von John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy`-Python-Bindings für HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP – Spezifikation für SequenceHash und SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits – SequenceHash: Multihashing für alle](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits – SequenceHash-Python-Implementierung](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV – SequenceHash-Testvektoren](https://github.com/C2SP/CCTV/tree/main/sequencehash)
