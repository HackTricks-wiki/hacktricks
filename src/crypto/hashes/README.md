# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Häufige CTF-Muster

- „Signature“ ist eigentlich `hash(secret || message)` → Length-Extension-Angriff.
- Nicht gesalzene Passwort-Hashes → schnelleres wiederholtes Cracken und vorberechnete Lookup-Angriffe.
- Hash mit MAC verwechseln (hash != authentication).

## Hash length extension attack

### Technik

Ein Length-Extension-Angriff kann möglich sein, wenn ein Server eine „Signature“ wie diese berechnet:

`sig = HASH(secret || message)`

und einen Merkle-Damgård-Hash wie MD5, SHA-1 oder SHA-256 verwendet.

Wenn du Folgendes kennst:

- `message`
- `sig`
- die Hash-Funktion
- (oder `len(secret)` brute-forcen kannst)

kannst du eine gültige Signature für

`message || padding || appended_data`

berechnen, ohne das Secret zu kennen.<sup>[[1]](#references)</sup>

### Wichtige Einschränkung: HMAC ist nicht betroffen

Length-Extension-Angriffe betreffen verwundbare Prefix-Konstruktionen wie `HASH(secret || message)`. Sie ermöglichen keinen Angriff auf die HMAC-Konstruktion (zum Beispiel HMAC-SHA256), die einen Schlüssel mit separaten inneren und äußeren Hash-Anwendungen kombiniert.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python-Bindings für das HashPump-Length-Extension-Tool<sup>[[7]](#references)</sup>

### Gute Erklärung

[Alles, was du über Hash-Length-Extension-Angriffe wissen musst](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Passwort-Hashing und Cracken

### Erste Fragen<sup>[[4]](#references)</sup>

- Ist der Hash **gesalzen**? (Achte auf Formate wie `salt$hash`.)
- Ist es ein **schneller Hash** (MD5/SHA1/SHA256) oder eine **langsame KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Gibt es einen **Format-Hinweis** (hashcat-Modus / John-Format)?

### Praktischer Ablauf<sup>[[5]](#references)[[6]](#references)</sup>

1. Hash identifizieren:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Wenn der Hash nicht gesalzen und verbreitet ist: Probiere Online-Datenbanken und Identifizierungstools aus dem Abschnitt zum Crypto-Workflow.
3. Andernfalls cracken:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Häufige Fehler, die du ausnutzen kannst

- Dasselbe Passwort wird von mehreren Benutzern verwendet → eines cracken, Pivot durchführen.
- Abgeschnittene Hashes / benutzerdefinierte Transformationen → normalisieren und erneut versuchen.
- Schwache KDF-Parameter (z. B. zu wenige PBKDF2-Iterationen) → weiterhin crackbar.

### bcrypt-Oracle mit gewählter Eingabe und angehängtem Secret

Ein aufrufbarer Helper, der `bcrypt(user_input || secret)` zurückgibt, kann Informationen über ein angehängtes Secret preisgeben, wenn seine bcrypt-Implementierung Eingaben nach 72 **Bytes** stillschweigend abschneidet. Eine Zeichenbegrenzung vor der UTF-8-Kodierung setzt diese Byte-Grenze nicht durch: Mehrbyte-Zeichen können die bcrypt-Eingabe auffüllen und nur Platz für ein kurzes Präfix des Secrets lassen. Gewählte Eingaben und die zurückgegebenen Hashes können dann Offline-Prüfungen möglicher Suffix-Bytes ermöglichen. Dafür sind Kontrolle über die Eingabe des Helpers, genaue Kenntnis seiner Transformation und Kodierung sowie eine Implementierung erforderlich, die tatsächlich abschneidet; ein aufrufbarer Helper oder ein bcrypt-Hash allein belegt diese Angriffskette nicht. [pyca/bcrypt dokumentiert](https://github.com/pyca/bcrypt#maximum-password-length), dass `hashpw` bei aktuellen Versionen für Eingaben über 72 Bytes einen Fehler auslöst, während frühere Versionen sie stillschweigend abgeschnitten haben. Andere Wrapper können lange Eingaben vorab hashen oder ablehnen. Prüfe daher die installierte Implementierung, statt einfach von einer Kürzung auszugehen.

Ein wiederhergestelltes Secret gegen ein anderes Konto einzusetzen, erfordert außerdem Belege dafür, dass dessen offengelegter Hash mit demselben Secret und derselben Transformation erzeugt wurde, sowie einen separaten Zugangsdaten- oder Login-Pfad. Ein als root ausgeführter Hashing-Helper sollte nur dann als Oracle betrachtet werden, wenn der Benutzer mit geringeren Rechten ihn gemäß der geltenden Richtlinie aufrufen kann. Bei der passiven Host-Aufzählung muss der Helper nicht aufgerufen und müssen keine gewählten Passwörter übermittelt werden.

## References

- [1] [SkullSecurity - Alles, was du über Hash-Length-Extension-Angriffe wissen musst](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Der keyed-hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP-Leitfaden zur Passwortspeicherung](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat-Beispiel-Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper-Befehlszeilenoptionen](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: Python-Bindings `hashpumpy` für HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
