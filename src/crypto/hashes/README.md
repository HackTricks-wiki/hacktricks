# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Häufige CTF-Muster

- „Signatur“ ist tatsächlich `hash(secret || message)` → Length-Extension-Angriff.
- Ungesalzene Passwort-Hashes → schnelleres wiederholtes Cracken und vorberechnete Lookup-Angriffe.
- Hash mit MAC verwechseln (Hash != Authentifizierung).

## Hash length extension attack

### Technik

Ein Length-Extension-Angriff ist möglicherweise möglich, wenn ein Server eine „Signatur“ wie diese berechnet:

`sig = HASH(secret || message)`

und einen Merkle-Damgård-Hash wie MD5, SHA-1 oder SHA-256 verwendet.

Wenn du Folgendes kennst:

- `message`
- `sig`
- Hash-Funktion
- (oder `len(secret)` durch Brute-Force ermitteln kannst)

kannst du eine gültige Signatur für Folgendes berechnen:

`message || padding || appended_data`

ohne das Secret zu kennen.<sup>[[1]](#references)</sup>

### Wichtige Einschränkung: HMAC ist nicht betroffen

Length-Extension-Angriffe betreffen anfällige Präfix-Konstruktionen wie `HASH(secret || message)`. Sie legen die HMAC-Konstruktion (zum Beispiel HMAC-SHA256) nicht offen, die einen Schlüssel mit getrennten inneren und äußeren Hash-Anwendungen kombiniert.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python-Bindings für das Length-Extension-Tool HashPump<sup>[[7]](#references)</sup>

### Gute Erklärung

[Alles, was du über Hash-Length-Extension-Angriffe wissen musst](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Passwort-Hashing und Cracking

### Erste Fragen<sup>[[4]](#references)</sup>

- Ist der Hash **gesalzen**? (Achte auf Formate wie `salt$hash`.)
- Ist es ein **schneller Hash** (MD5/SHA1/SHA256) oder eine **langsame KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Gibt es einen **Format-Hinweis** (hashcat-Modus / John-Format)?

### Praktischer Workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Hash identifizieren:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Bei ungesalzenen, gängigen Hashes: Online-Datenbanken und Identifikations-Tools aus dem Abschnitt zum Crypto-Workflow ausprobieren.
3. Andernfalls cracken:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Häufige Fehler, die du ausnutzen kannst

- Dasselbe Passwort wird von mehreren Nutzern wiederverwendet → eines cracken, dann pivoten.
- Gekürzte Hashes / benutzerdefinierte Transformationen → normalisieren und erneut versuchen.
- Schwache KDF-Parameter (z. B. zu wenige PBKDF2-Iterationen) → weiterhin crackbar.

### bcrypt-Oracle mit frei gewählter Eingabe und angehängtem Secret

Ein aufrufbarer Helper, der `bcrypt(user_input || secret)` zurückgibt, kann Informationen über ein angehängtes Secret preisgeben, wenn seine bcrypt-Implementierung Eingaben nach 72 **Bytes** stillschweigend abschneidet. Eine Zeichenbegrenzung vor der UTF-8-Kodierung setzt diese Byte-Begrenzung nicht durch: Mehrbytezeichen können die bcrypt-Eingabe füllen und nur für einen kleinen Präfix des Secrets Platz lassen. Frei gewählte Eingaben und die dazu zurückgegebenen Hashes können dann Offline-Prüfungen möglicher Suffix-Bytes ermöglichen. Dafür sind Kontrolle über die Eingabe des Helpers, Kenntnis seiner genauen Transformation und Kodierung sowie eine Implementierung erforderlich, die tatsächlich abschneidet; ein aufrufbarer Helper oder ein bcrypt-Hash allein belegt nicht die gesamte Angriffskette. [Die Dokumentation von pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) gibt an, dass `hashpw` bei Eingaben über 72 Bytes derzeit einen Fehler auslöst, während frühere Versionen sie stillschweigend abgeschnitten haben. Andere Wrapper können lange Eingaben vorab hashen oder zurückweisen. Prüfe daher die installierte Implementierung, statt ein Abschneiden vorauszusetzen.

Ein wiederhergestelltes Secret gegen ein anderes Konto einzusetzen, erfordert außerdem Belege dafür, dass dessen offengelegter Hash mit demselben Secret und derselben Transformation erzeugt wurde, sowie einen separaten Zugangsdaten- oder Login-Pfad. Ein als root ausgeführter Hashing-Helper sollte nur dann als Oracle betrachtet werden, wenn der Nutzer mit geringeren Rechten ihn gemäß den geltenden Richtlinien aufrufen kann; bei der passiven Host-Aufklärung muss er weder aufgerufen noch mit frei gewählten Passwörtern versorgt werden.

## References

- [1] [SkullSecurity – Alles, was du über Hash-Length-Extension-Angriffe wissen musst](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 – Der Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP-Leitfaden zur Passwortspeicherung](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat-Beispiel-Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper: Befehlszeilenoptionen](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: Python-Bindings `hashpumpy` für HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
