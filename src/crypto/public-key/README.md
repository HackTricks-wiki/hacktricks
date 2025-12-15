# Public-Key-Kryptographie

{{#include ../../banners/hacktricks-training.md}}

Die meisten schweren CTF-Crypto-Aufgaben landen hier: RSA, ECC/ECDSA, lattices und schlechte Zufallswerte.

## Empfohlene Tools

- SageMath (LLL/lattices, modulare Arithmetik): https://www.sagemath.org/
- RsaCtfTool (Schweizer Taschenmesser): https://github.com/Ganapati/RsaCtfTool
- factordb (schnelle Faktorisierungsprüfungen): http://factordb.com/

## RSA

Beginne hier, wenn du `n,e,c` und einen zusätzlichen Hinweis hast (gemeinsamer Modulus, kleiner Exponent, partielle Bits, verwandte Nachrichten).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Wenn Signaturen involviert sind, teste zuerst Nonce-Probleme (reuse/bias/leaks), bevor du von harter Mathematik ausgehst.

### ECDSA nonce reuse / bias

Wenn zwei Signaturen denselben Nonce `k` wiederverwenden, kann der private Schlüssel zurückgewonnen werden.

Selbst wenn `k` nicht identisch ist, kann **bias/leakage** von Nonce-Bits über Signaturen hinweg für lattice recovery ausreichen (häufiges CTF-Thema).

Technische Rekonstruktion, wenn `k` wiederverwendet wird:

ECDSA Signaturgleichungen (Gruppenordnung `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Wenn derselbe `k` für zwei Nachrichten `m1, m2` wiederverwendet wird und Signaturen `(r, s1)` und `(r, s2)` erzeugt:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Wenn ein Protokoll nicht validiert, dass Punkte auf der erwarteten Kurve (oder Untergruppe) liegen, kann ein Angreifer Operationen in einer schwachen Gruppe erzwingen und Geheimnisse zurückgewinnen.

Technischer Hinweis:

- Validieren, dass Punkte auf der Kurve liegen und in der korrekten Untergruppe sind.
- Viele CTF-Aufgaben modellieren dies als "server multiplies attacker-chosen point by secret scalar and returns something."

### Tools

- SageMath für Kurvenarithmetik / lattices
- `ecdsa` Python-Bibliothek zum Parsen/Verifizieren

{{#include ../../banners/hacktricks-training.md}}
