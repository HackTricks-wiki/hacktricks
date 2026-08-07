# Kryptografie mit öffentlichen Schlüsseln

{{#include ../../banners/hacktricks-training.md}}


Die meiste schwierige CTF-Kryptografie läuft darauf hinaus: RSA, ECC/ECDSA, Lattices und schlechte Zufallszahlen.

## Empfohlene Tools

- SageMath (LLL/Lattices, modulare Arithmetik): https://www.sagemath.org/
- RsaCtfTool (Schweizer Taschenmesser): https://github.com/Ganapati/RsaCtfTool
- factordb (schnelle Faktorisierungsprüfungen): http://factordb.com/

## RSA

Beginne hier, wenn du `n,e,c` und einen zusätzlichen Hinweis hast (gemeinsamer Modulus, niedriger Exponent, partielle Bits, verwandte Nachrichten).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Wenn Signaturen beteiligt sind, teste zuerst auf Nonce-Probleme (Wiederverwendung/Bias/leaks), bevor du von schwieriger Mathematik ausgehst.

### Wiederverwendung / Bias der ECDSA-Nonce

Wenn zwei Signaturen dieselbe Nonce `k` wiederverwenden, kann der private Schlüssel wiederhergestellt werden.

Auch wenn `k` nicht identisch ist, kann **Bias/Leakage** von Nonce-Bits über mehrere Signaturen hinweg für eine Wiederherstellung mithilfe von Lattices ausreichen (ein häufiges CTF-Thema).

Technische Wiederherstellung bei wiederverwendetem `k`:

ECDSA-Signaturgleichungen (Gruppenordnung `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Wenn dasselbe `k` für zwei Nachrichten `m1, m2` wiederverwendet wird und die Signaturen `(r, s1)` und `(r, s2)` entstehen:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-Curve-Angriffe

Wenn ein Protokoll nicht überprüft, ob Punkte auf der erwarteten Kurve (oder in der erwarteten Untergruppe) liegen, kann ein Angreifer Operationen in einer schwachen Gruppe erzwingen und Geheimnisse wiederherstellen.

Technischer Hinweis:

- Überprüfe, dass Punkte auf der Kurve liegen und sich in der korrekten Untergruppe befinden.
- Viele CTF-Aufgaben modellieren dies als „Der Server multipliziert einen vom Angreifer gewählten Punkt mit einem geheimen Skalar und gibt etwas zurück.“

### Tools

- SageMath für Kurvenarithmetik / Lattices
- Python-Bibliothek `ecdsa` zum Parsen und Verifizieren

{{#include ../../banners/hacktricks-training.md}}
