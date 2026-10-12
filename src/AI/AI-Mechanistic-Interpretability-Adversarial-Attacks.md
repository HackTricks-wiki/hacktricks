# Adversarielle Angriffe, gesteuert durch mechanistische Interpretierbarkeit

{{#include ../banners/hacktricks-training.md}}

## Superposition als Angriffsfläche

Ein unterparametrisierter Aktivierungsraum kann mehr semantische Merkmale codieren, als er Dimensionen hat, indem er den Merkmalen nichtorthogonale Vektoren zuweist. Daher projiziert ein aktiviertes Merkmal auch auf die Richtungen anderer Merkmale. Das Training kann Kombinationen ausgleichen, die innerhalb der Verteilung vorkommen, aber eine ungewöhnliche Kombination ansonsten gültiger Merkmale kann sich in Richtung eines Zielmerkmals konstruktiv überlagern, das in der Eingabe nicht vorhanden ist.<sup>[[1]](#references)[[2]](#references)</sup>

Für Merkmalsvektoren `v_i ∈ R^D`, Aktivierungen `a_i` und ein Ziel `t` ist die folgende Größe nützlich, um mögliche Kombinationen zu finden:<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

Dies ist lediglich eine Screening-Heuristik. Ein Exploit muss Vorzeichen und Größenordnungen beibehalten und den tatsächlichen Decoder auswerten, zum Beispiel `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))` bei einem linearen Decoder mit gebundenen Gewichten. Negative Terme können den Angriff aufheben, während Decoder-Bias, Feature-Vektornormen, Aktivierungsschwellen und ReLU-Gating verhindern können, dass ein hoher absoluter Kosinuswert die Zielaktivierung hervorruft.<sup>[[1]](#references)</sup>

## White-box-Angriffs-Workflow

Eine praktische Untersuchung kann einen Modell-Bottleneck, einen Sparse Autoencoder (SAE) oder ein anderes interpretierbares Feature-Dictionary verwenden. Das Ziel besteht nicht nur darin, die finale Klasse zu ändern, sondern die Rekonstruktion ein gewähltes internes Feature einführen zu lassen, das vor der Kompression nicht aktiv war. Der vorgeschlagene Workflow lautet:<sup>[[1]](#references)</sup>

1. **Feature-Richtungen ermitteln:** Die relevanten Encoder-/Decoder-Vektoren extrahieren, inaktive Features entfernen und aktive Richtungen mithilfe von Samples mit maximaler Aktivierung oder einer Feature-Circuit-Analyse Konzepten zuordnen.
2. **Interferenzen einstufen:** Eine Kopie der Vektoren normalisieren, ihre Kosinus-Ähnlichkeitsmatrix berechnen, die Diagonale auf null setzen und die stärksten Nicht-Diagonal-Nachbarn des Ziels untersuchen. Kandidaten anhand tatsächlicher Aktivierungsstärken und vorzeichenbehafteter roher Skalarprodukte erneut berechnen.
3. **Gleichzeitige Aktivierung sicherstellen:** Eine kleine Gruppe positiv beitragender Features beibehalten, die in derselben Schicht oder demselben Residual Stream aktiviert werden können. Kombinationen bevorzugen, die in den Trainingsdaten selten oder gar nicht vorkommen; gewöhnliche korrelierte Kombinationen wurden beim Training mit größerer Wahrscheinlichkeit kompensiert.
4. **Eingabe synthetisieren:** Datensatzbeispiele oder aktivierungsmaximierende Muster für die ausgewählten beitragenden Features kombinieren. Bei einem begrenzten linearen Pixel-Detektor einen Pixel bei positivem Gewicht auf einen hohen und bei negativem Gewicht auf einen niedrigen Wert setzen und anschließend die resultierenden Muster überlagern. Die manuelle Beibehaltung einer In-Distribution-Struktur und inhibitorischen **Negativräume** kann nicht zugehörige Features unterdrücken.
5. **Mechanismus überprüfen:** Aktivierungen vor der Kompression, die komprimierten Koordinaten, rekonstruierte Aktivierungen und die nachgelagerte Ausgabe in einem Forward Pass aufzeichnen. Ein erfolgreicher Test zeigt, dass das Ziel vor der Rekonstruktion inaktiv und danach aktiv ist und dass die vorhergesagte Änderung verschwindet, wenn die beitragenden Features abgetragen werden.

Die folgende minimale Triage stuft beitragende Features für einen Decoder mit gebundenen Gewichten ein, dessen **Zeilen** Feature-Vektoren darstellen (zuerst transponieren, wenn die Features Spalten sind). Für die vorzeichenbehaftete Bewertung rohe Gewichte und für die Kosinus-Einstufung nur normalisierte Gewichte verwenden.<sup>[[1]](#references)</sup>

```python
import numpy as np

norm = np.linalg.norm(W_dec, axis=1, keepdims=True)
unit = W_dec / np.clip(norm, 1e-12, None)
cosine = unit @ unit.T
np.fill_diagonal(cosine, 0.0)

target = 42
signed = activations * (W_dec @ W_dec[target])
signed[target] = -np.inf
order = np.argsort(signed)[::-1]
print([(int(i), float(signed[i]), float(cosine[i, target]))
       for i in order[:20] if signed[i] > 0])
```

Leite Exploitability nicht allein aus der Cosine Similarity ab. Teste den vollständigen Decoder einschließlich Bias und Nichtlinearität, bestätige, dass die beitragenden Features tatsächlich gleichzeitig auftreten können, und vergleiche sie mit passenden Kombinationen aus der In-Distribution. Ähnliche Richtungen können eine legitime semantische Beziehung statt ausnutzbarer Interferenz durch Packing kodieren.<sup>[[1]](#references)</sup>

## Demonstrierter Toy-Model-Angriff

Der Proof of Concept verwendete einen bewusst gut interpretierbaren MNIST-Klassifikator mit zwei Zweigen. In einem Zweig wurde ein spärlicher, 128-dimensionaler ReLU-Featurevektor direkt klassifiziert, im anderen in einen zweidimensionalen Superpositionsraum komprimiert; derselbe Klassifikator verarbeitete sowohl die ursprünglichen als auch die rekonstruierten Features.<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

Zwei Feature-Richtungen, die mit 3/0-ähnlichen Formen verbunden waren, wurden geometrisch von Class-5-Richtungen eingeschlossen. Wurden ihre maximal aktivierenden Bilder addiert, waren diese beitragenden Features vor der Kompression am stärksten aktiviert. Die Rekonstruktion aktivierte jedoch mehrere Class-5-Features, und der Superpositionszweig sagte 5 voraus. Ein handgezeichnetes Bild, das nur minimale und maximale Pixelwerte verwendete, reproduzierte den Effekt. Das zeigt, dass in diesem Toy-Setting keine exakt per Gradientenoptimierung erzeugten Pixelstörungen nötig waren.<sup>[[1]](#references)</sup>

## Geometrische Triage größerer Modelle

Die Arbeit untersuchte außerdem das Gemma Scope `layer 20 / width 65k / average L0 20` SAE. Die Autoren multiplizierten die einheitsnormalisierte Decoder-Matrix mit ihrer Transponierten, setzten die Diagonale auf null, sortierten die Nachbarn jedes Features und bildeten den Mittelwert nach Rang. Die mittlere Kosinusähnlichkeit zum stärksten Nachbarn betrug `0.49`, während die mittlere Ähnlichkeit zum 27. Nachbarn `0.25` betrug; geometrisch könnten vier solcher Richtungen der Projektion eines einzelnen Zielvektors entsprechen. Diese Werte identifizieren lediglich Kandidaten – sie zeigen weder, dass sich vier geeignete Features gemeinsam aktivieren lassen, noch, dass das Ziel seinen Decoder-Schwellenwert überschreitet.<sup>[[1]](#references)</sup>

## Geltungsbereich und Einschränkungen

Dies ist eine Technik im Forschungsstadium für **White-Box**-Analysen und kein demonstrierter Angriff auf ein eingesetztes CNN oder ein Frontier-LLM. Sie setzt Superposition, geeignete nicht-orthogonale Richtungen, interpretierbaren Zugriff auf interne Features, eine kontrollierbare Aktivierung der beitragenden Features und deren gemeinsames Auftreten in derselben Schicht während eines Forward Pass voraus.<sup>[[1]](#references)</sup>

Bei Bild-MLPs ist die Zusammensetzung von Features ungewöhnlich direkt. Bei einem Transformer ist sie schwieriger, da die Attention die ausgewählten Feature-Aktivierungen im selben Residual Stream zusammenführen muss. Die Arbeit zeigt nicht, wie sich dies für eine Out-of-Distribution-Kombination erzwingen lässt. Behauptungen über die Manipulation von Verhaltens- oder Refusal-Richtungen, physischen Vision-Systemen oder führenden Modellen bleiben daher Hypothesen.<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson and Anley — Eine vorläufige Untersuchung interpretierbarer adversarialer Angriffe durch Feature-Interferenz in Superposition (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — Interpretierbare adversariale Angriffe in Superposition](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)
{{#include ../banners/hacktricks-training.md}}
