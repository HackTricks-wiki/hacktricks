# Modelle RCE

{{#include ../banners/hacktricks-training.md}}

## Laai modelle na RCE

Masjienleer modelle word gewoonlik in verskillende formate gedeel, soos ONNX, TensorFlow, PyTorch, ens. Hierdie modelle kan in ontwikkelaars se masjiene of produksiesisteme gelaai word om hulle te gebruik. Gewoonlik behoort die modelle nie kwaadwillige kode te bevat nie, maar daar is 'n paar gevalle waar die model gebruik kan word om arbitrêre kode op die stelsel uit te voer as 'n beoogde funksie of as gevolg van 'n kwesbaarheid in die model laai biblioteek.

Tydens die skryf hiervan is hier 'n paar voorbeelde van hierdie tipe kwesbaarhede:

| **Raamwerk / Gereedskap**   | **Kwesbaarheid (CVE indien beskikbaar)**                                                                                     | **RCE Vektor**                                                                                                                         | **Verwysings**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Onveilige deserialisering in* `torch.load` **(CVE-2025-32434)**                                                              | Kwaadwillige pickle in model kontrolepunt lei tot kode-uitvoering (om `weights_only` beskerming te omseil)                               | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + kwaadwillige model aflaai veroorsaak kode-uitvoering; Java deserialisering RCE in bestuur API                                     | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (onveilige YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                    | Laai model vanaf YAML gebruik `yaml.unsafe_load` (kode exec) <br> Laai model met **Lambda** laag voer arbitrêre Python kode uit          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Gemaakte `.tflite` model veroorsaak heelgetal oorgang → heap korrupsie (potensiële RCE)                                               | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Laai 'n model via `joblib.load` voer pickle uit met aanvaller se `__reduce__` payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (onveilige `np.load`) *betwis*                                                                             | `numpy.load` standaard het toegelaat dat gepekelde objekreeks – kwaadwillige `.npy/.npz` veroorsaak kode exec                           | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversaal) <br> **CVE-2024-5187** (tar traversaal)                                                  | ONNX model se eksterne gewigte pad kan die gids ontsnap (lees arbitrêre lêers) <br> Kwaadwillige ONNX model tar kan arbitrêre lêers oorskryf (wat lei tot RCE) | |
| ONNX Runtime (ontwerp risiko) | *(Geen CVE)* ONNX pasgemaakte ops / beheerstroom                                                                                 | Model met pasgemaakte operateur vereis laai van aanvaller se inheemse kode; komplekse model grafieke misbruik logika om onbedoelde berekeninge uit te voer | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (pad traversaal)                                                                                          | Gebruik model-laai API met `--model-control` geaktiveer laat relatiewe pad traversaal toe om lêers te skryf (bv. oorskryf `.bashrc` vir RCE) | |
| **GGML (GGUF formaat)**     | **CVE-2024-25664 … 25668** (meervoudige heap oorgange)                                                                       | Misvormde GGUF model lêer veroorsaak heap buffer oorgange in parser, wat arbitrêre kode-uitvoering op die slagoffer stelsel moontlik maak | |
| **Keras (ou formate)**      | *(Geen nuwe CVE)* Erflike Keras H5 model                                                                                      | Kwaadwillige HDF5 (`.h5`) model met Lambda laag kode voer steeds uit op laai (Keras safe_mode dek nie ou formaat nie – “downgrade aanval”) | |
| **Ander** (generies)        | *Ontwerp fout* – Pickle serialisering                                                                                         | Baie ML gereedskap (bv. pickle-gebaseerde model formate, Python `pickle.load`) sal arbitrêre kode wat in model lêers ingebed is uitvoer tensy dit gemitigeer word | |

Boonop is daar 'n paar python pickle-gebaseerde modelle soos die wat deur [PyTorch](https://github.com/pytorch/pytorch/security) gebruik word wat gebruik kan word om arbitrêre kode op die stelsel uit te voer as hulle nie met `weights_only=True` gelaai word nie. So, enige pickle-gebaseerde model kan spesiaal kwesbaar wees vir hierdie tipe aanvalle, selfs al is hulle nie in die tabel hierbo gelys nie.

{{#include ../banners/hacktricks-training.md}}
