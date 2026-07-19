# Contourner le KYC avec l'IA

{{#include ../banners/hacktricks-training.md}}

Les modèles génératifs peuvent être utilisés pour **contourner les workflows KYC, de vérification de l'âge et de détection biométrique de vivacité basés sur un navigateur**. Le point faible ne se situe souvent **ni au niveau du transport ni chez le fournisseur cloud de détection de vivacité**, mais au niveau de la **frontière de confiance de la caméra** : un navigateur de bureau fait généralement confiance à tout périphérique que `getUserMedia()` expose comme webcam.

## Chaîne d'attaque pratique

1. **Générer un média conforme aux challenges** avec un modèle video-to-video à partir d'un acteur source et d'une image de référence de la victime.
2. **Injecter le flux falsifié avant la signature ou l'upload**, par exemple via une caméra virtuelle Linux créée avec `v4l2loopback` et alimentée par OBS ou FFmpeg.
3. Laisser le navigateur et le SDK du fournisseur (WebRTC, AWS, etc.) **capturer, signer et uploader les frames contrôlées par l'attaquant comme si elles provenaient d'une webcam réelle**.

Cela est important lors des assessments, car les chunks WebSocket signés ou le framing propriétaire d'un SDK peuvent rendre la **modification au niveau réseau** impraticable, tandis que **l'injection au niveau de la caméra** continue de fonctionner.

## Angles de test à forte valeur

- **Acceptation des webcams virtuelles** : si le workflow fonctionne depuis un navigateur de bureau, tester si OBS, `v4l2loopback` ou les caméras virtuelles du fournisseur sont acceptés comme des périphériques normaux.
- **Redirection de l'API caméra sur mobile** : les workflows mobiles natifs peuvent rester vulnérables lorsque Frida hooke les API caméra et remplace les buffers du capteur par des frames provenant d'un MP4 ou d'une caméra virtuelle fournie par un émulateur.
- **Affaiblissement des contraintes** : les pages qui exigent un `deviceId`, un `frameRate`, une `width`, une `height` ou un `facingMode` exacts peuvent parfois être contournées en monkeypatchant `navigator.mediaDevices.getUserMedia` et en remplaçant les contraintes strictes par des plages plus larges.
- **Génération de faible qualité suivie de post-traitement** : générer la vidéo la moins coûteuse que le modèle puisse produire de manière fiable, puis utiliser un upscaling FFmpeg ou une interpolation d'images pour satisfaire les exigences de capture.
- **Challenges actifs prévisibles** : les séquences répétées de mouvements de tête ou de flash lumineux méritent d'être enregistrées et rejouées via un workflow génératif.
- **Détection faible du replay** : de simples perturbations de scène, comme des changements de recadrage ou de position, des modifications d'overlay ou de légers mouvements, peuvent suffire lorsque la logique anti-replay ne vérifie qu'une similarité superficielle entre les frames.

## Différences de confiance entre mobile et ordinateur de bureau

Les applications mobiles natives peuvent augmenter le coût pour l'attaquant grâce à :

- **l'attestation des capteurs ou du Secure Element** pour les buffers caméra ;
- des signaux d'**intégrité de l'exécution** tels que **Play Integrity** ou **App Attest** ;
- la **corrélation des mouvements** entre la vidéo et les données de télémétrie de l'accéléromètre ou du gyroscope.

Les workflows web de bureau ne disposent généralement pas d'une chaîne de confiance équivalente pour la caméra ; ils constituent donc généralement le chemin offrant le moins de résistance.

## Notes pour la revue défensive

Lors de la revue d'une intégration KYC ou de détection de vivacité, vérifier si elle :

- autorise un **fallback via navigateur de bureau** pour un workflow qui n'a été modélisé contre les menaces que pour une capture mobile ;
- repose principalement sur la **détection algorithmique de vivacité** sans escalade humaine robuste pour les sessions suspectes ;
- utilise des **challenges stables ou prévisibles** qui peuvent être préenregistrés et injectés dans un pipeline de génération ;
- détecte le **monkeypatching de `getUserMedia`**, les caméras virtuelles, une télémétrie matérielle incohérente du navigateur ou l'absence d'attestation du périphérique.

## Références

- [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
