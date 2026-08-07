# Contourner le KYC avec l'IA

{{#include ../banners/hacktricks-training.md}}

Les modèles génératifs peuvent être utilisés pour **contourner les workflows KYC, de vérification de l'âge et de détection de vivacité biométrique basés sur un navigateur**. Le point faible ne se situe souvent **ni au niveau du transport ni chez le fournisseur cloud de détection de vivacité**, mais au niveau de la **limite de confiance de la caméra** : un navigateur desktop fait généralement confiance à tout périphérique que `getUserMedia()` expose comme webcam.<sup>[[1]](#references)</sup>

## Chaîne d'attaque pratique

1. **Générer un média conforme aux challenges** avec un modèle video-to-video à partir d'un acteur source et d'une image de référence de la victime.<sup>[[1]](#references)</sup>
2. **Injecter le flux falsifié avant la signature ou l'upload**, par exemple via une caméra virtuelle Linux créée avec `v4l2loopback` et alimentée par OBS ou FFmpeg.<sup>[[3]](#references)</sup>
3. Laisser le navigateur et le SDK du fournisseur (WebRTC, AWS, etc.) **capturer, signer et uploader les frames contrôlées par l'attaquant comme si elles provenaient d'une webcam réelle**.<sup>[[2]](#references)</sup>

Cela est important lors des assessments, car les chunks WebSocket signés ou le framing propriétaire d'un SDK peuvent rendre la **modification au niveau réseau** impraticable, tandis que **l'injection au niveau de la caméra** continue de fonctionner.<sup>[[1]](#references)</sup>

## Axes de test à forte valeur

- **Acceptation des webcams virtuelles** : si le workflow fonctionne depuis un navigateur desktop, vérifier si OBS, `v4l2loopback` ou les caméras virtuelles du fournisseur sont acceptés comme des périphériques normaux.<sup>[[1]](#references)</sup>
- **Redirection de l'API caméra sur mobile** : les workflows mobiles natifs peuvent rester vulnérables lorsque Frida hooke les APIs caméra et remplace les buffers du capteur par des frames provenant d'un MP4 ou d'une caméra virtuelle fournie par un émulateur.
- **Affaiblissement des contraintes** : les pages qui exigent un `deviceId`, un `frameRate`, une `width`, une `height` ou un `facingMode` précis peuvent parfois être contournées en monkeypatchant `navigator.mediaDevices.getUserMedia` et en remplaçant les contraintes strictes par des plages plus larges.<sup>[[4]](#references)</sup>
- **Génération basse qualité avec post-traitement** : générer la vidéo la moins coûteuse que le modèle peut restituer de manière fiable, puis utiliser l'upscaling de FFmpeg ou l'interpolation d'images pour satisfaire les exigences de capture.
- **Challenges actifs prévisibles** : les séquences répétées de mouvements de tête ou de flashs lumineux méritent d'être enregistrées et rejouées via un workflow génératif.
- **Détection de replay faible** : de simples perturbations de scène, comme des changements de crop ou de position, des modifications de overlays ou de légers mouvements, peuvent suffire lorsque la logique anti-replay vérifie uniquement une similarité superficielle entre les frames.<sup>[[1]](#references)</sup>

## Différences de confiance entre mobile et desktop

Les applications mobiles natives peuvent augmenter le coût de l'attaque avec :<sup>[[1]](#references)</sup>

- **l'attestation du capteur ou du Secure Element** pour les buffers caméra ;
- les signaux d'**intégrité de l'exécution**, tels que **Play Integrity** ou **App Attest** ;
- la **corrélation des mouvements** entre la vidéo et les données de télémétrie de l'accéléromètre ou du gyroscope.

Les workflows web desktop ne disposent généralement pas d'une chaîne de confiance équivalente pour la caméra et constituent donc généralement le chemin offrant le moins de résistance.<sup>[[1]](#references)</sup>

## Notes pour la revue défensive

Lors de la revue d'une intégration KYC ou de détection de vivacité, vérifier si elle :<sup>[[1]](#references)</sup>

- autorise un **fallback via navigateur desktop** pour un workflow dont le threat modeling ne concernait que la capture mobile ;
- repose principalement sur la **détection algorithmique de vivacité** sans escalade humaine solide pour les sessions suspectes ;
- utilise des **challenges stables ou prévisibles** qui peuvent être préenregistrés et injectés dans un pipeline de génération ;
- détecte le **monkeypatching de `getUserMedia`**, les caméras virtuelles, les données de télémétrie matérielle incohérentes du navigateur ou l'absence d'attestation du périphérique.<sup>[[1]](#references)</sup>

## Références

- [1] [Synacktiv - Contourner la vérification de l'âge avec des modèles vidéo génératifs](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
