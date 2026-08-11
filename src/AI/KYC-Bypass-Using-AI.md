# Bypass du KYC avec l'IA

{{#include ../banners/hacktricks-training.md}}

Les modèles génératifs peuvent être utilisés pour **contourner les workflows KYC basés sur un navigateur, la vérification de l'âge et la détection biométrique de vivacité**. Le point faible ne se situe souvent **ni au niveau du transport ni chez le fournisseur cloud de détection de vivacité**, mais au niveau de la **frontière de confiance de la caméra** : un navigateur desktop fait généralement confiance à tout périphérique que `getUserMedia()` expose comme webcam.<sup>[[1]](#references)</sup>

## Chaîne d'attaque pratique

1. **Générer un média conforme aux challenges** avec un modèle video-to-video à partir d'un acteur source et d'une image de référence de la victime.<sup>[[1]](#references)</sup>
2. **Injecter le flux falsifié avant la signature ou l'upload**, par exemple via une caméra virtuelle Linux créée avec `v4l2loopback` et alimentée par OBS ou FFmpeg.<sup>[[3]](#references)</sup>
3. Laisser le navigateur et le SDK du fournisseur (WebRTC, AWS, etc.) **capturer, signer et uploader les frames contrôlées par l'attaquant comme si elles provenaient d'une webcam réelle**.<sup>[[2]](#references)</sup>

Cela est important lors des assessments, car les chunks WebSocket signés ou le framing propriétaire d'un SDK peuvent rendre la **modification au niveau réseau** impraticable, tandis que **l'injection au niveau de la caméra** continue de fonctionner.<sup>[[1]](#references)</sup>

## Axes de test à forte valeur

- **Acceptation des webcams virtuelles** : si le workflow fonctionne depuis un navigateur desktop, tester si OBS, `v4l2loopback` ou les caméras virtuelles du fournisseur sont acceptés comme des périphériques normaux.<sup>[[1]](#references)</sup>
- **Redirection de l'API caméra sur mobile** : les workflows natifs peuvent rester vulnérables lorsque l'instrumentation runtime, comme Frida, hooke les API caméra et remplace les buffers du capteur par des frames provenant d'un fichier MP4 ou d'une caméra virtuelle fournie par un émulateur. Cela nécessite le contrôle de l'environnement d'exécution du client et doit être évalué avec les signaux de root/jailbreak et d'intégrité de l'application.<sup>[[1]](#references)</sup>
- **Affaiblissement des contraintes** : les pages qui exigent un `deviceId`, un `frameRate`, une `width`, une `height` ou un `facingMode` exacts peuvent parfois être contournées en monkeypatchant `navigator.mediaDevices.getUserMedia` et en remplaçant les contraintes strictes par des plages plus larges.<sup>[[4]](#references)</sup>
- **Génération de faible qualité avec post-traitement** : tester si une vidéo générée à faible coût peut être upscalée ou interpolée par frames avec FFmpeg suffisamment pour respecter les contraintes de capture.<sup>[[1]](#references)</sup>
- **Challenges actifs prévisibles** : les séquences répétées de mouvements de tête ou de flash lumineux méritent d'être enregistrées et rejouées via un workflow génératif.
- **Détection faible du replay** : de simples perturbations de scène, comme des changements de recadrage ou de position, des modifications de superposition ou de légers mouvements, peuvent suffire lorsque la logique anti-replay ne vérifie que la similarité superficielle entre les frames.<sup>[[1]](#references)</sup>

## Différences de confiance entre mobile et desktop

Les applications mobiles natives peuvent augmenter le coût pour l'attaquant grâce aux éléments suivants :<sup>[[1]](#references)</sup>

- **signaux de provenance ou d'attestation supportés par le matériel**, y compris les preuves adossées à un Secure Element lorsque la plateforme et la stack de capture les exposent réellement ;
- des signaux d'**intégrité de l'exécution**, tels que **Play Integrity** ou **App Attest** ;<sup>[[5]](#references)[[6]](#references)</sup>
- une **corrélation des mouvements** entre la vidéo et la télémétrie de l'accéléromètre ou du gyroscope.

Les workflows web desktop ne disposent généralement pas d'une chaîne de confiance équivalente pour la caméra ; ils constituent donc généralement la voie de moindre résistance.<sup>[[1]](#references)</sup>

## Notes pour la revue défensive

Lors de l'examen d'une intégration KYC ou de détection de vivacité, vérifier si elle :<sup>[[1]](#references)</sup>

- autorise un **fallback via navigateur desktop** pour un workflow dont le threat modeling ne concernait que la capture mobile ;
- repose principalement sur la **détection algorithmique de vivacité** sans escalade humaine solide pour les sessions suspectes ;
- utilise des **challenges stables ou prévisibles** qui peuvent être préenregistrés et injectés dans une pipeline de génération ;
- détecte le **monkeypatching de `getUserMedia`**, les caméras virtuelles, une télémétrie matérielle incohérente du navigateur ou l'absence d'attestation du périphérique.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC : contourner la vérification de l'âge avec des modèles vidéo génératifs](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — Play Integrity API](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
