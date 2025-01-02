# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

**Apple Events** एप्पल के macOS में एक विशेषता है जो अनुप्रयोगों को एक-दूसरे के साथ संवाद करने की अनुमति देती है। ये **Apple Event Manager** का हिस्सा हैं, जो macOS ऑपरेटिंग सिस्टम का एक घटक है जो इंटरप्रोसेस संचार को संभालने के लिए जिम्मेदार है। यह प्रणाली एक अनुप्रयोग को दूसरे अनुप्रयोग को एक संदेश भेजने की अनुमति देती है ताकि वह एक विशेष ऑपरेशन कर सके, जैसे कि एक फ़ाइल खोलना, डेटा प्राप्त करना, या एक आदेश निष्पादित करना।

mina daemon `/System/Library/CoreServices/appleeventsd` है जो सेवा `com.apple.coreservices.appleevents` को पंजीकृत करता है।

हर अनुप्रयोग जो घटनाएँ प्राप्त कर सकता है, इस daemon के साथ अपनी Apple Event Mach Port की जांच करेगा। और जब एक ऐप इसे एक घटना भेजना चाहता है, तो ऐप इस पोर्ट को daemon से अनुरोध करेगा।

Sandboxed अनुप्रयोगों को घटनाएँ भेजने के लिए `allow appleevent-send` और `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` जैसी विशेषाधिकारों की आवश्यकता होती है। ध्यान दें कि `com.apple.security.temporary-exception.apple-events` जैसी अनुमतियाँ उन लोगों को प्रतिबंधित कर सकती हैं जिनके पास घटनाएँ भेजने की अनुमति है, जिसके लिए `com.apple.private.appleevents` जैसी अनुमतियों की आवश्यकता होगी।

> [!TIP]
> संदेश भेजने के बारे में जानकारी लॉग करने के लिए env वेरिएबल **`AEDebugSends`** का उपयोग करना संभव है:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
