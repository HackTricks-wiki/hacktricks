# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

**Apple Events** Apple के macOS का एक feature है, जो applications को एक-दूसरे के साथ communicate करने की अनुमति देता है। ये **Apple Event Manager** का हिस्सा हैं, जो macOS operating system का एक component है और interprocess communication को handle करने के लिए responsible है। यह system एक application को दूसरी application को message भेजकर किसी विशेष operation को perform करने का request करने में सक्षम बनाता है, जैसे file खोलना, data retrieve करना या command execute करना।

मुख्य daemon `/System/Library/CoreServices/appleeventsd` है, जो `com.apple.coreservices.appleevents` service को register करता है।

Events receive कर सकने वाली हर application इस daemon के साथ अपना Apple Event Mach Port provide करके register करेगी। और जब कोई app उसे event भेजना चाहती है, तो app daemon से इस port का request करेगी।

Sandboxed applications को events भेजने में सक्षम होने के लिए `allow appleevent-send` और `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` जैसे privileges की आवश्यकता होती है। ध्यान दें कि `com.apple.security.temporary-exception.apple-events` जैसे entitlements यह restrict कर सकते हैं कि events भेजने की access किसे है, जिसके लिए `com.apple.private.appleevents` जैसे entitlements आवश्यक होंगे।

> [!TIP]
> भेजे गए message से संबंधित information log करने के लिए **`AEDebugSends`** env variable का उपयोग करना संभव है:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
