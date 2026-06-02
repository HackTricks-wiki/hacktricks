# Android Carrier Billing and Premium SMS Fraudware Analysis

{{#include ../../banners/hacktricks-training.md}}

Some Android fraudware focuses on **charging the victim through the mobile operator path** instead of stealing banking credentials. The common pattern is to activate only when the SIM/operator matches a hardcoded or remotely supplied target list, such as **MCC/MNC**, operator name, or operator code. Otherwise, the app shows benign content to reduce analyst exposure.

## Fraud Flow

Typical workflow:

1. Read telephony identifiers and gate execution by operator/country.
2. If needed, disable Wi-Fi so carrier portals see the victim coming from the mobile network.
3. Open the carrier billing flow in a hidden `WebView` while the foreground UI shows unrelated content.
4. Use JavaScript to press Request OTP / Confirm buttons and fill subscription forms.
5. Capture the billing OTP with the SMS Retriever API or direct SMS access, then inject it into the hidden `WebView`.
6. Fall back to premium SMS enrollment by sending keywords to short codes when the operator flow is SMS-based.
7. Exfiltrate cookies, HTML, operator metadata, and conversion status to tune selectors and campaign analytics.

## Reversing Indicators

Interesting implementation details to hunt for during reversing:

- **Operator gating:** `TelephonyManager.getSimOperator()`, `getSimOperatorName()`, `getNetworkOperator()` plus hardcoded MCC/MNC lists.
- **Hidden WebViews:** off-screen/minimized `WebView` objects loading carrier URLs while the visible UI keeps the user distracted.
- **JS-driven fraud:** `evaluateJavascript(...)` / `loadUrl("javascript:...")` used to click billing buttons or populate TAC/OTP fields.
- **OTP interception without `READ_SMS`:** malware can abuse Google's [SMS Retriever API](https://developers.google.com/android/reference/com/google/android/gms/auth/api/phone/SmsRetrieverApi) to receive OTP-style messages that match the retriever flow.
- **Cookie theft:** `CookieManager.getInstance().getCookie(<billing_url>)` after loading the carrier page to reuse the WebView billing session.
- **Delayed SMS scheduling:** premium SMS sends spaced by 60-90 seconds to look less bursty and bypass anti-fraud heuristics.
- **Telemetry over public services:** Telegram Bot API or similar SaaS channels used as a lightweight install, send-status, and operator-reporting backend.

## Quick Triage

```bash
rg -n 'getSimOperator|getNetworkOperator|SmsRetriever|startSmsRetriever|sendTextMessage|CookieManager|getCookie|setWifiEnabled|evaluateJavascript|javascript:' .
```

Hook WebView cookie access while analyzing the sample:

```javascript
Java.perform(() => {
  const CM = Java.use('android.webkit.CookieManager');
  CM.getCookie.overload('java.lang.String').implementation = function (url) {
    console.log('[CookieManager] ' + url);
    return this.getCookie(url);
  };
});
```

## Dynamic Analysis Notes

- Force different operator paths in the emulator/device by hooking `TelephonyManager` getters or patching Smali constants.
- Watch for network changes before the billing page is opened; toggling Wi-Fi can be the signal that the malware needs the operator-authenticated path.
- If the sample keeps a benign page visible, inspect for secondary/off-screen WebViews and dump both the HTML and cookies after each carrier portal load.

## References

- [Premium Deception: Uncovering a Global Android Carrier Billing Fraud Campaign](https://zimperium.com/blog/premium-deception-uncovering-a-global-android-carrier-billing-fraud-campaign)
- [SmsRetrieverApi reference](https://developers.google.com/android/reference/com/google/android/gms/auth/api/phone/SmsRetrieverApi)
- [Android `CookieManager` reference](https://developer.android.com/reference/android/webkit/CookieManager)

{{#include ../../banners/hacktricks-training.md}}
