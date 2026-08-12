# Word Macros

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Macros zinaweza kuwa na **code isiyoweza kufikiwa au isiyohusika** inayolenga kuchelewesha uchanganuzi. Tambua masharti yasiyobadilika na fuatilia tabia inayoweza kufikiwa kabla ya kutumia muda ku-reverse branch. Mfano ulio hapa chini unatumia sharti la `If` ambalo haliwezi kamwe kuwa kweli ili kuficha junk code.

![Word macro yenye branch ya masharti isiyoweza kufikiwa iliyo na junk code](<../images/image (369).png>)

## Macro Forms

VBA UserForms zinaweza kuhifadhi data katika controls kama vile text boxes. Kwa kuwa forms, frames, na pages zinaweza kila moja kutoa `Controls` collection, wachanganuzi wanapaswa kuorodhesha hierarchy nzima ya controls badala ya kutegemea tu kile kinachoonyeshwa na form. Mfano ulio hapa chini huhifadhi data iliyofichwa katika text boxes zinazopishana.<sup>[[1]](#references)</sup>

Wakati wa dynamic analysis, function ya VBA `GetObject` inaweza kupata Automation object kutoka kwenye file au kuambatisha kwenye Automation server ambayo tayari inaendeshwa. Macros zinaweza kutumia ufikiaji huo wa object kufikia data ambayo si dhahiri katika document inayoonekana; kagua object iliyorudishwa pamoja na control tree ya UserForm.<sup>[[2]](#references)</sup>

![Macro UserForm yenye data iliyofichwa katika text boxes zinazopishana](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Collections, controls, and objects (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - `GetObject` function](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
