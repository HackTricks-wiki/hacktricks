# Stealing Sensitive Information Disclosure from a Web

If at some point you find a** web page that presents you sensitive information based on your session**: Maybe it's reflecting cookies, or printing or CC details or any other sensitive information, you may try to steal it.\
Here I present you the main ways to can try to achieve it:

* [**CORS bypass**](pentesting-web/cors-bypass.md): If you can bypass CORS headers you will be able to steal the information performing Ajax request for a malicious page.
* ****[**XSS**](pentesting-web/xss-cross-site-scripting/): If you find a XSS vulnerability on the page you may be able to abuse it to steal the information.
* ****[**Danging Markup**](pentesting-web/dangling-markup-html-scriptless-injection.md): If you cannot inject XSS tags you still may be able to steal the info using other regular HTML tags.
* [**Clickjaking**](pentesting-web/clickjacking.md): If there is no  protection against this attack, you may be able to trick the user into sending you the sensitive data (an example [here](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).
