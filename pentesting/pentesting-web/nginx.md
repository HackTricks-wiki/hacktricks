# Nginx

**Most part of this page was copied from** [**https://blog.detectify.com/2020/11/10/common-nginx-misconfigurations/**](https://blog.detectify.com/2020/11/10/common-nginx-misconfigurations/)\*\*\*\*

## Missing root location

```text
server {
        root /etc/nginx;

        location /hello.txt {
                try_files $uri $uri/ =404;
                proxy_pass http://127.0.0.1:8080/;
        }
}
```

The root directive specifies the root folder for Nginx. In the above example, the root folder is `/etc/nginx` which means that we can reach files within that folder. The above configuration does not have a location for `/ (location / {...})`, only for `/hello.txt`. Because of this, the `root` directive will be globally set, meaning that requests to `/` will take you to the local path `/etc/nginx`.   

A request as simple as `GET /nginx.conf` would reveal the contents of the Nginx configuration file stored in `/etc/nginx/nginx.conf`. If the root is set to `/etc`, a `GET` request to `/nginx/nginx.conf` would reveal the configuration file. In some cases it is possible to reach other configuration files, access-logs and even encrypted credentials for HTTP basic authentication.

## Alias LFI Misconfiguration

Inside the Nginx configuration look the "location" statements, if someone looks like:

```text
location /imgs { 
    alias /path/images/ 
}
```

There is a LFI vulnerability because:

```text
/imgs../flag.txt
```

Transforms to:

```text
/path/images/../flag.txt
```

The correct configuration will be:

```text
location /imgs/ { 
    alias /path/images/ 
}
```

**So, if you find some Nginx server you should check for this vulnerability. Also, you can discover it if you find that the files/directories brute force is behaving weird.**

More info: [https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/](https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/)

Accunetix tests:

```text
alias../ => HTTP status code 403
alias.../ => HTTP status code 404
alias../../ => HTTP status code 403
alias../../../../../../../../../../../ => HTTP status code 400
alias../ => HTTP status code 403
```

## Unsafe variable use

Some frameworks, scripts and Nginx configurations unsafely use the variables stored by Nginx. This can lead to issues such as XSS, bypassing HttpOnly-protection, information disclosure and in some cases even RCE.

### SCRIPT\_NAME

With a configuration such as the following:

```text
        location ~ \.php$ {
                include fastcgi_params;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                fastcgi_pass 127.0.0.1:9000;
        }
```

The main issue will be that Nginx will send any URL to the PHP interpreter ending in `.php` even if the file doesn’t exist on disc. This is a common mistake in many Nginx configurations, as outlined in the “[Pitfalls and Common Mistakes](https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/#passing-uncontrolled-requests-to-php)” document created by Nginx. 

An XSS will occur if the PHP-script tries to define a base URL based on `SCRIPT_NAME`;

```text
<?php

if(basename($_SERVER['SCRIPT_NAME']) ==
basename($_SERVER['SCRIPT_FILENAME']))
   echo dirname($_SERVER['SCRIPT_NAME']);

?>

GET /index.php/<script>alert(1)</script>/index.php
SCRIPT_NAME  =  /index.php/<script>alert(1)</script>/index.php
```

### Usage of $uri can lead to CRLF Injection

Another misconfiguration related to Nginx variables is to use `$uri` or `$document_uri` instead of `$request_uri`. `$uri` and `$document_uri` contain the normalized URI whereas the `normalization` in Nginx includes URL decoding the URI. [Volema](http://blog.volema.com/nginx-insecurities.html#header:~:text=Case%202%3A%20rewrite%20with%20%24uri%20%28%24document_uri%29) found that `$uri` is commonly used when creating redirects in the Nginx configuration which results in a CRLF injection.

An example of a vulnerable Nginx configuration is:

```text
location / {
  return 302 https://example.com$uri;
}
```

The new line characters for HTTP requests are \r \(Carriage Return\) and \n \(Line Feed\). URL-encoding the new line characters results in the following representation of the characters `%0d%0a`. When these characters are included in a request like `http://localhost/%0d%0aDetectify:%20clrf` to a server with the misconfiguration, the server will respond with a new header named `Detectify` since the $uri variable contains the URL-decoded new line characters.

```text
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.19.3
Content-Type: text/html
Content-Length: 145
Connection: keep-alive
Location: https://example.com/
Detectify: clrf
```

Learn more about the risks of CRLF injection and response splitting at  [https://blog.detectify.com/2019/06/14/http-response-splitting-exploitations-and-mitigations/](https://blog.detectify.com/2019/06/14/http-response-splitting-exploitations-and-mitigations/).

### Any variable

In some cases, user-supplied data can be treated as an Nginx variable. It’s unclear why this may be happening, but it’s not that uncommon or easy to test for as seen in this [H1 report](https://hackerone.com/reports/370094). If we search for the error message, we can see that it is found in the [SSI filter module](https://github.com/nginx/nginx/blob/2187586207e1465d289ae64cedc829719a048a39/src/http/modules/ngx_http_ssi_filter_module.c#L365), thus revealing that this is due to SSI.

One way to test for this is to set a referer header value: 

```text
$ curl -H ‘Referer: bar’ http://localhost/foo$http_referer | grep ‘foobar’
```

We scanned for this misconfiguration and found several instances where a user could print the value of Nginx variables. The number of found vulnerable instances has declined which could indicate that this was patched. 

## Raw backend response reading

With Nginx’s `proxy_pass`, there’s the possibility to intercept errors and HTTP headers created by the backend. This is very useful if you want to hide internal error messages and headers so they are instead handled by Nginx. Nginx will automatically serve a custom error page if the backend answers with one. But what if Nginx does not understand that it’s an HTTP response? 

If a client sends an invalid HTTP request to Nginx, that request will be forwarded as-is to the backend, and the backend will answer with its raw content. Then, Nginx won’t understand the invalid HTTP response and just forward it to the client. Imagine a uWSGI application like this: 

```text
def application(environ, start_response):
   start_response('500 Error', [('Content-Type',
'text/html'),('Secret-Header','secret-info')])
   return [b"Secret info, should not be visible!"]
```

And with the following directives in Nginx: 

```text
http {
   error_page 500 /html/error.html;
   proxy_intercept_errors on;
   proxy_hide_header Secret-Header;
}
```

[proxy\_intercept\_errors](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_intercept_errors) will serve a custom response if the backend has a response status greater than 300. In our uWSGI application above, we will send a `500 Error` which would be intercepted by Nginx.

[proxy\_hide\_header](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_hide_header) is pretty much self explanatory; it will hide any specified HTTP header from the client. 

If we send a normal `GET` request, Nginx will return:

```text
HTTP/1.1 500 Internal Server Error
Server: nginx/1.10.3
Content-Type: text/html
Content-Length: 34
Connection: close
```

But if we send an invalid HTTP request, such as:

```text
GET /? XTTP/1.1
Host: 127.0.0.1
Connection: close
```

We will get the following response:

```text
XTTP/1.1 500 Error
Content-Type: text/html
Secret-Header: secret-info

Secret info, should not be visible!
```

## merge\_slashes set to off

The [merge\_slashes](http://nginx.org/en/docs/http/ngx_http_core_module.html#merge_slashes) directive is set to “on” by default which is a mechanism to compress two or more forward slashes into one, so `///` would become `/`. If Nginx is used as a reverse-proxy and the application that’s being proxied is vulnerable to local file inclusion, using extra slashes in the request could leave room for exploit it. This is described in detail by [Danny Robinson and Rotem Bar](https://medium.com/appsflyer/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d).

We found 33 Nginx configuration files with `merge_slashes` set to “off”.  

## Try it yourself

Detectify has created a GitHub repository where you can use Docker to set up your own vulnerable Nginx test server with some of the misconfigurations discussed in this article and try finding them yourself!

[https://github.com/detectify/vulnerable-nginx](https://github.com/detectify/vulnerable-nginx)

## Static Analyzer tools

### [GIXY](https://github.com/yandex/gixy)

Gixy is a tool to analyze Nginx configuration. The main goal of Gixy is to prevent security misconfiguration and automate flaw detection.

