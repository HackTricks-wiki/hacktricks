# Reset/Forgoten Password Bypass

## HTTP Headers

Sometimes in order to reset a password you contact an api endpoint and **send the email you want to reset the password**, like in the following example:

![](.gitbook/assets/1_6qc-agcjyzwmf8rgnvr_eg.png)

The back-end may take the information present in the **Host header** and use it for the link where the token to reset the password is going to be sent.  
For example, in this case if could send the reset password email to _something@gmail.com_ and set the token link to _https://bing.com/resetpasswd?token=12348rhfblrihvkurewfwu23_

Example from [https://medium.com/@abhishake100/password-reset-poisoning-to-ato-and-otp-bypass-1a3b0eba5491](https://medium.com/@abhishake100/password-reset-poisoning-to-ato-and-otp-bypass-1a3b0eba5491)

In other occasions you can manage to obtain the **same** **results** modifying the domain used in the **Referer header like in** [**here**](https://medium.com/bugbountywriteup/fun-with-header-and-forget-password-without-that-nasty-twist-cbf45e5cc8db)**.**

