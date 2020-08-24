# Reset Password Bypass

Sometimes in order to reset a password you contact an api endpoint and **send the email you want to reset the password**, like in the following example:

![](.gitbook/assets/1_6qc-agcjyzwmf8rgnvr_eg.png)

The back-end may take the information present in the **Host header** and use it for the link where the token to reset the password is going to be sent.  
For example, in this case if could send the reset password email to _something@gmail.com_ and set the token link to _https://bing.com/resetpasswd?token=12348rhfblrihvkurewfwu23_

Example from [https://medium.com/@abhishake100/password-reset-poisoning-to-ato-and-otp-bypass-1a3b0eba5491](https://medium.com/@abhishake100/password-reset-poisoning-to-ato-and-otp-bypass-1a3b0eba5491)

