# What this is

This is an example implementation of SSL public key pinning for iOS, using NSURLConnection. 
When a client connects to a server over SSL/TLS, the server provides a certificate. That certificate contains a public key. In this example we extract the public key and compare it against a local copy. If the server public key does not match expectations, we do not trust it and will not connect.

Using the public key has advantages over checking the whole certificate. Certificates contain a public key, information about the certificate, and other keys. Certificates can change often, while the public keys within them should change much less often.

THIS IS ESPECIALLY USEFUL IF YOU ARE USING SELF SIGNED CERTIFICATES.
See [Techical Note 2232: HTTPS Server Trust Evaluation](https://developer.apple.com/library/mac/technotes/tn2232/_index.html) for more information on SSL trust evaluation.

### Getting started

In order to implement SSL pinning you will need a certificate within your application to verify the remote credentials against.
The public key of this certificate should match that of the server(s) you intend to trust. Obviously, you need a way to get these certificates and in the correct format. This example project expects the data to be in OpenSSL `DER` format, with the certificate files named "HOSTNAME.der".

Example of getting a certificate from an existing server and outputting in PEM format:

`openssl s_client -showcerts -connect www.google.com:443 -prexit > www.google.com.pem </dev/null`

Example of verifying a `PEM` certificate:

`openssl x509 -in www.google.com.pem -text -noout`

Example of converting a certificate in `PEM` format to `DER`:

`openssl x509 -outform der -in www.google.com.pem -out www.google.com.der`

Example of verifying a DER certificate:

`openssl x509 -in www.google.com.der -text -noout`


Follow the examples above to create `DER` formatted certificate files for the hosts you are interested in connecting to. Include the certificate files in your project and make sure the are copied into the build product bundle as part of your build process.

### Use

You can use `PublicKeyPinningConnectionDelegate` as an example of how to implement SSL public key pinning yourself, or you can subclass it when implementing your own delegate. It provides only authentication. It will evaluate server credential trust, but for all other authentication methods it falls over to the default handling of the URL loading system. It won't handle receiving data, errors, etc. - that is up to you.