In order to implement SSL pinning you will need a certificate within your application to verify the remote credentials against.
The public key of this certificate should match that of the server(s) you intend to trust. Obviously, you need a way to get these certificates and in the correct format. This example project expects the data to be in OpenSSL DER format, with the certificate files named "HOSTNAME.der".

Example of getting a certificate from an existing server and outputting in PEM format:
openssl s_client -showcerts -connect www.google.com:443 -prexit > www.google.com.pem </dev/null

Example of verifying a PEM certificate
openssl x509 -in www.google.com.pem -text -noout

Example of converting a certificate in PEM format to DER:
openssl x509 -outform der -in www.google.com.pem -out www.google.com.der

Example of verifying a DER certificate
openssl x509 -in www.google.com.der -text -noout


Follow the examples above to create DER formatted certificate files for the hosts you are interested in connecting to. Include the certificate files in your project and make sure the are copied into the build product bundle as part of your build process.

You can use PublicKeyPinningConnectionDelegate as an example of how to implement SSL public key pinning yourself, or you can subclass it when implementing your own delegate. It provides only authentication. It will evaluate server credential trust, but for all other authentication methods it falls over to the default handling of the URL loading system. It won't handle receiving data, errors, etc. - that is up to you.