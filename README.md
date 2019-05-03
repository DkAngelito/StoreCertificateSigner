# StoreCertificateSigner
Create a signature using non-exportable private key in Windows certificate store

This repo allows to create a cryptographic signature of the provided hash using the private keys associated with the certificate that is located in Windows certificate store. The most important part is that the private keys are "non-exportable", thus they are not retrieved by the code but only a context to the private keys is found and used for signing. 

The signing part is done using NCrypt library (C/C++) code and there is a wrapper that compiles it into C++\CLI managed class that can be called from C#.
