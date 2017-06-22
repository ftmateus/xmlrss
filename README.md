# XMLRSS - A Java Crypto Provider for Redactable Signatures

Currently, xmlrss implements three redactable signature algorithms:

* PSRSS (based on "On Updatable Redactable Signatures" by Pöhls and Samelin)
* GSRSS (the general construction for sets, based on "A General Framework for Redactable Signatures and New
  Constructions" by Derler et al.)
* GLRSS (the general construction for lists, based on "A General Framework for Redactable Signatures and New
  Constructions" by Derler et al.)

XML encodings for following redactable signature algorithms:

* PSRSS
* GSRSS
* GLRSS

Implementations of cryptographic accumulators:

* PSA accumulator (based on the trapdoor accumulator in "On Updatable Redactable Signatures" by Pöhls and Samelin)
* BP accumulator (based on "Collision-Free Accumulators and Fail-Stop Signature Schemes Without Trees" by Barić and
  Pfitzmann)

## How to use it

xmlrss can be used very similar to other cryptographic service providers in Java:

* Add the xmlrss library as a dependency for your project
* Register the `WPProvider`
* Use redactable signatures via the `RedactableSignature` engine class

## How to compile it

This project uses gradle, which is pretty much self contained. Usually only a Java installation is required.
```
./gradlew build
```
