SafeID
--------------------

SafeID protects passwords using the Pythia PRF protocol. This module and it's
associated command-line tool (safeid) are a proof-of-concept that demonstrates
how a web server could protect user passwords as an alternative to simply
hashing passwords with random salts.

Requirements
--------------
SafeID uses the Pythia Python package, which requires the Charm Crypto Library for Python: 
http://www.charm-crypto.com/Download.html
If there was a PIP package, we'd automatically install upon installing Pythia, but sadly, there isn't one.