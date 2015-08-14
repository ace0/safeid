SafeID
=====================

SafeID protects passwords using the Pythia PRF protocol. This package includes
a python module and a command-line tool (safeid) that demonstrates
how a web server can protect passwords using a remote Pythia PRF service.

Quick Start
--------------------
If you have Python and PIP, you can install SafeID with:

`pip install safeid`

By default, SafeID uses a test and development Pythia PRF hosted at https://remote-crypto.io.

To use the SafeID command to protect a new password:

```PPASS=`safeid new 'passphrase'` ```

The output of SafeID is packaged as a JSON array. It's bulky, and so the above command is the easiest way to capture the output as a shell variable. Run the command without the 'PPASS=' or examine the output with:

`echo $PPASS`

You can check any Pythia-protected password with this command. (The double-quotes around the protected password are very important otherwise the shell will break up the JSON array.)

`safeid check 'passphrase' "$PPASS"`


Requirements
------------------------
SafeID uses the pyrelic Python module: https://github.com/ace0/pyrelic

