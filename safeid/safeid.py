#!/usr/bin/env python
"""
SafeID interacts with a Pythia PRF service to protect and verify passwords.
"""
import argparse, json, sys
from common import *
from httpJson import ServiceException, fetch, extract

from pyrelic.ecoprf import EcOprf
from pythiacrypto.groups import ec224

defaultServer = "https://remote-crypto.io"
queryUrlTemplate = "{}/pythia/oquery-ecc?w={}&t={}&m={}"
prf = EcOprf(ec224, serialize=True)

usage = \
"""safeid COMMAND [-s/--server https://pythia-server] [args]
Process passwords using the Pythia protocol

COMMANDS
new 'pw'            Protects a password using the Pythia protocol. 
                    Outputs the result as a JSON list.
check 'pw' 'JSON'   Checks a given passphrase against an existing 
                    protected password (JSON list).
"""


def new(password, server=defaultServer, clientId=None):
	"""
	Encrypts a new @password by interacting with the Pythia service.
	@clientId: If specified, this value is used. If omitted, a suitable 
	           value is selected.

	@returns a tuple of required values to verify the password: (w,t,z,p) 
	 where:
		@w: client ID (key selector)
		@t: tweak (randomly generated user ID)
		@z: protected passwords
		@p: server public key bound to clientId - used to verify future
		    proofs from this server.
	"""
	# Set the client ID
	if not clientId:
		w = secureRandom()
	else:
		w = clientId

	# Generate a random tweak t
	t = secureRandom()
	z,p = query(password, w, t, server)
	return w, t, z, p


def check(password, w, t, z, p, server=defaultServer):
	"""
	Checks an existing @password against the Pythia server using the 
	values (w,t,z,p).
	@returns: True if the password passes authentication; False otherwise.
	"""
	zPrime,_ = query(password, w, t, previousPubkey=p, server=server)
	return z == zPrime


def query(password, w, t, server=defaultServer, previousPubkey=None):
	"""
	Queries the a Pythia PRF service and verifies the server's ZKP.
	@returns (z,p) where: @z is the encrypted password and @p is the
		server's pubkey bound to clientId

	Raises an exception if there are any problems interacting with the service
		or if the server's ZKP fails verification.
	"""
	# Blind the password
	r,m = prf.wrapMessage(password)

	# Query the service via HTTP(S) GET
	response = fetch(queryUrlTemplate.format(server,w,t,m))

	# Grab the required fields from the response.
	p,y,c,u = extract(response, ["p","y","c","u"])

	# Verify ZKP 
	prf.verifyZkp(w, t, m, p, y, c, u, previousPubkey)

	# Deblind the result
	z = prf.unwrapResponse(r,y)

	# Return the important fields.
	return (z,p)


def main():
	"""
	Run the safeid command line program
	"""
	try:
		process(sys.argv)
	except Exception as e:
		print e


def process(args):
	"""
	Command line interface to SafeID
	"""
	# Parse arguments
	parser = argparse.ArgumentParser(usage=usage)
	parser.add_argument("COMMAND", choices=["new", "check"])
	parser.add_argument("passphrase", type=str)
	parser.add_argument("protectedPassphrase", nargs="?", type=str)
	parser.add_argument("-s", "--server", default=defaultServer, type=str)
	a = parser.parse_args(args[1:])

	##
	# Run the expected command
	##

	# New password
	if a.COMMAND == "new":
		print json.dumps(new(a.passphrase, a.server))

	# Check existing password
	elif a.COMMAND == "check" and a.protectedPassphrase:

		# Parse the encrypted password
		w,t,z,p = json.loads(a.protectedPassphrase)

		# Check the password
		if check(a.passphrase,w,t,z,p,a.server):
			print  "Password is authentic"
		else:
			print "Invalid password "

	else:
		print "usage: " + usage


# Run!
if __name__ == "__main__":
	main()

