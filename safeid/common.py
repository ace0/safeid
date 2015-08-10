"""
Common routines
"""
import hmac as HMAC
from base64 import urlsafe_b64encode as b64encode
import hashlib, os

HASH_ALG = hashlib.sha256
HASH_LENGTH = 32

TAG_PASSWORD = "TAG_SAFEID_PASSWORD"
TAG_USER = "TAG_SAFEID_USER"

def hmac(tag, message, key, alg=HASH_ALG):
	"""
	Generates a hashed message authentication code (HMAC) by prepending the
	specified @tag string to a @message, then hashing according to HMAC with the 
	cryptographic @key and hashing @alg -orithm.
	@returns the result of the HMAC after encoding with the specified
		@encode function.  By default this is url-safe base64 encoding.
	"""
	# Run the inputs through HMAC and then run the digest @d through
	# (URL-safe) base64 encoding.
	d = HMAC.new(str(key), tag + message, digestmod=alg).digest()
	return b64encode(d)


def secureRandom(n=HASH_LENGTH):
	"""
	Gets a secure random string (base64 encoded) of @n bytes.
	"""
	return str(b64encode(os.urandom(n))[:n])


def dp(**kwargs):
	"""
	Debugging print. Prints a list of labels and values, each on their
	own line.
	"""
	for label,value in kwargs.iteritems():
		print "{0}\t{1}".format(label, value)
