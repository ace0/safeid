"""
Routines for interacting with a remote service via HTTP/HTTPS and parsing the 
response as JSON.
"""
import httplib2, json, socket

httpClient = httplib2.Http()

ERROR_JSON = "Could not understand response from the remote service; not "\
	"valid JSON content. "


class ServiceException(Exception):
	"""
	An exception occurred while interacting with a remote PRF service.
	Don't freak out: this is the internet, these things happen.
	"""
	def __init__(self, message):
		self.message = message

	def __str__(self):
		return self.message


def fetch(url, maxTries=5, debug=False):
	"""
	Aggressively tries to fetch the response value from @url.

	@returns result or throws an exception if no valid response is 
	retrieved after @maxTries attempts.
	"""
	if debug:
		print "Fetching " + url

	# Try to get the URL, but quit after the maximum number of tries.
	for _ in range(maxTries):
		try:
			# Fetch the URL with a GET request.
			response, content = httpClient.request(url, "GET")

			# Read the response
			return parse(response, content, url)

		# TODO: test socket errors and HTTP timeouts
		except socket.error as (errno, msg):
			if debug:
				print "socket.error: " + msg
			errorMessage = "Could not connect to service: " + msg

	# No success after multiple tries
	raise ServiceException(errorMessage)


def extract(d, requiredFields):
	"""
	Verifies that the dictionary @d contains the @requiredFields.
	@returns the required fields as a tuple.

	Raises a ServiceException if any of the required fields are missing.
	"""
	# Check for the required fields.
	for k in requiredFields:
		if k not in d:
			raise ServiceException("Server's response is missing required "\
				"field {}. \nServer's response: \n{}".format(k, d))

	return tuple([d[x] for x in requiredFields])


def parse(response, content, url):
	"""
	Parse the HTTP @response and @content from the remote service and return
	a dictionary. Raises a ServiceException if the server reported any status
	except HTTP 200 (OK) or if the reponses is not valid JSON.
	"""
	# Check the status code of the response.
	if response.status != 200:
		error = "Remote service reported an error (status:{} {}) for "\
			"URL {}".format(response.status, response.reason, url)
		raise ServiceException(error)

	# Try to decode the content as JSON
	try:
		return json.loads(content)

	except ValueError:
		raise ServiceException(ERROR_JSON + "\n" + content)
