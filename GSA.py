import srp
import base64
from datetime import datetime
import requests
import plistlib

def GSA_authenticate(username, password):

	####################
	###### Step 1 ######
	####################


	# Create the a2k section of the plist payload.
	a2k_data = srp.create_salted_verification_key(username, password, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
	time = datetime.utcnow().isoformat()[:-7]+'Z'

	# Request headers for Apple's GSA API.

	headers = {
		'Host': 'gsa.apple.com',
		'Content-Type': 'text/x-xml-plist',
		'X-Mme-Client-Info': '<iPhone6,1> <iPhone OS;12.4.8;16G201> <com.apple.akd/1.0 (com.apple.akd/1.0)>',
		'Accept': '*/*',
		'Accept-Language': 'en-us',
		'User-Agent': 'akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0'
	}

	url = "https://gsa.apple.com/grandslam/GsService2"

	data_obj = {
		"Header": {
			"Version": "1.0.1"
		},
		"Request": {
			"A2k": a2k_data,
			"cpd": {
				"AppleIDClientIdentifier": "D4B7512F-E841-4AEA-A569-4F1E84738182",
				"X-Apple-I-Client-Time": time,
				"X-Apple-I-MD": "AAAABQAAABCMMt6qegoLwK7/SjhV8/XQAAAAAw==",
				"X-Apple-I-MD-M": "BvleDr7BzY/U0+RwcEwPJiikBNW9J69y8qtmJi1xrzXVwz+iTq5fZWSA2S+9ssE3dDpMpuXCxsWQ/at1",
				"X-Apple-I-MD-RINFO": "17106176",
				"X-Apple-I-SRL-NO": "C39L80JCFNJT",
				"X-Mme-Device-Id": "2c7a7a35e0a441245fbf7e2c5cad03fce2dca5d8",
				"bootstrap": True,
				"capp": "AppStore",
				"ckgen": True,
				"dc": "#d4c5b3",
				"dec": "#e1e4e3",
				"loc": "en_US",
				"pbe": False,
				"prtn": "ME349",
				"svct": "iTunes"
			},
			"o": "init",
			"ps": ["s2k", "s2k_fo"],
			"u": username
		}
	}
	data = plistlib.dumps(data_obj).decode("utf-8")

	r = requests.post(url, data=data, headers=headers, verify=False)
	content = r.content
	pl = plistlib.loads(content)
	
	# Extract s and B from request.
	s_b64 = base64.b64encode(pl["Response"]["s"]).decode("utf-8")
	B_b64 = base64.b64encode(pl["Response"]["B"]).decode("utf-8")
	
	# Extract c parameter which is used in subsequent header.
	c = pl["Response"]["c"]


	# Build M1
	s = base64.b64decode(s_b64)
	B = base64.b64decode(B_b64)
	
	usr = srp.User( username, password, hash_alg=srp.SHA256, ng_type=srp.NG_2048 )
	M1 = usr.process_challenge(s, B)










	####################
	###### Step 2 ######
	####################

	time = datetime.utcnow().isoformat()[:-7]+'Z'

	data2_obj = {
		"Header": {
			"Version": "1.0.1"
		},
		"Request": {
			"M1": M1,
			"c": c,
			"cpd": {
				"AppleIDClientIdentifier": "D4B7512F-E841-4AEA-A569-4F1E84738182",
				"X-Apple-I-Client-Time": time,
				"X-Apple-I-MD": "AAAABQAAABCMMt6qegoLwK7/SjhV8/XQAAAAAw==",
				"X-Apple-I-MD-M": "BvleDr7BzY/U0+RwcEwPJiikBNW9J69y8qtmJi1xrzXVwz+iTq5fZWSA2S+9ssE3dDpMpuXCxsWQ/at1",
				"X-Apple-I-MD-RINFO": "17106176",
				"X-Apple-I-SRL-NO": "C39L80JCFNJT",
				"X-Mme-Device-Id": "2c7a7a35e0a441245fbf7e2c5cad03fce2dca5d8",
				"bootstrap": True,
				"capp": "AppStore",
				"ckgen": True,
				"dc": "#d4c5b3",
				"dec": "#e1e4e3",
				"loc": "en_US",
				"pbe": False,
				"prtn": "ME349",
				"svct": "iTunes"
			},
			"o": "complete",
			"u": username
		}
	}
	data2 = plistlib.dumps(data2_obj).decode("utf-8")

	r = requests.post(url, data=data2, headers=headers, verify=False)
	return r.content
