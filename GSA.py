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
	a2k = base64.b64encode(a2k_data[1]).decode("utf-8")
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

	data = """<?xml version="1.0" encoding="UTF-8"?>
				<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
				<plist version="1.0">
				<dict>
					<key>Header</key>
					<dict>
						<key>Version</key>
						<string>1.0.1</string>
					</dict>
					<key>Request</key>
					<dict>
						<key>A2k</key>
						<data>
						"""+a2k+"""
						</data>
						<key>cpd</key>
						<dict>
							<key>AppleIDClientIdentifier</key>
							<string>D4B7512F-E841-4AEA-A569-4F1E84738182</string>
							<key>X-Apple-I-Client-Time</key>
							<string>"""+time+"""</string>
							<key>X-Apple-I-MD</key>
							<string>AAAABQAAABCMMt6qegoLwK7/SjhV8/XQAAAAAw==</string>
							<key>X-Apple-I-MD-M</key>
							<string>BvleDr7BzY/U0+RwcEwPJiikBNW9J69y8qtmJi1xrzXVwz+iTq5fZWSA2S+9ssE3dDpMpuXCxsWQ/at1</string>
							<key>X-Apple-I-MD-RINFO</key>
							<string>17106176</string>
							<key>X-Apple-I-SRL-NO</key>
							<string>C39L80JCFNJT</string>
							<key>X-Mme-Device-Id</key>
							<string>2c7a7a35e0a441245fbf7e2c5cad03fce2dca5d8</string>
							<key>bootstrap</key>
							<true/>
							<key>capp</key>
							<string>AppStore</string>
							<key>ckgen</key>
							<true/>
							<key>dc</key>
							<string>#d4c5b3</string>
							<key>dec</key>
							<string>#e1e4e3</string>
							<key>loc</key>
							<string>en_US</string>
							<key>pbe</key>
							<false/>
							<key>prtn</key>
							<string>ME349</string>
							<key>svct</key>
							<string>iTunes</string>
						</dict>
						<key>o</key>
						<string>init</string>
						<key>ps</key>
						<array>
							<string>s2k</string>
							<string>s2k_fo</string>
						</array>
						<key>u</key>
						<string>"""+username+"""</string>
					</dict>
				</dict>
				</plist>"""

	r = requests.post(url, data=data, headers=headers, verify=False)
	content = r.content
	pl = plistlib.loads(content)
	
	#print(content) #uncomment this to print out the output.
	
	# Extract s and B from request.
	s_b64 =  base64.b64encode(pl["Response"]["s"]).decode("utf-8")
	B_b64 =  base64.b64encode(pl["Response"]["B"]).decode("utf-8")
	
	#Extract c parameter which is used in subsequent header.
	c = pl["Response"]["c"]


	#Build M1 
	s = base64.b64decode(s_b64)
	B = base64.b64decode(B_b64)
	
	usr = srp.User( username, password, hash_alg=srp.SHA256, ng_type=srp.NG_2048 )
	M1 = usr.process_challenge( s, B )
	M1 = base64.b64encode(M1).decode("utf-8")
	
	print("M1: "+M1)










	####################
	###### Step 2 ######
	####################

	time = datetime.utcnow().isoformat()[:-7]+'Z'


	data2 = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Header</key>
	<dict>
		<key>Version</key>
		<string>1.0.1</string>
	</dict>
	<key>Request</key>
	<dict>
		<key>M1</key>
		<data>
		"""+M1+"""
		</data>
		<key>c</key>
		<string>"""+c+"""</string>
		<key>cpd</key>
		<dict>
			<key>AppleIDClientIdentifier</key>
			<string>D4B7512F-E841-4AEA-A569-4F1E84738182</string>
			<key>X-Apple-I-Client-Time</key>
			<string>"""+time+"""</string>
			<key>X-Apple-I-MD</key>
			<string>AAAABQAAABCMMt6qegoLwK7/SjhV8/XQAAAAAw==</string>
			<key>X-Apple-I-MD-M</key>
			<string>BvleDr7BzY/U0+RwcEwPJiikBNW9J69y8qtmJi1xrzXVwz+iTq5fZWSA2S+9ssE3dDpMpuXCxsWQ/at1</string>
			<key>X-Apple-I-MD-RINFO</key>
			<string>17106176</string>
			<key>X-Apple-I-SRL-NO</key>
			<string>C39L80JCFNJT</string>
			<key>X-Mme-Device-Id</key>
			<string>2c7a7a35e0a441245fbf7e2c5cad03fce2dca5d8</string>
			<key>bootstrap</key>
			<true/>
			<key>capp</key>
			<string>AppStore</string>
			<key>ckgen</key>
			<true/>
			<key>dc</key>
			<string>#d4c5b3</string>
			<key>dec</key>
			<string>#e1e4e3</string>
			<key>loc</key>
			<string>en_US</string>
			<key>pbe</key>
			<false/>
			<key>prtn</key>
			<string>ME349</string>
			<key>svct</key>
			<string>iTunes</string>
		</dict>
		<key>o</key>
		<string>complete</string>
		<key>u</key>
		<string>"""+username+"""</string>
	</dict>
</dict>
</plist>"""




	r = requests.post(url, data=data2, headers=headers, verify=False)
	content = r.content
	#print(content) #uncomment this to print out the output. Will currently result in invalid Apple ID / Password message.








GSA_authenticate("EMAIL HERE", "PASSWORD HERE")
