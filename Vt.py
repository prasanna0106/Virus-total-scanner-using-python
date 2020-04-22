import requests
import json
import time
import os

path = '<MONITOR FOLDER DIR>'
os.chdir(path)
files = sorted(os.listdir(os.getcwd()), key=os.path.getmtime)

oldest = files[0]
newest = files[-1]

print ("Oldest:", oldest)
print ("Newest:", newest)
print ("All by modified oldest to newest:", files)


url = 'https://www.virustotal.com/vtapi/v2/file/scan'
params = {'apikey': 'VT API KEY'}
files = {'file': ('newest', open( newest, 'rb'))}
response = requests.post(url, files=files, params=params)

x= response.json()
json_str = json.dumps(x)
resp = json.loads(json_str)
y= (resp['scan_id'])
#print(y)
#print(resp)


url = 'https://www.virustotal.com/vtapi/v2/file/report'
params = {'apikey': 'VT API KEY', 'resource': y}
response = requests.get(url, params=params)
z = (response.json())
json_strr = json.dumps(z)
resps = json.loads(json_strr)
#print(resps)
if (resps['response_code']) == -2:
   print("API limit exceeded scan submitted waiting for 120 seconds")
   time.sleep(120)
else: print("API is working")


a = (resps['total'])
b = (resps['positives'])
c = (resps['permalink'])

#print("Total scanned engines " + str(a) + "out of which positive are " + str(b) + "virus total link " + str(c) )
s = ("Scanned file name" + str(newest) +"Total scanned engines " + str(a) + "out of which positive are " + str(b) + "virus total link " + str(c) )
# print("out of which positive are " + str(b) )
# print("virus total link " + str(c) )

#print(r)
if __name__ == '__main__':
   wekbook_url = 'SLACK WEB HOOK URL'

   data = {
       'text' : s
   }
   response = requests.post(wekbook_url, data=json.dumps(data),
   headers={'Content-Type': 'application/json'})
   print('Response: ' + str(response.text))
   print('Response code: ' + str(response.status_code))
