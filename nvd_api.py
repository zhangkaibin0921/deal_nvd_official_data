import re
from time import sleep
import requests
url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-1999-0001"
response = requests.get(url)
while response.status_code!=200:
    sleep(10)
    response = requests.get(url)
page_text=response.text
detail=[]
products=set()
manufacture_product=set()
pattern=r"cpe:2\.3:.:(.*?):(.*?):(.*?):"
matches = re.findall(pattern, page_text)
if matches:
    for match in matches:
        vendor = match[0]
        product = match[1]
        version = match[2]
        detail1 = {}
        detail1['manufacturers'] = vendor
        detail1['product'] = product
        detail1['version'] =version
        detail.append(detail1)
        products.add(product)
        manufacture_product.add(vendor + ":::" + product)
print(detail,products,manufacture_product)





