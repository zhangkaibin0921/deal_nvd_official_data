#这个文件夹最后都没有用上
import json

file_path = "nvd_from_github_VulDB_Spider.json"
with open(file_path, "r",encoding='latin-1') as json_file:
    json_data = json.load(json_file)

list=json_data['RECORDS']

res={}

for item in list:
    if item['nvd_cve_id'].startswith("CVE-19") or item['nvd_cve_id'].startswith("CVE-2000") or item['nvd_cve_id'].startswith("CVE-2002"):
        res[item['nvd_cve_id']]=item
        print(item['nvd_cve_id'])

with open("nvdcve-1.1-19_2000_2001", "w") as json_file:
    json.dump(res, json_file)