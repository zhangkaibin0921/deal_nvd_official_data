#处理nvd官方数据，存入数据库中。主要提取cpe字段
import json
import os
import mysql.connector

directory = 'data_from_official'
file_names = os.listdir(directory)
xml_list= [file_name for file_name in file_names if file_name.endswith('.json')]

conn = mysql.connector.connect(
    host='127.0.0.1',
    user='root',
    password='123456',
    database='test'
)
cursor = conn.cursor()


def addOne(filename):
    with open(directory+filename,'r',encoding='latin-1') as file:
        temp=file.read()
        json_data=json.loads(temp)

    for temp in json_data['CVE_Items']:
        cve=temp['cve']
        cve_id=cve['CVE_data_meta']['ID']


        nodes=temp['configurations']['nodes']

        detail=[]
        products=set()
        manufacture_product=set()


        try:
            for node in nodes:
                if node['operator']=='AND':
                    cpes = node['children']
                else:
                    cpes=node['cpe_match']

                for cpe in cpes:
                    if 'cpe_match'in cpe:
                        for i in cpe['cpe_match']:
                            i = i['cpe23Uri']
                            cpe1 = i.split(':')
                            detail1 = {}
                            detail1['manufacture'] = cpe1[3]
                            detail1['product'] = cpe1[4]
                            detail1['version'] = cpe1[5]
                            detail.append(detail1)
                            products.add(cpe1[4])
                            manufacture_product.add(cpe1[3] + ":::" + cpe1[4])
                            # print(detail,products,manufacture_product)

                    else:
                        cpe=cpe['cpe23Uri']
                        cpe1=cpe.split(':')
                        detail1={}
                        detail1['manufacture']=cpe1[3]
                        detail1['product'] = cpe1[4]
                        detail1['version'] = cpe1[5]
                        detail.append(detail1)
                        products.add(cpe1[4])
                        manufacture_product.add(cpe1[3]+":::"+cpe1[4])
                        #print(detail,products,manufacture_product)
        except:
            print(filename, cve_id)

        query = "insert  into nvd (cve_id,detail,products,manufacture_products) values(%s,%s,%s,%s)"
        cursor.execute(query, (cve_id,str(detail),str(products),str(manufacture_product)))
        conn.commit()

for filename in xml_list:#['nvdcve-1.1-2002.json']:
    addOne(filename)


#更新vule_detail逻辑
# conn = mysql.connector.connect(
#     host='127.0.0.1',
#     user='root',
#     password='123456',
#     database='test'
# )
# cursor = conn.cursor()
#
# query = "select cve_id from vule_detail where cve_id is not null"
# cursor.execute(query)
# result = cursor.fetchall()
#
# for row in result:
#     cve_id = str(row[0])
#     print(cve_id)
#     query = "select detail,products,manufacture_products from nvd where cve_id=%s"
#     cursor.execute(query,(cve_id,))
#     res = cursor.fetchone()
#     if res and str(res[0])!='[]':
#         detail=str(res[0]).replace('manufacture','manufacturers')
#
#         query="update vule_detail set detail=%s,product=%s,fingerprint=%s where cve_id=%s"
#         cursor.execute(query, (detail,str(res[2]),str(res[1]),cve_id,))
#         conn.commit()
#         print(detail,str(res[2]),str(res[1]),cve_id,)
