import requests
import json

# API地址
url = "https://u898402-8d7e-d7f133cc.bjb1.seetacloud.com:8443/fix_code"

# 测试代码
test_code = """
def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()
"""

# 发送请求
response = requests.post(url, json={
    "code": test_code,
    "vuln_type": "SQL注入"
}, verify=False)  # verify=False 是因为自签名证书

# 打印结果
if response.status_code == 200:
    result = response.json()
    print("修复后的代码：")
    print(result["fixed"])
else:
    print("错误：", response.text)