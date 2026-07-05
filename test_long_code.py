import requests
import time

# 构造一个超过15000字符的代码
def generate_long_code(length=15000):
    # 基础代码模板
    base_code = """
def test_function():
    print("This is a test")
    return True
"""
    # 重复添加注释来增加长度
    comment_line = "# This is a comment line to increase code length. " * 10
    long_code = base_code
    
    while len(long_code) < length:
        long_code += comment_line + "\n"
    
    return long_code[:length]

# 测试超长代码
def test_long_code():
    print("=" * 50)
    print("测试：超长代码输入处理")
    print("=" * 50)
    
    # 生成15000字符的代码
    long_code = generate_long_code(15000)
    print(f"生成的代码长度: {len(long_code)} 字符")
    
    # 发送请求
    response = requests.post(
        "http://localhost:8000/api/v1/analyze/",
        json={
            "code": long_code,
            "language": "python"
        }
    )
    
    print(f"HTTP状态码: {response.status_code}")
    print(f"响应内容: {response.json()}")
    
    if response.status_code == 400 or response.status_code == 200:
        result = response.json()
        if isinstance(result, list) and len(result) > 0:
            vuln = result[0]
            if vuln.get("vulnerability_type") == "代码长度超限":
                print("\n✅ 测试通过：系统正确检测到代码长度超限")
            else:
                print(f"\n❌ 测试失败：返回了其他结果 {vuln.get('vulnerability_type')}")
        else:
            print(f"\n❌ 测试失败：返回结果异常 {result}")

# 测试正常长度代码（对比）
def test_normal_code():
    print("\n" + "=" * 50)
    print("测试：正常长度代码输入（对比）")
    print("=" * 50)
    
    normal_code = "def test():\n    print('hello')\n"
    print(f"代码长度: {len(normal_code)} 字符")
    
    response = requests.post(
        "http://localhost:8000/api/v1/analyze/",
        json={
            "code": normal_code,
            "language": "python"
        }
    )
    
    print(f"HTTP状态码: {response.status_code}")
    
    if response.status_code == 200:
        print("\n✅ 正常代码可以正常分析")
    else:
        print(f"\n❌ 测试失败：{response.text}")

if __name__ == "__main__":
    test_long_code()
    test_normal_code()