import os
import sys
import re

find_key_dict = {
    "url": r"\".*?[^http]/.*?\\?.*?=\"",
    "apikey": r"api.*?key.*?=",
    "username": r"user.*?=\".*?\"",
    "password": r"passw.*?=\".*?\"",
    "accesskey": r"access.*?key.*?:",
    "tokenkey": r"token.*?key.*?:",
    "secret": r"secret.*?=.*?\".*?\"",
    "workwechat": r".*?corpid.*?=",
    "mobile": r"['\"](1(3([0-35-9]\d|4[1-8])|4[14-9]\d|5([\d]\d|7[1-79])|66\d|7[2-35-8]\d|8\d{2}|9[89]\d)\d{7})['\"]",
    "mail": r"['\"][a-zA-Z0-9\._\-]*@[a-zA-Z0-9\._\-]{1,63}\.((?!js|css|jpg|jpeg|png|ico)[a-zA-Z]{2,})['\"]",
    "ip": r"['\"]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}['\"]",
    "jwt": r"['\"](ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|ey[A-Za-z0-9_\/+-]{10,}\.[A-Za-z0-9._\/+-]{10,})[\"']",
    "algorithm": r"\W(Base64\.encode|Base64\.decode|btoa|atob|CryptoJS\.AES|CryptoJS\.DES|JSEncrypt|rsa|KJUR|$\.md5|md5|sha1|sha256|sha512)[\(\.]"
}

# 遍历解包文件
def unpack_files(rootDir) -> list:
    unpack_files = []
    for root, dirs, files in os.walk(rootDir):
        for file in files:
            file_path = os.path.join(root, file)
            if file_path.endswith(".js"):
                unpack_files.append(file_path)
    return unpack_files

# 关键字检索
def findkeystring(unpack_files) -> dict:
    result = {}
    # 初始化结果集
    for key in find_key_dict:
        result[key] = []
    for file_path in unpack_files:
        with open(file_path, "r") as fr:
            for num, line in enumerate(fr):
                for key in find_key_dict:
                    patt = find_key_dict[key]
                    line = line.strip().strip("\n")
                    line_match = re.findall(patt, line, re.I)
                    if line_match:
                        result[key].append({
                            "num": num,
                            "file": file_path,
                            "content": line,
                            "key": key
                        })
    return result

def key_output(result):
    """
        以关键字为导向输出结果
    """
    for key in result:
        if result[key]:
            print("="*10 + " " + key + " " + "="*10)
            for key_value in result[key]:
                print("{}:{} -> {}".format(
                    key_value["file"],
                    key_value["num"],
                    key_value["content"],
                ))

def main():
    print("""
        使用方法: 参数为解包目录
        python3 minipro_finder.py ~/unpack
    """)
    try:
        rootdir = sys.argv[1]
    except Exception as e:
        print("Error: 请填写解包目录")
        return
    find_res = findkeystring(unpack_files(rootdir))
    key_output(find_res)

if __name__ == "__main__":
    main()
