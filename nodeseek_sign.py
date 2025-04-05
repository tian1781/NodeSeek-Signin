# -- coding: utf-8 --
import os
import sys
import time
import json
from curl_cffi import requests
from turnstile_solver import TurnstileSolver, TurnstileSolverError
from yescaptcha import YesCaptchaSolver, YesCaptchaSolverError

# 配置参数
API_BASE_URL = os.environ.get("API_BASE_URL", "")
CLIENTT_KEY = os.environ.get("CLIENTT_KEY", "")
NS_RANDOM = os.environ.get("NS_RANDOM", "true")
NS_COOKIE = os.environ.get("NS_COOKIE", "")
USER = os.environ.get("USER", "")
PASS = os.environ.get("PASS", "")
SOLVER_TYPE = os.environ.get("SOLVER_TYPE", "turnstile")

# 多账号配置
ACCOUNTS = os.environ.get("ACCOUNTS", "")

def load_send():
    global send
    global hadsend
    cur_path = os.path.abspath(os.path.dirname(__file__))
    sys.path.append(cur_path)
    if os.path.exists(cur_path + "/notify.py"):
        try:
            from notify import send
            hadsend = True
        except:
            print("加载notify.py的通知服务失败，请检查~")
            hadsend = False
    else:
        print("加载通知服务失败,缺少notify.py文件")
        hadsend = False

load_send()

def load_accounts():
    """加载多账号配置"""
    accounts = []
    
    # 优先使用 ACCOUNTS 环境变量
    if ACCOUNTS:
        try:
            # 尝试解析 JSON 格式的账号配置
            accounts = json.loads(ACCOUNTS)
            print(f"从环境变量加载了 {len(accounts)} 个账号")
            return accounts
        except json.JSONDecodeError:
            print("解析 ACCOUNTS 环境变量失败，格式应为 JSON 数组")
    
    # 兼容单账号配置
    if USER and PASS:
        accounts.append({
            "username": USER,
            "password": PASS,
            "cookie": NS_COOKIE
        })
        print("使用单账号配置")
    elif NS_COOKIE:
        accounts.append({
            "username": "",
            "password": "",
            "cookie": NS_COOKIE
        })
        print("仅使用 Cookie 配置")
    
    return accounts


def session_login(username, password):
    # 根据环境变量选择使用哪个验证码解决器
    try:
        if SOLVER_TYPE.lower() == "yescaptcha":
            print(f"正在使用 YesCaptcha 解决验证码来登录账号 {username}...")
            solver = YesCaptchaSolver(
                api_base_url="https://api.yescaptcha.com",
                client_key=CLIENTT_KEY
            )
        else:  # 默认使用 turnstile_solver
            print(f"正在使用 TurnstileSolver 解决验证码来登录账号 {username}...")
            solver = TurnstileSolver(
                api_base_url=API_BASE_URL,
                client_key=CLIENTT_KEY
            )
        
        token = solver.solve(
            url="https://www.nodeseek.com/signIn.html",
            sitekey="0x4AAAAAAAaNy7leGjewpVyR",
            verbose=True
        )
        
        if not token:
            print("获取验证码令牌失败，无法登录")
            return None
            
    except (TurnstileSolverError, YesCaptchaSolverError) as e:
        print(f"验证码解析错误: {e}")
        return None
    except Exception as e:
        print(f"获取验证码过程中发生异常: {e}")
        return None
    
    # 创建会话并登录
    session = requests.Session(impersonate="chrome110")
    
    try:
        session.get("https://www.nodeseek.com/signIn.html")
    except Exception as e:
        print(f"访问登录页面失败: {e}")
    
    url = "https://www.nodeseek.com/api/account/signIn"
    headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        'sec-ch-ua': "\"Not A(Brand\";v=\"99\", \"Microsoft Edge\";v=\"121\", \"Chromium\";v=\"121\"",
        'sec-ch-ua-mobile': "?0",
        'sec-ch-ua-platform': "\"Windows\"",
        'origin': "https://www.nodeseek.com",
        'sec-fetch-site': "same-origin",
        'sec-fetch-mode': "cors",
        'sec-fetch-dest': "empty",
        'referer': "https://www.nodeseek.com/signIn.html",
        'accept-language': "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        'Content-Type': "application/json"
    }
    
    data = {
        "username": username,
        "password": password,
        "token": token,
        "source": "turnstile"
    }
    
    try:
        response = session.post(url, json=data, headers=headers)
        response_data = response.json()
        print(response_data)
        
        if response_data.get('success') == True:
            
            cookie_dict = session.cookies.get_dict()
            cookie_string = '; '.join([f"{name}={value}" for name, value in cookie_dict.items()])
            #print(f"获取到的Cookie: {cookie_string}")
            
            return cookie_string
        else:
            message = response_data.get('message', '登录失败')
            print(f"登录失败: {message}")
            return None
    except Exception as e:
        print("登录异常:", e)
        print("实际响应内容:", response.text if 'response' in locals() else "没有响应")
        return None


def sign(cookie):
    if not cookie:
        print("请先设置Cookie")
        return "no_cookie", ""
        
    url = f"https://www.nodeseek.com/api/attendance?random={NS_RANDOM}"
    headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        'origin': "https://www.nodeseek.com",
        'referer': "https://www.nodeseek.com/board",
        'Cookie': cookie
    }

    try:
        response = requests.post(url, headers=headers, impersonate="chrome110")
        response_data = response.json()
        print(f"签到返回: {response_data}")
        message = response_data.get('message', '')
        
        # 简化判断逻辑
        if "鸡腿" in message or response_data.get('success') == True:
            # 如果消息中包含"鸡腿"或success为True，都视为签到成功
            print(f"签到成功: {message}")
            return "success", message
        elif "已完成签到" in message:
            print(f"已经签到过: {message}")
            return "already_signed", message
        elif message == "USER NOT FOUND" or response_data.get('status') == 404:
            print("Cookie已失效")
            return "invalid_cookie", message
        else:
            print(f"签到失败: {message}")
            return "fail", message
            
    except Exception as e:
        print("发生异常:", e)
        return "error", str(e)

def get_username_from_cookie(cookie):
    """尝试从Cookie中获取用户名信息，用于日志区分"""
    if not cookie:
        return "未知用户"
    try:
        # 创建带Cookie的会话
        headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
            'Cookie': cookie
        }
        response = requests.get("https://www.nodeseek.com/api/account/userInfo", headers=headers, impersonate="chrome110")
        user_info = response.json()
        if user_info.get('success') and user_info.get('data'):
            return user_info['data'].get('username', '未知用户')
    except Exception as e:
        print(f"获取用户信息失败: {e}")
    return "未知用户"

if __name__ == "__main__":
    # 加载账号配置
    accounts = load_accounts()
    
    if not accounts:
        print("未配置任何账号信息，程序退出")
        sys.exit(1)
    
    # 记录所有账号的签到结果
    all_results = []
    
    # 遍历每个账号进行签到
    for i, account in enumerate(accounts):
        username = account.get("username", "")
        password = account.get("password", "")
        cookie = account.get("cookie", "")
        
        print(f"\n开始处理第 {i+1}/{len(accounts)} 个账号")
        
        # 如果有Cookie，先尝试使用现有Cookie签到
        sign_result, sign_message = "no_cookie", ""
        account_identifier = username or get_username_from_cookie(cookie) or f"账号{i+1}"
        
        if cookie:
            print(f"使用现有Cookie为账号 {account_identifier} 签到...")
            sign_result, sign_message = sign(cookie)
        
        # 处理签到结果
        if sign_result in ["success", "already_signed"]:
            status = "签到成功" if sign_result == "success" else "今天已经签到过了"
            print(f"账号 {account_identifier} {status}")
            all_results.append(f"账号 {account_identifier}: {status} - {sign_message}")
        else:
            # 签到失败或没有Cookie，尝试登录
            if username and password:
                print(f"账号 {account_identifier} 尝试登录获取新Cookie...")
                new_cookie = session_login(username, password)
                if new_cookie:
                    print(f"账号 {account_identifier} 登录成功，使用新Cookie签到")
                    sign_result, sign_message = sign(new_cookie)
                    
                    status = "签到成功" if sign_result in ["success", "already_signed"] else "签到失败"
                    result_msg = f"账号 {account_identifier}: {status} - {sign_message}"
                    all_results.append(result_msg)
                    
                    # 更新账号的Cookie
                    account["cookie"] = new_cookie
                else:
                    print(f"账号 {account_identifier} 登录失败")
                    all_results.append(f"账号 {account_identifier}: 登录失败")
            else:
                print(f"账号 {account_identifier} 无法执行操作：没有有效Cookie且未设置用户名密码")
                all_results.append(f"账号 {account_identifier}: 无法执行操作 - 没有有效Cookie且未设置用户名密码")
    
    # 汇总所有账号的签到结果
    summary = "\n".join(all_results)
    print("\n=== 签到汇总 ===")
    print(summary)
    
    # 发送通知
    if hadsend:
        send("nodeseek多账号签到汇总", summary)
