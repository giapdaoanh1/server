from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin
import re
import requests
import urllib.parse
import json
import time
from flask import Flask, request, jsonify
from typing import Dict
import os
import urllib3
import warnings

# Tắt cảnh báo SSL và HTTPS
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

class TokenStorage:
    def __init__(self):
        self.file_path = "tokens.json"
        if not os.path.exists(self.file_path):
            self._save_tokens({})

    def _load_tokens(self) -> Dict:
        try:
            with open(self.file_path, 'r', encoding='utf-8') as file:
                return json.load(file)
        except:
            return {}

    def _save_tokens(self, tokens: Dict):
        with open(self.file_path, 'w', encoding='utf-8') as file:
            json.dump(tokens, file, indent=4, ensure_ascii=False)

    def get_token(self, email: str) -> dict:
        tokens = self._load_tokens()
        return tokens.get(email)

    def save_token(self, email: str, token_data: dict):
        tokens = self._load_tokens()
        tokens[email] = token_data
        self._save_tokens(tokens)

    def delete_token(self, email: str):
        tokens = self._load_tokens()
        if email in tokens:
            del tokens[email]
            self._save_tokens(tokens)

class OutlookAuth:
    def __init__(self, proxy=None):
        self.DEFAULT_HEADERS = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'en-US,en;q=0.9',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Thunderbird/128.2.3'
        }
        self.CLIENT_ID = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"
        self.REDIRECT_URI = "https://localhost"
        self.proxy = proxy

    def get_proxy_config(self):
        if not self.proxy:
            return None
        try:
            return {
                'http': self.proxy,
                'https': self.proxy
            }
        except Exception as e:
            raise Exception(f"PROXY_ERROR: Lỗi cấu hình proxy: {str(e)}")

    def make_request(self, method, url, **kwargs):
        try:
            proxies = self.get_proxy_config()
            if proxies:
                kwargs['proxies'] = proxies
                kwargs['verify'] = False
            
            response = requests.request(method, url, **kwargs)
            
            if response.status_code == 407:
                raise Exception("PROXY_ERROR: Proxy yêu cầu xác thực")
            
            return response
            
        except requests.exceptions.ProxyError as e:
            raise Exception(f"PROXY_ERROR: Lỗi kết nối proxy: {str(e)}")
        except requests.exceptions.SSLError as e:
            raise Exception(f"PROXY_ERROR: Lỗi SSL với proxy: {str(e)}")
        except requests.exceptions.RequestException as e:
            if "Failed to parse" in str(e):
                raise Exception(f"PROXY_ERROR: Sai định dạng proxy URL")
            raise Exception(f"PROXY_ERROR: Lỗi request: {str(e)}")

    def get_headers(self, additional_headers: dict = {}):
        headers = self.DEFAULT_HEADERS.copy()
        headers.update(additional_headers)
        return headers

    def extract_hidden_inputs(self, html_content: str) -> dict:
        """
        Trích xuất tất cả input hidden từ HTML content với nhiều pattern khác nhau
        """
        if not html_content:
            return {}

        inputs = {}
        
        # Pattern 1: input type="hidden" chuẩn
        pattern1 = r'<input\s+type="hidden"\s+name="([^"]+)"\s+id="[^"]*"\s+value="([^"]*)"'
        matches1 = re.finditer(pattern1, html_content)
        for match in matches1:
            inputs[match.group(1)] = match.group(2)

        # Pattern 2: input type="hidden" không có id
        pattern2 = r'<input\s+type="hidden"\s+name="([^"]+)"\s+value="([^"]*)"'
        matches2 = re.finditer(pattern2, html_content)
        for match in matches2:
            if match.group(1) not in inputs:  # Không ghi đè nếu đã có
                inputs[match.group(1)] = match.group(2)

        # Pattern 3: input type="hidden" với thứ tự thuộc tính khác
        pattern3 = r'<input[^>]+type="hidden"[^>]+name="([^"]+)"[^>]+value="([^"]*)"'
        matches3 = re.finditer(pattern3, html_content)
        for match in matches3:
            if match.group(1) not in inputs:  # Không ghi đè nếu đã có
                inputs[match.group(1)] = match.group(2)

        return inputs

    def handle_let_app(self, post_url: str, html_content: str, cookies: dict) -> str:
        post_headers = self.get_headers({'content-type': "application/x-www-form-urlencoded"})
        form_data = self.extract_hidden_inputs(html_content)
        form_data["ucaction"] = "Yes"
        encoded_data = urllib.parse.urlencode(form_data)
        resp = self.make_request('POST', post_url, data=encoded_data, 
                               headers=post_headers, cookies=cookies, 
                               allow_redirects=False)
        return resp.headers.get('Location')

    def handle_add_recovery(self, post_url: str, html_content: str, cookies: dict, recovery_email: str = None) -> str:
        """
        Xử lý form thêm email khôi phục và consent update
        """
        try:
            post_headers = self.get_headers({'content-type': "application/x-www-form-urlencoded"})
            
            # Extract form data
            form_data = self.extract_hidden_inputs(html_content)
            if not form_data:
                print("Warning: Không tìm thấy input hidden trong form")
                form_data = {
                    "action": "Skip",
                    "uaid": re.search(r'uaid=([^&]+)', post_url).group(1) if re.search(r'uaid=([^&]+)', post_url) else "",
                }

            # Xử lý theo loại form
            if "Consent/Update" in post_url:
                form_data["ucaction"] = "Yes"  # Đồng ý cho phép ứng dụng truy cập
            else:
                form_data["action"] = "Skip"  # Skip thêm email khôi phục

            # Print debug info
            print(f"Debug - Request URL: {post_url}")
            print(f"Debug - Form data: {form_data}")
            
            # Gửi request
            skip_resp = self.make_request('POST', post_url, 
                                        data=urllib.parse.urlencode(form_data),
                                        headers=post_headers, 
                                        cookies=cookies,
                                        allow_redirects=False)
            
            print(f"Debug - Response status: {skip_resp.status_code}")
            print(f"Debug - Response headers: {skip_resp.headers}")

            redirect_url = skip_resp.headers.get('Location')
            
            if not redirect_url and skip_resp.text:
                # Tìm URL redirect trong HTML response
                redirect_patterns = [
                    r'window\.location\.href\s*=\s*[\'"]([^\'"]+)[\'"]',
                    r'action=[\'"]([^\'"]+)[\'"]',
                    r'href=[\'"]([^\'"]+)[\'"]'
                ]
                
                for pattern in redirect_patterns:
                    match = re.search(pattern, skip_resp.text)
                    if match:
                        redirect_url = match.group(1)
                        break

            # Xử lý các loại redirect đặc biệt
            if redirect_url:
                if any(x in redirect_url for x in ["oauth20_authorize.srf", "cancelonint"]):
                    # Tạo URL authorize mới
                    auth_url = (f"https://login.live.com/oauth20_authorize.srf?"
                               f"response_type=code&"
                               f"client_id={self.CLIENT_ID}&"
                               f"redirect_uri={self.REDIRECT_URI}&"
                               f"scope=offline_access Mail.ReadWrite")
                    
                    auth_resp = self.make_request('GET', auth_url,
                                                headers=self.get_headers(),
                                                cookies=cookies)
                    
                    form_match = re.search("id=\"fmHF\" action=\"(.*?)\"", auth_resp.text)
                    if form_match:
                        consent_url = form_match.group(1)
                        consent_data = self.extract_hidden_inputs(auth_resp.text)
                        consent_data["ucaction"] = "Yes"
                        
                        consent_resp = self.make_request('POST', consent_url,
                                                       data=urllib.parse.urlencode(consent_data),
                                                       headers=post_headers,
                                                       cookies=cookies,
                                                       allow_redirects=False)
                        
                        redirect_url = consent_resp.headers.get('Location')
                        print(f"Debug - Final redirect URL: {redirect_url}")

                # Nếu là URL tương đối, chuyển thành URL tuyệt đối
                if redirect_url.startswith('/'):
                    redirect_url = f"https://login.live.com{redirect_url}"

            if not redirect_url:
                # Kiểm tra nếu có code trong URL hiện tại
                code_match = re.search(r'code=([^&]+)', post_url)
                if code_match:
                    return f"https://localhost?code={code_match.group(1)}"
                raise Exception("Không thể lấy URL redirect")

            return redirect_url

        except Exception as e:
            print(f"Debug - Error detail: {str(e)}")
            print(f"Debug - HTML response: {skip_resp.text if 'skip_resp' in locals() else 'Not available'}")
            raise Exception(f"Lỗi xử lý form: {str(e)}")

    def authenticate(self, email: str, password: str, recovery_email: str = None) -> dict:
        try:
            auth_url = f"https://login.live.com/oauth20_authorize.srf?response_type=code&client_id={self.CLIENT_ID}&redirect_uri={self.REDIRECT_URI}&scope=offline_access Mail.ReadWrite&login_hint={email}"
            
            resp1 = self.make_request('GET', auth_url, headers=self.get_headers())

            post_url = re.search("https://login.live.com/ppsecure/post.srf?(.*?)',", resp1.text)
            if not post_url:
                raise Exception("AUTH_ERROR: URL đăng nhập không hợp lệ")
                
            post_url = "https://login.live.com/ppsecure/post.srf" + post_url.group(1)
            ppft = re.search("<input type=\"hidden\" name=\"PPFT\" id=\"(.*?)\" value=\"(.*?)\"", resp1.text)
            if not ppft:
                raise Exception("AUTH_ERROR: Token PPFT không hợp lệ")
            
            login_data = {
                'login': email,
                'loginfmt': email,
                'passwd': password,
                'PPFT': ppft.group(2)
            }
            
            post_headers = self.get_headers({'content-type': "application/x-www-form-urlencoded"})
            login_resp = self.make_request('POST', post_url, 
                                         data=urllib.parse.urlencode(login_data),
                                         headers=post_headers, 
                                         cookies=resp1.cookies.get_dict(),
                                         allow_redirects=False)

            redirect_url = login_resp.headers.get('Location')
            cookies = login_resp.cookies.get_dict()

            if not redirect_url or redirect_url == "":
                form_match = re.search("id=\"fmHF\" action=\"(.*?)\"", login_resp.text)
                if not form_match:
                    if "incorrect" in login_resp.text.lower():
                        raise Exception("AUTH_ERROR: Email hoặc mật khẩu không chính xác")
                    raise Exception("AUTH_ERROR: Không thể xác thực tài khoản")
                    
                post_url = form_match.group(1)
                
                if "Abuse?mkt=" in post_url:
                    raise Exception("ACCOUNT_ERROR: Tài khoản bị khóa do vi phạm")
                if "Update?mkt=" in post_url or "Add?mkt=" in post_url:
                    try:
                        redirect_url = self.handle_add_recovery(post_url, login_resp.text, cookies)
                    except Exception as e:
                        print(f"Debug - Error in Add/Update handling: {str(e)}")
                        raise Exception(f"Lỗi xử lý form bảo mật: {str(e)}")
                elif "confirm?mkt=" in post_url:
                    raise Exception("SECURITY_ERROR: Tài khoản yêu cầu xác minh bảo mật")
                elif "accountlocked" in login_resp.text.lower():
                    raise Exception("ACCOUNT_ERROR: Tài khoản đã bị khóa")
                elif "incorrect" in login_resp.text.lower():
                    raise Exception("AUTH_ERROR: Email hoặc mật khẩu không chính xác")
            
            if not redirect_url:
                raise Exception("AUTH_ERROR: Không thể hoàn tất xác thực")
            
            code = redirect_url.split('=')[1]
            token_data = {
                'code': code,
                'client_id': self.CLIENT_ID,
                'redirect_uri': self.REDIRECT_URI,
                'grant_type': 'authorization_code'
            }
            
            token_resp = self.make_request('POST', 
                                         "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                                         data=token_data, 
                                         headers=post_headers)
            
            if token_resp.status_code != 200:
                raise Exception("AUTH_ERROR: Không thể lấy token")
                
            return token_resp.json()
            
        except Exception as e:
            if str(e).startswith(("PROXY_ERROR:", "AUTH_ERROR:", "SECURITY_ERROR:", "ACCOUNT_ERROR:")):
                raise e
            raise Exception(f"AUTH_ERROR: Lỗi xác thực: {str(e)}")

    def read_mail(self, access_token: str, filter_sender: str = None, minutes: int = None) -> dict:
        base_url = "https://graph.microsoft.com/v1.0/me/mailFolders"
        headers = {'Authorization': f'Bearer {access_token}'}
        token_expired = False
        proxy_error = None

        # Xử lý thời gian
        time_info = None
        if minutes is not None:
            try:
                minutes = int(minutes)
                current_time = datetime.utcnow()
                current_time_vn = current_time.replace(microsecond=0) + timedelta(hours=7)
                time_ago_vn = current_time_vn - timedelta(minutes=minutes)
                time_info = {'current': current_time_vn, 'ago': time_ago_vn}
                print(f"Thời gian hiện tại (VN): {current_time_vn.strftime('%Y-%m-%d %H:%M:%S')} +07")
                print(f"Thời gian {minutes} phút trước (VN): {time_ago_vn.strftime('%Y-%m-%d %H:%M:%S')} +07")
            except ValueError:
                raise Exception("PARAM_ERROR: Giá trị minutes không hợp lệ")

        for folder in ['Inbox', 'JunkEmail']:
            try:
                top_count = 10 if filter_sender or minutes else 5
                url = (f"{base_url}/{folder}/messages?"
                      "$select=subject,receivedDateTime,from,body,parentFolderId&"
                      f"$top={top_count}&"
                      "$orderby=receivedDateTime desc")
                
                try:
                    response = self.make_request('GET', url, headers=headers)
                except Exception as request_error:
                    if str(request_error).startswith("PROXY_ERROR:"):
                        proxy_error = str(request_error)
                    continue
                
                if response.status_code == 401:
                    token_expired = True
                    print(f"Token hết hạn khi đọc {folder}")
                    break

                try:
                    emails = response.json().get('value', [])
                except Exception as e:
                    print(f"Lỗi parse JSON từ {folder}: {str(e)}")
                    continue

                valid_emails = []
                for email in emails:
                    try:
                        sender = email.get('from', {}).get('emailAddress', {}).get('address', '')
                        received_time = email.get('receivedDateTime', '')
                        
                        if filter_sender and sender.lower() != filter_sender.lower():
                            continue
                        
                        if received_time:
                            received_utc = datetime.strptime(received_time, "%Y-%m-%dT%H:%M:%SZ")
                            received_vn = received_utc.replace(microsecond=0) + timedelta(hours=7)
                            
                            if time_info and not (time_info['ago'] <= received_vn <= time_info['current']):
                                continue
                            
                            body_content = email.get('body', {})
                            
                            formatted_email = {
                                "subject": email.get('subject', 'Không có tiêu đề'),
                                "sender": sender,
                                "received_time": received_vn.strftime("%Y-%m-%d %H:%M:%S +07"),
                                "folder": folder,
                                "body": body_content.get('content', ''),
                                "body_type": body_content.get('contentType', '')
                            }
                            valid_emails.append(formatted_email)
                            
                            print(f"\nEmail từ {sender}:")
                            print(f"Thời gian nhận (VN): {received_vn.strftime('%Y-%m-%d %H:%M:%S')} +07")
                            print(f"Subject: {formatted_email['subject']}")
                            print(f"Folder: {folder}")
                            
                    except Exception as email_error:
                        print(f"Lỗi xử lý email: {str(email_error)}")
                        continue
                
                if valid_emails:
                    valid_emails.sort(key=lambda x: x['received_time'], reverse=True)
                    return valid_emails
                    
            except Exception as folder_error:
                print(f"Lỗi đọc folder {folder}: {str(folder_error)}")
                continue

        # Xử lý các lỗi theo thứ tự ưu tiên
        if proxy_error:
            raise Exception(proxy_error)
            
        if token_expired:
            raise Exception("TOKEN_EXPIRED")
        
        # Thông báo không tìm thấy email
        message = []
        if filter_sender:
            message.append(f"từ {filter_sender}")
        if minutes is not None:
            message.append(f"trong {minutes} phút vừa qua")
        
        error_msg = "Không tìm thấy mail nào " + " ".join(message) if message else "Không tìm thấy mail nào"
        raise Exception(f"NOT_FOUND: {error_msg}")

token_storage = TokenStorage()

@app.route('/read_mail', methods=['POST'])
def handle_read_mail():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'error': 'Dữ liệu không hợp lệ',
                'error_type': 'invalid_request'
            }), 400
            
        if 'email' not in data or 'password' not in data:
            return jsonify({
                'error': 'Thiếu thông tin email hoặc password',
                'error': 'Thiếu thông tin email hoặc password',
                'error_type': 'invalid_request'
            }), 400
            
        email = data['email']
        password = data['password']
        filter_sender = data.get('filter_sender')
        minutes = data.get('minutes')
        proxy = data.get('proxy')

        def authenticate_and_read():
            tokens = auth.authenticate(email=email, password=password)
            if 'access_token' not in tokens:
                raise Exception("AUTH_ERROR: Không thể lấy được access token")
            token_storage.save_token(email, tokens)
            return auth.read_mail(tokens['access_token'], filter_sender=filter_sender, minutes=minutes)

        # Khởi tạo OutlookAuth với proxy
        try:
            auth = OutlookAuth(proxy=proxy)
        except Exception as e:
            error_msg = str(e)
            if error_msg.startswith("PROXY_ERROR:"):
                return jsonify({
                    'error': error_msg.replace("PROXY_ERROR: ", ""),
                    'error_type': 'proxy_error'
                }), 400
            raise e

        try:
            # Thử dùng token hiện có
            stored_token = token_storage.get_token(email)
            if stored_token and 'access_token' in stored_token:
                try:
                    result = auth.read_mail(stored_token['access_token'], 
                                         filter_sender=filter_sender,
                                         minutes=minutes)
                    return jsonify({'emails': result})
                except Exception as e:
                    error_msg = str(e)
                    if error_msg == "TOKEN_EXPIRED":
                        print("Token hết hạn, đang refresh...")
                        token_storage.delete_token(email)
                        try:
                            result = authenticate_and_read()
                            return jsonify({'emails': result})
                        except Exception as refresh_error:
                            if str(refresh_error).startswith(("PROXY_ERROR:", "AUTH_ERROR:", 
                                "SECURITY_ERROR:", "ACCOUNT_ERROR:", "NOT_FOUND:", "PARAM_ERROR:")):
                                raise refresh_error
                            raise Exception(f"AUTH_ERROR: Lỗi refresh token: {str(refresh_error)}")
                    raise e

            # Không có token, đăng nhập mới
            print("Không có token, đang lấy mới...")
            result = authenticate_and_read()
            return jsonify({'emails': result})

        except Exception as e:
            error_msg = str(e)
            # Xử lý các loại lỗi cụ thể
            if error_msg.startswith("PROXY_ERROR:"):
                return jsonify({
                    'error': error_msg.replace("PROXY_ERROR: ", ""),
                    'error_type': 'proxy_error'
                }), 400
            elif error_msg.startswith("AUTH_ERROR:"):
                return jsonify({
                    'error': error_msg.replace("AUTH_ERROR: ", ""),
                    'error_type': 'auth_error'
                }), 401
            elif error_msg.startswith("SECURITY_ERROR:"):
                return jsonify({
                    'error': error_msg.replace("SECURITY_ERROR: ", ""),
                    'error_type': 'security_error'
                }), 403
            elif error_msg.startswith("ACCOUNT_ERROR:"):
                return jsonify({
                    'error': error_msg.replace("ACCOUNT_ERROR: ", ""),
                    'error_type': 'account_error'
                }), 403
            elif error_msg.startswith("NOT_FOUND:"):
                return jsonify({
                    'error': error_msg.replace("NOT_FOUND: ", ""),
                    'error_type': 'not_found'
                }), 404
            elif error_msg.startswith("PARAM_ERROR:"):
                return jsonify({
                    'error': error_msg.replace("PARAM_ERROR: ", ""),
                    'error_type': 'invalid_parameter'
                }), 400
            # Lỗi không xác định
            return jsonify({
                'error': f"Lỗi không xác định: {str(e)}",
                'error_type': 'unknown_error'
            }), 500

    except Exception as e:
        return jsonify({
            'error': f"Lỗi hệ thống: {str(e)}",
            'error_type': 'system_error'
        }), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
