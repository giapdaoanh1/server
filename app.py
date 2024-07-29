from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import json
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Thay đổi secret_key cho an toàn hơn

USERS_FILE = 'users.json'
BALANCES_FILE = 'balances.json'
TOTAL_DEPOSITED_FILE = 'total_deposited.json'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_user(username, password):
    users = load_users()
    users[username] = password
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

def load_balances():
    if os.path.exists(BALANCES_FILE):
        with open(BALANCES_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_balances(balances):
    with open(BALANCES_FILE, 'w') as f:
        json.dump(balances, f)

def load_total_deposited():
    if os.path.exists(TOTAL_DEPOSITED_FILE):
        with open(TOTAL_DEPOSITED_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_total_deposited(total_deposited):
    with open(TOTAL_DEPOSITED_FILE, 'w') as f:
        json.dump(total_deposited, f)

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data['username']
        password = data['password']
        users = load_users()
        if username in users and users[username] == password:
            session['username'] = username
            if username == 'admin':
                return jsonify({'message': 'Đăng nhập thành công', 'type': 'admin'}), 200
            return jsonify({'message': 'Đăng nhập thành công', 'type': 'success'}), 200
        return jsonify({'message': 'Tên người dùng hoặc mật khẩu không hợp lệ!', 'type': 'error'}), 401
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data['username']
        password = data['password']
        users = load_users()
        if username in users:
            return 'Tên người dùng đã tồn tại!'
        save_user(username, password)
        return 'Đăng ký thành công!'
    return render_template('register.html')

@app.route('/home')
def user_home():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    balances = load_balances()
    total_deposited = load_total_deposited()
    
    balance = balances.get(username, '0')
    formatted_balance = f"{float(balance):,.0f} VND"
    
    total = total_deposited.get(username, '0')
    formatted_total_deposited = f"{float(total):,.0f} VND"

    return render_template('home.html', username=username, balance=formatted_balance, total_deposited=formatted_total_deposited)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'delete' in request.form:
            users = load_users()
            balances = load_balances()
            total_deposited = load_total_deposited()
            users_to_delete = request.form.getlist('username')
            for user in users_to_delete:
                if user in users:
                    del users[user]
                if user in balances:
                    del balances[user]
                if user in total_deposited:
                    del total_deposited[user]
            with open(USERS_FILE, 'w') as f:
                json.dump(users, f)
            save_balances(balances)
            save_total_deposited(total_deposited)
        elif 'update' in request.form:
            balances = load_balances()
            total_deposited = load_total_deposited()
            users_to_update = request.form.getlist('username')
            for user in users_to_update:
                # Lấy số dư hiện tại
                current_balance = float(balances.get(user, '0').replace(',', ''))
                # Lấy số tiền nhập vào, loại bỏ dấu phân cách phần nghìn
                amount_str = request.form.get(f'amount_{user}', '0').replace(',', '')
                amount = float(amount_str)
                # Lấy loại phép toán
                operation = request.form.get(f'operation_{user}')
                
                if operation == 'add':
                    new_balance = current_balance + amount
                elif operation == 'subtract':
                    new_balance = max(current_balance - amount, 0)  # Đảm bảo số dư không âm
                else:
                    new_balance = current_balance
                
                balances[user] = str(new_balance)
                total_deposited[user] = total_deposited.get(user, '0')  # Preserve previous total deposited

            save_balances(balances)
            save_total_deposited(total_deposited)

    users = load_users().keys()
    balances = load_balances()
    total_deposited = load_total_deposited()
    
    # Chuyển đổi số dư và tổng số tiền đã gửi sang VND để hiển thị
    formatted_balances = {user: f"{float(balance):,.0f} VND" for user, balance in balances.items()}
    formatted_total_deposited = {user: f"{float(total_deposited.get(user, '0')):,.0f} VND" for user in users}

    return render_template('admin.html', users=users, balances=formatted_balances, total_deposited=formatted_total_deposited)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='171.254.85.139', port=80, debug=True)
