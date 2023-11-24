from base64 import b64encode
import requests
from flask import Flask, request, render_template, redirect, session, jsonify
import json
import bcrypt
import jwt  # Install PyJWT for JWT functionality
import datetime

app = Flask(__name__)
app.secret_key = 'secretkey123'
users_db = {}


# Encoding and Decoding Functions
def encode_basic_auth(username, password):
    credentials = f"{username}:{password}"
    encoded_credentials = b64encode(credentials.encode('utf-8')).decode('utf-8')
    return f'Basic {encoded_credentials}'


def encode_bearer_token(username):
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {'username': username, 'exp': expiration_time}
    secret_key = 'your-secret-key'  # Replace with a strong secret key
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    return token


def load_users():
    global users_db
    with open('users.json', 'r') as file:
        users_db = json.load(file)


def save_users():
    with open('users.json', 'w') as file:
        json.dump(users_db, file, indent=4)


# Authenticate user
def authenticate_user(username, password):
    if username in users_db:
        stored_password = users_db[username]['hashed_password'].encode('utf-8')
        salt = users_db[username]['salt'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return bcrypt.checkpw(password.encode('utf-8'), stored_password)
    return False


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/main')
def main():
    print(f"User authenticated. Session: {session}")
    if session.get('logged_in'):
        return render_template('main.html')
    else:
        return "Unauthorized access"


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users_db:
            error = "Username already exists"
        else:
            # Generate a random salt and hash the password
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            users_db[username] = {'hashed_password': hashed_password.decode('utf-8'), 'salt': salt.decode('utf-8')}
            save_users()
            return 'Account created successfully'
    return render_template('signup.html', error=error)


@app.route('/basic_auth', methods=['GET'])
def basic_auth():
    credentials = request.headers.get('Authorization')
    return jsonify({'basic_auth_token': credentials})


@app.route('/bearer_token', methods=['POST'])
def bearer_token():
    auth_header = request.headers.get('Authorization')

    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        try:
            secret_key = 'your-secret-key'  # Replace with the same secret key used in encode_bearer_token
            payload = jwt.decode(token, secret_key, algorithms=['HS256'])
            return jsonify({'message': 'Bearer Token is valid', 'username': payload['username']})
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Bearer Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid Bearer Token'}), 401
    else:
        return jsonify({'message': 'Bearer Token not provided'}), 401


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    session['logged_in'] = False

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user is authenticated using Basic Auth
        credentials = encode_basic_auth(username, password)
        headers = {'Authorization': credentials}
        response = requests.get(url='http://localhost:8080/basic_auth', headers=headers)

        if response.status_code == 200:
            session['logged_in'] = True
            # Use the encode_bearer_token function to generate a Bearer Token
            bearer_token = encode_bearer_token(username)

            # Use the generated Bearer Token to make a request to the /bearer_token endpoint
            headers = {'Authorization': f'Bearer {bearer_token}'}
            response = requests.post(url='http://localhost:8080/bearer_token', headers=headers)

            if response.status_code == 200:
                return redirect('/main')
            else:
                print(response.content)
                error = "Invalid credentials"
        else:
            print(response.content)
            error = "Invalid credentials"

    return render_template('login.html', error=error)



if __name__ == '__main__':
    load_users()
    app.run(debug=True, port=8080)
