from settings import REDIS, SECRET_KEY, KUBERNETES, SALT, BASIC_AUTH_USER
from flask import Flask, redirect, url_for, abort, request, session, render_template
from flask_session import Session
from kubernetes import client
from kube import getKubeConf
from ldap import global_ldap_authentication
from flask_httpauth import HTTPBasicAuth
import redis
import json
import requests
import base64
import logging
from hashlib import sha256

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_REDIS'] = redis.from_url(f"redis://{REDIS['HOST']}:{REDIS['PORT']}")
app.config['BASIC_AUTH_USER'] = BASIC_AUTH_USER
app.config['BASIC_AUTH_KEY'] = sha256(base64.b64encode((SECRET_KEY + SALT).encode('ascii'))).hexdigest()

server_session = Session(app)

auth = HTTPBasicAuth()

kube_conf = client.Configuration()
kube_conf.api_key['authorization'] = KUBERNETES['API_KEY']
kube_conf.api_key_prefix['authorization'] = 'Bearer'
kube_conf.host = KUBERNETES['ENDPOINT']
kube_conf.ssl_ca_cert = "./ca.pem"

logging.basicConfig(level=logging.INFO)
logging.basicConfig(format='%(process)d-%(levelname)s-%(message)s')

logging.debug(kube_conf.host, kube_conf.api_key)
# выглядит секурно
logging.info(f"BASIC AUTH PASSWORD IS { (app.config['BASIC_AUTH_KEY']) }")

API = "http://127.0.0.1:5000/api/v1/"  # это похоже на то, что это переменная окружения
# слишком длинно
# можно сделать константой (ну и в отдельном файле все константы собрать)
api_headers = {
    'accept': 'application/json',
    # нужно определиться, используем ли мы %s или f
    # encode.decode. возможно что-то идет не так.
    # слишком сложно, я бы засунул в функцию, если не получится упросить.
    'Authorization': 'Basic %s' % base64.b64encode((f"{ app.config['BASIC_AUTH_USER'] } : { app.config['BASIC_AUTH_KEY'] }").encode()).decode()
}


def verify_password(header):
    try:
        splitted_header = header.split()
        hashed_string = splitted_header[1]
        logging.debug(f'hashed string is {hashed_string}')
        decoded_auth = base64.b64decode(hashed_string)
        striped_auth = decoded_auth.split()
        size = len(striped_auth)
        if size == 3:
            username = striped_auth[0]
            password = striped_auth[2] 
            if username == app.config['BASIC_AUTH_USER'] and password == app.config['BASIC_AUTH_KEY']:
                return 'OK'
    except:
        abort(403)

#### FRONT ####
@app.route('/', methods=['GET'])
def index():
    if request.method == 'GET':
        if 'user' in session:
            return redirect(url_for('kubeConfig'))
        else:
            return redirect(url_for('loginOptions'))

@app.route('/auth')
def loginOptions(): # snake_case
    return render_template('login_options.html')

@app.route('/login', methods=['GET', 'POST'])
def loginForm():  # snake_case
    error = None
    if request.method == 'POST':
            # вообще я бы посоветовал попробовать marshmallow
            # https://marshmallow.readthedocs.io/en/stable/
            # там можно сделать payload schema и валидировать данные
            form_username = str(request.form['username'])
            form_password = str(request.form['password'])
            request_body = {"username" : form_username, "password" : form_password}
            # так как тут идет вызов http, для оптимизации можно завезти асинхронщину
            check_ldap = requests.post(API + 'login', json=request_body, headers=api_headers)
            if check_ldap.ok:
                data = check_ldap.json()
                if data['code'] == 200:  # а если нет?)
                    session['user'] = data['username']
                    return redirect(url_for('kubeConfig'))
            else:
                error = 'Invalid Credentials. Please try again.'
    return render_template('login_form.html', error=error)

@app.route('/kubeconfig', methods=['POST', 'GET'])
def kubeConfig(): # snake_case
        if request.method == 'GET':
            if 'user' in session:
                username = session['user']
                request_body = {"username" :  session['user']}
                response = requests.post(API + 'kubeconf', json=request_body, headers=api_headers)
                if response.ok:
                    response_dict = response.json()
                    ca_data = base64.b64encode((response_dict['ca.crt']).encode()).decode()
                    username = response_dict['namespace'] 
                    token = response_dict['token']
                    # лучше в конфиг, чтобы не переписывать кодец
                    service_account = 'default'
                    cluster_name = 'yc-managed-k8s'
                    kube_endpoint = kube_conf.host 
                    # слищком длинно
                    return render_template('kubeconfig.html', username=username,cluster_name=cluster_name, ca_data=ca_data, token=token, service_account=service_account, kube_endpoint=kube_endpoint)
            else:
                abort(403)
        elif request.method == 'POST':
            data = request.get_data()
            logging.debug(f"data is %s", data)
            return 'helli'

#### API ####
@app.route('/api/v1/login', methods=['POST'])
def apiLogin():  # snake_case
    auth_header = request.headers.get('Authorization')
    logging.debug(auth_header)
    auth = verify_password(auth_header)
    logging.debug(auth)
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400) # missing arguments
    result = global_ldap_authentication(username, password)
    try:
        session['user'] = json.loads(result[0].get_data(as_text=False))['username']
    except:  # нельзя пустой except
        abort(403)

    logging.debug(session['user'])
    return result

@app.route('/api/v1/kubeconf', methods=['POST'])
def apiKubeconf():  # snake_case
    auth_header = request.headers.get('Authorization')
    logging.debug(auth_header)
    auth = verify_password(auth_header)
    logging.debug(auth)
    try:
        username = request.json.get('username')
        responce = getKubeConf(kube_conf, username)
        return responce
    except KeyError:  # ну ведь умеешь же)
        abort(403) # Unautorized


if __name__ == "__main__":
    app.run(host= '0.0.0.0')