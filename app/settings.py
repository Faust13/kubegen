import os

LDAP = {
    "SERVER" : os.environ.get('LDAP_SERVER', '127.0.0.1').strip(),
    "DN" : os.environ.get('LDAP_DN', 'dc=example,dc=org').strip()
    }
SECRET_KEY = os.environ.get('SECRET_KEY', 'BAD_SECRET_KEY')
REDIS = {
    "HOST" : os.environ.get('REDIS_HOST', '127.0.0.1').strip(),
    'PORT' : os.environ.get('REDIS_PORT', '6379').strip()
    }

KUBERNETES = {
    "API_KEY" : os.environ.get('KUBE_API_KEY', 'BearerToken'),
    "ENDPOINT" : os.environ.get('KUBE_ENDPOINT', 'http://localhost')
}
SALT = os.environ.get('SALT', 'somestring')
BASIC_AUTH_USER = os.environ.get('BASIC_AUTH_USER', 'admin') 

#LOG_FORMAT = os.environ.get('LOG_FORMAT', '')