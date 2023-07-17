import os
# Как выяснилось, в питоне модно и молодежно использовать двойные кавычки, а не одинарные,
# лучше везде поменять.
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


# это все можно сделать покрасивше, через pydantic-settings.
# https://docs.pydantic.dev/latest/usage/pydantic_settings/
class LDAPSettings(BaseSettings):
    server: str = "127.0.0.1"
    dn: str = "dc=example,dc=org"


class RedisSettings(BaseSettings):
    host: str = Field("127.0.0.1", validation_alias="REDIS_HOST")
    port: int = Field(6379, validation_alias="REDIS_PORT")


#LOG_FORMAT = os.environ.get('LOG_FORMAT', '')