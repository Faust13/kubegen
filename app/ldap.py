from settings import LDAP
from ldap3 import Server, Connection, ALL
from flask import jsonify

def global_ldap_authentication(user_name, user_pwd):
    """
      Function: global_ldap_authentication
       Purpose: Make a connection to encrypted LDAP server.
       :params: ** Mandatory Positional Parameters
                1. user_name - LDAP user Name
                2. user_pwd - LDAP User Password
       :return: None
    """

    # fetch the username and password
    ldap_user_name = user_name.strip()
    ldap_user_pwd = user_pwd.strip()

    # ldap server hostname and port
    ldsp_server = LDAP['SERVER']

    # dn
    root_dn = LDAP['DN']

    # user
    user = f'cn={ldap_user_name} {ldap_user_name},ou={root_dn}'

    server = Server(ldsp_server, get_info=ALL)
    print(f'''try to bind to ldap server {server} with creds {user}/{ldap_user_pwd}
            ''')
    try:
        connection = Connection(server,
                                user=user,
                                password=ldap_user_pwd,
                                auto_bind=True)
        print(f"{connection} successed")
        auth_connection = jsonify({'Status': 'Success', 'code': 200, 'username': ldap_user_name }), 200
    except:
        auth_connection = jsonify({'Status': 'Failed', 'code': 401, 'error' : 'Failed Authentication'}), 401
       
    return auth_connection