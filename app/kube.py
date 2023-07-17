from flask import abort, jsonify
import base64
from kubernetes import client
from kubernetes.client.rest import ApiException

def getKubeConf(kubeconfig, username: str):  # snake_case, typecheck?
    with client.ApiClient(kubeconfig) as api_client:
        # Create an instance of the API class
        kube_api = client.CoreV1Api(api_client)
        namespace = username
        service_account = 'default'  # можно такое вообще выделить как константу 
        try:
            sa = kube_api.read_namespaced_service_account(service_account, namespace)
            secret_name=sa.secrets[0].name
            try:  # трай эксепт внутри трай эксепта - не хорошо. Нужно подумать, как упростить.
                secret = kube_api.read_namespaced_secret(secret_name, namespace)
                ca_crt = base64.b64decode(secret.data['ca.crt'])  # а точно ли там есть серты и другие данные?
                final_ns = base64.b64decode(secret.data['namespace'])
                token = base64.b64decode(secret.data['token'])
                # слишком длинные строки ненадо, там вроде ограничение на 88 или 98 символов
                return jsonify({
                    'token': token.decode('utf-8'), 
                    'ca.crt':ca_crt.decode('utf-8'), 
                    'namespace':final_ns.decode('utf-8'),
                })
            except ApiException as e:
                # про принты уже писал
                print("Exception when calling ApiClient->read_namespaced_secret: %s\n" % e) 
                abort(500)
        except ApiException as e:
            print("Exception when calling ApiClient->read_namespaced_service_account: %s\n" % e)
            abort(500)