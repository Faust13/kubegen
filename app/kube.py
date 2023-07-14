from flask import abort, jsonify
import base64
from kubernetes import client
from kubernetes.client.rest import ApiException

def getKubeConf(kubeconfig, username: str):
    with client.ApiClient(kubeconfig) as api_client:
    # Create an instance of the API class
        kube_api = client.CoreV1Api(api_client)
        namespace = username
        service_account = 'default'
        try:
            sa = kube_api.read_namespaced_service_account(service_account, namespace)
            secret_name=sa.secrets[0].name
            try:
                secret = kube_api.read_namespaced_secret(secret_name, namespace)
                ca_crt = base64.b64decode(secret.data['ca.crt'])
                final_ns = base64.b64decode(secret.data['namespace'])
                token = base64.b64decode(secret.data['token'])
                return jsonify({'token': token.decode('utf-8'), 'ca.crt':ca_crt.decode('utf-8'), 'namespace':final_ns.decode('utf-8')})
            except ApiException as e:
                print("Exception when calling ApiClient->read_namespaced_secret: %s\n" % e)
                abort(500)
        except ApiException as e:
            print("Exception when calling ApiClient->read_namespaced_service_account: %s\n" % e)
            abort(500)