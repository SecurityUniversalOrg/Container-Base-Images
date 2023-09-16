import requests


OAUTH_SCOPES = ['read:vulnerabilities', 'write:vulnerabilities']


class ApiClient(object):
    def __init__(self, client_id, client_secret, vulnmanagerurl):
        self.vulnmanagerurl = vulnmanagerurl
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_key = self.get_access_token()
        self.request_headers = {"Authorization": f"Bearer {self.api_key}"}

    def get_access_token(self):
        url = f'{self.vulnmanagerurl}/oauth/token'
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": " ".join(OAUTH_SCOPES)
        }
        response = requests.post(url, headers=headers, data=data)
        resp = response.json()
        return resp['access_token']
    
    def send_get(self, endpoint):
        url = f'{self.vulnmanagerurl}/{endpoint}'
        response = requests.get(url, headers=self.request_headers)
        resp = response.json()
        return resp

    def send_search(self, endpoint, field, value):
        url = f'{self.vulnmanagerurl}/{endpoint}'
        if ':' in field:
            fields = field.split(':')
            values = value.split(':')
            data = {}
            index = 0
            for i in fields:
                data[i] = values[index]
                index +=1
        else:
            data = {
                field: value,
            }
        response = requests.post(url, headers=self.request_headers, json=data)
        resp = response.json()
        return resp

    def send_post(self, endpoint, data):
        url = f'{self.vulnmanagerurl}/{endpoint}'
        response = requests.post(url, headers=self.request_headers, json=data)
        resp = response.json()
        return resp


