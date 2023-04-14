import base64
import json
import logging
import urllib.request
import urllib.parse

from config import *

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')

def authenticated_http_req(url, user, pwd):
    request = urllib.request.Request(url)
    base64string = base64.b64encode(('%s:%s' % (user, pwd)).encode('utf-8')).decode('utf-8')
    request.add_header('Authorization', 'Basic %s' % base64string)
    return request

def json_get_req(url):
    try:
        request = authenticated_http_req(url, ONOS_USER, ONOS_PASS)
        response = urllib.request.urlopen(request)
        return json.loads(response.read())
    except IOError as e:
        logging.error(e)
        return ''

def json_post_req(url, json_data):
    try:
        request = authenticated_http_req(url, ONOS_USER, ONOS_PASS)
        request.add_header('Content-Type', 'application/json; charset=utf-8')
        request.add_header('Accept', 'application/json; charset=utf-8')
        data = json_data.encode('utf-8')
        response = urllib.request.urlopen(request, data)
        return json.loads(response.read())
    except IOError as e:
        logging.error(e)
        return ''
