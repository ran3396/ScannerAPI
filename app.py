import os
from flask import Flask, request
from werkzeug.utils import secure_filename
import requests
import threading
from functools import wraps
import logging
import time

UPLOAD_FOLDER = '.\\files'
API_KEY = '5a1d577ff44f5a77804dd1003ca882e96edbc78548e95da356042b0cd7f0c5cb'   # Should be in env variable in prod
LOG_FILE = 'scannerAPI.log'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Run func in new thread
def run_in_new_thread(func):
    @wraps(func)
    def run(*args, **kwargs):
        t = threading.Thread(target=func, args=args, kwargs=kwargs)
        t.start()
        return t
    return run


@run_in_new_thread
@app.route('/scan', methods=['POST'])
def scan_files():
    if 'file' not in request.files:
        return {'message': 'File not found'}
    file = request.files['file']
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    try:
        file.save(file_path)
    except PermissionError:
        return {'message': 'There was a problem with processing the file'}
    else:
        file_md5 = virustotal_scan(file_path, filename)
        if file_md5:
            file_md5 = file_md5['md5']
            response = virustotal_report(file_md5)
            if response:
                return {'message': f'{response["positives"]} out of {response["total"]}'
                                   f' scanners detected the file as malicious'}
        return {'message': 'There was a problem with third party API'}


# Send the file to virustotal for scanning
def virustotal_scan(file_path, filename):
    url = f'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': API_KEY}
    file_to_scan = {'file': (filename, open(file_path, 'rb'))}
    try:
        response = requests.post(url, files=file_to_scan, params=params)
        return response.json()
    except requests.exceptions.RequestException:
        return None


# Trying to get report from virustotal 3 times, if not succeed return None --> Free API account is limited
def virustotal_report(md5):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': md5}
    try:
        for i in range(3):
            response = requests.get(url, params=params)
            if response.status_code == 200:
                return response.json()
            time.sleep(2)
        return None
    except requests.exceptions.RequestException:
        return None


logging.basicConfig(filename=LOG_FILE, level=logging.INFO, filemode='w')
logger = logging.getLogger()
app.run(port=5000, debug=True)
