from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import logging
import cgi
import requests
import time
import os
import datetime


UPLOAD_FOLDER = '.\\files'
API_KEY = '5a1d577ff44f5a77804dd1003ca882e96edbc78548e95da356042b0cd7f0c5cb'   # Should be in env variable in prod
LOG_FILE = 'scannerAPI.log'


class ScannerAPIHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST',
                     'CONTENT_TYPE': self.headers['Content-Type'],
                     })
        logging.info(f'{datetime.datetime.now()} - {self.requestline}, from {self.client_address}')
        if 'file' not in form.keys():
            self.__build_response({'message': 'File not found'}, 400)
            return
        file = form['file']
        filename = file.filename
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        try:
            with open(file_path, 'wb') as f:
                f.write(file.file.read())
        except PermissionError:
            self.__build_response({'message': 'There was a problem with processing the file'}, 500)
            return
        else:
            file_md5 = self.__virustotal_scan(file_path, filename)
            if file_md5:
                file_md5 = file_md5['md5']
                response = self.__virustotal_report(file_md5)
                if response:
                    self.__build_response({'message': f'{response["positives"]} out of {response["total"]}'
                                                      f' scanners detected the file as malicious'}, 200)
                    return
            self.__build_response({'message': 'There was a problem with third party API'}, 503)
            return

    # Send the file to virustotal for scanning
    def __virustotal_scan(self, file_path, filename):
        url = f'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': API_KEY}
        file_to_scan = {'file': (filename, open(file_path, 'rb'))}
        try:
            response = requests.post(url, files=file_to_scan, params=params)
            return response.json()
        except requests.exceptions.RequestException:
            return None

    # Trying to get report from virustotal 3 times, if not succeed return None --> Free API account is limited
    def __virustotal_report(self, md5):
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

    def __build_response(self, message, response_code):
        self.send_response(response_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(str(message).encode())


if __name__ == '__main__':
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, filemode='w')
    logging.info('Starting server...\n')
    logger = logging.getLogger()
    server = ThreadingHTTPServer(('localhost', 5000), ScannerAPIHandler)
    server.serve_forever()
