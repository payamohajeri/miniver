#!/usr/bin/env python
# -*- coding: utf-8 -*-

import BaseHTTPServer
import SimpleHTTPServer
import SocketServer
import urlparse
import logging
import simplejson
import sys


class ThreadingHTTPServer(SocketServer.ThreadingMixIn,
                          BaseHTTPServer.HTTPServer):
    pass


class MyHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        SimpleHTTPServer.SimpleHTTPRequestHandler.__init__(
            self,
            *args,
            **kwargs
        )
        self.protocol_version = 'HTTP/1.1'

    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):
        logging.info('======= GET STARTED =======')
        logging.info(self.headers)
        parsed_params = urlparse.urlparse(self.path)
        query_parsed = urlparse.parse_qs(parsed_params.query)
        if parsed_params.path == '/test':
            self.test_request(query_parsed)
        else:
            SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        logging.info('======= POST STARTED =======')
        logging.info(self.headers)
        parsed_params = urlparse.urlparse(self.path)
        if parsed_params.path == '/test':
            self.data_string = self.rfile.read(
                int(self.headers['Content-Length']))
            logging.info("============== DATA ==============")
            logging.info(self.data_string)
            data = simplejson.loads(self.data_string)
            logging.info(simplejson.dumps(data))
            self.test_request(data)
        else:
            SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

    def test_request(self, query):
        logging.info('======= GET TEST REQUEST =======')
        self._set_headers()
        self.wfile.write(
            '{"test": [{"test": "test"}]}'
        )
        self._finish()

    def _finish(self):
        if not self.wfile.closed:
            self.wfile.flush()
        self.wfile.close()
        self.rfile.close()

    def request_error(self, error):
        printErrors = [
            "Unknown error, seems we have exception in code. "
        ]
        self.endPrintRequest(errorType=error, errorMsg=printErrors[error])


def main(Handler):
    logging.basicConfig(
        filename='server.log',
        level=logging.DEBUG,
        format='%(name)s - %(levelname)s - %(asctime)s - '
        '%(process)d - %(thread)d - %(message)s',
    )
    exit_code = 3
    try:
        httpd = ThreadingHTTPServer(
            ('0.0.0.0', 8000), Handler, bind_and_activate=False)
        sa = httpd.socket.getsockname()
        httpd.allow_reuse_address = True
        httpd.server_bind()
        httpd.server_activate()
        logging.info('Serving HTTP on ' + str(sa[0]) + ' port ' + str(sa[1]))
        httpd.serve_forever()
        exit_code = 0
    except KeyboardInterrupt:
        logging.warning('^C received, shutting down the web server')
        httpd.socket.close()
        exit_code = 1
    except Exception as exc:
        logging.exception(
            "{0}({1})".format(type(exc).__name__, str(exc)))
        exit_code = 2
    finally:
        logging.info("Exiting with exit code : " + str(exit_code))

    return exit_code


def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger.debug("Uncaught exception",
                 exc_info=(exc_type, exc_value, exc_traceback))

if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    log_handler = logging.StreamHandler(stream=sys.stdout)
    logger.addHandler(log_handler)
    sys.excepthook = handle_exception
    main(MyHandler)
