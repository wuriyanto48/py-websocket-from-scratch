import sys
import socket
import logging
import hashlib
import random
import string
import signal
from b64 import b64_encode
import re
from multiprocessing import Process

logging.basicConfig()
logger = logging.getLogger("wspy")
logger.setLevel(logging.INFO)

BUFFER = 1024*1024
CRLF = bytes([13, 10])
SPACE = bytes([32])

WEBSOCKET_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

'''
websocket OPCode
https://datatracker.ietf.org/doc/html/rfc6455#section-5.2
'''
CONTINUE_OPCODE = 0x0
TEXT_OPCODE = 0x1
BINARY_OPCODE = 0x2
DISCONNECT_OPCODE = 0x8
PING_OPCODE = 0x9
PONG_OPCODE = 0xA

'''
content type
'''
CT_X_WWW_FORM = 'application/x-www-form-urlencoded'
CT_JSON = 'application/json'
CT_XML = 'application/xml'
CT_ZIP = 'application/zip'
CT_TEXT_HTML = 'text/html'
CT_TEXT_PLAIN = 'text/plain'
CT_IMAGE_JPEG = 'image/jpeg'
CT_IMAGE_PNG = 'image/png'
CT_IMAGE_GIF = 'image/gif'
CT_IMAGE_SVG = 'image/svg+xml'
CT_IMAGE_WEBP = 'image/webp'
CT_IMAGE_TIFF = 'image/tiff'
CT_IMAGE_BMP = 'image/bmp'

def generate_session_id(len: int) -> str:
    str_digits = string.ascii_lowercase + string.digits
    random_str = ''.join(random.choices(str_digits, k=len))
    hashed = hashlib.sha1(random_str.encode())
    return hashed.hexdigest()

def generate_ws_server_key(ws_key: str) -> str:
    key_str = f'{ws_key}{WEBSOCKET_GUID}'
    hashed = hashlib.sha1(key_str.encode('utf-8'))
    return b64_encode(hashed.digest()).decode()

def build_response(headers: dict, http_code: int, http_code_msg: str, body: str = None) -> str:
    proto = f'HTTP/1.1 {http_code} {http_code_msg}\r\n'
    headers_raw = ''.join([f'{k}: {v}\r\n' for k, v in headers.items()])
    response = f'{proto}{headers_raw}'
    if body is not None:
        response = f'{response}\r\n{body}\r\n\r\n'
    else:
        response = f'{response}\r\n'
    return response

class Request:
    def __init__(self) -> None:
        self.method = ''
        self.path_url = None
        self.headers = None
        self.body = None

    @staticmethod
    def parse_request(request: bytes):
        request_parts = request.split(CRLF+CRLF)
        proto_header_parts = request_parts[0].split(CRLF)
        proto_path_parts = proto_header_parts[0].split(SPACE)

        method = proto_path_parts[0].decode()
        path_url = proto_path_parts[1].decode()
        headers_decoded = [header.decode() for header in proto_header_parts[1:]]
        headers = {}
        for h in headers_decoded:
            h_parts = h.split(':')
            h_key = h_parts[0]
            h_val = [h_v.strip() for h_v in h_parts[1:]]

            h_key = h_key.strip()
            h_val = h_val
            headers[h_key] = h_val
        print(method)
        print(path_url)
        [print(k, v) for (k, v) in headers.items()]

        body = request_parts[1:]

        request_object = Request()
        request_object.method = method
        request_object.path_url = path_url
        request_object.headers = headers
        request_object.body = body
        return request_object

class ClientObject(Process):
    def __init__(self, client: socket.socket, session_id: str, server):
        Process.__init__(self, name=session_id, daemon=True)

        self.client = client
        self.session_id = session_id
        self.server = server
    
    def run(self) -> None:
        while True:
            try:
                headers = {}
                content = self.client.recv(BUFFER)
                request_parts = content.split(CRLF+CRLF)
                if re.search(b'^GET', content) or re.search(b'^POST', content):
                    proto_header_parts = request_parts[0].split(CRLF)
                    if len(proto_header_parts) > 0:
                        headers_decoded = [header.decode() for header in proto_header_parts[1:]]
                        
                        for h in headers_decoded:
                            h_parts = h.split(':')
                            h_key = h_parts[0]
                            h_val = [h_v.strip() for h_v in h_parts[1:]]
                            h_key = h_key.strip()
                            h_val = h_val
                            headers[h_key] = h_val

                        proto_path_parts = proto_header_parts[0].split(SPACE)
                        if len(proto_path_parts) > 0:
                            
                            method = proto_path_parts[0].decode()
                            path_url = proto_path_parts[1].decode()

                            '''
                            websocket connection
                            '''
                            if path_url == '/chat' and method == 'GET':
                                logger.info('server -> receive websocket upgrade')
                                sec_websocket_key = headers['Sec-WebSocket-Key']
                                logger.info(f'server -> Sec-WebSocket-Key {sec_websocket_key}')

                                server_websocket_key = generate_ws_server_key(sec_websocket_key[0])
                                logger.info(f'server -> server_websocket_key {server_websocket_key}')
                                headers = {
                                    'Upgrade': 'websocket',
                                    'Connection': 'Upgrade',
                                    'Sec-WebSocket-Accept': server_websocket_key
                                }

                                response = build_response(headers, 101, 'Switching Protocols', None).encode('utf-8')
                                logger.info(f'server -> response {response}')
                                self.client.sendall(response)
                            else:
                                if path_url == '/favicon.ico' and method == 'GET':
                                    continue

                                if path_url == '/' and method == 'GET':
                                    parsed_request = Request.parse_request(content)
                                    logger.info(f'server -> receive outside websocket section {parsed_request.body}')

                                    with open('index.html', 'r') as html_body:
                                        body = html_body.read()
                                        headers = {
                                            'Content-Type': 'text/html; encoding=utf8',
                                            'Content-Length': len(body),
                                        }
                                        response = build_response(headers, 200, 'OK', body).encode('utf-8')
                                        self.client.sendall(response)
                                        self.close()
                                        break
                                        
                                else:
                                    logger.info('server -> receive outside websocket section')
                                    parsed_request = Request.parse_request(content)
                                    logger.info(f'server -> receive outside websocket section {parsed_request.body}')

                                    body = 'hello world'
                                    headers = {
                                        'Content-Type': 'text/plain; encoding=utf8',
                                        'Content-Length': len(body),
                                    }
                                    response = build_response(headers, 200, 'OK', body).encode('utf-8')
                                    self.client.sendall(response)
                                    self.close()
                                    break
                else:
                    logger.info('server -> server begin decode websocket message')
                    logger.info(f'server -> receive {content}')
                    logger.info(f'server -> receive {[print(bin(b)) for b in bytearray(content)]}')
                    for b in content:
                        print(f'{b} | {bin(b)}')


                    '''
                    Frame format:

                    0                   1                   2                   3
                    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                    +-+-+-+-+-------+-+-------------+-------------------------------+
                    |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
                    |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
                    |N|V|V|V|       |S|             |   (if payload len==126/127)   |
                    | |1|2|3|       |K|             |                               |
                    +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
                    |     Extended payload length continued, if payload len == 127  |
                    + - - - - - - - - - - - - - - - +-------------------------------+
                    |                               |Masking-key, if MASK set to 1  |
                    +-------------------------------+-------------------------------+
                    | Masking-key (continued)       |          Payload Data         |
                    +-------------------------------- - - - - - - - - - - - - - - - +
                    :                     Payload Data continued ...                :
                    + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
                    |                     Payload Data continued ...                |
                    +---------------------------------------------------------------+
                    
                    FIN the 1st bit
                    https://datatracker.ietf.org/doc/html/rfc6455#section-5.2
                    FIN:  1 bit
                    if FIN == 1 indicates that this is the final fragment in a message.  The first
                    fragment MAY also be the final fragment.

                    FIN can be determined wih operation & to the first value(first byte) 
                    with 10000000 = 128 or 0x80 in hexadecimal
                    for example 129 = 10000001 

                    remove first one higher bit by ANDing with 128 (0x80)
                    10000001 = 129
                    10000000 = 128
                    ------------- &
                    10000000 so first bit = 1

                    '''
                    fin = (content[0] & 0x80) != 0

                    '''
                    RSV 1, 2, 3
                    RSV1, RSV2, RSV3:  1 bit each

                    MUST be 0 unless an extension is negotiated that defines meanings
                    for non-zero values.  If a nonzero value is received and none of
                    the negotiated extensions defines the meaning of such a nonzero
                    value, the receiving endpoint MUST _Fail the WebSocket
                    Connection_.

                    rsv checking algorithm
                    10000001 = 129
                    mask = 00000001

                    check if second bit from first byte = 0
                    10000001 >> 6 = 00000010 
                    00000010 & mask = 00000000 or 0 in decimal

                    check if third bit from first byte = 0
                    10000001 >> 5 = 00000100 
                    00000100 & mask = 00000000 or 0 in decimal

                    check if fourth bit from first byte = 0
                    10000001 >> 4 = 00001000
                    00000100 & mask = 00000000 or 0 in decimal
                    '''
                    rsvs = []
                    logger.info(f'websocket server -> rsv masking {bin(content[0])}')
                    for i in range(3):
                        j = (6 - i)
                        logger.info(f'websocket server -> rsv masking {j} {bin(content[0] >> j)}')
                        rsv = ((content[0] >> j) & 1) == 0
                        rsvs.append(rsv)

                    '''
                    MASK the 8th bit
                    client to server message should be masked
                    first bit form content[1] should be 1

                    MASK can be determined wih operation & to the second value(second byte) with 10000000 = 128
                    for example the second byte is 133 = 10000101
                    10000101 = 133
                    10000000 = 128
                    ------------- &
                    10000000 so first bit = 1
                    if 1 then we can determined if message is masked
                    '''
                    mask = (content[1] & 0x80) != 0

                    '''
                    OPCODE bit (4 5 6 7)
                    *  %x0 denotes a continuation frame
                    *  %x1 denotes a text frame
                    *  %x2 denotes a binary frame
                    *  %x3-7 are reserved for further non-control frames
                    *  %x8 denotes a connection close
                    *  %x9 denotes a ping
                    *  %xA denotes a pong
                    *  %xB-F are reserved for further control frames
                    
                    opcode can be determined wih operation & to the first value (first byte)
                    with 00001111 = 15 or 0x0f in hexadecimal,
                    in other words: remove first 4 higher bits,
                                    and keep last 4 lower bits 
                    00001111 = 15
                    10000001 = 129
                    ---------------&
                    00000001 = 1 or 0x1 in hexadecimal
                    '''
                    opcode = content[0] & 0x0f
                    logger.info(f'websocket server -> opcode {opcode}')

                    '''
                    MESSAGE LENGTH bit (9 0 1 2 3 4 5)
                    message length can be determined with operation & 
                    with 01111111 = 127 or 0x7f in hexadecimal

                    remove first one higher bit by ANDing (&) with 127

                    10000101 = 133
                    01111111 = 127
                    ---------------&
                    00000101 = 5
                    '''
                    message_len = content[1] & 0x7f

                    '''
                    lengthFields
                    for check where MASK position begin from
                    '''
                    lengthFields = 2

                    # if not mask:
                    #     logger.error(f'server -> message not masked, closing connection')
                    #     self.close()
                    #     break

                    if opcode != TEXT_OPCODE and opcode != DISCONNECT_OPCODE:
                        logger.error(f'server -> currently support text and disconnect frame only, closing connection')
                        self.close()
                        break

                    if opcode == DISCONNECT_OPCODE:
                        logger.error(f'server -> client send disconnect opcode, closing connection')
                        message = 'closing connection'
                        lengthFields = 2
                        header_w = []
                        bw = 0

                        if fin:
                            bw |= 0x80
                        
                        bw |= opcode
                        header_w.append(bw)

                        '''
                        set message to not masked -> bw = 0
                        '''
                        bw = 0

                        if len(message) <= 125:
                            bw |= len(message)
                        elif len(message) < 65536:
                            bw |= 126
                            lengthFields = 4
                        else:
                            bw |= 127
                            lengthFields = 8
                        header_w.append(bw)

                        # header_w = header_w + [ord(m) for m in message]
                        logger.info(f'header_w {header_w}')

                        # send
                        self.write(bytes(header_w))
                        self.write(message.encode())

                        self.close()
                        break

                    '''
                    Payload length:  7 bits, 7+16 bits, or 7+64 bits

                    The length of the "Payload data", in bytes: if 0-125, that is the
                    payload length.  If 126, the following 2 bytes interpreted as a
                    16-bit unsigned integer are the payload length.  If 127, the
                    following 8 bytes interpreted as a 64-bit unsigned integer (the
                    most significant bit MUST be 0) are the payload length.  Multibyte
                    length quantities are expressed in network byte order.  Note that
                    in all cases, the minimal number of bytes MUST be used to encode
                    the length, for example, the length of a 124-byte-long string
                    can't be encoded as the sequence 126, 0, 124.  The payload length
                    is the length of the "Extension data" + the length of the
                    "Application data".  The length of the "Extension data" may be
                    zero, in which case the payload length is the length of the
                    "Application data".
                    '''
                    if message_len <= 125:
                        message_len = message_len

                    if message_len == 126:
                        message_len = int.from_bytes([content[3], content[2], 0], 'little')
                        lengthFields = 4
                    # elif message_len == 127:

                    if mask:
                        decoded = []
                        masks = []
                        for i in range(4):
                            m = content[lengthFields + i]
                            masks.append(m)

                        lengthFields = lengthFields + 4

                        logger.info(f'websocket server -> fin {fin}')
                        logger.info(f'websocket server -> mask {mask}')
                        logger.info(f'websocket server -> masks {masks}')
                        logger.info(f'websocket server -> message_len {message_len}')
                        logger.info(f'websocket server -> lengthFields {lengthFields}')
                        logger.info(f'websocket server -> rsvs {rsvs}')

                        logger.info('--------------------')
                        '''
                        Decoding algorithm
                        D_i = E_i XOR M_(i mod 4)
                        where D is the decoded message array, E is the encoded 
                        message array, M is the mask byte array, and i is the index of the message byte to decode.
                        '''
                        for d in range(message_len):
                            decoded_data = content[lengthFields + d] ^ masks[d % 4]
                            decoded.append(decoded_data)
                            print(f'{content[lengthFields + d]} | {masks[d % 4]} | {content[lengthFields + d] ^ masks[d % 4]}')

                        decoded_message = bytes(decoded).decode()
                        logger.info(f'decoded_message {decoded_message}')

                    logger.info('---------- Begin write ---------')

                    message = decoded_message
                    lengthFields = 2
                    header_w = []
                    bw = 0

                    if fin:
                        bw |=0x80
                    
                    bw |= opcode
                    header_w.append(bw)

                    '''
                    set message to not masked -> bw = 0
                    '''
                    bw = 0

                    if len(message) <= 125:
                        bw |= len(message)
                    elif len(message) < 65536:
                        bw |= 126
                        lengthFields = 4
                    else:
                        bw |= 127
                        lengthFields = 8
                    header_w.append(bw)

                    '''
                    append message length
                    '''
                    for i in range(lengthFields):
                        j = (lengthFields - 1 - i) * 8
                        length_b = (len(message) >> j) & 0xff
                        # header_w.append(length_b)

                    # header_w = header_w + [ord(m) for m in message]
                    logger.info(f'header_w {header_w}')
                    self.write(bytes(header_w))
                    self.write(message.encode())

                    # send to all connected client
                    # for c in self.server.clients.values():
                    #     logger.info(f'conneced client {c.session_id}')
                    #     c.write(bytes(header_w))
                    #     c.write(message.encode())

                    # self.close()
                    # break
            except Exception as e:
                logger.error(f'server -> error reading client data: {e.with_traceback()}')
                self.close()
                break

    def write(self, data: bytes) -> None:
        self.client.send(data)

    def close(self) -> None:
        if self.client is not None:
            self.client.close()

class Server:
    def __init__(self, host: str, port: int):
        self.terminate = False
        self.host = host
        self.port = port
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.clients = {}
    
    def bind(self):
        try:
            self.listener.bind((self.host, self.port))
        except Exception as e:
            logger.error(f'server -> error: {e}')
            sys.exit(-1)
    
    def listen(self):
        self.listener.listen(5)
        logger.info('server -> waiting client connection')

        while True:
            if self.terminate:
                logger.info(f'terminate {self.terminate}')
                break

            sock_client, address = self.listener.accept()
            logger.info(f'server -> received new client {address[0]} : {address[1]}')
            client_object = ClientObject(client=sock_client, session_id=generate_session_id(5), server=self)

            # add client to client data
            self.clients[client_object.session_id] = client_object
            client_object.start()
    
    def shutdown(self):
        logger.info('server -> shutdown....')
        self.terminate = True
        if self.listener is not None:
            self.listener.close()
            sys.exit(-1)

if __name__ == '__main__':
    server = Server('127.0.0.1', 8666)

    def graceful_shutdown(signum, frame):
        logger.info('graceful_shutdown ...')
        server.shutdown()

    signal.signal(signalnum=signal.SIGINT, handler=graceful_shutdown)
    signal.signal(signalnum=signal.SIGTERM, handler=graceful_shutdown)

    server.bind()

    server.listen()