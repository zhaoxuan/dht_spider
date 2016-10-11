#!/usr/bin/env python
# encoding: utf-8

import socket
import time
import collections
import threading

from hashlib import sha1
from struct import unpack, pack
from random import randint
from bencode import bencode, bdecode
from pyformance import global_registry
from pyformance.reporters import ConsoleReporter

RESPONSE = 'r'
QUERY = 'q'
ERROR = 'e'
BOOT_NODE = ("router.utorrent.com", 6881)

BIND_IP = '0.0.0.0'
BIND_PORT = 6881
MAX_NODE_SIZE = 1000
NODES = collections.deque(maxlen=MAX_NODE_SIZE)
TOKEN_LENGTH = 2
INTERVAL = 0.0005
REGISTRY = global_registry()


def entropy(length):
    """Generate a hexadecimal string with input length

    Args:
        length: character length

    Returns:
    """
    return "".join(chr(randint(0, 255)) for _ in xrange(length))


def random_id():
    """generate node id

    """
    hash_method = sha1()
    hash_method.update(entropy(20))
    return hash_method.digest()


NID = random_id()


class KNode(object):

    def __init__(self, nid, ip, port):
        self.nid = nid
        self.ip = ip
        self.port = port


class DHTServer(threading.Thread):
    """docstring for DHTServer"""
    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.max_node_size = MAX_NODE_SIZE
        self.nid = NID
        self.ufd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.ufd.bind((BIND_IP, BIND_PORT))
        self.bind_ip = BIND_IP

    def send_krpc(self, msg, address):
        self.ufd.sendto(bencode(msg), address)

    def run(self):
        while True:
            try:
                (data, address) = self.ufd.recvfrom(65536)
                if len(data) > 0:
                    msg = bdecode(data)
                    self.process_message(msg, address)
                else:
                    continue
            except Exception, e:
                # print 'Exception: ' + str(e)
                pass

    def process_message(self, msg, address):
        method = msg['y']

        if method == RESPONSE:
            nodes_data = msg["r"]["nodes"]
            self.reponse_handler(nodes_data)
        elif method == QUERY:
            self.query_handler(msg, address)
        else:
            pass

    def reponse_handler(self, nodes_data):
        nodes = self.decode_nodes(nodes_data)

        for node in nodes:
            (nid, ip, port) = node

            if len(nid) != 20:
                continue

            if ip == self.bind_ip:
                continue

            if port < 1 or port > 65535:
                continue

            n = KNode(nid, ip, port)
            NODES.append(n)

    def decode_nodes(self, nodes_bencode_data):
        """
        nodes_bencode_data
        """
        n = []
        length = len(nodes_bencode_data)
        if (length % 26) != 0:
            return n

        for i in range(0, length, 26):
            nid = nodes_bencode_data[i:i + 20]
            ip = socket.inet_ntoa(nodes_bencode_data[i + 20:i + 24])
            port = unpack("!H", nodes_bencode_data[i + 24:i + 26])[0]
            n.append((nid, ip, port))

        return n

    def encode_nodes(self, length=8):
        """ KNode 转成 bencode 数据

        Args:
            length: KNode length
        """
        data_bits = ''

        for index in xrange(length):
            node = NODES[index]

            nid = node.nid
            ip = node.ip
            port = node.port
            data = nid + socket.inet_aton(ip) + pack("!H", port)
            data_bits += data

        length = len(data_bits)

        if (length % 26) == 0:
            return data_bits
        else:
            return ''

    def broadcast_self(self):
        while True:
            time.sleep(INTERVAL)
            if len(NODES) == 0:
                self.find_node(self.nid, BOOT_NODE[0], BOOT_NODE[1])
            else:
                node = NODES.popleft()
                REGISTRY.gauge('node.queue.size').set_value(len(NODES))
                REGISTRY.meter('meter.send.find_node').mark()
                self.find_node(node.nid, node.ip, node.port)

    def find_node(self, nid, ip, port):
        transaction = entropy(2)

        query = {
            "t": transaction,
            "y": "q",
            "q": "find_node",
            "a": {
                "id": nid,
                "target": random_id()
            }
        }

        self.send_krpc(query, (ip, port))

    def response_ping(self, query_data, address):
        transaction = query_data['t']

        response = {
            't': transaction,
            'y': 'r',
            'r': {
                'id': self.nid
            }
        }

        REGISTRY.counter('response.ping').inc()
        self.send_krpc(response, address)

    def response_get_peers(self, query_data, address):
        transaction = query_data['t']
        params = query_data['a']
        infohash = params['infohash']
        token = infohash[:TOKEN_LENGTH]

        response = {
            't': transaction,
            'y': 'r',
            'a': {
                'id': self.nid,
                'token': token,
                'nodes': self.encode_nodes(4)
            }
        }

        REGISTRY.counter('response.get_peers').inc()
        self.send_krpc(response, address)

    def response_announce_peer(self, query_data, address):
        transaction = query_data['t']

        response = {
            't': transaction,
            'y': 'r',
            'a': {
                'id': self.nid
            }
        }

        REGISTRY.counter('response.announce_peer').inc()
        self.send_krpc(response, address)

    def response_find_node(self, query_data, address):
        transaction = query_data['t']
        infohash = query_data['a']['info_hash']

        node_bits = self.encode_nodes(8)
        token = infohash[:TOKEN_LENGTH]

        response = {
            't': transaction,
            'y': 'r',
            'r': {
                'id': self.nid,
                'nodes': node_bits,
                'token': token
            }
        }

        REGISTRY.counter('response.find_node').inc()
        self.send_krpc(response, address)

    def query_handler(self, query_data, address):
        query_method = query_data['q']

        if query_method == 'get_peers':
            self.response_get_peers(query_data, address)
        elif query_method == 'announce_peer':
            self.response_announce_peer(query_data, address)
        elif query_method == 'find_node':
            # self.response_find_node(query_data, address)
            pass
        elif query_method == 'ping':
            self.response_ping(query_data, address)
        else:
            pass


reporter = ConsoleReporter(reporting_interval=5)
reporter.start()

server = DHTServer()
server.start()
server.broadcast_self()
