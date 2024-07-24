import hashlib
import random
import socket
import re
import bencode
import urllib.parse
import struct
from math import ceil
from constants import *
from Peer import Peer
from os import urandom
from bencodepy.exceptions import *


def _get_random_transaction_id_packed():
    result = None
    while result is None:
        try:
            result = struct.pack("!i", int(urandom(4).hex(), base=16))
        except:
            pass
    return result


def _get_response_dict(response):
    idx = response.index(b"Content-Length")
    actual_response = response[idx:]
    idx = actual_response.index(b"d")  # finding the start of the dictionary encoding
    actual_response = actual_response[idx:]
    return bencode.decode(actual_response)


class Tracker:
    def __init__(self, filename: str):
        data_decoded = bencode.bread(filename)
        self.announce_url = data_decoded["announce"]
        try:
            self.announce_list = data_decoded[announce_list_keyword]
        except KeyError as e:
            pass
        self.info = data_decoded[info_keyword]
        self.info_hash = hashlib.sha1(bencode.encode(self.info)).digest()
        self.name = self.info[name_keyword]
        self.piece_length = self.info[piece_len_keyword]
        self.pieces = self.info[pieces_keyword]
        self.len = self._get_len_property()

    def _get_len_property(self):
        if len_keyword in self.info:  # Single File Mode
            return self.info[len_keyword]
        else:  # Multiple File Mode
            return sum([file[len_keyword] for file in self.info[files_keyword]])

    def get_piece_hash_by_idx(self, idx):
        return self.pieces[idx * 20: (idx * 20) + 20]

    def get_num_pieces(self):
        return ceil(self.len / self.piece_length)

    def get_peers_list(self, peer_id, port):
        p_list = []
        if "http" in self.announce_url:
            try:
                print("==== Trying non-compact mode first ====")
                p_list = self.get_list_of_peers_http_non_compact(port, peer_id)
            except (TypeError, BencodeDecodeError):
                print("==== non-compact mode didn't work, trying compact mode ====")
                p_list = self.get_list_of_peers_http_compact(port, peer_id)
        elif "udp" in self.announce_url:
            p_list = self.get_list_of_peers_udp(port, peer_id)
        return p_list

    def get_list_of_peers_http_non_compact(self, port: int, peer_id: str):
        sd = self._send_http_request(peer_id, port, False)

        response = sd.recv(4096)
        print("** Received a HTTP response from tracker")
        if b"400 Bad Request" in response:
            print("Error while receiving peer list from tracker!")
            return []

        response_dict = _get_response_dict(response)
        peers_list = [Peer(p[peer_id_keyword], p[peer_ip_keyword], p[peer_port_keyword], -1)
                      for p in response_dict[peers_keyword]]
        # num_seeders = response_dict[complete_keyword] if complete_keyword in response_dict else 0
        # num_leechers = response_dict[incomplete_keyword] if incomplete_keyword in response_dict else 0

        # if len(peers_list) != num_seeders + num_leechers:
        #     print("Error: expected different number of peer list!")
        sd.close()
        return peers_list

    def get_list_of_peers_http_compact(self, port: int, peer_id: str):
        sd = self._send_http_request(peer_id, port, True)

        response = sd.recv(4096)
        print("** Received a HTTP response from tracker")
        if b"400 Bad Request" in response:
            print("Error while receiving peer list from tracker!")
            return []

        response_dict = _get_response_dict(response)
        # num_seeders = response_dict[complete_keyword] if complete_keyword in response_dict else 0
        # num_leechers = response_dict[incomplete_keyword] if incomplete_keyword in response_dict else 0
        idx = 0
        peers_list = []
        while idx < len(response_dict[peers_keyword]):
            ip_net = int.from_bytes(response_dict[peers_keyword][idx:idx + 4], "little")
            ip_addr = socket.inet_ntoa(struct.pack('!L', socket.ntohl(ip_net)))
            idx += 4
            port = int.from_bytes(response_dict[peers_keyword][idx:idx + 2], "big")
            idx += 2
            peers_list.append(Peer("Unknown", ip_addr, port, -1))

        # if len(peers_list) != num_seeders + num_leechers:
        #     print("Error: expected different number of peer list!")
        sd.close()
        return peers_list

    def _send_http_request(self, peer_id, port, is_compact):
        t_ip_addr, t_port = self._get_ip_port_of_tracker_http()

        print(f"** BitTorrentClient is connecting to a tracker in {t_ip_addr}:{t_port}")
        sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sd = socket.create_connection((t_ip_addr, t_port), timeout=5)
            # sd.settimeout(None)
        except socket.error as e:
            print("Error: ", e)
        http_get_req = f"GET /announce?info_hash={urllib.parse.quote(self.info_hash)}" \
                       f"&peer_id={urllib.parse.quote(peer_id)}&port={str(port)}" \
                       f"&uploaded=0&downloaded=0&left={str(self.len)}"
        http_get_req += f"&compact=1" if is_compact else f"&compact=0"
        http_get_req += f"&event=started " \
                        f"HTTP/1.1\r\nHost: {t_ip_addr}:{str(t_port)}\r\n\r\n"
        print("** Sending a HTTP request (GET) to tracker")
        sd.sendall(bytes(http_get_req, 'utf-8'))
        return sd

    def _get_ip_port_of_tracker_http(self):
        try:
            http_idx = self.announce_url.find("http://")
            announce_url = self.announce_url[http_idx:]
        except ValueError:
            announce_url = self.announce_url
        try:
            ann_idx = self.announce_url.find("/announce")
            announce_url = self.announce_url[7:ann_idx]
        except ValueError:
            pass
        t_ip_addr, t_port = 0, 0
        try:
            col_idx = announce_url.find(":")
            t_port = int(announce_url[col_idx + 1:])
            t_addr = announce_url[:col_idx]
            t_ip_addr = socket.gethostbyname(t_addr)
        except ValueError:
            print("Error: couldn't find port to connect!")
        return t_ip_addr, t_port

    def _get_ip_port_of_tracker_udp(self):
        announce_url = self.announce_url
        try:
            udp_idx = self.announce_url.find("udp://")
            if udp_idx != -1:
                announce_url = self.announce_url[udp_idx+6:]
        except ValueError:
            pass
        t_ip_addr, t_port = 0, 0
        try:
            res = re.findall('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)', announce_url)
            if not res:
                res = re.findall('(.+):(\d+)', announce_url)
            t_ip_addr, t_port = res[0][0], int(res[0][1])
        except IndexError:
            print("Error: couldn't find ip and port to connect!")
        return t_ip_addr, t_port

    def get_list_of_peers_udp(self, port, peer_id):
        t_ip_addr, t_port = self._get_ip_port_of_tracker_udp()

        print(f"** BitTorrentClient is connecting to a tracker in {t_ip_addr}:{t_port}")
        sd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        connection_id = struct.pack("!Q", 0x41727101980)
        action = struct.pack("!I", 0)
        transaction_id = _get_random_transaction_id_packed()
        message = b"".join([connection_id, action, transaction_id])
        sd.sendto(message, (t_ip_addr, t_port))
        tracker_response = sd.recv(16)
        action, transaction_id, connection_id = struct.unpack("!IIQ", tracker_response)

        connection_id = struct.pack("!Q", connection_id)
        action = struct.pack("!i", 1)
        transaction_id = _get_random_transaction_id_packed()
        info_hash = struct.pack("!20s", self.info_hash)
        p_id = struct.pack("!20s", bytes(peer_id, "utf-8"))
        downloaded = struct.pack("!Q", 0)
        left = struct.pack("!Q", self.len)
        uploaded = struct.pack("!Q", 0)
        event = struct.pack("!i", 2)
        ip = struct.pack("!I", 0)
        key = struct.pack("!I", int(urandom(4).hex(), base=16))
        num_want = struct.pack("!i", -1)
        port_listen = struct.pack("!H", port)
        message = b"".join([connection_id, action, transaction_id, info_hash,
                            p_id, downloaded, left, uploaded, event, ip, key,
                            num_want, port_listen])
        sd.sendto(message, (t_ip_addr, t_port))
        # sd.setblocking(True)
        sd.settimeout(5)
        try:
            tracker_response = sd.recv(1400)
        except socket.timeout:
            tracker_response = b""

        action, transaction_id, interval, leechers, seeders = struct.unpack("!IIIII", tracker_response[:20])
        peers_cnt = leechers + seeders
        peers_list = []
        idx = 20
        while idx < len(tracker_response) and len(peers_list) < peers_cnt:
            ip_net, port = struct.unpack("!iH", tracker_response[idx:idx+6])
            ip_addr = socket.inet_ntoa(struct.pack('!i', ip_net))
            # ip_addr = socket.inet_ntoa(struct.pack('!L', socket.ntohl(ip_net)))
            peers_list.append(Peer("Unknown", ip_addr, port, -1))
            idx += 6

        sd.close()
        return peers_list
