import socket
import json
import hashlib
import subprocess
import struct
import logging
import uuid

_LOGGER = logging.getLogger(__name__)

class TPLinkTalkbackPlayer:
    """Core class to handle communication and playback to a TP-Link camera."""

    def __init__(self, ip, user, password):
        self._ip = ip
        self._user = user
        self._password = password
        self._client_uuid = str(uuid.uuid4()) 

    def play_media(self, media_url):
        """Connects, plays an audio file from a URL, and disconnects."""
        camera_sock = None
        udp_sock = None
        process = None
        
        try:
            _LOGGER.info("Starting playback session...")
            camera_sock = self._connect_and_auth()
            if not camera_sock:
                raise ConnectionError("Failed to authenticate with camera.")

            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.bind(('127.0.0.1', 0))
            local_port = udp_sock.getsockname()[1]
            ffmpeg_target_url = f'rtp://127.0.0.1:{local_port}'

            adelay = 300
            command = [
                'ffmpeg',
                '-re',                          
                '-i', media_url,                
                '-af', (
                    f'aresample=8000,'          
                    f'pan=mono|c0=c0,'          
                    f'adelay={adelay}:all=1,' 
                    f'arealtime'                
                ),
                '-acodec', 'pcm_alaw',          
                '-f', 'rtp',                    
                ffmpeg_target_url               
            ]
            
            _LOGGER.info(f"Starting FFmpeg to play: {media_url}")
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

            while process.poll() is None:
                udp_sock.settimeout(2.0)
                try:
                    rtp_packet, _ = udp_sock.recvfrom(2048)
                    if rtp_packet:
                        interleaved_header = b'$' + struct.pack('!BH', 1, len(rtp_packet))
                        camera_sock.sendall(interleaved_header + rtp_packet)
                except socket.timeout:
                    if process.poll() is not None: break
            
            _LOGGER.info("FFmpeg process finished.")

        except Exception as e:
            _LOGGER.error(f"Error during media playback: {e}", exc_info=True)
        finally:
            if process:
                stderr = process.communicate()[1]
                if stderr and process.returncode != 0:
                     _LOGGER.error(f"FFmpeg error: {stderr.decode()}")
                process.terminate()
            if udp_sock: udp_sock.close()
            if camera_sock: camera_sock.close()
            _LOGGER.info("Playback session finished and all resources cleaned up.")

    def _md5_str(self, s):
        return hashlib.md5(s.encode('utf-8')).hexdigest()

    def _calculate_digest(self, realm, nonce, method, uri):
        ha1 = self._md5_str(f"{self._user}:{realm}:{self._password}")
        ha2 = self._md5_str(f"{method}:{uri}")
        return self._md5_str(f"{ha1}:{nonce}:{ha2}")

    def _connect_and_auth(self):
        """Performs the full 3-step MULTITRANS handshake."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            sock.connect((self._ip, 554))
            uri = f"rtsp://{self._ip}/multitrans"

            # Step 1: Get challenge
            req1 = (f"MULTITRANS {uri} RTSP/1.0\r\nCSeq: 0\r\n"
                    f"X-Client-UUID: {self._client_uuid}\r\n\r\n")
            sock.sendall(req1.encode())
            resp1 = sock.recv(2048).decode()
            if "401" not in resp1: raise ConnectionError("Failed to get auth challenge.")
            
            digest_line = [l for l in resp1.split('\r\n') if 'WWW-Authenticate: Digest' in l][0]
            realm = digest_line.split('realm="')[1].split('"')[0]
            nonce = digest_line.split('nonce="')[1].split('"')[0]
            
            # Step 2: Send auth
            response = self._calculate_digest(realm, nonce, "MULTITRANS", uri)
            auth_header = f'Digest username="{self._user}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response}"'
            req2 = (f"MULTITRANS {uri} RTSP/1.0\r\nCSeq: 1\r\nAuthorization: {auth_header}\r\n"
                    f"X-Client-UUID: {self._client_uuid}\r\n\r\n")
            sock.sendall(req2.encode())
            resp2 = sock.recv(2048).decode()
            if "200 OK" not in resp2: raise ConnectionRefusedError("Authentication failed.")
            session_id = [l for l in resp2.split('\r\n') if 'Session:' in l][0].split(': ')[1].strip()

            # Step 3: Open talk channel
            payload = json.dumps({"type":"request","seq":0,"params":{"method":"get","talk":{"mode":"half_duplex"}}})
            req3 = (f"MULTITRANS {uri} RTSP/1.0\r\nCSeq: 2\r\nSession: {session_id}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n{payload}")
            sock.sendall(req3.encode())
            resp3 = sock.recv(2048).decode()
            if '"error_code":0' not in resp3: raise ConnectionError("Failed to open talkback channel.")
            
            _LOGGER.info("Successfully authenticated and talkback channel is open.")
            return sock
        except Exception as e:
            sock.close()
            _LOGGER.error(f"Handshake failed: {e}")
            return None