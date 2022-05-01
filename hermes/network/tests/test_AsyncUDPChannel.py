from hermes.network.AsyncUDPChannel import AsyncUDPChannel
import collections
import socket
import time
from hermes.security.utils import generate_key_32
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def test_new_udp_socket_correctly_set_encryption_in_transit():
    # Given
    encryption_in_transit = False

    # When
    udp_socket = AsyncUDPChannel(encryption_in_transit=encryption_in_transit, socket_port=50000).start()

    # Then
    assert udp_socket.encryption_in_transit is encryption_in_transit

    udp_socket.stop()
    time.sleep(.5)


def test_new_udp_socket_correctly_set_buffer_size():
    # Given
    buffer_size = 1024

    # When
    udp_socket = AsyncUDPChannel(buffer_size=buffer_size, socket_port=50001).start()

    # Then
    assert udp_socket.buffer_size == buffer_size
    udp_socket.stop()
    time.sleep(.5)


def test_new_udp_socket_correctly_set_socket_ip():
    # Given
    socket_ip = "127.0.0.1"

    # When
    udp_socket = AsyncUDPChannel(socket_ip=socket_ip, socket_port=50002).start()

    # Then
    assert udp_socket.socket_ip == socket_ip
    udp_socket.stop()
    time.sleep(.5)


def test_new_udp_socket_correctly_set_socket_port():
    # Given
    socket_port = 50003

    # When
    udp_socket = AsyncUDPChannel(socket_port=socket_port).start()

    # Then
    assert udp_socket.socket_port == socket_port
    udp_socket.stop()
    time.sleep(.5)


def test_new_udp_socket_correctly_set_max_queue_size():
    # Given
    max_queue_size = 1000

    # When
    udp_socket = AsyncUDPChannel(max_queue_size=max_queue_size, socket_port=50004).start()

    # Then
    assert udp_socket.max_queue_size == max_queue_size
    udp_socket.stop()
    time.sleep(.5)


def test_new_udp_socket_correctly_setup_an_empty_queue():
    # Given

    # When
    udp_socket = AsyncUDPChannel(socket_port=50005).start()

    # Then
    assert collections.Counter(udp_socket.queue) == collections.Counter([])
    udp_socket.stop()
    time.sleep(.5)


def test_new_udp_socket_correctly_setup_a_socket_using_udp_protocol():
    # Given

    # When
    udp_socket = AsyncUDPChannel(socket_port=50006).start()

    # Then
    assert udp_socket.socket.type == socket.SocketKind.SOCK_DGRAM
    assert udp_socket.socket.family == socket.AddressFamily.AF_INET
    assert udp_socket.socket.proto == socket.IPPROTO_UDP
    udp_socket.stop()
    time.sleep(.5)


def test_udp_socket_can_start_and_stop_its_thread():
    # Given
    socket_ip = "127.0.0.1"
    socket_port = 50007

    # When
    udp_socket = AsyncUDPChannel(socket_ip=socket_ip, socket_port=socket_port).start()
    udp_socket.stop()
    time.sleep(.5)

    # Then
    assert udp_socket.is_running is False


def test_socket_can_receive_message_while_running():
    # Given
    socket_ip = "127.0.0.1"
    socket_port = 50008
    msg = str.encode("tests", "utf8")

    # When
    udp_socket = AsyncUDPChannel(socket_ip=socket_ip, socket_port=socket_port).start()
    udp_socket.socket.sendto(msg, (socket_ip, socket_port))
    time.sleep(.1)

    # Then
    assert len(udp_socket.queue) == 1
    assert udp_socket.queue[0][1] == (socket_ip, socket_port)
    assert udp_socket.queue[0][0] == msg
    udp_socket.stop()
    time.sleep(.5)


def test_socket_can_send_message_while_running():
    # Given
    socket_ip = "127.0.0.1"
    socket_port = 50009
    msg = str.encode("tests", "utf8")

    # When
    udp_socket = AsyncUDPChannel(socket_ip=socket_ip, socket_port=socket_port).start()
    udp_socket.sendto(msg, (socket_ip, socket_port))
    time.sleep(.1)

    # Then
    assert len(udp_socket.queue) == 1
    assert udp_socket.queue[0][1] == (socket_ip, socket_port)
    assert udp_socket.queue[0][0] == msg
    udp_socket.stop()
    time.sleep(.5)


def test_socket_can_received_multiple_message_while_running():
    # Given
    socket_ip = "127.0.0.1"
    socket_port = 50010
    msg = str.encode("tests", "utf8")
    n_msg = 10

    # When
    udp_socket = AsyncUDPChannel(socket_ip=socket_ip, socket_port=socket_port, max_queue_size=n_msg).start()
    for i in range(n_msg):
        udp_socket.sendto(msg, (socket_ip, socket_port))
    time.sleep(.1)
    udp_socket.stop()
    time.sleep(.5)

    # Then
    assert len(udp_socket.queue) == n_msg


def test_pull_allow_to_get_first_message_in_the_queue():
    # Given
    socket_ip = "127.0.0.1"
    socket_port = 50011
    n_msg = 2

    # When
    udp_socket = AsyncUDPChannel(socket_ip=socket_ip, socket_port=socket_port, max_queue_size=n_msg).start()
    udp_socket.sendto(bytes([0]), (socket_ip, socket_port))
    udp_socket.sendto(bytes([1]), (socket_ip, socket_port))
    time.sleep(.1)
    result = udp_socket.pull()

    # Then
    assert result[0] == bytes([0])
    assert len(udp_socket.queue) == 1
    udp_socket.stop()
    time.sleep(.5)


def test_new_udp_socket_correctly_set_encryption_key():
    # Given
    key = generate_key_32()

    # When
    udp_socket = AsyncUDPChannel(key=key, socket_port=50012).start()

    # Then
    assert udp_socket.get_key() == key
    udp_socket.stop()
    time.sleep(.5)


def test_key_is_not_none_when_no_value_is_given():
    # Given

    # When
    udp_socket = AsyncUDPChannel(socket_port=50013).start()

    # Then
    assert udp_socket.get_key() is not None
    udp_socket.stop()
    time.sleep(.5)


def test_new_socket_creates_a_fernet_encoder():
    # Given
    key = generate_key_32()

    # When
    udp_socket = AsyncUDPChannel(key=key, socket_port=50014).start()

    # Then
    assert udp_socket.encoder is not None
    assert type(udp_socket.encoder) is ChaCha20Poly1305
    udp_socket.stop()
    time.sleep(.5)


def test_change_key_correctly_change_the_key():
    # Given
    key_old = generate_key_32()
    key_new = generate_key_32()

    # When
    udp_socket = AsyncUDPChannel(key=key_old, socket_port=50015).start()
    udp_socket.change_key(key_new)

    # Then
    assert udp_socket.get_key() == key_new
    udp_socket.stop()
    time.sleep(.5)


def test_change_key_correctly_change_the_fernet_encoder():
    # Given
    key_old = generate_key_32()
    key_new = generate_key_32()
    msg = b"tests"

    # When
    udp_socket = AsyncUDPChannel(key=key_old, socket_port=50016).start()
    msg_crypt = udp_socket._encrypt(msg)
    msg_decrypt_old = udp_socket._decrypt(msg_crypt)
    udp_socket.change_key(key_new)

    # Then
    assert msg_decrypt_old == msg

    udp_socket.stop()
    time.sleep(.5)


def test_udp_socket_send_encrypted_messages_when_encryption_in_transit_set_to_true():
    # Given
    key = generate_key_32()
    msg = b"tests"
    socket_ip = "127.0.0.1"
    socket_port = 50017
    test_socket_port = 50018
    n_msg = 2
    test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    test_socket.bind((socket_ip, test_socket_port))
    test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket = AsyncUDPChannel(key=key, socket_ip=socket_ip, socket_port=socket_port, max_queue_size=n_msg,
                                 encryption_in_transit=True).start()

    # When
    udp_socket.sendto(msg, (socket_ip, test_socket_port))
    rcv_msg = test_socket.recv(100)
    time.sleep(.1)

    udp_socket.stop()
    test_socket.close()
    time.sleep(.5)

    # Then
    assert rcv_msg != msg
    assert msg == udp_socket._decrypt(rcv_msg)


def test_udp_socket_can_read_encrypted_messages_when_encryption_in_transit_set_to_true():
    # Given
    msg = b"tests"
    socket_ip = "127.0.0.1"
    socket_port = 50019
    n_msg = 2
    udp_socket = AsyncUDPChannel(socket_ip=socket_ip, socket_port=socket_port, max_queue_size=n_msg,
                                 encryption_in_transit=True).start()

    # When
    udp_socket.sendto(msg, (socket_ip, socket_port))
    time.sleep(.1)

    udp_socket.stop()
    time.sleep(.5)

    # Then
    assert udp_socket.pull()[0] == msg


def test_new_udp_socket_correctly_set_enable_multicast():
    # Given
    enable_multicast = True

    # When
    udp_socket = AsyncUDPChannel(enable_multicast=enable_multicast, socket_port=50020).start()

    # Then
    assert udp_socket.enable_multicast is enable_multicast
    udp_socket.stop()
    time.sleep(.5)


def test_new_udp_socket_correctly_set_multicast_ttl():
    # Given
    multicast_ttl = 3

    # When
    udp_socket = AsyncUDPChannel(multicast_ttl=multicast_ttl, socket_port=50021).start()

    # Then
    assert udp_socket.multicast_ttl is multicast_ttl
    udp_socket.stop()
    time.sleep(.5)


def test_udp_socket_can_read_unencrypted_messages_when_encryption_in_transit_set_to_true():
    # Given
    msg = b"tests"
    socket_ip = "127.0.0.1"
    socket_port = 50022
    n_msg = 2
    udp_socket = AsyncUDPChannel(socket_ip=socket_ip, socket_port=socket_port, max_queue_size=n_msg,
                                 encryption_in_transit=True).start()

    # When
    udp_socket.sendto(msg, (socket_ip, socket_port), skip_encryption=True)
    time.sleep(.1)

    udp_socket.stop()
    time.sleep(.5)

    # Then
    assert udp_socket.pull()[0] == msg

# python -m pytest -s -vv hermes/network
