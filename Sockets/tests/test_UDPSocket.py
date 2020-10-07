from Sockets.UDPSocket import UDPSocket
import collections
import socket
import time
import pytest
from cryptography.fernet import Fernet, InvalidToken


def test_new_udp_socket_correctly_set_encryption_in_transit():
    # Given
    encryption_in_transit = False

    # When
    udp_socket = UDPSocket(encryption_in_transit=False)

    # Then
    assert udp_socket.encryption_in_transit is encryption_in_transit


def test_new_udp_socket_correctly_set_buffer_size():
    # Given
    buffer_size = 1024

    # When
    udp_socket = UDPSocket(buffer_size=buffer_size)

    # Then
    assert udp_socket.buffer_size == buffer_size


def test_new_udp_socket_correctly_set_socket_ip():
    # Given
    socket_ip = "127.0.0.1"

    # When
    udp_socket = UDPSocket(socket_ip=socket_ip)

    # Then
    assert udp_socket.socket_ip == socket_ip


def test_new_udp_socket_correctly_set_socket_port():
    # Given
    socket_port = 50000

    # When
    udp_socket = UDPSocket(socket_port=socket_port)

    # Then
    assert udp_socket.socket_port == socket_port


def test_new_udp_socket_correctly_set_max_queue_size():
    # Given
    max_queue_size = 1000

    # When
    udp_socket = UDPSocket(max_queue_size=max_queue_size)

    # Then
    assert udp_socket.max_queue_size == max_queue_size


def test_new_udp_socket_correctly_setup_an_empty_queue():
    # Given

    # When
    udp_socket = UDPSocket()

    # Then
    assert collections.Counter(udp_socket.queue) == collections.Counter([])


def test_new_udp_socket_correctly_setup_a_socket_using_udp_protocol():
    # Given

    # When
    udp_socket = UDPSocket()

    # Then
    assert udp_socket.socket.type == socket.SocketKind.SOCK_DGRAM
    assert udp_socket.socket.family == socket.AddressFamily.AF_INET
    assert udp_socket.socket.proto == socket.IPPROTO_UDP


def test_udp_socket_can_start_and_stop_its_thread():
    # Given
    socket_ip = "127.0.0.1"
    socket_port = 50000

    # When
    udp_socket = UDPSocket(socket_ip=socket_ip, socket_port=socket_port)
    udp_socket.start_socket()
    time.sleep(.1)
    udp_socket.stop_socket()

    # Then
    assert udp_socket.is_running is False


def test_socket_can_receive_message_while_running():
    # Given
    socket_ip = "127.0.0.1"
    socket_port = 50000
    msg = str.encode("test", "utf8")

    # When
    udp_socket = UDPSocket(socket_ip=socket_ip, socket_port=socket_port)
    udp_socket.start_socket()
    udp_socket.socket.sendto(msg, (socket_ip, socket_port))
    time.sleep(.1)
    udp_socket.stop_socket()

    # Then
    assert len(udp_socket.queue) == 1
    assert udp_socket.queue[0][1] == (socket_ip, socket_port)
    assert udp_socket.queue[0][0] == msg


def test_socket_can_send_message_while_running():
    # Given
    socket_ip = "127.0.0.1"
    socket_port = 50000
    msg = str.encode("test", "utf8")

    # When
    udp_socket = UDPSocket(socket_ip=socket_ip, socket_port=socket_port)
    udp_socket.start_socket()
    udp_socket.sendto(msg, (socket_ip, socket_port))
    time.sleep(.1)
    udp_socket.stop_socket()

    # Then
    assert len(udp_socket.queue) == 1
    assert udp_socket.queue[0][1] == (socket_ip, socket_port)
    assert udp_socket.queue[0][0] == msg


def test_socket_can_received_multiple_message_while_running():
    # Given
    socket_ip = "127.0.0.1"
    socket_port = 50000
    msg = str.encode("test", "utf8")
    n_msg = 10

    # When
    udp_socket = UDPSocket(socket_ip=socket_ip, socket_port=socket_port, max_queue_size=n_msg)
    udp_socket.start_socket()
    for i in range(n_msg):
        udp_socket.sendto(msg, (socket_ip, socket_port))
    time.sleep(.1)
    udp_socket.stop_socket()

    # Then
    assert len(udp_socket.queue) == n_msg


def test_pull_allow_to_get_first_message_in_the_queue():
    # Given
    socket_ip = "127.0.0.1"
    socket_port = 50000
    n_msg = 2

    # When
    udp_socket = UDPSocket(socket_ip=socket_ip, socket_port=socket_port, max_queue_size=n_msg)
    udp_socket.start_socket()
    udp_socket.sendto(bytes([0]), (socket_ip, socket_port))
    udp_socket.sendto(bytes([1]), (socket_ip, socket_port))
    time.sleep(.1)
    result = udp_socket.pull()
    udp_socket.stop_socket()

    # Then
    assert result[0] == bytes([0])
    assert len(udp_socket.queue) == 1


def test_new_udp_socket_correctly_set_encryption_key():
    # Given
    key = Fernet.generate_key()

    # When
    udp_socket = UDPSocket(key=key)

    # Then
    assert udp_socket.key == key


def test_key_is_not_none_when_no_value_is_given():
    # Given

    # When
    udp_socket = UDPSocket()

    # Then
    assert udp_socket.key is not None


def test_new_socket_creates_a_fernet_encoder():
    # Given
    key = Fernet.generate_key()

    # When
    udp_socket = UDPSocket(key=key)

    # Then
    assert udp_socket.fernet_encoder is not None
    assert type(udp_socket.fernet_encoder) is Fernet


def test_change_key_correctly_change_the_key():
    # Given
    key_old = Fernet.generate_key()
    key_new = Fernet.generate_key()

    # When
    udp_socket = UDPSocket(key=key_old)
    udp_socket.change_key(key_new)

    # Then
    assert udp_socket.key == key_new


def test_change_key_correctly_change_the_fernet_encoder():
    # Given
    key_old = Fernet.generate_key()
    key_new = Fernet.generate_key()
    msg = b"test"

    # When
    udp_socket = UDPSocket(key=key_old)
    msg_crypt = udp_socket.fernet_encoder.encrypt(msg)
    msg_decrypt_old = udp_socket.fernet_encoder.decrypt(msg_crypt)
    udp_socket.change_key(key_new)

    # Then
    assert msg_decrypt_old == msg
    with pytest.raises(InvalidToken):
        udp_socket.fernet_encoder.decrypt(msg_crypt)


def test_udp_socket_send_encrypted_messages_when_encryption_in_transit_set_to_true():
    # Given
    key = Fernet.generate_key()
    test_fernet = Fernet(key=key)
    msg = b"test"
    socket_ip = "127.0.0.1"
    socket_port = 50000
    test_socket_port = 50001
    n_msg = 2
    test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    test_socket.bind((socket_ip, test_socket_port))
    test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket = UDPSocket(key=key, socket_ip=socket_ip, socket_port=socket_port, max_queue_size=n_msg,
                           encryption_in_transit=True)
    udp_socket.start_socket()

    # When
    udp_socket.sendto(msg, (socket_ip, test_socket_port))
    rcv_msg = test_socket.recv(100)
    time.sleep(.1)

    udp_socket.stop_socket()
    test_socket.shutdown(socket.SHUT_RD)
    test_socket.close()

    # Then
    assert test_fernet.decrypt(rcv_msg) == msg


def test_udp_socket_can_read_encrypted_messages_when_encryption_in_transit_set_to_true():
    # Given
    msg = b"test"
    socket_ip = "127.0.0.1"
    socket_port = 50000
    n_msg = 2
    udp_socket = UDPSocket(socket_ip=socket_ip, socket_port=socket_port, max_queue_size=n_msg,
                           encryption_in_transit=True)
    udp_socket.start_socket()

    # When
    udp_socket.sendto(msg, (socket_ip, socket_port))
    time.sleep(.1)

    udp_socket.stop_socket()

    # Then
    assert udp_socket.pull()[0] == msg
