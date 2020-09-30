from Sockets.UDPSocket import UDPSocket
import collections
import socket
import time
import pytest


def test_new_udp_socket_correctly_set_secure_connection():
    # Given
    secure_connection = False

    # When
    udp_socket = UDPSocket(secure_connection=False)

    # Then
    assert udp_socket.secure_connection is secure_connection


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
