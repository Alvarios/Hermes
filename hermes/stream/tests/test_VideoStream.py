import multiprocessing as mp
from hermes.stream.VideoStream import VideoStream
from hermes.stream.ImageManager import ImageManager
import numpy as np
import pytest
import time


def test_video_stream_define_an_image_manager_with_correct_parameter():
    # Given
    expected_type = ImageManager
    max_packet_size = 10000

    # When
    vs = VideoStream(max_packet_size=max_packet_size,
                     socket_port=60000).start()

    # Then
    assert isinstance(vs.im, expected_type)
    assert vs.im.max_packet_size == max_packet_size
    vs.stop()


def test_video_stream_define_an_empty_list_of_video_topic():
    # Given
    expected_list = []

    # When
    vs = VideoStream(socket_port=60001).start()

    # Then
    assert vs.opened_topics == []
    vs.stop()


def test_refresh_image_correctly_refresh_image_in_im():
    # Given
    expected_img = np.array(
        [[[0, 0, 0], [0, 0, 0], [0, 0, 0]], [[0, 0, 0], [0, 0, 0], [0, 0, 0]],
         [[0, 0, 0], [0, 0, 0], [0, 0, 0]]])

    # When
    vs = VideoStream(socket_port=60002).start()
    vs.refresh_image(expected_img)

    # Then
    assert np.array_equiv(vs.get_current_image(), expected_img)
    vs.stop()


def test_video_stream_is_created_with_correct_role():
    # Given
    role_1 = VideoStream.EMITTER
    role_2 = VideoStream.CONSUMER

    # When
    vs1 = VideoStream(role=role_1, socket_port=60003).start()
    vs2 = VideoStream(role=role_2, socket_port=60004).start()

    # Then
    assert vs1.role == role_1
    assert vs2.role == role_2

    vs1.stop()
    vs2.stop()


def test_video_stream_cannot_be_created_with_unexpected_role():
    # Given
    role = "tests"

    # When

    # Then
    with pytest.raises(ValueError):
        vs = VideoStream(role=role, socket_port=60005).start()
        vs.stop()
        vs.join()


def test_video_stream_create_two_connection_pipe():
    # Given

    # When
    vs = VideoStream(socket_port=60006).start()

    # Then
    assert type(vs.external_pipe) is not None
    assert type(vs.internal_pipe) is not None

    vs.stop()


def test_video_stream_can_be_started_and_stopped():
    # Given
    vs = VideoStream(socket_port=60007).start()

    # When
    while vs.get_is_running() is False:
        pass

    # Then
    assert vs.get_is_running()
    vs.stop()


def test_add_subscriber_correctly_add_a_subscriber():
    # Given
    sub_address_port = ('127.0.01', 60008)
    vs = VideoStream(socket_port=60009).start()
    while vs.get_is_running() is False:
        pass

    # When
    vs.add_subscriber(sub_address_port)

    # Then
    assert len(vs.get_subs_list()) == 1
    assert vs.get_subs_list()[0] == sub_address_port

    vs.stop()


def test_remove_subscriber_correctly_remove_a_subscriber():
    # Given
    sub_address_port = ('127.0.01', 60010)
    vs = VideoStream(socket_port=60011).start()
    while vs.get_is_running() is False:
        pass

    # When
    vs.add_subscriber(sub_address_port)
    vs.remove_subscriber(0)

    # Then
    assert len(vs.get_subs_list()) == 0

    vs.stop()


def test_get_rcv_img_return_none_if_rcv_img_buffer_is_empty():
    # Given
    sub_address_port = ('127.0.01', 60012)
    vs = VideoStream(role=VideoStream.CONSUMER, socket_port=60013).start()
    while vs.get_is_running() is False:
        pass

    # When
    result = vs.get_rcv_img()

    # Then

    assert result is None

    vs.stop()


def test_two_video_stream_can_transmit_images():
    # Given
    expected_img = np.array(4 * [4 * 4 * [[0, 0, 0]]])
    emitter_address_port = ('127.0.0.1', 60014)
    consumer_address_port = ('127.0.0.1', 60015)
    emitter = VideoStream(role=VideoStream.EMITTER,
                          socket_ip=emitter_address_port[0],
                          socket_port=emitter_address_port[1]).start()
    consumer = VideoStream(role=VideoStream.CONSUMER,
                           socket_ip=consumer_address_port[0],
                           socket_port=consumer_address_port[1],
                           use_rcv_img_buffer=False,
                           buffer_size=1000000).start()
    while emitter.get_is_running() is False:
        pass
    while consumer.get_is_running() is False:
        pass
    emitter.refresh_image(expected_img)
    emitter.add_subscriber(consumer_address_port)
    time.sleep(.01)

    # When
    result = consumer.get_rcv_img()
    emitter.stop()
    consumer.stop()

    # Then
    assert np.array_equiv(result, expected_img)


def test_two_video_stream_can_transmit_encrypted_images():
    # Given
    expected_img = np.array(4 * [4 * 4 * [[0, 0, 0]]])
    emitter_address_port = ('127.0.0.1', 60014)
    consumer_address_port = ('127.0.0.1', 60015)
    emitter = VideoStream(role=VideoStream.EMITTER,
                          socket_ip=emitter_address_port[0],
                          socket_port=emitter_address_port[1],
                          encryption_in_transit=True).start()
    while emitter.get_is_running() is False:
        pass
    key = emitter.get_key()
    consumer = VideoStream(role=VideoStream.CONSUMER,
                           socket_ip=consumer_address_port[0],
                           socket_port=consumer_address_port[1],
                           use_rcv_img_buffer=False,
                           buffer_size=1000000, encryption_in_transit=True,
                           key=key).start()

    while consumer.get_is_running() is False:
        pass
    emitter.refresh_image(expected_img)
    emitter.add_subscriber(consumer_address_port)
    time.sleep(.1)

    # When

    result = consumer.get_rcv_img()
    emitter.stop()
    consumer.stop()

    # Then
    print()
    print(expected_img.shape)
    print(result.shape)
    assert np.array_equiv(result, expected_img)

# python -m pytest -s -vv hermes/stream/tests/test_VideoStream.py
