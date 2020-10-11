import multiprocessing as mp
from Stream.VideoStream import VideoStream, ImageManager, VideoTopic
import numpy as np
import pytest
import time


def test_video_stream_is_instance_of_process():
    # Given
    expected_type = mp.Process

    # When
    vs = VideoStream()

    # Then
    assert isinstance(vs, expected_type)
    vs.stop()
    vs.join()


def test_video_stream_define_an_image_manager_with_correct_parameter():
    # Given
    expected_type = ImageManager
    max_packet_size = 10000

    # When
    vs = VideoStream(max_packet_size=max_packet_size)

    # Then
    assert isinstance(vs.im, expected_type)
    assert vs.im.max_packet_size == max_packet_size
    vs.stop()
    vs.join()


def test_video_stream_define_an_empty_list_of_video_topic():
    # Given
    expected_list = []

    # When
    vs = VideoStream()

    # Then
    assert vs.opened_topics == []
    vs.stop()
    vs.join()


def test_refresh_image_correctly_refresh_image_in_im():
    # Given
    expected_img = np.array(
        [[[0, 0, 0], [0, 0, 0], [0, 0, 0]], [[0, 0, 0], [0, 0, 0], [0, 0, 0]], [[0, 0, 0], [0, 0, 0], [0, 0, 0]]])

    # When
    vs = VideoStream()
    vs.refresh_image(expected_img)

    # Then
    assert np.array_equiv(vs.get_current_image(), expected_img)
    vs.stop()
    vs.join()


def test_video_stream_is_created_with_correct_role():
    # Given
    role_1 = VideoStream.EMITTER
    role_2 = VideoStream.CONSUMER

    # When
    vs1 = VideoStream(role=role_1)
    vs2 = VideoStream(role=role_2)

    # Then
    assert vs1.role == role_1
    assert vs2.role == role_2

    vs1.stop()
    vs1.join()
    vs2.stop()
    vs2.join()


def test_video_stream_cannot_be_created_with_unexpected_role():
    # Given
    role = "test"

    # When

    # Then
    with pytest.raises(ValueError):
        vs = VideoStream(role=role)
        vs.stop()
        vs.join()


def test_video_stream_create_two_connection_pipe():
    # Given
    expected_type = mp.connection.PipeConnection

    # When
    vs = VideoStream()

    # Then
    assert type(vs.external_pipe) == expected_type
    assert type(vs.internal_pipe) == expected_type

    vs.stop()
    vs.join()


def test_video_stream_can_be_started_and_stopped():
    # Given
    vs = VideoStream()

    # When
    while vs.get_is_running() is False:
        pass

    # Then
    assert vs.get_is_running()
    vs.stop()
    vs.join()


def test_add_subscriber_correctly_add_a_subscriber():
    # Given
    sub_address_port = ('127.0.01', 50000)
    vs = VideoStream()
    while vs.get_is_running() is False:
        pass

    # When
    vs.add_subscriber(sub_address_port)

    # Then
    assert len(vs.get_subs_list()) == 1
    assert vs.get_subs_list()[0] == sub_address_port

    vs.stop()
    vs.join()


def test_remove_subscriber_correctly_remove_a_subscriber():
    # Given
    sub_address_port = ('127.0.01', 50000)
    vs = VideoStream()
    while vs.get_is_running() is False:
        pass

    # When
    vs.add_subscriber(sub_address_port)
    vs.remove_subscriber(0)

    # Then
    assert len(vs.get_subs_list()) == 0

    vs.stop()
    vs.join()
