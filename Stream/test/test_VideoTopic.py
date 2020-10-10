from Stream.VideoStream import VideoStream, VideoTopic
from Messages.UDPMessage import UDPMessage
from math import pow
import pytest


def test_new_video_topic_is_created_with_correct_values_given_as_parameter():
    # Given
    expected_nb_packet = 10
    expected_total_bytes = 50
    expected_pixel_size = 3
    expected_time_creation = 1000

    # When
    vt = VideoTopic(nb_packet=expected_nb_packet, total_bytes=expected_total_bytes, pixel_size=expected_pixel_size,
                    time_creation=expected_time_creation)

    # Then
    assert vt.nb_packet == expected_nb_packet
    assert vt.total_bytes == expected_total_bytes
    assert vt.pixel_size == expected_pixel_size
    assert vt.time_creation == expected_time_creation


def test_nb_packet_cannot_be_less_than_one_and_cannot_exceed_max_size():
    # Given
    min_nb = 0
    max_nb = pow(2, 8 * VideoStream.NB_PACKET_SIZE)
    total_bytes = 50
    pixel_size = 3
    time_creation = 1000

    # When

    # Then
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=min_nb, total_bytes=total_bytes, pixel_size=pixel_size, time_creation=time_creation)
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=max_nb, total_bytes=total_bytes, pixel_size=pixel_size, time_creation=time_creation)


def test_total_bytes_cannot_be_less_than_one_and_cannot_exceed_max_size():
    # Given
    min_nb = 0
    max_nb = pow(2, 8 * VideoStream.TOTAL_BYTES_SIZE)
    nb_packet = 5
    pixel_size = 3
    time_creation = 1000

    # When

    # Then
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=nb_packet, total_bytes=min_nb, pixel_size=pixel_size, time_creation=time_creation)
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=nb_packet, total_bytes=max_nb, pixel_size=pixel_size, time_creation=time_creation)


def test_pixel_size_cannot_be_less_than_one_and_cannot_exceed_max_size():
    # Given
    min_nb = 0
    max_nb = pow(2, 8 * VideoStream.SIZE_PIXEL_SIZE)
    nb_packet = 5
    total_bytes = 50
    time_creation = 1000

    # When

    # Then
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, pixel_size=min_nb, time_creation=time_creation)
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, pixel_size=max_nb, time_creation=time_creation)


def test_time_creation_cannot_be_negative_and_cannot_exceed_max_size():
    # Given
    min_nb = -1
    max_nb = pow(2, 8 * UDPMessage.TIME_CREATION_LENGTH)
    nb_packet = 5
    total_bytes = 50
    pixel_size = 3

    # When

    # Then
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, pixel_size=pixel_size, time_creation=min_nb)
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, pixel_size=pixel_size, time_creation=max_nb)
