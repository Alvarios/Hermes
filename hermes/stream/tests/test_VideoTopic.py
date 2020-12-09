from hermes.stream.VideoTopic import VideoTopic
from hermes.stream.ImageManager import ImageManager
from hermes.messages.UDPMessage import UDPMessage
from math import pow
import pytest
import collections
import numpy as np


def test_new_video_topic_is_created_with_correct_values_given_as_parameter():
    # Given
    expected_nb_packet = 10
    expected_total_bytes = 50
    expected_height = 10
    expected_length = 10
    expected_pixel_size = 3
    expected_time_creation = 1000

    # When
    vt = VideoTopic(nb_packet=expected_nb_packet, total_bytes=expected_total_bytes, height=expected_height,
                    length=expected_length, pixel_size=expected_pixel_size, time_creation=expected_time_creation)

    # Then
    assert vt.nb_packet == expected_nb_packet
    assert vt.total_bytes == expected_total_bytes
    assert vt.height == expected_height
    assert vt.length == expected_length
    assert vt.pixel_size == expected_pixel_size
    assert vt.time_creation == expected_time_creation


def test_nb_packet_cannot_be_less_than_one_and_cannot_exceed_max_size():
    # Given
    min_nb = 0
    max_nb = pow(2, 8 * ImageManager.NB_PACKET_SIZE)
    total_bytes = 50
    height = 10
    length = 10
    pixel_size = 3
    time_creation = 1000

    # When

    # Then
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=min_nb, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                   time_creation=time_creation)
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=max_nb, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                   time_creation=time_creation)


def test_total_bytes_cannot_be_less_than_one_and_cannot_exceed_max_size():
    # Given
    min_nb = 0
    max_nb = pow(2, 8 * ImageManager.TOTAL_BYTES_SIZE)
    nb_packet = 5
    height = 10
    length = 10
    pixel_size = 3
    time_creation = 1000

    # When

    # Then
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=nb_packet, total_bytes=min_nb, height=height, length=length, pixel_size=pixel_size,
                   time_creation=time_creation)
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=nb_packet, total_bytes=max_nb, height=height, length=length, pixel_size=pixel_size,
                   time_creation=time_creation)


def test_pixel_size_cannot_be_less_than_one_and_cannot_exceed_max_size():
    # Given
    min_nb = 0
    max_nb = pow(2, 8 * ImageManager.SIZE_PIXEL_SIZE)
    nb_packet = 5
    total_bytes = 50
    time_creation = 1000
    height = 10
    length = 10

    # When

    # Then
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=min_nb,
                   time_creation=time_creation)
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=max_nb,
                   time_creation=time_creation)


def test_time_creation_cannot_be_negative_and_cannot_exceed_max_size():
    # Given
    min_nb = -1
    max_nb = pow(2, 8 * UDPMessage.TIME_CREATION_LENGTH)
    nb_packet = 5
    total_bytes = 50
    pixel_size = 3
    height = 10
    length = 10

    # When

    # Then
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                   time_creation=min_nb)
    with pytest.raises(ValueError):
        VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                   time_creation=max_nb)


def test_new_video_topic_setup_a_list_of_udp_message_of_size_nb_packet():
    # Given
    nb_packet = 10
    total_bytes = 50
    pixel_size = 3
    creation = 1000
    height = 10
    length = 10

    # When
    vt = VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                    time_creation=creation)

    # Then
    assert len(vt.rcv_messages) == nb_packet


def test_new_video_topic_setup_rcv_error_to_false():
    # Given
    nb_packet = 10
    total_bytes = 50
    pixel_size = 3
    creation = 1000
    height = 10
    length = 10

    # When
    vt = VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                    time_creation=creation)

    # Then
    assert vt.rcv_error is False


def test_add_messages_correctly_add_messages_to_rcv_messages():
    # Given
    nb_packet = 2
    total_bytes = 50
    pixel_size = 3
    creation = 1000
    height = 10
    length = 10
    vt = VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                    time_creation=creation)
    test_msg1 = UDPMessage(subtopic=1)
    test_msg2 = UDPMessage(subtopic=2, payload=bytes([1]))

    # When
    vt.add_message(test_msg1)
    vt.add_message(test_msg2)

    # Then
    assert collections.Counter(list(vt.rcv_messages[0].payload)) == collections.Counter(list(test_msg1.payload))
    assert collections.Counter(list(vt.rcv_messages[1].payload)) == collections.Counter(list(test_msg2.payload))


def test_add_messages_set_rcv_error_to_true_if_message_nb_greater_than_nb_packet():
    # Given
    nb_packet = 2
    total_bytes = 50
    pixel_size = 3
    creation = 1000
    height = 10
    length = 10
    vt = VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                    time_creation=creation)
    message_nb = 4
    test_msg = UDPMessage(subtopic=message_nb)

    # When
    vt.add_message(test_msg)

    # Then
    assert vt.rcv_error is True


def test_add_messages_set_rcv_error_to_true_if_message_is_corrupted():
    # Given
    nb_packet = 2
    total_bytes = 50
    pixel_size = 3
    creation = 1000
    height = 10
    length = 10
    vt = VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                    time_creation=creation)
    test_msg = UDPMessage()
    test_msg.crc = list(test_msg.crc)
    test_msg.crc[0] += 1
    test_msg.crc = bytes(test_msg.crc)

    # When
    vt.add_message(test_msg)

    # Then
    assert vt.rcv_error is True


def test_all_msg_received_return_true_if_all_messages_have_been_received():
    # Given
    nb_packet = 5
    total_bytes = 50
    pixel_size = 3
    creation = 1000
    height = 10
    length = 10
    vt = VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                    time_creation=creation)

    for i in range(nb_packet):
        vt.add_message(UDPMessage(subtopic=i + 1))

    # When
    result = vt.all_msg_received()

    # Then
    assert result is True


def test_total_bytes_correct_return_true_if_expected_number_of_bytes_is_the_same_than_the_received_number():
    # Given
    nb_packet = 2
    total_bytes = 50
    pixel_size = 3
    creation = 1000
    height = 10
    length = 10
    vt = VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                    time_creation=creation)

    for i in range(nb_packet):
        vt.add_message(UDPMessage(subtopic=i + 1, payload=bytes(25 * [0])))

    # When
    result = vt.total_bytes_correct()

    # Then
    assert result


def test_rebuild_img_return_none_if_total_bytes_modulo_pixel_size_is_not_0():
    # Given
    nb_packet = 2
    total_bytes = 50
    pixel_size = 3
    creation = 1000
    height = 10
    length = 10

    vt = VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                    time_creation=creation)

    for i in range(nb_packet):
        vt.add_message(UDPMessage(subtopic=i + 1, payload=bytes(25 * [0])))

    # When
    result = vt.rebuild_img()

    # Then
    assert result is None


def test_rebuild_img_return_none_if_total_bytes_modulo_height_is_not_0():
    # Given
    nb_packet = 2
    total_bytes = 30
    pixel_size = 3
    creation = 1000
    height = 7
    length = 10

    vt = VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                    time_creation=creation)

    for i in range(nb_packet):
        vt.add_message(UDPMessage(subtopic=i + 1, payload=bytes(25 * [0])))

    # When
    result = vt.rebuild_img()

    # Then
    assert result is None


def test_rebuild_img_return_none_if_total_bytes_modulo_length_is_not_0():
    # Given
    nb_packet = 2
    total_bytes = 30
    pixel_size = 3
    creation = 1000
    height = 10
    length = 7

    vt = VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                    time_creation=creation)

    for i in range(nb_packet):
        vt.add_message(UDPMessage(subtopic=i + 1, payload=bytes(25 * [0])))

    # When
    result = vt.rebuild_img()

    # Then
    assert result is None


def test_rebuild_img_return_numpy_array_as_expected_for_pixel_size_3():
    # Given
    nb_packet = 3
    total_bytes = 90
    pixel_size = 3
    creation = 1000
    height = 10
    length = 3

    vt = VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                    time_creation=creation)

    for i in range(nb_packet):
        vt.add_message(UDPMessage(subtopic=i + 1, payload=bytes(30 * [0])))

    # When
    result = vt.rebuild_img()

    # Then
    assert result.shape == (height, length, pixel_size)
    assert np.array_equiv(result.flatten(), np.array(height * length * pixel_size * [0]))


def test_rebuild_img_return_numpy_array_as_expected_for_pixel_size_1():
    # Given
    nb_packet = 3
    total_bytes = 30
    pixel_size = 1
    creation = 1000
    height = 10
    length = 3

    vt = VideoTopic(nb_packet=nb_packet, total_bytes=total_bytes, height=height, length=length, pixel_size=pixel_size,
                    time_creation=creation)

    for i in range(nb_packet):
        vt.add_message(UDPMessage(subtopic=i + 1, payload=bytes(10 * [0])))

    # When
    result = vt.rebuild_img()

    # Then
    assert result.shape == (height, length)
    assert np.array_equiv(result.flatten(), np.array(height * length * pixel_size * [0]))


def test_from_message_correctly_create_a_new_video_topic():
    # Given
    nb_packet = 3
    total_bytes = 90
    height = 10
    length = 3
    pixel_size = 3

    expected_payload = nb_packet.to_bytes(ImageManager.NB_PACKET_SIZE, 'little') + total_bytes.to_bytes(
        ImageManager.TOTAL_BYTES_SIZE, 'little') + height.to_bytes(ImageManager.HEIGHT_SIZE, 'little') + length.to_bytes(
        ImageManager.LENGTH_SIZE, 'little') + pixel_size.to_bytes(ImageManager.SIZE_PIXEL_SIZE, 'little')
    expected_topic = 10

    # When
    header = ImageManager.get_header_msg(expected_topic, nb_packet, total_bytes, height, length, pixel_size)
    header_message = UDPMessage.from_bytes(header)
    result = VideoTopic.from_message(header_message)

    # Then
    assert result.nb_packet == nb_packet
    assert result.total_bytes == total_bytes
    assert result.height == height
    assert result.length == length
    assert result.pixel_size == pixel_size
    assert result.time_creation == int.from_bytes(header_message.time_creation, 'little')


