from Stream.VideoStream import VideoStream
import numpy as np
import pytest
import collections
from Messages.UDPMessage import UDPMessage


def test_new_video_stream_correctly_setup_an_empty_numpy_array_for_image():
    # Given
    expected_current_image_size = 0

    # When
    vs = VideoStream()

    # Then
    assert vs.current_image.size == 0


def test_new_video_stream_correctly_setup_max_packet_size():
    # Given
    max_packet_size = 1000

    # When
    vs = VideoStream(max_packet_size=max_packet_size)

    # Then
    assert vs.current_image.size == 0


def test_refresh_image_correctly_change_current_image():
    # Given
    new_image = np.array([[0, 0, 0], [1, 1, 1], [2, 2, 2]])
    vs = VideoStream()

    # When
    vs.refresh_image(new_image)

    # Then
    assert np.array_equiv(vs.current_image, new_image)


def test_refresh_image_raise_an_error_if_shape_length_is_greater_than_3():
    # Given
    new_image = np.array(
        [[[1, 1, 1], [1, 1, 1], [1, 1, 1]], [[1, 1, 1], [1, 1, 1], [1, 1, 1]], [[1, 1, 1], [1, 1, 1], [1, 1, 1]]])
    vs = VideoStream()

    # When

    # Then
    with pytest.raises(ValueError):
        vs.refresh_image(new_image)


def test_refresh_image_raise_an_error_if_shape_length_is_2_and_pixels_does_not_contains_3_values():
    # Given
    new_image = np.array([[0, 0], [1, 1], [2, 2]])
    vs = VideoStream()

    # When

    # Then
    with pytest.raises(ValueError):
        vs.refresh_image(new_image)


def test_split_image_correctly_returns_a_list_of_bytes_with_one_element_for_small_image_of_pixels():
    # Given
    new_image = np.array([[0, 0, 0], [1, 1, 1], [2, 2, 2]])
    expected_result = [bytes([0, 0, 0, 1, 1, 1, 2, 2, 2])]
    vs = VideoStream(max_packet_size=100)
    vs.refresh_image(new_image)

    # When
    result = vs.split_image()

    # Then
    assert collections.Counter(result) == collections.Counter(expected_result)


def test_split_image_correctly_returns_a_list_of_bytes_with_many_elements_for_big_image_of_pixels():
    # Given
    new_image = np.array(4 * 4 * [[0, 0, 0]])
    expected_result = 4 * [bytes(12 * [0])]
    vs = VideoStream(max_packet_size=12)
    vs.refresh_image(new_image)

    # When
    result = vs.split_image()

    # Then
    assert collections.Counter(result) == collections.Counter(expected_result)


def test_get_header_msg_correctly_return_an_array_of_bytes_with_correct_metadata():
    # Given
    new_image = np.array(4 * 4 * [[0, 0, 0]])
    vs = VideoStream(max_packet_size=12)
    vs.refresh_image(new_image)
    split_img = vs.split_image()
    expected_payload = len(split_img).to_bytes(VideoStream.NB_PACKET_SIZE, 'little') + len(
        new_image.flatten()).to_bytes(VideoStream.TOTAL_BYTES_SIZE, 'little') + (3).to_bytes(
        VideoStream.SIZE_PIXEL_SIZE, 'little')
    expected_topic = 10

    # When
    result = vs.get_header_msg(expected_topic, len(split_img), len(new_image.flatten()), 3)
    result_message = UDPMessage.from_bytes(result)

    # Then
    assert result_message.payload == expected_payload
    assert int.from_bytes(result_message.topic, 'little') == expected_topic


def test_get_pixel_size_correctly_return_3_for_pixel_size_3():
    # Given
    new_image = np.array(4 * 4 * [[0, 0, 0]])
    vs = VideoStream()
    vs.refresh_image(new_image)
    expected_pixel_size = 3

    # When
    result = vs.get_pixel_size()

    # Then
    assert result == expected_pixel_size


def test_get_pixel_size_correctly_return_1_for_pixel_size_1():
    # Given
    new_image = np.array(4 * [0])
    vs = VideoStream()
    vs.refresh_image(new_image)
    expected_pixel_size = 1

    # When
    result = vs.get_pixel_size()

    # Then
    assert result == expected_pixel_size


def test_get_messages_correctly_return_a_list_of_message_to_send_that_represent_the_current_image():
    # Given
    new_image = np.array(4 * 4 * [[0, 0, 0]])
    vs = VideoStream(max_packet_size=12)
    vs.refresh_image(new_image)
    expected_topic = 10
    split_img = vs.split_image()
    expected_header = len(split_img).to_bytes(VideoStream.NB_PACKET_SIZE, 'little') + len(
        new_image.flatten()).to_bytes(VideoStream.TOTAL_BYTES_SIZE, 'little') + (3).to_bytes(
        VideoStream.SIZE_PIXEL_SIZE, 'little')

    # When
    result = vs.get_messages(10)

    # Then
    assert len(result) == len(split_img) + 1
    assert collections.Counter(UDPMessage.from_bytes(result[0]).payload) == collections.Counter(list(expected_header))
    for i in range(1, len(result)):
        msg = UDPMessage.from_bytes(result[i])
        assert int.from_bytes(msg.message_nb, 'little') == i
        assert int.from_bytes(msg.topic, 'little') == expected_topic
        assert msg.payload == bytes(12 * [0])


