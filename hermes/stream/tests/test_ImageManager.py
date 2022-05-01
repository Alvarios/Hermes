from hermes.stream.ImageManager import ImageManager
import numpy as np
import pytest
import collections
from hermes.messages.UDPMessage import UDPMessage


def test_new_image_manager_correctly_setup_an_empty_numpy_array_for_image():
    # Given
    expected_current_image_size = 0

    # When
    im = ImageManager()

    # Then
    assert im.current_image.size == 0


def test_new_image_manager_correctly_setup_max_packet_size():
    # Given
    max_packet_size = 1000

    # When
    im = ImageManager(max_packet_size=max_packet_size)

    # Then
    assert im.current_image.size == 0


def test_refresh_image_correctly_change_current_image():
    # Given
    new_image = np.array([[[0, 0, 0], [1, 1, 1], [2, 2, 2]], [[0, 0, 0], [1, 1, 1], [2, 2, 2]]])
    im = ImageManager()

    # When
    im.refresh_image(new_image)

    # Then
    assert np.array_equiv(im.current_image, new_image)


def test_refresh_image_raise_an_error_if_shape_length_is_greater_than_3():
    # Given
    new_image = np.array(
        [[[[1, 1, 1], [1, 1, 1], [1, 1, 1]], [[1, 1, 1], [1, 1, 1], [1, 1, 1]], [[1, 1, 1], [1, 1, 1], [1, 1, 1]]]])
    im = ImageManager()

    # When

    # Then
    with pytest.raises(ValueError):
        im.refresh_image(new_image)


def test_refresh_image_raise_an_error_if_shape_length_is_2_and_pixels_does_not_contains_3_values():
    # Given
    new_image = np.array([[[0, 0], [1, 1], [2, 2]]])
    im = ImageManager()

    # When

    # Then
    with pytest.raises(ValueError):
        im.refresh_image(new_image)


def test_split_image_correctly_returns_a_list_of_bytes_with_one_element_for_small_image_of_pixels():
    # Given
    new_image = np.array([[0, 0, 0], [1, 1, 1], [2, 2, 2]])
    expected_result = [bytes([0, 0, 0, 1, 1, 1, 2, 2, 2])]
    im = ImageManager(max_packet_size=100)
    im.refresh_image(new_image)

    # When
    result = im.split_image()

    # Then
    assert collections.Counter(result) == collections.Counter(expected_result)


def test_split_image_correctly_returns_a_list_of_bytes_with_many_elements_for_big_image_of_pixels():
    # Given
    new_image = np.array(4 * 4 * [[0, 0, 0]])
    expected_result = 4 * [bytes(12 * [0])]
    im = ImageManager(max_packet_size=12)
    im.refresh_image(new_image)

    # When
    result = im.split_image()

    # Then
    assert collections.Counter(result) == collections.Counter(expected_result)


def test_get_header_msg_correctly_return_an_array_of_bytes_with_correct_metadata():
    # Given
    nb_packet = 2
    total_bytes = 50
    height = 2
    length = 25
    pixel_size = 3
    encoding = 0

    expected_payload = nb_packet.to_bytes(ImageManager.NB_PACKET_SIZE, 'little') + total_bytes.to_bytes(
        ImageManager.TOTAL_BYTES_SIZE, 'little') + height.to_bytes(ImageManager.HEIGHT_SIZE,
                                                                   'little') + length.to_bytes(
        ImageManager.LENGTH_SIZE, 'little') + pixel_size.to_bytes(ImageManager.SIZE_PIXEL_SIZE,
                                                                  'little') + encoding.to_bytes(
        ImageManager.ENCODING_SIZE, 'little')
    expected_topic = 10

    # When
    result = ImageManager.get_header_msg(expected_topic, nb_packet, total_bytes, height, length, pixel_size)
    result_message = UDPMessage.from_bytes(result)

    # Then
    assert result_message.payload == expected_payload
    assert int.from_bytes(result_message.topic, 'little') == expected_topic


def test_get_pixel_size_correctly_return_3_for_pixel_size_3():
    # Given
    new_image = np.array(4 * [4 * 4 * [[0, 0, 0]]])
    im = ImageManager()
    im.refresh_image(new_image)
    expected_pixel_size = 3

    # When
    result = im.get_pixel_size()

    # Then
    assert result == expected_pixel_size


def test_get_pixel_size_correctly_return_1_for_pixel_size_1():
    # Given
    new_image = np.array(4 * [4 * [0]])
    im = ImageManager()
    im.refresh_image(new_image)
    expected_pixel_size = 1

    # When
    result = im.get_pixel_size()

    # Then
    assert result == expected_pixel_size


def test_get_messages_correctly_return_a_list_of_message_to_send_that_represent_the_current_image():
    # Given
    new_image = np.array(4 * [4 * 4 * [[0, 0, 0]]])
    im = ImageManager(max_packet_size=64)
    im.refresh_image(new_image)
    nb_packet = 3
    total_bytes = 192
    height = 4
    length = 16
    pixel_size = 3
    expected_topic = 10
    encoding = 0
    expected_header = nb_packet.to_bytes(ImageManager.NB_PACKET_SIZE, 'little') + total_bytes.to_bytes(
        ImageManager.TOTAL_BYTES_SIZE, 'little') + height.to_bytes(ImageManager.HEIGHT_SIZE,
                                                                   'little') + length.to_bytes(
        ImageManager.LENGTH_SIZE, 'little') + pixel_size.to_bytes(ImageManager.SIZE_PIXEL_SIZE,
                                                                  'little') + encoding.to_bytes(
        ImageManager.ENCODING_SIZE, 'little')

    # When
    result = list(im.get_messages(expected_topic))

    # Then
    assert collections.Counter(UDPMessage.from_bytes(result[0]).payload) == collections.Counter(list(expected_header))
    for i in range(1, len(result)):
        msg = UDPMessage.from_bytes(result[i])
        assert int.from_bytes(msg.subtopic, 'little') == i
        assert int.from_bytes(msg.topic, 'little') == expected_topic
        assert msg.payload == bytes(64 * [0])
