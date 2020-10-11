from Stream.VideoStream import TopicManager, ImageManager, VideoTopic
from Messages.UDPMessage import UDPMessage
import numpy as np
import pytest


@pytest.fixture
def get_msg_sample():
    new_image = np.array(4 * [4 * 4 * [[0, 0, 0]]])
    im = ImageManager(max_packet_size=64)
    im.refresh_image(new_image)
    return im.get_messages(1)


def test_topic_manager_is_created_with_empty_open_topic_and_img_queue():
    # Given
    expected_open_topic = {}
    expected_img_queue = []

    # When
    tm = TopicManager()

    # Then
    assert tm.open_topic == expected_open_topic
    assert tm.img_queue == expected_img_queue


def test_in_waiting_return_true_if_an_image_is_waiting_in_img_queue_else_false():
    # Given
    tm = TopicManager()

    # When
    rslt1 = tm.in_waiting()
    tm.img_queue.append(np.array([]))
    rslt2 = tm.in_waiting()

    # Then
    assert rslt1 is False
    assert rslt2 is True


def test_add_msg_correctly_create_a_topic_if_a_new_topic_need_to_be_created(get_msg_sample):
    # Given
    messages = get_msg_sample
    tm = TopicManager()

    # When
    tm.add_message(UDPMessage.from_bytes(messages[0]))

    # Then
    assert type(tm.open_topic[int.from_bytes(UDPMessage.from_bytes(messages[0]).topic, 'little')]) is VideoTopic
