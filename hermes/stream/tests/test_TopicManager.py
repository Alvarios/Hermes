from hermes.stream.TopicManager import TopicManager
from hermes.stream.VideoTopic import VideoTopic
from hermes.stream.ImageManager import ImageManager
from hermes.messages.UDPMessage import UDPMessage
import numpy as np
import pytest
import time


@pytest.fixture
def get_msg_sample():
    new_image = np.array(4 * [4 * 4 * [[0, 0, 0]]])
    im = ImageManager(max_packet_size=64)
    im.refresh_image(new_image)
    return list(im.get_messages(1))


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


def test_add_msg_correctly_add_msg_to_an_existing_topic(get_msg_sample):
    # Given
    messages = get_msg_sample
    tm = TopicManager()

    # When
    tm.add_message(UDPMessage.from_bytes(messages[0]))
    tm.add_message(UDPMessage.from_bytes(messages[1]))

    # Then
    assert tm.open_topic[1].rcv_messages[0].payload == UDPMessage.from_bytes(messages[1]).payload
    assert tm.open_topic[1].rcv_messages[0].subtopic == UDPMessage.from_bytes(messages[1]).subtopic


def test_topic_exist_return_true_if_asked_topic_exist_else_return_false(get_msg_sample):
    # Given
    messages = get_msg_sample
    tm = TopicManager()
    existing_topic = 1
    non_existing_topic = 2

    # When
    tm.add_message(UDPMessage.from_bytes(messages[0]))
    result1 = tm.topic_exist(existing_topic)
    result2 = tm.topic_exist(non_existing_topic)

    # Then
    assert result1 is True
    assert result2 is False


def test_add_msg_add_data_messages_to_dead_letter_queue_when_its_topic_does_not_exist(get_msg_sample):
    # Given
    messages = get_msg_sample
    tm = TopicManager()

    # When
    tm.add_message(UDPMessage.from_bytes(messages[1]))

    # Then
    assert tm.dead_letter_queue[0].payload == UDPMessage.from_bytes(messages[1]).payload
    assert tm.dead_letter_queue[0].subtopic == UDPMessage.from_bytes(messages[1]).subtopic


def test_add_msg_add_message_from_dlq_to_its_topic_when_it_is_created_and_remove_msg_from_dlq(get_msg_sample):
    # Given
    messages = get_msg_sample
    tm = TopicManager()

    # When
    tm.add_message(UDPMessage.from_bytes(messages[1]))
    tm.add_message(UDPMessage.from_bytes(messages[0]))

    # Then
    assert tm.open_topic[1].rcv_messages[0].payload == UDPMessage.from_bytes(messages[1]).payload
    assert tm.open_topic[1].rcv_messages[0].subtopic == UDPMessage.from_bytes(messages[1]).subtopic
    assert len(tm.dead_letter_queue) == 0


def test_process_dlq_correctly_remove_outdated_messages_from_dlq(get_msg_sample):
    # Given
    messages = get_msg_sample
    tm = TopicManager()
    tm.add_message(UDPMessage.from_bytes(messages[1]))

    time.sleep(.01)
    new_image = np.array(4 * [4 * 4 * [[0, 0, 0]]])
    im = ImageManager(max_packet_size=64)
    im.refresh_image(new_image)
    new_messages = list(im.get_messages(2))
    tm.add_message(UDPMessage.from_bytes(new_messages[1]))

    # When

    tm.add_message(UDPMessage.from_bytes(new_messages[0]))

    # Then

    assert len(tm.dead_letter_queue) == 0


def test_add_msg_remove_completed_topics_from_open_topic(get_msg_sample):
    # Given
    messages = get_msg_sample
    tm = TopicManager()
    tm.add_message(UDPMessage.from_bytes(messages[0]))

    # When
    for i in messages[1:]:
        tm.add_message(UDPMessage.from_bytes(i))

    # Then
    assert len(tm.open_topic.keys()) == 0


def test_check_topic_remove_old_opened_topic_when_a_topic_is_completed(get_msg_sample):
    # Given
    messages = get_msg_sample
    tm = TopicManager()
    tm.add_message(UDPMessage.from_bytes(messages[0]))

    time.sleep(.01)
    new_image = np.array(4 * [4 * 4 * [[0, 0, 0]]])
    im = ImageManager(max_packet_size=64)
    im.refresh_image(new_image)
    new_messages = list(im.get_messages(2))
    tm.add_message(UDPMessage.from_bytes(new_messages[0]))

    # When
    for i in new_messages[1:]:
        tm.add_message(UDPMessage.from_bytes(i))

    # Then
    assert len(tm.open_topic.keys()) == 0


def test_check_topic_add_topic_image_to_img_queue_when_topic_is_complete(get_msg_sample):
    # Given
    expected_img = np.array(4 * [4 * 4 * [[0, 0, 0]]])
    messages = get_msg_sample
    tm = TopicManager()
    tm.add_message(UDPMessage.from_bytes(messages[0]))

    # When
    for i in messages[1:]:
        tm.add_message(UDPMessage.from_bytes(i))

    # Then
    assert np.array_equiv(expected_img, tm.img_queue[0])


def test_pull_return_the_first_image_of_the_list_if_an_image_is_waiting_else_none(get_msg_sample):
    # Given
    expected_img = np.array(4 * [4 * 4 * [[0, 0, 0]]])
    messages = get_msg_sample
    tm = TopicManager()
    tm.add_message(UDPMessage.from_bytes(messages[0]))

    # When
    for i in messages[1:]:
        tm.add_message(UDPMessage.from_bytes(i))

    pull1 = tm.pull()
    pull2 = tm.pull()

    # Then
    assert np.array_equiv(expected_img, pull1)
    assert pull2 is None
