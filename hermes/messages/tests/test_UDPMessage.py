from hermes.messages.UDPMessage import UDPMessage
import time
import zlib
import pytest


def test_new_udp_message_created_with_correct_payload_when_type_bytes():
    # Given
    payload = bytes([48, 48, 48, 48])

    # When
    msg = UDPMessage(payload=payload)

    # Then
    assert msg.payload == payload


def test_new_udp_message_created_with_correct_payload_when_string():
    # Given
    expected_payload = bytes([48, 48, 48, 48])
    payload = "0000"

    # When
    msg = UDPMessage(payload=payload)

    # Then
    assert msg.payload == expected_payload


def test_new_udp_message_created_with_correct_msg_id_when_type_bytes():
    # Given
    msg_id = bytes([48, 48, 48, 48])

    # When
    msg = UDPMessage(code=msg_id)

    # Then
    assert msg.msg_id == msg_id


def test_new_udp_message_created_with_correct_msg_id_when_type_int():
    # Given
    expected_msg_id = bytes([1, 0, 0, 0])
    msg_id = 1

    # When
    msg = UDPMessage(code=msg_id)

    # Then
    assert msg.msg_id == expected_msg_id


def test_new_udp_message_created_with_correct_time_creation():
    # Given
    expected_time_creation = int(time.time() * 1_000_000)

    # When
    msg = UDPMessage()

    # Then
    assert expected_time_creation - 2_000_000 < int.from_bytes(msg.time_creation,
                                                               'little') < expected_time_creation + 2_000_000


def test_new_udp_message_created_with_correct_topic_when_type_bytes():
    # Given
    topic = bytes([1, 0, 0, 0])

    # When
    msg = UDPMessage(topic=topic)

    # Then
    assert msg.topic == topic


def test_new_udp_message_created_with_correct_topic_when_type_int():
    # Given
    expected_topic = bytes([1, 0, 0, 0])
    topic = 1

    # When
    msg = UDPMessage(topic=topic)

    # Then
    assert msg.topic == expected_topic


def test_new_udp_message_created_with_correct_message_nb_when_type_bytes():
    # Given
    message_nb = bytes(UDPMessage.SUBTOPIC_LENGTH * [1])

    # When
    msg = UDPMessage(subtopic=message_nb)

    # Then
    assert msg.subtopic == message_nb


def test_new_udp_message_created_with_correct_message_nb_when_type_int():
    # Given
    expected_message_nb = bytes([1] + (UDPMessage.SUBTOPIC_LENGTH - 1) * [0])
    message_nb = 1

    # When
    msg = UDPMessage(subtopic=message_nb)

    # Then
    assert msg.subtopic == expected_message_nb


def test_new_udp_message_created_with_correct_crc():
    # Given
    message_nb = bytes([0, 0])
    payload = bytes([48, 48, 48, 48])
    msg_id = bytes([48, 48, 48, 48])
    topic = bytes([1, 0, 0, 0])

    # When
    msg = UDPMessage(subtopic=message_nb, payload=payload, code=msg_id, topic=topic)
    full_content = msg.msg_id + msg.time_creation + msg.topic + msg.subtopic + msg.payload
    expected_crc = zlib.crc32(full_content).to_bytes(UDPMessage.CRC_LENGTH, 'little')

    # Then
    assert msg.crc == expected_crc


def test_new_udp_message_created_with_correct_message_id_length_when_input_too_small():
    # Given
    msg_id = bytes([1, 0])

    # When
    msg = UDPMessage(code=msg_id)

    # Then
    assert len(msg.msg_id) == UDPMessage.MSG_ID_LENGTH


def test_new_udp_message_throw_error_when_input_message_id_too_big():
    # Given
    msg_id = bytes([1, 0, 0, 0, 0, 0])

    # When

    # Then
    with pytest.raises(ValueError):
        UDPMessage(code=msg_id)


def test_new_udp_message_created_with_correct_topic_length_when_input_too_small():
    # Given
    topic = bytes([1, 0])

    # When
    msg = UDPMessage(topic=topic)

    # Then
    assert len(msg.topic) == UDPMessage.TOPIC_LENGTH


def test_new_udp_message_throw_error_when_input_topic_too_big():
    # Given
    topic = bytes([1, 0, 0, 0, 0, 0])

    # When

    # Then
    with pytest.raises(ValueError):
        UDPMessage(topic=topic)


def test_new_udp_message_created_with_correct_message_nb_length_when_input_too_small():
    # Given
    msg_nb = bytes([1])

    # When
    msg = UDPMessage(subtopic=msg_nb)

    # Then
    assert len(msg.subtopic) == UDPMessage.SUBTOPIC_LENGTH


def test_new_udp_message_throw_error_when_input_message_nb_too_big():
    # Given
    msg_nb = bytes([1, 0, 0, 0, 0, 0])

    # When

    # Then
    with pytest.raises(ValueError):
        UDPMessage(subtopic=msg_nb)


def test_check_crc_returns_true_when_crc_correct():
    # Given
    message_nb = bytes([0, 0])
    payload = bytes([48, 48, 48, 48])
    msg_id = bytes([48, 48, 48, 48])
    topic = bytes([1, 0, 0, 0])

    # When
    msg = UDPMessage(subtopic=message_nb, payload=payload, code=msg_id, topic=topic)

    # Then
    assert msg.validate_integrity() is True


def test_check_crc_returns_false_when_crc_incorrect():
    # Given
    message_nb = bytes([0, 0])
    payload = bytes([48, 48, 48, 48])
    msg_id = bytes([48, 48, 48, 48])
    topic = bytes([1, 0, 0, 0])

    # When
    msg = UDPMessage(subtopic=message_nb, payload=payload, code=msg_id, topic=topic)
    msg.full_content = bytes()

    # Then
    assert msg.validate_integrity() is False


def test_to_bytes_returns_full_message_as_bytes():
    # Given
    message_nb = bytes([0, 0])
    payload = bytes([48, 48, 48, 48])
    msg_id = bytes([48, 48, 48, 48])
    topic = bytes([1, 0, 0, 0])

    # When
    msg = UDPMessage(subtopic=message_nb, payload=payload, code=msg_id, topic=topic)
    expected_result = msg.full_content + msg.crc

    # Then
    assert msg.to_bytes() == expected_result


def test_from_bytes_correctly_load_a_message():
    # Given
    message_nb = bytes(UDPMessage.SUBTOPIC_LENGTH * [1])
    payload = bytes([49, 49, 49, 49])
    msg_id = bytes([48, 48, 48, 48])
    topic = bytes([1, 0, 0, 0])

    # When
    msg = UDPMessage(subtopic=message_nb, payload=payload, code=msg_id, topic=topic)
    result = UDPMessage.from_bytes(msg.to_bytes())

    # Then
    assert result.msg_id == msg_id
    assert result.time_creation == msg.time_creation
    assert result.topic == topic
    assert result.subtopic == message_nb
    assert result.payload == payload
    assert result.crc == msg.crc


def test_from_bytes_returns_none_if_message_is_corrupted():
    # Given
    message_nb = bytes([2, 0])
    payload = bytes([49, 49, 49, 49])
    msg_id = bytes([48, 48, 48, 48])
    topic = bytes([1, 0, 0, 0])

    # When
    msg = UDPMessage(subtopic=message_nb, payload=payload, code=msg_id, topic=topic)
    msg.crc = bytes()
    result = UDPMessage.from_bytes(msg.to_bytes())

    # Then
    assert result is None


def test_from_bytes_returns_none_if_input_too_small():
    # Given

    # When
    result = UDPMessage.from_bytes(bytes())

    # Then
    assert result is None


def test_new_udp_message_throw_error_when_input_payload_too_big():
    # Given
    payload = bytes([0] * (UDPMessage.PAYLOAD_MAX_SIZE + 1))

    # When

    # Then
    with pytest.raises(ValueError):
        UDPMessage(payload=payload)
