# -*- coding: utf-8 -*-
"""Implementation of a class used to manage VideoTopics in VideoStream.py.

    Copyright (C) 2020  Clement Dulouard

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

Also add information on how to contact you by electronic and paper mail.

  If your software can interact with users remotely through a computer
network, you should also make sure that it provides a way for users to
get its source.  For example, if your program is a web application, its
interface could display a "Source" link that leads users to an archive
of the code.  There are many ways you could offer source, and different
solutions will be better for different programs; see section 13 for the
specific requirements.

  You should also get your employer (if you work as a programmer) or school,
if any, to sign a "copyright disclaimer" for the program, if necessary.
For more information on this, and how to apply and follow the GNU AGPL, see
<https://www.gnu.org/licenses/>.
"""
from typing import Dict, List, NoReturn

import numpy as np

from hermes.messages.UDPMessage import UDPMessage
from hermes.stream.VideoTopic import VideoTopic


class TopicManager:
    """A class designed to manage the incoming messages in order to rebuild
    images.

        Attributes :
            open_topic : A dictionary of VideoTopic representing current open
            topic.
            img_queue : A list of images waiting to be pulled.
            dead_letter_queue : A list of added data messages with no existing
            topic.
    """

    def __init__(self) -> None:
        """Create a new TopicManager instance."""
        self.open_topic: Dict[int, VideoTopic] = {}
        self.img_queue: List[np.array] = []
        self.dead_letter_queue: List[UDPMessage] = []

    def in_waiting(self) -> bool:
        """Return True if an image is waiting in img_queue.

        :return: A boolean that tell if an image is waiting in img_queue.
        """
        return len(self.img_queue) > 0

    def add_message(self, new_message: UDPMessage) -> NoReturn:
        """Read incoming message and do the work needed by the message.

        This function contains three cases, the first one is when the added
        message requires the creation of a new
        topic. The function will create the topic if it is possible and then
        will check the dead letter queue to
        check if there are messages associated to this new topic. The outdated
        messages in the dlq will be deleted at this step.

        The second case is when a data message is received. If the associated
        topic exists, the message will be added to
        this topic. If the topic is completed with the incoming message, the
        image will be rebuilt and added to img_queue.

        The third case is when the message cannot be processed now. If it is
        the case it will be put in the dlq to be processed later.

        :param new_message: The message to process.
        """
        topic = int.from_bytes(new_message.topic, 'little')
        msg_nb = int.from_bytes(new_message.subtopic, 'little')
        if msg_nb == 0 and (topic not in self.open_topic.keys()):
            self.open_topic[topic] = VideoTopic.from_message(new_message)
            self.process_dlq(topic)
        elif topic in self.open_topic.keys() and self.open_topic[
            topic].nb_packet >= msg_nb:
            self.open_topic[topic].add_message(new_message)
            self.check_topic(topic)
        else:
            self.put_dlq(new_message)

    def topic_exist(self, topic_num: int) -> bool:
        """Check if a given topic exist.

        :param topic_num: The id of the topic to check.

        :return: A boolean that tell if the topic exist.
        """
        return topic_num in self.open_topic.keys()

    def put_dlq(self, msg: UDPMessage) -> NoReturn:
        """Put a new message in the dead letter queue."""
        if type(msg) is UDPMessage:
            self.dead_letter_queue.append(msg)

    def process_dlq(self, new_topic: int) -> NoReturn:
        """Reprocess message if possible and delete outdated ones.

        :param new_topic: The last topic created.
        """
        new_topic_time: int = self.open_topic[new_topic].time_creation
        remaining_messages = []
        for msg in self.dead_letter_queue:
            if type(msg) is not UDPMessage:
                continue
            if int.from_bytes(msg.topic, 'little') in self.open_topic.keys():
                self.add_message(msg)
            elif int.from_bytes(msg.time_creation, 'little') >= new_topic_time:
                remaining_messages.append(remaining_messages)
        self.dead_letter_queue = remaining_messages

    def check_topic(self, topic_num) -> NoReturn:
        """Rebuild image and add it to the queue nd delete old topic if needed.

        :param topic_num: The topic to check.
        """
        keep_open = {}
        if self.open_topic[topic_num].all_msg_received():
            time_topic = self.open_topic[topic_num].time_creation
            new_img = (self.open_topic.pop(topic_num)).rebuild_img()
            if new_img is not None:
                self.img_queue.append(new_img)
            for topic_key in self.open_topic.keys():
                if self.open_topic[topic_key].time_creation >= time_topic:
                    keep_open[topic_key] = self.open_topic[topic_key]
            self.open_topic = keep_open

    def pull(self) -> np.array:
        """Returns the first image of img_queue if it is available.

        :return: The first image of the queue.
        """
        if self.in_waiting():
            return self.img_queue.pop(0)
