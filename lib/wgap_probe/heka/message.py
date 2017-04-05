import os
import socket
import time
import uuid as uuidlib
import collections


from .message_pb2 import Field, Message as ProtobufMessage
from . import severity as severity_levels


# Envelope version, only changes when the message format changes.
ENV_VERSION = '0.8'


def _set_field_type_and_return_list(field, value):
    """
    Set the type on the protobuf field and return the resulting list.

    """
    if value is None:
        raise ValueError("None is not allowed for field values.  [%s]" % field.name)

    elif isinstance(value, int):
        field.value_type = Field.INTEGER
        field_list = field.value_integer

    elif isinstance(value, float):
        field.value_type = Field.DOUBLE
        field_list = field.value_double

    elif isinstance(value, bool):
        field.value_type = Field.BOOL
        field_list = field.value_bool

    elif isinstance(value, (str,bytes)):
        field.value_type = Field.STRING
        field_list = field.value_string

    else:
        raise ValueError("Unexpected value type : [%s][%s]" % (type(value), value))

    return field_list


def _flatten_fields(msg, field_map, prefix=None):
    for k, v in field_map.items():
        field = msg.fields.add()

        if prefix:
            full_name = "%s.%s" % (prefix, k)
        else:
            full_name = k

        field.name = full_name
        field.representation = ""

        if isinstance(v, collections.Mapping):
            msg.fields.remove(field)
            _flatten_fields(msg, v, prefix=full_name)

        elif isinstance(v, collections.Iterable) and not isinstance(v, (str,bytes)):
            values = iter(v)
            try:
                first_value = next(values)
            except StopIteration:
                first_value = None

            field_list = _set_field_type_and_return_list(field, first_value)
            field_list.append(first_value)

            for value in values:
                if not isinstance(value, type(first_value)):
                    raise ValueError("Multiple values in the same field cannot be of different types.  [%s]" % field.name)
                field_list.append(value)
        else:
            field_list = _set_field_type_and_return_list(field, v)
            field_list.append(v)


_FIELD_TYPE_TO_ATTRIBUTE = {
    Field.INTEGER: 'value_integer',
    Field.DOUBLE: 'value_double',
    Field.BOOL: 'value_bool',
    Field.STRING: 'value_string',
}


def _get_value_from_field(field):
    attr_name = _FIELD_TYPE_TO_ATTRIBUTE[field.value_type]
    return getattr(field, attr_name)


class Message(object):
    def __init__(
        self,
        type='',
        logger='',
        severity=severity_levels.DEBUG,
        fields=None,
        payload='',

        env_version=ENV_VERSION,
        pid=None,
        hostname=None,
        timestamp=None,
        uuid=None,
    ):
        if pid is None:
            pid = os.getpid()

        if hostname is None:
            hostname = socket.gethostname()

        if timestamp is None:
            timestamp = time.time()*10e9

        if fields is None:
            fields = {}

        protobuf_message = ProtobufMessage(
            timestamp=timestamp,
            type=type,
            logger=logger,
            severity=severity,
            payload=payload,
            env_version=ENV_VERSION,
            pid=pid,
            hostname=hostname,
        )

        _flatten_fields(protobuf_message, fields)

        # Calculate UUID if needed and add to protobuf
        if uuid is None:
            uuid = uuidlib.uuid5(
                uuidlib.NAMESPACE_OID,
                str(protobuf_message)
            ).bytes

        protobuf_message.uuid = uuid

        self.protobuf_message = protobuf_message

    @classmethod
    def decode(cls, bytes):
        protobuf_message = ProtobufMessage()
        protobuf_message.ParseFromString(bytes)

        message = cls()
        message.protobuf_message = protobuf_message
        return message

    def encode(self):
        return self.protobuf_message.SerializeToString()

    #
    # Proxy methods for underlying protobuf
    #

    @property
    def type(self):
        return self.protobuf_message.type

    @type.setter
    def type(self, value):
        self.protobuf_message.type = value

    @property
    def logger(self):
        return self.protobuf_message.logger

    @logger.setter
    def logger(self, value):
        self.protobuf_message.logger = value

    @property
    def severity(self):
        return self.protobuf_message.severity

    @severity.setter
    def severity(self, value):
        self.protobuf_message.severity = value

    @property
    def payload(self):
        return self.protobuf_message.payload

    @payload.setter
    def payload(self, value):
        self.protobuf_message.payload = value

    @property
    def pid(self):
        return self.protobuf_message.pid

    @pid.setter
    def pid(self, value):
        self.protobuf_message.pid = value

    @property
    def hostname(self):
        return self.protobuf_message.hostname

    @hostname.setter
    def hostname(self, value):
        self.protobuf_message.hostname = value

    @property
    def timestamp(self):
        return self.protobuf_message.timestamp

    @timestamp.setter
    def timestamp(self, value):
        self.protobuf_message.timestamp = value

    @property
    def uuid(self):
        return self.protobuf_message.uuid

    @uuid.setter
    def uuid(self, value):
        self.protobuf_message.uuid = value

    @property
    def fields(self):
        return {
            field.name: _get_value_from_field(field)
            for field in self.protobuf_message.fields
        }
