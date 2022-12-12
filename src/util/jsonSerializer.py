import json


def json_serializer(kafka_message):
    return json.dumps(kafka_message, ensure_ascii=False).encode("utf-8")


def json_deserializer(kafka_message):
    return json.loads(kafka_message.decode("utf-8"))
