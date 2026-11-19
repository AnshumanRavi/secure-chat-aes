"""
The server's input validation: every malformed request gets a clear ERROR code, nothing
is forwarded, and the connection stays usable (a bad request is not an attack).
"""

import uuid

import pytest

from common.protocol import MsgType
from tests.test_files import user

VALID_ID = "a" * 32
SHA = "0" * 64


def file_start(**overrides):
    message = {"type": MsgType.FILE_START, "id": uuid.uuid4().hex, "to": "{peer}", "name": "a.pdf",
               "size": 10, "chunks": 1, "sha256": SHA, "kind": "document"}
    message.update(overrides)
    return message


CASES = [
    # (description, message, expected error code)
    ("chat without id", {"type": MsgType.CHAT_MSG, "to": "{peer}", "text": "hi"}, "BAD_MESSAGE"),
    ("chat id too long", {"type": MsgType.CHAT_MSG, "id": "x" * 65, "to": "{peer}", "text": "hi"}, "BAD_MESSAGE"),
    ("empty chat text", {"type": MsgType.CHAT_MSG, "id": VALID_ID, "to": "{peer}", "text": ""}, "BAD_MESSAGE"),
    ("chat text too long", {"type": MsgType.CHAT_MSG, "id": VALID_ID, "to": "{peer}", "text": "x" * 10_001},
     "BAD_MESSAGE"),
    ("chat text not a string", {"type": MsgType.CHAT_MSG, "id": VALID_ID, "to": "{peer}", "text": ["hi"]},
     "BAD_MESSAGE"),
    ("bad e2e body", {"type": MsgType.CHAT_MSG, "id": VALID_ID, "to": "{peer}", "e2e": {"ct": 5}}, "BAD_MESSAGE"),
    ("e2e body too large", {"type": MsgType.CHAT_MSG, "id": VALID_ID, "to": "{peer}",
                            "e2e": {"ct": "A" * (48 * 1024 + 1)}}, "BAD_MESSAGE"),
    ("unknown recipient", {"type": MsgType.CHAT_MSG, "id": VALID_ID, "to": "no_such_user", "text": "hi"},
     "UNKNOWN_USER"),
    ("read without ids", {"type": MsgType.READ, "to": "{peer}"}, "BAD_MESSAGE"),
    ("read with too many ids", {"type": MsgType.READ, "to": "{peer}", "ids": ["x"] * 501}, "BAD_MESSAGE"),
    ("read in a foreign group", {"type": MsgType.READ, "to": "{peer}", "ids": ["x"], "group_id": "nope"},
     "NOT_A_MEMBER"),
    ("group without name", {"type": MsgType.CREATE_GROUP, "name": " ", "members": ["{peer}"]}, "BAD_GROUP"),
    ("group name too long", {"type": MsgType.CREATE_GROUP, "name": "x" * 41, "members": ["{peer}"]}, "BAD_GROUP"),
    ("group description too long", {"type": MsgType.CREATE_GROUP, "name": "G", "description": "x" * 201,
                                    "members": ["{peer}"]}, "BAD_GROUP"),
    ("group members not a list", {"type": MsgType.CREATE_GROUP, "name": "G", "members": "{peer}"}, "BAD_GROUP"),
    ("group with only me", {"type": MsgType.CREATE_GROUP, "name": "G", "members": ["{me}"]}, "BAD_GROUP"),
    ("group with too many members", {"type": MsgType.CREATE_GROUP, "name": "G",
                                     "members": [f"user{i}" for i in range(50)]}, "BAD_GROUP"),
    ("group with unknown member", {"type": MsgType.CREATE_GROUP, "name": "G", "members": ["ghost_member"]},
     "UNKNOWN_USER"),
    ("group message without id", {"type": MsgType.GROUP_MSG, "group_id": "g", "text": "hi"}, "BAD_MESSAGE"),
    ("group message without text", {"type": MsgType.GROUP_MSG, "id": VALID_ID, "group_id": "g"}, "BAD_MESSAGE"),
    ("leave a group I'm not in", {"type": MsgType.LEAVE_GROUP, "group_id": "nope"}, "NOT_A_MEMBER"),
    ("identity key not a string", {"type": MsgType.PUBLISH_KEY, "public_key": 42}, "BAD_KEY"),
    ("identity key is not P-256", {"type": MsgType.PUBLISH_KEY, "public_key": "-----BEGIN JUNK-----"}, "BAD_KEY"),
    ("empty display name", {"type": MsgType.UPDATE_PROFILE, "display_name": "  "}, "BAD_PROFILE"),
    ("display name too long", {"type": MsgType.UPDATE_PROFILE, "display_name": "x" * 31}, "BAD_PROFILE"),
    ("about too long", {"type": MsgType.UPDATE_PROFILE, "about": "x" * 141}, "BAD_PROFILE"),
    ("file without id", file_start(id=None), "BAD_MESSAGE"),
    ("file without name", file_start(name=""), "FILE_REJECTED"),
    ("file too large", file_start(size=26 * 1024 * 1024, chunks=416), "FILE_REJECTED"),
    ("file chunk count wrong", file_start(chunks=7), "FILE_REJECTED"),
    ("file without hash", file_start(sha256="xyz"), "FILE_REJECTED"),
    ("file kind unknown", file_start(kind="exe"), "FILE_REJECTED"),
    ("file thumbnail too big", file_start(thumb="A" * (96 * 1024 + 1)), "FILE_REJECTED"),
    ("file to unknown user", file_start(to="ghost_user"), "UNKNOWN_USER"),
    ("file to a foreign group", file_start(to=None, group_id="nope"), "NOT_A_MEMBER"),
    ("chunk of unknown transfer", {"type": MsgType.FILE_CHUNK, "id": "nope", "index": 0, "data": ""},
     "FILE_REJECTED"),
    ("end of unknown transfer", {"type": MsgType.FILE_END, "id": "nope"}, "FILE_REJECTED"),
    ("server-only message type", {"type": MsgType.AUTH_OK}, "UNSUPPORTED"),
]


@pytest.fixture(scope="module")
def pair(server, tmp_path_factory):
    folder = tmp_path_factory.mktemp("validation")
    me, my_events = user(server, folder)
    peer, peer_events = user(server, folder)
    yield me, my_events, peer, peer_events
    me.logout()
    peer.logout()


def fill(value, me, peer):
    if isinstance(value, str):
        return value.replace("{me}", me).replace("{peer}", peer)
    if isinstance(value, list):
        return [fill(v, me, peer) for v in value]
    return value


@pytest.mark.parametrize("description, message, code", CASES, ids=[c[0] for c in CASES])
def test_malformed_request_is_rejected(pair, description, message, code):
    me, my_events, peer, peer_events = pair
    request = {k: fill(v, me.username, peer.username) for k, v in message.items() if v is not None}
    me._send(request)
    assert my_events.wait("error")["code"] == code
    me.ping()                                       # still connected and served
    assert me.connected


def test_nothing_reached_the_peer(pair):
    _, _, peer, peer_events = pair
    for event in ("message", "group", "file_incoming"):
        with pytest.raises(AssertionError):
            peer_events.wait(event, timeout=0.2)
