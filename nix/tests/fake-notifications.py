"""A notification service that records what it is asked to show.

usage: fake-notifications LOG

Owns org.freedesktop.Notifications on the session bus and appends one line
per call to LOG: "notify ID SUMMARY | BODY" and "close ID".
"""

import asyncio
import sys

from dbus_next.aio import MessageBus
from dbus_next.service import ServiceInterface, method


class Notifications(ServiceInterface):
    def __init__(self, log):
        super().__init__("org.freedesktop.Notifications")
        self.log = log
        self.last_id = 0

    def record(self, line):
        with open(self.log, "a") as log:
            log.write(line + "\n")

    # dbus-next reads D-Bus signatures from the annotations.
    @method()
    def Notify(
        self,
        app_name: "s",
        replaces_id: "u",
        app_icon: "s",
        summary: "s",
        body: "s",
        actions: "as",
        hints: "a{sv}",
        expire_timeout: "i",
    ) -> "u":
        self.last_id += 1
        self.record(f"notify {self.last_id} {summary} | {body}")
        return self.last_id

    @method()
    def CloseNotification(self, notification_id: "u"):
        self.record(f"close {notification_id}")

    @method()
    def GetCapabilities(self) -> "as":
        return ["body"]

    @method()
    def GetServerInformation(self) -> "ssss":
        return ["fake-notifications", "skagent", "1", "1.2"]


async def main():
    bus = await MessageBus().connect()
    bus.export("/org/freedesktop/Notifications", Notifications(sys.argv[1]))
    await bus.request_name("org.freedesktop.Notifications")
    await bus.wait_for_disconnect()


asyncio.run(main())
