"""A notification service that records what it is asked to show, and
answers like a user would when a test says so.

usage: fake-notifications LOG

Owns org.freedesktop.Notifications on the session bus and appends one line
per call to LOG: "notify ID SUMMARY | BODY", "actions ID KEY=LABEL ..." for
a notification with buttons, and "close ID". LOG.hints gets a line per
notification shown: "ID transient" for one that asks not to be kept once
its bubble is gone, else "ID kept". A notification that replaces
one that is still there keeps its ID; replacing one that was closed makes a
new one.

A test presses a button of the notification shown last by writing its key
to LOG.press, and closes that notification like a user by creating
LOG.dismiss. A pressed button closes its notification, as services do for
one that isn't resident: ActionInvoked, and NotificationClosed right after
it. While LOG.closes-first exists, the two come the other way around.
"""

import asyncio
import os
import sys

from dbus_next.aio import MessageBus
from dbus_next.service import ServiceInterface, method, signal

DISMISSED_BY_USER = 2
CLOSED_BY_CALL = 3


class Notifications(ServiceInterface):
    def __init__(self, log):
        super().__init__("org.freedesktop.Notifications")
        self.log = log
        self.last_id = 0
        self.shown = 0
        # The notifications that are there: shown, and not closed.
        self.open = set()

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
        if replaces_id in self.open:
            number = replaces_id
        else:
            self.last_id += 1
            number = self.last_id
        self.open.add(number)
        self.shown = number
        self.record(f"notify {number} {summary} | {body}")
        transient = "transient" in hints and hints["transient"].value
        with open(self.log + ".hints", "a") as file:
            file.write(f"{number} {'transient' if transient else 'kept'}\n")
        if actions:
            pairs = zip(actions[::2], actions[1::2])
            buttons = " ".join(f"{key}={label}" for key, label in pairs)
            self.record(f"actions {number} {buttons}")
        return number

    @method()
    def CloseNotification(self, notification_id: "u"):
        self.record(f"close {notification_id}")
        if notification_id in self.open:
            self.open.discard(notification_id)
            self.NotificationClosed(notification_id, CLOSED_BY_CALL)

    @method()
    def GetCapabilities(self) -> "as":
        return ["actions", "body"]

    @method()
    def GetServerInformation(self) -> "ssss":
        return ["fake-notifications", "skagent", "1", "1.2"]

    @signal()
    def ActionInvoked(self, notification_id: "u", action_key: "s") -> "us":
        return [notification_id, action_key]

    @signal()
    def NotificationClosed(self, notification_id: "u", reason: "u") -> "uu":
        return [notification_id, reason]


async def user(notifications):
    """Does what the test's files say with the notification shown last."""
    press = notifications.log + ".press"
    dismiss = notifications.log + ".dismiss"
    closes_first = notifications.log + ".closes-first"
    while True:
        await asyncio.sleep(0.05)
        if os.path.exists(press):
            with open(press) as file:
                key = file.read().strip()
            os.remove(press)
            number = notifications.shown
            notifications.record(f"pressed {number} {key}")
            notifications.open.discard(number)
            if os.path.exists(closes_first):
                notifications.NotificationClosed(number, DISMISSED_BY_USER)
                notifications.ActionInvoked(number, key)
            else:
                notifications.ActionInvoked(number, key)
                notifications.NotificationClosed(number, DISMISSED_BY_USER)
        if os.path.exists(dismiss):
            os.remove(dismiss)
            number = notifications.shown
            notifications.record(f"dismissed {number}")
            notifications.open.discard(number)
            notifications.NotificationClosed(number, DISMISSED_BY_USER)


async def main():
    bus = await MessageBus().connect()
    notifications = Notifications(sys.argv[1])
    bus.export("/org/freedesktop/Notifications", notifications)
    await bus.request_name("org.freedesktop.Notifications")
    await asyncio.gather(bus.wait_for_disconnect(), user(notifications))


asyncio.run(main())
