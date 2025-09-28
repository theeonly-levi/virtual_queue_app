# Virtual Queue App

MVP virtual clinic queue system featuring:
* Patient queue management (position tracking)
* In-app notification center
* Optional push notifications (Firebase Cloud Messaging)
* AI medication info assistant (guardrailed)
* Basic visit logging & extensible architecture

## Notifications Overview

The app now supports two channels:

1. Push Notifications (account registration events) via **Firebase Cloud Messaging (FCM)** using `pyfcm`.
2. In-App Notifications (queue position updates + a copy of registration) stored in-memory.
