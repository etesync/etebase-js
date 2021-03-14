<p align="center">
  <img width="120" src="https://raw.githubusercontent.com/etesync/etesync-web/master/src/images/logo.svg" />
  <h1 align="center">Etebase - your end-to-end encrypted backend</h1>
</p>

The Etebase TypeScript client API for the web, node and react-native!


[![GitHub tag](https://img.shields.io/github/tag/etesync/etebase-js.svg)](https://github.com/etesync/etebase-js/tags)
[![NPM version](https://img.shields.io/npm/v/etebase.svg)](https://www.npmjs.com/package/etebase)
[![Build Status](https://travis-ci.com/etesync/etebase-js.svg?branch=master)](https://travis-ci.com/etesync/etebase-js)
[![Chat with us](https://img.shields.io/badge/chat-IRC%20|%20Matrix%20|%20Web-blue.svg)](https://www.etebase.com/community-chat/)

# What is it?

Etebase is an end-to-end encrypted backend as a service. Think Firebase,
but encrypted in a way that only your users can access their data.

Etebase makes it easy to build end-to-end encrypted applications by taking
care of the encryption and its related challenges. It is fully
[open-source](./LICENSE) (clients and server) so anyone can review,
audit or contribute to its development!

# Using Etebase in your project

This repository is the JavaScript/TypeScript library for communication with
an [Etebase server](https://github.com/etesync/server) (there also exists
libraries for Python, Java, Kotlin, C/C++ and Rust).
See https://docs.etebase.com/installation for details on how to install the
library and dependencies.

The following is a minimal example of how to change the Etebase password.

```typescript
import * as Etebase from 'etebase';
const etebase = await Etebase.Account.login("username", "password");
await etebase.changePassword("new password");
await etebase.logout();
```

There are more examples in the Guides section at https://docs.etebase.com/.

## Known issues

If you get build errors complaining about `export = URI;` from urijs then
you need to set `compilerOptions.allowSyntheticDefaultImports` to true in
`tsconfig.json`.

# Examples of projects that use Etebase

* [EteSync Notes](https://github.com/etesync/etesync-notes) - A secure,
  end-to-end encrypted, and privacy-respecting notes mobile application.
* [EteSync Web](https://github.com/etesync/etesync-web) - A secure,
  end-to-end encrypted, and privacy-respecting notes web frontend application.
* [EteSync DAV](https://github.com/etesync/etesync-dav) - Provides a local
  CalDAV and CardDAV server that acts as an EteSync compatibility layer/adapter
  for clients such as Thunderbird, Outlook and Apple Contacts to connect with
  EteSync.

# Building Etebase

```shell
git clone https://github.com/etesync/etebase-js
cd etebase-js
yarn install
yarn run build
```

Running tests requires a (test) [Etebase server](https://github.com/etesync/server)
running, defaulting to `http://localhost:8033`, but can be overridden with the
environment variable `ETEBASE_TEST_API_URL`.

```shell
cd ..
git clone https://github.com/etesync/server
cd server

... # Follow README.md install instructions
... # Build and start a server

cd ../etebase-js
env ETEBASE_TEST_API_URL=http://localhost:8033 yarn run test
```
## Known issues

Yarn is required for building this project, attempting to use npm will fail.
