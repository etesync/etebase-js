export * from "etebase";

import "react-native-get-random-values";
import RnSodium from "react-native-sodium";

import { _setRnSodium } from "etebase";

_setRnSodium(RnSodium);
