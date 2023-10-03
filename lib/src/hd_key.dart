import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:pinenacl/ed25519.dart';

import 'constants.dart';
import 'key_data.dart';

// Supported curve
const ED25519_HD_KEY = _ED25519HD();

/// Implementation of ED25519 private key derivation from master private key
class _ED25519HD {
  static final _pathRegex = RegExp(r"^(m\/)?(\d+'?\/)*\d+'?$");

  const _ED25519HD();

  KeyData derivePath(String path, List<int> seedBytes,
      {int offset = HARDENED_OFFSET}) {
    if (!_ED25519HD._pathRegex.hasMatch(path)) {
      throw ArgumentError(
          "Invalid derivation path. Expected BIP32 path format");
    }

    KeyData master = getMasterKeyFromSeed(seedBytes);

    List<String> segments = path.split('/');
    segments = segments.sublist(1);

    KeyData result = master;

    for (String segment in segments) {
      int index = int.parse(segment.substring(0, segment.length - 1));
      result = _getCKDPriv(result, index + offset);
    }

    return result;
  }

  KeyData getMasterKeyFromSeed(List<int> seedBytes,
          {String masterSecret = ED25519_CURVE}) =>
      _getKeys(seedBytes, utf8.encode(masterSecret));

  List<int> getPublicKey(List<int> privateKey, [bool withZeroByte = true]) {
    final signature = SigningKey.fromSeed(Uint8List.fromList(privateKey));
    final publicKey = signature.publicKey;

    if (withZeroByte == true) {
      List<int> dataBytes = List.filled(33, 0);
      dataBytes[0] = 0x00;
      dataBytes.setRange(1, 33, publicKey);
      return dataBytes;
    } else {
      return publicKey;
    }
  }

  KeyData _getCKDPriv(KeyData data, int index) {
    Uint8List dataBytes = Uint8List(37);
    dataBytes[0] = 0x00;
    dataBytes.setRange(1, 33, data.key);
    dataBytes.buffer.asByteData().setUint32(33, index);
    return _getKeys(dataBytes, data.chainCode);
  }

  KeyData _getKeys(List<int> data, List<int> keyParameter) {
    final hmac = Hmac(sha512, keyParameter);
    final mac = hmac.convert(data);

    final I = mac.bytes;
    final IL = I.sublist(0, 32);
    final IR = I.sublist(32);

    return KeyData(key: IL, chainCode: IR);
  }
}
