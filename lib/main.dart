import 'package:elliptic/elliptic.dart';

// if working with PEM
import 'package:pem/pem.dart';
import 'package:ecdsa/ecdsa.dart';
import 'package:string_to_hex/string_to_hex.dart';

const String privateKeyFromBE = '''
    -----BEGIN PRIVATE KEY-----
    MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgVcB/UNPxalR9zDYAjQIf
    jojUDiQuGnSJrFEEzZPT/92hRANCAASc7UJtgnF/abqWM60T3XNJEzBv5ez9TdwK
    H0M6xpM2q+53wmsN/eYLdgtjgBd3DBmHtPilCkiFICXyaA8z9LkJ
    -----END PRIVATE KEY-----
  ''';

Future<void> main() async {
  // truyền vào đây otp
  eccEncrypt('0467');
}

void eccEncrypt(String text) {
  var privateKey = getPrivateKey();
  var pub = privateKey.publicKey;

  var hashHex = StringToHex.toHexString(text).replaceAll('0x', '');
  var hash = List<int>.generate(hashHex.length ~/ 2,
      (i) => int.parse(hashHex.substring(i * 2, i * 2 + 2), radix: 16));

  // test endcode data (data đã được mã hoá)
  var sigData = signature(privateKey, hash);
  print('sig: $sigData');

  // test decode data (kiểm tra chuỗi data đã mã hoá - test)
  var result = verify(pub, hash, sigData);
  print('result: $result');
}

PrivateKey getPrivateKey() {
  var ec = getP256();

  // working with PEM requires https://pub.dev/packages/pem
  // Parse PEM encoded private key.
  var rawPriv = PemCodec(PemLabel.privateKey).decode(privateKeyFromBE);
  // Parse PEM encoded public key.
  PrivateKey privateFromPEM = PrivateKey.fromBytes(ec, rawPriv);
  print('privateAliceFromPEM: 0x$privateFromPEM');

  return privateFromPEM;
}
