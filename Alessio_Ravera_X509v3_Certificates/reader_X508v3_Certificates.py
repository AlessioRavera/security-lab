#!/usr/bin/env python3
import argparse
import os
from pyasn1_modules import pem, rfc2459
from pyasn1.type.univ import ObjectIdentifier
from Crypto.Hash import SHA as SHA1, SHA256, SHA384, SHA512
from pyasn1_modules.rfc2437 import RSAPublicKey, sha1WithRSAEncryption
from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder
from pyasn1_modules.rfc2459 import id_at_commonName as OID_COMMON_NAME, id_ce_keyUsage as OID_EXT_KEY_USAGE, KeyUsage

rsa_signing_algorithms = {
    sha1WithRSAEncryption: SHA1,  # defined in RFC 2437 (obsoleted by RFC 3447)
    ObjectIdentifier('1.2.840.113549.1.1.11'): SHA256,  # defined in RFC 3447
    ObjectIdentifier('1.2.840.113549.1.1.12'): SHA384,  # defined in RFC 3447
    ObjectIdentifier('1.2.840.113549.1.1.13'): SHA512}  # defined in RFC 3447

def find_key_usage(extensions):
    return next(e['extnValue'] for e in extensions if e['extnID'] == OID_EXT_KEY_USAGE)

def common_name(name):
    name = name.getComponent()
    for relative_distinguished_name in name:
        for attribute_type_and_value in relative_distinguished_name:
            oid = attribute_type_and_value['type']
            if oid == OID_COMMON_NAME:
                value = attribute_type_and_value['value']
    ds, rest = der_decoder.decode(value, asn1Spec=rfc2459.DirectoryString())
    return(ds.getComponent())

def can_be_used_for_signing_certificates(extensions):
    ku_ext = find_key_usage(extensions)
    ku, rest = der_decoder.decode(ku_ext, asn1Spec=KeyUsage())
    key_cert_bit = KeyUsage.namedValues.getValue('keyCertSign')
    try:
        return ku[key_cert_bit] == 1
    except Exception:
        return False

def from_bitstring_to_bytes(bs):
    i = int("".join(str(bit) for bit in bs), base=2)
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')

def get_rsa_public_key(tbs_cert):
    subject_pk = tbs_cert['subjectPublicKeyInfo']
    pk = from_bitstring_to_bytes(subject_pk['subjectPublicKey'])
    rsa_pk, rest = der_decoder.decode(pk, asn1Spec=RSAPublicKey())
    assert len(rest) == 0
    return rsa_pk['modulus'], rsa_pk['publicExponent']

def verify_cert(cert, key_store):
    tbs_cert = cert['tbsCertificate']
    print("\nVerifying certificate for", common_name(tbs_cert['subject']))
    issuer = common_name(tbs_cert['issuer'])
    subject = common_name(tbs_cert['subject'])
    signature_algo = cert['signatureAlgorithm']
    algo_oid = signature_algo['algorithm']
    rsa_signing_algorithm = rsa_signing_algorithms[algo_oid].new()
    sv = cert['signatureValue']
    signature_value = int("".join(str(bit) for bit in sv), base=2)
    rsa_signing_algorithm.update(der_encoder.encode(tbs_cert))
    digest_tbs_cert = rsa_signing_algorithm.hexdigest()
    try:
        signed_value = pow(signature_value, int(key_store[issuer][1]), int(key_store[issuer][0]))
    except Exception:
        print("Cannot verify the signature, import the \"" + issuer + "\" certificate")
        return

    sv = (hex(signed_value))
    if digest_tbs_cert in sv:
        if issuer == subject:
            print("Self-signed")
        else:
            print("Signed by",issuer)
    else:
        print("Certificate Has an Invalid Digital Signature")


def main():
    parser = argparse.ArgumentParser(description="Decode PEM encoded certificates")
    parser.add_argument("filenames", nargs="+", metavar="filename", type=str, help="Input files")
    args = parser.parse_args()
    CERT_DIR = 'example_certificates'
    key_store = {}
    certs = []
    for filename in args.filenames:
        print(filename)
        filename = os.path.join(CERT_DIR, filename)
        with open(filename) as f:
            binary_data = pem.readPemFromFile(f)
        cert, rest = der_decoder.decode(binary_data, asn1Spec=rfc2459.Certificate())
        certs.append(cert)
        tbs_cert = cert['tbsCertificate']
        issuer = common_name(tbs_cert['issuer'])
        subject = common_name(tbs_cert['subject'])
        notBefore = tbs_cert['validity']['notBefore'][0]
        notAfter = tbs_cert['validity']['notAfter'][0]
        extensions = tbs_cert['extensions']
        print('Issuer:', issuer)
        print('Subject:', subject)
        print('Validity: from')
        print('\tfrom:', notBefore.asDateTime.strftime("%d %B %Y"))
        print('\tto:', notAfter.asDateTime.strftime("%d %B %Y"))
        if can_be_used_for_signing_certificates(extensions):
            print("This key can be used to sign PK certificates")
            key_store[subject] = get_rsa_public_key(tbs_cert)
        print("_________________________________________")

    for cert in certs:
        verify_cert(cert, key_store)


if __name__ == "__main__":
    main()