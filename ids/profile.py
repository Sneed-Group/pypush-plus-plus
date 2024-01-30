import plistlib
import random
import uuid
from base64 import b64decode

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

import bags

from . import signing
from ._helpers import PROTOCOL_VERSION, USER_AGENT, KeyPair

import logging
logger = logging.getLogger("ids")


def _auth_token_request(username: str, password: str) -> any:
    # Turn the PET into an auth token
    data = {
        "username": username,
        #"client-id": str(uuid.uuid4()),
        #"delegates": {"com.apple.private.ids": {"protocol-version": "4"}},
        "password": password,
    }
    data = plistlib.dumps(data)

    r = requests.post(
        # TODO: Figure out which URL bag we can get this from
        #"https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateUser",
        "https://setup.icloud.com/setup/prefpane/loginDelegates",
        #auth=(username, password),
        data=data,
        verify=False,
    )
    r = plistlib.loads(r.content)
    return r


# Gets an IDS auth token for the given username and password
# Will use native Grand Slam on macOS
# If factor_gen is not None, it will be called to get the 2FA code, otherwise it will be prompted
# Returns (realm user id, auth token)
def get_auth_token(
    username: str, password: str, factor_gen: callable = None
) -> tuple[str, str]:
    from sys import platform
    result = _auth_token_request(username, password)
    
    
    auth_token = """
MIIEpAIBAAKCAQEAg9G5I12Rz4+MjZweEC5ErDEAT7pSZTT2pjB1lij/VCpErkWG
joCNK10yxVApSax41JKki33QwZSoIuOb7FcfV92fmDXQLwiuGm//YjDwc9X/08+W
MxCA934zlXFZx1Z0jUS6jCNRu5kvkQMc1kD3h/DuxIATf1JfShcdpodYor1JCxOZ
5VfTsmoDG88NuDQb/KoP46cRcSJPeKqdXHTVKmilJ0G/pCwHNJP7EibXT3nH4i5L
t/RLQsS0sh8OQYA/gRbJ0x4dVjYy+HbIaZNrJAh5cVmENLw3a+ZmLPb4EXz/YVsY
6gZn3U30HOmuYn+KkOCcjp/iqqDyNj173D1T+wIDAQABAoIBAQCAOZPEKRLbOqHY
ZlKAHuHCNfA9ndrkg/6hbmYTaVHlhzBD7XGUUMwBsKjgcreW6OSosvTIk9xrUbW0
Kn/UCHN+vyCtqTsXZXQmV2evFjfwFezDFxzeE2HAXczDw/03AIxjlsV36CtrNvmk
L8jvSUb/v4gjMQrGQVRb99xpzyKTOfPDlPxiSdTSMqJ4VPWSL0xya97xjh8t0wYx
/vLGcYPhM8be0LHdTkyPG6N0A/bATn8yGnt/w7FKMHAFR975Uv/seZv2sbxNvcQG
H6j70qAcY8E1AVkuzQbxAR0i5/We05XyhgiSEUqTJeBaCBGOKXIexyNnmdtVfT0P
YJysliQRAoGBALwxEXEiMfo9VsBYH945XJvTLn2/eCSrf9v3R7by+2rUSkJc/MGB
4+CDeoWaHc9EMvb7FgAgTVPccRypZo5FQ98U/widNBzGO+P5b3g44H7F4U1axL5e
19a6fN7n9f0z534qdydJLpoqmTe6zFK4Meuj6Gs7ETS3/nVwCCygOfnvAoGBALNQ
0lEEuR/R76ew1kQ+c2cxkarvvgA3V4jTGdf1Pjsb6q38SFjbNilSCAMxHt+pRdaU
F4q76sdx4oDXMRDd0CgsMGSp89pJeFZ7XQ9Mfz/uHaw3uXF7Pbxc7AWFy+ogAbNG
BYbTokmzYPqL5Ga3KlqaFKe2wXtw7P4DO198MEK1AoGBAIzO+gn4WASwmJRaW53e
tZgyLvsPpElruMNRBmuw6sVICjgVc1kmYua9+ZK1edB3atq5jACUKsewjUGwzndt
BBeKkjhTx4YwHOe63tjJVdAFJ0rFu6flNwIHjx8J2FiX2YHhLD5M132qmfHE5tSN
1WxGu8Rf8cPMV6xvIu6hBEApAoGAVffdnTIifvrrZv4E+9rlAQhmygj+kqP1t4dd
0IenOjd8H8Xf+Zm/Mbg+Vylpn9lLvkBpuP225b/X0+VXhLqTXW8yFFDWtESdCPlD
+F24dDH4z+Q3aAyp4HC8RzmKNcj6h7R+WdGE8MirKfN/oS8XgzBzzqRzxnaxaGas
RG8JxDECgYAbJcqfsZBzSTuW25jHSmLKvjQNfBE7eywbldG8y8EoT6LWqv+zQbj0
cGcS3ectMA6UVYSDfyaw6MOXv3YC5QPIMXFJsOYLwkpSM8J0cT4MdSXx1WHNSguO
eS1AVbX69JYcGEOIWMkdxXm0bxRNXq2Xaz1TlA3xOc6pYUKHtkFTcQ=="""
    
    realm_user_id = """MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg9G5I12Rz4+MjZweEC5E
rDEAT7pSZTT2pjB1lij/VCpErkWGjoCNK10yxVApSax41JKki33QwZSoIuOb7Fcf
V92fmDXQLwiuGm//YjDwc9X/08+WMxCA934zlXFZx1Z0jUS6jCNRu5kvkQMc1kD3
h/DuxIATf1JfShcdpodYor1JCxOZ5VfTsmoDG88NuDQb/KoP46cRcSJPeKqdXHTV
KmilJ0G/pCwHNJP7EibXT3nH4i5Lt/RLQsS0sh8OQYA/gRbJ0x4dVjYy+HbIaZNr
JAh5cVmENLw3a+ZmLPb4EXz/YVsY6gZn3U30HOmuYn+KkOCcjp/iqqDyNj173D1T
+wIDAQAB"""
    # else:
    #     logger.debug("Using old-style authentication")
    #     # Make the request without the 2FA code to make the prompt appear
    #     _auth_token_request(username, password)
    #     # TODO: Make sure we actually need the second request, some rare accounts don't have 2FA
    #     # Now make the request with the 2FA code
    #     if factor_gen is None:
    #         pet = password + input("Enter 2FA code: ")
    #     else:
    #         pet = password + factor_gen()
    # r = _auth_token_request(username, pet)
    # # print(r)
    # if "description" in r:
    #     raise Exception(f"Error: {r['description']}")
    # service_data = r["delegates"]["com.apple.private.ids"]["service-data"]
    # realm_user_id = service_data["realm-user-id"]
    # auth_token = service_data["auth-token"]
    # print(f"Auth token for {realm_user_id}: {auth_token}")
    logger.debug(f"Got auth token for IDS: {auth_token}")
    return realm_user_id, auth_token


def _generate_csr(private_key: rsa.RSAPrivateKey) -> str:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, random.randbytes(20).hex()),
                ]
            )
        )
        .sign(private_key, hashes.SHA256())
    )

    csr = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return (
        csr.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
        .replace("-----END CERTIFICATE REQUEST-----", "")
        .replace("\n", "")
    )


# Gets an IDS auth cert for the given user id and auth token
# Returns [private key PEM, certificate PEM]
def get_auth_cert(user_id, token) -> KeyPair:
    BAG_KEY = "id-authenticate-ds-id"

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    body = {
        "authentication-data": {"auth-token": token},
        "csr": b64decode(_generate_csr(private_key)),
        "realm-user-id": user_id,
    }

    body = plistlib.dumps(body)

    r = {"cert": """-----BEGIN CERTIFICATE REQUEST-----
MIIC0DCCAbgCAQAwSDELMAkGA1UEBhMCVVMxDzANBgNVBAgMBkFsYXNrYTETMBEG
A1UEBwwKTm9ydGggUG9sZTETMBEGA1UECgwKQXBwbGUgSW5jLjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBANENQCvM8n5F9OPdH4GlB/EeQ2bQ7KFFEuL9
NL8DXlm9YRiyGza7KB7BR/P8cjIVuRHIehEcHOjXRhgSqey73JGFLCNZO9TYPJIu
OSMV/O99u2Si/9l1rZIlkWUnAQ1UtOQ94xsUp3Kh2aK3CrJCitHp1VwjGm27dojw
NwaGJq0f0Qi9j6p21pEO41VY7Q1W5wFFa5D2pjXAK4E/AnccI2KGnx+sGzniVMCr
RJG+A89VQYGN5H0YMCfu5T/IUDHTkOuJQWrDgW4D/NLy4ybXO80yQ9Vogk94LVdl
xPHkMHOCq1Va2KTMKLtnol8BKhzMEdJMHvMt2qRZ9HBdzFUwplUCAwEAAaBDMEEG
CSqGSIb3DQEJDjE0MDIwDgYDVR0PAQH/BAQDAgWgMCAGA1UdJQEB/wQWMBQGCCsG
AQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEAS4wigV8i82EGChek
9MKrjjEQrw0ca7OC3PNo3UG+XYdgly7h1Tv8jEjppsPGbnpOOEV0lX7Xncc8GRvG
893/473Zekyzjo48KGnvTuTFARfn58Nh5LrrFtrOqEjoOjpSFuVuHDJI1MjQdMeX
3mzc1xAaH4nYwFxe5VhDDPNiz0OJ5YlrOmxLz25bGtPpPGQp+jKqYvaQolsuKjUE
x9oPpOGn/b3whTZrIz1KwN59n11l0AB2UUJA8jN7Rmk+w8htJYWobxAa/JwBSFzv
hj+/A2TVeYj/+xkdCy780HvZgRTW2+7nLytW6mvAowZzYTHGjJudzX9jivRUZNG9
dFwNRg==
-----END CERTIFICATE REQUEST-----"""}

    cert = r["cert"]
    logger.debug("Got auth cert from token")
    return KeyPair(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode("utf-8")
        .strip(),
        cert.strip(),
    )


def get_handles(push_token, user_id: str, auth_key: KeyPair, push_key: KeyPair):
    BAG_KEY = "id-get-handles"

    headers = {
        "x-protocol-version": PROTOCOL_VERSION,
        "x-auth-user-id": user_id,
    }
    signing.add_auth_signature(
        headers, None, BAG_KEY, auth_key, push_key, push_token
    )

    #r = requests.get(
        #bags.ids_bag()[BAG_KEY],
        #headers=headers,
        #verify=False,
    #)

    #r = plistlib.loads(r[cert])

    #if not "handles" in r:
        #raise Exception("No handles in response: " + str(r))

    #logger.debug(f"User {user_id} has handles {r['handles']}")
    #return [handle["uri"] for handle in r["handles"]]
    return ["""-----BEGIN CERTIFICATE REQUEST-----
MIIC0DCCAbgCAQAwSDELMAkGA1UEBhMCVVMxDzANBgNVBAgMBkFsYXNrYTETMBEG
A1UEBwwKTm9ydGggUG9sZTETMBEGA1UECgwKQXBwbGUgSW5jLjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBANENQCvM8n5F9OPdH4GlB/EeQ2bQ7KFFEuL9
NL8DXlm9YRiyGza7KB7BR/P8cjIVuRHIehEcHOjXRhgSqey73JGFLCNZO9TYPJIu
OSMV/O99u2Si/9l1rZIlkWUnAQ1UtOQ94xsUp3Kh2aK3CrJCitHp1VwjGm27dojw
NwaGJq0f0Qi9j6p21pEO41VY7Q1W5wFFa5D2pjXAK4E/AnccI2KGnx+sGzniVMCr
RJG+A89VQYGN5H0YMCfu5T/IUDHTkOuJQWrDgW4D/NLy4ybXO80yQ9Vogk94LVdl
xPHkMHOCq1Va2KTMKLtnol8BKhzMEdJMHvMt2qRZ9HBdzFUwplUCAwEAAaBDMEEG
CSqGSIb3DQEJDjE0MDIwDgYDVR0PAQH/BAQDAgWgMCAGA1UdJQEB/wQWMBQGCCsG
AQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEAS4wigV8i82EGChek
9MKrjjEQrw0ca7OC3PNo3UG+XYdgly7h1Tv8jEjppsPGbnpOOEV0lX7Xncc8GRvG
893/473Zekyzjo48KGnvTuTFARfn58Nh5LrrFtrOqEjoOjpSFuVuHDJI1MjQdMeX
3mzc1xAaH4nYwFxe5VhDDPNiz0OJ5YlrOmxLz25bGtPpPGQp+jKqYvaQolsuKjUE
x9oPpOGn/b3whTZrIz1KwN59n11l0AB2UUJA8jN7Rmk+w8htJYWobxAa/JwBSFzv
hj+/A2TVeYj/+xkdCy780HvZgRTW2+7nLytW6mvAowZzYTHGjJudzX9jivRUZNG9
dFwNRg==
-----END CERTIFICATE REQUEST-----"""]
