import time
import os
import io

from logging import debug

from .base import Enum8, Enum16, Decode, Encode, Read, Struct

def bytes_or_json(v):
    if hasattr(v, 'to_json'):
        return v.to_json()
    else:
        return ['hex', ''.join('{0:02x}'.format(x) for x in bytes(v))]

class ProtocolVersion(Enum16):
    SSLv2 = 0x0200
    SSLv3 = 0x0300
    TLSv1_0 = 0x0301
    TLSv1_1 = 0x0302
    TLSv1_2 = 0x0303
    MAX = 0xffff

    _Highest = TLSv1_2

class CipherSuite(Enum16):
    TLS_NULL_WITH_NULL_NULL = 0x0000
    TLS_RSA_WITH_NULL_MD5 = 0x0001
    TLS_RSA_WITH_NULL_SHA = 0x0002
    TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003
    TLS_RSA_WITH_RC4_128_MD5 = 0x0004
    TLS_RSA_WITH_RC4_128_SHA = 0x0005
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 0x0006
    TLS_RSA_WITH_IDEA_CBC_SHA = 0x0007
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0008
    TLS_RSA_WITH_DES_CBC_SHA = 0x0009
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x000B
    TLS_DH_DSS_WITH_DES_CBC_SHA = 0x000C
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x000D
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x000E
    TLS_DH_RSA_WITH_DES_CBC_SHA = 0x000F
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x0011
    TLS_DHE_DSS_WITH_DES_CBC_SHA = 0x0012
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0014
    TLS_DHE_RSA_WITH_DES_CBC_SHA = 0x0015
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = 0x0017
    TLS_DH_anon_WITH_RC4_128_MD5 = 0x0018
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = 0x0019
    TLS_DH_anon_WITH_DES_CBC_SHA = 0x001A
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = 0x001B
    SSL_FORTEZZA_KEA_WITH_NULL_SHA = 0x001C
    SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA = 0x001D
    TLS_KRB5_WITH_DES_CBC_SHA_or_SSL_FORTEZZA_KEA_WITH_RC4_128_SHA  =  0x001E
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA = 0x001F
    TLS_KRB5_WITH_RC4_128_SHA = 0x0020
    TLS_KRB5_WITH_IDEA_CBC_SHA = 0x0021
    TLS_KRB5_WITH_DES_CBC_MD5 = 0x0022
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = 0x0023
    TLS_KRB5_WITH_RC4_128_MD5 = 0x0024
    TLS_KRB5_WITH_IDEA_CBC_MD5 = 0x0025
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = 0x0026
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = 0x0027
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA = 0x0028
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = 0x0029
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = 0x002A
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = 0x002B
    TLS_PSK_WITH_NULL_SHA = 0x002C
    TLS_DHE_PSK_WITH_NULL_SHA = 0x002D
    TLS_RSA_PSK_WITH_NULL_SHA = 0x002E
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F
    TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0x0030
    TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x0031
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033
    TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x0034
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
    TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0x0036
    TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x0037
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039
    TLS_DH_anon_WITH_AES_256_CBC_SHA = 0x003A
    TLS_RSA_WITH_NULL_SHA256 = 0x003B
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = 0x003E
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x003F
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x0040
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0041
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x0042
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0043
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x0044
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0045
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA = 0x0046
    TLS_ECDH_ECDSA_WITH_NULL_SHA_draft = 0x0047
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA_draft = 0x0048
    TLS_ECDH_ECDSA_WITH_DES_CBC_SHA_draft = 0x0049
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA_draft = 0x004A
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA_draft = 0x004B
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA_draft = 0x004C
    TLS_ECDH_ECNRA_WITH_DES_CBC_SHA_draft = 0x004D
    TLS_ECDH_ECNRA_WITH_3DES_EDE_CBC_SHA_draft = 0x004E
    TLS_ECMQV_ECDSA_NULL_SHA_draft = 0x004F
    TLS_ECMQV_ECDSA_WITH_RC4_128_SHA_draft = 0x0050
    TLS_ECMQV_ECDSA_WITH_DES_CBC_SHA_draft = 0x0051
    TLS_ECMQV_ECDSA_WITH_3DES_EDE_CBC_SHA_draft = 0x0052
    TLS_ECMQV_ECNRA_NULL_SHA_draft = 0x0053
    TLS_ECMQV_ECNRA_WITH_RC4_128_SHA_draft = 0x0054
    TLS_ECMQV_ECNRA_WITH_DES_CBC_SHA_draft = 0x0055
    TLS_ECMQV_ECNRA_WITH_3DES_EDE_CBC_SHA_draft = 0x0056
    TLS_ECDH_anon_NULL_WITH_SHA_draft = 0x0057
    TLS_ECDH_anon_WITH_RC4_128_SHA_draft = 0x0058
    TLS_ECDH_anon_WITH_DES_CBC_SHA_draft = 0x0059
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA_draft = 0x005A
    TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA_draft = 0x005B
    TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA_draft = 0x005C
    TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 = 0x0060
    TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 = 0x0061
    TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA = 0x0062
    TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = 0x0063
    TLS_RSA_EXPORT1024_WITH_RC4_56_SHA = 0x0064
    TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA = 0x0065
    TLS_DHE_DSS_WITH_RC4_128_SHA = 0x0066
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = 0x0068
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x0069
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x006A
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B
    TLS_DH_anon_WITH_AES_128_CBC_SHA256 = 0x006C
    TLS_DH_anon_WITH_AES_256_CBC_SHA256 = 0x006D
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD = 0x0072
    TLS_DHE_DSS_WITH_AES_128_CBC_RMD = 0x0073
    TLS_DHE_DSS_WITH_AES_256_CBC_RMD = 0x0074
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD = 0x0077
    TLS_DHE_RSA_WITH_AES_128_CBC_RMD = 0x0078
    TLS_DHE_RSA_WITH_AES_256_CBC_RMD = 0x0079
    TLS_RSA_WITH_3DES_EDE_CBC_RMD = 0x007C
    TLS_RSA_WITH_AES_128_CBC_RMD = 0x007D
    TLS_RSA_WITH_AES_256_CBC_RMD = 0x007E
    TLS_GOSTR341094_WITH_28147_CNT_IMIT = 0x0080
    TLS_GOSTR341001_WITH_28147_CNT_IMIT = 0x0081
    TLS_GOSTR341094_WITH_NULL_GOSTR3411 = 0x0082
    TLS_GOSTR341001_WITH_NULL_GOSTR3411 = 0x0083
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0084
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0085
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0086
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0087
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0088
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA = 0x0089
    TLS_PSK_WITH_RC4_128_SHA = 0x008A
    TLS_PSK_WITH_3DES_EDE_CBC_SHA = 0x008B
    TLS_PSK_WITH_AES_128_CBC_SHA = 0x008C
    TLS_PSK_WITH_AES_256_CBC_SHA = 0x008D
    TLS_DHE_PSK_WITH_RC4_128_SHA = 0x008E
    TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = 0x008F
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA = 0x0090
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA = 0x0091
    TLS_RSA_PSK_WITH_RC4_128_SHA = 0x0092
    TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = 0x0093
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA = 0x0094
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA = 0x0095
    TLS_RSA_WITH_SEED_CBC_SHA = 0x0096
    TLS_DH_DSS_WITH_SEED_CBC_SHA = 0x0097
    TLS_DH_RSA_WITH_SEED_CBC_SHA = 0x0098
    TLS_DHE_DSS_WITH_SEED_CBC_SHA = 0x0099
    TLS_DHE_RSA_WITH_SEED_CBC_SHA = 0x009A
    TLS_DH_anon_WITH_SEED_CBC_SHA = 0x009B
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009F
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = 0x00A0
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = 0x00A1
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = 0x00A2
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = 0x00A3
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = 0x00A4
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = 0x00A5
    TLS_DH_anon_WITH_AES_128_GCM_SHA256 = 0x00A6
    TLS_DH_anon_WITH_AES_256_GCM_SHA384 = 0x00A7
    TLS_PSK_WITH_AES_128_GCM_SHA256 = 0x00A8
    TLS_PSK_WITH_AES_256_GCM_SHA384 = 0x00A9
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = 0x00AA
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = 0x00AB
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = 0x00AC
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = 0x00AD
    TLS_PSK_WITH_AES_128_CBC_SHA256 = 0x00AE
    TLS_PSK_WITH_AES_256_CBC_SHA384 = 0x00AF
    TLS_PSK_WITH_NULL_SHA256 = 0x00B0
    TLS_PSK_WITH_NULL_SHA384 = 0x00B1
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = 0x00B2
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = 0x00B3
    TLS_DHE_PSK_WITH_NULL_SHA256 = 0x00B4
    TLS_DHE_PSK_WITH_NULL_SHA384 = 0x00B5
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = 0x00B6
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = 0x00B7
    TLS_RSA_PSK_WITH_NULL_SHA256 = 0x00B8
    TLS_RSA_PSK_WITH_NULL_SHA384 = 0x00B9
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BA
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BB
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BC
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BD
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BE
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BF
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C0
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C1
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C2
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C3
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C4
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C5
    TLS_ECDH_ECDSA_WITH_NULL_SHA = 0xC001
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 0xC002
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC003
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xC004
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xC005
    TLS_ECDHE_ECDSA_WITH_NULL_SHA = 0xC006
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xC007
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC008
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A
    TLS_ECDH_RSA_WITH_NULL_SHA = 0xC00B
    TLS_ECDH_RSA_WITH_RC4_128_SHA = 0xC00C
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 0xC00D
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xC00E
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xC00F
    TLS_ECDHE_RSA_WITH_NULL_SHA = 0xC010
    TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xC011
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xC012
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014
    TLS_ECDH_anon_WITH_NULL_SHA = 0xC015
    TLS_ECDH_anon_WITH_RC4_128_SHA = 0xC016
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = 0xC017
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA = 0xC018
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA = 0xC019
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = 0xC01A
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 0xC01B
    TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = 0xC01C
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA = 0xC01D
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0xC01E
    TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = 0xC01F
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA = 0xC020
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xC021
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0xC022
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC025
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC026
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xC029
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xC02A
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02D
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02E
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xC031
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xC032
    TLS_ECDHE_PSK_WITH_RC4_128_SHA = 0xC033
    TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = 0xC034
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = 0xC035
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = 0xC036
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = 0xC037
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = 0xC038
    TLS_ECDHE_PSK_WITH_NULL_SHA = 0xC039
    TLS_ECDHE_PSK_WITH_NULL_SHA256 = 0xC03A
    TLS_ECDHE_PSK_WITH_NULL_SHA384 = 0xC03B
    TLS_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC03C
    TLS_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC03D
    TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = 0xC03E
    TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = 0xC03F
    TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC040
    TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC041
    TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = 0xC042
    TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = 0xC043
    TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC044
    TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC045
    TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 = 0xC046
    TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 = 0xC047
    TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xC048
    TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xC049
    TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xC04A
    TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xC04B
    TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC04C
    TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC04D
    TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC04E
    TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC04F
    TLS_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC050
    TLS_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC051
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC052
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC053
    TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC054
    TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC055
    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = 0xC056
    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = 0xC057
    TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = 0xC058
    TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = 0xC059
    TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 = 0xC05A
    TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 = 0xC05B
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xC05C
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xC05D
    TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xC05E
    TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xC05F
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC060
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC061
    TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC062
    TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC063
    TLS_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC064
    TLS_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC065
    TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC066
    TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC067
    TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC068
    TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC069
    TLS_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06A
    TLS_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06B
    TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06C
    TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06D
    TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06E
    TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06F
    TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC070
    TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC071
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC072
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC073
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC074
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC075
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC076
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC077
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC078
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC079
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07A
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07B
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07C
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07D
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07E
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07F
    TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 0xC080
    TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 0xC081
    TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 0xC082
    TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 0xC083
    TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 = 0xC084
    TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 = 0xC085
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC086
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC087
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC088
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC089
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08A
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08B
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08C
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08D
    TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08E
    TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08F
    TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC090
    TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC091
    TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC092
    TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC093
    TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC094
    TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC095
    TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC096
    TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC097
    TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC098
    TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC099
    TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC09A
    TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC09B
    TLS_RSA_WITH_AES_128_CCM = 0xC09C
    TLS_RSA_WITH_AES_256_CCM = 0xC09D
    TLS_DHE_RSA_WITH_AES_128_CCM = 0xC09E
    TLS_DHE_RSA_WITH_AES_256_CCM = 0xC09F
    TLS_RSA_WITH_AES_128_CCM_8 = 0xC0A0
    TLS_RSA_WITH_AES_256_CCM_8 = 0xC0A1
    TLS_DHE_RSA_WITH_AES_128_CCM_8 = 0xC0A2
    TLS_DHE_RSA_WITH_AES_256_CCM_8 = 0xC0A3
    TLS_PSK_WITH_AES_128_CCM = 0xC0A4
    TLS_PSK_WITH_AES_256_CCM = 0xC0A5
    TLS_DHE_PSK_WITH_AES_128_CCM = 0xC0A6
    TLS_DHE_PSK_WITH_AES_256_CCM = 0xC0A7
    TLS_PSK_WITH_AES_128_CCM_8 = 0xC0A8
    TLS_PSK_WITH_AES_256_CCM_8 = 0xC0A9
    TLS_PSK_DHE_WITH_AES_128_CCM_8 = 0xC0AA
    TLS_PSK_DHE_WITH_AES_256_CCM_8 = 0xC0AB
    SSL_RSA_FIPS_WITH_DES_CBC_SHA = 0xFEFE
    SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA = 0xFEFF
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF

    MAX = 0xffff

class Compression(Enum8):
    Null = 0
    Deflate = 1
    LSZ = 64
    MAX = 0xff
    
    @staticmethod
    def all():
        return [ Compression.Deflate, Compression.LSZ, Compression.Null ]
    
    @staticmethod
    def none():
        return [ Compression.Null ]

class ContentType(Enum8):
    ChangeCipherSpec = 20
    Alert = 21
    Handshake = 22
    ApplicationData = 23
    Heartbeat = 24
    MAX = 0xff

class HandshakeType(Enum8):
    HelloRequest = 0
    ClientHello = 1
    ServerHello = 2
    Certificate = 11
    ServerKeyExchange = 12
    CertificateRequest = 13
    ServerHelloDone = 14
    CertificateVerify = 15
    ClientKeyExchange = 16
    Finished = 20
    CertificateURL = 21
    CertificateStatus = 22
    MAX = 0xff

class ChangeCipherSpec(Struct):
    def __init__(self):
        Struct.__init__(self)

    def encode(self):
        return Encode.u8(1)

    def to_json(self):
        return dict(value = 1)

    @staticmethod
    def read(b):
        value = Read.u8(b)
        if value != 1:
            raise ValueError('ChangeCipherSpec payload incorrect')
        return ChangeCipherSpec()

class AlertLevel(Enum8):
    Warning = 1
    Fatal = 2
    MAX = 0xff

class AlertDescription(Enum8):
    CloseNotify = 0
    UnexpectedMessage = 10
    BadRecordMac = 20
    DecryptionFailed = 21
    RecordOverflow = 22
    DecompressionFailure = 30
    HandshakeFailure = 40
    NoCertificate = 41
    BadCertificate = 42
    UnsupportedCertificate = 43
    CertificateRevoked = 44
    CertificateExpired = 45
    CertificateUnknown = 46
    IllegalParameter = 47
    UnknownCA = 48
    AccessDenied = 49
    DecodeError = 50
    DecryptError = 51
    ExportRestriction = 60
    ProtocolVersion = 70
    InsufficientSecurity = 71
    InternalError = 80
    UserCanceled = 90
    NoRenegotiation = 100
    UnsupportedExtension = 110
    UnrecognisedName = 112
    MAX = 255

class Alert(Struct):
    def __init__(self, level = AlertLevel.MAX, desc = AlertDescription.MAX):
        Struct.__init__(self)
        self.level = level
        self.desc = desc

    def encode(self):
        return AlertLevel.encode(self.level) + AlertDescription.encode(self.desc)

    def to_json(self):
        return dict(level = AlertLevel.to_json(self.level),
                    desc = AlertDescription.to_json(self.desc))

    @staticmethod
    def read(f):
        a = Alert()
        a.level = AlertLevel.read(f)
        a.desc = AlertDescription.read(f)
        return a

class ApplicationData(Struct):
    def __init__(self, data = None):
        Struct.__init__(self)
        self.data = data

    def encode(self):
        return bytes(self.data)

    def to_json(self):
        return dict(data = self.data)

    @staticmethod
    def read(f):
        return ApplicationData(data = f.read())

class HeartbeatMessageType(Enum8):
    Request = 1
    Response = 2
    MAX = 255

class Heartbeat(Struct):
    def __init__(self, type = None, payload = None):
        Struct.__init__(self)
        self.type = type
        self.payload = payload
        self.bytes_remain = 0

    def append_fragment(self, other):
        assert other.type == ContentType.Heartbeat
        extra, self.bytes_remain = Read.partial(io.BytesIO(other.body), self.bytes_remain)
        self.payload += extra

    def is_fully_received(self):
        return self.bytes_remain == 0

    def encode(self):
        return HeartbeatMessageType.encode(self.type) + \
               Encode.u16(len(self.payload)) + \
               list(self.payload)

    def to_json(self):
        return dict(type = HeartbeatMessageType.to_json(self.type),
                    payload = bytes_or_json(self.payload))
    
    @staticmethod
    def read(f):
        h = Heartbeat()
        h.type = HeartbeatMessageType.read(f)
        ll = Read.u16(f)
        print('heartbeat len is %d' % ll)
        h.payload, h.bytes_remain = Read.partial(f, ll)
        return h

class Handshake(Struct):
    def __init__(self, type, body):
        Struct.__init__(self)
        self.type = type
        self.body = body

    def encode(self):
        body = bytes(self.body)
        return HandshakeType.encode(self.type) + \
               Encode.u24(len(body)) + \
               list(body)

    def to_json(self):
        return dict(type = HandshakeType.to_json(self.type),
                    body = bytes_or_json(self.body))

    def read_body(self, f):
        ll = Read.u24(f)
        body_bytes = Read.must(f, ll)

        decoders = {
            HandshakeType.ClientHello: ClientHello.decode,
            HandshakeType.ServerHello: ServerHello.decode,
            HandshakeType.Certificate: Certificate.decode,
            HandshakeType.ServerHelloDone: ServerHelloDone.decode,
            HandshakeType.ClientKeyExchange: ClientKeyExchange.decode,
            HandshakeType.ServerKeyExchange: ServerKeyExchange.decode,
            HandshakeType.Finished: Finished.decode,
        }

        if self.type not in decoders:
            raise NotImplementedError('do not yet know how to decode {0}'.format(HandshakeType.tostring(self.type)))

        self.body = decoders[self.type](body_bytes)

    @staticmethod
    def read(f):
        h = Handshake(None, None)
        h.type = HandshakeType.read(f)
        h.read_body(f)
        return h

class Random(Struct):
    NONCE_LEN = 28
    
    def __init__(self, utctime = None, nonce = None):
        Struct.__init__(self)
        self.time = utctime
        self.nonce = nonce

    def encode(self):
        return Encode.u32(self.time) + list(self.nonce)

    def to_json(self):
        return dict(time = self.time,
                    nonce = bytes_or_json(self.nonce))

    @staticmethod
    def read(f):
        return Random(Read.u32(f), Read.must(f, Random.NONCE_LEN))

    @staticmethod
    def generate():
        return Random(int(time.time()), os.urandom(Random.NONCE_LEN))

class ExtensionType(Enum16):
    ServerName = 0
    MaxFragmentLength = 1
    ClientCertificateUrl = 2
    TrustedCAKeys = 3
    TruncatedHMAC = 4
    StatusRequest = 5
    UserMapping = 6
    ClientAuthz = 7
    ServerAuthz = 8
    CertificateType = 9
    EllipticCurves = 10
    ECPointFormats = 11
    SRP = 12
    SignatureAlgorithms = 13
    UseSRTP = 14
    Heartbeat = 15
    Padding = 21 # http://tools.ietf.org/html/draft-agl-tls-padding-03
    SessionTicket = 35
    NextProtocolNegotiation = 0x3374
    ChannelId = 0x754f
    RenegotiationInfo = 0xff01
    
    MAX = 0xffff

class Extension(Struct):
    def __init__(self, type = None, data = None):
        Struct.__init__(self)
        self.type = type
        self.data = data

    def encode(self):
        body = bytes(self.data)
        return ExtensionType.encode(self.type) + \
               Encode.u16(len(body)) + \
               list(body)

    def to_json(self):
        return dict(type = ExtensionType.to_json(self.type),
                    body = bytes_or_json(self.data))

    @staticmethod
    def read(f):
        e = Extension()
        e.type = ExtensionType.read(f, lax_enum = True)
        e.data = Read.vec(f, Read.u16, Read.u8)
        return e

class ServerNameExtensionBody(Struct):
    def __init__(self, names = None):
        Struct.__init__(self)
        self.names = names if names else []

    def encode(self):
        return Encode.vec(Encode.u16, self.names)

    def to_json(self):
        return [x.to_json() for x in self.names]

    @staticmethod
    def read(f):
        return ServerNameExtensionBody(Read.vec(f, Read.u16, ServerName.read))

class ServerNameType(Enum8):
    HostName = 0
    MAX = 0xff

class ServerName(Struct):
    def __init__(self, type, body):
        Struct.__init__(self)
        self.type = type
        self.body = body

    def encode(self):
        return ServerNameType.encode(self.type) + \
               Encode.item_vec(Encode.u16, Encode.u8, self.body)

    def to_json(self):
        return dict(type = ServerNameType.to_json(self.type),
                    body = bytes_or_json(self.body))
    
    @staticmethod
    def hostname(h):
        return ServerName(ServerNameType.HostName, bytes(h, 'utf-8'))
    
    @staticmethod
    def read(f):
        sn = ServerName(None, None)
        sn.type = ServerNameType.read(f)
        sn.body = Read.vec(f, Read.u16, Read.u8)
        return sn

class NamedCurve(Enum16):
    sect163k1 = 1
    sect163r1 = 2
    sect163r2 = 3
    sect193r1 = 4
    sect193r2 = 5
    sect233k1 = 6
    sect233r1 = 7
    sect239k1 = 8
    sect283k1 = 9
    sect283r1 = 10
    sect409k1 = 11
    sect409r1 = 12
    sect571k1 = 13
    sect571r1 = 14
    secp160k1 = 15
    secp160r1 = 16
    secp160r2 = 17
    secp192k1 = 18
    secp192r1 = 19
    secp224k1 = 20
    secp224r1 = 21
    secp256k1 = 22
    secp256r1 = 23
    secp384r1 = 24
    secp521r1 = 25
    arbitrary_explicit_prime_curves = 0xFF01
    arbitrary_explicit_char2_curves = 0xFF02

    MAX = 0xffff

class EllipticCurvesExtensionBody(Struct):
    def __init__(self, curves = None):
        Struct.__init__(self)
        self.curves = curves if curves else []

    def encode(self):
        return Encode.item_vec(Encode.u16, NamedCurve._Encode, self.curves)

    def to_json(self):
        return [NamedCurve.to_json(x) for x in self.curves]

    @staticmethod
    def read(f):
        return EllipticCurvesExtensionBody(Read.vec(f, Read.u16, NamedCurve.read))
    
    @staticmethod
    def all_named_curves():
        return EllipticCurvesExtensionBody(list(range(NamedCurve.sect163k1,
                                                      NamedCurve.secp521r1 + 1)))

    @staticmethod
    def all_common_prime_curves():
        return EllipticCurvesExtensionBody([NamedCurve.secp256r1,
                                            NamedCurve.secp384r1,
                                            NamedCurve.secp521r1])
    


class ClientHello(Struct):
    def __init__(self, version = None, random = None, session_id = None,
                 ciphersuites = None, compressions = None, extensions = None):
        Struct.__init__(self)
        self.version = version if version else ProtocolVersion._Highest
        self.random = random if random else Random.generate()
        self.session_id = session_id if session_id else []
        self.ciphersuites = ciphersuites if ciphersuites else []
        self.compressions = compressions if compressions else []
        self.extensions = extensions if extensions else []

    def encode(self):
        o = []
        o.extend(ProtocolVersion.encode(self.version))
        o.extend(self.random.encode())
        o.extend(Encode.item_vec(Encode.u8, Encode.u8, self.session_id))
        o.extend(Encode.item_vec(Encode.u16, CipherSuite._Encode, self.ciphersuites))
        o.extend(Encode.item_vec(Encode.u8, Compression._Encode, self.compressions))
        if len(self.extensions):
            o.extend(Encode.vec(Encode.u16, self.extensions))
        return o

    def to_json(self):
        return dict(version = ProtocolVersion.to_json(self.version),
                    random = self.random.to_json(),
                    session_id = bytes_or_json(self.session_id),
                    ciphersuites = [CipherSuite.to_json(x) for x in self.ciphersuites],
                    compressions = [Compression.to_json(x) for x in self.compressions],
                    extensions = [x.to_json() for x in self.extensions])

    @staticmethod
    def read(f):
        c = ClientHello()
        c.version = ProtocolVersion.read(f)
        c.random = Random.read(f)
        c.session_id = Read.vec(f, Read.u8, Read.u8)
        c.ciphersuites = Read.vec(f, Read.u16, lambda f: CipherSuite.read(f, lax_enum = True))
        c.compressions = Read.vec(f, Read.u8, Compression.read)

        left = f.read()
        if len(left):
            c.extensions = Read.vec(io.BytesIO(left), Read.u16, Extension.read)
        
        return c

class ServerHello(Struct):
    def __init__(self, version = None, random = None, session_id = None, ciphersuite = None, compression = None, extensions = None):
        Struct.__init__(self)
        self.version = version
        self.random = random
        self.session_id = session_id
        self.ciphersuite = ciphersuite
        self.compression = compression
        self.extensions = extensions if extensions else []

    def encode(self):
        return ProtocolVersion.encode(self.version) + \
               self.random.encode() + \
               Encode.item_vec(Encode.u8, Encode.u8, self.session_id) + \
               CipherSuite.encode(self.ciphersuite) + \
               Compression.encode(self.compression) + \
               (Encode.vec(Encode.u16, self.extensions) if self.extensions else [])

    def to_json(self):
        return dict(version = ProtocolVersion.to_json(self.version),
                    random = self.random.to_json(),
                    session_id = bytes_or_json(self.session_id),
                    ciphersuite = CipherSuite.to_json(self.ciphersuite),
                    compression = Compression.to_json(self.compression),
                    extensions = [x.to_json() for x in self.extensions])

    @staticmethod
    def read(f):
        s = ServerHello()
        s.version = ProtocolVersion.read(f)
        s.random = Random.read(f)
        s.session_id = Read.vec(f, Read.u8, Read.u8)
        s.ciphersuite = CipherSuite.read(f)
        s.compression = Compression.read(f)

        left = f.read()
        if len(left):
            s.extensions = Read.vec(io.BytesIO(left), Read.u16, Extension.read)
            
        return s

class ServerHelloDone(Struct):
    def encode(self): return []
    def to_json(): return {}
    @staticmethod
    def read(f):
        return ServerHelloDone()

class ClientKeyExchange(Struct):
    def __init__(self, body = None):
        Struct.__init__(self)
        self.body = body if body else []
    
    def encode(self):
        return self.body

    def to_json(self):
        return bytes_or_json(self.body)
    
    @staticmethod
    def read(f):
        c = ClientKeyExchange()
        c.body = f.read()
        return c

class ServerKeyExchange(Struct):
    def __init__(self, body = None):
        Struct.__init__(self)
        self.body = body if body else []
    
    def encode(self):
        return self.body

    def to_json(self):
        return bytes_or_json(self.body)
    
    @staticmethod
    def read(f):
        c = ServerKeyExchange()
        c.body = f.read()
        return c

class Finished(Struct):
    def __init__(self, body = None):
        Struct.__init__(self)
        self.body = body if body else []
    
    def encode(self):
        return self.body

    def to_json(self):
        return bytes_or_json(self.body)
    
    @staticmethod
    def read(f):
        c = Finished()
        c.body = bytes([Read.u8(f) for _ in range(12)])
        return c

class ASN1Cert(Struct):
    def __init__(self, data = None):
        Struct.__init__(self)
        self.data = data

    def encode(self):
        return Encode.item_vec(Encode.u24, Encode.u8, self.data)

    def to_json(self):
        return bytes_or_json(self.data)

    @staticmethod
    def read(f):
        ac = ASN1Cert()
        ac.data = Read.vec(f, Read.u24, Read.u8)
        return ac

class Certificate(Struct):
    def __init__(self, certs = None):
        Struct.__init__(self)
        self.certs = certs if certs else []

    def encode(self):
        return Encode.item_vec(Encode.u24, ASN1Cert.encode, self.certs)

    def to_json(self):
        return [x.to_json() for x in self.certs]

    @staticmethod
    def read(f):
        c = Certificate()
        c.certs = Read.vec(f, Read.u24, ASN1Cert.read)
        return c

class Message(Struct):
    def __init__(self, type = 0, version = 0, body = None):
        Struct.__init__(self)
        self.type = type
        self.version = version
        self.body = body
        self.opaque = False

    @staticmethod
    def prefix_has_full_frame(b):
        lb = len(b)
        if lb < 5:
            return False
        fl = Decode.u16(b[3:5])
        return len(b) >= fl + 5

    @staticmethod
    def read(f, opaque = False):
        m = Message()
        m.type = ContentType.read(f)
        m.version = ProtocolVersion.read(f)
        m.read_body(f, opaque)
        return m

    def interpret_body(self):
        decoders = {
            ContentType.Alert: Alert.decode,
            ContentType.ApplicationData: ApplicationData.decode,
            ContentType.ChangeCipherSpec: ChangeCipherSpec.decode,
            ContentType.Handshake: Handshake.decode,
            ContentType.Heartbeat: Heartbeat.decode
        }

        assert decoders.keys() == ContentType.table().keys()
        self.body = decoders[self.type](self.body)
        self.opaque = False

    def read_body(self, f, opaque):
        ll = Read.u16(f)
        self.body = Read.must(f, ll)
        self.opaque = opaque

        if not self.opaque:
            self.interpret_body()

    def encode(self):
        return bytes(self.header()) + bytes(self.body)

    def header(self):
        # the stuff which gets put into the mac (minus sequence number and body)
        return ContentType.encode(self.type) + \
               ProtocolVersion.encode(self.version) + \
               Encode.u16(len(bytes(self.body)))

    def to_json(self):
        return dict(type = ContentType.to_json(self.type),
                    version = ProtocolVersion.to_json(self.version),
                    body = bytes_or_json(self.body))
                    

