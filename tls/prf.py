import hashlib
import hmac

def TLSv1_0_PRF(outlen, secret, label, seed):
    ls = len(secret)
    ls1 = ls2 = (ls + 1) // 2
    
    def xor(xx, yy):
        o = []
        for i in range(len(xx)):
            o.append(xx[i] ^ yy[i])
        return bytes(o)
    
    md5 = TLSv1_2_PRF(outlen, secret[:ls1], label, seed, hashlib.md5)
    sha1 = TLSv1_2_PRF(outlen, secret[-ls2:], label, seed, hashlib.sha1)

    return xor(md5, sha1)

def TLSv1_2_PRF(outlen, secret, label, seed, h):
    label = bytes(label, 'ASCII')
    secret = bytes(secret)
    seed = bytes(seed)

    def p_hash(hashfn, outlen, k, pt):
        o = []
        a_im = pt
        for i in range(0, outlen, hashfn().digest_size):
            a_i = hmac.new(k, a_im, hashfn).digest()
            output = hmac.new(k, a_i + pt, hashfn).digest()
            o.append(output)
            a_im = a_i
        return bytes(b''.join(o))[:outlen]

    return p_hash(h, outlen, secret, label + seed)

if __name__ == '__main__':
    # TLS1.0 PRF test vector
    secret = bytes.fromhex('ab' * 48)
    label = "PRF Testvector"
    seed = bytes.fromhex('cd' * 64)
    master_secret = TLSv1_0_PRF(104, secret, label, seed)
    assert len(master_secret) == 104
    assert master_secret == bytes.fromhex('d3d4d1e349b5d515044666d51de32bab258cb521b6b053463e354832fd976754443bcf9a296519bc289abcbc1187e4ebd31e602353776c408aafb74cbc85eff69255f9788faa184cbb957a9819d84a5d7eb006eb459d3ae8de9810454b8b2d8f1afbc655a8c9a013')

    # TLS1.2 PRF test vector
    label = 'test label'
    secret = bytes.fromhex('9b be 43 6b a9 40 f0 17 b1 76 52 84 9a 71 db 35')
    seed = bytes.fromhex('a0 ba 9f 93 6c da 31 18 27 a6 f7 96 ff d5 19 8c')

    master_secret = TLSv1_2_PRF(100, secret, label, seed, hashlib.sha256)
    assert len(master_secret) == 100
    assert master_secret == bytes.fromhex('e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66')
