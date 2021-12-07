from hashlib import sha1, sha256, md5

def get_hash(malware, hashfunc):

    h = hashfunc()
    with open(malware,'rb') as f:
        chunk = 0
        while chunk != b'':
            chunk = f.read(1024)
            h.update(chunk)
    return h.hexdigest()