from Cryptodome.Cipher import AES

def decr_API(encrypted_API_key):

    iv = '<unjA$?v*K>57YQb'.encode('utf8')
    key = 'q.&jvG,@6Jx3C%;F'.encode('utf8')

    aes = AES.new(key, AES.MODE_CBC, iv)

    decd = aes.decrypt(encrypted_API_key)

    return decd.decode("utf8")

