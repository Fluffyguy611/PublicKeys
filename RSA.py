import random
import math
import logging

logging.basicConfig(level=logging.INFO, filename="logfile.log", filemode='a', format='%(message)s')

lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
   67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
   157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241,
   251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,317, 331, 337, 347, 349,
   353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449,
   457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569,
   571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
   673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
   797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907,
   911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]


def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b


def findModInverse(a, m):
    result = 0
    try:
        result = pow(a, -1, m)
    except:
        return 0
    return result


def rabinMiller(num):
    s = num - 1
    t = 0

    while s % 2 == 0:
        s = s // 2
        t += 1
    for trials in range(3):
        a = random.randint(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
        return True


def isPrime(num):
    if num < 2:
        return False
    if num in lowPrimes:
        return True
    for prime in lowPrimes:
        if num % prime == 0:
            return False
    return rabinMiller(num)


def generatePrime(keysize):
    while True:
        num = random.randint(2 ** (keysize - 1), 2 ** keysize)
        if isPrime(num):
            return num


def checkIfKeyIsBigEnoght(keySize):
    if keySize < 50:
        keySize += 100
    return keySize


def generateKey(keySize):
    keySize = checkIfKeyIsBigEnoght(keySize)
    p = generatePrime(keySize)
    q = generatePrime(keySize)
    n = p * q

    # e = (p-1)*(q-1).
    while True:
        e = random.randint(2 ** (keySize - 1), 2 ** keySize)
        if gcd(e, (p - 1) * (q - 1)) == 1:
            break

    # Oblicz d, czyli element odwrotny do e
    d = findModInverse(e, (p - 1) * (q - 1))
    publicKey = (n, e)
    privateKey = (n, d)

    return publicKey, privateKey

def rsa_encrypt(plaintextBlock, public_key):
    n, e = public_key
    encrypted_blocks = []
    for block in plaintextBlock:
        encrypted_block = pow(block, e, n)
        encrypted_blocks.append(encrypted_block)
    return encrypted_blocks


def text_to_blocks(text, block_size):
    unicode_list = [ord(char) for char in text]
    blocks = []
    for i in range(0, len(unicode_list), block_size):
        block = 0
        for j in range(block_size):
            if i + j < len(unicode_list):
                block += unicode_list[i+j] * int(math.pow(256, j))  # Change the base here if desired
        blocks.append(block)
    return blocks


def rsa_decrypt(ciphertext, private_key):
    n, d = private_key
    decrypted_blocks = []
    for block in ciphertext:
        decrypted_block = pow(block, d, n)
        decrypted_blocks.append(decrypted_block)
    return decrypted_blocks


def getTextFromBlocks(blockInts, messageLength, blockSize):
    # Converts a list of block integers to the original message string.
    # The original message length is needed to properly convert the last
    # block integer.
    message = []
    for blockInt in blockInts:
        blockMessage = []
        for i in range(blockSize - 1, -1, -1):
            if len(message) + i < messageLength:
                # Decode the message string for the 128 (or whatever
                # blockSize is set to) characters from this block integer.
                asciiNumber = blockInt // (256 ** i)
                blockInt = blockInt % (256 ** i)
                blockMessage.insert(0, chr(asciiNumber))
        message.extend(blockMessage)
    return ''.join(message)


def saveKeyToFile(key, filename):
    with open(filename, 'w') as file:
        file.write(','.join(map(str, key)))


def loadKeyFromFile(filename):
    with open(filename, 'r') as file:
        key_data = file.read().split(",")
    return int(key_data[0]), int(key_data[1])


def saveEncryptedMsgToFile(messageLength, encrypted_message, filename):
    encryptedContent = '%s_%s' % (messageLength, encrypted_message)
    fo = open(filename, 'w')
    fo.write(encryptedContent)
    fo.close()


def loadEncryptedMsgFromFile(filename):
    fo = open(filename)
    content = fo.read()
    messageLength, encryptedMessage = content.split('_')
    fo.close()
    return encryptedMessage, messageLength


def saveDecryptedMsgToFile(decrypted_message, filename):
    with open(filename, 'w') as file:
        file.write(decrypted_message)


def loadDecryptedMsgFromFile(filename):
    with open(filename, 'r') as file:
        decrypted_message = file.read()
    return decrypted_message


def keyGeneration():
    key_size = int(input("Enter the key size: "))
    public_key, private_key = generateKey(key_size)

    logging.info(f"Key size: {key_size} \npublic key: {public_key} \nprivate key: {private_key}")

    saveKeyToFile(public_key, 'public_key.txt')
    saveKeyToFile(private_key, 'private_key.txt')
    print("Keys generated and saved to public_key.txt and private_key.txt.")


def encryptText():
    block_size = int(input("Enter the block size: "))
    message = input("Enter the message to encrypt: ")

    public_key = loadKeyFromFile('public_key.txt')

    plaintextBlocks = text_to_blocks(message, block_size)
    encryptedBlock = rsa_encrypt(plaintextBlocks, public_key)
    for i in range(len(encryptedBlock)):
        encryptedBlock[i] = str(encryptedBlock[i])
    encryptedContent = ','.join(encryptedBlock)
    print(plaintextBlocks)
    print(encryptedContent)

    logging.info(f"Message: \"{message}\" \nblock size: {block_size} \npublic key: {public_key} \nencrypted msg: {encryptedContent}")

    saveEncryptedMsgToFile(len(message), encryptedContent, 'encrypted_message.txt')
    print(f"{encryptedContent} encrypted and saved to encrypted_message.txt.")
    print()


def decryptText():
    block_size = int(input("Enter the block size: "))
    print()

    encryptedMessage, messageLength = loadEncryptedMsgFromFile('encrypted_message.txt')
    messageLength = int(messageLength)
    private_key = loadKeyFromFile('private_key.txt')

    encryptedBlocks = []
    for block in encryptedMessage.split(','):
        encryptedBlocks.append(int(block))

    decryptedBlocks = rsa_decrypt(encryptedBlocks, private_key)
    decryptedText = getTextFromBlocks(decryptedBlocks, messageLength, block_size)
    logging.info(f"Encrypted Message: \"{encryptedBlocks}\" \nblock size: {block_size} \nprivate key: {private_key}"
                 f"\nencrypted msg: \"{decryptedText}\"\n")

    saveDecryptedMsgToFile(decryptedText, 'decrypted_message.txt')
    print(f"\"{decryptedText}\" decrypted and saved to decrypted_message.txt.")
    print()


if __name__ == '__main__':
    keyGeneration()
    encryptText()
    decryptText()



