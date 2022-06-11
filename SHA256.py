from pwn import *
import sys


if len(sys.argv) != 2:
    print("Too many arguments")
    exit()

hash = sys.argv[1]
dictionary = "rockyou.txt"
attempts = 0

with log.progress("Attempting to hack: {}!\n".format(hash)) as p:
    with open(dictionary, "r", encoding='latin-1') as f:
        for password in f:
            password = password.strip("\n").encode('latin-1')
            password_hash = sha256sumhex(password)
            p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
            if password_hash == hash:
                p.success("Password hash found after {} attempts! {} hashes to {}!".format(attempts, password.decode('latin-1'), password_hash))
                exit()
            attempts += 1
        p.failure("Password hash not found")

