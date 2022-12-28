import hashlib
from hmac import compare_digest


def passwd_hash(passwd):
  fpasswd = passwd.encode('utf-8')
  sha1 = hashlib.sha1(fpasswd)
  return sha1.hexdigest()


def crack_sha1_hash(hash, use_salts=False):

  if (use_salts):
    with open('./top-10000-passwords.txt', 'r') as top_10000_password:
      # Remove new line '\n'
      passwords = top_10000_password.read().splitlines()
      for passwd in passwords:

        with open('./known-salts.txt', 'r') as know_salts:
          salts = know_salts.read().splitlines()
          for salt in salts:
            salt1 = passwd_hash(passwd + salt)
            salt2 = passwd_hash(salt + passwd)
            salt3 = passwd_hash(salt + passwd + salt)

            if hash == salt1 or hash == salt2 or hash == salt3:
              return passwd
            else:
              result = "PASSWORD NOT IN DATABASE"

      return result

  else:
    with open('./top-10000-passwords.txt', 'r') as top_10000_password:
      passwords = top_10000_password.read().splitlines()
      for passwd in passwords:
        if compare_digest(hash, passwd_hash(passwd)):
          return passwd
        else:
          result = "PASSWORD NOT IN DATABASE"

      return result
