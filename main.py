import hashlib
import requests
from sys import argv


# request pwned_password API and get the response
def request_api_response(first5char):
    url = f"https://api.pwnedpasswords.com/range/{first5char}"
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f"Error fetching {response.status_code}, please check the API again")
    else:
        return response


# get the count of required password
def get_count(first5char, tail_to_check):
    response = request_api_response(first5char)
    for tail, count in (line.split(':') for line in response.text.splitlines()):
        if tail == tail_to_check:
            return count
    return 0


#  hashing password
def check_password(password):
    hash_pass = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5char, tail = hash_pass[:5], hash_pass[5:]
    count = get_count(first5char, tail)
    if count:
        print(f"password {password} found {count} times, you should probably find a more secure password.")
    else:
        print(f"password {password} not found, all good!")


def main(args):
    for password in args:
        check_password(password)


if __name__ == '__main__':
    main(argv[1:])
