"""
Script to recover discord users on android.

@author:   (@BoBNewz)
"""

import re, sys

def main(parameter):

    pattern_users = r'[a-zA-Z0-9_@]+#[0-9]{4}'
    try:
        f = open(parameter).readlines()
        for line in f:
            users = re.findall(pattern_users, line)
            if users:
                for user in users:
                    if user.split("#")[0].isdigit():
                        pass
                    elif user.split("#")[1] == "0000":
                        pass
                    else:
                        print(user)
    except:
        print("No file available")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        print("Usage : python android_discord_users.py strings.txt")
