import os


def run_command(user_input):
    # This is insecure - potential shell injection vulnerability
    os.system(user_input)


def main():
    user_command = input("Enter a command: ")
    run_command(user_command)


if __name__ == "__main__":
    main()