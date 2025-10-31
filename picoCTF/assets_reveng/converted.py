import sys


def func(x):
    a = x
    b = 87
    c = 3
    d = 3
    e = b << c
    e = e // d
    e = e - a
    return e


def main():
    # Simulate argv and argc from sys.argv
    argc = len(sys.argv)
    argv = sys.argv

    if argc > 1:
        val = int(argv[1])
    else:
        val = 0

    result = func(val)
    if result == 0:
        print("You win!")
    else:
        print("You Lose :(")


if __name__ == "__main__":
    main()
