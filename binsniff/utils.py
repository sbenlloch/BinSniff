def _log(tag, text):

    colors = {'W': '\033[33m', 'E': '\033[31m', 'S': '\033[32m', 'I': '\033[36m'}
    symbols = {'W': '⚠', 'E': '✖', 'S': '✔', 'I': 'ℹ'}
    print(colors[tag] + symbols[tag] + " " + text + "\033[0m")
