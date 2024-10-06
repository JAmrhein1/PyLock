# main.py

from tkinter import Tk
from pylock_gui import PyLockGUI

def main():
    root = Tk()
    app = PyLockGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
