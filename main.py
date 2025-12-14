import tkinter as tk
from app import App

def main() -> None:
    root = tk.Tk()
    app = App(root)
    app.start()

    def on_close():
        app.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

if __name__ == "__main__":
    main()
