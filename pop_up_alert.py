import tkinter as tk
import threading

def popup_alert(text):
    def show():
        root = tk.Tk()
        root.title("IPS ALERT")
        width = 700
        height = 400
        label = tk.Label(
            root,
            text=text,
            fg="red",
            font=("Arial", 24, "bold"),
            wraplength=260,
            justify="center"
        )
        label.pack(expand=True)
        root.resizable(False, False)
        root.attributes("-topmost", True)

        root.update_idletasks()

        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        root.geometry(f"{width}x{height}+{x}+{y}")

        root.after(5000, root.destroy)
        root.mainloop()
    threading.Thread(target=show, daemon=True).start()
