import tkinter as tk
from tkinter import filedialog, messagebox
from utils import encrypt_file, decrypt_file

class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption/Decryption Tool")
        self.root.geometry("460x320")
        self.root.configure(bg="#1e1e2f")
        self.root.resizable(False, False)
        self.file_path = ""

        # Header
        tk.Label(
            root, text="🔐 File Encryption/Decryption", bg="#1e1e2f", fg="#ffffff",
            font=("Helvetica", 18, "bold")
        ).pack(pady=15)

        # File selection
        self.file_label = tk.Label(root, text="No file selected", bg="#1e1e2f", fg="#aaaaaa")
        self.file_label.pack(pady=5)

        select_btn = tk.Button(root, text="📁 Select File", command=self.select_file,
                               bg="#4a4a6a", fg="#ffffff", activebackground="#66668a",
                               relief="flat", font=("Helvetica", 10, "bold"), width=20)
        select_btn.pack(pady=5)

        # Password entry
        tk.Label(root, text="Enter Password:", bg="#1e1e2f", fg="#ffffff").pack(pady=(15, 5))
        self.password_entry = tk.Entry(root, show="*", width=30, font=("Helvetica", 10))
        self.password_entry.pack(pady=5)

        # Action buttons
        action_frame = tk.Frame(root, bg="#1e1e2f")
        action_frame.pack(pady=15)

        encrypt_btn = tk.Button(action_frame, text="Encrypt File", command=self.encrypt,
                                bg="#3cb371", fg="white", width=15, relief="flat",
                                activebackground="#2e8b57", font=("Helvetica", 10, "bold"))
        encrypt_btn.grid(row=0, column=0, padx=10)

        decrypt_btn = tk.Button(action_frame, text="Decrypt File", command=self.decrypt,
                                bg="#1e90ff", fg="white", width=15, relief="flat",
                                activebackground="#104e8b", font=("Helvetica", 10, "bold"))
        decrypt_btn.grid(row=0, column=1, padx=10)

        # Footer
        tk.Label(root, text="© 2025 SecureApp", bg="#1e1e2f", fg="#444").pack(side="bottom", pady=10)

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path = path
            self.file_label.config(text=path.split("/")[-1])

    def encrypt(self):
        password = self.password_entry.get()
        if not self.file_path or not password:
            messagebox.showwarning("Missing Input", "Please select a file and enter a password.")
            return
        try:
            encrypt_file(self.file_path, password)
            messagebox.showinfo("Success", "File encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        password = self.password_entry.get()
        if not self.file_path or not password:
            messagebox.showwarning("Missing Input", "Please select a file and enter a password.")
            return
        try:
            decrypt_file(self.file_path, password)
            messagebox.showinfo("Success", "File decrypted successfully.")
        except Exception as e:
           import traceback
           traceback.print_exc()  # Print full error to terminal
           messagebox.showerror("Error", f"Decryption Failed:\n{e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
