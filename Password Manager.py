import threading
import customtkinter as ctk
from Quantum_Protected_Password_Generator import generate_quantum_password, set_token
from Vault import load_vault, save_vault, get_entries, add_entry

class QuantumPasswordGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")

        self.COL_BG = "#0B0F14"
        self.COL_PANEL = "#111826"
        self.COL_PANEL_2 = "#0F1722"
        self.COL_BORDER = "#1E2A3A"
        self.COL_TEXT = "#E6ECF2"
        self.COL_MUTED = "#9FB0C0"
        self.COL_PURPLE = "#6E56CF"
        self.COL_PURPLE_HOVER = "#7C68D6"
        self.COL_GREEN = "#25C26E"
        self.COL_WARN = "#F0B429"
        self.COL_DANGER = "#E55555"

        self.title("Quantum Password Manager")
        self.geometry("980x560")
        self.minsize(900, 520)
        self.configure(fg_color=self.COL_BG)

        self.master_password = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.header = ctk.CTkFrame(self, fg_color="#2A2142", corner_radius=0)
        self.header.grid(row=0, column=0, sticky="nsew")
        self.header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self.header,
            text="Quantum Password Manager",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=self.COL_TEXT
        ).grid(row=0, column=0, padx=22, pady=16, sticky="w")

        self.main = ctk.CTkFrame(self, fg_color=self.COL_BG, corner_radius=0)
        self.main.grid(row=1, column=0, sticky="nsew", padx=18, pady=18)
        self.main.grid_columnconfigure((0, 1), weight=1, uniform="cols")
        self.main.grid_rowconfigure(0, weight=1)

        self.left = ctk.CTkFrame(self.main, fg_color=self.COL_PANEL, corner_radius=16, border_width=1, border_color=self.COL_BORDER)
        self.left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.left.grid_columnconfigure(0, weight=1)

        self.right = ctk.CTkFrame(self.main, fg_color=self.COL_PANEL_2, corner_radius=16, border_width=1, border_color=self.COL_BORDER)
        self.right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.right.grid_columnconfigure(0, weight=1)
        self.right.grid_rowconfigure(3, weight=1)

        self.is_generating = False

        self.build_left()
        self.build_right()
        self.show_unlock_modal()

    def build_left(self):
        ctk.CTkLabel(self.left, text="Generate Password", font=ctk.CTkFont(size=18, weight="bold"), text_color=self.COL_TEXT).grid(row=0, column=0, padx=18, pady=(18, 8), sticky="w")

        self.password_var = ctk.StringVar(value="")
        self.output = ctk.CTkEntry(self.left, textvariable=self.password_var, height=44, fg_color="#0B1220", border_color=self.COL_BORDER, text_color=self.COL_TEXT, placeholder_text="Click Generate…")
        self.output.grid(row=1, column=0, padx=18, pady=(0, 14), sticky="ew")

        btn_row = ctk.CTkFrame(self.left, fg_color="transparent")
        btn_row.grid(row=2, column=0, padx=18, pady=(0, 14), sticky="ew")
        btn_row.grid_columnconfigure((0, 1), weight=1)

        self.generate_btn = ctk.CTkButton(btn_row, text="Generate", height=42, fg_color=self.COL_PURPLE, hover_color=self.COL_PURPLE_HOVER, text_color="white", command=self.on_generate)
        self.generate_btn.grid(row=0, column=0, padx=(0, 8), sticky="ew")

        self.copy_btn = ctk.CTkButton(btn_row, text="Copy", height=42, fg_color="#162235", hover_color="#1B2B44", text_color=self.COL_TEXT, command=self.on_copy)
        self.copy_btn.grid(row=0, column=1, padx=(8, 0), sticky="ew")

        length_row = ctk.CTkFrame(self.left, fg_color="transparent")
        length_row.grid(row=3, column=0, padx=18, pady=(0, 6), sticky="ew")
        length_row.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(length_row, text="Length", font=ctk.CTkFont(size=13, weight="bold"), text_color=self.COL_TEXT).grid(row=0, column=0, sticky="w")

        self.length_value = ctk.CTkLabel(length_row, text="20", font=ctk.CTkFont(size=13), text_color=self.COL_MUTED)
        self.length_value.grid(row=0, column=1, sticky="e")

        self.length_slider = ctk.CTkSlider(self.left, from_=8, to=64, number_of_steps=56, command=self.on_slider)
        self.length_slider.set(20)
        self.length_slider.grid(row=4, column=0, padx=18, pady=(0, 12), sticky="ew")

        self.with_symbols = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(self.left, text="Include symbols", variable=self.with_symbols).grid(row=5, column=0, padx=18, pady=(0, 12), sticky="w")

        ctk.CTkLabel(self.left, text="Save to Vault", font=ctk.CTkFont(size=13, weight="bold"), text_color=self.COL_TEXT).grid(row=6, column=0, padx=18, pady=(6, 8), sticky="w")

        self.site_var = ctk.StringVar(value="")
        self.user_var = ctk.StringVar(value="")

        self.site_entry = ctk.CTkEntry(self.left, textvariable=self.site_var, height=40, fg_color="#0B1220", border_color=self.COL_BORDER, text_color=self.COL_TEXT, placeholder_text="Site / App (e.g., Gmail)")
        self.site_entry.grid(row=7, column=0, padx=18, pady=(0, 10), sticky="ew")

        self.user_entry = ctk.CTkEntry(self.left, textvariable=self.user_var, height=40, fg_color="#0B1220", border_color=self.COL_BORDER, text_color=self.COL_TEXT, placeholder_text="Username / Email")
        self.user_entry.grid(row=8, column=0, padx=18, pady=(0, 12), sticky="ew")

        save_row = ctk.CTkFrame(self.left, fg_color="transparent")
        save_row.grid(row=9, column=0, padx=18, pady=(0, 12), sticky="ew")
        save_row.grid_columnconfigure((0, 1), weight=1)

        self.save_btn = ctk.CTkButton(save_row, text="Save Entry", height=40, fg_color="#162235", hover_color="#1B2B44", text_color=self.COL_TEXT, command=self.on_save_entry)
        self.save_btn.grid(row=0, column=0, padx=(0, 8), sticky="ew")

        self.token_btn = ctk.CTkButton(save_row, text="Load Token", height=40, fg_color="#162235", hover_color="#1B2B44", text_color=self.COL_TEXT, command=self.on_set_token)
        self.token_btn.grid(row=0, column=1, padx=(8, 0), sticky="ew")

        self.status = ctk.CTkLabel(self.left, text="Locked. Unlock vault to save/view entries.", font=ctk.CTkFont(size=12), text_color=self.COL_WARN)
        self.status.grid(row=10, column=0, padx=18, pady=(0, 18), sticky="w")

    def build_right(self):
        top_row = ctk.CTkFrame(self.right, fg_color="transparent")
        top_row.grid(row=0, column=0, padx=18, pady=(18, 8), sticky="ew")
        top_row.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(top_row, text="Vault", font=ctk.CTkFont(size=18, weight="bold"), text_color=self.COL_TEXT).grid(row=0, column=0, sticky="w")

        self.refresh_btn = ctk.CTkButton(top_row, text="Refresh", height=34, fg_color="#162235", hover_color="#1B2B44", text_color=self.COL_TEXT, command=self.refresh_vault_view)
        self.refresh_btn.grid(row=0, column=1, sticky="e")

        self.search_var = ctk.StringVar(value="")
        self.search_entry = ctk.CTkEntry(self.right, textvariable=self.search_var, height=40, fg_color="#0B1220", border_color=self.COL_BORDER, text_color=self.COL_TEXT, placeholder_text="Search (site or username)")
        self.search_entry.grid(row=1, column=0, padx=18, pady=(0, 12), sticky="ew")
        self.search_entry.bind("<KeyRelease>", lambda _e: self.refresh_vault_view())

        self.scroll = ctk.CTkScrollableFrame(self.right, fg_color="transparent")
        self.scroll.grid(row=3, column=0, padx=18, pady=(0, 18), sticky="nsew")
        self.scroll.grid_columnconfigure(0, weight=1)

        self.refresh_vault_view()

    def show_unlock_modal(self):
        self.unlock = ctk.CTkToplevel(self)
        self.unlock.title("Unlock Vault")
        self.unlock.geometry("420x260")
        self.unlock.resizable(False, False)
        self.unlock.configure(fg_color=self.COL_BG)
        self.unlock.grab_set()
        self.unlock.grid_columnconfigure(0, weight=1)
        self.unlock.protocol("WM_DELETE_WINDOW", self.destroy)

        ctk.CTkLabel(self.unlock, text="Enter Master Password", font=ctk.CTkFont(size=18, weight="bold"), text_color=self.COL_TEXT).grid(row=0, column=0, padx=18, pady=(20, 10), sticky="w")
        ctk.CTkLabel(self.unlock, text="Creates vault.enc if it doesn't exist.", font=ctk.CTkFont(size=12), text_color=self.COL_MUTED).grid(row=1, column=0, padx=18, pady=(0, 12), sticky="w")

        self.master_var = ctk.StringVar(value="")
        self.master_entry = ctk.CTkEntry(self.unlock, textvariable=self.master_var, height=42, fg_color="#0B1220", border_color=self.COL_BORDER, text_color=self.COL_TEXT, show="•", placeholder_text="Master password")
        self.master_entry.grid(row=2, column=0, padx=18, pady=(0, 14), sticky="ew")
        self.master_entry.focus()

        btn_row = ctk.CTkFrame(self.unlock, fg_color="transparent")
        btn_row.grid(row=3, column=0, padx=18, pady=(0, 10), sticky="ew")
        btn_row.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkButton(btn_row, text="Unlock", height=40, fg_color=self.COL_PURPLE, hover_color=self.COL_PURPLE_HOVER, text_color="white", command=self.try_unlock).grid(row=0, column=0, padx=(0, 8), sticky="ew")
        ctk.CTkButton(btn_row, text="Cancel", height=40, fg_color="#162235", hover_color="#1B2B44", text_color=self.COL_TEXT, command=self.destroy).grid(row=0, column=1, padx=(8, 0), sticky="ew")

        self.unlock_status = ctk.CTkLabel(self.unlock, text="", font=ctk.CTkFont(size=12), text_color=self.COL_WARN)
        self.unlock_status.grid(row=4, column=0, padx=18, pady=(0, 18), sticky="w")

        self.unlock.bind("<Return>", lambda _e: self.try_unlock())

    def try_unlock(self):
        mp = self.master_var.get()
        if not mp:
            self.unlock_status.configure(text="Enter a master password.")
            return
        try:
            v = load_vault(mp)
            if "entries" not in v:
                v = {"entries": []}
            save_vault(mp, v)
            self.master_password = mp
            self.unlock.destroy()
            self.set_status("Vault unlocked.", self.COL_GREEN)
            self.refresh_vault_view()
        except Exception as e:
            self.unlock_status.configure(text=f"Unlock failed: {e}")

    def on_set_token(self):
        try:
            set_token("api_key.json")
            self.set_status("Token saved.", self.COL_GREEN)
        except Exception as e:
            self.set_status(f"Token load failed: {e}", self.COL_DANGER)

    def on_slider(self, value):
        self.length_value.configure(text=str(int(round(value))))

    def on_copy(self):
        pwd = self.password_var.get().strip()
        if not pwd:
            self.set_status("Nothing to copy.", self.COL_WARN)
            return
        self.clipboard_clear()
        self.clipboard_append(pwd)
        self.set_status("Copied.", self.COL_GREEN)

    def on_generate(self):
        if self.is_generating:
            return
        self.is_generating = True
        self.generate_btn.configure(state="disabled")
        self.copy_btn.configure(state="disabled")
        self.set_status("Generating on IBM Quantum…", self.COL_MUTED)
        length = int(self.length_value.cget("text"))
        with_symbols = self.with_symbols.get()
        threading.Thread(target=self.worker_generate, args=(length, with_symbols), daemon=True).start()

    def worker_generate(self, length, with_symbols):
        try:
            pwd = generate_quantum_password(length=length, with_symbols=with_symbols)
            self.after(0, lambda: self.finish_generate(pwd, None))
        except Exception as e:
            self.after(0, lambda: self.finish_generate("", e))

    def finish_generate(self, pwd, err):
        if err:
            self.password_var.set("")
            self.set_status(f"Generation failed: {err}", self.COL_DANGER)
        else:
            self.password_var.set(pwd)
            self.set_status("Password generated.", self.COL_GREEN)
        self.generate_btn.configure(state="normal")
        self.copy_btn.configure(state="normal")
        self.is_generating = False

    def on_save_entry(self):
        if not self.master_password:
            self.set_status("Unlock vault first.", self.COL_WARN)
            self.show_unlock_modal()
            return

        site = self.site_var.get().strip()
        username = self.user_var.get().strip()
        password = self.password_var.get().strip()

        if not site or not username or not password:
            self.set_status("Need site, username, and a generated password.", self.COL_WARN)
            return

        try:
            add_entry(self.master_password, site, username, password)
            self.site_var.set("")
            self.user_var.set("")
            self.refresh_vault_view()
            self.set_status("Saved to vault.", self.COL_GREEN)
        except Exception as e:
            self.set_status(f"Save failed: {e}", self.COL_DANGER)

    def refresh_vault_view(self):
        for w in self.scroll.winfo_children():
            w.destroy()

        if not self.master_password:
            ctk.CTkLabel(self.scroll, text="Vault locked.", text_color=self.COL_MUTED).grid(row=0, column=0, sticky="w", pady=8)
            return

        q = self.search_var.get().strip().lower()
        try:
            entries = get_entries(self.master_password)
        except Exception as e:
            ctk.CTkLabel(self.scroll, text=f"Vault read error: {e}", text_color=self.COL_DANGER, wraplength=380, justify="left").grid(row=0, column=0, sticky="w", pady=8)
            return

        filtered = []
        for e in entries:
            s = (e.get("site", "") + " " + e.get("username", "")).lower()
            if not q or q in s:
                filtered.append(e)

        if not filtered:
            ctk.CTkLabel(self.scroll, text="No entries found.", text_color=self.COL_MUTED).grid(row=0, column=0, sticky="w", pady=8)
            return

        for i, e in enumerate(filtered):
            card = ctk.CTkFrame(self.scroll, fg_color="#0B1220", corner_radius=14, border_width=1, border_color=self.COL_BORDER)
            card.grid(row=i, column=0, sticky="ew", pady=8)
            card.grid_columnconfigure(0, weight=1)

            site = e.get("site", "")
            username = e.get("username", "")
            password = e.get("password", "")

            ctk.CTkLabel(card, text=site, font=ctk.CTkFont(size=14, weight="bold"), text_color=self.COL_TEXT).grid(row=0, column=0, padx=14, pady=(12, 2), sticky="w")
            ctk.CTkLabel(card, text=username, font=ctk.CTkFont(size=12), text_color=self.COL_MUTED).grid(row=1, column=0, padx=14, pady=(0, 10), sticky="w")

            actions = ctk.CTkFrame(card, fg_color="transparent")
            actions.grid(row=2, column=0, padx=14, pady=(0, 12), sticky="ew")
            actions.grid_columnconfigure((0, 1), weight=1)

            ctk.CTkButton(actions, text="Copy Password", height=34, fg_color="#162235", hover_color="#1B2B44", text_color=self.COL_TEXT, command=lambda p=password: self.copy_text(p)).grid(row=0, column=0, padx=(0, 8), sticky="ew")
            ctk.CTkButton(actions, text="Copy Username", height=34, fg_color="#162235", hover_color="#1B2B44", text_color=self.COL_TEXT, command=lambda u=username: self.copy_text(u)).grid(row=0, column=1, padx=(8, 0), sticky="ew")

    def copy_text(self, text):
        if not text:
            self.set_status("Nothing to copy.", self.COL_WARN)
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.set_status("Copied.", self.COL_GREEN)

    def set_status(self, msg, color):
        self.status.configure(text=msg, text_color=color)

if __name__ == "__main__":
    app = QuantumPasswordGUI()
    app.mainloop()