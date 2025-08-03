#!/usr/bin/env python3
"""
Main Application for Signcryption System

Provides a user-friendly GUI for the Schmidt-Samoa & OSS signcryption system.
Implements the HCI recommendations from the professional analysis memo.

Author: Claude (Based on Professional Analysis Memo)
Date: August 2025
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import json
import os
from pathlib import Path
import threading

# Import our cryptographic modules
from key_generator import KeyGenerator, generate_schmidt_samoa_keys, generate_oss_keys
from schmidt_samoa import encrypt, decrypt
from oss_signature import sign, verify


class SigncryptionApp:
    """Main GUI application for the signcryption system."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Signcryption System: Schmidt-Samoa & OSS")
        self.root.geometry("800x700")
        
        # Initialize key storage
        self.current_ss_public = None
        self.current_ss_private = None
        self.current_oss_public = None
        self.current_oss_private = None
        
        # Create keys directory
        Path("keys").mkdir(exist_ok=True)
        
        self.setup_ui()
        self.show_security_warning()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Key Management
        self.setup_key_management_tab(notebook)
        
        # Tab 2: Protect Message (Sign + Encrypt)
        self.setup_protect_tab(notebook)
        
        # Tab 3: Open Message (Decrypt + Verify)
        self.setup_open_tab(notebook)
        
        # Tab 4: About & Security
        self.setup_about_tab(notebook)
    
    def setup_key_management_tab(self, notebook):
        """Set up the key management tab."""
        key_frame = ttk.Frame(notebook)
        notebook.add(key_frame, text="🔑 Key Management")
        
        # Title
        title_label = ttk.Label(key_frame, text="Key Management", font=("Arial", 16, "bold"))
        title_label.pack(pady=10)
        
        # Key generation section
        gen_frame = ttk.LabelFrame(key_frame, text="Generate New Keys", padding=10)
        gen_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(gen_frame, text="Key Size:").grid(row=0, column=0, sticky=tk.W)
        self.key_size_var = tk.StringVar(value="2048")
        key_size_combo = ttk.Combobox(gen_frame, textvariable=self.key_size_var, 
                                     values=["2048", "3072", "4096"], state="readonly")
        key_size_combo.grid(row=0, column=1, padx=5)
        
        ttk.Button(gen_frame, text="Generate Schmidt-Samoa Keys", 
                  command=self.generate_ss_keys).grid(row=1, column=0, columnspan=2, pady=5, sticky=tk.EW)
        ttk.Button(gen_frame, text="Generate OSS Keys", 
                  command=self.generate_oss_keys).grid(row=2, column=0, columnspan=2, pady=5, sticky=tk.EW)
        
        # Key loading section
        load_frame = ttk.LabelFrame(key_frame, text="Load Existing Keys", padding=10)
        load_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(load_frame, text="Load Schmidt-Samoa Public Key", 
                  command=lambda: self.load_key("ss_public")).grid(row=0, column=0, padx=5, pady=2, sticky=tk.EW)
        ttk.Button(load_frame, text="Load Schmidt-Samoa Private Key", 
                  command=lambda: self.load_key("ss_private")).grid(row=0, column=1, padx=5, pady=2, sticky=tk.EW)
        ttk.Button(load_frame, text="Load OSS Public Key", 
                  command=lambda: self.load_key("oss_public")).grid(row=1, column=0, padx=5, pady=2, sticky=tk.EW)
        ttk.Button(load_frame, text="Load OSS Private Key", 
                  command=lambda: self.load_key("oss_private")).grid(row=1, column=1, padx=5, pady=2, sticky=tk.EW)
        
        load_frame.grid_columnconfigure(0, weight=1)
        load_frame.grid_columnconfigure(1, weight=1)
        
        # Key status section
        status_frame = ttk.LabelFrame(key_frame, text="Key Status", padding=10)
        status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.key_status_text = scrolledtext.ScrolledText(status_frame, height=8, state=tk.DISABLED)
        self.key_status_text.pack(fill=tk.BOTH, expand=True)
        
        self.update_key_status()
    
    def setup_protect_tab(self, notebook):
        """Set up the protect message tab."""
        protect_frame = ttk.Frame(notebook)
        notebook.add(protect_frame, text="🔒 Protect Message")
        
        # Title
        title_label = ttk.Label(protect_frame, text="Protect Message (Sign + Encrypt)", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=10)
        
        # Message input
        input_frame = ttk.LabelFrame(protect_frame, text="Message to Protect", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.protect_message_text = scrolledtext.ScrolledText(input_frame, height=8)
        self.protect_message_text.pack(fill=tk.BOTH, expand=True)
        
        # Buttons
        button_frame = ttk.Frame(protect_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Load from File", 
                  command=self.load_message_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", 
                  command=lambda: self.protect_message_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        
        # Process button
        self.protect_button = ttk.Button(protect_frame, text="🔒 PROTECT MESSAGE", 
                                        command=self.protect_message, style="Accent.TButton")
        self.protect_button.pack(pady=10)
        
        # Output
        output_frame = ttk.LabelFrame(protect_frame, text="Protected Message (Encrypted)", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.protected_text = scrolledtext.ScrolledText(output_frame, height=8, state=tk.DISABLED)
        self.protected_text.pack(fill=tk.BOTH, expand=True)
        
        # Save button
        ttk.Button(protect_frame, text="Save Protected Message", 
                  command=self.save_protected_message).pack(pady=5)
    
    def setup_open_tab(self, notebook):
        """Set up the open message tab."""
        open_frame = ttk.Frame(notebook)
        notebook.add(open_frame, text="🔓 Open Message")
        
        # Title
        title_label = ttk.Label(open_frame, text="Open Message (Decrypt + Verify)", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=10)
        
        # Protected message input
        input_frame = ttk.LabelFrame(open_frame, text="Protected Message to Open", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.open_message_text = scrolledtext.ScrolledText(input_frame, height=6)
        self.open_message_text.pack(fill=tk.BOTH, expand=True)
        
        # Buttons
        button_frame = ttk.Frame(open_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Load from File", 
                  command=self.load_protected_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", 
                  command=lambda: self.open_message_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        
        # Process button
        self.open_button = ttk.Button(open_frame, text="🔓 OPEN MESSAGE", 
                                     command=self.open_message, style="Accent.TButton")
        self.open_button.pack(pady=10)
        
        # Verification status
        self.verification_frame = ttk.Frame(open_frame)
        self.verification_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.verification_label = ttk.Label(self.verification_frame, text="", 
                                           font=("Arial", 12, "bold"))
        self.verification_label.pack()
        
        # Decrypted message output
        output_frame = ttk.LabelFrame(open_frame, text="Decrypted Message", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.decrypted_text = scrolledtext.ScrolledText(output_frame, height=8, state=tk.DISABLED)
        self.decrypted_text.pack(fill=tk.BOTH, expand=True)
    
    def setup_about_tab(self, notebook):
        """Set up the about and security tab."""
        about_frame = ttk.Frame(notebook)
        notebook.add(about_frame, text="ℹ️ About & Security")
        
        about_text = scrolledtext.ScrolledText(about_frame, wrap=tk.WORD)
        about_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        about_content = """
SIGNCRYPTION SYSTEM: SCHMIDT-SAMOA & OSS

⚠️ CRITICAL SECURITY WARNING ⚠️

This application implements a signcryption system that combines:
- Schmidt-Samoa Cryptosystem for encryption
- Ong-Schnorr-Shamir (OSS) Digital Signature for authentication

IMPORTANT SECURITY NOTICE:
The OSS (Ong-Schnorr-Shamir) signature scheme used in this implementation is CRYPTOGRAPHICALLY BROKEN and vulnerable to forgery attacks. This system should NEVER be used for real-world security applications.

This implementation is provided for EDUCATIONAL PURPOSES ONLY to demonstrate:
- Signcryption concepts
- Software engineering best practices
- User interface design for cryptographic applications

FOR PRODUCTION USE:
Use industry-standard algorithms such as:
- RSA or ECC for encryption
- ECDSA or EdDSA for digital signatures
- Standardized libraries like OpenSSL

HOW IT WORKS:
1. PROTECT MESSAGE: The system first signs your message using OSS, then encrypts both the message and signature using Schmidt-Samoa
2. OPEN MESSAGE: The system decrypts the data, then verifies the signature to ensure authenticity

ARCHITECTURE:
- Sign-then-Encrypt approach
- Modular design with separate cryptographic components
- Clear user feedback for verification results
- Proper error handling and validation

DEVELOPED BY: Claude (AI Assistant)
BASED ON: Professional Analysis Memo
DATE: August 2025

Remember: This is a demonstration system. Use proven cryptographic libraries and algorithms for any real security needs.
"""
        
        about_text.insert(tk.END, about_content)
        about_text.config(state=tk.DISABLED)
    
    def show_security_warning(self):
        """Show security warning on startup."""
        warning_msg = (
            "⚠️ SECURITY WARNING ⚠️\n\n"
            "This application uses the OSS signature scheme which is "
            "CRYPTOGRAPHICALLY INSECURE and vulnerable to forgery attacks.\n\n"
            "This is for EDUCATIONAL PURPOSES ONLY.\n\n"
            "Never use this for real security applications!"
        )
        messagebox.showwarning("Security Warning", warning_msg)
    
    def generate_ss_keys(self):
        """Generate Schmidt-Samoa key pair."""
        try:
            key_size = int(self.key_size_var.get())
            
            def generate():
                self.update_status("Generating Schmidt-Samoa keys...")
                public_key, private_key = generate_schmidt_samoa_keys(key_size)
                
                # Save keys
                generator = KeyGenerator()
                generator.save_keys_to_file(public_key, "keys/schmidt_samoa_public.json")
                generator.save_keys_to_file(private_key, "keys/schmidt_samoa_private.json")
                
                self.current_ss_public = public_key
                self.current_ss_private = private_key
                
                self.root.after(0, lambda: [
                    self.update_key_status(),
                    self.update_status("Schmidt-Samoa keys generated successfully!"),
                    messagebox.showinfo("Success", "Schmidt-Samoa keys generated and saved!")
                ])
            
            threading.Thread(target=generate, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")
    
    def generate_oss_keys(self):
        """Generate OSS key pair."""
        try:
            key_size = int(self.key_size_var.get())
            
            def generate():
                self.update_status("Generating OSS keys (INSECURE!)...")
                public_key, private_key = generate_oss_keys(key_size)
                
                # Save keys
                generator = KeyGenerator()
                generator.save_keys_to_file(public_key, "keys/oss_public.json")
                generator.save_keys_to_file(private_key, "keys/oss_private.json")
                
                self.current_oss_public = public_key
                self.current_oss_private = private_key
                
                self.root.after(0, lambda: [
                    self.update_key_status(),
                    self.update_status("OSS keys generated (remember: INSECURE!)"),
                    messagebox.showwarning("Keys Generated", 
                                         "OSS keys generated!\n\n⚠️ Remember: OSS is cryptographically insecure!")
                ])
            
            threading.Thread(target=generate, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")
    
    def load_key(self, key_type):
        """Load key from file."""
        filename = filedialog.askopenfilename(
            title=f"Load {key_type.replace('_', ' ').title()}",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir="keys"
        )
        
        if filename:
            try:
                generator = KeyGenerator()
                key_data = generator.load_keys_from_file(filename)
                
                if key_type == "ss_public":
                    self.current_ss_public = key_data
                elif key_type == "ss_private":
                    self.current_ss_private = key_data
                elif key_type == "oss_public":
                    self.current_oss_public = key_data
                elif key_type == "oss_private":
                    self.current_oss_private = key_data
                
                self.update_key_status()
                messagebox.showinfo("Success", f"{key_type.replace('_', ' ').title()} loaded successfully!")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load key: {str(e)}")
    
    def update_key_status(self):
        """Update the key status display."""
        self.key_status_text.config(state=tk.NORMAL)
        self.key_status_text.delete(1.0, tk.END)
        
        status = "CURRENT KEY STATUS:\n\n"
        
        if self.current_ss_public:
            status += "✅ Schmidt-Samoa Public Key: Loaded\n"
            status += f"   Algorithm: {self.current_ss_public.get('algorithm', 'Unknown')}\n"
            status += f"   Key Size: {self.current_ss_public.get('key_size', 'Unknown')} bits\n\n"
        else:
            status += "❌ Schmidt-Samoa Public Key: Not loaded\n\n"
        
        if self.current_ss_private:
            status += "✅ Schmidt-Samoa Private Key: Loaded\n\n"
        else:
            status += "❌ Schmidt-Samoa Private Key: Not loaded\n\n"
        
        if self.current_oss_public:
            status += "✅ OSS Public Key: Loaded (⚠️ INSECURE!)\n"
            status += f"   Algorithm: {self.current_oss_public.get('algorithm', 'Unknown')}\n"
            status += f"   Key Size: {self.current_oss_public.get('key_size', 'Unknown')} bits\n\n"
        else:
            status += "❌ OSS Public Key: Not loaded\n\n"
        
        if self.current_oss_private:
            status += "✅ OSS Private Key: Loaded (⚠️ INSECURE!)\n\n"
        else:
            status += "❌ OSS Private Key: Not loaded\n\n"
        
        status += "REQUIREMENTS FOR OPERATION:\n"
        status += "• To PROTECT messages: Need OSS Private + Schmidt-Samoa Public\n"
        status += "• To OPEN messages: Need Schmidt-Samoa Private + OSS Public\n"
        
        self.key_status_text.insert(tk.END, status)
        self.key_status_text.config(state=tk.DISABLED)
    
    def load_message_file(self):
        """Load message from text file."""
        filename = filedialog.askopenfilename(
            title="Load Message File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.protect_message_text.delete(1.0, tk.END)
                self.protect_message_text.insert(tk.END, content)
                messagebox.showinfo("Success", "Message loaded successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def protect_message(self):
        """Protect message using sign-then-encrypt."""
        # Check required keys
        if not self.current_oss_private:
            messagebox.showerror("Error", "OSS Private Key required for signing!")
            return
        
        if not self.current_ss_public:
            messagebox.showerror("Error", "Schmidt-Samoa Public Key required for encryption!")
            return
        
        message = self.protect_message_text.get(1.0, tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Please enter a message to protect!")
            return
        
        try:
            def process():
                self.update_status("Signing message with OSS...")
                signature = sign(message, self.current_oss_private)
                
                # Combine message and signature
                combined_data = json.dumps({
                    'message': message,
                    'signature': signature,
                    'algorithm': 'OSS+Schmidt-Samoa'
                })
                
                self.update_status("Encrypting with Schmidt-Samoa...")
                encrypted_data = encrypt(combined_data, self.current_ss_public)
                
                # Update UI
                self.root.after(0, lambda: [
                    self.display_protected_message(encrypted_data),
                    self.update_status("Message protected successfully!"),
                    messagebox.showinfo("Success", "Message signed and encrypted successfully!")
                ])
            
            threading.Thread(target=process, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to protect message: {str(e)}")
    
    def display_protected_message(self, encrypted_data):
        """Display the protected message."""
        self.protected_text.config(state=tk.NORMAL)
        self.protected_text.delete(1.0, tk.END)
        self.protected_text.insert(tk.END, encrypted_data)
        self.protected_text.config(state=tk.DISABLED)
    
    def save_protected_message(self):
        """Save protected message to file."""
        content = self.protected_text.get(1.0, tk.END).strip()
        if not content:
            messagebox.showerror("Error", "No protected message to save!")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save Protected Message",
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Success", "Protected message saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
    
    def load_protected_file(self):
        """Load protected message from file."""
        filename = filedialog.askopenfilename(
            title="Load Protected Message",
            filetypes=[("Encrypted files", "*.enc"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.open_message_text.delete(1.0, tk.END)
                self.open_message_text.insert(tk.END, content)
                messagebox.showinfo("Success", "Protected message loaded successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def open_message(self):
        """Open message using decrypt-then-verify."""
        # Check required keys
        if not self.current_ss_private:
            messagebox.showerror("Error", "Schmidt-Samoa Private Key required for decryption!")
            return
        
        if not self.current_oss_public:
            messagebox.showerror("Error", "OSS Public Key required for verification!")
            return
        
        encrypted_data = self.open_message_text.get(1.0, tk.END).strip()
        if not encrypted_data:
            messagebox.showerror("Error", "Please enter encrypted data to open!")
            return
        
        try:
            def process():
                self.update_status("Decrypting with Schmidt-Samoa...")
                decrypted_json = decrypt(encrypted_data, self.current_ss_private)
                
                # Parse the combined data
                combined_data = json.loads(decrypted_json)
                original_message = combined_data['message']
                signature = combined_data['signature']
                
                self.update_status("Verifying signature with OSS...")
                is_valid = verify(original_message, signature, self.current_oss_public)
                
                # Update UI
                self.root.after(0, lambda: [
                    self.display_verification_result(is_valid),
                    self.display_decrypted_message(original_message if is_valid else ""),
                    self.update_status(f"Message opened. Signature {'VALID' if is_valid else 'INVALID'}!")
                ])
            
            threading.Thread(target=process, daemon=True).start()
            
        except Exception as e:
            self.root.after(0, lambda: [
                self.display_verification_result(False),
                self.display_decrypted_message(""),
                messagebox.showerror("Error", f"Failed to open message: {str(e)}")
            ])
    
    def display_verification_result(self, is_valid):
        """Display signature verification result with clear feedback."""
        if is_valid:
            self.verification_label.config(
                text="✅ SIGNATURE VALID - Message is authentic!",
                foreground="darkgreen",
                background="lightgreen"
            )
        else:
            self.verification_label.config(
                text="❌ WARNING: SIGNATURE INVALID - Message may be tampered!",
                foreground="darkred",
                background="lightpink"
            )
    
    def display_decrypted_message(self, message):
        """Display the decrypted message."""
        self.decrypted_text.config(state=tk.NORMAL)
        self.decrypted_text.delete(1.0, tk.END)
        if message:
            self.decrypted_text.insert(tk.END, message)
        else:
            self.decrypted_text.insert(tk.END, "[Message hidden due to invalid signature]")
        self.decrypted_text.config(state=tk.DISABLED)
    
    def update_status(self, message):
        """Update status (could be implemented as status bar)."""
        print(f"Status: {message}")


def main():
    """Main function to run the application."""
    root = tk.Tk()
    
    # Configure styles
    style = ttk.Style()
    style.theme_use('clam')
    
    # Create and run the application
    app = SigncryptionApp(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication closed by user.")
    except Exception as e:
        print(f"Application error: {e}")
        messagebox.showerror("Critical Error", f"Application error: {e}")


if __name__ == "__main__":
    main()