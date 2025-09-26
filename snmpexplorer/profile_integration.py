# profile_integration.py
from __future__ import annotations

import os
from typing import Optional
from tkinter import messagebox, simpledialog

from session_profile import SessionProfile


def merge_save_device_to_profile(
    parent_widget,
    profile_path: str,
    device_host: str,
    device_user: str,
    ask_password: bool = True,
    ssh_password: Optional[str] = None,
) -> bool:
    """
    Merge device + (optional) ssh_password into the profile.
    If the profile already contains encrypted fields, the user must provide
    the same password to keep using them.
    """
    profile_path = (profile_path or "").strip()
    if not profile_path:
        messagebox.showwarning("Profile", "Profile path is empty.")
        return False

    # Load or create
    if os.path.exists(profile_path):
        try:
            sp = SessionProfile.load(profile_path)
        except Exception as e:
            messagebox.showerror("Profile", f"Failed to load profile:\n{e}")
            return False
    else:
        sp = SessionProfile()

    # If we need to touch secrets, ask for a password
    pwd = None
    if ask_password:
        pwd = simpledialog.askstring(
            "Profile Password",
            "Enter a password to encrypt this profile (remember it!).",
            show="•",
            parent=parent_widget,
        )
        if not pwd:
            return False

    # If the profile already has encrypted items, verify password (if provided)
    def _verify_password_if_needed():
        if not pwd:
            return True
        # Try decrypting any existing secret so we fail early on wrong password
        try:
            if sp.grafana_token_enc:
                _ = sp.get_grafana_token(pwd)
            if sp.ssh_password_enc:
                _ = sp.get_ssh_password(pwd)
            return True
        except Exception as e:
            messagebox.showerror(
                "Profile",
                "Password does not match existing encrypted data in the profile.\n"
                "Use the same password you used previously.\n\n"
                f"Details: {e}"
            )
            return False

    if not _verify_password_if_needed():
        return False

    # Merge non-secrets
    sp.set_device(device_host or "", device_user or "")

    # Merge SSH password (encrypted) if provided and we have a profile password
    if ssh_password is not None:
        if not pwd:
            messagebox.showwarning(
                "Profile",
                "A profile password is required to encrypt and save the SSH password."
            )
            return False
        sp.set_ssh_password(pwd, ssh_password)

    try:
        sp.save(profile_path)
    except Exception as e:
        messagebox.showerror("Profile", f"Failed to save profile:\n{e}")
        return False

    messagebox.showinfo("Profile", f"Saved device details to:\n{profile_path}")
    return True


def load_device_from_profile(profile_path: str) -> Optional[tuple[str, str]]:
    """
    Load (device_host, device_user) from profile — no password required for these.
    """
    try:
        sp = SessionProfile.load(profile_path)
    except Exception:
        return None
    host = getattr(sp, "device_host", "") or ""
    user = getattr(sp, "device_user", "") or ""
    if not (host or user):
        return None
    return host, user


def load_ssh_password_from_profile(parent_widget, profile_path: str) -> Optional[str]:
    """
    Prompt for profile password and return decrypted SSH password, or None.
    """
    if not os.path.exists(profile_path):
        messagebox.showwarning("Profile", "Profile file not found.")
        return None
    try:
        sp = SessionProfile.load(profile_path)
    except Exception as e:
        messagebox.showerror("Profile", f"Failed to load profile:\n{e}")
        return None

    if not sp.ssh_password_enc:
        messagebox.showinfo("Profile", "No SSH password saved in this profile.")
        return None

    pwd = simpledialog.askstring(
        "Profile Password",
        "Enter your profile password to decrypt the SSH password:",
        show="•",
        parent=parent_widget,
    )
    if not pwd:
        return None

    try:
        return sp.get_ssh_password(pwd)
    except Exception as e:
        messagebox.showerror("Profile", f"Unable to decrypt SSH password:\n{e}")
        return None
