"""Create the first PhishGuard owner from a trusted server/local shell.

Set PHISHGUARD_OWNER_EMAIL before running:
    python -m scripts.create_owner

This command does not expose an HTTP owner-registration endpoint.
"""
import getpass
import os
import re

from backend.database.auth_service import auth_service


def main():
    configured = os.getenv("PHISHGUARD_OWNER_EMAIL", "").strip().lower()
    if not configured:
        raise SystemExit("Set PHISHGUARD_OWNER_EMAIL to the intended owner email before running this command.")

    email = input("Owner email: ").strip().lower()
    if email != configured:
        raise SystemExit("The entered email must exactly match PHISHGUARD_OWNER_EMAIL.")

    password = getpass.getpass("Create owner password (12–128 characters): ")
    confirm = getpass.getpass("Confirm owner password: ")
    if password != confirm:
        raise SystemExit("Passwords do not match.")
    if not 12 <= len(password) <= 128:
        raise SystemExit("Password must contain 12 to 128 characters.")

    auth_service.initialize()
    with auth_service.connection() as db:
        existing = db.execute("SELECT id,email FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
        if existing:
            db.execute(
                "UPDATE users SET email_verified=1,email_verified_at=COALESCE(email_verified_at,CURRENT_TIMESTAMP),is_active=1,session_version=session_version+1 WHERE id=?",
                (existing["id"],),
            )
            from werkzeug.security import generate_password_hash
            db.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(password, method="scrypt"), existing["id"]))
            user_id = existing["id"]
            action = "Existing account verified and owner password reset."
        else:
            user = auth_service.create_user(email, password)
            user_id = user["id"]
            db.execute(
                "UPDATE users SET email_verified=1,email_verified_at=CURRENT_TIMESTAMP WHERE id=?",
                (user_id,),
            )
            action = "Owner account created and email marked verified."

    print(action)
    print(f"Owner account ID: {user_id}")
    print("Next: restart PhishGuard and open /admin/login.")
    print("Keep PHISHGUARD_OWNER_EMAIL configured in the server environment.")


if __name__ == "__main__":
    main()
