import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import getpass

from werkzeug.security import generate_password_hash

from app import create_app, db
from app.models import Role, User

app = create_app()

DEFAULT_ROLES = ["Admin", "Developer", "Approver", "Viewer"]


def create_admin():
    with app.app_context():
        for role_name in DEFAULT_ROLES:
            role = Role.query.filter_by(name=role_name).first()

            if role is None:
                db.session.add(Role(name=role_name))

        db.session.commit()

        full_name = input("Administrator full name: ").strip()
        email = input("Administrator email: ").strip().lower()
        password = getpass.getpass("Administrator password: ")
        confirm_password = getpass.getpass("Confirm password: ")

        if not full_name or not email:
            print("Name and email are required.")
            return

        if password != confirm_password:
            print("Passwords do not match.")
            return

        if len(password) < 12:
            print("Use a password with at least 12 characters.")
            return

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            print("A user with that email already exists.")
            return

        admin_role = Role.query.filter_by(name="Admin").first()

        admin = User(
            full_name=full_name,
            email=email,
            password_hash=generate_password_hash(password),
            role_id=admin_role.id,
            is_active=True,
        )

        db.session.add(admin)
        db.session.commit()

        print(f"Administrator created successfully: {email}")


if __name__ == "__main__":
    create_admin()
