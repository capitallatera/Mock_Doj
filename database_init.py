from app.database import Base, engine, SessionLocal
from app.models.user import User, Organization, Role, PortalPage, RoleDetail
from app.models.blacklisted_token import BlacklistedToken
from app.auth_module.logic import get_password_hash
from sqlalchemy.orm import Session

def init_db():
    Base.metadata.create_all(bind=engine)
    db: Session = SessionLocal()
    try:
        # Create a default organization if it doesn't exist
        if not db.query(Organization).filter(Organization.name == "Default Org").first():
            default_org = Organization(name="Default Org")
            db.add(default_org)
            db.commit()
            db.refresh(default_org)
            print(f"Created organization: {default_org.name}")
        else:
            default_org = db.query(Organization).filter(Organization.name == "Default Org").first()

        # Create a default role if it doesn't exist
        if not db.query(Role).filter(Role.name == "Admin").first():
            admin_role = Role(name="Admin")
            db.add(admin_role)
            db.commit()
            db.refresh(admin_role)
            print(f"Created role: {admin_role.name}")
        else:
            admin_role = db.query(Role).filter(Role.name == "Admin").first()

        # Create a default portal page if it doesn't exist
        if not db.query(PortalPage).filter(PortalPage.endpoint == "/admin").first():
            admin_page = PortalPage(endpoint="/admin", name="Admin Dashboard")
            db.add(admin_page)
            db.commit()
            db.refresh(admin_page)
            print(f"Created portal page: {admin_page.name}")
        else:
            admin_page = db.query(PortalPage).filter(PortalPage.endpoint == "/admin").first()

        # Create role detail for admin role and admin page if it doesn't exist
        if not db.query(RoleDetail).filter(RoleDetail.role_id == admin_role.id, RoleDetail.portal_page_id == admin_page.id).first():
            admin_role_detail = RoleDetail(
                role_id=admin_role.id,
                portal_page_id=admin_page.id,
                create=True, view=True, edit=True, remove=True, export=True, print=True, send=True
            )
            db.add(admin_role_detail)
            db.commit()
            db.refresh(admin_role_detail)
            print(f"Created role detail for {admin_role.name} on {admin_page.name}")

        # Create a test user if it doesn't exist
        if not db.query(User).filter(User.username == "testuser").first():
            hashed_password = get_password_hash("testpassword")
            test_user = User(
                username="testuser",
                email="test@example.com",
                name="Test User",
                password=hashed_password,
                status=True,
                approval=True,
                role_id=admin_role.id,
                organization_id=default_org.id
            )
            db.add(test_user)
            db.commit()
            db.refresh(test_user)
            print(f"Created test user: {test_user.username}")
        else:
            print("Test user 'testuser' already exists.")

    finally:
        db.close()

if __name__ == "__main__":
    init_db()
