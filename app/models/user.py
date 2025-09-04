from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    name = Column(String)
    password = Column(String)
    status = Column(Boolean, default=True)
    approval = Column(Boolean, default=False)
    avatar = Column(String, nullable=True)
    refresh_token_jti = Column(String, nullable=True)

    role_id = Column(Integer, ForeignKey("roles.id"), nullable=True)
    role = relationship("Role", back_populates="users")

    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    organization = relationship("Organization", back_populates="users")

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)

    users = relationship("User", back_populates="organization")

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)

    users = relationship("User", back_populates="role")
    details = relationship("RoleDetail", back_populates="role")

class PortalPage(Base):
    __tablename__ = "portal_pages"

    id = Column(Integer, primary_key=True, index=True)
    endpoint = Column(String, unique=True, index=True)
    name = Column(String)

    role_details = relationship("RoleDetail", back_populates="portal_page")

class RoleDetail(Base):
    __tablename__ = "role_details"

    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"))
    portal_page_id = Column(Integer, ForeignKey("portal_pages.id"))
    create = Column(Boolean, default=False)
    view = Column(Boolean, default=False)
    edit = Column(Boolean, default=False)
    remove = Column(Boolean, default=False)
    export = Column(Boolean, default=False)
    print = Column(Boolean, default=False)
    send = Column(Boolean, default=False)

    role = relationship("Role", back_populates="details")
    portal_page = relationship("PortalPage", back_populates="role_details")
