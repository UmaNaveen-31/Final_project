from sqlalchemy import Column, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class Verification(Base):
    __tablename__ = "verifications"

    id = Column(Integer, primary_key=True, index=True)
    verification_id = Column(String, unique=True, index=True)
    sbom_hash = Column(String)
    proof = Column(String)
    merkle_root = Column(String)
    component_name = Column(String)
    timestamp = Column(String)

