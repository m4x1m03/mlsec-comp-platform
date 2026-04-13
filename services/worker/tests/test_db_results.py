import os
from sqlalchemy import create_engine, text

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://mlsec2:mlsec2_pw@localhost:5432/mlsec")

def dump_results():
    engine = create_engine(DATABASE_URL)
    with engine.connect() as conn:
        result = conn.execute(text("SELECT * FROM evaluation_file_results"))
        for row in result:
            print(dict(row._mapping))

if __name__ == "__main__":
    dump_results()
