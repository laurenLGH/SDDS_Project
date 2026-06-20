from pathlib import Path

# Paths
DB_PATH = Path(__file__).resolve().parent.parent/"data"/"corpus.db"
GOLDEN_IMAGE_PATH = Path(__file__).resolve().parent.parent/"data"/"golden_image.csv"

# Ingestion settings
NVD_DAYS_BACK   = 20
BLOGS_DAYS_BACK = 20
