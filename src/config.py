from pathlib import Path

# Paths
DB_PATH           = Path(__file__).resolve().parent.parent/"data"/"corpus.db"
GOLDEN_IMAGE_PATH = Path(__file__).resolve().parent.parent/"data"/"golden_image.csv"

# Ingestion settings
NVD_DAYS_BACK   = 10
BLOGS_DAYS_BACK = 10

# Scoring weights (here so easy to change)
# Criticality weights based on golden image 
# KEV multiplier increases the score by 1.5X if its the vulnerabilitiy has been known to be exploited
CRITICALITY_WEIGHT = {"Critical": 1.2, "High": 1.0, "Medium": 0.7, "Low": 0.3}
KEV_MULTIPLIER     = {1: 1.5, 0: 1.0}

#NLP
STOP_WORDS = {
    "and", "or", "the", "for", "in", "of", "a", "an", "&",
    "enterprise", "professional", "standard",
    "business", "corporate", "community",
    "advanced", "premium", "plus", "pro",
    "edition", "suite", "apps","application", "software", "solution",
    "service", "platform", "client",
    "server", "desktop",
}
