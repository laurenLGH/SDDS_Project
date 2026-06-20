from pathlib import Path

NVD_CSV_PATH   = Path(__file__).resolve().parent / "data" / "nvd_cves.csv"
KEV_CSV_PATH   = Path(__file__).resolve().parent / "data" / "kev.csv"
BLOGS_CSV_PATH = Path(__file__).resolve().parent / "data" / "blogs.csv"

CRITICALITY_WEIGHT = {"Critical": 1.2, "High": 1.0, "Medium": 0.7, "Low": 0.3}
KEV_MULTIPLIER     = {1: 1.5, 0: 1.0}

STOP_WORDS = {
    "and", "or", "the", "for", "in", "of", "a", "an", "&",
    "enterprise", "professional", "standard",
    "business", "corporate", "community",
    "advanced", "premium", "plus", "pro",
    "edition", "suite", "apps","application", "software", "solution",
    "service", "platform", "client",
    "server", "desktop",
}
