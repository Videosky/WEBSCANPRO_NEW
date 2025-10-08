import requests
import csv
import json
from bs4 import BeautifulSoup
import pandas as pd
import re
import os
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
import matplotlib.pyplot as plt
import plotly.express as px

# ==========================
# 1️⃣ SCRAPER SECTION
# ==========================
def scrape_quotes(url="https://quotes.toscrape.com/"):
    """
    Scrapes quotes, authors, and tags from the website.
    """
    print(f"Attempting to scrape data from: {url}")
    all_data = []
    page = 1

    while True:
        print(f"Scraping page {page}...")
        response = requests.get(f"{url}page/{page}/")
        if response.status_code != 200:
            break

        soup = BeautifulSoup(response.text, "html.parser")
        quotes = soup.select("div.quote")

        if not quotes:
            break

        for q in quotes:
            text = q.select_one("span.text").get_text(strip=True)
            author = q.select_one("small.author").get_text(strip=True)
            tags = [t.get_text(strip=True) for t in q.select("div.tags a.tag")]

            all_data.append({
                "quote": text,
                "author": author,
                "tags": ", ".join(tags)
            })

        page += 1

    print(f"✅ Scraped {len(all_data)} quotes total.")
    return all_data


def save_data(data, csv_filename="metadata.csv", json_filename="metadata.json"):
    """
    Save scraped data to CSV and JSON.
    """
    if not data:
        print("No data to save.")
        return

    # JSON
    with open(json_filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"✅ Saved {json_filename}")

    # CSV
    df = pd.DataFrame(data)
    df.to_csv(csv_filename, index=False, encoding="utf-8")
    print(f"✅ Saved {csv_filename}")


# ==========================
# 2️⃣ FEATURE + ML SECTION
# ==========================
def run_ml_pipeline(metadata_file="metadata.csv"):
    print(f"\n📊 Loading dataset: {metadata_file}")
    df = pd.read_csv(metadata_file)
    df.dropna(inplace=True)

    # Add text-based features
    df["quote_length"] = df["quote"].apply(len)
    df["num_special_chars"] = df["quote"].apply(lambda x: len(re.findall(r"[^a-zA-Z0-9\s]", x)))
    df["num_words"] = df["quote"].apply(lambda x: len(x.split()))
    df["has_exclamation"] = df["quote"].apply(lambda x: 1 if "!" in x else 0)

    # Simulated author popularity (based on frequency)
    author_counts = df["author"].value_counts()
    df["author_popularity"] = df["author"].map(author_counts)
    df["author_popularity"] = df["author_popularity"].apply(lambda x: 1 if x > 2 else 0)

    # Save extracted features
    feature_file = "features_extracted.csv"
    df.to_csv(feature_file, index=False)
    print(f"✅ Features saved as {feature_file}")

    # ==========================
    # 3️⃣ VISUALIZATION SECTION
    # ==========================
    sns.set(style="whitegrid", palette="muted")

    # --- Scatter plot (Seaborn) ---
    plt.figure(figsize=(8,6))
    sns.scatterplot(
        x="quote_length",
        y="num_words",
        hue="author_popularity",
        size="num_special_chars",
        data=df,
        palette="coolwarm",
        alpha=0.7,
        sizes=(50, 200)
    )
    plt.title("🔍 Quote Length vs Word Count (Colored by Popularity, Sized by Special Chars)")
    plt.xlabel("Quote Length (characters)")
    plt.ylabel("Number of Words")
    plt.legend(title="Author Popularity", loc="best")
    plt.tight_layout()
    plt.show()

    # --- Histogram of quote lengths ---
    plt.figure(figsize=(8,5))
    sns.histplot(df["quote_length"], bins=20, kde=True, color="skyblue")
    plt.title("📊 Distribution of Quote Lengths")
    plt.xlabel("Quote Length")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.show()

    # --- Bar chart of most common authors ---
    plt.figure(figsize=(10,6))
    top_authors = df["author"].value_counts().head(10)
    sns.barplot(x=top_authors.values, y=top_authors.index, palette="viridis")
    plt.title("👩‍🎓 Top 10 Authors by Quote Count")
    plt.xlabel("Number of Quotes")
    plt.ylabel("Author")
    plt.tight_layout()
    plt.show()

    # --- Correlation heatmap ---
    plt.figure(figsize=(6,4))
    corr = df[["quote_length","num_words","num_special_chars","has_exclamation","author_popularity"]].corr()
    sns.heatmap(corr, annot=True, cmap="coolwarm", fmt=".2f")
    plt.title("🔥 Feature Correlation Heatmap")
    plt.tight_layout()
    plt.show()

    # --- Pairplot ---
    sns.pairplot(df[["quote_length","num_words","num_special_chars","author_popularity"]],
                 hue="author_popularity", palette="coolwarm")
    plt.suptitle("💠 Pairwise Feature Relationships", y=1.02)
    plt.show()

    # ==========================
    # 4️⃣ SIMPLE ML
    # ==========================
    X = df[["quote_length", "num_words", "num_special_chars", "has_exclamation"]]
    y = df["author_popularity"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f"✅ Model trained successfully!")
    print(f"📈 Accuracy: {acc*100:.2f}%")

    # --- Interactive Scatter Plot (Plotly) ---
    fig = px.scatter(
        df,
        x="quote_length",
        y="num_words",
        color=df["author_popularity"].map({0: "Less Popular", 1: "Popular"}),
        size="num_special_chars",
        hover_data=["author", "tags"],
        title="🌈 Interactive Scatter: Quote Length vs Word Count",
        color_discrete_map={"Popular": "red", "Less Popular": "blue"}
    )
    fig.show()


# ==========================
# 5️⃣ MAIN EXECUTION
# ==========================
if __name__ == "__main__":
    print("Files will be saved in this directory:")
    print(os.getcwd())
    print("-" * 40)

    # Step 1: Scrape
    data = scrape_quotes()

    # Step 2: Save
    save_data(data)

    # Step 3: Extract + Visualize + ML
    if data:
        run_ml_pipeline("metadata.csv")

    print("-" * 40)
    print("🚀 Script finished successfully.")
