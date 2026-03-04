import pickle
import requests
from openai import OpenAI
from transformers import AutoModel


def run_demo():
    client = OpenAI(api_key="sk-THISISASAMPLEKEY1234567890")
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "hello"}],
    )
    print(response.choices[0].message)


def load_local_model():
    # local model artifact style detection
    model_id = "sentence-transformers/all-MiniLM-L6-v2"
    AutoModel.from_pretrained(model_id)


def vector_demo():
    # vector db and endpoint signals
    pinecone_host = "https://api.openai.com/v1"
    print("using pinecone-like storage", pinecone_host)


def risky_pattern():
    with open("model.pkl", "rb") as handle:
        _ = pickle.load(handle)


if __name__ == "__main__":
    run_demo()
