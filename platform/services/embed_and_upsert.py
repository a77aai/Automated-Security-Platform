#!/usr/bin/env python3
import json
from qdrant_client import QdrantClient
from qdrant_client.http.models import VectorParams, Distance, PointStruct, PayloadSchemaType
from sentence_transformers import SentenceTransformer

JSONL_PATH = "/home/i77/AS-Platform/attack_cards.jsonl"
MODEL_PATH = "/home/i77/AS-Platform/models/bge-small-en-v1.5"
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
COLLECTION = "RAG_detection_knowledge"

def main():
    print("[+] Loading embedding model...")
    model = SentenceTransformer(MODEL_PATH)
    vector_size = model.get_sentence_embedding_dimension()
    print(f"[+] Embedding dimension: {vector_size}")

    print("[+] Connecting to Qdrant...")
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)

    if client.collection_exists(COLLECTION):
        print(f"[+] Deleting existing collection: {COLLECTION}")
        client.delete_collection(collection_name=COLLECTION)

    print(f"[+] Creating collection: {COLLECTION}")
    client.create_collection(
        collection_name=COLLECTION,
        vectors_config=VectorParams(
            size=vector_size,
            distance=Distance.COSINE
        )
    )

    for field in ["doc_type", "platforms", "event_families", "tags"]:
        try:
            client.create_payload_index(
                collection_name=COLLECTION,
                field_name=field,
                field_schema=PayloadSchemaType.KEYWORD
            )
            print(f"[+] Indexed payload field: {field}")
        except Exception as e:
            print(f"[WARN] Could not index {field}: {e}")

    points = []
    pid = 1

    print("[+] Reading cards and generating embeddings...")
    with open(JSONL_PATH, "r", encoding="utf-8") as f:
        for line in f:
            card = json.loads(line)
            text = card.get("text", "").strip()
            if not text:
                continue

            emb = model.encode(text).tolist()
            payload = dict(card)

            points.append(
                PointStruct(
                    id=pid,
                    vector=emb,
                    payload=payload
                )
            )
            pid += 1

            if len(points) >= 64:
                client.upsert(
                    collection_name=COLLECTION,
                    points=points,
                    wait=True
                )
                print(f"[+] Uploaded batch of {len(points)} points")
                points = []

    if points:
        client.upsert(
            collection_name=COLLECTION,
            points=points,
            wait=True
        )
        print(f"[+] Uploaded final batch of {len(points)} points")

    print("[+] Done. Clean ATT&CK cards inserted into Qdrant.")

if __name__ == "__main__":
    main()