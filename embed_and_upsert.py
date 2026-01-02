import os
from qdrant_client import QdrantClient
from qdrant_client.http.models import VectorParams, Distance, PointStruct
from sentence_transformers import SentenceTransformer

CHUNK_FOLDER = "/home/i77/AS-Platform/chunked"
MODEL_PATH = "/home/i77/AS-Platform/models/bge-small-en-v1.5"
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
COLLECTION = "RAG_knowledge"

def main():

    print("[+] Loading embedding model...")
    model = SentenceTransformer(MODEL_PATH)
    VECTOR_SIZE = model.get_sentence_embedding_dimension()
    print(f"[+] Embedding dimension: {VECTOR_SIZE}")

    print("[+] Connecting to Qdrant...")
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)

    # Create collection
    print(f"[+] Creating Qdrant collection: {COLLECTION}")
    client.recreate_collection(
        collection_name=COLLECTION,
        vectors_config=VectorParams(
            size=VECTOR_SIZE,
            distance=Distance.COSINE   
        )
    )

    print("[+] Processing chunks...")
    points = []
    pid = 1

    for file in sorted(os.listdir(CHUNK_FOLDER)):
        path = os.path.join(CHUNK_FOLDER, file)

        if not file.endswith(".txt"):
            continue

        with open(path, "r", encoding="utf-8") as f:
            text = f.read().strip()

        if not text:
            continue

        emb = model.encode(text).tolist()

        points.append(
            PointStruct(
                id=pid,
                vector=emb,
                payload={"text": text, "source": file}
            )
        )

        pid += 1

        # batch upload
        if len(points) >= 64:
            client.upsert(collection_name=COLLECTION, points=points)
            points = []

    if points:
        client.upsert(collection_name=COLLECTION, points=points)

    print("[+] Done! All embeddings inserted into Qdrant.")

if __name__ == "__main__":
    main()