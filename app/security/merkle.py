import hashlib


def hash_leaf(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_pair(left, right):
    return hashlib.sha256(
        (left + right).encode("utf-8")
    ).hexdigest()


def build_merkle_root(values):
    if not values:
        raise ValueError("At least one value is required")

    level = [hash_leaf(value) for value in values]

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])

        next_level = []

        for i in range(0, len(level), 2):
            next_level.append(
                hash_pair(level[i], level[i + 1])
            )

        level = next_level

    return level[0]


def build_merkle_proof(values, index):
    if not values:
        raise ValueError("At least one value is required")

    if index < 0 or index >= len(values):
        raise IndexError("Invalid claim index")

    level = [hash_leaf(value) for value in values]
    proof = []
    current_index = index

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])

        sibling_index = current_index - 1 if current_index % 2 else current_index + 1

        proof.append({
            "hash": level[sibling_index],
            "position": "left" if sibling_index < current_index else "right"
        })

        next_level = []

        for i in range(0, len(level), 2):
            next_level.append(hash_pair(level[i], level[i + 1]))

        current_index //= 2
        level = next_level

    return proof


def verify_merkle_proof(value, proof, root):
    current_hash = hash_leaf(value)

    for step in proof:
        if step["position"] == "left":
            current_hash = hash_pair(step["hash"], current_hash)
        else:
            current_hash = hash_pair(current_hash, step["hash"])

    return current_hash == root
