import networkx as nx
import hashlib
import random
import secrets
import matplotlib.pyplot as plt
from typing import Dict

def generate_3_colorable_graph(n=1000, p=0.01):
    G = nx.Graph()
    G.add_nodes_from(range(n))

    size = n // 3
    groups = {
        0: list(range(0, size)),
        1: list(range(size, 2 * size)),
        2: list(range(2 * size, 3 * size)),
    }

    leftover = list(range(3 * size, n))
    for i, node in enumerate(leftover):
        groups[i % 3].append(node)

    for a in range(3):
        for b in range(a + 1, 3):
            for u in groups[a]:
                for v in groups[b]:
                    if random.random() < p:
                        G.add_edge(u, v)

    password_coloring = {node: group for group, nodes in groups.items() for node in nodes}

    return G, password_coloring


def draw_local_graph(graph, colors, edge, round_num):
    plt.clf()
    u, v = edge

    neigh = set([u, v])
    neigh.update(graph.neighbors(u))
    neigh.update(graph.neighbors(v))

    sub = graph.subgraph(neigh)
    pos = nx.spring_layout(sub, seed=42)

    colormap = {0: "red", 1: "green", 2: "blue"}

    nx.draw(sub, pos,
            node_color=[colormap.get(colors.get(n), "gray") for n in sub.nodes()],
            edge_color="gray",
            node_size=120)

    nx.draw_networkx_edges(sub, pos, edgelist=[(u, v)], edge_color="yellow", width=3)

    plt.title(f"Round {round_num} — Zero-Knowledge Proof")
    plt.pause(0.1)

def password_to_coloring(password: str, graph: nx.Graph) -> Dict[int, int]:
    seed_value = int(hashlib.sha256(password.encode()).hexdigest(), 16)
    random.seed(seed_value)
    return {node: random.randint(0, 2) for node in graph.nodes()}

def passwords_match(graph, password_coloring, rounds=20, visualize=True) -> bool:
    edges = list(graph.edges())

    for r in range(1, rounds + 1):
        base = [0, 1, 2]
        random.shuffle(base)
        perm = {i: base[i] for i in range(3)}

        nonces = {}
        commitments = {}
        permuted = {}

        for v in graph.nodes():
            c = password_coloring[v]
            pc = perm[c]
            nonce = secrets.token_hex(16)

            commitments[v] = hashlib.sha256(f"{v}||{pc}||{nonce}".encode()).hexdigest()
            nonces[v] = nonce
            permuted[v] = pc

        u, v = random.choice(edges)

        check_u = hashlib.sha256(f"{u}||{permuted[u]}||{nonces[u]}".encode()).hexdigest() == commitments[u]
        check_v = hashlib.sha256(f"{v}||{permuted[v]}||{nonces[v]}".encode()).hexdigest() == commitments[v]
        diff = permuted[u] != permuted[v]

        if visualize:
            draw_local_graph(graph, permuted, (u, v), r)

        if not (check_u and check_v and diff):
            return False

    return True



if __name__ == "__main__":
    plt.ion()

    graph, correct_coloring = generate_3_colorable_graph()

    REAL_PASSWORD = "pass"

    entered = input("Enter password: ").strip()

    if entered == REAL_PASSWORD:
        test_coloring = correct_coloring
    else:
        test_coloring = password_to_coloring(entered, graph)

    ok = passwords_match(graph, test_coloring, rounds=40, visualize=True)

    if ok:
        print("\nCorrect Password")
    else:
        print("\nWrong Password")

    plt.ioff()
    plt.show()
