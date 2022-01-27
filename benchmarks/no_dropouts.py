import os.path

import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib import pyplot as plt
from datetime import datetime

from protocol import ClientProtocol, ServerProtocol
from time import perf_counter

from protocol.models.server_messages import BroadCastClientKeys


def benchmark(n_clients: int = 100, input_size: int = 10000, iterations: int = 100):
    client_protocol = ClientProtocol()
    server_protocol = ServerProtocol()

    setup_time = 0
    client_key_broadcast_time = 0
    server_key_broadcast_time = 0
    client_key_share_time = 0
    server_cipher_distribution_time = 0
    client_masked_input_time = 0
    server_mask_collection_time = 0
    client_process_unmask_broadcast_time = 0
    server_aggregate_time = 0
    for i in range(iterations):
        print(f"Iteration {i}")
        client_key_broadcasts = []

        client_keys = []
        for c in range(n_clients):
            user_id = f"user_{c}"

            # measure setup
            setup_start = perf_counter()
            keys, msg = client_protocol.setup()
            setup_end = perf_counter()
            setup_time += setup_end - setup_start

            client_keys.append(keys)

            # measure broadcast
            client_broadcast_start = perf_counter()
            client_key_bc = BroadCastClientKeys(user_id=user_id, broadcast=msg)
            client_broadcast_end = perf_counter()
            client_key_broadcast_time += client_broadcast_end - client_broadcast_start

            # add all the client broadcasts to the list
            client_key_broadcasts.append(client_key_bc)

        # measure server broadcast
        server_key_bc_start = perf_counter()
        server_key_broadcast = server_protocol.broadcast_keys(client_key_broadcasts)
        server_key_bc_end = perf_counter()
        server_key_broadcast_time += server_key_bc_end - server_key_bc_start

        # key sharing for all participants
        seeds = []
        client_key_share_messages = []
        for c in range(n_clients):
            user_id = f"user_{c}"
            key_share_start = perf_counter()
            seed, share_message = client_protocol.process_key_broadcast(
                keys=client_keys[c],
                user_id=user_id,
                broadcast=server_key_broadcast,
                k=3
            )

            key_share_end = perf_counter()
            client_key_share_time += key_share_end - key_share_start

            seeds.append(seed)
            client_key_share_messages.append(share_message)

        masked_inputs = []
        server_cipher_broadcasts = []
        for c in range(n_clients):
            user_id = f"user_{c}"

            # server process key shares and broadcast ciphers
            server_cipher_distribution_start = perf_counter()
            server_cipher_broadcast = server_protocol.broadcast_cyphers(user_id=user_id,
                                                                        shared_ciphers=client_key_share_messages)
            server_cipher_distribution_end = perf_counter()
            server_cipher_distribution_time += server_cipher_distribution_end - server_cipher_distribution_start

            server_cipher_broadcasts.append(server_cipher_broadcast)

            # client process ciphers and generate masked input
            client_masked_input_start = perf_counter()
            masked_input = client_protocol.process_cipher_broadcast(
                user_id=user_id,
                cipher_broadcast=server_cipher_broadcast,
                seed=seeds[c],
                input=np.zeros(input_size),
                participants=server_key_broadcast.participants,
                keys=client_keys[c]
            )
            client_masked_input_end = perf_counter()
            client_masked_input_time += client_masked_input_end - client_masked_input_start
            masked_inputs.append(masked_input)

        # server process masked inputs and broadcast unmask participants

        server_mask_collection_start = perf_counter()
        unmask_broadcast = server_protocol.broadcast_unmask_participants(masked_inputs)
        server_mask_collection_end = perf_counter()
        server_mask_collection_time += server_mask_collection_end - server_mask_collection_start

        unmask_shares = []
        for c in range(n_clients):
            user_id = f"user_{c}"
            client_process_unmask_broadcast_start = perf_counter()

            unmask_share = client_protocol.process_unmask_broadcast(
                user_id=user_id,
                keys=client_keys[c],
                cipher_broadcast=server_cipher_broadcasts[c],
                unmask_broadcast=unmask_broadcast,
                participants=server_key_broadcast.participants,
            )

            client_process_unmask_broadcast_end = perf_counter()
            client_process_unmask_broadcast_time += (
                    client_process_unmask_broadcast_end - client_process_unmask_broadcast_start)

            unmask_shares.append(unmask_share)

        # server process unmask shares and generate output
        server_aggregate_start = perf_counter()

        output = server_protocol.aggregate_masked_inputs(
            unmask_shares=unmask_shares,
            client_key_broadcasts=client_key_broadcasts,
            masked_inputs=masked_inputs
        )
        server_aggregate_end = perf_counter()
        server_aggregate_time += server_aggregate_end - server_aggregate_start

    results = {
        "n_clients": n_clients,
        "input_size": input_size,
        "client_setup_time": setup_time / (iterations * n_clients),
        "client_key_broadcast_time": client_key_broadcast_time / (iterations * n_clients),
        "client_key_share_time": client_key_share_time / (iterations * n_clients),
        "client_masked_input_time": client_masked_input_time / (iterations * n_clients),
        "client_process_unmask_broadcast_time": client_process_unmask_broadcast_time / (iterations * n_clients),
        "server_key_broadcast_time": server_key_broadcast_time / iterations,
        "server_cipher_distribution_time": server_cipher_distribution_time / (iterations * n_clients),
        "server_mask_collection_time": server_mask_collection_time / iterations,
        "server_aggregation_time": server_aggregate_time / iterations,
    }
    print("Results:")
    print(f"Client setup time: {results['client_setup_time']}")
    print(f"Client key broadcast time: {results['client_key_broadcast_time']}")
    print(f"Server key broadcast time: {results['server_key_broadcast_time']}")
    print(f"Client key share time: {results['client_key_share_time']}")
    print(f"Server cipher distribution time: {results['server_cipher_distribution_time']}")
    print(f"Client masked input time: {results['client_masked_input_time']}")
    print(f"Server mask collection time: {results['server_mask_collection_time']}")
    print(f"Client process unmask broadcast time: {results['client_process_unmask_broadcast_time']}")
    print(f"Server aggregate time: {results['server_aggregation_time']}")
    print(results)
    return results


def benchmark_n_clients():
    clients = [3, 5, 10, 15, 20, 30, 35, 40, 45, 50]
    results = {}
    input_size = 10000
    for n_clients in clients:
        print(f"\nRunning protocol with {n_clients} clients")
        print()
        result = benchmark(n_clients=n_clients, iterations=1, input_size=input_size)
        results[n_clients] = result

    results_df = pd.DataFrame(results).T

    now = datetime.now()
    date = now.strftime("%Y-%m-%d")
    results_df.to_csv(f"results/no_dropouts_benchmark_n_clients_{date}.csv")
    results_df.drop(columns=["input_size"], inplace=True)
    processed_df = pd.melt(results_df, id_vars=["n_clients"])
    print(processed_df.columns)

    sns.set(rc={'figure.figsize': (15, 8)})

    line_plot = sns.lineplot(data=processed_df, hue="variable", x="n_clients", y="value")

    plt.legend(loc="upper left")
    plt.ylabel("time (s)")
    plt.title(f"No dropouts benchmark n_clients - {date}")
    fig = line_plot.get_figure()
    fig.savefig(f"results/no_dropouts_benchmark_n_clients_{date}.png")
    plt.show()


def benchmark_input_size():
    input_sizes = [1000, 10000, 100000, 1000000]
    results = {}
    for size in input_sizes:
        print(f"\nRunning protocol with input size: {size}")
        print()
        result = benchmark(n_clients=20, iterations=1, input_size=size)
        results[size] = result

    results_df = pd.DataFrame(results).T

    now = datetime.now()
    date = now.strftime("%Y-%m-%d")
    results_df.to_csv(f"results/no_dropouts_benchmark_input_size_{date}.csv")
    results_df.drop(columns=["n_clients"], inplace=True)
    processed_df = pd.melt(results_df, id_vars=["input_size"])

    sns.set(rc={'figure.figsize': (15, 8)})

    line_plot = sns.lineplot(data=processed_df, hue="variable", x="input_size", y="value")

    plt.legend(loc="upper left")
    plt.ylabel("time (s)")
    plt.title(f"No dropouts benchmark input size - {date}")
    fig = line_plot.get_figure()
    fig.savefig(f"results/no_dropouts_benchmark_input_size_{date}.png")
    plt.show()


if __name__ == '__main__':
    if not os.path.isdir("results"):
        os.mkdir("results")
    # benchmark(n_clients=10, iterations=2)
    benchmark_n_clients()
    benchmark_input_size()
