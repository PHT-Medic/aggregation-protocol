import numpy as np

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
                broadcast=server_cipher_broadcast,
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

    print(f"Client setup time: {setup_time / (iterations * n_clients)}")
    print(f"Client key broadcast time: {client_key_broadcast_time / (iterations * n_clients)}")
    print(f"Server key broadcast time: {server_key_broadcast_time / iterations}")
    print(f"Client key share time: {client_key_share_time / (iterations * n_clients)}")
    print(f"Server cipher distribution time: {server_cipher_distribution_time / (iterations * n_clients)}")
    print(f"Client masked input time: {client_masked_input_time / (iterations * n_clients)}")
    print(f"Server mask collection time: {server_mask_collection_time / iterations}")
    print(f"Client process unmask broadcast time: {client_process_unmask_broadcast_time / (iterations * n_clients)}")
    print(f"Server aggregate time: {server_aggregate_time / iterations}")


if __name__ == '__main__':
    benchmark(n_clients=10, iterations=2)
