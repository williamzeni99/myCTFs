import socket
import time

def communicate_with_server(server_host, server_port, message):
    # Creazione del socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connessione al server
        client_socket.connect((server_host, server_port))

        # Invio del messaggio al server
        client_socket.sendall(message[0])
        time.sleep(0.1)
        client_socket.sendall(message[1])
        # Ricezione della risposta dal server
        time.sleep(0.1)
        data = client_socket.recv(1024)
        print()

    except Exception as e:
        print(f"Errore durante la comunicazione con il server: {e}")

    finally:
        # Chiusura del socket
        client_socket.close()

# Esempio di utilizzo
server_host = "bin.training.offdef.it"  # Sostituire con l'indirizzo del server
server_port = 4010        # Sostituire con la porta del server
messages_to_send = [b'\x04\x00\x00\x00\x00\x00\x00\x00', b'data']

communicate_with_server(server_host, server_port, messages_to_send)

