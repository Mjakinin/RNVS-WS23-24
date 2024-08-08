#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/sha.h>

#include "data.h"
#include "http.h"
#include "util.h"

#define MAX_RESOURCES 100
#define MAX_UDP_REPLIES 10
#define MAX_NODES 3

//BONUS: greife auf CACHE zu und guck ob antwort schon vorhanden zu der und der resource

struct tuple resources[MAX_RESOURCES] = {
    {"/static/foo", "Foo", sizeof "Foo" - 1},
    {"/static/bar", "Bar", sizeof "Bar" - 1},
    {"/static/baz", "Baz", sizeof "Baz" - 1}};

dht_node node_dht;

chord_message replies[MAX_UDP_REPLIES] = {{0}};

int latest_reply = -1;

void send_lookup(uint16_t key)
{
    int dht_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (dht_socket == -1)
    {
        perror("UDP socket");
        exit(EXIT_FAILURE);
    }
    // send lookup
    struct sockaddr_in receiverAddress;
    memset(&receiverAddress, 0, sizeof(receiverAddress));
    receiverAddress.sin_family = AF_INET;
    receiverAddress.sin_addr.s_addr = inet_addr(node_dht.SUCC_IP);
    receiverAddress.sin_port = htons(node_dht.SUCC_PORT);

    uint32_t node_ip = htonl(inet_addr(node_dht.SELF_IP));
    if (node_ip == INADDR_NONE)
    {
        perror("IP Conversion failed");
        exit(EXIT_FAILURE);
    }
    chord_message lookup_msg = create_chordMessage(0, key, (uint16_t)node_dht.SELF_ID, node_ip, (uint16_t)node_dht.SELF_PORT);
    int bytes = sendto(dht_socket, &lookup_msg, sizeof(chord_message), 0, (struct sockaddr *)&receiverAddress, sizeof(receiverAddress));
    if (bytes == -1)
    {
        perror("sendto lookup");
        close(dht_socket);
        exit(EXIT_FAILURE);
    }
}

int found_node_responsible(uint16_t key)
{
    int found_node = 0;

    if (((key > (uint16_t)node_dht.SELF_ID) && (key <= (uint16_t)node_dht.SUCC_ID)) || ((node_dht.SELF_ID > node_dht.SUCC_ID) && (key > node_dht.SELF_ID || key < node_dht.SUCC_ID)))
    { // if the successor dht node is responsible for the resource
        found_node = 2;
    }
    else if ((node_dht.PRED_ID < node_dht.SELF_ID) && (key <= (uint16_t)node_dht.SELF_ID && key > (uint16_t)node_dht.PRED_ID))
    { // Wenn key weder im Zuständigkeitsbereich der Node noch des Nachfolgers
        found_node = 1;
    }
    else if ((node_dht.PRED_ID > node_dht.SELF_ID) && (key > (uint16_t)node_dht.PRED_ID || key <= (uint16_t)node_dht.SELF_ID))
    { // Spezialfall bei der im Uhrzeugersinn ersten Node
        found_node = 1;
    }
    return found_node;
}

// aufteilen: check_for_lookup() und send_lookup()

/**
 * Sends an HTTP reply to the client based on the received request.
 *
 * @param conn      The file descriptor of the client connection socket.
 * @param request   A pointer to the struct containing the parsed request information.
 */
void send_reply(int conn, struct request *request)
{

    // Create a buffer to hold the HTTP reply
    char buffer[HTTP_MAX_SIZE];
    char *reply = buffer;
    int redirect = 1;

    uint16_t key = hashPath(request->uri);

    // if node exists:
    if (node_dht.initialized == 1)
    {
        int node_found = found_node_responsible(key);
        if (node_found == 2)
        { // if the successor dht node is responsible for the resource
            sprintf(reply, "HTTP/1.1 303 See Other\r\nLocation: http://%s:%d%s\r\nContent-Length: 0\r\n\r\n", node_dht.SUCC_IP, node_dht.SUCC_PORT, request->uri);
        }
        else if (node_found == 0)
        { 
            if(latest_reply == -1){
                reply = "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n";
                send_lookup(key);
            }
            else{
                // Überarbeiten wegen falschem Verständnis: Array an replies ist als Cache gedacht, um Zugriff zu beschleunigen
                uint32_t ipAddress =  replies[latest_reply].node_ip;
                char ipAddressStr[INET_ADDRSTRLEN];
                sprintf(reply, "HTTP/1.1 303 See Other\r\nLocation: http://%s:%d%s\r\nContent-Length: 0\r\n\r\n",inet_ntop(AF_INET, &ipAddress, ipAddressStr, INET_ADDRSTRLEN), ntohs(replies[latest_reply].node_port), request->uri);
            }
        }
        else
        {
            redirect = 0;
        }
    }
    if (node_dht.initialized == 0 || !redirect)
    {

        // fprintf(stderr, "Handling %s request for %s (%lu byte payload)\n", request->method, request->payload_length);

        if (strcmp(request->method, "GET") == 0)
        {
            // Find the resource with the given URI in the 'resources' array.
            size_t resource_length;
            const char *resource = get(request->uri, resources, MAX_RESOURCES, &resource_length);

            if (resource)
            {
                sprintf(reply, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n%.*s", resource_length, (int)resource_length, resource);
            }
            else
            {
                reply = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            }
        }
        else if (strcmp(request->method, "PUT") == 0)
        {
            // Try to set the requested resource with the given payload in the 'resources' array.
            if (set(request->uri, request->payload, request->payload_length, resources, MAX_RESOURCES))
            {
                reply = "HTTP/1.1 204 No Content\r\n\r\n";
            }
            else
            {
                reply = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
            }
        }
        else if (strcmp(request->method, "DELETE") == 0)
        {
            // Try to delete the requested resource from the 'resources' array
            if (delete (request->uri, resources, MAX_RESOURCES))
            {
                reply = "HTTP/1.1 204 No Content\r\n\r\n";
            }
            else
            {
                reply = "HTTP/1.1 404 Not Found\r\n\r\n";
            }
        }
        else
        {
            reply = "HTTP/1.1 501 Method Not Supported\r\n\r\n";
        }
    }

    // Send the reply back to the client
    if (send(conn, reply, strlen(reply), 0) == -1)
    {
        perror("send");
        close(conn);
    }
}

/**
 * Processes an incoming packet from the client.
 *
 * @param conn The socket descriptor representing the connection to the client.
 * @param buffer A pointer to the incoming packet's buffer.
 * @param n The size of the incoming packet.
 *
 * @return Returns the number of bytes processed from the packet.
 *         If the packet is successfully processed and a reply is sent, the return value indicates the number of bytes processed.
 *         If the packet is malformed or an error occurs during processing, the return value is -1.
 *
 */
size_t process_packet(int conn, char *buffer, size_t n)
{
    struct request request = {
        .method = NULL,
        .uri = NULL,
        .payload = NULL,
        .payload_length = -1};
    ssize_t bytes_processed = parse_request(buffer, n, &request);

    if (bytes_processed > 0)
    {
        send_reply(conn, &request);

        // Check the "Connection" header in the request to determine if the connection should be kept alive or closed.
        const string connection_header = get_header(&request, "Connection");
        if (connection_header && strcmp(connection_header, "close"))
        {
            return -1;
        }
    }
    else if (bytes_processed == -1)
    {
        // If the request is malformed or an error occurs during processing, send a 400 Bad Request response to the client.
        const string bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(conn, bad_request, strlen(bad_request), 0);
        printf("Received malformed request, terminating connection.\n");
        close(conn);
        return -1;
    }

    return bytes_processed;
}

/**
 * Sets up the connection state for a new socket connection.
 *
 * @param state A pointer to the connection_state structure to be initialized.
 * @param sock The socket descriptor representing the new connection.
 *
 */
static void connection_setup(struct connection_state *state, int sock)
{
    // Set the socket descriptor for the new connection in the connection_state structure.
    state->sock = sock;

    // Set the 'end' pointer of the state to the beginning of the buffer.
    state->end = state->buffer;

    // Clear the buffer by filling it with zeros to avoid any stale data.
    memset(state->buffer, 0, HTTP_MAX_SIZE);
}

/**
 * Discards the front of a buffer
 *
 * @param buffer A pointer to the buffer to be modified.
 * @param discard The number of bytes to drop from the front of the buffer.
 * @param keep The number of bytes that should be kept after the discarded bytes.
 *
 * @return Returns a pointer to the first unused byte in the buffer after the discard.
 * @example buffer_discard(ABCDEF0000, 4, 2):
 *          ABCDEF0000 ->  EFCDEF0000 -> EF00000000, returns pointer to first 0.
 */
char *buffer_discard(char *buffer, size_t discard, size_t keep)
{
    memmove(buffer, buffer + discard, keep);
    memset(buffer + keep, 0, discard); // invalidate buffer
    return buffer + keep;
}

/**
 * Handles incoming connections and processes data received over the socket.
 *
 * @param state A pointer to the connection_state structure containing the connection state.
 * @return Returns true if the connection and data processing were successful, false otherwise.
 *         If an error occurs while receiving data from the socket, the function exits the program.
 */
bool handle_connection(struct connection_state *state)
{
    // Calculate the pointer to the end of the buffer to avoid buffer overflow
    const char *buffer_end = state->buffer + HTTP_MAX_SIZE;

    // Check if an error occurred while receiving data from the socket
    ssize_t bytes_read = recv(state->sock, state->end, buffer_end - state->end, 0);
    if (bytes_read == -1)
    {
        perror("recv");
        close(state->sock);
        exit(EXIT_FAILURE);
    }
    else if (bytes_read == 0)
    {
        return false;
    }

    char *window_start = state->buffer;
    char *window_end = state->end + bytes_read;

    ssize_t bytes_processed = 0;
    while ((bytes_processed = process_packet(state->sock, window_start, window_end - window_start)) > 0)
    {
        window_start += bytes_processed;
    }
    if (bytes_processed == -1)
    {
        return false;
    }

    state->end = buffer_discard(state->buffer, window_start - state->buffer, window_end - window_start);
    return true;
}

/**
 * Derives a sockaddr_in structure from the provided host and port information.
 *
 * @param host The host (IP address or hostname) to be resolved into a network address.
 * @param port The port number to be converted into network byte order.
 *
 * @return A sockaddr_in structure representing the network address derived from the host and port.
 */
static struct sockaddr_in derive_sockaddr(const char *host, const char *port)
{
    struct addrinfo hints = {
        .ai_family = AF_INET,
    };
    struct addrinfo *result_info;

    // Resolve the host (IP address or hostname) into a list of possible addresses.
    int returncode = getaddrinfo(host, port, &hints, &result_info);
    if (returncode)
    {
        fprintf(stderr, "Error parsing host/port");
        exit(EXIT_FAILURE);
    }

    // Copy the sockaddr_in structure from the first address in the list
    struct sockaddr_in result = *((struct sockaddr_in *)result_info->ai_addr);

    // Free the allocated memory for the result_info
    freeaddrinfo(result_info);
    return result;
}

/**
 * Sets up a TCP server socket and binds it to the provided sockaddr_in address.
 *
 * @param addr The sockaddr_in structure representing the IP address and port of the server.
 *
 * @return The file descriptor of the created TCP server socket.
 */
static int setup_server_socket(struct sockaddr_in addr)
{
    const int enable = 1;
    const int backlog = 1;

    // Create a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Avoid dead lock on connections that are dropped after poll returns but before accept is called
    if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1)
    {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }

    // Set the SO_REUSEADDR socket option to allow reuse of local addresses
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == -1)
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind socket to the provided address
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        perror("bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Start listening on the socket with maximum backlog of 1 pending connection
    if (listen(sock, backlog))
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return sock;
}

int setup_dht_socket(struct sockaddr_in addr)
{
    const int enable = 1;

    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket == -1)
    {
        perror("UDP socket");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == -1)
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    if (bind(udp_socket, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        perror("bind UDP");
        close(udp_socket);
        exit(EXIT_FAILURE);
    }
    return udp_socket;
}

int setup_dht_node(char **argv)
{
    int success = 1;
    if (getenv("PRED_ID") && getenv("PRED_IP") && getenv("PRED_PORT"))
    {
        node_dht.PRED_ID = atoi(getenv("PRED_ID"));
        node_dht.PRED_IP = getenv("PRED_IP");
        node_dht.PRED_PORT = atoi(getenv("PRED_PORT"));
    }
    else
    {
        success = -1;
    }
    if (getenv("SUCC_ID") && getenv("SUCC_IP") && getenv("SUCC_PORT"))
    {
        node_dht.SUCC_ID = atoi(getenv("SUCC_ID"));
        node_dht.SUCC_IP = getenv("SUCC_IP");
        node_dht.SUCC_PORT = atoi(getenv("SUCC_PORT"));
    }
    else
    {
        success = -1;
    }
    node_dht.SELF_ID = atoi(argv[3]);
    node_dht.SELF_IP = argv[1];
    node_dht.SELF_PORT = atoi(argv[2]);
    node_dht.initialized = 1;

    return success;
}

int add_to_replies(chord_message *msg){
    for(int i = 0; i < MAX_UDP_REPLIES; i++){
        if(replies[i].node_port == 0){
            replies[i] = *msg;
            return i;
        }
    }
    for(int j = 0; j < MAX_UDP_REPLIES-1; j++){
        replies[j] = replies[j+1];
    }
    replies[9] = *msg;
    return 9;
}


// Function to send a Join message to the anchor node
void send_join(const char *anchor_ip, int anchor_port, int self_id, const char *self_ip, int self_port) {
    int join_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (join_socket == -1) {
        perror("UDP socket");
        exit(EXIT_FAILURE);
    }

    // Manually set up the sockaddr_in structure for the anchor node
    struct sockaddr_in anchor_addr;
    memset(&anchor_addr, 0, sizeof(anchor_addr));
    anchor_addr.sin_family = AF_INET;
    anchor_addr.sin_addr.s_addr = inet_addr(anchor_ip);
    anchor_addr.sin_port = htons(anchor_port);

    // Create a Join message
    chord_message join_msg = create_chordMessage(4, 0, (uint16_t)self_id, htonl(inet_addr(self_ip)), (uint16_t)self_port);

    // Send the Join message to the anchor node
    int bytes_sent = sendto(join_socket, &join_msg, sizeof(chord_message), 0, (struct sockaddr *)&anchor_addr, sizeof(anchor_addr));
    if (bytes_sent == -1) {
        perror("sendto join");
        close(join_socket);
        exit(EXIT_FAILURE);
    }

    close(join_socket);
}


/**
 *  The program expects 3; otherwise, it returns EXIT_FAILURE.
 *
 *  Call as:
 *
 *  ./build/webserver self.ip self.port
 */
int main(int argc, char **argv)
{
    if (argc < 3)
    {
        return EXIT_FAILURE;
    }
    node_dht.initialized = 0;
    if (argc == 4)
    {
        if (setup_dht_node(argv) == -1)
        {
            perror("error in dht setup");
            exit(EXIT_FAILURE);
        }
    }

    if (argc == 6)
    {
        send_join(argv[4], atoi(argv[5]), atoi(argv[3]), argv[1], atoi(argv[2]));
    }

    struct sockaddr_in addr = derive_sockaddr(argv[1], argv[2]);

    // Set up a server socket.
    int server_socket = setup_server_socket(addr);

    int udp_socket = setup_dht_socket(addr);

    // Create an array of pollfd structures to monitor sockets.
    struct pollfd sockets[3] = {
        {.fd = server_socket, .events = POLLIN},
        {.fd = udp_socket, .events = POLLIN}};

    struct connection_state state = {0};
    while (true)
    {

        // Use poll() to wait for events on the monitored sockets.
        int ready = poll(sockets, sizeof(sockets) / sizeof(sockets[0]), -1);
        if (ready == -1)
        {
            perror("poll");
            exit(EXIT_FAILURE);
        }

        // Process events on the monitored sockets.
        for (size_t i = 0; i < sizeof(sockets) / sizeof(sockets[0]); i++)
        {
            if (sockets[i].revents != POLLIN)
            {
                // If there are no POLLIN events on the socket, continue to the next iteration.
                continue;
            }
            int s = sockets[i].fd;

            if (s == server_socket)
            {

                // If the event is on the server_socket, accept a new connection from a client.
                int connection = accept(server_socket, NULL, NULL);
                if (connection == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    close(server_socket);
                    perror("accept");
                    exit(EXIT_FAILURE);
                }
                else
                {
                    connection_setup(&state, connection);

                    // limit to one connection at a time
                    sockets[0].events = 0;
                    sockets[2].fd = connection;
                    sockets[2].events = POLLIN;
                }
            }
            else if (s == udp_socket)
            {
                struct sockaddr_in their_addr;
                socklen_t addr_len = sizeof(their_addr);
                char buf_udp[HTTP_MAX_SIZE];  // buffer wird jedes mal neu erstellt

                int bytes_read = recvfrom(udp_socket, buf_udp, HTTP_MAX_SIZE - 1, 0, (struct sockaddr *)&their_addr, &addr_len);
                if (bytes_read == -1)
                {
                    perror("Error when receiving UDP DGRAM");
                    exit(EXIT_FAILURE);
                }
                // lookup reply
                chord_message *received_message = (chord_message *)buf_udp;
                int node_found = found_node_responsible(ntohs(received_message->hash_id));
                if (node_found == 0 && received_message->message_type != 1)
                {
                    int redirect_socket = socket(AF_INET, SOCK_DGRAM, 0);
                    if (redirect_socket == -1)
                    {
                        perror("UDP socket");
                        exit(EXIT_FAILURE);
                    }
                    struct sockaddr_in nextAddr;
                    memset(&nextAddr, 0, sizeof(nextAddr));
                    nextAddr.sin_family = AF_INET;
                    nextAddr.sin_addr.s_addr = inet_addr(node_dht.SUCC_IP);
                    nextAddr.sin_port = htons(node_dht.SUCC_PORT);
                    chord_message *lookup_msg = (chord_message *)buf_udp;
                    int bytes = sendto(redirect_socket, lookup_msg, sizeof(chord_message), 0, (struct sockaddr *)&nextAddr, sizeof(nextAddr));
                    if (bytes == -1)
                    {
                        perror("sendto lookup");
                        close(redirect_socket);
                        exit(EXIT_FAILURE);
                    }
                    // wenn nicht selbst oder nächster node verantwortlich -> noch einen lookup an nächste node schicken
                }
                else if ((node_found == 1 || node_found == 2) && received_message->message_type != 1)
                {
                    // sonst: their_addr aus recv nehmen, neuen socket erstellen und dann reply im format senden
                    int dht_socket = socket(AF_INET, SOCK_DGRAM, 0);
                    if (dht_socket == -1)
                    {
                        perror("UDP socket");
                        exit(EXIT_FAILURE);
                    }
                    fprintf(stderr, "Replying in UDP now...\n\n");
                    // fprintf(stderr, "their_addr IP: %s\n their_addr Port: %d\n\n", inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port));
                    chord_message lookup_msg;
                    if (node_found == 1)
                    {
                        lookup_msg = create_chordMessage(1, (uint16_t)node_dht.SELF_ID, (uint16_t)node_dht.SELF_ID, htonl(inet_addr(node_dht.SELF_IP)), (uint16_t)node_dht.SELF_PORT);
                    }
                    else
                    {
                        lookup_msg = create_chordMessage(1, (uint16_t)node_dht.SELF_ID, (uint16_t)node_dht.SUCC_ID, htonl(inet_addr(node_dht.SUCC_IP)), (uint16_t)node_dht.SUCC_PORT);
                    }
                    struct sockaddr_in requestAddr;
                    memset(&requestAddr, 0, sizeof(requestAddr));
                    requestAddr.sin_family = AF_INET;
                    requestAddr.sin_addr.s_addr = received_message->node_ip;
                    requestAddr.sin_port = received_message->node_port;

                    int bytes = sendto(dht_socket, &lookup_msg, sizeof(chord_message), 0, (struct sockaddr *)&requestAddr, sizeof(requestAddr));
                    if (bytes == -1)
                    {
                        perror("sendto lookup");
                        close(dht_socket);
                        exit(EXIT_FAILURE);
                    }
                }
                else if(received_message -> message_type == 1){
                    latest_reply = add_to_replies(received_message);
                }
                // wenn message type == 1 -> empfangene Antwort speichern, neueste zurückgeben über HTTP TCP stream (303)
            }
            else
            {
                assert(s == state.sock);

                // Call the 'handle_connection' function to process the incoming data on the socket.
                bool cont = handle_connection(&state);
                if (!cont)
                { // get ready for a new connection
                    sockets[0].events = POLLIN;
                    sockets[2].fd = -1;
                    sockets[2].events = 0;
                }
            }
        }
    }
    close(udp_socket);
    close(server_socket);

    return EXIT_SUCCESS;
}

/**
 * Aktuelles Verständnis zu recvfrom() in UDP: Wir empfangen eine Message, nehmen sie in den Buffer auf, resetten den Buffer dann wieder und schließen dann die Verbindung?
 * -> also keine Synthese von aufeinanderfolgenden Nachrichten / Anfragen zu einer vollständigen ?
 * their_addr ist nach recvfrom() NULL?
 * node_index ist lokal immer auf -1 nach poll() geworden
 * http reply funktioniert auch mit send() statt sendto() obwohl udp socket? ???????
 * Folgendes Muster: wir erhalten Anfrage -> wenn nicht wir verantwortlich, dann send() an anderen SUCC_Port, SUCC_port empfängt nachricht mit recvfrom() -> send() an PRED_PORT
 * Sockets werden bei Erstellen der dht nodes beim Aufruf erstellt -> jeder aufruf ruft die main funkion auf und kreiert damit einen neuen unabhängigen socket mit eigenem port -> array an node_dht unnötig
 * jeder sock man kann direkt an einen succ_port senden , da udp_socket vorhanden
 */