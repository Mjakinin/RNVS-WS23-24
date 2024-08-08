#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define BACKLOG 20 // number of packages queued

struct paths_tree
{
    char path_name[256];
    char content[8192];
    struct paths_tree *next;
} typedef paths_Node;

void add_Node(paths_Node **head, char *new_path, char *data_buf)
{
    paths_Node *newNode = malloc(sizeof(paths_Node));

    strncpy(newNode->path_name, new_path, 256);
    strncpy(newNode->content, data_buf, 8192);

    newNode->next = NULL;
    if (*head == NULL)
    {
        *head = newNode;
        return;
    }
    paths_Node *current = *head;

    while (current->next != NULL)
    {
        current = current->next;
    }
    current->next = newNode;
}

void freeList(paths_Node *head)
{
    paths_Node *current = head;
    while (current != NULL)
    {
        paths_Node *element = current->next;
        free(current);
        current = element;
    }
}

void send_response(int socket, int status_code)
{ // Hilfsfunktion zum checken der Request-> je nachdem was fuer eine Anfrage kommt, wird dementsprechend eine response generiert und gesendet
    const char *status_line;
    switch (status_code)
    {
    case 400:
        status_line = "HTTP/1.1 400 Bad Request\r\n\r\n";
        break;
    case 404:
        status_line = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        break;
    case 200:
        status_line = "HTTP/1.1 200 Ok\r\nContent-Length: 3\r\n\r\n";
        break;
    case 403:
        status_line = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        break;
    case 204:
        status_line = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
        break;
    case 201:
        status_line = "HTTP/1.1 201 Created\r\nContent-Length:0\r\n\r\n";
        break;
    default:
        status_line = "HTTP/1.1 501 Not Implemented\r\n\r\n";
        break;
    }
    send(socket, status_line, strlen(status_line), 0);
}

void send_response_with_payload(int socket, int payload_len)
{
    char status_line[100];
    snprintf(status_line, sizeof(status_line), "HTTP/1.1 200 Ok\r\nContent-Length: %d\r\n\r\n", payload_len);
    send(socket, status_line, strlen(status_line), 0);
}

char *is_valid_path_uri(char *uri)
{
    char *valid_path1 = "/static/foo";
    char *valid_path2 = "/static/bar";
    char *valid_path3 = "/static/baz";
    if (uri != NULL)
    {
        if (strcmp(uri, valid_path1) == 0)
        {
            return "Foo";
        }
        else if (strcmp(uri, valid_path2) == 0)
        {
            return "Bar";
        }
        else if (strcmp(uri, valid_path3) == 0)
        {
            return "Baz";
        }
        else
        {
            return NULL;
        }
    }
    else
    {
        return NULL;
    }
}

int is_dynamic_in_path(char *uri)
{
    char *dynamic = "dynamic/";
    if (uri != NULL)
    {
        if (strstr(uri, dynamic) != NULL)
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }
}

paths_Node *is_element_in_dynamicPaths(char *uri, paths_Node *head)
{
    paths_Node *current = head;
    while (current != NULL)
    {
        if (strcmp(uri, current->path_name) == 0)
        {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

void replace_node_content(char *uri, paths_Node *head, char *data_buf)
{
    if (head != NULL)
    {
        paths_Node *current = head;
        while (current != NULL)
        {
            if (strcmp(uri, current->path_name) == 0)
            {
                strncpy(current->content, data_buf, 8192);
                return;
            }
            current = current->next;
        }
    }
}

void delete_node(char *uri, paths_Node **head)
{
    if (*head != NULL)
    {
        paths_Node *prev = NULL;
        paths_Node *current = *head;

        // Check if the first node is the one to be deleted
        if (strcmp(uri, current->path_name) == 0)
        {
            *head = current->next; // Update head to the next node
            free(current);         // Free the deleted node
            return;
        }

        // Traverse the list to find the node to be deleted
        while (current != NULL)
        {
            if (strcmp(uri, current->path_name) == 0)
            {
                prev->next = current->next;
                current->next = NULL;
                free(current);
                return;
            }
            prev = current;
            current = current->next;
        }
    }
}

void reply_with_status(char *data_buf, char *end_of_header, int new_socket, paths_Node **head, int total_bytes)
{
    char data_buf_copy[8192] = "";
    strncpy(data_buf_copy, data_buf, sizeof(data_buf_copy) - 1);
    data_buf_copy[sizeof(data_buf_copy) - 1] = '\0';

    char *request_line = strtok((char *)data_buf_copy, "\r\n");
    if (request_line != NULL)
    {
        char *method = strtok(request_line, " ");
        char *uri = strtok(NULL, " ");
        char *http_version = strtok(NULL, " ");
        char *path_static = is_valid_path_uri(uri);

        if (method != NULL && uri != NULL && http_version != NULL)
        {
            // Checke welche methode verwendet wird und schicke dementsprechend die response
            paths_Node *path_dynamic = is_element_in_dynamicPaths(uri, *head);
            if (strcmp(method, "GET") == 0)
            {
                if (path_static != NULL)
                {
                    send_response(new_socket, 200);
                    send(new_socket, path_static, strlen(path_static), 0);
                }
                else if (is_dynamic_in_path(uri) == 1 && path_dynamic == NULL)
                {
                    send_response(new_socket, 404);
                }
                else if (is_dynamic_in_path(uri) == 1 && path_dynamic != NULL)
                {
                    send_response_with_payload(new_socket, strlen(path_dynamic->content));
                    send(new_socket, path_dynamic->content, strlen(path_dynamic->content), 0);
                }
                else{
                    send_response(new_socket, 404);
                }
            }
            else if ((strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0) && strstr(data_buf, "Content-Length") == NULL) // invalide Anfrage: keine Payload
            {
                send_response(new_socket, 400);
            }
            else if (strcmp(method, "PUT") == 0)
            {
                char *content_length_ptr = strstr(data_buf, "Content-Length:") + 16;
                char *content_length_str = strtok(content_length_ptr, "\r\n\r\n");
                int content_length = strtol(content_length_str, NULL, 10);
                int header_length = end_of_header - data_buf;
                header_length += 4;

                if (is_dynamic_in_path(uri) == 1 && path_dynamic != NULL)
                {
                    send_response(new_socket, 204);
                    while (total_bytes < (content_length + header_length))
                    {
                        int bytes = recv(new_socket, data_buf + total_bytes, 8192 - total_bytes, 0);
                        if (bytes <= 0)
                        { // daten vorhanden? Nein-> error
                            perror("Error receiving data");
                            bytes++;
                        }
                        total_bytes += bytes;
                    }
                    replace_node_content(uri, *head, end_of_header + 4);
                }
                else if (is_dynamic_in_path(uri) == 1 && path_dynamic == NULL)
                {
                    send_response(new_socket, 201);
                    while (total_bytes < (content_length + header_length))
                    {
                        int bytes = recv(new_socket, data_buf + total_bytes, 8192 - total_bytes, 0);
                        if (bytes <= 0)
                        { // daten vorhanden? Nein-> error
                            perror("Error receiving data");
                            bytes++;
                        }
                        total_bytes += bytes;
                    }
                    add_Node(head, uri, end_of_header + 4);
                }
                else
                {
                    send_response(new_socket, 403);
                }
            }
            else if (strcmp(method, "DELETE") == 0)
            {
                if (is_dynamic_in_path(uri) == 1 && path_dynamic != NULL)
                {
                    send_response(new_socket, 204);
                    delete_node(uri, head);
                }
                else if (is_dynamic_in_path(uri) == 1 && path_dynamic == NULL)
                {
                    send_response(new_socket, 404);
                }
                else
                {
                    send_response(new_socket, 403);
                }
            }
            else
            {
                send_response(new_socket, 501);
            }
        }
        else
        {
            send_response(new_socket, 400);
        }
    }
    else
    {
        send_response(new_socket, 400);
    }
}

int main(int argc, char *argv[])
{
    int status;
    struct addrinfo hints, *res;
    struct sockaddr_storage remote_addr; // this is where the information about the remote client goes
    socklen_t remote_addr_size = sizeof remote_addr;
    char *reply_msg = "Reply\r\n\r\n";
    int reply_msg_len = strlen(reply_msg);
    char *data_buf = malloc(8192);
    paths_Node *head = NULL; // for paths that are created under dynamic/ with PUT

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
    hints.ai_socktype = SOCK_STREAM;

    // check auf den richtigen call
    if (argc != 3)
    {
        fprintf(stderr, "Falscher Zugriff! Verwendung: %s <Adresse> <Port> \n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // schreibe die adress information in res
    if ((status = getaddrinfo(argv[1], argv[2], &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return 2;
    }
    // erstell den socket

    int server_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (server_socket == -1)
    {
        perror("Fehler beim Erstellen des Sockets");
        exit(EXIT_FAILURE);
    }

    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    // bind zum port
    if (bind(server_socket, res->ai_addr, res->ai_addrlen) == -1)
    {
        perror("Fehler beim Binden des Ports");
        exit(EXIT_FAILURE);
    };

    // listen to incoming connections and put them in queue with len=Backlog
    if (listen(server_socket, BACKLOG) == -1)
    {
        perror("Failure when listening to incoming connection!");
        exit(EXIT_FAILURE);
    }

    // zum bearbeiten mehrerer Requests
    while (1)
    {
        int new_socket = accept(server_socket, (struct sockaddr *)&remote_addr, &remote_addr_size);
        // setsockopt(new_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
        if (new_socket == -1)
        {
            perror("Failure when trying to accept incoming connection!");
            exit(EXIT_FAILURE);
        }
        // lese daten vom socket
        int total_bytes = 0;
        while (total_bytes <= 8192)
        {
            int bytes = recv(new_socket, data_buf + total_bytes, 8192 - total_bytes, 0);
            if (bytes <= 0)
            { // daten vorhanden? Nein-> error
                perror("Error receiving data");
                bytes++;
            }
            total_bytes += bytes;

            // check ob ende der request eine HTTP request ist
            char *end_of_header = strstr(data_buf, "\r\n\r\n");
            if (end_of_header != NULL)
            {
                // Berechne die laenge der anfrage mit header und path_static
                int request_length = end_of_header - (char *)data_buf;

                // analysiere die anfrage auf die methode,content und version
                    // setze den buffer zurück die nächste request
                    reply_with_status(data_buf, end_of_header, new_socket, &head, total_bytes);
                    memset(data_buf, 0, 8192);
                    total_bytes = 0;
            }
        }
        // schließ die connection des sockets
        close(new_socket);
    }
    // wenn alles vorbei ist, dann free res
    freeList(head);
    freeaddrinfo(res);
    free(data_buf);

    return 0;
}
