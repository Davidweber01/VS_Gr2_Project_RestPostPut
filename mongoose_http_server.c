#include <mongoose_http_server.h>
#include "mongoose.h"
#include "utils/uartstdio.h"
#include "utils/ustdlib.h"
#include "mjson/mjson.h"

#define SYSTICKHZ 100
#define SYSTICKMS (1000 / SYSTICKHZ)

struct mg_mgr g_mgr;

typedef struct
{
    int id;
    char name[50];
    char email[100];
} User;

#define MAX_USERS 100

// Define a format string for the JSON representation of a User
#define USER_JSON_FORMAT "{\n  \"id\": %d,\n  \"name\": \"%s\",\n  \"email\": \"%s\"\n}"

static User users_db[MAX_USERS];
static int users_count = 0;

User* get_user_by_id(int id);
void parse_user_from_request(struct http_message *hm, User *user);
int create_user(User new_user);
void parse_user_from_request(struct http_message *hm, User *user);
int update_user(int id, User updated_user);
char* user_to_json(const User *user);
char* users_to_json(const User *users, int count);
int extract_user_id(const char *uri);
void handle_get_request(struct http_message *hm, struct mg_connection *nc,
                        char addr[32]);
void handle_post_request(struct http_message *hm, struct mg_connection *nc,
                         char addr[32]);
void handle_put_request(struct http_message *hm, struct mg_connection *nc,
                        char addr[32]);
void send_ok_message(struct mg_connection *nc, char addr[32],
                     char json_buffer[256]);
void send_error_message(struct mg_connection *nc, char addr[32],
                        const char *message);

// The main Mongoose event handler.
void ev_handler(struct mg_connection *nc, int ev, void *ev_data)
{
    if (ev == MG_EV_POLL)
        return;

    switch (ev)
    {
    case MG_EV_ACCEPT:
    {
        char addr[32];
        mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr),
        MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);
        UARTprintf("%p: Connection from %s\r\n", nc, addr);
        break;
    }
    case MG_EV_HTTP_REQUEST:
    {
        struct http_message *hm = (struct http_message*) ev_data;
        char addr[32];
        mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr),
        MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);

        if (mg_vcmp(&hm->method, "GET") == 0)
        {
            handle_get_request(hm, nc, addr);
        }
        else if (mg_vcmp(&hm->method, "POST") == 0)
        {
            handle_post_request(hm, nc, addr);
        }
        else if (mg_vcmp(&hm->method, "PUT") == 0)
        {
            handle_put_request(hm, nc, addr);
        }
        else
        {
            send_error_message(nc, addr, "\r\nThis is not supported.\r\n");
        }
        nc->flags |= MG_F_SEND_AND_CLOSE;

        break;
    }
    case MG_EV_CLOSE:
    {
        UARTprintf("%p: Connection closed\r\n", nc);
        break;
    }
    }
}

void handle_get_request(struct http_message *hm, struct mg_connection *nc,
                        char addr[32])
{
    if (mg_vcmp(&hm->uri, "/users") == 0)
    {
        char *json_buffer = users_to_json(users_db, users_count);

        send_ok_message(nc, addr, json_buffer);

        // Free the allocated buffer
        free(json_buffer);
    }
    else
    {
        int user_id = extract_user_id(hm->uri.p);
        if (user_id >= 0)
        {
            User *user = get_user_by_id(user_id);
            if (user != NULL)
            {
                char *json_buffer = user_to_json(user);

                send_ok_message(nc, addr, json_buffer);

                // Free the allocated buffer
                free(json_buffer);
            }
            else
            {
                send_error_message(
                        nc, addr,
                        "\r\n<h1>No User found for this ID.</h1>\r\n");
            }
        }
        else
        {
            send_error_message(nc, addr,
                               "\r\n<h1>No User found for this ID.</h1>\r\n");
        }
    }
}

void handle_post_request(struct http_message *hm, struct mg_connection *nc,
                         char addr[32])
{
    if (mg_vcmp(&hm->uri, "/users") == 0)
    {
        User new_user;
        parse_user_from_request(hm, &new_user);

        // Ensure the ID is unique
        new_user.id = ++users_count;

        if (create_user(new_user))
        {
            char json_buffer[256];
            usnprintf(json_buffer, sizeof(json_buffer),
                      "{\"id\": %d, \"name\": \"%s\", \"email\": \"%s\"}",
                      new_user.id, new_user.name, new_user.email);

            send_ok_message(nc, addr, json_buffer);
        }
        else
        {
            send_error_message(nc, addr,
                               "\r\n<h1>Error creating new User.</h1>\r\n");
        }
    }
    else
    {
        send_error_message(nc, addr,
                           "\r\n<h1>This URI is not supported.</h1>\r\n");
    }
}

void handle_put_request(struct http_message *hm, struct mg_connection *nc,
                        char addr[32])
{
    int user_id = extract_user_id(hm->uri.p);
    if (user_id >= 0)
    {
        User updated_user;
        parse_user_from_request(hm, &updated_user);

        // Ensure the ID matches the URI ID
        updated_user.id = user_id;
        if (update_user(user_id, updated_user))
        {
            char json_buffer[256];
            usnprintf(json_buffer, sizeof(json_buffer),
                      "{\"id\": %d, \"name\": \"%s\", \"email\": \"%s\"}",
                      updated_user.id, updated_user.name, updated_user.email);
            send_ok_message(nc, addr, json_buffer);
        }
        else
        {
            send_error_message(nc, addr,
                               "\r\n<h1>Error updating new User.</h1>\r\n");
        }
    }
    else
    {
        send_error_message(nc, addr, "\r\n<h1>Invalid User ID.</h1>\r\n");
    }
}

void send_ok_message(struct mg_connection *nc, char addr[32],
                     char json_buffer[256])
{
    mg_send_response_line(nc, 200, "Content-Type: application/json\r\n"
                          "Connection: close");
    mg_printf(nc, "\r\n%s\r\n", json_buffer);
}

void send_error_message(struct mg_connection *nc, char addr[32],
                        const char *message)
{
    mg_send_response_line(nc, 400, "Content-Type: text/html\r\n"
                          "Connection: close");
    mg_printf(nc, message);
}

void parse_user_from_request(struct http_message *hm, User *user)
{
    char *buf = (char*) calloc(hm->body.len + 1, sizeof(char));
    if (buf == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for buffer\n");
        return;
    }

    memcpy(buf, hm->body.p, hm->body.len);
    buf[hm->body.len] = '\0'; // Null-terminate the JSON string

    // Extract id
    if (mjson_get_number(buf, hm->body.len, "$.id", (double*) user->id) <= 0)
    {
        user->id = -1; // Default value if not found
    }

    // Extract name
    if (mjson_get_string(buf, hm->body.len, "$.name", user->name,
                         sizeof(user->name)) <= 0)
    {
        user->name[0] = '\0'; // Default value if not found
    }

    // Extract email
    if (mjson_get_string(buf, hm->body.len, "$.email", user->email,
                         sizeof(user->email)) <= 0)
    {
        user->email[0] = '\0'; // Default value if not found
    }

    free(buf);
}

int update_user(int id, User updated_user)
{
    User *user = get_user_by_id(id);
    if (user != NULL)
    {
        *user = updated_user;
        return 1;
    }
    return 0;
}

User* get_user_by_id(int id)
{
    int i;
    for (i = 0; i < users_count; ++i)
    {
        if (users_db[i].id == id)
        {
            return &users_db[i];
        }
    }
    return NULL;
}

int extract_user_id(const char *uri)
{
    // Find the end of the URI segment
    const char *end = strchr(uri, ' ');
    if (end == NULL)
    {
        return -1; // Handle the error appropriately
    }

    // Locate the last '/' character in the URI
    const char *id_str = NULL;
    for (const char *p = uri; p < end; ++p)
    {
        if (*p == '/')
        {
            id_str = p;
        }
    }

    if (id_str == NULL || id_str >= end)
    {
        return -1; // Handle the error appropriately
    }

    id_str++; // Move past the '/'

    // Extract the user ID
    int user_id = atoi(id_str);
    if (user_id == 0 && *id_str != '0')
    {
        return -1; // Handle the error appropriately
    }

    return user_id;
}

int create_user(User new_user)
{
    if (users_count < MAX_USERS)
    {
        users_db[users_count - 1] = new_user;
        return 1;
    }
    return 0;
}

char* user_to_json(const User *user)
{
    // Calculate the required buffer size
    int len = snprintf(NULL, 0, USER_JSON_FORMAT, user->id, user->name,
                       user->email);

    if (len < 0)
    {
        fprintf(stderr, "Error calculating JSON length\n");
        return NULL;
    }

    // Allocate buffer with the exact required size (+1 for null terminator)
    char *buffer = (char*) malloc(len + 1);
    if (buffer == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for buffer\n");
        return NULL;
    }

    // Write JSON data for one user
    snprintf(buffer, len + 1, USER_JSON_FORMAT, user->id, user->name,
             user->email);

    return buffer;
}

char* users_to_json(const User *users, int count)
{
    // Estimate initial buffer size
    size_t buffer_size = 1024; // Start with a reasonable size
    char *buffer = (char*) malloc(buffer_size);
    if (buffer == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for buffer\n");
        return NULL;
    }

    // Initialize buffer
    buffer[0] = '\0';
    size_t len = 0;

    // Write opening bracket
    len += snprintf(buffer + len, buffer_size - len, "[\n");

    for (int i = 0; i < count; ++i)
    {
        char *user_json = user_to_json(&users[i]);
        if (user_json == NULL)
        {
            free(buffer);
            return NULL;
        }

        size_t user_json_len = strlen(user_json);
        if (len + user_json_len + 3 > buffer_size)
        { // 3 for ",\n\0"
            buffer_size = len + user_json_len + 3;
            buffer = (char*) realloc(buffer, buffer_size);
            if (buffer == NULL)
            {
                fprintf(stderr, "Failed to reallocate memory for buffer\n");
                free(user_json);
                return NULL;
            }
        }

        len += snprintf(buffer + len, buffer_size - len, "  %s", user_json);
        free(user_json);

        if (i < count - 1)
        {
            len += snprintf(buffer + len, buffer_size - len, ",\n");
        }
        else
        {
            len += snprintf(buffer + len, buffer_size - len, "\n");
        }
    }

    // Write closing bracket
    len += snprintf(buffer + len, buffer_size - len, "]\n");

    return buffer;
}
