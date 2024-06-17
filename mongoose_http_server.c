#include <mongoose_http_server.h>
#include "mongoose.h"

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

static User users_db[MAX_USERS];
static int users_count = 0;

// The main Mongoose event handler.
void ev_handler(struct mg_connection *nc, int ev, void *ev_data)
{
    static int led_value = 0;
    if (ev == MG_EV_POLL)
        return;
    // UARTprintf("%p: ev %d\r\n", nc, ev);
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
            if (mg_vcmp(&hm->uri, "/users") == 0)
            {
                char *json_buffer = users_to_json(users_db, users_count);

                mg_send_response_line(nc, 200,
                                      "Content-Type: application/json\r\n"
                                      "Connection: close");
                mg_printf(nc, "\r\n%s\r\n", json_buffer);

                // Free the allocated buffer
                free(json_buffer);
            }
        }
        else if (mg_vcmp(&hm->method, "POST") == 0)
        {
            if (mg_vcmp(&hm->uri, "/users") == 0)
            {
                User new_user;
                parse_user_from_request(hm, &new_user);

                // Ensure the ID is unique
                new_user.id = ++users_count;

                if (create_user(new_user))
                {
                    char user_json[256];
                    usnprintf(
                            user_json, sizeof(user_json),
                            "{\"id\": %d, \"name\": \"%s\", \"email\": \"%s\"}",
                            new_user.id, new_user.name, new_user.email);

                    mg_send_response_line(nc, 200,
                                          "Content-Type: application/json\r\n"
                                          "Connection: close");
                    mg_printf(nc, "\r\n%s\r\n", user_json);

                    //free(user_json);
                }
                else
                {
                    mg_send_response_line(nc, 200, "Content-Type: text/html\r\n"
                                          "Connection: close");
                    mg_printf(nc, "\r\n<h1>Error creating new User.</h1>\r\n",
                              addr, (int) hm->uri.len, hm->uri.p);
                }
            }
        }
        else if (mg_vcmp(&hm->method, "PUT") == 0)
        {
            int user_id = extract_user_id(hm->uri);
            if (user_id >= 0)
            {
                User updated_user;
                parse_user_from_request(hm, &updated_user);

                // Ensure the ID matches the URI ID
                updated_user.id = user_id;
                if (update_user(user_id, updated_user))
                {
                    char user_json[256];
                    usnprintf(
                            user_json, sizeof(user_json),
                            "{\"id\": %d, \"name\": \"%s\", \"email\": \"%s\"}",
                            updated_user.id, updated_user.name,
                            updated_user.email);
                    mg_send_response_line(nc, 200,
                                          "Content-Type: application/json\r\n"
                                          "Connection: close");
                    mg_printf(nc, "\r\n%s\r\n", user_json);
                }
                else
                {
                    mg_send_response_line(nc, 200, "Content-Type: text/html\r\n"
                                          "Connection: close");
                    mg_printf(nc, "\r\n<h1>Error updating new User.</h1>\r\n",
                              addr, (int) hm->uri.len, hm->uri.p);
                }
            }
            else
            {
                mg_send_response_line(nc, 200, "Content-Type: text/html\r\n"
                                      "Connection: close");
                mg_printf(nc, "\r\n<h1>Invalid User ID.</h1>\r\n", addr,
                          (int) hm->uri.len, hm->uri.p);
            }

        }
        else
        {
            UARTprintf("%p: HTTP request\r\n", nc);
            mg_send_response_line(nc, 200, "Content-Type: text/html\r\n"
                                  "Connection: close");
            mg_printf(nc, "\r\n<h1>Hello, %s!</h1>\r\n"
                      "You asked for %.*s\r\n",
                      addr, (int) hm->uri.len, hm->uri.p);
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
    if (mjson_get_number(buf, hm->body.len, "$.id", &user->id) <= 0)
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

char* users_to_json(const User *users, int count)
{
    // Calculate buffer size
    size_t buffer_size = 2; // For the opening and closing brackets
    for (int i = 0; i < count; ++i)
    {
        // Estimating size for each user's JSON representation
        buffer_size += 100 + strlen(users[i].name) + strlen(users[i].email);
        if (i < count - 1)
        {
            buffer_size += 2; // For the comma and newline
        }
    }

    // Allocate buffer
    char *buffer = (char*) malloc(buffer_size);
    if (buffer == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for buffer\n");
        return NULL;
    }

    // Write JSON data to buffer
    char *ptr = buffer;
    ptr += sprintf(ptr, "[\n");
    for (int i = 0; i < count; ++i)
    {
        ptr += sprintf(ptr, "  {\n");
        ptr += sprintf(ptr, "    \"id\": %d,\n", users[i].id);
        ptr += sprintf(ptr, "    \"name\": \"%s\",\n", users[i].name);
        ptr += sprintf(ptr, "    \"email\": \"%s\"\n", users[i].email);
        if (i < count - 1)
        {
            ptr += sprintf(ptr, "  },\n");
        }
        else
        {
            ptr += sprintf(ptr, "  }\n");
        }
    }
    ptr += sprintf(ptr, "]\n");

    return buffer;
}
