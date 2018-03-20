#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <json.h>
#include <json_object.h>

#define UDPCHAT_PORT 16887
#define BUFLEN 2048 //Must be more than enough
#define PEER_MAXCOUNT 32

#define TELEGRAM_API_URL "https://api.telegram.org"
#define TELEGRAM_API_CALL_URL_SIZE 1024

CURL *curl;

int telegram_api_init() {
	int r = 0;
	if (!(curl = curl_easy_init())) {
		printf("curl_easy_init() failed\n");
		goto finish;
	}
	r = 1;
finish:
	return r;
}

struct data_with_size {
	int size;
	char *data;
};

size_t curl_write_to_mem(void *ptr, size_t size, size_t nmemb, void *out) {
	struct data_with_size *_out = out;
	int n = _out->size + size * nmemb;
	void *p = realloc(_out->data, n + 1);
	if (!p) {
		perror("realloc");
		return -1;
	}
	_out->data = p;
	memcpy(&_out->data[_out->size], ptr, nmemb * size);
	_out->size = n;
	return nmemb;
}

struct json_object* telegram_api_query(const char *token, const char *method, const char *post) {
	struct json_object *r = NULL;
	long int resp_code;
	CURLcode res;
	char url[TELEGRAM_API_CALL_URL_SIZE];
	struct data_with_size out = {.size = 0, .data = NULL};
	snprintf(url, TELEGRAM_API_CALL_URL_SIZE, TELEGRAM_API_URL "/bot%s/%s", token, method);
	//printf("url=%s\n", url);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	if (post)
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_to_mem);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		printf("curl_easy_perform failed: %s\n", curl_easy_strerror(res));
		goto finish;
	}
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp_code);
	if (!out.size) {
		printf("empty answer\n");
		goto finish;
	}
	out.data[out.size] = '\0';
	//printf("%s\n", out.data);
	if (resp_code != 200) {
		printf("api failed\n");
		goto finish;
	}
	r = json_tokener_parse(out.data);
finish:
	free(out.data);
	return r;
}

int telegram_response_is_ok(json_object *resp) {
	struct json_object *ok = json_object_object_get(resp, "ok");
	if (!ok)
		return 0;

	if (json_object_get_type(ok) != json_type_boolean)
		return 0;

	if (json_object_get_boolean(ok))
		return 1;

	return 0;
}

void telegram_api_shutdown() {
	if (curl)
		curl_easy_cleanup(curl);
}

int main(int argc, char **argv) {
	struct sockaddr_in si_me, si_other;
	const char *token;
	int i, n;
	socklen_t slen = sizeof(si_other);
	ssize_t recv_len;
	char buf[BUFLEN + 1];
	char buf_out[BUFLEN + 1];
	struct pollfd fds[1];
	fds[0].fd = -1;
	const char *extresp_query_string = "\377\377\377\377extResponse udpchat ";
	unsigned int extresp_query_string_len = strlen(extresp_query_string);
	const char *other_addr;
	int port = UDPCHAT_PORT;
	struct json_object *updates, *update, *result, *message, *text, *chat, *chat_id, *from, *first_name, *update_id, *sendmessage;
	char update_id_str[64];
	long int tg_chat_id, tg_update_id = -2, tg_update_id_new;
	int tg_chat_id_obtained = 0;
	int peers_count = 0;
	const char *udp_message;
	struct sockaddr_in peers[PEER_MAXCOUNT];
	char *colon;
	const char *tg_text, *tg_firstname;
	char peer_string[1024];
	int sender_peer;
	char *msg_escaped;
	if (argc < 3) {
		printf("Usage: %s <token> <peer1> [peer2] ...\n");
		goto finish;
	}
	for (i = 2; i < argc && peers_count < PEER_MAXCOUNT; i++) {
		strncpy(peer_string, argv[i], sizeof(peer_string));
		peer_string[sizeof(peer_string) - 1] = '\0';
		if ((colon = strchr(peer_string, ':'))) {
			peers[peers_count].sin_family = AF_INET;
			peers[peers_count].sin_port = htons(atoi(&colon[1]));
			*colon = '\0';
			printf("address=%s, port=%s\n", peer_string, &colon[1]);
			inet_pton(AF_INET, peer_string, &peers[peers_count].sin_addr);
		} else {
			peers[peers_count].sin_family = AF_INET;
			peers[peers_count].sin_port = htons(26000);
			inet_pton(AF_INET, peer_string, &peers[peers_count].sin_addr);
		}
		peers_count++;
	}
	token = argv[1];
	if (!telegram_api_init()) {
		printf("telegram_api_init failed\n");
		goto finish;
	}

	if (!peers) {
		printf("no peers\n");
	}
	if ((fds[0].fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		goto finish;

	memset(&si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(port);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(fds[0].fd, (struct sockaddr*)&si_me, sizeof(si_me)) == -1)
		goto finish;

	for(;;)
	{
		sender_peer = -1;
		fds[0].revents = 0;
		fds[0].events = POLLIN;
		if (poll(fds, 1, 2000) < 0)
			goto finish;

		udp_message = "";
		if (fds[0].revents & POLLIN)
		{
			if ((recv_len = recvfrom(fds[0].fd, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen)) < 0)
				goto finish;

			buf[recv_len] = '\0';
			printf("%s\n", buf);
			if (memcmp(buf, extresp_query_string, extresp_query_string_len) == 0) {
				for (i = 0; i < peers_count; i++) {
					if (memcmp(&si_other.sin_addr, &peers[i].sin_addr, sizeof(struct in_addr)) == 0 && si_other.sin_port == peers[i].sin_port) {
						udp_message = &buf[extresp_query_string_len];
						sender_peer = i;
						break;
					}
				}
				if (sender_peer < 0) {
					printf("Peer not found for packet\n");
				}
				if (udp_message[0] != '\0')
					for (i = 0; i < peers_count; i++) {
						if (sender_peer == i)
							continue;

						printf("Send message to peer %i\n", i);
						sendto(fds[0].fd, buf, recv_len, 0, &peers[i], sizeof(peers[i]));
					}
			} else
				printf("Unknown request: %s\n", buf);
		}

		snprintf(update_id_str, sizeof(update_id_str), "offset=%li", tg_update_id + 1);
		updates = telegram_api_query(token, "getUpdates", update_id_str);
		if (!updates)
			continue;

		if (!telegram_response_is_ok(updates))
			printf("telegram api answer is not ok\n");

		result = json_object_object_get(updates, "result");
		if (!result)
			continue;

		n = json_object_array_length(result);
		for (i = 0; i < n; i++) {
			update = json_object_array_get_idx(result, i);
			message = json_object_object_get(update, "message");
			if (!message) continue;
			update_id = json_object_object_get(update, "update_id");
			if (!update_id) continue;
			tg_update_id_new = json_object_get_int64(update_id);
			if (tg_update_id_new > tg_update_id)
				tg_update_id = tg_update_id_new;

			//printf("Get message from telegram\n");
			text = json_object_object_get(message, "text");
			if (!text) continue;
			chat = json_object_object_get(message, "chat");
			if (!chat) continue;
			chat_id = json_object_object_get(chat, "id");
			if (!chat_id) continue;
			from = json_object_object_get(message, "from");
			if (!from) continue;
			first_name = json_object_object_get(from, "first_name");
			if (!first_name) continue;
			if (tg_chat_id_obtained) {
				if (tg_chat_id != json_object_get_int(chat_id))
					continue;
			} else {
				tg_chat_id = json_object_get_int(chat_id);
				tg_chat_id_obtained = 1;
			}
			tg_text = json_object_get_string(text);
			tg_firstname = json_object_get_string(first_name);
			//printf("Text (from chat: %li): %s\n", tg_chat_id, tg_text);

			snprintf(buf_out, BUFLEN, "%s %s@telegram: %s", extresp_query_string, tg_firstname, tg_text);
			for (i = 0; i < peers_count; i++) {
				sendto(fds[0].fd, buf_out, strlen(buf_out), 0, &peers[i], sizeof(peers[i]));
			}
		}
		json_object_put(updates);
		if (*udp_message && tg_chat_id_obtained) {
			msg_escaped = curl_easy_escape(curl, udp_message, strlen(udp_message));
			snprintf(buf_out, BUFLEN, "chat_id=%li&text=%s", (long int)tg_chat_id, msg_escaped);
			curl_free(msg_escaped);
			sendmessage = telegram_api_query(token, "sendMessage", buf_out);
			if (sendmessage) {
				if (!telegram_response_is_ok(sendmessage))
					printf("telegram api answer is not ok\n");

				json_object_put(sendmessage);
			}
		}
	}
finish:
	telegram_api_shutdown();
	if (errno)
		perror("udpchat_server");

	if (fds[0].fd >= 0)
		close(fds[0].fd);

	return 0;
}