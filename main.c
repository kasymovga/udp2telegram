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
#include <iconv.h>

#define UDPCHAT_PORT 16887
#define BUFLEN 2048 //Must be more than enough
#define PEER_MAXCOUNT 256

#define TELEGRAM_API_URL "https://api.telegram.org"
#define TELEGRAM_API_CALL_URL_SIZE 1024

CURL *curl;
iconv_t utf8_validator;

uint32_t utf8_range[5] = {
	1,       // invalid - let's not allow the creation of 0-bytes :P
	1,       // ascii minimum
	0x80,    // 2-byte minimum
	0x800,   // 3-byte minimum
	0x10000, // 4-byte minimum
};

static char qfont_table[256] = {
	'\0', '#',  '#',  '#',  '#',  '.',  '#',  '#',
	'#',  9,    10,   '#',  ' ',  13,   '.',  '.',
	'[',  ']',  '0',  '1',  '2',  '3',  '4',  '5',
	'6',  '7',  '8',  '9',  '.',  '<',  '=',  '>',
	' ',  '!',  '"',  '#',  '$',  '%',  '&',  '\'',
	'(',  ')',  '*',  '+',  ',',  '-',  '.',  '/',
	'0',  '1',  '2',  '3',  '4',  '5',  '6',  '7',
	'8',  '9',  ':',  ';',  '<',  '=',  '>',  '?',
	'@',  'A',  'B',  'C',  'D',  'E',  'F',  'G',
	'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
	'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',
	'X',  'Y',  'Z',  '[',  '\\', ']',  '^',  '_',
	'`',  'a',  'b',  'c',  'd',  'e',  'f',  'g',
	'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
	'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
	'x',  'y',  'z',  '{',  '|',  '}',  '~',  '<',

	'<',  '=',  '>',  '#',  '#',  '.',  '#',  '#',
	'#',  '#',  ' ',  '#',  ' ',  '>',  '.',  '.',
	'[',  ']',  '0',  '1',  '2',  '3',  '4',  '5',
	'6',  '7',  '8',  '9',  '.',  '<',  '=',  '>',
	' ',  '!',  '"',  '#',  '$',  '%',  '&',  '\'',
	'(',  ')',  '*',  '+',  ',',  '-',  '.',  '/',
	'0',  '1',  '2',  '3',  '4',  '5',  '6',  '7',
	'8',  '9',  ':',  ';',  '<',  '=',  '>',  '?',
	'@',  'A',  'B',  'C',  'D',  'E',  'F',  'G',
	'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
	'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',
	'X',  'Y',  'Z',  '[',  '\\', ']',  '^',  '_',
	'`',  'a',  'b',  'c',  'd',  'e',  'f',  'g',
	'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
	'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
	'x',  'y',  'z',  '{',  '|',  '}',  '~',  '<'
};

unsigned char utf8_lengths[256] = { // 0 = invalid
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // ascii characters
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x80 - 0xBF are within multibyte sequences
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // they could be interpreted as 2-byte starts but
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // the codepoint would be < 127
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // C0 and C1 would also result in overlong encodings
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	4, 4, 4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	// with F5 the codepoint is above 0x10FFFF,
	// F8-FB would start 5-byte sequences
	// FC-FD would start 6-byte sequences
	// ...
};

#define U8_ANALYZE_INFINITY 7
static int u8_analyze(const char *_s, size_t *_start, size_t *_len, uint32_t *_ch, size_t _maxlen) {
	const unsigned char *s = (const unsigned char*)_s;
	size_t i, j;
	size_t bits = 0;
	uint32_t ch;
	i = 0;
findchar:
	while (i < _maxlen && s[i] && (bits = utf8_lengths[s[i]]) == 0)
		++i;

	if (i >= _maxlen || !s[i]) {
		if (_start) *_start = i;
		if (_len) *_len = 0;
		return 0;
	}
	if (bits == 1) { // ascii
		if (_start) *_start = i;
		if (_len) *_len = 1;
		if (_ch) *_ch = (uint32_t)s[i];
		return 1;
	}
	ch = (s[i] & (0xFF >> bits));
	for (j = 1; j < bits; ++j) {
		if ( (s[i+j] & 0xC0) != 0x80 ) {
			i += j;
			goto findchar;
		}
		ch = (ch << 6) | (s[i+j] & 0x3F);
	}
	if (ch < utf8_range[bits] || ch >= 0x10FFFF) {
		i += bits;
		goto findchar;
	}
	if (_start)
		*_start = i;

	if (_len)
		*_len = bits;

	if (_ch)
		*_ch = ch;

	return 1;
}

uint32_t u8_getchar(const char *_s, const char **_end) {
	size_t st, ln;
	uint32_t ch;
	if (!u8_analyze(_s, &st, &ln, &ch, U8_ANALYZE_INFINITY))
		ch = 0;

	if (_end)
		*_end = _s + st + ln;

	return ch;
}

int u8_fromchar(uint32_t w, char *to, size_t maxlen) {
	if (maxlen < 1)
		return 0;

	if (!w)
		return 0;

	if (w < 0x80) {
		to[0] = (char)w;
		return 1;
	}
	// for a little speedup
	if (w < 0x800) {
		if (maxlen < 2)
			return 0;

		to[1] = 0x80 | (w & 0x3F); w >>= 6;
		to[0] = 0xC0 | w;
		return 2;
	}
	if (w < 0x10000) {
		if (maxlen < 2)
			return 0;

		to[2] = 0x80 | (w & 0x3F); w >>= 6;
		to[1] = 0x80 | (w & 0x3F); w >>= 6;
		to[0] = 0xE0 | w;
		return 3;
	}
	// RFC 3629
	if (w <= 0x10FFFF) {
		if (maxlen < 4)
			return -1;

		to[3] = 0x80 | (w & 0x3F); w >>= 6;
		to[2] = 0x80 | (w & 0x3F); w >>= 6;
		to[1] = 0x80 | (w & 0x3F); w >>= 6;
		to[0] = 0xF0 | w;
		return 4;
	}
	return 0;
}

static void string_sanitize(char *in, char *out) {
	uint32_t c;
	char buf[8];
	int n;
	while (*in) {
		c = u8_getchar(in, (const char **)&in);
		if (c >= 0xE000 && c < 0xE100) c -= 0xE000;
		if (c < 256)
			c = qfont_table[c];

		if (c) {
			if (c < 128) {
				*out = c;
				out++;
			} else {
				n = u8_fromchar(c, buf, 8);
				memcpy(out, buf, n);
				out += n;
			}
		}
	}
	*out = 0;
}


int telegram_api_init() {
	int r = 0;
	if (!(curl = curl_easy_init())) {
		printf("curl_easy_init() failed\n");
		goto finish;
	}
	r = 1;
	utf8_validator = iconv_open("UTF-8//IGNORE","UTF-8");
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
		printf("api failed %s\n", out.data);
		goto finish;
	}
	r = json_tokener_parse(out.data);
finish:
	free(out.data);
	return r;
}

void htmlescape(const char *in, char *out, int out_len) {
	const char *c;
	for (c = in; *c && out_len > 1; c++) {
		switch (*c) {
		case '>':
			if (out_len > 5) {
				strcpy(out, "&gt;");
				out_len -= 4;
				out += 4;
			}
			break;
		case '<':
			if (out_len > 5) {
				strcpy(out, "&lt;");
				out_len -= 4;
				out += 4;
			}
			break;
		case '&':
			if (out_len > 6) {
				strcpy(out, "&amp;");
				out_len -= 5;
				out += 5;
			}
			break;
		default:
			*out = *c;
			out_len--;
			out++;
			break;
		}
	}
	*out = '\0';
}

void message2html(const char *in, char *out, int out_len) {
	char escaped[out_len];
	htmlescape(in, escaped, out_len);
	char *colon = strchr(escaped, ':');
	if (colon) {
		*colon = '\0';
		snprintf(out, out_len, "<b>%s</b>:%s", escaped, &colon[1]);
	} else {
		snprintf(out, out_len, "<i>%s</i>", escaped);
	}
}

int telegram_response_is_ok(json_object *resp) {
	struct json_object *ok;
	if (!json_object_object_get_ex(resp, "ok", &ok))
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

	if (utf8_validator != (iconv_t) -1)
		iconv_close(utf8_validator);
}

long long int restore_chat_id() {
	long long int id = 0;
	FILE *f = NULL;
	if (!(f = fopen(".chatid", "r")))
		goto finish;

	fscanf(f, "%lli", &id);
	if (id)
		printf("Restored chat id: %lli\n", id);
finish:
	if (f)
		fclose(f);

	return id;
}

void save_chat_id(long long int id) {
	FILE *f = NULL;
	if (!(f = fopen(".chatid", "w")))
		goto finish;

	fprintf(f, "%lli", id);
finish:
	if (f)
		fclose(f);
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
	int port = UDPCHAT_PORT;
	char update_id_str[64];
	long long int tg_chat_id = 0, tg_update_id = -2, tg_update_id_new;
	int tg_chat_id_obtained = 0;
	int peers_count = 0;
	const char *udp_message;
	struct sockaddr_in peers[PEER_MAXCOUNT];
	char *colon;
	const char *tg_text, *tg_nick;
	char peer_string[1024];
	char html_message[2048];
	int sender_peer;
	char *msg_escaped;
	if (argc < 3) {
		printf("Usage: %s <token> <peer1> [peer2] ...\n", argv[0]);
		goto finish;
	}
	tg_chat_id = restore_chat_id();
	if (tg_chat_id)
		tg_chat_id_obtained = 1;

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

	if (!peers_count) {
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

	for (;;) {
		sender_peer = -1;
		fds[0].revents = 0;
		fds[0].events = POLLIN;
		if (poll(fds, 1, 2000) < 0)
			goto finish;

		udp_message = "";
		if (fds[0].revents & POLLIN) {
			if ((recv_len = recvfrom(fds[0].fd, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen)) < 0)
				goto finish;

			buf[recv_len] = '\0';
			//printf("%s\n", buf);
			if (memcmp(buf, extresp_query_string, extresp_query_string_len) == 0) {
				for (i = 0; i < peers_count; i++) {
					if (memcmp(&si_other.sin_addr, &peers[i].sin_addr, sizeof(struct in_addr)) == 0 && si_other.sin_port == peers[i].sin_port) {
						udp_message = &buf[extresp_query_string_len];
						sender_peer = i;
						break;
					}
				}
				if (sender_peer < 0) {
					printf("Peer %s:%i not found for packet\n", inet_ntoa(si_other.sin_addr), (int)htons(si_other.sin_port));
				}
				if (udp_message[0] != '\0')
					for (i = 0; i < peers_count; i++) {
						if (sender_peer == i)
							continue;

						//printf("Send message to peer %i\n", i);
						sendto(fds[0].fd, buf, recv_len, 0, &peers[i], sizeof(peers[i]));
					}
			} else
				printf("Unknown request: %s\n", buf);
		}
		snprintf(update_id_str, sizeof(update_id_str), "offset=%lli", (long long int)tg_update_id + 1);
		struct json_object *updates, *result, *sendmessage;
		updates = telegram_api_query(token, "getUpdates", update_id_str);
		if (!updates)
			continue;

		if (!telegram_response_is_ok(updates)) {
			printf("telegram api answer is not ok\n");
			goto skip_parse;
		}

		if (!json_object_object_get_ex(updates, "result", &result))
			goto skip_parse;

		n = json_object_array_length(result);
		for (i = 0; i < n; i++) {
			struct json_object *update, *message, *text, *chat, *chat_id, *from, *first_name, *update_id, *username;
			update = json_object_array_get_idx(result, i);
			if (!json_object_object_get_ex(update, "message", &message)) continue;
			if (!json_object_object_get_ex(update, "update_id", &update_id)) continue;
			tg_update_id_new = json_object_get_int64(update_id);
			if (tg_update_id_new > tg_update_id)
				tg_update_id = tg_update_id_new;

			//printf("Get message from telegram\n");
			if (!json_object_object_get_ex(message, "text", &text)) continue;
			if (!json_object_object_get_ex(message, "chat", &chat)) continue;
			if (!json_object_object_get_ex(chat, "id", &chat_id)) continue;
			if (!json_object_object_get_ex(message, "from", &from)) continue;
			if (json_object_object_get_ex(from, "username", &username))
				tg_nick = json_object_get_string(username);
			else {
				if (json_object_object_get_ex(from, "first_name", &first_name))
					tg_nick = json_object_get_string(first_name);
				else
					tg_nick = "anonymous";
			}
			if (tg_chat_id_obtained) {
				if (tg_chat_id != json_object_get_int64(chat_id))
					continue;
			} else {
				tg_chat_id = json_object_get_int64(chat_id);
				tg_chat_id_obtained = 1;
				save_chat_id(tg_chat_id);
				printf("Get chat id: %lli\n", (long long int)tg_chat_id);
			}
			tg_text = json_object_get_string(text);
			//printf("Text (from chat: %li): %s\n", tg_chat_id, tg_text);

			snprintf(buf_out, BUFLEN, "%s %s@telegram: %s", extresp_query_string, tg_nick, tg_text);
			for (i = 0; i < peers_count; i++) {
				sendto(fds[0].fd, buf_out, strlen(buf_out), 0, &peers[i], sizeof(peers[i]));
			}
		}
skip_parse:
		if (updates)
			json_object_put(updates);

		if (*udp_message && tg_chat_id_obtained) {
			string_sanitize((char *)udp_message, (char *)udp_message);
			message2html(udp_message, html_message, sizeof(html_message));
			msg_escaped = curl_easy_escape(curl, html_message, strlen(html_message));
			//printf("html_message=%s\n", html_message);
			snprintf(buf_out, BUFLEN, "chat_id=%lli&parse_mode=HTML&text=%s", (long long int)tg_chat_id, msg_escaped);
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
