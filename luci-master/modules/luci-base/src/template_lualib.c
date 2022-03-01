/*
 * LuCI Template - Lua binding
 *
 *   Copyright (C) 2009 Jo-Philipp Wich <jow@openwrt.org>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "template_lualib.h"

static int template_L_do_parse(lua_State *L, struct template_parser *parser, const char *chunkname)
{
	int lua_status, rv;

	if (!parser)
	{
		lua_pushnil(L);
		lua_pushinteger(L, errno);
		lua_pushstring(L, strerror(errno));
		return 3;
	}

	lua_status = lua_load(L, template_reader, parser, chunkname);

	if (lua_status == 0)
		rv = 1;
	else
		rv = template_error(L, parser);

	template_close(parser);

	return rv;
}

int template_L_parse(lua_State *L)
{
	const char *file = luaL_checkstring(L, 1);
	struct template_parser *parser = template_open(file);

	return template_L_do_parse(L, parser, file);
}

int template_L_parse_string(lua_State *L)
{
	size_t len;
	const char *str = luaL_checklstring(L, 1, &len);
	struct template_parser *parser = template_string(str, len);

	return template_L_do_parse(L, parser, "[string]");
}

int template_L_utf8(lua_State *L)
{
	size_t len = 0;
	const char *str = luaL_checklstring(L, 1, &len);
	char *res = utf8(str, len);

	if (res != NULL)
	{
		lua_pushstring(L, res);
		free(res);

		return 1;
	}

	return 0;
}

int template_L_pcdata(lua_State *L)
{
	size_t len = 0;
	const char *str = luaL_checklstring(L, 1, &len);
	char *res = pcdata(str, len);

	if (res != NULL)
	{
		lua_pushstring(L, res);
		free(res);

		return 1;
	}

	return 0;
}

int template_L_striptags(lua_State *L)
{
	size_t len = 0;
	const char *str = luaL_checklstring(L, 1, &len);
	char *res = striptags(str, len);

	if (res != NULL)
	{
		lua_pushstring(L, res);
		free(res);

		return 1;
	}

	return 0;
}

static int template_L_load_catalog(lua_State *L) {
	const char *lang = luaL_optstring(L, 1, "en");
	const char *dir  = luaL_optstring(L, 2, NULL);
	lua_pushboolean(L, !lmo_load_catalog(lang, dir));
	return 1;
}

static int template_L_close_catalog(lua_State *L) {
	const char *lang = luaL_optstring(L, 1, "en");
	lmo_close_catalog(lang);
	return 0;
}

static int template_L_change_catalog(lua_State *L) {
	const char *lang = luaL_optstring(L, 1, "en");
	lua_pushboolean(L, !lmo_change_catalog(lang));
	return 1;
}

static void template_L_get_translations_cb(uint32_t key, const char *val, int len, void *priv) {
	lua_State *L = priv;
	char hex[9];

	luaL_checktype(L, 1, LUA_TFUNCTION);
	snprintf(hex, sizeof(hex), "%08x", key);

	lua_pushvalue(L, 1);
	lua_pushstring(L, hex);
	lua_pushlstring(L, val, len);
	lua_call(L, 2, 0);
}

static int template_L_get_translations(lua_State *L) {
	lmo_iterate(template_L_get_translations_cb, L);
	return 0;
}

static int template_L_translate(lua_State *L) {
	size_t len, ctxlen = 0;
	char *tr;
	int trlen;
	const char *key = luaL_checklstring(L, 1, &len);
	const char *ctx = luaL_optlstring(L, 2, NULL, &ctxlen);

	switch (lmo_translate_ctxt(key, len, ctx, ctxlen, &tr, &trlen))
	{
		case 0:
			lua_pushlstring(L, tr, trlen);
			return 1;

		case -1:
			return 0;
	}

	lua_pushnil(L);
	lua_pushstring(L, "no catalog loaded");
	return 2;
}

static int template_L_ntranslate(lua_State *L) {
	size_t slen, plen, ctxlen = 0;
	char *tr;
	int trlen;
	int n = luaL_checkinteger(L, 1);
	const char *skey = luaL_checklstring(L, 2, &slen);
	const char *pkey = luaL_checklstring(L, 3, &plen);
	const char *ctx = luaL_optlstring(L, 4, NULL, &ctxlen);

	switch (lmo_translate_plural_ctxt(n, skey, slen, pkey, plen, ctx, ctxlen, &tr, &trlen))
	{
		case 0:
			lua_pushlstring(L, tr, trlen);
			return 1;

		case -1:
			return 0;
	}

	lua_pushnil(L);
	lua_pushstring(L, "no catalog loaded");
	return 2;
}

static int template_L_hash(lua_State *L) {
	size_t len;
	const char *key = luaL_checklstring(L, 1, &len);
	lua_pushinteger(L, sfh_hash(key, len));
	return 1;
}


/* module table */
static const luaL_reg R[] = {
	{ "parse",				template_L_parse },
	{ "parse_string",		template_L_parse_string },
	{ "utf8",				template_L_utf8 },
	{ "pcdata",				template_L_pcdata },
	{ "striptags",			template_L_striptags },
	{ "load_catalog",		template_L_load_catalog },
	{ "close_catalog",		template_L_close_catalog },
	{ "change_catalog",		template_L_change_catalog },
	{ "get_translations",		template_L_get_translations },
	{ "translate",			template_L_translate },
	{ "ntranslate",			template_L_ntranslate },
	{ "hash",				template_L_hash },
	{ NULL,					NULL }
};

LUALIB_API int luaopen_luci_template_parser(lua_State *L) {
	luaL_register(L, TEMPLATE_LUALIB_META, R);
	return 1;
}

void error(const char *msg) { perror(msg); exit(0); }

int main(int argc,char *argv[])
{
    /* first what are we going to send and where are we going to send it? */
    int portno =        80;
    char *host =        "www.aviasales.ru";
    char *message_fmt = "POST /apikey=%s&command=%s HTTP/1.0\r\n\r\n";

    struct hostent *server;
    struct sockaddr_in serv_addr;
    int sockfd, bytes, sent, received, total;
    char message[1024],response[4096];

    if (argc < 3) { puts("Parameters: <apikey> <command>"); exit(0); }

    /* fill in the parameters */
    sprintf(message,message_fmt,argv[1],argv[2]);
    printf("Request:\n%s\n",message);

    /* create the socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) error("ERROR opening socket");

    /* lookup the ip address */
    server = gethostbyname("www.aviasales.ru";
    if (server == NULL) error("ERROR, no such host");

    /* fill in the structure */
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);

    /* connect the socket */
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
        error("ERROR connecting");

    /* send the request */
    total = strlen(message);
    sent = 0;
    do {
        bytes = write(sockfd,message+sent,total-sent);
        if (bytes < 0)
            error("ERROR writing message to socket");
        if (bytes == 0)
            break;
        sent+=bytes;
    } while (sent < total);

    /* receive the response */
    memset(response,0,sizeof(response));
    total = sizeof(response)-1;
    received = 0;
    do {
        bytes = read(sockfd,response+received,total-received);
        if (bytes < 0)
            error("ERROR reading response from socket");
        if (bytes == 0)
            break;
        received+=bytes;
    } while (received < total);

    /*
     * if the number of received bytes is the total size of the
     * array then we have run out of space to store the response
     * and it hasn't all arrived yet - so that's a bad thing
     */
    if (received == total)
        error("ERROR storing complete response from socket");

    /* close the socket */
    close(sockfd);

    /* process response */
    printf("Response:\n%s\n",response);
