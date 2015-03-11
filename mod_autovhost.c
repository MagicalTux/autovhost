#define _POSIX_C_SOURCE 200809L

#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/un.h>

// Fix constants
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "apr.h"
#include "apr_strings.h"
#include "apr_hooks.h"
#include "apr_lib.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"  /* for ap_hook_translate_name */
#include "http_protocol.h" /* for ap_hook_log_transaction */
#include "http_log.h"

#include "http_config.h"

// Fix constants
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#define PACKAGE_NAME "mod_autovhost"
#define PACKAGE_TARNAME "mod_autovhost"
#define PACKAGE_VERSION "1.0"
#define PACKAGE_STRING "mod_autovhost 1.0"

AP_DECLARE_MODULE(autovhost);

typedef struct autovhost_sconf_t {
	const char *prefix;
	const char *socket;
} autovhost_sconf_t;

struct autovhost_info {
	apr_pool_t *pool;
	char *host;
	char *vhost;
	char *basepath;
};

static const char c2x_table[] = "0123456789abcdef";

static struct tms request_times;

static APR_INLINE unsigned char *c2x(unsigned what, unsigned char prefix,
		unsigned char *where)
{
#if APR_CHARSET_EBCDIC
	what = apr_xlate_conv_byte(ap_hdrs_to_ascii, (unsigned char)what);
#endif /*APR_CHARSET_EBCDIC*/
	*where++ = prefix;
	*where++ = c2x_table[what >> 4];
	*where++ = c2x_table[what & 0xf];
	return where;
}

/*
 * Escapes a uri in a similar way as php's urlencode does.
 * Based on ap_os_escape_path in server/util.c
 */
static char *escape_uri(apr_pool_t *p, const char *path) {
	char *copy = apr_palloc(p, 3 * strlen(path) + 3);
	const unsigned char *s = (const unsigned char *)path;
	unsigned char *d = (unsigned char *)copy;
	unsigned c;

	while ((c = *s)) {
		if (apr_isalnum(c) || c == '_') {
			*d++ = c;
		}
		else if (c == ' ') {
			*d++ = '+';
		}
		else {
			d = c2x(c, '%', d);
		}
		++s;
	}
	*d = '\0';
	return copy;
}

static void *autovhost_create_server_config(apr_pool_t *p, server_rec *s) {
	autovhost_sconf_t *conf;
	conf = (autovhost_sconf_t*)apr_pcalloc(p, sizeof(autovhost_sconf_t));
	conf->prefix = NULL;
	conf->socket = NULL;
	return conf;
}

static void *autovhost_merge_server_config(apr_pool_t *p, void *parentv, void *childv) {
	autovhost_sconf_t *parent = (autovhost_sconf_t*)parentv;
	autovhost_sconf_t *child = (autovhost_sconf_t*)childv;
	autovhost_sconf_t *conf = (autovhost_sconf_t*)apr_pcalloc(p, sizeof(autovhost_sconf_t));

	if (child->prefix == NULL) {
		conf->prefix = parent->prefix;
	} else {
		conf->prefix = child->prefix;
	}

	return conf;
}

static bool test_path(const char *prefix, const char *vhost, size_t vhost_len, char **host, size_t *len, struct autovhost_info *info, int depth) {
	char tmp_buf[256];
	char *tmp_ptr = (char*)&tmp_buf;
	struct stat s;
	size_t prefix_len = strlen(prefix);

	if (strcmp(vhost, "sessions") == 0) return false;
	if (strcmp(vhost, "includes") == 0) return false;

	// transform in prefix/x/xy/buf/vhost. Final length: prefix+buf+vhost+7+NUL
	int final_len = vhost_len + *len + prefix_len + 8;
	if (final_len > (sizeof(tmp_buf)-1)) return false;
	memcpy(tmp_ptr, prefix, prefix_len); tmp_ptr += prefix_len;
	*(tmp_ptr++) = '/';
	*(tmp_ptr++) = **host;
	*(tmp_ptr++) = '/';
	*(tmp_ptr++) = **host;
	*(tmp_ptr++) = (*host)[1];
	*(tmp_ptr++) = '/';
	memcpy(tmp_ptr, *host, *len); tmp_ptr += *len;
	char *tmp_ptr_end_of_host = tmp_ptr;
	*tmp_ptr = 0; // for now

	do {
		char tmp_buf2[256];
		int linklen = readlink((char*)&tmp_buf, (char*)&tmp_buf2, sizeof(tmp_buf2)-1);
		if (linklen > 0) {
			char *tmp_vhost;
			if (depth > 5) return false; // avoid going too far
			// resume lookup from symlink value
			if (linklen >= sizeof(tmp_buf2)-1) return false;
			tmp_buf2[linklen] = 0; // we got a new domain
			*host = apr_pstrdup(info->pool, (char*)&tmp_buf2);
			// check for subdomain redirect
			tmp_vhost = *host;
			while(*tmp_vhost != 0) {
				if (*tmp_vhost == '/') {
					(*(tmp_vhost++)) = 0;
					size_t tmp_vhost_len = linklen - (tmp_vhost - (*host));
					*len = linklen - (tmp_vhost_len + 1);
					return test_path(prefix, tmp_vhost, tmp_vhost_len, host, len, info, depth+1);
				}
				tmp_vhost++;
			}
			*len = linklen;
			return test_path(prefix, vhost, vhost_len, host, len, info, depth+1);
		}
	} while(0);

	*(tmp_ptr++) = '/';
	memcpy(tmp_ptr, vhost, vhost_len); tmp_ptr += vhost_len;
	*(tmp_ptr++) = 0;

	if (stat((char*)&tmp_buf, &s) == -1) return false;
	if (!S_ISDIR(s.st_mode)) return false;

	// found it!
	*tmp_ptr_end_of_host = 0;
	info->host = apr_pstrdup(info->pool, *host);
	info->vhost = apr_pstrdup(info->pool, vhost);
	info->basepath = apr_pstrdup(info->pool, (char*)&tmp_buf);
	
	return true;
}

bool scan_host(char *host, const char *prefix, struct autovhost_info *info) {
	// check validity, only valid chars are a-z 0-9 . _
	// also, copy host_ro to new var host
	while(host[0] == '.') host++;
	size_t len = strlen(host);
	if (len <= 0) return false;

	char last_c = '.';
	for(int i = 0; i < len; i++) {
		char c = host[i];
		if ((c == '.') && (last_c == '.')) return false; // invalid
		last_c = c;

		if (c >= 'A' && c <= 'Z') {
			c += 32; // make lowercase
			host[i] = c;
		}
		if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '.') || (c == '-') || (c == '_')) {
			continue;
		}
		return false;
	}

	// test for default paths
	if (test_path(prefix, "_default", 8, &host, &len, info, 0)) return true;
	if (test_path(prefix, "www", 3, &host, &len, info, 0)) return true;

	char *vhost = host;

	// start playing with host
	while(1) {
		if (vhost != host) host[-1] = '.';
		// first, locate a .
		bool found = false;
		for(int i = 0; i < len; i++) {
			if (host[i] == '.') {
				found = true;
				host[i] = 0;
				host += i+1;
				len -= i+1;
				break;
			}
		}
		if (!found) return false; // out of ideas
		if (len < 2) return false; // no domain has less than 2 chars
		size_t vhost_len = strlen(vhost);
		if (test_path(prefix, vhost, vhost_len, &host, &len, info, 0)) return true;
		// re-test subparts of vhost
		for(int i = 0; i < vhost_len; i++) {
			if (vhost[i] == '.') if (test_path(prefix, vhost + i + 1, vhost_len - (i+1), &host, &len, info, 0)) return true;
		}
		// defaults
		if (test_path(prefix, "_default", 8, &host, &len, info, 0)) return true;
		if (test_path(prefix, "www", 3, &host, &len, info, 0)) return true;
	}
}

#if 0
void do_test(const char *host) {
	char buf[256];
	if (scan_host(host, "/www/", (char*)&buf, sizeof(buf))) {
		printf("success for %s: %s\n", host, (char*)&buf);
	} else {
		printf("failed for %s\n", host);
	}
}
#endif

#define APACHE_SET_DIRECTIVE(_p, _dir, _args) do { \
	(_p)->directive = _dir; \
	(_p)->args = _args; \
	(_p)->next = NULL; \
	(_p)->first_child = NULL; \
	(_p)->parent = NULL; \
	(_p)->data = NULL; \
	(_p)->filename = __FILE__; \
	(_p)->line_num = __LINE__; \
	(_p)->last = NULL; \
} while(0)

#define PUSH_APACHE_CONFIG(_s, _pool, _dir, _args) do { \
	ap_directive_t *x = apr_pcalloc(_pool, sizeof(ap_directive_t)); \
	APACHE_SET_DIRECTIVE(x, _dir, _args); \
	x->first_child = (_s)->first_child; \
	x->parent = (_s)->parent; \
	(_s) = x; \
} while(0)

#define PUSH_APACHE_DIRECTIVE(_dir, _args) do { \
	APACHE_SET_DIRECTIVE(t, _dir, _args); \
	const char *errmsg = ap_walk_config(t, &parms, r->per_dir_config); \
	if (errmsg != NULL) { \
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to merge config: %s", errmsg); \
	} \
} while(0)

//	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "test: %s prefix: %s uri: %s docroot: %s serverpath: %s", ap_get_server_name(r), conf->prefix, r->uri, (char*)&buf, r->server->path);

static int autovhost_translate(request_rec *r) {
	autovhost_sconf_t *conf;
	conf = (autovhost_sconf_t*)ap_get_module_config(r->server->module_config, &autovhost_module);
	core_server_config *core_conf = ap_get_module_config(r->server->module_config, &core_module);

	if (conf->prefix == NULL) return DECLINED;
	if (r->prev != NULL) return DECLINED; // do not touch (ie. waste time on already configured) subrequests

	times(&request_times);

	struct autovhost_info *info = apr_pcalloc(r->pool, sizeof(struct autovhost_info));
	info->pool = r->pool;

	if (!scan_host(apr_pstrdup(r->pool, ap_get_server_name(r)), conf->prefix, info)) {
		if (!scan_host(apr_pstrdup(r->pool, "default"), conf->prefix, info))
			return DECLINED; // no result, no default :(
	}

	if (info->basepath == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Success reported, but no info data");
		return DECLINED;
	}

	// duplicate string and assign ap_document_root - YAY THIS IS DIRTYYYYYYYYYYYYY!
	core_conf->ap_document_root = apr_pstrcat(r->pool, info->basepath, "/", info->vhost, NULL);

	// prepare stuff to be able to push directives on Apache
	ap_directive_t *t = apr_pcalloc(r->pool, sizeof(ap_directive_t));
	cmd_parms parms;
	parms.pool = r->pool;
	parms.temp_pool = r->pool;
	parms.server = r->server;
	parms.override = OR_ALL|ACCESS_CONF|RSRC_CONF;//(RSRC_CONF | OR_ALL) & ~(OR_AUTHCFG | OR_LIMIT);
	parms.override_opts = OPT_ALL | OPT_SYM_OWNER | OPT_MULTI;
	parms.override_list = NULL;
	parms.path = __FILE__;
	if (r->per_dir_config == NULL) {
		r->per_dir_config = ap_create_per_dir_config(r->pool);
	}

	// store some notes
	apr_table_addn(r->notes, "autovhost_host", info->host);
	apr_table_addn(r->notes, "autovhost_vhost", info->vhost);

	// Fake some input headers to make us look better (DIRTY BIS)
	apr_table_addn(r->headers_in, "X-VHost-Info", apr_pstrcat(r->pool, info->host, "/", info->vhost, NULL));

	int fd = open(apr_pstrcat(r->pool, info->basepath, "_", info->vhost, ".config", NULL), O_RDONLY);
	if (fd > 0) {
		unsigned char version;
		if (read(fd, &version, 1) != 1) version = 0xff;
		if (version == 1) {
			while(1) {
				unsigned char code;
				if (read(fd, &code, 1) != 1) break;
				if (code == 0xff) break; // "end of file"
				if (code == 0) {
					unsigned char len;
					char *setting;
					char *value;
					if (read(fd, &len, 1) != 1) break;
					setting = apr_pcalloc(r->pool, len+1);
					if (read(fd, setting, len) != len) break;
					if (read(fd, &len, 1) != 1) break;
					value = apr_pcalloc(r->pool, len+1);
					if (read(fd, value, len) != len) break;
					PUSH_APACHE_DIRECTIVE(setting, value);
					continue;
				}
				break; // unknown code
			}
		}
		close(fd);
	}

	// Configure apache options/etc (we made sure apache was nude with #define CORE_PRIVATE, now let's grop those privates)
	char *tmp = apr_pstrcat(r->pool, "doc_root \"", ap_escape_quotes(r->pool, core_conf->ap_document_root), "\"", NULL);
	PUSH_APACHE_DIRECTIVE("php_admin_value", tmp);
	tmp = apr_pstrcat(r->pool, "open_basedir \"/tmp/:/usr/share/fonts/php/:/dev/urandom:/dev/null:/proc/loadavg:/www/pear:/www/zend:", ap_escape_quotes(r->pool, info->basepath), "/\"", NULL);
	PUSH_APACHE_DIRECTIVE("php_admin_value", tmp);
	tmp = apr_pstrcat(r->pool, "session.save_path \"", ap_escape_quotes(r->pool, info->basepath), "/sessions\"", NULL);
	PUSH_APACHE_DIRECTIVE("php_value", tmp);

	return DECLINED; /* we played with the config, but let apache continue processing normally, with the new informations we are providing */
}

struct lots_of_infos_for_make_table {
	int len;
	apr_pool_t *pool;
	apr_table_t *table;
	char *buf;
	int pos;
};

int make_table_escape_uri(void *rec, const char *key, const char *value) {
	struct lots_of_infos_for_make_table *info = (struct lots_of_infos_for_make_table*)rec;
	if (value == NULL) return 1; // skip empty/null stuff
	char *new_key = escape_uri(info->pool, key);
	char *new_value = escape_uri(info->pool, value);
	apr_table_addn(info->table, new_key, new_value);
	info->len += strlen(new_key)+strlen(new_value)+2; // "&" and "="
	return -1;
}

int build_final_buffer_for_table(void *rec, const char *key, const char *value) {
	struct lots_of_infos_for_make_table *info = (struct lots_of_infos_for_make_table*)rec;
	if (info->buf == NULL) {
		info->buf = apr_pcalloc(info->pool, info->len+1); // +1 = NUL
	}
	if (info->pos > 0) {
		info->buf[info->pos] = '&'; info->pos++;
	}
	int len = strlen(key);
	memcpy(info->buf + info->pos, key, len); info->pos += len;
	info->buf[info->pos] = '='; info->pos++;
	len = strlen(value);
	memcpy(info->buf + info->pos, value, len); info->pos += len;
	return -1;
}

static int append_received_headers(void *rec, const char *key, const char *value) {
	struct lots_of_infos_for_make_table *info = (struct lots_of_infos_for_make_table*)rec;
	char *real_key = apr_pstrcat(info->pool, "headers_in[", key, "][]", NULL);
	apr_table_addn(info->table, real_key, value);
	return -1;
}

static int append_sent_headers(void *rec, const char *key, const char *value) {
	struct lots_of_infos_for_make_table *info = (struct lots_of_infos_for_make_table*)rec;
	char *real_key = apr_pstrcat(info->pool, "headers_out[", key, "][]", NULL);
	apr_table_addn(info->table, real_key, value);
	return -1;
}

static int autovhost_log(request_rec *r) {
	autovhost_sconf_t *conf = (autovhost_sconf_t*)ap_get_module_config(r->server->module_config, &autovhost_module);
	if (conf->socket == NULL) return DECLINED;
	// combined format: "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"
	// %h: remote host
	// %l: Remote logname (from identd, if supplied). This will return a dash unless mod_ident is present and IdentityCheck is set On.
	// %u: Remote user (from auth; may be bogus if return status (%s) is 401)
	// %t: Time the request was received (standard english format)
	// %r: First line of request
	// %>s: Status. For requests that got internally redirected, this is the status of the *original* request --- %>s for the last.
	// %b: Size of response in bytes, excluding HTTP headers. In CLF format, i.e. a '-' rather than a 0 when no bytes are sent
	//
	// Going to send this in a more parsing friendly format
	
	apr_table_t *data_table = apr_table_make(r->pool, 8);
	struct lots_of_infos_for_make_table n;
	n.pool = r->pool;
	n.table = data_table;

	request_rec *orig = r;
	while(orig->prev) orig = orig->prev;
	while(r->next) r = r->next;

	// compute cpu time
	struct tms final_times;
	times(&final_times);
	long ticks_per_second = sysconf(_SC_CLK_TCK);
	long tms_utime_delta = (final_times.tms_utime - request_times.tms_utime) * 1000000 / ticks_per_second;
	long tms_stime_delta = (final_times.tms_stime - request_times.tms_stime) * 1000000 / ticks_per_second;
	long tms_cutime_delta = (final_times.tms_cutime - request_times.tms_cutime) * 1000000 / ticks_per_second;
	long tms_cstime_delta = (final_times.tms_cstime - request_times.tms_cstime) * 1000000 / ticks_per_second;
	// convert tms_*_delta to 1/1000000th second

	apr_table_addn(data_table, "now", apr_ltoa(r->pool, apr_time_now()));
	apr_table_addn(data_table, "host", apr_table_get(orig->notes, "autovhost_host"));
	apr_table_addn(data_table, "vhost", apr_table_get(orig->notes, "autovhost_vhost"));
	apr_table_addn(data_table, "remote_ip", orig->connection->client_ip);
	apr_table_addn(data_table, "local_ip", orig->connection->local_ip);
	apr_table_addn(data_table, "local_port", apr_itoa(r->pool, orig->connection->local_addr->port));
	apr_table_addn(data_table, "remote_logname", ap_get_remote_logname(orig));
	apr_table_addn(data_table, "user", orig->user);
	if (r->parsed_uri.password) {
		apr_table_addn(data_table, "request", apr_pstrcat(r->pool, orig->method, " ", apr_uri_unparse(r->pool, &orig->parsed_uri, 0), orig->assbackwards ? NULL : " ", orig->protocol, NULL));
	} else {
		apr_table_addn(data_table, "request", orig->the_request);
	}
	apr_table_addn(data_table, "filename", r->filename); // we want "last" filename, as original one will be flawed if we got an internal redirect
	apr_table_addn(data_table, "uri", orig->uri);
	apr_table_addn(data_table, "method", orig->method);
	apr_table_addn(data_table, "protocol", orig->protocol);
	apr_table_addn(data_table, "query", orig->args);
	apr_table_addn(data_table, "status", apr_itoa(r->pool, r->status));
	apr_table_addn(data_table, "bytes_sent", apr_ltoa(r->pool, r->bytes_sent));
	apr_table_addn(data_table, "request_start", apr_ltoa(r->pool, orig->request_time)); // contains time()*1000000+microtime
	apr_table_addn(data_table, "tms_utime_delta", apr_ltoa(r->pool, tms_utime_delta));
	apr_table_addn(data_table, "tms_stime_delta", apr_ltoa(r->pool, tms_stime_delta));
	apr_table_addn(data_table, "tms_cutime_delta", apr_ltoa(r->pool, tms_cutime_delta));
	apr_table_addn(data_table, "tms_cstime_delta", apr_ltoa(r->pool, tms_cstime_delta));
	apr_table_addn(data_table, "server_hostname", r->server->server_hostname);
	apr_table_do(append_received_headers, &n, r->headers_in, NULL);
	apr_table_do(append_sent_headers, &n, r->headers_out, NULL);

	// urlencode data in a new table
	apr_table_t *data_table_esc = apr_table_make(r->pool, 8);
	n.len = 0;
	n.table = data_table_esc;
	n.buf = NULL;
	n.pos = 0;

	apr_table_do(make_table_escape_uri, &n, data_table, NULL);
	apr_table_do(build_final_buffer_for_table, &n, data_table_esc, NULL);

	int sock;

	// send packet via unix socket
	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to create socket: %s", strerror(errno));
		return DECLINED;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, conf->socket);

	/* if (bind(sock, &addr, sizeof(addr)) < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to bind socket: %s", strerror(errno));
		close(sock);
		return DECLINED;
	} */

	int real_len = strlen(n.buf);
	int slen = sendto(sock, n.buf, real_len, 0, (struct sockaddr*)&addr, sizeof(addr));

	if (slen == -1) {
		struct stat file_stat;
		if (stat("/usr/bin/write_daemon", &file_stat) == -1) {
			// missing, don't even try
			close(sock);
			return OK;
		}
		// try to run the daemon, which sould be in /usr/bin
		int pid = fork();
		if (pid == 0) { // child
			char *my_argv[7];
			my_argv[0] = "/usr/bin/write_daemon";
			my_argv[1] = "-f"; // do fork
			my_argv[2] = "-s"; // socket location
			my_argv[3] = strdup(conf->socket);
			my_argv[4] = "-t"; // target
			my_argv[5] = "/var/log/http/raw_";
			my_argv[6] = NULL;
			execv(my_argv[0], my_argv);
			exit(1);
		}
		if (pid > 0) {
			// forked
			int status;
			waitpid(pid, &status, 0); // wait for socket alloc
			// retry transmission
			slen = sendto(sock, n.buf, real_len, 0, (struct sockaddr*)&addr, sizeof(addr));
		}
		if (slen == -1) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to send log: %s", strerror(errno));
			close(sock);
			return DECLINED;
		}
	}

	close(sock);

//	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Estimated len: %d - string: %s", n.len, n.buf);

	return OK;
}

static void register_hooks(apr_pool_t *p) {
	static const char * const aszPre[]={ "mod_alias.c","mod_userdir.c",NULL };
	ap_hook_translate_name(autovhost_translate, aszPre, NULL, APR_HOOK_FIRST);
	ap_hook_log_transaction(autovhost_log,NULL,NULL,APR_HOOK_MIDDLE);
}

static const char *autovhost_set_prefix(cmd_parms *cmd, void *dummy, const char *map) {
	autovhost_sconf_t *conf;
	conf = (autovhost_sconf_t*)ap_get_module_config(cmd->server->module_config, &autovhost_module);

	if (!ap_os_is_path_absolute(cmd->pool, map)) {
		if (strcasecmp(map, "none")) {
			return "path string must be an absolute path, or 'none'";
		}
		conf->prefix = NULL;
		return NULL;
	}

	conf->prefix = map;
	return NULL;
}

static const char *autovhost_set_socket(cmd_parms *cmd, void *dummy, const char *map) {
	autovhost_sconf_t *conf;
	conf = (autovhost_sconf_t*)ap_get_module_config(cmd->server->module_config, &autovhost_module);

	if (!ap_os_is_path_absolute(cmd->pool, map)) {
		if (strcasecmp(map, "none")) {
			return "path string must be an absolute path, or 'none'";
		}
		conf->socket = NULL;
		return NULL;
	}

	conf->socket = map;
	return NULL;
}

static const command_rec autovhost_commands[] = {
	AP_INIT_TAKE1(
		"AutoVhostPrefix",
		autovhost_set_prefix,
		NULL,
		RSRC_CONF,
		"Allows definition of auto-vhost base root"
	),
	AP_INIT_TAKE1(
		"AutoVHostLogSocket",
		autovhost_set_socket,
		NULL,
		RSRC_CONF,
		"Allows definition of auto-vhost logging socket"
	),
	{ NULL }
};

module AP_MODULE_DECLARE_DATA autovhost_module = {
	STANDARD20_MODULE_STUFF,
	NULL, /* dir config creater */
	NULL, /* dir merger --- default is to override */
	autovhost_create_server_config,
	autovhost_merge_server_config,
	autovhost_commands,
	register_hooks
};

