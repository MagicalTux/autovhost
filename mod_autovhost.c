#include "apr.h"
#include "apr_strings.h"
#include "apr_hooks.h"
#include "apr_lib.h"

/* we are about to rape http_core. Let's get it undressed first */
#define CORE_PRIVATE

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"  /* for ap_hook_translate_name */
#include "http_protocol.h" /* for ap_hook_log_transaction */
#include "http_log.h"

#include "http_config.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

module AP_MODULE_DECLARE_DATA autovhost_module;

typedef struct autovhost_sconf_t {
	const char *prefix;
} autovhost_sconf_t;

struct autovhost_info {
	apr_pool_t *pool;
	char *host;
	char *vhost;
	char *basepath;
};

static const char c2x_table[] = "0123456789abcdef";

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

bool test_path(const char *prefix, const char *vhost, size_t vhost_len, const char *host, size_t len, struct autovhost_info *info) {
	char tmp_buf[256];
	char *tmp_ptr = (char*)&tmp_buf;
	size_t prefix_len = strlen(prefix);
	// transform in prefix/x/xy/buf/vhost. Final length: prefix+buf+vhost+7+NUL
	int final_len = vhost_len + len + prefix_len + 8;
	if (final_len > (sizeof(tmp_buf)-1)) return false;
	memcpy(tmp_ptr, prefix, prefix_len); tmp_ptr += prefix_len;
	*(tmp_ptr++) = '/';
	*(tmp_ptr++) = host[0];
	*(tmp_ptr++) = '/';
	*(tmp_ptr++) = host[0];
	*(tmp_ptr++) = host[1];
	*(tmp_ptr++) = '/';
	memcpy(tmp_ptr, host, len); tmp_ptr += len;
	char *tmp_ptr_end_of_host = tmp_ptr;
	*(tmp_ptr++) = '/';
	memcpy(tmp_ptr, vhost, vhost_len); tmp_ptr += vhost_len;
	*(tmp_ptr++) = 0;

	struct stat s;
	if (stat((char*)&tmp_buf, &s) == -1) return false;
	if (!S_ISDIR(s.st_mode)) return false;

	// found it!
	*tmp_ptr_end_of_host = 0;
	info->host = apr_pstrdup(info->pool, host);
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
	if (test_path(prefix, "_default", 8, host, len, info)) return true;
	if (test_path(prefix, "www", 3, host, len, info)) return true;

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
		if (test_path(prefix, vhost, vhost_len, host, len, info)) return true;
		// re-test subparts of vhost
		for(int i = 0; i < vhost_len; i++) {
			if (vhost[i] == '.') if (test_path(prefix, vhost + i + 1, vhost_len - (i+1), host, len, info)) return true;
		}
		// defaults
		if (test_path(prefix, "_default", 8, host, len, info)) return true;
		if (test_path(prefix, "www", 3, host, len, info)) return true;
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

	if (conf->prefix == NULL) return DECLINED;
	if (r->prev != NULL) return DECLINED; // do not touch (ie. waste time on already configured) subrequests

	struct autovhost_info *info = apr_pcalloc(r->pool, sizeof(struct autovhost_info));
	info->pool = r->pool;

	if (!scan_host(apr_pstrdup(r->pool, ap_get_server_name(r)), conf->prefix, info))
		return DECLINED; // no result :(

	if (info->basepath == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Success reported, but no info data");
		return DECLINED;
	}

	// duplicate string and assign ap_document_root - YAY THIS IS DIRTYYYYYYYYYYYYY!
	core_server_config *core_conf = ap_get_module_config(r->server->module_config, &core_module);
	core_conf->ap_document_root = apr_pstrcat(r->pool, info->basepath, "/", info->vhost, NULL);

	// prepare stuff to be able to push directives on Apache
	ap_directive_t *t = apr_pcalloc(r->pool, sizeof(ap_directive_t));
	cmd_parms parms;
	parms.pool = r->pool;
	parms.temp_pool = r->pool;
	parms.server = r->server;
	parms.override = OR_ALL|ACCESS_CONF|RSRC_CONF;//(RSRC_CONF | OR_ALL) & ~(OR_AUTHCFG | OR_LIMIT);
	parms.override_opts = OPT_ALL | OPT_SYM_OWNER | OPT_MULTI;
	parms.path = __FILE__;
	if (r->per_dir_config == NULL) {
		r->per_dir_config = ap_create_per_dir_config(r->pool);
	}

	// Fake some input headers to make us look better (DIRTY BIS)
	apr_table_add(r->headers_in, "X-VHost-Info", apr_pstrcat(r->pool, info->host, "/", info->vhost, NULL));

	// Configure apache options/etc (we made sure apache was nude with #define CORE_PRIVATE, now let's grop those privates)
	char *tmp = apr_pstrcat(r->pool, "doc_root \"", ap_escape_quotes(r->pool, core_conf->ap_document_root), "\"", NULL);
	PUSH_APACHE_DIRECTIVE("php_admin_value", tmp);
	tmp = apr_pstrcat(r->pool, "open_basedir \"/tmp/:/usr/share/fonts/php/:/dev/urandom:/proc/loadavg:/www/pear:/www/zend:", ap_escape_quotes(r->pool, info->basepath), "/\"", NULL);
	PUSH_APACHE_DIRECTIVE("php_admin_value", tmp);
	tmp = apr_pstrcat(r->pool, "session.save_path \"", ap_escape_quotes(r->pool, info->basepath), "/sessions\"", NULL);
	PUSH_APACHE_DIRECTIVE("php_admin_value", tmp);
//	PUSH_APACHE_DIRECTIVE("Options", "-Indexes");

	return DECLINED; /* we played with the config, but let apache continue processing normally, with the new informations we are providing */
}

static int autovhost_log(request_rec *r) {
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
//	char *logdata = apr_psprintf(r->pool, "%s", r->connection->remote_ip
	return OK;
}

static void register_hooks(apr_pool_t *p) {
	static const char * const aszPre[]={ "mod_alias.c","mod_userdir.c",NULL };
	ap_hook_translate_name(autovhost_translate, aszPre, NULL, APR_HOOK_MIDDLE);
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

static const command_rec autovhost_commands[] = {
	AP_INIT_TAKE1(
		"AutoVhostPrefix",
		autovhost_set_prefix,
		NULL,
		RSRC_CONF,
		"Allows definition of auto-vhost base root"
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

