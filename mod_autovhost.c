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

bool test_path(const char *prefix, const char *vhost, size_t vhost_len, char *host, size_t len, char *buf, size_t buf_len) {
	char tmp_buf[256];
	char *tmp_ptr = (char*)&tmp_buf;
	size_t prefix_len = strlen(prefix);
	// transform in prefix+x/xy/buf/vhost. Final length: prefix+buf+vhost+6+NUL
	int final_len = vhost_len + len + prefix_len + 7;
	if (final_len > (sizeof(tmp_buf)-1)) return false;
	if (final_len > (buf_len-1)) return false;
	memcpy(tmp_ptr, prefix, prefix_len); tmp_ptr += prefix_len;
	*(tmp_ptr++) = host[0];
	*(tmp_ptr++) = '/';
	*(tmp_ptr++) = host[0];
	*(tmp_ptr++) = host[1];
	*(tmp_ptr++) = '/';
	memcpy(tmp_ptr, host, len); tmp_ptr += len;
	*(tmp_ptr++) = '/';
	memcpy(tmp_ptr, vhost, vhost_len); tmp_ptr += vhost_len;
	*(tmp_ptr++) = 0;

	struct stat s;
	if (stat((char*)&tmp_buf, &s) == -1) return false;
	if (!S_ISDIR(s.st_mode)) return false;

//	printf("test: %s\n", (char*)&tmp_buf);
	memcpy(buf, (char*)&tmp_buf, tmp_ptr-(char*)&tmp_buf);
	
	return true;
}

bool scan_host(const char *host_ro, const char *prefix, char *buf, size_t buf_len) {
	// check validity, only valid chars are a-z 0-9 . _
	// also, copy host_ro to new var host
	while(host_ro[0] == '.') host_ro++;
	size_t len = strlen(host_ro);
	if (len <= 0) return false;
	if (buf_len < len+1) return false;
	char *host = buf;
	memset(host, 0, len+1);

	char last_c = '.';
	for(int i = 0; i < len; i++) {
		char c = host_ro[i];
		if ((c == '.') && (last_c == '.')) return false; // invalid
		last_c = c;

		if (c >= 'A' && c <= 'Z') c += 32; // make lowercase
		if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '.') || (c == '-') || (c == '_')) {
			host[i] = c;
			continue;
		}
		return false;
	}

	// test for default paths
	if (test_path(prefix, "_default", 8, buf, len, buf, buf_len)) return true;
	if (test_path(prefix, "www", 3, buf, len, buf, buf_len)) return true;

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
		if (test_path(prefix, vhost, vhost_len, host, len, buf, buf_len)) return true;
		// re-test subparts of vhost
		for(int i = 0; i < vhost_len; i++) {
			if (vhost[i] == '.') if (test_path(prefix, vhost + i + 1, vhost_len - (i+1), host, len, buf, buf_len)) return true;
		}
		// defaults
		if (test_path(prefix, "_default", 8, host, len, buf, buf_len)) return true;
		if (test_path(prefix, "www", 3, host, len, buf, buf_len)) return true;
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

static int autovhost_translate(request_rec *r) {
	autovhost_sconf_t *conf;
	conf = (autovhost_sconf_t*)ap_get_module_config(r->server->module_config, &autovhost_module);

	// play with r here

	return DECLINED; // do nothing
}

static void register_hooks(apr_pool_t *p) {
	static const char * const aszPre[]={ "mod_alias.c","mod_userdir.c",NULL };
	ap_hook_translate_name(autovhost_translate, aszPre, NULL, APR_HOOK_MIDDLE);
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

