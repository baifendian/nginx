
/*
 * Author: yi.wu@baifendian.com
 * for a simple auth proxy backend
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ldap.h>

typedef struct {
    u_char *host;
    u_int port;
    LDAP *ld;
} ngx_stream_simple_auth_srv_conf_t;

static ngx_int_t ngx_stream_simple_auth_handler(ngx_stream_session_t *s);
static char * ngx_stream_simple_auth_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_stream_simple_auth_init(ngx_conf_t *cf);
static void * ngx_stream_simple_auth_create_srv_conf(ngx_conf_t *cf);
static char * ngx_stream_simple_auth_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
ngx_int_t validate_inital_session(ngx_stream_session_t *s);
extern LDAP *ldap_init(const u_char *host, int port);
extern int ldap_simple_bind_s(LDAP *ld, const u_char *who, const u_char *passwd);
extern void ldap_unbind(LDAP *ld);

static ngx_command_t  ngx_stream_simple_auth_commands[] = {
    { ngx_string("simple_auth"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_simple_auth_rule,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_stream_module_t  ngx_stream_simple_auth_module_ctx = {
    ngx_stream_simple_auth_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_simple_auth_create_srv_conf,     /* create server configuration */
    ngx_stream_simple_auth_merge_srv_conf       /* merge server configuration */
};

ngx_module_t  ngx_stream_simple_auth_module = {
    NGX_MODULE_V1,
    &ngx_stream_simple_auth_module_ctx,         /* module context */
    ngx_stream_simple_auth_commands,            /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};
// ---------------module entries------------------
static void *
ngx_stream_simple_auth_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_simple_auth_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_simple_auth_srv_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->host = NGX_CONF_UNSET_PTR;
    conf->port = 389; // default
    conf->ld   = NGX_CONF_UNSET_PTR;
    return conf;
}

static char *
ngx_stream_simple_auth_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    // ngx_stream_simple_auth_srv_conf_t *prev = parent;
    // ngx_stream_simple_auth_srv_conf_t *conf = child;

    // ngx_conf_merge_uint_value(conf->min_radius, prev->min_radius, 10);
    // ngx_conf_merge_uint_value(conf->max_radius, prev->max_radius, 20);
    //
    // if (conf->min_radius < 1) {
    //     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
    //         "min_radius must be equal or more than 1");
    //     return NGX_CONF_ERROR;
    // }
    // if (conf->max_radius < conf->min_radius) {
    //     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
    //         "max_radius must be equal or more than min_radius");
    //     return NGX_CONF_ERROR;
    // }

    return NGX_CONF_OK;
}

static char *
ngx_stream_simple_auth_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_stream_simple_auth_srv_conf_t *ascf = conf;
  ngx_str_t                         *value;
  value = cf->args->elts;
  if (!value || !ascf) {
    return NGX_CONF_ERROR;
  }
  u_char *sep_char = ngx_strchr(value[1].data, ':');
  if (sep_char == NULL) {
    return NGX_CONF_ERROR;
  }

  ascf->host = ngx_palloc(cf->pool, sizeof(u_char)*(sep_char - value[1].data + 1));
  ngx_cpystrn(ascf->host, value[1].data, sep_char - value[1].data + 1);
  ngx_uint_t pass_length = value[1].len - (sep_char-value[1].data);
  u_char *port_str = ngx_palloc(cf->pool, sizeof(u_char) * pass_length);
  ngx_cpystrn(port_str, ++sep_char, pass_length);
  ascf->port = ngx_atoi(port_str, pass_length-1);
  ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
    "@@@@got in to simple auth config, host(%s), port(%d), port_str(%s), pass_length(%d)@@@@",
    ascf->host, ascf->port, port_str, pass_length);


  return NGX_CONF_OK;
}

static ngx_int_t ngx_stream_simple_auth_handler(ngx_stream_session_t *s)
{
  ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0, "@@@@got in to simple auth handler@@@@");
  ngx_int_t rc;
  if (!s->auth_pass) {
    rc = validate_inital_session(s);
    if (rc == 0) {
      s->auth_pass = 1;
      ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0, "@@@@ simple auth session grant@@@@");
      return NGX_OK;
    } else if (rc == -2) {
      return NGX_OK; // return for next call
    } else if (rc == -1) {
      return NGX_ERROR;
    }
  }
  ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0, "@@@@ simple auth session grant@@@@");
  return NGX_OK;
}

static ngx_int_t
ngx_stream_simple_auth_init(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    cmcf->auth_handler = ngx_stream_simple_auth_handler;
    return NGX_OK;
}
// ---------------------------------
ngx_int_t validate_inital_session(ngx_stream_session_t *s) {
  // validate the client buf, return 0 if validation OK
  ngx_stream_simple_auth_srv_conf_t *ascf;
  ngx_buf_t                         *b;
  ngx_connection_t                  *c;
  ngx_int_t                         rc = -1;
  int                               version, ldap_rc;
  c = s->connection;

  ascf = ngx_stream_get_module_srv_conf(s, ngx_stream_simple_auth_module);
  if (!ascf) {
    return -1;
  }
  // iterate ascf->rules to check input buf
  b = &s->upstream->downstream_buf;
  if (b->start != NULL) {
    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
      "@@@@in simple auth, downstream buffer: %s, pos(%d), last(%d)", b->start,
      b->pos-b->start, b->last-b->start);
  }
  // the buf may be anything!
  u_int auth_str_len = b->last - b->start;
  if (auth_str_len == 0) {
    return -2;
  }
  u_char *sep_char = ngx_strchr(b->start, ':');
  if (!sep_char) {
    return -1;
  }
  // copy the splited user name info
  u_char *user_name = ngx_palloc(c->pool, sizeof(u_char)*(sep_char - b->start + 1));
  if (!user_name){
    return -1;
  }
  ngx_cpystrn(user_name, b->start, sep_char - b->start + 1);
  ngx_uint_t pass_length = auth_str_len - (sep_char - b->start) - 1;
  u_char *passwd_hashed = ngx_palloc(c->pool, sizeof(u_char)*pass_length);
  if (!passwd_hashed) {
    return -1;
  }
  ngx_cpystrn(passwd_hashed, ++sep_char, pass_length);

  /* validate client auth package with LDAP */
  /* Bind to the LDAP server. user_name should be the DN */
  /* init connection to LDAP server when config. */

  /* Get a handle to an LDAP connection. */
  if ( (ascf->ld = ldap_init( ascf->host, ascf->port )) == NULL ) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
      "init LDAP connection error");
    return NGX_ERROR;
  }
  /* Specify the LDAP version supported by the client. */
  /* FIXME: version should be in config file */
  version = LDAP_VERSION3;
  ldap_set_option( ascf->ld, LDAP_OPT_PROTOCOL_VERSION, &version );

  ldap_rc = ldap_simple_bind_s( ascf->ld, user_name, passwd_hashed );
  if ( ldap_rc != LDAP_SUCCESS ) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                  "access forbidden by rule ldap_simple_bind_s: %s",
                  ldap_err2string(rc));
    rc = -1;
  } else {
    rc = 0;
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                  "user auth granted: %s",
                  user_name);
  }
  ldap_unbind( ascf->ld );
  /* clean buffer */
  b->pos = b->start;
  b->last = b->start;
  ngx_pfree(c->pool, user_name);
  ngx_pfree(c->pool, passwd_hashed);
  return rc;
}

