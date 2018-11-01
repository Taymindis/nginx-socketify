
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef enum  {
	NGX_SOCKETIFY_EOL_STR_MATCH = 1,
	NGX_SOCKETIFY_SCAN       = 2,
	NGX_SOCKETIFY_START_STR_MATCH = 3,

	NGX_SOCKETIFY_SCAN_AFTER = 5,
	NGX_SOCKETIFY_SCAN_FR_START = 6,

	NGX_SOCKETIFY_COUNT_AFTER = 7,
	NGX_SOCKETIFY_COUNT_FR_START = 8,
	NGX_SOCKETIFY_COUNT_NEXT = 9,

	NGX_SOCKETIFY_IN_BTWN_DEF = 11,
	NGX_SOCKETIFY_IN_BTWN_ASCII_LF = 12,
	NGX_SOCKETIFY_IN_BTWN_ASCII_RT = 13,
	NGX_SOCKETIFY_IN_BTWN_ASCII = 14,

	NGX_SOCKETIFY_FILTER_REGEX_RESP = 20,
	NGX_SOCKETIFY_FILTER_SUBSTRING_RESP = 21,
	NGX_SOCKETIFY_FILTER_APPEND_SUBSTRING_RESP = 22,
	NGX_SOCKETIFY_FILTER_APPEND_REGEX_RESP = 23,
	NGX_SOCKETIFY_DIRECT_RESP = 24,
	NGX_SOCKETIFY_DIRECT_APPEND_RESP = 25,


	// NGX_SOCKETIFY_PROXY_RESP_FILTER = 26,

	NGX_SOCKETIFY_NONE = 30
} enum_ngx_socketify_t;

typedef struct {
	ngx_queue_t swlcf_queue;
	ngx_array_t caches;  /* ngx_http_file_cache_t * */
} ngx_http_socketify_main_conf_t;

typedef struct {
	ngx_str_t                 *strstrfilter;
	ngx_int_t                  offset_lf;
	ngx_int_t                  offset_rt;
} ngx_http_socketify_substr_t;

typedef struct {
	ngx_str_t                 *strstrfilter;
	ngx_int_t                  offset_lf;
	ngx_int_t                  offset_rt;
	ngx_http_complex_value_t   datainput;
} ngx_http_socketify_substr_resp_var_t;

typedef struct {
	union {
		ngx_regex_t                 *regex;
		ngx_http_socketify_substr_t *substr;
	} t;
	ngx_str_t                 header_name;
	ngx_flag_t                is_header_in;
	ngx_flag_t                is_regex;
} ngx_http_socketify_filter_resp_to_hdr_t;

typedef struct {
	/* replace union --
	 ngx_regex_t                 *regex;
	 ngx_http_socketify_substr_t *substr;
	 ngx_str_t                   *app_str;*/
	void                       *filter_pt;
	ngx_uint_t                 http_resp_code;
	enum_ngx_socketify_t       filter_type;
} ngx_http_socketify_filter_resp_t;

#if (NGX_PCRE)
// typedef struct {
//   ngx_regex_t               *regex;
//   ngx_uint_t                 http_resp_code;
// } ngx_http_socketify_regexfilter_t;

typedef struct {
	ngx_regex_t               *regex;
	ngx_http_complex_value_t   datainput;
} ngx_http_socketify_regex_var_t;
#endif

typedef struct {
	enum_ngx_socketify_t       scan_type;
	ngx_str_t                  scan_after;
	enum_ngx_socketify_t       count_type;
	ngx_str_t                  count_after;
	ngx_uint_t                 extra_byte_cnt;
	ngx_int_t                  max_range_scanned;
} ngx_http_socketify_scan_match_t;

typedef struct {
	void			     *match_pt;
	enum_ngx_socketify_t match_type;
} ngx_http_socketify_done_recv_match_t;

typedef struct {
	ngx_queue_t _queue; // for swlcf_queue
	ngx_http_upstream_conf_t   upstream;
	ngx_uint_t                 gzip_flag;
	ngx_str_t                  sendbuf_cmds;
	ngx_http_complex_value_t   send_buf;
	ngx_uint_t                 unescape_type;
	ngx_str_t                  socket_schema;
	ngx_str_t                  content_type;

	ngx_uint_t                 nmatch;
	ngx_array_t 			  *done_recv_matches;
	ngx_array_t               *filt_resp;
	ngx_array_t               *filt_resp_to_hdrs;
	ngx_uint_t                nresp_appendable;


#if (NGX_HTTP_CACHE)
	ngx_http_complex_value_t       cache_key;
#endif
} ngx_http_socketify_loc_conf_t;

typedef struct {
	// ngx_http_request_t        *request;
	size_t                     scan_bytes;
	ngx_str_t                  cnt_next;
	ngx_uint_t                 nmatch; // incubating

	/**Filter installation**/
	ngx_chain_t             *free;
	ngx_chain_t             *busy;
	ngx_buf_t 				*ext_resp_buf;
} ngx_http_socketify_ctx_t;

typedef struct {
	ngx_http_complex_value_t   cplx_val;
	ngx_uint_t                 escape_type;
} ngx_http_socketify_escape_val_t;

// static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
// static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

#define NO_ESCAPE_REUQUIRED 9
#define JSON_ESCAPE_UNESC 6
#define HTML_ESCAPE_UNESC 7
#define CRLF_ESCAPE_UNESC 8

#define DEFAULT_MAX_RANGE_SCANNED 20 // Scanned for first 20 character, if no lenght number found, return invalid header

#define CLEAR_BUF(b)                      \
    b->pos = b->last;

static ngx_conf_enum_t  ngx_esc_unesc_type[] = {
	{ ngx_string("uri"), 0 },
	{ ngx_string("uri_args"), 1 },
	{ ngx_string("uri_component"), 2 },
	{ ngx_string("uri_html"), 3 },
	{ ngx_string("uri_refresh"), 4 },
	{ ngx_string("uri_memcached"), 5 },
	{ ngx_string("uri_redis"), 4 },
	{ ngx_string("json_string"),  JSON_ESCAPE_UNESC},
	{ ngx_string("multiline"),  CRLF_ESCAPE_UNESC},
	{ ngx_null_string, NO_ESCAPE_REUQUIRED }
};

#define content_type_plaintext "text/plain"
// #define content_type_html "text/html; charset=utf-8"
// #define content_type_json "application/json"
// #define content_type_jsonp "application/javascript"
// #define content_type_xformencoded "application/x-www-form-urlencoded"

#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_http_socketify_create_key(ngx_http_request_t *r);
static char *ngx_http_socketify_cache(ngx_conf_t *cf, ngx_command_t *cmd,
                                      void *conf);
static char *ngx_http_socketify_cache_key(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
#endif
static ngx_int_t ngx_http_socketify_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_socketify_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_socketify_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_socketify_header_resp_reupdate(ngx_http_request_t *r, ngx_http_socketify_loc_conf_t *swlcf, ngx_str_t *resp );
static ngx_int_t ngx_http_socketify_filter_init(void *data);
static ngx_int_t ngx_http_socketify_filter(void *data, ssize_t bytes);
static ngx_int_t ngx_http_socketify_copy_filter(ngx_event_pipe_t *p, ngx_buf_t *buf);
static void ngx_http_socketify_abort_request(ngx_http_request_t *r);
static void ngx_http_socketify_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

static ngx_int_t ngx_http_socketify_post_configuration(ngx_conf_t *cf);
static void *ngx_http_socketify_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_socketify_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_socketify_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_socketify_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_socketify_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_send_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_send_simple_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_send_ascii_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_scan_len_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_start_match_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_eol_match_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_done_recv_simple_match_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, enum_ngx_socketify_t match_type);
static char *ngx_conf_socketify_done_recv_ascii_match_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, enum_ngx_socketify_t match_type);
// static char *ngx_conf_socketify_proxy_resp_filter_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// static char *ngx_conf_socketify_eol_match_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_escape_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_ascii_to_char_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_strlen_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_socketify_get_escape_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_socketify_get_ascii_to_char_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_socketify_get_strlen_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static uintptr_t ngx_socketify_escape_crlf(u_char *dst, u_char *src, size_t size);
static u_char* ngx_socketify_unescape_crlf(u_char *src, size_t size);
uintptr_t ngx_socketify_escape_json(u_char *dst, u_char *src, size_t size);
u_char *ngx_socketify_unescape_json(u_char *src, size_t size);
static uintptr_t ngx_http_socketify_cache_headers_value(ngx_http_request_t *r, u_char* src, ngx_uint_t status_code, ngx_uint_t contentlen, ngx_str_t *content_type);
static uintptr_t ngx_http_socketify_int_to_string(u_char *str, size_t max_len, ngx_uint_t num);
static char* ngx_conf_socketify_ascii_to_string(ngx_pool_t *p, u_char* asciistr, u_char splitchar, ngx_str_t *rs);
static u_char *ngx_socketify_strstr(u_char *s1, size_t s1_len, u_char *s2, size_t s2_len );

#if (NGX_PCRE)
static char *ngx_conf_socketify_regex_filt_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_regex_resp_hdr_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_regex_filt_var_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_socketify_get_regex_filt_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
#endif

static char *ngx_conf_socketify_get_btwn_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_get_btwn_command_(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, enum_ngx_socketify_t btwn_type);
static char *ngx_conf_socketify_get_btwn_var_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_get_btwn_var_cmd_(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, enum_ngx_socketify_t btwn_type);
static ngx_int_t ngx_http_socketify_get_substr_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static char *ngx_conf_socketify_substr_hdr_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_substr_hdr_command_(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, enum_ngx_socketify_t btwn_type);
static char *ngx_conf_socketify_direct_append_resp_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_socketify_resp_appendable_check(ngx_array_t *filt_resps);
// static ngx_int_t ngx_http_socketify_header_filter(ngx_http_request_t *r);
// static ngx_int_t ngx_http_socketify_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

ngx_module_t  ngx_http_socketify_module;

static ngx_conf_bitmask_t  ngx_http_socketify_next_upstream_masks[] = {
	{ ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
	{ ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
	{ ngx_string("invalid_response"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
	{ ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
	{ ngx_string("non_idempotent"), NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
	{ ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
	{ ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
	{ ngx_string("http_403"), NGX_HTTP_UPSTREAM_FT_HTTP_403 },
	{ ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
#if (nginx_version >= 1012002)
	{ ngx_string("http_429"), NGX_HTTP_UPSTREAM_FT_HTTP_429 },
#endif
	{ ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
	{ ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
	{ ngx_null_string, 0 }
};

static ngx_command_t  ngx_http_socketify_commands[] = {

	{	ngx_string("socketify_pass"),
		NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
		ngx_http_socketify_pass,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
#if (NGX_HTTP_CACHE)

	{	ngx_string("socketify_cache"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_http_socketify_cache,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},

	{	ngx_string("socketify_cache_key"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_http_socketify_cache_key,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},

	{	ngx_string("socketify_cache_path"),
		NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE,
		ngx_http_file_cache_set_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_socketify_main_conf_t, caches),
		&ngx_http_socketify_module
	},

	{	ngx_string("socketify_cache_bypass"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
		ngx_http_set_predicate_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.cache_bypass),
		NULL
	},

	{	ngx_string("socketify_no_cache"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
		ngx_http_set_predicate_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.no_cache),
		NULL
	},

	{	ngx_string("socketify_cache_valid"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
		ngx_http_file_cache_valid_set_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.cache_valid),
		NULL
	},

	{	ngx_string("socketify_cache_min_uses"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.cache_min_uses),
		NULL
	},

#if (nginx_version >= 1012002)
	{	ngx_string("socketify_cache_max_range_offset"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_off_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.cache_max_range_offset),
		NULL
	},

	{	ngx_string("socketify_cache_background_update"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.cache_background_update),
		NULL
	},
#endif
	{	ngx_string("socketify_cache_use_stale"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
		ngx_conf_set_bitmask_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.cache_use_stale),
		&ngx_http_socketify_next_upstream_masks
	},

	{	ngx_string("socketify_cache_methods"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
		ngx_conf_set_bitmask_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.cache_methods),
		&ngx_http_upstream_cache_method_mask
	},

	{	ngx_string("socketify_cache_lock"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.cache_lock),
		NULL
	},

	{	ngx_string("socketify_cache_lock_timeout"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_msec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.cache_lock_timeout),
		NULL
	},

	{	ngx_string("socketify_cache_lock_age"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_msec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.cache_lock_age),
		NULL
	},

	{	ngx_string("socketify_cache_revalidate"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.cache_revalidate),
		NULL
	},

#endif

	{	ngx_string("socketify_buffering"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.buffering),
		NULL },

	{	ngx_string("socketify_ignore_headers"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
		ngx_conf_set_bitmask_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.ignore_headers),
		&ngx_http_upstream_ignore_headers_masks
	},
	{	ngx_string("socketify_bind"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
		ngx_http_upstream_bind_set_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.local),
		NULL
	},

	{	ngx_string("socketify_connect_timeout"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_msec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.connect_timeout),
		NULL
	},

	{	ngx_string("socketify_send_timeout"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_msec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.send_timeout),
		NULL
	},

	{	ngx_string("socketify_buffer_size"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_size_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.buffer_size),
		NULL
	},

	{	ngx_string("socketify_buffers"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
		ngx_conf_set_bufs_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.bufs),
		NULL
	},

	{	ngx_string("socketify_busy_buffers_size"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_size_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.busy_buffers_size_conf),
		NULL
	},

	{	ngx_string("socketify_read_timeout"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_msec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.read_timeout),
		NULL
	},

	{	ngx_string("socketify_next_upstream"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
		ngx_conf_set_bitmask_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.next_upstream),
		&ngx_http_socketify_next_upstream_masks
	},

	{	ngx_string("socketify_next_upstream_tries"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.next_upstream_tries),
		NULL
	},

	{	ngx_string("socketify_next_upstream_timeout"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_msec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.next_upstream_timeout),
		NULL
	},
	{	ngx_string("socketify_pass_request_headers"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.pass_request_headers),
		NULL
	},

	{	ngx_string("socketify_pass_request_body"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.pass_request_body),
		NULL
	},

	{	ngx_string("socketify_intercept_errors"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, upstream.intercept_errors),
		NULL
	},


	{	ngx_string("socketify_gzip_flag"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, gzip_flag),
		NULL
	},
	{	ngx_string("socketify_escape"),
		NGX_HTTP_SRV_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
		ngx_conf_socketify_escape_command,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	{	ngx_string("socketify_ascii_to_char"),
		NGX_HTTP_SRV_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
		ngx_conf_socketify_ascii_to_char_command,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	{	ngx_string("socketify_strlen"),
		NGX_HTTP_SRV_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
		ngx_conf_socketify_strlen_command,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	{	ngx_string("socketify_send"),
		NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
		ngx_conf_socketify_send_command,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	{
		ngx_string("socketify_done_recv_by_scan_len"),
		NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1234,
		ngx_conf_socketify_scan_len_command,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	{	ngx_string("socketify_done_recv_if_eol_match"),
		NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
		ngx_conf_socketify_eol_match_cmd,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	{	ngx_string("socketify_done_recv_if_start_match"),
		NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
		ngx_conf_socketify_start_match_cmd,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	// {	ngx_string("socketify_proxy_resp_filter"),
	// 	NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_NOARGS,
	// 	ngx_conf_socketify_proxy_resp_filter_cmd,
	// 	NGX_HTTP_LOC_CONF_OFFSET,
	// 	0,
	// 	NULL
	// },
	{	ngx_string("socketify_npacket_should_recv"),
		NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, nmatch),
		NULL
	},
	{	ngx_string("socketify_unescape_response"),
		NGX_HTTP_SRV_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_enum_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, unescape_type),
		&ngx_esc_unesc_type
	},
#if (NGX_PCRE)
	{	ngx_string("socketify_regex_filter_to_var"),
		NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE123,
		ngx_conf_socketify_regex_filt_var_cmd,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	{	ngx_string("socketify_regex_resp"),
		NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE12,
		ngx_conf_socketify_regex_filt_command,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	{	ngx_string("socketify_regex_resp_to_hdr"),
		NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE2,
		ngx_conf_socketify_regex_resp_hdr_cmd,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
#endif

	{	ngx_string("socketify_append_resp"),
		NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE12,
		ngx_conf_socketify_direct_append_resp_cmd,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},

	{	ngx_string("socketify_substr_to_var"),
		NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | (NGX_CONF_TAKE4 | NGX_CONF_TAKE6),
		ngx_conf_socketify_get_btwn_var_cmd,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	{	ngx_string("socketify_substr_resp"),
		NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_2MORE,
		ngx_conf_socketify_get_btwn_command,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	{	ngx_string("socketify_substr_resp_to_hdr"),
		NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | (NGX_CONF_TAKE3 | NGX_CONF_TAKE5),
		ngx_conf_socketify_substr_hdr_command,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	{	ngx_string("socketify_content_type"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, content_type),
		NULL
	},
	{	ngx_string("socketify_socket_schema"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_socketify_loc_conf_t, socket_schema),
		NULL
	},
	ngx_null_command
};

// #if (NGX_HTTP_CACHE)

// static ngx_keyval_t  ngx_http_socketify_cache_headers[] = {
//     { ngx_string("HTTP_IF_MODIFIED_SINCE"),
//       ngx_string("$upstream_cache_last_modified") },
//     { ngx_string("HTTP_IF_UNMODIFIED_SINCE"), ngx_string("") },
//     { ngx_string("HTTP_IF_NONE_MATCH"), ngx_string("$upstream_cache_etag") },
//     { ngx_string("HTTP_IF_MATCH"), ngx_string("") },
//     { ngx_string("HTTP_RANGE"), ngx_string("") },
//     { ngx_string("HTTP_IF_RANGE"), ngx_string("") },
//     { ngx_null_string, ngx_null_string }
// };

// #endif

static ngx_http_module_t  ngx_http_socketify_module_ctx = {
	NULL,                                  /* preconfiguration */
	ngx_http_socketify_post_configuration, /* postconfiguration */

	ngx_http_socketify_create_main_conf, /* create main configuration */
	ngx_http_socketify_init_main_conf, /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	ngx_http_socketify_create_loc_conf,    /* create location configuration */
	ngx_http_socketify_merge_loc_conf      /* merge location configuration */
};

ngx_module_t  ngx_http_socketify_module = {
	NGX_MODULE_V1,
	&ngx_http_socketify_module_ctx,        /* module context */
	ngx_http_socketify_commands,           /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};

/** substring s2, include null **/
static u_char *
ngx_socketify_strstr(u_char *s1, size_t s1_len, u_char *s2, size_t s2_len ) {
	u_char  c1, c2;
	size_t  i;

	c2 = *s2;
	do {
		c1 = *s1++;
		if (c1 == c2) {
			if (s2_len > s1_len) {
				return NULL;
			}
			for (i = 1; i < s2_len; i++) {
				if (*s1++ != s2[i]) {
					goto RE_SEARCH;
				}
			}
			return s1 - s2_len;
RE_SEARCH:
			continue;
		}
	} while (s1_len-- > 0);
	return NULL;
}


#if (NGX_HTTP_CACHE)

static char *
ngx_http_socketify_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_socketify_loc_conf_t *flcf = conf;

	ngx_str_t                         *value;
	ngx_http_complex_value_t           cv;
	ngx_http_compile_complex_value_t   ccv;

	value = cf->args->elts;

	if (flcf->upstream.cache != NGX_CONF_UNSET) {
		return "is duplicate";
	}

	if (ngx_strcmp(value[1].data, "off") == 0) {
		flcf->upstream.cache = 0;
		return NGX_CONF_OK;
	}

	if (flcf->upstream.store > 0) {
		return "is incompatible with \"socketify_store\"";
	}

	flcf->upstream.cache = 1;

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = &value[1];
	ccv.complex_value = &cv;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	if (cv.lengths != NULL) {

		flcf->upstream.cache_value = ngx_palloc(cf->pool,
		                                        sizeof(ngx_http_complex_value_t));
		if (flcf->upstream.cache_value == NULL) {
			return NGX_CONF_ERROR;
		}

		*flcf->upstream.cache_value = cv;

		return NGX_CONF_OK;
	}

	flcf->upstream.cache_zone = ngx_shared_memory_add(cf, &value[1], 0,
	                            &ngx_http_socketify_module);
	if (flcf->upstream.cache_zone == NULL) {
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}


static char *
ngx_http_socketify_cache_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_socketify_loc_conf_t *flcf = conf;

	ngx_str_t                         *value;
	ngx_http_compile_complex_value_t   ccv;

	value = cf->args->elts;

	if (flcf->cache_key.value.data) {
		return "is duplicate";
	}

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = &value[1];
	ccv.complex_value = &flcf->cache_key;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

#endif

static char *
ngx_conf_socketify_escape_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_str_t                             *values;
	ngx_http_compile_complex_value_t       ccv;
	ngx_str_t                              varname;
	ngx_uint_t                             i;
	ngx_http_socketify_escape_val_t    *eval_buf;


	values = cf->args->elts;

	if (cf->args->nelts == 4) {
		eval_buf = ngx_pcalloc(cf->pool, sizeof(ngx_http_socketify_escape_val_t));
		eval_buf->escape_type = NGX_CONF_UNSET_UINT;
		ngx_memzero(&eval_buf->cplx_val, sizeof(ngx_http_complex_value_t));

		ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
		ccv.cf = cf;
		ccv.value = &values[1];
		ccv.complex_value = &eval_buf->cplx_val;

		if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
			return NGX_CONF_ERROR;
		}

		for (i = 0; ngx_esc_unesc_type[i].name.len != 0; i++) {
			if (ngx_esc_unesc_type[i].name.len != values[2].len
			        || ngx_strcasecmp(ngx_esc_unesc_type[i].name.data, values[2].data) != 0)
			{
				continue;
			}

			eval_buf->escape_type = ngx_esc_unesc_type[i].value;
		}

		varname.data = values[3].data;
		varname.len = values[3].len;
		ngx_http_variable_t  *var;
		var = ngx_http_add_variable(cf, &varname, NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH);
		if (var == NULL) {
			return NGX_CONF_ERROR;
		}
		var->get_handler = ngx_http_socketify_get_escape_var;
		var->data = (uintptr_t) eval_buf;
	} else {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid argument given, should be %s\n%s",
		                   "socketify_escape <content_to_escape> <escape_type> <response_to_var>",
		                   "e.g. socketify_escape $request_body redis escaped_body");
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static char *
ngx_conf_socketify_ascii_to_char_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_str_t                             *values;
	ngx_str_t                              varname;
	ngx_uint_t                             *ascii_number; // 0-255 only

	values = cf->args->elts;

	if (cf->args->nelts == 3) {
		ascii_number = ngx_pcalloc(cf->pool, sizeof(ngx_uint_t));

		*ascii_number = ngx_atoi(values[1].data, values[1].len);
		if (*ascii_number == (ngx_uint_t) NGX_ERROR || *ascii_number > 255 ) {
			return "invalid number via adding extra bytes";
		}

		varname.data = values[2].data;
		varname.len = values[2].len;

		ngx_http_variable_t  *var;
		var = ngx_http_add_variable(cf, &varname, NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH);
		if (var == NULL) {
			return NGX_CONF_ERROR;
		}
		var->get_handler = ngx_http_socketify_get_ascii_to_char_var;
		var->data = (uintptr_t) ascii_number;
	} else {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid argument given, should be %s\n%s",
		                   "socketify_ascii_to_char <number 0-255> variable",
		                   "e.g. socketify_ascii_to_char 0 nullstring");
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static char *
ngx_conf_socketify_strlen_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_str_t                             *values;
	ngx_http_compile_complex_value_t       ccv;
	ngx_str_t                              varname;
	ngx_http_complex_value_t              *eval_buf;

	values = cf->args->elts;

	if (cf->args->nelts == 3) {
		eval_buf = ngx_pcalloc(cf->pool, sizeof(ngx_http_complex_value_t));
		ngx_memzero(eval_buf, sizeof(ngx_http_complex_value_t));

		ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
		ccv.cf = cf;
		ccv.value = &values[1];
		ccv.complex_value = eval_buf;

		if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
			return NGX_CONF_ERROR;
		}

		varname.data = values[2].data;
		varname.len = values[2].len;
		ngx_http_variable_t  *var;
		var = ngx_http_add_variable(cf, &varname, NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH);
		if (var == NULL) {
			return NGX_CONF_ERROR;
		}
		var->get_handler = ngx_http_socketify_get_strlen_var;
		var->data = (uintptr_t) eval_buf;
	} else {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid argument given, should be %s\n%s",
		                   "socketify_strlen <content> <response_to_var>",
		                   "e.g. socketify_strlen $arg_key key_len");
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static char *
ngx_conf_socketify_send_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_str_t *values = cf->args->elts;
	values = values + 1;
	if ( ngx_strncmp(values->data, (char*)"ascii=", sizeof("ascii=") - 1 ) == 0 ) {
		values->data += (sizeof("ascii=") - 1);
		values->len -= (sizeof("ascii=") - 1);
		return ngx_conf_socketify_send_ascii_command(cf, cmd, conf);
	} else {
		return ngx_conf_socketify_send_simple_command(cf, cmd, conf);
	}
}

static char *
ngx_conf_socketify_send_simple_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_socketify_main_conf_t *swmcf;
	ngx_http_socketify_loc_conf_t *swlcf = conf;
	ngx_str_t                         *values, *sendbuf_cmds;
	u_char                            *p;

	swmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_socketify_module);
	if (swmcf == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "socket writer config not found. ");
		return NGX_CONF_ERROR;
	}

	values = cf->args->elts;
	sendbuf_cmds = &swlcf->sendbuf_cmds;

	if (values[1].len == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no socket buffer to write.. ");
		return NGX_CONF_ERROR;
	}

	p = ngx_pcalloc(cf->pool, sendbuf_cmds->len + values[1].len );

	if (sendbuf_cmds->len > 0) {
		ngx_memcpy(p, sendbuf_cmds->data, sendbuf_cmds->len);
		ngx_memcpy(p + sendbuf_cmds->len, values[1].data, values[1].len);
		ngx_pfree(cf->pool, sendbuf_cmds->data);
		sendbuf_cmds->data = p;
		sendbuf_cmds->len += values[1].len;
	} else {
		ngx_memcpy(p, values[1].data, values[1].len);
		sendbuf_cmds->data = p;
		sendbuf_cmds->len = values[1].len;
	}

	if (swlcf->_queue.next == NGX_CONF_UNSET_PTR) {
		ngx_queue_init(&swlcf->_queue);
		ngx_queue_insert_tail(&swmcf->swlcf_queue, &swlcf->_queue);
	}
	return NGX_CONF_OK;
}

static char *
ngx_conf_socketify_send_ascii_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_socketify_main_conf_t *swmcf;
	ngx_http_socketify_loc_conf_t *swlcf = conf;
	ngx_str_t                         *values, *sendbuf_cmds;
	u_char                            *p;
	ngx_str_t                          asciistr;

	swmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_socketify_module);
	if (swmcf == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "socket writer config not found. ");
		return NGX_CONF_ERROR;
	}

	values = cf->args->elts;
	sendbuf_cmds = &swlcf->sendbuf_cmds;

	if (values[1].len == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no socket buffer to write.. ");
		return NGX_CONF_ERROR;
	}

	if ( NGX_CONF_OK != (char*) (p = (u_char*) ngx_conf_socketify_ascii_to_string(cf->pool, values[1].data, (u_char)'|', &asciistr) ) ) {
		return (char*) p;
	}

	p = ngx_pcalloc(cf->pool, sendbuf_cmds->len + asciistr.len );

	if (sendbuf_cmds->len > 0) {
		ngx_memcpy(p, sendbuf_cmds->data, sendbuf_cmds->len);
		ngx_memcpy(p + sendbuf_cmds->len, asciistr.data, asciistr.len);
		ngx_pfree(cf->pool, sendbuf_cmds->data);
		sendbuf_cmds->data = p;
		sendbuf_cmds->len += asciistr.len;
	} else {
		ngx_memcpy(p, asciistr.data, asciistr.len);
		sendbuf_cmds->data = p;
		sendbuf_cmds->len = asciistr.len;
	}

	if (swlcf->_queue.next == NGX_CONF_UNSET_PTR) {
		ngx_queue_init(&swlcf->_queue);
		ngx_queue_insert_tail(&swmcf->swlcf_queue, &swlcf->_queue);
	}
	return NGX_CONF_OK;
}

static char *
ngx_conf_socketify_scan_len_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_socketify_loc_conf_t         *swlcf = conf;
	ngx_str_t                             *values;
	ngx_http_socketify_done_recv_match_t  *drm;
	ngx_uint_t                            i;
	ngx_http_socketify_scan_match_t       *sm;

	if (swlcf->done_recv_matches == NULL || swlcf->done_recv_matches == NGX_CONF_UNSET_PTR) {
		swlcf->done_recv_matches = ngx_array_create(cf->pool, 3, sizeof(ngx_http_socketify_done_recv_match_t));
	}

	drm = swlcf->done_recv_matches->elts;

	for (i = 0; i < swlcf->done_recv_matches->nelts; i++) {
		if ( drm->match_type == NGX_SOCKETIFY_SCAN ) {
			return "scan len command cannot be more than 1 in one location directive";
		}
	}


	sm = ngx_pcalloc(cf->pool, sizeof(ngx_http_socketify_scan_match_t));
	if (sm == NULL) {
		return "Error insufficient memory";
	}

	sm->max_range_scanned = DEFAULT_MAX_RANGE_SCANNED;
	sm->scan_type = NGX_SOCKETIFY_SCAN_FR_START;
	sm->count_type = NGX_SOCKETIFY_COUNT_NEXT;
	sm->extra_byte_cnt = 0;

	values = cf->args->elts;

	for (i = 1; i < cf->args->nelts; i ++) {
		if ( ngx_strncmp(values[i].data, (char*)"scan_aft=", sizeof("scan_aft=") - 1 ) == 0 ) {
			if ( values[i].len > sizeof("scan_aft=") - 1 ) {
				sm->scan_after.data = (values[i].data + sizeof("scan_aft=") - 1);
				sm->scan_after.len = ngx_strlen(sm->scan_after.data);
				sm->scan_type = NGX_SOCKETIFY_SCAN_AFTER;
			}
		} else if ( ngx_strncmp(values[i].data, (char*)"scan_range=", sizeof("scan_range=") - 1 ) == 0 ) {
			if ( values[i].len > sizeof("scan_range=") - 1 ) {
				sm->max_range_scanned  = ngx_atoi(values[i].data +  sizeof("scan_range=") - 1, values[i].len - (sizeof("scan_range=") - 1) );
				if (sm->max_range_scanned == NGX_ERROR) {
					return "invalid number via adding scan_range";
				}
			}
		} else if ( ngx_strncmp(values[i].data, (char*)"count_aft=", sizeof("count_aft=") - 1 ) == 0 ) {
			if ( values[i].len > sizeof("count_aft=") - 1 ) {
				sm->count_after.data = (values[i].data + sizeof("count_aft=") - 1);
				sm->count_after.len = ngx_strlen(sm->count_after.data);
				sm->count_type = NGX_SOCKETIFY_COUNT_AFTER;
			} else {
				sm->count_type = NGX_SOCKETIFY_COUNT_FR_START;
			}
		} else if ( ngx_strncmp(values[i].data, (char*)"count_extra=", sizeof("count_extra=") - 1 ) == 0 ) {
			if ( values[i].len > sizeof("count_extra=") - 1 ) {
				sm->extra_byte_cnt  = ngx_atoi(values[i].data +  sizeof("count_extra=") - 1, values[i].len - (sizeof("count_extra=") - 1) );
				if (sm->extra_byte_cnt == (ngx_uint_t) NGX_ERROR) {
					return "invalid number via adding count_extra";
				}
			}
		}
	}

	drm = ngx_array_push(swlcf->done_recv_matches);
	if (drm == NULL) {
		return "Error insufficient memory";
	}
	drm->match_type = NGX_SOCKETIFY_SCAN;
	drm->match_pt = sm;

	return NGX_CONF_OK;
}

static char *
ngx_conf_socketify_start_match_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_str_t *values = cf->args->elts;
	values = values + 1;

	if ( ngx_strncmp(values->data, (char*)"ascii=", sizeof("ascii=") - 1 ) == 0 ) {
		values->data += (sizeof("ascii=") - 1);
		values->len -= (sizeof("ascii=") - 1);
		return ngx_conf_socketify_done_recv_ascii_match_cmd(cf, cmd, conf, NGX_SOCKETIFY_START_STR_MATCH);
	} else {
		return ngx_conf_socketify_done_recv_simple_match_cmd(cf, cmd, conf, NGX_SOCKETIFY_START_STR_MATCH);
	}
}

static char *
ngx_conf_socketify_eol_match_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_str_t *values = cf->args->elts;
	values = values + 1;

	if ( ngx_strncmp(values->data, (char*)"ascii=", sizeof("ascii=") - 1 ) == 0 ) {
		values->data += (sizeof("ascii=") - 1);
		values->len -= (sizeof("ascii=") - 1);
		return ngx_conf_socketify_done_recv_ascii_match_cmd(cf, cmd, conf, NGX_SOCKETIFY_EOL_STR_MATCH);
	} else {
		return ngx_conf_socketify_done_recv_simple_match_cmd(cf, cmd, conf, NGX_SOCKETIFY_EOL_STR_MATCH);
	}
}

static char *
ngx_conf_socketify_done_recv_simple_match_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, enum_ngx_socketify_t match_type) {
	ngx_http_socketify_loc_conf_t         *swlcf = conf;
	ngx_http_socketify_done_recv_match_t  *drm;
	ngx_str_t                             *values, *match_val;

	values = cf->args->elts;

	if (swlcf->done_recv_matches == NULL || swlcf->done_recv_matches == NGX_CONF_UNSET_PTR) {
		swlcf->done_recv_matches = ngx_array_create(cf->pool, 3, sizeof(ngx_http_socketify_done_recv_match_t));
	}

	drm = ngx_array_push(swlcf->done_recv_matches);
	if (drm == NULL) {
		return "Error insufficient memory";
	}
	match_val = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
	if (match_val == NULL) {
		return "Error insufficient memory";
	}
	match_val->len = values[1].len;
	match_val->data = values[1].data;

	drm->match_pt = match_val;
	drm->match_type = match_type;

	return NGX_CONF_OK;
}

static char *
ngx_conf_socketify_done_recv_ascii_match_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, enum_ngx_socketify_t match_type) {
	ngx_http_socketify_loc_conf_t         *swlcf = conf;
	ngx_http_socketify_done_recv_match_t  *drm;
	ngx_str_t                             *values, *match_val;
	char*                                 status;

	values = cf->args->elts;

	if (swlcf->done_recv_matches == NULL || swlcf->done_recv_matches == NGX_CONF_UNSET_PTR) {
		swlcf->done_recv_matches = ngx_array_create(cf->pool, 3, sizeof(ngx_http_socketify_done_recv_match_t));
	}

	drm = ngx_array_push(swlcf->done_recv_matches);
	if (drm == NULL) {
		return "Error insufficient memory";
	}
	match_val = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
	if (match_val == NULL) {
		return "Error insufficient memory";
	}

	if ( (status = ngx_conf_socketify_ascii_to_string(cf->pool, values[1].data, (u_char)'|', match_val) ) != NGX_CONF_OK ) {
		return status;
	}

	drm->match_pt = match_val;
	drm->match_type = match_type;

	return NGX_CONF_OK;
}

#if (NGX_PCRE)
static char *
ngx_conf_socketify_regex_filt_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_socketify_loc_conf_t        *swlcf = conf;
	ngx_str_t                            *values;
	ngx_http_socketify_filter_resp_t     *regexfilter;
	ngx_regex_compile_t                  rc;
	char                                 *status;

	if (swlcf->filt_resp == NULL || swlcf->filt_resp == NGX_CONF_UNSET_PTR) {
		swlcf->filt_resp = ngx_array_create(cf->pool, 3, sizeof(ngx_http_socketify_filter_resp_t));
	}

	values = cf->args->elts;
	u_char               errstr[NGX_MAX_CONF_ERRSTR];

	ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

	rc.pattern = values[1];
	rc.pool = cf->pool;
	rc.err.len = NGX_MAX_CONF_ERRSTR;
	rc.err.data = errstr;
	rc.options = PCRE_MULTILINE;

// #if (NGX_HAVE_CASELESS_FILESYSTEM)
//   rc.options = NGX_REGEX_CASELESS;
// #else
//   rc.options = caseless ? NGX_REGEX_CASELESS : 0;
// #endif

	if (ngx_regex_compile(&rc) != NGX_OK) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
		return NGX_CONF_ERROR;
	}

	if (rc.captures != 1) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		                   "output filter pattern \"%V\" must have only 1 captures", &values[1]);
		return NGX_CONF_ERROR;
	}

	regexfilter = ngx_array_push(swlcf->filt_resp);
	if (regexfilter == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,  "no enuff memory");
		return NGX_CONF_ERROR;
	}

	regexfilter->filter_type = NGX_SOCKETIFY_FILTER_REGEX_RESP;
	regexfilter->filter_pt = rc.regex;
	regexfilter->http_resp_code = 200; // DEFAULT
	if (cf->args->nelts == 3) {
		if ( (sizeof("append") - 1) == values[2].len && ngx_strcmp(values[2].data, (char*)"append") == 0 ) {
			status = ngx_conf_socketify_resp_appendable_check(swlcf->filt_resp);
			if ( status != NGX_CONF_OK ) {
				return status;
			}
			swlcf->nresp_appendable++;
			regexfilter->filter_type = NGX_SOCKETIFY_FILTER_APPEND_REGEX_RESP;
		} else {
			regexfilter->http_resp_code = ngx_atoi(values[2].data, values[2].len);
			if (regexfilter->http_resp_code == (ngx_uint_t) NGX_ERROR) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				                   "Invalid response code given %V", &values[2]);
				return NGX_CONF_ERROR;
			}
		}
	}

	return NGX_CONF_OK;
}

/** Using for post action header variable **/
static char *
ngx_conf_socketify_regex_resp_hdr_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_socketify_loc_conf_t            *swlcf = conf;
	ngx_str_t                                    *values;
	ngx_http_socketify_filter_resp_to_hdr_t   *filters_hdr;

	if (swlcf->filt_resp_to_hdrs == NULL || swlcf->filt_resp_to_hdrs == NGX_CONF_UNSET_PTR) {
		swlcf->filt_resp_to_hdrs = ngx_array_create(cf->pool, 3, sizeof(ngx_http_socketify_filter_resp_to_hdr_t));
	}

	values = cf->args->elts;

	ngx_regex_compile_t  rc;
	u_char               errstr[NGX_MAX_CONF_ERRSTR];

	ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

	rc.pattern = values[1];
	rc.pool = cf->pool;
	rc.err.len = NGX_MAX_CONF_ERRSTR;
	rc.err.data = errstr;
	rc.options = PCRE_MULTILINE;

	if (ngx_regex_compile(&rc) != NGX_OK) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
		return NGX_CONF_ERROR;
	}

	if (rc.captures != 1) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		                   "output filter pattern \"%V\" must have only 1 captures", &values[1]);
		return NGX_CONF_ERROR;
	}

	filters_hdr = ngx_array_push(swlcf->filt_resp_to_hdrs);
	if (filters_hdr == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,  "no enuff memory");
		return NGX_CONF_ERROR;
	}

	filters_hdr->t.regex = rc.regex;
	filters_hdr->is_regex = 1;
	if ( ngx_strncmp(values[2].data, (char*)"header_in=", sizeof("header_in=") - 1 ) == 0 ) {
		filters_hdr->header_name.data = values[2].data + sizeof("header_in=") - 1;
		filters_hdr->header_name.len = ngx_strlen(filters_hdr->header_name.data);
		filters_hdr->is_header_in = 1;
	} else if ( ngx_strncmp(values[2].data, (char*)"header_out=", sizeof("header_out=") - 1 ) == 0 ) {
		filters_hdr->header_name.data = values[2].data + sizeof("header_out=") - 1;
		filters_hdr->header_name.len = ngx_strlen(filters_hdr->header_name.data);
		filters_hdr->is_header_in = 0;
	} else {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,  "no valid on argument 2, header_in= / header_out=");
		return NGX_CONF_ERROR;
	}
	return NGX_CONF_OK;
}

static char *
ngx_conf_socketify_regex_filt_var_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_str_t                             *values;
	ngx_str_t                              varname;
	ngx_regex_compile_t                    rc;
	u_char                                 errstr[NGX_MAX_CONF_ERRSTR];
	ngx_http_socketify_regex_var_t     *regex_var;
	ngx_http_compile_complex_value_t       ccv;

	values = cf->args->elts;

	regex_var = ngx_pcalloc(cf->pool, sizeof(ngx_http_socketify_regex_var_t));

	if (cf->args->nelts == 4) {
		ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
		ccv.cf = cf;
		ccv.value = &values[1];
		ccv.complex_value = &regex_var->datainput;

		if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
			return NGX_CONF_ERROR;
		}

		ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

		rc.pattern = values[2];
		rc.pool = cf->pool;
		rc.err.len = NGX_MAX_CONF_ERRSTR;
		rc.err.data = errstr;
		rc.options = PCRE_MULTILINE;

		if (ngx_regex_compile(&rc) != NGX_OK) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
			return NGX_CONF_ERROR;
		}

		if (rc.captures != 1) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			                   "output filter pattern \"%V\" must have only 1 captures", &values[2]);
			return NGX_CONF_ERROR;
		}

		regex_var->regex = rc.regex;

		varname.data = values[3].data;
		varname.len = values[3].len;

		ngx_http_variable_t  *var;
		var = ngx_http_add_variable(cf, &varname, NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH);
		if (var == NULL) {
			return NGX_CONF_ERROR;
		}
		var->get_handler = ngx_http_socketify_get_regex_filt_var;
		var->data = (uintptr_t) regex_var;
	} else {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid argument given, should be %s",
		                   "socketify_regex_filter_to_var <data> <regex> output_var");
		return NGX_CONF_ERROR;
	}
	return NGX_CONF_OK;
}
#endif

static char *
ngx_conf_socketify_get_btwn_var_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_str_t *values = cf->args->elts;
	values = values + 2;
	ngx_str_t *values2 = values + 1;

	if ( (ngx_strncmp(values->data, (char*)"ascii=", sizeof("ascii=") - 1 ) == 0) &&
	        (ngx_strncmp(values2->data, (char*)"ascii=", sizeof("ascii=") - 1 ) == 0) ) {
		values->data += (sizeof("ascii=") - 1);
		values->len -= (sizeof("ascii=") - 1);
		values2->data += (sizeof("ascii=") - 1);
		values2->len -= (sizeof("ascii=") - 1);
		return ngx_conf_socketify_get_btwn_var_cmd_(cf, cmd, conf, NGX_SOCKETIFY_IN_BTWN_ASCII);
	} else if ( (ngx_strncmp(values->data, (char*)"ascii=", sizeof("ascii=") - 1 ) == 0) ) {
		values->data += (sizeof("ascii=") - 1);
		values->len -= (sizeof("ascii=") - 1);
		return ngx_conf_socketify_get_btwn_var_cmd_(cf, cmd, conf, NGX_SOCKETIFY_IN_BTWN_ASCII_LF);
	} else if ( (ngx_strncmp(values2->data, (char*)"ascii=", sizeof("ascii=") - 1 ) == 0) ) {
		values2->data += (sizeof("ascii=") - 1);
		values2->len -= (sizeof("ascii=") - 1);
		return ngx_conf_socketify_get_btwn_var_cmd_(cf, cmd, conf, NGX_SOCKETIFY_IN_BTWN_ASCII_RT);
	} else {
		return ngx_conf_socketify_get_btwn_var_cmd_(cf, cmd, conf, NGX_SOCKETIFY_IN_BTWN_DEF);
	}
}

static char *
ngx_conf_socketify_get_btwn_var_cmd_(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, enum_ngx_socketify_t btwn_type) {
	ngx_str_t                             *values;
	ngx_uint_t                             i, j = 0;
	ngx_flag_t                             is_negative;
	ngx_str_t                              varname;
	ngx_http_socketify_substr_resp_var_t *_btwn;

	values = cf->args->elts;
	if (cf->args->nelts == 5 || cf->args->nelts == 7) {
		_btwn = ngx_pcalloc(cf->pool, sizeof(ngx_http_socketify_substr_resp_var_t) );
		if (_btwn == NULL) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,  "no enuff memory");
			return NGX_CONF_ERROR;
		}

		ngx_http_compile_complex_value_t   ccv;
		ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
		ccv.cf = cf;
		ccv.value = &values[1];
		ccv.complex_value = &_btwn->datainput;

		if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
			return NGX_CONF_ERROR;
		}

		_btwn->offset_lf = 0; // DEFAULT
		_btwn->offset_rt = 0; // DEFAULT
		_btwn->strstrfilter = ngx_pcalloc(cf->pool, sizeof(ngx_str_t) * 2);

		for (i = 2; i < cf->args->nelts - 1/*6*/; i++) {
			if ( i == 4) {
				if (*(values[i].data) == '-') {
					is_negative = 1;
					values[i].data++;
					values[i].len--;
				} else {
					is_negative = 0;
				}
				_btwn->offset_lf = ngx_atoi(values[i].data, values[i].len);
				if (_btwn->offset_lf == NGX_ERROR) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					                   "Invalid offset number %V", &values[i]);
					return NGX_CONF_ERROR;
				}

				if ( values[2].len < (ngx_uint_t) _btwn->offset_lf) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					                   "Invalid offset left number, should not be more than the data range %V", &values[2]);
					return NGX_CONF_ERROR;
				}

				if (is_negative) {
					_btwn->offset_lf *= -1;
				}
			} else if (i == 5) {
				if (*(values[i].data) == '-') {
					is_negative = 1;
					values[i].data++;
					values[i].len--;
				} else {
					is_negative = 0;
				}
				_btwn->offset_rt = ngx_atoi(values[i].data, values[i].len);
				if (_btwn->offset_rt == NGX_ERROR) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					                   "Invalid offset number %V", &values[i]);
					return NGX_CONF_ERROR;
				}

				if (values[3].len < (ngx_uint_t) _btwn->offset_rt) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					                   "Invalid offset right number, should not be more than the data range %V", &values[3]);
					return NGX_CONF_ERROR;
				}

				if (is_negative) {
					_btwn->offset_rt *= -1;
				}
			}  else if (values[i].len == 0) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				                   "Text cannot be empty %V", &values[i]);
				return NGX_CONF_ERROR;
			} else {
				if (j == 2) {
					return "Index out of bound";
				}
				switch (btwn_type) {
				case NGX_SOCKETIFY_IN_BTWN_DEF:
					_btwn->strstrfilter[j].data = values[i].data;
					_btwn->strstrfilter[j].len = values[i].len;
					break;
				case NGX_SOCKETIFY_IN_BTWN_ASCII:
					if ( ngx_conf_socketify_ascii_to_string(cf->pool, values[i].data,
					                                        (u_char)'|', &_btwn->strstrfilter[j]) != NGX_CONF_OK ) {
						return "Error via processing socketify_substr_to_var";
					}
					break;
				case NGX_SOCKETIFY_IN_BTWN_ASCII_LF:
					if ( i == 2 ) {
						if ( ngx_conf_socketify_ascii_to_string(cf->pool, values[i].data,
						                                        (u_char)'|', &_btwn->strstrfilter[j]) != NGX_CONF_OK ) {
							return "Error via processing socketify_substr_to_var";
						}
					} else {
						_btwn->strstrfilter[j].data = values[i].data;
						_btwn->strstrfilter[j].len = values[i].len;
					}
					break;
				case NGX_SOCKETIFY_IN_BTWN_ASCII_RT:
					if ( i == 3 ) {
						if ( ngx_conf_socketify_ascii_to_string(cf->pool, values[i].data,
						                                        (u_char)'|', &_btwn->strstrfilter[j]) != NGX_CONF_OK ) {
							return "Error via processing socketify_substr_to_var";
						}
					} else {
						_btwn->strstrfilter[j].data = values[i].data;
						_btwn->strstrfilter[j].len = values[i].len;
					}
					break;
				default:
					break;
				}
				j++;
			}
		}
	} else {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid argument given, should be %s",
		                   "socketify_substr_to_var <datainput> <[ascii=]lf> <[ascii=]rt> <offsetlf> <offsetrt> output_var");
		return NGX_CONF_ERROR;
	}

	varname.data = values[i].data;
	varname.len = values[i].len;

	ngx_http_variable_t  *var;
	var = ngx_http_add_variable(cf, &varname, NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH);
	if (var == NULL) {
		return NGX_CONF_ERROR;
	}
	var->get_handler = ngx_http_socketify_get_substr_var;
	var->data = (uintptr_t) _btwn;

	return NGX_CONF_OK;
}

static char *
ngx_conf_socketify_get_btwn_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_str_t *values = cf->args->elts;
	values = values + 1;
	ngx_str_t *values2 = values + 1;

	if ( (ngx_strncmp(values->data, (char*)"ascii=", sizeof("ascii=") - 1 ) == 0) &&
	        (ngx_strncmp(values2->data, (char*)"ascii=", sizeof("ascii=") - 1 ) == 0) ) {
		values->data += (sizeof("ascii=") - 1);
		values->len -= (sizeof("ascii=") - 1);
		values2->data += (sizeof("ascii=") - 1);
		values2->len -= (sizeof("ascii=") - 1);
		return ngx_conf_socketify_get_btwn_command_(cf, cmd, conf, NGX_SOCKETIFY_IN_BTWN_ASCII);
	} else if ( (ngx_strncmp(values->data, (char*)"ascii=", sizeof("ascii=") - 1 ) == 0) ) {
		values->data += (sizeof("ascii=") - 1);
		values->len -= (sizeof("ascii=") - 1);
		return ngx_conf_socketify_get_btwn_command_(cf, cmd, conf, NGX_SOCKETIFY_IN_BTWN_ASCII_LF);
	} else if ( (ngx_strncmp(values2->data, (char*)"ascii=", sizeof("ascii=") - 1 ) == 0) ) {
		values2->data += (sizeof("ascii=") - 1);
		values2->len -= (sizeof("ascii=") - 1);
		return ngx_conf_socketify_get_btwn_command_(cf, cmd, conf, NGX_SOCKETIFY_IN_BTWN_ASCII_RT);
	} else {
		return ngx_conf_socketify_get_btwn_command_(cf, cmd, conf, NGX_SOCKETIFY_IN_BTWN_DEF);
	}
}

static char *
ngx_conf_socketify_get_btwn_command_(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, enum_ngx_socketify_t btwn_type) {
	ngx_http_socketify_loc_conf_t            *swlcf = conf;
	ngx_str_t                                *values;
	ngx_uint_t                               i;
	ngx_flag_t                               is_negative;
	ngx_http_socketify_substr_t              *_substr;
	ngx_http_socketify_filter_resp_t         *filt_resp;
	char                                     *status;

	if (swlcf->filt_resp == NULL || swlcf->filt_resp == NGX_CONF_UNSET_PTR) {
		swlcf->filt_resp = ngx_array_create(cf->pool, 3, sizeof(ngx_http_socketify_filter_resp_t));
	}

	values = cf->args->elts;
	if (cf->args->nelts == 3 || cf->args->nelts == 4 || cf->args->nelts == 6) {
		_substr = ngx_pcalloc(cf->pool, sizeof(ngx_http_socketify_substr_t));
		_substr->offset_lf = 0; // DEFAULT
		_substr->offset_rt = 0; // DEFAULT
		_substr->strstrfilter = ngx_pcalloc(cf->pool, sizeof(ngx_str_t) * 2);
		for (i = 1; i < cf->args->nelts - 1; i++) {
			if ( i == 3) {
				if (*(values[i].data) == '-') {
					is_negative = 1;
					values[i].data++;
					values[i].len--;
				} else {
					is_negative = 0;
				}
				_substr->offset_lf = ngx_atoi(values[i].data, values[i].len);
				if (_substr->offset_lf == NGX_ERROR) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					                   "Invalid offset number %V", &values[i]);
					return NGX_CONF_ERROR;
				}

				if ( values[1].len < (ngx_uint_t) _substr->offset_lf) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					                   "Invalid offset left number, should not be more than the data range %V", &values[1]);
					return NGX_CONF_ERROR;
				}

				if (is_negative) {
					_substr->offset_lf *= -1;
				}
			} else if (i == 4) {
				if (*(values[i].data) == '-') {
					is_negative = 1;
					values[i].data++;
					values[i].len--;
				} else {
					is_negative = 0;
				}
				_substr->offset_rt = ngx_atoi(values[i].data, values[i].len);
				if (_substr->offset_rt == NGX_ERROR) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					                   "Invalid offset number %V", &values[i]);
					return NGX_CONF_ERROR;
				}

				if (values[2].len < (ngx_uint_t) _substr->offset_rt) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					                   "Invalid offset right number, should not be more than the data range %V", &values[2]);
					return NGX_CONF_ERROR;
				}

				if (is_negative) {
					_substr->offset_rt *= -1;
				}
			} else if (values[i].len == 0) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				                   "Text cannot be empty %V", &values[i]);
				return NGX_CONF_ERROR;
			} else {
				switch (btwn_type) {
				case NGX_SOCKETIFY_IN_BTWN_DEF:
					_substr->strstrfilter[i - 1].data = values[i].data;
					_substr->strstrfilter[i - 1].len = values[i].len;
					break;
				case NGX_SOCKETIFY_IN_BTWN_ASCII:
					if ( ngx_conf_socketify_ascii_to_string(cf->pool, values[i].data,
					                                        (u_char)'|', &_substr->strstrfilter[i - 1]) != NGX_CONF_OK ) {
						return "Error via processing ngx_conf_socketify_get_btwn_command";
					}
					break;
				case NGX_SOCKETIFY_IN_BTWN_ASCII_LF:
					if ( i == 1 ) {
						if ( ngx_conf_socketify_ascii_to_string(cf->pool, values[i].data,
						                                        (u_char)'|', &_substr->strstrfilter[i - 1]) != NGX_CONF_OK ) {
							return "Error via processing ngx_conf_socketify_get_btwn_command";
						}
					} else {
						_substr->strstrfilter[i - 1].data = values[i].data;
						_substr->strstrfilter[i - 1].len = values[i].len;
					}
					break;
				case NGX_SOCKETIFY_IN_BTWN_ASCII_RT:
					if ( i == 2 ) {
						if ( ngx_conf_socketify_ascii_to_string(cf->pool, values[i].data,
						                                        (u_char)'|', &_substr->strstrfilter[i - 1]) != NGX_CONF_OK ) {
							return "Error via processing ngx_conf_socketify_get_btwn_command";
						}
					} else {
						_substr->strstrfilter[i - 1].data = values[i].data;
						_substr->strstrfilter[i - 1].len = values[i].len;
					}
					break;
				default:
					break;
				}
			}
		}

		filt_resp = ngx_array_push(swlcf->filt_resp);
		if (filt_resp == NULL) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,  "no enuff memory");
			return NGX_CONF_ERROR;
		}

		filt_resp->http_resp_code = 200;
		filt_resp->filter_pt = _substr;
		filt_resp->filter_type = NGX_SOCKETIFY_FILTER_SUBSTRING_RESP;

		if ( (i == 5 && cf->args->nelts == 6) || (i == 3 && cf->args->nelts == 4)) {
			if ( (sizeof("append") - 1) == values[i].len && ngx_strcmp(values[i].data, (char*)"append") == 0 ) {
				status = ngx_conf_socketify_resp_appendable_check(swlcf->filt_resp);
				if ( status != NGX_CONF_OK ) {
					return status;
				}
				swlcf->nresp_appendable++;
				filt_resp->filter_type = NGX_SOCKETIFY_FILTER_APPEND_SUBSTRING_RESP;
			} else {
				filt_resp->http_resp_code = ngx_atoi(values[i].data, values[i].len);
				if (filt_resp->http_resp_code == (ngx_uint_t) NGX_ERROR) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					                   "Invalid response code given %V", &values[i]);
					return NGX_CONF_ERROR;
				}
			}
		}

		return NGX_CONF_OK;
	} else {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid argument given, should be %s",
		                   "socketify_substr_resp <[ascii=]lf> <[ascii=]rt> <offsetlf> <offsetrt> resp_code");
		return NGX_CONF_ERROR;
	}
	return NGX_CONF_ERROR;
}

static char *
ngx_conf_socketify_substr_hdr_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_str_t *values = cf->args->elts;
	values = values + 1;
	ngx_str_t *values2 = values + 1;

	if ( (ngx_strncmp(values->data, (char*)"ascii=", sizeof("ascii=") - 1 ) == 0) &&
	        (ngx_strncmp(values2->data, (char*)"ascii=", sizeof("ascii=") - 1 ) == 0) ) {
		values->data += (sizeof("ascii=") - 1);
		values->len -= (sizeof("ascii=") - 1);
		values2->data += (sizeof("ascii=") - 1);
		values2->len -= (sizeof("ascii=") - 1);
		return ngx_conf_socketify_substr_hdr_command_(cf, cmd, conf, NGX_SOCKETIFY_IN_BTWN_ASCII);
	} else if ( (ngx_strncmp(values->data, (char*)"ascii=", sizeof("ascii=") - 1 ) == 0) ) {
		values->data += (sizeof("ascii=") - 1);
		values->len -= (sizeof("ascii=") - 1);
		return ngx_conf_socketify_substr_hdr_command_(cf, cmd, conf, NGX_SOCKETIFY_IN_BTWN_ASCII_LF);
	} else if ( (ngx_strncmp(values2->data, (char*)"ascii=", sizeof("ascii=") - 1 ) == 0) ) {
		values2->data += (sizeof("ascii=") - 1);
		values2->len -= (sizeof("ascii=") - 1);
		return ngx_conf_socketify_substr_hdr_command_(cf, cmd, conf, NGX_SOCKETIFY_IN_BTWN_ASCII_RT);
	} else {
		return ngx_conf_socketify_substr_hdr_command_(cf, cmd, conf, NGX_SOCKETIFY_IN_BTWN_DEF);
	}
}

static char *
ngx_conf_socketify_substr_hdr_command_(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, enum_ngx_socketify_t btwn_type) {
	ngx_http_socketify_loc_conf_t                 *swlcf = conf;
	ngx_str_t                                         *values, *strstrfilter;
	ngx_uint_t                                        i;
	ngx_flag_t                                        is_negative;
	ngx_http_socketify_filter_resp_to_hdr_t       *resphdr;
	ngx_http_socketify_substr_t                   *substr;

	if (swlcf->filt_resp_to_hdrs == NULL || swlcf->filt_resp_to_hdrs == NGX_CONF_UNSET_PTR) {
		swlcf->filt_resp_to_hdrs = ngx_array_create(cf->pool, 3, sizeof(ngx_http_socketify_filter_resp_to_hdr_t));
	}

	values = cf->args->elts;
	if (cf->args->nelts == 4 || cf->args->nelts == 6) {
		substr = ngx_pcalloc(cf->pool, sizeof(ngx_http_socketify_substr_t));
		substr->offset_lf = 0; // DEFAULT
		substr->offset_rt = 0; // DEFAULT
		strstrfilter = substr->strstrfilter = ngx_pcalloc(cf->pool, sizeof(ngx_str_t) * 2);
		for (i = 1; i < cf->args->nelts - 1; i++) {
			if ( i == 3) {
				if (*(values[i].data) == '-') {
					is_negative = 1;
					values[i].data++;
					values[i].len--;
				} else {
					is_negative = 0;
				}
				substr->offset_lf = ngx_atoi(values[i].data, values[i].len);
				if (substr->offset_lf == NGX_ERROR) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					                   "Invalid offset number %V", &values[i]);
					return NGX_CONF_ERROR;
				}

				if ( values[1].len < (ngx_uint_t) substr->offset_lf) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					                   "Invalid offset left number, should not be more than the data range %V", &values[1]);
					return NGX_CONF_ERROR;
				}

				if (is_negative) {
					substr->offset_lf *= -1;
				}
			} else if (i == 4) {
				if (*(values[i].data) == '-') {
					is_negative = 1;
					values[i].data++;
					values[i].len--;
				} else {
					is_negative = 0;
				}
				substr->offset_rt = ngx_atoi(values[i].data, values[i].len);
				if (substr->offset_rt == NGX_ERROR) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					                   "Invalid offset number %V", &values[i]);
					return NGX_CONF_ERROR;
				}

				if (values[2].len < (ngx_uint_t) substr->offset_rt) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					                   "Invalid offset right number, should not be more than the data range %V", &values[2]);
					return NGX_CONF_ERROR;
				}

				if (is_negative) {
					substr->offset_rt *= -1;
				}
			} else if (values[i].len == 0) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				                   "Text cannot be empty %V", &values[i]);
				return NGX_CONF_ERROR;
			} else {
				switch (btwn_type) {
				case NGX_SOCKETIFY_IN_BTWN_DEF:
					strstrfilter[i - 1].data = values[i].data;
					strstrfilter[i - 1].len = values[i].len;
					break;
				case NGX_SOCKETIFY_IN_BTWN_ASCII:
					if ( ngx_conf_socketify_ascii_to_string(cf->pool, values[i].data,
					                                        (u_char)'|', &strstrfilter[i - 1]) != NGX_CONF_OK ) {
						return "Error via processing ngx_conf_socketify_get_substrn_command";
					}
					break;
				case NGX_SOCKETIFY_IN_BTWN_ASCII_LF:
					if ( i == 1 ) {
						if ( ngx_conf_socketify_ascii_to_string(cf->pool, values[i].data,
						                                        (u_char)'|', &strstrfilter[i - 1]) != NGX_CONF_OK ) {
							return "Error via processing ngx_conf_socketify_get_substrn_command";
						}
					} else {
						strstrfilter[i - 1].data = values[i].data;
						strstrfilter[i - 1].len = values[i].len;
					}
					break;
				case NGX_SOCKETIFY_IN_BTWN_ASCII_RT:
					if ( i == 2 ) {
						if ( ngx_conf_socketify_ascii_to_string(cf->pool, values[i].data,
						                                        (u_char)'|', &strstrfilter[i - 1]) != NGX_CONF_OK ) {
							return "Error via processing ngx_conf_socketify_get_substrn_command";
						}
					} else {
						strstrfilter[i - 1].data = values[i].data;
						strstrfilter[i - 1].len = values[i].len;
					}
					break;
				default:
					break;
				}
			}
		}

		resphdr = ngx_array_push(swlcf->filt_resp_to_hdrs);
		if (resphdr == NULL) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,  "no enuff memory");
			return NGX_CONF_ERROR;
		}

		resphdr->t.substr = substr;
		resphdr->is_regex = 0;
		if ( ngx_strncmp(values[i].data, (char*)"header_in=", sizeof("header_in=") - 1 ) == 0 ) {
			resphdr->header_name.data = values[i].data + sizeof("header_in=") - 1;
			resphdr->header_name.len = ngx_strlen(resphdr->header_name.data);
			resphdr->is_header_in = 1;
		} else if ( ngx_strncmp(values[i].data, (char*)"header_out=", sizeof("header_out=") - 1 ) == 0 ) {
			resphdr->header_name.data = values[i].data + sizeof("header_out=") - 1;
			resphdr->header_name.len = ngx_strlen(resphdr->header_name.data);
			resphdr->is_header_in = 0;
		} else {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,  "no valid on argument, header_in= / header_out=");
			return NGX_CONF_ERROR;
		}

		return NGX_CONF_OK;
	} else {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,  "Invalid argument given, should be <sublf> <subrt> header_in=..");
		return NGX_CONF_ERROR;
	}
	return NGX_CONF_ERROR;
}

static char *
ngx_conf_socketify_direct_append_resp_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_socketify_loc_conf_t            *swlcf = conf;
	ngx_str_t                                *values, *appendstr;
	ngx_http_socketify_filter_resp_t         *filt_resp;

	if (swlcf->filt_resp == NULL || swlcf->filt_resp == NGX_CONF_UNSET_PTR) {
		swlcf->filt_resp = ngx_array_create(cf->pool, 3, sizeof(ngx_http_socketify_filter_resp_t));
	}

	values = cf->args->elts;

	filt_resp = ngx_array_push(swlcf->filt_resp);
	if (filt_resp == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,  "no enuff memory");
		return NGX_CONF_ERROR;
	}

	appendstr = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
	appendstr->data = values[1].data;
	appendstr->len = values[1].len;

	if ( cf->args->nelts == 3 ) {
		filt_resp->http_resp_code  = ngx_atoi(values[2].data, values[2].len  );
		if (filt_resp->http_resp_code == (ngx_uint_t) NGX_ERROR) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			                   "Invalid response code given %V", &values[2]);
			return NGX_CONF_ERROR;
		}
		filt_resp->filter_type = NGX_SOCKETIFY_DIRECT_RESP;
	} else {
		filt_resp->http_resp_code = 200;
		filt_resp->filter_type = NGX_SOCKETIFY_DIRECT_APPEND_RESP;
		swlcf->nresp_appendable++;
	}
	filt_resp->filter_pt = appendstr;

	return NGX_CONF_OK;
}

static char*
ngx_conf_socketify_resp_appendable_check(ngx_array_t *filt_resps) {
	ngx_http_socketify_filter_resp_t *resp;
	ngx_uint_t                        i;
	resp = filt_resps->elts;
	for (i = 0; i < filt_resps->nelts - 1 /* -1 to remove pre added value when checking */; i++) {
		if (resp->filter_type == NGX_SOCKETIFY_FILTER_REGEX_RESP || resp->filter_type == NGX_SOCKETIFY_FILTER_SUBSTRING_RESP) {
			return "append after response output is not allowed, please put on top of response output";
		}
		resp++;
	}
	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_socketify_handler(ngx_http_request_t *r)
{
	ngx_int_t                       rc;
	ngx_http_upstream_t            *u;
	ngx_http_socketify_ctx_t       *ctx;
	ngx_http_socketify_loc_conf_t  *swlcf;

#if (NGX_HTTP_CACHE)
	ngx_http_socketify_main_conf_t  *fmcf;
#endif

	// if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
	//   return NGX_HTTP_NOT_ALLOWED;
	// }

	// rc = ngx_http_discard_request_body(r);

	// if (rc != NGX_OK) {
	//   return rc;
	// }

	if (ngx_http_set_content_type(r) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (ngx_http_upstream_create(r) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	u = r->upstream;

	swlcf = ngx_http_get_module_loc_conf(r, ngx_http_socketify_module);

	// ngx_str_set(&u->schema, "tcp://");
	if (swlcf->socket_schema.len == 0) {
		ngx_str_set(&u->schema, "tcp://");
	} else {
		u->schema.data = swlcf->socket_schema.data;
		u->schema.len = swlcf->socket_schema.len;
	}

	u->output.tag = (ngx_buf_tag_t) &ngx_http_socketify_module;

	u->conf = &swlcf->upstream;
#if (NGX_HTTP_CACHE)
	fmcf = ngx_http_get_module_main_conf(r, ngx_http_socketify_module);

	u->caches = &fmcf->caches;
	u->create_key = ngx_http_socketify_create_key;
#endif
	u->create_request = ngx_http_socketify_create_request;
	u->reinit_request = ngx_http_socketify_reinit_request;
	u->process_header = ngx_http_socketify_process_header;
	u->abort_request = ngx_http_socketify_abort_request;
	u->finalize_request = ngx_http_socketify_finalize_request;

	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_socketify_ctx_t));
	if (ctx == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	ctx->scan_bytes = NGX_CONF_UNSET_SIZE;
	// ctx->request = r;

	ngx_http_set_ctx(r, ctx, ngx_http_socketify_module);

	u->buffering = swlcf->upstream.buffering;

	u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
	if (u->pipe == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	u->pipe->input_filter = ngx_http_socketify_copy_filter;
	u->pipe->input_ctx = r;




	u->input_filter_init = ngx_http_socketify_filter_init;
	u->input_filter = ngx_http_socketify_filter;
	u->input_filter_ctx = r;

	// r->main->count++;

	// ngx_http_upstream_init(r);
	if (!swlcf->upstream.request_buffering
	        && swlcf->upstream.pass_request_body) {
		r->request_body_no_buffering = 1;
	}

	rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		return rc;
	}

	return NGX_DONE;
}


#if (NGX_HTTP_CACHE)

static ngx_int_t
ngx_http_socketify_create_key(ngx_http_request_t *r)
{
	ngx_str_t                    *key;
	ngx_http_socketify_loc_conf_t  *flcf;

	key = ngx_array_push(&r->cache->keys);
	if (key == NULL) {
		return NGX_ERROR;
	}

	flcf = ngx_http_get_module_loc_conf(r, ngx_http_socketify_module);

	if (ngx_http_complex_value(r, &flcf->cache_key, key) != NGX_OK) {
		return NGX_ERROR;
	}

	return NGX_OK;
}

#endif

static ngx_int_t
ngx_http_socketify_create_request(ngx_http_request_t *r) {
	ngx_buf_t                      *b;
	ngx_chain_t                    *cl;
	ngx_str_t                       send_buf;
	ngx_http_socketify_loc_conf_t  *swlcf;

	swlcf = ngx_http_get_module_loc_conf(r, ngx_http_socketify_module);

	if (swlcf->send_buf.value.len) {
		if (ngx_http_complex_value(r, &swlcf->send_buf, &send_buf) != NGX_OK) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", "error when submitting request");
			return NGX_ERROR;
		}
	} else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", "no buffer to write?");
		return NGX_ERROR;
	}

	b = ngx_create_temp_buf(r->pool, send_buf.len);
	if (b == NULL) {
		return NGX_ERROR;
	}
	b->last = ngx_copy(b->last, send_buf.data, send_buf.len);

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	               "Request body --- \n: \"%*s\"", ngx_buf_size(b), b->pos);

	cl = ngx_alloc_chain_link(r->pool);
	if (cl == NULL) {
		return NGX_ERROR;
	}

	cl->buf = b;
	cl->next = NULL;

	r->upstream->request_bufs = cl;

	return NGX_OK;
}

static ngx_int_t
ngx_http_socketify_reinit_request(ngx_http_request_t *r) {
	return NGX_OK;
}

static ngx_int_t
ngx_http_socketify_process_header(ngx_http_request_t *r) {
	ngx_str_t                               resp, *strstrfil1, *strstrfil2, *appendable_resp;
	ngx_array_t                             *done_recv_matches, *filt_resp_arr;
	ngx_http_socketify_done_recv_match_t    *drm;
	ngx_http_socketify_scan_match_t         *scanmatch;
	ngx_http_socketify_filter_resp_t        *filt_resps;
	// ngx_http_socketify_filter_resp_t      *btwn_matchs, *btwn_match;
	u_char                                  *p, *dest, *src, c;
	ngx_int_t                               n;
	ngx_uint_t                              i, appendable_ind;
	ngx_http_upstream_t                     *u;
	ngx_http_socketify_loc_conf_t           *swlcf;
	size_t                                  last_match_len, p_offset, len;
	ngx_http_socketify_ctx_t                *ctx;
	ngx_regex_t                             *_regex;
	ngx_http_socketify_substr_t             *_substr;

	u = r->upstream;
	swlcf = ngx_http_get_module_loc_conf(r, ngx_http_socketify_module);
	if (swlcf == NULL) {
		return NGX_ERROR;
	}

	p = u->buffer.pos;
	dest = u->buffer.last;
	p_offset = dest - p;
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	               "recv size: \"%O\"", p_offset);
#if (NGX_HTTP_CACHE)
	if (!r->cached) {
#endif
		done_recv_matches = swlcf->done_recv_matches;
		drm = done_recv_matches->elts;

		for (i = 0; i < done_recv_matches->nelts; i++ ) {
			switch (drm->match_type) {
			case NGX_SOCKETIFY_EOL_STR_MATCH:
				strstrfil2 = drm->match_pt;
				last_match_len = strstrfil2->len;
				if ( p_offset >= last_match_len &&
				        ngx_socketify_strstr(&(p[p_offset - last_match_len]), last_match_len, strstrfil2->data, last_match_len) ) {
					goto RECV_DONE;
				}
				break;
			case NGX_SOCKETIFY_START_STR_MATCH:
				strstrfil2 = drm->match_pt;
				last_match_len = strstrfil2->len;
				if ( p_offset >= last_match_len &&
				        ngx_socketify_strstr(p, last_match_len, strstrfil2->data, last_match_len) ) {
					goto RECV_DONE;
				}
				break;
			case NGX_SOCKETIFY_SCAN:
				scanmatch = drm->match_pt;
				ctx = ngx_http_get_module_ctx(r, ngx_http_socketify_module);
				if (ctx == NULL) {
					return NGX_ERROR;
				}

				/**This is one time only per request**/
				if (ctx->scan_bytes == NGX_CONF_UNSET_SIZE ) {
					if (p_offset == 0) {
						return NGX_AGAIN;
					}

					if (scanmatch->scan_type == NGX_SOCKETIFY_SCAN_AFTER) {
						if ( !(p = ngx_socketify_strstr(p, p_offset, scanmatch->scan_after.data, scanmatch->scan_after.len) ) ) {
							goto NEXT_MATCHING;
						}
						p += scanmatch->scan_after.len;
						last_match_len = dest - p;
					} else {
						last_match_len = p_offset;
					}

					n = scanmatch->max_range_scanned;

					while ( last_match_len-- && (c = *p) && n--) {
						if (c < '0' || c > '9') {
							p++;
							continue;
						}
						src = p++;
						if (last_match_len == 0) {
							goto NEXT_MATCHING;
						}
						last_match_len--;
						while ( last_match_len-- && (c = *p) ) {
							if (c < '0' || c > '9') {
								goto SCAN_EXPECTED_BYTES;
							}
							p++;
						}
						goto NEXT_MATCHING;
SCAN_EXPECTED_BYTES:
						ctx->scan_bytes = ngx_atoi(src, p - src);
						if (ctx->scan_bytes == (size_t) NGX_ERROR) {
							ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
							              "Unable to scan the length from the buffer, %*s", p_offset,  u->buffer.pos);
							return NGX_HTTP_UPSTREAM_INVALID_HEADER;
						}

						ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
						               "scanned byte length to read-------------------------: \"%O\"", ctx->scan_bytes);
						ctx->scan_bytes += scanmatch->extra_byte_cnt;
						if (scanmatch->count_type == NGX_SOCKETIFY_COUNT_NEXT) {
							last_match_len = (p - u->buffer.pos);
							ctx->cnt_next.data = ngx_palloc(r->pool, last_match_len );
							ngx_memcpy(ctx->cnt_next.data, u->buffer.pos, last_match_len );
							ctx->cnt_next.len = last_match_len;
						}
						p = u->buffer.pos;
						goto CMP_BYTES_LEN; //break;
					}
					if ( n < 0 && ctx->scan_bytes == NGX_CONF_UNSET_SIZE ) {
						return NGX_HTTP_UPSTREAM_INVALID_HEADER;
					} else {
						goto NEXT_MATCHING;
					}
				}
				/**End This is one time only per request**/

CMP_BYTES_LEN:
				ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "compare -- %O >= %O : ", p_offset, ctx->scan_bytes);
				switch (scanmatch->count_type) {
				case NGX_SOCKETIFY_COUNT_AFTER:
					if ( ( p = ngx_socketify_strstr(p, p_offset, scanmatch->count_after.data, scanmatch->count_after.len) ) ) {
						if ( (dest - p) >= (ngx_int_t) ctx->scan_bytes ) {
							goto RECV_LEN_DONE;
						}
					}
				case NGX_SOCKETIFY_COUNT_NEXT:
					if ( ( p = ngx_socketify_strstr(p, p_offset, ctx->cnt_next.data, ctx->cnt_next.len) ) ) {
						if ( (dest - p) >= (ngx_int_t) ctx->scan_bytes ) {
							goto RECV_LEN_DONE;
						}
					}
					break;
				case NGX_SOCKETIFY_COUNT_FR_START:
				default:
					if ( p_offset >= ctx->scan_bytes ) {
						goto RECV_LEN_DONE;
					}
					break;
				}

				break;

			default:
NEXT_MATCHING:
				break;
			}
			drm++;
		}
		return NGX_AGAIN;

RECV_DONE:
		ctx = ngx_http_get_module_ctx(r, ngx_http_socketify_module);
		if (ctx == NULL) {
			return NGX_ERROR;
		}
RECV_LEN_DONE:

		if (ctx->nmatch++ < swlcf->nmatch ) {
			return NGX_AGAIN;
		}

		switch (swlcf->unescape_type) {
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
			dest = p;
			src = p;
			ngx_unescape_uri(&dest, &src, p_offset, swlcf->unescape_type);
			resp.data = p;
			resp.len = dest - resp.data;
			break;
		case JSON_ESCAPE_UNESC:
			src = p;
			dest = ngx_socketify_unescape_json( src, p_offset);
			if (dest == NULL) {
				goto no_found;
			}
			resp.data = src;
			resp.len = dest - src;
			break;
		case CRLF_ESCAPE_UNESC:
			src = p;
			dest = ngx_socketify_unescape_crlf( src, p_offset);
			resp.data = src;
			resp.len = dest - src;
			break;
		default:
			resp.data = p;
			resp.len = p_offset;
			break;
		}

		/*************** some variables from here will be reuse, scan_bytes, last_match_len and etc ****************************/

		if (swlcf->nresp_appendable) {
			appendable_resp = ngx_palloc(r->pool, swlcf->nresp_appendable * sizeof(ngx_str_t));
			appendable_ind = 0;
			/**Use for last total len**/
			last_match_len = 0;
		}

		// ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		//                "response before filter: \"%V\"", &resp);
		/**We only capture the second group, so we need 20 capture **/

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
		if ( ( filt_resp_arr = swlcf->filt_resp) ) {
			filt_resps = filt_resp_arr->elts;
			for (i = 0; i < filt_resp_arr->nelts; i++, filt_resps++) {
				switch (filt_resps->filter_type) {
				case NGX_SOCKETIFY_FILTER_REGEX_RESP:
				case NGX_SOCKETIFY_FILTER_APPEND_REGEX_RESP:
#if (NGX_PCRE)
					_regex = (ngx_regex_t*)filt_resps->filter_pt;
					int captures[20];
					n = ngx_regex_exec(_regex, &resp, captures, 20);
					ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					               "number of matched: \"%d\"", n);
					if (n > 0 ) { /* match */
						len = captures[3] - captures[2];
						src = resp.data + captures[2];
						if ( len == 0 ) {
							continue;
						}
						if ( filt_resps->filter_type == NGX_SOCKETIFY_FILTER_REGEX_RESP ) {
							if (swlcf->nresp_appendable) {
								appendable_resp -= appendable_ind; // back to starting position
								last_match_len += len;
								p = ngx_palloc(r->pool, last_match_len * sizeof(u_char));
								for (i = 0; i < appendable_ind; i++) {
									p = ngx_copy(p, appendable_resp->data, appendable_resp->len);
									appendable_resp++;
								}
								p = ngx_copy(p, src, len);
								u->buffer.last = u->buffer.end = p;
								u->buffer.pos = p - last_match_len;
								u->headers_in.content_length_n = last_match_len;
								u->state->status = u->headers_in.status_n = filt_resps->http_resp_code;
							} else {
								u->headers_in.content_length_n = len;
								u->state->status = u->headers_in.status_n = filt_resps->http_resp_code;
								u->buffer.pos = src;
								u->buffer.last = src + len;
							}
							if (r->cache && u->cacheable /* && ngx_strncasecmp(u->method.data, (u_char *) "GET", 3) == 0 */) {
								ngx_memcpy(u->buffer.pos - r->cache->header_start, u->buffer.start, r->cache->header_start);
								u->buffer.start = u->buffer.pos - r->cache->header_start;
							}
							goto found;
						}
						appendable_resp->data = src;
						appendable_resp->len = len;
						last_match_len += len;
						appendable_ind++;
						appendable_resp++;
					} /*else if (n == NGX_REGEX_NO_MATCHED) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "socket invalid data: \"%V\"", &presp);
      goto no_found;
    } else {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "invalid Match of regex: \"%V\"", &presp);
      goto no_found;

    }*/
#endif
					break;
				case NGX_SOCKETIFY_FILTER_SUBSTRING_RESP:
				case NGX_SOCKETIFY_FILTER_APPEND_SUBSTRING_RESP:
					_substr = (ngx_http_socketify_substr_t*)filt_resps->filter_pt;
					strstrfil1 = &_substr->strstrfilter[0];
					strstrfil2 = &_substr->strstrfilter[1];
					src = resp.data;
					len = resp.len;
					p = ngx_socketify_strstr(src, len, strstrfil1->data, strstrfil1->len);
					if (!p) {
						continue;
					}

					p += _substr->offset_lf;
					p_offset = ( p - src );
					p = ngx_socketify_strstr(p, len - p_offset, strstrfil2->data, strstrfil2->len );
					if (!p) {
						continue;
					}
					p += _substr->offset_rt;
					src += p_offset;
					len = p - src;

					if ( len == 0 ) {
						continue;
					}
					if ( filt_resps->filter_type == NGX_SOCKETIFY_FILTER_SUBSTRING_RESP ) {
						if (swlcf->nresp_appendable) {
							appendable_resp -= appendable_ind; // back to starting position
							last_match_len += len;
							p = ngx_palloc(r->pool, last_match_len * sizeof(u_char));
							for (i = 0; i < appendable_ind; i++) {
								p = ngx_copy(p, appendable_resp->data, appendable_resp->len);
								appendable_resp++;
							}
							p = ngx_copy(p, src, len);
							u->buffer.last = u->buffer.end = p;
							u->buffer.pos = p - last_match_len;
							u->headers_in.content_length_n = last_match_len;
							u->state->status = u->headers_in.status_n = filt_resps->http_resp_code;
						} else {
							// resp = presp;
							u->headers_in.content_length_n = len;
							u->state->status = u->headers_in.status_n = filt_resps->http_resp_code;
							u->buffer.pos = src;
							u->buffer.last = src + len;
						}
						if (r->cache && u->cacheable /* && ngx_strncasecmp(u->method.data, (u_char *) "GET", 3) == 0 */) {
							ngx_memcpy(u->buffer.pos - r->cache->header_start, u->buffer.start, r->cache->header_start);
							u->buffer.start = u->buffer.pos - r->cache->header_start;
						}
						goto found;
					}
					appendable_resp->data = src;
					appendable_resp->len = len;
					last_match_len += len;
					appendable_ind++;
					appendable_resp++;
					break;
				case NGX_SOCKETIFY_DIRECT_APPEND_RESP:
					strstrfil1 = (ngx_str_t*)filt_resps->filter_pt;
					appendable_resp->data = strstrfil1->data;
					appendable_resp->len = strstrfil1->len;
					last_match_len += appendable_resp->len;
					appendable_ind++;
					appendable_resp++;
					break;
				case NGX_SOCKETIFY_DIRECT_RESP:
					strstrfil1 = (ngx_str_t*)filt_resps->filter_pt;
					if (swlcf->nresp_appendable) {
						last_match_len += strstrfil1->len;
						appendable_resp -= appendable_ind;
						p = ngx_palloc(r->pool, last_match_len * sizeof(u_char));
						for (i = 0; i < appendable_ind; i++) {
							p = ngx_copy(p, appendable_resp->data, appendable_resp->len);
							appendable_resp++;
						}
						p = ngx_copy(p, strstrfil1->data, strstrfil1->len);
						u->buffer.last = u->buffer.end = p;
						u->buffer.pos = p - last_match_len;
						u->headers_in.content_length_n = last_match_len;
						u->state->status = u->headers_in.status_n = filt_resps->http_resp_code;
					} else {
						u->headers_in.content_length_n = strstrfil1->len;
						u->state->status = u->headers_in.status_n = filt_resps->http_resp_code;
						u->buffer.pos = strstrfil1->data;
						u->buffer.last = strstrfil1->data + strstrfil1->len;
					}
					if (r->cache && u->cacheable /* && ngx_strncasecmp(u->method.data, (u_char *) "GET", 3) == 0 */) {
						ngx_memcpy(u->buffer.pos - r->cache->header_start, u->buffer.start, r->cache->header_start);
						u->buffer.start = u->buffer.pos - r->cache->header_start;
					}
					goto found;
					break;
				default:
					break;
				}
			}
			goto no_found;
		}
#pragma GCC diagnostic pop

		// if ( ( filt_resp_arr = swlcf->inbetween) ) {
		//   btwn_matchs = filt_resp_arr->elts;
		//   for (i = 0; i < filt_resp_arr->nelts; i++) {
		//     btwn_match = btwn_matchs + i;

		//   }
		// }

		if ( resp.len == 0 ) {
			goto no_found;
		}
		u->headers_in.content_length_n = resp.len;
		u->headers_in.status_n = 200;
		u->state->status = 200;
		size_t  contentlen;
		u_char *pp, *headerpp, *endheaderpp;
		uintptr_t est_len;
		size_t _header_len;
found:
		// u->buffer.pos = resp.data;
#if (NGX_HTTP_CACHE)
		if (r->cache && u->cacheable /* && ngx_strncasecmp(u->method.data, (u_char *) "GET", 3) == 0 */) {
			contentlen = u->headers_in.content_length_n;
			est_len = ngx_http_socketify_cache_headers_value(r, NULL, u->headers_in.status_n, contentlen, &swlcf->content_type );
			headerpp = ngx_pcalloc(r->pool, est_len * sizeof(u_char));
			endheaderpp = (u_char*) ngx_http_socketify_cache_headers_value(r, headerpp, u->headers_in.status_n, contentlen, &swlcf->content_type );
			_header_len = endheaderpp - headerpp;
			// u->headers_in.content_length_n = contentlen;
			if ( _header_len > (size_t) (u->buffer.end - u->buffer.last) ) {
				/* "Buffer size is not enough for caching, realloc" */
				pp = ngx_pcalloc(r->pool, r->cache->header_start + resp.len + _header_len);
				pp = ngx_copy(pp, u->buffer.pos - r->cache->header_start, r->cache->header_start);
				u->buffer.start = pp - r->cache->header_start;
				u->buffer.end = u->buffer.last = ngx_copy(pp + _header_len, u->buffer.pos, contentlen);
				u->buffer.pos = ngx_copy(pp, (u_char*) headerpp, _header_len);
			} else {
				pp = u->buffer.pos;
				/*u->buffer.end =*/ u->buffer.last = ngx_movemem(pp + _header_len, pp, contentlen);
				u->buffer.pos = ngx_copy(pp, headerpp, _header_len);
			}

			ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			               "total buffer: %*s", u->buffer.last - u->buffer.pos,  u->buffer.pos);
			goto header_cache_done;
		}
#endif
		if (swlcf->nresp_appendable) {
			/** if it is not cacheable, then set start = pos**/
			u->buffer.start = u->buffer.pos;
		}
		// u->headers_in.content_length_n = contentlen;
		// ctx->scan_bytes = 0;



		// u->buffer.pos = ngx_pcalloc(r->pool, sizeof(sample) - 1 + 22);
		// u->buffer.pos = ngx_copy(u->buffer.pos, sample, sizeof(sample) - 1);
		// u->buffer.pos =(u_char*) "HTTP/1.1 200 OK\r\n";
		// u->buffer.pos+=17;
		/** No filter action needed, direct go to found **/
header_cache_done:
		r->headers_out.content_type = swlcf->content_type;

		/* gzip header flags, we don't need it as config file can handle encoding */
		if (swlcf->gzip_flag) {
//   flags = ngx_atoi(start, p - start - 1);

//   if (flags == (ngx_uint_t) NGX_ERROR) {
//     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
//                   "socket writer sent invalid flags in response \"%V\" "
//                   "for key \"%V\"",
//                   &resp, &ctx->key);
//     return NGX_HTTP_UPSTREAM_INVALID_HEADER;
//   }

//   if (flags & swlcf->gzip_flag) {
//     h = ngx_list_push(&r->headers_out.headers);
//     if (h == NULL) {
//       return NGX_ERROR;
//     }

//     h->hash = 1;
//     ngx_str_set(&h->key, "Content-Encoding");
//     ngx_str_set(&h->value, "gzip");
//     r->headers_out.content_encoding = h;
//   }
		}

		if ( ngx_http_socketify_header_resp_reupdate(r, swlcf, &resp) == NGX_ERROR ) {
			ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "Unable to parse response to headers");
		}
#if (NGX_HTTP_CACHE)
	} else { // it is r->cached
		if ( ngx_strncmp(p, "HTTP/1", sizeof("HTTP/1") - 1)  != 0 || !( p = ngx_strlchr(p + 6, dest, ' ') ) ) {
			return NGX_AGAIN; // Invalid cached header
		}
		p++;
		u->headers_in.status_n = ngx_atoi(p, 3);
		if (u->headers_in.status_n  == (ngx_uint_t) NGX_ERROR) {
			return NGX_AGAIN; // Invalid cached header
		}
		p += 4; // skipt the status code ine
		p = src = ((u_char*) ngx_strnstr(p, "Content-Length: ", dest - p) ) + sizeof("Content-Length: ") - 1;
		if (!src) {
			return NGX_AGAIN; // Invalid cached header
		}

		for ( ;; ) {
			c = *p++;
			if (c < '0' || c > '9') {
				break;
			}
		}
		p--;
		p_offset = ngx_atoi(src, p - src);
		u->buffer.pos = dest - p_offset;

		// ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		//                "AAA cached buffer is %*s",  p_offset, u->buffer.pos);
		// ngx_memcpy(u->buffer.pos - r->cache->header_start, u->buffer.start, r->cache->header_start);
		// 					u->buffer.start = u->buffer.pos - r->cache->header_start;
		r->headers_out.content_type = swlcf->content_type;
	}
#endif
	return NGX_OK;

	// if (u->headers_in.content_length_n == NGX_ERROR) {
	//   ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
	//                 "socket writer sent invalid length in response \"%V\" ",
	//                 &resp);
	//   return NGX_HTTP_UPSTREAM_INVALID_HEADER;
	// } else if (u->headers_in.content_length_n == 0) {
no_found:
	ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
	              "response: \"%V\" was not found ", &resp);

	u->headers_in.content_length_n = 0;
	u->headers_in.status_n = 404;
	u->state->status = 404;
	u->buffer.pos = resp.data + resp.len; //p + sizeof("END" CRLF) - 1;
	u->keepalive = 1;
	// }
	// else {
	//   u->headers_in.status_n = http_resp_code;
	//   u->state->status = http_resp_code;
	//   u->buffer.start = u->buffer.pos = resp.data;
	//   u->buffer.end = u->buffer.last = resp.data + resp.len;
	// }


	return NGX_OK;
}

static ngx_int_t
ngx_http_socketify_header_resp_reupdate(ngx_http_request_t *r, ngx_http_socketify_loc_conf_t *swlcf, ngx_str_t *resp ) {
	ngx_array_t                                 *filt_arr;
	ngx_http_socketify_filter_resp_to_hdr_t     *filter_mtch;
	ngx_str_t                                   *strstrfil1, *strstrfil2;
	ngx_http_socketify_substr_t                 *substr;
	u_char                                      *p, *base;
	size_t                                      p_offset, baselen;
	ngx_int_t                                   n;
	ngx_uint_t                                  i;
	ngx_table_elt_t                             *h;
	ngx_http_core_main_conf_t                   *cmcf;
	ngx_http_header_t                           *hh;


	if ( ( filt_arr = swlcf->filt_resp_to_hdrs) ) {
		filter_mtch = filt_arr->elts;
		for (i = 0; i < filt_arr->nelts; i++, filter_mtch++) {
			base = resp->data;
			baselen = resp->len;
			if (filter_mtch->is_regex) {
				int captures[20];
				n = ngx_regex_exec(filter_mtch->t.regex, resp, captures, 20);

				if (n > 0 ) { /* match */
					baselen = captures[3] - captures[2];
					base += captures[2];
					if ( baselen == 0 ) {
						continue;
					}
				} else {
					continue;
				}
			} else {
				substr = filter_mtch->t.substr;
				strstrfil1 = &substr->strstrfilter[0];
				strstrfil2 = &substr->strstrfilter[1];

				p = ngx_socketify_strstr(base, baselen, strstrfil1->data, strstrfil1->len);
				if (!p) {
					continue;
				}

				p += substr->offset_lf;
				p_offset = ( p - base );
				p = ngx_socketify_strstr(p, baselen - p_offset, strstrfil2->data, strstrfil2->len );
				if (!p) {
					continue;
				}
				p += substr->offset_rt;
				base += p_offset;
				baselen = p - base;

				if ( baselen == 0 ) {
					continue;
				}
			}
// ADD_HEADER:
			if (filter_mtch->is_header_in) {
				h = ngx_list_push(&r->headers_in.headers);
				if (h == NULL) {
					return NGX_ERROR;
				}

				h->key.len = filter_mtch->header_name.len;
				h->key.data = filter_mtch->header_name.data;
				h->hash = ngx_hash_key(h->key.data, h->key.len);

				h->value.len = baselen;
				h->value.data = base;

				h->lowcase_key = h->key.data;
				cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

				hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash, h->lowcase_key, h->key.len);

				if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
					return NGX_ERROR;
				}
			} else {
				h = ngx_list_push(&r->headers_out.headers);
				if (h == NULL) {
					return NGX_ERROR;
				}
				h->hash = 1; /*to mark HTTP output headers show set 1, show missing set 0*/
				h->key.len = filter_mtch->header_name.len;
				h->key.data = filter_mtch->header_name.data;
				h->value.len = baselen;
				h->value.data = base;
			}
		}
	}
	return NGX_OK;
}

static ngx_int_t
ngx_http_socketify_filter_init(void *data)
{

	ngx_http_request_t    *r = data;
	ngx_http_upstream_t   *u;
	ngx_http_socketify_ctx_t  *ctx;

	u = r->upstream;
	ctx = ngx_http_get_module_ctx(r, ngx_http_socketify_module);

	if (ctx == NULL) {
		return NGX_ERROR;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	               "http proxy filter init length:%O",
	               u->headers_in.content_length_n);
	/* as per RFC2616, 4.4 Message Length */

	if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
	        || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED)
	{
		/* 1xx, 204, and 304 and replies to HEAD requests */
		/* no 1xx since we don't send Expect and Upgrade */

		u->pipe->length = 0;
		u->length = 0;
		u->keepalive = !u->headers_in.connection_close;

		// } else if (u->headers_in.chunked) {
		//     /* chunked */

		//     u->pipe->input_filter = ngx_http_proxy_chunked_filter;
		//     u->pipe->length = 3; /* "0" LF LF */

		//     u->input_filter = ngx_http_proxy_non_buffered_chunked_filter;
		//     u->length = 1;

	} else if (u->headers_in.content_length_n == 0) {
		/* empty body: special case as filter won't be called */

		u->pipe->length = 0;
		u->length = 0;
		u->keepalive = !u->headers_in.connection_close;

	} else {
		/* content length or connection close */

		u->pipe->length = u->headers_in.content_length_n;
		u->length = u->headers_in.content_length_n;
	}

	return NGX_OK;
}

/** To check whether has any to change for response, flush the bytes **/
static ngx_int_t
ngx_http_socketify_filter(void *data, ssize_t bytes) {
	ngx_http_request_t   *r = data;

	ngx_buf_t            *b;
	ngx_chain_t          *cl, **ll;
	ngx_http_upstream_t  *u;

	u = r->upstream;

	for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
		ll = &cl->next;
	}

	cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
	if (cl == NULL) {
		return NGX_ERROR;
	}

	*ll = cl;

	cl->buf->flush = 1;
	cl->buf->memory = 1;

	b = &u->buffer;

	cl->buf->pos = b->last;
	b->last += bytes;
	cl->buf->last = b->last;
	cl->buf->tag = u->output.tag;

	if (u->length == -1) {
		return NGX_OK;
	}

	u->length -= bytes;

	if (u->length == 0) {
		u->keepalive = !u->headers_in.connection_close;
	}

	return NGX_OK;
}


static ngx_int_t
ngx_http_socketify_copy_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
	ngx_buf_t                *b;
	ngx_chain_t              *cl;
	ngx_http_request_t       *r;

	if (buf->pos == buf->last) {
		return NGX_OK;
	}

	cl = ngx_chain_get_free_buf(p->pool, &p->free);
	if (cl == NULL) {
		return NGX_ERROR;
	}

	b = cl->buf;

	ngx_memcpy(b, buf, sizeof(ngx_buf_t));
	b->shadow = buf;
	b->tag = p->tag;
	b->last_shadow = 1;
	b->recycled = 1;
	buf->shadow = b;

	ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);
	if (p->in) {
		*p->last_in = cl;
	} else {
		p->in = cl;
	}
	p->last_in = &cl->next;

	if (p->length == -1) {
		return NGX_OK;
	}

	p->length -= b->last - b->pos;

	if (p->length == 0) {
		r = p->input_ctx;
		p->upstream_done = 1;
		r->upstream->keepalive = !r->upstream->headers_in.connection_close;

	} else if (p->length < 0) {
		r = p->input_ctx;
		p->upstream_done = 1;

		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
		              "upstream sent more data than specified in "
		              "\"Content-Length\" header");
	}

	return NGX_OK;
}

static void
ngx_http_socketify_abort_request(ngx_http_request_t *r) {
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	               "abort http socket_writer request");
	return;
}

static void
ngx_http_socketify_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
	               "finalize http socket_writer request");
	return;
}

static ngx_int_t
ngx_http_socketify_post_configuration(ngx_conf_t *cf) {
	ngx_http_socketify_main_conf_t   *swmcf;
	ngx_http_socketify_loc_conf_t    *swlcf;
	ngx_queue_t                      *swlcf_queue, *q;
	ngx_http_socketify_filter_resp_t *filt_resps;
	ngx_uint_t                       i;

	swmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_socketify_module);
	if (swmcf == NULL) {
		return NGX_ERROR;
	}
	swlcf_queue = &swmcf->swlcf_queue;

	/*** Loop and remove queue ***/
	while (! (ngx_queue_empty(swlcf_queue)) )  {
		q = ngx_queue_head(swlcf_queue);
		swlcf = ngx_queue_data(q, ngx_http_socketify_loc_conf_t, _queue);

		ngx_http_compile_complex_value_t   ccv;

		ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
		ccv.cf = cf;
		ccv.value = &swlcf->sendbuf_cmds;
		ccv.complex_value = &swlcf->send_buf;

		if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
			return NGX_ERROR;
		}

		if (swlcf->nresp_appendable) {
			filt_resps = swlcf->filt_resp->elts;
			for (i = 0; i < swlcf->filt_resp->nelts; i++) {
				if (filt_resps->filter_type == NGX_SOCKETIFY_FILTER_REGEX_RESP ||
				        filt_resps->filter_type == NGX_SOCKETIFY_FILTER_SUBSTRING_RESP ||
				        filt_resps->filter_type == NGX_SOCKETIFY_DIRECT_RESP) {
					if ( i != (swlcf->filt_resp->nelts - 1) ) {
						ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						                   "invalid response append, you should have output response at the bottom of append response");
						return NGX_ERROR;
					}
					goto NEXT_LOC_QUEUE;
				}
				filt_resps++;
			}
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			                   "invalid response append, you should have output response at the bottom of append response");
			return NGX_ERROR;
		}
NEXT_LOC_QUEUE:
		// if ( swlcf->match_type == NGX_SOCKETIFY_PROXY_RESP_FILTER && swlcf->sendbuf_cmds.len ) {
		// 	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		// 	                   "Proxy response filter only for proxy pass instead of socketify_pass, and socketify send are not allow");
		// 	return NGX_ERROR;
		// }

		ngx_queue_remove(q);
	}


	// ngx_http_next_header_filter = ngx_http_top_header_filter;
	// ngx_http_top_header_filter = ngx_http_socketify_header_filter;

	// ngx_http_next_body_filter = ngx_http_top_body_filter;
	// ngx_http_top_body_filter = ngx_http_socketify_body_filter;

	return NGX_OK;
}

static void *
ngx_http_socketify_create_main_conf(ngx_conf_t *cf) {
	ngx_http_socketify_main_conf_t *swmcf;
	swmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_socketify_main_conf_t));
	if (swmcf == NULL) {
		return NGX_CONF_ERROR;
	}

#if (NGX_HTTP_CACHE)
	if (ngx_array_init(&swmcf->caches, cf->pool, 4,
	                   sizeof(ngx_http_file_cache_t *))
	        != NGX_OK)
	{
		return NULL;
	}
#endif
	ngx_queue_init(&swmcf->swlcf_queue);
	return swmcf;
}

static char *
ngx_http_socketify_init_main_conf(ngx_conf_t *cf, void *conf) {
	return NGX_CONF_OK;
}



static void *
ngx_http_socketify_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_socketify_loc_conf_t  *conf;

	// ngx_http_socketify_main_conf_t *swmcf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_socketify_loc_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}
	/*
	 * set by ngx_pcalloc():
	 *
	 *     conf->upstream.bufs.num = 0;
	 *     conf->upstream.next_upstream = 0;
	 *     conf->upstream.temp_path = NULL;
	 *     conf->socket_schema.len = 0;
	 *     conf->socket_schema.data = NULL;
	 *     conf->sendbuf_cmds.len = 0;
	 *     conf->sendbuf_cmds.data = NULL;
	 */

#if (NGX_HTTP_CACHE)
	conf->upstream.cache = NGX_CONF_UNSET;
	conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
#if (nginx_version >= 1012002)
	conf->upstream.cache_max_range_offset = NGX_CONF_UNSET;
	conf->upstream.cache_background_update = NGX_CONF_UNSET;
#endif
	conf->upstream.cache_bypass = NGX_CONF_UNSET_PTR;
	conf->upstream.no_cache = NGX_CONF_UNSET_PTR;
	conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
	conf->upstream.cache_lock = NGX_CONF_UNSET;
	conf->upstream.cache_lock_timeout = NGX_CONF_UNSET_MSEC;
	conf->upstream.cache_lock_age = NGX_CONF_UNSET_MSEC;
	conf->upstream.cache_revalidate = NGX_CONF_UNSET;
#endif

	conf->upstream.local = NGX_CONF_UNSET_PTR;
	conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
	conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
	conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
	conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
	conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;


	conf->upstream.store = NGX_CONF_UNSET;
	conf->upstream.store_access = NGX_CONF_UNSET_UINT;
	conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
	conf->upstream.buffering = NGX_CONF_UNSET;
	conf->upstream.request_buffering = NGX_CONF_UNSET;
	conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
	conf->upstream.force_ranges = NGX_CONF_UNSET;

	conf->upstream.local = NGX_CONF_UNSET_PTR;

	conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
	conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
	conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
	conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;

	conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
	conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
	conf->upstream.limit_rate = NGX_CONF_UNSET_SIZE;

	conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
	conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
	conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;

	conf->upstream.pass_request_headers = NGX_CONF_UNSET;
	conf->upstream.pass_request_body = NGX_CONF_UNSET;

	conf->gzip_flag = NGX_CONF_UNSET_UINT;
	ngx_memzero(&conf->send_buf, sizeof(ngx_http_complex_value_t));
	conf->unescape_type = NGX_CONF_UNSET_UINT;
	conf->nmatch = NGX_CONF_UNSET_UINT;

	// conf->scan_type = NGX_SOCKETIFY_NONE;
	// conf->count_type = NGX_SOCKETIFY_NONE;
	// conf->extra_byte_cnt = NGX_CONF_UNSET_UINT;
	// conf->max_range_scanned = NGX_CONF_UNSET;

// #if (NGX_PCRE)
//   conf->regexfilter = NULL;
// #endif
//   conf->strstrfilter = NULL;
//   conf->offset_lf = NGX_CONF_UNSET;
//   conf->offset_rt = NGX_CONF_UNSET;

	conf->sendbuf_cmds.len = 0;
	conf->sendbuf_cmds.data = NULL;
	conf->_queue.next = NGX_CONF_UNSET_PTR;
	// conf->match_type = NGX_SOCKETIFY_NONE;
	conf->filt_resp = NGX_CONF_UNSET_PTR;
	conf->done_recv_matches = NGX_CONF_UNSET_PTR;
	conf->filt_resp_to_hdrs = NGX_CONF_UNSET_PTR;
	conf->nresp_appendable = 0;

	// conf->succ_resp_status = NGX_CONF_UNSET_UINT;
	conf->upstream.cyclic_temp_file = 0;

	conf->upstream.change_buffering = 1;

	conf->upstream.intercept_errors = NGX_CONF_UNSET;
	conf->upstream.intercept_404 = 1;

	return conf;
}

#ifdef NGX_CONF_PREFIX
static ngx_path_init_t  socketify_temp_path = {
	ngx_string(NGX_CONF_PREFIX "socketify_temp"), { 1, 2, 0 }
};
#else
static ngx_path_init_t  socketify_temp_path = {
	ngx_string(NGX_PREFIX "socketify_temp"), { 1, 2, 0 }
};
#endif

static char *
ngx_http_socketify_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_core_loc_conf_t *clcf; // clcf just for default content type setting only
	ngx_http_socketify_loc_conf_t *prev = parent;
	ngx_http_socketify_loc_conf_t *conf = child;
	size_t 						   size;

#if (NGX_HTTP_CACHE)

	if (conf->upstream.store > 0) {
		conf->upstream.cache = 0;
	}

	if (conf->upstream.cache > 0) {
		conf->upstream.store = 0;
	}

#endif
	ngx_conf_merge_ptr_value(conf->upstream.local,
	                         prev->upstream.local, NULL);

	ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
	                          prev->upstream.next_upstream_tries, 0);

	ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
	                          prev->upstream.connect_timeout, 60000);

	ngx_conf_merge_msec_value(conf->upstream.send_timeout,
	                          prev->upstream.send_timeout, 60000);

	ngx_conf_merge_msec_value(conf->upstream.read_timeout,
	                          prev->upstream.read_timeout, 60000);

	ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
	                          prev->upstream.next_upstream_timeout, 0);

	if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path,
	                              prev->upstream.temp_path,
	                              &socketify_temp_path)
	        != NGX_OK)
	{
		return NGX_CONF_ERROR;
	}

	// if (conf->upstream.busy_buffers_size < size) {
	//     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
	//         "\"scgi_busy_buffers_size\" must be equal to or greater "
	//         "than the maximum of the value of \"scgi_buffer_size\" and "
	//         "one of the \"scgi_buffers\"");

	//     return NGX_CONF_ERROR;
	// }

	// if (conf->upstream.busy_buffers_size
	//     > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
	// {
	//     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
	//         "\"scgi_busy_buffers_size\" must be less than "
	//         "the size of all \"scgi_buffers\" minus one buffer");

	//     return NGX_CONF_ERROR;
	// }

	if (conf->upstream.store == NGX_CONF_UNSET) {
		ngx_conf_merge_value(conf->upstream.store,
		                     prev->upstream.store, 0);

		conf->upstream.store_lengths = prev->upstream.store_lengths;
		conf->upstream.store_values = prev->upstream.store_values;
	}

	ngx_conf_merge_uint_value(conf->upstream.store_access,
	                          prev->upstream.store_access, 0600);



	ngx_conf_merge_value(conf->upstream.buffering,
	                     prev->upstream.buffering, 1);

	ngx_conf_merge_value(conf->upstream.request_buffering,
	                     prev->upstream.request_buffering, 1);

	ngx_conf_merge_value(conf->upstream.ignore_client_abort,
	                     prev->upstream.ignore_client_abort, 0);

	ngx_conf_merge_value(conf->upstream.force_ranges,
	                     prev->upstream.force_ranges, 0);


	ngx_conf_merge_value(conf->upstream.intercept_errors,
	                     prev->upstream.intercept_errors, 1);


	ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
	                          prev->upstream.connect_timeout, 60000);


	ngx_conf_merge_size_value(conf->upstream.send_lowat,
	                          prev->upstream.send_lowat, 0);

	ngx_conf_merge_size_value(conf->upstream.buffer_size,
	                          prev->upstream.buffer_size,
	                          (size_t) ngx_pagesize);

	ngx_conf_merge_size_value(conf->upstream.limit_rate,
	                          prev->upstream.limit_rate, 0);


	ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
	                          8, ngx_pagesize);

	if (conf->upstream.bufs.num < 2) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		                   "there must be at least 2 \"socketify_buffers\"");
		return NGX_CONF_ERROR;
	}


	size = conf->upstream.buffer_size;
	if (size < conf->upstream.bufs.size) {
		size = conf->upstream.bufs.size;
	}


	ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
	                          prev->upstream.busy_buffers_size_conf,
	                          NGX_CONF_UNSET_SIZE);

	if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
		conf->upstream.busy_buffers_size = 2 * size;
	} else {
		conf->upstream.busy_buffers_size =
		    conf->upstream.busy_buffers_size_conf;
	}

	if (conf->upstream.busy_buffers_size < size) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		                   "\"socketify_busy_buffers_size\" must be equal to or greater "
		                   "than the maximum of the value of \"socketify_buffer_size\" and "
		                   "one of the \"socketify_buffers\"");

		return NGX_CONF_ERROR;
	}

	if (conf->upstream.busy_buffers_size
	        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		                   "\"socketify_busy_buffers_size\" must be less than "
		                   "the size of all \"socketify_buffers\" minus one buffer");

		return NGX_CONF_ERROR;
	}

	ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
	                          prev->upstream.temp_file_write_size_conf,
	                          NGX_CONF_UNSET_SIZE);

	if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
		conf->upstream.temp_file_write_size = 2 * size;
	} else {
		conf->upstream.temp_file_write_size =
		    conf->upstream.temp_file_write_size_conf;
	}

	if (conf->upstream.temp_file_write_size < size) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		                   "\"socketify_temp_file_write_size\" must be equal to or greater than "
		                   "the maximum of the value of \"socketify_buffer_size\" and "
		                   "one of the \"socketify_buffers\"");

		return NGX_CONF_ERROR;
	}


	ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
	                          prev->upstream.max_temp_file_size_conf,
	                          NGX_CONF_UNSET_SIZE);

	if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
		conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
	} else {
		conf->upstream.max_temp_file_size =
		    conf->upstream.max_temp_file_size_conf;
	}

	if (conf->upstream.max_temp_file_size != 0
	        && conf->upstream.max_temp_file_size < size)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		                   "\"socketify_max_temp_file_size\" must be equal to zero to disable "
		                   "temporary files usage or must be equal to or greater than "
		                   "the maximum of the value of \"socketify_buffer_size\" and "
		                   "one of the \"socketify_buffers\"");

		return NGX_CONF_ERROR;
	}

	ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
	                             prev->upstream.next_upstream,
	                             (NGX_CONF_BITMASK_SET
	                              | NGX_HTTP_UPSTREAM_FT_ERROR
	                              | NGX_HTTP_UPSTREAM_FT_TIMEOUT));

	if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
		conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
		                               | NGX_HTTP_UPSTREAM_FT_OFF;
	}

	if (conf->upstream.upstream == NULL) {
		conf->upstream.upstream = prev->upstream.upstream;
	}




	ngx_conf_merge_uint_value(conf->gzip_flag, prev->gzip_flag, 0);
	ngx_conf_merge_uint_value(conf->unescape_type, prev->unescape_type, NGX_CONF_UNSET_UINT);
	ngx_conf_merge_uint_value(conf->nmatch, prev->nmatch, 0);
	ngx_conf_merge_uint_value(conf->nresp_appendable, prev->nresp_appendable, 0);

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	if (clcf->default_type.len) {
		if (conf->content_type.data == NULL) {
			if (prev->content_type.data) {
				conf->content_type.len = prev->content_type.len;
				conf->content_type.data = prev->content_type.data;
			} else {
				conf->content_type.len = clcf->default_type.len;
				conf->content_type.data = clcf->default_type.data;
			}
		}
	} else {
		ngx_conf_merge_str_value(conf->content_type, prev->content_type, content_type_plaintext);
	}

	// ngx_conf_merge_uint_value(conf->extra_byte_cnt, prev->extra_byte_cnt, NGX_CONF_UNSET_UINT);

	// if (conf->scan_type == NGX_SOCKETIFY_NONE) {
	//   conf->scan_type = prev->scan_type;
	// }
	// if (conf->count_type == NGX_SOCKETIFY_NONE) {
	//   conf->count_type = prev->count_type;
	// }
	// ngx_conf_merge_value(conf->max_range_scanned, prev->max_range_scanned, NGX_CONF_UNSET);

	// if (conf->match_type == NGX_SOCKETIFY_NONE) {
	// 	conf->match_type = prev->match_type;
	// }


	ngx_conf_merge_ptr_value(conf->done_recv_matches, prev->done_recv_matches, NULL);
	ngx_conf_merge_ptr_value(conf->filt_resp, prev->filt_resp, NULL);
	ngx_conf_merge_ptr_value(conf->filt_resp_to_hdrs, prev->filt_resp_to_hdrs, NULL);


#if (NGX_HTTP_CACHE)

	if (conf->upstream.cache == NGX_CONF_UNSET) {
		ngx_conf_merge_value(conf->upstream.cache,
		                     prev->upstream.cache, 0);

		conf->upstream.cache_zone = prev->upstream.cache_zone;
		conf->upstream.cache_value = prev->upstream.cache_value;
	}

	if (conf->upstream.cache_zone && conf->upstream.cache_zone->data == NULL) {
		ngx_shm_zone_t  *shm_zone;

		shm_zone = conf->upstream.cache_zone;

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		                   "\"socketify_cache\" zone \"%V\" is unknown",
		                   &shm_zone->shm.name);

		return NGX_CONF_ERROR;
	}

	ngx_conf_merge_uint_value(conf->upstream.cache_min_uses,
	                          prev->upstream.cache_min_uses, 1);

#if (nginx_version >= 1012002)

	ngx_conf_merge_off_value(conf->upstream.cache_max_range_offset,
	                         prev->upstream.cache_max_range_offset,
	                         NGX_MAX_OFF_T_VALUE);

	ngx_conf_merge_value(conf->upstream.cache_background_update,
	                     prev->upstream.cache_background_update, 0);

#endif
	ngx_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
	                             prev->upstream.cache_use_stale,
	                             (NGX_CONF_BITMASK_SET
	                              | NGX_HTTP_UPSTREAM_FT_OFF));

	if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) {
		conf->upstream.cache_use_stale = NGX_CONF_BITMASK_SET
		                                 | NGX_HTTP_UPSTREAM_FT_OFF;
	}

	if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_ERROR) {
		conf->upstream.cache_use_stale |= NGX_HTTP_UPSTREAM_FT_NOLIVE;
	}

	if (conf->upstream.cache_methods == 0) {
		conf->upstream.cache_methods = prev->upstream.cache_methods;
	}

	conf->upstream.cache_methods |= NGX_HTTP_GET | NGX_HTTP_HEAD;

	ngx_conf_merge_ptr_value(conf->upstream.cache_bypass,
	                         prev->upstream.cache_bypass, NULL);

	ngx_conf_merge_ptr_value(conf->upstream.no_cache,
	                         prev->upstream.no_cache, NULL);

	ngx_conf_merge_ptr_value(conf->upstream.cache_valid,
	                         prev->upstream.cache_valid, NULL);

	if (conf->cache_key.value.data == NULL) {
		conf->cache_key = prev->cache_key;
	}

	if (conf->upstream.cache && conf->cache_key.value.data == NULL) {
		ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
		                   "no \"socketify_cache_key\" for \"socketify_cache\"");
	}

	ngx_conf_merge_value(conf->upstream.cache_lock,
	                     prev->upstream.cache_lock, 0);

	ngx_conf_merge_msec_value(conf->upstream.cache_lock_timeout,
	                          prev->upstream.cache_lock_timeout, 5000);

	ngx_conf_merge_msec_value(conf->upstream.cache_lock_age,
	                          prev->upstream.cache_lock_age, 5000);

	ngx_conf_merge_value(conf->upstream.cache_revalidate,
	                     prev->upstream.cache_revalidate, 0);

#endif
	// ngx_conf_merge_uint_value(conf->succ_resp_status, prev->succ_resp_status, NGX_CONF_UNSET_UINT);

	// if (conf->strstrfilter == NULL) {
	//   conf->strstrfilter = prev->strstrfilter;
	// }

// #if (NGX_PCRE)
//   if (conf->regexfilter == NULL) {
//     conf->regexfilter = prev->regexfilter;
//   }
// #endif

	// ngx_conf_merge_value(conf->offset_lf, prev->offset_lf, 0);
	// ngx_conf_merge_value(conf->offset_rt, prev->offset_rt, 0);

	if (conf->sendbuf_cmds.data == NULL) {
		conf->sendbuf_cmds.data = prev->sendbuf_cmds.data;
		conf->sendbuf_cmds.len = prev->sendbuf_cmds.len;
	}

	if (conf->_queue.next == NGX_CONF_UNSET_PTR) {
		conf->_queue = prev->_queue;
	}

	return NGX_CONF_OK;
}


static char *
ngx_http_socketify_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_socketify_loc_conf_t *swlcf = conf;

	ngx_str_t                 *values;
	ngx_url_t                  u;
	ngx_http_core_loc_conf_t  *clcf;

	if (swlcf->upstream.upstream) {
		return "is duplicate";
	}

	// if (swlcf->match_type == NGX_SOCKETIFY_PROXY_RESP_FILTER) {
	// 	return "Proxy response filter only for proxy pass instead of socketify_pass, and socketify send are not allow";
	// }

	values = cf->args->elts;

	ngx_memzero(&u, sizeof(ngx_url_t));

	u.url = values[1];
	u.no_resolve = 1;

	swlcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
	if (swlcf->upstream.upstream == NULL) {
		return NGX_CONF_ERROR;
	}

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	clcf->handler = ngx_http_socketify_handler;

	if (clcf->name.data[clcf->name.len - 1] == '/') {
		clcf->auto_redirect = 1;
	}

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_socketify_get_escape_var(ngx_http_request_t *r,
                                  ngx_http_variable_value_t *v, uintptr_t data) {

	ngx_str_t                            escape_buf;
	u_char                               *p;
	ngx_uint_t                           escape;
	ngx_http_socketify_escape_val_t  *eval_buf = (ngx_http_socketify_escape_val_t*) data;
	ngx_http_complex_value_t              *cplx_val;


	// swlcf = ngx_http_get_module_loc_conf(r, ngx_http_socketify_module);

	if (eval_buf == NULL) {
		v->not_found = 1;
		return NGX_OK;
	}

	cplx_val = &eval_buf->cplx_val;

	if (cplx_val->value.len) {
		if (ngx_http_complex_value(r, cplx_val, &escape_buf) != NGX_OK) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", "Error while escaping buffer..");
			v->not_found = 1;
			return NGX_OK;
		}
	} else {
		v->not_found = 1;
		return NGX_OK;
	}

	switch (eval_buf->escape_type) {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
		escape = 2 * ngx_escape_uri(NULL, escape_buf.data, escape_buf.len, eval_buf->escape_type);
		if (escape) {
			p = ngx_palloc(r->pool,  escape_buf.len + escape);
			if (p == NULL) {
				v->not_found = 1;
				return NGX_OK;
			}
			ngx_escape_uri(p, escape_buf.data, escape_buf.len, eval_buf->escape_type);
		} else {
			p = escape_buf.data;
		}
		break;
	case JSON_ESCAPE_UNESC:
		escape = ngx_socketify_escape_json(NULL, escape_buf.data, escape_buf.len);
		if (escape) {
			p = ngx_palloc(r->pool,  escape_buf.len + escape);
			if (p == NULL) {
				v->not_found = 1;
				return NGX_OK;
			}
			ngx_socketify_escape_json(p, escape_buf.data, escape_buf.len);
		} else {
			p = escape_buf.data;
		}
		break;
	// case HTML_ESCAPE_UNESC:
	// escape = ngx_escape_html(NULL, escape_buf.data, escape_buf.len);
	// p = ngx_palloc(r->pool,  escape_buf.len + escape);
	// if (p == NULL) {
	//   v->not_found = 1;
	//   return NGX_OK;
	// }
	// if (escape) {
	//   ngx_escape_html(p, escape_buf.data, escape_buf.len);
	// }
	// break;
	case CRLF_ESCAPE_UNESC:
		escape = ngx_socketify_escape_crlf(NULL, escape_buf.data, escape_buf.len);
		if (escape) {
			p = ngx_palloc(r->pool,  escape_buf.len + escape);
			if (p == NULL) {
				v->not_found = 1;
				return NGX_OK;
			}
			ngx_socketify_escape_crlf(p, escape_buf.data, escape_buf.len);
		} else {
			p = escape_buf.data;
		}
		break;
	default:
		escape = 0;
		p = escape_buf.data;
		break;
	}

	v->len = escape_buf.len + escape;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;
	v->data = p;

	return NGX_OK;
}

static ngx_int_t
ngx_http_socketify_get_ascii_to_char_var(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data) {

	ngx_uint_t                           *ascii_number = (ngx_uint_t*) data;
	u_char                               *converted_ch;

	converted_ch = ngx_pcalloc(r->pool, sizeof(u_char));

	if (converted_ch == NULL) {
		v->not_found = 1;
		return NGX_OK;
	}

	*converted_ch = (u_char) * ascii_number;

	v->len = 1;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;
	v->data = converted_ch;

	return NGX_OK;
}

#if (NGX_PCRE)
static ngx_int_t
ngx_http_socketify_get_regex_filt_var(ngx_http_request_t *r,
                                      ngx_http_variable_value_t *v, uintptr_t data) {
	ngx_http_socketify_regex_var_t *regex_var = (ngx_http_socketify_regex_var_t*) data;
	int                                captures[20];
	ngx_int_t                          n;
	ngx_str_t                          buf;
	u_char                             *p;

	if (regex_var->datainput.value.len) {
		if (ngx_http_complex_value(r, &regex_var->datainput, &buf) != NGX_OK) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "variable complex value error");
			v->not_found = 1;
			return NGX_OK;
		}
	} else {
		v->not_found = 1;
		return NGX_OK;
	}

	n = ngx_regex_exec(regex_var->regex, &buf, captures, 20);

	if (n > 0 ) { /* match */
		v->len = captures[3] - captures[2];
		buf.data += captures[2];
		if ( v->len == 0 ) {
			v->not_found = 1;
			return NGX_OK;
		}
		v->data = p = ngx_palloc(r->pool,  v->len);
		ngx_memcpy(p, buf.data, v->len);
		v->valid = 1;
		v->no_cacheable = 0;
		v->not_found = 0;
	}
	v->not_found = 1;
	return NGX_OK;
}
#endif

static ngx_int_t
ngx_http_socketify_get_substr_var(ngx_http_request_t *r,
                                  ngx_http_variable_value_t *v, uintptr_t data) {

	ngx_http_socketify_substr_resp_var_t *btwn_match = (ngx_http_socketify_substr_resp_var_t*) data;
	ngx_str_t                          *strstrfil1, *strstrfil2;
	u_char                             *p;
	ngx_str_t                          buf;
	size_t                             p_offset;

	if (btwn_match->datainput.value.len) {
		if (ngx_http_complex_value(r, &btwn_match->datainput, &buf) != NGX_OK) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "variable complex value error");
			v->not_found = 1;
			return NGX_OK;
		}
	} else {
		v->not_found = 1;
		return NGX_OK;
	}

	strstrfil1 = &btwn_match->strstrfilter[0];
	strstrfil2 = &btwn_match->strstrfilter[1];
	// ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "REQUEST BODY %V", &buf);

	p = ngx_socketify_strstr(buf.data, buf.len, strstrfil1->data, strstrfil1->len);
	if (!p) {
		v->not_found = 1;
		return NGX_OK;
	}
	p += btwn_match->offset_lf;
	p_offset = ( p - buf.data );
	p = ngx_socketify_strstr(p, buf.len - p_offset, strstrfil2->data, strstrfil2->len );
	if (!p) {
		v->not_found = 1;
		return NGX_OK;
	}
	p += btwn_match->offset_rt;
	buf.data += p_offset;
	v->len = p - buf.data;

	if ( v->len == 0 ) {
		v->not_found = 1;
		return NGX_OK;
	}
	v->data = p = ngx_palloc(r->pool, v->len);
	ngx_memcpy(p, buf.data, v->len);
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	return NGX_OK;
}

static ngx_int_t
ngx_http_socketify_get_strlen_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
	ngx_str_t                            buf;
	u_char                               *str_number;
	ngx_http_complex_value_t             *eval_buf = (ngx_http_complex_value_t*) data;

	if (eval_buf == NULL) {
		v->not_found = 1;
		return NGX_OK;
	}

	if (eval_buf->value.len) {
		if (ngx_http_complex_value(r, eval_buf, &buf) != NGX_OK) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", "Error while escaping buffer..");
			v->not_found = 1;
			return NGX_OK;
		}
	} else {
		v->not_found = 1;
		return NGX_OK;
	}

	/*Max 20 digit*/
	str_number = ngx_pcalloc(r->pool, 20 * sizeof(u_char));
	(void) ngx_snprintf(str_number, 20, "%O", buf.len);


	v->len = ngx_strlen(str_number);
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;
	v->data = str_number;

	return NGX_OK;
}

static uintptr_t
ngx_socketify_escape_crlf(u_char * dst, u_char * src, size_t size) {
	u_char      ch;
	ngx_uint_t  len;

	if (dst == NULL) {
		len = 0;

		while (size--) {
			ch = *src++;
			if (ch == '\n' || ch == '\r') {
				len++;
			}
		}
		return (uintptr_t) len;
	}

	while (size--) {
		ch = *src++;

		if (ch == '\r') {
			*dst++ = '\\';
			*dst++ = 'r';
		} else if (ch == '\n' ) {
			*dst++ = '\\';
			*dst++ = 'n';
		} else {
			*dst++ = ch;
		}
	}
	return (uintptr_t) dst;
}

static u_char*
ngx_socketify_unescape_crlf(u_char * src, size_t size) {
	u_char      ch,
	            *dst = src;

	while (size--) {
		ch = *src++;
		if (ch == '\\' && size) {
			if (src[0] == 'r') {
				*dst++ = '\r';
				src++;
				size--;
			} else if (src[0] == 'n' ) {
				*dst++ = '\n';
				src++;
				size--;
			} else {
				*dst++ = ch;
			}
		} else {
			*dst++ = ch;
		}
	}
	return dst;
}

#define socketify_hex_codes "0123456789ABCDEF"

uintptr_t
ngx_socketify_escape_json(u_char * dst, u_char * src, size_t size) {
	u_char      ch;
	ngx_uint_t  len;

	if (dst == NULL) {
		len = 0;
		while (size) {
			ch = *src++;
			if (ch == '\\' || ch == '"') {
				len++;
			} else if (ch <= 0x1f) {
				switch (ch) {
				case '\n':
				case '\r':
				case '\t':
				case '\b':
				case '\f':
					len++;
					break;
				default:
					len += 2; // for hex
				}
			}
			size--;
		}
		return (uintptr_t) len;
	}

	while (size) {
		ch = *src++;
		if (ch > 0x1f) {
			if (ch == '\\' || ch == '"') {
				*dst++ = '\\';
			}
			*dst++ = ch;
		} else {
			switch (ch) {
			case '\n':
				*dst++ = '\\';
				*dst++ = 'n';
				break;
			case '\r':
				*dst++ = '\\';
				*dst++ = 'r';
				break;
			case '\t':
				*dst++ = '\\';
				*dst++ = 't';
				break;
			case '\b':
				*dst++ = '\\';
				*dst++ = 'b';
				break;
			case '\f':
				*dst++ = '\\';
				*dst++ = 'f';
				break;
			default:
				*dst++ = socketify_hex_codes[ch >> 4];
				*dst++ = socketify_hex_codes[ch & 0x0F];
			}
		}
		size--;
	}
	return (uintptr_t) dst;
}

u_char *
ngx_socketify_unescape_json(u_char * src, size_t size) {
	u_char            ch,
	                  nextchr,
	                  *dst = src,
	                   hex[2];
	ngx_int_t         hex_ind;

	while (size--) {
		ch = *src++;
		if (ch == '\\' && size) {
			nextchr = src[0];
			switch (nextchr) {
			case 'n':
				*dst++ = '\n';
				src++;
				size--;
				break;
			case 'r':
				*dst++ = '\r';
				src++;
				size--;
				break;
			case 't':
				*dst++ = '\t';
				src++;
				size--;
				break;
			case 'b':
				*dst++ = '\b';
				src++;
				size--;
				break;
			case 'f':
				*dst++ = '\f';
				src++;
				size--;
				break;
			case '\\':
				*dst++ = '\\';
				src++;
				size--;
				break;
			case '"':
				*dst++ = '"';
				src++;
				size--;
				break;
			default:
				if (nextchr <= 0x1f) {
					hex_ind = 0;
					goto hex_;
				} else {
					*dst++ = ch;
				}
			}
		} else if (ch <= 0x1f) { // should have at least 2
			hex_ind = 0;
hex_:
			if (ch >= '0' && ch <= '9') {
				hex[hex_ind] = ch - '0';
			} else if (ch >= 'A' && ch <= 'F') {
				hex[hex_ind] = ch - 'A' + 10;
			} else if (ch >= 'a' && ch <= 'f') {
				hex[hex_ind] = ch - 'a' + 10;
			} else {
				return NULL;
			}
			if (hex_ind == 1) {
				*dst++ = (hex[0] << 4) | hex[1];
				src++;
				size--;
				continue;
			}
			ch = src[0];
			hex_ind = 1;
			goto hex_;
		} else {
			*dst++ = ch;
		}
	}
	return dst;
}

static char*
ngx_conf_socketify_ascii_to_string(ngx_pool_t *p, u_char * asciistr, u_char splitchar, ngx_str_t *rs) {
	u_char *ptok, *nexttok, *data;
	size_t i = 0, total_ascii = 0;
	ngx_int_t ascii;

	ptok = asciistr;

	while ( (nexttok = (u_char*) ngx_strchr(ptok, splitchar) ) ) {
		ptok = nexttok + 1;
		total_ascii++;
	}
	if (ptok) {
		total_ascii++;
	}

	data = rs->data = ngx_pcalloc(p, sizeof(u_char) * total_ascii);
	rs->len = total_ascii;

	ptok = asciistr;
	while ( (nexttok = (u_char*) ngx_strchr(ptok, splitchar) ) ) {
		ascii = ngx_atoi(ptok, nexttok - ptok);
		if (ascii == NGX_ERROR) {
			return "Invalid ascii, range 0-255";
		}
		data[i++] = (u_char) ascii;
		ptok = nexttok + 1;
	}

	ascii = ngx_atoi(ptok, ngx_strlen(ptok) );
	if (ascii == NGX_ERROR) {
		return "Invalid ascii, range 0-255";
	}
	data[i++] = (u_char) ascii;

	return NGX_CONF_OK;
}

/**Return Dest, only cache content length, content type, status code **/
static uintptr_t
ngx_http_socketify_cache_headers_value(ngx_http_request_t *r, u_char* p, ngx_uint_t status_code, ngx_uint_t contentlen, ngx_str_t *content_type) {
	size_t len;
	// u_char *_p;
	// ngx_http_core_loc_conf_t  *clcf;
	// clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
	if (!p) {
		len = sizeof("HTTP/1.x xxx") - 1 + sizeof(CRLF) - 1;
		// if (r->headers_out.server == NULL) {
		// 	if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
		// 		len += sizeof(ngx_http_server_full_string) - 1;

		// 	} else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
		// 		len += sizeof(ngx_http_server_build_string) - 1;
		// 	} else {
		// 		len += sizeof(ngx_http_server_string) - 1;
		// 	}
		// len +=sizeof(CRLF) - 1;
		// }

		// if (r->headers_out.date == NULL) {
		// 	len += sizeof("Date: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
		// }
		// if (r->headers_out.content_type.len) {
		// 	len += sizeof("Content-Type: ") - 1
		// 	       + r->headers_out.content_type.len + 2;

		// 	if (r->headers_out.content_type_len == r->headers_out.content_type.len
		// 	        && r->headers_out.charset.len)
		// 	{
		// 		len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
		// 	}
		// }
		if (content_type->len) {
			len += sizeof("Content-Type: ") - 1 + content_type->len + 2;
		}

		if (contentlen > 0) {
			len += sizeof("Content-Length: ") - 1 + NGX_OFF_T_LEN + sizeof(CRLF) - 1;
		}

		// if (r->headers_out.last_modified == NULL
		//         && r->headers_out.last_modified_time != -1)
		// {
		// 	len += sizeof("Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
		// }

		// if (r->keepalive) {
		// 	len += sizeof("Connection: keep-alive" CRLF) - 1;
		// 	if (clcf->keepalive_header) {
		// 		len += sizeof("Keep-Alive: timeout=") - 1 + NGX_TIME_T_LEN + 2;
		// 	}
		// } else {
		// 	len += sizeof("Connection: close" CRLF) - 1;
		// }

// #if (NGX_HTTP_GZIP)
// 		if (r->gzip_vary) {
// 			if (clcf->gzip_vary) {
// 				len += sizeof("Vary: Accept-Encoding" CRLF) - 1;

// 			} else {
// 				r->gzip_vary = 0;
// 			}
// 		}
// #endif
		len = len + sizeof(CRLF) - 1;

		return len;
	}

	p = ngx_copy(p, "HTTP/1.1 ", sizeof("HTTP/1.x ") - 1);
	p = (u_char*)  ngx_http_socketify_int_to_string(p, 3/*status code max 3 only*/, status_code);
	*p++ = CR; *p++ = LF;

	// if (r->headers_out.server == NULL) {
	// 	if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
	// 		p = ngx_copy(p, ngx_http_server_full_string, sizeof(ngx_http_server_full_string) - 1);
	// 	} else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
	// 		p = ngx_copy(p, ngx_http_server_build_string, sizeof(ngx_http_server_build_string) - 1);
	// 	} else {
	// 		p = ngx_copy(p, ngx_http_server_string, sizeof(ngx_http_server_string) - 1);
	// 	}
	// *p++ = CR; *p++ = LF;
	// }

	// if (r->headers_out.date == NULL) {
	// 	p = ngx_copy(p, "Date: ", sizeof("Date: ") - 1);
	// 	p = ngx_copy(p, ngx_cached_http_time.data, ngx_cached_http_time.len);
	// 	*p++ = CR; *p++ = LF;
	// }

	// if (r->headers_out.content_type.len) {
	// 	p = ngx_copy(p, "Content-Type: ", sizeof("Content-Type: ") - 1);
	// 	_p = p;
	// 	p = ngx_copy(p, r->headers_out.content_type.data,
	// 	             r->headers_out.content_type.len);

	// 	if (r->headers_out.content_type_len == r->headers_out.content_type.len
	// 	        && r->headers_out.charset.len) {
	// 		p = ngx_copy(p, "; charset=", sizeof("; charset=") - 1);
	// 		p = ngx_copy(p, r->headers_out.charset.data, r->headers_out.charset.len);

	// 		/* update r->headers_out.content_type for possible logging */
	// 		r->headers_out.content_type.len = p - _p;
	// 		r->headers_out.content_type.data = _p;
	// 	}
	// 	*p++ = CR; *p++ = LF;
	// }
	if (content_type->len) {
		p = ngx_copy(p, "Content-Type: ", sizeof("Content-Type: ") - 1 );
		p = ngx_copy(p, content_type->data, content_type->len);
		*p++ = CR; *p++ = LF;
	}

	if (contentlen > 0) {
		p = ngx_copy(p, "Content-Length: ", sizeof("Content-Length: ") - 1 );
		p = (u_char*) ngx_http_socketify_int_to_string(p, 20 /*Max 20 digit len*/, contentlen);
		*p++ = CR; *p++ = LF;
	}

	// if (r->headers_out.last_modified == NULL
	//         && r->headers_out.last_modified_time != -1)
	// {
	// 	p = ngx_copy(p, "Last-Modified: ", sizeof("Last-Modified: ") - 1);
	// 	p = ngx_http_time(p, r->headers_out.last_modified_time);
	// 	*p++ = CR; *p++ = LF;
	// }

	// if (r->keepalive) {
	// 	p = ngx_copy(p, "Connection: keep-alive" CRLF, sizeof("Connection: keep-alive" CRLF) - 1);

	// 	if (clcf->keepalive_header) {
	// 		p = ngx_sprintf(p, "Keep-Alive: timeout=%T" CRLF,
	// 		                clcf->keepalive_header);
	// 	}
	// } else {
	// 	p = ngx_copy(p, "Connection: close" CRLF, sizeof("Connection: close" CRLF) - 1);
	// }

// #if (NGX_HTTP_GZIP)
// 	if (r->gzip_vary) {
// 		p = ngx_copy(p, "Vary: Accept-Encoding" CRLF, sizeof("Vary: Accept-Encoding" CRLF) - 1);
// 	}
// #endif

	*p++ = CR; *p++ = LF;

	return (uintptr_t)p;
}

static uintptr_t
ngx_http_socketify_int_to_string(u_char *str, size_t max_len, ngx_uint_t num) {
	ngx_uint_t i, rem, len = 0, n;
	n = num;

	if (!str)  {
		n = num;
		while (n != 0)
		{
			if (max_len == len++) {
				return 0;
			}
			n /= 10;
		}
		return (uintptr_t) len;
	}

	while (n != 0)
	{
		if (max_len == len++) {
			return 0;
		}
		n /= 10;
	}
	for (i = 0; i < len; i++)
	{
		rem = num % 10;
		num = num / 10;
		str[len - (i + 1)] = rem + '0';
	}
	// str[len] = '\0';
	/* return last pointer */
	return (uintptr_t) str + len;
}

// static ngx_uint_t
// ngx_http_socketify_string_to_int(char str[], size_t len) {
// 	ngx_uint_t i, num = 0;

// 	for (i = 0; i < len; i++) {
// 		num = num + ((str[len - (i + 1)] - '0') * pow(10, i));
// 	}

// 	return num;
// }

/*External response filter*/

// static ngx_int_t
// ngx_http_socketify_header_filter(ngx_http_request_t *r) {
// 	ngx_http_socketify_loc_conf_t *slcf;
// 	ngx_http_socketify_ctx_t       *ctx;
// 	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Ext Response filtering");

// 	slcf = ngx_http_get_module_loc_conf(r, ngx_http_socketify_module);

// 	if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED
// 	        || r->headers_out.status == NGX_HTTP_NO_CONTENT
// 	        || r->headers_out.status < NGX_HTTP_OK
// 	        || r != r->main
// 	        || r->method == NGX_HTTP_HEAD)
// 	{
// 		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "========  head response only =============");
// 	}

// 	if (slcf->match_type != NGX_SOCKETIFY_PROXY_RESP_FILTER/*
//             || r->headers_out.content_type.len != sizeof("application/json") - 1
//             || ngx_strncmp(r->headers_out.content_type.data, "application/json",
//                            r->headers_out.content_type.len) != 0*/) {
// 		goto SKIP_SOCKETIFY_FILTER;
// 	}


// 	if (r->header_only) {
// 		return ngx_http_next_header_filter(r);
// 	}

// 	ctx = ngx_http_get_module_ctx(r, ngx_http_socketify_module);
// 	if (ctx == NULL) {
// 		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_socketify_ctx_t));
// 		if (ctx == NULL) {
// 			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unable to allocate memory");
// 			return NGX_ERROR;
// 		}
// 	}

// 	if (!ctx->ext_resp_buf) {
// 		ctx->ext_resp_buf = ngx_create_temp_buf(r->pool, r->headers_out.content_length_n);
// 	}

// 	ngx_http_set_ctx(r, ctx, ngx_http_socketify_module);

// SKIP_SOCKETIFY_FILTER:
// 	r->filter_need_in_memory = 1;
// 	// if (r == r->main) {

// 	ngx_http_clear_content_length(r);
// 	ngx_http_clear_accept_ranges(r);
// 	ngx_http_weak_etag(r);
// 	// }


// 	return ngx_http_next_header_filter(r);
// }

// static ngx_int_t
// ngx_http_socketify_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
// 	ngx_http_socketify_loc_conf_t *slcf;

// 	slcf = ngx_http_get_module_loc_conf(r, ngx_http_socketify_module);

// 	if (slcf->match_type != NGX_SOCKETIFY_PROXY_RESP_FILTER) {
// 		return ngx_http_next_body_filter(r, in);
// 	}

// 	ngx_int_t                   rc;
// 	ngx_buf_t                  *b;
// 	ngx_chain_t                *cl, *tl, *out, **ll;
// 	ngx_http_socketify_ctx_t  *ctx;

// 	ctx = ngx_http_get_module_ctx(r, ngx_http_socketify_module);
// 	if (ctx == NULL) {
// 		return NGX_ERROR;
// 	}

// 	/* create a new chain "out" from "in" with all the changes */

// 	ll = &out;

// 	for (cl = in; cl; cl = cl->next) {

// 		ctx->ext_resp_buf->last = ngx_copy(ctx->ext_resp_buf->last, cl->buf->pos, ngx_buf_size(cl->buf));
// 		/* loop until last buf then we do the response filter */
// 		if (cl->buf->last_buf) {
// 			tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
// 			if (tl == NULL) {
// 				return NGX_ERROR;
// 			}

// 			b = tl->buf;

// 			// ngx_index_docs_parser(r, b, ctx->ext_resp_buf->pos, ctx->ext_resp_buf->last - ctx->ext_resp_buf->pos);
// 			/**PARSE**/

// 			b->start = ctx->ext_resp_buf->start;
// 			b->pos = ctx->ext_resp_buf->pos;
// 			b->last = ctx->ext_resp_buf->last;
// 			b->end = ctx->ext_resp_buf->end;

// 			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Filter result %*s", b->last - b->pos , b->pos );
// 			/**END PARSE**/

// 			b->tag = (ngx_buf_tag_t) &ngx_http_socketify_module;
// 			b->temporary = 1;
// 			b->last_buf = 1;


// 			*ll = tl;
// 			ll = &tl->next;
// 			CLEAR_BUF(cl->buf);
// 			goto out_result;
// 		}

// 		CLEAR_BUF(cl->buf); // clear current buffer

// 	}
// out_result:
// 	*ll = NULL;

// 	/* send the new chain */

// 	rc = ngx_http_next_body_filter(r, out);

// 	/* update "busy" and "free" chains for reuse */

// 	ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
// 	                        (ngx_buf_tag_t) &ngx_http_socketify_module);

// 	return rc;
// }