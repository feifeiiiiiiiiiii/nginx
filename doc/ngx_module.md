#### Nginx 模块组成

模块的配置

```
ngx_http_<module_name>_(main|srv|loc)_conf_t 

eg:
    typedef struct {
        ngx_unit_t methods;
        ngx_flag_t create_full_put_path;
        ngx_unit_t access;
    } ngx_http_dav_loc_t;

```

模块指令

```

struct ngx_command_s {
    ngx_str_t name;     // 模块指令的名称 如: proxy_pass;
    ngx_uint_t type;    // 模块指令出现的合法位置
                        // NGX_HTTP_MAIN_CONF 指令出现在全局配置部分合法
                        // NGX_HTTP_SRV_CONF  指令出现在主机配置部分合法
                        // NGX_HTTP_LOC_CONF  指令出现在loc配置部分合法
                        // NGX_HTTP_UPS_CONF  指令出现在上游服务器配置部分合法
                        // NGX_CONF_NOARGS    指令没有参数
                        // NGX_CONF_TAKE1     指令读入一个参数
                        // NGX_CONF_TAKE2     指令读入两个参数
                        // NGX_CONF_TAKE7     指令读入7个参数
                        // NGX_CONF_FLAG      指令读入一个布尔
                        // NGX_CONF_1MORE     指令至少读入一个参数
                        // NGX_CONF_2MORE     指令至少读入两个参数
    char *(*set)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf); 
                        // cf 指向ngx_conf_t的指针, 包含从配置文件中指令传过来的参数
                        // cmd 指向ngx_command_t的指针
                        // 指向自定义模块配置的指针 conf 告诉 Nginx 把这个值是放在全局配置部分、
                           主机配置部分还是位置配置部分(用 NGX_HTTP_MAIN_CONF_OFFSET, NGX_HTTP_SRV_CONF_OFFSET或NGX_HTTP_LOC_CONF_OFFSET)。然后offset确定
                           到底是保存在结构体的哪个位置
    ngx_uint_t conf;    
    ngx_unit_t offset;  
    void *post; // 一般为NULL

};

```

模块的上下文

```
typedef struct {
    ngx_int_t   (*preconfiguration)(ngx_conf_t *cf);    // 读入配置文件前调用
    ngx_int_t   (*postconfiguration)(ngx_conf_t *cf);   // 读入配置文件后调用

    void       *(*create_main_conf)(ngx_conf_t *cf);    // 创建全局部分配置调用
    char       *(*init_main_conf)(ngx_conf_t *cf, void *conf);  // 初始化全局配置调用

    void       *(*create_srv_conf)(ngx_conf_t *cf); // 创建主机配置调用
    char       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf); // 与全局配置合并调用

    void       *(*create_loc_conf)(ngx_conf_t *cf); // 创建位置部分调用
    char       *(*merge_loc_conf)(ngx_conf_t *cf, void *prev, void *conf);  // 与主机部分合并调用
} ngx_http_module_t;

```

剖析处理模块

```
 调用ngx_http_get_module_loc_conf获得当前的配置结构体

 eg:
  static ngx_int_t
    ngx_http_circle_gif_handler(ngx_http_request_t *r) {
    ngx_http_circle_gif_loc_conf_t  *circle_gif_config;
    circle_gif_config = ngx_http_get_module_loc_conf(r,ngx_http_circle_gif_module);
    ...
}

```

产生回复

```

typedef struct {
    ...
    /* the memory pool, used in the ngx_palloc functions */
    ngx_pool_t   *pool;
    ngx_str_t   uri;
    ngx_str_t   args;
    ngx_http_headers_in_t             headers_in;
    ...
} ngx_http_request_t;
uri 是请求的路径,比如:"/query.cgi"。
args 是在问号之后请求的参数(比如 "name=john")。
headers_in 有很多有用的东西,如cookie和浏览器信息

```

发送HTTP头部 & HTTP主体

```
处理函数生成头部变量,然后调用ngx_http_send_header(r)函数,下面列出些有用的部分:
typedef stuct {
    ...
    ngx_uint_t   status;
    size_t   content_type_len;
    ngx_str_t                         content_type;
    ngx_table_elt_t                  *content_encoding;
    off_t   content_length_n;
    time_t   date_time;
    ..
    time_t                            last_modified_time;
} ngx_http_headers_out_t;


现在模块已经产生了一个回复,把它放到内存中。需要为回复分配一块特别的buffer,并把这个buffer连接到一个链表,然后调用“send body”函数发送
这些链表有什么用?在 Nginx 中,处理模块和过滤模块在处理完成后产生的回 复都包含在缓冲中,每次产生一个 buffer;每个链表成员保存指向下一个成员的指针,
如果是最后的 buffer,就置为 NULL。这里我们简单地假定只有一个 buffer 成员。
首先,模块声明一块 buffer 和一条链表:
    ngx_buf_t    *b;
    ngx_chain_t   out
第二步是分配缓冲,然后指向我们的回复数据:
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"Failed to allocate response buffer.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->pos = some_bytes; /* first position in memory of the data */
    b->last = some_bytes + some_bytes_length; /* last position 
    b->memory = 1; /* content is in read-only memory */
    b->last_buf = 1; /* there will be no more buffers in the request

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);

```



